"""entrypoints/cli.py — the thin CLI surface (CLAUDE.md §1.3, §3.4, §6.1.4).

Parses args, assembles BYOK credentials from the caller's own environment (§3.5), calls
`graph.build.run`, prints the report, and exits with the gate's code — no audit logic, and
it never shells out to the HTTP server. Subcommands: audit (gates CI), query (evidence only,
always exit 0), gc (PGVector CronJob maintenance, §3.4).
"""

from __future__ import annotations

import argparse
import logging
import sys

from credentials import MissingCredentialError, UserCredentials
from graph import build as graph_build
from graph.router import AuditRequest
from graph.state import RunMode


def _print_report(result) -> None:
    gd = result.gate_decision
    status = "PASS" if result.passed else "FAIL"
    print(f"[{result.run_id}] {status}  overall={gd.overall.name}  exit={result.exit_code}")
    if result.incomplete:
        print("  ⚠ incomplete analysis — result is provisional")
    print(gd.summary)


def _run(req: AuditRequest, *, tools, session, memory, config, require_embedding: bool) -> int:
    try:
        creds = UserCredentials.from_env(require_embedding=require_embedding)
    except MissingCredentialError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    result = graph_build.run(req, credentials=creds, tools=tools, session=session, memory=memory, config=config)
    _print_report(result)
    return result.exit_code


def main(argv=None, *, tools=None, session=None, memory=None, config=None) -> int:
    """Entry point. Machinery is injected for testability; in production a thin
    `__main__` wires the real tools/session/memory and calls this."""
    parser = argparse.ArgumentParser(prog="depaudit")
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="full-repo audit (gates CI)")
    p_audit.add_argument("target", nargs="?", default=".", help="repo path / git URL / lockfile")

    p_query = sub.add_parser("query", help="single-package investigation (evidence only)")
    p_query.add_argument("target", help="package spec, e.g. npm:left-pad@1.3.0")

    sub.add_parser("gc", help="PGVector garbage collection (CronJob entry, §3.4)")

    args = parser.parse_args(argv)

    if args.command == "gc":
        return _run_gc(memory)

    use_memory = memory is not None
    if args.command == "audit":
        req = AuditRequest(mode=RunMode.AUDIT, target=args.target)
    else:  # query
        req = AuditRequest(mode=RunMode.QUERY, target=args.target)
    return _run(req, tools=tools, session=session, memory=memory, config=config, require_embedding=use_memory)


def _run_gc(memory) -> int:
    """Finite maintenance job: apply the §3.4 differentiated retention. Never part of an
    audit run. Requires only the embedding/store deployment, not an LLM key."""
    if memory is None:
        print("gc: no memory store configured; nothing to do")
        return 0
    if not hasattr(memory, "gc"):
        print("gc: memory manager exposes no gc(); store retention is TTL-only", file=sys.stderr)
        return 0
    report = memory.gc()
    print(f"gc complete: {report}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    # Production wiring supplies the real tools/session/memory; kept out of the library
    # surface so importing this module has no side effects.
    raise SystemExit(main())
