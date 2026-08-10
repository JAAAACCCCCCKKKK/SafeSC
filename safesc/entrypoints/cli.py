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

from safesc.security.credentials import MissingCredentialError, UserCredentials
from safesc.graph import build as graph_build
from safesc.graph.router import AuditRequest
from safesc.graph.state import RunMode


def _dep_count(result) -> int:
    """Best-effort dependency count from the run's final state (AuditState or dict)."""
    state = result.final_state
    deps = getattr(state, "dependencies", None)
    if deps is None and isinstance(state, dict):
        deps = state.get("dependencies")
    try:
        return len(deps) if deps is not None else -1
    except TypeError:
        return -1


def _print_report(result, *, target: str = "") -> None:
    gd = result.gate_decision
    status = "PASS" if result.passed else "FAIL"
    print(f"[{result.run_id}] {status}  overall={gd.overall.name}  exit={result.exit_code}")
    if result.incomplete:
        print("  ⚠ incomplete analysis — result is provisional")
    print(gd.summary)
    if _dep_count(result) == 0:
        # A silent "0 deps" almost always means discovery found no lockfile — surface
        # why, since an empty audit trivially passes and can hide a misconfiguration.
        where = f" under '{target}'" if target else ""
        print(
            f"  ⚠ no dependencies detected{where}. SafeSC found no supported lockfile "
            "(e.g. requirements.txt, uv.lock, poetry.lock, package-lock.json, "
            "pnpm-lock.yaml, Cargo.lock, go.sum, pom.xml). Check that the repository is "
            "checked out before this step and that 'target' points at the project root."
        )


def _emit_reports(result, *, report_dir, report_format) -> None:
    """Build the canonical report from the run's final state and write artifacts (§6, §7).
    Kept out of the graph: the reporter only projects the already-written decision."""
    from safesc.reporter import FORMATS, build_report, write_reports

    report = build_report(result.final_state, run_id=result.run_id)
    formats = FORMATS if report_format in (None, "all") else [report_format]
    written = write_reports(report, report_dir, formats=formats)
    for path in written:
        print(f"  wrote {path}")


def _run(req: AuditRequest, *, tools, session, memory, config, require_embedding: bool,
         report_dir=None, report_format=None) -> int:
    try:
        creds = UserCredentials.from_env(require_embedding=require_embedding)
    except MissingCredentialError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    result = graph_build.run(req, credentials=creds, tools=tools, session=session, memory=memory, config=config)
    _print_report(result, target=req.target)
    if report_dir:
        _emit_reports(result, report_dir=report_dir, report_format=report_format)
    return result.exit_code


def main(argv=None, *, tools=None, session=None, memory=None, config=None) -> int:
    """Entry point. Machinery is injected for testability; in production a thin
    `__main__` wires the real tools/session/memory and calls this."""
    parser = argparse.ArgumentParser(prog="safesc")
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_report_args(p):
        p.add_argument("--report-dir", default=None, help="write JSON/Markdown/SARIF artifacts here")
        p.add_argument("--format", dest="report_format", default="all",
                       choices=["all", "json", "markdown", "md", "sarif"],
                       help="report format to write (default: all)")

    def _add_exclude_arg(p):
        # Declared here purely so `--help` documents it and `parse_args` doesn't reject
        # it as unrecognised; the value itself is already consumed by
        # `bootstrap._preparse_exclude` and baked into `tools` before this parser ever
        # runs (tools are constructed before this function is called — see
        # entrypoints/bootstrap.py). Not read from `args` below.
        p.add_argument(
            "--exclude", action="append", metavar="PATTERN", default=None,
            help="gitignore-syntax pattern to exclude (repeatable), layered on top of "
                 "any .safescignore file at the target root",
        )

    p_audit = sub.add_parser("audit", help="full-repo audit (gates CI)")
    p_audit.add_argument("target", nargs="?", default=".", help="repo path / git URL / lockfile")
    _add_report_args(p_audit)
    _add_exclude_arg(p_audit)

    p_query = sub.add_parser("query", help="single-package investigation (evidence only)")
    p_query.add_argument("target", help="package spec, e.g. npm:left-pad@1.3.0")
    _add_report_args(p_query)
    _add_exclude_arg(p_query)

    sub.add_parser("gc", help="PGVector garbage collection (CronJob entry, §3.4)")

    args = parser.parse_args(argv)

    if args.command == "gc":
        return _run_gc(memory)

    use_memory = memory is not None
    if args.command == "audit":
        req = AuditRequest(mode=RunMode.AUDIT, target=args.target)
    else:  # query
        req = AuditRequest(mode=RunMode.QUERY, target=args.target)
    return _run(
        req, tools=tools, session=session, memory=memory, config=config, require_embedding=use_memory,
        report_dir=args.report_dir, report_format=args.report_format,
    )


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
