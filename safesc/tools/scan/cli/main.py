"""``scan`` — SafeSC Stage 2-3 CLI (provenance verification + trust signals).

Subcommand interface (agent-invokable, one stage per tool):

    scan verify  <path>   Stage 2 — verify lockfile hashes vs registries (JSON)
    scan signals <path>   Stage 3 — collect cheap trust signals (JSON)

Backward-compatible flag interface (unchanged behaviour):

    scan --verify <path>    Stage 2 hash verification (JSON)
    scan --signals <path>   Stage 3 cheap signals (JSON)

With no subcommand or flag, ``scan <path>`` runs Stage 2 verification.

Both interfaces accept a repeatable ``--exclude PATTERN`` (gitignore syntax, matched
relative to <path>), layered on top of any ``.safescignore`` file auto-discovered at
<path> — see `safesc.tools.index.core.discovery.discover`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from safesc.tools.index.core.discovery import discover
from safesc.tools.index.core.normalizer import parse_lockfiles
from safesc.tools.scan.cli.commands import cmd_signals, cmd_verify

_SUBCOMMANDS = frozenset({"verify", "signals"})


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan",
        usage="scan [--verify | --signals] [path]\n       scan <command> [path]",
        description="SafeSC Stage 2-3: verify provenance and collect trust signals.",
        epilog=(
            "Default (flag) interface:\n"
            "  scan [path]            Stage 2 - verify lockfile hashes vs registries "
            "(JSON; default path: current directory)\n"
            "  scan --verify [path]   Stage 2 - hash verification (JSON; the default)\n"
            "  scan --signals [path]  Stage 3 - collect cheap trust signals (JSON)\n\n"
            "Use 'scan <command> --help' for a subcommand's options."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Mirror the legacy top-level flags so they show up in `scan --help`; the legacy path
    # (not this parser) actually consumes them.
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--verify", action="store_true",
        help="Stage 2: verify lockfile hashes against registry hashes (JSON; default).",
    )
    mode.add_argument(
        "--signals", action="store_true",
        help="Stage 3: collect cheap trust signals over every dependency (JSON).",
    )
    parser.add_argument(
        "--exclude", action="append", metavar="PATTERN", default=None,
        help="Gitignore-syntax pattern to exclude (repeatable), layered on top of any "
             ".safescignore file at <path>.",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_verify = sub.add_parser(
        "verify", help="Stage 2: verify lockfile hashes against registry hashes (JSON)."
    )
    p_verify.add_argument("path", nargs="?", default=".", help="Repository root (default: .)")
    p_verify.add_argument(
        "--exclude", action="append", metavar="PATTERN", default=None,
        help="Gitignore-syntax pattern to exclude (repeatable).",
    )

    p_signals = sub.add_parser(
        "signals", help="Stage 3: collect cheap trust signals over every dependency (JSON)."
    )
    p_signals.add_argument("path", nargs="?", default=".", help="Repository root (default: .)")
    p_signals.add_argument(
        "--exclude", action="append", metavar="PATTERN", default=None,
        help="Gitignore-syntax pattern to exclude (repeatable).",
    )

    return parser


def _run_subcommand(args: list[str]) -> int:
    parser = _build_parser()
    ns = parser.parse_args(args)
    root = Path(ns.path)
    exclude = ns.exclude or []

    if ns.command == "verify":
        return cmd_verify(root, exclude=exclude)
    if ns.command == "signals":
        return cmd_signals(root, exclude=exclude)

    parser.print_help()
    return 0


def _extract_exclude(args: list[str]) -> tuple[list[str], list[str]]:
    """Pull `--exclude PATTERN` pairs out of the legacy flag interface's args (which
    otherwise treats any non-`--`-prefixed token as the positional path)."""
    patterns: list[str] = []
    remaining: list[str] = []
    i = 0
    while i < len(args):
        if args[i] == "--exclude" and i + 1 < len(args):
            patterns.append(args[i + 1])
            i += 2
            continue
        remaining.append(args[i])
        i += 1
    return patterns, remaining


def _run_legacy(args: list[str]) -> int:
    """Preserve the original flag-based behaviour verbatim (default: verify)."""
    exclude, args = _extract_exclude(args)
    run_signals = "--signals" in args
    positional = [a for a in args if not a.startswith("--")]
    root = Path(positional[0]) if positional else Path.cwd()

    try:
        files = discover(root, exclude=exclude)
    except NotADirectoryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    deps = parse_lockfiles(files)

    if run_signals:
        from safesc.tools.scan.signals.collector import run_collection

        signals = run_collection(deps)
        print(json.dumps([s.to_dict() for s in signals], indent=2))
        return 0

    from safesc.tools.scan.signals.provenance.verifier import run_verification

    results = run_verification(deps)
    print(json.dumps([r.to_dict() for r in results], indent=2))
    has_critical = any(r.severity.value == "critical" for r in results)
    return 1 if has_critical else 0


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    # Help must never run verification/signal collection — the legacy default makes real
    # network requests to registries, so a user asking for help must not trigger outbound
    # HTTP. Handle `-h`/`--help` up front; subcommand help is left to argparse below.
    if args and args[0] in {"-h", "--help"}:
        _build_parser().print_help()
        return 0

    if args and args[0] in _SUBCOMMANDS:
        return _run_subcommand(args)

    return _run_legacy(args)


if __name__ == "__main__":
    sys.exit(main())
