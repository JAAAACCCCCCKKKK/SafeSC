"""``index`` — SafeSC Stage 0-1 CLI (discovery + normalisation).

Subcommand interface (agent-invokable, one stage per tool):

    index discover <path> [--json]   Stage 0 — find dependency lockfiles
    index parse    <path>            Stage 1 — parse lockfiles to a JSON dep array

Backward-compatible flag interface (unchanged behaviour):

    index <path>            Stage 0 discovery (human-readable)
    index --json <path>     Stage 1 parse (JSON)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools.index.cli.commands import cmd_discover, cmd_parse
from tools.index.core.discovery import discover, print_discovered
from tools.index.core.normalizer import parse_lockfiles, to_json

_SUBCOMMANDS = frozenset({"discover", "parse"})


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="index",
        description="SafeSC Stage 0-1: discover and normalise dependency lockfiles.",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_discover = sub.add_parser(
        "discover", help="Stage 0: discover dependency lockfiles under a path."
    )
    p_discover.add_argument("path", nargs="?", default=".", help="Repository root (default: .)")
    p_discover.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON instead of text."
    )

    p_parse = sub.add_parser(
        "parse", help="Stage 1: parse lockfiles into a normalised JSON dependency array."
    )
    p_parse.add_argument("path", nargs="?", default=".", help="Repository root (default: .)")

    return parser


def _run_subcommand(args: list[str]) -> int:
    parser = _build_parser()
    ns = parser.parse_args(args)
    root = Path(ns.path)

    if ns.command == "discover":
        return cmd_discover(root, as_json=ns.json)
    if ns.command == "parse":
        return cmd_parse(root)

    parser.print_help()
    return 0


def _run_legacy(args: list[str]) -> int:
    """Preserve the original flag-based behaviour verbatim."""
    output_json = "--json" in args
    positional = [a for a in args if not a.startswith("--")]
    root = Path(positional[0]) if positional else Path.cwd()

    try:
        files = discover(root)
    except NotADirectoryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if output_json:
        deps = parse_lockfiles(files)
        print(to_json(deps))
        return 0

    print_discovered(files, root.resolve())
    return 0


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    # Route to the unified subcommand interface only when the first token is a
    # known subcommand; otherwise fall back to the legacy flag interface so
    # existing invocations (e.g. `index --json <path>`) behave identically.
    if args and args[0] in _SUBCOMMANDS:
        return _run_subcommand(args)

    return _run_legacy(args)


if __name__ == "__main__":
    sys.exit(main())
