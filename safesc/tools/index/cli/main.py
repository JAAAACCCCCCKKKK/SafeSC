"""``index`` — SafeSC Stage 0-1 CLI (discovery + normalisation).

Subcommand interface (agent-invokable, one stage per tool):

    index discover <path> [--json]   Stage 0 — find dependency lockfiles
    index parse    <path>            Stage 1 — parse lockfiles to a JSON dep array

Backward-compatible flag interface (unchanged behaviour):

    index <path>            Stage 0 discovery (human-readable)
    index --json <path>     Stage 1 parse (JSON)

Both interfaces accept a repeatable ``--exclude PATTERN`` (gitignore syntax, matched
relative to <path>), layered on top of any ``.safescignore`` file auto-discovered at
<path> — see `safesc.tools.index.core.discovery.discover`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from safesc.tools.index.cli.commands import cmd_discover, cmd_parse
from safesc.tools.index.core.discovery import discover, print_discovered
from safesc.tools.index.core.normalizer import parse_lockfiles, to_json

_SUBCOMMANDS = frozenset({"discover", "parse"})


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="index",
        usage="index [--json] [path]\n       index <command> [path] [options]",
        description="SafeSC Stage 0-1: discover and normalise dependency lockfiles.",
        epilog=(
            "Default (flag) interface:\n"
            "  index [path]           Stage 0 - discover lockfiles (human-readable; "
            "default path: current directory)\n"
            "  index --json [path]    Stage 1 - parse lockfiles into a JSON dependency "
            "array\n\n"
            "Use 'index <command> --help' for a subcommand's options."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Mirror the legacy top-level flag so it appears in `index --help` and so the parser
    # can render accurate usage; the legacy path (not this parser) actually consumes it.
    parser.add_argument(
        "--json", action="store_true",
        help="Stage 1: parse discovered lockfiles into a JSON dependency array.",
    )
    parser.add_argument(
        "--exclude", action="append", metavar="PATTERN", default=None,
        help="Gitignore-syntax pattern to exclude (repeatable), layered on top of any "
             ".safescignore file at <path>.",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_discover = sub.add_parser(
        "discover", help="Stage 0: discover dependency lockfiles under a path."
    )
    p_discover.add_argument("path", nargs="?", default=".", help="Repository root (default: .)")
    p_discover.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON instead of text."
    )
    p_discover.add_argument(
        "--exclude", action="append", metavar="PATTERN", default=None,
        help="Gitignore-syntax pattern to exclude (repeatable).",
    )

    p_parse = sub.add_parser(
        "parse", help="Stage 1: parse lockfiles into a normalised JSON dependency array."
    )
    p_parse.add_argument("path", nargs="?", default=".", help="Repository root (default: .)")
    p_parse.add_argument(
        "--exclude", action="append", metavar="PATTERN", default=None,
        help="Gitignore-syntax pattern to exclude (repeatable).",
    )

    return parser


def _run_subcommand(args: list[str]) -> int:
    parser = _build_parser()
    ns = parser.parse_args(args)
    root = Path(ns.path)
    exclude = ns.exclude or []

    if ns.command == "discover":
        return cmd_discover(root, as_json=ns.json, exclude=exclude)
    if ns.command == "parse":
        return cmd_parse(root, exclude=exclude)

    parser.print_help()
    return 0


def _extract_exclude(args: list[str]) -> tuple[list[str], list[str]]:
    """Pull `--exclude PATTERN` pairs out of the legacy flag interface's args (which
    otherwise treats any non-`--`-prefixed token as the positional path — a pattern
    value like `tests/**` would be misread as the path if left in place)."""
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
    """Preserve the original flag-based behaviour verbatim."""
    exclude, args = _extract_exclude(args)
    output_json = "--json" in args
    positional = [a for a in args if not a.startswith("--")]
    root = Path(positional[0]) if positional else Path.cwd()

    try:
        files = discover(root, exclude=exclude)
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

    # Help must never run discovery/parsing (no filesystem walk, no I/O). Handle it up
    # front for the legacy flag interface, which otherwise treats `--help` as an unknown
    # `--` flag and silently runs the default action. Subcommand help (e.g.
    # `index discover --help`) is left to argparse below.
    if args and args[0] in {"-h", "--help"}:
        _build_parser().print_help()
        return 0

    # Route to the unified subcommand interface only when the first token is a
    # known subcommand; otherwise fall back to the legacy flag interface so
    # existing invocations (e.g. `index --json <path>`) behave identically.
    if args and args[0] in _SUBCOMMANDS:
        return _run_subcommand(args)

    return _run_legacy(args)


if __name__ == "__main__":
    sys.exit(main())
