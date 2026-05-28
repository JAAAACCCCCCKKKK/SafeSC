"""Top-level CLI for depaudit.

Stage 0 (discovery) runs by default.
Pass --json to also run Stage 1 (parse) and emit a JSON dependency array.
"""

from __future__ import annotations

import sys
from pathlib import Path

from depaudit.core.discovery import discover, print_discovered
from depaudit.core.normalizer import parse_lockfiles, to_json


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

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
    else:
        print_discovered(files, root.resolve())

    return 0


if __name__ == "__main__":
    sys.exit(main())
