"""Top-level CLI for depaudit.

Currently only Stage 0 (discovery) is implemented.
"""

from __future__ import annotations

import sys
from pathlib import Path

from depaudit.core.discovery import discover, print_discovered


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    root = Path(args[0]) if args else Path.cwd()

    try:
        files = discover(root)
    except NotADirectoryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_discovered(files, root.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())