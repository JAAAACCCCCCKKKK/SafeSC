"""Stage 0-1 command implementations for the ``index`` tool.

Each function is a thin, self-contained wrapper around one pipeline stage.  It
takes a filesystem *root*, runs exactly one stage, emits a machine-consumable
result to stdout, and returns a process exit code — making every stage
individually callable so an agent can drive the pipeline one tool at a time.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from safesc.tools.index.core.discovery import DiscoveredFile, discover, print_discovered
from safesc.tools.index.core.normalizer import parse_lockfiles, to_json


def _discovered_to_dict(f: DiscoveredFile, root: Path) -> dict:
    """JSON-friendly view of a :class:`DiscoveredFile`."""
    return {
        "path": str(f.path),
        "relative_path": str(f.path.relative_to(root)),
        "ecosystem": f.ecosystem,
        "matched_glob": f.matched_glob,
    }


def cmd_discover(root: Path, *, as_json: bool = False) -> int:
    """Stage 0 — discover dependency lockfiles under *root*."""
    root = root.resolve()
    try:
        files = discover(root)
    except NotADirectoryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if as_json:
        print(json.dumps([_discovered_to_dict(f, root) for f in files], indent=2))
    else:
        print_discovered(files, root)
    return 0


def cmd_parse(root: Path) -> int:
    """Stage 1 — parse discovered lockfiles into a normalised dependency array."""
    try:
        files = discover(root)
    except NotADirectoryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    deps = parse_lockfiles(files)
    print(to_json(deps))
    return 0
