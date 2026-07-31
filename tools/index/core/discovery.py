"""Stage 0 — Dependency-file Discovery.

Walks a repository root, asks each registered :class:`EcosystemAdapter` which
glob patterns it owns, and collects every matching path.  At this stage the
results are printed to stdout; later stages will consume the returned list.

Usage (programmatic)::

    from tools.index.core.discovery import discover
    from pathlib import Path

    found = discover(Path("/path/to/repo"))
    # found -> [DiscoveredFile(path=..., ecosystem="python"), ...]

Usage (CLI)::

    python -m tools.index.core.discovery /path/to/repo
"""

from __future__ import annotations

import fnmatch
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from tools.index.ecosystems.base import EcosystemAdapter

# ── Default adapter registry ──────────────────────────────────────────────────
# Import here so that the registry is populated by default.  Additional
# adapters can be injected at call time via the `extra_adapters` parameter.

from tools.index.ecosystems.python.adapter import PythonAdapter
from tools.index.ecosystems.javascript.adapter import JavaScriptAdapter
from tools.index.ecosystems.rust.adapter import RustAdapter
from tools.index.ecosystems.go.adapter import GoAdapter
from tools.index.ecosystems.java.adapter import JavaAdapter

_DEFAULT_ADAPTERS: list[EcosystemAdapter] = [
    PythonAdapter(),
    JavaScriptAdapter(),
    RustAdapter(),
    GoAdapter(),
    JavaAdapter(),
]

# Directories that are never interesting and slow down the walk considerably.
_PRUNE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        "target",          # Rust / Java build output
        ".gradle",
    }
)


# ── Result type ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, order=True)
class DiscoveredFile:
    """A single dependency file found on disk."""

    path: Path
    """Absolute path to the discovered file."""

    ecosystem: str
    """Name of the ecosystem adapter that claimed this file."""

    matched_glob: str
    """The glob pattern that triggered the match."""


# ── Core logic ────────────────────────────────────────────────────────────────


def _build_pattern_map(
    adapters: list[EcosystemAdapter],
) -> list[tuple[str, str, EcosystemAdapter]]:
    """Return a flat list of ``(glob, ecosystem_name, adapter)`` triples."""
    rows: list[tuple[str, str, EcosystemAdapter]] = []
    for adapter in adapters:
        for glob in adapter.lockfile_globs:
            rows.append((glob, adapter.name, adapter))
    return rows


def _matches_any(filename: str, pattern_map: list[tuple[str, str, EcosystemAdapter]]):
    """Yield ``(glob, ecosystem_name)`` for every pattern that matches *filename*.

    Matching is **case-insensitive on every OS**. ``fnmatch.fnmatch`` delegates case
    handling to ``os.path.normcase``, which folds case on Windows but is case-SENSITIVE on
    Linux/macOS — so a repo containing ``Requirements.txt`` or ``Pipfile.LOCK`` would be
    silently missed on a Linux CI runner while passing on a Windows dev box. Lower-casing
    both sides with ``fnmatchcase`` makes discovery deterministic across platforms.
    """
    fname_lc = filename.lower()
    for glob, ecosystem_name, _adapter in pattern_map:
        # fnmatch only compares the bare filename; path separators don't matter.
        if fnmatch.fnmatchcase(fname_lc, glob.lower()):
            yield glob, ecosystem_name


def discover(
    root: Path,
    *,
    extra_adapters: Sequence[EcosystemAdapter] = (),
    prune_dirs: frozenset[str] = _PRUNE_DIRS,
) -> list[DiscoveredFile]:
    """Walk *root* and return every dependency file found.

    Parameters
    ----------
    root:
        Repository root to scan.  Must be an existing directory.
    extra_adapters:
        Additional ecosystem adapters to consider beyond the built-in set.
        Useful for testing or for ecosystems not yet included by default.
    prune_dirs:
        Directory names that are skipped entirely during the walk.

    Returns
    -------
    list[DiscoveredFile]
        Sorted list (by path) of all discovered dependency files.

    Raises
    ------
    NotADirectoryError
        If *root* does not exist or is not a directory.
    """
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Repository root does not exist or is not a directory: {root}")

    adapters = _DEFAULT_ADAPTERS + list(extra_adapters)
    pattern_map = _build_pattern_map(adapters)

    found: list[DiscoveredFile] = []

    for dirpath, dirnames, filenames in root.walk():
        # Prune unwanted directories in-place so os.walk doesn't descend.
        dirnames[:] = [d for d in dirnames if d not in prune_dirs]

        for filename in filenames:
            for glob, ecosystem_name in _matches_any(filename, pattern_map):
                found.append(
                    DiscoveredFile(
                        path=dirpath / filename,
                        ecosystem=ecosystem_name,
                        matched_glob=glob,
                    )
                )
                # A single file may only be claimed by the first matching
                # adapter to avoid duplicates in the result list.
                break

    return sorted(found)


# ── Pretty printer ────────────────────────────────────────────────────────────


def print_discovered(files: list[DiscoveredFile], root: Path) -> None:
    """Print *files* to stdout in a human-readable format."""
    if not files:
        print("No dependency files found.")
        return

    # Group by ecosystem for a cleaner display.
    by_ecosystem: dict[str, list[DiscoveredFile]] = {}
    for f in files:
        by_ecosystem.setdefault(f.ecosystem, []).append(f)

    total = len(files)
    print(f"Found {total} dependency file{'s' if total != 1 else ''}:\n")

    for ecosystem, items in sorted(by_ecosystem.items()):
        print(f"  [{ecosystem}]")
        for item in items:
            rel = item.path.relative_to(root)
            print(f"    {rel}  (matched: {item.matched_glob})")
        print()


# ── CLI entry-point ───────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """Minimal CLI: ``python -m tools.index.core.discovery [<path>]``."""
    args = argv if argv is not None else sys.argv[1:]
    root = Path(args[0]) if args else Path.cwd()

    root = root.resolve()
    try:
        files = discover(root)
    except NotADirectoryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_discovered(files, root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
