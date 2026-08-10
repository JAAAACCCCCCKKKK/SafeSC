"""Stage 0 — Dependency-file Discovery.

Walks a repository root, asks each registered :class:`EcosystemAdapter` which
glob patterns it owns, and collects every matching path.  At this stage the
results are printed to stdout; later stages will consume the returned list.

Usage (programmatic)::

    from safesc.tools.index.core.discovery import discover
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

import pathspec

from safesc.tools.index.ecosystems.base import EcosystemAdapter

# Gitignore-style ignore file auto-discovered at the SCANNED ROOT (not the SafeSC
# install) — lets a consumer repo permanently exclude paths (e.g. test fixtures that
# deliberately look like real dependency files) from every SafeSC entrypoint
# (`index`, `scan`, `safesc audit`/`query`) with zero flags, since they all funnel
# through this one `discover()`. Real-world incident that motivated this: SafeSC's own
# self-audit workflow scans "." and was tripped up by its own synthetic attack-pattern
# test fixtures under tests/fixtures/ — see CLAUDE.md.
DEFAULT_IGNORE_FILENAME = ".safescignore"

# ── Default adapter registry ──────────────────────────────────────────────────
# Import here so that the registry is populated by default.  Additional
# adapters can be injected at call time via the `extra_adapters` parameter.

from safesc.tools.index.ecosystems.python.adapter import PythonAdapter
from safesc.tools.index.ecosystems.javascript.adapter import JavaScriptAdapter
from safesc.tools.index.ecosystems.rust.adapter import RustAdapter
from safesc.tools.index.ecosystems.go.adapter import GoAdapter
from safesc.tools.index.ecosystems.java.adapter import JavaAdapter

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


def _load_ignore_patterns(root: Path, ignore_filename: str) -> list[str]:
    """Gitignore-syntax lines from ``root / ignore_filename``, or `[]` if absent/unreadable.
    `pathspec` itself handles comments (`#`) and blank lines per the gitignore spec, so raw
    lines are passed through unmodified."""
    ignore_path = root / ignore_filename
    if not ignore_path.is_file():
        return []
    try:
        return ignore_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _build_exclude_spec(
    root: Path, exclude: Sequence[str], ignore_filename: str
) -> "pathspec.PathSpec | None":
    """Combine the auto-discovered ignore file with any caller-supplied patterns
    (CLI-level overrides layer on top of, never replace, a committed ignore file)."""
    patterns = [*_load_ignore_patterns(root, ignore_filename), *exclude]
    if not patterns:
        return None
    return pathspec.PathSpec.from_lines("gitignore", patterns)


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
    exclude: Sequence[str] = (),
    ignore_filename: str = DEFAULT_IGNORE_FILENAME,
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
        Directory names (by bare name, anywhere in the tree) that are skipped
        entirely during the walk — generic build/VCS/cache junk (``node_modules``,
        ``.git``, ``dist``, ...), the same everywhere and not user-configurable.
    exclude:
        Gitignore-syntax patterns (matched against the path relative to *root*,
        POSIX-separated) to additionally exclude, layered on top of any patterns
        found in ``root / ignore_filename``. This is the caller-supplied override
        (e.g. a CLI ``--exclude`` flag); it augments rather than replaces a
        committed ignore file.
    ignore_filename:
        Name of the gitignore-syntax file auto-discovered at *root*, if present.
        Defaults to ``.safescignore`` — lets a repo permanently exclude paths
        (e.g. test fixtures that deliberately look like real dependency files)
        from every SafeSC entrypoint with zero flags, since discovery is the one
        chokepoint every entrypoint (``index``, ``scan``, ``safesc audit``/``query``)
        funnels through.

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
    spec = _build_exclude_spec(root, exclude, ignore_filename)

    found: list[DiscoveredFile] = []

    for dirpath, dirnames, filenames in root.walk():
        # Prune unwanted directories in-place so os.walk doesn't descend.
        dirnames[:] = [d for d in dirnames if d not in prune_dirs]

        if spec is not None:
            # Prune whole subtrees the ignore spec matches (mirrors gitignore's own
            # directory pruning) instead of only filtering individual files, so a
            # pattern like `tests/fixtures/**` also skips walking into that subtree.
            kept: list[str] = []
            for d in dirnames:
                rel_dir = (dirpath / d).relative_to(root).as_posix() + "/"
                if not spec.match_file(rel_dir):
                    kept.append(d)
            dirnames[:] = kept

        for filename in filenames:
            if spec is not None:
                rel_file = (dirpath / filename).relative_to(root).as_posix()
                if spec.match_file(rel_file):
                    continue
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
