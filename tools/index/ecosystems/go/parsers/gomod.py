"""Parse go.mod (and companion go.sum for hashes)."""

from __future__ import annotations

import re
from pathlib import Path

from tools.index.core.models import Dependency
from tools.index.core.text_io import read_text

_DEP_LINE_RE = re.compile(r"^\s+(\S+)\s+(\S+)(.*)")


def _load_gosum(gosum: Path) -> dict[tuple[str, str], str]:
    hashes: dict[tuple[str, str], str] = {}
    if not gosum.exists():
        return hashes
    try:
        for line in read_text(gosum).splitlines():
            parts = line.strip().split()
            if len(parts) != 3:
                continue
            module, version_tag, hash_val = parts
            if "/go.mod" not in version_tag and hash_val.startswith("h1:"):
                hashes[(module, version_tag)] = hash_val
    except OSError:
        pass
    return hashes


def _parse_gomod(path: Path) -> list[Dependency]:
    try:
        text = read_text(path)
    except OSError:
        return []

    gosum = _load_gosum(path.parent / "go.sum")
    deps: list[tuple[str, str, bool]] = []
    seen: set[tuple[str, str]] = set()

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped == "require (" or stripped.startswith("require ("):
            i += 1
            while i < len(lines) and lines[i].strip() != ")":
                m = _DEP_LINE_RE.match(lines[i])
                if m:
                    module, version, rest = m.group(1), m.group(2), m.group(3)
                    if not module.startswith("//"):
                        key = (module, version)
                        if key not in seen:
                            seen.add(key)
                            deps.append((module, version, "// indirect" not in rest))
                i += 1
        elif re.match(r"^require\s+\S+\s+\S+", stripped):
            parts = stripped.split()
            module, version = parts[1], parts[2]
            key = (module, version)
            if key not in seen:
                seen.add(key)
                deps.append((module, version, True))
        i += 1

    result: list[Dependency] = []
    for module, version, is_direct in deps:
        result.append(Dependency(
            name=module,
            version=version,
            ecosystem="go",
            lockfile_path=path,
            hash=gosum.get((module, version)),
            source_url=f"https://proxy.golang.org/{module}/@v/{version}.zip",
            is_direct=is_direct,
            layer_number=1 if is_direct else 2,
            parent_name=None,
        ))
    return result

def _parse_gosum_standalone(path: Path) -> list[Dependency]:
    result: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    try:
        for line in read_text(path).splitlines():
            parts = line.strip().split()
            if len(parts) != 3:
                continue
            module, version_tag, hash_val = parts
            if "/go.mod" in version_tag:
                continue
            key = (module, version_tag)
            if key not in seen:
                seen.add(key)
                result.append(Dependency(
                    name=module,
                    version=version_tag,
                    ecosystem="go",
                    lockfile_path=path,
                    hash=hash_val,
                    source_url=f"https://proxy.golang.org/{module}/@v/{version_tag}.zip",
                    is_direct=False,
                    layer_number=2,
                    parent_name=None,
                ))
    except OSError:
        pass
    return result


def parse(path: Path) -> list[Dependency]:
    if path.name == "go.sum":
        # Defer to go.mod if present in the same directory (avoids duplicates).
        if (path.parent / "go.mod").exists():
            return []
        return _parse_gosum_standalone(path)
    return _parse_gomod(path)
