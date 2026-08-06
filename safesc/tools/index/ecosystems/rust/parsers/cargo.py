"""Parse Cargo.lock (TOML v1/v2/v3)."""

from __future__ import annotations

import tomllib
from collections import deque
from pathlib import Path

from safesc.tools.index.core.models import Dependency
from safesc.tools.index.core.text_io import read_text
from safesc.tools.index.core.url_classify import normalise_vcs_url

_CRATES_URL = "https://static.crates.io/crates/{name}/{name}-{version}.crate"


def parse(path: Path) -> list[Dependency]:
    try:
        # BOM-aware decode + tomllib.loads so a UTF-16 Cargo.lock is not silently empty.
        data = tomllib.loads(read_text(path))
    except Exception:
        return []

    packages: list[dict] = data.get("package", [])
    if not packages:
        return []

    pkg_map: dict[tuple[str, str], dict] = {
        (p["name"], p["version"]): p for p in packages
    }

    # Workspace members have no "source" field
    roots = [p for p in packages if "source" not in p]

    direct_keys: set[tuple[str, str]] = set()
    for root in roots:
        for dep_str in root.get("dependencies", []):
            parts = dep_str.split()
            if len(parts) >= 2:
                direct_keys.add((parts[0], parts[1]))

    layer_map: dict[tuple[str, str], int] = {}
    parent_map: dict[tuple[str, str], str | None] = {}
    queue: deque[tuple[str, str]] = deque()
    visited: set[tuple[str, str]] = set()

    for key in direct_keys:
        if key in pkg_map:
            layer_map[key] = 1
            parent_map[key] = None
            queue.append(key)
            visited.add(key)

    while queue:
        current = queue.popleft()
        for dep_str in pkg_map.get(current, {}).get("dependencies", []):
            parts = dep_str.split()
            if len(parts) >= 2:
                dep_key = (parts[0], parts[1])
                if dep_key not in visited and dep_key in pkg_map:
                    visited.add(dep_key)
                    layer_map[dep_key] = layer_map.get(current, 1) + 1
                    parent_map[dep_key] = current[0]
                    queue.append(dep_key)

    result: list[Dependency] = []
    for pkg in packages:
        if "source" not in pkg:
            continue  # workspace root, not an external dep
        name = pkg["name"]
        version = pkg["version"]
        checksum = pkg.get("checksum")
        key = (name, version)

        # The crates.io URL is the artifact (.crate) download, not a clonable repo.
        # A git-sourced crate carries a real repo URL in its `source` field instead.
        source_val = pkg.get("source", "")
        artifact_url = source_url = None
        if "registry" in source_val:
            artifact_url = _CRATES_URL.format(name=name, version=version)
        elif isinstance(source_val, str) and source_val.startswith(("git+", "git:")):
            source_url = normalise_vcs_url(source_val)

        result.append(Dependency(
            name=name,
            version=version,
            ecosystem="rust",
            lockfile_path=path,
            hash=f"sha256:{checksum}" if checksum else None,
            source_url=source_url,
            artifact_url=artifact_url,
            is_direct=key in direct_keys,
            layer_number=layer_map.get(key),
            parent_name=parent_map.get(key),
        ))
    return result
