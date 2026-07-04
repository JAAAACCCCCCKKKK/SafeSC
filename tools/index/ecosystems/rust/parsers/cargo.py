"""Parse Cargo.lock (TOML v1/v2/v3)."""

from __future__ import annotations

import tomllib
from collections import deque
from pathlib import Path

from tools.index.core.models import Dependency

_CRATES_URL = "https://static.crates.io/crates/{name}/{name}-{version}.crate"


def parse(path: Path) -> list[Dependency]:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
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

        source_url = None
        if "registry" in pkg.get("source", ""):
            source_url = _CRATES_URL.format(name=name, version=version)

        result.append(Dependency(
            name=name,
            version=version,
            ecosystem="rust",
            lockfile_path=path,
            hash=f"sha256:{checksum}" if checksum else None,
            source_url=source_url,
            is_direct=key in direct_keys,
            layer_number=layer_map.get(key),
            parent_name=parent_map.get(key),
        ))
    return result
