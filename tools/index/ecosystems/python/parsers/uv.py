"""Parse uv.lock (TOML, uv >=0.1)."""

from __future__ import annotations

import tomllib
from collections import deque
from pathlib import Path

from tools.index.core.models import Dependency


def parse(path: Path) -> list[Dependency]:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return []

    packages: list[dict] = data.get("package", [])
    pkg_map: dict[str, dict] = {p["name"]: p for p in packages}

    # Root has source.virtual or source.editable pointing to "."
    root = next(
        (p for p in packages
         if isinstance(p.get("source"), dict)
         and ("virtual" in p["source"] or "editable" in p["source"])),
        None,
    )

    direct_names: set[str] = set()
    if root:
        for dep in root.get("dependencies", []):
            if isinstance(dep, dict):
                direct_names.add(dep.get("name", "").lower())

    # BFS to compute layer and parent
    layer_map: dict[str, int] = {}
    parent_map: dict[str, str | None] = {}
    queue: deque[str] = deque()
    visited: set[str] = set()

    for name in direct_names:
        layer_map[name] = 1
        parent_map[name] = None
        queue.append(name)
        visited.add(name)

    while queue:
        current = queue.popleft()
        pkg = pkg_map.get(current, {})
        for dep in pkg.get("dependencies", []):
            if not isinstance(dep, dict):
                continue
            n = dep.get("name", "").lower()
            if n and n not in visited:
                visited.add(n)
                layer_map[n] = layer_map.get(current, 1) + 1
                parent_map[n] = current
                queue.append(n)

    result: list[Dependency] = []
    for pkg in packages:
        if pkg is root:
            continue
        name = pkg["name"].lower()
        version = pkg.get("version", "")

        hash_val = url = None
        wheels = pkg.get("wheels", [])
        sdist = pkg.get("sdist")
        if wheels and isinstance(wheels, list) and isinstance(wheels[0], dict):
            hash_val = wheels[0].get("hash")
            url = wheels[0].get("url")
        elif isinstance(sdist, dict):
            hash_val = sdist.get("hash")
            url = sdist.get("url")

        result.append(Dependency(
            name=name,
            version=version,
            ecosystem="python",
            lockfile_path=path,
            hash=hash_val,
            source_url=url,
            is_direct=name in direct_names,
            layer_number=layer_map.get(name),
            parent_name=parent_map.get(name),
        ))

    return result
