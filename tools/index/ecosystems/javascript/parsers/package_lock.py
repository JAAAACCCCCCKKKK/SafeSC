"""Parse package-lock.json / npm-shrinkwrap.json (npm v1/v2/v3)."""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path

from tools.index.core.models import Dependency


def _package_json_direct(directory: Path) -> set[str]:
    pkg = directory / "package.json"
    if not pkg.exists():
        return set()
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    direct: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        direct.update(data.get(key, {}).keys())
    return direct


def _strip_nm(key: str) -> str:
    prefix = "node_modules/"
    return key[len(prefix):] if key.startswith(prefix) else key


def _parse_v2_v3(packages: dict, path: Path) -> list[Dependency]:
    root = packages.get("", {})
    direct_names: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        direct_names.update(root.get(key, {}).keys())

    flat: dict[str, dict] = {}
    for key, data in packages.items():
        if not key or key.count("node_modules/") > 1:
            continue
        flat[_strip_nm(key)] = data

    layer_map: dict[str, int] = {}
    parent_map: dict[str, str | None] = {}
    queue: deque[str] = deque()
    visited: set[str] = set()
    for name in direct_names:
        if name in flat:
            layer_map[name] = 1
            parent_map[name] = None
            queue.append(name)
            visited.add(name)
    while queue:
        current = queue.popleft()
        for dep_name in flat.get(current, {}).get("dependencies", {}).keys():
            if dep_name not in visited and dep_name in flat:
                visited.add(dep_name)
                layer_map[dep_name] = layer_map.get(current, 1) + 1
                parent_map[dep_name] = current
                queue.append(dep_name)

    result: list[Dependency] = []
    for key, data in packages.items():
        if not key or key.count("node_modules/") > 1:
            continue
        name = _strip_nm(key)
        result.append(Dependency(
            name=name,
            version=data.get("version", ""),
            ecosystem="javascript",
            lockfile_path=path,
            hash=data.get("integrity"),
            source_url=data.get("resolved"),
            is_direct=name in direct_names,
            layer_number=layer_map.get(name),
            parent_name=parent_map.get(name),
        ))
    return result


def _parse_v1(deps: dict, path: Path, direct_names: set[str],
              parent: str | None = None, layer: int = 1) -> list[Dependency]:
    result: list[Dependency] = []
    for name, data in deps.items():
        if not isinstance(data, dict):
            continue
        result.append(Dependency(
            name=name,
            version=data.get("version", ""),
            ecosystem="javascript",
            lockfile_path=path,
            hash=data.get("integrity"),
            source_url=data.get("resolved"),
            is_direct=name in direct_names,
            layer_number=layer,
            parent_name=parent,
        ))
        nested = data.get("dependencies", {})
        if nested:
            result.extend(_parse_v1(nested, path, direct_names, parent=name, layer=layer + 1))
    return result


def parse(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    if data.get("lockfileVersion", 1) >= 2:
        return _parse_v2_v3(data.get("packages", {}), path)
    direct_names = _package_json_direct(path.parent)
    return _parse_v1(data.get("dependencies", {}), path, direct_names)
