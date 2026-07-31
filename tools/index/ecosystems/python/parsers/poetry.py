"""Parse poetry.lock (TOML)."""

from __future__ import annotations

import tomllib
from collections import deque
from pathlib import Path

from tools.index.core.models import Dependency
from tools.index.core.text_io import read_text


def _direct_from_pyproject(lockfile_dir: Path) -> set[str]:
    pyproject = lockfile_dir / "pyproject.toml"
    if not pyproject.exists():
        return set()
    try:
        data = tomllib.loads(read_text(pyproject))
    except Exception:
        return set()

    direct: set[str] = set()
    poetry = data.get("tool", {}).get("poetry", {})
    for section in ("dependencies", "dev-dependencies"):
        for name in poetry.get(section, {}):
            if name.lower() != "python":
                direct.add(name.lower())
    for group_data in poetry.get("group", {}).values():
        for name in group_data.get("dependencies", {}):
            if name.lower() != "python":
                direct.add(name.lower())
    for dep_str in data.get("project", {}).get("dependencies", []):
        name = dep_str.split("[")[0]
        for op in (">=", "==", "!=", "<=", ">", "<", "~=", "@"):
            name = name.split(op)[0]
        direct.add(name.strip().lower())
    return direct


def parse(path: Path) -> list[Dependency]:
    try:
        data = tomllib.loads(read_text(path))
    except Exception:
        return []

    packages: list[dict] = data.get("package", [])
    direct_names = _direct_from_pyproject(path.parent)
    pkg_map: dict[str, dict] = {p["name"].lower(): p for p in packages}

    deps_of: dict[str, list[str]] = {}
    for pkg in packages:
        name = pkg["name"].lower()
        raw_deps = pkg.get("dependencies", {})
        dep_names = []
        if isinstance(raw_deps, dict):
            for dep_name in raw_deps:
                if dep_name.lower() != "python":
                    dep_names.append(dep_name.lower())
        deps_of[name] = dep_names

    layer_map: dict[str, int] = {}
    parent_map: dict[str, str | None] = {}
    queue: deque[str] = deque()
    visited: set[str] = set()

    for name in direct_names:
        if name in pkg_map:
            layer_map[name] = 1
            parent_map[name] = None
            queue.append(name)
            visited.add(name)

    while queue:
        current = queue.popleft()
        for dep_name in deps_of.get(current, []):
            if dep_name not in visited:
                visited.add(dep_name)
                layer_map[dep_name] = layer_map.get(current, 1) + 1
                parent_map[dep_name] = current
                queue.append(dep_name)

    result: list[Dependency] = []
    for pkg in packages:
        name = pkg["name"].lower()
        version = pkg.get("version", "")
        hash_val = None
        files = pkg.get("files", [])
        if files and isinstance(files[0], dict):
            hash_val = files[0].get("hash")
        result.append(Dependency(
            name=name,
            version=version,
            ecosystem="python",
            lockfile_path=path,
            hash=hash_val,
            source_url=None,
            is_direct=name in direct_names,
            layer_number=layer_map.get(name),
            parent_name=parent_map.get(name),
        ))
    return result
