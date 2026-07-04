"""Parse yarn.lock v1 (classic Yarn)."""

from __future__ import annotations

import json
import re
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


def parse(path: Path) -> list[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # Yarn Berry (v2+) uses a different format; skip it.
    if "__metadata:" in text:
        return []

    direct_names = _package_json_direct(path.parent)
    result: list[Dependency] = []
    lines = text.splitlines()
    i, n = 0, len(lines)

    while i < n:
        line = lines[i]
        if not line.strip() or line.startswith("#"):
            i += 1
            continue

        # Block header: no leading whitespace, ends with ":"
        if not line[0].isspace() and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1]
            raw_entries = [e.strip().strip('"') for e in header.split(",")]
            pkg_names: set[str] = set()
            for entry in raw_entries:
                # Scoped: "@scope/name@range" — skip leading "@"
                if entry.startswith("@"):
                    idx = entry.find("@", 1)
                else:
                    idx = entry.find("@")
                if idx > 0:
                    pkg_names.add(entry[:idx])

            version = integrity = resolved = None
            i += 1
            while i < n and (not lines[i] or lines[i][0].isspace()):
                body = lines[i].strip()
                if body.startswith("version "):
                    m = re.search(r'"([^"]+)"', body)
                    version = m.group(1) if m else body.split()[-1].strip('"')
                elif body.startswith("resolved "):
                    m = re.search(r'"([^"]+)"', body)
                    resolved = m.group(1) if m else body.split()[-1].strip('"')
                    if resolved and "#" in resolved:
                        resolved = resolved.split("#")[0]
                elif body.startswith("integrity "):
                    integrity = body.split()[-1]
                i += 1

            if version:
                for name in pkg_names:
                    result.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem="javascript",
                        lockfile_path=path,
                        hash=integrity,
                        source_url=resolved,
                        is_direct=name in direct_names,
                        layer_number=1 if name in direct_names else None,
                        parent_name=None,
                    ))
        else:
            i += 1

    return result
