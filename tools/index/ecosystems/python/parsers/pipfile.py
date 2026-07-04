"""Parse Pipfile.lock (JSON)."""

from __future__ import annotations

import json
from pathlib import Path

from tools.index.core.models import Dependency


def parse(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    result: list[Dependency] = []
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            if not isinstance(info, dict):
                continue
            version = info.get("version", "").lstrip("=")
            hashes = info.get("hashes", [])
            result.append(Dependency(
                name=name.lower(),
                version=version,
                ecosystem="python",
                lockfile_path=path,
                hash=hashes[0] if hashes else None,
                source_url=None,
                is_direct=True,
                layer_number=1,
                parent_name=None,
            ))
    return result
