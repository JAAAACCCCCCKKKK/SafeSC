"""Parse requirements*.txt (pip format)."""

from __future__ import annotations

import re
from pathlib import Path

from tools.index.core.models import Dependency

_NAME_VERSION_RE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[([^\]]+)\])?"
    r"\s*===?\s*([^\s;\\#]+)"
)
_HASH_RE = re.compile(r"--hash=([^:\s]+:[A-Fa-f0-9]+)")


def parse(path: Path) -> list[Dependency]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    lines: list[str] = []
    pending = ""
    for line in raw.splitlines():
        if line.endswith("\\"):
            pending += line[:-1] + " "
        else:
            pending += line
            lines.append(pending)
            pending = ""
    if pending:
        lines.append(pending)

    result: list[Dependency] = []
    for line in lines:
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _NAME_VERSION_RE.match(line)
        if not m:
            continue
        name = m.group(1).lower()
        extras_raw = m.group(2)
        version = m.group(3)
        extras = [e.strip() for e in extras_raw.split(",")] if extras_raw else []
        hashes = _HASH_RE.findall(line)
        result.append(Dependency(
            name=name,
            version=version,
            ecosystem="python",
            lockfile_path=path,
            hash=hashes[0] if hashes else None,
            source_url=None,
            is_direct=True,
            layer_number=1,
            parent_name=None,
            extras=extras,
        ))
    return result
