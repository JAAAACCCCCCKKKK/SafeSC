"""Parse gradle.lockfile / buildscript-gradle.lockfile (Gradle dependency locking)."""

from __future__ import annotations

from pathlib import Path

from tools.index.core.models import Dependency
from tools.index.core.text_io import read_text

_MVN_CENTRAL = (
    "https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}"
    "/{artifact}-{version}.jar"
)


def parse(path: Path) -> list[Dependency]:
    if path.name not in ("gradle.lockfile", "buildscript-gradle.lockfile"):
        return []
    try:
        text = read_text(path)
    except OSError:
        return []

    result: list[Dependency] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line == "empty=":
            continue
        eq_idx = line.rfind("=")
        if eq_idx < 0:
            continue
        coord = line[:eq_idx]
        parts = coord.split(":")
        if len(parts) != 3:
            continue
        group_id, artifact_id, version = parts
        if coord in seen:
            continue
        seen.add(coord)
        group_path = group_id.replace(".", "/")
        result.append(Dependency(
            name=f"{group_id}:{artifact_id}",
            version=version,
            ecosystem="java",
            lockfile_path=path,
            hash=None,
            # Maven Central .jar is an artifact download, not a source repo.
            artifact_url=_MVN_CENTRAL.format(
                group_path=group_path, artifact=artifact_id, version=version
            ),
            is_direct=False,
            layer_number=None,
            parent_name=None,
        ))
    return result
