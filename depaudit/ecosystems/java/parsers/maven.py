"""Parse pom.xml (Maven)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from depaudit.core.models import Dependency

_MVN_CENTRAL = (
    "https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}"
    "/{artifact}-{version}.jar"
)
_NS_RE = re.compile(r"\{[^}]+\}")


def _strip_ns(tag: str) -> str:
    return _NS_RE.sub("", tag)


def parse(path: Path) -> list[Dependency]:
    try:
        tree = ET.parse(path)
    except (OSError, ET.ParseError):
        return []

    root = tree.getroot()

    props: dict[str, str] = {}
    for el in root.iter():
        if _strip_ns(el.tag) == "properties":
            for prop in el:
                props[_strip_ns(prop.tag)] = (prop.text or "").strip()

    def resolve(value: str) -> str:
        if value.startswith("${") and value.endswith("}"):
            return props.get(value[2:-1], value)
        return value

    result: list[Dependency] = []
    for dep_el in root.iter():
        if _strip_ns(dep_el.tag) != "dependency":
            continue
        children = {_strip_ns(c.tag): (c.text or "").strip() for c in dep_el}
        group_id = resolve(children.get("groupId", ""))
        artifact_id = resolve(children.get("artifactId", ""))
        version = resolve(children.get("version", ""))
        scope = children.get("scope", "compile")

        if not group_id or not artifact_id:
            continue

        source_url = None
        if version and scope not in ("system", "provided"):
            group_path = group_id.replace(".", "/")
            source_url = _MVN_CENTRAL.format(
                group_path=group_path,
                artifact=artifact_id,
                version=version,
            )

        result.append(Dependency(
            name=f"{group_id}:{artifact_id}",
            version=version,
            ecosystem="java",
            lockfile_path=path,
            hash=None,
            source_url=source_url,
            is_direct=True,
            layer_number=1,
            parent_name=None,
            extras=[scope] if scope and scope != "compile" else [],
        ))
    return result
