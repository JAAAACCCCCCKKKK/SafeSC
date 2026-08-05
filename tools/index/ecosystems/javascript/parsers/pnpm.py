"""Parse pnpm-lock.yaml (pnpm v6–v9)."""

from __future__ import annotations

from pathlib import Path

from tools.index.core.models import Dependency
from tools.index.core.text_io import read_text
from tools.index.core.url_classify import split_source_artifact


def parse(path: Path) -> list[Dependency]:
    try:
        import yaml  # type: ignore[import-untyped]
        data = yaml.safe_load(read_text(path))
    except Exception:
        return []

    if not isinstance(data, dict):
        return []

    version_raw = str(data.get("lockfileVersion", "5")).strip("'\"")
    try:
        version_major = int(version_raw.split(".")[0])
    except ValueError:
        version_major = 5

    direct_names: set[str] = set()
    if version_major >= 9:
        for importer_key in (".", ""):
            importer = data.get("importers", {}).get(importer_key, {})
            if importer:
                for section in ("dependencies", "devDependencies", "optionalDependencies"):
                    direct_names.update(importer.get(section, {}).keys())
                break
    else:
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            direct_names.update(data.get(section, {}).keys())

    result: list[Dependency] = []
    for pkg_key, pkg_data in data.get("packages", {}).items():
        if not isinstance(pkg_data, dict):
            continue
        clean = pkg_key.lstrip("/")
        if not clean:
            continue

        if clean.startswith("@"):
            inner = clean[1:]
            at_idx = inner.find("@")
            if at_idx < 0:
                continue
            name = "@" + inner[:at_idx]
            version = inner[at_idx + 1:].split("(")[0]
        else:
            at_idx = clean.rfind("@")
            if at_idx <= 0:
                continue
            name = clean[:at_idx]
            version = clean[at_idx + 1:].split("(")[0]

        resolution = pkg_data.get("resolution", {})
        integrity = resolution.get("integrity") if isinstance(resolution, dict) else None
        tarball = resolution.get("tarball") if isinstance(resolution, dict) else None

        source_url, artifact_url = split_source_artifact(tarball)
        result.append(Dependency(
            name=name,
            version=version,
            ecosystem="javascript",
            lockfile_path=path,
            hash=integrity,
            source_url=source_url,
            artifact_url=artifact_url,
            is_direct=name in direct_names,
            layer_number=1 if name in direct_names else None,
            parent_name=None,
        ))
    return result
