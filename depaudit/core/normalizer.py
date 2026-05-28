"""Stage 1 — orchestrate lockfile parsing and produce a normalised dependency list."""

from __future__ import annotations

import json
from typing import Sequence

from depaudit.core.discovery import DiscoveredFile
from depaudit.core.models import Dependency
from depaudit.ecosystems.base import EcosystemAdapter
from depaudit.ecosystems.python.adapter import PythonAdapter
from depaudit.ecosystems.javascript.adapter import JavaScriptAdapter
from depaudit.ecosystems.rust.adapter import RustAdapter
from depaudit.ecosystems.go.adapter import GoAdapter
from depaudit.ecosystems.java.adapter import JavaAdapter

_DEFAULT_ADAPTERS: list[EcosystemAdapter] = [
    PythonAdapter(),
    JavaScriptAdapter(),
    RustAdapter(),
    GoAdapter(),
    JavaAdapter(),
]


def parse_lockfiles(
    discovered: Sequence[DiscoveredFile],
    *,
    extra_adapters: Sequence[EcosystemAdapter] = (),
) -> list[Dependency]:
    """Parse every discovered lockfile and return a flat, normalised dependency list.

    A second pass fills ``parent_url`` for any dependency whose parent''s
    ``source_url`` is known within the same run.
    """
    adapters = _DEFAULT_ADAPTERS + list(extra_adapters)
    adapter_by_name: dict[str, EcosystemAdapter] = {a.name: a for a in adapters}

    all_deps: list[Dependency] = []
    for f in discovered:
        adapter = adapter_by_name.get(f.ecosystem)
        if adapter is None:
            continue
        try:
            deps = adapter.parse_lockfile(f.path)
        except Exception:
            deps = []
        all_deps.extend(deps)

    # Second pass: fill parent_url where the parent''s source_url is known.
    url_by_pkg: dict[tuple[str, str], str] = {}
    for dep in all_deps:
        if dep.source_url:
            url_by_pkg.setdefault((dep.ecosystem, dep.name), dep.source_url)

    for dep in all_deps:
        if dep.parent_name and dep.parent_url is None:
            dep.parent_url = url_by_pkg.get((dep.ecosystem, dep.parent_name))

    return all_deps


def to_json(deps: list[Dependency], *, indent: int = 2) -> str:
    return json.dumps([d.to_dict() for d in deps], indent=indent, default=str)
