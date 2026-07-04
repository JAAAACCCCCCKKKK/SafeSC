"""Ecosystem adapter plug-ins.

Besides hosting the per-ecosystem adapters, this package exposes a single
filename-based :func:`parse` dispatch helper.  Given any lockfile path it selects
the owning adapter (by :meth:`EcosystemAdapter.is_lockfile`) and returns the
normalised dependencies, or an empty list when no adapter claims the file.
"""

from __future__ import annotations

from pathlib import Path

from tools.index.core.models import Dependency
from tools.index.ecosystems.base import EcosystemAdapter
from tools.index.ecosystems.go.adapter import GoAdapter
from tools.index.ecosystems.java.adapter import JavaAdapter
from tools.index.ecosystems.javascript.adapter import JavaScriptAdapter
from tools.index.ecosystems.python.adapter import PythonAdapter
from tools.index.ecosystems.rust.adapter import RustAdapter

_DEFAULT_ADAPTERS: list[EcosystemAdapter] = [
    PythonAdapter(),
    JavaScriptAdapter(),
    RustAdapter(),
    GoAdapter(),
    JavaAdapter(),
]


def parse(path: Path) -> list[Dependency]:
    """Parse *path* with the first adapter that recognises it.

    Returns an empty list when no adapter owns the file (adapters themselves
    never raise for unparseable content).
    """
    path = Path(path)
    for adapter in _DEFAULT_ADAPTERS:
        if adapter.is_lockfile(path):
            return adapter.parse_lockfile(path)
    return []


__all__ = ["EcosystemAdapter", "parse"]
