"""Go ecosystem adapter — lockfile discovery patterns."""

from __future__ import annotations

from pathlib import Path

from tools.index.core.models import Dependency
from tools.index.ecosystems.base import EcosystemAdapter


class GoAdapter(EcosystemAdapter):
    """Adapter for Go dependency files (go modules)."""

    @property
    def name(self) -> str:
        return "go"

    @property
    def lockfile_globs(self) -> list[str]:
        return [
            "go.mod",
            "go.sum",
        ]

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        from tools.index.ecosystems.go.parsers.gomod import parse
        return parse(path)
