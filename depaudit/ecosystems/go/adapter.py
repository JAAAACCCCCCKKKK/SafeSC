"""Go ecosystem adapter — lockfile discovery patterns."""

from __future__ import annotations

from depaudit.ecosystems.base import EcosystemAdapter


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