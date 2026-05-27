"""JavaScript ecosystem adapter — lockfile discovery patterns."""

from __future__ import annotations

from depaudit.ecosystems.base import EcosystemAdapter


class JavaScriptAdapter(EcosystemAdapter):
    """Adapter for JavaScript/Node.js dependency files (npm, yarn, pnpm)."""

    @property
    def name(self) -> str:
        return "javascript"

    @property
    def lockfile_globs(self) -> list[str]:
        return [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "npm-shrinkwrap.json",
        ]