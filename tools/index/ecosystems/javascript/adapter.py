"""JavaScript ecosystem adapter — lockfile discovery patterns."""

from __future__ import annotations

from pathlib import Path

from tools.index.core.models import Dependency
from tools.index.ecosystems.base import EcosystemAdapter


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

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        name = path.name
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            from tools.index.ecosystems.javascript.parsers.package_lock import parse
            return parse(path)
        if name == "yarn.lock":
            from tools.index.ecosystems.javascript.parsers.yarn import parse
            return parse(path)
        if name == "pnpm-lock.yaml":
            from tools.index.ecosystems.javascript.parsers.pnpm import parse
            return parse(path)
        return []
