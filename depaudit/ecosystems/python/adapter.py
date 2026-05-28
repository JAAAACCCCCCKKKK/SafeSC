"""Python ecosystem adapter — lockfile discovery patterns."""

from __future__ import annotations

from pathlib import Path

from depaudit.core.models import Dependency
from depaudit.ecosystems.base import EcosystemAdapter


class PythonAdapter(EcosystemAdapter):
    """Adapter for Python dependency files (uv, poetry, pip, pipenv)."""

    @property
    def name(self) -> str:
        return "python"

    @property
    def lockfile_globs(self) -> list[str]:
        return [
            "uv.lock",
            "poetry.lock",
            "requirements.txt",
            "requirements-*.txt",
            "requirements/*.txt",
            "Pipfile.lock",
            "pyproject.toml",    # may declare deps directly
            "setup.cfg",         # legacy direct deps
        ]

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        name = path.name
        if name == "uv.lock":
            from depaudit.ecosystems.python.parsers.uv import parse
            return parse(path)
        if name == "poetry.lock":
            from depaudit.ecosystems.python.parsers.poetry import parse
            return parse(path)
        if name.endswith(".txt"):
            from depaudit.ecosystems.python.parsers.requirements import parse
            return parse(path)
        if name == "Pipfile.lock":
            from depaudit.ecosystems.python.parsers.pipfile import parse
            return parse(path)
        return []  # pyproject.toml / setup.cfg: declarations only, no pinned versions
