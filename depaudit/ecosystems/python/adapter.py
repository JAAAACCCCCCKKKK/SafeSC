"""Python ecosystem adapter — lockfile discovery patterns."""

from __future__ import annotations

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