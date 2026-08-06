"""Rust ecosystem adapter — lockfile discovery patterns."""

from __future__ import annotations


from pathlib import Path

from safesc.tools.index.core.models import Dependency
from safesc.tools.index.ecosystems.base import EcosystemAdapter


class RustAdapter(EcosystemAdapter):
    """Adapter for Rust dependency files (Cargo)."""

    @property
    def name(self) -> str:
        return "rust"

    @property
    def lockfile_globs(self) -> list[str]:
        return [
            "Cargo.lock",
            "Cargo.toml",
        ]

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        if path.name == "Cargo.lock":
            from safesc.tools.index.ecosystems.rust.parsers.cargo import parse
            return parse(path)
        return []  # Cargo.toml is a declaration file, not a lockfile
