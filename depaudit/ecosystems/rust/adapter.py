"""Rust ecosystem adapter — lockfile discovery patterns."""

from __future__ import annotations

from depaudit.ecosystems.base import EcosystemAdapter


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