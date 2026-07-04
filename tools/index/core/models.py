"""Normalised dependency model shared across all pipeline stages."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Dependency:
    """A single resolved dependency extracted from any lockfile."""

    name: str
    version: str
    ecosystem: str
    lockfile_path: Path

    hash: str | None = None          # e.g. "sha256:abc123..." or "h1:..."
    source_url: str | None = None    # download URL of the resolved artifact
    is_direct: bool = False          # True when declared directly by the project
    layer_number: int | None = None  # 1=direct, 2+=transitive, None=unknown
    parent_name: str | None = None   # name of the package that depends on this one
    parent_url: str | None = None    # source_url of the parent (filled post-parse)
    extras: list[str] = field(default_factory=list)  # optional features / scopes

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "lockfile": str(self.lockfile_path),
            "hash": self.hash,
            "source_url": self.source_url,
            "is_direct": self.is_direct,
            "layer_number": self.layer_number,
            "parent_name": self.parent_name,
            "parent_url": self.parent_url,
            "extras": self.extras,
        }
