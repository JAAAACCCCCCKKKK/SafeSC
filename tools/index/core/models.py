"""Normalised dependency model shared across all pipeline stages."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class Dependency(BaseModel):
    """A single resolved dependency extracted from any lockfile.

    This is the canonical source-of-truth model. It is a Pydantic model so the
    agent layer (graph/) can thread it through typed LangGraph state; graph/state.py
    keeps a field-compatible fallback (name/version/ecosystem/source_url/hash/
    artifact_url/ref) for standalone importability.
    """

    name: str
    version: str
    ecosystem: str
    lockfile_path: Path

    hash: Optional[str] = None          # e.g. "sha256:abc123..." or "h1:..."
    source_url: Optional[str] = None    # source repository / VCS URL of the package
    artifact_url: Optional[str] = None  # download URL of the resolved artifact
    ref: Optional[str] = None           # git ref / commit the version resolves to
    is_direct: bool = False             # True when declared directly by the project
    layer_number: Optional[int] = None  # 1=direct, 2+=transitive, None=unknown
    parent_name: Optional[str] = None   # name of the package that depends on this one
    parent_url: Optional[str] = None    # source_url of the parent (filled post-parse)
    extras: list[str] = Field(default_factory=list)  # optional features / scopes

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "lockfile": str(self.lockfile_path),
            "hash": self.hash,
            "source_url": self.source_url,
            "artifact_url": self.artifact_url,
            "ref": self.ref,
            "is_direct": self.is_direct,
            "layer_number": self.layer_number,
            "parent_name": self.parent_name,
            "parent_url": self.parent_url,
            "extras": self.extras,
        }
