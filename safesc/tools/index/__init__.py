"""index — Stage 0–1 library: discover and normalise dependency lockfiles.

Ecosystem-agnostic discovery (Stage 0) and lockfile parsing into the shared
:class:`Dependency` model (Stage 1). This is library code with no entrypoint of its own:
in SafeSC the stages run only through the agent tools in
``safesc.agents.tools.pipeline`` (CLAUDE.md §2.1).
"""

from __future__ import annotations

from safesc.tools.index.core.discovery import DiscoveredFile, discover
from safesc.tools.index.core.models import Dependency
from safesc.tools.index.core.normalizer import parse_lockfiles, to_json

__all__ = ["DiscoveredFile", "Dependency", "discover", "parse_lockfiles", "to_json"]
