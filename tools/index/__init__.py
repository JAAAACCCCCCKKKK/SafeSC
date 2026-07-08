"""index — SafeSC Stage 0-1 tool: discover and normalise dependency lockfiles.

This package owns the ecosystem-agnostic discovery walk (Stage 0) and the
lockfile parsing / normalisation into the shared :class:`Dependency` model
(Stage 1).  It is consumed both by the ``index`` CLI and by the ``scan`` tool,
which reuses discovery + parsing to obtain the dependency set it audits.
"""

from __future__ import annotations

from tools.index.core.discovery import DiscoveredFile, discover, print_discovered
from tools.index.core.models import Dependency
from tools.index.core.normalizer import parse_lockfiles, to_json

__version__ = "0.1.0"

__all__ = [
    "DiscoveredFile",
    "Dependency",
    "discover",
    "print_discovered",
    "parse_lockfiles",
    "to_json",
]
