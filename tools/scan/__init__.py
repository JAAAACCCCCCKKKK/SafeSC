"""scan — SafeSC Stage 2-3 tool: verify provenance and collect trust signals.

This package owns hash verification against registries (Stage 2) and the cheap
signal collectors (Stage 3).  It operates purely on the shared
:class:`Dependency` model produced by the ``index`` tool, from which it also
re-uses discovery and parsing so ``scan`` can run standalone against a repo.
"""

from __future__ import annotations

from tools.index.core.models import Dependency
from tools.scan.signals.provenance.insecure_url import InsecureUrlCollector
from tools.scan.signals.provenance.registries import get_registry_hash

__version__ = "0.1.0"

__all__ = [
    "Dependency",
    "InsecureUrlCollector",
    "get_registry_hash",
]
