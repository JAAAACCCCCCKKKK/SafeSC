"""scan — Stage 2–3 library: verify provenance and collect cheap trust signals.

Hash verification against registries (Stage 2) and the cheap signal collectors (Stage 3),
operating on the shared :class:`Dependency` model. Library code with no entrypoint of its
own: in SafeSC the stages run only through the agent tools in
``safesc.agents.tools.pipeline`` (CLAUDE.md §2.1).
"""

from __future__ import annotations

from safesc.tools.index.core.models import Dependency
from safesc.tools.scan.signals.provenance.insecure_url import InsecureUrlCollector
from safesc.tools.scan.signals.provenance.registries import get_registry_hash

__all__ = ["Dependency", "InsecureUrlCollector", "get_registry_hash"]
