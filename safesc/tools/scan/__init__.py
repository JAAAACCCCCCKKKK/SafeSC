"""scan — SafeSC Stage 2-3 tool: verify provenance and collect trust signals.

This package owns hash verification against registries (Stage 2) and the cheap
signal collectors (Stage 3).  It operates purely on the shared
:class:`Dependency` model produced by the ``index`` tool, from which it also
re-uses discovery and parsing so ``scan`` can run standalone against a repo.

The stage orchestrators (``run_verification`` / ``run_collection``) stay
importable for direct callers.  The ``@tool`` wrappers at the bottom expose the
same two frozen stages to the agent layer (CLAUDE.md §2.1) as deterministic,
LLM-free tools — mirroring ``tools/deep_analysis_tool.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from safesc.tools.index.core.discovery import discover
from safesc.tools.index.core.models import Dependency
from safesc.tools.index.core.normalizer import parse_lockfiles
from safesc.tools.scan.signals.provenance.insecure_url import InsecureUrlCollector
from safesc.tools.scan.signals.provenance.registries import get_registry_hash

# --- soft LangChain import ----------------------------------------------------
# The stage orchestrators are usable and testable without LangChain installed;
# the ``@tool`` wrappers degrade to plain functions if it is absent.
try:
    from langchain_core.tools import tool  # type: ignore
except Exception:  # pragma: no cover - fallback for early-build environments

    def tool(fn=None, **_kwargs):  # type: ignore
        def _decorate(f):
            return f

        return _decorate(fn) if callable(fn) else _decorate


__version__ = "0.1.0"


# =============================================================================
# Tool I/O models — strict Pydantic, no judgement (CLAUDE.md §2.1)
# =============================================================================


class RepoRequest(BaseModel):
    """Input for the Stage 2-3 tools: a filesystem root to audit.

    ``scan`` re-uses ``index`` discovery + parsing to obtain the dependency set,
    so both stages run standalone from a repository root.
    """

    root: str = Field(..., description="Filesystem path to the repository root to audit")


# =============================================================================
# LangChain @tool wrappers — the frozen Stage 2-3 spine as agent tools.
# They accept a JSON string (agent-friendly) and return a JSON string.
# Deterministic and idempotent: no LLM, no verdict (CLAUDE.md §2.1, §6.1.2).
# =============================================================================


@tool
def verify_hash(request_json: str) -> str:
    """Stage 2 — verify lockfile hashes against registry hashes for a repo root.
    Input: JSON matching RepoRequest, e.g. {"root": "/path/to/repo"}. Re-uses
    discovery + parsing, then returns a JSON array of hash-verification results
    (per dependency: status, severity, lockfile/registry hash). Deterministic and
    LLM-free; emits provenance signals only, no gate decision."""
    from safesc.tools.scan.signals.provenance.verifier import run_verification

    req = RepoRequest.model_validate_json(request_json)
    root = Path(req.root).resolve()
    files = discover(root)
    deps = parse_lockfiles(files)
    results = run_verification(deps)
    return json.dumps([r.to_dict() for r in results], indent=2)


@tool
def collect_cheap_signals(request_json: str) -> str:
    """Stage 3 — collect cheap identity/behavior/provenance/popularity/vulnerability
    signals over every dependency for a repo root.
    Input: JSON matching RepoRequest, e.g. {"root": "/path/to/repo"}. Re-uses
    discovery + parsing, then returns a JSON array of Signal objects. Deterministic
    and LLM-free; emits evidence only, no verdict (scoring is a later stage)."""
    from safesc.tools.scan.signals.collector import run_collection

    req = RepoRequest.model_validate_json(request_json)
    root = Path(req.root).resolve()
    files = discover(root)
    deps = parse_lockfiles(files)
    signals = run_collection(deps)
    return json.dumps([s.to_dict() for s in signals], indent=2)


__all__ = [
    "Dependency",
    "RepoRequest",
    "InsecureUrlCollector",
    "get_registry_hash",
    "verify_hash",
    "collect_cheap_signals",
]
