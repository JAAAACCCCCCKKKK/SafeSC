"""index — SafeSC Stage 0-1 tool: discover and normalise dependency lockfiles.

This package owns the ecosystem-agnostic discovery walk (Stage 0) and the
lockfile parsing / normalisation into the shared :class:`Dependency` model
(Stage 1).  It is consumed both by the ``index`` CLI and by the ``scan`` tool,
which reuses discovery + parsing to obtain the dependency set it audits.

The pure functions (``discover`` / ``parse_lockfiles``) stay importable for
direct callers.  The ``@tool`` wrappers at the bottom expose the same two frozen
stages to the agent layer (CLAUDE.md §2.1) as deterministic, LLM-free tools —
mirroring ``tools/deep_analysis_tool.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from tools.index.core.discovery import DiscoveredFile, discover, print_discovered
from tools.index.core.models import Dependency
from tools.index.core.normalizer import parse_lockfiles, to_json

# --- soft LangChain import ----------------------------------------------------
# The pure functions above are usable and testable without LangChain installed;
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
    """Input for the Stage 0-1 tools: a filesystem root to scan."""

    root: str = Field(..., description="Filesystem path to the repository root to scan")


def _discovered_to_dict(f: DiscoveredFile, root: Path) -> dict:
    """JSON-friendly view of a :class:`DiscoveredFile`."""
    return {
        "path": str(f.path),
        "relative_path": str(f.path.relative_to(root)),
        "ecosystem": f.ecosystem,
        "matched_glob": f.matched_glob,
    }


# =============================================================================
# LangChain @tool wrappers — the frozen Stage 0-1 spine as agent tools.
# They accept a JSON string (agent-friendly) and return a JSON string.
# Deterministic and idempotent: no LLM, no verdict (CLAUDE.md §2.1, §6.1.2).
# =============================================================================


@tool
def discover_lockfiles(request_json: str) -> str:
    """Stage 0 — discover dependency lockfiles under a repository root.
    Input: JSON matching RepoRequest, e.g. {"root": "/path/to/repo"}. Returns a
    JSON array of discovered lockfiles (path, relative_path, ecosystem,
    matched_glob). Deterministic and LLM-free; produces no verdict."""
    req = RepoRequest.model_validate_json(request_json)
    root = Path(req.root).resolve()
    files = discover(root)
    return json.dumps([_discovered_to_dict(f, root) for f in files], indent=2)


@tool
def parse_normalize(request_json: str) -> str:
    """Stage 1 — parse discovered lockfiles into a normalised Dependency[] array.
    Input: JSON matching RepoRequest, e.g. {"root": "/path/to/repo"}. Returns a
    JSON array of Dependency objects. Deterministic and LLM-free; produces no
    verdict."""
    req = RepoRequest.model_validate_json(request_json)
    root = Path(req.root).resolve()
    files = discover(root)
    deps = parse_lockfiles(files)
    return to_json(deps)


__all__ = [
    "DiscoveredFile",
    "Dependency",
    "RepoRequest",
    "discover",
    "print_discovered",
    "parse_lockfiles",
    "to_json",
    "discover_lockfiles",
    "parse_normalize",
]
