"""
graph/router.py — the entry router (CLAUDE.md §2.2-A).

This is branch point (A): it splits on request SCOPE, which is known at entry.
It is deliberately RULE-BASED and RISK-INDEPENDENT — it must not read, compute, or
depend on any trust signal, because no signals exist yet (Stages 0-3 have not run).

Do NOT confuse this with branch point (B), the post-Stage-3 risk gate in spine.py,
which decides *which suspicious deps get LLM specialists*. Scope is a routing concern
and lives here; risk is a scorer concern and lives there. Keeping them apart is the
whole reason the v2 design is coherent (principle #3).

    single package / direct lookup  -> SINGLE_AGENT path
    full repository / lockfile set   -> FULL_SPINE path

Mode (audit vs query) is orthogonal to scope: it only decides whether the run
produces a CI gate + exit code. A query over a whole repo is allowed (read-only,
FULL_SPINE path, no gate).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from graph.state import RunMode, RunScope, RoutePath

# Node names used when wiring the graph's conditional edges.
NODE_SINGLE_AGENT = "single_agent"
NODE_SPINE = "spine"


# =============================================================================
# I/O models
# =============================================================================


class AuditRequest(BaseModel):
    """What the FastAPI entrypoints hand the graph."""

    mode: RunMode
    target: str = Field(..., description="A package spec, a git URL, or a repo/lockfile path")
    ecosystem: Optional[str] = None
    scope_override: Optional[RunScope] = Field(
        None, description="Explicit override; bypasses structural detection but never risk"
    )


class RouteDecision(BaseModel):
    mode: RunMode
    scope: RunScope
    path: RoutePath
    produces_gate: bool
    reason: str


# =============================================================================
# Scope classification (rule-based, risk-free)
# =============================================================================

# name  or  name@version  or  ecosystem:name@version  (no path separators)
_PACKAGE_SPEC_RE = re.compile(r"^(?:[a-z]+:)?@?[\w.\-]+(?:/[\w.\-]+)?(?:@[\w.\-+]+)?$")
_GIT_URL_RE = re.compile(r"^https://[^\s/]+/.+?(?:\.git)?$", re.IGNORECASE)
_LOCKFILE_NAMES = {
    "requirements.txt", "poetry.lock", "uv.lock", "pipfile.lock",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "cargo.lock", "go.sum", "go.mod", "pom.xml", "build.gradle",
}


def _looks_like_repo(target: str) -> bool:
    t = target.strip()
    if t in (".", "./") or t.startswith(("/", "./", "../", "~")):
        return True
    if _GIT_URL_RE.match(t) and (t.endswith(".git") or "/tree/" in t or t.count("/") >= 4):
        return True
    # a filesystem path that exists or points at a known lockfile
    name = Path(t).name.lower()
    if name in _LOCKFILE_NAMES:
        return True
    try:
        if Path(t).exists() and Path(t).is_dir():
            return True
    except OSError:
        pass
    return False


def _looks_like_package_spec(target: str) -> bool:
    t = target.strip()
    if t.startswith("pkg:"):  # Package URL (purl)
        return True
    if "/" in t and not t.startswith("@"):
        return False  # has a path separator and is not an npm scope → treat as path
    return bool(_PACKAGE_SPEC_RE.match(t))


def classify_scope(req: AuditRequest) -> RunScope:
    """Structural, deterministic. Never consults risk/signals."""
    if req.scope_override is not None:
        return req.scope_override
    target = req.target.strip()
    if not target:
        # empty target under audit = scan the current repo
        return RunScope.FULL_REPO
    if target.startswith("pkg:"):
        return RunScope.SINGLE_PACKAGE
    if _looks_like_repo(target):
        return RunScope.FULL_REPO
    if _looks_like_package_spec(target):
        return RunScope.SINGLE_PACKAGE
    # ambiguous → fall back on mode intent: an audit defaults to a repo, a query to a package
    return RunScope.FULL_REPO if req.mode == RunMode.AUDIT else RunScope.SINGLE_PACKAGE


# =============================================================================
# Routing
# =============================================================================


def route(req: AuditRequest) -> RouteDecision:
    scope = classify_scope(req)
    path = RoutePath.SINGLE_AGENT if scope == RunScope.SINGLE_PACKAGE else RoutePath.FULL_SPINE
    produces_gate = req.mode == RunMode.AUDIT  # only audits gate CI (§1.3)
    reason = (
        f"scope={scope.value} (from {'override' if req.scope_override else 'structure'}); "
        f"mode={req.mode.value} → {'gate+exit code' if produces_gate else 'evidence only'}"
    )
    return RouteDecision(mode=req.mode, scope=scope, path=path, produces_gate=produces_gate, reason=reason)


# =============================================================================
# LangGraph glue
# =============================================================================


def router_node(state) -> dict:
    """Entry node: writes the scope decision onto the state. Reads no signals."""
    req = AuditRequest(mode=state.mode, target=state.target, ecosystem=getattr(state, "ecosystem", None))
    decision = route(req)
    return {"scope": decision.scope, "path": decision.path}


def route_condition(state) -> str:
    """Conditional-edge selector: returns the next node name based on scope only."""
    return NODE_SINGLE_AGENT if state.path == RoutePath.SINGLE_AGENT else NODE_SPINE
