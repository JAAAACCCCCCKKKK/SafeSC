"""
graph/spine.py — the deterministic spine (CLAUDE.md §2.2-B, §2.5).

Two responsibilities, both LLM-free:

  1. Run Stages 0→1→2→3 as a FIXED, NON-DISCRETIONARY sequence. The agent never
     chooses whether these run — the spine does. That is the security property in
     §2.5: an attacker cannot craft metadata that talks the pipeline out of hash
     verification, because nothing here is agent-driven.

  2. The post-Stage-3 RISK GATE (branch point B). After cheap signals are in, the
     gate decides, per dependency, (a) whether it is gray-zone enough to warrant
     Stage-4 LLM analysis, and (b) which specialists it fans out to. The gate only
     *routes*; it never writes the final verdict (that is report_agent, §2.4).

Key boundaries honoured:
  - No LLM here. The spine is pre-LLM (§2.1).
  - Only identity/behavior/provenance can fan out — popularity/vulnerability have no
    LLM task (§4.4), so a dep suspicious only on those stays deterministic and is
    NOT sent to a specialist. This is also what keeps the Stage-4 trigger rate in the
    §5.1 5–10% band; `GateConfig.gray_floor` is the primary tuning lever.
  - A dimension already at the decided ceiling (e.g. a confirmed hash mismatch =
    CRITICAL provenance) is recorded but NOT sent to an LLM — the LLM could only
    escalate, and it is already maxed, so spending the call adds no signal (§5.3).
  - Every stage degrades independently and never crashes the run (§8.5).

The gate core is `plan_gate()`, a pure function unit-tested without LangGraph. The
single-agent path (one package) can reuse it verbatim. `gate_edge()` is the thin
LangGraph `Send` adapter around it.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from pydantic import BaseModel, Field

from graph.state import (
    AuditState,
    Dependency,
    Severity,
    Signal,
    SignalOrigin,
    TrustDimension,
    dep_key,
    emit_degraded,
)

logger = logging.getLogger("depaudit.spine")

# Send is only needed for the LangGraph adapter; keep the module importable/testable
# without LangGraph installed.
try:  # pragma: no cover
    from langgraph.types import Send  # type: ignore
except Exception:  # pragma: no cover
    try:
        from langgraph.constants import Send  # type: ignore
    except Exception:
        Send = None  # type: ignore

# Node names for graph wiring.
NODE_INDEX = "index"  # Stage 0+1: discovery + parse/normalize (always adjacent, no gate between)
NODE_HASH_VERIFY = "hash_verify"
NODE_CHEAP_SIGNALS = "cheap_signals"
NODE_GATE = "gate"
NODE_REPORT = "report"  # report_agent (§2.4)
SPECIALIST_NODE = {
    TrustDimension.IDENTITY: "identity_agent",
    TrustDimension.BEHAVIOR: "behavior_agent",
    TrustDimension.PROVENANCE: "provenance_agent",
}


# =============================================================================
# Contracts injected/produced by the spine
# =============================================================================


class LockfileRef(BaseModel):
    path: str
    ecosystem: str


class SpecialistTask(BaseModel):
    """Payload a fan-out `Send` carries to a specialist node. The specialist reads the
    full signal set from state; this just names the dep and why it was flagged."""

    dep_key: str
    dependency: Dependency
    dimension: TrustDimension
    trigger_severity: Severity
    trigger_sources: list[str] = Field(default_factory=list)


class SpineTools(Protocol):
    """The four Stage 0–3 seams. Wire these to the real implementations in
    tools/index/ and tools/scan/ (see load_default_tools). Signatures are the §2.1
    tool contracts; the spine owns sequencing, degradation, and the gate — the tools
    stay pure and per-dep so the harness can bound their concurrency (§5.1)."""

    def discover(self, target: str) -> list[LockfileRef]: ...          # Stage 0
    def parse(self, lockfiles: list[LockfileRef]) -> list[Dependency]: ...  # Stage 1
    def verify_hash(self, dep: Dependency) -> list[Signal]: ...        # Stage 2
    def collect_signals(self, dep: Dependency) -> list[Signal]: ...    # Stage 3


@dataclass
class InjectedTools:
    """Concrete SpineTools built from four callables (dependency injection). Lets the
    spine be unit-tested with fakes and wired to real tools without import coupling."""

    discover: Callable[[str], list[LockfileRef]]
    parse: Callable[[list[LockfileRef]], list[Dependency]]
    verify_hash: Callable[[Dependency], list[Signal]]
    collect_signals: Callable[[Dependency], list[Signal]]


# --- adapters: real tool output types -> the unified graph.state.Signal ------
#
# The frozen Stage 0-3 code predates the agent layer and speaks its own types:
# Stage 0 yields `DiscoveredFile`, Stages 2/3 yield `tools.scan.signals.models.Signal`
# and `HashVerificationResult`. The spine works only in `graph.state.Signal`, so these
# translators live here (the one place allowed to know both shapes, §6.1.5). They are
# pure and are unit-tested directly with fakes.

# scan Severity (info/low/medium/high/critical) -> graph Severity. `info` is the
# scan layer's "no concern" tier, so it maps to CLEAN and never escalates (§4.3).
_SCAN_SEVERITY_TO_GRAPH: dict[str, Severity] = {
    "info": Severity.CLEAN,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _scan_severity_to_graph(scan_severity) -> Severity:
    return _SCAN_SEVERITY_TO_GRAPH[scan_severity.value]


def _scan_signal_to_graph(s) -> Signal:
    """tools.scan.signals.models.Signal -> graph.state.Signal (Stage 3)."""
    return Signal(
        dep_key=dep_key(s.dep),
        dimension=TrustDimension(s.dimension.value),
        origin=SignalOrigin.STATIC,
        source=s.code,
        severity=_scan_severity_to_graph(s.severity),
        confidence=1.0,
        summary=s.message,
        evidence=list(s.evidence),
        false_positive_hints=list(s.false_positive_hints),
    )


def _hash_result_to_graph(r) -> Signal:
    """HashVerificationResult -> graph.state.Signal, always a provenance signal (Stage 2)."""
    return Signal(
        dep_key=dep_key(r.dep),
        dimension=TrustDimension.PROVENANCE,
        origin=SignalOrigin.STATIC,
        source=f"stage2.hash.{r.status.value}",
        severity=_scan_severity_to_graph(r.severity),
        confidence=1.0,
        summary=r.detail or f"hash {r.status.value}",
        evidence=[h for h in (r.lockfile_hash, r.registry_hash) if h],
        false_positive_hints=[],
    )


def load_default_tools() -> InjectedTools:
    """Wire the spine's four seams to the real Stage 0–3 code. Kept in one place so
    the rest of the spine never imports those modules directly (layering, §6.1.5).

    The frozen tools use different names/shapes/async than the §2.1 contract, so each
    seam is a thin per-dep adapter: it calls the real (batch/async) implementation and
    translates its output into the unified `graph.state.Signal`."""
    from pathlib import Path

    from tools.index.core import discovery, normalizer  # type: ignore
    from tools.index.core.discovery import DiscoveredFile  # type: ignore
    from tools.scan.signals import collector  # type: ignore
    from tools.scan.signals.provenance import verifier  # type: ignore

    def discover(target: str) -> list[LockfileRef]:  # Stage 0
        found = discovery.discover(Path(target))
        return [LockfileRef(path=str(f.path), ecosystem=f.ecosystem) for f in found]

    def parse(lockfiles: list[LockfileRef]) -> list[Dependency]:  # Stage 1
        discovered = [
            DiscoveredFile(path=Path(lf.path), ecosystem=lf.ecosystem, matched_glob="")
            for lf in lockfiles
        ]
        return normalizer.parse_lockfiles(discovered)

    def verify_hash(dep: Dependency) -> list[Signal]:  # Stage 2
        return [_hash_result_to_graph(r) for r in verifier.run_verification([dep])]

    def collect_signals(dep: Dependency) -> list[Signal]:  # Stage 3
        return [_scan_signal_to_graph(s) for s in collector.run_collection([dep])]

    return InjectedTools(
        discover=discover,
        parse=parse,
        verify_hash=verify_hash,
        collect_signals=collect_signals,
    )


# =============================================================================
# Stage nodes (fixed sequence; each degrades independently)
# =============================================================================


def index_node(state: AuditState, tools: InjectedTools) -> dict:
    """Stages 0+1 → discover lockfiles, then parse/normalize into the dependency set.

    Merged into one node because discovery and parsing are always adjacent (no gate
    between them), so there is no reason to thread the intermediate lockfile list
    through a state channel. Degradation is still per-stage: a discovery failure
    yields an empty dep set with a note; a parse failure is annotated separately."""
    try:
        lockfiles = tools.discover(state.target)
    except Exception as exc:
        logger.exception("discovery failed")
        return {"dependencies": [], **emit_degraded(NODE_INDEX, f"discovery failed: {exc}")}
    try:
        deps = tools.parse(lockfiles)
        return {"dependencies": deps}
    except Exception as exc:
        logger.exception("parse failed")
        return {"dependencies": [], **emit_degraded(NODE_INDEX, f"parse failed: {exc}")}


def hash_verify_node(state: AuditState, tools: InjectedTools) -> dict:
    """Stage 2 → provenance signals from hash verification. Per-dep; one dep failing
    degrades only that dep."""
    signals: list[Signal] = []
    degraded: list = []
    for dep in state.dependencies:
        try:
            signals.extend(tools.verify_hash(dep))
        except Exception as exc:
            logger.warning("hash verify failed for %s: %s", dep_key(dep), exc)
            degraded += emit_degraded(NODE_HASH_VERIFY, f"{dep_key(dep)}: {exc}")["degraded_notes"]
    out: dict = {"signals": signals}
    if degraded:
        out["degraded_notes"] = degraded
    return out


def cheap_signals_node(state: AuditState, tools: InjectedTools) -> dict:
    """Stage 3 → the cheap static signals across all five dimensions."""
    signals: list[Signal] = []
    degraded: list = []
    for dep in state.dependencies:
        try:
            signals.extend(tools.collect_signals(dep))
        except Exception as exc:
            logger.warning("cheap signals failed for %s: %s", dep_key(dep), exc)
            degraded += emit_degraded(NODE_CHEAP_SIGNALS, f"{dep_key(dep)}: {exc}")["degraded_notes"]
    out: dict = {"signals": signals}
    if degraded:
        out["degraded_notes"] = degraded
    return out


# =============================================================================
# The gate (branch point B) — pure core
# =============================================================================


class GateConfig(BaseModel):
    gray_floor: Severity = Severity.MEDIUM       # >= this on an LLM dimension → gray zone
    decided_ceiling: Severity = Severity.CRITICAL  # >= this → already decided, skip the LLM
    llm_dimensions: frozenset[TrustDimension] = frozenset(
        {TrustDimension.IDENTITY, TrustDimension.BEHAVIOR, TrustDimension.PROVENANCE}
    )

    model_config = {"frozen": True}


class GatePlan(BaseModel):
    """What the gate decided, per dep. `escalations` feeds the max-wins state channel;
    `fan_out` names the specialists to Send to. Deps absent from fan_out are handled
    deterministically and flow straight to the scorer."""

    escalations: dict[str, Severity] = Field(default_factory=dict)
    fan_out: list[SpecialistTask] = Field(default_factory=list)

    def escalated_count(self) -> int:
        return len({t.dep_key for t in self.fan_out})


def _dimension_severity(signals: list[Signal], key: str) -> dict[TrustDimension, tuple[Severity, list[str]]]:
    """Per-dimension max static severity for one dep, plus the sources that set it."""
    out: dict[TrustDimension, tuple[Severity, list[str]]] = {}
    for s in signals:
        if s.dep_key != key:
            continue
        cur, srcs = out.get(s.dimension, (Severity.CLEAN, []))
        if s.severity > cur:
            out[s.dimension] = (s.severity, [s.source])
        elif s.severity == cur and s.severity > Severity.CLEAN:
            out[s.dimension] = (cur, srcs + [s.source])
    return out


def plan_gate(state: AuditState, config: Optional[GateConfig] = None) -> GatePlan:
    """Deterministic gate. For each dep: record its overall static severity, and fan
    out to a specialist for each LLM-capable dimension sitting in the gray band
    [gray_floor, decided_ceiling). Reusable by the single-agent path.

    Escalate-only holds: the gate can raise a dep into Stage 4 but never clears a
    signal, and a dep it declines to escalate still carries its full static severity
    to the scorer."""
    config = config or GateConfig()
    plan = GatePlan()
    by_key = {dep_key(d): d for d in state.dependencies}

    for key, dep in by_key.items():
        dim_sev = _dimension_severity(state.signals, key)
        overall = max((sev for sev, _ in dim_sev.values()), default=Severity.CLEAN)
        if overall > Severity.CLEAN:
            plan.escalations[key] = overall  # merged max-wins into state.escalations

        for dim in config.llm_dimensions:
            sev, sources = dim_sev.get(dim, (Severity.CLEAN, []))
            if config.gray_floor <= sev < config.decided_ceiling:
                plan.fan_out.append(
                    SpecialistTask(
                        dep_key=key,
                        dependency=dep,
                        dimension=dim,
                        trigger_severity=sev,
                        trigger_sources=sources,
                    )
                )
    return plan


# =============================================================================
# LangGraph glue
# =============================================================================


def gate_node(state: AuditState, config: Optional[GateConfig] = None) -> dict:
    """Writes the gate's escalation view into state (max-wins channel). Fan-out is
    handled by gate_edge, not here."""
    plan = plan_gate(state, config)
    return {"escalations": plan.escalations}


def gate_edge(state: AuditState, config: Optional[GateConfig] = None):
    """Conditional-edge selector. Returns per-dep `Send`s to specialists for gray-zone
    deps, or routes straight to the scorer when nothing escalates. All deps reach the
    scorer regardless — clean deps need no node; their signals are already in state."""
    if Send is None:  # pragma: no cover
        raise RuntimeError("LangGraph is required to build the runnable graph; gate_edge needs Send.")
    plan = plan_gate(state, config)
    sends = [
        Send(SPECIALIST_NODE[t.dimension], {"task": t.model_dump()})
        for t in plan.fan_out
        if t.dimension in SPECIALIST_NODE
    ]
    return sends if sends else NODE_REPORT


# =============================================================================
# Wiring helper
# =============================================================================


def add_spine(builder, tools: InjectedTools, config: Optional[GateConfig] = None) -> str:
    """Add the spine nodes and fixed edges to a LangGraph StateGraph builder.

        index → hash_verify → cheap_signals → gate ─┬─▶ specialists ─▶ report
                                                     └─▶ report  (nothing gray)

    Returns the entry node name (NODE_INDEX) so the caller can wire the router's
    full-spine branch to it. Specialist nodes and the report node are added by their
    own modules before compile; this references them only by the shared names above.
    """
    builder.add_node(NODE_INDEX, functools.partial(index_node, tools=tools))
    builder.add_node(NODE_HASH_VERIFY, functools.partial(hash_verify_node, tools=tools))
    builder.add_node(NODE_CHEAP_SIGNALS, functools.partial(cheap_signals_node, tools=tools))
    builder.add_node(NODE_GATE, functools.partial(gate_node, config=config))

    builder.add_edge(NODE_INDEX, NODE_HASH_VERIFY)
    builder.add_edge(NODE_HASH_VERIFY, NODE_CHEAP_SIGNALS)
    builder.add_edge(NODE_CHEAP_SIGNALS, NODE_GATE)
    builder.add_conditional_edges(
        NODE_GATE,
        functools.partial(gate_edge, config=config),
        [*SPECIALIST_NODE.values(), NODE_REPORT],
    )
    return NODE_INDEX
