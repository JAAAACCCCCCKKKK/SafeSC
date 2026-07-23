"""graph/spine.py — the deterministic spine (CLAUDE.md §2.2-B, §2.5).
Two LLM-free jobs: run Stages 0→3 as a FIXED sequence (the §2.5 injection defence), and
the post-Stage-3 RISK GATE (branch point B) routing gray-zone deps to specialists without
writing a verdict. Only identity/behavior/provenance fan out (§4.4); the §5.3 LLM cap is
enforced here. `plan_gate()` is the pure, LangGraph-free core.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from pydantic import BaseModel, Field

from graph.state import (
    AuditState,
    DegradedNote,
    Dependency,
    Severity,
    Signal,
    SignalOrigin,
    TrustDimension,
    dep_key,
    emit_degraded,
)

logger = logging.getLogger("safesc.spine")

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
    """The four Stage 0–3 seams, wired to tools/index/ and tools/scan/ (see
    load_default_tools). The spine owns sequencing, degradation, and the gate; the
    tools stay pure and per-dep so the harness can bound concurrency (§5.1)."""

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


# Adapters: frozen Stage 0-3 code speaks its own types; these translators are the one
# place allowed to know both shapes (§6.1.5) and map them to graph.state.Signal. Pure.

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
    """Wire the spine's four seams to the real Stage 0–3 code, kept in one place so the
    spine never imports those modules directly (§6.1.5). Each seam is a thin per-dep
    adapter that calls the real implementation and translates to `graph.state.Signal`."""
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
    Merged because they are always adjacent (no gate between). Degradation is per-stage:
    discovery and parse failures each yield an empty set with their own note."""
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
    """What the gate decided, per dep: `escalations` feeds the max-wins channel and
    `fan_out` names specialists to Send to. Deps absent from fan_out flow straight to
    the scorer; `degraded_notes` records specialists dropped by the §5.3 budget."""

    escalations: dict[str, Severity] = Field(default_factory=dict)
    fan_out: list[SpecialistTask] = Field(default_factory=list)
    degraded_notes: list[DegradedNote] = Field(default_factory=list)

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
    """Deterministic gate: record each dep's static severity and fan out a specialist
    per LLM-capable dimension in the gray band [gray_floor, decided_ceiling). Cap-aware
    (§5.3): candidates truncated to the remaining budget; dropped deps keep escalation."""
    config = config or GateConfig()
    plan = GatePlan()
    by_key = {dep_key(d): d for d in state.dependencies}

    candidates: list[SpecialistTask] = []
    for key, dep in by_key.items():
        dim_sev = _dimension_severity(state.signals, key)
        overall = max((sev for sev, _ in dim_sev.values()), default=Severity.CLEAN)
        if overall > Severity.CLEAN:
            plan.escalations[key] = overall  # merged max-wins into state.escalations

        for dim in config.llm_dimensions:
            sev, sources = dim_sev.get(dim, (Severity.CLEAN, []))
            if config.gray_floor <= sev < config.decided_ceiling:
                candidates.append(
                    SpecialistTask(
                        dep_key=key,
                        dependency=dep,
                        dimension=dim,
                        trigger_severity=sev,
                        trigger_sources=sources,
                    )
                )

    # Highest severity first; (dep_key, dimension) as a stable tiebreak so truncation
    # is fully deterministic regardless of dep/dimension iteration order.
    candidates.sort(key=lambda t: (-int(t.trigger_severity), t.dep_key, t.dimension.value))

    budget = max(0, state.llm_call_cap - state.llm_calls)
    plan.fan_out = candidates[:budget]
    for t in candidates[budget:]:
        plan.degraded_notes.append(
            DegradedNote(
                node=NODE_GATE,
                reason=(
                    f"LLM budget exhausted (cap={state.llm_call_cap}, used={state.llm_calls}): "
                    f"skipped {t.dimension.value} specialist for {t.dep_key} "
                    f"(trigger={t.trigger_severity.name}); analysis incomplete"
                ),
            )
        )
    return plan


# =============================================================================
# LangGraph glue
# =============================================================================


def gate_node(state: AuditState, config: Optional[GateConfig] = None) -> dict:
    """Writes the gate's escalation view into state (max-wins channel), plus any
    budget-truncation notes (§5.3). Fan-out itself is handled by gate_edge, not here;
    both call plan_gate and see the same deterministic cap."""
    plan = plan_gate(state, config)
    out: dict = {"escalations": plan.escalations}
    if plan.degraded_notes:
        out["degraded_notes"] = plan.degraded_notes
    return out


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
    """Add the spine nodes and fixed edges (index → hash_verify → cheap_signals → gate)
    to a builder, returning the entry node name (NODE_INDEX) for the router's full-spine
    branch. Specialist and report nodes are added by their own modules before compile."""
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
