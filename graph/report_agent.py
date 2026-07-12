"""graph/report_agent.py — the scorer / terminal reducer (CLAUDE.md §2.4).

The ONLY place a gate decision is computed or written; runs no LLM. Combines every
signal deterministically (each dep = max severity across its signals, weakest-link) and
emits one `GateDecision`. Fails an audit only (§1.3); marks degraded runs incomplete.
"""

from __future__ import annotations

import functools

from pydantic import BaseModel

from graph.spine import NODE_REPORT
from graph.state import (
    AuditState,
    GateDecision,
    RunMode,
    Severity,
    Signal,
    TrustDimension,
    dep_key,
)

# END is only needed to wire the terminal edge into a real graph; keep the module
# importable/testable without LangGraph installed.
try:  # pragma: no cover
    from langgraph.graph import END  # type: ignore
except Exception:  # pragma: no cover
    END = None  # type: ignore


class ScoreConfig(BaseModel):
    fail_threshold: Severity = Severity.HIGH  # a dep at >= this fails an audit gate
    model_config = {"frozen": True}


def _dep_breakdown(signals: list[Signal], key: str) -> dict[TrustDimension, Severity]:
    dims: dict[TrustDimension, Severity] = {}
    for s in signals:
        if s.dep_key != key:
            continue
        if s.severity > dims.get(s.dimension, Severity.CLEAN):
            dims[s.dimension] = s.severity
    return dims


def _top_reason(signals: list[Signal], key: str) -> str:
    worst: Signal | None = None
    for s in signals:
        if s.dep_key == key and (worst is None or s.severity > worst.severity):
            worst = s
    if worst is None:
        return "no signals"
    origin = worst.origin.value
    return f"{worst.dimension.value}={worst.severity.name} ({origin}:{worst.source})"


def score(state: AuditState, config: ScoreConfig | None = None) -> GateDecision:
    config = config or ScoreConfig()
    per_dep: dict[str, Severity] = {}
    lines: list[str] = []

    for dep in state.dependencies:
        key = dep_key(dep)
        sigs = state.signals_for(key)
        sev = max((s.severity for s in sigs), default=Severity.CLEAN)
        per_dep[key] = sev
        if sev >= config.fail_threshold:
            lines.append(f"  {key}: {sev.name} — {_top_reason(state.signals, key)}")

    overall = max(per_dep.values(), default=Severity.CLEAN)

    # A gray-zone dep that never received an LLM signal (cap-truncated or degraded)
    # means the picture is incomplete for that dep.
    escalated = {k for k, v in state.escalations.items() if v >= Severity.MEDIUM}
    have_llm = {s.dep_key for s in state.signals if s.origin.value == "llm"}
    unanalysed = escalated - have_llm
    incomplete = bool(state.degraded_notes) or bool(unanalysed) or state.llm_calls > state.llm_call_cap

    is_audit = state.mode == RunMode.AUDIT
    passed = overall < config.fail_threshold
    exit_code = 0 if (passed or not is_audit) else 1

    summary_parts = [
        f"{'AUDIT' if is_audit else 'QUERY'}: overall={overall.name}, "
        f"{'PASS' if passed else 'FAIL'} (exit {exit_code}); "
        f"{len(per_dep)} deps, {sum(1 for v in per_dep.values() if v >= config.fail_threshold)} at/above {config.fail_threshold.name}."
    ]
    if lines:
        summary_parts.append("Flagged:\n" + "\n".join(lines))
    if incomplete:
        reasons = []
        if state.degraded_notes:
            reasons.append(f"{len(state.degraded_notes)} degraded node(s)")
        if unanalysed:
            reasons.append(f"{len(unanalysed)} gray-zone dep(s) without LLM analysis")
        if state.llm_calls > state.llm_call_cap:
            reasons.append("LLM call cap exceeded")
        summary_parts.append("⚠ INCOMPLETE ANALYSIS: " + "; ".join(reasons) + " — treat result as provisional.")

    return GateDecision(
        per_dep=per_dep,
        overall=overall,
        passed=passed,
        exit_code=exit_code,
        summary="\n".join(summary_parts),
    )


def report_node(state: AuditState, config: ScoreConfig | None = None) -> dict:
    """Terminal node: the sole writer of `gate_decision` (write-once channel, §2.6)."""
    return {"gate_decision": score(state, config)}


def add_report(builder, config: ScoreConfig | None = None) -> str:
    """Add the terminal scorer node under `NODE_REPORT` and mark it the finish point.
    Complements `spine.add_spine`, whose gate edges route here. Returns the node name."""
    builder.add_node(NODE_REPORT, functools.partial(report_node, config=config))
    if END is not None:  # pragma: no cover - requires LangGraph
        builder.add_edge(NODE_REPORT, END)
    return NODE_REPORT
