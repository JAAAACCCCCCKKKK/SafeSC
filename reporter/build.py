"""reporter/build.py — assemble the canonical `AuditReport` from a finished run.

The reporter reads the *final* graph state (dependencies + accumulated signals) and the
already-written `GateDecision` (the scorer's verdict, §2.4). It re-derives NOTHING that
would count as a decision: the per-dep severity here is the same weakest-link max the
scorer computed, surfaced for display, never a second opinion.

Accepts either an `AuditState` (Pydantic state) or the raw mapping LangGraph returns, so
the caller need not know which form the checkpointer produced.
"""

from __future__ import annotations

from typing import Any, Optional

from graph.state import (
    AuditState,
    GateDecision,
    Severity,
    Signal,
    dep_key,
)

from reporter.models import (
    AuditReport,
    DegradedView,
    DependencyFinding,
    SignalView,
)


def _get(state: Any, key: str, default):
    """Read a field from an AuditState or from the raw dict LangGraph returns."""
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def _sev_name(sev: Severity | int | str) -> str:
    if isinstance(sev, Severity):
        return sev.name
    if isinstance(sev, int):
        return Severity(sev).name
    return str(sev)


def _signal_view(sig: Signal) -> SignalView:
    return SignalView(
        dimension=sig.dimension.value,
        origin=sig.origin.value,
        source=sig.source,
        severity=sig.severity.name,
        confidence=sig.confidence,
        summary=sig.summary,
        evidence=list(sig.evidence),
        reasoning=sig.reasoning,
        false_positive_hints=list(sig.false_positive_hints),
    )


def _finding(dep, signals: list[Signal]) -> DependencyFinding:
    key = dep_key(dep)
    # per-dimension max + overall max (mirrors report_agent._dep_breakdown / score)
    dim_max: dict[str, Severity] = {}
    max_sev = Severity.CLEAN
    for s in signals:
        d = s.dimension.value
        if s.severity > dim_max.get(d, Severity.CLEAN):
            dim_max[d] = s.severity
        if s.severity > max_sev:
            max_sev = s.severity
    dims = {d: v.name for d, v in dim_max.items()}

    lockfile = getattr(dep, "lockfile_path", None)
    return DependencyFinding(
        dep_key=key,
        name=getattr(dep, "name", ""),
        version=getattr(dep, "version", ""),
        ecosystem=getattr(dep, "ecosystem", ""),
        lockfile_path=str(lockfile) if lockfile is not None else None,
        source_url=getattr(dep, "source_url", None),
        severity=max_sev.name,
        dimensions=dims,
        signals=[_signal_view(s) for s in signals],
    )


def build_report(
    state: AuditState | dict,
    *,
    run_id: str = "",
    generated_at: Optional[str] = None,
) -> AuditReport:
    """Project a finished run into the canonical `AuditReport`.

    `state` is the final `AuditState` (or the raw dict LangGraph returns). `generated_at`
    is injectable so callers that need byte-reproducible output (golden tests, cached
    artifacts) can pin it; left `None` it is simply omitted rather than being a hidden
    wall-clock dependency."""
    # LangGraph may hand back either an AuditState or a mapping; when it is a mapping the
    # values could be plain dicts (a fully-dumped checkpoint), so coerce to real models.
    if isinstance(state, dict):
        try:
            state = AuditState.model_validate(state)
        except Exception:
            pass  # partial/hand-built dict — fall back to best-effort attribute reads
    deps = list(_get(state, "dependencies", []) or [])
    all_signals: list[Signal] = list(_get(state, "signals", []) or [])
    degraded = list(_get(state, "degraded_notes", []) or [])
    gate: Optional[GateDecision] = _get(state, "gate_decision", None)
    mode = _get(state, "mode", None)
    mode_str = getattr(mode, "value", None) or (str(mode) if mode is not None else "audit")

    by_key: dict[str, list[Signal]] = {}
    for s in all_signals:
        by_key.setdefault(s.dep_key, []).append(s)

    findings: list[DependencyFinding] = [_finding(dep, by_key.get(dep_key(dep), [])) for dep in deps]

    # Signals may reference a dep_key with no matching Dependency (e.g. single-package
    # query where the spine did not populate `dependencies`); surface them too.
    seen = {dep_key(d) for d in deps}
    for key, sigs in by_key.items():
        if key not in seen:
            findings.append(_synthetic_finding(key, sigs))

    findings.sort(key=lambda f: (-Severity[f.severity].value, f.dep_key))
    flagged = [f for f in findings if f.is_flagged]

    if gate is not None:
        overall = _sev_name(gate.overall)
        passed = gate.passed
        exit_code = gate.exit_code
        summary = gate.summary
    else:  # defensive: run never reached the scorer
        overall = max((Severity[f.severity] for f in findings), default=Severity.CLEAN).name
        passed = overall == Severity.CLEAN.name
        exit_code = 0 if passed else 1
        summary = "no gate decision produced"

    return AuditReport(
        run_id=run_id,
        mode=mode_str,
        generated_at=generated_at,
        overall_severity=overall,
        passed=passed,
        exit_code=exit_code,
        incomplete="INCOMPLETE" in (summary or ""),
        total_dependencies=len(deps),
        flagged_count=len(flagged),
        summary=summary,
        findings=findings,
        degraded=[DegradedView(node=getattr(n, "node", ""), reason=getattr(n, "reason", "")) for n in degraded],
    )


def _synthetic_finding(key: str, signals: list[Signal]) -> DependencyFinding:
    """A finding for a dep_key present only in signals (no Dependency object)."""
    ecosystem, _, rest = key.partition(":")
    name, _, version = rest.partition("@")
    dim_max: dict[str, Severity] = {}
    max_sev = Severity.CLEAN
    for s in signals:
        d = s.dimension.value
        if s.severity > dim_max.get(d, Severity.CLEAN):
            dim_max[d] = s.severity
        if s.severity > max_sev:
            max_sev = s.severity
    return DependencyFinding(
        dep_key=key,
        name=name,
        version=version,
        ecosystem=ecosystem,
        severity=max_sev.name,
        dimensions={d: v.name for d, v in dim_max.items()},
        signals=[_signal_view(s) for s in signals],
    )
