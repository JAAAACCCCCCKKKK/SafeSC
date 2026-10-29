"""reporter/build.py — assemble the canonical `AuditReport` from a finished run.

Reads the run's ledger (dependencies, signals, candidates, subagent runs, notes) and the
already-written `Decision`. It re-derives NOTHING that would count as a decision: the
per-dep severity shown is the same weakest-link max the scorer computed, for display.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from safesc.core.signals import Severity, Signal, dep_key
from safesc.reporter.models import (
    AuditReport,
    CandidateView,
    DegradedView,
    DependencyFinding,
    SignalView,
    SubagentRunView,
)

if TYPE_CHECKING:
    from safesc.core.ledger import Decision, RunLedger


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


def _rollup(signals: list[Signal]) -> tuple[Severity, dict[str, str]]:
    dim_max: dict[str, Severity] = {}
    for s in signals:
        if s.severity > dim_max.get(s.dimension.value, Severity.CLEAN):
            dim_max[s.dimension.value] = s.severity
    overall = max(dim_max.values(), default=Severity.CLEAN)
    return overall, {d: v.name for d, v in dim_max.items()}


def _finding(dep, signals: list[Signal]) -> DependencyFinding:
    sev, dims = _rollup(signals)
    lockfile = getattr(dep, "lockfile_path", None)
    return DependencyFinding(
        dep_key=dep_key(dep),
        name=getattr(dep, "name", ""),
        version=getattr(dep, "version", ""),
        ecosystem=getattr(dep, "ecosystem", ""),
        lockfile_path=str(lockfile) if lockfile is not None else None,
        source_url=getattr(dep, "source_url", None),
        direct=bool(getattr(dep, "is_direct", False) or getattr(dep, "layer_number", None) == 1),
        severity=sev.name,
        dimensions=dims,
        signals=[_signal_view(s) for s in sorted(signals, key=lambda s: (-int(s.severity), s.source))],
    )


def build_report(
    ledger: "RunLedger",
    decision: "Decision",
    *,
    model: str = "",
    generated_at: Optional[str] = None,
) -> AuditReport:
    """Project a finished run into the canonical `AuditReport`. `generated_at` is
    injectable so golden tests can pin it; left None it is omitted."""
    by_key: dict[str, list[Signal]] = {}
    for s in ledger.signals:
        by_key.setdefault(s.dep_key, []).append(s)
    deps = ledger.dependencies
    findings = [_finding(d, by_key.get(dep_key(d), [])) for d in deps]
    findings.sort(key=lambda f: (-Severity[f.severity].value, f.dep_key))

    return AuditReport(
        run_id=ledger.run_id,
        target=ledger.options.target,
        mode="ci" if ledger.options.ci else "interactive",
        model=model,
        generated_at=generated_at,
        overall_severity=decision.overall.name,
        passed=decision.passed,
        exit_code=decision.exit_code,
        trust_score=decision.score,
        grade=decision.grade,
        incomplete=decision.incomplete,
        incomplete_reasons=list(decision.incomplete_reasons),
        total_dependencies=len(deps),
        flagged_count=sum(1 for f in findings if f.is_flagged),
        summary=decision.summary,
        findings=findings,
        vulnerability_candidates=[
            CandidateView(
                id=c.id, dep_key=c.dep_key, title=c.title, cwe=c.cwe,
                location=f"{c.file}:{c.line}" if c.line else c.file,
                claimed_severity=c.claimed_severity, status=c.status, verifier_note=c.verifier_note,
            )
            for c in sorted(ledger.candidates.values(), key=lambda c: c.id)
        ],
        subagent_runs=[
            SubagentRunView(dep_key=r.dep_key, role=r.role.value, status=r.status, detail=r.detail)
            for r in ledger.subagent_runs
        ],
        degraded=[DegradedView(node=n.node, reason=n.reason) for n in ledger.notes],
    )
