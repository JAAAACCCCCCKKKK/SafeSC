"""core/gate.py — the post-Stage-3 risk gate (CLAUDE.md §2.2-B), as a pure function.

Reads only the static signals in the ledger and returns the gray-zone (dep, dimension)
pairs that need LLM analysis. It decides *what must be looked at*, never *what the verdict
is*: the orchestrator may look at more, but it cannot finalize a score until everything
listed here has been attempted or the run's subagent budget is spent (`RunLedger.
required_coverage`). Only identity/behavior/provenance have LLM tasks (§4.4); vulnerability
and popularity are fully decided by their deterministic signals.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from safesc.core.signals import Severity, Signal, SignalOrigin, TrustDimension, dep_key

if TYPE_CHECKING:
    from safesc.core.ledger import RunLedger

LLM_DIMENSIONS: frozenset[TrustDimension] = frozenset(
    {TrustDimension.IDENTITY, TrustDimension.BEHAVIOR, TrustDimension.PROVENANCE}
)


class TriageItem(BaseModel):
    dep_key: str
    dimension: TrustDimension
    severity: Severity
    sources: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


def dimension_severity(signals: list[Signal], key: str) -> dict[TrustDimension, tuple[Severity, list[str]]]:
    """Per-dimension max *static* severity for one dep, plus the sources that set it."""
    out: dict[TrustDimension, tuple[Severity, list[str]]] = {}
    for s in signals:
        if s.dep_key != key or s.origin != SignalOrigin.STATIC:
            continue
        cur, srcs = out.get(s.dimension, (Severity.CLEAN, []))
        if s.severity > cur:
            out[s.dimension] = (s.severity, [s.source])
        elif s.severity == cur and s.severity > Severity.CLEAN:
            out[s.dimension] = (cur, srcs + [s.source])
    return out


def plan_triage(ledger: "RunLedger") -> list[TriageItem]:
    """Gray-zone items, highest static severity first, (dep_key, dimension) as a stable
    tiebreak so the order is fully deterministic."""
    floor = ledger.options.gray_floor
    ceiling = ledger.options.decided_ceiling
    signals = ledger.signals
    items: list[TriageItem] = []
    for dep in ledger.dependencies:
        key = dep_key(dep)
        dims = dimension_severity(signals, key)
        for dim in sorted(LLM_DIMENSIONS, key=lambda d: d.value):
            sev, sources = dims.get(dim, (Severity.CLEAN, []))
            if floor <= sev < ceiling:
                evidence = [
                    e for s in signals
                    if s.dep_key == key and s.dimension == dim and s.origin == SignalOrigin.STATIC
                    for e in s.evidence
                ]
                items.append(TriageItem(dep_key=key, dimension=dim, severity=sev, sources=sources, evidence=evidence))
    items.sort(key=lambda t: (-int(t.severity), t.dep_key, t.dimension.value))
    return items
