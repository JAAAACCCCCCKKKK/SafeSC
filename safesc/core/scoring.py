"""core/scoring.py — the scorer: the only place a verdict is computed (CLAUDE.md §2.4).

Runs no LLM and has no discretion. The orchestrator *triggers* it (through the
`finalize_score` tool, once per run), but nothing an agent says reaches it except as
signals already merged into the ledger through the deterministic fusion table.

Rules, in order:

1. **Per-dependency severity** = the maximum severity across all of its signals
   (weakest-link). Under an escalate-only system an average could pull a genuine HIGH
   toward the mean, which the architecture forbids.
2. **Gate**: the run fails when any dependency reaches ``fail_on`` (HIGH by default).
3. **Trust score** (0–100, for humans and dashboards; it never overrides the gate):
   start at 100 and subtract a fixed penalty per dependency by its severity
   (``PENALTY``), then apply weakest-link ceilings so many clean deps cannot dilute one
   bad one: any HIGH caps the score at 59, any CRITICAL at 19. An incomplete analysis
   caps it at 89 — a provisional result can never read as excellent.
4. **Grade**: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F.
5. **Incomplete** when any coverage gap exists: a degraded tool or subagent, required
   coverage left unattempted (usually because the subagent budget ran out), or a
   vulnerability candidate that never got verified. Under ``strict`` an incomplete run
   fails the gate; otherwise it passes provisionally and says so loudly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from safesc.core.signals import Severity, dep_key

if TYPE_CHECKING:
    from safesc.core.ledger import Decision, RunLedger

PENALTY: dict[Severity, int] = {
    Severity.CLEAN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 4,
    Severity.HIGH: 15,
    Severity.CRITICAL: 40,
}
CEILING: dict[Severity, int] = {Severity.HIGH: 59, Severity.CRITICAL: 19}
INCOMPLETE_CEILING = 89
GRADES: tuple[tuple[int, str], ...] = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2


def trust_score(per_dep: dict[str, Severity], *, incomplete: bool) -> int:
    score = 100 - sum(PENALTY[s] for s in per_dep.values())
    for sev, cap in CEILING.items():
        if any(s >= sev for s in per_dep.values()):
            score = min(score, cap)
    if incomplete:
        score = min(score, INCOMPLETE_CEILING)
    return max(0, min(100, score))


def grade_for(score: int) -> str:
    for floor, grade in GRADES:
        if score >= floor:
            return grade
    return "F"


def _top_reason(ledger: "RunLedger", key: str) -> str:
    worst = max(ledger.signals_for(key), key=lambda s: s.severity, default=None)
    if worst is None:
        return "no signals"
    return f"{worst.dimension.value}={worst.severity.name} ({worst.origin.value}:{worst.source})"


def incomplete_reasons(ledger: "RunLedger") -> list[str]:
    reasons: list[str] = []
    if ledger.notes:
        reasons.append(f"{len(ledger.notes)} degraded step(s)")
    if not ledger.static_complete():
        missing = ", ".join(s.value for s in ledger.missing_stages(*_stages()))
        reasons.append(f"static stage(s) never ran: {missing}")
    unattempted = [
        (k, role) for k, role, _ in ledger.required_coverage()
        if not ledger.attempted(k, role) and role.value != "vuln_verifier"
    ]
    if unattempted:
        reasons.append(f"{len(unattempted)} required subagent analysis(es) not run (budget exhausted)")
    pending = [c for c in ledger.candidates.values() if c.status == "pending"]
    if pending:
        reasons.append(f"{len(pending)} vulnerability candidate(s) never verified")
    degraded = [r for r in ledger.subagent_runs if r.status != "ok"]
    if degraded:
        reasons.append(f"{len(degraded)} subagent run(s) degraded or denied")
    return reasons


def _stages():
    from safesc.core.ledger import STATIC_STAGES

    return STATIC_STAGES


def score(ledger: "RunLedger", *, strict: bool = False) -> "Decision":
    from safesc.core.ledger import Decision

    fail_on = ledger.options.fail_on
    per_dep: dict[str, Severity] = {}
    for dep in ledger.dependencies:
        key = dep_key(dep)
        per_dep[key] = max((s.severity for s in ledger.signals_for(key)), default=Severity.CLEAN)

    overall = max(per_dep.values(), default=Severity.CLEAN)
    reasons = incomplete_reasons(ledger)
    incomplete = bool(reasons)
    passed = overall < fail_on and not (strict and incomplete)
    value = trust_score(per_dep, incomplete=incomplete)
    grade = grade_for(value)

    flagged = [k for k, v in per_dep.items() if v >= fail_on]
    lines = [
        f"{'PASS' if passed else 'FAIL'}: overall={overall.name}, trust score {value}/100 ({grade}); "
        f"{len(per_dep)} deps, {len(flagged)} at/above {fail_on.name}."
    ]
    if flagged:
        lines.append("Flagged:\n" + "\n".join(
            f"  {k}: {per_dep[k].name} — {_top_reason(ledger, k)}"
            for k in sorted(flagged, key=lambda k: (-per_dep[k], k))
        ))
    if incomplete:
        tail = " — counted as a failure (--strict)." if strict else " — treat result as provisional."
        lines.append("⚠ INCOMPLETE ANALYSIS: " + "; ".join(reasons) + tail)

    return Decision(
        per_dep=per_dep,
        overall=overall,
        passed=passed,
        exit_code=EXIT_PASS if passed else EXIT_FAIL,
        score=value,
        grade=grade,
        incomplete=incomplete,
        incomplete_reasons=reasons,
        summary="\n".join(lines),
    )
