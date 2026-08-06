"""reporter/markdown_reporter.py — human-readable Markdown projection of an `AuditReport`.

The format a reviewer reads in a PR comment or CI log: a headline verdict, an incomplete-
analysis banner when the run degraded (§5.3/§8.5 — never let a partial run look like a
clean pass), a per-dependency table, and an expandable evidence block per flagged dep.
Clean deps are summarised, not enumerated, so a large green audit stays scannable.
"""

from __future__ import annotations

from safesc.reporter.models import AuditReport, DependencyFinding

_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "CLEAN": "🟢",
}


def _badge(sev: str) -> str:
    return f"{_EMOJI.get(sev, '⚪')} {sev}"


def _finding_details(f: DependencyFinding) -> list[str]:
    lines = [f"#### {_badge(f.severity)} `{f.dep_key}`"]
    if f.source_url:
        lines.append(f"- source: {f.source_url}")
    if f.lockfile_path:
        lines.append(f"- lockfile: `{f.lockfile_path}`")
    for s in sorted(f.signals, key=lambda x: x.severity, reverse=True):
        head = f"- **{s.dimension}** {_badge(s.severity)} · `{s.source}` ({s.origin}, conf={s.confidence:.2f})"
        lines.append(head)
        if s.summary:
            lines.append(f"  - {s.summary}")
        if s.reasoning and s.reasoning != s.summary:
            lines.append(f"  - reasoning: {s.reasoning}")
        for ev in s.evidence[:10]:
            lines.append(f"    - evidence: {ev}")
        for hint in s.false_positive_hints[:5]:
            lines.append(f"    - fp-hint: {hint}")
    return lines


def render_markdown(report: AuditReport) -> str:
    status = "PASS ✅" if report.passed else "FAIL ❌"
    out: list[str] = [
        f"# SafeSC report — {report.mode.upper()}",
        "",
        f"**Result:** {status}  |  **Overall:** {_badge(report.overall_severity)}  |  "
        f"**Exit:** {report.exit_code}",
        f"**Run:** `{report.run_id or 'n/a'}`"
        + (f"  |  **Generated:** {report.generated_at}" if report.generated_at else ""),
        "",
        f"{report.total_dependencies} dependencies analysed, "
        f"{report.flagged_count} flagged.",
    ]

    if report.incomplete:
        out += [
            "",
            "> ⚠️ **INCOMPLETE ANALYSIS** — this run degraded or hit a limit; treat the "
            "result as provisional. See details below.",
        ]

    flagged = report.flagged_findings
    if flagged:
        out += ["", "## Flagged dependencies", "", "| Dependency | Severity | Dimensions |", "|---|---|---|"]
        for f in flagged:
            dims = ", ".join(f"{d}={v}" for d, v in sorted(f.dimensions.items())) or "—"
            out.append(f"| `{f.dep_key}` | {_badge(f.severity)} | {dims} |")
        out += ["", "## Evidence"]
        for f in flagged:
            out += ["", *_finding_details(f)]
    else:
        out += ["", "No dependencies were flagged. ✅"]

    if report.degraded:
        out += ["", "## Degraded nodes", ""]
        for n in report.degraded:
            out.append(f"- `{n.node}`: {n.reason}")

    return "\n".join(out) + "\n"
