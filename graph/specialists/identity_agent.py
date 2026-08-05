"""graph/specialists/identity_agent.py — name-squatting + maintainer-handover (§2.3, §4.4).

Combines README/doc evidence gathered here with the static maintainer signals already in
state (which put the dep in the gray zone via task.trigger_sources); reasons about intent.
"""

from __future__ import annotations

from graph.specialists.base import (
    COMMON_SYSTEM_RULES,
    SpecialistDeps,
    _coerce_task,
    _fmt_items,
    run_specialist,
)
from graph.spine import SpecialistTask
from graph.state import TrustDimension

DIMENSION = TrustDimension.IDENTITY
EVIDENCE_DIMS = ("identity",)

SYSTEM_PROMPT = (
    COMMON_SYSTEM_RULES
    + " Your dimension is IDENTITY. Judge two things: (a) TYPOSQUAT / IMPERSONATION — "
    "when the static scanner flags this package's name as a near-miss of a popular "
    "package, decide whether it is a genuine squat trying to trade on that package's "
    "reputation, or a LEGITIMATE package that shares a name root by design (an official "
    "companion/derived library, a namespaced variant, a fork, or a plugin). Use the "
    "REGISTRY PROVENANCE facts as your primary evidence: a reputable/known publisher, a "
    "real canonical source repository, and a mature release history (many versions over a "
    "long span) point to legitimacy; an anonymous or brand-new single-release package with "
    "no real repo that mimics a popular name points to a squat. (b) SOCIAL-ENGINEERING — "
    "documentation that coerces the user into unsafe actions (disable antivirus, run "
    "curl|sh, grant broad tokens), README/branding that impersonates a well-known package, "
    "or language consistent with a recent maintainer handover being abused. "
    "Verdicts: return 'malicious' only for a clear squat/impersonation or coercive "
    "install instructions; 'suspicious' when provenance is weak/ambiguous but not damning; "
    "'clean' when registry provenance and docs establish the package as a legitimate, "
    "independently-notable project despite the name resemblance. Ordinary install "
    "instructions are 'clean'. Cite the specific registry facts (publisher, repo, release "
    "count/dates) or README lines you relied on."
)


def _fmt_registry(reg) -> str:
    if reg is None or not getattr(reg, "resolved", False):
        return "Registry provenance: (unavailable — could not resolve on the registry)"
    lines = ["Registry provenance:"]
    fields = [
        ("publisher/author", getattr(reg, "author", None)),
        ("source repo", getattr(reg, "repo_url", None)),
        ("homepage", getattr(reg, "homepage", None)),
        ("summary", getattr(reg, "summary", None)),
        ("total published releases", getattr(reg, "total_releases", None)),
        ("first release", getattr(reg, "first_release_at", None)),
        ("latest release", getattr(reg, "latest_release_at", None)),
    ]
    for label, value in fields:
        if value not in (None, "", 0):
            lines.append(f"  - {label}: {value}")
    if getattr(reg, "total_releases", 0) == 0:
        lines.append("  - total published releases: 0 (no release history found)")
    return "\n".join(lines)


def _serialize(evidence) -> str:
    idn = getattr(evidence, "identity", None)
    docs = getattr(idn, "docs", []) if idn else []
    nearest = getattr(idn, "nearest_popular", None) if idn else None
    registry = getattr(idn, "registry", None) if idn else None
    status = getattr(evidence, "status", "complete")
    header = f"[evidence status: {status}]"
    if nearest:
        header += (
            f"\nStatic scanner flagged this name as a near-miss of the popular package "
            f"'{nearest}'. Determine squat vs. legitimate-shared-root using the provenance below."
        )
    return "\n\n".join(
        [
            header,
            _fmt_registry(registry),
            _fmt_items("Docs (README / SECURITY / etc.)", docs),
        ]
    )


def run(task: SpecialistTask, deps: SpecialistDeps) -> dict:
    return run_specialist(
        task,
        dimension=DIMENSION,
        system_prompt=SYSTEM_PROMPT,
        evidence_dims=EVIDENCE_DIMS,
        serialize=_serialize,
        deps=deps,
    )


def build_node(deps: SpecialistDeps):
    def node(payload) -> dict:
        return run(_coerce_task(payload), deps)

    return node
