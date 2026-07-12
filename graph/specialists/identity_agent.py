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
    + " Your dimension is IDENTITY. Judge social-engineering and impersonation intent: "
    "documentation that coerces the user into unsafe actions (disable antivirus, run "
    "curl|sh, grant broad tokens), README/branding that impersonates a well-known "
    "package to trade on its reputation, or language consistent with a recent "
    "maintainer handover being used to slip in trust. The static typosquat/maintainer "
    "signals that flagged this dep are given as trigger context; use the README/SECURITY "
    "text as your evidence. Ordinary install instructions are 'clean'."
)


def _serialize(evidence) -> str:
    idn = getattr(evidence, "identity", None)
    docs = getattr(idn, "docs", []) if idn else []
    status = getattr(evidence, "status", "complete")
    return "\n\n".join([f"[evidence status: {status}]", _fmt_items("Docs (README / SECURITY / etc.)", docs)])


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
