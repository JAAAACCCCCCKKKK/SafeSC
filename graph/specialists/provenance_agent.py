"""graph/specialists/provenance_agent.py — source↔artifact + commit consistency (§2.3, §4.4)."""

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

DIMENSION = TrustDimension.PROVENANCE
EVIDENCE_DIMS = ("provenance",)

SYSTEM_PROMPT = (
    COMMON_SYSTEM_RULES
    + " Your dimension is PROVENANCE. Judge whether the published artifact faithfully "
    "derives from its source repository. Content present in the artifact but not "
    "traceable to source (`artifact_only_file`) is the key red flag — but weigh it: "
    "files marked likely_generated (PKG-INFO, .dist-info, build output) are normally "
    "benign, whereas injected executable code that appears only in the artifact is "
    "'malicious'. Also assess whether recent commits are consistent with the release "
    "(a version bump whose diff contains unrelated obfuscated changes is 'suspicious')."
)


def _serialize(evidence) -> str:
    p = getattr(evidence, "provenance", None)
    artifact_only = getattr(p, "artifact_only_files", []) if p else []
    commits = getattr(p, "recent_commits", []) if p else []
    status = getattr(evidence, "status", "complete")
    header = f"[evidence status: {status}]"
    return "\n\n".join(
        [header, _fmt_items("Artifact-only content (not traceable to source)", artifact_only), _fmt_items("Recent commits", commits)]
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
