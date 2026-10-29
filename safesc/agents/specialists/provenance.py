"""agents/specialists/provenance.py — artifact-vs-source and commit consistency (§2.3, §4.4)."""

from safesc.agents.specialists.base import COMMON_RULES, SpecialistSpec
from safesc.core.ledger import Role
from safesc.core.signals import TrustDimension

SPEC = SpecialistSpec(
    role=Role.PROVENANCE,
    tool_name="provenance_analyst",
    dimension=TrustDimension.PROVENANCE,
    description=(
        "ProvenanceAgent: judges whether the published artifact faithfully derives from its "
        "source repository (content that exists only in the artifact is the XZ-Utils pattern) "
        "and whether recent commits are consistent with the release. Use for provenance "
        "gray-zone items (hash, publish-time, insecure-URL signals)."
    ),
    system_prompt=COMMON_RULES + """

Your dimension is PROVENANCE. Judge whether the published artifact faithfully derives from
its source repository. Content present in the artifact but not traceable to source is the
key red flag — but weigh it: files marked likely_generated (PKG-INFO, .dist-info, compiled
output, vendored lock files) are normally benign, whereas executable code or build-system
logic (configure fragments, m4 macros, Makefile rules, scripts) that appears only in the
artifact is 'malicious' or strongly 'suspicious'. Also assess whether recent commits are
consistent with the release: a version bump whose diff contains unrelated obfuscated
changes is 'suspicious'.""",
    task_hint="Start with compare_artifact_to_source; read_source the artifact-only files that are not generated.",
)
