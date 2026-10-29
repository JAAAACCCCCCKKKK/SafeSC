"""agents/specialists/identity.py — name-squatting and impersonation intent (§2.3, §4.4)."""

from safesc.agents.specialists.base import COMMON_RULES, SpecialistSpec
from safesc.core.ledger import Role
from safesc.core.signals import TrustDimension

SPEC = SpecialistSpec(
    role=Role.IDENTITY,
    tool_name="identity_analyst",
    dimension=TrustDimension.IDENTITY,
    description=(
        "IdentityAgent: decides whether a dependency is a typosquat / impersonation or a "
        "legitimate package that merely shares a name root, and whether its docs coerce users "
        "into unsafe actions. Use for identity gray-zone items (typosquat, homoglyph, repo-URL "
        "mismatch) and for any dependency whose name or publisher looks off."
    ),
    system_prompt=COMMON_RULES + """

Your dimension is IDENTITY. Judge two things.
(a) TYPOSQUAT / IMPERSONATION: when the name is a near-miss of a popular package, is this a
squat trading on that reputation, or a legitimate companion, fork, plugin or namespaced
variant? Registry provenance is your primary evidence: a reputable publisher, a real
canonical repository and a mature release history point to legitimacy; an anonymous,
brand-new, single-release package with no real repository that mimics a popular name
points to a squat.
(b) SOCIAL ENGINEERING: documentation that tells users to disable security tooling, pipe
remote scripts into a shell, or hand over broad tokens; branding that impersonates a
well-known project.
Verdicts: 'malicious' only for a clear squat/impersonation or coercive install
instructions; 'suspicious' when provenance is weak or ambiguous; 'clean' when provenance
establishes an independently notable project despite the resemblance.""",
    task_hint=(
        "Start with get_registry_metadata and inspect_docs (pass nearest_popular if a typosquat "
        "signal names one); compare against the popular package's registry facts if useful."
    ),
)
