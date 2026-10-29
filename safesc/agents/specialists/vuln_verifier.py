"""agents/specialists/vuln_verifier.py — independently verify the hunter's candidates.

A second agent, with a fresh context that never saw the hunter's reasoning or confidence,
re-reads the code behind each candidate and decides: confirmed, refuted, inconclusive, or
already publicly reported. Only a confirmed candidate becomes a signal, and its severity is
the fusion-table severity for its confidence, capped by the impact the verifier assessed
(`Signal.from_llm_output(..., ceiling=...)`) — a confirmed low-impact flaw can never fail a
gate. A candidate the verifier judges an intentional backdoor is a behaviour finding and
fuses as 'malicious'. The verifier cannot add candidates of its own.
"""

from safesc.agents.specialists.base import COMMON_RULES, SpecialistSpec
from safesc.agents.specialists.models import VerificationReport
from safesc.core.ledger import Role
from safesc.core.signals import TrustDimension

SPEC = SpecialistSpec(
    role=Role.VULN_VERIFIER,
    tool_name="vuln_verifier",
    dimension=TrustDimension.VULNERABILITY,
    output_model=VerificationReport,
    description=(
        "VulnVerifier: independently verifies every pending vulnerability candidate that "
        "vuln_hunter registered for a dependency — re-reads the code, checks reachability and "
        "exploitability, and checks whether it is already publicly reported. Must be called "
        "for every dependency with unverified candidates before the score can be finalized."
    ),
    system_prompt=COMMON_RULES + """

Your task is INDEPENDENT VERIFICATION of vulnerability candidates another agent proposed.
Treat each claim as unproven and try to REFUTE it first:
1. fetch_dependency_source, then read_source the cited file and line, and the code around
   and leading to it (callers, input validation, bounds checks, safe wrappers).
2. Decide reachability: can untrusted input actually reach this sink through the package's
   public API or its normal use? Dead code, test code and examples are not reachable.
3. Decide impact if reachable: low / medium / high / critical.
4. lookup_known_vulnerabilities for the package: if the flaw matches a published advisory,
   the status is 'already_reported' (cite the advisory id).
Statuses: 'confirmed' only when you have read the code yourself and the flaw is real and
reachable; 'refuted' when the claim is wrong or unreachable; 'inconclusive' when you cannot
tell. Set intentional_backdoor only for deliberately malicious code (hidden command
channels, credential theft, logic bombs), not for ordinary bugs. Return a verdict for
EVERY listed candidate id, citing the file:line lines you read yourself.""",
    task_hint="Start with fetch_dependency_source; then read each cited location.",
)
