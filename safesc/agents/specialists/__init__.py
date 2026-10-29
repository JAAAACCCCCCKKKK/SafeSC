"""agents/specialists — the six Stage-4 subagents, exposed to the orchestrator as tools.

Identity, behavior and provenance cover the three trust dimensions that have genuine LLM
tasks (§2.3, §4.4); authorship, vuln_hunter and vuln_verifier extend SafeSC beyond known
advisories into account-takeover and unreported-vulnerability detection. There is still no
popularity agent: popularity and known-CVE matching stay fully deterministic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from safesc.agents.specialists import authorship, behavior, identity, provenance, vuln_hunter, vuln_verifier
from safesc.agents.specialists.base import SpecialistSpec, make_specialist_tool
from safesc.core.ledger import Role

if TYPE_CHECKING:
    from safesc.agents.context import AgentContext

SPECIALISTS: dict[Role, SpecialistSpec] = {
    spec.role: spec
    for spec in (identity.SPEC, behavior.SPEC, provenance.SPEC, authorship.SPEC, vuln_hunter.SPEC, vuln_verifier.SPEC)
}
TOOL_ROLE: dict[str, Role] = {spec.tool_name: role for role, spec in SPECIALISTS.items()}


def build_specialist_tools(ctx: "AgentContext", toolbox: Callable[[], list]) -> list:
    return [make_specialist_tool(ctx, spec, toolbox) for spec in SPECIALISTS.values()]


__all__ = ["SPECIALISTS", "TOOL_ROLE", "SpecialistSpec", "build_specialist_tools"]
