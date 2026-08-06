"""graph/specialists — the Stage-4 LLM specialists (CLAUDE.md §2.3).

Only identity/behavior/provenance exist here; popularity/vulnerability are deterministic
(§4.4). Each module exposes ``run(task, deps)`` and ``build_node(deps)``. ``add_specialists``
registers each node under its ``SPECIALIST_NODE`` name and wires it to the report node.
"""

from __future__ import annotations

from safesc.graph.spine import NODE_REPORT, SPECIALIST_NODE
from safesc.graph.specialists import behavior_agent, identity_agent, provenance_agent
from safesc.graph.specialists.base import SpecialistDeps, run_specialist
from safesc.graph.state import TrustDimension

# The single source of truth mapping a trust dimension to its specialist module.
SPECIALIST_MODULES = {
    TrustDimension.IDENTITY: identity_agent,
    TrustDimension.BEHAVIOR: behavior_agent,
    TrustDimension.PROVENANCE: provenance_agent,
}


def build_specialist_node(dimension: TrustDimension, deps: SpecialistDeps):
    """Return the LangGraph node callable for one specialist dimension."""
    return SPECIALIST_MODULES[dimension].build_node(deps)


def add_specialists(builder, deps: SpecialistDeps) -> list[str]:
    """Add the three specialist nodes and wire each forward to the report node.
    Names match ``spine.SPECIALIST_NODE`` so the gate edges land here. Returns the names."""
    added: list[str] = []
    for dimension, module in SPECIALIST_MODULES.items():
        node_name = SPECIALIST_NODE[dimension]
        builder.add_node(node_name, module.build_node(deps))
        builder.add_edge(node_name, NODE_REPORT)
        added.append(node_name)
    return added


__all__ = [
    "SpecialistDeps",
    "run_specialist",
    "SPECIALIST_MODULES",
    "build_specialist_node",
    "add_specialists",
    "behavior_agent",
    "identity_agent",
    "provenance_agent",
]
