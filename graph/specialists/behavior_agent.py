"""graph/specialists/behavior_agent.py — install-script intent + deobfuscation (§2.3, §4.4)."""

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

DIMENSION = TrustDimension.BEHAVIOR
EVIDENCE_DIMS = ("behavior",)

SYSTEM_PROMPT = (
    COMMON_SYSTEM_RULES
    + " Your dimension is BEHAVIOR. Judge whether install-time scripts and any "
    "obfuscated/dynamic-execution code show malicious intent: network exfiltration, "
    "credential/env harvesting, dropping or executing remote payloads, or hiding logic "
    "behind base64/eval. Benign build steps (compiling native extensions, fetching "
    "declared assets from official sources) are 'clean'. A postinstall hook that fetches "
    "and executes remote code, or a decoded blob that runs shell, is 'malicious'."
)


def _serialize(evidence) -> str:
    b = getattr(evidence, "behavior", None)
    scripts = getattr(b, "install_scripts", []) if b else []
    obf = getattr(b, "obfuscation_candidates", []) if b else []
    status = getattr(evidence, "status", "complete")
    header = f"[evidence status: {status}]"
    return "\n\n".join([header, _fmt_items("Install scripts", scripts), _fmt_items("Obfuscation candidates", obf)])


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
    """Return the LangGraph node for `behavior_agent` (receives a Send payload)."""
    def node(payload) -> dict:
        return run(_coerce_task(payload), deps)

    return node
