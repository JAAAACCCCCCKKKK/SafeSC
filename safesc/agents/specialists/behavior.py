"""agents/specialists/behavior.py — install-time intent and deobfuscation (§2.3, §4.4)."""

from safesc.agents.specialists.base import COMMON_RULES, SpecialistSpec
from safesc.core.ledger import Role
from safesc.core.signals import TrustDimension

SPEC = SpecialistSpec(
    role=Role.BEHAVIOR,
    tool_name="behavior_analyst",
    dimension=TrustDimension.BEHAVIOR,
    description=(
        "BehaviorAgent: judges the intent of install-time code (npm lifecycle hooks, setup.py / "
        "PEP 517 builds, build.rs) and of obfuscated or dynamically-executed code — exfiltration, "
        "credential harvesting, remote payloads. Use for behavior gray-zone items and whenever "
        "a dependency runs code at install or hides logic."
    ),
    system_prompt=COMMON_RULES + """

Your dimension is BEHAVIOR. Judge whether install-time scripts and any obfuscated or
dynamically executed code show malicious intent: network exfiltration, credential or
environment harvesting, downloading or executing remote payloads, persistence, or logic
hidden behind base64/hex/eval, or behaviour conditioned on the host (CI variables,
hostname, locale, the identity of the consuming project). Benign build steps — compiling a
native extension, generating code, fetching declared assets from the project's own
official source — are 'clean'. A hook that fetches and executes remote code, or a decoded
blob that runs a shell, is 'malicious'.""",
    task_hint=(
        "Start with inspect_install_scripts; fetch_dependency_source + search_source/read_source "
        "to follow any referenced script or decoded blob to its sink."
    ),
)
