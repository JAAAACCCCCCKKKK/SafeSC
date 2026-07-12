"""
graph/llm_client.py — the concrete `LLMClient` for the Stage-4 specialists, built from
a user-supplied (BYOK) key.

This is the real implementation of the injected seam declared in
`graph/specialists/base.py` (`LLMClient = (system, user) -> LLMOutput`). Each call is
made with the *caller's* Anthropic key — there is no shared or ambient key. The client
object is constructed per `UserCredentials`, so two concurrent requests never share a
key or an account.

Keeping the key here (in an injected closure) rather than in `AuditState` is what stops
it from being checkpointed to Redis (§3.1) — see credentials.py invariant #2.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from credentials import LLMCredentials, UserCredentials
from graph.specialists.base import LLMClient, SpecialistDeps
from graph.state import LLMOutput

logger = logging.getLogger("depaudit.llm")

_MAX_TOKENS = 1024
_JSON_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


def parse_llm_output(text: str) -> LLMOutput:
    """Extract and validate a §4.2 object from a raw model completion. Pure and
    unit-testable. The harness constraint validator (§2.7.1) owns retry-on-reject;
    here we just parse strictly."""
    cleaned = _JSON_FENCE.sub("", text).strip()
    # tolerate leading/trailing prose by grabbing the outermost JSON object
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        cleaned = cleaned[start : end + 1]
    return LLMOutput.model_validate_json(cleaned)


def make_claude_llm(creds: LLMCredentials) -> LLMClient:
    """Build an `LLMClient` bound to the user's key. The Anthropic SDK is imported
    lazily so this module (and the specialists) stay importable without it."""
    from anthropic import Anthropic  # lazy: only needed at real call time

    client = Anthropic(
        api_key=creds.api_key.get_secret_value(),
        **({"base_url": creds.base_url} if creds.base_url else {}),
    )

    def _call(system: str, user: str) -> LLMOutput:
        resp = client.messages.create(
            model=creds.model,
            max_tokens=_MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        # concatenate text blocks; structured-output enforcement is the validator's job
        text = "".join(getattr(b, "text", "") for b in resp.content)
        return parse_llm_output(text)

    return _call


def build_specialist_deps(
    creds: UserCredentials,
    *,
    memory_lookup=None,
    artifact_download=None,
    gather_evidence=None,
) -> SpecialistDeps:
    """Assemble `SpecialistDeps` with a BYOK Claude client wired in. This is the single
    place the LLM key crosses into the graph, and it crosses via injection — never via
    `AuditState`. Call it once per run at the entrypoint, then pass the deps when
    building the specialist nodes."""
    return SpecialistDeps(
        llm=make_claude_llm(creds.llm),
        gather_evidence=gather_evidence,
        memory_lookup=memory_lookup,
        artifact_download=artifact_download,
    )
