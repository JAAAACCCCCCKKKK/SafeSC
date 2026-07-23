"""graph/llm_client.py — the concrete BYOK `LLMClient` for the Stage-4 specialists.

Real implementation of the injected seam in `graph/specialists/base.py`. Each call uses
the caller's own key for their chosen provider (constructed per `UserCredentials`, never
shared). Holding the key in an injected closure (not `AuditState`) keeps it out of Redis
(§3.1).

Provider is caller-selectable (BYOK, §3.5): `LLMCredentials.provider` picks the wire
protocol, and a small registry maps that to a builder. Ships with `anthropic` and
`openai` (the latter also covers every OpenAI-compatible endpoint via `base_url` —
Azure OpenAI, OpenRouter, Together, Groq, Ollama, vLLM, a LiteLLM proxy, …). Deployments
can plug additional providers with `register_llm_provider()` without editing this module.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Callable, Optional

from credentials import LLMCredentials, UserCredentials
from graph.specialists.base import LLMClient, SpecialistDeps
from graph.state import LLMOutput

logger = logging.getLogger("safesc.llm")

# provider name (lower-case) -> factory building an LLMClient bound to the user's creds.
LLMClientFactory = Callable[[LLMCredentials], LLMClient]
_PROVIDERS: dict[str, LLMClientFactory] = {}


def register_llm_provider(name: str, factory: LLMClientFactory) -> None:
    """Register (or override) a reasoning-LLM provider. Lets a deployment add a bespoke
    provider — e.g. a custom gateway or SDK — without changing SafeSC's code."""
    _PROVIDERS[name.lower()] = factory


def supported_providers() -> list[str]:
    """The provider names `make_llm` currently accepts."""
    return sorted(_PROVIDERS)


def make_llm(creds: LLMCredentials) -> LLMClient:
    """Dispatch to the factory for `creds.provider`, honouring the caller's model choice.
    Raises a clear error naming the supported providers if the name is unknown."""
    factory = _PROVIDERS.get(creds.provider.lower())
    if factory is None:
        raise ValueError(
            f"unsupported LLM provider '{creds.provider}'. "
            f"Supported: {supported_providers()}. "
            "Register a custom one with graph.llm_client.register_llm_provider()."
        )
    return factory(creds)

_MAX_TOKENS = 1024
_JSON_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


def parse_llm_output(text: str) -> LLMOutput:
    """Extract and validate a §4.2 object from a raw model completion (pure).
    The harness constraint validator (§2.7.1) owns retry-on-reject; we just parse."""
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


def make_openai_llm(creds: LLMCredentials) -> LLMClient:
    """Build an `LLMClient` for OpenAI and any OpenAI-compatible endpoint (routed via
    `creds.base_url`). The SDK is imported lazily so this module stays importable without
    it; install the optional `openai` extra to use this provider."""
    from openai import OpenAI  # lazy: only needed at real call time

    client = OpenAI(
        api_key=creds.api_key.get_secret_value(),
        **({"base_url": creds.base_url} if creds.base_url else {}),
    )

    def _call(system: str, user: str) -> LLMOutput:
        resp = client.chat.completions.create(
            model=creds.model,
            max_tokens=_MAX_TOKENS,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        text = resp.choices[0].message.content or ""
        return parse_llm_output(text)

    return _call


# Built-in providers. Both SDKs are lazily imported inside their factory, so registering
# them here has no import cost and the core stays installable without either SDK.
register_llm_provider("anthropic", make_claude_llm)
register_llm_provider("openai", make_openai_llm)


def build_specialist_deps(
    creds: UserCredentials,
    *,
    memory_lookup=None,
    artifact_download=None,
    gather_evidence=None,
    validator=None,
) -> SpecialistDeps:
    """Assemble `SpecialistDeps` with a BYOK Claude client wired in — the single place
    the LLM key crosses into the graph, via injection, never `AuditState`. Call once
    per run at the entrypoint, then pass the deps when building specialist nodes."""
    return SpecialistDeps(
        llm=make_llm(creds.llm),
        gather_evidence=gather_evidence,
        memory_lookup=memory_lookup,
        artifact_download=artifact_download,
        validator=validator,
    )
