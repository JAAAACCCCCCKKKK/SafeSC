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
from contextlib import contextmanager
from typing import Callable, Optional

from safesc.security.credentials import LLMCredentials, UserCredentials
from safesc.graph.specialists.base import LLMClient, SpecialistDeps
from safesc.graph.state import LLMOutput

logger = logging.getLogger("safesc.llm")


# ── HTTP-call diagnostics ─────────────────────────────────────────────────────
# The Anthropic/OpenAI SDKs raise httpx-backed exceptions (APIStatusError,
# APIConnectionError, APITimeoutError, RateLimitError, …). Pull the request URL, HTTP
# status, and response body off them so a failed LLM call is diagnosable instead of a bare
# "auto-repair exhausted". Everything is best-effort getattr — we never import SDK types.
# NB: only the request *URL* and the response *body* are logged, never headers — the BYOK
# key travels in an Authorization/x-api-key header and must not leak into logs (§3.5).

_MAX_BODY_LOG = 800


def _http_diagnostics(exc: BaseException) -> tuple[object, object, object, str]:
    """Best-effort (status_code, method, url, response_body) from an SDK exception."""
    request = getattr(exc, "request", None)
    response = getattr(exc, "response", None)
    if request is None and response is not None:
        request = getattr(response, "request", None)

    method = getattr(request, "method", None)
    url = getattr(request, "url", None)

    status = getattr(exc, "status_code", None)
    if status is None and response is not None:
        status = getattr(response, "status_code", None)

    body: object = None
    if response is not None:
        try:
            body = response.text
        except Exception:  # pragma: no cover - defensive
            body = None
    if body is None:
        body = getattr(exc, "body", None)
    body_str = "" if body is None else str(body)
    if len(body_str) > _MAX_BODY_LOG:
        body_str = body_str[:_MAX_BODY_LOG] + " …[truncated]"

    return status, method, (str(url) if url is not None else None), body_str


@contextmanager
def _logged_llm_call(provider: str, model: str, base_url: Optional[str]):
    """Wrap a provider SDK request: log the target before, and full HTTP diagnostics
    (URL, status, response body) on failure, then re-raise for the harness to handle."""
    endpoint = base_url or "<provider default>"
    logger.info("LLM request -> provider=%s model=%s base_url=%s", provider, model, endpoint)
    try:
        yield
    except BaseException as exc:  # noqa: BLE001 — logged then re-raised unchanged
        status, method, url, body = _http_diagnostics(exc)
        logger.error(
            "LLM request FAILED -> provider=%s model=%s base_url=%s | http_status=%s "
            "request=%s %s | error_type=%s error=%s | response_body=%s",
            provider, model, endpoint, status,
            method or "?", url or "<unknown-url>",
            type(exc).__name__, exc, body or "<none>",
        )
        raise

# provider name (lower-case) -> factory building an LLMClient bound to the user's creds.
LLMClientFactory = Callable[[LLMCredentials], LLMClient]
_PROVIDERS: dict[str, LLMClientFactory] = {}

# Built-in provider -> the optional extra that ships its SDK. Used only to render an
# actionable install hint; custom providers registered via `register_llm_provider()` fall
# back to their own name.
_PROVIDER_EXTRAS = {"anthropic": "anthropic", "openai": "openai"}


class MissingProviderSDKError(RuntimeError):
    """The configured provider's SDK is not installed.

    Raised by `make_llm` (i.e. inside `build_specialist_deps`, before the graph starts),
    NOT lazily inside a specialist node. That timing is the point: a specialist raising
    ModuleNotFoundError mid-run would be caught by `auto_repaired_node`, classified
    non-transient, and turned into a degraded note — so the audit would finish, pass the
    gate, and exit 0 having never made a single LLM call. Silently downgrading to a
    deterministic-only scan while the user believes Stage 4 ran is the worst failure mode
    a security tool can have. Failing before the run starts makes it impossible.
    """


def _require_sdk(module: str, provider: str) -> None:
    """Fail fast with an install hint if the provider SDK is absent.

    Uses `importlib.util.find_spec` rather than a try/import so that an ImportError raised
    *inside* an installed-but-broken SDK is not mistaken for "not installed". An
    already-imported module is treated as present up front: `find_spec` reads a cached
    module's `__spec__` and raises `ValueError` when that attribute is `None` (as on a
    bare `types.ModuleType`, e.g. an injected test double), so checking `sys.modules`
    first both honours the injected module and sidesteps that error.
    """
    import importlib.util
    import sys

    if module in sys.modules:
        return

    if importlib.util.find_spec(module) is None:
        extra = _PROVIDER_EXTRAS.get(provider, provider)
        raise MissingProviderSDKError(
            f"provider '{provider}' needs the '{module}' package, which is part of the "
            f"optional '{extra}' extra.\n"
            f"Install it with:  pip install 'safesc[agent,{extra}]'"
        )


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
            "Register a custom one with safesc.graph.llm_client.register_llm_provider()."
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
    lazily so this module (and the specialists) stay importable without it; the
    availability check runs first so a missing SDK surfaces here, before the graph
    starts, instead of degrading a specialist mid-run (see MissingProviderSDKError)."""
    _require_sdk("anthropic", "anthropic")
    from anthropic import Anthropic  # lazy: only needed at real call time

    client = Anthropic(
        api_key=creds.api_key.get_secret_value(),
        **({"base_url": creds.base_url} if creds.base_url else {}),
    )

    def _call(system: str, user: str) -> LLMOutput:
        with _logged_llm_call("anthropic", creds.model, creds.base_url):
            resp = client.messages.create(
                model=creds.model,
                max_tokens=_MAX_TOKENS,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        logger.debug(
            "LLM response <- provider=anthropic model=%s stop_reason=%s usage=%s",
            creds.model, getattr(resp, "stop_reason", None), getattr(resp, "usage", None),
        )
        # concatenate text blocks; structured-output enforcement is the validator's job
        text = "".join(getattr(b, "text", "") for b in resp.content)
        return parse_llm_output(text)

    return _call


def make_openai_llm(creds: LLMCredentials) -> LLMClient:
    """Build an `LLMClient` for OpenAI and any OpenAI-compatible endpoint (routed via
    `creds.base_url`). The SDK is imported lazily so this module stays importable without
    it; the availability check runs first so a missing SDK fails before the run rather
    than degrading a specialist mid-run (see MissingProviderSDKError)."""
    _require_sdk("openai", "openai")
    from openai import OpenAI  # lazy: only needed at real call time

    client = OpenAI(
        api_key=creds.api_key.get_secret_value(),
        **({"base_url": creds.base_url} if creds.base_url else {}),
    )

    def _call(system: str, user: str) -> LLMOutput:
        with _logged_llm_call("openai", creds.model, creds.base_url):
            resp = client.chat.completions.create(
                model=creds.model,
                max_tokens=_MAX_TOKENS,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
        choice = resp.choices[0] if getattr(resp, "choices", None) else None
        logger.debug(
            "LLM response <- provider=openai model=%s finish_reason=%s usage=%s",
            creds.model, getattr(choice, "finish_reason", None), getattr(resp, "usage", None),
        )
        text = (getattr(getattr(choice, "message", None), "content", None) or "") if choice else ""
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
    """Assemble `SpecialistDeps` with a BYOK LLM client for the caller's configured
    provider — the single place the LLM key crosses into the graph, via injection, never
    `AuditState`. Call once per run at the entrypoint, then pass the deps when building
    specialist nodes. Raises `MissingProviderSDKError` here (before the graph runs) if the
    configured provider's SDK is not installed."""
    return SpecialistDeps(
        llm=make_llm(creds.llm),
        gather_evidence=gather_evidence,
        memory_lookup=memory_lookup,
        artifact_download=artifact_download,
        validator=validator,
    )