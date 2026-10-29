"""config/llm.py — the LLM every SafeSC run requires, validated before anything starts (§3.5).

SafeSC has exactly one configuration surface for its reasoning model, three environment
variables owned by the caller (bring-your-own-key):

    LLM_PROVIDER   one of SUPPORTED_PROVIDERS (every provider Strands ships a model for
                   that authenticates with an API key)
    LLM_MODEL      a model id that provider serves
    LLM_API_KEY    the caller's key for that provider

plus two optional ones: ``LLM_BASE_URL`` for proxies, gateways and OpenAI-compatible
endpoints, and ``LLM_CONTEXT_WINDOW`` (tokens) so Strands' context manager compresses at
85% of the model's real window rather than of a 200k default.

`load_llm_config` checks them in a fixed order and raises a distinct `LLMConfigError`
subclass at the first failure, so a misconfiguration is reported as precisely as possible:

1. all three variables are present            → MissingLLMConfigError
2. the provider is one SafeSC supports         → UnsupportedProviderError
3. the model id belongs to that provider       → ModelProviderMismatchError
4. the provider endpoint (and, where it can be
   checked without a key, the model) is reachable → ModelUnreachableError
5. an authenticated probe call succeeds; its
   failure is classified as a bad key, an
   unavailable model, or an unreachable host    → InvalidAPIKeyError / ModelUnreachableError

The key is held as a `SecretStr`, scrubbed from every error message, and never written to
the ledger, memory, logs or reports (§3.5).
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping, Optional

from pydantic import SecretStr

ENV_PROVIDER = "LLM_PROVIDER"
ENV_MODEL = "LLM_MODEL"
ENV_API_KEY = "LLM_API_KEY"
ENV_BASE_URL = "LLM_BASE_URL"
ENV_CONTEXT_WINDOW = "LLM_CONTEXT_WINDOW"
REQUIRED_ENV = (ENV_PROVIDER, ENV_MODEL, ENV_API_KEY)

DEFAULT_MAX_TOKENS = 8192
REACH_TIMEOUT_S = 10.0
PROBE_TIMEOUT_S = 60.0


# =============================================================================
# Errors
# =============================================================================


class LLMConfigError(RuntimeError):
    """Base class: the configured LLM cannot be used. The CLI exits 2 on any of these."""


class MissingLLMConfigError(LLMConfigError):
    def __init__(self, missing: list[str]):
        self.missing = missing
        super().__init__(
            "missing required environment variable(s): " + ", ".join(missing)
            + f". SafeSC needs {ENV_PROVIDER}, {ENV_MODEL} and {ENV_API_KEY} to run."
        )


class UnsupportedProviderError(LLMConfigError):
    def __init__(self, provider: str):
        self.provider = provider
        super().__init__(
            f"{ENV_PROVIDER}={provider!r} is not a supported provider. "
            f"Supported: {', '.join(sorted(SUPPORTED_PROVIDERS))}."
        )


class ModelProviderMismatchError(LLMConfigError):
    pass


class ModelUnreachableError(LLMConfigError):
    pass


class InvalidAPIKeyError(LLMConfigError):
    pass


# =============================================================================
# Provider specs
# =============================================================================


def _family(model: str) -> Optional[str]:
    """The provider a model id *looks* like it belongs to, for helpful mismatch errors."""
    m = model.lower().removeprefix("models/")
    if m.startswith("claude-"):
        return "anthropic"
    if re.match(r"^(gpt-|o\d|chatgpt-|codex-)", m):
        return "openai"
    if re.match(r"^(gemini-|gemma-)", m):
        return "gemini"
    if re.match(r"^(mistral|open-mistral|open-mixtral|codestral|pixtral|ministral|magistral|devstral|voxtral)", m):
        return "mistral"
    if m.startswith("palmyra-"):
        return "writer"
    return None


def _rule(pattern: str, what: str) -> Callable[[str, Optional[str]], Optional[str]]:
    rx = re.compile(pattern, re.IGNORECASE)

    def check(model: str, _base_url: Optional[str]) -> Optional[str]:
        return None if rx.match(model) else f"expected {what}"

    return check


def _openai_rule(model: str, base_url: Optional[str]) -> Optional[str]:
    # Behind LLM_BASE_URL the OpenAI wire protocol fronts other vendors' models
    # (OpenRouter, Groq, vLLM, Azure deployments ...), so any id is legitimate there.
    if base_url:
        return None if re.match(r"^\S+$", model) else "a model id without whitespace"
    if re.match(r"^(gpt-|gpt\d|o\d|chatgpt-|codex-|computer-use-)", model, re.IGNORECASE):
        return None
    return "an OpenAI model id such as gpt-5 or o4-mini (set LLM_BASE_URL for an OpenAI-compatible endpoint)"


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    model_rule: Callable[[str, Optional[str]], Optional[str]]
    endpoint: Callable[["LLMConfig"], Optional[str]]
    build: Callable[["LLMConfig", int], Any]
    keyless: bool = False  # the provider has no auth; LLM_API_KEY is still required but unused
    example: str = ""


def _aws_region() -> str:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"


def _build_anthropic(c: "LLMConfig", max_tokens: int):
    from strands.models.anthropic import AnthropicModel

    client_args = {"api_key": c.secret()}
    if c.base_url:
        client_args["base_url"] = c.base_url
    return AnthropicModel(client_args=client_args, model_id=c.model, max_tokens=max_tokens)


def _build_openai(c: "LLMConfig", max_tokens: int):
    from strands.models.openai import OpenAIModel

    client_args = {"api_key": c.secret()}
    if c.base_url:
        client_args["base_url"] = c.base_url
    return OpenAIModel(client_args=client_args, model_id=c.model)


def _build_openai_responses(c: "LLMConfig", max_tokens: int):
    from strands.models.openai_responses import OpenAIResponsesModel

    client_args = {"api_key": c.secret()}
    if c.base_url:
        client_args["base_url"] = c.base_url
    return OpenAIResponsesModel(client_args=client_args, model_id=c.model)


def _build_bedrock(c: "LLMConfig", max_tokens: int):
    from strands.models.bedrock import BedrockModel

    return BedrockModel(
        model_id=c.model, api_key=c.secret(), region_name=_aws_region(),
        endpoint_url=c.base_url or None, max_tokens=max_tokens,
    )


def _build_gemini(c: "LLMConfig", max_tokens: int):
    from strands.models.gemini import GeminiModel

    return GeminiModel(client_args={"api_key": c.secret()}, model_id=c.model)


def _build_mistral(c: "LLMConfig", max_tokens: int):
    from strands.models.mistral import MistralModel

    client_args = {"server_url": c.base_url} if c.base_url else None
    return MistralModel(api_key=c.secret(), client_args=client_args, model_id=c.model, max_tokens=max_tokens)


def _build_litellm(c: "LLMConfig", max_tokens: int):
    from strands.models.litellm import LiteLLMModel

    client_args = {"api_key": c.secret()}
    if c.base_url:
        client_args["api_base"] = c.base_url
    return LiteLLMModel(client_args=client_args, model_id=c.model)


def _build_llamaapi(c: "LLMConfig", max_tokens: int):
    from strands.models.llamaapi import LlamaAPIModel

    client_args = {"api_key": c.secret()}
    if c.base_url:
        client_args["base_url"] = c.base_url
    return LlamaAPIModel(client_args=client_args, model_id=c.model)


def _build_ollama(c: "LLMConfig", max_tokens: int):
    from strands.models.ollama import OllamaModel

    # Local Ollama ignores auth; a hosted Ollama (e.g. ollama.com) takes the key as a bearer.
    return OllamaModel(
        c.base_url or "http://localhost:11434",
        ollama_client_args={"headers": {"Authorization": f"Bearer {c.secret()}"}},
        model_id=c.model,
    )


def _build_llamacpp(c: "LLMConfig", max_tokens: int):
    from strands.models.llamacpp import LlamaCppModel

    model = LlamaCppModel(base_url=c.base_url or "http://localhost:8080", model_id=c.model)
    # llama.cpp's server checks a bearer key only when started with --api-key.
    model.client.headers["Authorization"] = f"Bearer {c.secret()}"
    return model


def _build_writer(c: "LLMConfig", max_tokens: int):
    from strands.models.writer import WriterModel

    client_args = {"api_key": c.secret()}
    if c.base_url:
        client_args["base_url"] = c.base_url
    return WriterModel(client_args=client_args, model_id=c.model, max_tokens=max_tokens)


SUPPORTED_PROVIDERS: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        "anthropic", _rule(r"^claude-[\w.\-]+$", "a Claude model id such as claude-sonnet-5"),
        lambda c: c.base_url or "https://api.anthropic.com", _build_anthropic, example="claude-sonnet-5",
    ),
    "openai": ProviderSpec(
        "openai", _openai_rule, lambda c: c.base_url or "https://api.openai.com/v1", _build_openai,
        example="gpt-5",
    ),
    "openai_responses": ProviderSpec(
        "openai_responses", _openai_rule, lambda c: c.base_url or "https://api.openai.com/v1",
        _build_openai_responses, example="gpt-5",
    ),
    "bedrock": ProviderSpec(
        "bedrock",
        _rule(
            r"^(arn:aws[\w-]*:bedrock:[\w-]+:\d*:\S+|((us|eu|apac|ap|jp|au|ca|us-gov|global)\.)?[a-z0-9-]+\.[\w.\-:]+)$",
            "a Bedrock model or inference-profile id such as us.anthropic.claude-sonnet-5 (or an ARN)",
        ),
        lambda c: c.base_url or f"https://bedrock-runtime.{_aws_region()}.amazonaws.com", _build_bedrock,
        example="us.anthropic.claude-sonnet-5",
    ),
    "gemini": ProviderSpec(
        "gemini", _rule(r"^(models/)?(gemini|gemma|learnlm)-[\w.\-]+$", "a Gemini model id such as gemini-2.5-pro"),
        lambda c: "https://generativelanguage.googleapis.com", _build_gemini, example="gemini-2.5-pro",
    ),
    "mistral": ProviderSpec(
        "mistral",
        _rule(
            r"^(mistral|open-mistral|open-mixtral|codestral|pixtral|ministral|magistral|devstral|voxtral)[\w.\-]*$",
            "a Mistral model id such as mistral-large-latest",
        ),
        lambda c: c.base_url or "https://api.mistral.ai", _build_mistral, example="mistral-large-latest",
    ),
    "litellm": ProviderSpec(
        "litellm", _rule(r"^[\w.\-]+/\S+$", "a LiteLLM 'provider/model' id such as groq/llama-3.3-70b-versatile"),
        lambda c: c.base_url, _build_litellm, example="groq/llama-3.3-70b-versatile",
    ),
    "llamaapi": ProviderSpec(
        "llamaapi", _rule(r"^\S*llama\S*$", "a Llama API model id such as Llama-4-Maverick-17B-128E-Instruct-FP8"),
        lambda c: c.base_url or "https://api.llama.com", _build_llamaapi,
        example="Llama-4-Maverick-17B-128E-Instruct-FP8",
    ),
    "ollama": ProviderSpec(
        "ollama", _rule(r"^[\w.\-/]+(:[\w.\-]+)?$", "an Ollama model tag such as qwen3:32b"),
        lambda c: c.base_url or "http://localhost:11434", _build_ollama, keyless=True, example="qwen3:32b",
    ),
    "llamacpp": ProviderSpec(
        "llamacpp", _rule(r"^\S+$", "the model name loaded in your llama.cpp server"),
        lambda c: c.base_url or "http://localhost:8080", _build_llamacpp, keyless=True, example="default",
    ),
    "writer": ProviderSpec(
        "writer", _rule(r"^palmyra-[\w.\-]+$", "a Writer model id such as palmyra-x5"),
        lambda c: c.base_url or "https://api.writer.com", _build_writer, example="palmyra-x5",
    ),
}

# Accepted spellings → canonical provider name.
_ALIASES = {
    "openai-responses": "openai_responses", "openairesponses": "openai_responses",
    "google": "gemini", "aws": "bedrock", "amazon-bedrock": "bedrock",
    "llama-api": "llamaapi", "llama_api": "llamaapi",
    "llama.cpp": "llamacpp", "llama-cpp": "llamacpp", "llama_cpp": "llamacpp",
}

# Strands also ships a SageMaker model, but SageMaker endpoints authenticate with AWS SigV4
# credentials, not an API key, so they cannot be driven by LLM_API_KEY. Bedrock (which does
# accept API keys) is the supported route to AWS-hosted models.
UNSUPPORTED_NOTES = {
    "sagemaker": "SageMaker endpoints authenticate with AWS SigV4 credentials, not an API key; "
                 "use LLM_PROVIDER=bedrock with a Bedrock API key instead.",
}


# =============================================================================
# Validated configuration
# =============================================================================


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    api_key: SecretStr = field(repr=False)
    base_url: Optional[str] = None
    context_window: Optional[int] = None

    @property
    def spec(self) -> ProviderSpec:
        return SUPPORTED_PROVIDERS[self.provider]

    def secret(self) -> str:
        return self.api_key.get_secret_value()

    def build_model(self, *, max_tokens: int = DEFAULT_MAX_TOKENS):
        """A fresh Strands model for this provider. One per agent, so no two concurrent
        agents share client state."""
        model = self.spec.build(self, max_tokens)
        if self.context_window:
            model.update_config(context_window_limit=self.context_window)
        return model

    def describe(self) -> str:
        where = f" via {self.base_url}" if self.base_url else ""
        return f"{self.provider}/{self.model}{where}"


Probe = Callable[[LLMConfig], Awaitable[None]]
Reach = Callable[[str], Awaitable[None]]


def _env(env: Mapping[str, str], name: str) -> str:
    return (env.get(name) or "").strip()


def normalize_provider(raw: str) -> str:
    p = raw.strip().lower()
    return _ALIASES.get(p, p.replace("-", "_"))


def load_llm_config(
    env: Mapping[str, str] | None = None,
    *,
    reach: Reach | None = None,
    probe: Probe | None = None,
) -> LLMConfig:
    """Validate the caller's LLM configuration in the documented order (module docstring).

    `reach` and `probe` are injectable for tests; production uses real network checks.
    """
    env = os.environ if env is None else env

    missing = [name for name in REQUIRED_ENV if not _env(env, name)]
    if missing:
        raise MissingLLMConfigError(missing)

    raw_provider = _env(env, ENV_PROVIDER)
    provider = normalize_provider(raw_provider)
    if provider not in SUPPORTED_PROVIDERS:
        err = UnsupportedProviderError(raw_provider)
        if provider in UNSUPPORTED_NOTES:
            err.args = (f"{err.args[0]} {UNSUPPORTED_NOTES[provider]}",)
        raise err
    spec = SUPPORTED_PROVIDERS[provider]

    model = _env(env, ENV_MODEL)
    base_url = _env(env, ENV_BASE_URL) or None
    problem = spec.model_rule(model, base_url)
    if problem:
        hint = ""
        family = _family(model)
        if family and family != provider and family in SUPPORTED_PROVIDERS:
            hint = f" {model!r} looks like a model from {family} — did you mean {ENV_PROVIDER}={family}?"
        raise ModelProviderMismatchError(
            f"{ENV_MODEL}={model!r} does not match provider {provider!r}: {problem}.{hint}"
        )

    window_raw = _env(env, ENV_CONTEXT_WINDOW)
    try:
        window = int(window_raw) if window_raw else None
    except ValueError:
        raise LLMConfigError(f"{ENV_CONTEXT_WINDOW}={window_raw!r} must be a whole number of tokens") from None

    config = LLMConfig(
        provider=provider, model=model, api_key=SecretStr(_env(env, ENV_API_KEY)),
        base_url=base_url, context_window=window,
    )
    _run(_check_reachable(config, reach or _http_reach))
    _run(_check_authenticated(config, probe or _model_probe))
    return config


def _run(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


# =============================================================================
# Step 4 — reachability
# =============================================================================


async def _http_reach(url: str) -> None:
    """Any HTTP response at all means the host is reachable; only transport errors fail."""
    import httpx

    async with httpx.AsyncClient(timeout=REACH_TIMEOUT_S, follow_redirects=False) as client:
        await client.get(url)


async def _check_reachable(config: LLMConfig, reach: Reach) -> None:
    url = config.spec.endpoint(config)
    if not url:
        return  # LiteLLM without a base URL routes per model prefix; the probe covers it
    try:
        await reach(url)
    except Exception as exc:
        raise ModelUnreachableError(
            f"cannot reach the {config.provider} endpoint {url}: {_scrub(exc, config)}"
        ) from None
    if config.provider == "ollama":
        await _check_ollama_model(config, url)


async def _check_ollama_model(config: LLMConfig, url: str) -> None:
    """Ollama lists its local models without auth, so model availability is checkable
    before any generation is attempted."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=REACH_TIMEOUT_S) as client:
            resp = await client.get(url.rstrip("/") + "/api/tags")
            names = {m.get("name", "") for m in resp.json().get("models", [])}
    except Exception:
        return  # the authenticated probe will report it precisely
    wanted = config.model if ":" in config.model else f"{config.model}:latest"
    if names and config.model not in names and wanted not in names:
        raise ModelUnreachableError(
            f"Ollama at {url} does not have model {config.model!r} (available: "
            f"{', '.join(sorted(names)[:10])}). Run `ollama pull {config.model}`."
        )


# =============================================================================
# Step 5 — authenticated probe + error classification
# =============================================================================


async def _model_probe(config: LLMConfig) -> None:
    """One minimal generation through the exact Strands client SafeSC will use, stopped
    at the first streamed event of content."""
    model = config.build_model(max_tokens=16)
    messages = [{"role": "user", "content": [{"text": "Reply with the single word OK."}]}]

    async def consume() -> None:
        stream = model.stream(messages, None, None)
        try:
            async for event in stream:
                if "contentBlockDelta" in event or "messageStop" in event:
                    break
        finally:
            closer = getattr(stream, "aclose", None)
            if closer is not None:
                await closer()

    await asyncio.wait_for(consume(), timeout=PROBE_TIMEOUT_S)


_AUTH_TEXT = (
    "invalid api key", "incorrect api key", "invalid x-api-key", "api key not valid",
    "invalid_api_key", "unauthorized", "unauthenticated", "authentication",
    "permission denied", "security token", "invalid token", "forbidden",
)
_MODEL_TEXT = (
    "model not found", "model_not_found", "does not exist", "unknown model", "invalid model",
    "no such model", "model identifier is invalid", "not supported", "is not found",
    "not_found", "not found",
)
_AUTH_NAMES = {
    "AuthenticationError", "PermissionDeniedError", "UnrecognizedClientException",
    "AccessDeniedException", "InvalidSignatureException", "Unauthorized",
}


def _status_code(exc: BaseException) -> Optional[int]:
    for attr in ("status_code", "code", "status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int) and 100 <= value < 600:
            return value
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):  # botocore ClientError
        meta = resp.get("ResponseMetadata") or {}
        code = meta.get("HTTPStatusCode")
        return code if isinstance(code, int) else None
    code = getattr(resp, "status_code", None)
    return code if isinstance(code, int) else None


def _error_code(exc: BaseException) -> str:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return str((resp.get("Error") or {}).get("Code") or "")
    return ""


def classify_probe_error(exc: BaseException) -> Optional[type[LLMConfigError]]:
    """Map a provider SDK failure to the configuration error it means.

    Returns None for failures that prove the credentials were accepted (throttling).
    """
    name = type(exc).__name__
    status = _status_code(exc)
    code = _error_code(exc)
    text = str(exc).lower()

    if name == "ModelThrottledException" or status == 429 or code == "ThrottlingException":
        return None
    if status in (401, 403) or name in _AUTH_NAMES or code in _AUTH_NAMES or any(t in text for t in _AUTH_TEXT):
        return InvalidAPIKeyError
    if (
        status == 404 or name == "NotFoundError" or code in ("ResourceNotFoundException",)
        or ("model" in text and any(t in text for t in _MODEL_TEXT))
    ):
        return ModelUnreachableError
    transport = (ConnectionError, TimeoutError, asyncio.TimeoutError, OSError)
    if isinstance(exc, transport) or "connect" in name.lower() or "timeout" in name.lower():
        return ModelUnreachableError
    return LLMConfigError


async def _check_authenticated(config: LLMConfig, probe: Probe) -> None:
    try:
        await probe(config)
    except Exception as exc:
        kind = classify_probe_error(exc)
        if kind is None:
            return
        detail = _scrub(exc, config)
        if kind is InvalidAPIKeyError:
            note = " (this provider has no authentication; any non-empty LLM_API_KEY works)" if config.spec.keyless else ""
            raise InvalidAPIKeyError(
                f"{config.provider} rejected {ENV_API_KEY}{note}: {detail}"
            ) from None
        if kind is ModelUnreachableError:
            raise ModelUnreachableError(
                f"model {config.model!r} is not available from {config.provider}: {detail}"
            ) from None
        raise LLMConfigError(f"{config.provider} probe call failed: {type(exc).__name__}: {detail}") from None


def _scrub(exc: BaseException | str, config: LLMConfig) -> str:
    text = str(exc).strip().replace("\n", " ")
    key = config.secret()
    if key:
        text = text.replace(key, "***")
    if not text and not isinstance(exc, str):
        text = type(exc).__name__
    return text[:400]
