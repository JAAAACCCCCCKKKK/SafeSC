"""config/llm.py — the required LLM, validated in a fixed order before anything runs.

Network steps are injected (`reach`, `probe`), so every case here is offline. A separate
test builds every provider's real Strands client, which needs no network, to pin that the
constructor arguments SafeSC passes are ones Strands actually accepts.
"""

from __future__ import annotations

import asyncio

import pytest

from safesc.config import llm as cfg
from safesc.config.llm import (
    InvalidAPIKeyError,
    LLMConfigError,
    MissingLLMConfigError,
    ModelProviderMismatchError,
    ModelUnreachableError,
    SUPPORTED_PROVIDERS,
    UnsupportedProviderError,
    classify_probe_error,
    load_llm_config,
)


async def _ok(*_a, **_k):
    return None


def _env(provider="anthropic", model="claude-sonnet-5", key="sk-secret-123", **extra):
    env = {"LLM_PROVIDER": provider, "LLM_MODEL": model, "LLM_API_KEY": key}
    env.update(extra)
    return {k: v for k, v in env.items() if v is not None}


def _load(env, *, reach=_ok, probe=_ok):
    return load_llm_config(env, reach=reach, probe=probe)


# ------------------------------------------------------------------ step 1: presence


@pytest.mark.parametrize("missing", ["LLM_PROVIDER", "LLM_MODEL", "LLM_API_KEY"])
def test_each_variable_is_required(missing):
    env = _env()
    env[missing] = "   "
    with pytest.raises(MissingLLMConfigError) as exc:
        _load(env)
    assert exc.value.missing == [missing]


def test_presence_is_checked_before_anything_else():
    calls = []

    async def reach(url):
        calls.append(url)

    with pytest.raises(MissingLLMConfigError) as exc:
        _load({"LLM_PROVIDER": "nonsense"}, reach=reach)
    assert exc.value.missing == ["LLM_MODEL", "LLM_API_KEY"] and calls == []


# ------------------------------------------------------------------ step 2: provider


def test_unsupported_provider_lists_supported():
    with pytest.raises(UnsupportedProviderError) as exc:
        _load(_env(provider="skynet"))
    assert "anthropic" in str(exc.value) and "ollama" in str(exc.value)


def test_sagemaker_is_rejected_with_a_reason():
    with pytest.raises(UnsupportedProviderError, match="SigV4"):
        _load(_env(provider="sagemaker"))


@pytest.mark.parametrize("raw,canonical", [
    ("Anthropic", "anthropic"), ("google", "gemini"), ("openai-responses", "openai_responses"),
    ("llama.cpp", "llamacpp"), ("llama-api", "llamaapi"), ("aws", "bedrock"),
])
def test_provider_aliases(raw, canonical):
    model = {"anthropic": "claude-x", "gemini": "gemini-2.5-pro", "openai_responses": "gpt-5", "llamacpp": "m",
             "llamaapi": "Llama-4-Maverick", "bedrock": "us.anthropic.claude-sonnet-5"}[canonical]
    assert _load(_env(provider=raw, model=model)).provider == canonical


def test_every_strands_api_key_provider_is_supported():
    assert set(SUPPORTED_PROVIDERS) == {
        "anthropic", "bedrock", "gemini", "litellm", "llamaapi", "llamacpp", "mistral", "ollama",
        "openai", "openai_responses", "writer",
    }


# ------------------------------------------------------------------ step 3: model ↔ provider


@pytest.mark.parametrize("provider,good,bad", [
    ("anthropic", "claude-opus-5", "gpt-5"),
    ("openai", "o4-mini", "claude-sonnet-5"),
    ("openai_responses", "gpt-5", "gemini-2.5-pro"),
    ("bedrock", "anthropic.claude-sonnet-5-v1:0", "claude sonnet"),
    ("bedrock", "arn:aws:bedrock:us-east-1:123456789012:inference-profile/x", "no-dot-here"),
    ("gemini", "models/gemini-2.5-flash", "claude-sonnet-5"),
    ("mistral", "codestral-latest", "gpt-5"),
    ("litellm", "groq/llama-3.3-70b-versatile", "gpt-5"),
    ("llamaapi", "Llama-3.3-70B-Instruct", "gpt-5"),
    ("ollama", "qwen3:32b", "has spaces"),
    ("writer", "palmyra-x5", "gpt-5"),
])
def test_model_must_match_provider(provider, good, bad):
    assert _load(_env(provider=provider, model=good)).model == good
    with pytest.raises(ModelProviderMismatchError):
        _load(_env(provider=provider, model=bad))


def test_mismatch_suggests_the_right_provider():
    with pytest.raises(ModelProviderMismatchError, match="LLM_PROVIDER=anthropic"):
        _load(_env(provider="openai", model="claude-sonnet-5"))


def test_openai_compatible_endpoint_accepts_any_model_id():
    config = _load(_env(provider="openai", model="anthropic/claude-sonnet-5", LLM_BASE_URL="https://openrouter.ai/api/v1"))
    assert config.base_url == "https://openrouter.ai/api/v1"


def test_model_is_checked_before_the_network():
    async def reach(_url):
        raise AssertionError("must not touch the network for a mismatched model")

    with pytest.raises(ModelProviderMismatchError):
        _load(_env(provider="anthropic", model="gpt-5"), reach=reach)


# ------------------------------------------------------------------ step 4: reachability


def test_unreachable_endpoint():
    async def reach(url):
        raise ConnectionError("connection refused")

    with pytest.raises(ModelUnreachableError, match="api.anthropic.com"):
        _load(_env(), reach=reach)


def test_reachability_is_checked_before_the_key():
    probed = []

    async def reach(url):
        raise TimeoutError("timed out")

    async def probe(config):
        probed.append(config)

    with pytest.raises(ModelUnreachableError):
        _load(_env(), reach=reach, probe=probe)
    assert probed == []


def test_endpoint_follows_base_url_and_bedrock_region(monkeypatch):
    seen = []

    async def reach(url):
        seen.append(url)

    _load(_env(provider="openai", model="gpt-5", LLM_BASE_URL="https://proxy.example/v1"), reach=reach)
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    _load(_env(provider="bedrock", model="eu.anthropic.claude-sonnet-5"), reach=reach)
    assert seen == ["https://proxy.example/v1", "https://bedrock-runtime.eu-west-1.amazonaws.com"]


def test_ollama_model_presence_is_checked_without_a_key(monkeypatch):
    class Resp:
        def json(self):
            return {"models": [{"name": "llama3.2:latest"}]}

    class Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return Resp()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    assert _load(_env(provider="ollama", model="llama3.2")).model == "llama3.2"
    with pytest.raises(ModelUnreachableError, match="ollama pull qwen3:32b"):
        _load(_env(provider="ollama", model="qwen3:32b"))


# ------------------------------------------------------------------ step 5: the key


class _Http(Exception):
    def __init__(self, status, message=""):
        super().__init__(message or f"Error code: {status}")
        self.status_code = status


class AuthenticationError(Exception):
    pass


class NotFoundError(Exception):
    pass


class ModelThrottledException(Exception):
    pass


class _BotoError(Exception):
    def __init__(self, code, status, message):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}, "ResponseMetadata": {"HTTPStatusCode": status}}


@pytest.mark.parametrize("exc,expected", [
    (_Http(401, "invalid x-api-key"), InvalidAPIKeyError),
    (_Http(403), InvalidAPIKeyError),
    (AuthenticationError("Incorrect API key provided"), InvalidAPIKeyError),
    (_BotoError("UnrecognizedClientException", 403, "The security token included in the request is invalid"), InvalidAPIKeyError),
    (_Http(404, "model: claude-nope not found"), ModelUnreachableError),
    (NotFoundError("The model `gpt-9` does not exist"), ModelUnreachableError),
    (_BotoError("ValidationException", 400, "The provided model identifier is invalid."), ModelUnreachableError),
    (_Http(400, "Invalid model: mistral-nope"), ModelUnreachableError),
    (ConnectionError("dns failure"), ModelUnreachableError),
    (TimeoutError(), ModelUnreachableError),
    (ModelThrottledException("slow down"), None),
    (_Http(429, "rate limited"), None),
    (_Http(500, "upstream exploded"), LLMConfigError),
])
def test_probe_errors_are_classified(exc, expected):
    assert classify_probe_error(exc) is expected


def test_invalid_key_is_reported_and_scrubbed():
    async def probe(config):
        raise _Http(401, f"Incorrect API key provided: {config.secret()}")

    with pytest.raises(InvalidAPIKeyError) as exc:
        _load(_env(key="sk-live-very-secret"), probe=probe)
    assert "sk-live-very-secret" not in str(exc.value) and "***" in str(exc.value)


def test_throttled_probe_still_validates():
    async def probe(_config):
        raise ModelThrottledException("busy")

    assert _load(_env(), probe=probe).provider == "anthropic"


def test_key_is_never_in_repr():
    config = _load(_env(key="sk-should-not-leak"))
    assert "sk-should-not-leak" not in repr(config) and config.secret() == "sk-should-not-leak"


def test_context_window_is_optional_and_validated():
    assert _load(_env(LLM_CONTEXT_WINDOW="32000")).context_window == 32000
    with pytest.raises(LLMConfigError, match="whole number"):
        _load(_env(LLM_CONTEXT_WINDOW="lots"))


# ------------------------------------------------------------------ real Strands clients


@pytest.mark.parametrize("provider,model", [
    ("anthropic", "claude-sonnet-5"), ("openai", "gpt-5"), ("openai_responses", "gpt-5"),
    ("bedrock", "us.anthropic.claude-sonnet-5"), ("gemini", "gemini-2.5-pro"), ("mistral", "mistral-large-latest"),
    ("litellm", "groq/llama-3.3-70b-versatile"), ("llamaapi", "Llama-3.3-70B-Instruct"),
    ("ollama", "qwen3:32b"), ("llamacpp", "default"), ("writer", "palmyra-x5"),
])
def test_every_provider_builds_a_real_strands_model(provider, model):
    from strands.models.model import Model

    config = _load(_env(provider=provider, model=model, LLM_CONTEXT_WINDOW="64000"))
    built = config.build_model()
    assert isinstance(built, Model)
    assert built.get_config().get("context_window_limit") == 64000


def test_default_probe_uses_the_strands_model(monkeypatch):
    """The real probe streams one minimal generation and stops at the first content."""
    events = []

    class FakeModel:
        async def stream(self, messages, specs, system):
            events.append(messages)
            yield {"messageStart": {"role": "assistant"}}
            yield {"contentBlockDelta": {"delta": {"text": "OK"}}}
            raise AssertionError("probe must stop at the first content")

    config = _load(_env())
    monkeypatch.setattr(cfg.LLMConfig, "build_model", lambda self, max_tokens=16: FakeModel())
    asyncio.run(cfg._model_probe(config))
    assert events and "OK" in str(events[0])
