"""Unit tests for graph/llm_client.py — BYOK multi-provider selection (§3.5).

The Anthropic / OpenAI SDKs are not test dependencies; each provider factory imports its
SDK lazily, so we inject a fake module into `sys.modules` to exercise the real dispatch,
model-passing, and response-parsing paths without any network or SDK install.
"""

from __future__ import annotations

import sys
import types

import pytest

from security.credentials import LLMCredentials, UserCredentials
from graph import llm_client as lc
from graph.state import LLMOutput

_JSON = '{"task":"behavior","verdict":"suspicious","confidence":0.8,"evidence":[],"reasoning":"r"}'


def _creds(provider="anthropic", model="m-x", base_url=None):
    return LLMCredentials(api_key="secret", provider=provider, model=model, base_url=base_url)


# ---- parse ----


def test_parse_llm_output_plain():
    out = lc.parse_llm_output(_JSON)
    assert isinstance(out, LLMOutput) and out.verdict == "suspicious"


def test_parse_llm_output_strips_fence_and_prose():
    text = "Here you go:\n```json\n" + _JSON + "\n```\nthanks"
    assert lc.parse_llm_output(text).task == "behavior"


# ---- registry / dispatch ----


def test_supported_providers_has_builtins():
    assert {"anthropic", "openai"} <= set(lc.supported_providers())


def test_make_llm_unknown_provider_raises():
    with pytest.raises(ValueError) as ei:
        lc.make_llm(_creds(provider="ollama-typo"))
    assert "unsupported LLM provider" in str(ei.value)
    assert "anthropic" in str(ei.value)


def test_register_llm_provider_roundtrip():
    seen = {}

    def factory(creds):
        def _call(system, user):
            seen["model"] = creds.model
            return lc.parse_llm_output(_JSON)
        return _call

    lc.register_llm_provider("MyProvider", factory)
    try:
        assert "myprovider" in lc.supported_providers()
        client = lc.make_llm(_creds(provider="myprovider", model="custom-1"))
        assert client("sys", "usr").verdict == "suspicious"
        assert seen["model"] == "custom-1"
    finally:
        lc._PROVIDERS.pop("myprovider", None)


# ---- anthropic provider ----


def _install_fake_anthropic(monkeypatch, capture):
    block = types.SimpleNamespace(text=_JSON)
    message = types.SimpleNamespace(content=[block])

    class _Messages:
        def create(self, **kw):
            capture.update(kw)
            return message

    class Anthropic:
        def __init__(self, **kw):
            capture["init"] = kw
            self.messages = _Messages()

    mod = types.ModuleType("anthropic")
    mod.Anthropic = Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", mod)


def test_anthropic_provider_calls_messages_with_model(monkeypatch):
    cap: dict = {}
    _install_fake_anthropic(monkeypatch, cap)
    client = lc.make_llm(_creds(provider="anthropic", model="claude-x"))
    out = client("system prompt", "user prompt")
    assert out.verdict == "suspicious"
    assert cap["model"] == "claude-x"
    assert cap["system"] == "system prompt"
    assert "base_url" not in cap["init"]  # no base_url passed when unset


def test_anthropic_provider_passes_base_url(monkeypatch):
    cap: dict = {}
    _install_fake_anthropic(monkeypatch, cap)
    lc.make_llm(_creds(provider="anthropic", base_url="https://proxy.example"))("s", "u")
    assert cap["init"]["base_url"] == "https://proxy.example"


# ---- openai (and openai-compatible) provider ----


def _install_fake_openai(monkeypatch, capture):
    message = types.SimpleNamespace(content=_JSON)
    choice = types.SimpleNamespace(message=message)
    completion = types.SimpleNamespace(choices=[choice])

    class _Completions:
        def create(self, **kw):
            capture.update(kw)
            return completion

    class _Chat:
        def __init__(self):
            self.completions = _Completions()

    class OpenAI:
        def __init__(self, **kw):
            capture["init"] = kw
            self.chat = _Chat()

    mod = types.ModuleType("openai")
    mod.OpenAI = OpenAI
    monkeypatch.setitem(sys.modules, "openai", mod)


def test_openai_provider_calls_chat_completions(monkeypatch):
    cap: dict = {}
    _install_fake_openai(monkeypatch, cap)
    out = lc.make_llm(_creds(provider="openai", model="gpt-4o"))("sys", "usr")
    assert out.verdict == "suspicious"
    assert cap["model"] == "gpt-4o"
    roles = [m["role"] for m in cap["messages"]]
    assert roles == ["system", "user"]


def test_openai_compatible_endpoint_via_base_url(monkeypatch):
    cap: dict = {}
    _install_fake_openai(monkeypatch, cap)
    creds = _creds(provider="openai", model="mixtral", base_url="http://localhost:11434/v1")
    lc.make_llm(creds)("s", "u")
    assert cap["init"]["base_url"] == "http://localhost:11434/v1"


# ---- build_specialist_deps uses the selected provider ----


def test_build_specialist_deps_dispatches_by_provider(monkeypatch):
    cap: dict = {}
    _install_fake_openai(monkeypatch, cap)
    creds = UserCredentials.from_request(llm_api_key="k", llm_provider="openai", llm_model="gpt-4o")
    deps = lc.build_specialist_deps(creds)
    assert deps.llm("s", "u").verdict == "suspicious"
    assert cap["model"] == "gpt-4o"
