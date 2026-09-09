"""Unit tests for caller-chosen LLM provider/model plumbing in credentials.py (§3.5).

There is NO default provider — the caller must configure one; a missing provider is a
hard error (mirrors the missing-key rule).
"""

from __future__ import annotations

import pytest

from safesc.security.credentials import (
    EmbeddingCredentials,
    MissingCredentialError,
    PROVIDER_DEFAULT_MODELS,
    UserCredentials,
)


def test_missing_provider_is_an_error():
    with pytest.raises(MissingCredentialError) as ei:
        UserCredentials.from_request(llm_api_key="k")
    assert "llm_provider" in str(ei.value)


def test_blank_provider_is_an_error():
    with pytest.raises(MissingCredentialError):
        UserCredentials.from_request(llm_api_key="k", llm_provider="   ")


def test_explicit_provider_uses_provider_default_model():
    c = UserCredentials.from_request(llm_api_key="k", llm_provider="openai")
    assert c.llm.provider == "openai"
    assert c.llm.model == PROVIDER_DEFAULT_MODELS["openai"]


def test_anthropic_provider_default_model():
    c = UserCredentials.from_request(llm_api_key="k", llm_provider="anthropic")
    assert c.llm.model == PROVIDER_DEFAULT_MODELS["anthropic"]


def test_provider_is_normalised_lowercase():
    c = UserCredentials.from_request(llm_api_key="k", llm_provider="OpenAI")
    assert c.llm.provider == "openai"


def test_explicit_model_wins():
    c = UserCredentials.from_request(llm_api_key="k", llm_provider="openai", llm_model="gpt-4o-mini")
    assert c.llm.model == "gpt-4o-mini"


def test_unknown_provider_requires_explicit_model():
    with pytest.raises(MissingCredentialError):
        UserCredentials.from_request(llm_api_key="k", llm_provider="my-gateway")


def test_unknown_provider_ok_with_explicit_model():
    c = UserCredentials.from_request(llm_api_key="k", llm_provider="my-gateway", llm_model="llama-3.1")
    assert c.llm.provider == "my-gateway" and c.llm.model == "llama-3.1"


def test_from_env_requires_provider(monkeypatch):
    monkeypatch.setenv("SAFESC_LLM_API_KEY", "k")
    monkeypatch.delenv("SAFESC_LLM_PROVIDER", raising=False)
    with pytest.raises(MissingCredentialError) as ei:
        UserCredentials.from_env()
    assert "SAFESC_LLM_PROVIDER" in str(ei.value)


def test_from_env_reads_provider(monkeypatch):
    monkeypatch.setenv("SAFESC_LLM_API_KEY", "k")
    monkeypatch.setenv("SAFESC_LLM_PROVIDER", "openai")
    monkeypatch.setenv("SAFESC_LLM_MODEL", "gpt-4o")
    c = UserCredentials.from_env()
    assert c.llm.provider == "openai" and c.llm.model == "gpt-4o"


def test_base_url_threads_through():
    c = UserCredentials.from_request(llm_api_key="k", llm_provider="anthropic", llm_base_url="https://gw.example")
    assert c.llm.base_url == "https://gw.example"


def test_api_key_never_leaks_in_dump():
    c = UserCredentials.from_request(llm_api_key="super-secret-key", llm_provider="openai")
    assert "super-secret-key" not in c.model_dump_json()
    assert "super-secret-key" not in str(c)

def test_keys_are_stripped_at_intake():
    c = UserCredentials.from_request(
        llm_api_key="sk-abc\n",
        llm_provider=" Anthropic \n",
        llm_model="  ",
        embedding_api_key="pa-xyz\r\n",
        embedding_model="\tvoyage-4-large\n",
    )
    assert c.llm.api_key.get_secret_value() == "sk-abc"
    assert c.llm.provider == "anthropic"
    assert c.llm.model == PROVIDER_DEFAULT_MODELS["anthropic"]  # blank model -> default
    assert c.embedding.api_key.get_secret_value() == "pa-xyz"
    assert c.embedding.model == "voyage-4-large"


def test_embedding_key_is_stripped_from_env(monkeypatch):
    monkeypatch.setenv("SAFESC_EMBEDDING_API_KEY", "pa-xyz\n")
    monkeypatch.setenv("SAFESC_EMBEDDING_BASE_URL", "")
    monkeypatch.delenv("SAFESC_EMBEDDING_MODEL", raising=False)
    c = EmbeddingCredentials.from_env()
    assert c.api_key.get_secret_value() == "pa-xyz"
    assert c.base_url is None  # a blank env var is absence, not an empty base URL


def test_whitespace_only_key_reads_as_missing(monkeypatch):
    """Not "a key that happens to be blank" — there is no ambient fallback (§3.5)."""
    monkeypatch.setenv("SAFESC_LLM_API_KEY", "   \n")
    monkeypatch.setenv("SAFESC_LLM_PROVIDER", "anthropic")
    with pytest.raises(MissingCredentialError) as ei:
        UserCredentials.from_env()
    assert "SAFESC_LLM_API_KEY" in str(ei.value)
