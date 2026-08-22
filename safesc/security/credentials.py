"""security/credentials.py — Bring-Your-Own-Key (BYOK) credentials for hosted-model services (§3.5).

Bundles the caller-supplied reasoning-LLM and embedding keys into an immutable
`UserCredentials`, threaded to the graph by injection only, never through `AuditState`.
Invariants: keys are `SecretStr` (never logged/dumped), never persisted to Redis/PGVector,
and have no ambient fallback — a missing caller key is an error.
"""

from __future__ import annotations

import os
from typing import Optional

from pydantic import BaseModel, SecretStr

# There is NO default LLM provider — the caller MUST choose one (BYOK, §3.5). This map
# only supplies a default *model* once a provider has been chosen; the caller may override.
PROVIDER_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-4o",
}
DEFAULT_EMBEDDING_MODEL = "voyage-3-large"  # dimensionality follows the model (§3.2)


class LLMCredentials(BaseModel):
    """User-supplied reasoning-LLM credentials.

    `provider` selects the client/wire protocol (e.g. "anthropic", "openai"); `base_url`
    then routes that protocol to any compatible endpoint (proxy / gateway / Bedrock /
    Azure / OpenRouter / a local server). Both `provider` and `model` are caller-chosen
    (BYOK) and required — there is no default provider.
    """

    api_key: SecretStr
    provider: str  # required: no default provider — the caller must configure one
    model: str     # required: resolved per-provider in `from_request` if not pinned
    base_url: Optional[str] = None  # proxy / gateway / Bedrock-compatible endpoint

    model_config = {"frozen": True}


class EmbeddingCredentials(BaseModel):
    """User-supplied embedding-provider credentials. Separate provider ⇒ separate key
    from the LLM (Anthropic has no first-party embeddings endpoint, §3.2)."""

    api_key: SecretStr
    base_url: Optional[str] = None
    model: str = DEFAULT_EMBEDDING_MODEL

    model_config = {"frozen": True}


    @classmethod
    def from_env(cls) -> "EmbeddingCredentials":
        """Build embedding credentials alone, without an LLM key.

        The maintenance jobs (`safesc fingerprint load`, and any store operation that
        embeds) touch the §3 stores but never reason, so requiring `SAFESC_LLM_API_KEY`
        for them would force an operator to hold a reasoning key just to run a CronJob.
        `UserCredentials.from_env` remains the intake for anything that actually runs the
        graph.
        """
        key = os.environ.get("SAFESC_EMBEDDING_API_KEY")
        if not key:
            raise MissingCredentialError("SAFESC_EMBEDDING_API_KEY")
        return cls(
            api_key=SecretStr(key),
            base_url=os.environ.get("SAFESC_EMBEDDING_BASE_URL"),
            model=os.environ.get("SAFESC_EMBEDDING_MODEL") or DEFAULT_EMBEDDING_MODEL,
        )


class UserCredentials(BaseModel):
    """The full BYOK bundle for one invocation. `embedding` is optional — only needed
    when the memory layer (§3) is enabled for the run."""

    llm: LLMCredentials
    embedding: Optional[EmbeddingCredentials] = None

    model_config = {"frozen": True}

    # -- constructors: same bundle, different intake --------------------------------

    @classmethod
    def from_request(
        cls,
        *,
        llm_api_key: str,
        llm_provider: Optional[str] = None,
        llm_base_url: Optional[str] = None,
        llm_model: Optional[str] = None,
        embedding_api_key: Optional[str] = None,
        embedding_base_url: Optional[str] = None,
        embedding_model: Optional[str] = None,
    ) -> "UserCredentials":
        """Build from an HTTP request's supplied values (API path)."""
        if not llm_api_key:
            raise MissingCredentialError("llm_api_key")
        provider = (llm_provider or "").strip().lower()
        if not provider:
            # No default provider: the caller must configure one (BYOK, §3.5).
            raise MissingCredentialError("llm_provider")
        model = llm_model or PROVIDER_DEFAULT_MODELS.get(provider)
        if not model:
            # A provider with no built-in default: the caller must pin a model explicitly.
            raise MissingCredentialError(
                f"llm_model (no built-in default for provider '{provider}')"
            )
        embedding = None
        if embedding_api_key:
            embedding = EmbeddingCredentials(
                api_key=SecretStr(embedding_api_key),
                base_url=embedding_base_url,
                model=embedding_model or DEFAULT_EMBEDDING_MODEL,
            )
        return cls(
            llm=LLMCredentials(
                api_key=SecretStr(llm_api_key),
                provider=provider,
                base_url=llm_base_url,
                model=model,
            ),
            embedding=embedding,
        )

    @classmethod
    def from_env(cls, *, require_embedding: bool = False) -> "UserCredentials":
        """Build from the *caller's own* environment (CLI/CI path) — still BYOK. Reads
        SAFESC_LLM_API_KEY and SAFESC_LLM_PROVIDER (both required; no default provider),
        plus optional SAFESC_LLM_MODEL / SAFESC_LLM_BASE_URL, and — if memory is on —
        SAFESC_EMBEDDING_API_KEY (+ _BASE_URL / _MODEL)."""
        llm_key = os.environ.get("SAFESC_LLM_API_KEY")
        if not llm_key:
            raise MissingCredentialError("SAFESC_LLM_API_KEY")
        llm_provider = os.environ.get("SAFESC_LLM_PROVIDER")
        if not (llm_provider or "").strip():
            raise MissingCredentialError("SAFESC_LLM_PROVIDER")
        emb_key = os.environ.get("SAFESC_EMBEDDING_API_KEY")
        if require_embedding and not emb_key:
            raise MissingCredentialError("SAFESC_EMBEDDING_API_KEY")
        return cls.from_request(
            llm_api_key=llm_key,
            llm_provider=llm_provider,
            llm_base_url=os.environ.get("SAFESC_LLM_BASE_URL"),
            llm_model=os.environ.get("SAFESC_LLM_MODEL"),
            embedding_api_key=emb_key,
            embedding_base_url=os.environ.get("SAFESC_EMBEDDING_BASE_URL"),
            embedding_model=os.environ.get("SAFESC_EMBEDDING_MODEL"),
        )

    def require_embedding(self) -> EmbeddingCredentials:
        if self.embedding is None:
            raise MissingCredentialError("embedding (memory enabled but no embedding key supplied)")
        return self.embedding


class MissingCredentialError(RuntimeError):
    """Raised when a required BYOK key is absent. There is NO ambient fallback."""

    def __init__(self, what: str):
        super().__init__(f"missing required user-supplied credential: {what}")
        self.what = what
