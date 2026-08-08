"""security — SafeSC's credential-handling boundary.

Houses the BYOK credential model (§3.5). Kept in its own package (rather than a loose
top-level module) so the code that validates and threads user-supplied keys lives in one
clearly-named place. Re-exports the public API so callers can `from safesc.security import ...`.
"""

from __future__ import annotations

from safesc.security.credentials import (
    DEFAULT_EMBEDDING_MODEL,
    PROVIDER_DEFAULT_MODELS,
    EmbeddingCredentials,
    LLMCredentials,
    MissingCredentialError,
    UserCredentials,
)

__all__ = [
    "DEFAULT_EMBEDDING_MODEL",
    "PROVIDER_DEFAULT_MODELS",
    "EmbeddingCredentials",
    "LLMCredentials",
    "MissingCredentialError",
    "UserCredentials",
]
