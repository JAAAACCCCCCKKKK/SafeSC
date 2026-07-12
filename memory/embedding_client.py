"""
memory/embedding_client.py — the embedding provider seam, built from a user-supplied
(BYOK) key.

Called ONLY by the Memory Manager (§2.7.4) — never by a specialist or any other node
(§6.1.6). The provider (Voyage by default; OpenAI/Cohere/Google compatible via
base_url) and model are configurable; the **key is user-supplied**, matching the LLM's
BYOK model, and never enters `AuditState` or any persisted artifact.

The memory layer that consumes this is still ⛔ unbuilt (§0.1); this module exists so
that when the Memory Manager lands, its embedding calls are BYOK from day one rather
than reaching for a server-side `.env` key.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from credentials import EmbeddingCredentials

logger = logging.getLogger("depaudit.embedding")

# An embedder maps texts -> vectors. Dimensionality is fixed by the model (§3.2) and
# must match the PGVector column width for the deployment.
Embedder = Callable[[list[str]], list[list[float]]]


def make_embedding_client(creds: EmbeddingCredentials) -> Embedder:
    """Build an `Embedder` bound to the user's embedding key. Defaults to the Voyage
    SDK; a `base_url` routes to any compatible provider without code change."""
    if creds.base_url:
        return _make_openai_compatible_embedder(creds)
    return _make_voyage_embedder(creds)


def _make_voyage_embedder(creds: EmbeddingCredentials) -> Embedder:
    import voyageai  # lazy import

    client = voyageai.Client(api_key=creds.api_key.get_secret_value())

    def _embed(texts: list[str]) -> list[list[float]]:
        result = client.embed(texts, model=creds.model)
        return result.embeddings

    return _embed


def _make_openai_compatible_embedder(creds: EmbeddingCredentials) -> Embedder:
    """For providers exposed behind an OpenAI-compatible `/embeddings` endpoint
    (routed via base_url). Keeps the provider swappable per §3.2."""
    from openai import OpenAI  # lazy import

    client = OpenAI(api_key=creds.api_key.get_secret_value(), base_url=creds.base_url)

    def _embed(texts: list[str]) -> list[list[float]]:
        resp = client.embeddings.create(model=creds.model, input=texts)
        return [d.embedding for d in resp.data]

    return _embed
