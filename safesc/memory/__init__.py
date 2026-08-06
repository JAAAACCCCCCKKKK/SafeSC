"""memory — the section 3 stores and the BYOK embedding seam.

Only the MemoryManager (2.7.4) reads or writes these; no graph node imports them directly
(6.1.6). Store clients are lazily constructed so the core package stays importable without
the optional `memory` extra (redis / psycopg / pgvector / langgraph-checkpoint-redis).
"""

from __future__ import annotations

from safesc.memory.embedding_client import Embedder, make_embedding_client
from safesc.memory.long_term import PGVectorConfig, PGVectorStore
from safesc.memory.short_term import RedisConfig, ShortTermStore

__all__ = [
    "Embedder",
    "make_embedding_client",
    "PGVectorConfig",
    "PGVectorStore",
    "RedisConfig",
    "ShortTermStore",
]
