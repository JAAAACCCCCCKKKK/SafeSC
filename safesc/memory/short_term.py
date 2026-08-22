"""memory/short_term.py — the Redis short-term store (CLAUDE.md §3.1).

Redis backs three short-term concerns, all keyed by the ULID `run_id` where relevant:
  1. the LangGraph **checkpointer** (mid-run state survives node retries / enables resume),
  2. the **hot cache** for in-flight tool results and cross-run cheap-signal reuse (TTL 7d),
  3. the **distributed semaphore** store the SessionManager drives (§2.7.3, §5.2).

This module is a thin, injectable wrapper around a duck-typed redis client — it is *the*
object passed as `redis=` to both the MemoryManager (`get`/`set`) and the SessionManager
(ZSET ops), so the harness never imports a store client directly (§6.1.6). The real client
is built lazily by `from_url`; tests inject a fake with the same surface. No audit logic
and no decisions live here.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger("safesc.memory.short_term")

DEFAULT_HOT_TTL_S = 7 * 24 * 3600  # §3.1 cross-run cheap-signal reuse window


@dataclass
class RedisConfig:
    url: str = "redis://localhost:6379/0"
    hot_ttl_s: int = DEFAULT_HOT_TTL_S
    cache_prefix: str = "cache:"          # hot tool-result / cheap-signal namespace
    socket_timeout_s: float = 5.0


class ShortTermStore:
    """Injectable Redis seam. Delegates the exact method surface the MemoryManager and
    SessionManager rely on; anything else falls through to the underlying client via
    ``__getattr__`` so the ZSET semaphore primitives keep working unchanged."""

    def __init__(self, client: Any, config: Optional[RedisConfig] = None):
        self._client = client
        self.config = config or RedisConfig()

    # ------------------------------------------------------------------ construction

    @classmethod
    def from_url(cls, config: Optional[RedisConfig] = None) -> "ShortTermStore":
        """Build a real redis-py client. Lazy import keeps `redis` an optional
        deployment dependency (the core stays importable without it)."""
        config = config or RedisConfig()
        try:
            import redis  # lazy: optional dependency
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "redis is not installed; install the 'memory' extra to use ShortTermStore"
            ) from exc
        # decode_responses=True → get() returns str, matching MemoryManager's json.loads
        client = redis.Redis.from_url(
            config.url, decode_responses=True, socket_timeout=config.socket_timeout_s
        )
        return cls(client, config)

    @property
    def client(self) -> Any:
        return self._client

    # ------------------------------------------------------------------ MemoryManager surface

    def get(self, name: str) -> Optional[str]:
        return self._client.get(name)

    def set(self, name: str, value: str, ex: Optional[int] = None) -> None:
        self._client.set(name, value, ex=ex)

    # ------------------------------------------------------------------ hot cache (§3.1)

    def cache_get(self, key: str) -> Optional[Any]:
        """Fetch a JSON-serialised hot-cache entry (tool result / cheap-signal reuse)."""
        raw = self._client.get(self.config.cache_prefix + key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            logger.warning("corrupt hot-cache entry at %s; ignoring", key)
            return None

    def cache_set(self, key: str, value: Any, ttl_s: Optional[int] = None) -> None:
        ttl = self.config.hot_ttl_s if ttl_s is None else ttl_s
        self._client.set(self.config.cache_prefix + key, json.dumps(value), ex=ttl)

    # ------------------------------------------------------------------ checkpointer (§3.1)

    def checkpointer(self):
        """Return a LangGraph Redis checkpointer bound to the same instance. Lazy import
        keeps langgraph-checkpoint-redis an optional deployment dependency.

        Two shapes have to be tolerated. Across `langgraph-checkpoint-redis` releases
        `from_conn_string` returns either the saver directly or a *context manager*
        yielding it; and the saver's Redis-side indices only exist after `setup()`.
        Neither is stable enough to assume, so both are probed. The context manager is
        deliberately entered without a matching `__exit__` — the saver must outlive this
        call for the whole graph run, and the process is finite (§1.3), so the connection
        is reclaimed at exit. `close()` on the store does not own it."""
        try:
            from langgraph.checkpoint.redis import RedisSaver  # lazy, optional
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "langgraph-checkpoint-redis is not installed; install the 'memory' extra "
                "to enable checkpointing"
            ) from exc

        saver = RedisSaver.from_conn_string(self.config.url)
        enter = getattr(saver, "__enter__", None)
        if enter is not None:
            saver = enter()
        setup = getattr(saver, "setup", None)
        if callable(setup):
            setup()  # idempotent: creates the checkpoint indices if absent
        return saver

    # ------------------------------------------------------------------ lifecycle

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception as exc:  # pragma: no cover - connectivity check
            logger.warning("redis ping failed: %s", exc)
            return False

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()

    # ------------------------------------------------------------------ ZSET passthrough

    def __getattr__(self, name: str) -> Any:
        """Delegate the ZSET semaphore primitives (zadd, zremrangebyscore, zcard, zrem,
        pexpire, …) and any other client method to the wrapped client. Only reached for
        attributes not defined above, so `get`/`set` keep their JSON-friendly wrappers."""
        return getattr(self._client, name)
