"""graph/harness/session_manager.py — run identity + distributed semaphores (§2.7.3).

Mints a lexicographically-sortable ULID `run_id` (so Redis/PGVector keys range-query by
time), and implements the §5.2 semaphores as a self-healing Redis ZSET-token pattern:
expired tokens age out via a sweep, so a dead worker never pins the semaphore. Two classes
cap the LLM budget (§5.3 backstop) and fan-out width. Redis is injected/duck-typed.
"""

from __future__ import annotations

import os
import secrets
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

# Crockford base32 (no I, L, O, U) — ULID alphabet.
_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid(ms: Optional[int] = None) -> str:
    """26-char ULID: 48-bit millisecond timestamp + 80-bit randomness, both base32.
    Lexicographic order == chronological order."""
    ms = int(time.time() * 1000) if ms is None else ms
    rand = secrets.randbits(80)
    n = (ms << 80) | rand
    out = bytearray(26)
    for i in range(25, -1, -1):
        out[i] = ord(_B32[n & 0x1F])
        n >>= 5
    return out.decode()


def llm_budget_key(run_id: str) -> str:
    return f"sem:llm_budget:{run_id}"


def fanout_width_key(run_id: str) -> str:
    return f"sem:fanout_width:{run_id}"


@dataclass
class SemaphoreResult:
    acquired: bool
    token: Optional[str] = None
    holders: int = 0  # live holders observed at acquire time (after expiry sweep)


class SessionManager:
    def __init__(self, redis, *, key_ttl_ms: int = 15 * 60 * 1000):
        self.redis = redis
        self.key_ttl_ms = key_ttl_ms  # backstop TTL if release fails

    def new_run(self) -> str:
        return new_ulid()

    # ---- semaphore primitives (ZSET token pattern) ----

    def _sweep_and_count(self, key: str, now_ms: int) -> int:
        # remove tokens whose expiry score is in the past, then count survivors
        self.redis.zremrangebyscore(key, 0, now_ms)
        return int(self.redis.zcard(key))

    def try_acquire(self, key: str, capacity: int, *, ttl_ms: Optional[int] = None) -> SemaphoreResult:
        """Non-blocking acquire. Sweeps expired tokens first (self-healing), then admits
        iff live holders < capacity."""
        now = int(time.time() * 1000)
        ttl = ttl_ms or self.key_ttl_ms
        holders = self._sweep_and_count(key, now)
        if holders >= capacity:
            return SemaphoreResult(acquired=False, holders=holders)
        token = uuid.uuid4().hex
        self.redis.zadd(key, {token: now + ttl})
        # keep the whole key from outliving the run even if every token leaks
        if hasattr(self.redis, "pexpire"):
            self.redis.pexpire(key, ttl + 60_000)
        return SemaphoreResult(acquired=True, token=token, holders=holders + 1)

    def release(self, key: str, token: str) -> None:
        try:
            self.redis.zrem(key, token)
        except Exception:  # release must never crash the run; TTL is the backstop
            pass

    @contextmanager
    def slot(self, key: str, capacity: int, *, ttl_ms: Optional[int] = None):
        """Context manager: yields a SemaphoreResult and releases in `finally` if acquired.
        Caller checks `s.acquired`; over capacity → back off / degrade."""
        res = self.try_acquire(key, capacity, ttl_ms=ttl_ms)
        try:
            yield res
        finally:
            if res.acquired and res.token:
                self.release(key, res.token)
