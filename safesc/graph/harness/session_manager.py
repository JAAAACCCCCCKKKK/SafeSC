"""graph/harness/session_manager.py — run identity + distributed semaphores (§2.7.3).

Mints a lexicographically-sortable ULID `run_id` (so Redis/PGVector keys range-query by
time), and implements the §5.2 semaphores as a self-healing Redis ZSET-token pattern:
expired tokens age out via a sweep, so a dead worker never pins the semaphore. Two classes
cap the LLM budget (§5.3 backstop) and fan-out width. Redis is injected/duck-typed.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import secrets
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlparse

from safesc.graph.state import emit_degraded

logger = logging.getLogger("safesc.session")

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


def host_key(url_or_host: str) -> str:
    """Key for the §5.2 per-external-host semaphore.

    Deliberately NOT run-scoped, unlike the two above. That is the whole point: a
    registry's rate limit is a property of the registry, not of one audit, so concurrent
    audits across a fleet must share one budget per host or they will collectively trip
    it while each stays individually polite.
    """
    host = urlparse(url_or_host).netloc or url_or_host
    return f"sem:host:{host}"


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
        Caller checks `s.acquired`; over capacity → back off / degrade.

        This is the CONCURRENCY-limit shape (`sem:fanout_width`): the token is returned as
        soon as the work finishes. For the BUDGET shape (`sem:llm_budget`), use `consume`,
        which never releases — see its docstring for why the two must not share a method.
        """
        res = self.try_acquire(key, capacity, ttl_ms=ttl_ms)
        try:
            yield res
        finally:
            if res.acquired and res.token:
                self.release(key, res.token)

    def consume(self, key: str, capacity: int, *, ttl_ms: Optional[int] = None) -> SemaphoreResult:
        """Spend one unit of a *budget*: acquire a token that is never released.

        `slot` and `consume` look alike and mean opposite things. A concurrency limit asks
        "how many at once", so its token comes back; a budget asks "how many in total for
        this run", so its token must not — releasing it would let the next specialist reuse
        the same unit and the §5.3 ceiling would never bind. The key's TTL (set on
        acquire) reclaims the whole ZSET after the run, which is the correct lifetime for a
        run-scoped budget.

        Returns `acquired=False` when the ceiling is reached; the caller skips its LLM call.
        """
        return self.try_acquire(key, capacity, ttl_ms=ttl_ms)

    # ---- per-host distributed gate (§5.2), consumed by the frozen scan layer ----

    def host_gate(
        self,
        capacity: int,
        *,
        ttl_ms: int = 30_000,
        wait_timeout_s: float = 10.0,
        poll_s: float = 0.05,
    ) -> Callable[[str], object]:
        """Build the `host_gate` seam `RateLimitedSession` accepts: url → async context
        manager holding one fleet-wide token for that URL's host.

        Three properties matter here, and all three are about not breaking Stage 3:

        * **Fail-open.** If Redis errors, or the wait times out, the request proceeds
          anyway with a warning. A rate limiter that gave up would return fewer signals,
          and fewer signals read as *cleaner* — an availability problem must never be able
          to manufacture a passing audit (§8).
        * **Off the event loop.** The redis client here is synchronous, so every call goes
          through `asyncio.to_thread`; calling it inline would stall every other in-flight
          collector on the same loop.
        * **Short TTL.** 30s matches the session's own request timeout, so a worker killed
          mid-request frees its slot in seconds rather than pinning the host for every
          other audit in the fleet.
        """
        deadline_poll = max(poll_s, 0.01)

        @asynccontextmanager
        async def _gate(url: str):
            key = host_key(url)
            token: Optional[str] = None
            deadline = time.monotonic() + wait_timeout_s
            try:
                while True:
                    res = await asyncio.to_thread(self.try_acquire, key, capacity, ttl_ms=ttl_ms)
                    if res.acquired:
                        token = res.token
                        break
                    if time.monotonic() >= deadline:
                        logger.warning(
                            "host semaphore %s full for %.1fs (capacity=%d); proceeding "
                            "without a token rather than dropping the request",
                            key, wait_timeout_s, capacity,
                        )
                        break
                    await asyncio.sleep(deadline_poll)
            except Exception as exc:  # redis down / misconfigured → never block Stage 3
                logger.warning("host semaphore unavailable for %s (%s); proceeding", key, exc)
            try:
                yield
            finally:
                if token:
                    try:
                        await asyncio.to_thread(self.release, key, token)
                    except Exception:  # TTL is the backstop
                        pass

        return _gate


# =============================================================================
# Node wrappers — where the run-scoped semaphores are actually enforced (§2.7.3)
# =============================================================================


def _merge_degraded(result: dict, note: dict) -> dict:
    """Append a degraded note to a node result without clobbering notes it already has."""
    merged = dict(result or {})
    merged["degraded_notes"] = list(merged.get("degraded_notes", [])) + list(note["degraded_notes"])
    return merged


def budgeted_node(
    node_fn: Callable[..., dict],
    *,
    node_name: str,
    session,
    run_id: str,
    capacity: int,
) -> Callable[..., dict]:
    """Enforce the §5.3 LLM ceiling across parallel branches (`sem:llm_budget:{run_id}`).

    `plan_gate` already truncates fan-out to the remaining budget, but it computes that
    from `state.llm_calls` at *planning* time; under fan-out several branches can be
    in flight before any of their deltas have merged back through the `sum_deltas`
    reducer. The reducer does the in-graph accounting; this semaphore is the backstop that
    makes the ceiling hold under concurrency — exactly the division §2.7.3 describes.

    Denial skips the specialist and degrades the dimension. That is the safe direction:
    the dep keeps its static escalation and the run is marked incomplete (§2.5 — a skipped
    specialist can only lose an escalation, never manufacture a downgrade).
    """

    @functools.wraps(node_fn)
    def _node(*args, **kwargs) -> dict:
        res = session.consume(llm_budget_key(run_id), capacity)
        if not res.acquired:
            logger.warning("llm budget exhausted (capacity=%d); skipping %s", capacity, node_name)
            return emit_degraded(
                node_name,
                f"LLM budget semaphore exhausted (capacity={capacity}, holders={res.holders}): "
                f"specialist skipped; analysis incomplete",
            )
        return node_fn(*args, **kwargs)

    return _node


def fanout_limited_node(
    node_fn: Callable[..., dict],
    *,
    node_name: str,
    session,
    run_id: str,
    capacity: int,
    attempts: int = 20,
    sleep: Callable[[float], None] = time.sleep,
    delay: float = 0.25,
) -> Callable[..., dict]:
    """Cap concurrent specialist fan-out (`sem:fanout_width:{run_id}`) so one large repo
    cannot open dozens of simultaneous LLM connections and trip a provider rate limit.

    Unlike the budget wrapper this one **fails open**: after a bounded wait it runs the
    node anyway and records a degraded note. Width is a politeness constraint, not a
    correctness one — skipping the call would silently lose an escalation signal, which is
    a strictly worse outcome than briefly exceeding the intended concurrency.

    Applied OUTERMOST, so one slot is held across the whole node including auto-repair's
    retries: `fanout_limited_node → auto_repaired_node → constraint_validated`. §2.7's
    fixed inner ordering (auto-repair outside the validator) is untouched.
    """

    @functools.wraps(node_fn)
    def _node(*args, **kwargs) -> dict:
        key = fanout_width_key(run_id)
        for attempt in range(attempts):
            res = session.try_acquire(key, capacity)
            if res.acquired:
                try:
                    return node_fn(*args, **kwargs)
                finally:
                    session.release(key, res.token)
            if attempt < attempts - 1:
                sleep(delay)
        logger.warning(
            "fan-out width %d still saturated after %d attempts; running %s anyway",
            capacity, attempts, node_name,
        )
        note = emit_degraded(
            node_name,
            f"fan-out width semaphore saturated (capacity={capacity}); specialist ran "
            f"without a slot, so this run may exceed its intended concurrency",
        )
        return _merge_degraded(node_fn(*args, **kwargs), note)

    return _node
