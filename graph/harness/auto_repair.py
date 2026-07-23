"""graph/harness/auto_repair.py — the outer infrastructure wrapper (CLAUDE.md §2.7.2).
Wraps spine tools, deep_analysis primitives, and the outer boundary of LLM nodes, retrying
ONLY transient faults (timeouts, rate limits, resets) with bounded backoff + jitter. It
never retries a semantic failure (§2.7.1 degrades; ValidationError is non-transient), so
the layers can't form a retry storm; on exhaustion the node degrades and the run continues.
"""

from __future__ import annotations

import functools
import logging
import random
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from graph.state import emit_degraded

logger = logging.getLogger("safesc.auto_repair")

# Substrings identifying transient infrastructure faults by message (SDK exception types
# aren't importable here, so we classify structurally). Extend per provider as needed.
_TRANSIENT_MARKERS = (
    "timeout", "timed out", "rate limit", "429", "too many requests",
    "connection reset", "connection aborted", "connection error", "temporarily unavailable",
    "503", "502", "504", "overloaded", "econnreset",
)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3          # total tries (1 initial + 2 retries)
    base_delay: float = 0.5        # seconds
    max_delay: float = 8.0
    jitter: float = 0.25           # fractional jitter added to each delay


def is_transient(exc: BaseException) -> bool:
    """True only for retryable infrastructure faults. Validation/semantic errors are
    explicitly NOT transient (guards against the retry-storm in §2.7.2)."""
    from graph.harness.constraint_validator import ValidationError

    if isinstance(exc, ValidationError):
        return False
    name = type(exc).__name__.lower()
    if any(m in name for m in ("timeout", "connectionerror", "connectionreseterror", "ratelimit")):
        return True
    msg = str(exc).lower()
    return any(m in msg for m in _TRANSIENT_MARKERS)


def _sleep_for(attempt: int, policy: RetryPolicy, sleep: Callable[[float], None]) -> None:
    delay = min(policy.max_delay, policy.base_delay * (2 ** attempt))
    delay *= 1.0 + random.random() * policy.jitter
    sleep(delay)


def with_retry(
    fn: Callable,
    *,
    policy: RetryPolicy = RetryPolicy(),
    transient: Callable[[BaseException], bool] = is_transient,
    sleep: Callable[[float], None] = time.sleep,
):
    """Retry a plain callable on transient faults; re-raise on exhaustion or on a
    non-transient error. Use to wrap tool calls (spine, deep_analysis) and the outer
    LLM infrastructure call."""

    @functools.wraps(fn)
    def _wrapped(*args, **kwargs):
        last: Optional[BaseException] = None
        for attempt in range(policy.max_attempts):
            try:
                return fn(*args, **kwargs)
            except BaseException as exc:  # noqa: BLE001 — re-raised below if non-transient
                if not transient(exc):
                    raise
                last = exc
                logger.warning("transient fault (attempt %d/%d): %s", attempt + 1, policy.max_attempts, exc)
                if attempt < policy.max_attempts - 1:
                    _sleep_for(attempt, policy, sleep)
        assert last is not None
        raise last

    return _wrapped


def auto_repaired_node(
    node_fn: Callable[..., dict],
    *,
    node_name: str,
    policy: RetryPolicy = RetryPolicy(),
    sleep: Callable[[float], None] = time.sleep,
) -> Callable[..., dict]:
    """Wrap a graph node so transient faults are retried and, on exhaustion, the node
    degrades (returns a degraded dict) instead of crashing the run (§8). This is the
    OUTER wrapper; compose as auto_repaired_node(constraint-validated node)."""

    retrying = with_retry(node_fn, policy=policy, sleep=sleep)

    @functools.wraps(node_fn)
    def _node(*args, **kwargs) -> dict:
        try:
            return retrying(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001
            logger.exception("node %s exhausted retries; degrading", node_name)
            return emit_degraded(node_name, f"auto-repair exhausted: {exc}")

    return _node
