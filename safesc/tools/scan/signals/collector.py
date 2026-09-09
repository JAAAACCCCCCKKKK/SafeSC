"""Stage 3 orchestrator — run all cheap-signal collectors over every dependency.

Cheap signals are a *full sweep*: every collector runs on every dependency,
concurrently, reusing the shared rate-limited session.  Each collector call is
isolated in a try/except safety net so that one failing collector (or one bad
dependency) can never crash the run — it degrades to fewer signals instead.

This stage only *emits* signals.  Scoring, gating, and Stage-4 escalation are
intentionally out of scope here and handled by a later stage.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Sequence

from safesc.tools.index.core.models import Dependency
from safesc.tools.scan.signals.base import SignalCollector
from safesc.tools.scan.signals.behavior.install_script import InstallScriptCollector
from safesc.tools.scan.signals.identity.homoglyph import HomoglyphCollector
from safesc.tools.scan.signals.identity.repo_url import RepoUrlCollector
from safesc.tools.scan.signals.identity.typosquat import TyposquatCollector
from safesc.tools.scan.signals.models import Dimension, Signal
from safesc.tools.scan.signals.popularity.archived import ArchivedRepoCollector
from safesc.tools.scan.signals.provenance.http import (
    RateLimitedSession,
    capture_fetch_failures,
)
from safesc.tools.scan.signals.provenance.insecure_url import InsecureUrlCollector
from safesc.tools.scan.signals.provenance.version_published import VersionPublishedCollector
from safesc.tools.scan.signals.vulnerability.osv import OsvCollector
from safesc.tools.scan.signals.vulnerability.yanked import YankedVersionCollector


logger = logging.getLogger(__name__)

# Reported to an ``on_error`` callback for a collector that produced an incomplete view of
# a dependency. Both mean "this collector's output is not a confirmed finding"; they are
# distinguished only so the log says which happened.
DEGRADED_EXCEPTION = "exception"
DEGRADED_FETCH = "fetch"


def default_collectors() -> list[SignalCollector]:
    """The built-in Stage 3 cheap-signal collectors, grouped by dimension."""
    return [
        # Identity
        TyposquatCollector(),
        HomoglyphCollector(),
        RepoUrlCollector(),
        # Behavior
        InstallScriptCollector(),
        # Provenance
        VersionPublishedCollector(),
        InsecureUrlCollector(),
        # Popularity
        ArchivedRepoCollector(),
        # Vulnerability
        OsvCollector(),
        YankedVersionCollector(),
    ]


# Dimensions whose collectors may have their signals reused from the short-term cache
# across runs (CLAUDE.md §3.1). The split is a property of what each dimension observes,
# not of the cache, which is why it lives here beside the collectors.
#
# Cacheable: for a *pinned* name@version these inputs are effectively immutable — the
# published artifact's install hooks and hashes, its publish timestamp, its declared repo
# URL, and its name's similarity to popular packages.
#
# NOT cacheable: vulnerability and popularity are the two that move underneath a frozen
# version. OSV advisories are filed continuously, so a cached "no known CVE" is precisely
# the stale answer that turns into a false clean; repo-archived status changes the same
# way. Both must be re-collected every run.
CACHEABLE_DIMENSIONS: frozenset[Dimension] = frozenset(
    {Dimension.IDENTITY, Dimension.BEHAVIOR, Dimension.PROVENANCE}
)


def split_collectors(
    collectors: Sequence[SignalCollector] | None = None,
) -> tuple[list[SignalCollector], list[SignalCollector]]:
    """Partition collectors into ``(cacheable, always_fresh)`` by their dimension."""
    active = list(collectors) if collectors is not None else default_collectors()
    cacheable = [c for c in active if c.dimension in CACHEABLE_DIMENSIONS]
    fresh = [c for c in active if c.dimension not in CACHEABLE_DIMENSIONS]
    return cacheable, fresh


async def _safe_collect(
    collector: SignalCollector,
    dep: Dependency,
    session: RateLimitedSession,
    on_error: Callable[[SignalCollector, Dependency, str], None] | None = None,
) -> list[Signal]:
    """Run one collector over one dependency, degrading to [] instead of raising.

    Two things can make that [] mean "I could not tell" rather than "nothing to report":
    the collector raised, or a request it made never got an answer (the collector then
    takes its ordinary ``metadata is None`` early return, so no exception is involved).
    Both are reported through *on_error*. The run still continues on fewer signals — §8
    is unchanged — but a caller that persists these signals beyond the run can now tell
    an incomplete collection from a clean one, which the cache must (CLAUDE.md §3.1).
    """
    with capture_fetch_failures() as failures:
        try:
            signals = await collector.collect(dep, session)
        except Exception as exc:
            # Graceful degradation: a misbehaving collector must not abort the run.
            logger.warning(
                "collector %s failed for %s: %s", type(collector).__name__, dep.name, exc
            )
            if on_error is not None:
                on_error(collector, dep, DEGRADED_EXCEPTION)
            return []
    if failures:
        logger.warning(
            "collector %s degraded for %s: %d unanswered request(s), first=%s",
            type(collector).__name__, dep.name, len(failures), failures[0],
        )
        if on_error is not None:
            on_error(collector, dep, DEGRADED_FETCH)
    return signals


async def collect_all(
    deps: Sequence[Dependency],
    *,
    collectors: Sequence[SignalCollector] | None = None,
    per_host_concurrency: int = 10,
    host_gate: Callable[[str], Any] | None = None,
    on_error: Callable[[SignalCollector, Dependency, str], None] | None = None,
) -> list[Signal]:
    """Run every collector over every dependency concurrently.

    Returns a flat list of all signals.  Order is grouped by dependency, then by
    collector, but callers should not rely on ordering for correctness.
    """
    active = list(collectors) if collectors is not None else default_collectors()
    if not deps or not active:
        return []

    async with RateLimitedSession(
        per_host=per_host_concurrency, host_gate=host_gate
    ) as session:
        tasks = [
            _safe_collect(collector, dep, session, on_error)
            for dep in deps
            for collector in active
        ]
        grouped = await asyncio.gather(*tasks)

    signals: list[Signal] = []
    for group in grouped:
        signals.extend(group)
    return signals


def run_collection(
    deps: Sequence[Dependency],
    *,
    collectors: Sequence[SignalCollector] | None = None,
    per_host_concurrency: int = 10,
    host_gate: Callable[[str], Any] | None = None,
    on_error: Callable[[SignalCollector, Dependency, str], None] | None = None,
) -> list[Signal]:
    """Synchronous entry point for Stage 3 (wraps the async collect_all).

    `host_gate` is the optional fleet-wide per-host limiter (§5.2); absent, limiting is
    process-local exactly as before. `on_error` (also optional) reports collectors whose
    view of a dependency was incomplete — see `_safe_collect`. Both default to absent, so
    every existing caller behaves exactly as it did.
    """
    return asyncio.run(
        collect_all(
            deps,
            collectors=collectors,
            per_host_concurrency=per_host_concurrency,
            host_gate=host_gate,
            on_error=on_error,
        )
    )
