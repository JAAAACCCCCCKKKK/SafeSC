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
from typing import Sequence

from depaudit.core.models import Dependency
from depaudit.signals.base import SignalCollector
from depaudit.signals.behavior.install_script import InstallScriptCollector
from depaudit.signals.identity.homoglyph import HomoglyphCollector
from depaudit.signals.identity.repo_url import RepoUrlCollector
from depaudit.signals.identity.typosquat import TyposquatCollector
from depaudit.signals.models import Signal
from depaudit.signals.popularity.archived import ArchivedRepoCollector
from depaudit.signals.provenance.http import RateLimitedSession
from depaudit.signals.provenance.insecure_url import InsecureUrlCollector
from depaudit.signals.provenance.version_published import VersionPublishedCollector
from depaudit.signals.vulnerability.osv import OsvCollector
from depaudit.signals.vulnerability.yanked import YankedVersionCollector


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


async def _safe_collect(
    collector: SignalCollector,
    dep: Dependency,
    session: RateLimitedSession,
) -> list[Signal]:
    try:
        return await collector.collect(dep, session)
    except Exception:
        # Graceful degradation: a misbehaving collector must not abort the run.
        return []


async def collect_all(
    deps: Sequence[Dependency],
    *,
    collectors: Sequence[SignalCollector] | None = None,
    per_host_concurrency: int = 10,
) -> list[Signal]:
    """Run every collector over every dependency concurrently.

    Returns a flat list of all signals.  Order is grouped by dependency, then by
    collector, but callers should not rely on ordering for correctness.
    """
    active = list(collectors) if collectors is not None else default_collectors()
    if not deps or not active:
        return []

    async with RateLimitedSession(per_host=per_host_concurrency) as session:
        tasks = [
            _safe_collect(collector, dep, session)
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
) -> list[Signal]:
    """Synchronous entry point for Stage 3 (wraps the async collect_all)."""
    return asyncio.run(
        collect_all(
            deps,
            collectors=collectors,
            per_host_concurrency=per_host_concurrency,
        )
    )
