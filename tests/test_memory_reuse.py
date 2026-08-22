"""Unit tests for reusing prior analysis (CLAUDE.md §3.1, §3.2, §2.7.4).

Two independent reuse paths are covered:

1. **Exact-artifact recall** — what `report_agent` persisted must be findable by the
   specialist that looks it up next time. Historically it was not: the write path keyed on
   `artifact_id` (`ecosystem:name@version+hash`) while the read path passed the bare
   `dep_key` (`ecosystem:name@version`), so every hashed dependency — i.e. essentially all
   of them — missed its own record. `make_task_lookup` closes that.

2. **Cross-run cheap-signal reuse** — the §3.1 hot cache lets a second audit skip the
   collectors whose answers cannot have changed for a pinned `name@version`, while the
   vulnerability/popularity collectors still run every time.

Everything here is offline: fake stores, fake collectors, no network and no key.
"""

from __future__ import annotations

import json
from pathlib import Path

from safesc.graph.harness.memory_manager import MemoryManager, artifact_id
from safesc.graph.spine import _cached_collect_signals, _signal_cache_key
from safesc.graph.specialists.base import SpecialistDeps, run_specialist
from safesc.graph.state import (
    AuditState,
    Dependency,
    GateDecision,
    LLMOutput,
    Severity,
    Signal,
    SignalOrigin,
    TrustDimension,
    dep_key,
)
from safesc.graph.spine import SpecialistTask
from safesc.memory.short_term import RedisConfig, ShortTermStore


def _dep(hash_="sha256:deadbeef") -> Dependency:
    return Dependency(
        name="evil-pkg", version="1.2.3", ecosystem="npm",
        lockfile_path=Path("package-lock.json"), hash=hash_,
    )


class FakeRedis:
    def __init__(self):
        self.kv: dict[str, str] = {}
        self.ttl: dict[str, int] = {}

    def get(self, name):
        return self.kv.get(name)

    def set(self, name, value, ex=None):
        self.kv[name] = value
        if ex is not None:
            self.ttl[name] = ex


class FakeVector:
    def __init__(self, hits=()):
        self.rows: dict[str, dict] = {}
        self.hits = list(hits)
        self.queries: list[str] = []

    def get(self, key):
        return self.rows.get(key)

    def upsert(self, key, embedding, record):
        self.rows[key] = {**record, "artifact_id": key}

    def query_similar(self, embedding, k):
        self.queries.append(embedding)
        return self.hits[:k]


def _embedder(texts):
    # Deterministic stand-in: the text itself, so a test can assert on what was embedded.
    return [list(t) and t for t in texts]


# ============================================================ 1. exact-artifact recall


def _persisted_manager() -> tuple[MemoryManager, FakeRedis, Dependency]:
    dep = _dep()
    redis = FakeRedis()
    mgr = MemoryManager(redis=redis)
    state = AuditState(target=".", dependencies=[dep])
    state.signals.append(
        Signal(
            dep_key=dep_key(dep), dimension=TrustDimension.BEHAVIOR, origin=SignalOrigin.STATIC,
            source="stage3.install_script", severity=Severity.HIGH,
            summary="npm lifecycle hook present",
        )
    )
    gate = GateDecision(per_dep={dep_key(dep): Severity.HIGH}, overall=Severity.HIGH,
                        passed=False, exit_code=1)
    mgr.persist(state, gate)
    return mgr, redis, dep


def test_persisted_record_is_found_by_the_task_lookup():
    """The regression: a specialist must retrieve the record its own run wrote."""
    mgr, _redis, dep = _persisted_manager()
    task = SpecialistTask(
        dep_key=dep_key(dep), dependency=dep, dimension=TrustDimension.BEHAVIOR,
        trigger_severity=Severity.HIGH, trigger_sources=["stage3.install_script"],
    )
    findings = mgr.make_task_lookup()(dep_key(dep), task=task)
    assert findings, "exact-hash prior was written but not retrieved"
    assert "exact-hash prior" in findings[0]
    assert "npm lifecycle hook" in findings[0]


def test_dep_key_lookup_would_have_missed_the_hashed_record():
    """Documents *why* the task form exists: the two keys genuinely differ."""
    mgr, _redis, dep = _persisted_manager()
    assert artifact_id(dep) != dep_key(dep)
    assert mgr.make_lookup(lambda dk: (dk, ""))(dep_key(dep)) == []


def test_task_lookup_queries_the_vector_store_with_behavioural_text():
    """The similarity query must describe behaviour, not the package name — name
    similarity is the identity dimension's deterministic job (§4.4)."""
    dep = _dep()
    vector = FakeVector()
    mgr = MemoryManager(redis=FakeRedis(), vector=vector, embedder=_embedder)
    task = SpecialistTask(
        dep_key=dep_key(dep), dependency=dep, dimension=TrustDimension.BEHAVIOR,
        trigger_severity=Severity.HIGH, trigger_sources=["stage3.install_script"],
        trigger_evidence=["hook=postinstall", "script=node ./setup.js"],
    )
    mgr.make_task_lookup()(dep_key(dep), task=task)
    assert vector.queries, "no similarity query was issued"
    query = vector.queries[0]
    assert "install_script" in query and "postinstall" in query
    assert "evil-pkg@1.2.3" not in query


def test_task_lookup_degrades_when_given_no_task():
    mgr = MemoryManager(redis=FakeRedis())
    assert mgr.make_task_lookup()("npm:whatever@1.0.0") == []


def test_specialist_offers_the_task_as_a_keyword_and_legacy_fakes_still_work():
    """`run_specialist` widens the seam the same way it widens `gather(...)`, so both
    shapes must work — the legacy one keeps every existing fake valid.

    The task travels as a *keyword* on purpose: a one-argument legacy lookup would accept
    a task passed positionally and silently receive the wrong type, while an unexpected
    keyword raises TypeError and takes the fallback path cleanly.
    """
    dep = _dep()
    task = SpecialistTask(
        dep_key=dep_key(dep), dependency=dep, dimension=TrustDimension.BEHAVIOR,
        trigger_severity=Severity.MEDIUM,
    )
    seen: dict[str, object] = {}

    def _run(lookup):
        deps = SpecialistDeps(
            llm=lambda sys_p, user_p: LLMOutput(
                task="behavior", verdict="clean", confidence=0.9, evidence=[], reasoning="fine",
            ),
            gather_evidence=lambda *a, **k: object(),
            memory_lookup=lookup,
        )
        return run_specialist(
            task, dimension=TrustDimension.BEHAVIOR, system_prompt="sys",
            evidence_dims=("behavior",), serialize=lambda ev: "evidence", deps=deps,
        )

    def task_lookup(dk, *, task=None):
        seen["task"] = task
        seen["task_key"] = dk
        return ["[exact-hash prior] severity=3 — seen before"]

    def legacy_lookup(dk: str):
        seen["legacy"] = dk
        return ["[exact-hash prior] severity=3 — seen before"]

    _run(task_lookup)
    assert seen["task"] is task
    assert seen["task_key"] == dep_key(dep)

    _run(legacy_lookup)
    assert seen["legacy"] == dep_key(dep)


# ============================================================ 2. cheap-signal reuse


def _sig(dimension: TrustDimension, source: str) -> Signal:
    return Signal(
        dep_key="npm:evil-pkg@1.2.3", dimension=dimension, origin=SignalOrigin.STATIC,
        source=source, severity=Severity.LOW, summary=source,
    )


_CACHEABLE = frozenset({TrustDimension.IDENTITY, TrustDimension.BEHAVIOR, TrustDimension.PROVENANCE})

_ALL = [
    _sig(TrustDimension.IDENTITY, "stage3.typosquat"),
    _sig(TrustDimension.BEHAVIOR, "stage3.install_script"),
    _sig(TrustDimension.VULNERABILITY, "stage3.osv"),
    _sig(TrustDimension.POPULARITY, "stage3.archived"),
]
_FRESH = [s for s in _ALL if s.dimension not in _CACHEABLE]


def _run_cached(cache, calls: dict):
    def run_all(dep):
        calls["all"] = calls.get("all", 0) + 1
        return list(_ALL)

    def run_fresh(dep):
        calls["fresh"] = calls.get("fresh", 0) + 1
        return list(_FRESH)

    return _cached_collect_signals(
        _dep(), cache=cache, run_all=run_all, run_fresh=run_fresh, cacheable_dims=_CACHEABLE,
    )


def test_cache_key_is_the_pinned_artifact_not_the_repo():
    assert _signal_cache_key(_dep()) == "sig:v1:npm:evil-pkg@1.2.3"


def test_miss_runs_everything_and_stores_only_the_cacheable_dimensions():
    store = ShortTermStore(FakeRedis(), RedisConfig())
    calls: dict = {}
    out = _run_cached(store, calls)
    assert calls == {"all": 1}
    assert len(out) == 4
    stored = store.cache_get(_signal_cache_key(_dep()))
    assert {s["dimension"] for s in stored} == {"identity", "behavior"}
    assert not any(s["dimension"] in ("vulnerability", "popularity") for s in stored)


def test_hit_reuses_cacheable_signals_and_still_refetches_the_volatile_ones():
    store = ShortTermStore(FakeRedis(), RedisConfig())
    _run_cached(store, {})            # populate
    calls: dict = {}
    out = _run_cached(store, calls)
    assert calls == {"fresh": 1}, "a cache hit must not re-run the cacheable collectors"
    dims = {s.dimension for s in out}
    assert TrustDimension.IDENTITY in dims and TrustDimension.BEHAVIOR in dims
    # the volatile dimensions are present because they were re-collected, not cached
    assert TrustDimension.VULNERABILITY in dims and TrustDimension.POPULARITY in dims


def test_vulnerability_signals_are_never_written_to_the_cache():
    """A cached 'no known CVE' is exactly the stale answer that becomes a false clean."""
    store = ShortTermStore(FakeRedis(), RedisConfig())
    _run_cached(store, {})
    raw = store.cache_get(_signal_cache_key(_dep()))
    assert all(s["dimension"] != "vulnerability" for s in raw)


def test_unreachable_cache_falls_through_to_a_full_collection():
    class ExplodingCache:
        def cache_get(self, key):
            raise ConnectionError("redis is down")

        def cache_set(self, key, value, ttl=None):
            raise ConnectionError("redis is down")

    calls: dict = {}
    out = _run_cached(ExplodingCache(), calls)
    assert calls == {"all": 1}
    assert len(out) == 4, "a broken cache must never shrink the signal set"


def test_corrupt_cache_entry_falls_through_to_a_full_collection():
    redis = FakeRedis()
    store = ShortTermStore(redis, RedisConfig())
    redis.kv["cache:" + _signal_cache_key(_dep())] = json.dumps([{"not": "a signal"}])
    calls: dict = {}
    out = _run_cached(store, calls)
    assert calls == {"all": 1}
    assert len(out) == 4
