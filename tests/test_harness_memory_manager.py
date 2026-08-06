"""Unit tests for graph/harness/memory_manager.py (§2.7.4).

Fakes stand in for Redis / PGVector / embedder. Covers the read snapshot (exact + similar,
prompt-only), the narrow write scope, max-wins-with-anomaly on collision, the lookup
adapter, best-effort failure handling, and gc delegation.
"""

from __future__ import annotations

import json

from safesc.graph.harness import memory_manager as mm
from safesc.graph.harness.memory_manager import MemoryConfig, MemoryContext, MemoryManager, artifact_id
from safesc.graph.state import (
    AuditState,
    GateDecision,
    Severity,
    Signal,
    SignalOrigin,
    TrustDimension,
)
from safesc.tools.index.core.models import Dependency


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, k):
        return self.store.get(k)

    def set(self, k, v, ex=None):
        self.store[k] = v


class FakeVector:
    def __init__(self, hits=None):
        self.hits = hits or []
        self.upserts = []
        self.records = {}
        self.gc_called = False

    def query_similar(self, vec, k):
        return self.hits[:k]

    def upsert(self, key, vec, record):
        self.upserts.append((key, record))
        self.records[key] = record

    def get(self, key):
        return self.records.get(key)

    def gc(self, **kw):
        self.gc_called = True
        return {"deleted": 7}


def _emb(texts):
    return [[0.1, 0.2, 0.3] for _ in texts]


def _dep(name="left-pad", version="1.3.0", eco="npm", h="sha512-abc"):
    return Dependency(name=name, version=version, ecosystem=eco,
                      lockfile_path="package-lock.json", hash=h)


def test_artifact_id_includes_hash_when_present():
    d = Dependency(name="x", version="1", ecosystem="npm",
                   lockfile_path="package-lock.json", hash="sha512-zzz")
    assert artifact_id(d) == "npm:x@1+sha512-zzz"


def test_artifact_id_without_hash():
    d = Dependency(name="x", version="1", ecosystem="npm",
                   lockfile_path="package-lock.json", hash=None)
    assert artifact_id(d) == "npm:x@1"


# ---- read ----


def test_read_context_exact_only():
    r = FakeRedis()
    r.store["mem:npm:x@1"] = json.dumps({"severity": 3, "summary": "was bad"})
    mgr = MemoryManager(redis=r)
    ctx = mgr.read_context("npm:x@1")
    assert ctx.exact["summary"] == "was bad"
    assert ctx.similar == ()


def test_read_context_with_similar_excludes_self():
    vec = FakeVector(hits=[
        {"artifact_id": "npm:x@1", "severity": 4, "summary": "self"},
        {"artifact_id": "npm:y@2", "severity": 2, "summary": "neighbour"},
    ])
    mgr = MemoryManager(redis=FakeRedis(), vector=vec, embedder=_emb)
    ctx = mgr.read_context("npm:x@1", query_text="install script exfiltrates env")
    ids = [s["artifact_id"] for s in ctx.similar]
    assert ids == ["npm:y@2"]


def test_read_context_similarity_failure_is_swallowed():
    class BadVec(FakeVector):
        def query_similar(self, vec, k):
            raise RuntimeError("pgvector down")

    mgr = MemoryManager(redis=FakeRedis(), vector=BadVec(), embedder=_emb)
    ctx = mgr.read_context("npm:x@1", query_text="q")
    assert ctx.similar == ()


def test_memory_context_as_prior_findings():
    ctx = MemoryContext(
        artifact_id="npm:x@1",
        exact={"severity": 3, "summary": "bad install"},
        similar=({"artifact_id": "npm:y@2", "severity": 2, "summary": "sketchy"},),
    )
    findings = ctx.as_prior_findings()
    assert any("exact-hash prior" in f for f in findings)
    assert any("npm:y@2" in f for f in findings)


def test_make_lookup_adapter():
    r = FakeRedis()
    r.store["mem:npm:x@1"] = json.dumps({"severity": 2, "summary": "hi"})
    mgr = MemoryManager(redis=r)
    lookup = mgr.make_lookup(lambda dk: ("npm:x@1", ""))
    assert any("hi" in f for f in lookup("npm:x@1"))


def test_make_lookup_resolve_failure_falls_back():
    mgr = MemoryManager(redis=FakeRedis())
    lookup = mgr.make_lookup(lambda dk: (_ for _ in ()).throw(ValueError("boom")))
    assert lookup("whatever") == []


# ---- write scope ----


def _state_with_signal(dep, dimension, severity):
    st = AuditState()
    st.dependencies = [dep]
    st.signals = [Signal(
        dep_key=f"{dep.ecosystem}:{dep.name}@{dep.version}",
        dimension=dimension,
        origin=SignalOrigin.STATIC,
        source="stage3.test",
        severity=severity,
        summary="sig summary",
        reasoning="because",
    )]
    return st


def test_persist_writes_escalated():
    dep = _dep()
    st = _state_with_signal(dep, TrustDimension.BEHAVIOR, Severity.HIGH)
    gate = GateDecision(per_dep={"npm:left-pad@1.3.0": Severity.HIGH})
    mgr = MemoryManager(redis=FakeRedis())
    report = mgr.persist(st, gate)
    assert artifact_id(dep) in report.written


def test_persist_skips_longtail_benign():
    dep = _dep()
    st = _state_with_signal(dep, TrustDimension.BEHAVIOR, Severity.CLEAN)
    gate = GateDecision(per_dep={"npm:left-pad@1.3.0": Severity.CLEAN})
    mgr = MemoryManager(redis=FakeRedis())
    report = mgr.persist(st, gate)
    assert report.written == []
    assert artifact_id(dep) in report.skipped


def test_persist_writes_high_popularity_benign():
    dep = _dep()
    st = _state_with_signal(dep, TrustDimension.POPULARITY, Severity.LOW)
    gate = GateDecision(per_dep={"npm:left-pad@1.3.0": Severity.CLEAN})
    mgr = MemoryManager(redis=FakeRedis())
    report = mgr.persist(st, gate)
    assert artifact_id(dep) in report.written


def test_persist_custom_popularity_hook():
    dep = _dep()
    st = _state_with_signal(dep, TrustDimension.BEHAVIOR, Severity.CLEAN)
    gate = GateDecision(per_dep={"npm:left-pad@1.3.0": Severity.CLEAN})
    cfg = MemoryConfig(is_high_popularity=lambda dk, state: True)
    mgr = MemoryManager(redis=FakeRedis(), config=cfg)
    report = mgr.persist(st, gate)
    assert artifact_id(dep) in report.written


# ---- collision / anomaly ----


def test_upsert_max_wins_flags_severity_decrease():
    dep = _dep()
    key = artifact_id(dep)
    r = FakeRedis()
    r.store[f"mem:{key}"] = json.dumps({"severity": int(Severity.CRITICAL), "summary": "old crit"})
    st = _state_with_signal(dep, TrustDimension.BEHAVIOR, Severity.MEDIUM)
    gate = GateDecision(per_dep={"npm:left-pad@1.3.0": Severity.MEDIUM})
    mgr = MemoryManager(redis=r)
    report = mgr.persist(st, gate)
    assert report.anomalies and "kept" in report.anomalies[0]
    stored = json.loads(r.store[f"mem:{key}"])
    assert stored["severity"] == int(Severity.CRITICAL)  # higher retained


def test_upsert_writes_vector_when_configured():
    dep = _dep()
    vec = FakeVector()
    st = _state_with_signal(dep, TrustDimension.BEHAVIOR, Severity.HIGH)
    gate = GateDecision(per_dep={"npm:left-pad@1.3.0": Severity.HIGH})
    mgr = MemoryManager(redis=FakeRedis(), vector=vec, embedder=_emb)
    mgr.persist(st, gate)
    assert vec.upserts and vec.upserts[0][0] == artifact_id(dep)


def test_persist_store_failure_is_best_effort():
    class BoomRedis(FakeRedis):
        def get(self, k):
            raise RuntimeError("redis down")

    dep = _dep()
    st = _state_with_signal(dep, TrustDimension.BEHAVIOR, Severity.HIGH)
    gate = GateDecision(per_dep={"npm:left-pad@1.3.0": Severity.HIGH})
    # set fails silently; _get_any swallows; write still recorded
    mgr = MemoryManager(redis=BoomRedis())
    report = mgr.persist(st, gate)
    assert artifact_id(dep) in report.written


# ---- gc ----


def test_gc_delegates_to_vector():
    vec = FakeVector()
    mgr = MemoryManager(vector=vec)
    assert mgr.gc() == {"deleted": 7}
    assert vec.gc_called is True


def test_gc_no_vector_is_noop():
    mgr = MemoryManager()
    out = mgr.gc()
    assert out["deleted"] == 0
