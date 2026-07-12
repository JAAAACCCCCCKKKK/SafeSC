"""Unit tests for the §3 stores (memory/short_term.py, memory/long_term.py).

Both stores are exercised through injected fakes — no live Redis/Postgres — pinning the
exact method surface the MemoryManager and SessionManager depend on, plus the max-wins
upsert, similarity ordering, and §3.4 GC retention SQL shape.
"""

from __future__ import annotations

import json

import pytest

from memory.long_term import PGVectorConfig, PGVectorStore, _vector_literal
from memory.short_term import RedisConfig, ShortTermStore


# ============================================================ short_term (Redis)


class FakeRedis:
    """Minimal duck-typed redis client: string get/set(+ex) and the ZSET ops the
    SessionManager drives, so one fake serves both consumers."""

    def __init__(self):
        self.kv: dict[str, str] = {}
        self.ttl: dict[str, int] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.pinged = False

    def get(self, name):
        return self.kv.get(name)

    def set(self, name, value, ex=None):
        self.kv[name] = value
        if ex is not None:
            self.ttl[name] = ex

    def ping(self):
        self.pinged = True
        return True

    # ZSET surface (reached via __getattr__ passthrough)
    def zadd(self, key, mapping):
        self.zsets.setdefault(key, {}).update(mapping)

    def zremrangebyscore(self, key, lo, hi):
        z = self.zsets.get(key, {})
        for m in [m for m, s in z.items() if lo <= s <= hi]:
            del z[m]

    def zcard(self, key):
        return len(self.zsets.get(key, {}))


def test_get_set_roundtrip_and_ttl():
    r = FakeRedis()
    store = ShortTermStore(r, RedisConfig(hot_ttl_s=42))
    store.set("mem:pkg", json.dumps({"severity": 3}), ex=10)
    assert json.loads(store.get("mem:pkg"))["severity"] == 3
    assert r.ttl["mem:pkg"] == 10


def test_hot_cache_serialises_and_applies_default_ttl():
    r = FakeRedis()
    store = ShortTermStore(r, RedisConfig(hot_ttl_s=99, cache_prefix="cache:"))
    store.cache_set("signals:repoA", {"deps": 5})
    assert r.ttl["cache:signals:repoA"] == 99
    assert store.cache_get("signals:repoA") == {"deps": 5}
    assert store.cache_get("missing") is None


def test_cache_get_tolerates_corrupt_entry():
    r = FakeRedis()
    r.kv["cache:bad"] = "{not json"
    store = ShortTermStore(r)
    assert store.cache_get("bad") is None


def test_zset_passthrough_supports_session_manager_surface():
    r = FakeRedis()
    store = ShortTermStore(r)
    # These are exactly the calls SessionManager makes against the injected client.
    store.zadd("sem:x", {"tok": 1000})
    assert store.zcard("sem:x") == 1
    store.zremrangebyscore("sem:x", 0, 1000)
    assert store.zcard("sem:x") == 0


def test_ping_delegates():
    r = FakeRedis()
    assert ShortTermStore(r).ping() is True
    assert r.pinged


def test_store_is_accepted_by_session_manager():
    from graph.harness.session_manager import SessionManager

    store = ShortTermStore(FakeRedis())
    sm = SessionManager(store)
    with sm.slot("sem:llm", capacity=1) as first:
        assert first.acquired
        with sm.slot("sem:llm", capacity=1) as second:
            assert not second.acquired  # capacity reached


# ============================================================ long_term (PGVector)


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.rowcount = 0
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.executed.append((" ".join(sql.split()), params))
        low = sql.lower()
        if "delete" in low:
            self.rowcount = self.conn.delete_rowcount
        elif "select" in low:
            self._result = self.conn.rows

    def fetchone(self):
        return self.conn.rows[0] if self.conn.rows else None

    def fetchall(self):
        return list(self.conn.rows)


class FakeConn:
    def __init__(self, rows=None, delete_rowcount=0):
        self.rows = rows or []
        self.delete_rowcount = delete_rowcount
        self.executed = []
        self.committed = False
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.committed = True
        self.closed = True
        return False


def _store(conn, config=None):
    return PGVectorStore(lambda: conn, config or PGVectorConfig(embedding_dim=3))


def test_vector_literal_format():
    assert _vector_literal([0.5, 1, 2.0]) == "[0.5,1,2]"


def test_upsert_emits_max_wins_conflict_sql():
    conn = FakeConn()
    _store(conn).upsert(
        "npm:left-pad@1.0+abc",
        [0.1, 0.2, 0.3],
        {"severity": 3, "summary": "install script exfil", "reasoning": "why", "evidence": ["f.js"]},
    )
    sql, params = conn.executed[-1]
    assert "ON CONFLICT (artifact_id) DO UPDATE" in sql
    assert "GREATEST" in sql  # defense-in-depth max-wins
    assert params[0] == "npm:left-pad@1.0+abc"
    assert params[2] == 3  # severity
    assert params[3] == "escalated"  # kind derived from severity >= floor
    assert json.loads(params[6]) == ["f.js"]  # evidence serialised to jsonb
    assert conn.committed


def test_upsert_marks_low_severity_benign():
    conn = FakeConn()
    _store(conn).upsert("npm:a@1+h", [0.0, 0.0, 0.0], {"severity": 0, "summary": "clean"})
    _, params = conn.executed[-1]
    assert params[3] == "benign"


def test_get_maps_row_to_record():
    conn = FakeConn(rows=[("npm:a@1+h", 3, "escalated", "sum", "reason", ["e1"])])
    rec = _store(conn).get("npm:a@1+h")
    assert rec == {
        "artifact_id": "npm:a@1+h",
        "severity": 3,
        "kind": "escalated",
        "summary": "sum",
        "reasoning": "reason",
        "evidence": ["e1"],
    }


def test_get_returns_none_when_absent():
    assert _store(FakeConn(rows=[])).get("missing") is None


def test_query_similar_orders_and_carries_score():
    rows = [
        ("npm:a@1+h", 3, "escalated", "s1", "r1", "[]", 0.05),
        ("npm:b@2+h", 1, "benign", "s2", "r2", "[]", 0.20),
    ]
    conn = FakeConn(rows=rows)
    hits = _store(conn).query_similar([0.1, 0.2, 0.3], k=2)
    sql, params = conn.executed[-1]
    assert "ORDER BY embedding <=> %s::vector LIMIT %s" in sql
    assert params[-1] == 2  # k
    assert hits[0]["artifact_id"] == "npm:a@1+h"
    assert hits[0]["score"] == 0.05
    assert hits[0]["evidence"] == []


def test_gc_deletes_only_old_benign_records():
    conn = FakeConn(delete_rowcount=7)
    report = _store(conn, PGVectorConfig(embedding_dim=3, escalate_floor=2, benign_retention_days=30)).gc()
    sql, params = conn.executed[-1]
    assert sql.startswith("DELETE FROM")
    assert "severity < %s" in sql
    assert "kind <> 'fingerprint'" in sql  # fingerprints kept indefinitely
    assert params == (2, 30)
    assert report == {"deleted": 7, "retention_days": 30}


def test_ensure_schema_pins_dim_and_creates_index():
    conn = FakeConn()
    _store(conn, PGVectorConfig(embedding_dim=1024, table="t")).ensure_schema()
    joined = " ".join(sql for sql, _ in conn.executed)
    assert "CREATE EXTENSION IF NOT EXISTS vector" in joined
    assert "vector(1024)" in joined
    assert "ivfflat" in joined


# ============================================================ MemoryManager integration


def test_memory_manager_uses_stores_end_to_end(monkeypatch):
    """The MemoryManager should read from / write to the real store objects via injection,
    confirming the interfaces line up (get/set, query_similar/upsert/get, gc)."""
    from graph.harness.memory_manager import MemoryManager

    redis = ShortTermStore(FakeRedis())
    vector = _store(FakeConn(delete_rowcount=3))
    embedder = lambda texts: [[0.1, 0.2, 0.3] for _ in texts]
    mm = MemoryManager(redis=redis, vector=vector, embedder=embedder)

    # read path: exact miss + similarity query executes against the vector store
    ctx = mm.read_context("npm:x@1+h", "some behaviour summary")
    assert ctx.artifact_id == "npm:x@1+h"

    # gc delegates to the vector store
    assert mm.gc() == {"deleted": 3, "retention_days": 90}
