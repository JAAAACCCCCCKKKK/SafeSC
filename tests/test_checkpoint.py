"""The two `--resume` checkpointers (memory/checkpoint.py, CLAUDE.md §3.1).

No Redis or Postgres is needed. `PlainRedisSaver` runs against an in-memory fake that
implements *only* plain Redis commands — so a regression that reaches for RediSearch
(`FT.*`, the reason the upstream RedisSaver fails on Upstash) raises AttributeError here
instead of passing. The Postgres helpers run against a fake connection and saver class.
"""

from __future__ import annotations

import fnmatch
from typing import TypedDict

import pytest

pytest.importorskip("langgraph")

from langgraph.graph import END, START, StateGraph  # noqa: E402

from safesc.memory import checkpoint as ck  # noqa: E402
from safesc.memory.checkpoint import PlainRedisSaver  # noqa: E402


# ============================================================ fake Redis (plain commands only)


def _b(value) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value).encode()


class FakeRedis:
    """Binary-mode (decode_responses=False) subset of redis-py: hashes, sorted sets, sets,
    lists, expire, delete, scan_iter, pipeline. Nothing else exists on purpose."""

    def __init__(self):
        self.data: dict[bytes, object] = {}
        self.ttls: dict[bytes, int] = {}

    # hashes
    def hset(self, key, field=None, value=None, mapping=None):
        h = self.data.setdefault(_b(key), {})
        items = dict(mapping or {})
        if field is not None:
            items[field] = value
        added = 0
        for f, v in items.items():
            added += _b(f) not in h
            h[_b(f)] = _b(v)
        return added

    def hsetnx(self, key, field, value):
        h = self.data.setdefault(_b(key), {})
        if _b(field) in h:
            return 0
        h[_b(field)] = _b(value)
        return 1

    def hgetall(self, key):
        return dict(self.data.get(_b(key), {}))

    def hmget(self, key, fields):
        h = self.data.get(_b(key), {})
        return [h.get(_b(f)) for f in fields]

    # lists
    def rpush(self, key, *values):
        lst = self.data.setdefault(_b(key), [])
        lst.extend(_b(v) for v in values)
        return len(lst)

    def lrange(self, key, start, end):
        lst = self.data.get(_b(key), [])
        return lst[start:] if end == -1 else lst[start : end + 1]

    # sorted sets (score 0 everywhere, so lexicographic)
    def zadd(self, key, mapping):
        z = self.data.setdefault(_b(key), set())
        before = len(z)
        z.update(_b(m) for m in mapping)
        return len(z) - before

    def zrange(self, key, start, end):
        members = sorted(self.data.get(_b(key), set()))
        return members[start:] if end == -1 else members[start : end + 1]

    def zrevrange(self, key, start, end):
        members = sorted(self.data.get(_b(key), set()), reverse=True)
        return members[start:] if end == -1 else members[start : end + 1]

    # sets
    def sadd(self, key, *members):
        s = self.data.setdefault(_b(key), set())
        before = len(s)
        s.update(_b(m) for m in members)
        return len(s) - before

    def smembers(self, key):
        return set(self.data.get(_b(key), set()))

    # keys
    def expire(self, key, seconds):
        self.ttls[_b(key)] = seconds
        return True

    def delete(self, *keys):
        removed = 0
        for key in keys:
            removed += self.data.pop(_b(key), None) is not None
            self.ttls.pop(_b(key), None)
        return removed

    def scan_iter(self, match="*"):
        return [k for k in list(self.data) if fnmatch.fnmatchcase(k.decode(), match)]

    def pipeline(self, transaction=True):
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, client):
        self._client = client
        self._calls = []

    def __getattr__(self, name):
        method = getattr(self._client, name)  # AttributeError for anything non-plain

        def queue(*args, **kwargs):
            self._calls.append((method, args, kwargs))
            return self

        return queue

    def execute(self):
        results = [method(*args, **kwargs) for method, args, kwargs in self._calls]
        self._calls = []
        return results


# ============================================================ a real graph that resumes


class _State(TypedDict):
    steps: list


def _graph(saver, calls, fail_second):
    def first(state):
        calls["first"] += 1
        return {"steps": state["steps"] + ["first"]}

    def second(state):
        calls["second"] += 1
        if fail_second["on"]:
            raise RuntimeError("worker killed")
        return {"steps": state["steps"] + ["second"]}

    builder = StateGraph(_State)
    builder.add_node("first", first)
    builder.add_node("second", second)
    builder.add_edge(START, "first")
    builder.add_edge("first", "second")
    builder.add_edge("second", END)
    return builder.compile(checkpointer=saver)


def test_an_interrupted_run_resumes_from_a_new_saver_without_redoing_finished_nodes():
    redis = FakeRedis()
    calls = {"first": 0, "second": 0}
    fail = {"on": True}
    config = {"configurable": {"thread_id": "thread-A"}}

    with pytest.raises(RuntimeError, match="worker killed"):
        _graph(PlainRedisSaver(redis), calls, fail).invoke({"steps": []}, config)

    # A fresh saver on the same store stands in for a new process after the crash.
    fail["on"] = False
    final = _graph(PlainRedisSaver(redis), calls, fail).invoke(None, config)

    assert final["steps"] == ["first", "second"]
    assert calls == {"first": 1, "second": 2}, "resume must not re-run the node that finished"


def test_a_different_thread_does_not_see_another_threads_checkpoint():
    redis = FakeRedis()
    calls = {"first": 0, "second": 0}
    _graph(PlainRedisSaver(redis), calls, {"on": False}).invoke(
        {"steps": []}, {"configurable": {"thread_id": "one"}}
    )
    assert PlainRedisSaver(redis).get_tuple({"configurable": {"thread_id": "two"}}) is None


# ============================================================ saver contract details


def _run_once(redis, thread="t1"):
    calls = {"first": 0, "second": 0}
    config = {"configurable": {"thread_id": thread}}
    _graph(PlainRedisSaver(redis), calls, {"on": False}).invoke({"steps": []}, config)
    return config


def test_list_is_newest_first_and_honours_limit_before_and_filter():
    redis = FakeRedis()
    config = _run_once(redis)
    saver = PlainRedisSaver(redis)

    history = list(saver.list(config))
    ids = [t.config["configurable"]["checkpoint_id"] for t in history]
    assert len(ids) >= 3 and ids == sorted(ids, reverse=True)
    assert history[0].checkpoint["channel_values"]["steps"] == ["first", "second"]
    assert history[0].parent_config["configurable"]["checkpoint_id"] == ids[1]

    assert len(list(saver.list(config, limit=2))) == 2
    before = {"configurable": {"thread_id": "t1", "checkpoint_id": ids[1]}}
    assert [t.config["configurable"]["checkpoint_id"] for t in saver.list(config, before=before)] == ids[2:]
    assert all(t.metadata["source"] == "loop" for t in saver.list(config, filter={"source": "loop"}))
    # no config: every thread, found by scanning (no search index involved)
    _run_once(redis, thread="t2")
    assert {t.config["configurable"]["thread_id"] for t in saver.list(None)} == {"t1", "t2"}


def test_regular_writes_are_kept_once_in_order_and_special_writes_replace():
    saver = PlainRedisSaver(FakeRedis())
    cfg = {"configurable": {"thread_id": "t", "checkpoint_ns": "", "checkpoint_id": "c1"}}
    saver.put(
        {"configurable": {"thread_id": "t", "checkpoint_ns": ""}},
        {"id": "c1", "v": 4, "ts": "", "channel_values": {}, "channel_versions": {}, "versions_seen": {}},
        {"source": "input", "step": -1},
        {},
    )
    saver.put_writes(cfg, [("a", 1), ("b", 2)], task_id="task")
    saver.put_writes(cfg, [("a", 99)], task_id="task")  # retried task: must not duplicate
    saver.put_writes(cfg, [("__error__", "boom")], task_id="task")
    saver.put_writes(cfg, [("__error__", "boom again")], task_id="task")

    writes = saver.get_tuple(cfg).pending_writes
    assert writes == [("task", "a", 1), ("task", "b", 2), ("task", "__error__", "boom again")]


def test_every_written_key_gets_the_ttl_and_namespaces_with_colons_do_not_collide():
    redis = FakeRedis()
    saver = PlainRedisSaver(redis, ttl_s=123)
    base = {"id": "c1", "v": 4, "ts": "", "channel_versions": {"x": "1"}, "versions_seen": {}}
    saver.put({"configurable": {"thread_id": "t", "checkpoint_ns": "a:b"}},
              {**base, "channel_values": {"x": "in a:b"}}, {}, {"x": "1"})
    saver.put({"configurable": {"thread_id": "t", "checkpoint_ns": "a"}},
              {**base, "channel_values": {"x": "in a"}}, {}, {"x": "1"})

    assert set(redis.ttls) == set(redis.data) and set(redis.ttls.values()) == {123}
    get = lambda ns: saver.get_tuple({"configurable": {"thread_id": "t", "checkpoint_ns": ns}})
    assert get("a:b").checkpoint["channel_values"] == {"x": "in a:b"}
    assert get("a").checkpoint["channel_values"] == {"x": "in a"}


def test_delete_thread_removes_every_key_for_that_thread_only():
    redis = FakeRedis()
    _run_once(redis, thread="gone")
    _run_once(redis, thread="kept")
    PlainRedisSaver(redis).delete_thread("gone")
    assert redis.data and all(b"gone" not in key for key in redis.data)
    assert PlainRedisSaver(redis).get_tuple({"configurable": {"thread_id": "kept"}}) is not None


async def test_async_methods_match_the_sync_ones():
    redis = FakeRedis()
    config = _run_once(redis)
    saver = PlainRedisSaver(redis)
    assert (await saver.aget_tuple(config)).checkpoint["id"] == saver.get_tuple(config).checkpoint["id"]
    assert len([t async for t in saver.alist(config)]) == len(list(saver.list(config)))


# ============================================================ Postgres helpers


class _FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        if self.conn.missing_tables:
            raise RuntimeError('relation "checkpoint_migrations" does not exist')
        return self

    def fetchone(self):
        return self.conn.row


class _FakePgConn:
    def __init__(self, row=None, missing_tables=False):
        self.row, self.missing_tables, self.closed = row, missing_tables, False

    def cursor(self):
        return _FakeCursor(self)

    def close(self):
        self.closed = True


class _FakePostgresSaver:
    MIGRATIONS = ["m0", "m1", "m2"]
    setups = 0

    def __init__(self, conn):
        self.conn = conn

    def setup(self):
        type(self).setups += 1


@pytest.fixture
def fake_pg(monkeypatch):
    state = {}

    def connect(dsn):
        state["dsn"] = dsn
        return state["conn"]

    monkeypatch.setattr(ck, "_connect_postgres", connect)
    monkeypatch.setattr(ck, "_postgres_saver_class", lambda: _FakePostgresSaver)
    _FakePostgresSaver.setups = 0
    return state


def test_postgres_checkpointer_is_returned_when_the_schema_is_current(fake_pg):
    fake_pg["conn"] = _FakePgConn(row={"v": 2})
    saver = ck.postgres_checkpointer("postgresql://db/safesc")
    assert isinstance(saver, _FakePostgresSaver) and not fake_pg["conn"].closed
    assert _FakePostgresSaver.setups == 0, "the audit path must never run DDL (§3.6)"


@pytest.mark.parametrize("conn", [
    _FakePgConn(missing_tables=True),
    _FakePgConn(row=None),
    _FakePgConn(row={"v": 1}),
], ids=["no-tables", "no-migrations", "behind"])
def test_postgres_checkpointer_refuses_an_unmigrated_schema_and_closes_the_connection(fake_pg, conn):
    fake_pg["conn"] = conn
    with pytest.raises(RuntimeError, match="safesc store init"):
        ck.postgres_checkpointer("postgresql://db/safesc")
    assert conn.closed


def test_setup_postgres_checkpointer_runs_migrations_and_closes(fake_pg):
    fake_pg["conn"] = _FakePgConn()
    ck.setup_postgres_checkpointer("postgresql://db/safesc")
    assert _FakePostgresSaver.setups == 1 and fake_pg["conn"].closed
