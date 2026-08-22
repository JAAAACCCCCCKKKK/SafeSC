"""Unit tests for the Session Manager (CLAUDE.md §2.7.3, §5.2, §5.3).

The semaphores existed but nothing acquired them; these tests pin both the primitives and
the call sites that now enforce them. The load-bearing distinctions:

* `slot` releases, `consume` does not — a concurrency limit and a budget are different
  things, and conflating them would silently un-cap the §5.3 ceiling.
* the LLM budget **fails closed** (skip + degrade) while fan-out width and the per-host
  gate **fail open** (proceed + warn). Each direction is chosen so the failure mode loses
  efficiency rather than losing a signal — fewer signals read as cleaner (§8).

Redis is a fake throughout; no live store, no event loop tricks beyond `asyncio.run`.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from safesc.graph.harness.session_manager import (
    SessionManager,
    budgeted_node,
    fanout_limited_node,
    fanout_width_key,
    host_key,
    llm_budget_key,
    new_ulid,
)


class FakeRedis:
    def __init__(self):
        self.zsets: dict[str, dict[str, float]] = {}
        self.expires: dict[str, int] = {}

    def zadd(self, key, mapping):
        self.zsets.setdefault(key, {}).update(mapping)

    def zremrangebyscore(self, key, lo, hi):
        z = self.zsets.get(key, {})
        for m in [m for m, score in z.items() if lo <= score <= hi]:
            del z[m]

    def zcard(self, key):
        return len(self.zsets.get(key, {}))

    def zrem(self, key, member):
        self.zsets.get(key, {}).pop(member, None)

    def pexpire(self, key, ms):
        self.expires[key] = ms


@pytest.fixture
def session():
    return SessionManager(FakeRedis())


# ============================================================ run identity


def test_ulid_is_lexicographically_chronological():
    early = new_ulid(ms=1_700_000_000_000)
    late = new_ulid(ms=1_700_000_001_000)
    assert early < late
    assert len(early) == 26 and early.isalnum()


def test_new_run_mints_distinct_ids(session):
    assert session.new_run() != session.new_run()


# ============================================================ primitives


def test_acquire_admits_up_to_capacity_then_refuses(session):
    key = "sem:test"
    first = session.try_acquire(key, 2)
    second = session.try_acquire(key, 2)
    third = session.try_acquire(key, 2)
    assert first.acquired and second.acquired
    assert not third.acquired and third.holders == 2


def test_release_frees_a_slot(session):
    key = "sem:test"
    got = session.try_acquire(key, 1)
    assert not session.try_acquire(key, 1).acquired
    session.release(key, got.token)
    assert session.try_acquire(key, 1).acquired


def test_expired_tokens_are_swept_so_a_dead_worker_cannot_pin_the_semaphore(session):
    key = "sem:test"
    session.redis.zadd(key, {"leaked": int(time.time() * 1000) - 60_000})
    assert session.try_acquire(key, 1).acquired, "an expired token must not hold the slot"


def test_slot_releases_in_finally_even_when_the_body_raises(session):
    key = "sem:test"
    with pytest.raises(RuntimeError):
        with session.slot(key, 1) as s:
            assert s.acquired
            raise RuntimeError("boom")
    assert session.try_acquire(key, 1).acquired


def test_consume_never_releases_so_a_budget_actually_binds(session):
    """The distinction that makes §5.3 work: three units of a 3-unit budget exhaust it."""
    key = llm_budget_key("run-1")
    assert session.consume(key, 3).acquired
    assert session.consume(key, 3).acquired
    assert session.consume(key, 3).acquired
    assert not session.consume(key, 3).acquired


# ============================================================ per-host gate (§5.2)


def test_host_key_is_global_not_run_scoped():
    assert host_key("https://pypi.org/simple/x") == "sem:host:pypi.org"
    assert host_key("https://registry.npmjs.org/x") == "sem:host:registry.npmjs.org"
    # no run id anywhere: that is what makes the budget fleet-wide
    assert "run" not in host_key("https://pypi.org/x")


def test_host_gate_holds_and_returns_a_token(session):
    gate = session.host_gate(1)

    async def _go():
        async with gate("https://pypi.org/a"):
            assert session.redis.zcard(host_key("https://pypi.org/a")) == 1
        return session.redis.zcard(host_key("https://pypi.org/a"))

    assert asyncio.run(_go()) == 0


def test_host_gate_fails_open_when_redis_raises(session):
    class Exploding(FakeRedis):
        def zremrangebyscore(self, *a, **k):
            raise ConnectionError("redis is down")

    gate = SessionManager(Exploding()).host_gate(1)
    ran = []

    async def _go():
        async with gate("https://pypi.org/a"):
            ran.append(True)

    asyncio.run(_go())
    assert ran == [True], "a broken limiter must not block Stage 3 collection"


def test_host_gate_proceeds_after_the_wait_budget_rather_than_dropping_the_request(session):
    key = host_key("https://pypi.org/a")
    session.redis.zadd(key, {"held": int(time.time() * 1000) + 600_000})  # saturated, not expired
    gate = session.host_gate(1, wait_timeout_s=0.05, poll_s=0.01)
    ran = []

    async def _go():
        async with gate("https://pypi.org/a"):
            ran.append(True)

    asyncio.run(_go())
    assert ran == [True]


# ============================================================ node wrappers


def _ok_node(*_a, **_k):
    return {"signals": ["s"], "llm_calls": 1}


def test_budgeted_node_runs_while_the_budget_lasts(session):
    node = budgeted_node(_ok_node, node_name="behavior_agent", session=session, run_id="r1", capacity=2)
    assert node({}) == {"signals": ["s"], "llm_calls": 1}
    assert node({}) == {"signals": ["s"], "llm_calls": 1}


def test_budgeted_node_skips_and_degrades_once_exhausted(session):
    node = budgeted_node(_ok_node, node_name="behavior_agent", session=session, run_id="r1", capacity=1)
    node({})
    out = node({})
    assert "signals" not in out
    notes = out["degraded_notes"]
    assert len(notes) == 1 and "budget semaphore exhausted" in notes[0].reason
    assert notes[0].node == "behavior_agent"


def test_budgeted_node_uses_the_run_scoped_key(session):
    budgeted_node(_ok_node, node_name="n", session=session, run_id="r9", capacity=1)({})
    assert llm_budget_key("r9") in session.redis.zsets


def test_fanout_limited_node_releases_its_slot_after_each_call(session):
    node = fanout_limited_node(
        _ok_node, node_name="identity_agent", session=session, run_id="r1", capacity=1,
    )
    node({})
    node({})
    assert session.redis.zcard(fanout_width_key("r1")) == 0


def test_fanout_limited_node_releases_even_when_the_node_raises(session):
    def _boom(*_a, **_k):
        raise RuntimeError("node failed")

    node = fanout_limited_node(_boom, node_name="n", session=session, run_id="r1", capacity=1)
    with pytest.raises(RuntimeError):
        node({})
    assert session.redis.zcard(fanout_width_key("r1")) == 0


def test_fanout_limited_node_fails_open_with_a_note_when_saturated(session):
    key = fanout_width_key("r1")
    session.redis.zadd(key, {"held": int(time.time() * 1000) + 600_000})
    node = fanout_limited_node(
        _ok_node, node_name="identity_agent", session=session, run_id="r1", capacity=1,
        attempts=2, sleep=lambda _s: None,
    )
    out = node({})
    assert out["signals"] == ["s"], "width is a politeness cap; skipping would lose a signal"
    assert any("width semaphore saturated" in n.reason for n in out["degraded_notes"])


def test_fanout_note_does_not_clobber_notes_the_node_produced(session):
    from safesc.graph.state import emit_degraded

    def _degrading(*_a, **_k):
        return emit_degraded("identity_agent", "evidence gather failed")

    session.redis.zadd(fanout_width_key("r1"), {"held": int(time.time() * 1000) + 600_000})
    node = fanout_limited_node(
        _degrading, node_name="identity_agent", session=session, run_id="r1", capacity=1,
        attempts=1, sleep=lambda _s: None,
    )
    reasons = [n.reason for n in node({})["degraded_notes"]]
    assert len(reasons) == 2
    assert any("evidence gather failed" in r for r in reasons)
    assert any("width semaphore saturated" in r for r in reasons)
