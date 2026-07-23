"""Unit tests for graph/harness/auto_repair.py (§2.7.2).

Covers transient classification, bounded retry with an injected (no-op) sleep, the
non-transient short-circuit (no retry storm with ValidationError), and the node wrapper
that degrades instead of crashing on exhaustion.
"""

from __future__ import annotations

import pytest

from graph.harness import auto_repair as ar
from graph.harness.constraint_validator import ValidationError


def test_is_transient_by_message():
    assert ar.is_transient(RuntimeError("HTTP 429 too many requests")) is True
    assert ar.is_transient(RuntimeError("connection reset by peer")) is True


def test_is_transient_by_type_name():
    assert ar.is_transient(TimeoutError("x")) is True
    assert ar.is_transient(ConnectionResetError("x")) is True


def test_is_transient_false_for_validation_error():
    assert ar.is_transient(ValidationError("bad schema")) is False


def test_is_transient_false_for_plain_error():
    assert ar.is_transient(ValueError("nope")) is False


def test_with_retry_succeeds_after_transient():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError("timed out")
        return "ok"

    wrapped = ar.with_retry(flaky, policy=ar.RetryPolicy(max_attempts=3), sleep=lambda _: None)
    assert wrapped() == "ok"
    assert calls["n"] == 3


def test_with_retry_reraises_non_transient_immediately():
    calls = {"n": 0}

    def boom():
        calls["n"] += 1
        raise ValueError("permanent")

    wrapped = ar.with_retry(boom, sleep=lambda _: None)
    with pytest.raises(ValueError):
        wrapped()
    assert calls["n"] == 1  # not retried


def test_with_retry_exhausts_and_reraises_last():
    def always_timeout():
        raise TimeoutError("still timing out")

    wrapped = ar.with_retry(always_timeout, policy=ar.RetryPolicy(max_attempts=2), sleep=lambda _: None)
    with pytest.raises(TimeoutError):
        wrapped()


def test_sleep_for_respects_max_delay():
    seen = {}
    ar._sleep_for(10, ar.RetryPolicy(base_delay=1.0, max_delay=8.0, jitter=0.0), lambda d: seen.setdefault("d", d))
    assert seen["d"] == pytest.approx(8.0)


def test_auto_repaired_node_passes_through_on_success():
    node = ar.auto_repaired_node(lambda **kw: {"signals": []}, node_name="behavior", sleep=lambda _: None)
    assert node(state=object()) == {"signals": []}


def test_auto_repaired_node_degrades_on_exhaustion():
    def failing(**kw):
        raise TimeoutError("dead upstream")

    node = ar.auto_repaired_node(failing, node_name="behavior",
                                 policy=ar.RetryPolicy(max_attempts=2), sleep=lambda _: None)
    result = node(state=object())
    notes = result["degraded_notes"]
    assert notes and notes[0].node == "behavior"
    assert "auto-repair exhausted" in notes[0].reason


def test_auto_repaired_node_degrades_on_non_transient():
    def failing(**kw):
        raise ValueError("boom")

    node = ar.auto_repaired_node(failing, node_name="identity", sleep=lambda _: None)
    result = node()
    assert result["degraded_notes"][0].node == "identity"
