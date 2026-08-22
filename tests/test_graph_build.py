"""Unit tests for graph/build.py — the `run()` seam the CLI entrypoint calls (§6.1.4).

The real graph compile needs LangGraph and the LLM client needs anthropic; neither is a
test dependency. `run()` exposes an injectable `graph_factory`, and `build_specialist_deps`
is monkeypatched, so the seam (BYOK injection, credential isolation, result shaping, the
§1.3 query rule) is exercised without either.
"""

from __future__ import annotations

import pytest

from safesc.security.credentials import UserCredentials
from safesc.graph import build as gb
from safesc.graph.build import (
    RunConfig,
    RunResult,
    _semaphore_wrapped,
    _shape_result,
    retrying_tools,
    thread_key,
)
from safesc.graph.router import AuditRequest
from safesc.graph.spine import InjectedTools
from safesc.graph.state import GateDecision, RunMode, Severity


class _FakeSession:
    def new_run(self) -> str:
        return "01FAKE-RUN-ID"


def _tools() -> InjectedTools:
    return InjectedTools(
        discover=lambda target: [],
        parse=lambda lockfiles: [],
        verify_hash=lambda dep: [],
        collect_signals=lambda dep: [],
    )


def _creds() -> UserCredentials:
    return UserCredentials.from_request(llm_api_key="secret-key-xyz", llm_provider="anthropic")


@pytest.fixture(autouse=True)
def _no_anthropic(monkeypatch):
    """Avoid constructing the real BYOK Claude client (anthropic not installed)."""
    monkeypatch.setattr("safesc.graph.llm_client.build_specialist_deps", lambda creds, **kw: object())


def _run_with_final(final, *, mode=RunMode.AUDIT, capture=None, config=None, target="pkg:pypi/requests@2.31.0"):
    def factory(**kwargs):
        if capture is not None:
            capture["factory_kwargs"] = kwargs

        class _Graph:
            def invoke(self, initial, cfg):
                if capture is not None:
                    capture["initial"] = initial
                    capture["cfg"] = cfg
                return final

        return _Graph()

    req = AuditRequest(mode=mode, target=target)
    return gb.run(
        req, credentials=_creds(), tools=_tools(), session=_FakeSession(),
        config=config, graph_factory=factory,
    )


def test_run_shapes_result_and_uses_session_run_id():
    gd = GateDecision(per_dep={"pypi:requests@2.31.0": Severity.CLEAN}, overall=Severity.CLEAN, passed=True, exit_code=0)
    res = _run_with_final({"gate_decision": gd, "degraded_notes": []})
    assert isinstance(res, RunResult)
    assert res.run_id == "01FAKE-RUN-ID"
    assert res.passed is True and res.exit_code == 0


def test_run_keeps_credentials_out_of_audit_state():
    cap: dict = {}
    gd = GateDecision(passed=True, exit_code=0)
    _run_with_final({"gate_decision": gd}, capture=cap)
    dumped = cap["initial"].model_dump()
    assert "secret-key-xyz" not in str(dumped)
    assert not any("key" in k.lower() for k in dumped)
    # run identity is threaded via configurable, not state
    assert cap["cfg"]["configurable"]["run_id"] == "01FAKE-RUN-ID"


def test_query_mode_never_returns_failing_exit_code():
    gd = GateDecision(overall=Severity.HIGH, passed=False, exit_code=1)
    res = _run_with_final({"gate_decision": gd}, mode=RunMode.QUERY)
    assert res.exit_code == 0  # §1.3: query is evidence-only


def test_audit_mode_propagates_failing_exit_code():
    gd = GateDecision(overall=Severity.HIGH, passed=False, exit_code=1)
    res = _run_with_final({"gate_decision": gd}, mode=RunMode.AUDIT)
    assert res.exit_code == 1 and res.passed is False


def test_incomplete_detected_from_summary():
    gd = GateDecision(passed=True, exit_code=0, summary="AUDIT ... ⚠ INCOMPLETE ANALYSIS: 1 degraded node(s)")
    res = _run_with_final({"gate_decision": gd})
    assert res.incomplete is True


def test_shape_result_defensive_when_no_gate_decision():
    res = _shape_result("rid", RunMode.AUDIT, {}, RunConfig())
    assert res.passed is False and res.exit_code == 1
    assert "no gate decision" in res.gate_decision.summary


def test_retrying_tools_wraps_all_four_callables():
    calls = {"n": 0}

    def flaky(_):
        calls["n"] += 1
        return []

    wrapped = retrying_tools(InjectedTools(discover=flaky, parse=flaky, verify_hash=flaky, collect_signals=flaky))
    assert wrapped.discover("t") == [] and wrapped.verify_hash("d") == []
    assert calls["n"] == 2


# ============================================================ checkpoint thread key (§3.1)


def test_default_thread_id_is_the_fresh_run_id():
    """Without --resume every invocation gets its own thread, so a routine second audit
    re-runs instead of replaying a finished one."""
    cap: dict = {}
    _run_with_final({"gate_decision": GateDecision(passed=True, exit_code=0)}, capture=cap)
    assert cap["cfg"]["configurable"]["thread_id"] == "01FAKE-RUN-ID"


def test_resume_uses_a_stable_thread_id_derived_from_the_request():
    cap: dict = {}
    _run_with_final(
        {"gate_decision": GateDecision(passed=True, exit_code=0)},
        capture=cap, config=RunConfig(resume=True),
    )
    conf = cap["cfg"]["configurable"]
    assert conf["thread_id"] == thread_key(AuditRequest(mode=RunMode.AUDIT, target="pkg:pypi/requests@2.31.0"))
    assert conf["thread_id"] != conf["run_id"], "run identity stays the ULID for keys/logs"


def test_thread_key_is_stable_per_request_and_distinct_across_requests():
    a = AuditRequest(mode=RunMode.AUDIT, target=".")
    b = AuditRequest(mode=RunMode.AUDIT, target="other")
    c = AuditRequest(mode=RunMode.QUERY, target=".")
    assert thread_key(a) == thread_key(AuditRequest(mode=RunMode.AUDIT, target="."))
    assert thread_key(a) != thread_key(b)
    assert thread_key(a) != thread_key(c), "mode is part of the identity"
    assert thread_key(a).startswith("safesc:")


def test_run_forwards_session_and_run_id_to_the_graph_factory():
    """The semaphore wrappers close over the run id at build time, so it has to reach the
    factory rather than travelling through RunnableConfig."""
    cap: dict = {}
    _run_with_final({"gate_decision": GateDecision(passed=True, exit_code=0)}, capture=cap)
    kwargs = cap["factory_kwargs"]
    assert kwargs["run_id"] == "01FAKE-RUN-ID"
    assert isinstance(kwargs["session"], _FakeSession)


# ============================================================ semaphore wrapping (§2.7.3)


def _node(*_a, **_k):
    return {"llm_calls": 1}


def test_semaphore_wrapping_is_identity_for_a_store_free_session():
    """Tier 2 has no Redis, so a specialist node must be left exactly as it was."""
    wrapped = _semaphore_wrapped(
        _node, node_name="identity_agent", session=_FakeSession(), run_id="r1", config=RunConfig(),
    )
    assert wrapped is _node


def test_semaphore_wrapping_is_identity_when_no_session_at_all():
    assert _semaphore_wrapped(_node, node_name="n", session=None, run_id="r", config=RunConfig()) is _node


def test_semaphore_wrapping_applies_both_limits_for_a_redis_backed_session():
    from safesc.graph.harness.session_manager import SessionManager, fanout_width_key, llm_budget_key
    from tests.test_harness_session_manager import FakeRedis

    session = SessionManager(FakeRedis())
    wrapped = _semaphore_wrapped(
        _node, node_name="identity_agent", session=session, run_id="r1",
        config=RunConfig(llm_call_cap=1, fanout_width=4),
    )
    assert wrapped is not _node
    assert wrapped({}) == {"llm_calls": 1}
    # budget spent and not returned; width slot returned
    assert session.redis.zcard(llm_budget_key("r1")) == 1
    assert session.redis.zcard(fanout_width_key("r1")) == 0
    # second call exceeds the cap of 1 and degrades rather than calling the LLM
    out = wrapped({})
    assert "llm_calls" not in out and out["degraded_notes"]
