"""Unit tests for graph/build.py — the `run()` seam both entrypoints call (§6.1.4).

The real graph compile needs LangGraph and the LLM client needs anthropic; neither is a
test dependency. `run()` exposes an injectable `graph_factory`, and `build_specialist_deps`
is monkeypatched, so the seam (BYOK injection, credential isolation, result shaping, the
§1.3 query rule) is exercised without either.
"""

from __future__ import annotations

import pytest

from credentials import UserCredentials
from graph import build as gb
from graph.build import RunConfig, RunResult, _shape_result, retrying_tools
from graph.router import AuditRequest
from graph.spine import InjectedTools
from graph.state import GateDecision, RunMode, Severity


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
    monkeypatch.setattr("graph.llm_client.build_specialist_deps", lambda creds, **kw: object())


def _run_with_final(final, *, mode=RunMode.AUDIT, capture=None):
    def factory(**kwargs):
        class _Graph:
            def invoke(self, initial, cfg):
                if capture is not None:
                    capture["initial"] = initial
                    capture["cfg"] = cfg
                return final

        return _Graph()

    req = AuditRequest(mode=mode, target="pkg:pypi/requests@2.31.0")
    return gb.run(req, credentials=_creds(), tools=_tools(), session=_FakeSession(), graph_factory=factory)


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
