"""Integration test for entrypoints/api.py × reporter — the `include_report` seam (§6).

The graph run is mocked (LangGraph/anthropic are not test deps); we assert the FastAPI
surface embeds the full canonical `AuditReport` only when asked, and never leaks the BYOK
key (§3.5 invariant #3).
"""

from __future__ import annotations

from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from entrypoints import api  # noqa: E402
from graph.build import RunResult  # noqa: E402
from graph.state import (  # noqa: E402
    AuditState,
    GateDecision,
    RunMode,
    Severity,
    Signal,
    SignalOrigin,
    TrustDimension,
    dep_key,
)
from tools.index.core.models import Dependency  # noqa: E402


def _result():
    dep = Dependency(name="evil", version="1.0.0", ecosystem="npm", lockfile_path=Path("package-lock.json"))
    sig = Signal(dep_key=dep_key(dep), dimension=TrustDimension.BEHAVIOR, origin=SignalOrigin.LLM,
                 source="llm.behavior", severity=Severity.HIGH, confidence=0.8, summary="exfiltrates env")
    gd = GateDecision(per_dep={dep_key(dep): Severity.HIGH}, overall=Severity.HIGH, passed=False,
                      exit_code=1, summary="AUDIT: overall=HIGH, FAIL")
    state = AuditState(mode=RunMode.AUDIT, dependencies=[dep], signals=[sig], gate_decision=gd)
    return RunResult(run_id="RID", gate_decision=gd, exit_code=1, degraded=[], incomplete=False, final_state=state)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(api.graph_build, "run", lambda *a, **k: _result())
    app = api.create_app(tools=object(), session=object())
    return TestClient(app)


_HDRS = {"X-LLM-Api-Key": "super-secret-key"}


def test_audit_without_report_omits_it(client):
    r = client.post("/audit", json={"target": "."}, headers=_HDRS)
    assert r.status_code == 200
    body = r.json()
    assert body["overall"] == "HIGH" and body["passed"] is False
    assert body["report"] is None


def test_audit_with_report_embeds_full_report(client):
    r = client.post("/audit", json={"target": ".", "include_report": True}, headers=_HDRS)
    assert r.status_code == 200
    report = r.json()["report"]
    assert report["overall_severity"] == "HIGH"
    assert report["findings"][0]["dep_key"] == "npm:evil@1.0.0"
    assert report["findings"][0]["signals"][0]["source"] == "llm.behavior"


def test_query_with_report(client):
    r = client.post("/query", json={"target": "npm:evil@1.0.0", "include_report": True}, headers=_HDRS)
    assert r.status_code == 200
    assert r.json()["report"]["schema_version"]


def test_response_never_leaks_key(client):
    r = client.post("/audit", json={"target": ".", "include_report": True}, headers=_HDRS)
    assert "super-secret-key" not in r.text


def test_missing_key_is_400(client):
    r = client.post("/audit", json={"target": "."})  # no X-LLM-Api-Key header
    assert r.status_code == 400
    assert "super-secret-key" not in r.text
