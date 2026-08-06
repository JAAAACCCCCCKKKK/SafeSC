"""Unit tests for reporter/ — the JSON / Markdown / SARIF sink (CLAUDE.md §6, §7).

The reporter makes NO decisions: these tests pin that it faithfully projects the scorer's
`GateDecision` + the run's signals into all three formats, that escalate-only stays visible
(clean signals produce no SARIF result), and that an incomplete run is surfaced loudly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from safesc.graph.state import (
    AuditState,
    DegradedNote,
    GateDecision,
    RunMode,
    Severity,
    Signal,
    SignalOrigin,
    TrustDimension,
    dep_key,
)
from safesc.reporter import (
    FORMATS,
    build_report,
    build_sarif,
    render,
    render_json,
    render_markdown,
    render_sarif,
    write_reports,
)
from safesc.reporter.models import AuditReport
from safesc.tools.index.core.models import Dependency


def _dep(name="pkg", version="1.0.0", ecosystem="npm"):
    return Dependency(name=name, version=version, ecosystem=ecosystem, lockfile_path=Path("package-lock.json"))


def _sig(dep, dimension, severity, origin=SignalOrigin.STATIC, source="stage3.x", **kw):
    return Signal(dep_key=dep_key(dep), dimension=dimension, origin=origin, source=source, severity=severity, **kw)


def _state_with_finding():
    dep = _dep()
    gd = GateDecision(
        per_dep={dep_key(dep): Severity.HIGH}, overall=Severity.HIGH, passed=False,
        exit_code=1, summary="AUDIT: overall=HIGH, FAIL (exit 1)",
    )
    return AuditState(
        mode=RunMode.AUDIT,
        dependencies=[dep],
        signals=[
            _sig(dep, TrustDimension.POPULARITY, Severity.LOW, source="stage3.downloads"),
            _sig(dep, TrustDimension.BEHAVIOR, Severity.HIGH, origin=SignalOrigin.LLM,
                 source="llm.behavior", confidence=0.8, summary="install script exfiltrates env",
                 reasoning="the postinstall reads process.env and POSTs it", evidence=["package/scripts/postinstall.js:12"]),
        ],
        gate_decision=gd,
    ), dep


# --------------------------------------------------------------------------- #
# build_report
# --------------------------------------------------------------------------- #

def test_build_report_rolls_up_per_dep_max():
    state, dep = _state_with_finding()
    report = build_report(state, run_id="RID")
    assert report.run_id == "RID"
    assert report.mode == "audit"
    assert report.overall_severity == "HIGH"
    assert report.passed is False and report.exit_code == 1
    assert report.total_dependencies == 1 and report.flagged_count == 1
    f = report.findings[0]
    assert f.severity == "HIGH"                                  # max across signals
    assert f.dimensions == {"popularity": "LOW", "behavior": "HIGH"}
    assert len(f.signals) == 2


def test_build_report_accepts_raw_dict_state():
    state, dep = _state_with_finding()
    report = build_report(state.model_dump(), run_id="RID")
    assert report.overall_severity == "HIGH"
    assert report.findings[0].dep_key == dep_key(dep)


def test_build_report_marks_incomplete_from_summary():
    dep = _dep()
    gd = GateDecision(passed=True, exit_code=0, summary="AUDIT ... ⚠ INCOMPLETE ANALYSIS: 1 degraded node(s)")
    state = AuditState(dependencies=[dep], gate_decision=gd, degraded_notes=[DegradedNote(node="gate", reason="budget")])
    report = build_report(state)
    assert report.incomplete is True
    assert report.degraded and report.degraded[0].node == "gate"


def test_build_report_defensive_without_gate_decision():
    dep = _dep()
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM)])
    report = build_report(state)
    assert report.overall_severity == "MEDIUM"
    assert report.passed is False and report.exit_code == 1


def test_build_report_surfaces_signal_only_dep_key():
    # a dep_key present only in signals (single-package query with no Dependency objects)
    gd = GateDecision(overall=Severity.CRITICAL, passed=False, exit_code=0, summary="QUERY:")
    sig = Signal(dep_key="npm:evil@9.9.9", dimension=TrustDimension.IDENTITY,
                 origin=SignalOrigin.LLM, source="llm.identity", severity=Severity.CRITICAL)
    state = AuditState(mode=RunMode.QUERY, dependencies=[], signals=[sig], gate_decision=gd)
    report = build_report(state)
    assert report.total_dependencies == 0
    assert any(f.dep_key == "npm:evil@9.9.9" and f.name == "evil" and f.version == "9.9.9" for f in report.findings)


def test_findings_sorted_by_severity_desc():
    d1, d2 = _dep("a"), _dep("b")
    state = AuditState(
        dependencies=[d1, d2],
        signals=[_sig(d1, TrustDimension.IDENTITY, Severity.LOW), _sig(d2, TrustDimension.BEHAVIOR, Severity.CRITICAL)],
    )
    report = build_report(state)
    assert [f.severity for f in report.findings] == ["CRITICAL", "LOW"]


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #

def test_render_json_roundtrips():
    state, _ = _state_with_finding()
    report = build_report(state, run_id="RID")
    text = render_json(report)
    data = json.loads(text)
    assert data["run_id"] == "RID"
    assert data["overall_severity"] == "HIGH"
    assert data["findings"][0]["signals"][0]["dimension"] in {"behavior", "popularity"}
    assert text.endswith("\n")


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #

def test_render_markdown_has_verdict_and_evidence():
    state, dep = _state_with_finding()
    md = render_markdown(build_report(state, run_id="RID"))
    assert "# SafeSC report" in md
    assert "FAIL" in md
    assert dep_key(dep) in md
    assert "install script exfiltrates env" in md
    assert "package/scripts/postinstall.js:12" in md


def test_render_markdown_incomplete_banner():
    dep = _dep()
    gd = GateDecision(passed=True, exit_code=0, summary="⚠ INCOMPLETE ANALYSIS: 1 degraded node(s)")
    state = AuditState(dependencies=[dep], gate_decision=gd)
    md = render_markdown(build_report(state))
    assert "INCOMPLETE ANALYSIS" in md


def test_render_markdown_clean_run():
    dep = _dep()
    gd = GateDecision(overall=Severity.CLEAN, passed=True, exit_code=0, summary="AUDIT: overall=CLEAN")
    state = AuditState(dependencies=[dep], gate_decision=gd)
    md = render_markdown(build_report(state))
    assert "No dependencies were flagged" in md


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #

def test_sarif_structure_and_result():
    state, dep = _state_with_finding()
    doc = build_sarif(build_report(state, run_id="RID"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "SafeSC"
    # clean/low + high signals: LOW popularity is not clean → it's a result too
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "llm.behavior" in rule_ids and "stage3.downloads" in rule_ids
    behavior = next(r for r in run["results"] if r["ruleId"] == "llm.behavior")
    assert behavior["level"] == "error"
    assert behavior["properties"]["security-severity"] == "8.0"
    assert behavior["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "package-lock.json"


def test_sarif_omits_clean_signals():
    dep = _dep()
    gd = GateDecision(overall=Severity.CLEAN, passed=True, exit_code=0, summary="AUDIT: clean")
    state = AuditState(
        dependencies=[dep],
        signals=[_sig(dep, TrustDimension.IDENTITY, Severity.CLEAN, origin=SignalOrigin.LLM, source="llm.identity")],
        gate_decision=gd,
    )
    doc = build_sarif(build_report(state))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_invocation_reflects_incomplete():
    dep = _dep()
    gd = GateDecision(passed=True, exit_code=0, summary="⚠ INCOMPLETE ANALYSIS: x")
    doc = build_sarif(build_report(AuditState(dependencies=[dep], gate_decision=gd)))
    assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_render_sarif_is_valid_json():
    state, _ = _state_with_finding()
    text = render_sarif(build_report(state))
    assert json.loads(text)["version"] == "2.1.0"


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #

def test_render_dispatch_and_unknown_format():
    state, _ = _state_with_finding()
    report = build_report(state)
    assert render(report, "json").startswith("{")
    assert render(report, "MARKDOWN").startswith("# SafeSC")
    with pytest.raises(ValueError):
        render(report, "pdf")


def test_write_reports_creates_files(tmp_path):
    state, _ = _state_with_finding()
    report = build_report(state, run_id="RID")
    paths = write_reports(report, tmp_path, formats=FORMATS)
    names = {p.name for p in paths}
    assert names == {"safesc-report.json", "safesc-report.md", "safesc-report.sarif"}
    for p in paths:
        assert p.exists() and p.read_text(encoding="utf-8").strip()


def test_write_reports_rejects_unknown_format(tmp_path):
    report = build_report(AuditState())
    with pytest.raises(ValueError):
        write_reports(report, tmp_path, formats=["json", "docx"])
