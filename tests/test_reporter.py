"""Unit tests for reporter/ — the JSON / Markdown / SARIF sink (CLAUDE.md §6, §7).

The reporter makes NO decisions: these tests pin that it faithfully projects the scorer's
`Decision` + the run's ledger into all three formats, that escalate-only stays visible
(clean signals produce no SARIF result), and that an incomplete run is surfaced loudly.
"""

from __future__ import annotations

import json

import pytest

from safesc.core.ledger import Decision, Role
from safesc.core.scoring import score
from safesc.core.signals import Severity, SignalOrigin, TrustDimension, dep_key
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
from tests.helpers import dep, ledger, sig


def _finding_run():
    d = dep()
    led = ledger(deps=[d], signals=[
        sig(d, TrustDimension.POPULARITY, Severity.LOW, source="popularity.archived"),
        sig(d, TrustDimension.BEHAVIOR, Severity.HIGH, origin=SignalOrigin.LLM, source="llm.behavior",
            confidence=0.8, summary="install script exfiltrates env",
            reasoning="the postinstall reads process.env and POSTs it", evidence=["package/scripts/postinstall.js:12"]),
    ])
    led.record_subagent(dep_key(d), Role.BEHAVIOR, "ok", "verdict=malicious")
    return led, score(led), d


def test_build_report_rolls_up_per_dep_max():
    led, decision, d = _finding_run()
    report = build_report(led, decision, model="anthropic/claude-test")
    assert report.run_id == "RUNID" and report.model == "anthropic/claude-test"
    assert report.overall_severity == "HIGH"
    assert report.passed is False and report.exit_code == 1
    assert report.trust_score == decision.score and report.grade == decision.grade
    assert report.total_dependencies == 1 and report.flagged_count == 1
    f = report.findings[0]
    assert f.severity == "HIGH" and f.direct is True
    assert f.dimensions == {"popularity": "LOW", "behavior": "HIGH"}
    assert [s.source for s in f.signals] == ["llm.behavior", "popularity.archived"]  # worst first
    assert report.subagent_runs[0].role == "behavior"


def test_build_report_carries_incompleteness_and_notes():
    d = dep()
    led = ledger(deps=[d])
    led.add_note("collect", "OsvCollector could not complete")
    report = build_report(led, score(led))
    assert report.incomplete is True and report.incomplete_reasons
    assert report.degraded[0].node == "collect"


def test_build_report_lists_vulnerability_candidates():
    d = dep()
    led = ledger(deps=[d])
    (cid,) = led.register_candidates(dep_key(d), [{
        "title": "strcpy overflow", "cwe": "CWE-120", "file": "src/a.c", "line": 7,
        "claimed_severity": "high", "description": "x",
    }])
    led.resolve_candidate(cid, "confirmed", "reachable via parse()")
    report = build_report(led, score(led))
    (c,) = report.vulnerability_candidates
    assert c.id == cid and c.location == "src/a.c:7" and c.status == "confirmed"
    md = render_markdown(report)
    assert "Unreported-vulnerability candidates" in md and "strcpy overflow (CWE-120)" in md


def test_findings_sorted_by_severity_desc():
    d1, d2 = dep("a"), dep("b")
    led = ledger(deps=[d1, d2], signals=[
        sig(d1, TrustDimension.IDENTITY, Severity.LOW), sig(d2, TrustDimension.BEHAVIOR, Severity.CRITICAL),
    ])
    assert [f.severity for f in build_report(led, score(led)).findings] == ["CRITICAL", "LOW"]


def test_render_json_roundtrips():
    led, decision, _ = _finding_run()
    data = json.loads(render_json(build_report(led, decision)))
    assert data["run_id"] == "RUNID" and data["overall_severity"] == "HIGH"
    assert data["schema_version"] == "2.0" and "trust_score" in data


def test_render_markdown_has_verdict_score_and_evidence():
    led, decision, d = _finding_run()
    md = render_markdown(build_report(led, decision))
    assert "# SafeSC report" in md and "FAIL" in md
    assert f"{decision.score}/100" in md
    assert dep_key(d) in md
    assert "install script exfiltrates env" in md
    assert "package/scripts/postinstall.js:12" in md


def test_render_markdown_error_and_clean_runs():
    d = dep()
    led = ledger(deps=[d])
    err = Decision(passed=False, exit_code=2, summary="ERROR: no verdict", incomplete=True,
                   incomplete_reasons=["the orchestrator did not finalize the score"], score=0, grade="F")
    md = render_markdown(build_report(led, err))
    assert "ERROR" in md and "INCOMPLETE ANALYSIS" in md
    clean = ledger(deps=[d], signals=[sig(d, TrustDimension.POPULARITY, Severity.CLEAN)])
    assert "No dependencies were flagged" in render_markdown(build_report(clean, score(clean)))


def test_sarif_structure_and_result():
    led, decision, _ = _finding_run()
    doc = build_sarif(build_report(led, decision))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "SafeSC"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"llm.behavior", "popularity.archived"} <= rule_ids
    behavior = next(r for r in run["results"] if r["ruleId"] == "llm.behavior")
    assert behavior["level"] == "error"
    assert behavior["properties"]["security-severity"] == "8.0"
    assert behavior["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "package-lock.json"
    assert run["invocations"][0]["properties"]["trust_score"] == decision.score


def test_sarif_omits_clean_signals_and_reflects_incomplete():
    d = dep()
    led = ledger(deps=[d], signals=[sig(d, TrustDimension.IDENTITY, Severity.CLEAN, origin=SignalOrigin.LLM, source="llm.identity")])
    doc = build_sarif(build_report(led, score(led)))
    assert doc["runs"][0]["results"] == [] and doc["runs"][0]["tool"]["driver"]["rules"] == []
    led.add_note("x", "y")
    doc = build_sarif(build_report(led, score(led)))
    assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert json.loads(render_sarif(build_report(led, score(led))))["version"] == "2.1.0"


def test_render_dispatch_and_write(tmp_path):
    led, decision, _ = _finding_run()
    report = build_report(led, decision)
    assert render(report, "json").startswith("{")
    assert render(report, "MARKDOWN").startswith("# SafeSC")
    with pytest.raises(ValueError):
        render(report, "pdf")
    names = {p.name for p in write_reports(report, tmp_path, formats=FORMATS)}
    assert names == {"safesc-report.json", "safesc-report.md", "safesc-report.sarif"}
    with pytest.raises(ValueError):
        write_reports(report, tmp_path, formats=["json", "docx"])
