"""core/ — signals + fusion, the ledger's merge rules, the gate, the scorer, target resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from safesc.core.gate import plan_triage
from safesc.core.ledger import Decision, Feature, Role, Stage
from safesc.core.scoring import grade_for, score, trust_score
from safesc.core.signals import LLMOutput, Severity, Signal, SignalOrigin, TrustDimension, dep_key, fuse
from safesc.core.targets import TargetKind, classify_target, default_target, is_ci, parse_package_spec
from tests.helpers import dep, ledger, sig

# ------------------------------------------------------------------ signals + fusion


@pytest.mark.parametrize("verdict,conf,expected", [
    ("malicious", 0.9, Severity.CRITICAL), ("malicious", 0.5, Severity.HIGH), ("malicious", 0.2, Severity.MEDIUM),
    ("suspicious", 0.7, Severity.HIGH), ("suspicious", 0.69, Severity.LOW), ("clean", 1.0, Severity.CLEAN),
])
def test_fusion_table(verdict, conf, expected):
    assert fuse(verdict, conf) is expected


def test_ceiling_caps_a_new_llm_signal():
    out = LLMOutput(verdict="suspicious", confidence=0.95, reasoning="confirmed but minor")
    assert Signal.from_llm_output("k", TrustDimension.VULNERABILITY, out, ceiling=Severity.MEDIUM).severity is Severity.MEDIUM
    assert Signal.from_llm_output("k", TrustDimension.VULNERABILITY, out).severity is Severity.HIGH


# ------------------------------------------------------------------ ledger


def test_signals_dedupe_by_identity_and_keep_the_higher():
    d = dep()
    led = ledger(deps=[d])
    hi = sig(d, TrustDimension.BEHAVIOR, Severity.HIGH, origin=SignalOrigin.LLM, source="llm.behavior")
    lo = sig(d, TrustDimension.BEHAVIOR, Severity.CLEAN, origin=SignalOrigin.LLM, source="llm.behavior")
    assert led.add_signals([hi]) == 1
    assert led.add_signals([lo]) == 0  # a later "clean" never clears an earlier finding
    assert led.add_signals([hi]) == 0  # retries are idempotent
    assert [s.severity for s in led.signals] == [Severity.HIGH]


def test_finalize_is_write_once():
    led = ledger()
    assert led.finalize(Decision(summary="first"))
    assert not led.finalize(Decision(summary="second"))
    assert led.decision.summary == "first"


def test_budget_is_consumed_never_returned():
    led = ledger(max_subagents=2)
    assert led.try_consume_budget() and led.try_consume_budget()
    assert not led.try_consume_budget() and led.budget_exhausted


def test_required_coverage_combines_gray_zone_features_and_candidates():
    direct, transitive = dep("a"), dep("b", direct=False)
    led = ledger(deps=[direct, transitive], features=frozenset({Feature.AUTHORSHIP}),
                 signals=[sig(transitive, TrustDimension.IDENTITY, Severity.MEDIUM)])
    req = {(k, r) for k, r, _ in led.required_coverage()}
    assert req == {(dep_key(transitive), Role.IDENTITY), (dep_key(direct), Role.AUTHORSHIP)}
    led.register_candidates(dep_key(direct), [{"title": "t", "file": "a.c"}])
    assert (dep_key(direct), Role.VULN_VERIFIER) in {(k, r) for k, r, _ in led.required_coverage()}


def test_transitive_feature_widens_scope():
    direct, transitive = dep("a"), dep("b", direct=False)
    led = ledger(deps=[direct, transitive], features=frozenset({Feature.VULN_HUNT, Feature.TRANSITIVE}))
    assert {k for k, r, _ in led.required_coverage()} == {dep_key(direct), dep_key(transitive)}


def test_outstanding_coverage_clears_when_attempted_or_budget_spent():
    d = dep()
    led = ledger(deps=[d], signals=[sig(d, TrustDimension.BEHAVIOR, Severity.MEDIUM)], max_subagents=1)
    assert led.outstanding_coverage()
    led.record_subagent(dep_key(d), Role.BEHAVIOR, "degraded", "boom")
    assert not led.outstanding_coverage()
    led2 = ledger(deps=[d], signals=[sig(d, TrustDimension.BEHAVIOR, Severity.MEDIUM)], max_subagents=1)
    led2.try_consume_budget()
    assert led2.outstanding_coverage() == []  # nothing can run any more; scorer reports it


def test_verifier_coverage_tracks_pending_candidates():
    d = dep()
    led = ledger(deps=[d])
    (cid,) = led.register_candidates(dep_key(d), [{"title": "t", "file": "a.c", "line": 3}])
    assert [(r) for _, r, _ in led.outstanding_coverage()] == [Role.VULN_VERIFIER]
    led.resolve_candidate(cid, "refuted", "bounds-checked")
    assert led.outstanding_coverage() == []


def test_citable_includes_workspace_files(tmp_path):
    d = dep()
    led = ledger(deps=[d])
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("x")
    led.set_workspace(dep_key(d), tmp_path)
    led.register_citable(dep_key(d), ["hasInstallScript=true"])
    assert {"src/a.c", "hasInstallScript=true"} <= led.citable(dep_key(d))


# ------------------------------------------------------------------ gate


def test_triage_takes_only_llm_dimensions_in_the_gray_band():
    d1, d2, d3 = dep("a"), dep("b"), dep("c")
    led = ledger(deps=[d1, d2, d3], signals=[
        sig(d1, TrustDimension.BEHAVIOR, Severity.HIGH),          # gray: needs analysis
        sig(d2, TrustDimension.IDENTITY, Severity.CRITICAL),       # already decided
        sig(d3, TrustDimension.VULNERABILITY, Severity.HIGH),      # deterministic dimension
        sig(d3, TrustDimension.PROVENANCE, Severity.LOW),          # below the floor
    ])
    assert [(t.dep_key, t.dimension) for t in plan_triage(led)] == [(dep_key(d1), TrustDimension.BEHAVIOR)]


def test_triage_ignores_llm_signals():
    d = dep()
    led = ledger(deps=[d], signals=[sig(d, TrustDimension.BEHAVIOR, Severity.HIGH, origin=SignalOrigin.LLM, source="llm.behavior")])
    assert plan_triage(led) == []


# ------------------------------------------------------------------ scorer


def _complete(led):
    for s in (Stage.DISCOVER, Stage.PARSE, Stage.VERIFY, Stage.COLLECT):
        led.mark_stage(s)
    return led


def test_score_rules_and_gate():
    clean = _complete(ledger(deps=[dep("a"), dep("b")]))
    d = score(clean)
    assert d.passed and d.exit_code == 0 and d.score == 100 and d.grade == "A" and not d.incomplete

    x = dep("x")
    high = _complete(ledger(deps=[x], signals=[sig(x, TrustDimension.VULNERABILITY, Severity.HIGH)]))
    d = score(high)
    assert not d.passed and d.exit_code == 1
    assert d.score == 59 and d.grade == "D"
    assert "x@1.0.0" in d.summary


def test_trust_score_penalties_and_ceilings():
    assert trust_score({"a": Severity.MEDIUM, "b": Severity.LOW}, incomplete=False) == 95
    assert trust_score({"a": Severity.HIGH}, incomplete=False) == 59
    assert trust_score({"a": Severity.CRITICAL}, incomplete=False) == 19
    assert trust_score({f"d{i}": Severity.MEDIUM for i in range(40)}, incomplete=False) == 0
    assert trust_score({}, incomplete=True) == 89
    assert [grade_for(s) for s in (100, 90, 89, 75, 60, 59, 40, 39)] == ["A", "A", "B", "B", "C", "D", "D", "F"]


def test_incomplete_is_provisional_unless_strict():
    d = dep()
    led = _complete(ledger(deps=[d], signals=[sig(d, TrustDimension.BEHAVIOR, Severity.MEDIUM)]))
    led.record_subagent(dep_key(d), Role.BEHAVIOR, "denied", "budget")
    lenient = score(led)
    assert lenient.passed and lenient.incomplete and "INCOMPLETE" in lenient.summary
    assert not score(led, strict=True).passed


def test_never_run_static_stage_is_incomplete():
    d = score(ledger(deps=[dep()]))
    assert d.incomplete and any("never ran" in r for r in d.incomplete_reasons)


def test_fail_on_threshold():
    x = dep()
    led = _complete(ledger(deps=[x], signals=[sig(x, TrustDimension.IDENTITY, Severity.MEDIUM)], fail_on=Severity.MEDIUM))
    assert not score(led).passed


# ------------------------------------------------------------------ targets


@pytest.mark.parametrize("target,kind", [
    (".", TargetKind.REPOSITORY), ("./sub", TargetKind.REPOSITORY), ("poetry.lock", TargetKind.REPOSITORY),
    ("C:\\work\\repo", TargetKind.REPOSITORY), ("some/dir", TargetKind.REPOSITORY),
    ("npm:left-pad@1.3.0", TargetKind.PACKAGE), ("pkg:pypi/requests@2.31.0", TargetKind.PACKAGE),
    ("@angular/core@17.0.0", TargetKind.PACKAGE), ("requests@2.31.0", TargetKind.PACKAGE),
])
def test_classify_target(target, kind):
    assert classify_target(target) is kind


@pytest.mark.parametrize("spec,expected", [
    ("npm:left-pad@1.3.0", ("javascript", "left-pad", "1.3.0")),
    ("pkg:pypi/requests@2.31.0", ("python", "requests", "2.31.0")),
    ("pkg:maven/org.apache/commons@1.0", ("java", "org.apache/commons", "1.0")),
    ("@angular/core@17.0.0", ("javascript", "@angular/core", "17.0.0")),
    ("crates:serde@1.0.200", ("rust", "serde", "1.0.200")),
])
def test_parse_package_spec(spec, expected):
    d = parse_package_spec(spec)
    assert (d.ecosystem, d.name, d.version) == expected and d.is_direct


def test_ci_detection_and_default_target(tmp_path):
    assert not is_ci({}) and not is_ci({"CI": "false"})
    assert is_ci({"CI": "true"}) and is_ci({"GITHUB_ACTIONS": "true"})
    assert default_target({}, cwd=tmp_path) == str(tmp_path)
    ws = tmp_path / "ws"
    ws.mkdir()
    assert default_target({"CI": "true", "GITHUB_WORKSPACE": str(ws)}, cwd=tmp_path) == str(ws)
    assert Path(default_target({"CI": "1"}, cwd=tmp_path)).exists()  # git top-level or cwd
