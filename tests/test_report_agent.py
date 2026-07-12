"""Unit tests for graph/report_agent.py — the scorer / terminal reducer (CLAUDE.md §2.4).

The scorer is the sole decision point. These tests pin the weakest-link combination,
the audit-vs-query gate behaviour, and the "incomplete analysis" surfacing (§5.3/§8.5).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from graph.report_agent import (
    ScoreConfig,
    _dep_breakdown,
    _top_reason,
    add_report,
    report_node,
    score,
)
from graph.spine import NODE_REPORT
from graph.state import (
    AuditState,
    DegradedNote,
    RunMode,
    Severity,
    Signal,
    SignalOrigin,
    TrustDimension,
    dep_key,
)
from tools.index.core.models import Dependency


def _dep(name="pkg", version="1.0.0", ecosystem="npm"):
    return Dependency(name=name, version=version, ecosystem=ecosystem, lockfile_path=Path("p"))


def _sig(dep, dimension, severity, origin=SignalOrigin.STATIC, source="stage3.x"):
    return Signal(dep_key=dep_key(dep), dimension=dimension, origin=origin, source=source, severity=severity)


# --------------------------------------------------------------------------- #
# combination / gate
# --------------------------------------------------------------------------- #

def test_empty_run_is_clean_pass():
    gd = score(AuditState())
    assert gd.overall is Severity.CLEAN
    assert gd.passed is True and gd.exit_code == 0


def test_per_dep_is_max_across_signals():
    dep = _dep()
    state = AuditState(
        dependencies=[dep],
        signals=[
            _sig(dep, TrustDimension.POPULARITY, Severity.LOW),
            _sig(dep, TrustDimension.BEHAVIOR, Severity.HIGH),
            _sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM),
        ],
    )
    gd = score(state)
    assert gd.per_dep[dep_key(dep)] is Severity.HIGH


def test_overall_is_max_across_deps():
    d1, d2 = _dep("a"), _dep("b")
    state = AuditState(
        dependencies=[d1, d2],
        signals=[_sig(d1, TrustDimension.IDENTITY, Severity.LOW), _sig(d2, TrustDimension.BEHAVIOR, Severity.CRITICAL)],
    )
    gd = score(state)
    assert gd.overall is Severity.CRITICAL


def test_audit_fails_at_or_above_threshold():
    dep = _dep()
    state = AuditState(mode=RunMode.AUDIT, dependencies=[dep], signals=[_sig(dep, TrustDimension.BEHAVIOR, Severity.HIGH)])
    gd = score(state)
    assert gd.passed is False and gd.exit_code == 1
    assert "Flagged:" in gd.summary and dep_key(dep) in gd.summary


def test_audit_passes_below_threshold():
    dep = _dep()
    state = AuditState(mode=RunMode.AUDIT, dependencies=[dep], signals=[_sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM)])
    gd = score(state)
    assert gd.passed is True and gd.exit_code == 0


def test_query_mode_never_returns_failing_exit_code():
    dep = _dep()
    state = AuditState(mode=RunMode.QUERY, dependencies=[dep], signals=[_sig(dep, TrustDimension.BEHAVIOR, Severity.CRITICAL)])
    gd = score(state)
    assert gd.overall is Severity.CRITICAL
    assert gd.passed is False       # verdict still reported honestly
    assert gd.exit_code == 0        # but a query never gates CI (§1.3)
    assert gd.summary.startswith("QUERY:")


def test_custom_fail_threshold():
    dep = _dep()
    state = AuditState(mode=RunMode.AUDIT, dependencies=[dep], signals=[_sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM)])
    gd = score(state, ScoreConfig(fail_threshold=Severity.MEDIUM))
    assert gd.passed is False and gd.exit_code == 1


def test_score_config_is_frozen():
    cfg = ScoreConfig()
    assert cfg.fail_threshold is Severity.HIGH
    with pytest.raises(Exception):
        cfg.fail_threshold = Severity.LOW


# --------------------------------------------------------------------------- #
# incomplete-analysis surfacing
# --------------------------------------------------------------------------- #

def test_degraded_notes_mark_incomplete():
    dep = _dep()
    state = AuditState(dependencies=[dep], degraded_notes=[DegradedNote(node="gate", reason="budget")])
    gd = score(state)
    assert "INCOMPLETE ANALYSIS" in gd.summary
    assert "degraded node" in gd.summary


def test_gray_zone_without_llm_signal_marks_incomplete():
    dep = _dep()
    state = AuditState(
        dependencies=[dep],
        signals=[_sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM)],
        escalations={dep_key(dep): Severity.MEDIUM},   # escalated but no llm signal present
    )
    gd = score(state)
    assert "without LLM analysis" in gd.summary


def test_gray_zone_with_llm_signal_is_complete():
    dep = _dep()
    state = AuditState(
        dependencies=[dep],
        signals=[
            _sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM),
            _sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM, origin=SignalOrigin.LLM, source="llm.identity"),
        ],
        escalations={dep_key(dep): Severity.MEDIUM},
    )
    gd = score(state)
    assert "INCOMPLETE ANALYSIS" not in gd.summary


def test_llm_cap_exceeded_marks_incomplete():
    state = AuditState(dependencies=[_dep()], llm_calls=201, llm_call_cap=200)
    gd = score(state)
    assert "LLM call cap exceeded" in gd.summary


def test_clean_complete_run_has_no_incomplete_banner():
    dep = _dep()
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.POPULARITY, Severity.LOW)])
    gd = score(state)
    assert "INCOMPLETE ANALYSIS" not in gd.summary


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def test_dep_breakdown_is_per_dimension_max():
    dep = _dep()
    signals = [
        _sig(dep, TrustDimension.IDENTITY, Severity.LOW),
        _sig(dep, TrustDimension.IDENTITY, Severity.HIGH),
        _sig(dep, TrustDimension.BEHAVIOR, Severity.MEDIUM),
    ]
    breakdown = _dep_breakdown(signals, dep_key(dep))
    assert breakdown[TrustDimension.IDENTITY] is Severity.HIGH
    assert breakdown[TrustDimension.BEHAVIOR] is Severity.MEDIUM


def test_top_reason_picks_worst_and_formats_origin():
    dep = _dep()
    signals = [
        _sig(dep, TrustDimension.IDENTITY, Severity.LOW, source="stage3.a"),
        _sig(dep, TrustDimension.BEHAVIOR, Severity.CRITICAL, origin=SignalOrigin.LLM, source="llm.behavior"),
    ]
    reason = _top_reason(signals, dep_key(dep))
    assert "behavior=CRITICAL" in reason
    assert "(llm:llm.behavior)" in reason


def test_top_reason_no_signals():
    assert _top_reason([], "npm:x@1") == "no signals"


# --------------------------------------------------------------------------- #
# node / wiring
# --------------------------------------------------------------------------- #

def test_report_node_writes_gate_decision_only():
    dep = _dep()
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.BEHAVIOR, Severity.HIGH)])
    out = report_node(state)
    assert set(out) == {"gate_decision"}
    assert out["gate_decision"].overall is Severity.HIGH


class _FakeBuilder:
    def __init__(self):
        self.nodes = {}
        self.edges = []

    def add_node(self, name, fn):
        self.nodes[name] = fn

    def add_edge(self, src, dst):
        self.edges.append((src, dst))


def test_add_report_registers_terminal_node():
    builder = _FakeBuilder()
    name = add_report(builder)
    assert name == NODE_REPORT
    assert NODE_REPORT in builder.nodes
