"""Unit tests for graph/state.py — the shared LangGraph state and its channel
reducers (CLAUDE.md §2.6). These exercise the reducers directly (they are plain
functions and need no LangGraph import) plus the §4.3 fusion table and the
escalate-only invariant."""

from __future__ import annotations

from pathlib import Path

import pytest

from graph.state import (
    AuditState,
    DegradedNote,
    GateDecision,
    LLMOutput,
    RoutePath,
    RunMode,
    RunScope,
    Severity,
    Signal,
    SignalOrigin,
    TrustDimension,
    _fuse,
    append_notes,
    dep_key,
    emit_degraded,
    emit_escalation,
    emit_signals,
    increment_llm_calls,
    max_severity,
    merge_signals,
    replace_if_present,
    sum_deltas,
    write_once,
)
from tools.index.core.models import Dependency


# --------------------------------------------------------------------------- #
# Enums / helpers
# --------------------------------------------------------------------------- #

def test_severity_is_ordered_for_max_wins():
    assert Severity.CLEAN < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert max(Severity.LOW, Severity.CRITICAL) is Severity.CRITICAL


def test_dep_key_from_dependency_and_str():
    dep = Dependency(name="requests", version="2.31.0", ecosystem="python", lockfile_path=Path("r.txt"))
    assert dep_key(dep) == "python:requests@2.31.0"
    assert dep_key("already:a@key") == "already:a@key"


# --------------------------------------------------------------------------- #
# §4.3 fusion table  (escalate-only)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "verdict,confidence,expected",
    [
        ("malicious", 0.9, Severity.CRITICAL),
        ("malicious", 0.7, Severity.CRITICAL),
        ("malicious", 0.5, Severity.HIGH),
        ("malicious", 0.4, Severity.HIGH),
        ("malicious", 0.1, Severity.MEDIUM),
        ("suspicious", 0.9, Severity.HIGH),
        ("suspicious", 0.7, Severity.HIGH),
        ("suspicious", 0.3, Severity.LOW),
        ("clean", 0.99, Severity.CLEAN),
        ("clean", 0.0, Severity.CLEAN),
        ("anything-unknown", 1.0, Severity.CLEAN),
        ("MALICIOUS", 0.9, Severity.CRITICAL),  # case-insensitive
    ],
)
def test_fuse_matches_fusion_table(verdict, confidence, expected):
    assert _fuse(verdict, confidence) is expected


def test_from_llm_output_clean_never_escalates():
    out = LLMOutput(task="behavior", verdict="clean", confidence=1.0, reasoning="looks fine")
    sig = Signal.from_llm_output("python:x@1", TrustDimension.BEHAVIOR, out)
    assert sig.severity is Severity.CLEAN
    assert sig.origin is SignalOrigin.LLM
    assert sig.source == "llm.behavior"


def test_from_llm_output_malicious_forces_critical_and_carries_evidence():
    out = LLMOutput(
        task="behavior",
        verdict="malicious",
        confidence=0.95,
        evidence=["exfiltrates env"],
        reasoning="posts process.env to remote host",
        false_positive_hints=["telemetry?"],
    )
    sig = Signal.from_llm_output("npm:evil@1", TrustDimension.BEHAVIOR, out)
    assert sig.severity is Severity.CRITICAL
    assert sig.evidence == ["exfiltrates env"]
    assert sig.false_positive_hints == ["telemetry?"]
    assert sig.confidence == 0.95


# --------------------------------------------------------------------------- #
# Channel reducers
# --------------------------------------------------------------------------- #

def _sig(key="k1", source="stage3.a", dim=TrustDimension.IDENTITY, sev=Severity.LOW):
    return Signal(dep_key=key, dimension=dim, origin=SignalOrigin.STATIC, source=source, severity=sev)


def test_merge_signals_is_additive_and_dedups():
    a = [_sig(source="stage3.a")]
    b = [_sig(source="stage3.a"), _sig(source="stage3.b")]  # first is a dup of a
    merged = merge_signals(a, b)
    identities = sorted(s.identity() for s in merged)
    assert identities == [("k1", "stage3.a", "identity"), ("k1", "stage3.b", "identity")]


def test_merge_signals_retry_is_idempotent():
    base = [_sig(source="stage3.a")]
    # same update applied twice (auto-repair retry) must not double-count
    once = merge_signals(base, [_sig(source="stage3.a")])
    twice = merge_signals(once, [_sig(source="stage3.a")])
    assert len(twice) == 1


def test_merge_signals_empty_update_returns_current():
    base = [_sig()]
    assert merge_signals(base, []) is base


def test_max_severity_takes_the_higher_tier():
    merged = max_severity({"d": Severity.LOW}, {"d": Severity.CRITICAL})
    assert merged["d"] is Severity.CRITICAL


def test_max_severity_never_downgrades():
    merged = max_severity({"d": Severity.HIGH}, {"d": Severity.LOW})
    assert merged["d"] is Severity.HIGH


def test_max_severity_is_order_independent():
    forward = max_severity(max_severity({}, {"d": Severity.LOW}), {"d": Severity.HIGH})
    reverse = max_severity(max_severity({}, {"d": Severity.HIGH}), {"d": Severity.LOW})
    assert forward == reverse == {"d": Severity.HIGH}


def test_sum_deltas_accumulates_and_handles_none():
    assert sum_deltas(None, None) == 0
    assert sum_deltas(None, 2) == 2
    assert sum_deltas(3, None) == 3
    assert sum_deltas(3, 4) == 7


def test_append_notes():
    a = [DegradedNote(node="n1", reason="r1")]
    b = [DegradedNote(node="n2", reason="r2")]
    assert [n.node for n in append_notes(a, b)] == ["n1", "n2"]
    assert append_notes(a, []) is a


def test_write_once_keeps_current_when_update_none():
    gd = GateDecision(passed=False)
    assert write_once(gd, None) is gd
    newgd = GateDecision(passed=True)
    assert write_once(gd, newgd) is newgd


def test_replace_if_present():
    assert replace_if_present([1], [2]) == [2]
    assert replace_if_present([1], []) == [1]


# --------------------------------------------------------------------------- #
# AuditState
# --------------------------------------------------------------------------- #

def test_audit_state_defaults():
    st = AuditState()
    assert st.mode is RunMode.AUDIT
    assert st.scope is RunScope.FULL_REPO
    assert st.path is RoutePath.FULL_SPINE
    assert st.signals == [] and st.escalations == {} and st.llm_calls == 0
    assert st.gate_decision is None


def test_would_exceed_cap():
    st = AuditState(llm_calls=199, llm_call_cap=200)
    assert st.would_exceed_cap(1) is False
    assert st.would_exceed_cap(2) is True


def test_signals_for_filters_by_dep_key():
    st = AuditState(signals=[_sig(key="a"), _sig(key="b", source="stage3.b")])
    assert len(st.signals_for("a")) == 1
    assert st.signals_for("a")[0].dep_key == "a"


def test_reducers_are_wired_into_annotated_fields():
    # Pydantic surfaces Annotated[T, reducer] extras via FieldInfo.metadata; this is
    # exactly what LangGraph reads at graph-build time.
    fields = AuditState.model_fields
    assert merge_signals in fields["signals"].metadata
    assert max_severity in fields["escalations"].metadata
    assert sum_deltas in fields["llm_calls"].metadata
    assert append_notes in fields["degraded_notes"].metadata
    assert write_once in fields["gate_decision"].metadata


# --------------------------------------------------------------------------- #
# node-return helpers
# --------------------------------------------------------------------------- #

def test_emit_helpers_return_delta_dicts():
    assert increment_llm_calls(3) == {"llm_calls": 3}
    assert emit_escalation("k", Severity.HIGH) == {"escalations": {"k": Severity.HIGH}}
    assert emit_signals([_sig()])["signals"][0].dep_key == "k1"
    note = emit_degraded("node", "why")["degraded_notes"][0]
    assert note.node == "node" and note.reason == "why"
