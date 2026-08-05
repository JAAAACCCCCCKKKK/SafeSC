"""Unit tests for graph/spine.py — the deterministic spine and the post-Stage-3
risk gate (CLAUDE.md §2.2-B, §2.5).

Everything here is LLM-free and LangGraph-free: the stage nodes take injected fake
tools, the gate core (`plan_gate`) is pure, and the LangGraph glue (`gate_edge`,
`add_spine`) is exercised with a fake `Send` / fake builder.
"""

from __future__ import annotations

from pathlib import Path
import tempfile

import pytest

import graph.spine as spine
from graph.spine import (
    NODE_CHEAP_SIGNALS,
    NODE_GATE,
    NODE_HASH_VERIFY,
    NODE_INDEX,
    NODE_REPORT,
    SPECIALIST_NODE,
    GateConfig,
    InjectedTools,
    LockfileRef,
    SpecialistTask,
    _dimension_severity,
    _hash_result_to_graph,
    _scan_severity_to_graph,
    _scan_signal_to_graph,
    add_spine,
    cheap_signals_node,
    gate_edge,
    gate_node,
    hash_verify_node,
    index_node,
    load_default_tools,
    plan_gate,
)
from graph.state import (
    AuditState,
    Severity,
    Signal,
    SignalOrigin,
    TrustDimension,
    dep_key,
)
from tools.index.core.models import Dependency


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _dep(name="requests", version="2.31.0", ecosystem="python"):
    return Dependency(name=name, version=version, ecosystem=ecosystem, lockfile_path=Path("r.txt"))


def _sig(dep, dimension, severity, source="stage3.x", evidence=None):
    return Signal(
        dep_key=dep_key(dep),
        dimension=dimension,
        origin=SignalOrigin.STATIC,
        source=source,
        severity=severity,
        evidence=list(evidence or []),
    )


def _tools(discover=None, parse=None, verify_hash=None, collect_signals=None):
    return InjectedTools(
        discover=discover or (lambda target: []),
        parse=parse or (lambda lockfiles: []),
        verify_hash=verify_hash or (lambda dep: []),
        collect_signals=collect_signals or (lambda dep: []),
    )


# --------------------------------------------------------------------------- #
# Stage nodes — fixed sequence, independent degradation
# --------------------------------------------------------------------------- #

def test_index_node_happy_path():
    dep = _dep()
    tools = _tools(
        discover=lambda target: [LockfileRef(path="r.txt", ecosystem="python")],
        parse=lambda lockfiles: [dep],
    )
    out = index_node(AuditState(target="."), tools)
    assert out == {"dependencies": [dep]}


def test_index_node_degrades_on_discovery_failure():
    def boom(target):
        raise RuntimeError("disk gone")

    out = index_node(AuditState(target="."), _tools(discover=boom))
    assert out["dependencies"] == []
    note = out["degraded_notes"][0]
    assert note.node == NODE_INDEX and "discovery failed" in note.reason


def test_index_node_degrades_on_parse_failure():
    def boom(lockfiles):
        raise ValueError("bad lockfile")

    tools = _tools(
        discover=lambda target: [LockfileRef(path="r.txt", ecosystem="python")],
        parse=boom,
    )
    out = index_node(AuditState(target="."), tools)
    assert out["dependencies"] == []
    assert "parse failed" in out["degraded_notes"][0].reason


def test_index_node_flags_discovered_but_empty_lockfile():
    # A discovered lockfile that parses to zero deps (e.g. a mis-encoded requirements.txt)
    # must degrade the run instead of passing as a silent clean 0-dep audit.
    tools = _tools(
        discover=lambda target: [LockfileRef(path="requirements.txt", ecosystem="python")],
        parse=lambda lockfiles: [],
    )
    out = index_node(AuditState(target="."), tools)
    assert out["dependencies"] == []
    notes = out["degraded_notes"]
    assert len(notes) == 1
    assert notes[0].node == NODE_INDEX
    assert "requirements.txt" in notes[0].reason
    assert "0 dependencies" in notes[0].reason


def test_index_node_does_not_flag_empty_manifest_only_file():
    # pyproject.toml / setup.cfg legitimately declare zero *pinned* deps; no warning.
    tools = _tools(
        discover=lambda target: [
            LockfileRef(path="pyproject.toml", ecosystem="python"),
            LockfileRef(path="setup.cfg", ecosystem="python"),
        ],
        parse=lambda lockfiles: [],
    )
    out = index_node(AuditState(target="."), tools)
    assert out == {"dependencies": []}


def test_index_node_flags_only_the_empty_lockfile_when_mixed():
    dep = _dep()  # lockfile_path == Path("r.txt")
    tools = _tools(
        discover=lambda target: [
            LockfileRef(path="r.txt", ecosystem="python"),            # produced a dep → ok
            LockfileRef(path="go.sum", ecosystem="go"),               # empty → flagged
        ],
        parse=lambda lockfiles: [dep],
    )
    out = index_node(AuditState(target="."), tools)
    assert out["dependencies"] == [dep]
    assert len(out["degraded_notes"]) == 1
    assert "go.sum" in out["degraded_notes"][0].reason


def test_hash_verify_node_aggregates_and_degrades_per_dep():
    good, bad = _dep("good"), _dep("bad")

    def verify(dep):
        if dep.name == "bad":
            raise RuntimeError("registry down")
        return [_sig(dep, TrustDimension.PROVENANCE, Severity.CRITICAL, "stage2.hash.mismatch")]

    out = hash_verify_node(AuditState(dependencies=[good, bad]), _tools(verify_hash=verify))
    assert len(out["signals"]) == 1
    assert out["signals"][0].dep_key == "python:good@2.31.0"
    assert any("bad" in n.reason for n in out["degraded_notes"])


def test_cheap_signals_node_aggregates_and_degrades_per_dep():
    good, bad = _dep("good"), _dep("bad")

    def collect(dep):
        if dep.name == "bad":
            raise RuntimeError("collector exploded")
        return [_sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM)]

    out = cheap_signals_node(AuditState(dependencies=[good, bad]), _tools(collect_signals=collect))
    assert len(out["signals"]) == 1
    assert out["degraded_notes"]


def test_stage_nodes_have_no_degraded_key_when_clean():
    dep = _dep()
    out = hash_verify_node(
        AuditState(dependencies=[dep]),
        _tools(verify_hash=lambda d: [_sig(d, TrustDimension.PROVENANCE, Severity.CLEAN)]),
    )
    assert "degraded_notes" not in out


# --------------------------------------------------------------------------- #
# The gate (branch point B) — pure core
# --------------------------------------------------------------------------- #

def test_gray_zone_llm_dimension_fans_out():
    dep = _dep()
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM, "stage3.typosquat")])
    plan = plan_gate(state)
    assert plan.escalated_count() == 1
    task = plan.fan_out[0]
    assert task.dimension is TrustDimension.IDENTITY
    assert task.trigger_severity is Severity.MEDIUM
    assert task.trigger_sources == ["stage3.typosquat"]
    assert plan.escalations[dep_key(dep)] is Severity.MEDIUM


def test_fan_out_task_carries_static_trigger_evidence():
    # The gate must forward the static signal's evidence (e.g. nearest_popular) to the
    # specialist so the IdentityAgent knows which popular package to compare against.
    dep = _dep(name="redisvl")
    state = AuditState(
        dependencies=[dep],
        signals=[
            _sig(
                dep, TrustDimension.IDENTITY, Severity.MEDIUM,
                "stage3.identity.typosquat",
                evidence=["nearest_popular=redis", "edit_distance=2"],
            )
        ],
    )
    plan = plan_gate(state)
    task = plan.fan_out[0]
    assert "nearest_popular=redis" in task.trigger_evidence
    assert "edit_distance=2" in task.trigger_evidence


def test_popularity_and_vulnerability_never_fan_out():
    dep = _dep()
    state = AuditState(
        dependencies=[dep],
        signals=[
            _sig(dep, TrustDimension.POPULARITY, Severity.HIGH),
            _sig(dep, TrustDimension.VULNERABILITY, Severity.HIGH),
        ],
    )
    plan = plan_gate(state)
    assert plan.fan_out == []                       # no LLM task for these dimensions
    assert plan.escalations[dep_key(dep)] is Severity.HIGH  # but severity still recorded


def test_decided_ceiling_is_not_sent_to_llm():
    dep = _dep()
    # A confirmed hash mismatch = CRITICAL provenance: already decided, no LLM needed.
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.PROVENANCE, Severity.CRITICAL)])
    plan = plan_gate(state)
    assert plan.fan_out == []
    assert plan.escalations[dep_key(dep)] is Severity.CRITICAL


def test_below_gray_floor_is_not_sent_to_llm():
    dep = _dep()
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.BEHAVIOR, Severity.LOW)])
    plan = plan_gate(state)
    assert plan.fan_out == []
    assert plan.escalations[dep_key(dep)] is Severity.LOW  # escalate-only: still carried


def test_clean_dep_is_absent_from_escalations():
    dep = _dep()
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.IDENTITY, Severity.CLEAN)])
    plan = plan_gate(state)
    assert plan.fan_out == []
    assert dep_key(dep) not in plan.escalations


def test_multiple_gray_dimensions_fan_out_each():
    dep = _dep()
    state = AuditState(
        dependencies=[dep],
        signals=[
            _sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM),
            _sig(dep, TrustDimension.BEHAVIOR, Severity.HIGH),
        ],
    )
    plan = plan_gate(state)
    dims = {t.dimension for t in plan.fan_out}
    assert dims == {TrustDimension.IDENTITY, TrustDimension.BEHAVIOR}
    assert plan.escalations[dep_key(dep)] is Severity.HIGH  # overall = max across dims


def test_gate_respects_custom_config():
    dep = _dep()
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.BEHAVIOR, Severity.LOW)])
    cfg = GateConfig(gray_floor=Severity.LOW)
    plan = plan_gate(state, cfg)
    assert plan.escalated_count() == 1  # LOW now inside the gray band


def test_gate_config_defaults_and_frozen():
    cfg = GateConfig()
    assert cfg.gray_floor is Severity.MEDIUM
    assert cfg.decided_ceiling is Severity.CRITICAL
    assert cfg.llm_dimensions == frozenset(
        {TrustDimension.IDENTITY, TrustDimension.BEHAVIOR, TrustDimension.PROVENANCE}
    )
    with pytest.raises(Exception):
        cfg.gray_floor = Severity.LOW  # frozen


def test_dimension_severity_max_and_source_accumulation():
    dep = _dep()
    signals = [
        _sig(dep, TrustDimension.IDENTITY, Severity.LOW, "a"),
        _sig(dep, TrustDimension.IDENTITY, Severity.HIGH, "b"),
        _sig(dep, TrustDimension.IDENTITY, Severity.HIGH, "c"),  # equal to max → source added
    ]
    result = _dimension_severity(signals, dep_key(dep))
    sev, sources = result[TrustDimension.IDENTITY]
    assert sev is Severity.HIGH
    assert set(sources) == {"b", "c"}


def test_gate_node_writes_escalations_and_dispatched():
    dep = _dep()
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM)])
    out = gate_node(state)
    # gray-zone on an LLM dimension → escalated AND recorded as dispatched to a specialist
    assert out["escalations"] == {dep_key(dep): Severity.MEDIUM}
    assert out["dispatched"] == [dep_key(dep)]
    assert "degraded_notes" not in out


def test_gate_node_no_dispatch_for_deterministic_only_escalation():
    # A dep escalated purely on a deterministic dimension (vulnerability) has no LLM
    # specialist, so the gate dispatches nothing — it must not appear in `dispatched`.
    dep = _dep()
    state = AuditState(
        dependencies=[dep],
        signals=[_sig(dep, TrustDimension.VULNERABILITY, Severity.HIGH, source="vulnerability.osv")],
    )
    out = gate_node(state)
    assert out["escalations"] == {dep_key(dep): Severity.HIGH}
    assert "dispatched" not in out  # nothing routed to an LLM specialist


# --------------------------------------------------------------------------- #
# Gate is cap-aware (§5.3): truncate fan-out to the remaining LLM budget
# --------------------------------------------------------------------------- #

def test_plan_gate_truncates_fan_out_to_remaining_budget():
    # 4 gray-zone candidates, but only budget for 2.
    deps = [_dep(name=f"pkg{i}") for i in range(4)]
    signals = [_sig(d, TrustDimension.IDENTITY, Severity.MEDIUM) for d in deps]
    state = AuditState(dependencies=deps, signals=signals, llm_call_cap=2, llm_calls=0)
    plan = plan_gate(state)
    assert len(plan.fan_out) == 2
    assert len(plan.degraded_notes) == 2
    # escalations are still recorded for ALL gray-zone deps, truncated or not.
    assert len(plan.escalations) == 4


def test_plan_gate_emits_highest_severity_first():
    high, med = _dep(name="high"), _dep(name="med")
    state = AuditState(
        dependencies=[med, high],  # deliberately not severity-ordered
        signals=[
            _sig(med, TrustDimension.IDENTITY, Severity.MEDIUM),
            _sig(high, TrustDimension.IDENTITY, Severity.HIGH),
        ],
        llm_call_cap=1,
        llm_calls=0,
    )
    plan = plan_gate(state)
    assert [t.dep_key for t in plan.fan_out] == [dep_key(high)]
    assert plan.degraded_notes and dep_key(med) in plan.degraded_notes[0].reason
    assert "MEDIUM" in plan.degraded_notes[0].reason


def test_plan_gate_accounts_for_already_spent_calls():
    deps = [_dep(name=f"pkg{i}") for i in range(3)]
    signals = [_sig(d, TrustDimension.BEHAVIOR, Severity.HIGH) for d in deps]
    # cap 5, already spent 4 → only 1 call left.
    state = AuditState(dependencies=deps, signals=signals, llm_call_cap=5, llm_calls=4)
    plan = plan_gate(state)
    assert len(plan.fan_out) == 1
    assert len(plan.degraded_notes) == 2


def test_plan_gate_zero_budget_drops_all_fan_out():
    dep = _dep()
    state = AuditState(
        dependencies=[dep],
        signals=[_sig(dep, TrustDimension.IDENTITY, Severity.HIGH)],
        llm_call_cap=3,
        llm_calls=3,  # cap already reached
    )
    plan = plan_gate(state)
    assert plan.fan_out == []
    assert len(plan.degraded_notes) == 1
    assert plan.escalations[dep_key(dep)] is Severity.HIGH  # escalate-only preserved


def test_plan_gate_truncation_is_deterministic_on_ties():
    # Equal severity across deps → stable tiebreak on (dep_key, dimension).
    deps = [_dep(name=n) for n in ("ccc", "aaa", "bbb")]
    signals = [_sig(d, TrustDimension.IDENTITY, Severity.HIGH) for d in deps]
    state = AuditState(dependencies=deps, signals=signals, llm_call_cap=2, llm_calls=0)
    plan1 = plan_gate(state)
    plan2 = plan_gate(state)
    kept = [t.dep_key for t in plan1.fan_out]
    assert kept == [t.dep_key for t in plan2.fan_out]      # deterministic
    assert kept == [dep_key(deps[1]), dep_key(deps[2])]    # aaa, bbb (lowest keys)


def test_gate_node_emits_degraded_notes_on_truncation():
    deps = [_dep(name=f"pkg{i}") for i in range(3)]
    signals = [_sig(d, TrustDimension.IDENTITY, Severity.HIGH) for d in deps]
    state = AuditState(dependencies=deps, signals=signals, llm_call_cap=1, llm_calls=0)
    out = gate_node(state)
    assert len(out["escalations"]) == 3
    assert len(out["degraded_notes"]) == 2
    assert all(n.node == NODE_GATE for n in out["degraded_notes"])


def test_gate_edge_respects_cap(monkeypatch):
    monkeypatch.setattr(spine, "Send", _FakeSend)
    deps = [_dep(name=f"pkg{i}") for i in range(4)]
    signals = [_sig(d, TrustDimension.BEHAVIOR, Severity.HIGH) for d in deps]
    state = AuditState(dependencies=deps, signals=signals, llm_call_cap=2, llm_calls=0)
    sends = gate_edge(state)
    assert isinstance(sends, list) and len(sends) == 2  # capped, not 4


# --------------------------------------------------------------------------- #
# LangGraph glue (fake Send / fake builder — LangGraph not required)
# --------------------------------------------------------------------------- #

class _FakeSend:
    def __init__(self, node, payload):
        self.node = node
        self.payload = payload


def test_gate_edge_requires_send(monkeypatch):
    monkeypatch.setattr(spine, "Send", None)
    with pytest.raises(RuntimeError):
        gate_edge(AuditState(dependencies=[_dep()]))


def test_gate_edge_returns_sends_for_gray_zone(monkeypatch):
    monkeypatch.setattr(spine, "Send", _FakeSend)
    dep = _dep()
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.IDENTITY, Severity.MEDIUM)])
    result = gate_edge(state)
    assert isinstance(result, list) and len(result) == 1
    assert result[0].node == SPECIALIST_NODE[TrustDimension.IDENTITY]
    assert result[0].payload["task"]["dep_key"] == dep_key(dep)


def test_gate_edge_routes_to_report_when_nothing_gray(monkeypatch):
    monkeypatch.setattr(spine, "Send", _FakeSend)
    dep = _dep()
    state = AuditState(dependencies=[dep], signals=[_sig(dep, TrustDimension.POPULARITY, Severity.HIGH)])
    assert gate_edge(state) == NODE_REPORT


class _FakeBuilder:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.conditional = []

    def add_node(self, name, fn):
        self.nodes[name] = fn

    def add_edge(self, src, dst):
        self.edges.append((src, dst))

    def add_conditional_edges(self, src, fn, targets):
        self.conditional.append((src, list(targets)))


def test_add_spine_wires_fixed_sequence():
    builder = _FakeBuilder()
    entry = add_spine(builder, load_default_tools())
    assert entry == NODE_INDEX
    assert set(builder.nodes) == {NODE_INDEX, NODE_HASH_VERIFY, NODE_CHEAP_SIGNALS, NODE_GATE}
    assert (NODE_INDEX, NODE_HASH_VERIFY) in builder.edges
    assert (NODE_HASH_VERIFY, NODE_CHEAP_SIGNALS) in builder.edges
    assert (NODE_CHEAP_SIGNALS, NODE_GATE) in builder.edges
    src, targets = builder.conditional[0]
    assert src == NODE_GATE
    assert NODE_REPORT in targets
    for node in SPECIALIST_NODE.values():
        assert node in targets


# --------------------------------------------------------------------------- #
# Real-tool adapters (scan/hash types -> graph.state.Signal)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "scan_value,expected",
    [
        ("info", Severity.CLEAN),
        ("low", Severity.LOW),
        ("medium", Severity.MEDIUM),
        ("high", Severity.HIGH),
        ("critical", Severity.CRITICAL),
    ],
)
def test_scan_severity_mapping(scan_value, expected):
    from tools.scan.signals.models import Severity as ScanSeverity

    assert _scan_severity_to_graph(ScanSeverity(scan_value)) is expected


def test_scan_signal_to_graph():
    from tools.scan.signals.models import Dimension, Severity as ScanSeverity, Signal as ScanSignal

    dep = _dep()
    scan_sig = ScanSignal(
        dep=dep,
        dimension=Dimension.IDENTITY,
        code="identity.typosquat",
        severity=ScanSeverity.HIGH,
        message="looks like 'requests'",
        evidence=["levenshtein=1"],
        false_positive_hints=["popular fork?"],
    )
    g = _scan_signal_to_graph(scan_sig)
    assert g.dep_key == dep_key(dep)
    assert g.dimension is TrustDimension.IDENTITY
    assert g.origin is SignalOrigin.STATIC
    assert g.source == "identity.typosquat"
    assert g.severity is Severity.HIGH
    assert g.summary == "looks like 'requests'"
    assert g.evidence == ["levenshtein=1"]
    assert g.false_positive_hints == ["popular fork?"]


def test_hash_result_to_graph_mismatch():
    from tools.scan.signals.provenance.models import HashVerificationResult, VerificationStatus

    dep = _dep()
    r = HashVerificationResult(
        dep=dep,
        lockfile_hash="sha256:aaa",
        registry_hash="sha256:bbb",
        status=VerificationStatus.MISMATCH,
        detail="hashes differ",
    )
    g = _hash_result_to_graph(r)
    assert g.dimension is TrustDimension.PROVENANCE
    assert g.severity is Severity.CRITICAL
    assert g.source == "stage2.hash.mismatch"
    assert g.evidence == ["sha256:aaa", "sha256:bbb"]
    assert g.summary == "hashes differ"


def test_hash_result_to_graph_match_is_clean():
    from tools.scan.signals.provenance.models import HashVerificationResult, VerificationStatus

    dep = _dep()
    r = HashVerificationResult(dep=dep, lockfile_hash="sha256:a", registry_hash="sha256:a", status=VerificationStatus.MATCH)
    g = _hash_result_to_graph(r)
    assert g.severity is Severity.CLEAN
    assert g.source == "stage2.hash.match"


# --------------------------------------------------------------------------- #
# load_default_tools — real Stage 0+1 integration (no network)
# --------------------------------------------------------------------------- #

def test_load_default_tools_discover_and_parse(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    tools = load_default_tools()

    lockfiles = tools.discover(str(tmp_path))
    assert any(lf.ecosystem == "python" and Path(lf.path).name == "requirements.txt" for lf in lockfiles)

    deps = tools.parse(lockfiles)
    assert isinstance(deps, list)
    assert any(d.name == "requests" and d.ecosystem == "python" for d in deps)
