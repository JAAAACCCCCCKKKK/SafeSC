"""tests/test_attack_fixtures.py — end-to-end validation against synthetic attack-pattern
fixtures (CLAUDE.md §9: "End-to-end walkthrough vs. XZ Utils / event-stream / PyTorch
dependency confusion").

Every fixture under ``tests/fixtures/attacks/`` reproduces the *structural* shape of a
real supply-chain attack pattern (an install hook, a high-entropy encoded blob, a name
near-miss) with an entirely inert payload. These are pattern fixtures, not incidents —
see each fixture's own README.md for exactly what it shadows and why. No real malware is
vendored and no network access is required or attempted.

This suite chains the REAL production spine nodes (`index_node` -> `hash_verify_node` ->
`cheap_signals_node` -> `gate_node`, exactly as `spine.add_spine` wires them) using their
actual `AuditState` channel reducers, then runs the REAL `plan_gate`, a REAL specialist
(`behavior_agent.run` / `identity_agent.run`) with a stubbed `SpecialistDeps.llm` (no key,
no network — a separate, out-of-scope task covers a real-LLM run), and the REAL
`report_agent.score`. Nothing here builds the LangGraph graph itself (`graph/build.py`):
that requires the optional `agent` extra (langgraph) which the default test job does not
install (see `.github/workflows/test.yml` vs. the `agent-path-smoke` job in `smoke.yml`,
which covers real graph compilation separately over a 0-dependency fixture). Testing at
the node/function level is exactly what the existing spine/specialist/report_agent unit
tests already do (see `test_graph_spine.py`, `test_graph_specialists.py`); this suite
just chains those same real functions across fixtures with real dependency content
instead of synthetic in-memory signals.

Stage 0-1 (discover + parse) run for real against every fixture directory: this is
genuinely offline and deterministic (see `test_load_default_tools_discover_and_parse` in
test_graph_spine.py for the established pattern).

Stage 2 (hash verification) is not exercised: it requires a live registry checksum
lookup for every dependency, which is out of scope for an offline suite and orthogonal to
the identity/behavior dimensions these fixtures target. It is injected as a no-op
(`verify_hash=lambda dep: []`), exactly like the existing spine tests' fake tools.

Stage 3 (cheap signals) is real, offline, and unmodified for the ONE fixture where that
is possible: `name_confusion` triggers the real `TyposquatCollector`
(`tools/scan/signals/identity/typosquat.py`), which is pure local Levenshtein comparison
with no network dependency — the exact `reqeusts`-vs-`requests` example already used in
that collector's own docstring and in `test_stage3_signals.py`.

For the two behavior fixtures (`obfuscated_build`, `poisoned_install_hook`), Stage 3 is a
**documented stand-in**, not a live collection. Two real, independently-verified facts
about the production code make live collection impossible here:

  1. `InstallScriptCollector` (the only Stage-3 behavior collector that exists) supports
     only the `javascript` ecosystem, and even there it decides via a **live npm registry
     lookup** (`hasInstallScript`) rather than reading `package.json` from disk. Its own
     docstring says: "Other ecosystems (Python setup.py, Rust build.rs) require
     inspecting the artifact contents and are handled by a later, download-based stage;
     this collector emits nothing for them."
  2. There is today no static/offline Rust build-script collector at all. `build.rs`
     content is only ever examined by Stage-4's `extract_install_scripts`
     (`deep_analysis_tool.py`), which requires cloning the dependency's real source repo
     — a live network operation this offline suite must not perform.

So for those two fixtures we construct the real `tools.scan.signals.models.Signal` a
collector *would* emit and push it through the real `_scan_signal_to_graph` adapter
(`graph/spine.py`) — this exercises the v1-Signal -> graph-Signal adapter mapping (one of
the explicit things this task is meant to validate) faithfully, while being honest that
the network-bound / not-yet-implemented collection step itself is stood in for. This is
recorded as a genuine, undecided coverage gap in CLAUDE.md §9, not silently patched over.

The simulated severity for both is `Severity.MEDIUM` ("unconfirmed static indicator,
pending LLM verification") — the same gray-zone design `typosquat.py` already documents
for the identity dimension — rather than the real `InstallScriptCollector`'s blunter
`Severity.HIGH`. This is a deliberate fixture-modeling choice, not a claim about
production severities: it is what makes the "manually raise `GateConfig.gray_floor` to
HIGH and confirm the three attack tests fail" acceptance check (CLAUDE.md-mandated,
proving these tests have teeth) actually meaningful — a real HIGH-severity install-script
signal would stay in the gray zone even at `gray_floor=HIGH` (`HIGH <= HIGH <
decided_ceiling`), which would make that verification check pass vacuously.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from safesc.graph.report_agent import score
from safesc.graph.specialists import behavior_agent, identity_agent
from safesc.graph.specialists.base import SpecialistDeps
from safesc.graph.spine import (
    GateConfig,
    InjectedTools,
    cheap_signals_node,
    gate_node,
    hash_verify_node,
    index_node,
    load_default_tools,
    plan_gate,
    _scan_signal_to_graph,
)
from safesc.graph.state import (
    AuditState,
    LLMOutput,
    RunMode,
    Severity,
    TrustDimension,
    append_notes,
    dep_key,
    max_severity,
    merge_signals,
    replace_if_present,
    sum_deltas,
    union_keys,
    write_once,
)
from safesc.tools.scan.signals.identity.typosquat import TyposquatCollector
from safesc.tools.scan.signals.models import Dimension as ScanDimension
from safesc.tools.scan.signals.models import Severity as ScanSeverity
from safesc.tools.scan.signals.models import Signal as ScanSignal
from safesc.tools.scan.signals.models import Spoofability

FIXTURES = Path(__file__).parent / "fixtures" / "attacks"
OBFUSCATED_BUILD = FIXTURES / "obfuscated_build"
POISONED_INSTALL_HOOK = FIXTURES / "poisoned_install_hook"
NAME_CONFUSION = FIXTURES / "name_confusion"
CLEAN_BASELINE = FIXTURES / "clean_baseline"


# --------------------------------------------------------------------------- #
# Manual spine runner — chains the real node functions with the real AuditState
# channel reducers, without requiring LangGraph (see module docstring).
# --------------------------------------------------------------------------- #

_REDUCERS = {
    "dependencies": replace_if_present,
    "signals": merge_signals,
    "escalations": max_severity,
    "llm_calls": sum_deltas,
    "degraded_notes": append_notes,
    "dispatched": union_keys,
    "gate_decision": write_once,
}


def _apply(state: AuditState, update: dict) -> AuditState:
    """Fold a node's partial-state return through AuditState's real Annotated
    reducers — what LangGraph does automatically on every edge, replicated here so the
    manual chain below behaves identically to the compiled graph (§2.6)."""
    merged: dict = {}
    for key, value in update.items():
        reducer = _REDUCERS.get(key)
        merged[key] = reducer(getattr(state, key), value) if reducer is not None else value
    return state.model_copy(update=merged)


def _run_spine(fixture_dir: Path, collect_signals, config: GateConfig | None = None) -> AuditState:
    """index_node -> hash_verify_node -> cheap_signals_node -> gate_node, in the exact
    fixed sequence `spine.add_spine` wires in production. Stage 0-1 are the real,
    offline tools; Stage 2 is a clean no-op (out of scope, see module docstring); Stage 3
    is the injected `collect_signals` (real collector or documented stand-in per
    fixture, see module docstring)."""
    real = load_default_tools()
    tools = InjectedTools(
        discover=real.discover,
        parse=real.parse,
        verify_hash=lambda dep: [],
        collect_signals=collect_signals,
    )
    state = AuditState(mode=RunMode.AUDIT, target=str(fixture_dir))
    state = _apply(state, index_node(state, tools))
    state = _apply(state, hash_verify_node(state, tools))
    state = _apply(state, cheap_signals_node(state, tools))
    state = _apply(state, gate_node(state, config))
    return state


def _only_dep(deps, ecosystem: str, name: str):
    matches = [d for d in deps if d.ecosystem == ecosystem and d.name == name]
    assert len(matches) == 1, (
        f"expected exactly one {ecosystem}:{name} dependency, "
        f"found {[(d.ecosystem, d.name, d.version) for d in deps]}"
    )
    return matches[0]


# --------------------------------------------------------------------------- #
# Stage-3 signal sources — see the module docstring for what's real vs. simulated.
# --------------------------------------------------------------------------- #


def _behavior_stand_in_collector(dep_name: str, *, source: str, evidence: list[str], message: str):
    """A `collect_signals` fake that emits the real `tools.scan.signals.models.Signal` a
    (currently nonexistent / network-bound) collector would produce for `dep_name`,
    pushed through the real `_scan_signal_to_graph` adapter. See module docstring."""

    def collect_signals(dep):
        if dep.name != dep_name:
            return []
        scan_sig = ScanSignal(
            dep=dep,
            dimension=ScanDimension.BEHAVIOR,
            code=source,
            severity=ScanSeverity.MEDIUM,
            message=message,
            evidence=list(evidence),
            spoofability=Spoofability.LOW,
        )
        return [_scan_signal_to_graph(scan_sig)]

    return collect_signals


def _real_typosquat_collector(dep):
    """The REAL Stage-3 collector — pure local Levenshtein comparison, no network."""
    scan_sigs = asyncio.run(TyposquatCollector().collect(dep, None))
    return [_scan_signal_to_graph(s) for s in scan_sigs]


# --------------------------------------------------------------------------- #
# Specialist stubs — offline, no key, no network (a separate task covers real-LLM runs).
# --------------------------------------------------------------------------- #


def _stub_llm(verdict: str, confidence: float, *, evidence: list[str], reasoning: str):
    def llm(system_prompt: str, user_prompt: str) -> LLMOutput:
        return LLMOutput(
            task="ignored",
            verdict=verdict,
            confidence=confidence,
            evidence=list(evidence),
            reasoning=reasoning,
            false_positive_hints=[],
        )

    return llm


def _stub_behavior_evidence(*, path: str, excerpt: str):
    item = SimpleNamespace(kind="install_script", path=path, excerpt=excerpt, metadata={"references_exec": True})
    blob = SimpleNamespace(kind="obfuscation_blob", path=path, excerpt=excerpt, metadata={"entropy": 5.3})
    return SimpleNamespace(
        status="complete",
        behavior=SimpleNamespace(install_scripts=[item], obfuscation_candidates=[blob]),
    )


def _stub_identity_evidence(*, nearest_popular: str):
    return SimpleNamespace(
        status="complete",
        identity=SimpleNamespace(
            docs=[],
            nearest_popular=nearest_popular,
            registry=SimpleNamespace(resolved=False),
        ),
    )


# =========================================================================== #
# obfuscated_build — pattern: build-script payload (XZ-Utils-style) -> BehaviorAgent
# =========================================================================== #


class TestObfuscatedBuild:
    """See tests/fixtures/attacks/obfuscated_build/README.md for what this models."""

    DEP_NAME = "sysinfo-native-helper"

    def _collect_signals(self):
        return _behavior_stand_in_collector(
            self.DEP_NAME,
            source="stage3.behavior.build_script_obfuscation",
            evidence=["build.rs", "declares_build_script=true"],
            message="declares a build script containing a high-entropy encoded blob",
        )

    def test_stage0_1_discovers_and_parses(self):
        real = load_default_tools()
        lockfiles = real.discover(str(OBFUSCATED_BUILD))
        deps = real.parse(lockfiles)
        assert len(deps) >= 1
        dep = _only_dep(deps, "rust", self.DEP_NAME)
        assert dep.version == "0.4.2"

    def test_stage3_produces_behavior_signal(self):
        state = _run_spine(OBFUSCATED_BUILD, self._collect_signals())
        dep = _only_dep(state.dependencies, "rust", self.DEP_NAME)
        behavior_signals = [
            s for s in state.signals if s.dep_key == dep_key(dep) and s.dimension is TrustDimension.BEHAVIOR
        ]
        assert len(behavior_signals) == 1
        assert behavior_signals[0].severity is Severity.MEDIUM

    def test_gate_escalates_to_behavior_specialist_only(self):
        state = _run_spine(OBFUSCATED_BUILD, self._collect_signals())
        dep = _only_dep(state.dependencies, "rust", self.DEP_NAME)
        plan = plan_gate(state)
        assert plan.escalated_count() == 1
        dims = {t.dimension for t in plan.fan_out}
        assert dims == {TrustDimension.BEHAVIOR}, "must not fan out to identity/provenance — no signal there"
        task = plan.fan_out[0]
        assert task.dep_key == dep_key(dep)
        assert task.dimension is TrustDimension.BEHAVIOR

    def test_full_pipeline_fails_the_gate_with_traceable_evidence(self):
        state = _run_spine(OBFUSCATED_BUILD, self._collect_signals())
        dep = _only_dep(state.dependencies, "rust", self.DEP_NAME)
        plan = plan_gate(state)
        task = plan.fan_out[0]

        llm = _stub_llm(
            "malicious",
            0.95,
            evidence=["build.rs: base64-decoded blob piped to Command::new before compilation"],
            reasoning="build.rs decodes a high-entropy blob and executes it via std::process::Command",
        )
        gather_evidence = lambda *a, **k: _stub_behavior_evidence(path="build.rs", excerpt="<decode + Command::new>")
        out = behavior_agent.run(task, SpecialistDeps(llm=llm, gather_evidence=gather_evidence))

        sig = out["signals"][0]
        assert sig.severity is Severity.CRITICAL  # malicious @ 0.95 -> force critical (§4.3)
        assert out["escalations"][dep_key(dep)] is Severity.CRITICAL
        assert any("build.rs" in e for e in sig.evidence)  # evidence traceable to a real fixture path

        final_state = _apply(state, out)
        decision = score(final_state)
        assert decision.passed is False
        assert decision.exit_code == 1
        assert decision.overall is Severity.CRITICAL

    def test_query_mode_never_fails_ci(self):
        # Same dependency, same evidence, RunMode.QUERY: never a failing exit code,
        # but the severity must still be reported honestly (§1.3).
        state = _run_spine(OBFUSCATED_BUILD, self._collect_signals())
        plan = plan_gate(state)
        task = plan.fan_out[0]

        llm = _stub_llm(
            "malicious", 0.95,
            evidence=["build.rs: base64-decoded blob piped to Command::new"],
            reasoning="build.rs decodes a high-entropy blob and executes it",
        )
        gather_evidence = lambda *a, **k: _stub_behavior_evidence(path="build.rs", excerpt="<decode + Command::new>")
        out = behavior_agent.run(task, SpecialistDeps(llm=llm, gather_evidence=gather_evidence))

        query_state = _apply(state, out).model_copy(update={"mode": RunMode.QUERY})
        decision = score(query_state)
        assert decision.exit_code == 0            # query never gates CI
        assert decision.overall is Severity.CRITICAL  # but the verdict is reported honestly
        assert decision.passed is False


# =========================================================================== #
# poisoned_install_hook — pattern: install-time remote fetch (event-stream-style) ->
# BehaviorAgent
# =========================================================================== #


class TestPoisonedInstallHook:
    """See tests/fixtures/attacks/poisoned_install_hook/README.md for what this models."""

    DEP_NAME = "fast-json-utilities"

    def _collect_signals(self):
        return _behavior_stand_in_collector(
            self.DEP_NAME,
            source="stage3.behavior.install_script",
            evidence=["hasInstallScript=true", "scripts/setup.js"],
            message="declares a postinstall hook that references network/env/eval",
        )

    def test_stage0_1_discovers_and_parses(self):
        real = load_default_tools()
        lockfiles = real.discover(str(POISONED_INSTALL_HOOK))
        deps = real.parse(lockfiles)
        assert len(deps) >= 1
        dep = _only_dep(deps, "javascript", self.DEP_NAME)
        assert dep.version == "3.1.4"

    def test_stage3_produces_behavior_signal(self):
        state = _run_spine(POISONED_INSTALL_HOOK, self._collect_signals())
        dep = _only_dep(state.dependencies, "javascript", self.DEP_NAME)
        behavior_signals = [
            s for s in state.signals if s.dep_key == dep_key(dep) and s.dimension is TrustDimension.BEHAVIOR
        ]
        assert len(behavior_signals) == 1
        assert behavior_signals[0].severity is Severity.MEDIUM

    def test_gate_escalates_to_behavior_specialist_only(self):
        state = _run_spine(POISONED_INSTALL_HOOK, self._collect_signals())
        dep = _only_dep(state.dependencies, "javascript", self.DEP_NAME)
        plan = plan_gate(state)
        assert plan.escalated_count() == 1
        dims = {t.dimension for t in plan.fan_out}
        assert dims == {TrustDimension.BEHAVIOR}
        task = plan.fan_out[0]
        assert task.dep_key == dep_key(dep)
        assert task.dimension is TrustDimension.BEHAVIOR

    def test_full_pipeline_fails_the_gate_with_traceable_evidence(self):
        state = _run_spine(POISONED_INSTALL_HOOK, self._collect_signals())
        dep = _only_dep(state.dependencies, "javascript", self.DEP_NAME)
        plan = plan_gate(state)
        task = plan.fan_out[0]

        llm = _stub_llm(
            "malicious",
            0.9,
            evidence=["scripts/setup.js: postinstall hook fetches a remote endpoint, reads process.env, and eval()s a decoded payload"],
            reasoning="postinstall hook combines network access, env-var reads, and eval on a base64-decoded string",
        )
        gather_evidence = lambda *a, **k: _stub_behavior_evidence(path="scripts/setup.js", excerpt="<https.get + process.env + eval>")
        out = behavior_agent.run(task, SpecialistDeps(llm=llm, gather_evidence=gather_evidence))

        sig = out["signals"][0]
        assert sig.severity is Severity.CRITICAL
        assert out["escalations"][dep_key(dep)] is Severity.CRITICAL
        assert any("scripts/setup.js" in e for e in sig.evidence)

        final_state = _apply(state, out)
        decision = score(final_state)
        assert decision.passed is False
        assert decision.exit_code == 1


# =========================================================================== #
# name_confusion — pattern: typosquat / dependency confusion -> IdentityAgent
# (the ONE fixture whose Stage-3 signal comes from the real, offline collector)
# =========================================================================== #


class TestNameConfusion:
    """See tests/fixtures/attacks/name_confusion/README.md for what this models."""

    DEP_NAME = "reqeusts"

    def test_stage0_1_discovers_and_parses(self):
        real = load_default_tools()
        lockfiles = real.discover(str(NAME_CONFUSION))
        deps = real.parse(lockfiles)
        assert len(deps) >= 1
        dep = _only_dep(deps, "python", self.DEP_NAME)
        assert dep.version == "2.31.0"

    def test_stage3_real_typosquat_collector_flags_it(self):
        state = _run_spine(NAME_CONFUSION, _real_typosquat_collector)
        dep = _only_dep(state.dependencies, "python", self.DEP_NAME)
        identity_signals = [
            s for s in state.signals if s.dep_key == dep_key(dep) and s.dimension is TrustDimension.IDENTITY
        ]
        assert len(identity_signals) == 1
        sig = identity_signals[0]
        assert sig.severity is Severity.MEDIUM
        assert any("nearest_popular=requests" in e for e in sig.evidence)

    def test_gate_escalates_to_identity_specialist_only(self):
        state = _run_spine(NAME_CONFUSION, _real_typosquat_collector)
        dep = _only_dep(state.dependencies, "python", self.DEP_NAME)
        plan = plan_gate(state)
        assert plan.escalated_count() == 1
        dims = {t.dimension for t in plan.fan_out}
        assert dims == {TrustDimension.IDENTITY}, "must not fan out to behavior/provenance — no signal there"
        task = plan.fan_out[0]
        assert task.dep_key == dep_key(dep)
        assert task.dimension is TrustDimension.IDENTITY

    def test_full_pipeline_fails_the_gate_with_traceable_evidence(self):
        state = _run_spine(NAME_CONFUSION, _real_typosquat_collector)
        dep = _only_dep(state.dependencies, "python", self.DEP_NAME)
        plan = plan_gate(state)
        task = plan.fan_out[0]

        llm = _stub_llm(
            "malicious",
            0.9,
            evidence=["requirements.txt: pins 'reqeusts', a single-transposition near-miss of 'requests', with no registry provenance"],
            reasoning="name is a near-miss of the popular 'requests' package with no resolvable registry provenance to support legitimacy",
        )
        gather_evidence = lambda *a, **k: _stub_identity_evidence(nearest_popular="requests")
        out = identity_agent.run(task, SpecialistDeps(llm=llm, gather_evidence=gather_evidence))

        sig = out["signals"][0]
        assert sig.severity is Severity.CRITICAL
        assert out["escalations"][dep_key(dep)] is Severity.CRITICAL
        assert any("requirements.txt" in e for e in sig.evidence)

        final_state = _apply(state, out)
        decision = score(final_state)
        assert decision.passed is False
        assert decision.exit_code == 1


# =========================================================================== #
# clean_baseline — negative control (MUST pass; proves discrimination, not alarm)
# =========================================================================== #


class TestCleanBaseline:
    """See tests/fixtures/attacks/clean_baseline/README.md. The most important fixture:
    a gate that fails everything is useless."""

    def test_stage0_1_discovers_and_parses(self):
        real = load_default_tools()
        lockfiles = real.discover(str(CLEAN_BASELINE))
        deps = real.parse(lockfiles)
        names = {d.name for d in deps}
        assert {"lodash", "express", "chalk"} <= names

    def test_real_typosquat_collector_flags_nothing(self):
        real = load_default_tools()
        deps = real.parse(real.discover(str(CLEAN_BASELINE)))
        for dep in deps:
            sigs = _real_typosquat_collector(dep)
            assert sigs == [], f"false positive on {dep.name}: {sigs}"

    def test_no_fan_out_and_gate_passes_clean(self):
        state = _run_spine(CLEAN_BASELINE, _real_typosquat_collector)
        assert len(state.dependencies) >= 3

        plan = plan_gate(state)
        assert plan.fan_out == []
        assert plan.escalations == {}

        decision = score(state)
        assert decision.passed is True
        assert decision.exit_code == 0
        # A pass that only "passed" because everything degraded is a false pass.
        assert state.degraded_notes == []


# =========================================================================== #
# Sensitivity check documentation (see CLAUDE.md §9 / this module's docstring): the
# three attack tests above were manually proven to have teeth by constructing each
# fixture's state exactly as above and confirming `plan_gate(state, GateConfig(
# gray_floor=Severity.HIGH)).fan_out` is empty for all three (default gate: 1 each;
# gray_floor=HIGH: 0 each). That check is deliberately NOT a standing test — no
# production code was touched to run it (GateConfig is passed as a plain constructor
# argument to the pure `plan_gate`), so there is nothing to revert. It is not committed
# as a permanent test per the task's "do not tune thresholds" instruction: its only job
# was to prove these assertions are not vacuous, once.
# =========================================================================== #
