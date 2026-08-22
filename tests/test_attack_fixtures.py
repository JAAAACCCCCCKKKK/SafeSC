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

Stage 3 (cheap signals) is real, offline, and unmodified across ALL FOUR fixtures — this
was not always true (see CLAUDE.md §9 v2.9) and is worth spelling out precisely:

  * `name_confusion` triggers the real `TyposquatCollector`
    (`tools/scan/signals/identity/typosquat.py`), which is pure local Levenshtein
    comparison with no network dependency at all — the exact `reqeusts`-vs-`requests`
    example already used in that collector's own docstring and in `test_stage3_signals.py`.
  * `obfuscated_build` and `poisoned_install_hook` trigger the real
    `InstallScriptCollector` (`tools/scan/signals/behavior/install_script.py`), which
    *does* decide via a live registry lookup (npm `hasInstallScript` / crates.io
    `lib_links`, per ecosystem) — so its one network call, `get_package_metadata`, is
    mocked to return a canned `PackageMetadata`, exactly mirroring the established
    pattern in `test_stage3_signals.py::TestInstallScriptCollector._patch_meta`. Every
    other line of the collector — ecosystem dispatch, dimension, code, severity,
    message/evidence branching — is real, unmodified production code; only the HTTP
    round-trip is stood in for.

`InstallScriptCollector`'s Rust coverage is itself real, not a fixture-only shim: crates.io
exposes a `lib_links` field on each published version, which mirrors the crate's
Cargo.toml `links` key — and Cargo *requires* a build script whenever `links` is set. That
makes "non-null `lib_links`" a sound, zero-false-positive (if incomplete — a build.rs used
purely for codegen, with no `links` key, isn't caught) proxy for "this crate has a build
script," verified live against crates.io (`openssl-sys`/`libz-sys` -> flagged,
`serde`/`log` -> not) while building this. See `install_script.py`'s module docstring.

Each fixture's static severity below is the real collector's actual production value,
never a softened stand-in — and they deliberately differ, which the sensitivity check at
the bottom of this file has to account for: `name_confusion` and `obfuscated_build` are
MEDIUM (a name near-miss and a Cargo `links` declaration are both routine facts pending
LLM verification), while `poisoned_install_hook` is HIGH (an npm lifecycle hook is
opted-in code execution). See `install_script.py`'s "Why severities differ".
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

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
    SignalOrigin,
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
from safesc.tools.scan.signals.behavior.install_script import InstallScriptCollector
from safesc.tools.scan.signals.identity.typosquat import TyposquatCollector
from safesc.tools.scan.signals.registry_meta import PackageMetadata

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


# The curated known-attack corpus shipped with the repo (§3.2).
CORPUS_DIR = Path(__file__).resolve().parents[1] / "fingerprints"


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


def _real_install_script_collector(dep_name: str, meta: PackageMetadata):
    """A `collect_signals` fake that runs the REAL `InstallScriptCollector` end to end,
    with its one underlying network call (`get_package_metadata`) mocked to return
    `meta` — the exact pattern `test_stage3_signals.py::TestInstallScriptCollector`
    already uses. Ecosystem dispatch, severity, code, and evidence are all real,
    unmodified production logic; only the HTTP round-trip is stood in for."""

    def collect_signals(dep):
        if dep.name != dep_name:
            return []
        with patch(
            "safesc.tools.scan.signals.behavior.install_script.get_package_metadata",
            new=AsyncMock(return_value=meta),
        ):
            scan_sigs = asyncio.run(InstallScriptCollector().collect(dep, MagicMock()))
        return [_scan_signal_to_graph(s) for s in scan_sigs]

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
        # Mirrors what a real crates.io response looks like for a crate that declares a
        # native link name (e.g. openssl-sys, libz-sys) — verified live while building
        # this fixture (see module docstring).
        return _real_install_script_collector(self.DEP_NAME, PackageMetadata(has_native_build_script=True))

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
        # MEDIUM: `links` is a routine build-system fact, so the real collector keeps it
        # in the gray zone rather than failing a gate on its own (see install_script.py).
        assert behavior_signals[0].severity is Severity.MEDIUM
        assert behavior_signals[0].evidence == ["lib_links!=null"]

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

    def test_a_seeded_fingerprint_reaches_the_specialist_prompt(self):
        """The §3.2 known-attack corpus, end to end and still offline.

        The curated XZ-Utils fingerprint is ingested into a fake vector store, the real
        MemoryManager retrieves it through the real task lookup, and the real specialist
        must carry it into its prompt labelled as a *pattern* — not as a prior verdict on
        this crate, which would be a different (and false) claim. It stays context only:
        the emitted signal is derived from the LLM verdict, never from the memory record.
        """
        from safesc.graph.harness.memory_manager import MemoryManager
        from safesc.memory.fingerprints import ingest, load_corpus

        class _FakeVector:
            def __init__(self):
                self.rows = {}

            def upsert(self, key, embedding, record):
                self.rows[key] = {**record, "artifact_id": key}

            def get(self, key):
                return self.rows.get(key)

            def query_similar(self, embedding, k):
                return [self.rows["fingerprint:xz-utils-build-payload"]][:k]

        vector = _FakeVector()
        embedder = lambda texts: [[float(len(t))] for t in texts]
        ingest(load_corpus(CORPUS_DIR), vector=vector, embedder=embedder)

        memory = MemoryManager(redis=None, vector=vector, embedder=embedder)
        state = _run_spine(OBFUSCATED_BUILD, self._collect_signals())
        task = plan_gate(state).fan_out[0]

        prompts: list[str] = []

        def _capturing_llm(system_prompt, user_prompt):
            prompts.append(user_prompt)
            return _stub_llm(
                "malicious", 0.95,
                evidence=["build.rs: decoded blob executed during compilation"],
                reasoning="matches a known build-time payload pattern",
            )(system_prompt, user_prompt)

        out = behavior_agent.run(
            task,
            SpecialistDeps(
                llm=_capturing_llm,
                gather_evidence=lambda *a, **k: _stub_behavior_evidence(
                    path="build.rs", excerpt="<decode + Command::new>"
                ),
                memory_lookup=memory.make_task_lookup(),
            ),
        )

        prompt = prompts[0]
        assert "known-attack pattern xz-utils-build-payload" in prompt
        assert "PRIOR FINDINGS" in prompt
        assert "must NOT lower your assessment" in prompt  # §3.3 stated in the prompt itself
        # the fingerprint informed the prompt; the signal still comes from the LLM verdict
        assert out["signals"][0].origin is SignalOrigin.LLM

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
        # Mirrors what the real npm registry reports for a package whose resolved
        # version declares a postinstall hook (package.json in this fixture).
        return _real_install_script_collector(self.DEP_NAME, PackageMetadata(has_install_script=True))

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
        assert behavior_signals[0].severity is Severity.HIGH  # real InstallScriptCollector severity
        assert behavior_signals[0].evidence == ["hasInstallScript=true"]

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
# Sensitivity check documentation (see CLAUDE.md §9 / this module's docstring): these
# tests were manually proven to have teeth using two different dials, because the three
# attack fixtures carry two different real static severities:
#
#   * `name_confusion` + `obfuscated_build` (MEDIUM): `plan_gate(state, GateConfig(
#     gray_floor=Severity.HIGH)).fan_out` empties — MEDIUM no longer clears the raised
#     floor.
#   * `poisoned_install_hook` (HIGH): raising `gray_floor` to HIGH does NOT suppress it
#     (`HIGH <= HIGH < decided_ceiling` still holds), so the correct dial for a HIGH
#     static signal is `decided_ceiling`. Lowering it to `Severity.HIGH` empties
#     `fan_out` (`HIGH <= sev < HIGH` is false when `sev` is itself `HIGH`).
#
# Neither check is a standing test — no production code was touched to run either
# (`GateConfig` is a plain constructor argument to the pure `plan_gate`), so there is
# nothing to revert, and per the task's "do not tune thresholds" instruction they are
# not committed as permanent tests. Their only job was to prove these assertions are not
# vacuous, once.
# =========================================================================== #
