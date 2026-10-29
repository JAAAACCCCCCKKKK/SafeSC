"""tests/test_attack_fixtures.py — end-to-end runs of the real agent stack against synthetic
attack-pattern fixtures (CLAUDE.md §9).

Every fixture under ``tests/fixtures/attacks/`` reproduces the *structural* shape of a real
supply-chain attack (a build-script payload, a poisoned install hook, a name near-miss)
with an inert payload, plus a clean negative control. See each fixture's README.md.

What runs for real, offline, with no key:

* the **orchestrator** — a real Strands `Agent` with the real tools, the real
  `PipelineGuard` steering handler and `GoalLoop`, driven by a scripted model;
* **Stages 0–1** — real discovery and parsing of the fixture directory;
* **Stage 3** — the real `InstallScriptCollector` (its one registry call mocked, as in
  `test_stage3_signals.py`) or the real, purely local `TyposquatCollector`;
* the **gate** — the real triage plan and the required-coverage check behind finalize;
* a **subagent** — the real specialist tool, building a real sub-`Agent` with the real
  evidence toolbox: it fetches the fixture as the dependency's source (the "download"
  packs the fixture directory), reads files through the read-only `read_source`, and its
  citations are validated against what it was actually shown;
* **memory** — a real `SafeSCMemory` in a temp dir: the curated corpus is injected into
  the subagent's prompt, and the verdict is persisted after the decision;
* the **scorer** — `finalize_score` → `core.scoring.score`.

Stage 2 (hash verification) needs a live registry and is a no-op here.
"""

from __future__ import annotations

import asyncio
import io
import re
import tarfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from safesc.agents.orchestrator import run_audit
from safesc.agents.tools.pipeline import StaticBackend, _real_discover, _real_parse
from safesc.core.ledger import RunOptions
from safesc.core.signals import Severity, SignalOrigin, TrustDimension, scan_signal_to_core
from safesc.memory import SafeSCMemory
from safesc.tools.scan.signals.behavior.install_script import InstallScriptCollector
from safesc.tools.scan.signals.collector import collect_all
from safesc.tools.scan.signals.identity.typosquat import TyposquatCollector
from safesc.tools.scan.signals.registry_meta import PackageMetadata
from tests.helpers import ScriptedModel, fake_llm, tool_results

FIXTURES = Path(__file__).parent / "fixtures" / "attacks"


def _backend(collectors, meta: PackageMetadata | None = None) -> StaticBackend:
    async def verify(_deps):
        return []

    async def collect(deps):
        if meta is None:
            sigs = await collect_all(deps, collectors=collectors)
        else:
            with patch("safesc.tools.scan.signals.behavior.install_script.get_package_metadata",
                       new=AsyncMock(return_value=meta)):
                sigs = await collect_all(deps, collectors=collectors)
        return [scan_signal_to_core(s) for s in sigs], []

    return StaticBackend(discover=_real_discover, parse=_real_parse, verify=verify, collect=collect)


def _downloader_for(fixture: Path):
    """'Download' the dependency's artifact: a tarball of the fixture directory."""
    def download(url: str, dest: Path) -> bool:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for p in sorted(fixture.rglob("*")):
                if p.is_file():
                    tf.add(p, arcname=f"package/{p.relative_to(fixture).as_posix()}")
        dest.write_bytes(buf.getvalue())
        return True
    return download


def _workspace_from(messages) -> str:
    for text in reversed(tool_results(messages)):
        m = re.search(r"Workspace \(absolute path, read-only\): (.+)", text)
        if m:
            return m.group(1).strip()
    raise AssertionError("no workspace in transcript")


def _static_pipeline():
    return [("tool", name, {}) for name in ("discover_lockfiles", "parse_dependencies", "verify_hashes", "collect_signals")]


def _run(fixture: Path, backend: StaticBackend, orchestrator_steps, subagent_models, tmp_path, **opts):
    orchestrator = ScriptedModel(orchestrator_steps)
    models = [orchestrator, *subagent_models]
    memory = SafeSCMemory(tmp_path / "memory")
    outcome = asyncio.run(run_audit(
        RunOptions(target=str(fixture), **opts), fake_llm(), memory,
        backend=backend, model_factory=lambda: models.pop(0), external_tools=[],
        downloader=_downloader_for(fixture), registry_lookup=lambda *a: None,
    ))
    outcome.orchestrator_model = orchestrator
    return outcome, memory


def _judging_subagent(path_in_package: str, verdict: str, confidence: float, reasoning: str) -> ScriptedModel:
    """fetch the source, read one file, then return an LLMOutput citing that file."""
    def read(messages, _tools):
        return ("tool", "read_source", {"command": "view", "path": f"{_workspace_from(messages)}/{path_in_package}"})

    return ScriptedModel([
        lambda m, t: ("tool", "fetch_dependency_source", {"dep_key": DEP_KEY_HOLDER["key"]}),
        read,
        ("tool", "LLMOutput", {"verdict": verdict, "confidence": confidence,
                               "evidence": [f"{path_in_package}: {reasoning[:60]}"], "reasoning": reasoning}),
    ])


DEP_KEY_HOLDER: dict = {}


class TestObfuscatedBuild:
    """build.rs decoding and executing a blob (XZ-Utils-style) -> BehaviorAgent."""

    KEY = "rust:sysinfo-native-helper@0.4.2"

    def _backend(self):
        return _backend([InstallScriptCollector()], PackageMetadata(has_native_build_script=True))

    def test_full_run_fails_the_gate_with_traceable_evidence(self, tmp_path):
        DEP_KEY_HOLDER["key"] = self.KEY
        sub = _judging_subagent("package/build.rs", "malicious", 0.95,
                                "build.rs decodes a high-entropy blob and executes it via Command::new")
        outcome, memory = _run(
            FIXTURES / "obfuscated_build", self._backend(),
            [*_static_pipeline(), ("tool", "required_analyses", {}),
             ("tool", "behavior_analyst", {"dep_key": self.KEY}), ("tool", "finalize_score", {}), ("text", "done")],
            [sub], tmp_path,
        )
        led = outcome.ledger
        static = [s for s in led.signals_for(self.KEY) if s.origin is SignalOrigin.STATIC]
        assert [(s.dimension, s.severity) for s in static] == [(TrustDimension.BEHAVIOR, Severity.MEDIUM)]
        llm = [s for s in led.signals_for(self.KEY) if s.origin is SignalOrigin.LLM]
        assert llm and llm[0].severity is Severity.CRITICAL and llm[0].source == "llm.behavior"
        assert any("build.rs" in e for e in llm[0].evidence)
        assert outcome.finalized and outcome.decision.passed is False and outcome.exit_code == 1
        assert outcome.decision.score <= 19 and outcome.decision.grade == "F"
        assert outcome.memory_report and outcome.memory_report.written  # persisted after the decision

    def test_known_attack_pattern_is_injected_as_context_only(self, tmp_path):
        DEP_KEY_HOLDER["key"] = self.KEY
        sub = _judging_subagent("package/build.rs", "malicious", 0.9, "decoded blob executed during the build")
        outcome, _ = _run(
            FIXTURES / "obfuscated_build", self._backend(),
            [*_static_pipeline(), ("tool", "behavior_analyst", {"dep_key": self.KEY}),
             ("tool", "finalize_score", {}), ("text", "done")],
            [sub], tmp_path,
        )
        first_call = str(sub.calls[0]["messages"])
        assert "known-attack pattern" in first_call and "PRIOR FINDINGS" in first_call
        assert "never lower" in first_call
        # the signal still comes from the subagent's own validated verdict, not from memory
        assert all(s.origin is not None for s in outcome.ledger.signals)

    def test_citing_a_file_never_shown_is_rejected_then_degrades(self, tmp_path):
        DEP_KEY_HOLDER["key"] = self.KEY
        bad = ("tool", "LLMOutput", {"verdict": "malicious", "confidence": 0.99,
                                     "evidence": ["src/stealer.rs: exfiltrates keys"], "reasoning": "made up"})
        sub = ScriptedModel([bad, bad, bad])
        outcome, _ = _run(
            FIXTURES / "obfuscated_build", self._backend(),
            [*_static_pipeline(), ("tool", "behavior_analyst", {"dep_key": self.KEY}),
             ("tool", "finalize_score", {}), ("text", "done")],
            [sub], tmp_path,
        )
        led = outcome.ledger
        assert not [s for s in led.signals if s.origin is SignalOrigin.LLM]  # nothing hallucinated got in
        assert led.subagent_runs[0].status == "degraded"
        assert outcome.decision.incomplete and outcome.decision.passed  # MEDIUM static only, flagged provisional


class TestPoisonedInstallHook:
    """postinstall hook fetching + eval'ing a payload (event-stream-style) -> BehaviorAgent."""

    KEY = "javascript:fast-json-utilities@3.1.4"

    def test_static_high_alone_fails_the_gate_and_llm_escalates(self, tmp_path):
        DEP_KEY_HOLDER["key"] = self.KEY
        sub = _judging_subagent("package/scripts/setup.js", "malicious", 0.9,
                                "postinstall reads process.env and evals a decoded payload")
        outcome, _ = _run(
            FIXTURES / "poisoned_install_hook",
            _backend([InstallScriptCollector()], PackageMetadata(has_install_script=True)),
            [*_static_pipeline(), ("tool", "behavior_analyst", {"dep_key": self.KEY}),
             ("tool", "finalize_score", {}), ("text", "done")],
            [sub], tmp_path,
        )
        sigs = {s.source: s.severity for s in outcome.ledger.signals_for(self.KEY)}
        assert sigs["behavior.install_script"] is Severity.HIGH
        assert sigs["llm.behavior"] is Severity.CRITICAL
        assert outcome.decision.overall is Severity.CRITICAL and outcome.exit_code == 1


class TestNameConfusion:
    """`reqeusts` vs `requests` -> IdentityAgent, from the real offline typosquat collector."""

    KEY = "python:reqeusts@2.31.0"

    def test_gray_zone_identity_is_required_before_finalize(self, tmp_path):
        steps = [
            *_static_pipeline(),
            ("tool", "finalize_score", {}),  # refused: identity analysis still required
            ("tool", "identity_analyst", {"dep_key": self.KEY}),
            ("tool", "finalize_score", {}),
            ("text", "done"),
        ]
        sub = ScriptedModel([
            ("tool", "get_dependency_signals", {"dep_key": self.KEY}),
            ("tool", "LLMOutput", {"verdict": "malicious", "confidence": 0.9,
                                   "evidence": ["nearest_popular=requests"],
                                   "reasoning": "single-transposition squat of requests with no provenance"}),
        ])
        outcome, _ = _run(FIXTURES / "name_confusion", _backend([TyposquatCollector()]), steps, [sub], tmp_path)
        transcript = tool_results(outcome.orchestrator_model.calls[-1]["messages"])
        assert any("Cannot finalize" in t and "identity(python:reqeusts@2.31.0)" in t for t in transcript)
        sources = {s.source: s.severity for s in outcome.ledger.signals_for(self.KEY)}
        assert sources["identity.typosquat"] is Severity.MEDIUM
        assert sources["llm.identity"] is Severity.CRITICAL
        assert outcome.finalized and outcome.exit_code == 1


class TestCleanBaseline:
    """Negative control: a gate that fails everything is useless."""

    def test_clean_project_passes_without_any_subagent(self, tmp_path):
        outcome, memory = _run(
            FIXTURES / "clean_baseline", _backend([TyposquatCollector()]),
            [*_static_pipeline(), ("tool", "required_analyses", {}), ("tool", "finalize_score", {}), ("text", "done")],
            [], tmp_path,
        )
        led = outcome.ledger
        assert {"lodash", "express", "chalk"} <= {d.name for d in led.dependencies}
        assert led.subagent_runs == [] and led.notes == []
        assert outcome.decision.passed and outcome.exit_code == 0
        assert outcome.decision.score == 100 and outcome.decision.grade == "A"
        assert not outcome.decision.incomplete
