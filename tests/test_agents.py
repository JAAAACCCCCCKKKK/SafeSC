"""agents/ — the orchestrator and subagents on a real Strands runtime, driven by scripted models.

Covers the properties that make agent discretion safe (CLAUDE.md §2.5): static stages run
only in order and only through tools; finalization is refused until coverage is met and
happens once; a run that never finalizes fails closed; the budget is fail-closed; subagent
output is validated; the hunter can only propose and the verifier can only dispose; the
read-only source viewer cannot write or escape its workspace.
"""

from __future__ import annotations

import asyncio
import io
import re
import tarfile
from pathlib import Path

import pytest

from safesc.agents.context import AgentContext
from safesc.agents.harness import validation
from safesc.agents.harness.guard import tool_blocker
from safesc.agents.orchestrator import new_run_id, run_audit
from safesc.agents.specialists import SPECIALISTS, TOOL_ROLE
from safesc.agents.specialists.base import run_specialist
from safesc.agents.tools.evidence import ReadOnlySourceGuard, build_evidence_tools
from safesc.core.ledger import Feature, Role, RunOptions, Stage
from safesc.core.signals import Severity, SignalOrigin, TrustDimension, dep_key
from safesc.core.targets import TargetKind
from safesc.memory import SafeSCMemory
from tests.helpers import ScriptedModel, backend, dep, fake_llm, ledger, sig, tool_results

PIPELINE = [("tool", n, {}) for n in ("discover_lockfiles", "parse_dependencies", "verify_hashes", "collect_signals")]
VULN_C = "#include <string.h>\nvoid parse_header(const char *in) {\n  char buf[16];\n  strcpy(buf, in);\n}\n"


def _downloader(files: dict[str, str]):
    def download(url: str, dest: Path) -> bool:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(f"package/{name}")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        dest.write_bytes(buf.getvalue())
        return True
    return download


def _audit(tmp_path, orchestrator_steps, subagents=(), *, deps=None, collect=(), downloader=None, **opts):
    deps = deps if deps is not None else [dep("lib")]
    orch = ScriptedModel(orchestrator_steps)
    models = [orch, *subagents]
    outcome = asyncio.run(run_audit(
        RunOptions(target=str(tmp_path), **opts), fake_llm(), SafeSCMemory(tmp_path / "mem"),
        backend=backend(deps, collect=list(collect)), model_factory=lambda: models.pop(0),
        external_tools=[], downloader=downloader or _downloader({"index.js": "module.exports = 1\n"}),
        registry_lookup=lambda *a: None,
    ))
    return outcome, orch


def _results(model: ScriptedModel) -> list[str]:
    return tool_results(model.calls[-1]["messages"])


def _workspace(messages) -> str:
    for text in reversed(tool_results(messages)):
        m = re.search(r"Workspace \(absolute path, read-only\): (.+)", text)
        if m:
            return m.group(1).strip()
    raise AssertionError("no workspace")


# ------------------------------------------------------------------ orchestrator rails


def test_run_id_is_a_sortable_ulid():
    a, b = new_run_id(), new_run_id()
    assert len(a) == 26 and re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", a) and a[:8] <= b[:8]


def test_static_stages_run_in_order_or_not_at_all(tmp_path):
    outcome, orch = _audit(tmp_path, [
        ("tool", "collect_signals", {}),        # out of order: refused by the guard
        ("tool", "finalize_score", {}),         # too early: refused
        *PIPELINE,
        ("tool", "verify_hashes", {}),          # repeat: refused
        ("tool", "finalize_score", {}),
        ("tool", "finalize_score", {}),         # second score: refused
        ("text", "done"),
    ])
    results = _results(orch)
    assert "collect_signals must wait" in results[0]
    assert "Cannot finalize: static stage(s) not run" in results[1]
    assert any("verify_hashes already ran" in r for r in results)
    assert sum("FINAL (deterministic" in r for r in results) == 1
    assert "already finalized" in results[-1]
    assert outcome.finalized and outcome.exit_code == 0 and not outcome.decision.incomplete


def test_never_finalizing_fails_closed_after_goal_loop(tmp_path):
    outcome, orch = _audit(tmp_path, [*PIPELINE], )
    assert not outcome.finalized
    assert outcome.exit_code == 2 and not outcome.decision.passed and outcome.decision.score == 0
    assert "no verdict" in outcome.decision.summary
    retries = [c for c in orch.calls if "stopped without calling finalize_score" in str(c["messages"])]
    assert retries, "GoalLoop must re-prompt before the run fails closed"
    assert outcome.memory_report is None  # nothing is persisted without a decision


def test_required_gray_zone_analysis_blocks_finalize(tmp_path):
    d = dep("lib")
    k = dep_key(d)
    sub = ScriptedModel([("tool", "get_dependency_signals", {"dep_key": k}),
                         ("tool", "LLMOutput", {"verdict": "clean", "confidence": 0.8, "reasoning": "benign build"})])
    outcome, orch = _audit(tmp_path, [
        *PIPELINE, ("tool", "finalize_score", {}), ("tool", "behavior_analyst", {"dep_key": k}),
        ("tool", "finalize_score", {}), ("text", "done"),
    ], [sub], deps=[d], collect=[sig(d, TrustDimension.BEHAVIOR, Severity.MEDIUM, source="behavior.install_script")])
    results = _results(orch)
    assert "behavior(javascript:lib@1.0.0)" in results[4]
    assert outcome.finalized and outcome.decision.passed  # clean verdict cannot clear, but adds nothing
    assert {s.source for s in outcome.ledger.signals_for(k)} == {"behavior.install_script", "llm.behavior"}
    assert outcome.decision.per_dep[k] is Severity.MEDIUM


def test_budget_is_fail_closed_and_marks_the_run_incomplete(tmp_path):
    a, b = dep("a"), dep("b")
    sub = ScriptedModel([("tool", "LLMOutput", {"verdict": "clean", "confidence": 0.5, "reasoning": "fine"})])
    outcome, orch = _audit(tmp_path, [
        *PIPELINE,
        ("tool", "behavior_analyst", {"dep_key": dep_key(a)}),
        ("tool", "behavior_analyst", {"dep_key": dep_key(b)}),  # denied: budget is 1
        ("tool", "finalize_score", {}), ("text", "done"),
    ], [sub], deps=[a, b], max_subagents=1,
        collect=[sig(a, TrustDimension.BEHAVIOR, Severity.MEDIUM), sig(b, TrustDimension.BEHAVIOR, Severity.MEDIUM)])
    assert any(r.startswith("DENIED") for r in _results(orch))
    statuses = sorted(r.status for r in outcome.ledger.subagent_runs)
    assert statuses == ["denied", "ok"]
    assert outcome.finalized and outcome.decision.incomplete and outcome.decision.score <= 89


def test_single_package_target(tmp_path):
    outcome, _ = _audit(tmp_path, [*PIPELINE, ("tool", "finalize_score", {}), ("text", "done")], deps=[])
    assert outcome.finalized
    outcome2 = asyncio.run(run_audit(
        RunOptions(target="npm:left-pad@1.3.0", target_kind=TargetKind.PACKAGE), fake_llm(), SafeSCMemory(tmp_path / "m2"),
        backend=backend([]), model_factory=lambda: ScriptedModel([*PIPELINE, ("tool", "finalize_score", {})]),
        external_tools=[],
    ))
    assert [dep_key(d) for d in outcome2.ledger.dependencies] == ["javascript:left-pad@1.3.0"]
    assert outcome2.finalized and outcome2.exit_code == 0


# ------------------------------------------------------------------ hunter → verifier


def _hunter(k: str, *, line=4):
    return ScriptedModel([
        ("tool", "fetch_dependency_source", {"dep_key": k}),
        ("tool", "scan_source_for_risky_patterns", {"dep_key": k}),
        ("tool", "HuntReport", {"candidates": [{
            "title": "Stack overflow in parse_header", "cwe": "CWE-120", "file": "package/src/hdr.c", "line": line,
            "severity": "high", "description": "untrusted header copied with strcpy into a 16-byte buffer",
            "evidence": ["package/src/hdr.c:4"], "confidence": 0.8}], "summary": "one lead"}),
    ])


def _verifier(k: str, cid_holder: dict, **verdict):
    def read(messages, _t):
        ws = _workspace(messages)
        cid_holder["id"] = re.search(r"- ([0-9a-f]{6}-V\d+):", str(messages)).group(1)
        return ("tool", "read_source", {"command": "view", "path": f"{ws}/package/src/hdr.c"})

    def report(messages, _t):
        return ("tool", "VerificationReport", {"results": [{
            "candidate_id": cid_holder["id"], "status": verdict.get("status", "confirmed"),
            "severity": verdict.get("severity", "high"), "intentional_backdoor": verdict.get("backdoor", False),
            "confidence": verdict.get("confidence", 0.9), "evidence": ["package/src/hdr.c:4"],
            "reasoning": "parse_header is exported and reached from read_request()"}]})

    return ScriptedModel([("tool", "fetch_dependency_source", {"dep_key": k}), read, report])


@pytest.mark.parametrize("verdict,expected", [
    ({}, Severity.HIGH),
    ({"severity": "medium"}, Severity.MEDIUM),                       # capped by assessed impact
    ({"confidence": 0.5}, Severity.LOW),                              # low confidence = evidence only
    ({"backdoor": True, "severity": "low"}, Severity.CRITICAL),       # intentional backdoor fuses as malicious
    ({"status": "refuted"}, None),
])
def test_vuln_hunt_requires_independent_verification(tmp_path, verdict, expected):
    d = dep("hdrparse")
    k = dep_key(d)
    holder: dict = {}
    outcome, orch = _audit(tmp_path, [
        *PIPELINE,
        ("tool", "required_analyses", {}),
        ("tool", "vuln_hunter", {"dep_key": k}),
        ("tool", "finalize_score", {}),                 # refused: candidate unverified
        ("tool", "vuln_verifier", {"dep_key": k}),
        ("tool", "finalize_score", {}), ("text", "done"),
    ], [_hunter(k), _verifier(k, holder, **verdict)], deps=[d],
        downloader=_downloader({"src/hdr.c": VULN_C}), features=frozenset({Feature.VULN_HUNT}))
    results = _results(orch)
    assert "vuln_hunter(dep_key='javascript:hdrparse@1.0.0')" in results[4]
    assert "UNVERIFIED candidate" in results[5]
    assert "vuln_verifier(javascript:hdrparse@1.0.0)" in results[6]
    (cand,) = outcome.ledger.candidates.values()
    assert cand.status == verdict.get("status", "confirmed")
    found = [s for s in outcome.ledger.signals_for(k) if s.origin is SignalOrigin.LLM]
    if expected is None:
        assert found == [] and outcome.decision.passed
    else:
        assert [s.severity for s in found] == [expected]
        assert found[0].source == f"llm.vuln_verifier.{cand.id}"
    assert outcome.finalized and not outcome.decision.incomplete


# ------------------------------------------------------------------ subagent runner directly


def _ctx(tmp_path, led, *, download=None):
    return AgentContext(ledger=led, llm=fake_llm(), memory=SafeSCMemory(tmp_path / "mem"),
                        downloader=download or _downloader({"src/hdr.c": VULN_C}), registry_lookup=lambda *a: None,
                        workspace_base=tmp_path / "ws")


def _complete(led):
    for s in (Stage.DISCOVER, Stage.PARSE, Stage.VERIFY, Stage.COLLECT):
        led.mark_stage(s)
    return led


def _toolbox(ctx):
    from safesc.agents.tools.inspection import build_ledger_views, build_registry_tools

    tools = build_ledger_views(ctx, orchestrator=False) + build_registry_tools(ctx) + build_evidence_tools(ctx)
    return lambda: tools


def test_verifier_cannot_invent_candidates(tmp_path):
    d = dep("x")
    k = dep_key(d)
    led = _complete(ledger(deps=[d]))
    (cid,) = led.register_candidates(k, [{"title": "t", "file": "package/src/hdr.c", "line": 4}])
    ctx = _ctx(tmp_path, led)
    invented = ("tool", "VerificationReport", {"results": [
        {"candidate_id": cid, "status": "refuted", "severity": "low", "confidence": 0.9, "reasoning": "dead code"},
        {"candidate_id": "zzzzzz-V9", "status": "confirmed", "severity": "critical", "confidence": 0.99,
         "evidence": [], "reasoning": "my own idea"}]})
    ctx.model_factory = lambda: ScriptedModel([invented, invented, invented])
    out = asyncio.run(run_specialist(ctx, SPECIALISTS[Role.VULN_VERIFIER], k, toolbox=_toolbox(ctx)))
    assert out.startswith("DEGRADED") and "unknown candidate" in out
    assert led.signals == [] and led.candidates[cid].status == "pending"


def test_unknown_dep_and_premature_calls_are_refused(tmp_path):
    led = ledger(deps=[dep("x")])
    ctx = _ctx(tmp_path, led)
    spec = SPECIALISTS[Role.BEHAVIOR]
    assert "unknown dependency" in asyncio.run(run_specialist(ctx, spec, "npm:nope@1", toolbox=lambda: []))
    assert "static pipeline" in asyncio.run(run_specialist(ctx, spec, dep_key(dep("x")), toolbox=lambda: []))
    assert led.budget_used == 0


def test_tool_blocker_rules():
    d = dep()
    led = ledger(deps=[d])
    assert "must wait" in tool_blocker(led, "parse_dependencies", {}, TOOL_ROLE)
    assert "collect_signals before" in tool_blocker(led, "behavior_analyst", {"dep_key": dep_key(d)}, TOOL_ROLE)
    _complete(led)
    assert "Unknown dep_key" in tool_blocker(led, "behavior_analyst", {"dep_key": "x"}, TOOL_ROLE)
    assert "no unverified" in tool_blocker(led, "vuln_verifier", {"dep_key": dep_key(d)}, TOOL_ROLE)
    assert tool_blocker(led, "authorship_analyst", {"dep_key": dep_key(d)}, TOOL_ROLE) is None
    assert tool_blocker(led, "list_flagged_dependencies", {}, TOOL_ROLE) is None


def test_validation_rules():
    shown = {"package/build.rs", "hasInstallScript=true"}
    assert validation.check_judgement(["build.rs: decodes a blob"], shown) is None
    assert validation.check_judgement(["see e.g. the registry"], shown) is None                # prose passes
    assert validation.check_judgement(["/ws/abs/package/build.rs:3"], shown, ["/ws/abs"]) is None
    assert "never shown" in validation.check_judgement(["src/evil.py: steals"], shown)


def test_read_source_is_view_only_and_confined(tmp_path):
    d = dep()
    led = ledger(deps=[d])
    ws = tmp_path / "ws"
    ws.mkdir()
    led.set_workspace(dep_key(d), ws)
    guard = ReadOnlySourceGuard(_ctx(tmp_path, led))

    class Event:
        def __init__(self, inp):
            self.tool_use = {"name": "read_source", "input": inp}
            self.cancel_tool = False

    for inp, allowed in [
        ({"command": "view", "path": str(ws / "a.c")}, True),
        ({"command": "create", "path": str(ws / "a.c"), "file_text": "x"}, False),
        ({"command": "str_replace", "path": str(ws / "a.c")}, False),
        ({"command": "view", "path": str(tmp_path / "secrets.txt")}, False),
        ({"command": "view", "path": str(ws / ".." / "secrets.txt")}, False),
    ]:
        ev = Event(inp)
        guard._check(ev)
        assert (ev.cancel_tool is False) is allowed, inp


def test_subagents_never_get_shell_or_code_execution(tmp_path):
    ctx = _ctx(tmp_path, ledger(deps=[dep()]))
    names = {t.tool_name for t in _toolbox(ctx)()}
    assert "read_source" in names and not names & {"shell", "python_repl", "file_editor", "http_request"}
