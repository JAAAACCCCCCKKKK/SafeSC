"""cli.py — `safesc` with no subcommands: LLM required, memory required, target defaulting."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from safesc import cli
from safesc.agents.orchestrator import run_audit
from safesc.config.llm import InvalidAPIKeyError
from safesc.core.ledger import Feature
from tests.helpers import ScriptedModel, backend, dep, fake_llm

PIPELINE = [("tool", n, {}) for n in ("discover_lockfiles", "parse_dependencies", "verify_hashes", "collect_signals")]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    for var in ("CI", "GITHUB_ACTIONS", "GITHUB_WORKSPACE", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "TF_BUILD", "JENKINS_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SAFESC_MEMORY_DIR", str(tmp_path / "memory"))


def _fake_run(captured: dict, deps=None, steps=None):
    async def run(options, llm, memory, **kw):
        captured["options"], captured["kw"] = options, kw
        return await run_audit(
            options, llm, memory, backend=backend(deps or [dep("lib")]), external_tools=[],
            model_factory=lambda: ScriptedModel(steps or [*PIPELINE, ("tool", "finalize_score", {})]),
        )
    return run


def test_bare_safesc_requires_the_three_llm_variables(monkeypatch, capsys):
    for var in ("LLM_PROVIDER", "LLM_MODEL", "LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert cli.main([]) == 2
    assert "LLM_PROVIDER, LLM_MODEL, LLM_API_KEY" in capsys.readouterr().err


def test_llm_errors_exit_2(capsys):
    def loader():
        raise InvalidAPIKeyError("anthropic rejected LLM_API_KEY: 401")

    assert cli.main([], llm_loader=loader) == 2
    assert "rejected LLM_API_KEY" in capsys.readouterr().err


def test_memory_is_required(monkeypatch, tmp_path, capsys):
    blocker = tmp_path / "f"
    blocker.write_text("x")
    assert cli.main(["--memory-dir", str(blocker / "m")], llm_loader=fake_llm) == 2
    assert "not writable" in capsys.readouterr().err


def test_missing_target_and_bad_feature(capsys):
    assert cli.main(["./definitely/not/here"], llm_loader=fake_llm) == 2
    assert cli.main(["--with", "telepathy"], llm_loader=fake_llm) == 2
    err = capsys.readouterr().err
    assert "does not exist" in err and "unknown --with feature" in err


def test_bare_safesc_inspects_the_current_directory(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    captured: dict = {}
    code = cli.main(["-q"], llm_loader=fake_llm, run=_fake_run(captured))
    assert code == 0
    opts = captured["options"]
    assert Path(opts.target) == tmp_path.resolve() and opts.ci is False and opts.features == frozenset()
    out = capsys.readouterr().out
    assert "PASS" in out and "trust score 100/100 (A)" in out


def test_in_ci_the_repository_is_inspected(monkeypatch, tmp_path):
    repo = tmp_path / "checkout"
    repo.mkdir()
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(repo))
    monkeypatch.chdir(tmp_path)
    captured: dict = {}
    assert cli.main(["-q"], llm_loader=fake_llm, run=_fake_run(captured)) == 0
    assert Path(captured["options"].target) == repo.resolve() and captured["options"].ci is True


def test_flags_and_with_options_reach_the_run(tmp_path):
    captured: dict = {}
    cli.main([str(tmp_path), "-q", "--with", "authorship,vuln-hunt", "--with", "github", "--fail-on", "MEDIUM",
              "--max-subagents", "7", "--strict", "--exclude", "fixtures/", "--mcp", "https://intel.example/mcp"],
             llm_loader=fake_llm, run=_fake_run(captured))
    o = captured["options"]
    assert o.features == frozenset({Feature.AUTHORSHIP, Feature.VULN_HUNT, Feature.GITHUB})
    assert o.fail_on.name == "MEDIUM" and o.max_subagents == 7 and o.exclude == ("fixtures/",)
    assert captured["kw"]["strict"] is True and captured["kw"]["mcp_urls"] == ("https://intel.example/mcp",)
    assert cli.parse_features(["all"]) == frozenset(Feature)


def test_package_spec_target_and_reports(tmp_path):
    captured: dict = {}
    out_dir = tmp_path / "reports"
    code = cli.main(["npm:left-pad@1.3.0", "-q", "--report-dir", str(out_dir), "--format", "json"],
                    llm_loader=fake_llm, run=_fake_run(captured, deps=[]))
    assert code == 0 and captured["options"].target == "npm:left-pad@1.3.0"
    data = json.loads((out_dir / "safesc-report.json").read_text(encoding="utf-8"))
    assert data["target"] == "npm:left-pad@1.3.0" and data["model"] == "anthropic/claude-test"


def test_gate_failure_and_no_verdict_exit_codes(tmp_path):
    from safesc.core.signals import Severity, TrustDimension
    from tests.helpers import sig

    d = dep("evil")

    async def failing(options, llm, memory, **kw):
        return await run_audit(options, llm, memory, external_tools=[],
                               backend=backend([d], collect=[sig(d, TrustDimension.VULNERABILITY, Severity.CRITICAL)]),
                               model_factory=lambda: ScriptedModel([*PIPELINE, ("tool", "finalize_score", {})]))

    assert cli.main([str(tmp_path), "-q"], llm_loader=fake_llm, run=failing) == 1
    stuck = _fake_run({}, steps=[("text", "I refuse to score")])
    assert cli.main([str(tmp_path), "-q"], llm_loader=fake_llm, run=stuck) == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0 and "safesc" in capsys.readouterr().out


def test_asyncio_is_not_left_running():
    asyncio.run(asyncio.sleep(0))  # the CLI owns its event loop; nothing leaks between runs
