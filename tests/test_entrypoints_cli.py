"""Unit tests for entrypoints/cli.py and entrypoints/bootstrap.py.

The thin CLI surface is exercised with the graph `run()` seam monkeypatched, so no
LangGraph/anthropic/LLM key is required. Covers audit/query/gc routing, BYOK env
handling, the missing-credential error path, and report emission.
"""

from __future__ import annotations

import types

import pytest

from safesc.entrypoints import bootstrap, cli
from safesc.graph.state import GateDecision, Severity


def _fake_result(*, exit_code=0, passed=True, incomplete=False, summary="ok"):
    gd = GateDecision(overall=Severity.CLEAN, passed=passed, exit_code=exit_code, summary=summary)
    return types.SimpleNamespace(
        run_id="01FAKE",
        gate_decision=gd,
        passed=passed,
        exit_code=exit_code,
        incomplete=incomplete,
        final_state=object(),
    )


@pytest.fixture
def _llm_env(monkeypatch):
    monkeypatch.setenv("SAFESC_LLM_API_KEY", "byok-secret")
    monkeypatch.setenv("SAFESC_LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("SAFESC_EMBEDDING_API_KEY", raising=False)


def test_audit_returns_gate_exit_code(monkeypatch, capsys, _llm_env):
    monkeypatch.setattr(cli.graph_build, "run", lambda *a, **k: _fake_result(exit_code=1, passed=False))
    rc = cli.main(["audit", "."], tools=object(), session=object())
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_query_prints_pass(monkeypatch, capsys, _llm_env):
    monkeypatch.setattr(cli.graph_build, "run", lambda *a, **k: _fake_result())
    rc = cli.main(["query", "npm:left-pad@1.3.0"], tools=object(), session=object())
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


def test_incomplete_note_printed(monkeypatch, capsys, _llm_env):
    monkeypatch.setattr(cli.graph_build, "run", lambda *a, **k: _fake_result(incomplete=True))
    cli.main(["audit"], tools=object(), session=object())
    assert "incomplete" in capsys.readouterr().out


def test_missing_credential_returns_2(monkeypatch, capsys):
    monkeypatch.delenv("SAFESC_LLM_API_KEY", raising=False)
    rc = cli.main(["audit", "."], tools=object(), session=object())
    assert rc == 2
    assert "error" in capsys.readouterr().err


def test_report_dir_emits_artifacts(monkeypatch, tmp_path, capsys, _llm_env):
    monkeypatch.setattr(cli.graph_build, "run", lambda *a, **k: _fake_result())
    monkeypatch.setattr("safesc.reporter.build_report", lambda state, run_id: object())
    written = [tmp_path / "safesc-report.json"]
    monkeypatch.setattr("safesc.reporter.write_reports", lambda report, d, formats: written)
    monkeypatch.setattr("safesc.reporter.FORMATS", ["json"])
    rc = cli.main(["audit", ".", "--report-dir", str(tmp_path), "--format", "json"],
                  tools=object(), session=object())
    assert rc == 0
    assert "wrote" in capsys.readouterr().out


def test_gc_without_memory(capsys):
    assert cli.main(["gc"]) == 0
    assert "nothing to do" in capsys.readouterr().out


def test_gc_with_memory_manager(capsys):
    class Mem:
        def gc(self):
            return {"deleted": 3}

    assert cli.main(["gc"], memory=Mem()) == 0
    assert "gc complete" in capsys.readouterr().out


def test_gc_memory_without_gc_method(capsys):
    assert cli.main(["gc"], memory=object()) == 0
    assert "TTL-only" in capsys.readouterr().err


# ---- bootstrap ----


def test_local_session_mints_ulid():
    rid = bootstrap.LocalSession().new_run()
    assert isinstance(rid, str) and len(rid) == 26


def test_build_local_runtime_is_store_free():
    tools, session, memory = bootstrap.build_local_runtime()
    assert memory is None
    assert hasattr(session, "new_run")
    assert tools is not None


def test_explain_missing_extra_orchestration(capsys):
    bootstrap._explain_missing_extra("langgraph")
    err = capsys.readouterr().err
    assert "safesc[agent]" in err


def test_explain_missing_extra_provider(capsys):
    # A provider SDK maps to its own extra, installed alongside the agent extra.
    bootstrap._explain_missing_extra("anthropic")
    err = capsys.readouterr().err
    assert "safesc[agent,anthropic]" in err

    bootstrap._explain_missing_extra("openai")
    assert "safesc[agent,openai]" in capsys.readouterr().err


def test_console_utf8_safe_is_noop_safe():
    bootstrap._make_console_utf8_safe()  # must not raise


def test_bootstrap_main_gc_end_to_end(capsys):
    # store-free runtime + gc subcommand needs no LLM key and no external stores.
    assert bootstrap.main(["gc"]) == 0
    assert "nothing to do" in capsys.readouterr().out


# ---- --exclude plumbing ----


def test_preparse_exclude_extracts_repeated_flags():
    argv = ["audit", ".", "--exclude", "a/**", "--report-dir", "out", "--exclude", "b/**"]
    assert bootstrap._preparse_exclude(argv) == ["a/**", "b/**"]


def test_preparse_exclude_empty_when_absent():
    assert bootstrap._preparse_exclude(["audit", "."]) == []


def test_build_local_runtime_bakes_in_exclude(tmp_path):
    # exclude is a construction-time parameter of load_default_tools (via
    # build_local_runtime), not a per-call one — see graph/spine.py's docstring.
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "requirements.txt").write_text("requests==2.31.0\n")

    tools, _session, _memory = bootstrap.build_local_runtime(exclude=["vendor/**"])
    lockfiles = tools.discover(str(tmp_path))
    assert [str(lf.path) for lf in lockfiles] == [str(tmp_path / "requirements.txt")]


def test_bootstrap_main_exclude_reaches_discovery(monkeypatch, capsys, _llm_env):
    # Full plumbing: --exclude on `safesc audit ...` is pre-parsed in bootstrap.main
    # before graph_build.run is ever called, and reaches the real discovery seam.
    captured = {}

    def _fake_run(req, *, tools, **kwargs):
        captured["tools"] = tools
        return _fake_result()

    monkeypatch.setattr(cli.graph_build, "run", _fake_run)
    assert bootstrap.main(["audit", ".", "--exclude", "everything/**"]) == 0
    assert callable(captured["tools"].discover)
