"""Unit tests for entrypoints/cli.py and entrypoints/bootstrap.py.

The thin CLI surface is exercised with the graph `run()` seam monkeypatched, so no
LangGraph/anthropic/LLM key is required. Covers audit/query/gc routing, BYOK env
handling, the missing-credential error path, and report emission.
"""

from __future__ import annotations

import types

import pytest

from entrypoints import bootstrap, cli
from graph.state import GateDecision, Severity


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
    monkeypatch.setattr("reporter.build_report", lambda state, run_id: object())
    written = [tmp_path / "safesc-report.json"]
    monkeypatch.setattr("reporter.write_reports", lambda report, d, formats: written)
    monkeypatch.setattr("reporter.FORMATS", ["json"])
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


def test_explain_missing_extra(capsys):
    bootstrap._explain_missing_extra("langgraph")
    assert "agent" in capsys.readouterr().err


def test_console_utf8_safe_is_noop_safe():
    bootstrap._make_console_utf8_safe()  # must not raise


def test_bootstrap_main_gc_end_to_end(capsys):
    # store-free runtime + gc subcommand needs no LLM key and no external stores.
    assert bootstrap.main(["gc"]) == 0
    assert "nothing to do" in capsys.readouterr().out
