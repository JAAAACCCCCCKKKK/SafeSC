"""Unit tests for the ``scan`` Stage 2-3 CLI (tools/scan/cli).

Exercises both the subcommand and legacy flag interfaces plus the command
implementations against empty directories (no deps → no network calls).
"""

from __future__ import annotations

import json
from pathlib import Path

from safesc.tools.scan.cli import commands, main as scan_main


def _make(root: Path, rel: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("requests==2.31.0\n")


def test_verify_subcommand(tmp_path, capsys):
    assert scan_main.main(["verify", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_signals_subcommand(tmp_path, capsys):
    assert scan_main.main(["signals", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_help_flag_prints_usage_and_exits_zero(capsys):
    assert scan_main.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "usage:" in out
    assert "scan" in out


def test_short_help_flag_prints_usage_and_exits_zero(capsys):
    assert scan_main.main(["-h"]) == 0
    assert "usage:" in capsys.readouterr().out


def test_help_does_not_run_verification_or_network(monkeypatch, capsys):
    # The legacy default verifies hashes against registries over the network. --help must
    # short-circuit before discovery, so a raising discover() proves no I/O is triggered.
    def _boom(*a, **k):
        raise AssertionError("discover() was called while handling --help")

    monkeypatch.setattr(scan_main, "discover", _boom)
    assert scan_main.main(["--help"]) == 0
    assert "usage:" in capsys.readouterr().out


def test_legacy_default_is_verify(tmp_path, capsys):
    assert scan_main.main([str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_legacy_signals_flag(tmp_path, capsys):
    assert scan_main.main(["--signals", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_legacy_no_args_uses_cwd(capsys):
    assert scan_main.main([]) == 0
    capsys.readouterr()


def test_legacy_not_a_directory(tmp_path, capsys):
    f = tmp_path / "file.txt"
    f.write_text("x")
    assert scan_main.main([str(f)]) == 1
    assert "Error" in capsys.readouterr().err


def test_cmd_verify_not_a_directory(tmp_path, capsys):
    f = tmp_path / "file.txt"
    f.write_text("x")
    assert commands.cmd_verify(f) == 1
    assert "Error" in capsys.readouterr().err


def test_cmd_signals_not_a_directory(tmp_path, capsys):
    f = tmp_path / "file.txt"
    f.write_text("x")
    assert commands.cmd_signals(f) == 1
    assert "Error" in capsys.readouterr().err


def test_cmd_verify_empty_repo(tmp_path, capsys):
    assert commands.cmd_verify(tmp_path) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cmd_signals_empty_repo(tmp_path, capsys):
    assert commands.cmd_signals(tmp_path) == 0
    assert json.loads(capsys.readouterr().out) == []


# ── --exclude (excluding every dependency file avoids real network calls) ────────

def test_verify_subcommand_exclude_flag(tmp_path, capsys):
    _make(tmp_path, "requirements.txt")
    assert scan_main.main(["verify", str(tmp_path), "--exclude", "requirements.txt"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_signals_subcommand_exclude_flag(tmp_path, capsys):
    _make(tmp_path, "requirements.txt")
    assert scan_main.main(["signals", str(tmp_path), "--exclude", "requirements.txt"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_legacy_exclude_flag_is_not_mistaken_for_the_path(tmp_path, capsys):
    _make(tmp_path, "requirements.txt")
    assert scan_main.main([str(tmp_path), "--exclude", "requirements.txt"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cmd_verify_exclude_param_directly(tmp_path, capsys):
    _make(tmp_path, "requirements.txt")
    assert commands.cmd_verify(tmp_path, exclude=["requirements.txt"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cmd_signals_exclude_param_directly(tmp_path, capsys):
    _make(tmp_path, "requirements.txt")
    assert commands.cmd_signals(tmp_path, exclude=["requirements.txt"]) == 0
    assert json.loads(capsys.readouterr().out) == []
