"""Unit tests for the ``scan`` Stage 2-3 CLI (tools/scan/cli).

Exercises both the subcommand and legacy flag interfaces plus the command
implementations against empty directories (no deps → no network calls).
"""

from __future__ import annotations

import json

from tools.scan.cli import commands, main as scan_main


def test_verify_subcommand(tmp_path, capsys):
    assert scan_main.main(["verify", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_signals_subcommand(tmp_path, capsys):
    assert scan_main.main(["signals", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


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
