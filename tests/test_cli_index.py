"""Unit tests for the ``index`` Stage 0-1 CLI (tools/index/cli).

Drives the subcommand + legacy flag interfaces and the command implementations against
throwaway directories, so no ecosystem parser specifics or network access are needed.
"""

from __future__ import annotations

import json

from pathlib import Path

from safesc.tools.index.cli import commands, main as index_main


def test_discover_subcommand_text(tmp_path, capsys):
    assert index_main.main(["discover", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert out  # print_discovered always emits something


def test_discover_subcommand_json_is_valid(tmp_path, capsys):
    assert index_main.main(["discover", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_parse_subcommand_emits_json_array(tmp_path, capsys):
    assert index_main.main(["parse", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_no_command_prints_help(capsys):
    assert index_main.main([]) == 0  # legacy path over cwd, prints discovery
    capsys.readouterr()


def test_help_flag_prints_usage_and_exits_zero(capsys):
    assert index_main.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "usage:" in out
    assert "index" in out


def test_short_help_flag_prints_usage_and_exits_zero(capsys):
    assert index_main.main(["-h"]) == 0
    assert "usage:" in capsys.readouterr().out


def test_help_does_not_run_discovery(monkeypatch, capsys):
    def _boom(*a, **k):  # discovery must not run for --help
        raise AssertionError("discover() was called while handling --help")

    monkeypatch.setattr(index_main, "discover", _boom)
    assert index_main.main(["--help"]) == 0
    assert "usage:" in capsys.readouterr().out


def test_legacy_json_flag(tmp_path, capsys):
    assert index_main.main(["--json", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_legacy_text(tmp_path, capsys):
    assert index_main.main([str(tmp_path)]) == 0
    assert capsys.readouterr().out


def test_cmd_discover_not_a_directory(tmp_path, capsys):
    f = tmp_path / "afile.txt"
    f.write_text("x")
    assert commands.cmd_discover(f) == 1
    assert "Error" in capsys.readouterr().err


def test_cmd_parse_not_a_directory(tmp_path, capsys):
    f = tmp_path / "afile.txt"
    f.write_text("x")
    assert commands.cmd_parse(f) == 1
    assert "Error" in capsys.readouterr().err


def test_legacy_not_a_directory(tmp_path, capsys):
    f = tmp_path / "nope.txt"
    f.write_text("x")
    assert index_main.main([str(f)]) == 1
    assert "Error" in capsys.readouterr().err


def test_cmd_discover_json_directly(tmp_path, capsys):
    assert commands.cmd_discover(Path(tmp_path), as_json=True) == 0
    assert json.loads(capsys.readouterr().out) == []


# ── --exclude ─────────────────────────────────────────────────────────────────

def _make(root: Path, rel: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x")


def test_subcommand_exclude_flag(tmp_path, capsys):
    _make(tmp_path, "requirements.txt")
    _make(tmp_path, "vendor/requirements.txt")
    assert index_main.main(["discover", str(tmp_path), "--exclude", "vendor/**", "--json"]) == 0
    found = json.loads(capsys.readouterr().out)
    assert [f["relative_path"] for f in found] == ["requirements.txt"]


def test_parse_subcommand_exclude_flag(tmp_path, capsys):
    _make(tmp_path, "requirements.txt")
    _make(tmp_path, "vendor/requirements.txt")
    assert index_main.main(["parse", str(tmp_path), "--exclude", "vendor/**"]) == 0
    deps = json.loads(capsys.readouterr().out)
    assert {d["lockfile"] for d in deps} == {str(tmp_path / "requirements.txt")}


def test_legacy_exclude_flag_is_not_mistaken_for_the_path(tmp_path, capsys):
    # A pattern value like "vendor/**" doesn't start with "--", so the legacy parser
    # must not treat it as the positional root path.
    _make(tmp_path, "requirements.txt")
    _make(tmp_path, "vendor/requirements.txt")
    assert index_main.main([str(tmp_path), "--exclude", "vendor/**", "--json"]) == 0
    deps = json.loads(capsys.readouterr().out)
    assert {d["lockfile"] for d in deps} == {str(tmp_path / "requirements.txt")}


def test_legacy_exclude_repeatable(tmp_path, capsys):
    _make(tmp_path, "requirements.txt")
    _make(tmp_path, "a/requirements.txt")
    _make(tmp_path, "b/requirements.txt")
    assert index_main.main([str(tmp_path), "--exclude", "a/**", "--exclude", "b/**", "--json"]) == 0
    deps = json.loads(capsys.readouterr().out)
    assert {d["lockfile"] for d in deps} == {str(tmp_path / "requirements.txt")}


def test_cmd_discover_exclude_param_directly(tmp_path, capsys):
    _make(tmp_path, "requirements.txt")
    _make(tmp_path, "vendor/requirements.txt")
    assert commands.cmd_discover(Path(tmp_path), as_json=True, exclude=["vendor/**"]) == 0
    found = json.loads(capsys.readouterr().out)
    assert [f["relative_path"] for f in found] == ["requirements.txt"]
