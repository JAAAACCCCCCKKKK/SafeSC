"""tools/authorship.py — code-style authorship profiling over real git history.

Builds a throwaway repository where one identity commits for months in a consistent style
and then, right before a release, the same identity commits code in a different hand
(tabs, camelCase, no conventional commits, another timezone, at night) — the shape of an
account taken over. A second repository has a consistent maintainer and must show little
drift. Requires a `git` executable; skipped otherwise.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from safesc.tools.authorship import compare, features, profile_repository, read_commits

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(repo: Path, *args: str, env: dict | None = None) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={**os.environ, **(env or {})})


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "commit.gpgsign", "false")
    return repo


def _commit(repo: Path, name: str, email: str, when: str, msg: str, path: str, body: str) -> None:
    (repo / path).parent.mkdir(parents=True, exist_ok=True)
    (repo / path).write_text(body, encoding="utf-8")
    _git(repo, "add", path)
    env = {"GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email, "GIT_AUTHOR_DATE": when,
           "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email, "GIT_COMMITTER_DATE": when}
    _git(repo, "commit", "-q", "-m", msg, env=env)


HONEST = "def parse_config(path):\n    with open(path) as fh:\n        return fh.read()\n\n\ndef load_items(raw):\n    return [item.strip() for item in raw.split(',')]\n"
FOREIGN = "function fetchRemote(u) {\n\tvar x = getData(u);\n\treturn x;\n}\nfunction sendBack(d) {\n\tpostIt(d);\n}\n"


def test_takeover_shape_is_reported(tmp_path):
    repo = _repo(tmp_path)
    for i in range(12):
        _commit(repo, "Alice", "alice@corp.example", f"2024-0{1 + i % 9}-1{i % 9}T14:00:00+01:00",
                f"feat: add parser part {i}", f"pkg/mod{i}.py", HONEST.replace("parse_config", f"parse_config_{i}"))
    for i in range(4):
        _commit(repo, "Alice", "alice@mail.example", f"2024-11-2{i}T03:00:00+08:00",
                f"Update {i}", f"pkg/net{i}.js", FOREIGN.replace("fetchRemote", f"fetchRemote{i}"))

    prof = profile_repository(repo, window=4)
    assert prof.history_commits == 16 and prof.window_size == 4
    (alice,) = [a for a in prof.authors if a.author == "alice@mail.example"]
    assert alice.compared_against == "project maintainers"  # new email: no own history
    shifts = " ".join(alice.notable_shifts)
    assert "timezone changed" in shifts and "new email domain" in shifts
    assert "tab_indent_ratio" in shifts and "msg_conventional_ratio" in shifts
    assert "no commits before the release window" in shifts
    assert alice.drift_index > 0.25
    assert "fetchRemote" in alice.window_sample and "parse_config" in alice.baseline_sample


def test_consistent_maintainer_shows_little_drift(tmp_path):
    repo = _repo(tmp_path)
    for i in range(12):
        _commit(repo, "Bob", "bob@corp.example", f"2024-0{1 + i % 9}-1{i % 9}T10:00:00-05:00",
                f"fix: tidy module {i}", f"pkg/m{i}.py", HONEST.replace("load_items", f"load_items_{i}"))
    prof = profile_repository(repo, window=4)
    (bob,) = prof.authors
    assert bob.compared_against == "own history"
    assert bob.notable_shifts == [] and bob.drift_index < 0.1


def test_no_history_degrades(tmp_path):
    prof = profile_repository(tmp_path)
    assert prof.authors == [] and prof.degraded


def test_feature_and_compare_units():
    from datetime import datetime

    from safesc.tools.authorship import Commit

    c = Commit("a", "n", "n@x.io", "n@x.io", datetime.fromisoformat("2024-01-01T12:00:00+00:00"), "G", "feat: x")
    f = features([c], ["    def a_b():", "        return 'x'"])
    assert f.indent_width == 4 and f.single_quote_ratio == 1.0 and f.snake_case_ratio == 1.0 and f.signed_ratio == 1.0
    g = features([c.__class__("b", "n", "n@x.io", "n@x.io", c.when, "N", "x")], ["\tfunction fooBar() {"])
    drift, index, shifts = compare(g, f)
    assert drift["tab_indent_ratio"] == 1.0 and index > 0
    assert any("signing stopped" in s for s in shifts)
    assert read_commits(Path("/nonexistent")) == []
