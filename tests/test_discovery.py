"""Unit tests for Stage 0 — discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.index import discover


def make_tree(root: Path, files: list[str]) -> None:
    """Create an empty file at each relative path under *root*."""
    for rel in files:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()


# ── Basic matching ─────────────────────────────────────────────────────────────


def test_finds_uv_lock(tmp_path: Path) -> None:
    make_tree(tmp_path, ["uv.lock"])
    results = discover(tmp_path)
    assert any(f.path.name == "uv.lock" and f.ecosystem == "python" for f in results)


def test_finds_poetry_lock(tmp_path: Path) -> None:
    make_tree(tmp_path, ["poetry.lock"])
    results = discover(tmp_path)
    assert any(f.path.name == "poetry.lock" for f in results)


def test_finds_package_lock(tmp_path: Path) -> None:
    make_tree(tmp_path, ["package-lock.json"])
    results = discover(tmp_path)
    assert any(f.ecosystem == "javascript" for f in results)


def test_finds_cargo_lock(tmp_path: Path) -> None:
    make_tree(tmp_path, ["Cargo.lock"])
    results = discover(tmp_path)
    assert any(f.ecosystem == "rust" for f in results)


def test_finds_go_sum(tmp_path: Path) -> None:
    make_tree(tmp_path, ["go.sum"])
    results = discover(tmp_path)
    assert any(f.ecosystem == "go" for f in results)


# ── Multi-ecosystem repo ───────────────────────────────────────────────────────


def test_mixed_repo(tmp_path: Path) -> None:
    make_tree(tmp_path, [
        "backend/uv.lock",
        "frontend/package-lock.json",
        "crates/Cargo.lock",
        "services/api/go.mod",
    ])
    results = discover(tmp_path)
    ecosystems = {f.ecosystem for f in results}
    assert ecosystems == {"python", "javascript", "rust", "go"}


# ── Pruning ────────────────────────────────────────────────────────────────────


def test_node_modules_pruned(tmp_path: Path) -> None:
    """Files inside node_modules must never appear in results."""
    make_tree(tmp_path, ["node_modules/some-pkg/package-lock.json"])
    results = discover(tmp_path)
    assert not any("node_modules" in str(f.path) for f in results)


def test_venv_pruned(tmp_path: Path) -> None:
    make_tree(tmp_path, [".venv/lib/python3.12/site-packages/requirements.txt"])
    results = discover(tmp_path)
    assert not any(".venv" in str(f.path) for f in results)


# ── Edge cases ─────────────────────────────────────────────────────────────────


def test_empty_repo(tmp_path: Path) -> None:
    assert discover(tmp_path) == []


def test_bad_root_raises(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        discover(tmp_path / "nonexistent")


def test_no_duplicates(tmp_path: Path) -> None:
    """Each file appears at most once even if multiple globs could match."""
    make_tree(tmp_path, ["requirements.txt"])
    results = discover(tmp_path)
    paths = [f.path for f in results]
    assert len(paths) == len(set(paths))


# ── Case-insensitive matching (cross-platform: fnmatch is case-sensitive on Linux) ──


@pytest.mark.parametrize("fname", ["Requirements.txt", "REQUIREMENTS.TXT", "requirements.TXT"])
def test_finds_requirements_regardless_of_case(tmp_path: Path, fname: str) -> None:
    make_tree(tmp_path, [fname])
    results = discover(tmp_path)
    assert any(f.ecosystem == "python" for f in results), (
        f"{fname} should be discovered on every OS (fnmatch is case-sensitive on Linux)"
    )


def test_finds_uppercase_pipfile_lock(tmp_path: Path) -> None:
    make_tree(tmp_path, ["Pipfile.LOCK"])
    results = discover(tmp_path)
    assert any(f.ecosystem == "python" for f in results)


def test_finds_lowercase_cargo_lock(tmp_path: Path) -> None:
    # Real glob is "Cargo.lock"; a lowercased on-disk name must still match.
    make_tree(tmp_path, ["cargo.lock"])
    results = discover(tmp_path)
    assert any(f.ecosystem == "rust" for f in results)