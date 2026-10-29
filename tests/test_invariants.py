"""Structural invariants (CLAUDE.md §6.1) — pinned by reading the source, so a refactor that
quietly breaks one fails here instead of in production."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "safesc"

STATIC_STAGE_MODULES = {
    "safesc.tools.index.core.discovery",
    "safesc.tools.index.core.normalizer",
    "safesc.tools.scan.signals.collector",
    "safesc.tools.scan.signals.provenance.verifier",
}


def _sources():
    for path in PKG.rglob("*.py"):
        yield path, ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))


def _imports(tree) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
            out |= {f"{node.module}.{a.name}" for a in node.names}
    return out


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def test_static_stages_are_invoked_only_through_agent_tools():
    """Requirement: the static steps are pure agent tools — only the pipeline tool module
    (outside the library itself) may import the stage implementations."""
    offenders = []
    for path, tree in _sources():
        rel = _rel(path)
        if rel.startswith("safesc/tools/") or rel == "safesc/agents/tools/pipeline.py":
            continue
        if _imports(tree) & STATIC_STAGE_MODULES:
            offenders.append(rel)
    assert offenders == []


def test_one_console_script():
    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["scripts"]
    assert scripts == {"safesc": "safesc.cli:main"}


def test_single_install_has_no_extras():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert "optional-dependencies" not in project
    assert any(d.startswith("strands-agents[") for d in project["dependencies"])


def test_no_agent_can_execute_code():
    forbidden = ("vended_tools.shell", "vended_tools._bash", "vended_tools.python_repl", "vended_tools.notebook")
    hits = [
        _rel(path) for path, tree in _sources()
        if any(any(f in imp for f in forbidden) for imp in _imports(tree))
    ]
    assert hits == []


def test_only_the_finalize_tool_writes_a_decision():
    writers = [
        _rel(path) for path, tree in _sources()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "finalize"
    ]
    assert writers == ["safesc/agents/tools/scoring.py"]


def test_memory_stores_have_one_owner():
    owners = [
        _rel(path) for path, tree in _sources()
        if _imports(tree) & {"safesc.memory.store", "safesc.memory.fingerprints"}
        and not _rel(path).startswith("safesc/memory/")
    ]
    assert owners == []


def test_tools_layer_stays_llm_free():
    for path, tree in _sources():
        if _rel(path).startswith("safesc/tools/"):
            assert not any(i.startswith(("strands", "safesc.agents", "safesc.config")) for i in _imports(tree)), _rel(path)
