"""Unit tests for graph/single_agent.py — the single-package ENTRY NODE (CLAUDE.md §2.2-A).

It is an ingestion node, not a separate analysis path: it turns a package spec into one
`Dependency` and hands off to the shared spine at hash_verify. These tests pin the spec
parsing across all accepted forms, the graceful degradation on bad input, and the wiring
into the spine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from graph.single_pkg import (
    NODE_RESOLVE_SINGLE,
    SYNTHETIC_LOCKFILE,
    add_single_package_entry,
    parse_package_spec,
    resolve_single_package,
)
from graph.spine import NODE_HASH_VERIFY
from graph.state import AuditState, RunMode


# --------------------------------------------------------------------------- #
# spec parsing
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "spec,ecosystem,name,version",
    [
        ("pkg:pypi/requests@2.31.0", "python", "requests", "2.31.0"),
        ("pkg:npm/@angular/core@12.0.0", "javascript", "@angular/core", "12.0.0"),
        ("pkg:npm/left-pad@1.3.0", "javascript", "left-pad", "1.3.0"),
        ("pkg:cargo/serde@1.0.0", "rust", "serde", "1.0.0"),
        ("pkg:golang/github.com/gin-gonic/gin@1.9.0", "go", "github.com/gin-gonic/gin", "1.9.0"),
        ("pkg:maven/org.apache/commons@1.0", "java", "org.apache/commons", "1.0"),
    ],
)
def test_parse_purl(spec, ecosystem, name, version):
    dep = parse_package_spec(spec)
    assert (dep.ecosystem, dep.name, dep.version) == (ecosystem, name, version)


def test_parse_purl_without_version():
    dep = parse_package_spec("pkg:pypi/requests")
    assert (dep.ecosystem, dep.name, dep.version) == ("python", "requests", "")


def test_parse_scoped_purl_without_version():
    dep = parse_package_spec("pkg:npm/@angular/core")
    assert (dep.ecosystem, dep.name, dep.version) == ("javascript", "@angular/core", "")


@pytest.mark.parametrize(
    "spec,ecosystem,name,version",
    [
        ("python:requests@2.31.0", "python", "requests", "2.31.0"),
        ("npm:left-pad@1.3.0", "javascript", "left-pad", "1.3.0"),
        ("cargo:serde@1.0.0", "rust", "serde", "1.0.0"),
        ("go:example.com/x@1.2.3", "go", "example.com/x", "1.2.3"),
    ],
)
def test_parse_ecosystem_prefixed(spec, ecosystem, name, version):
    dep = parse_package_spec(spec)
    assert (dep.ecosystem, dep.name, dep.version) == (ecosystem, name, version)


def test_parse_npm_scope_infers_javascript():
    dep = parse_package_spec("@angular/core@12.0.0")
    assert (dep.ecosystem, dep.name, dep.version) == ("javascript", "@angular/core", "12.0.0")


def test_parse_npm_scope_without_version():
    dep = parse_package_spec("@angular/core")
    assert (dep.ecosystem, dep.name, dep.version) == ("javascript", "@angular/core", "")


def test_parse_bare_spec_uses_default_ecosystem():
    dep = parse_package_spec("left-pad@1.3.0", default_ecosystem="npm")
    assert (dep.ecosystem, dep.name, dep.version) == ("javascript", "left-pad", "1.3.0")


def test_parse_bare_spec_without_ecosystem_leaves_it_empty():
    dep = parse_package_spec("requests")
    assert dep.ecosystem == "" and dep.name == "requests" and dep.version == ""


def test_default_ecosystem_alias_is_canonicalised():
    dep = parse_package_spec("requests@2.31.0", default_ecosystem="pypi")
    assert dep.ecosystem == "python"


@pytest.mark.parametrize("spec", ["", "   ", None])
def test_parse_empty_returns_none(spec):
    assert parse_package_spec(spec) is None


def test_parse_malformed_purl_returns_none():
    assert parse_package_spec("pkg:justtype") is None  # no '/'


def test_resolved_dep_uses_synthetic_lockfile_and_is_direct():
    dep = parse_package_spec("pkg:pypi/requests@2.31.0")
    assert dep.lockfile_path == Path(SYNTHETIC_LOCKFILE)
    assert dep.is_direct is True and dep.layer_number == 1


# --------------------------------------------------------------------------- #
# entry node
# --------------------------------------------------------------------------- #

def test_resolve_single_package_writes_one_dependency():
    out = resolve_single_package(AuditState(mode=RunMode.QUERY, target="pkg:pypi/requests@2.31.0"))
    assert set(out) == {"dependencies"}
    assert len(out["dependencies"]) == 1
    assert out["dependencies"][0].name == "requests"


def test_resolve_single_package_uses_state_ecosystem_hint():
    out = resolve_single_package(AuditState(target="left-pad@1.3.0", ecosystem="npm"))
    assert out["dependencies"][0].ecosystem == "javascript"


def test_resolve_single_package_degrades_on_unparseable_spec():
    out = resolve_single_package(AuditState(target=""))
    assert out["dependencies"] == []
    note = out["degraded_notes"][0]
    assert note.node == NODE_RESOLVE_SINGLE
    assert "could not parse" in note.reason


# --------------------------------------------------------------------------- #
# wiring into the shared spine
# --------------------------------------------------------------------------- #

class _FakeBuilder:
    def __init__(self):
        self.nodes = {}
        self.edges = []

    def add_node(self, name, fn):
        self.nodes[name] = fn

    def add_edge(self, src, dst):
        self.edges.append((src, dst))


def test_add_single_package_entry_wires_into_spine():
    builder = _FakeBuilder()
    entry = add_single_package_entry(builder)
    assert entry == NODE_RESOLVE_SINGLE
    assert NODE_RESOLVE_SINGLE in builder.nodes
    # converges on the shared spine — no separate analysis subgraph
    assert (NODE_RESOLVE_SINGLE, NODE_HASH_VERIFY) in builder.edges
