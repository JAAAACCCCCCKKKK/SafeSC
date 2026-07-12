"""Unit tests for graph/router.py — the entry router (CLAUDE.md §2.2-A).

The router splits on request SCOPE only and must be rule-based and
risk-independent. These tests pin the structural classification, the
scope→path mapping, and the mode→gate orthogonality."""

from __future__ import annotations

import pytest

from graph.router import (
    NODE_FULL_SPINE_ENTRY,
    NODE_SINGLE_PACKAGE_ENTRY,
    AuditRequest,
    classify_scope,
    route,
    route_condition,
    router_node,
)
from graph.state import AuditState, RoutePath, RunMode, RunScope


def _req(target, mode=RunMode.QUERY, override=None):
    return AuditRequest(mode=mode, target=target, scope_override=override)


# --------------------------------------------------------------------------- #
# classify_scope — single package
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "target",
    [
        "requests",
        "requests@2.31.0",
        "django@4.2.1",
        "pkg:pypi/requests@2.31.0",   # purl
        "@angular/core",              # npm scope
        "@scope/pkg@1.2.3",
    ],
)
def test_single_package_specs(target):
    assert classify_scope(_req(target)) is RunScope.SINGLE_PACKAGE


# --------------------------------------------------------------------------- #
# classify_scope — full repo
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "target",
    [
        ".",
        "./",
        "/abs/path/to/repo",
        "~/projects/thing",
        "../sibling",
        "https://github.com/psf/requests.git",
        "https://github.com/psf/requests/tree/main",
        "https://gitlab.com/group/sub/project",   # >= 4 slashes
        "requirements.txt",
        "poetry.lock",
        "path/to/package-lock.json",
        "go.mod",
    ],
)
def test_full_repo_targets(target):
    assert classify_scope(_req(target)) is RunScope.FULL_REPO


# --------------------------------------------------------------------------- #
# overrides, emptiness, ambiguity
# --------------------------------------------------------------------------- #

def test_scope_override_wins_over_structure():
    # a clear package spec, but override forces repo
    assert classify_scope(_req("requests", override=RunScope.FULL_REPO)) is RunScope.FULL_REPO
    # a clear repo path, but override forces single package
    assert classify_scope(_req(".", override=RunScope.SINGLE_PACKAGE)) is RunScope.SINGLE_PACKAGE


def test_empty_target_is_full_repo():
    assert classify_scope(_req("")) is RunScope.FULL_REPO


def test_ambiguous_target_falls_back_on_mode_intent():
    ambiguous = "foo bar baz"  # space → neither a repo nor a package spec
    assert classify_scope(_req(ambiguous, mode=RunMode.AUDIT)) is RunScope.FULL_REPO
    assert classify_scope(_req(ambiguous, mode=RunMode.QUERY)) is RunScope.SINGLE_PACKAGE


def test_classify_scope_never_reads_risk_signals():
    # Router only receives an AuditRequest — there is no channel through which a
    # signal could reach it. This asserts the API surface stays risk-free.
    assert set(AuditRequest.model_fields) == {"mode", "target", "ecosystem", "scope_override"}


# --------------------------------------------------------------------------- #
# route() — scope→path and mode→gate
# --------------------------------------------------------------------------- #

def test_route_single_package_goes_single_package_entry():
    d = route(_req("requests", mode=RunMode.QUERY))
    assert d.scope is RunScope.SINGLE_PACKAGE
    assert d.path is RoutePath.SINGLE_PACKAGE
    assert d.produces_gate is False


def test_route_repo_audit_produces_gate():
    d = route(_req(".", mode=RunMode.AUDIT))
    assert d.path is RoutePath.FULL_SPINE
    assert d.produces_gate is True


def test_query_over_full_repo_is_allowed_without_gate():
    # mode (audit/query) is orthogonal to scope (§2.2-A)
    d = route(_req(".", mode=RunMode.QUERY))
    assert d.scope is RunScope.FULL_REPO
    assert d.path is RoutePath.FULL_SPINE
    assert d.produces_gate is False


def test_route_reason_is_populated():
    assert "scope=" in route(_req("requests")).reason


# --------------------------------------------------------------------------- #
# LangGraph glue
# --------------------------------------------------------------------------- #

def test_router_node_writes_scope_and_path():
    state = AuditState(mode=RunMode.QUERY, target="requests")
    out = router_node(state)
    assert out == {"scope": RunScope.SINGLE_PACKAGE, "path": RoutePath.SINGLE_PACKAGE}


def test_route_condition_selects_entry_node_by_path():
    assert route_condition(AuditState(path=RoutePath.SINGLE_PACKAGE)) == NODE_SINGLE_PACKAGE_ENTRY
    assert route_condition(AuditState(path=RoutePath.FULL_SPINE)) == NODE_FULL_SPINE_ENTRY


def test_entry_nodes_match_real_graph_nodes():
    # route_condition must return the actual spine/entry node names, not placeholders.
    from graph.single_pkg import NODE_RESOLVE_SINGLE
    from graph.spine import NODE_INDEX

    assert NODE_SINGLE_PACKAGE_ENTRY == NODE_RESOLVE_SINGLE
    assert NODE_FULL_SPINE_ENTRY == NODE_INDEX
