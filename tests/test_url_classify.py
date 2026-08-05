"""Unit tests for tools/index/core/url_classify.py.

The module routes a lockfile URL to the right Dependency field: a VCS/source URL to
`source_url` (clonable) vs an artifact download to `artifact_url`. Getting this wrong is
exactly the bug that made `git clone <wheel-url>` fail for every registry dependency.
"""

from __future__ import annotations

import pytest

from tools.index.core.url_classify import (
    is_artifact_url,
    is_vcs_url,
    module_path_to_repo_url,
    normalise_vcs_url,
    split_source_artifact,
)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/pkg/errors",
        "https://gitlab.com/group/proj",
        "git+https://github.com/o/r.git",
        "git://github.com/o/r",
        "https://bitbucket.org/team/repo",
    ],
)
def test_is_vcs_url_true(url):
    assert is_vcs_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0-py3-none-any.whl",
        "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
        "https://static.crates.io/crates/serde/serde-1.0.193.crate",
        "https://repo1.maven.org/maven2/com/google/guava/guava/32.1.3/guava-32.1.3.jar",
        "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip",
        # a github URL that actually points at a release artifact is NOT clonable
        "https://github.com/o/r/releases/download/v1/thing.tar.gz",
    ],
)
def test_is_vcs_url_false_for_artifacts(url):
    assert is_vcs_url(url) is False
    assert is_artifact_url(url) is True


def test_normalise_vcs_url_strips_prefix_query_fragment_and_git_suffix():
    assert normalise_vcs_url("git+https://github.com/o/r.git?rev=abc#tag") == "https://github.com/o/r"
    assert normalise_vcs_url("https://github.com/o/r") == "https://github.com/o/r"


def test_split_routes_artifact_to_artifact_url():
    src, art = split_source_artifact(
        "https://files.pythonhosted.org/packages/x/ormsgpack-1.12.2-cp312-cp312-macosx.whl"
    )
    assert src is None
    assert art.endswith(".whl")


def test_split_routes_vcs_to_source_url():
    src, art = split_source_artifact("git+https://github.com/o/r.git")
    assert src == "https://github.com/o/r"
    assert art is None


def test_split_none_is_none():
    assert split_source_artifact(None) == (None, None)
    assert split_source_artifact("") == (None, None)


def test_split_unknown_defaults_to_artifact_not_source():
    # A non-VCS, non-suffixed URL must NOT be handed to git clone; treat as artifact.
    src, art = split_source_artifact("https://example.com/download/thing")
    assert src is None
    assert art == "https://example.com/download/thing"


@pytest.mark.parametrize(
    "module, expected",
    [
        ("github.com/pkg/errors", "https://github.com/pkg/errors"),
        ("github.com/spf13/cobra/v2", "https://github.com/spf13/cobra"),  # major suffix dropped
        ("gitlab.com/group/project", "https://gitlab.com/group/project"),
    ],
)
def test_module_path_to_repo_url(module, expected):
    assert module_path_to_repo_url(module) == expected


@pytest.mark.parametrize(
    "module",
    [
        "golang.org/x/net",          # vanity domain, needs go-import lookup we don't do
        "example.com/foo/bar",       # unknown host
        "shortpath",                 # too short
        "",
    ],
)
def test_module_path_to_repo_url_none_for_non_vcs(module):
    assert module_path_to_repo_url(module) is None
