"""Minimal GitHub repository metadata helper (Stage 3, ecosystem-agnostic).

Given any repository URL, extract ``owner/repo`` and fetch the handful of
fields cheap popularity signals need from the public REST API.  All failures
(non-GitHub host, rate limit, network) degrade to ``None`` so a collector never
crashes the run.

Authentication is optional but recommended in CI: set ``GITHUB_TOKEN`` to lift
the anonymous rate limit (spec §6.2 token pools can layer on later).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from tools.scan.signals.provenance.http import RateLimitedSession

_GITHUB_PATH = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/#?]+)",
    re.IGNORECASE,
)


@dataclass
class GitHubRepo:
    owner: str
    repo: str
    archived: bool
    stars: int
    pushed_at: str | None = None


def parse_repo_slug(url: str | None) -> tuple[str, str] | None:
    """Return ``(owner, repo)`` for a github.com URL, or None."""
    if not url:
        return None
    match = _GITHUB_PATH.match(url.strip())
    if not match:
        return None
    owner = match.group("owner")
    repo = match.group("repo")
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if not owner or not repo:
        return None
    return owner, repo


def _auth_headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


async def get_repo(url: str | None, session: RateLimitedSession) -> GitHubRepo | None:
    """Fetch repo metadata for *url*, or None if not a resolvable GitHub repo."""
    slug = parse_repo_slug(url)
    if slug is None:
        return None
    owner, repo = slug
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    data = await session.get_json(api_url, headers=_auth_headers())
    if not data or not isinstance(data, dict):
        return None
    return GitHubRepo(
        owner=owner,
        repo=repo,
        archived=bool(data.get("archived")),
        stars=int(data.get("stargazers_count") or 0),
        pushed_at=data.get("pushed_at"),
    )
