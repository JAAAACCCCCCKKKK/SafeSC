"""Popularity signal: the source repository is archived.

Attacker's-eye view: an archived (read-only, unmaintained) upstream is a prime
takeover target.  Maintainers stop watching it, yet the package can still be
republished on the registry — or its name/namespace reclaimed — so a malicious
new release draws no scrutiny.  Per the cheat sheet, "repo archived but still
publishing new versions -> high".

Requires the registry-declared repo URL (via registry metadata) and a single
GitHub API call.  Any failure (non-GitHub host, no token / rate limited,
network) degrades to no signal rather than a false alarm.
"""

from __future__ import annotations

from depaudit.core.models import Dependency
from depaudit.signals.base import SignalCollector
from depaudit.signals.github import get_repo
from depaudit.signals.models import Dimension, Severity, Signal, Spoofability
from depaudit.signals.provenance.http import RateLimitedSession
from depaudit.signals.registry_meta import get_registry_metadata


class ArchivedRepoCollector(SignalCollector):
    """Flags dependencies whose GitHub source repository is archived."""

    @property
    def dimension(self) -> Dimension:
        return Dimension.POPULARITY

    async def collect(
        self, dep: Dependency, session: RateLimitedSession
    ) -> list[Signal]:
        meta = await get_registry_metadata(dep, session)
        if meta is None or not meta.repo_url:
            return []

        repo = await get_repo(meta.repo_url, session)
        if repo is None or not repo.archived:
            return []

        return [
            Signal(
                dep=dep,
                dimension=Dimension.POPULARITY,
                code="popularity.repo_archived",
                severity=Severity.HIGH,
                message=(
                    f"Source repository {repo.owner}/{repo.repo} for {dep.name} "
                    f"is archived (unmaintained), yet the package is still in use."
                ),
                evidence=[
                    f"repo={repo.owner}/{repo.repo}",
                    "archived=true",
                    f"stars={repo.stars}",
                ],
                spoofability=Spoofability.MEDIUM,
                false_positive_hints=[
                    "The project may have moved to a maintained fork; verify "
                    "whether a successor repository exists.",
                ],
            )
        ]
