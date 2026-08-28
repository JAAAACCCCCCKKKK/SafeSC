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

from safesc.tools.index.core.models import Dependency
from safesc.tools.scan.signals.base import SignalCollector
from safesc.tools.scan.signals.github import GitHubRepo, get_repo
from safesc.tools.scan.signals.models import Dimension, Severity, Signal, Spoofability
from safesc.tools.scan.signals.provenance.http import RateLimitedSession
from safesc.tools.scan.signals.registry_meta import get_package_metadata, get_registry_metadata


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

        extra_evidence, severity, verdict_note = await self._evaluate_publishing(dep, session, repo)

        return [
            Signal(
                dep=dep,
                dimension=Dimension.POPULARITY,
                code="popularity.repo_archived",
                severity=severity,
                message=(
                    f"Source repository {repo.owner}/{repo.repo} for {dep.name} "
                    f"is archived (unmaintained), yet the package is still in use."
                    f"{verdict_note}"
                ),
                evidence=[
                    f"repo={repo.owner}/{repo.repo}",
                    "archived=true",
                    f"stars={repo.stars}",
                    *extra_evidence,
                ],
                spoofability=Spoofability.MEDIUM,
                false_positive_hints=[
                    "The project may have moved to a maintained fork; verify "
                    "whether a successor repository exists.",
                ],
            )
        ]

    async def _evaluate_publishing(
        self, dep: Dependency, session: RateLimitedSession, repo: GitHubRepo
    ) -> tuple[list[str], Severity, str]:
        """Comprehensive evaluation: cross-check the registry (PyPI/npm/crates.io, via
        the existing ecosystem-dispatched ``get_package_metadata``) for whether the
        package is *still receiving releases* after its source went dark.

        Per the attacker's-eye view (module docstring), that combination — archived
        repo, active releases — is the highest-risk case: nobody is watching the
        source, yet new artifacts keep reaching consumers, so it stays HIGH. A repo
        that went quiet and *also* stopped publishing is ordinary abandonment rather
        than an active supply-chain risk, so it is evidenced but downgraded to MEDIUM —
        real staleness worth surfacing, but not something that alone should fail a gate.

        Best-effort and additive only: any failure, or missing release/push timestamps
        to compare, degrades to the pre-existing HIGH-always behavior rather than
        losing the base signal (§8 — fewer/weaker signals must never read as cleaner).
        This adds at most one extra HTTP request per dependency, and typically none —
        the vulnerability/provenance collectors already fetch this same document for
        the same dep via the session's L1 cache (registry_meta.py module docstring).
        """
        try:
            pkg = await get_package_metadata(dep, session)
        except Exception:
            pkg = None
        if pkg is None or not pkg.latest_release_at or not repo.pushed_at:
            return [], Severity.HIGH, ""

        evidence = [
            f"latest_release={pkg.latest_release_at}",
            f"total_releases={pkg.total_releases}",
            f"repo_last_push={repo.pushed_at}",
        ]
        still_publishing = pkg.latest_release_at > repo.pushed_at
        evidence.append(f"still_publishing_after_archive={str(still_publishing).lower()}")

        if still_publishing:
            return evidence, Severity.HIGH, (
                " New releases have shipped after the repository's last recorded "
                "push — the registry package is active while its source is not."
            )
        return evidence, Severity.MEDIUM, (
            " No release has shipped since around when the repository went quiet — "
            "this reads as ordinary abandonment rather than an active risk."
        )
