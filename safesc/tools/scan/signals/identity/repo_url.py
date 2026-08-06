"""Identity signal: the registry-declared source repository does not exist.

Cheat-sheet rule: *registry-declared repo URL does not exist -> high*.  A
package that advertises a source repo which 404s is a broken-provenance / social
-engineering smell (e.g. an abandoned or never-published repo used to look
legitimate).

To avoid false positives on transient errors, a signal is emitted ONLY when the
URL is *definitively* absent (``url_exists`` returns ``False``).  Indeterminate
results (timeouts, 5xx) and missing metadata produce no signal — graceful
degradation per development principle #4.
"""

from __future__ import annotations

from safesc.tools.index.core.models import Dependency
from safesc.tools.scan.signals.base import SignalCollector
from safesc.tools.scan.signals.models import Dimension, Severity, Signal, Spoofability
from safesc.tools.scan.signals.provenance.http import RateLimitedSession
from safesc.tools.scan.signals.registry_meta import get_registry_metadata


class RepoUrlCollector(SignalCollector):
    """Flags dependencies whose declared source repository URL is dead."""

    @property
    def dimension(self) -> Dimension:
        return Dimension.IDENTITY

    async def collect(
        self, dep: Dependency, session: RateLimitedSession
    ) -> list[Signal]:
        meta = await get_registry_metadata(dep, session)
        if meta is None or not meta.repo_url:
            return []

        exists = await session.url_exists(meta.repo_url)
        if exists is not False:
            # True (exists) or None (indeterminate) -> no signal.
            return []

        return [
            Signal(
                dep=dep,
                dimension=Dimension.IDENTITY,
                code="identity.repo_url_missing",
                severity=Severity.HIGH,
                message=(
                    f"Registry-declared source repository {meta.repo_url!r} "
                    f"does not exist (HTTP 404/410)."
                ),
                evidence=[f"declared_repo_url={meta.repo_url}"],
                spoofability=Spoofability.MEDIUM,
                false_positive_hints=[
                    "The repository may be private or recently moved/renamed "
                    "rather than malicious.",
                ],
            )
        ]
