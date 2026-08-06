"""Provenance signal: the pinned version is not published on the registry.

Attacker's-eye view: a lockfile that pins ``foo==1.2.3`` while the public
registry has no ``1.2.3`` is a strong tamper / confusion smell:

* the lockfile may have been hand-edited to point at a malicious artifact that
  was never (or no longer) published to the canonical registry, or
* the version exists only on a *different* registry the attacker controls
  (classic dependency-confusion staging).

The hash verifier (Stage 2) can only compare hashes when the registry returns
the version; this collector covers the complementary case where the version is
absent entirely.

To avoid false positives the signal fires ONLY when the registry returned a
non-empty published-version set that demonstrably excludes the pinned version.
Missing/unavailable metadata produces no signal (graceful degradation).
"""

from __future__ import annotations

from safesc.tools.index.core.models import Dependency
from safesc.tools.scan.signals.base import SignalCollector
from safesc.tools.scan.signals.models import Dimension, Severity, Signal, Spoofability
from safesc.tools.scan.signals.provenance.http import RateLimitedSession
from safesc.tools.scan.signals.registry_meta import get_package_metadata


class VersionPublishedCollector(SignalCollector):
    """Flags pinned versions that are absent from the registry's release list."""

    @property
    def dimension(self) -> Dimension:
        return Dimension.PROVENANCE

    async def collect(
        self, dep: Dependency, session: RateLimitedSession
    ) -> list[Signal]:
        meta = await get_package_metadata(dep, session)
        if meta is None or not meta.published_versions:
            return []  # no authoritative version list -> cannot conclude absence
        if meta.version_present:
            return []

        return [
            Signal(
                dep=dep,
                dimension=Dimension.PROVENANCE,
                code="provenance.version_not_published",
                severity=Severity.HIGH,
                message=(
                    f"Pinned version {dep.version!r} of {dep.name} is not among "
                    f"the {len(meta.published_versions)} versions published on "
                    f"the registry."
                ),
                evidence=[
                    f"pinned_version={dep.version}",
                    f"published_version_count={len(meta.published_versions)}",
                ],
                spoofability=Spoofability.MEDIUM,
                false_positive_hints=[
                    "Could be a private/internal version, a recently yanked "
                    "release, or a normalisation mismatch in the version string.",
                ],
            )
        ]
