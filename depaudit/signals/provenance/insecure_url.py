"""Provenance signal: the artifact is fetched over an insecure (non-TLS) URL.

Attacker's-eye view: if the resolved download URL is plain ``http://``, a
network-positioned attacker (rogue proxy, poisoned mirror, compromised CI
runner egress) can transparently swap the artifact for a malicious one.  The
recorded hash defends the *contents*, but an attacker who can MITM the download
can often also influence whatever produced the lockfile, so an http transport
is a provenance weakness worth surfacing on its own.

Purely local — inspects ``dep.source_url`` — so it costs nothing.
"""

from __future__ import annotations

from depaudit.core.models import Dependency
from depaudit.signals.base import SignalCollector
from depaudit.signals.models import Dimension, Severity, Signal, Spoofability
from depaudit.signals.provenance.http import RateLimitedSession


class InsecureUrlCollector(SignalCollector):
    """Flags dependencies whose artifact source URL is not HTTPS."""

    @property
    def dimension(self) -> Dimension:
        return Dimension.PROVENANCE

    async def collect(
        self, dep: Dependency, session: RateLimitedSession
    ) -> list[Signal]:
        url = (dep.source_url or "").strip()
        if not url or not url.lower().startswith("http://"):
            return []

        return [
            Signal(
                dep=dep,
                dimension=Dimension.PROVENANCE,
                code="provenance.insecure_source_url",
                severity=Severity.MEDIUM,
                message=(
                    f"Artifact for {dep.name} {dep.version} is fetched over "
                    f"insecure HTTP, exposing it to man-in-the-middle tampering."
                ),
                evidence=[f"source_url={url}"],
                spoofability=Spoofability.LOW,
                false_positive_hints=[
                    "Some legacy internal mirrors serve over http on a trusted "
                    "network segment.",
                ],
            )
        ]
