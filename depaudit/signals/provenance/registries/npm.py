"""Fetch package integrity hash from the npm registry."""

from __future__ import annotations

from depaudit.core.models import Dependency
from depaudit.signals.provenance.http import RateLimitedSession


async def get_registry_hash(dep: Dependency, session: RateLimitedSession) -> str | None:
    """Return the SRI integrity string (sha512-...) for this package version, or None."""
    # Scoped packages: @scope/name → %40scope%2Fname
    encoded_name = dep.name.replace("@", "%40").replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded_name}/{dep.version}"
    data = await session.get_json(url)
    if not data:
        return None

    dist: dict = data.get("dist", {})
    # npm registry exposes both 'integrity' (SRI sha512) and 'shasum' (sha1).
    # We prefer integrity (sha512 SRI) to match package-lock.json and yarn.lock.
    integrity = dist.get("integrity")
    if integrity:
        return integrity

    shasum = dist.get("shasum")
    if shasum:
        return f"sha1:{shasum}"

    return None