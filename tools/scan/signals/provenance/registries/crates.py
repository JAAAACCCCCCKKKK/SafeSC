"""Fetch crate checksum from crates.io API."""

from __future__ import annotations

from tools.index.core.models import Dependency
from tools.scan.signals.provenance.http import RateLimitedSession


async def get_registry_hash(dep: Dependency, session: RateLimitedSession) -> str | None:
    """Return sha256:<hex> checksum for this crate version, or None."""
    url = f"https://crates.io/api/v1/crates/{dep.name}/{dep.version}"
    data = await session.get_json(url)
    if not data:
        return None

    version_info: dict = data.get("version", {})
    checksum = version_info.get("checksum") or version_info.get("dl_checksum")
    if checksum:
        if not checksum.startswith("sha256:"):
            return f"sha256:{checksum}"
        return checksum

    return None
