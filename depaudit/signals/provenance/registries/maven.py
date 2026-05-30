"""Fetch artifact hash from Maven Central (or any Maven repository)."""

from __future__ import annotations

from depaudit.core.models import Dependency
from depaudit.signals.provenance.http import RateLimitedSession


async def get_registry_hash(dep: Dependency, session: RateLimitedSession) -> str | None:
    """Return sha256:<hex> for the primary jar artifact, or None.

    Maven Central publishes a .sha256 file alongside each artifact.
    The artifact URL is already stored in dep.source_url; we just fetch the
    companion .sha256 file.
    """
    if not dep.source_url:
        return None

    sha256_url = dep.source_url + ".sha256"
    text = await session.get_text(sha256_url)
    if text:
        # Maven sha256 files are just the raw hex digest, possibly with filename.
        hex_hash = text.strip().split()[0]
        if len(hex_hash) == 64:
            return f"sha256:{hex_hash}"

    # Fall back to sha1 (universally available on Maven Central).
    sha1_url = dep.source_url + ".sha1"
    text = await session.get_text(sha1_url)
    if text:
        hex_hash = text.strip().split()[0]
        if len(hex_hash) == 40:
            return f"sha1:{hex_hash}"

    return None