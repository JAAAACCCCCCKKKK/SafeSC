"""Fetch package hash from PyPI JSON API."""

from __future__ import annotations

from tools.index.core.models import Dependency
from tools.scan.signals.provenance.http import RateLimitedSession


async def get_registry_hash(dep: Dependency, session: RateLimitedSession) -> str | None:
    """Return the sha256: prefixed hash for the best wheel/sdist match, or None."""
    url = f"https://pypi.org/pypi/{dep.name}/{dep.version}/json"
    data = await session.get_json(url)
    if not data:
        return None

    urls: list[dict] = data.get("urls", [])
    lockfile_hash = dep.hash or ""

    # Prefer the specific file whose hash matches the lockfile (any algorithm).
    for file_info in urls:
        digests: dict[str, str] = file_info.get("digests", {})
        sha256 = digests.get("sha256", "")
        if not sha256:
            continue
        candidate = f"sha256:{sha256}"
        if lockfile_hash and lockfile_hash == candidate:
            return candidate

    # Fall back: return the sha256 of the first wheel, then first sdist.
    for preferred_type in ("bdist_wheel", "sdist"):
        for file_info in urls:
            if file_info.get("packagetype") == preferred_type:
                sha256 = (file_info.get("digests") or {}).get("sha256", "")
                if sha256:
                    return f"sha256:{sha256}"

    return None
