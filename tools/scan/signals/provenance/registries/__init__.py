"""Dispatch hash lookup to the correct registry module by ecosystem."""

from __future__ import annotations

from tools.index.core.models import Dependency
from tools.scan.signals.provenance.http import RateLimitedSession

from . import crates, goproxy, maven, npm, pypi

_HANDLERS = {
    "python": pypi.get_registry_hash,
    "javascript": npm.get_registry_hash,
    "rust": crates.get_registry_hash,
    "go": goproxy.get_registry_hash,
    "java": maven.get_registry_hash,
}


async def get_registry_hash(dep: Dependency, session: RateLimitedSession) -> str | None:
    handler = _HANDLERS.get(dep.ecosystem)
    if handler is None:
        return None
    return await handler(dep, session)
