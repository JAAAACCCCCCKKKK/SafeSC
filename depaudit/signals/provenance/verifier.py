"""Stage 2: Hash verification — compare lockfile hashes against registry hashes."""

from __future__ import annotations

import asyncio
from typing import Sequence

from depaudit.core.models import Dependency
from depaudit.signals.provenance.http import RateLimitedSession
from depaudit.signals.provenance.models import HashVerificationResult, VerificationStatus
from depaudit.signals.provenance.registries import get_registry_hash as _fetch_registry_hash


def _normalize_hash(h: str) -> str:
    h = h.strip()
    if h.startswith("sha256:"):
        return "sha256:" + h[7:].lower()
    # SRI (sha512-...) and Go (h1:...) are case-sensitive — return as-is.
    return h


async def _verify_one(dep: Dependency, session: RateLimitedSession) -> HashVerificationResult:
    lockfile_hash = _normalize_hash(dep.hash) if dep.hash else None

    if lockfile_hash is None:
        return HashVerificationResult(
            dep=dep,
            lockfile_hash=None,
            registry_hash=None,
            status=VerificationStatus.MISSING_LOCKFILE_HASH,
            detail="Lockfile does not record a hash for this dependency.",
        )

    registry_hash_raw = await _fetch_registry_hash(dep, session)

    if registry_hash_raw is None:
        return HashVerificationResult(
            dep=dep,
            lockfile_hash=lockfile_hash,
            registry_hash=None,
            status=VerificationStatus.REGISTRY_UNAVAILABLE,
            detail="Registry did not return a hash (network error or package not found).",
        )

    registry_hash = _normalize_hash(registry_hash_raw)

    if lockfile_hash == registry_hash:
        return HashVerificationResult(
            dep=dep,
            lockfile_hash=lockfile_hash,
            registry_hash=registry_hash,
            status=VerificationStatus.MATCH,
        )

    return HashVerificationResult(
        dep=dep,
        lockfile_hash=lockfile_hash,
        registry_hash=registry_hash,
        status=VerificationStatus.MISMATCH,
        detail=(
            f"Lockfile hash {lockfile_hash!r} does not match "
            f"registry hash {registry_hash!r}."
        ),
    )


async def verify_all(
    deps: Sequence[Dependency],
    *,
    per_host_concurrency: int = 10,
) -> list[HashVerificationResult]:
    """Verify hashes for all deps concurrently. Returns results in the same order."""
    async with RateLimitedSession(per_host=per_host_concurrency) as session:
        tasks = [_verify_one(dep, session) for dep in deps]
        return list(await asyncio.gather(*tasks))


def run_verification(
    deps: Sequence[Dependency],
    *,
    per_host_concurrency: int = 10,
) -> list[HashVerificationResult]:
    """Synchronous entry point for Stage 2 (wraps the async verify_all)."""
    return asyncio.run(verify_all(deps, per_host_concurrency=per_host_concurrency))