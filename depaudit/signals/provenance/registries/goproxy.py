"""Fetch module zip hash from the Go module proxy / checksum database."""

from __future__ import annotations

from depaudit.core.models import Dependency
from depaudit.signals.provenance.http import RateLimitedSession


async def get_registry_hash(dep: Dependency, session: RateLimitedSession) -> str | None:
    """Return the h1: hash for this Go module version, or None.

    Strategy (in order):
    1. proxy.golang.org .ziphash  — fast but not cached for all modules.
    2. sum.golang.org/lookup      — authoritative checksum database.

    Response format for sum.golang.org/lookup:
        <tree-size>
        <module> <version> h1:<zip-hash>=
        <module> <version>/go.mod h1:<gomod-hash>=
        ...
    We want the line where the second token equals the version exactly
    (not the /go.mod variant) and the third token starts with "h1:".
    """
    module = dep.name
    version = dep.version

    # 1. Try the proxy .ziphash endpoint.
    proxy_url = f"https://proxy.golang.org/{module}/@v/{version}.ziphash"
    text = await session.get_text(proxy_url)
    if text:
        stripped = text.strip()
        if stripped.startswith("h1:"):
            return stripped
        if stripped and not stripped.startswith("h"):
            return f"sha256:{stripped}"

    # 2. Fall back to the checksum database.
    sum_url = f"https://sum.golang.org/lookup/{module}@{version}"
    text = await session.get_text(sum_url)
    if not text:
        return None
    for line in text.splitlines():
        parts = line.strip().split()
        # Three-token line: "<module> <version> h1:<hash>"
        if len(parts) == 3 and parts[1] == version and parts[2].startswith("h1:"):
            return parts[2]

    return None
