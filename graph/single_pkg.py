"""graph/single_pkg.py — the single-package ENTRY NODE (CLAUDE.md §2.2-A).

Not a separate agent path: a single-package query parses the spec into one `Dependency`
and joins the shared spine at hash_verify; everything downstream is reused verbatim.
Keeping it a fixed entry node (not a ReAct loop) preserves the §2.5 injection defence.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from graph.spine import NODE_HASH_VERIFY
from graph.state import Dependency, emit_degraded

logger = logging.getLogger("safesc.single_package")

# Node name for graph wiring. The router's single-package branch lands here.
NODE_RESOLVE_SINGLE = "resolve_single_package"

# There is no lockfile for a directly-specified package; use a stable sentinel so the
# Dependency stays valid and self-describing without pointing at a real file.
SYNTHETIC_LOCKFILE = "<single-package-query>"

# purl / registry aliases → the canonical ecosystem name the index+scan layers use
# (exactly python/javascript/rust/go/java; see tools/index adapters).
_ECOSYSTEM_ALIASES = {
    "pypi": "python",
    "pip": "python",
    "python": "python",
    "npm": "javascript",
    "javascript": "javascript",
    "js": "javascript",
    "cargo": "rust",
    "crates": "rust",
    "rust": "rust",
    "golang": "go",
    "go": "go",
    "maven": "java",
    "java": "java",
}
_KNOWN_PREFIXES = frozenset(_ECOSYSTEM_ALIASES)


# =============================================================================
# Spec parsing (pure, deterministic — no risk, no network)
# =============================================================================


def _split_name_version(spec: str) -> tuple[str, str]:
    """Split ``name[@version]``. A leading '@' is an npm scope, not a version sep, so
    only an '@' past position 0 counts as the version delimiter."""
    at = spec.rfind("@")
    if at > 0:
        return spec[:at], spec[at + 1:]
    return spec, ""


def _split_purl_version(body: str) -> tuple[str, str]:
    """Split a purl body ``type/namespace/name[@version]``. The version never contains
    '/', so we find the version '@' only in the segment after the last '/'."""
    slash = body.rfind("/")
    at = body.find("@", slash + 1)
    if at != -1:
        return body[:at], body[at + 1:]
    return body, ""


def _make_dep(ecosystem: str, name: str, version: str) -> Dependency:
    return Dependency(
        name=name,
        version=version,
        ecosystem=ecosystem,
        lockfile_path=Path(SYNTHETIC_LOCKFILE),
        is_direct=True,
        layer_number=1,
    )


def _parse_purl(spec: str) -> Optional[Dependency]:
    body = spec[len("pkg:"):]
    if "/" not in body:
        return None
    left, version = _split_purl_version(body)
    ptype, _, name = left.partition("/")
    name = name.strip("/")
    if not ptype or not name:
        return None
    ecosystem = _ECOSYSTEM_ALIASES.get(ptype.lower(), ptype.lower())
    return _make_dep(ecosystem, name, version)


def parse_package_spec(target: str, default_ecosystem: Optional[str] = None) -> Optional[Dependency]:
    """Turn a package spec into one `Dependency`, or None if unparseable.
    Accepts purl, ecosystem-prefixed (`python:x@1`), npm scope (`@ng/core@1`),
    and bare `name[@version]` (ecosystem from `default_ecosystem`)."""
    spec = (target or "").strip()
    if not spec:
        return None

    if spec.startswith("pkg:"):
        return _parse_purl(spec)

    # ecosystem-prefixed form — but not an npm scope ("@…") and not a purl (handled above)
    if ":" in spec and not spec.startswith("@"):
        prefix, rest = spec.split(":", 1)
        if prefix.lower() in _KNOWN_PREFIXES:
            name, version = _split_name_version(rest)
            if name:
                return _make_dep(_ECOSYSTEM_ALIASES[prefix.lower()], name, version)

    name, version = _split_name_version(spec)
    if not name:
        return None
    if spec.startswith("@"):
        ecosystem = "javascript"  # npm scope
    elif default_ecosystem:
        ecosystem = _ECOSYSTEM_ALIASES.get(default_ecosystem.lower(), default_ecosystem)
    else:
        ecosystem = ""  # unknown; downstream registry checks degrade gracefully
    return _make_dep(ecosystem, name, version)


# =============================================================================
# The entry node + wiring
# =============================================================================


def resolve_single_package(state) -> dict:
    """Entry node: parse `state.target` into one `Dependency` for the shared spine.
    An unparseable spec degrades to an empty dep set with a note, never a crash (§8.5)."""
    dep = parse_package_spec(state.target, getattr(state, "ecosystem", None))
    if dep is None:
        return {
            "dependencies": [],
            **emit_degraded(NODE_RESOLVE_SINGLE, f"could not parse package spec: {state.target!r}"),
        }
    return {"dependencies": [dep]}


def add_single_package_entry(builder) -> str:
    """Add the entry node and wire it into the shared spine at hash_verify.
    Returns the entry node name for the router's single-package branch."""
    builder.add_node(NODE_RESOLVE_SINGLE, resolve_single_package)
    builder.add_edge(NODE_RESOLVE_SINGLE, NODE_HASH_VERIFY)
    return NODE_RESOLVE_SINGLE
