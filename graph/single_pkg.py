"""
graph/single_agent.py — the single-package ENTRY NODE (CLAUDE.md §2.2-A).

This is deliberately NOT a separate agent path. A single-package query and a full-repo
audit share the entire deterministic spine (hash_verify → cheap_signals → gate →
specialists → report); they differ ONLY at ingestion:

  * full repo  → `spine.index_node` walks the tree to discover + parse lockfiles;
  * single pkg → the package is already named, so we parse the spec straight into one
                 `Dependency` and jump into the spine at `hash_verify`.

Everything from hash_verify onward — the gate (`plan_gate`), the specialists
(`run_specialist`), and the scorer (`score`) — is reused verbatim, because the analysis
is agnostic to the number of dependencies: one dep flows through the same nodes as five
hundred.

Keeping this an entry node (not a free-form ReAct loop) is a security property, not
tidiness. §2.5's whole argument is that Stages 0–3 are a fixed, non-discretionary
sequence the agent cannot reorder or skip; a ReAct agent choosing its own tool order
would reopen the very injection vector §2.5 closes. So the single-package case uses the
same fixed spine and the same gate — only the ingestion step changes. (An exploratory,
human-in-the-loop research agent that walks transitive deps is a possible future opt-in
feature, but it lives OUTSIDE this deterministic, CI-gating path.)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from graph.spine import NODE_HASH_VERIFY
from graph.state import Dependency, emit_degraded

logger = logging.getLogger("depaudit.single_package")

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
    """Split a purl body ``type/namespace/name[@version]``. The name may be scoped and
    thus contain '@' and '/', but the version never contains '/', so we only look for
    the version '@' in the segment after the last '/'."""
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
    """Turn a package spec into a single `Dependency`, or None if unparseable.

    Accepted forms:
      * purl                       ``pkg:pypi/requests@2.31.0``, ``pkg:npm/@angular/core@12``
      * ecosystem-prefixed         ``python:requests@2.31.0``, ``npm:left-pad@1.3.0``
      * npm scope                  ``@angular/core@12.0.0`` (→ javascript)
      * bare name[@version]        ``left-pad@1.3.0`` (ecosystem from `default_ecosystem`)
    """
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
    """Entry node for the single-package path. Parses `state.target` into one
    `Dependency` and writes it to `state.dependencies`; the shared spine takes over at
    `hash_verify`. A spec it cannot parse degrades to an empty dep set with a note,
    never a crash (§8.5)."""
    dep = parse_package_spec(state.target, getattr(state, "ecosystem", None))
    if dep is None:
        return {
            "dependencies": [],
            **emit_degraded(NODE_RESOLVE_SINGLE, f"could not parse package spec: {state.target!r}"),
        }
    return {"dependencies": [dep]}


def add_single_package_entry(builder) -> str:
    """Add the single-package entry node and wire it into the shared spine at
    hash_verify. Returns the entry node name so the router's single-package branch can
    point at it. The spine (`spine.add_spine`) and report node are added separately."""
    builder.add_node(NODE_RESOLVE_SINGLE, resolve_single_package)
    builder.add_edge(NODE_RESOLVE_SINGLE, NODE_HASH_VERIFY)
    return NODE_RESOLVE_SINGLE
