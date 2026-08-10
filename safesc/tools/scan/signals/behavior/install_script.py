"""Behavior signal: the package declares an install-time or build-time script.

Attacker's-eye view: install/build hooks are the single most reliable
code-execution primitive in a supply-chain attack — the payload runs
automatically before any application code is imported or reviewed.  Real
incidents (e.g. event-stream, many npm crypto-stealers, XZ Utils' build.rs-style
build-script abuse) abused exactly this.

Two ecosystems have a cheap, factual registry-metadata flag, so this runs in
Stage 3 without downloading the package:

* **npm** — ``hasInstallScript`` (or a ``preinstall``/``install``/``postinstall``
  entry in ``scripts``) on the resolved version.
* **Rust (crates.io)** — a non-null ``lib_links`` on the resolved version, which
  mirrors the crate's Cargo.toml ``links`` key. Cargo *requires* a build script
  whenever ``links`` is set (a crate cannot claim a native link-name without
  one), so this is a sound, zero-false-positive proxy for "this crate has a
  build script" — but an *incomplete* one: a crate whose ``build.rs`` exists
  purely for codegen (no native linking, no ``links`` key) is not caught here
  and still needs Stage-4's content inspection
  (``deep_analysis_tool.extract_install_scripts``) to be seen at all.

Other ecosystems (Python ``setup.py``) have no comparable cheap registry flag
and require inspecting the artifact contents at Stage 4; this collector emits
nothing for them.

Per spec §2.3 the *presence* of an install/build script on a transitive
dependency is an explicit escalation trigger — hence its own dimension and
signal. Both ecosystems below intentionally over-flag (per-ecosystem false-
positive hints below): the point of this Stage-3 signal is a coarse, cheap
"look closer" flag, not a verdict — the downstream BehaviorAgent (Stage 4)
inspects actual script/build.rs content to discriminate malicious intent from
benign native compilation.
"""

from __future__ import annotations

from safesc.tools.index.core.models import Dependency
from safesc.tools.scan.signals.base import SignalCollector
from safesc.tools.scan.signals.models import Dimension, Severity, Signal, Spoofability
from safesc.tools.scan.signals.provenance.http import RateLimitedSession
from safesc.tools.scan.signals.registry_meta import PackageMetadata, get_package_metadata

_METADATA_SUPPORTED = {"javascript", "rust"}


def _flagged(dep: Dependency, meta: PackageMetadata) -> bool:
    if dep.ecosystem == "javascript":
        return meta.has_install_script
    if dep.ecosystem == "rust":
        return meta.has_native_build_script
    return False


def _message_and_evidence(dep: Dependency) -> tuple[str, list[str]]:
    if dep.ecosystem == "rust":
        return (
            f"{dep.name} {dep.version} declares a native link name ('links' in "
            f"Cargo.toml), which requires a build script (build.rs) that executes "
            f"automatically at compile time.",
            ["lib_links!=null"],
        )
    return (
        f"{dep.name} {dep.version} declares an install-time script "
        f"(preinstall/install/postinstall), which executes automatically on install.",
        ["hasInstallScript=true"],
    )


_FALSE_POSITIVE_HINTS = {
    "javascript": [
        "Many legitimate packages with native add-ons use install scripts to "
        "compile bindings; inspect the script intent.",
    ],
    "rust": [
        "Declaring a native link name is standard practice for FFI/sys crates "
        "(e.g. openssl-sys, libz-sys) compiling or linking a C library; inspect "
        "build.rs content, not just its presence.",
    ],
}


class InstallScriptCollector(SignalCollector):
    """Flags dependencies whose resolved version declares an install/build hook."""

    @property
    def dimension(self) -> Dimension:
        return Dimension.BEHAVIOR

    async def collect(
        self, dep: Dependency, session: RateLimitedSession
    ) -> list[Signal]:
        # Only ecosystems whose registry metadata exposes install/build hooks cheaply.
        if dep.ecosystem not in _METADATA_SUPPORTED:
            return []

        meta = await get_package_metadata(dep, session)
        if meta is None or not _flagged(dep, meta):
            return []

        message, evidence = _message_and_evidence(dep)
        return [
            Signal(
                dep=dep,
                dimension=Dimension.BEHAVIOR,
                code="behavior.install_script",
                severity=Severity.HIGH,
                message=message,
                evidence=evidence,
                spoofability=Spoofability.LOW,
                false_positive_hints=_FALSE_POSITIVE_HINTS[dep.ecosystem],
            )
        ]
