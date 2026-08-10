"""Behavior signal: the package declares an install-time or build-time script.

Attacker's-eye view: install/build hooks are the single most reliable
code-execution primitive in a supply-chain attack — the payload runs
automatically before any application code is imported or reviewed.  Real
incidents (e.g. event-stream, many npm crypto-stealers, XZ Utils' build.rs-style
build-script abuse) abused exactly this.

Three ecosystems have a cheap, factual registry-metadata flag, so this runs in
Stage 3 without downloading the package:

* **npm** (HIGH) — ``hasInstallScript`` (or a ``preinstall``/``install``/
  ``postinstall`` entry in ``scripts``) on the resolved version.
* **Rust (crates.io)** (HIGH) — a non-null ``lib_links`` on the resolved
  version, which mirrors the crate's Cargo.toml ``links`` key. Cargo *requires*
  a build script whenever ``links`` is set (a crate cannot claim a native
  link-name without one), so this is a sound, zero-false-positive proxy for
  "this crate has a build script".
* **Python (PyPI)** (MEDIUM) — the resolved version publishes an sdist but no
  wheel, so pip cannot unpack a prebuilt artifact and must build from source,
  executing the project's PEP 517 backend (``setup.py``, or an in-tree
  ``backend-path`` backend). A published wheel is only unpacked and runs no
  project code at install time, so wheel-bearing releases are never flagged.

**Why Rust's proxy is deliberately narrow, and stays that way.** A ``build.rs``
that never sets ``links`` (pure codegen, std-only) declares no distinguishing
registry metadata at all and is invisible here — it is seen only by Stage-4's
``deep_analysis_tool.extract_install_scripts``. That is a deliberate product
decision, not an oversight: build scripts are the *norm* in Rust, not the
exception (``serde``, ``libc``, ``anyhow`` and ``proc-macro2`` all ship one —
4 of 6 crates in a spot-check of common dependencies, confirmed by unpacking
the published ``.crate`` files). A "has a build.rs at all" signal would
therefore fire on roughly two-thirds of every Rust dependency tree, which is
useless as an escalation trigger and would blow the CLAUDE.md §5.1 5–10%
Stage-4 trigger-rate target along with the §5.3 LLM budget. ``links`` is the
right signal *because* it is selective (2 of those same 12 sampled crates).

**Why severities differ.** npm/Rust flags mean the package *opted in* to
running code (a declared lifecycle hook, a declared native link). Python's
sdist-only flag is weaker evidence of intent — it is a packaging choice, and
most sdist-only projects are ordinary pure-Python packages whose build is
setuptools boilerplate. So Python is MEDIUM: enough to land in the §2.2-B
gray zone and be routed to the BehaviorAgent for intent verification, but
never enough to fail a CI gate on its own (the ``fail_threshold`` is HIGH).
This mirrors ``identity/typosquat.py``'s deliberate MEDIUM cap.

Per spec §2.3 the *presence* of an install/build script on a transitive
dependency is an explicit escalation trigger — hence its own dimension and
signal. Every ecosystem below intentionally over-flags (see the per-ecosystem
false-positive hints): the point of this Stage-3 signal is a coarse, cheap
"look closer" flag, not a verdict — the downstream BehaviorAgent (Stage 4)
inspects actual script/build.rs/setup.py content to discriminate malicious
intent from benign native compilation.
"""

from __future__ import annotations

from safesc.tools.index.core.models import Dependency
from safesc.tools.scan.signals.base import SignalCollector
from safesc.tools.scan.signals.models import Dimension, Severity, Signal, Spoofability
from safesc.tools.scan.signals.provenance.http import RateLimitedSession
from safesc.tools.scan.signals.registry_meta import PackageMetadata, get_package_metadata

_METADATA_SUPPORTED = {"javascript", "rust", "python"}

# Per-ecosystem severity — see the module docstring's "Why severities differ".
_SEVERITY = {
    "javascript": Severity.HIGH,
    "rust": Severity.HIGH,
    "python": Severity.MEDIUM,
}


def _flagged(dep: Dependency, meta: PackageMetadata) -> bool:
    if dep.ecosystem == "javascript":
        return meta.has_install_script
    if dep.ecosystem == "rust":
        return meta.has_native_build_script
    if dep.ecosystem == "python":
        return meta.requires_source_build
    return False


def _message_and_evidence(dep: Dependency) -> tuple[str, list[str]]:
    if dep.ecosystem == "rust":
        return (
            f"{dep.name} {dep.version} declares a native link name ('links' in "
            f"Cargo.toml), which requires a build script (build.rs) that executes "
            f"automatically at compile time.",
            ["lib_links!=null"],
        )
    if dep.ecosystem == "python":
        return (
            f"{dep.name} {dep.version} publishes no wheel, so installing it must "
            f"build from source, executing the project's build backend "
            f"(setup.py / PEP 517) at install time.",
            ["sdist_only=true", "bdist_wheel=absent"],
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
    "python": [
        "Shipping only an sdist is a routine packaging choice, not by itself a "
        "red flag — most such projects are pure Python with boilerplate "
        "setuptools builds. Inspect setup.py / pyproject build hooks for intent.",
        "C-extension packages that build per-platform (rather than publishing "
        "wheels) legitimately compile at install time.",
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
                severity=_SEVERITY[dep.ecosystem],
                message=message,
                evidence=evidence,
                spoofability=Spoofability.LOW,
                false_positive_hints=_FALSE_POSITIVE_HINTS[dep.ecosystem],
            )
        ]
