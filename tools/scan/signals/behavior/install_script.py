"""Behavior signal: the package declares an install-time script.

Attacker's-eye view: install hooks are the single most reliable code-execution
primitive in a supply-chain attack — the payload runs automatically on
``npm install`` before any application code is imported or reviewed.  Real
incidents (e.g. event-stream, many npm crypto-stealers) abused exactly this.

For npm this is a cheap, factual metadata flag (``hasInstallScript`` or a
``preinstall``/``install``/``postinstall`` entry in ``scripts``), so it runs in
Stage 3 without downloading the package.  Other ecosystems (Python ``setup.py``,
Rust ``build.rs``) require inspecting the artifact contents and are handled by a
later, download-based stage; this collector emits nothing for them.

Per spec §2.3 the *presence* of an install script on a transitive dependency is
an explicit escalation trigger — hence its own dimension and signal.
"""

from __future__ import annotations

from tools.index.core.models import Dependency
from tools.scan.signals.base import SignalCollector
from tools.scan.signals.models import Dimension, Severity, Signal, Spoofability
from tools.scan.signals.provenance.http import RateLimitedSession
from tools.scan.signals.registry_meta import get_package_metadata

_METADATA_SUPPORTED = {"javascript"}


class InstallScriptCollector(SignalCollector):
    """Flags dependencies whose resolved version declares an install hook."""

    @property
    def dimension(self) -> Dimension:
        return Dimension.BEHAVIOR

    async def collect(
        self, dep: Dependency, session: RateLimitedSession
    ) -> list[Signal]:
        # Only ecosystems whose registry metadata exposes install hooks cheaply.
        if dep.ecosystem not in _METADATA_SUPPORTED:
            return []

        meta = await get_package_metadata(dep, session)
        if meta is None or not meta.has_install_script:
            return []

        return [
            Signal(
                dep=dep,
                dimension=Dimension.BEHAVIOR,
                code="behavior.install_script",
                severity=Severity.HIGH,
                message=(
                    f"{dep.name} {dep.version} declares an install-time script "
                    f"(preinstall/install/postinstall), which executes "
                    f"automatically on install."
                ),
                evidence=["hasInstallScript=true"],
                spoofability=Spoofability.LOW,
                false_positive_hints=[
                    "Many legitimate packages with native add-ons use install "
                    "scripts to compile bindings; inspect the script intent.",
                ],
            )
        ]
