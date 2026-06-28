"""Data model for hash verification results (Stage 2)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

# Severity is the shared, canonical tier enum (defined once in signals.models).
# Re-exported here so existing Stage 2 imports keep working.
from depaudit.signals.models import Severity

if TYPE_CHECKING:
    from depaudit.core.models import Dependency


class VerificationStatus(str, Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    MISSING_LOCKFILE_HASH = "missing_lockfile_hash"
    REGISTRY_UNAVAILABLE = "registry_unavailable"
    UNSUPPORTED_ECOSYSTEM = "unsupported_ecosystem"


_STATUS_SEVERITY: dict[VerificationStatus, Severity] = {
    VerificationStatus.MATCH: Severity.INFO,
    VerificationStatus.MISMATCH: Severity.CRITICAL,
    VerificationStatus.MISSING_LOCKFILE_HASH: Severity.LOW,
    VerificationStatus.REGISTRY_UNAVAILABLE: Severity.INFO,
    VerificationStatus.UNSUPPORTED_ECOSYSTEM: Severity.INFO,
}


@dataclass
class HashVerificationResult:
    dep: "Dependency"
    lockfile_hash: str | None
    registry_hash: str | None
    status: VerificationStatus
    detail: str = ""

    @property
    def severity(self) -> Severity:
        return _STATUS_SEVERITY[self.status]

    def to_dict(self) -> dict:
        return {
            "name": self.dep.name,
            "version": self.dep.version,
            "ecosystem": self.dep.ecosystem,
            "lockfile_hash": self.lockfile_hash,
            "registry_hash": self.registry_hash,
            "status": self.status.value,
            "severity": self.severity.value,
            "detail": self.detail,
        }
