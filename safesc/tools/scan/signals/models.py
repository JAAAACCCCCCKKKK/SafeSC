"""Unified signal model shared by all Stage 3 (and later Stage 4) collectors.

Every collector — static or LLM-based — emits :class:`Signal` objects with an
identical shape so they can all converge at the scorer.  No single Signal makes
a CI decision on its own; the scorer aggregates them (max-severity per
dimension) in a later stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from safesc.tools.index.core.models import Dependency


class Severity(str, Enum):
    """Ordered severity tiers.  Order is meaningful — see :func:`max_severity`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


# Lowest → highest.  Used to compute the weakest-link (max) severity.
_SEVERITY_ORDER: list[Severity] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def max_severity(severities: Iterable[Severity]) -> Severity:
    """Return the highest severity in *severities*, or INFO if empty."""
    highest = Severity.INFO
    for sev in severities:
        if sev.rank > highest.rank:
            highest = sev
    return highest


class Dimension(str, Enum):
    """The five independent trust dimensions.  Severities never cross-add."""

    IDENTITY = "identity"
    BEHAVIOR = "behavior"
    PROVENANCE = "provenance"
    POPULARITY = "popularity"
    VULNERABILITY = "vulnerability"


class Spoofability(str, Enum):
    """How easily an attacker could forge this signal to look benign.

    Per development principle #6, spoofable signals must carry low weight.  The
    scorer consumes this hint; Stage 3 only records it.
    """

    LOW = "low"        # deterministic / externally anchored (hash, CVE, name distance)
    MEDIUM = "medium"  # attacker-influenced but costly (registry metadata)
    HIGH = "high"      # trivially forged (stars, download counts, README text)


@dataclass
class Signal:
    """A single piece of evidence about one dependency, in one dimension."""

    dep: "Dependency"
    dimension: Dimension
    code: str                       # stable machine code, e.g. "identity.typosquat"
    severity: Severity
    message: str
    evidence: list[str] = field(default_factory=list)
    spoofability: Spoofability = Spoofability.MEDIUM
    false_positive_hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.dep.name,
            "version": self.dep.version,
            "ecosystem": self.dep.ecosystem,
            "dimension": self.dimension.value,
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": list(self.evidence),
            "spoofability": self.spoofability.value,
            "false_positive_hints": list(self.false_positive_hints),
        }
