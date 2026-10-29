"""core/signals.py — the unified signal model every producer emits (CLAUDE.md §2.3, §4.3).

Static tools (Stages 0–3) and LLM subagents (Stage 4) produce the *same* `Signal` shape and
feed the scorer identically. A subagent's structured output is mapped through the §4.3
fusion table here, deterministically — the model never chooses a severity directly.
"""

from __future__ import annotations

from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from safesc.tools.index.core.models import Dependency


class Severity(IntEnum):
    """Ordered so max() implements weakest-link directly."""

    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class TrustDimension(str, Enum):
    IDENTITY = "identity"
    BEHAVIOR = "behavior"
    PROVENANCE = "provenance"
    POPULARITY = "popularity"
    VULNERABILITY = "vulnerability"


class SignalOrigin(str, Enum):
    STATIC = "static"  # deterministic agent tools (Stages 0-3)
    LLM = "llm"        # Stage-4 subagents


def dep_key(dep: "Dependency | str") -> str:
    """Stable identity for a dependency across the run: 'ecosystem:name@version'."""
    if isinstance(dep, str):
        return dep
    return f"{dep.ecosystem}:{dep.name}@{dep.version}"


class Signal(BaseModel):
    """Unified signal both static tools and LLM subagents emit (§2.3).

    `severity` is this signal's normalised contribution; combining signals into the gate
    is the scorer's job (§2.4).
    """

    dep_key: str
    dimension: TrustDimension
    origin: SignalOrigin
    source: str = Field(..., description="e.g. 'identity.typosquat' or 'llm.behavior'")
    severity: Severity
    confidence: float = 1.0
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    reasoning: str = ""                      # LLM origin only
    false_positive_hints: list[str] = Field(default_factory=list)

    def identity(self) -> tuple[str, str, str]:
        return (self.dep_key, self.source, self.dimension.value)

    @classmethod
    def from_llm_output(
        cls,
        key: str,
        dimension: TrustDimension,
        out: "LLMOutput",
        *,
        source: str | None = None,
        ceiling: Severity = Severity.CRITICAL,
    ) -> "Signal":
        """Map a §4.2 subagent output into a Signal via the §4.3 fusion table.

        Escalate-only: a 'clean' verdict maps to CLEAN and contributes nothing. `ceiling`
        caps the fused severity from above (used by the vulnerability verifier, whose
        finding can never outrank the severity of the flaw it confirmed); it can only
        lower what the table grants a *new* LLM signal, never any existing signal.
        """
        return cls(
            dep_key=key,
            dimension=dimension,
            origin=SignalOrigin.LLM,
            source=source or f"llm.{out.task}",
            severity=min(fuse(out.verdict, out.confidence), ceiling),
            confidence=out.confidence,
            summary=out.reasoning[:280],
            evidence=list(out.evidence),
            reasoning=out.reasoning,
            false_positive_hints=list(out.false_positive_hints),
        )


Verdict = Literal["clean", "suspicious", "malicious"]


class LLMOutput(BaseModel):
    """The mandatory structured output every judging subagent returns (§4.2)."""

    task: str = Field("", description="Leave empty; SafeSC fills it in.")
    verdict: Verdict = Field(..., description="clean | suspicious | malicious")
    confidence: float = Field(..., ge=0.0, le=1.0, description="0.0-1.0")
    evidence: list[str] = Field(
        default_factory=list,
        description="Specific files (path or path:line) or registry facts you relied on.",
    )
    reasoning: str = Field("", description="Why — concise, evidence-based.")
    false_positive_hints: list[str] = Field(
        default_factory=list, description="Benign explanations a reviewer should consider."
    )


def fuse(verdict: str, confidence: float) -> Severity:
    """CLAUDE.md §4.3 fusion table. Escalate-only: 'clean' -> CLEAN."""
    v = (verdict or "").lower()
    if v == "malicious":
        return Severity.CRITICAL if confidence >= 0.7 else (Severity.HIGH if confidence >= 0.4 else Severity.MEDIUM)
    if v == "suspicious":
        return Severity.HIGH if confidence >= 0.7 else Severity.LOW  # <0.7 = evidence only
    return Severity.CLEAN


class DegradedNote(BaseModel):
    """A coverage gap: some part of the run could not analyse what it was meant to."""

    node: str
    reason: str


# scan-layer Severity (info/low/medium/high/critical) -> core Severity. `info` is the scan
# layer's "no concern" tier, so it maps to CLEAN and never escalates (§4.3).
_SCAN_SEVERITY: dict[str, Severity] = {
    "info": Severity.CLEAN,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def from_scan_severity(scan_severity) -> Severity:
    return _SCAN_SEVERITY[getattr(scan_severity, "value", scan_severity)]


def scan_signal_to_core(s) -> Signal:
    """safesc.tools.scan.signals.models.Signal -> core Signal (Stage 3)."""
    return Signal(
        dep_key=dep_key(s.dep),
        dimension=TrustDimension(s.dimension.value),
        origin=SignalOrigin.STATIC,
        source=s.code,
        severity=from_scan_severity(s.severity),
        confidence=1.0,
        summary=s.message,
        evidence=list(s.evidence),
        false_positive_hints=list(s.false_positive_hints),
    )


def hash_result_to_core(r) -> Signal:
    """HashVerificationResult -> core Signal, always a provenance signal (Stage 2)."""
    return Signal(
        dep_key=dep_key(r.dep),
        dimension=TrustDimension.PROVENANCE,
        origin=SignalOrigin.STATIC,
        source=f"stage2.hash.{r.status.value}",
        severity=from_scan_severity(r.severity),
        confidence=1.0,
        summary=r.detail or f"hash {r.status.value}",
        evidence=[h for h in (r.lockfile_hash, r.registry_hash) if h],
    )
