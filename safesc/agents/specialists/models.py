"""agents/specialists/models.py — structured outputs of the Stage-4 subagents (§4.2).

Judging subagents (identity, behavior, provenance, authorship) return the §4.2 `LLMOutput`.
The vulnerability pair returns richer reports, but the same rule holds: SafeSC maps them
to signals deterministically, so the models' prose never becomes a severity directly.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

from safesc.core.signals import LLMOutput

ClaimedSeverity = Literal["low", "medium", "high", "critical"]


class CandidateClaim(BaseModel):
    """One suspected, unreported vulnerability in the dependency's own code."""

    title: str = Field(..., description="Short name of the flaw, e.g. 'Stack buffer overflow in parse_header'.")
    cwe: Optional[str] = Field(None, description="CWE id if known, e.g. CWE-120.")
    file: str = Field(..., description="File path relative to the workspace root.")
    line: Optional[int] = Field(None, description="1-based line of the sink, if known.")
    severity: ClaimedSeverity = Field(..., description="Impact if real and reachable.")
    description: str = Field(..., description="What is wrong, the data flow into it, and why it matters.")
    evidence: list[str] = Field(default_factory=list, description="file:line references you read.")
    confidence: float = Field(..., ge=0.0, le=1.0)


class HuntReport(BaseModel):
    """VulnHunter output: candidates only — verification is a different agent's job."""

    candidates: list[CandidateClaim] = Field(
        default_factory=list, max_length=10,
        description="At most 10 most plausible candidates; empty if nothing credible was found.",
    )
    summary: str = Field("", description="What you examined and why the rest was dismissed.")


class CandidateVerdict(BaseModel):
    candidate_id: str = Field(..., description="The id exactly as given, e.g. 1a2b3c-V1.")
    status: Literal["confirmed", "refuted", "inconclusive", "already_reported"]
    severity: ClaimedSeverity = Field(..., description="Your own assessment of impact if confirmed.")
    intentional_backdoor: bool = Field(False, description="True only if the code is deliberately malicious, not merely buggy.")
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list, description="file:line references you read yourself.")
    advisory_ids: list[str] = Field(default_factory=list, description="Matching CVE/GHSA/OSV ids when already_reported.")
    reasoning: str = Field(..., description="Reachability, exploitability, and why.")


class VerificationReport(BaseModel):
    """VulnVerifier output: an independent verdict for every pending candidate."""

    results: list[CandidateVerdict] = Field(default_factory=list)
    summary: str = ""


__all__ = ["CandidateClaim", "CandidateVerdict", "HuntReport", "LLMOutput", "VerificationReport"]
