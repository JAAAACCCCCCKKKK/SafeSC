"""reporter/models.py — the normalised, render-agnostic report (CLAUDE.md §6, §7).

The reporter is a pure, deterministic sink: it turns a finished run's `AuditState` into a
single canonical `AuditReport`, and the three renderers (JSON / Markdown / SARIF) each
project *that* — never the graph state directly. Keeping one intermediate model means the
three formats can never disagree about what the run found.

These models carry NO decision logic (that is the scorer's job, §2.4) and NO secrets
(§3.5 invariant #3): they are built from signals + the already-computed `GateDecision`.
Severity is stored as its **name** (a stable string) so every serialisation is
human-readable and enum-representation-independent.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

REPORT_SCHEMA_VERSION = "1.0"


class SignalView(BaseModel):
    """One signal as it appears in the report — static (Stage 0–3) or LLM (Stage 4),
    identical shape (§5.1.3). This is evidence, verbatim; the reporter adds no judgement."""

    dimension: str
    origin: str                                   # "static" | "llm"
    source: str                                   # e.g. "stage3.typosquat" / "llm.behavior"
    severity: str                                 # Severity name
    confidence: float = 1.0
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    reasoning: str = ""                           # LLM origin only
    false_positive_hints: list[str] = Field(default_factory=list)


class DependencyFinding(BaseModel):
    """Per-dependency roll-up: the combined severity, the per-dimension breakdown, and
    every contributing signal. `severity` is the weakest-link max the scorer used (§2.4)."""

    dep_key: str
    name: str = ""
    version: str = ""
    ecosystem: str = ""
    lockfile_path: Optional[str] = None
    source_url: Optional[str] = None
    severity: str = "CLEAN"
    dimensions: dict[str, str] = Field(default_factory=dict)   # dimension -> Severity name
    signals: list[SignalView] = Field(default_factory=list)

    @property
    def is_flagged(self) -> bool:
        return self.severity != "CLEAN"


class DegradedView(BaseModel):
    node: str
    reason: str


class AuditReport(BaseModel):
    """The canonical run report. One per run; the three renderers project this."""

    schema_version: str = REPORT_SCHEMA_VERSION
    run_id: str = ""
    mode: str = "audit"                            # "audit" | "query"
    generated_at: Optional[str] = None             # ISO-8601; injectable for reproducibility

    overall_severity: str = "CLEAN"
    passed: bool = True
    exit_code: int = 0
    incomplete: bool = False

    total_dependencies: int = 0
    flagged_count: int = 0

    summary: str = ""                              # the scorer's human summary (§2.4)
    findings: list[DependencyFinding] = Field(default_factory=list)
    degraded: list[DegradedView] = Field(default_factory=list)

    @property
    def flagged_findings(self) -> list[DependencyFinding]:
        return [f for f in self.findings if f.is_flagged]
