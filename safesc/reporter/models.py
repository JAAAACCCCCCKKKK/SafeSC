"""reporter/models.py — the normalised, render-agnostic report (CLAUDE.md §6, §7).

The reporter is a pure, deterministic sink: it turns a finished run's ledger and the
scorer's `Decision` into a single canonical `AuditReport`, and the three renderers (JSON /
Markdown / SARIF) each project *that*. One intermediate model means the formats can never
disagree about what the run found.

These models carry NO decision logic (that is the scorer's job, §2.4) and NO secrets
(§3.5): they are built from signals + the already-computed decision. Severity is stored as
its **name** so every serialisation is human-readable.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

REPORT_SCHEMA_VERSION = "2.0"


class SignalView(BaseModel):
    """One signal as it appears in the report — static or LLM, identical shape."""

    dimension: str
    origin: str                                   # "static" | "llm"
    source: str                                   # e.g. "identity.typosquat" / "llm.behavior"
    severity: str                                 # Severity name
    confidence: float = 1.0
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    reasoning: str = ""                           # LLM origin only
    false_positive_hints: list[str] = Field(default_factory=list)


class DependencyFinding(BaseModel):
    """Per-dependency roll-up. `severity` is the weakest-link max the scorer used (§2.4)."""

    dep_key: str
    name: str = ""
    version: str = ""
    ecosystem: str = ""
    lockfile_path: Optional[str] = None
    source_url: Optional[str] = None
    direct: bool = False
    severity: str = "CLEAN"
    dimensions: dict[str, str] = Field(default_factory=dict)   # dimension -> Severity name
    signals: list[SignalView] = Field(default_factory=list)

    @property
    def is_flagged(self) -> bool:
        return self.severity != "CLEAN"


class CandidateView(BaseModel):
    """A suspected unreported vulnerability and what the verifier made of it."""

    id: str
    dep_key: str
    title: str
    cwe: Optional[str] = None
    location: str = ""
    claimed_severity: str = ""
    status: str = "pending"
    verifier_note: str = ""


class SubagentRunView(BaseModel):
    dep_key: str
    role: str
    status: str
    detail: str = ""


class DegradedView(BaseModel):
    node: str
    reason: str


class AuditReport(BaseModel):
    """The canonical run report. One per run; the three renderers project this."""

    schema_version: str = REPORT_SCHEMA_VERSION
    run_id: str = ""
    target: str = ""
    mode: str = "interactive"                      # "ci" | "interactive"
    model: str = ""                                # provider/model that ran the agents
    generated_at: Optional[str] = None             # ISO-8601; injectable for reproducibility

    overall_severity: str = "CLEAN"
    passed: bool = True
    exit_code: int = 0
    trust_score: int = 100
    grade: str = "A"
    incomplete: bool = False
    incomplete_reasons: list[str] = Field(default_factory=list)

    total_dependencies: int = 0
    flagged_count: int = 0

    summary: str = ""                              # the scorer's human summary (§2.4)
    findings: list[DependencyFinding] = Field(default_factory=list)
    vulnerability_candidates: list[CandidateView] = Field(default_factory=list)
    subagent_runs: list[SubagentRunView] = Field(default_factory=list)
    degraded: list[DegradedView] = Field(default_factory=list)

    @property
    def flagged_findings(self) -> list[DependencyFinding]:
        return [f for f in self.findings if f.is_flagged]
