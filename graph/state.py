"""graph/state.py — the single shared LangGraph state (CLAUDE.md §2.6).

Sole inter-node channel. Concurrently-written fields carry channel reducers so
out-of-order specialist fan-in merges deterministically (see reducers below).
On the pinned LangGraph 1.x range, Pydantic state with `Annotated` reducers is fully
supported. (Historical aside: on much older 0.x builds this would have needed a TypedDict
with the same Annotated fields; that fallback is no longer relevant.)
"""

from __future__ import annotations

from enum import Enum, IntEnum
from typing import Annotated, Optional, TYPE_CHECKING

from pydantic import BaseModel, Field

# Soft-import the canonical Dependency (tools/index/core/models.py) so graph/ stays
# standalone-testable; the fallback below MUST stay field-compatible with the real model.
if TYPE_CHECKING:
    from tools.index.core.models import Dependency  # noqa: F401
else:
    try:
        from tools.index.core.models import Dependency
    except Exception:

        class Dependency(BaseModel):  # minimal stand-in — see note above
            name: str
            version: str
            ecosystem: str
            lockfile_path: Optional[str] = None
            source_url: Optional[str] = None
            artifact_url: Optional[str] = None
            hash: Optional[str] = None
            ref: Optional[str] = None


# =============================================================================
# Enums / constants
# =============================================================================


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
    STATIC = "static"  # Stages 0-3 collectors
    LLM = "llm"        # Stage-4 specialists


class RunMode(str, Enum):
    AUDIT = "audit"    # CI trigger, produces a gate + exit code
    QUERY = "query"    # interactive, evidence only, no gate (§1.3)


class RunScope(str, Enum):
    SINGLE_PACKAGE = "single_package"
    FULL_REPO = "full_repo"


class RoutePath(str, Enum):
    # Both paths share the deterministic spine; they differ only at the ENTRY node
    # (ingestion), never in the analysis (§2.2-A).
    SINGLE_PACKAGE = "single_package"  # entry: resolve_single_package → spine @ hash_verify
    FULL_SPINE = "full_spine"          # entry: index (discover+parse) → spine


class NodeStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"


def dep_key(dep: "Dependency | str", *, ecosystem: str = "", name: str = "", version: str = "") -> str:
    """Stable identity for a dependency across the graph: 'ecosystem:name@version'."""
    if isinstance(dep, str):
        return dep
    return f"{dep.ecosystem}:{dep.name}@{dep.version}"


# =============================================================================
# Value models
# =============================================================================


class Signal(BaseModel):
    """Unified signal both static collectors and LLM specialists emit (§5.1.3).
    `severity` is this signal's normalised contribution; combining into the gate is
    the scorer's job (§2.4). One LLM signal's §4.3 fusion is deterministic table lookup.
    """

    dep_key: str
    dimension: TrustDimension
    origin: SignalOrigin
    source: str = Field(..., description="e.g. 'stage3.typosquat' or 'llm.behavior'")
    severity: Severity
    confidence: float = 1.0
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    reasoning: str = ""                      # LLM origin only
    false_positive_hints: list[str] = Field(default_factory=list)

    def identity(self) -> tuple[str, str, str]:
        return (self.dep_key, self.source, self.dimension.value)

    @classmethod
    def from_llm_output(cls, dep_key: str, dimension: TrustDimension, out: "LLMOutput") -> "Signal":
        """Map a §4.2 specialist output into a Signal via the §4.3 fusion table.
        Escalate-only: a 'clean' verdict maps to CLEAN and contributes nothing.
        """
        return cls(
            dep_key=dep_key,
            dimension=dimension,
            origin=SignalOrigin.LLM,
            source=f"llm.{out.task}",
            severity=_fuse(out.verdict, out.confidence),
            confidence=out.confidence,
            summary=out.reasoning[:280],
            evidence=list(out.evidence),
            reasoning=out.reasoning,
            false_positive_hints=list(out.false_positive_hints),
        )


class LLMOutput(BaseModel):
    """The mandatory structured output every specialist returns (§4.2).
    The constraint validator rejects anything that does not parse into this."""

    task: str
    verdict: str  # "clean" | "suspicious" | "malicious"
    confidence: float
    evidence: list[str] = Field(default_factory=list)
    reasoning: str = ""
    false_positive_hints: list[str] = Field(default_factory=list)


def _fuse(verdict: str, confidence: float) -> Severity:
    """CLAUDE.md §4.3 fusion table. Escalate-only: 'clean' -> CLEAN."""
    v = (verdict or "").lower()
    if v == "malicious":
        return Severity.CRITICAL if confidence >= 0.7 else (Severity.HIGH if confidence >= 0.4 else Severity.MEDIUM)
    if v == "suspicious":
        return Severity.HIGH if confidence >= 0.7 else Severity.LOW  # <0.7 = evidence only, minimal contribution
    return Severity.CLEAN


class GateDecision(BaseModel):
    """Terminal output — written once, by report_agent only (§2.4)."""

    per_dep: dict[str, Severity] = Field(default_factory=dict)
    overall: Severity = Severity.CLEAN
    passed: bool = True
    exit_code: int = 0
    summary: str = ""


class DegradedNote(BaseModel):
    node: str
    reason: str


# =============================================================================
# Channel reducers  (current, update) -> merged
# =============================================================================


def replace_if_present(current, update):
    """Set-once semantics: keep the incoming value only if it is non-empty."""
    return update if update else current


def merge_signals(current: list[Signal], update: list[Signal]) -> list[Signal]:
    """Additive + dedup by (dep_key, source, dimension). Dedup makes node retries
    (auto-repair, §2.7) idempotent instead of double-counting."""
    if not update:
        return current
    seen = {s.identity() for s in current}
    out = list(current)
    for s in update:
        if s.identity() not in seen:
            seen.add(s.identity())
            out.append(s)
    return out


def max_severity(current: dict[str, Severity], update: dict[str, Severity]) -> dict[str, Severity]:
    """MAX-WINS: conflicting tiers resolve to the higher one (escalate-only, §3.3/§4.3).
    Order-independent, so out-of-order fan-in is safe."""
    if not update:
        return current
    out = dict(current)
    for k, v in update.items():
        out[k] = v if (k not in out or v > out[k]) else out[k]
    return out


def sum_deltas(current: Optional[int], update: Optional[int]) -> int:
    """SUM of per-node deltas: each node returns only the calls IT made. A plain
    overwrite would drop a parallel branch's calls and defeat the §5.3 cap."""
    return (current or 0) + (update or 0)


def append_notes(current: list[DegradedNote], update: list[DegradedNote]) -> list[DegradedNote]:
    return current + update if update else current


def union_keys(current: Optional[list[str]], update: Optional[list[str]]) -> list[str]:
    """Order-preserving set-union of dep_keys. The gate is the sole writer of
    `dispatched`, but a reducer keeps fan-in deterministic and idempotent under retries."""
    if not update:
        return current or []
    out = list(current or [])
    for k in update:
        if k not in out:
            out.append(k)
    return out


def write_once(current, update):
    """For gate_decision: only report_agent writes it; last write wins."""
    return update if update is not None else current


# =============================================================================
# The shared state
# =============================================================================


class AuditState(BaseModel):
    # --- routing (set by router, §2.2-A) ---
    mode: RunMode = RunMode.AUDIT
    scope: RunScope = RunScope.FULL_REPO
    path: RoutePath = RoutePath.FULL_SPINE
    target: str = ""
    ecosystem: Optional[str] = None  # optional ingestion hint for a single-package spec

    # --- established by the deterministic spine, then fixed ---
    dependencies: Annotated[list[Dependency], replace_if_present] = Field(default_factory=list)

    # --- written concurrently by fan-out specialists (need reducers) ---
    signals: Annotated[list[Signal], merge_signals] = Field(default_factory=list)
    escalations: Annotated[dict[str, Severity], max_severity] = Field(default_factory=dict)
    llm_calls: Annotated[int, sum_deltas] = 0
    degraded_notes: Annotated[list[DegradedNote], append_notes] = Field(default_factory=list)
    # dep_keys the gate fanned out to LLM specialists — lets the scorer distinguish
    # "no LLM analysis warranted" (deterministic-only flags) from "LLM analysis missing".
    dispatched: Annotated[list[str], union_keys] = Field(default_factory=list)

    # --- gate: report_agent only (§2.4) ---
    gate_decision: Annotated[Optional[GateDecision], write_once] = None

    # --- config threaded through the run ---
    llm_call_cap: int = 200  # §5.3 hard ceiling; concrete value TBD (doc §9)

    # ---- read helpers (no writes; safe to call in any node) ----

    def would_exceed_cap(self, planned: int = 1) -> bool:
        return (self.llm_calls + planned) > self.llm_call_cap

    def signals_for(self, key: str) -> list[Signal]:
        return [s for s in self.signals if s.dep_key == key]


# ---- node-return helpers (nodes return deltas, not absolute state) ----


def increment_llm_calls(n: int = 1) -> dict:
    """A node reports the calls it made: `return increment_llm_calls(2)`.
    The sum_deltas reducer folds it into the running total."""
    return {"llm_calls": n}


def emit_escalation(key: str, severity: Severity) -> dict:
    return {"escalations": {key: severity}}


def emit_signals(signals: list[Signal]) -> dict:
    return {"signals": signals}


def emit_degraded(node: str, reason: str) -> dict:
    return {"degraded_notes": [DegradedNote(node=node, reason=reason)]}
