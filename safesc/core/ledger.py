"""core/ledger.py — the run's blackboard (CLAUDE.md §2.6).

One `RunLedger` per run is the sole channel between agents: every tool reads and writes it,
and no agent ever messages another directly. It is plain, thread-safe Python — Strands runs
the tool calls of a single model turn concurrently — and it is never shown to a model whole:
tools return compact summaries and the full record stays here (lesson-8 "externalize").

The merge rules are the ones the LangGraph reducers used to enforce, now enforced in code:

* signals: additive, deduplicated by ``(dep_key, source, dimension)``; on a collision the
  higher severity wins, so retries are idempotent and a re-run can only escalate;
* stages: monotonic — a stage, once completed, stays completed;
* the decision: write-once (§2.4) — `finalize` refuses a second write.

It also holds the two things that make agent discretion safe (§2.5): the ordered stage
prerequisites every tool checks, and the *required coverage* list that must be worked
through (or exhausted by budget) before a score may be finalized.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Literal, Optional

from pydantic import BaseModel, Field

from safesc.core.signals import DegradedNote, Severity, Signal, TrustDimension, dep_key
from safesc.core.targets import TargetKind
from safesc.tools.index.core.models import Dependency


class Stage(str, Enum):
    """The fixed, non-discretionary static sequence (§2.1, §2.5)."""

    DISCOVER = "discover"
    PARSE = "parse"
    VERIFY = "verify"
    COLLECT = "collect"


STATIC_STAGES: tuple[Stage, ...] = (Stage.DISCOVER, Stage.PARSE, Stage.VERIFY, Stage.COLLECT)


class Role(str, Enum):
    """Stage-4 subagents. Identity/behavior/provenance mirror their trust dimensions."""

    IDENTITY = "identity"
    BEHAVIOR = "behavior"
    PROVENANCE = "provenance"
    AUTHORSHIP = "authorship"
    VULN_HUNTER = "vuln_hunter"
    VULN_VERIFIER = "vuln_verifier"


ROLE_FOR_DIMENSION: dict[TrustDimension, Role] = {
    TrustDimension.IDENTITY: Role.IDENTITY,
    TrustDimension.BEHAVIOR: Role.BEHAVIOR,
    TrustDimension.PROVENANCE: Role.PROVENANCE,
}


class Feature(str, Enum):
    """Complementary analyses enabled with ``--with`` (each widens required coverage)."""

    AUTHORSHIP = "authorship"    # code-style authorship analysis on every direct dep
    VULN_HUNT = "vuln-hunt"      # unreported-vulnerability hunt (+ verification) on every direct dep
    TRANSITIVE = "transitive"    # extend the two above to transitive deps as well
    GITHUB = "github"            # attach the GitHub MCP server (needs GITHUB_TOKEN)


RunStatus = Literal["ok", "degraded", "denied"]


@dataclass
class RunOptions:
    target: str
    target_kind: TargetKind = TargetKind.REPOSITORY
    exclude: tuple[str, ...] = ()
    features: frozenset[Feature] = frozenset()
    max_subagents: int = 40
    subagent_turns: int = 16
    fail_on: Severity = Severity.HIGH
    gray_floor: Severity = Severity.MEDIUM
    decided_ceiling: Severity = Severity.CRITICAL
    ci: bool = False


@dataclass(frozen=True)
class LockfileRef:
    path: str
    ecosystem: str


@dataclass(frozen=True)
class SubagentRun:
    dep_key: str
    role: Role
    status: RunStatus
    detail: str = ""


class VulnCandidate(BaseModel):
    """A suspected, unreported vulnerability: a hunter's *claim*, not yet a finding."""

    id: str
    dep_key: str
    title: str
    cwe: Optional[str] = None
    file: str
    line: Optional[int] = None
    claimed_severity: Literal["low", "medium", "high", "critical"] = "medium"
    description: str = ""
    status: Literal["pending", "confirmed", "refuted", "inconclusive", "already_reported"] = "pending"
    verifier_note: str = ""


class Decision(BaseModel):
    """The scorer's output — written once, by `finalize` only (§2.4)."""

    per_dep: dict[str, Severity] = Field(default_factory=dict)
    overall: Severity = Severity.CLEAN
    passed: bool = True
    exit_code: int = 0
    score: int = 100
    grade: str = "A"
    incomplete: bool = False
    incomplete_reasons: list[str] = Field(default_factory=list)
    summary: str = ""


class RunLedger:
    """Thread-safe blackboard for one run. See module docstring for the merge rules."""

    def __init__(self, run_id: str, options: RunOptions):
        self.run_id = run_id
        self.options = options
        self._lock = threading.RLock()
        self.lockfiles: list[LockfileRef] = []
        self._deps: dict[str, Dependency] = {}
        self._signals: dict[tuple[str, str, str], Signal] = {}
        self.notes: list[DegradedNote] = []
        self.stages: set[Stage] = set()
        self.subagent_runs: list[SubagentRun] = []
        self.budget_used = 0
        self.candidates: dict[str, VulnCandidate] = {}
        self._citable: dict[str, set[str]] = {}
        self.workspaces: dict[str, Path] = {}
        self.decision: Optional[Decision] = None

    # ------------------------------------------------------------------ dependencies

    @property
    def dependencies(self) -> list[Dependency]:
        with self._lock:
            return list(self._deps.values())

    def set_dependencies(self, deps: Iterable[Dependency]) -> None:
        with self._lock:
            for dep in deps:
                self._deps.setdefault(dep_key(dep), dep)

    def get_dependency(self, key: str) -> Optional[Dependency]:
        with self._lock:
            return self._deps.get(key)

    # ------------------------------------------------------------------ signals

    @property
    def signals(self) -> list[Signal]:
        with self._lock:
            return list(self._signals.values())

    def add_signals(self, signals: Iterable[Signal]) -> int:
        """Merge signals; returns how many were new or raised an existing severity."""
        changed = 0
        with self._lock:
            for s in signals:
                ident = s.identity()
                cur = self._signals.get(ident)
                if cur is None or s.severity > cur.severity:
                    self._signals[ident] = s
                    changed += 1
        return changed

    def signals_for(self, key: str) -> list[Signal]:
        with self._lock:
            return [s for s in self._signals.values() if s.dep_key == key]

    def add_note(self, node: str, reason: str) -> None:
        with self._lock:
            self.notes.append(DegradedNote(node=node, reason=reason))

    # ------------------------------------------------------------------ stages

    def mark_stage(self, stage: Stage) -> None:
        with self._lock:
            self.stages.add(stage)

    def missing_stages(self, *needed: Stage) -> list[Stage]:
        with self._lock:
            return [s for s in needed if s not in self.stages]

    def static_complete(self) -> bool:
        return not self.missing_stages(*STATIC_STAGES)

    # ------------------------------------------------------------------ evidence

    def register_citable(self, key: str, refs: Iterable[str]) -> None:
        """Record what a deterministic tool showed an agent about `key`, so a subagent's
        citations can be checked against evidence that actually exists (§2.7.1)."""
        with self._lock:
            bucket = self._citable.setdefault(key, set())
            bucket.update(r for r in refs if r)

    def citable(self, key: str) -> set[str]:
        with self._lock:
            refs = set(self._citable.get(key, set()))
            root = self.workspaces.get(key)
        if root is not None and root.is_dir():
            refs.update(_workspace_files(root))
        return refs

    def set_workspace(self, key: str, root: Path) -> None:
        with self._lock:
            self.workspaces[key] = root

    # ------------------------------------------------------------------ budget + coverage

    def try_consume_budget(self) -> bool:
        """Take one subagent invocation from the run budget. Never released (§5.3)."""
        with self._lock:
            if self.budget_used >= self.options.max_subagents:
                return False
            self.budget_used += 1
            return True

    @property
    def budget_exhausted(self) -> bool:
        with self._lock:
            return self.budget_used >= self.options.max_subagents

    def record_subagent(self, key: str, role: Role, status: RunStatus, detail: str = "") -> None:
        with self._lock:
            self.subagent_runs.append(SubagentRun(key, role, status, detail))

    def attempted(self, key: str, role: Role) -> bool:
        with self._lock:
            return any(r.dep_key == key and r.role == role for r in self.subagent_runs)

    def required_coverage(self) -> list[tuple[str, Role, str]]:
        """Every (dep, role) this run must analyse before it may be scored, with why.

        Three sources, all deterministic: the post-Stage-3 gray zone (§2.2-B); the
        `--with` features, which demand authorship / vuln-hunting on direct deps (or all
        deps under `transitive`); and every hunter candidate still awaiting verification.
        """
        from safesc.core.gate import plan_triage

        required: list[tuple[str, Role, str]] = []
        for item in plan_triage(self):
            role = ROLE_FOR_DIMENSION.get(item.dimension)
            if role is not None:
                required.append((item.dep_key, role, f"{item.dimension.value} gray zone ({item.severity.name})"))
        feats = self.options.features
        scope = [
            d for d in self.dependencies
            if Feature.TRANSITIVE in feats or d.is_direct or d.layer_number == 1
        ]
        if Feature.AUTHORSHIP in feats:
            required += [(dep_key(d), Role.AUTHORSHIP, "--with authorship") for d in scope]
        if Feature.VULN_HUNT in feats:
            required += [(dep_key(d), Role.VULN_HUNTER, "--with vuln-hunt") for d in scope]
        with self._lock:
            pending = sorted({c.dep_key for c in self.candidates.values() if c.status == "pending"})
        required += [(k, Role.VULN_VERIFIER, "unverified vulnerability candidates") for k in pending]
        seen: set[tuple[str, Role]] = set()
        unique = []
        for k, role, why in required:
            if (k, role) not in seen:
                seen.add((k, role))
                unique.append((k, role, why))
        return unique

    def outstanding_coverage(self) -> list[tuple[str, Role, str]]:
        """Required coverage not yet attempted. Empty once the budget is spent: whatever is
        left can no longer be run, and the scorer reports it as incomplete instead."""
        if self.budget_exhausted:
            return []
        out = []
        for k, role, why in self.required_coverage():
            if role == Role.VULN_VERIFIER:
                if self.pending_candidates(k):
                    out.append((k, role, why))
            elif not self.attempted(k, role):
                out.append((k, role, why))
        return out

    # ------------------------------------------------------------------ vuln candidates

    def register_candidates(self, key: str, claims: Iterable[dict]) -> list[str]:
        with self._lock:
            base = len([c for c in self.candidates.values() if c.dep_key == key])
            ids = []
            for i, claim in enumerate(claims, start=base + 1):
                cid = f"{_short(key)}-V{i}"
                self.candidates[cid] = VulnCandidate(id=cid, dep_key=key, **claim)
                ids.append(cid)
            return ids

    def pending_candidates(self, key: str) -> list[VulnCandidate]:
        with self._lock:
            return [c for c in self.candidates.values() if c.dep_key == key and c.status == "pending"]

    def resolve_candidate(self, cid: str, status: str, note: str = "") -> None:
        with self._lock:
            c = self.candidates[cid]
            self.candidates[cid] = c.model_copy(update={"status": status, "verifier_note": note[:500]})

    # ------------------------------------------------------------------ decision

    def finalize(self, decision: Decision) -> bool:
        """Write-once. Returns False (and changes nothing) if already finalized."""
        with self._lock:
            if self.decision is not None:
                return False
            self.decision = decision
            return True


def _short(key: str) -> str:
    """A compact, deterministic, id-safe label for a dep key."""
    import hashlib

    return hashlib.sha256(key.encode()).hexdigest()[:6]


_MAX_WORKSPACE_FILES = 20_000


def _workspace_files(root: Path) -> set[str]:
    out: set[str] = set()
    for i, p in enumerate(root.rglob("*")):
        if i > _MAX_WORKSPACE_FILES:
            break
        if p.is_file() and not p.is_symlink():
            out.add(p.relative_to(root).as_posix())
    return out
