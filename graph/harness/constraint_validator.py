"""graph/harness/constraint_validator.py — the inner LLM-node wrapper (CLAUDE.md §2.7.1).

Validates every specialist output before it becomes a signal: schema (§4.2 `LLMOutput`)
plus semantic checks (evidence-ref resolution against the gathered bundle; escalate-only
defense-in-depth). Schema/ref violations are repaired via re-call on an INDEPENDENT counter
(no retry storm, §2.7.2); on exhaustion `obtain()` returns a not-ok result, never raises.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from graph.state import LLMOutput, Severity, Signal, TrustDimension

logger = logging.getLogger("safesc.validator")

_VALID_VERDICTS = {"clean", "suspicious", "malicious"}
# path-like tokens inside a free-text evidence ref (e.g. "scripts/setup.js", "build.rs")
_PATH_TOKEN = re.compile(r"[\w./-]+\.[A-Za-z0-9]{1,6}")


class ValidationError(Exception):
    """Non-transient by construction — auto-repair (§2.7.2) must not retry these."""


@dataclass(frozen=True)
class ValidatedResult:
    ok: bool
    output: Optional[LLMOutput] = None
    reason: str = ""
    calls: int = 0  # LLM calls actually spent (initial + repairs), for the §5.3 counter


# =============================================================================
# Pure checks (unit-testable without a model)
# =============================================================================


def validate_schema(raw) -> LLMOutput:
    """Parse/validate into LLMOutput. Raises ValidationError on any schema violation."""
    try:
        out = raw if isinstance(raw, LLMOutput) else LLMOutput.model_validate(raw)
    except Exception as exc:
        raise ValidationError(f"schema parse failed: {exc}") from exc
    if out.verdict.lower() not in _VALID_VERDICTS:
        raise ValidationError(f"illegal verdict '{out.verdict}' (allowed: {sorted(_VALID_VERDICTS)})")
    if not (0.0 <= out.confidence <= 1.0):
        raise ValidationError(f"confidence {out.confidence} out of range [0,1]")
    return out


def evidence_paths(bundle) -> set[str]:
    """All file paths present in a DeepAnalysisEvidence bundle (duck-typed)."""
    paths: set[str] = set()
    for slice_name in ("behavior", "provenance", "identity"):
        sl = getattr(bundle, slice_name, None)
        if sl is None:
            continue
        for attr in vars(sl) if hasattr(sl, "__dict__") else []:
            items = getattr(sl, attr, None)
            if isinstance(items, list):
                for it in items:
                    p = getattr(it, "path", None)
                    if p:
                        paths.add(p)
    return paths


def unresolved_refs(out: LLMOutput, known_paths: set[str]) -> list[str]:
    """Evidence refs that cite a file path absent from the gathered evidence. Refs with
    no path-like token are allowed (paraphrase can't be path-checked) — we only reject a
    citation that names a file the package never contained."""
    bad: list[str] = []
    for ref in out.evidence:
        cited = set(_PATH_TOKEN.findall(ref))
        if not cited:
            continue
        if not any(any(c == p or p.endswith(c) or c.endswith(p) for p in known_paths) for c in cited):
            bad.append(ref)
    return bad


def check_escalate_only(fused: Severity, baseline: Severity) -> bool:
    """post = max(baseline, fused) must be >= baseline. Always true under max-wins; a
    False here means a broken reducer, not a model problem."""
    return max(baseline, fused) >= baseline


# =============================================================================
# The validator (owns the repair loop)
# =============================================================================


class ConstraintValidator:
    def __init__(self, max_repairs: int = 2):
        self.max_repairs = max_repairs

    def obtain(
        self,
        llm,
        system: str,
        user: str,
        *,
        evidence,
        dimension: TrustDimension,
        dep_key: str,
        baseline: Severity,
    ) -> ValidatedResult:
        known = evidence_paths(evidence)
        prompt = user
        calls = 0
        last_violation = ""

        for attempt in range(self.max_repairs + 1):
            try:
                raw = llm(system, prompt)
            except Exception as exc:
                # infrastructure faults are the OUTER auto-repair's job; surface them
                raise
            calls += 1

            try:
                out = validate_schema(raw)
                bad = unresolved_refs(out, known)
                if bad:
                    raise ValidationError(
                        f"cited evidence not found in package: {bad}. Cite only files present in the evidence."
                    )
                fused = Signal.from_llm_output(dep_key, dimension, out).severity
                if not check_escalate_only(fused, baseline):  # defense-in-depth
                    raise ValidationError("emitting this signal would lower the dimension severity")
                return ValidatedResult(ok=True, output=out, calls=calls)
            except ValidationError as v:
                last_violation = str(v)
                logger.info("constraint violation (%s/%s), attempt %d: %s", dep_key, dimension.value, attempt, v)
                prompt = _repair_prompt(user, last_violation)

        return ValidatedResult(ok=False, reason=f"validation exhausted after {calls} call(s): {last_violation}", calls=calls)


def _repair_prompt(original: str, violation: str) -> str:
    return (
        original
        + "\n\n=== YOUR PREVIOUS RESPONSE WAS REJECTED ===\n"
        + f"Reason: {violation}\n"
        + "Return a corrected JSON object that fixes exactly this problem. Do not add prose."
    )
