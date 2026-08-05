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


# Registry-provenance fields are FACTS, not files. The IdentityAgent is explicitly
# asked to cite them (publisher, canonical repo, release dates), so their *values* are
# valid, citable evidence and must be admitted alongside file paths — otherwise a
# correct registry citation is wrongly rejected as a "file not in package".
_REGISTRY_FACT_FIELDS = (
    "author", "repo_url", "homepage", "summary",
    "first_release_at", "latest_release_at",
)


def evidence_paths(bundle) -> set[str]:
    """All *citable tokens* present in a DeepAnalysisEvidence bundle (duck-typed):
    file paths from every list slice, plus registry-provenance fact values from the
    identity slice (publisher, repo, dates, …). Named `evidence_paths` for back-compat;
    it is really the set of things a specialist is allowed to cite."""
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
    paths |= _registry_fact_tokens(bundle)
    return paths


def _registry_fact_tokens(bundle) -> set[str]:
    """Citable tokens from the identity slice's registry-provenance facts.

    Each fact value (and its whitespace-separated sub-tokens) is admitted so the LLM can
    cite e.g. `source repo: https://github.com/redis/redis-vl-python` or the bare repo
    URL, or a release timestamp, and have it resolve against the gathered evidence."""
    identity = getattr(bundle, "identity", None)
    registry = getattr(identity, "registry", None) if identity is not None else None
    if registry is None or not getattr(registry, "resolved", False):
        return set()
    tokens: set[str] = set()
    for field in _REGISTRY_FACT_FIELDS:
        value = getattr(registry, field, None)
        if not value:
            continue
        text = str(value)
        tokens.add(text)
        # also admit each path-like sub-token (URL fragments, emails, dates) so a
        # citation that quotes only part of a fact still resolves.
        tokens.update(_PATH_TOKEN.findall(text))
    nearest = getattr(identity, "nearest_popular", None)
    if nearest:
        tokens.add(str(nearest))
    return tokens


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
