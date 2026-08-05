"""Unit tests for graph/harness/constraint_validator.py (§2.7.1).

Covers the pure checks (schema, evidence-ref resolution, escalate-only) and the repair
loop (repair on rejection with an independent counter; degrade-not-raise on exhaustion).
No real model — `llm` is a plain callable stub.
"""

from __future__ import annotations

import types

import pytest

from graph.harness import constraint_validator as cv
from graph.state import LLMOutput, Severity, TrustDimension


def _out(**kw):
    base = dict(task="behavior", verdict="suspicious", confidence=0.8, evidence=[], reasoning="r")
    base.update(kw)
    return LLMOutput(**base)


# ---- pure checks ----


def test_validate_schema_accepts_model_and_dict():
    assert isinstance(cv.validate_schema(_out()), LLMOutput)
    assert isinstance(cv.validate_schema(_out().model_dump()), LLMOutput)


def test_validate_schema_rejects_bad_verdict():
    with pytest.raises(cv.ValidationError):
        cv.validate_schema(_out(verdict="totally-safe"))


def test_validate_schema_rejects_out_of_range_confidence():
    with pytest.raises(cv.ValidationError):
        cv.validate_schema(_out(confidence=1.7))


def test_validate_schema_rejects_unparseable():
    with pytest.raises(cv.ValidationError):
        cv.validate_schema({"not": "an llm output"})


def test_evidence_paths_collects_from_slices():
    item = types.SimpleNamespace(path="scripts/postinstall.js")
    beh = types.SimpleNamespace(scripts=[item])
    bundle = types.SimpleNamespace(behavior=beh, provenance=None, identity=None)
    assert "scripts/postinstall.js" in cv.evidence_paths(bundle)


def test_unresolved_refs_flags_unknown_path():
    out = _out(evidence=["see evil.js for the payload"])
    assert cv.unresolved_refs(out, {"scripts/setup.js"}) == ["see evil.js for the payload"]


def test_unresolved_refs_allows_paraphrase_and_known_path():
    out = _out(evidence=["the install step is suspicious", "scripts/setup.js exfiltrates env"])
    assert cv.unresolved_refs(out, {"scripts/setup.js"}) == []


def _identity_bundle_with_registry(**registry_fields):
    reg = types.SimpleNamespace(resolved=True, homepage=None, summary=None, **registry_fields)
    for f in ("author", "repo_url", "homepage", "summary", "first_release_at", "latest_release_at"):
        if not hasattr(reg, f):
            setattr(reg, f, None)
    identity = types.SimpleNamespace(docs=[], nearest_popular=registry_fields.get("nearest"), registry=reg)
    return types.SimpleNamespace(behavior=None, provenance=None, identity=identity)


def test_evidence_paths_includes_registry_facts():
    bundle = _identity_bundle_with_registry(
        author='"Redis Inc." <applied.ai@redis.com>',
        repo_url="https://github.com/redis/redis-vl-python",
        first_release_at="2023-08-07T02:55:03.922746Z",
    )
    tokens = cv.evidence_paths(bundle)
    assert "https://github.com/redis/redis-vl-python" in tokens
    assert "2023-08-07T02:55:03.922746Z" in tokens


def test_registry_fact_citations_are_accepted():
    # Regression: the IdentityAgent is asked to cite registry facts (publisher, repo,
    # dates). Those are facts, not files — they must resolve, not be rejected as
    # "file not in package" (which previously degraded every typosquat verification).
    bundle = _identity_bundle_with_registry(
        author='"Redis Inc." <applied.ai@redis.com>',
        repo_url="https://github.com/redis/redis-vl-python",
        first_release_at="2023-08-07T02:55:03.922746Z",
        latest_release_at="2026-07-31T20:16:25.724329Z",
    )
    known = cv.evidence_paths(bundle)
    out = _out(
        verdict="clean",
        confidence=0.9,
        evidence=[
            'source repo: https://github.com/redis/redis-vl-python',
            'first release: 2023-08-07T02:55:03.922746Z',
            'latest release: 2026-07-31T20:16:25.724329Z',
        ],
    )
    assert cv.unresolved_refs(out, known) == []


def test_registry_facts_ignored_when_unresolved():
    reg = types.SimpleNamespace(resolved=False)
    identity = types.SimpleNamespace(docs=[], nearest_popular=None, registry=reg)
    bundle = types.SimpleNamespace(behavior=None, provenance=None, identity=identity)
    # No registry facts admitted → a file citation still fails as before.
    out = _out(evidence=["see phantom.py"])
    assert cv.unresolved_refs(out, cv.evidence_paths(bundle)) == ["see phantom.py"]


def test_check_escalate_only():
    assert cv.check_escalate_only(Severity.HIGH, Severity.LOW) is True
    assert cv.check_escalate_only(Severity.CLEAN, Severity.CLEAN) is True


# ---- repair loop ----


def _evidence_bundle(paths):
    items = [types.SimpleNamespace(path=p) for p in paths]
    beh = types.SimpleNamespace(scripts=items)
    return types.SimpleNamespace(behavior=beh, provenance=None, identity=None)


def test_obtain_succeeds_first_try():
    v = cv.ConstraintValidator()
    llm = lambda s, u: _out(evidence=["scripts/setup.js is bad"])
    res = v.obtain(llm, "sys", "usr", evidence=_evidence_bundle(["scripts/setup.js"]),
                   dimension=TrustDimension.BEHAVIOR, dep_key="npm:x@1", baseline=Severity.CLEAN)
    assert res.ok and res.calls == 1
    assert res.output.verdict == "suspicious"


def test_obtain_repairs_then_succeeds():
    calls = {"n": 0}

    def llm(s, u):
        calls["n"] += 1
        if calls["n"] == 1:
            return _out(verdict="banana")  # schema violation → repair
        return _out(evidence=[])

    v = cv.ConstraintValidator(max_repairs=2)
    res = v.obtain(llm, "sys", "usr", evidence=_evidence_bundle([]),
                   dimension=TrustDimension.BEHAVIOR, dep_key="npm:x@1", baseline=Severity.CLEAN)
    assert res.ok and res.calls == 2


def test_obtain_exhausts_and_degrades_without_raising():
    v = cv.ConstraintValidator(max_repairs=1)
    llm = lambda s, u: _out(verdict="never-valid")
    res = v.obtain(llm, "sys", "usr", evidence=_evidence_bundle([]),
                   dimension=TrustDimension.BEHAVIOR, dep_key="npm:x@1", baseline=Severity.CLEAN)
    assert res.ok is False
    assert res.calls == 2  # initial + 1 repair
    assert "exhausted" in res.reason


def test_obtain_reraises_infrastructure_fault():
    def llm(s, u):
        raise TimeoutError("upstream timed out")

    v = cv.ConstraintValidator()
    with pytest.raises(TimeoutError):
        v.obtain(llm, "sys", "usr", evidence=_evidence_bundle([]),
                 dimension=TrustDimension.BEHAVIOR, dep_key="npm:x@1", baseline=Severity.CLEAN)


def test_repair_prompt_carries_violation():
    p = cv._repair_prompt("original ask", "illegal verdict")
    assert "original ask" in p and "illegal verdict" in p
