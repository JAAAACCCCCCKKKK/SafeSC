"""memory/ — required local memory: max-wins verdict store, read-only known-attack corpus,
the Strands MemoryManager wiring (recall + injection, never an add tool), the single
post-decision write and its narrow scope."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from safesc.core.ledger import Stage
from safesc.core.scoring import score
from safesc.core.signals import Severity, TrustDimension, dep_key
from safesc.memory import MemoryInitError, SafeSCMemory, artifact_id, default_memory_dir
from safesc.memory.fingerprints import KnownAttackStore, load_corpus
from safesc.memory.store import VerdictStore, parse_record, render_record
from tests.helpers import dep, ledger, sig


def _run(coro):
    return asyncio.run(coro)


def test_record_roundtrip():
    rec = {"artifact_id": "npm:x@1+sha512-abc", "severity": 3, "summary": "s", "evidence": ["a"], "reasoning": "r"}
    assert parse_record(render_record(rec)) == rec


def test_verdict_store_is_max_wins_and_flags_decreases(tmp_path):
    store = VerdictStore(tmp_path)
    aid = "npm:evil@1.0.0+sha512-deadbeef"
    assert _run(store.put({"artifact_id": aid, "severity": 4, "summary": "exfiltrates env"})) is None
    anomaly = _run(store.put({"artifact_id": aid, "severity": 0, "summary": "looks fine"}))
    assert anomaly and "kept CRITICAL" in anomaly
    stored = _run(store.get(aid))
    assert stored["severity"] == 4 and stored["summary"] == "exfiltrates env"


def test_verdict_store_search_hides_the_machine_record(tmp_path):
    store = VerdictStore(tmp_path)
    _run(store.put({"artifact_id": "npm:evil@1.0.0", "severity": 4, "summary": "postinstall exfiltrates tokens"}))
    hits = _run(store.search("postinstall exfiltrates"))
    assert hits and "SafeSC prior verdict: npm:evil@1.0.0" in hits[0].content
    assert "safesc-record" not in hits[0].content and hits[0].metadata["severity"] == 4
    assert store.writable is False


def test_known_attack_store_matches_behaviour_and_labels_it():
    store = KnownAttackStore(load_corpus())
    hits = _run(store.search("release tarball ships build-system files absent from the git repository and decodes a payload"))
    assert hits and hits[0].metadata["id"] == "xz-utils-build-payload"
    assert hits[0].content.startswith("[known-attack pattern xz-utils-build-payload]")
    assert store.writable is False


def test_corpus_rejects_duplicate_ids(tmp_path):
    (tmp_path / "a.yaml").write_text("- {id: x, summary: s, text: t}\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("fingerprints:\n  - {id: x, summary: s, text: t}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_corpus(tmp_path)


def test_manager_has_recall_but_no_add_tool(tmp_path):
    mem = SafeSCMemory(tmp_path)
    names = {t.tool_name for t in mem.manager().tools}
    assert names == {"recall_prior_findings"}


def test_memory_is_required(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    with pytest.raises(MemoryInitError):
        SafeSCMemory(blocker / "memory")


def test_default_dir_honours_env(tmp_path):
    assert default_memory_dir({"SAFESC_MEMORY_DIR": str(tmp_path)}) == tmp_path
    assert default_memory_dir({"XDG_CACHE_HOME": str(tmp_path)}).parts[-2:] in (("safesc", "memory"),)


def test_persist_writes_escalated_and_popular_clean_only(tmp_path):
    hashed, popular, longtail = dep("evil", hash="sha512-abc"), dep("react"), dep("tiny")
    led = ledger(deps=[hashed, popular, longtail], signals=[
        sig(hashed, TrustDimension.BEHAVIOR, Severity.HIGH, summary="hook exfiltrates", evidence=["setup.js"]),
        sig(popular, TrustDimension.POPULARITY, Severity.CLEAN),
    ])
    for s in (Stage.DISCOVER, Stage.PARSE, Stage.VERIFY, Stage.COLLECT):
        led.mark_stage(s)
    mem = SafeSCMemory(tmp_path)
    assert _run(mem.persist(led)).written == []  # nothing before the decision exists
    led.finalize(score(led))
    report = _run(mem.persist(led))
    assert set(report.written) == {artifact_id(hashed), artifact_id(popular)}
    assert artifact_id(longtail) in report.skipped
    stored = _run(mem.verdicts.get(artifact_id(hashed)))
    assert stored["severity"] == int(Severity.HIGH) and stored["artifact_id"].endswith("+sha512-abc")


def test_persisted_verdict_is_injected_into_a_later_agent(tmp_path):
    """Write after one run; a later run's subagent sees it — labelled, as context only."""
    from strands import Agent

    from tests.helpers import ScriptedModel

    mem = SafeSCMemory(tmp_path)
    _run(mem.verdicts.put({"artifact_id": "javascript:evil@1.0.0", "severity": 4, "summary": "postinstall steals npm tokens"}))
    model = ScriptedModel([("text", "ok")])
    Agent(model=model, memory_manager=mem.manager(injection=True), callback_handler=None)(
        "Dependency under analysis: javascript:evil@1.0.0 postinstall steals tokens"
    )
    seen = str(model.calls[0]["messages"])
    assert "prior verdict" in seen and "postinstall steals npm tokens" in seen and "never lower" in seen


def test_artifact_id_includes_hash():
    assert artifact_id(dep("x", hash="sha256:1")) == "javascript:x@1.0.0+sha256:1"
    assert artifact_id(dep("x")) == dep_key(dep("x"))


def test_memory_dir_is_created(tmp_path):
    target = tmp_path / "deep" / "memory"
    SafeSCMemory(target)
    assert Path(target).is_dir()
