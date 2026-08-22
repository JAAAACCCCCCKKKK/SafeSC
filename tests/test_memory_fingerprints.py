"""Unit tests for the known-attack fingerprint corpus (CLAUDE.md §3.2, §3.4).

Covers the whole path: the shipped YAML corpus parses, ingest is the only writer of
`kind='fingerprint'`, the store never demotes or garbage-collects one, and a retrieved
fingerprint reaches a specialist's prompt labelled as a *pattern* rather than as a prior
verdict on some other package. All offline — fake vector store, fake embedder.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from safesc.graph.harness.memory_manager import MemoryContext, MemoryManager
from safesc.memory.fingerprints import (
    KEY_PREFIX,
    RECORD_KIND,
    FingerprintRecord,
    fingerprint_id,
    ingest,
    is_fingerprint,
    load_corpus,
)
from safesc.memory.long_term import PGVectorConfig, PGVectorStore

CORPUS = Path(__file__).resolve().parents[1] / "fingerprints"


class FakeVector:
    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.vectors: dict[str, list] = {}

    def upsert(self, key, embedding, record):
        self.rows[key] = record
        self.vectors[key] = embedding

    def get(self, key):
        return self.rows.get(key)

    def query_similar(self, embedding, k):
        return list(self.rows.values())[:k]


def _embedder(texts):
    return [[float(len(t))] for t in texts]


# ============================================================ corpus


def test_shipped_corpus_parses_and_covers_the_documented_patterns():
    records = load_corpus(CORPUS)
    ids = {r.id for r in records}
    # The §9 walkthrough names these three explicitly; the corpus must actually carry them.
    assert "xz-utils-build-payload" in ids
    assert "event-stream-handover-postinstall" in ids
    assert "dependency-confusion-internal-name" in ids
    assert all(r.text.strip() and r.summary.strip() for r in records)


def test_corpus_entries_are_inert_prose_not_code():
    """A fingerprint describes behaviour; shipping runnable content in the corpus would
    make the detection asset itself a payload."""
    for rec in load_corpus(CORPUS):
        blob = rec.text + rec.summary
        assert "eval(" not in blob and "exec(" not in blob
        assert not blob.lstrip().startswith("#!")


def test_load_corpus_rejects_duplicate_ids(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "fingerprints:\n  - id: dup\n    summary: s\n    text: t\n", encoding="utf-8"
    )
    (tmp_path / "b.yaml").write_text(
        "fingerprints:\n  - id: dup\n    summary: s2\n    text: t2\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="duplicate fingerprint id"):
        load_corpus(tmp_path)


def test_load_corpus_accepts_a_bare_list_and_a_single_file(tmp_path):
    f = tmp_path / "one.yaml"
    f.write_text("- id: solo\n  summary: s\n  text: t\n", encoding="utf-8")
    assert [r.id for r in load_corpus(f)] == ["solo"]


def test_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        load_corpus(Path("does") / "not" / "exist")


def test_default_corpus_path_resolves_and_loads():
    """`safesc fingerprint load` with no argument must work for a pip-installed copy,
    not only from a repo checkout."""
    from safesc.memory.fingerprints import default_corpus_path

    assert default_corpus_path().is_dir()
    assert load_corpus() == load_corpus(CORPUS)


# ============================================================ ingest


def test_ingest_writes_namespaced_keys_and_the_fingerprint_kind():
    vector = FakeVector()
    records = load_corpus(CORPUS)
    report = ingest(records, vector=vector, embedder=_embedder)

    assert len(report["written"]) == len(records) and not report["failed"]
    assert all(k.startswith(KEY_PREFIX) for k in vector.rows)
    assert {r["kind"] for r in vector.rows.values()} == {RECORD_KIND}


def test_fingerprint_keys_cannot_collide_with_an_artifact_identity():
    """`artifact_id` is always `ecosystem:name@version[+hash]`, so the namespace is
    disjoint — a package can never overwrite a curated pattern."""
    key = FingerprintRecord(id="xz", summary="s", text="t").key
    assert key == "fingerprint:xz"
    assert "@" not in key.split(":", 1)[1]


def test_ingest_survives_an_embedding_failure_and_reports_it():
    def _broken(texts):
        raise ConnectionError("embedding provider down")

    vector = FakeVector()
    report = ingest(load_corpus(CORPUS), vector=vector, embedder=_broken)
    assert report["written"] == []
    assert len(report["failed"]) == report["total"]
    assert vector.rows == {}


def test_ingest_batches_so_one_bad_batch_does_not_lose_the_rest():
    calls = {"n": 0}

    def _flaky(texts):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        return _embedder(texts)

    records = [FingerprintRecord(id=f"f{i}", summary="s", text="t") for i in range(4)]
    vector = FakeVector()
    report = ingest(records, vector=vector, embedder=_flaky, batch_size=2)
    assert len(report["failed"]) == 2 and len(report["written"]) == 2


# ============================================================ store semantics


class RecordingCursor:
    def __init__(self, sink):
        self.sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.sink.append((" ".join(sql.split()), params))

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    rowcount = 0


class RecordingConn:
    def __init__(self, sink):
        self.sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return RecordingCursor(self.sink)


def _store(sink):
    return PGVectorStore(lambda: RecordingConn(sink), PGVectorConfig())


def test_upsert_honours_an_explicit_fingerprint_kind():
    sink: list = []
    _store(sink).upsert("fingerprint:xz", [0.1], {"severity": 4, "kind": RECORD_KIND, "summary": "s"})
    _sql, params = sink[0]
    assert RECORD_KIND in params


def test_upsert_still_derives_kind_from_severity_when_none_is_given():
    sink: list = []
    _store(sink).upsert("npm:x@1", [0.1], {"severity": 0, "summary": "s"})
    assert "benign" in sink[0][1]
    sink.clear()
    _store(sink).upsert("npm:x@1", [0.1], {"severity": 4, "summary": "s"})
    assert "escalated" in sink[0][1]


def test_conflict_clause_never_demotes_a_stored_fingerprint():
    sink: list = []
    _store(sink).upsert("fingerprint:xz", [0.1], {"severity": 4, "kind": RECORD_KIND})
    sql = sink[0][0]
    # the CASE pins the kind to 'fingerprint' whenever either side already is one
    assert "WHEN safesc_memory.kind = 'fingerprint'" in sql
    assert "OR EXCLUDED.kind = 'fingerprint'" in sql
    assert "THEN 'fingerprint'" in sql


def test_gc_retains_fingerprints_indefinitely():
    sink: list = []
    _store(sink).gc(retention_days=1)
    sql, params = sink[0]
    assert "kind <> 'fingerprint'" in sql
    assert "DELETE" in sql


# ============================================================ retrieval labelling


def _record(kind, aid, summary):
    return {"artifact_id": aid, "severity": 4, "kind": kind, "summary": summary}


def test_prior_findings_label_a_fingerprint_distinctly_from_a_prior_verdict():
    ctx = MemoryContext(
        artifact_id="npm:evil@1.0.0+sha256:x",
        similar=(
            _record(RECORD_KIND, "fingerprint:xz-utils-build-payload", "build-time payload"),
            _record("escalated", "npm:other@2.0.0", "unrelated prior verdict"),
        ),
    )
    findings = ctx.as_prior_findings()
    assert findings[0].startswith("[known-attack pattern xz-utils-build-payload]")
    assert findings[1].startswith("[similar npm:other@2.0.0]")


def test_is_fingerprint_and_id_helpers():
    rec = _record(RECORD_KIND, "fingerprint:abc", "s")
    assert is_fingerprint(rec) and fingerprint_id(rec) == "abc"
    assert not is_fingerprint(_record("benign", "npm:x@1", "s"))
    assert not is_fingerprint(None)
    # a record whose key is not namespaced degrades to the raw id rather than slicing wrong
    assert fingerprint_id({"artifact_id": "npm:x@1"}) == "npm:x@1"


def test_a_retrieved_fingerprint_is_context_only_and_never_becomes_a_signal():
    """§3.3: memory informs the prompt; it is never merged into `AuditState.signals`."""
    vector = FakeVector()
    ingest(
        [FingerprintRecord(id="xz", summary="build-time payload", text="obfuscated build")],
        vector=vector, embedder=_embedder,
    )
    mgr = MemoryManager(redis=None, vector=vector, embedder=_embedder)
    ctx = mgr.read_context("npm:evil@1.0.0+sha256:x", "obfuscated build script")
    assert ctx.exact is None
    assert any("known-attack pattern xz" in f for f in ctx.as_prior_findings())
    assert not hasattr(ctx, "signals")
