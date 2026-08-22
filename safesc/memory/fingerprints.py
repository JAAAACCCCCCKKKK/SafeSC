"""memory/fingerprints.py — the known-attack fingerprint corpus (CLAUDE.md §3.2, §3.4).

A fingerprint is a *curated* description of a real supply-chain attack pattern, embedded
into the same PGVector table as finalized verdicts so that `query_similar` can surface it
when a dependency under analysis behaves like a known attack. It is retrieval context and
nothing more: like every other memory record it reaches a specialist only as prompt-only
prior findings (§3.3) and can only ever escalate (§4.3).

Two properties make this safe, and both are structural rather than conventional:

  * **No audit run can write one.** Fingerprints enter the store exclusively through
    `safesc fingerprint load`, an external finite job with the same shape as `safesc gc`
    (§3.4). `report_agent`'s write path (§2.7.4) only ever emits `escalated`/`benign`.
  * **They are version-controlled.** The corpus lives in `fingerprints/*.yaml` and changes
    through code review, so "what SafeSC believes an attack looks like" is auditable.

Records are keyed `fingerprint:{id}`, a namespace no artifact identity can collide with
(`artifact_id` is always `ecosystem:name@version[+hash]`), and carry `kind='fingerprint'`,
which `PGVectorStore.gc` retains indefinitely — the corpus is a threat-intelligence asset
whose value grows with time, not an audit log.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, Optional, Sequence

from pydantic import BaseModel, Field

logger = logging.getLogger("safesc.memory.fingerprints")

# Namespace prefix for the store key. Kept distinct from every `artifact_id` form so a
# fingerprint and a real verdict can never overwrite one another.
KEY_PREFIX = "fingerprint:"

RECORD_KIND = "fingerprint"


class FingerprintRecord(BaseModel):
    """One curated attack pattern.

    `text` is the field that gets embedded — write it as a behavioural description of what
    the attack *does*, not as prose about the incident, because it is matched against a
    dependency's static-signal summary (see `MemoryManager.make_task_lookup`). `severity`
    is the graph `Severity` int; it exists so a retrieved fingerprint carries the weight of
    the pattern it describes, and it is never applied to a verdict directly.
    """

    id: str
    summary: str
    text: str
    severity: int = 4  # Severity.CRITICAL — these describe confirmed attacks
    references: list[str] = Field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{KEY_PREFIX}{self.id}"

    def as_store_record(self) -> dict:
        """Shape expected by `PGVectorStore.upsert` / `MemoryManager` readers."""
        return {
            "artifact_id": self.key,
            "severity": int(self.severity),
            "kind": RECORD_KIND,
            "summary": self.summary[:280],
            "reasoning": self.text[:1000],
            "evidence": list(self.references),
        }


def default_corpus_path() -> Path:
    """Where the shipped corpus lives.

    Two locations, because the file has to serve two readers: it is version-controlled at
    the repo root (so changes to "what SafeSC believes an attack looks like" go through
    code review) and force-included into the wheel at `safesc/memory/corpus/` (so an
    installed copy can run `safesc fingerprint load` with no checkout). The installed copy
    wins when both exist.
    """
    installed = Path(__file__).resolve().parent / "corpus"
    if installed.is_dir():
        return installed
    return Path(__file__).resolve().parents[2] / "fingerprints"


def load_corpus(path: str | Path | None = None) -> list[FingerprintRecord]:
    """Read one YAML file, or every `*.yaml`/`*.yml` in a directory.

    The file is a list of mappings, or a mapping with a top-level `fingerprints:` key.
    Duplicate ids across files are an error rather than a last-write-wins merge — a silent
    overwrite would let one file quietly redefine another's pattern.

    With no path, the shipped corpus is used (`default_corpus_path`).
    """
    import yaml  # core dependency (pyyaml), already required for pnpm-lock parsing

    target = Path(path) if path is not None else default_corpus_path()
    files: list[Path]
    if target.is_dir():
        files = sorted(p for p in target.iterdir() if p.suffix in (".yaml", ".yml"))
    else:
        files = [target]
    if not files:
        raise FileNotFoundError(f"no fingerprint YAML found at {target}")

    records: list[FingerprintRecord] = []
    seen: dict[str, Path] = {}
    for f in files:
        raw = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        entries = raw.get("fingerprints", []) if isinstance(raw, dict) else raw
        for entry in entries:
            rec = FingerprintRecord.model_validate(entry)
            if rec.id in seen:
                raise ValueError(
                    f"duplicate fingerprint id '{rec.id}' in {f} (already defined in {seen[rec.id]})"
                )
            seen[rec.id] = f
            records.append(rec)
    return records


def ingest(
    records: Sequence[FingerprintRecord],
    *,
    vector,
    embedder,
    batch_size: int = 32,
) -> dict:
    """Embed and upsert the corpus into the long-term store.

    Best-effort per batch: an embedding-provider failure on one batch is logged and skipped
    so a partial corpus still lands, matching the graceful-degradation rule (§8). Returns a
    report the CLI prints. This is the ONLY writer of `kind='fingerprint'` records.
    """
    written: list[str] = []
    failed: list[str] = []
    for batch in _batched(records, batch_size):
        texts = [r.text for r in batch]
        try:
            vectors = embedder(texts)
        except Exception as exc:
            logger.warning("embedding failed for %d fingerprint(s): %s", len(batch), exc)
            failed.extend(r.id for r in batch)
            continue
        for rec, vec in zip(batch, vectors):
            try:
                vector.upsert(rec.key, vec, rec.as_store_record())
                written.append(rec.id)
            except Exception as exc:
                logger.warning("upsert failed for fingerprint %s: %s", rec.id, exc)
                failed.append(rec.id)
    return {"written": written, "failed": failed, "total": len(records)}


def is_fingerprint(record: Optional[dict]) -> bool:
    """True when a retrieved store record is a curated attack pattern rather than a prior
    verdict. Used to label it distinctly in a specialist's prompt."""
    return bool(record) and record.get("kind") == RECORD_KIND


def fingerprint_id(record: dict) -> str:
    """The corpus id from a retrieved record's namespaced key."""
    aid = str(record.get("artifact_id", ""))
    return aid[len(KEY_PREFIX):] if aid.startswith(KEY_PREFIX) else aid


def _batched(items: Sequence[FingerprintRecord], n: int) -> Iterable[Sequence[FingerprintRecord]]:
    for i in range(0, len(items), n):
        yield items[i : i + n]
