"""memory/fingerprints.py — the curated known-attack corpus, as a read-only memory store (§3.2).

A fingerprint describes the *behavioural shape* of a documented supply-chain attack
(XZ-Utils build payload, event-stream handover, dependency confusion, protestware) as inert
prose. It reaches a subagent exactly like a prior verdict — as prompt-only context through
the Strands `MemoryManager` (injection + recall tool) — and can only ever raise concern.

Two properties keep it safe, both structural:

* **No run can write one.** `KnownAttackStore` is loaded from the version-controlled YAML
  shipped with SafeSC into an in-process index at startup and is not writable; there is no
  code path from an agent or a finished audit into it. "What SafeSC believes an attack
  looks like" changes only through code review.
* **It is labelled as what it is.** Entries render as ``[known-attack pattern <id>]`` so a
  subagent never confuses "this resembles a documented attack" with "this exact artifact
  was judged before".
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("safesc.memory.fingerprints")

STORE_NAME = "known_attacks"


class FingerprintRecord(BaseModel):
    """One curated attack pattern. `text` is what retrieval matches against — written as
    what the attack *does*, in the same register a dependency's signal summary uses."""

    id: str
    summary: str
    text: str
    severity: int = 4  # Severity.CRITICAL — these describe confirmed attacks
    references: list[str] = Field(default_factory=list)

    def render(self) -> str:
        refs = f"\nreferences: {', '.join(self.references)}" if self.references else ""
        return f"[known-attack pattern {self.id}] {self.summary}\n{self.text}{refs}"


def default_corpus_path() -> Path:
    """The shipped corpus: force-included into the wheel at `safesc/memory/corpus/`, and
    version-controlled at the repo root `fingerprints/`. The installed copy wins."""
    installed = Path(__file__).resolve().parent / "corpus"
    if installed.is_dir():
        return installed
    return Path(__file__).resolve().parents[2] / "fingerprints"


def load_corpus(path: str | Path | None = None) -> list[FingerprintRecord]:
    """Read one YAML file, or every `*.yaml`/`*.yml` in a directory.

    The file is a list of mappings, or a mapping with a top-level `fingerprints:` key.
    Duplicate ids are an error rather than last-write-wins — a silent overwrite would let
    one file quietly redefine another's pattern.
    """
    import yaml

    target = Path(path) if path is not None else default_corpus_path()
    files = sorted(p for p in target.iterdir() if p.suffix in (".yaml", ".yml")) if target.is_dir() else [target]
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
                raise ValueError(f"duplicate fingerprint id '{rec.id}' in {f} (already defined in {seen[rec.id]})")
            seen[rec.id] = f
            records.append(rec)
    return records


class KnownAttackStore:
    """Strands `MemoryStore` over the curated corpus. Read-only by construction."""

    name = STORE_NAME
    description = "Curated descriptions of documented supply-chain attacks (read-only reference patterns)."
    writable = False
    extraction = None

    def __init__(self, records: list[FingerprintRecord], max_search_results: int = 2):
        from strands.storage import InMemoryStorage

        self.max_search_results = max_search_results
        self._records = {r.id: r for r in records}
        self._storage = InMemoryStorage()
        self._loaded = False

    async def initialize(self) -> None:
        if self._loaded:
            return
        for rec in self._records.values():
            await self._storage.write(f"{rec.id}.md", rec.render().encode("utf-8"))
        self._loaded = True

    async def search(self, query: str, options: Any = None) -> list:
        from strands.memory import MemoryEntry

        await self.initialize()
        limit = (options or {}).get("max_search_results") or self.max_search_results
        out = []
        for hit in await self._storage.search(query):
            if len(out) >= limit or hit.score <= 0:
                break
            rec = self._records.get(hit.key.removesuffix(".md"))
            if rec is not None:
                out.append(MemoryEntry(
                    content=rec.render(), store_name=self.name,
                    metadata={"kind": "fingerprint", "id": rec.id, "score": hit.score},
                ))
        return out

    def get_tools(self) -> list:
        return []

    def search_sync(self, query: str, limit: int = 3) -> list:
        return asyncio.run(self.search(query, {"max_search_results": limit}))
