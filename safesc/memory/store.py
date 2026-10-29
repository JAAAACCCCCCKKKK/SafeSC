"""memory/store.py — prior verdicts per exact artifact, on Strands local storage (§3.1–§3.3).

One markdown record per artifact identity (``ecosystem:name@version[+hash]``) under
``<memory-dir>/verdicts/``. Records are written by exactly one caller — `SafeSCMemory.persist`,
after the scorer has decided (§2.7.4) — and read by agents only through the Strands
`MemoryManager` (injection into prompts + a recall tool). The store is not writable from
an agent: `writable = False`, and the manager is built without an add tool.

Severity is **max-wins** per artifact. A pinned artifact's content cannot change, so a
verdict on it should only ever rise across runs; a lower write keeps the stored severity
and is reported as an anomaly (a bug, or a hash collision) rather than silently applied.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

STORE_NAME = "verdicts"
_RECORD_RE = re.compile(r"<!--safesc-record (\{.*\})-->\s*$", re.S)
_SEVERITY_NAMES = ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def record_key(artifact_id: str) -> str:
    digest = hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()[:16]
    slug = re.sub(r"[^a-z0-9.\-]+", "-", artifact_id.lower().split("+", 1)[0])[:60].strip("-")
    return f"{slug}-{digest}.md"


def render_record(rec: dict) -> str:
    sev = _SEVERITY_NAMES[int(rec.get("severity", 0))]
    lines = [
        f"# SafeSC prior verdict: {rec['artifact_id']}",
        f"severity: {sev}",
        f"recorded: {rec.get('recorded', '')}",
        f"summary: {rec.get('summary', '')}",
    ]
    if rec.get("dimensions"):
        lines.append("dimensions: " + ", ".join(f"{k}={v}" for k, v in rec["dimensions"].items()))
    if rec.get("evidence"):
        lines.append("evidence: " + "; ".join(rec["evidence"][:12]))
    if rec.get("reasoning"):
        lines.append(f"reasoning: {rec['reasoning']}")
    return "\n".join(lines) + f"\n<!--safesc-record {json.dumps(rec, sort_keys=True)}-->\n"


def parse_record(text: str) -> Optional[dict]:
    m = _RECORD_RE.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except ValueError:
        return None


class VerdictStore:
    """Strands `MemoryStore` of prior verdicts. Reads go through the MemoryManager; the one
    writer is `put`, called only by `SafeSCMemory.persist`."""

    name = STORE_NAME
    description = (
        "SafeSC's prior verdicts for exact dependency artifacts (ecosystem:name@version+hash). "
        "Context only — a prior verdict never lowers the current one."
    )
    writable = False
    extraction = None

    def __init__(self, root: Path, max_search_results: int = 3):
        from strands.storage import LocalFileStorage

        self.root = Path(root)
        self.max_search_results = max_search_results
        self._storage = LocalFileStorage(str(self.root)).namespace(STORE_NAME)

    async def initialize(self) -> None:
        (self.root / STORE_NAME).mkdir(parents=True, exist_ok=True)

    def get_tools(self) -> list:
        return []

    async def search(self, query: str, options: Any = None) -> list:
        from strands.memory import MemoryEntry

        limit = (options or {}).get("max_search_results") or self.max_search_results
        out = []
        for hit in await self._storage.search(query):
            if len(out) >= limit or hit.score <= 0:
                break
            data = hit.data if hit.data is not None else await self._storage.read(hit.key)
            if not data:
                continue
            text = data.decode("utf-8", errors="replace")
            rec = parse_record(text) or {}
            visible = _RECORD_RE.sub("", text).strip()
            out.append(MemoryEntry(
                content=visible, store_name=self.name,
                metadata={"kind": "verdict", "artifact_id": rec.get("artifact_id"), "severity": rec.get("severity")},
            ))
        return out

    async def get(self, artifact_id: str) -> Optional[dict]:
        data = await self._storage.read(record_key(artifact_id))
        return parse_record(data.decode("utf-8", errors="replace")) if data else None

    async def put(self, rec: dict) -> Optional[str]:
        """Write with max-wins. Returns an anomaly description when a lower severity was
        attempted (the stored, higher one is kept), else None."""
        anomaly = None
        existing = await self.get(rec["artifact_id"])
        if existing is not None and int(existing.get("severity", 0)) > int(rec["severity"]):
            anomaly = (
                f"{rec['artifact_id']}: attempted {_SEVERITY_NAMES[int(rec['severity'])]} over stored "
                f"{_SEVERITY_NAMES[int(existing['severity'])]} (kept {_SEVERITY_NAMES[int(existing['severity'])]})"
            )
            rec = {**rec, "severity": int(existing["severity"]),
                   "summary": existing.get("summary", rec.get("summary", "")),
                   "reasoning": existing.get("reasoning", rec.get("reasoning", ""))}
        rec = {**rec, "recorded": rec.get("recorded") or datetime.now(timezone.utc).isoformat(timespec="seconds")}
        await self._storage.write(record_key(rec["artifact_id"]), render_record(rec).encode("utf-8"))
        return anomaly
