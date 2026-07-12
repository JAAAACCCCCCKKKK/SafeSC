"""memory/long_term.py — the PGVector long-term store (CLAUDE.md §3.2, §3.4).

The canonical long-term store: embeddings of finalized verdicts per `package@version+hash`,
their evidence/reasoning text, and known-attack fingerprints. It is used purely as
**retrieval context** — the MemoryManager (§2.7.4) is the only caller, and what it reads is
handed to a specialist as prompt-only prior findings that can never lower a verdict (§3.3).

Interface consumed by the MemoryManager:
  * ``query_similar(embedding, k) -> list[dict]`` — behaviourally-similar prior records,
  * ``upsert(artifact_id, embedding, record) -> None`` — write at the tail of report_agent,
  * ``get(artifact_id) -> dict | None`` — exact-key fetch for the max-wins collision check,
  * ``gc(...) -> dict`` — §3.4 differentiated retention, invoked only by `depaudit gc`.

Vectors are written as pgvector literals with an explicit ``::vector`` cast, so the store
works over a plain DB-API connection without registering an adapter. The connection is
injected (``connect`` factory) so tests run against a fake; `from_dsn` builds the real
psycopg one lazily, keeping psycopg/pgvector optional deployment deps.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

logger = logging.getLogger("depaudit.memory.long_term")

# Column width is fixed by the embedding model (§3.2); pin per deployment. voyage-3-large
# emits 1024-d vectors — change the model ⇒ re-index, not a hot swap.
DEFAULT_EMBEDDING_DIM = 1024

# Records at or above this severity are the threat-intelligence asset kept indefinitely;
# below it are benign confirmations subject to GC (§3.4). Mirrors MemoryConfig.escalate_floor.
DEFAULT_ESCALATE_FLOOR = 2  # Severity.MEDIUM


@dataclass
class PGVectorConfig:
    dsn: str = "postgresql://localhost:5432/depaudit"
    table: str = "depaudit_memory"
    embedding_dim: int = DEFAULT_EMBEDDING_DIM
    escalate_floor: int = DEFAULT_ESCALATE_FLOOR
    benign_retention_days: int = 90  # low-severity clean records expire on this cycle


def _vector_literal(embedding: list[float]) -> str:
    """Render a float vector as a pgvector literal: '[0.1,0.2,...]'."""
    return "[" + ",".join(format(float(x), ".8g") for x in embedding) + "]"


class PGVectorStore:
    """Injectable PGVector seam. `connect` returns a DB-API connection usable as a context
    manager (commit/close on exit) exposing `cursor()` (also a context manager)."""

    def __init__(self, connect: Callable[[], Any], config: Optional[PGVectorConfig] = None):
        self._connect = connect
        self.config = config or PGVectorConfig()

    # ------------------------------------------------------------------ construction

    @classmethod
    def from_dsn(cls, config: Optional[PGVectorConfig] = None) -> "PGVectorStore":
        """Build a store over real psycopg connections. Lazy import keeps psycopg an
        optional deployment dependency."""
        config = config or PGVectorConfig()
        try:
            import psycopg  # lazy: optional dependency
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "psycopg is not installed; install the 'memory' extra to use PGVectorStore"
            ) from exc

        def _connect() -> Any:
            return psycopg.connect(config.dsn)

        return cls(_connect, config)

    # ------------------------------------------------------------------ schema

    def ensure_schema(self) -> None:
        """Create the extension, table, and ANN index if absent. Idempotent; run once at
        deploy / before first use. The vector column width is pinned to the config dim."""
        t = self.config.table
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {t} (
                        artifact_id TEXT PRIMARY KEY,
                        embedding   vector({self.config.embedding_dim}) NOT NULL,
                        severity    INTEGER NOT NULL,
                        kind        TEXT NOT NULL DEFAULT 'benign',
                        summary     TEXT NOT NULL DEFAULT '',
                        reasoning   TEXT NOT NULL DEFAULT '',
                        evidence    JSONB NOT NULL DEFAULT '[]'::jsonb,
                        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                    """
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS {t}_embedding_idx "
                    f"ON {t} USING ivfflat (embedding vector_cosine_ops)"
                )

    # ------------------------------------------------------------------ read

    def get(self, artifact_id: str) -> Optional[dict]:
        t = self.config.table
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT artifact_id, severity, kind, summary, reasoning, evidence "
                    f"FROM {t} WHERE artifact_id = %s",
                    (artifact_id,),
                )
                row = cur.fetchone()
        return self._row_to_record(row) if row else None

    def query_similar(self, embedding: list[float], k: int) -> list[dict]:
        """Return the k nearest prior records by cosine distance (smaller == closer).
        Each dict carries a `score` (the distance) alongside the retrieval fields."""
        t = self.config.table
        vec = _vector_literal(embedding)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT artifact_id, severity, kind, summary, reasoning, evidence, "
                    f"       embedding <=> %s::vector AS score "
                    f"FROM {t} ORDER BY embedding <=> %s::vector LIMIT %s",
                    (vec, vec, k),
                )
                rows = cur.fetchall()
        return [self._row_to_record(r, with_score=True) for r in rows]

    # ------------------------------------------------------------------ write

    def upsert(self, artifact_id: str, embedding: list[float], record: dict) -> None:
        """Insert or update. Defense-in-depth max-wins in SQL (`GREATEST`) even though the
        MemoryManager already resolved it — protects against a cross-process race where two
        runs persist the same immutable hash concurrently (§2.7.4)."""
        t = self.config.table
        vec = _vector_literal(embedding)
        severity = int(record.get("severity", 0))
        params = (
            artifact_id,
            vec,
            severity,
            self._kind_for(severity),
            (record.get("summary") or "")[:280],
            (record.get("reasoning") or "")[:1000],
            json.dumps(record.get("evidence", [])),
        )
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO {t}
                        (artifact_id, embedding, severity, kind, summary, reasoning, evidence)
                    VALUES (%s, %s::vector, %s, %s, %s, %s, %s::jsonb)
                    ON CONFLICT (artifact_id) DO UPDATE SET
                        embedding  = EXCLUDED.embedding,
                        severity   = GREATEST({t}.severity, EXCLUDED.severity),
                        kind       = CASE
                                        WHEN EXCLUDED.severity >= {t}.severity
                                        THEN EXCLUDED.kind ELSE {t}.kind END,
                        summary    = EXCLUDED.summary,
                        reasoning  = EXCLUDED.reasoning,
                        evidence   = EXCLUDED.evidence,
                        updated_at = now()
                    """,
                    params,
                )

    # ------------------------------------------------------------------ GC (§3.4)

    def gc(self, *, retention_days: Optional[int] = None) -> dict:
        """Differentiated retention: escalated records and known-attack fingerprints are
        kept indefinitely; low-severity benign confirmations older than the cycle expire.
        Invoked only by the external `depaudit gc` CronJob, never by a graph node."""
        t = self.config.table
        days = self.config.benign_retention_days if retention_days is None else retention_days
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"DELETE FROM {t} "
                    f"WHERE severity < %s AND kind <> 'fingerprint' "
                    f"AND updated_at < now() - make_interval(days => %s)",
                    (self.config.escalate_floor, days),
                )
                deleted = getattr(cur, "rowcount", -1)
        logger.info("pgvector gc deleted %s benign record(s) older than %sd", deleted, days)
        return {"deleted": deleted, "retention_days": days}

    # ------------------------------------------------------------------ helpers

    def _kind_for(self, severity: int) -> str:
        return "escalated" if severity >= self.config.escalate_floor else "benign"

    @staticmethod
    def _row_to_record(row, *, with_score: bool = False) -> dict:
        rec = {
            "artifact_id": row[0],
            "severity": row[1],
            "kind": row[2],
            "summary": row[3],
            "reasoning": row[4],
            "evidence": _as_list(row[5]),
        }
        if with_score:
            rec["score"] = row[6]
        return rec


def _as_list(value: Any) -> list:
    """Normalise a JSONB column (driver may hand back a str or an already-parsed list)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else [parsed]
    except (ValueError, TypeError):
        return []
