"""memory/checkpoint.py — the LangGraph checkpointers behind ``--resume`` (CLAUDE.md §3.1).

Two backends, preferred in this order by ``entrypoints.bootstrap._select_checkpointer``:

1. **Postgres** (`PostgresSaver` from ``langgraph-checkpoint-postgres``) whenever
   ``SAFESC_PGVECTOR_DSN`` is set. Durable and TTL-free, and the pgvector tier already has
   the database. Its tables are created by ``safesc store init``; the audit path only
   *verifies* the schema is current (`postgres_checkpointer`) and never runs DDL, matching
   §3.6's rule that an audit needs no DDL privileges.
2. **Plain Redis** (`PlainRedisSaver`, in ``memory/redis_checkpoint.py``) as the fallback.
   ``langgraph-checkpoint-redis`` indexes checkpoints with RediSearch (``FT.*``), which Upstash and most managed Redis do
   not ship, so ``--resume`` never worked there. This saver uses only hash, sorted-set, set
   and list commands, which every Redis-compatible service supports.

This module imports no LangGraph at load time, so the Postgres helpers stay importable
without the ``agent`` extra; `PlainRedisSaver` (which does need it) is re-exported lazily.

Checkpoints hold `AuditState`, which by §3.5 never carries a credential, so neither backend
can persist a BYOK key. No audit logic and no decisions live here.
"""

from __future__ import annotations

from typing import Any

DEFAULT_CHECKPOINT_TTL_S = 7 * 24 * 3600


# ============================================================ Postgres


def _postgres_saver_class():
    try:
        from langgraph.checkpoint.postgres import PostgresSaver  # lazy, optional
    except ImportError as exc:
        raise RuntimeError(
            "langgraph-checkpoint-postgres is not installed; install the 'memory' extra"
        ) from exc
    return PostgresSaver


def _connect_postgres(dsn: str) -> Any:
    """The connection shape `PostgresSaver` requires (mirrors its own `from_conn_string`).
    Opened directly rather than through that context manager, which would close the
    connection as soon as its generator was garbage-collected."""
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.Connection.connect(
        dsn, autocommit=True, prepare_threshold=0, row_factory=dict_row
    )


def setup_postgres_checkpointer(dsn: str) -> None:
    """Create or migrate the checkpoint tables. Called by ``safesc store init`` only."""
    saver_cls = _postgres_saver_class()
    conn = _connect_postgres(dsn)
    try:
        saver_cls(conn).setup()
    finally:
        conn.close()


def postgres_checkpointer(dsn: str) -> Any:
    """A `PostgresSaver` for an audit run, after checking the schema is fully migrated.

    Raises when the tables are missing or behind, so the caller falls back to Redis instead
    of failing on the first checkpoint write mid-run. The connection is left open for the
    whole (finite, §1.3) process.
    """
    saver_cls = _postgres_saver_class()
    conn = _connect_postgres(dsn)
    try:
        with conn.cursor() as cur:
            row = cur.execute(
                "SELECT v FROM checkpoint_migrations ORDER BY v DESC LIMIT 1"
            ).fetchone()
    except Exception as exc:
        conn.close()
        raise RuntimeError(f"checkpoint tables missing ({exc}); run `safesc store init`") from exc
    latest = len(saver_cls.MIGRATIONS) - 1
    current = -1 if row is None else row["v"]
    if current < latest:
        conn.close()
        raise RuntimeError(
            f"checkpoint schema is at migration {current} of {latest}; run `safesc store init`"
        )
    return saver_cls(conn)


def __getattr__(name: str) -> Any:
    # PEP 562 lazy re-export: `PlainRedisSaver` subclasses LangGraph's base saver, so importing
    # it eagerly would make the Postgres helpers above unimportable without the `agent` extra.
    if name == "PlainRedisSaver":
        from safesc.memory.redis_checkpoint import PlainRedisSaver

        return PlainRedisSaver
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
