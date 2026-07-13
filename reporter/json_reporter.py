"""reporter/json_reporter.py — machine-readable JSON projection of an `AuditReport`.

This is the lossless format: the full canonical report serialised verbatim, so downstream
tooling (dashboards, the long-term store's ingest, other CI steps) can consume the exact
signal set without re-parsing prose. Deterministic key order + trailing newline keep diffs
and golden tests stable.
"""

from __future__ import annotations

from reporter.models import AuditReport


def render_json(report: AuditReport, *, indent: int = 2) -> str:
    """Serialise the report to JSON. Pydantic drives field order, so output is stable."""
    return report.model_dump_json(indent=indent, exclude_none=False) + "\n"
