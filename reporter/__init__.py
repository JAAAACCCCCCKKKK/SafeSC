"""reporter/ — the final sink: turn a finished run into JSON / Markdown / SARIF.

The reporter is intentionally *outside* the graph (§6): it makes no decisions and holds no
secrets — it only projects the scorer's already-written `GateDecision` plus the run's
signals into artifacts. One canonical `AuditReport` (built by `build_report`) feeds three
pure renderers, so the formats can never disagree.

Typical use from an entrypoint (§6.1.4):

    from reporter import build_report, render, write_reports
    report = build_report(final_state, run_id=run_id)
    print(render(report, "markdown"))
    write_reports(report, out_dir, formats=["json", "sarif"])
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable

from reporter.build import build_report
from reporter.json_reporter import render_json
from reporter.markdown_reporter import render_markdown
from reporter.models import (
    AuditReport,
    DegradedView,
    DependencyFinding,
    SignalView,
)
from reporter.sarif_reporter import build_sarif, render_sarif

# format name -> (renderer, file extension)
_RENDERERS: dict[str, tuple[Callable[[AuditReport], str], str]] = {
    "json": (render_json, "json"),
    "markdown": (render_markdown, "md"),
    "md": (render_markdown, "md"),
    "sarif": (render_sarif, "sarif"),
}

FORMATS = ("json", "markdown", "sarif")


def render(report: AuditReport, fmt: str) -> str:
    """Render `report` into one format string. Raises ValueError on unknown format."""
    key = fmt.lower()
    if key not in _RENDERERS:
        raise ValueError(f"unknown report format {fmt!r}; choose from {sorted(_RENDERERS)}")
    return _RENDERERS[key][0](report)


def write_reports(
    report: AuditReport,
    out_dir: str | Path,
    *,
    formats: Iterable[str] = FORMATS,
    stem: str = "depaudit-report",
) -> list[Path]:
    """Render and write one file per requested format into `out_dir`. Returns the paths.

    The directory is created if missing; filenames are `{stem}.{ext}` so repeated runs
    overwrite in place (CI artifact convention)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for fmt in formats:
        key = fmt.lower()
        if key not in _RENDERERS:
            raise ValueError(f"unknown report format {fmt!r}; choose from {sorted(_RENDERERS)}")
        renderer, ext = _RENDERERS[key]
        path = out / f"{stem}.{ext}"
        path.write_text(renderer(report), encoding="utf-8")
        written.append(path)
    return written


__all__ = [
    "AuditReport",
    "DependencyFinding",
    "SignalView",
    "DegradedView",
    "build_report",
    "build_sarif",
    "render",
    "render_json",
    "render_markdown",
    "render_sarif",
    "write_reports",
    "FORMATS",
]
