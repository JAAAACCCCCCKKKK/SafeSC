"""cli.py — the `safesc` command: one use case, everything else is a flag (CLAUDE.md §1.3).

    safesc                         inspect the current directory (in CI: the checked-out repo)
    safesc path/or/lockfile        inspect another project
    safesc npm:left-pad@1.3.0      inspect a single package
    safesc --with authorship       + code-style authorship analysis of every direct dependency
    safesc --with vuln-hunt        + unreported-vulnerability hunting (and verification)
    safesc --with all              every complementary analysis

Before anything runs, the CLI requires an LLM (LLM_PROVIDER / LLM_MODEL / LLM_API_KEY,
validated in a fixed order — see `config.llm`) and memory (a writable local directory).
Either missing is exit 2. Then the orchestrator agent runs the audit (`agents.orchestrator`)
and the CLI prints the deterministic verdict and writes reports. The CLI contains no audit
logic and never calls a static stage itself — only agents do (§2.1).

Exit codes: 0 pass · 1 gate failed · 2 error (configuration, memory, or no verdict).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import warnings
from pathlib import Path
from typing import Optional, Sequence

from safesc.core.ledger import Feature, RunOptions
from safesc.core.scoring import EXIT_ERROR
from safesc.core.signals import Severity
from safesc.core.targets import TargetKind, classify_target, default_target, is_ci

_FEATURE_ALIASES = {
    "authorship": {Feature.AUTHORSHIP}, "code-style": {Feature.AUTHORSHIP},
    "vuln-hunt": {Feature.VULN_HUNT}, "vulns": {Feature.VULN_HUNT}, "vuln": {Feature.VULN_HUNT},
    "transitive": {Feature.TRANSITIVE},
    "github": {Feature.GITHUB},
    "all": {Feature.AUTHORSHIP, Feature.VULN_HUNT, Feature.TRANSITIVE, Feature.GITHUB},
}


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("safesc")
    except Exception:
        return "unknown"


def parse_features(values: Optional[Sequence[str]]) -> frozenset[Feature]:
    out: set[Feature] = set()
    for raw in values or ():
        for item in raw.split(","):
            name = item.strip().lower()
            if not name:
                continue
            if name not in _FEATURE_ALIASES:
                raise argparse.ArgumentTypeError(
                    f"unknown --with feature {name!r}; choose from {', '.join(sorted(_FEATURE_ALIASES))}"
                )
            out |= _FEATURE_ALIASES[name]
    return frozenset(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="safesc",
        description="Agentic dependency supply-chain trust audit. Requires LLM_PROVIDER, LLM_MODEL and LLM_API_KEY.",
        epilog="Exit codes: 0 pass, 1 gate failed, 2 error (configuration, memory, or no verdict).",
    )
    p.add_argument("target", nargs="?", default=None,
                   help="directory, lockfile, or package spec (npm:name@1.0.0, pkg:pypi/x@1). "
                        "Default: the current directory, or the repository root in CI.")
    p.add_argument("--with", dest="features", action="append", metavar="FEATURE",
                   help="enable complementary analyses (repeatable or comma-separated): "
                        "authorship, vuln-hunt, transitive, github, all")
    p.add_argument("--exclude", action="append", metavar="PATTERN", default=None,
                   help="gitignore-syntax path to skip during discovery (repeatable); layers on .safescignore")
    p.add_argument("--report-dir", default=None, help="write report files here")
    p.add_argument("--format", dest="report_format", default="all",
                   choices=["all", "json", "markdown", "md", "sarif"], help="report format(s) to write (default: all)")
    p.add_argument("--fail-on", default="HIGH", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="fail the gate when any dependency reaches this severity (default: HIGH)")
    p.add_argument("--strict", action="store_true", help="treat an incomplete analysis as a gate failure")
    p.add_argument("--max-subagents", type=int, default=40, metavar="N",
                   help="subagent invocations allowed per run (default: 40)")
    p.add_argument("--memory-dir", type=Path, default=None,
                   help="memory directory (default: $SAFESC_MEMORY_DIR or the user cache dir)")
    p.add_argument("--mcp", action="append", default=[], metavar="URL",
                   help="attach an extra read-only MCP server (streamable HTTP) for subagents; repeatable")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("--version", action="version", version=f"safesc {_version()}")
    return p


def _configure_console(verbose: bool) -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass
    level = logging.DEBUG if verbose else getattr(logging, os.environ.get("SAFESC_LOG_LEVEL", "WARNING").upper(), logging.WARNING)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    # Strands warns once per agent when no context window is configured; LLM_CONTEXT_WINDOW
    # is the documented fix, and the warning is noise on every run without it.
    warnings.filterwarnings("ignore", message="context_window_limit is not set")
    logging.getLogger("safesc").setLevel(level)


def _err(message: str) -> int:
    print(f"safesc: {message}", file=sys.stderr)
    return EXIT_ERROR


def main(argv: Optional[Sequence[str]] = None, *, llm_loader=None, run=None) -> int:
    """Entry point. `llm_loader` and `run` are injectable for tests; production uses
    `config.llm.load_llm_config` and `agents.orchestrator.run_audit`."""
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_console(args.verbose)

    try:
        features = parse_features(args.features)
    except argparse.ArgumentTypeError as exc:
        return _err(str(exc))
    if args.max_subagents < 1:
        return _err("--max-subagents must be at least 1")

    # 1. The LLM is required, and validated before anything else (presence → provider →
    #    model ↔ provider → reachability → key).
    from safesc.config.llm import LLMConfigError, load_llm_config

    try:
        llm = (llm_loader or load_llm_config)()
    except LLMConfigError as exc:
        return _err(str(exc))

    # 2. Memory is required.
    from safesc.memory import MemoryInitError, SafeSCMemory

    try:
        memory = SafeSCMemory.open(args.memory_dir)
    except MemoryInitError as exc:
        return _err(str(exc))

    # 3. Target: explicit, else the current directory (interactive) / the repo root (CI).
    ci = is_ci()
    target = args.target or default_target()
    kind = classify_target(target)
    if kind == TargetKind.REPOSITORY and not Path(target).exists():
        return _err(f"target {target!r} does not exist")

    options = RunOptions(
        target=str(Path(target).resolve()) if kind == TargetKind.REPOSITORY else target,
        target_kind=kind,
        exclude=tuple(args.exclude or ()),
        features=features,
        max_subagents=args.max_subagents,
        fail_on=Severity[args.fail_on],
        ci=ci,
    )

    from safesc.agents.harness.progress import Progress
    from safesc.agents.orchestrator import run_audit

    progress = Progress(enabled=not args.quiet)
    outcome = asyncio.run((run or run_audit)(
        options, llm, memory, strict=args.strict, mcp_urls=tuple(args.mcp), progress=progress,
    ))

    _print_result(outcome, llm.describe())
    if args.report_dir:
        _write_reports(outcome, llm.describe(), args.report_dir, args.report_format)
    return outcome.exit_code


def _print_result(outcome, model: str) -> None:
    d = outcome.decision
    status = "PASS" if d.passed else ("ERROR" if d.exit_code == EXIT_ERROR else "FAIL")
    print(f"[{outcome.run_id}] {status}  trust score {d.score}/100 ({d.grade})  overall={d.overall.name}  exit={d.exit_code}")
    print(d.summary)
    if outcome.finalized and not outcome.ledger.dependencies:
        print(
            "  ⚠ no dependencies detected. SafeSC found no supported lockfile (requirements.txt, uv.lock, "
            "poetry.lock, package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.lock, go.sum, pom.xml, …)."
        )
    for w in outcome.warnings:
        print(f"  ⚠ {w}", file=sys.stderr)


def _write_reports(outcome, model: str, report_dir: str, report_format: str) -> None:
    from safesc.reporter import FORMATS, build_report, write_reports

    report = build_report(outcome.ledger, outcome.decision, model=model)
    formats = FORMATS if report_format == "all" else [report_format]
    for path in write_reports(report, report_dir, formats=formats):
        print(f"  wrote {path}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
