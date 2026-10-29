"""agents/tools/pipeline.py — Stages 0–3 as agent tools, the only way they ever run (§2.1).

The four static stages are deterministic, LLM-free and idempotent, and in SafeSC they are
invoked **only by an agent**: these tools are handed to the orchestrator and to nothing
else, and no entrypoint calls the underlying library directly
(`tests/test_invariants.py` pins that).

Letting a model *trigger* the stages must not let it *skip* or *redirect* them — the §2.5
control-flow-injection threat. Three structural properties hold that line:

* the tools take **no target argument**: what is scanned is fixed by the run options
  before any agent starts, so package content cannot point discovery elsewhere;
* each tool **refuses to run out of order** (the ledger's stage prerequisites), and the
  orchestrator's steering handler gives the same feedback before the call is even made;
* `finalize_score` refuses to score until all four stages have completed, so an agent
  talked out of running a stage produces no verdict at all — never a passing one.

Each tool writes its full results to the ledger and returns only a compact summary.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Awaitable, Callable, Sequence

from strands import tool

from safesc.core.gate import plan_triage
from safesc.core.ledger import LockfileRef, Stage
from safesc.core.signals import Severity, Signal, hash_result_to_core, scan_signal_to_core
from safesc.core.targets import TargetKind, parse_package_spec
from safesc.tools.index.core.models import Dependency

if TYPE_CHECKING:
    from safesc.agents.context import AgentContext

logger = logging.getLogger("safesc.tools.pipeline")

# Manifests that legitimately declare zero *pinned* dependencies: an empty parse of these
# is expected. Any other discovered file that yields nothing is a coverage gap (most often
# an encoding problem) and must not pass as a silent clean audit (§8).
_MANIFEST_ONLY = frozenset({"pyproject.toml", "setup.cfg", "cargo.toml"})


def _real_discover(target: str, exclude: Sequence[str]) -> list[LockfileRef]:
    from safesc.tools.index.core import discovery

    path = Path(target)
    if path.is_file():
        found = discovery.discover(path.parent, exclude=exclude)
        found = [f for f in found if f.path.resolve() == path.resolve()]
    else:
        found = discovery.discover(path, exclude=exclude)
    return [LockfileRef(path=str(f.path), ecosystem=f.ecosystem) for f in found]


def _real_parse(lockfiles: list[LockfileRef]) -> list[Dependency]:
    from safesc.tools.index.core import normalizer
    from safesc.tools.index.core.discovery import DiscoveredFile

    discovered = [DiscoveredFile(path=Path(lf.path), ecosystem=lf.ecosystem, matched_glob="") for lf in lockfiles]
    return normalizer.parse_lockfiles(discovered)


async def _real_verify(deps: list[Dependency]) -> list[Signal]:
    from safesc.tools.scan.signals.provenance import verifier

    return [hash_result_to_core(r) for r in await verifier.verify_all(deps)]


async def _real_collect(deps: list[Dependency]) -> tuple[list[Signal], list[str]]:
    """Stage 3 over every dep at once. Returns signals plus one note per collector type
    that could not give a complete answer for some deps (outside popularity, whose GitHub
    checks routinely hit anonymous rate limits and never gate a verdict on their own)."""
    from safesc.tools.scan.signals import collector

    degraded: Counter[tuple[str, str]] = Counter()

    def on_error(coll, dep, reason) -> None:
        degraded[(type(coll).__name__, coll.dimension.value)] += 1

    signals = await collector.collect_all(deps, on_error=on_error)
    notes = [
        f"{name} could not complete for {n} dependency(ies) ({dim}); its silence is not a clean result"
        for (name, dim), n in sorted(degraded.items()) if dim != "popularity"
    ]
    return [scan_signal_to_core(s) for s in signals], notes


@dataclass
class StaticBackend:
    """The four Stage 0–3 implementations. Real by default; tests inject fakes."""

    discover: Callable[[str, Sequence[str]], list[LockfileRef]] = field(default=_real_discover)
    parse: Callable[[list[LockfileRef]], list[Dependency]] = field(default=_real_parse)
    verify: Callable[[list[Dependency]], Awaitable[list[Signal]]] = field(default=_real_verify)
    collect: Callable[[list[Dependency]], Awaitable[tuple[list[Signal], list[str]]]] = field(default=_real_collect)


def _order_error(ctx: "AgentContext", stage: Stage, *needed: Stage) -> str | None:
    missing = ctx.ledger.missing_stages(*needed)
    if missing:
        return f"ERROR: {stage.value} cannot run yet — call {missing[0].value} first (fixed order: discover → parse → verify → collect)."
    return None


def _severity_counts(signals: list[Signal]) -> dict[str, int]:
    worst: dict[str, Severity] = {}
    for s in signals:
        if s.severity > worst.get(s.dep_key, Severity.CLEAN):
            worst[s.dep_key] = s.severity
    counts = Counter(v.name for v in worst.values())
    return {name: counts.get(name, 0) for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(name)}


def build_pipeline_tools(ctx: "AgentContext") -> list:
    ledger = ctx.ledger
    backend = ctx.backend

    @tool
    def discover_lockfiles() -> str:
        """Stage 0: find every dependency lockfile/manifest in the run's target.

        Always the first call of a run. Takes no arguments: the target is fixed when the
        run starts and cannot be changed.
        """
        opts = ledger.options
        if opts.target_kind == TargetKind.PACKAGE:
            ledger.lockfiles = []
            ledger.mark_stage(Stage.DISCOVER)
            return f"Target is a single package spec ({opts.target}); nothing to discover. Next: parse_dependencies."
        try:
            found = backend.discover(opts.target, opts.exclude)
        except Exception as exc:
            ledger.add_note("discover", f"discovery failed: {exc}")
            ledger.mark_stage(Stage.DISCOVER)
            return f"Discovery FAILED ({exc}); the run is incomplete. Continue with parse_dependencies."
        ledger.lockfiles = found
        ledger.mark_stage(Stage.DISCOVER)
        if not found:
            return "No supported lockfiles found in the target. Continue with parse_dependencies."
        by_eco = Counter(lf.ecosystem for lf in found)
        listing = "\n".join(f"  - {lf.path} ({lf.ecosystem})" for lf in found[:40])
        more = f"\n  … and {len(found) - 40} more" if len(found) > 40 else ""
        return f"Found {len(found)} lockfile(s): {dict(by_eco)}\n{listing}{more}\nNext: parse_dependencies."

    @tool
    def parse_dependencies() -> str:
        """Stage 1: parse the discovered lockfiles into the run's dependency set."""
        err = _order_error(ctx, Stage.PARSE, Stage.DISCOVER)
        if err:
            return err
        opts = ledger.options
        if opts.target_kind == TargetKind.PACKAGE:
            dep = parse_package_spec(opts.target)
            if dep is None:
                ledger.add_note("parse", f"could not parse package spec {opts.target!r}")
                deps: list[Dependency] = []
            else:
                deps = [dep]
        else:
            try:
                deps = backend.parse(ledger.lockfiles)
            except Exception as exc:
                ledger.add_note("parse", f"parse failed: {exc}")
                deps = []
            produced = {Path(d.lockfile_path) for d in deps if getattr(d, "lockfile_path", None) is not None}
            for lf in ledger.lockfiles:
                if Path(lf.path) not in produced and Path(lf.path).name.lower() not in _MANIFEST_ONLY:
                    ledger.add_note(
                        "parse",
                        f"lockfile '{lf.path}' parsed to 0 dependencies — likely an encoding or format problem",
                    )
        ledger.set_dependencies(deps)
        ledger.mark_stage(Stage.PARSE)
        direct = sum(1 for d in deps if d.is_direct or d.layer_number == 1)
        by_eco = Counter(d.ecosystem or "unknown" for d in deps)
        return (
            f"Parsed {len(deps)} dependencies ({direct} direct) across {dict(by_eco)}. "
            "Next: verify_hashes."
        )

    @tool
    async def verify_hashes() -> str:
        """Stage 2: verify every dependency's lockfile hash against its registry."""
        err = _order_error(ctx, Stage.VERIFY, Stage.DISCOVER, Stage.PARSE)
        if err:
            return err
        deps = ledger.dependencies
        try:
            signals = await backend.verify(deps) if deps else []
        except Exception as exc:
            ledger.add_note("verify", f"hash verification failed: {exc}")
            signals = []
        ledger.add_signals(signals)
        ledger.mark_stage(Stage.VERIFY)
        flagged = [s for s in signals if s.severity > Severity.CLEAN]
        lines = "\n".join(f"  - {s.dep_key}: {s.severity.name} {s.summary}" for s in flagged[:20])
        status = Counter(s.source.rsplit(".", 1)[-1] for s in signals)
        return f"Verified {len(deps)} deps: {dict(status)}.\n{lines}\nNext: collect_signals."

    @tool
    async def collect_signals() -> str:
        """Stage 3: collect the cheap static signals (identity, behavior, provenance,
        popularity, vulnerability) for every dependency, then return the triage view."""
        err = _order_error(ctx, Stage.COLLECT, Stage.DISCOVER, Stage.PARSE, Stage.VERIFY)
        if err:
            return err
        deps = ledger.dependencies
        try:
            signals, notes = await backend.collect(deps) if deps else ([], [])
        except Exception as exc:
            signals, notes = [], [f"signal collection failed: {exc}"]
        ledger.add_signals(signals)
        for note in notes:
            ledger.add_note("collect", note)
        ledger.mark_stage(Stage.COLLECT)
        triage = plan_triage(ledger)
        lines = [
            f"Collected {len(signals)} signal(s) over {len(deps)} deps. "
            f"Deps by worst severity: {json.dumps(_severity_counts(ledger.signals))}."
        ]
        if notes:
            lines.append(f"{len(notes)} collector(s) degraded — the run will be marked incomplete.")
        if triage:
            lines.append(f"{len(triage)} gray-zone item(s) REQUIRE subagent analysis:")
            lines += [
                f"  - {t.dep_key} [{t.dimension.value} {t.severity.name}] via {', '.join(t.sources)}"
                for t in triage[:30]
            ]
        else:
            lines.append("No gray-zone items: no identity/behavior/provenance analysis is required.")
        lines.append("Use required_analyses for the full to-do list, list_flagged_dependencies to browse.")
        return "\n".join(lines)

    return [discover_lockfiles, parse_dependencies, verify_hashes, collect_signals]
