"""agents/harness/guard.py — the orchestrator's rails (lesson 7: deterministic steering).

`PipelineGuard` inspects every tool call the orchestrator is about to make and, when the
call would break the run's invariants, blocks it with `Guide` — the call does not run, and
the reason is fed back so the model corrects course. The checks are the ledger's own,
so the guard and the tools can never disagree:

* the static stages run in their fixed order, each once (§2.1, §2.5);
* no subagent runs before the static pipeline has produced the signals it triages on;
* a verifier runs only where a hunter left candidates;
* `finalize_score` is refused until every static stage has run and every required
  analysis has been attempted (or the subagent budget is spent), and refused a second time
  once the score exists (§2.4).

The guard is the courteous layer. The tools enforce the same rules themselves, so a run
with the guard misconfigured still cannot skip a stage or finalize early.
"""

from __future__ import annotations

from typing import Optional

from strands.vended_plugins.steering import Guide, Proceed, SteeringHandler

from safesc.core.ledger import STATIC_STAGES, Role, RunLedger, Stage

PIPELINE_TOOLS: dict[str, tuple[Stage, tuple[Stage, ...]]] = {
    "discover_lockfiles": (Stage.DISCOVER, ()),
    "parse_dependencies": (Stage.PARSE, (Stage.DISCOVER,)),
    "verify_hashes": (Stage.VERIFY, (Stage.DISCOVER, Stage.PARSE)),
    "collect_signals": (Stage.COLLECT, (Stage.DISCOVER, Stage.PARSE, Stage.VERIFY)),
}
FINALIZE_TOOL = "finalize_score"


def finalize_blocker(ledger: RunLedger) -> Optional[str]:
    if ledger.decision is not None:
        return "The score is already finalized for this run (once per run). Stop and reply with a short summary."
    missing = ledger.missing_stages(*STATIC_STAGES)
    if missing:
        return f"Cannot finalize: static stage(s) not run: {', '.join(s.value for s in missing)}. Run them in order first."
    todo = ledger.outstanding_coverage()
    if todo:
        listing = "; ".join(f"{role.value}({k})" for k, role, _ in todo[:10])
        more = f" (+{len(todo) - 10} more)" if len(todo) > 10 else ""
        return f"Cannot finalize: {len(todo)} required analysis(es) not yet run: {listing}{more}."
    return None


def tool_blocker(ledger: RunLedger, name: str, tool_input: dict, specialist_roles: dict[str, Role]) -> Optional[str]:
    if name in PIPELINE_TOOLS:
        stage, needed = PIPELINE_TOOLS[name]
        if stage in ledger.stages:
            return f"{name} already ran in this run; its results are in the ledger. Move on to the next step."
        missing = ledger.missing_stages(*needed)
        if missing:
            return f"{name} must wait: run {missing[0].value} first (fixed order discover → parse → verify → collect)."
        return None
    if name == FINALIZE_TOOL:
        return finalize_blocker(ledger)
    if name in specialist_roles:
        if ledger.missing_stages(Stage.COLLECT):
            return "Run the static pipeline through collect_signals before calling any subagent."
        key = str((tool_input or {}).get("dep_key", ""))
        if ledger.get_dependency(key) is None:
            return f"Unknown dep_key {key!r}; use list_flagged_dependencies or required_analyses for valid keys."
        if specialist_roles[name] == Role.VULN_VERIFIER and not ledger.pending_candidates(key):
            return f"{key} has no unverified vulnerability candidates; vuln_verifier is only for candidates vuln_hunter registered."
    return None


class PipelineGuard(SteeringHandler):
    name = "safesc-pipeline-guard"

    def __init__(self, ledger: RunLedger, specialist_roles: dict[str, Role]):
        super().__init__()
        self.ledger = ledger
        self.specialist_roles = specialist_roles

    async def steer_before_tool(self, *, agent, tool_use, **kwargs):
        reason = tool_blocker(self.ledger, tool_use.get("name", ""), tool_use.get("input") or {}, self.specialist_roles)
        if reason:
            return Guide(reason=reason)
        return Proceed(reason="within the run's invariants")
