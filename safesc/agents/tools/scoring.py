"""agents/tools/scoring.py — `finalize_score`, the orchestrator's last call (§2.4).

The orchestrator decides *when* to score; `core.scoring.score` alone decides *what* the
score is. The tool refuses to run until the run is complete enough to score (the same
check the steering guard applies) and writes the decision exactly once.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from strands import tool

from safesc.agents.harness.guard import finalize_blocker
from safesc.core.scoring import score

if TYPE_CHECKING:
    from safesc.agents.context import AgentContext


def build_scoring_tool(ctx: "AgentContext", *, strict: bool = False):
    ledger = ctx.ledger

    @tool
    def finalize_score() -> str:
        """Compute the run's final score with SafeSC's deterministic rules. Call exactly
        once, after the static pipeline and every required analysis. You cannot influence
        the result except through the signals the pipeline and subagents already recorded."""
        blocker = finalize_blocker(ledger)
        if blocker:
            return f"REFUSED: {blocker}"
        decision = score(ledger, strict=strict)
        if not ledger.finalize(decision):
            return "REFUSED: the score was already finalized for this run."
        return f"FINAL (deterministic, once per run):\n{decision.summary}\nNow reply with a brief summary and stop."

    return finalize_score
