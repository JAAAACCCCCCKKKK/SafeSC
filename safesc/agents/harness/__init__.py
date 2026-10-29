"""agents/harness — the deterministic rails around every agent (CLAUDE.md §2.7).

* `guard.PipelineGuard` — steering: fixed static order, finalize prerequisites (lesson 7);
* `validation` — subagent output validation against evidence actually shown (§2.7.1);
* `progress.ProgressHook` — one line per tool call, so silent agents stay observable;
* the read-only source guard lives with the tool it guards (`agents.tools.evidence`).
"""
