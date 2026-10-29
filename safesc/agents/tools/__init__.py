"""agents/tools — every capability an agent can use, as Strands tools.

* `pipeline` — Stages 0–3 (orchestrator only; the only way the static stages ever run);
* `inspection` — read-only ledger views and registry/advisory lookups;
* `evidence` — Stage-4 evidence primitives, source fetch/read/search, risky-pattern scan,
  authorship profiling;
* `external` — vended web_fetch and MCP servers;
* `scoring` — `finalize_score`, the orchestrator's once-per-run call into the scorer.
"""
