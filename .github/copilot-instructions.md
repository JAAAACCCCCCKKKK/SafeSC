# CLAUDE.md — depaudit Project Development Rules (v2.2: Agent Architecture)

> **v2.2 (progress sync).** First agent-layer code has landed: the Stage-4 evidence tool (`tools/deep_analysis_tool.py`), the shared state with channel reducers (`graph/state.py`), the scope-only entry router (`graph/router.py`), the deterministic spine + post-Stage-3 gate (`graph/spine.py`), the three Stage-4 LLM specialists (`graph/specialists/`), and the scorer/terminal reducer (`graph/report_agent.py`). Two §9 open questions are now resolved (max-wins reducer; rule-based risk-independent router). Structure diagram in §6 updated to the real tree. See §0.1 for the build status matrix.

This document supersedes the v1 CI-pipeline-only rules. It defines the architectural and development constraints for **depaudit** as it evolves from a one-shot CI pipeline into an **agentic dependency-audit system**. Stages 0–3 (Discovery, Parse & Normalize, Hash Verification, Cheap Signals) are frozen, packaged as deterministic tools, and reused unchanged by the new agent layer. All code contributions must conform to the boundaries defined here.

The single most important thing to understand before reading further: **the agent layer changes *how work is scheduled*, not *how decisions are made*.** Every v1 iron rule about the scorer being the sole decision point and the LLM only escalating (never downgrading) survives verbatim. The graph is a scheduler on top of the v1 signal→scorer model, not a replacement for it.

---

## 0. Migration Note (v1 → v2)

| Aspect | v1 | v2 |
|---|---|---|
| Execution model | One CI run, one execution, then exit | CI audit **and** interactive query, both finite (still no daemon) |
| Stages 0–3 | Inline pipeline code | Frozen, wrapped as typed deterministic tools |
| Stage 4 (LLM deep analysis) | Single step | Fan-out to per-dimension LLM specialist nodes |
| Stage 5 (Report/Gate = scorer) | Final pipeline step | Terminal reducer node; still the only decision point |
| Orchestration | Sequential function calls | LangGraph state machine |
| Signal → scorer flow | Static + LLM signals → scorer | **Unchanged.** Graph nodes are just signal producers |
| Cache | In-process / filesystem / S3 | Redis (short-term) + PGVector (long-term) |
| Concurrency | Local per-host semaphores | Redis-backed distributed semaphores |

**v1 §1.3 ("No real-time monitoring / agent mode") is revised.** depaudit gains an agent mode, but every execution is still **triggered and finite** — a CI event, a webhook, or an explicit CLI/API query — never a persistent monitor.

### 0.1 Build Status

| Component | Location | Status |
|---|---|---|
| Stages 0–3 (index + scan) | `tools/index/`, `tools/scan/` | ✅ v1, frozen |
| Stage-4 evidence primitives | `tools/deep_analysis_tool.py` | ✅ implemented, unit-tested |
| Shared state + channel reducers | `graph/state.py` | ✅ implemented, unit-tested |
| Entry router (scope only) | `graph/router.py` | ✅ implemented, unit-tested |
| Deterministic spine (Stage 0→3 + gate) | `graph/spine.py` | ✅ implemented, unit-tested |
| Stage-4 specialists (Identity/Behavior/Provenance) | `graph/specialists/` | ✅ implemented, unit-tested |
| Scorer / report_agent | `graph/report_agent.py` | ✅ implemented, unit-tested |
| Harness (validator / auto-repair / session) | `graph/harness/` | ⛔ not started |
| Memory (Redis + PGVector) | `memory/` | ⛔ not started |
| FastAPI entrypoints | `entrypoints/` | ⛔ not started |

Design decisions locked in by the landed code (details in-section): the unified `Signal` format (§2.3, §4.3), max-wins escalation merge (§2.6), sum-delta LLM-call counting (§5.3), and rule-based risk-independent scope routing (§2.2-A).

---

## 1. Project Scope and Boundaries

### 1.1 Goal
Discover dependency lockfiles, traverse dependencies, evaluate trust across five dimensions, identify social-engineering and dependency-injection indicators, and either (a) gate a CI pipeline, or (b) answer an interactive investigation query — using the same deterministic signals and the same scorer in both modes. The agent reasons about *what to investigate*, never *what the verdict is*.

### 1.2 Clear Differentiation
Unchanged from v1: reuse Syft/OSV.dev; core value is multi-dimensional trust scoring + LLM intent analysis; blind-spot coverage is malicious behavioral intent + broken provenance. v2 additionally reuses LangGraph/LangChain instead of building a bespoke agent runtime.

### 1.3 Hard Scope Constraints (revised)
- **Two entrypoints, both finite**: `audit` (CI/webhook trigger, full repo, produces exit code) and `query` (interactive, single question, evidence only — **no exit code, no gate**). See §6.2.
- **Multi-language support**: ecosystem logic stays plugin-based (unchanged).
- **Custom registry support**: unchanged.
- **Bounded agent autonomy**: agents choose *which Stage-4 specialists to invoke and in what order*. They may **not** reorder or skip Stages 0–3, invent gate logic, or bypass the scorer. See §2.5 for why this boundary is a security property, not just tidiness.

### 1.4 First-Release Priority
Unchanged: Python (uv/poetry/pip) → npm/pnpm → Cargo → Go modules → Maven/Gradle.

---

## 2. Architecture: Deterministic Spine + Agentic Fan-Out

The v1 pipeline is preserved as a **fixed deterministic spine**. Agent discretion is confined to a single, well-bounded region: choosing which LLM specialists examine the small suspicious subset after the Stage-3 gate.

### 2.1 Stages 0–3 as Deterministic Tools (frozen)

| Tool | Wraps | LLM? | Output |
|---|---|---|---|
| `discover_lockfiles` | Stage 0 | no | lockfile paths |
| `parse_normalize` | Stage 1 | no | unified `Dependency[]` |
| `verify_hash` | Stage 2 | no | provenance signals |
| `collect_cheap_signals` | Stage 3 | no | identity/behavior/provenance/popularity/vulnerability **static** signals |

All four are LangChain `@tool` functions with strict Pydantic I/O. They must stay pure, **idempotent, and LLM-free** — idempotency matters now because a nondeterministic agent may retry them. This is v1 §4.4's "forbidden for LLM" list, now enforced *structurally* by the tool boundary rather than by convention.

### 2.2 The Two Routing Decisions (kept distinct on purpose)

v2 has **two** separate branch points. Conflating them was the main design error to avoid:

**(A) Entry router — splits on request *scope*, known at entry, no risk involved.** *(implemented: `graph/router.py`)*
- `query` for a single package, or a direct question → **single-agent path**.
- `audit` over a full repo → **full-spine path**.
This is pure decomposition. It cannot depend on risk, because *no signals have been collected yet* — you cannot know a package is a dependency-confusion candidate until Stage 3 has run. The shipped classifier is **rule-based and risk-independent** (package-spec/purl/npm-scope → single; git URL/lockfile path/`.` → repo; override wins; ambiguous falls back on mode intent). Mode (audit vs query) is orthogonal to scope — it only decides whether a CI gate + exit code is produced, so a read-only query over a full repo is allowed.

**(B) Post-Stage-3 gate — splits on *risk*, known only after cheap signals.**
This is v1 §2.2's tiered trigger, unchanged: the vast majority of deps are low-risk and skip Stage 4; only gray-zone deps fan out to LLM specialists. **This is where "complexity" actually enters** — and it enters as a data-driven gate, not an entry-time guess.

Keeping (A) and (B) separate is what makes the design coherent: scope is a routing concern, risk is a scorer concern, and they live in different places.

### 2.3 Stage-4 Specialists (the fan-out targets)

After the gate, each gray-zone dependency fans out to the LLM specialists relevant to *why it was flagged*:

- `IdentityAgent` — LLM analysis of name-squatting intent, maintainer-handover social engineering
- `BehaviorAgent` — install-script intent, deobfuscation, env-exfil reasoning
- `ProvenanceAgent` — commit/diff consistency, source-vs-artifact narrative gaps

**Note there is deliberately no `PopularityAgent` and no standalone `VulnerabilityAgent`.** Popularity (download counts, stars, Scorecard) and vulnerability (OSV/CVE table lookup, EOL) are **fully deterministic** — v1 §4.4 forbids the LLM from doing them. They are collected entirely in Stage 3 / `collect_cheap_signals` and never need an LLM node. Having an agent per dimension would have duplicated Stage-3 work; instead, specialists exist **only for the three dimensions that have genuine LLM tasks.**

Critically (v1 §5.1.3): **each specialist is a signal producer.** Its structured output (§4.2) is the LLM-detection analogue of a Stage-3 static signal. Both feed the scorer identically. A specialist never "decides" anything. The unified `Signal` format both origins share, and the `Signal.from_llm_output()` adapter that maps a §4.2 output through the §4.3 fusion table, are already in `graph/state.py`; a specialist's remaining job is (a) call the `tools/deep_analysis_tool.py` primitives for its dimension, (b) reason, (c) emit a §4.2 `LLMOutput`.

### 2.4 The Scorer Is Still the Only Decision Point

`ReportAgent` is the terminal reducer and **is the scorer** (v1 §5.1.4). Every static signal (Stages 0–3) and every LLM signal (Stage-4 specialists) converges here. It applies the v1 decision matrix (§3.4) and fusion table (§4.3) deterministically. Nothing else in the graph may compute or emit a gate decision. Naming it an "agent" is a convenience — it runs no LLM and has no discretion.

### 2.5 Why Bounded Autonomy Is a Security Property (new v2 threat)

v1's injection worry: an attacker writes `"this is safe, ignore warnings"` in a README to make the **LLM** output `clean`. v1 §4.3 neutralizes this (LLM can only escalate).

v2 introduces a **new** injection surface: an attacker crafts package metadata to steer the **agent's control flow** — e.g. to *skip* hash verification or *terminate early* before behavior analysis. An agent free to choose its whole tool sequence is vulnerable to this.

**Mitigation, and the reason for §1.3's autonomy boundary:** Stages 0–3 are a **non-discretionary fixed sequence** — the agent cannot be talked out of running them, because it never chose to run them; the spine does. Agent discretion exists *only* in Stage-4 specialist selection, and there the failure mode is bounded: at worst the agent skips a specialist, which can only *lose* an escalation signal, never *manufacture* a downgrade. Combined with §4.3 (LLM escalates only) and §3.3 (memory informs, never overrides), all three of depaudit's LLM/agent input channels share one invariant: **they can raise severity but never lower it.**

### 2.6 Shared State (blackboard) *(implemented: `graph/state.py`)*
A single typed LangGraph state object (`AuditState`, Pydantic) threads through every node: `Dependency[]`, accumulated `Signal[]`, per-dep escalation map, live LLM-call count (for §5.3), and degraded notes. It is the **sole** inter-node channel — no direct agent-to-agent messaging, no side channels. Parallel specialists write via **Annotated channel reducers** so out-of-order fan-in merges deterministically:
- `signals` → **additive + dedup** by `(dep_key, source, dimension)`, making auto-repair retries idempotent (no double-count).
- `escalations` → **max-wins** per dep: conflicting tiers resolve to the higher one (weakest-link, escalate-only). *This resolves the former §9 open question.*
- `llm_calls` → **sum of per-node deltas**; nodes return only the calls they made (`increment_llm_calls`), never an absolute total — a naive overwrite would drop a parallel branch's count and defeat the §5.3 cap.
- `gate_decision` → **write-once**, `report_agent` only (§2.4).

State is Pydantic per this doc; if a pinned LangGraph predates reliable Pydantic-state support, swap `AuditState` for a `TypedDict` with the same Annotated fields — reducers and value models are unchanged.

### 2.7 Harness Layer
- **Constraint validator** (wraps every LLM node): validates output against §4.2 before it reaches shared state; malformed output is retried, not accepted.
- **Auto-repair**: bounded retry + exponential backoff around every tool node (v1 §6.2 policy). On exhaustion the node marks its contribution `degraded`; the run continues.
- **Session manager**: assigns a run/session id and holds Redis-backed distributed semaphores (§5.2).

---

## 3. Memory System

### 3.1 Short-Term Memory — Redis
- LangGraph checkpointer backend: mid-run state survives node retries and enables resume.
- Hot cache for in-flight tool results (replaces v1 L1) and cross-run cheap-signal reuse on the same repo/branch, TTL 7 days (v1 L2).
- Distributed semaphore store (§5.2).

Note: within a single graph run, parallel specialists synchronize via LangGraph fan-in (§2.6), **not** via Redis pub/sub. Redis holds state and rate limits; it is not a message bus between nodes.

### 3.2 Long-Term Memory — PGVector
- Stores embeddings of: finalized verdicts per `package@version+hash`, LLM evidence/reasoning text, allowlist entries, and known-attack fingerprints (e.g. XZ-Utils-style patterns).
- Used purely as **retrieval context**: before a Stage-4 specialist runs, PGVector is queried for prior or behaviorally-similar findings and those are supplied as few-shot context. This cuts redundant deep analysis (cost) and grounds the LLM in prior evidence.
- Replaces v1's L3 (S3/Redis team cache). PGVector is now the canonical long-term store; Redis stays hot/short-term only.

### 3.3 Memory Safety Boundary (iron rule, extended)
- Retrieved memory may **inform** LLM reasoning; it may **never** downgrade the current run's severity. A prior `clean` verdict on the same hash is evidence, not an override — because memory is another attacker-poisonable input channel, subject to the same "escalate-only" invariant as §2.5 and §4.3.
- Long-term writes happen **only after** `ReportAgent` finalizes a run. No unverified in-flight signal is ever persisted.

---

## 4. LLM Usage Constraints (v1 iron rules, now enforced at graph level)

### 4.1 Role of the LLM
Unchanged: **the LLM produces evidence, not decisions.** In v2 this is enforced by construction — no LLM node has write access to the gate decision (§2.4).

### 4.2 Mandatory Structured Output
Every LLM node returns:
```json
{
  "task": "<task_name>",
  "verdict": "clean | suspicious | malicious",
  "confidence": 0.0-1.0,
  "evidence": [...],
  "reasoning": "...",
  "false_positive_hints": [...]
}
```
Enforced via a LangChain structured-output parser bound to a Pydantic model; the constraint validator (§2.7) rejects non-conforming output.

### 4.3 LLM × Rules Engine Fusion
Unchanged from v1:

| LLM verdict | confidence | Adjustment |
|---|---|---|
| malicious | ≥ 0.7 | Force critical |
| malicious | 0.4–0.7 | Escalate one tier |
| suspicious | ≥ 0.7 | Escalate one tier |
| suspicious | < 0.7 | Evidence only |
| clean | any | No adjustment |

**Iron rule:** LLM signals and retrieved memory may only *escalate*, never downgrade.

### 4.4 LLM Task Scope
Unchanged from v1 §4.4. Suitable: install-script intent, commit/diff consistency, README coercion, maintainer-handover signals, deobfuscation. Forbidden (kept deterministic): hash comparison, CVE matching, name-similarity, timestamp comparison. **This is exactly why §2.3 has specialists only for Identity/Behavior/Provenance** — the other two dimensions are entirely in the forbidden list.

---

## 5. Cost, Concurrency, and Caps

### 5.1 Time Budget
Unchanged v1 §6.1 targets; CI run target remains under 5 minutes; Stage-4 trigger rate 5–10%.

### 5.2 Concurrency
Redis-backed distributed semaphores per external host, replacing v1 local semaphores, so concurrent audits and queries share one global rate budget. Exponential backoff with bounded retries; configurable API-token pools for rotation (v1 §6.2).

### 5.3 LLM Call Cap
Hard per-run ceiling tracked in shared state (§2.6). The counting mechanism is in place (`AuditState.llm_calls` via the `sum_deltas` reducer, plus `would_exceed_cap()`); nodes check before spending and report their delta after. Enforcement is **deterministic at the gate**: `plan_gate` (`graph/spine.py`) ranks fan-out candidates by trigger severity and emits only the first `llm_call_cap − llm_calls`, dropping the rest *before* any `Send`. Truncated deps keep their static escalation and get an "incomplete analysis" degraded note (v1 §6.3) — a routing decision, not a silent truncation, and not something parallel specialist branches can race past. The concrete cap value is still TBD (§9).

---

## 6. Project Structure (Enforced)

The v1 Stages 0–3 already live under `tools/` split into two frozen sub-packages — `index/` (discovery + normalize + ecosystem adapters) and `scan/` (signal collectors). Stage 4 adds a peer module, `deep_analysis_tool.py`. The agent layer is a new top-level `graph/`. Legend: ✅ built · ⛔ pending.

```
depaudit/
├── tools/                            # Stages 0–4, deterministic, LLM-free
│   ├── index/                        # ✅ Stages 0–1
│   │   ├── core/                     #    discovery.py, normalizer.py, models.py (→ Dependency)
│   │   ├── cli/
│   │   └── ecosystems/               #    base.py + go|java|javascript|python|rust adapters+parsers
│   ├── scan/                         # ✅ Stages 2–3
│   │   ├── cli/
│   │   └── signals/                  #    base, collector, github, registry_meta, models
│   │       └── behavior|identity|popularity|provenance|vulnerability/   # static collectors
│   └── deep_analysis_tool.py         # ✅ Stage 4 (evidence only, no LLM, no verdict)
│                                     #    clone/diff/extract primitives the specialists call
├── graph/                            # agent layer (the scheduler)
│   ├── state.py                      # ✅ AuditState + channel reducers (§2.6)
│   ├── router.py                     # ✅ scope split only (§2.2-A)
│   ├── spine.py                      # ✅ fixed Stage 0→3 sequence + post-Stage-3 gate (§2.2-B)
│   ├── single_agent.py               # ⛔ single-package path
│   ├── specialists/                  # ✅ base.py + identity_agent.py, behavior_agent.py, provenance_agent.py
│   │                                 #    (no popularity/vulnerability agent — §2.3)
│   ├── report_agent.py               # ✅ terminal reducer == scorer, sole decision writer (§2.4)
│   └── harness/                      # ⛔ constraint_validator.py, auto_repair.py, session_manager.py
├── memory/                           # ⛔ short_term.py (Redis), long_term.py (PGVector)
├── entrypoints/                      # ⛔ api.py (FastAPI: audit + query + webhook), cli.py
└── reporter/                         # ⛔ SARIF / Markdown / JSON (v1 design; not yet implemented)
```

Naming note: the `*_agent.py` specialists and `report_agent.py` are graph nodes, not autonomous agents in the swarm sense; `report_agent` runs no LLM at all (§2.4).

### 6.1 Structural Invariants
1. **Only `graph/report_agent.py` (or the single-agent reducer) writes the gate decision** — enforced today by the `write_once` reducer on `AuditState.gate_decision` (v2 form of v1 §5.1.4).
2. **`tools/` stays LLM-free — including `tools/deep_analysis_tool.py`.** If a stage needs LLM judgment it belongs in `graph/specialists/`, never in `tools/`. `deep_analysis_tool.py` provides deterministic primitives (clone, diff, extract) and returns evidence bundles with **no verdict/score field**; the *reasoning* lives in the specialist node.
3. **Adding an ecosystem still means one adapter under `tools/index/ecosystems/`**, untouched by the agent layer (v1 §5.1).
4. **The graph is the core; `entrypoints/` are thin.** CLI and API both call `graph.run(request)`; neither contains audit logic and the CLI does not shell out to the HTTP server.
5. **v1 layering preserved:** `tools/scan/signals/` and `graph/specialists/` receive standardized `Dependency` objects and never import `tools/index/ecosystems/`; adapters never judge (v1 §5.1.1–.2).

---

## 7. Tech Stack (v2)

| Layer | Choice | Rationale |
|---|---|---|
| API | FastAPI | Async, typed models, serves `audit` + `query` |
| Orchestration | LangGraph | Explicit state machine; native fan-out/fan-in; checkpointing |
| Tool/chain wrapping | LangChain | `@tool` wrapping of Stages 0–3; structured-output parsers |
| Short-term memory | Redis | Checkpointer, distributed semaphores, hot cache (v1 L1/L2) |
| Long-term memory | PGVector | Verdict/evidence/attack-fingerprint embeddings (v1 L3) |
| LLM | Claude API | Structured output + prompt caching (unchanged) |
| Lockfile parsing | Syft → CycloneDX | Unchanged |
| CVE source | OSV.dev | Unchanged |
| Reports | SARIF + Markdown + JSON | Unchanged |
| CI integration | GitHub Action + CLI | Exit code drives the gate (audit mode only) |

---

## 8. Development Principles (v2 Quick Reference)

1. **Explainability > accuracy** — every escalation traces to a specific static or LLM signal in shared state.
2. **Deterministic spine > agent cleverness** — the agent chooses *which specialist looks*, never *what the verdict is*.
3. **Two branch points, kept separate** — scope at entry (§2.2-A), risk at the gate (§2.2-B). Never conflate them.
4. **Escalate-only, three channels** — LLM signals, retrieved memory, and agent control-flow can each only raise severity, never lower it (§2.5, §3.3, §4.3).
5. **Graceful degradation** — any node failure degrades that node's contribution and is annotated; it never crashes the run.
6. **Zero-touch ecosystem additions** — one adapter, no core/graph changes.
7. **The scorer is still the only judge** — the graph reschedules v1's signal→scorer flow; it does not replace it.

---

## 9. Confirmed but Unimplemented

Resolved since v2.1:
- [x] Entry-router scope heuristic — shipped rule-based and risk-independent (§2.2-A, `graph/router.py`).
- [x] Channel-reducer semantics for conflicting escalations — **max-wins** confirmed and implemented (§2.6, `graph/state.py`).

Still open:
- [ ] Post-Stage-3 gate threshold *values* — the gate mechanism has shipped (`graph/spine.py`: `plan_gate` + `GateConfig` with `gray_floor`/`decided_ceiling`/`llm_dimensions`, §2.2-B); the concrete gray-zone floor is a default (`MEDIUM`) still to be tuned against the §5.1 5–10% trigger-rate target
- [ ] Concrete hard cap *value* for LLM calls per run — mechanism and enforcement have shipped (`sum_deltas` + `would_exceed_cap`, enforced deterministically in `plan_gate`, §5.3); only the numeric ceiling is TBD
- [ ] LangGraph Redis checkpointer schema: keying, TTL, eviction
- [ ] PGVector embedding model + dimensionality; similarity threshold for "behaviorally similar package"
- [ ] Auth model for the `query` route (new attack surface)
- [ ] Agent-control-flow injection tests (§2.5) — adversarial metadata attempting to induce early termination
- [ ] Prompt-injection defense for specialists (carried from v1)
- [ ] Monorepo / multi-config-file support (carried from v1)
- [ ] End-to-end walkthrough vs. XZ Utils / event-stream / PyTorch dependency confusion (carried from v1)

---

*Living document. Significant architectural changes must be reflected here and pass review.*
