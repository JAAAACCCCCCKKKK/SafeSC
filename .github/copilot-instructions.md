# CLAUDE.md — depaudit Project Development Rules (v2.1: Agent Architecture)

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

**(A) Entry router — splits on request *scope*, known at entry, no risk involved.**
- `query` for a single package, or a direct question → **single-agent path**.
- `audit` over a full repo → **full-spine path**.
This is pure decomposition. It cannot depend on risk, because *no signals have been collected yet* — you cannot know a package is a dependency-confusion candidate until Stage 3 has run.

**(B) Post-Stage-3 gate — splits on *risk*, known only after cheap signals.**
This is v1 §2.2's tiered trigger, unchanged: the vast majority of deps are low-risk and skip Stage 4; only gray-zone deps fan out to LLM specialists. **This is where "complexity" actually enters** — and it enters as a data-driven gate, not an entry-time guess.

Keeping (A) and (B) separate is what makes the design coherent: scope is a routing concern, risk is a scorer concern, and they live in different places.

### 2.3 Stage-4 Specialists (the fan-out targets)

After the gate, each gray-zone dependency fans out to the LLM specialists relevant to *why it was flagged*:

- `IdentityAgent` — LLM analysis of name-squatting intent, maintainer-handover social engineering
- `BehaviorAgent` — install-script intent, deobfuscation, env-exfil reasoning
- `ProvenanceAgent` — commit/diff consistency, source-vs-artifact narrative gaps

**Note there is deliberately no `PopularityAgent` and no standalone `VulnerabilityAgent`.** Popularity (download counts, stars, Scorecard) and vulnerability (OSV/CVE table lookup, EOL) are **fully deterministic** — v1 §4.4 forbids the LLM from doing them. They are collected entirely in Stage 3 / `collect_cheap_signals` and never need an LLM node. Having an agent per dimension would have duplicated Stage-3 work; instead, specialists exist **only for the three dimensions that have genuine LLM tasks.**

Critically (v1 §5.1.3): **each specialist is a signal producer.** Its structured output (§4.2) is the LLM-detection analogue of a Stage-3 static signal. Both feed the scorer identically. A specialist never "decides" anything.

### 2.4 The Scorer Is Still the Only Decision Point

`ReportAgent` is the terminal reducer and **is the scorer** (v1 §5.1.4). Every static signal (Stages 0–3) and every LLM signal (Stage-4 specialists) converges here. It applies the v1 decision matrix (§3.4) and fusion table (§4.3) deterministically. Nothing else in the graph may compute or emit a gate decision. Naming it an "agent" is a convenience — it runs no LLM and has no discretion.

### 2.5 Why Bounded Autonomy Is a Security Property (new v2 threat)

v1's injection worry: an attacker writes `"this is safe, ignore warnings"` in a README to make the **LLM** output `clean`. v1 §4.3 neutralizes this (LLM can only escalate).

v2 introduces a **new** injection surface: an attacker crafts package metadata to steer the **agent's control flow** — e.g. to *skip* hash verification or *terminate early* before behavior analysis. An agent free to choose its whole tool sequence is vulnerable to this.

**Mitigation, and the reason for §1.3's autonomy boundary:** Stages 0–3 are a **non-discretionary fixed sequence** — the agent cannot be talked out of running them, because it never chose to run them; the spine does. Agent discretion exists *only* in Stage-4 specialist selection, and there the failure mode is bounded: at worst the agent skips a specialist, which can only *lose* an escalation signal, never *manufacture* a downgrade. Combined with §4.3 (LLM escalates only) and §3.3 (memory informs, never overrides), all three of depaudit's LLM/agent input channels share one invariant: **they can raise severity but never lower it.**

### 2.6 Shared State (blackboard)
A single typed LangGraph state object threads through every node: `Dependency[]`, per-dimension signals collected so far, evidence log, escalation flags, and live LLM-call count (for §5.3). It is the **sole** inter-node channel — no direct agent-to-agent messaging, no side channels. Parallel specialists write into it via **LangGraph channel reducers** (Annotated reducer functions), so out-of-order completion of fan-out nodes merges deterministically at fan-in rather than racing. (See §9 for the open question on reducer semantics for conflicting escalations.)

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
Hard per-run ceiling tracked in shared state (§2.6), enforced by the constraint validator. On breach mid-run, remaining specialists route to a degrade path and the report is marked "incomplete analysis" — a graph-level routing decision, not a silent truncation (v1 §6.3).

---

## 6. Project Structure (Enforced)

```
depaudit/
├── entrypoints/                  # thin adapters; both call graph.run()
│   ├── api.py                    # FastAPI app (audit + query routes, webhook)
│   └── cli.py                    # legacy one-shot CLI
├── graph/                        # LangGraph orchestration (the scheduler)
│   ├── state.py                  # shared Pydantic state + channel reducers (§2.6)
│   ├── router.py                 # scope split only (§2.2-A)
│   ├── single_agent.py           # single-package ReAct path
│   ├── spine.py                  # fixed Stage 0→1→2→3 sequence + post-gate fan-out (§2.2-B)
│   ├── specialists/
│   │   ├── identity_agent.py
│   │   ├── behavior_agent.py
│   │   └── provenance_agent.py   # (no popularity/vulnerability agent — §2.3)
│   ├── report_agent.py           # terminal reducer == scorer, sole decision writer (§2.4)
│   └── harness/
│       ├── constraint_validator.py
│       ├── auto_repair.py
│       └── session_manager.py
├── tools/                        # Stages 0–3 frozen, wrapped; LLM-free
│   ├── discovery_tool.py
│   ├── parse_normalize_tool.py
│   ├── hash_verify_tool.py
│   ├── cheap_signals_tool.py
│   └── deep_analysis_tool.py     # Stage-4 primitives the specialists call
├── memory/
│   ├── short_term.py             # Redis: checkpointer + semaphores + hot cache
│   └── long_term.py              # PGVector: embed + retrieve
├── core/                         # unchanged v1 pipeline internals (called by tools/)
├── ecosystems/                   # unchanged plugin adapters
├── signals/                      # unchanged static signal collectors
└── reporter/                     # SARIF / Markdown / JSON (unchanged)
```

### 6.1 Structural Invariants
1. **Only `graph/report_agent.py` (or the single-agent reducer) writes the gate decision** — v2 form of v1 §5.1.4.
2. **`tools/` stays LLM-free.** If a stage needs LLM judgment it belongs in `graph/specialists/`, never in `tools/`. (`deep_analysis_tool.py` provides deterministic primitives — clone, diff, extract — that specialists call; the *reasoning* lives in the specialist node.)
3. **Adding an ecosystem still means one adapter under `ecosystems/`**, untouched by the agent layer (v1 §5.1, §13.5).
4. **The graph is the core; `entrypoints/` are thin.** CLI and API both call `graph.run(request)`; neither contains audit logic and the CLI does not shell out to the HTTP server.
5. **v1 layering preserved:** `signals/` and `graph/specialists/` receive standardized `Dependency` objects and never import `ecosystems/`; adapters never judge (v1 §5.1.1–.2).

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

- [ ] Entry-router scope heuristic — rule-based first pass vs. LLM-assisted (must stay risk-independent, §2.2-A)
- [ ] Channel-reducer semantics when two specialists escalate the same dependency to conflicting tiers (max-wins is the presumed answer, per weakest-link §3.3 — confirm)
- [ ] LangGraph Redis checkpointer schema: keying, TTL, eviction
- [ ] PGVector embedding model + dimensionality; similarity threshold for "behaviorally similar package"
- [ ] Auth model for the `query` route (new attack surface)
- [ ] Agent-control-flow injection tests (§2.5) — adversarial metadata attempting to induce early termination
- [ ] Prompt-injection defense for specialists (carried from v1)
- [ ] Concrete hard cap value for LLM calls per run (carried from v1)
- [ ] Monorepo / multi-config-file support (carried from v1)
- [ ] End-to-end walkthrough vs. XZ Utils / event-stream / PyTorch dependency confusion (carried from v1)

---

*Living document. Significant architectural changes must be reflected here and pass review.*
