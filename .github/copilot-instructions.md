# CLAUDE.md — depaudit Project Development Rules (v2.6: Agent Architecture)

> **v2.6 (stores landed).** The two §3 store clients are now **implemented and unit-tested**: `memory/short_term.py` (`ShortTermStore` — the injectable Redis seam serving the hot cache, the checkpointer factory, and the SessionManager's ZSET ops via one client) and `memory/long_term.py` (`PGVectorStore` — `query_similar`/`upsert`/`get`/`gc` over a plain DB-API connection, vectors written as `::vector` literals, defense-in-depth `GREATEST` max-wins, §3.4 differentiated-retention GC). Both use **lazy imports** so the core stays installable without the new optional `memory` extra (redis / psycopg / pgvector / langgraph-checkpoint-redis); both are consumed by the MemoryManager purely via **injection** (§6.1.6). `MemoryManager.gc()` now delegates to the vector store so `depaudit gc` (§3.4) is wired end-to-end. What remains is **deployment**, not code: a live Redis/Postgres instance, a pinned embedding model+dimension, and the similarity cutoff. Builds on v2.5 (harness + memory-manager).

> **v2.5 (harness + memory landed).** The four Harness components (§2.7) and the Memory Manager's read/write paths are now **implemented and unit-tested**, moving §2.7 and §3 from design to code: `graph/harness/{constraint_validator,auto_repair,session_manager,memory_manager}.py`. The constraint validator's repair loop is independent of auto-repair (no retry storm); semaphores use the self-healing ZSET-token pattern; memory persists only escalated + high-popularity-benign records with max-wins/anomaly-flagging. The stores themselves (a live Redis/PGVector deployment) and the FastAPI entrypoints remain the last ⛔ items. Builds on v2.4 (BYOK).

> **v2.4 (BYOK).** All hosted-model services are now **bring-your-own-key**: the caller supplies the reasoning-LLM key and (when memory is on) the embedding key per invocation; depaudit holds no server-side/ambient key. Keys are `SecretStr`, threaded via injection only, and **never enter `AuditState`** (which is checkpointed to Redis), logs, or PGVector. Landed: `credentials.py`, `graph/llm_client.py` (concrete BYOK Claude client), `memory/embedding_client.py` (BYOK seam). See §3.5. Builds on v2.3's harness/memory design.

> **v2.3 (design sync).** The Harness Layer (§2.7) is expanded from three bullets into four specified components, adding a **Memory Manager** (§2.7.4) as the single read/write point for the §3 stores. The memory read/write paths, embedding source, and GC strategy are now pinned: embeddings come from an **external provider API (BYOK, see §3.5)** (Voyage AI for the Claude stack — Anthropic has no first-party embeddings endpoint — kept provider-swappable, §3.2); long-term GC runs as a **Kubernetes CronJob** (§3.4). These are **design-level** decisions; the harness and memory modules remain ⛔ unimplemented (§0.1). Builds on v2.2's landed agent-layer code (state, router, spine, specialists, scorer).

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
| BYOK credentials + LLM client | `credentials.py`, `graph/llm_client.py` | ✅ implemented, unit-tested (§3.5) |
| Harness (validator / auto-repair / session / memory-mgr) | `graph/harness/` | ✅ implemented, unit-tested (§2.7) |
| Memory Manager (read/write logic) | `graph/harness/memory_manager.py` | ✅ implemented, unit-tested (§2.7.4) |
| Graph assembly + `run()` seam | `graph/build.py` | ✅ implemented, unit-tested (§6.1.4) |
| Memory store clients (Redis + PGVector) | `memory/short_term.py`, `memory/long_term.py` | ✅ implemented, unit-tested (§3.1, §3.2); consumed by MemoryManager via injection |
| Live store deployment (Redis/Postgres instance, checkpointer schema, pgvector index) | infra | ⛔ deployment wiring only, not logic |
| Embedding client (BYOK seam) | `memory/embedding_client.py` | ◑ seam built; called by MemoryManager |
| Entrypoints (FastAPI `api.py` + `cli.py`) | `entrypoints/` | ✅ implemented (api unit-tested via `run()` seam) |
| Reporter (SARIF / Markdown / JSON) | `reporter/` | ✅ implemented, unit-tested (§6, §7) |

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

Four cross-cutting wrappers sit between the graph nodes and the outside world. None of them make audit decisions — they enforce the invariants the rest of this doc assumes. All live under `graph/harness/`. **Wrapping order is fixed** — `auto_repair(outer) → constraint_validated(inner)` — so a semantic rejection can never masquerade as an infrastructure fault (see §2.7.2).

#### 2.7.1 Constraint Validator (`constraint_validator.py`) *(implemented)*
Wraps every LLM node. Two layers, because a prompt constraint is not an enforcement mechanism:
- **Schema layer** — the §4.2 output is parsed into the `LLMOutput` Pydantic model; missing fields, out-of-range `confidence`, or an illegal `verdict` are rejected before anything reaches shared state.
- **Semantic layer** — the checks the schema can't express: every `evidence` ref must resolve to a real entry in the run's evidence log (blocks hallucinated citations), and the resulting fused signal is compared against the dimension's current baseline — any attempt to *lower* it is rejected outright. This is §4.3's escalate-only rule enforced in code, not trusted to the model.

Malformed output is retried with a repair prompt carrying the specific violation. This retry counter is **independent** of the auto-repair counter (§2.7.2). On exhaustion the node's contribution is marked `degraded` and a `coverage_gap` note is written, so the scorer *knows a dimension went unanalysed* rather than silently seeing no signal for it. *(Impl: the `coverage_gap` note reuses the `degraded_notes` channel with a `coverage_gap:` prefix; the scorer's existing "escalated dep with no LLM signal" check (§2.4) already treats it as incomplete. Evidence-ref resolution is path-based: a citation naming a file absent from the gathered bundle is rejected; a paraphrase with no path token is allowed. The escalate-only semantic check is defense-in-depth — under additive+max-wins (§2.6) a clean LLM verdict never lowers a dimension, so the check only fires if that reducer invariant is ever broken.)*

#### 2.7.2 Auto-repair (`auto_repair.py`) *(implemented)*
Wraps the deterministic spine tools, the `deep_analysis_tool.py` primitives, and the *outer* (infrastructure) boundary of LLM nodes. Handles **transient** faults only — timeouts, rate-limit responses, connection resets — with bounded retry + exponential backoff and jitter (v1 §6.2).

The division of labour with §2.7.1 is the load-bearing detail: the inner constraint-validated wrapper, on exhaustion, **returns a `degraded` result rather than raising**. So auto-repair never sees a semantic failure and never retries one — otherwise the two layers' retry budgets multiply into a retry storm. On its *own* exhaustion, auto-repair marks the node `degraded` and the run continues (§8, graceful degradation).

#### 2.7.3 Session Manager (`session_manager.py`) *(implemented)*
- Assigns each run a **ULID** `run_id` — lexicographically sortable, so Redis and PGVector keys range-query and GC by time without a separate index.
- Holds the §5.2 distributed semaphores as a Redis **ZSET token** pattern, not a raw INCR/DECR counter: acquire = `ZADD run_id→expiry_ts`; the live holder count is `ZCARD` taken *after* a `ZREMRANGEBYSCORE` sweep of expired tokens. This self-heals when a worker dies mid-run — a leaked slot ages out on its own instead of pinning the semaphore for every later run.
- Two semaphore classes: `sem:llm_budget:{run_id}` (a hard cross-branch cap that backstops the §5.3 `sum_deltas` counter — the reducer does the in-graph logic, the semaphore stops parallel branches racing past the ceiling) and `sem:fanout_width:{run_id}` (caps concurrent specialist fan-out so one large repo can't open dozens of simultaneous LLM connections and trip external rate limits).
- Release runs in a `finally`; a key TTL slightly longer than the worst-case run time is the backstop if release itself fails.

#### 2.7.4 Memory Manager (`memory_manager.py`) *(implemented)*
The stores in §3 *hold* memory; this component is the **only** code allowed to read or write them, so the §3.3 safety boundary is enforced in one place instead of being re-litigated inside three specialists.

**Read path** — a decorator peer to `constraint_validated`, run before a specialist executes:
- Pulls the exact-hash hot record from Redis and the top-*k* behaviourally-similar records from PGVector, packaged as an **immutable `MemoryContext` snapshot**.
- That snapshot is injected into the specialist's prompt as *"prior findings"* only. It is **never** merged into `AuditState.signals`. If a specialist agrees with a retrieved finding it must re-derive it from *current* evidence and emit its own signal with its own `evidence` refs — **forced re-attestation**. This is the concrete mechanism behind §3.3: a poisoned `clean` record in PGVector still has to clear the §2.7.1 evidence check, which it cannot, so it can never buy a downgrade.

**Write path** — a single call at the tail of `report_agent`, after the gate decision exists (never mid-run, never from a specialist — that would race under fan-out):
- Upsert keyed by artifact identity (`package@version+hash`). On collision, severity resolves **max-wins** — the same reducer semantics as §2.6, lifted from "parallel branches within one run" to "the same immutable hash across historical runs". Because the hash is immutable, a verdict's severity should only ever *rise* across runs; a *decrease* is treated as an anomaly (bug or hash collision) and flagged, not silently written.
- **Write scope is deliberately narrow**: persist (a) anything ever escalated, and (b) clean confirmations for high-popularity packages. Long-tail first-seen clean results are *not* cached — they add little retrieval value and widen the surface for an attacker to seed a "looks-clean" record.

**Embedding and GC** are external dependencies — configured, not vendored. See §3.2 (embedding provider) and §3.4 (retention / CronJob).

---

## 3. Memory System

### 3.1 Short-Term Memory — Redis *(implemented: `memory/short_term.py`)*
- LangGraph checkpointer backend: mid-run state survives node retries and enables resume. `ShortTermStore.checkpointer()` returns a `RedisSaver` bound to the same instance (lazy import).
- Hot cache for in-flight tool results (replaces v1 L1) and cross-run cheap-signal reuse on the same repo/branch, TTL 7 days (v1 L2) — `cache_get`/`cache_set` under a `cache:` namespace.
- Distributed semaphore store (§5.2).

`ShortTermStore` is a thin, injectable wrapper: it exposes the JSON-friendly `get`/`set` the MemoryManager uses and passes the SessionManager's ZSET semaphore primitives (`zadd`/`zremrangebyscore`/`zcard`/`zrem`/`pexpire`) straight through to the wrapped client, so it is *the* single object injected as `redis=` to both consumers — no node imports a raw client (§6.1.6). `from_url` builds the real redis-py client lazily.

Note: within a single graph run, parallel specialists synchronize via LangGraph fan-in (§2.6), **not** via Redis pub/sub. Redis holds state and rate limits; it is not a message bus between nodes.

### 3.2 Long-Term Memory — PGVector *(implemented: `memory/long_term.py`)*
- Stores embeddings of: finalized verdicts per `package@version+hash`, LLM evidence/reasoning text, allowlist entries, and known-attack fingerprints (e.g. XZ-Utils-style patterns). `PGVectorStore` exposes `query_similar`/`upsert`/`get`/`gc` plus an idempotent `ensure_schema()`; vectors are written as `::vector` literals over a plain DB-API connection (no adapter registration), and `upsert` carries a defense-in-depth `GREATEST(...)` max-wins so a cross-process race on the same immutable hash can't lower a stored severity (§2.7.4). The connection is injected (`connect` factory), so it unit-tests against a fake; `from_dsn` builds the real psycopg one lazily.
- Used purely as **retrieval context**: before a Stage-4 specialist runs, PGVector is queried for prior or behaviorally-similar findings and those are supplied as few-shot context. This cuts redundant deep analysis (cost) and grounds the LLM in prior evidence.
- Replaces v1's L3 (S3/Redis team cache). PGVector is now the canonical long-term store; Redis stays hot/short-term only.
- **Embeddings are produced by an external provider API, not by depaudit.** The LLM provider (Claude) has *no* first-party embeddings endpoint, so the embedding model is a **separate service with a separate, user-supplied key (BYOK, §3.5)**. Base URL and model stay configurable per deployment (`EMBEDDING_BASE_URL` / `EMBEDDING_MODEL` may set non-secret defaults), but the **key itself is caller-supplied and never server-stored**. For the Claude stack this defaults to **Voyage AI** (Anthropic's recommended partner); a base URL leaves it provider-swappable (OpenAI / Google / Cohere) with no code change. The wrapper lives in `memory/embedding_client.py` and is called *only* by the Memory Manager (§2.7.4). Vector **dimensionality follows from the chosen model and fixes the PGVector column width**, so it must be pinned per deployment — changing embedding model means a re-index, not a hot swap.

### 3.3 Memory Safety Boundary (iron rule, extended)
- Retrieved memory may **inform** LLM reasoning; it may **never** downgrade the current run's severity. A prior `clean` verdict on the same hash is evidence, not an override — because memory is another attacker-poisonable input channel, subject to the same "escalate-only" invariant as §2.5 and §4.3.
- Long-term writes happen **only after** `ReportAgent` finalizes a run. No unverified in-flight signal is ever persisted.
- **Both halves of this rule are enforced by the Memory Manager (§2.7.4)**, which is the sole reader and writer of Redis/PGVector. No specialist imports a store client; read access is only ever the injected read-only `MemoryContext`, and the single write point is the tail of `report_agent`. Centralising the stores behind one component is what makes "memory can only escalate" a checkable property rather than a convention scattered across nodes.

### 3.4 Retention & Garbage Collection
- **Redis** — TTL-based, already covered (§3.1); no separate job.
- **PGVector** — differentiated retention: escalated records and known-attack fingerprints are kept indefinitely (their value as a fingerprint library *grows* with time); low-confidence clean records expire on a cycle to keep the index from growing without bound. This mirrors the narrow write scope of §2.7.4 — the store is a threat-intelligence asset, not an audit log.
- **GC runs as a Kubernetes CronJob**, outside any audit run: a scheduled `depaudit gc` invocation, never triggered by a graph node. Keeping it external preserves §1.3 (every audit run stays finite; maintenance is its own separate finite job) and makes GC cadence an ops concern, tunable without touching the harness. The entry point is a thin `gc` subcommand in `entrypoints/cli.py` that the CronJob calls.

### 3.5 Credentials — Bring-Your-Own-Key (BYOK) *(implemented: `credentials.py`, `graph/llm_client.py`, `memory/embedding_client.py`)*

Every hosted-model service depaudit calls — the reasoning **LLM** (Claude, used by specialists) and the **embedding** provider (Voyage/compatible, used only by the Memory Manager) — is keyed by the **caller**, not by the depaudit deployment. There is **no server-side or ambient key**; a missing key is a hard error (`MissingCredentialError`), never a silent fall-through to a shared account.

Intake, one bundle two paths (`UserCredentials`):
- **API path** (`query`/`audit` over HTTP) — keys arrive in the request; `UserCredentials.from_request(...)`.
- **CLI / CI path** — keys come from the *caller's own* environment (`DEPAUDIT_LLM_API_KEY`, optionally `DEPAUDIT_EMBEDDING_API_KEY`, plus non-secret `_BASE_URL`/`_MODEL`); `UserCredentials.from_env(...)`. This is still BYOK: the key belongs to whoever runs depaudit.

The embedding key is optional and only required when the memory layer is enabled for the run.

Security invariants (depaudit is a security tool — these are load-bearing):
1. Keys are `SecretStr`: absent from reprs, logs, tracebacks, and `model_dump()`/`model_dump_json()`.
2. **Keys never enter `AuditState`**, which is checkpointed to Redis (§3.1) — that would persist a user secret. Credentials travel out of band via injected deps (`build_specialist_deps`) and LangGraph `configurable`, never through a state channel. This is *why* the specialist `LLMClient` was designed as an injected seam (§2.3) rather than a state field.
3. Keys are never written to PGVector or any report artifact.
4. The Anthropic/embedding client is constructed **per `UserCredentials`**, so concurrent runs never share a key or an account. A `base_url` on either credential routes through a proxy/gateway/Bedrock-compatible endpoint without code change.

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

The v1 Stages 0–3 already live under `tools/` split into two frozen sub-packages — `index/` (discovery + normalize + ecosystem adapters) and `scan/` (signal collectors). Stage 4 adds a peer module, `deep_analysis_tool.py`. The agent layer is a new top-level `graph/`. Legend: ✅ built · ◑ partial (seam built, backing store pending) · ⛔ pending.

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
│   ├── single_pkg.py                 # ✅ single-package entry node → shared spine (§2.2-A)
│   ├── spine.py                      # ✅ fixed Stage 0→3 sequence + post-Stage-3 gate (§2.2-B)
│   ├── specialists/                  # ✅ base.py + identity_agent.py, behavior_agent.py, provenance_agent.py
│   │                                 #    (no popularity/vulnerability agent — §2.3)
│   ├── llm_client.py                 # ✅ concrete BYOK Claude client (§3.5)
│   ├── report_agent.py               # ✅ terminal reducer == scorer, sole decision writer (§2.4)
│   ├── build.py                      # ✅ graph assembly + run() seam both entrypoints call (§6.1.4)
│   └── harness/                      # ✅ constraint_validator.py, auto_repair.py,
│                                     #    session_manager.py, memory_manager.py (§2.7)
├── memory/                           # ✅ short_term.py (ShortTermStore/Redis, §3.1),
│                                     #    long_term.py (PGVectorStore, §3.2/§3.4),
│                                     #    embedding_client.py (BYOK seam, §3.2/§3.5).
│                                     #    All injected into MemoryManager; live store = infra (⛔)
├── entrypoints/                      # ✅ api.py (FastAPI: audit + query + webhook),
│                                     #    cli.py (audit | query | gc — gc = PGVector CronJob, §3.4)
├── reporter/                         # ✅ SARIF / Markdown / JSON — build_report + 3 pure renderers (§6, §7)
└── credentials.py                    # ✅ BYOK credentials for LLM + embedding services (§3.5)
```

Naming note: the `*_agent.py` specialists and `report_agent.py` are graph nodes, not autonomous agents in the swarm sense; `report_agent` runs no LLM at all (§2.4).

### 6.1 Structural Invariants
1. **Only `graph/report_agent.py` (or the single-agent reducer) writes the gate decision** — enforced today by the `write_once` reducer on `AuditState.gate_decision` (v2 form of v1 §5.1.4).
2. **`tools/` stays LLM-free — including `tools/deep_analysis_tool.py`.** If a stage needs LLM judgment it belongs in `graph/specialists/`, never in `tools/`. `deep_analysis_tool.py` provides deterministic primitives (clone, diff, extract) and returns evidence bundles with **no verdict/score field**; the *reasoning* lives in the specialist node.
3. **Adding an ecosystem still means one adapter under `tools/index/ecosystems/`**, untouched by the agent layer (v1 §5.1).
4. **The graph is the core; `entrypoints/` are thin.** CLI and API both call `graph.build.run(request)`; neither contains audit logic and the CLI does not shell out to the HTTP server.
5. **v1 layering preserved:** `tools/scan/signals/` and `graph/specialists/` receive standardized `Dependency` objects and never import `tools/index/ecosystems/`; adapters never judge (v1 §5.1.1–.2).
6. **Redis and PGVector have exactly one reader/writer: the Memory Manager (§2.7.4).** No node imports a store or embedding client directly; specialists see memory only as an injected read-only `MemoryContext`, and long-term persistence happens at exactly one point (tail of `report_agent`). This is the structural form of the §3.3 escalate-only-memory rule.
7. **BYOK keys are injected, never state.** No credential ever appears in `AuditState`, a state channel, a log line, a degraded note, or a persisted artifact. The LLM key reaches specialists only through `build_specialist_deps` (injection); the embedding key reaches only the Memory Manager. This is what keeps user secrets out of the Redis checkpoint (§3.5).

---

## 7. Tech Stack (v2)

| Layer | Choice | Rationale |
|---|---|---|
| API | FastAPI | Async, typed models, serves `audit` + `query` |
| Orchestration | LangGraph | Explicit state machine; native fan-out/fan-in; checkpointing |
| Tool/chain wrapping | LangChain | `@tool` wrapping of Stages 0–3; structured-output parsers |
| Short-term memory | Redis | Checkpointer, distributed semaphores, hot cache (v1 L1/L2) |
| Long-term memory | PGVector | Verdict/evidence/attack-fingerprint embeddings (v1 L3) |
| Embeddings | Voyage AI (configurable) | Separate provider, **BYOK key** (§3.5); Claude has no embeddings endpoint (§3.2) |
| LLM | Claude API | Structured output + prompt caching; **BYOK key** per caller (§3.5) |
| Credentials | BYOK (`SecretStr`) | Caller-supplied per invocation; never in state/logs/PGVector (§3.5) |
| Scheduled maintenance | Kubernetes CronJob | PGVector GC as an external finite job — `depaudit gc` (§3.4) |
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

Resolved at design level in v2.3 (specified, not yet coded):
- [x] Harness Layer components — four wrappers specified (§2.7); the **Memory Manager** (§2.7.4) is the single read/write point enforcing §3.3.
- [x] Embedding source — **external provider API, BYOK key** (§3.5) (Voyage AI for the Claude stack; base-URL/model configurable, §3.2). Dimensionality pins to the chosen model.
- [x] Long-term store GC — **Kubernetes CronJob** invoking `depaudit gc`, external to audit runs (§3.4).

Resolved in v2.4 (coded):
- [x] Credentials model — **BYOK** for all hosted-model services (`credentials.py`, `graph/llm_client.py`, `memory/embedding_client.py`, §3.5); keys are `SecretStr`, injected, never in `AuditState`/logs/PGVector, no ambient fallback.

Resolved in v2.5 (coded):
- [x] Harness Layer — all four components implemented and unit-tested (§2.7): constraint validator (schema+semantic, independent repair loop), auto-repair (transient-only, no retry storm), session manager (ULID + self-healing ZSET semaphores), memory manager (§2.7.4).
- [x] Memory read/write paths — implemented (`graph/harness/memory_manager.py`): immutable `MemoryContext` (prompt-only), single write at `report_agent` tail, max-wins + severity-decrease anomaly flagging, narrow write scope.

Resolved in v2.6 (coded):
- [x] Store *clients* — `memory/short_term.py` (`ShortTermStore`, Redis) and `memory/long_term.py` (`PGVectorStore`) implemented and unit-tested; injected into the MemoryManager/SessionManager, lazily importing the optional `memory` extra. `MemoryManager.gc()` delegates to the vector store, wiring `depaudit gc` (§3.4) end-to-end.

Still open:
- [ ] Post-Stage-3 gate threshold *values* — the gate mechanism has shipped (`graph/spine.py`: `plan_gate` + `GateConfig` with `gray_floor`/`decided_ceiling`/`llm_dimensions`, §2.2-B); the concrete gray-zone floor is a default (`MEDIUM`) still to be tuned against the §5.1 5–10% trigger-rate target
- [ ] Concrete hard cap *value* for LLM calls per run — mechanism and enforcement have shipped (`sum_deltas` + `would_exceed_cap`, enforced deterministically in `plan_gate`, §5.3); only the numeric ceiling is TBD
- [ ] Live store deployment — a running Redis + Postgres/PGVector instance, LangGraph checkpointer schema (keying, TTL, eviction), and running `ensure_schema()` for the pgvector table + index. The store *clients* have shipped (§3.1, §3.2); this is the last piece and is deployment wiring, not logic
- [ ] Concrete embedding *model* (e.g. `voyage-3-large` vs a cheaper tier) and the similarity threshold for "behaviourally similar" — the *source* is settled (§3.2); the specific model and cutoff are tuning choices, and the model choice also fixes the PGVector column dimensionality
- [ ] Auth model for the `query` route (new attack surface)
- [ ] Agent-control-flow injection tests (§2.5) — adversarial metadata attempting to induce early termination
- [ ] Prompt-injection defense for specialists (carried from v1)
- [ ] Monorepo / multi-config-file support (carried from v1)
- [ ] End-to-end walkthrough vs. XZ Utils / event-stream / PyTorch dependency confusion (carried from v1)

---

*Living document. Significant architectural changes must be reflected here and pass review.*