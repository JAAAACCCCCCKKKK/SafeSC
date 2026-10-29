# CLAUDE.md — SafeSC Project Development Rules (v3.0: Strands Agents)

> **v3.0 (refactor onto Strands Agents).** The LangGraph state machine, the Redis/PGVector
> memory tiers, the separate `audit`/`query`/`gc`/`store`/`fingerprint` subcommands, the
> standalone `index`/`scan` CLIs and the `agent`/`anthropic`/`openai`/`memory` extras are
> gone. SafeSC is now one install (`pip install safesc`), one command (`safesc`), and one
> use case: an **orchestrator agent** (Strands `Agent`, model + harness) drives the run by
> calling tools — the four static stages, read-only views, **six subagents** exposed as
> tools (agents-as-tools), and `finalize_score`, which runs the deterministic scorer once.
> Every run **requires** an LLM (`LLM_PROVIDER` / `LLM_MODEL` / `LLM_API_KEY`, validated in
> a fixed order before anything starts) and **memory** (a local directory; Strands
> `MemoryManager`, no service, no second key). Two new subagent capabilities extend scope:
> **authorship verification** (code-style analysis against account takeover) and
> **unreported-vulnerability hunting** with **independent verification**.
>
> The governing idea is unchanged from v2: **the agent layer changes how work is scheduled,
> not how decisions are made.** Static stages are now *invoked* by an agent, but an agent
> still cannot skip, redirect or reorder them, cannot finalize early, and cannot write a
> severity. Every iron rule below survives; §2.5 explains how each is now enforced.

---

## 0. Migration Note (v2 → v3)

| Aspect | v2 (LangGraph) | v3 (Strands) |
|---|---|---|
| Install | `pip install "safesc[agent,anthropic,memory]"` | `pip install safesc` — all providers, one install |
| Entry | `safesc audit\|query\|gc\|store\|fingerprint`, `index`, `scan` | `safesc [target] [--with …] [flags]` |
| Target | explicit, `.` default | cwd interactively, repo root in CI (`core/targets.py`) |
| Static stages | fixed graph nodes (spine) | agent-only tools with hard ordering (`agents/tools/pipeline.py`) |
| Orchestration | compiled state graph, deterministic fan-out | orchestrator agent + steering guard + GoalLoop |
| Stage 4 | one LLM call per (dep, dimension) | subagents with their own tool loop, structured output, repair |
| LLM config | `SAFESC_LLM_*`, optional | `LLM_PROVIDER`/`LLM_MODEL`/`LLM_API_KEY`, required, validated |
| Memory | optional Redis + PGVector + embedding key | required, local files, Strands MemoryManager, no key |
| State | `AuditState` + Annotated reducers | `RunLedger` (thread-safe, same merge rules) |
| Scorer | `report_agent` node | `core/scoring.py`, triggered once by `finalize_score` |
| New analyses | — | authorship, vuln hunter + verifier |

### 0.1 Build Status

| Component | Location | Status |
|---|---|---|
| Stages 0–3 library (index + scan) | `safesc/tools/index/`, `safesc/tools/scan/` | ✅ v1, frozen (library only, no entrypoint) |
| Stage-4 evidence primitives | `safesc/tools/deep_analysis_tool.py` | ✅ |
| Source fetching / risky-pattern scan / stylometry | `safesc/tools/{source,vulnscan,authorship}.py` | ✅ new, LLM-free |
| Deterministic core (signals, ledger, gate, scorer, targets) | `safesc/core/` | ✅ |
| LLM configuration + validation | `safesc/config/llm.py` | ✅ (all 11 Strands API-key providers) |
| Memory (verdict store, known-attack store, manager) | `safesc/memory/` | ✅ |
| Agent tools (pipeline, views, evidence, external, scoring) | `safesc/agents/tools/` | ✅ |
| Harness (steering guard, validation, progress) | `safesc/agents/harness/` | ✅ |
| Six subagents | `safesc/agents/specialists/` | ✅ |
| Orchestrator + `run_audit` | `safesc/agents/orchestrator.py` | ✅ |
| CLI | `safesc/cli.py` | ✅ |
| Reporter (SARIF / Markdown / JSON) | `safesc/reporter/` | ✅ (schema 2.0) |

---

## 1. Project Scope and Boundaries

### 1.1 Goal
Discover dependency lockfiles, evaluate every dependency across five trust dimensions,
investigate suspicious ones with LLM subagents (including account-takeover authorship
analysis and unreported-vulnerability hunting), and produce **one deterministic score per
run** that can gate CI. The agent reasons about *what to investigate*, never *what the
verdict is*.

### 1.2 Differentiation
Reuse OSV.dev and the registries for known facts; SafeSC's value is multi-dimensional
trust scoring, LLM intent analysis, authorship verification and hidden-vulnerability
discovery. Reuse Strands Agents instead of a bespoke agent runtime.

### 1.3 Hard Scope Constraints
- **One use case, finite.** A run is triggered (CLI or CI), audits one target, exits with
  0 (pass) / 1 (gate failed) / 2 (configuration error or no verdict). No daemon, no
  persistent monitor. A hosted HTTP API is out of scope for this repo.
- **LLM and memory are mandatory.** No run starts without a validated model (§3.5) and a
  writable memory directory (§3).
- **Complementary features are flags**, chiefly `--with authorship|vuln-hunt|transitive|github|all`.
- **Bounded autonomy**: agents choose which subagents to call beyond the required set, in
  what order, with what focus. They may not skip/reorder/redirect the static stages,
  finalize early, finalize twice, or write a severity (§2.5).
- **Multi-language, plugin-based ecosystems**; first-release priority unchanged:
  Python → npm/pnpm → Cargo → Go → Maven/Gradle.

---

## 2. Architecture: Deterministic Core, Agentic Scheduling

### 2.1 Static Stages as Agent-Only Tools

| Tool | Stage | LLM? | Writes to the ledger |
|---|---|---|---|
| `discover_lockfiles` | 0 | no | lockfile refs |
| `parse_dependencies` | 1 | no | `Dependency[]` (+ empty-lockfile coverage gaps) |
| `verify_hashes` | 2 | no | provenance signals |
| `collect_signals` | 3 | no | static signals, all five dimensions (+ degraded-collector gaps) |

The implementations stay in `safesc/tools/` — pure, idempotent, LLM-free (v1 §4.4's
"forbidden for LLM" list). **They are invoked only by agents**: no entrypoint imports
them; only `agents/tools/pipeline.py` does (pinned by `tests/test_invariants.py`). The
tools take **no target argument** — the target is fixed in `RunOptions` before any agent
starts — and each refuses to run before its predecessor. They return compact summaries;
full results stay in the ledger.

**Excluding paths**: `discover()` auto-loads `.safescignore` (gitignore syntax via
`pathspec`) from the scanned root, plus `--exclude` patterns baked into `RunOptions`.
`collect_signals` notes degraded collectors (a collector that could not answer is not a
clean result) except popularity, whose anonymous GitHub limits are routine.

### 2.2 The Two Routing Decisions (kept distinct on purpose)

**(A) Target — known at start, no risk involved** (`core/targets.py`). No argument:
the current directory interactively, the repository root in CI (`GITHUB_WORKSPACE` /
`CI_PROJECT_DIR` / `BUILD_SOURCESDIRECTORY` / git top-level; CI detected from the
standard env markers). Then a rule-based, risk-free classification: path / lockfile →
repository; package spec (`npm:x@1`, `pkg:pypi/x@1`, `@scope/x@1`) → single package.

**(B) Risk gate — known only after Stage 3** (`core/gate.py`). `plan_triage` lists every
(dep, dimension) whose *static* severity on identity/behavior/provenance is in the gray
band `[gray_floor=MEDIUM, decided_ceiling=CRITICAL)`. These, plus the `--with` features
(authorship / vuln-hunt on direct deps, or all deps with `transitive`) and every pending
vulnerability candidate, form the ledger's **required coverage**. `finalize_score` is
refused until each required item has been attempted (ok, degraded or denied) or the
subagent budget is spent; what remains is reported as incomplete.

### 2.3 Subagents (`agents/specialists/`)

Agents-as-tools (Strands lesson 10): each call builds a fresh `Agent` with its own context,
model client, the shared evidence toolbox, read-only memory (injection + recall) and a
structured output model. The tool's description is the orchestrator's routing logic.

| Tool | Role | Output | Lands on |
|---|---|---|---|
| `identity_analyst` | squat vs legitimate; coercive docs | `LLMOutput` | identity |
| `behavior_analyst` | install-time / obfuscated code intent | `LLMOutput` | behavior |
| `provenance_analyst` | artifact-vs-source, commit consistency | `LLMOutput` | provenance |
| `authorship_analyst` | was the release written by its maintainers? (account takeover) | `LLMOutput` | identity |
| `vuln_hunter` | unreported vulnerabilities in the dep's own source | `HuntReport` (candidates) | — (candidates only) |
| `vuln_verifier` | independently confirm/refute every pending candidate | `VerificationReport` | vulnerability (or behavior for a backdoor) |

There is still **no popularity agent and no CVE agent**: popularity and known-advisory
matching stay fully deterministic. Every subagent is a **signal producer**; none decides.

### 2.4 The Scorer Is the Only Decision Point

`core/scoring.py:score(ledger)` is the only code that computes a verdict; `finalize_score`
is the only code that writes one (`RunLedger.finalize`, write-once — pinned by
`tests/test_invariants.py`). Rules: per-dep severity = max over its signals (weakest-link);
gate fails at `--fail-on` (default HIGH); trust score = 100 − Σ penalty(LOW 1, MEDIUM 4,
HIGH 15, CRITICAL 40), capped at 59 by any HIGH, 19 by any CRITICAL, 89 when incomplete;
grade A≥90 B≥75 C≥60 D≥40 else F; `--strict` turns incompleteness into failure.

### 2.5 Why Bounded Autonomy Is a Security Property

Threat: crafted package metadata steers the agent's control flow — skip hash
verification, scan a decoy path, stop before analysis, or finalize a pass early. v2
removed the choice entirely (a fixed graph). v3 lets the orchestrator *call* the stages,
so each escape route is closed structurally instead:

| Attack | Why it fails |
|---|---|
| skip a stage | `finalize_score` refuses without all four; no finalize = no verdict = exit 2 |
| reorder / repeat | each tool refuses out-of-order calls; the guard refuses repeats |
| redirect the scan | stage tools take no target argument |
| stop before analysing gray-zone deps | required coverage blocks finalize |
| stop early overall | `GoalLoop` re-prompts; if still unfinished the run fails closed (exit 2) |
| finalize twice / overwrite | write-once ledger; guard and tool both refuse |
| talk a subagent into "clean" | LLM verdicts can only add signals; the ledger keeps the higher per identity |
| cite fabricated evidence | citations validated against what tools showed; failure = coverage gap |
| poison memory | memory is prompt-only context, never merged into signals; agents cannot write it |
| run the payload | no agent has a shell / REPL / write tool; source is read-only and confined |

At worst the orchestrator skips *optional* exploration, which can only lose an escalation.
All three LLM/agent input channels — subagent verdicts, memory, control flow — share one
invariant: **they can raise severity, never lower it**, and a failure to finish is never a
pass.

### 2.6 Shared State — `RunLedger` (`core/ledger.py`)

The sole channel between agents; never shown to a model whole (tools return summaries).
Thread-safe (Strands runs one turn's tool calls concurrently). Merge rules:
- **signals**: additive, dedup by `(dep_key, source, dimension)`, **max-wins** on collision
  (retries idempotent; a later "clean" never clears a finding);
- **stages**: monotonic; **decision**: write-once;
- **budget**: consumed per subagent invocation, never returned;
- **citable evidence**: per dep, everything a tool showed (+ fetched workspace files);
- **candidates**: hunter claims, resolved only by the verifier.

### 2.7 Harness (`agents/harness/`, Strands lessons 5–7)

- **`PipelineGuard`** (deterministic `SteeringHandler`): blocks with `Guide` + reason any
  out-of-order / repeated stage, any subagent before Stage 3 or on an unknown dep, a
  verifier without candidates, and a premature or second finalize. The tools enforce the
  same rules themselves, so a misconfigured guard still cannot be bypassed.
- **`GoalLoop`** on the orchestrator: validator = "a decision exists"; up to 3 attempts.
- **Budget gate** (inside every subagent tool): one unit per invocation, taken before the
  agent is built; denial **fails closed** (analysis lost, run incomplete).
- **Validation + repair** (`validation.py`): schema by structured output; semantics here —
  file citations must resolve, hunter files must exist, verifier must cover exactly the
  pending candidates. Up to 2 repairs, independent of infrastructure retries; exhaustion
  → `coverage_gap` note, no signal.
- **`ReadOnlySourceGuard`** (hook): `read_source` (vended `file_editor`) may only `view`,
  only inside a fetched workspace.
- **`ProgressHook`**: one stderr line per tool call; all agents run with
  `callback_handler=None`.
- Every agent uses `context_manager="auto"` (offload large results, summarize, compress at
  85%); `LLM_CONTEXT_WINDOW` makes the 85% real.

---

## 3. Memory System (required) — `memory/`

- **Location**: `--memory-dir` / `SAFESC_MEMORY_DIR` / user cache dir. In CI the action
  carries it between runs with `actions/cache`. Unwritable → `MemoryInitError`, exit 2.
- **Stores** (Strands `MemoryStore`s, keyword search, no embeddings, no key):
  - `VerdictStore` — one record per artifact identity `ecosystem:name@version[+hash]`,
    **max-wins** (a lower write keeps the stored severity and is reported as an anomaly);
  - `KnownAttackStore` — the curated corpus in `fingerprints/*.yaml` (version-controlled,
    force-included in the wheel), loaded read-only at start. **No run can add one.**
- **Read path**: `SafeSCMemory.manager()` builds a Strands `MemoryManager` with the
  `recall_prior_findings` tool and prompt injection (subagents), **never an add tool**.
  Injected text is labelled (`prior verdict` vs `known-attack pattern`) and banners that it
  is context only.
- **Write path**: `SafeSCMemory.persist(ledger)` once, after the decision exists. Narrow
  scope: dependencies ≥ MEDIUM, plus clean confirmations whose popularity was checked and
  found benign. Long-tail first-seen clean results are not kept.

### 3.3 Memory Safety Boundary (iron rule)
Retrieved memory may **inform**; it may **never downgrade**. It is never merged into
signals; agreeing with it still requires citing current evidence (§2.7 validation).
Writes happen only after scoring, by one owner (`memory/manager.py`; pinned by
`tests/test_invariants.py`).

### 3.4 Retention
Local files, no expiry yet. Deleting the memory directory is always safe (memory can only
escalate). A size/age policy is an open item (§9).

### 3.5 LLM Configuration (BYOK) — `config/llm.py`

Required: `LLM_PROVIDER`, `LLM_MODEL`, `LLM_API_KEY`; optional `LLM_BASE_URL`,
`LLM_CONTEXT_WINDOW`. Providers: every Strands model that authenticates with an API key —
`anthropic, openai, openai_responses, bedrock (API key), gemini, mistral, litellm,
llamaapi (deprecated upstream), ollama, llamacpp, writer`. SageMaker is excluded (SigV4,
no API key). Validation order, each with its own error class and exit 2:
1. presence (`MissingLLMConfigError`) → 2. provider legal (`UnsupportedProviderError`) →
3. model belongs to provider, per-provider rule with a cross-family hint
(`ModelProviderMismatchError`) → 4. endpoint reachable (+ Ollama model pulled)
(`ModelUnreachableError`) → 5. one minimal authenticated generation through the exact
Strands client; failures classified as bad key (`InvalidAPIKeyError`) / unavailable model /
unreachable host; throttling counts as accepted.

Invariants: the key is a `SecretStr`, absent from reprs, scrubbed from every error, never
in the ledger, memory, logs or reports. One model client per agent.

---

## 4. LLM Usage Constraints

### 4.1 Role — the LLM produces evidence, not decisions (enforced by construction, §2.4).

### 4.2 Mandatory Structured Output — Strands `structured_output_model`:
`LLMOutput {task, verdict: clean|suspicious|malicious, confidence 0–1, evidence[],
reasoning, false_positive_hints[]}`; `HuntReport {candidates ≤10, summary}`;
`VerificationReport {results[candidate_id, status, severity, intentional_backdoor,
confidence, evidence, advisory_ids, reasoning]}`.

### 4.3 Fusion (unchanged table, one deterministic extension)

| LLM verdict | confidence | Adjustment |
|---|---|---|
| malicious | ≥ 0.7 | CRITICAL |
| malicious | 0.4–0.7 | HIGH |
| suspicious | ≥ 0.7 | HIGH |
| suspicious | < 0.7 | LOW (evidence only) |
| clean | any | CLEAN (contributes nothing) |

Extension: a **verified** vulnerability fuses as `suspicious` at the verifier's confidence,
**capped by its assessed impact** (`ceiling`: low→LOW … critical→CRITICAL), so a confirmed
low-impact flaw can never fail a gate; an intentional backdoor fuses as `malicious` on
behavior. Hunter candidates contribute nothing until verified.
**Iron rule:** LLM signals and memory may only escalate, never downgrade.

### 4.4 Task Scope
LLM-suitable: install-script intent, deobfuscation, commit/diff consistency, README
coercion, maintainer-handover / authorship judgement, vulnerability triage and
verification. Forbidden to the LLM (deterministic tools only): hash comparison, CVE
matching, name similarity, timestamp comparison, stylometric measurement, pattern scanning.

---

## 5. Cost, Concurrency, Caps

- **Subagent budget**: `--max-subagents` (default 40) invocations per run; fail-closed.
- **Turn limits** (Strands `Limits`): subagent 16 per invocation (+6 per repair),
  orchestrator 250; `GoalLoop` 3 attempts.
- **Concurrency**: Strands runs one turn's tool calls in parallel (several subagents at
  once); the ledger is thread-safe; registry calls keep v1's per-host `RateLimitedSession`.
- **Bounded evidence**: tool outputs truncated (~12k chars), scans capped (files, findings
  per rule), artifacts ≤ 60 MB, clones depth-limited.

---

## 6. Project Structure (Enforced)

```
safesc/
├── cli.py                     # `safesc` — args, LLM + memory checks, run, print, reports
├── config/llm.py              # LLM_* validation + Strands model factory (§3.5)
├── core/                      # deterministic, LLM-free
│   ├── signals.py             # Severity, TrustDimension, Signal, LLMOutput, fusion
│   ├── ledger.py              # RunLedger, RunOptions, roles, features, Decision
│   ├── gate.py                # plan_triage (§2.2-B)
│   ├── scoring.py             # the scorer (§2.4)
│   └── targets.py             # default target, CI detection, package specs (§2.2-A)
├── agents/
│   ├── orchestrator.py        # run_audit: orchestrator Agent + guard + GoalLoop, fail-closed
│   ├── context.py             # AgentContext (per-run seams)
│   ├── harness/               # guard.py, validation.py, progress.py
│   ├── specialists/           # base.py (runner) + six SPEC modules + models.py
│   └── tools/                 # pipeline.py, inspection.py, evidence.py, external.py, scoring.py
├── memory/                    # manager.py (sole owner), store.py, fingerprints.py
├── reporter/                  # build_report(ledger, decision) + JSON / Markdown / SARIF
└── tools/                     # LLM-free library: index/, scan/, deep_analysis_tool.py,
                               #   source.py, vulnscan.py, authorship.py
fingerprints/                  # curated known-attack corpus (YAML)
```

### 6.1 Structural Invariants (pinned by `tests/test_invariants.py` unless noted)
1. Only `finalize_score` (`agents/tools/scoring.py`) writes a decision.
2. Static stage implementations are imported only by `agents/tools/pipeline.py`.
3. `safesc/tools/` never imports Strands, agents or config — it stays LLM-free.
4. No agent is given shell, bash, python-repl or notebook tools.
5. Memory stores are imported only inside `safesc/memory/`; agents get no add tool
   (`tests/test_memory.py`).
6. One console script (`safesc`); no optional extras.
7. Adding an ecosystem = one adapter under `tools/index/ecosystems/`, no agent changes.
8. Keys are injected (`LLMConfig`), never in the ledger, memory, logs or reports.

---

## 7. Tech Stack

| Layer | Choice |
|---|---|
| Agent runtime | Strands Agents ≥ 1.62 (Agent, tools, hooks, steering, GoalLoop, MemoryManager, context manager) |
| Models | Any Strands API-key provider (§3.5), caller's key |
| Vended / MCP tools | `web_fetch` (agentic), read-only `file_editor`; GitHub MCP (read-only allow-list), user MCP servers |
| Memory | Strands `LocalFileStorage` + keyword search; curated YAML corpus |
| Lockfile parsing | built-in adapters; `pathspec` for excludes |
| CVE / malicious-package data | OSV.dev |
| Reports | SARIF + Markdown + JSON |
| CI | GitHub Action (composite) + CLI exit codes |

---

## 8. Development Principles

1. **Explainability > accuracy** — every escalation traces to a signal with evidence.
2. **Deterministic core > agent cleverness** — agents choose what to look at, never the verdict.
3. **Two branch points, kept separate** — target at start, risk after Stage 3.
4. **Escalate-only, three channels** — subagents, memory, control flow (§2.5).
5. **Fail closed on the verdict, degrade gracefully on evidence** — a broken tool is a
   noted gap; an unfinished run is exit 2, never a pass.
6. **Zero-touch ecosystem additions.**
7. **Tests drive real Strands agents with scripted models** (`tests/helpers.py`), offline.

---

## 9. Open Items

- [ ] Gate threshold *values* (`gray_floor`, `decided_ceiling`) and the default subagent
      budget, to be tuned against real trigger rates and cost.
- [ ] Memory retention policy (size/age) for the local verdict store.
- [ ] Real-LLM end-to-end run against `tests/fixtures/attacks/` behind
      `@pytest.mark.integration` (scheduled, never the default PR path).
- [ ] Adversarial control-flow tests with *model-generated* injection attempts (the
      structural defences in §2.5 are tested with scripted models today).
- [ ] Authorship from published artifacts when no git history exists (diff consecutive
      releases' added code against prior releases).
- [ ] A separate (cheaper/different-provider) model for the verifier and summarizer,
      per lesson 2 — today every agent uses the one configured model.
- [ ] Monorepo / multi-config support (carried from v1).

### History (condensed)
v1: CI pipeline, Stages 0–5. v2.0–2.4: LangGraph spine + specialists, escalate-only fusion,
BYOK. v2.5–2.6: harness + Redis/PGVector clients. v2.7–2.11: attack-pattern fixtures,
`.safescignore`, rust/python behaviour signals with the "only opted-in code execution may
fail a gate" policy (`test_only_optedin_code_execution_can_fail_a_gate`, still enforced).
v2.12–2.14: store wiring, checkpointing, signal cache. **v3.0**: Strands refactor (this
document) — the v2 stores, checkpointing, distributed semaphores and cross-run signal cache
were removed with the multi-tier deployment model; local memory replaces them.

---

*Living document. Significant architectural changes must be reflected here and pass review.*
