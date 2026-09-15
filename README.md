# SafeSC

**Supply-chain trust auditing for CI pipelines** — SafeSC discovers your dependency
lockfiles, verifies provenance, and scores every dependency across five trust dimensions
(identity, behavior, provenance, popularity, vulnerability). Deterministic signals do the
heavy lifting; an LLM is used only to reason about the small, suspicious subset and can
only *raise* severity, never lower it.

- **Deterministic spine, agentic fan-out.** Stages 0–3 (discover → parse → verify hashes →
  cheap signals) always run in a fixed order. Only gray-zone dependencies fan out to
  LLM specialists (name-squatting, install-script intent, provenance gaps).
- **Bring-your-own-key (BYOK).** You supply your own LLM key, provider, and model. SafeSC
  holds no server-side key; keys never enter logs, reports, or persisted state.
- **One-step CI gate.** A single GitHub Action installs SafeSC, runs the audit, uploads a
  SARIF report to code scanning, archives artifacts, and fails the build on a critical
  finding.

---

## Install

```bash
pip install "safesc[agent,anthropic]"    # or [agent,openai]
```

> **`pip install safesc` alone is not enough for the CI gate.** The bare package ships the
> deterministic Stage 0–3 tools (`index`, `scan`) only. The `agent` extra adds the
> orchestration layer, and you must also pick a provider extra — SafeSC bundles no LLM SDK
> because there is no default provider (BYOK). See [Optional extras](#optional-extras).

Using the GitHub Action instead? It handles installation for you — skip to
[Quick start](#quick-start--github-action).

---

## Quick start — GitHub Action

Add the following workflow to a **consumer** repository (e.g. `.github/workflows/safesc.yml`)
and create a repository secret named `SAFESC_LLM_API_KEY` with your BYOK LLM key. There is
**no default provider** — you must choose one:

```yaml
name: SafeSC
on: [push]

permissions:
  actions: read
  contents: read
  security-events: write   # required to upload the SARIF report

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: JAAAACCCCCCKKKK/SafeSC@v1
        with:
          llm-api-key: ${{ secrets.SAFESC_LLM_API_KEY }}
          llm-provider: anthropic          # required: anthropic | openai
```

To pin a specific **model** or route to a custom **endpoint**, add the optional inputs:

```yaml
      - uses: JAAAACCCCCCKKKK/SafeSC@v1
        with:
          target: "."                              # repo path, lockfile, or git URL
          llm-api-key: ${{ secrets.SAFESC_LLM_API_KEY }}
          llm-provider: openai                     # required: anthropic | openai
          llm-model: gpt-4o                         # blank = provider default
          llm-base-url: https://your-gateway/v1     # any OpenAI-compatible endpoint
          format: all                               # all | json | markdown | sarif
          report-dir: safesc-reports
```

### Action inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `llm-api-key` | ✅ | — | BYOK reasoning-LLM API key for your chosen provider. Pass a secret. |
| `llm-provider` | ✅ | — | `anthropic` or `openai` (also any OpenAI-compatible endpoint via `llm-base-url`). No default. |
| `llm-model` | | provider default | Model id, e.g. `claude-sonnet-5`, `gpt-4o`. Blank = provider default. |
| `llm-base-url` | | — | Override the LLM base URL (proxy / gateway / Bedrock / Azure / OpenAI-compatible). |
| `target` | | `.` | Repo path, lockfile, or git URL to audit. |
| `exclude` | | — | Gitignore-syntax patterns to exclude from discovery, one per line. See [Excluding paths](#excluding-paths). |
| `format` | | `all` | Report format(s): `all` \| `json` \| `markdown` \| `sarif`. |
| `report-dir` | | `safesc-reports` | Directory to write JSON / Markdown / SARIF artifacts. |
| `github-token` | | `${{ github.token }}` | Authenticates SafeSC's GitHub API calls (Stage-3 popularity signals). The default is right for nearly everyone — see [GitHub API rate limits](#github-api-rate-limits). |
| `python-version` | | `3.12` | Python version used to run SafeSC. |
| `upload-sarif` | | `true` | Upload the SARIF report to GitHub code scanning. |
| `upload-artifact` | | `true` | Archive `report-dir` as a build artifact. |
| `artifact-name` | | `safesc-reports` | Name for the archived artifact. |
| `redis-url` | | — | Enables checkpointing, fleet-wide rate limiting, the signal cache and prior-verdict recall. See [Optional memory layer](#optional-memory-layer). |
| `pgvector-dsn` | | — | Adds similarity search + fingerprint grounding. Requires `embedding-api-key`. |
| `embedding-api-key` | | — | BYOK embedding key. Required whenever `pgvector-dsn` is set. Pass a secret. |
| `embedding-model` / `embedding-base-url` | | `voyage-4-large` | Embedding provider overrides. |
| `embedding-dim` | | `1024` | pgvector column width. **Must** match the embedding model. Fixed at `store init`. |
| `memory-strict` | | `false` | Fail if a configured store is unreachable, instead of auditing store-free. |
| `store-init` | | `false` | Run `safesc store init` before auditing (needs DDL privileges; only needed once). |

**Output:** `exit-code` — `0` = gate pass, `1` = gate fail on a critical finding.

> **SARIF upload (code scanning).** `upload-sarif: true` needs the job to grant
> `permissions: security-events: write` **and** a repo where code scanning is available
> (public repos, or private repos with GitHub Advanced Security). If either is missing,
> GitHub returns `Resource not accessible by integration`; SafeSC treats this as
> **non-fatal** — it prints a warning, still archives the report artifact, and the audit's
> exit code is unaffected. Set `upload-sarif: false` to skip the upload entirely.

---

## Choosing your model & provider

SafeSC is provider-agnostic for the reasoning LLM. A provider is **required** (there is no
default) — pick one, optionally a model, and pass your own key via the Action inputs above,
environment variables (CLI/CI), or API headers.

| Provider | `llm-provider` | Default model | Notes |
|---|---|---|---|
| Anthropic | `anthropic` | `claude-sonnet-5` | Native Claude API. |
| OpenAI | `openai` | `gpt-4o` | Native OpenAI API. |
| OpenAI-compatible | `openai` + `llm-base-url` | *(set your own)* | Azure OpenAI, OpenRouter, Together, Groq, Ollama, vLLM, LiteLLM proxy… |

Need another provider? Register one at runtime without editing SafeSC:

```python
from safesc.graph.llm_client import register_llm_provider
register_llm_provider("my-provider", my_factory)   # my_factory(LLMCredentials) -> LLMClient
```

---

## CLI usage

Install the CI tier — the orchestration extra **plus the SDK for your chosen provider**
(no Redis/Postgres required):

```bash
pip install "safesc[agent,anthropic]"   # Anthropic provider
pip install "safesc[agent,openai]"      # OpenAI / OpenAI-compatible provider
```

Then supply your key **and provider** via the environment and run:

```bash
export SAFESC_LLM_API_KEY=sk-ant-...
export SAFESC_LLM_PROVIDER=anthropic     # required — no default

# Full-repo audit (produces a CI exit code)
safesc audit . --report-dir safesc-reports --format all

# Single-package investigation (evidence only, never fails CI)
safesc query npm:left-pad@1.3.0
```

Store-backed deployments get three more subcommands — `safesc store init`,
`safesc fingerprint load`, and `safesc gc` — plus `--resume`; see
[Optional memory layer](#optional-memory-layer).

Use a different provider/model entirely through the environment:

```bash
export SAFESC_LLM_PROVIDER=openai
export SAFESC_LLM_MODEL=gpt-4o
export SAFESC_LLM_API_KEY=sk-...

# Or a local OpenAI-compatible server (e.g. Ollama):
export SAFESC_LLM_PROVIDER=openai
export SAFESC_LLM_BASE_URL=http://localhost:11434/v1
export SAFESC_LLM_MODEL=mixtral
```

The frozen Stage 0–3 tools are also exposed as standalone commands: `index` (discover /
parse) and `scan` (verify / signals).

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `SAFESC_LLM_API_KEY` | audit / query | BYOK reasoning-LLM key. Not read by `gc`, `store init` or `fingerprint load`. |
| `SAFESC_LLM_PROVIDER` | audit / query | `anthropic` or `openai` — no default. Same exemption as above. |
| `SAFESC_LLM_MODEL` | | Model id (blank = provider default). |
| `SAFESC_LLM_BASE_URL` | | Override the LLM base URL. |
| `SAFESC_EMBEDDING_API_KEY` | | Only if the optional memory layer is enabled. |
| `SAFESC_EMBEDDING_BASE_URL` / `SAFESC_EMBEDDING_MODEL` | | Embedding provider overrides (default `voyage-4-large`). |
| `SAFESC_REDIS_URL` | | Enables the memory layer's short-term half — see below. |
| `SAFESC_PGVECTOR_DSN` | | Enables the long-term half (also needs an embedding key). |
| `SAFESC_EMBEDDING_DIM` | | Vector column width. **Must** match your embedding model. Fixed at `store init`. |
| `SAFESC_MEMORY_STRICT` | | `1` = fail if a configured store is unreachable, instead of degrading. |
| `SAFESC_HOST_CONCURRENCY` / `SAFESC_HOT_TTL_S` | | Per-registry concurrency (`10`) and cache TTL (7 days). |
| `SAFESC_LOG_LEVEL` | | SafeSC's own log verbosity (default `INFO`; `DEBUG` traces LLM requests). |
| `SAFESC_DEEP_CACHE` | | Directory for Stage-4 clone/extract scratch data (default: system temp). |

Only `audit` and `query` need an LLM key. The three maintenance commands — `gc`,
`store init`, `fingerprint load` — return before any reasoning credential is read, so a
CronJob can hold a store/embedding key alone and no reasoning key at all.

The last four rows have **no Action input**, by design: they are tuning and debugging
knobs rather than deployment wiring. They still work from a workflow, because a composite
action inherits job-level environment and the Action's own `env:` block does not name
them:

```yaml
env:                        # job level — passes through to the Action
  SAFESC_LOG_LEVEL: DEBUG
  SAFESC_HOST_CONCURRENCY: "4"
steps:
  - uses: JAAAACCCCCCKKKK/SafeSC@v1
    with:
      llm-api-key: ${{ secrets.SAFESC_LLM_API_KEY }}
      llm-provider: anthropic
```

---

## GitHub API rate limits

Stage 3's popularity collectors call the GitHub REST API (archived status, stars, last
push). **Anonymous access is 60 requests/hour per IP, shared across GitHub-hosted
runners**, so any real dependency tree exhausts it and you will see:

```
WARNING:safesc.tools.scan.signals.collector:collector ArchivedRepoCollector degraded for
  <pkg>: 1 unanswered request(s), first=https://api.github.com/repos/<owner>/<repo>
```

The Action authenticates with the job's own `GITHUB_TOKEN` by default (1000 requests/hour),
so this should not appear. If it does, either `github-token` was explicitly set to an empty
value, or you are running the CLI outside Actions -- export `GITHUB_TOKEN` (or `GH_TOKEN`)
there too.

This is worth fixing rather than ignoring. Popularity is deliberately **not** cached (§3.1
-- an archived repo is exactly the fact that changes under a pinned version), so it is
re-collected on every run: an unauthenticated audit loses the signal on every run, not once.
It fails toward *cleaner*, which is why the collector now warns instead of degrading
silently.

---

## Optional memory layer

SafeSC runs fine with no external stores, and that is the default — a CI audit is a single
finite run. Attaching a store makes audits **faster, politer to registries, and better
grounded**. It cannot make them more permissive; see the invariant below.

| Store | What you get |
|---|---|
| **Redis** (`SAFESC_REDIS_URL`) | Checkpointing, so `safesc audit . --resume` reattaches to an interrupted run · fleet-wide per-registry rate limiting shared across concurrent audits · a 7-day cross-run cache of the cheap signals that cannot change for a pinned `name@version` · exact-hash recall of prior verdicts. **Needs no second API key.** |
| **Postgres + pgvector** (`SAFESC_PGVECTOR_DSN`) | Adds *similarity* search — behaviourally related prior findings, and a curated known-attack fingerprint corpus — as grounding for Stage-4 LLM analysis. Requires an embedding key. Also hosts the `--resume` checkpointer, which is used in preference to Redis's once `safesc store init` has created its tables. |

Either half works alone. Redis-only is the cheapest useful configuration: everything
except similarity search, with one store and no extra key.

```bash
pip install "safesc[agent,anthropic,memory]"

export SAFESC_REDIS_URL=redis://localhost:6379/0
export SAFESC_PGVECTOR_DSN=postgresql://user:pw@localhost:5432/safesc   # optional
export SAFESC_EMBEDDING_API_KEY=pa-...                                  # with pgvector only

safesc store init                             # once: create the pgvector schema
safesc fingerprint load                       # once: ingest the shipped attack corpus
safesc audit .                                # now cached + grounded
safesc gc                                     # periodically: retention sweep (CronJob)
```

#### Choosing the embedding model

The default is **`voyage-4-large`** at **1024** dimensions. You are not locked to it — set
`SAFESC_EMBEDDING_MODEL`, or point `SAFESC_EMBEDDING_BASE_URL` at any OpenAI-compatible
`/embeddings` endpoint (OpenAI, Cohere, Google, a gateway, a local server) and SafeSC will
use that instead.

The reason for this particular default is that the whole voyage-4 family — `voyage-4-large`,
`voyage-4`, `voyage-4-lite`, `voyage-4-nano` — **shares one embedding space**, so vectors
written by one are directly comparable to vectors written by another. Moving between tiers
to trade accuracy against cost is a config change, not a migration: your existing corpus
stays valid and does not need re-embedding.

Two things still do force a full re-index, because neither is covered by the shared space:

- **Changing `SAFESC_EMBEDDING_DIM`.** The width is interpolated into the DDL as
  `vector(N)` at `safesc store init`, so it is a schema change regardless of which model
  wrote the vectors. Pick the width once, then move tiers freely at that width.
- **Leaving the family** — voyage-3, OpenAI, Cohere. Those embedding spaces are unrelated
  to voyage-4's, so old and new vectors are not comparable even at an identical width.

To re-index: drop the table, re-run `safesc store init` with the new settings, and
`safesc fingerprint load`. Prior verdicts are rebuilt by subsequent audits; the Redis half
is unaffected, since exact-hash recall uses no embeddings at all.

**This can only ever make SafeSC stricter, never more permissive.** Retrieved memory
reaches the LLM as prior context that may raise concern but is structurally incapable of
lowering a verdict — it is never merged into the signal set, and a specialist that agrees
with a prior finding must re-derive it from current evidence. That is why a configured but
unreachable store only prints a warning and audits without it. Set `SAFESC_MEMORY_STRICT=1`
if you would rather that be a hard error. Only `safesc fingerprint load` writes
fingerprints — an audit run cannot — and the corpus lives in version control under
`fingerprints/`.

### Using it from CI

The store has to **outlive the job**. A `services:` container does not: it is recreated per
job, so the cache starts empty every run, checkpoints are unreachable, and rate limiting is
scoped to a single audit — you pay for the store and get none of the four benefits. Use a
**managed store** reachable over the network (from GitHub-hosted runners) or a
**self-hosted runner** beside your own instances.

**Step 1 — one-time setup.** Do this *before* the first audit, in its own
`workflow_dispatch` workflow. `store init` creates the pgvector schema; without it every
audit logs `relation "safesc_memory" does not exist` and silently keeps no long-term
memory. Keep it out of the audit workflow — re-ingesting the fingerprint corpus on every
run just burns embedding calls rewriting identical rows.

```yaml
- run: |
    pip install "safesc[agent,anthropic,memory]"
    safesc store init
    safesc fingerprint load
  env:
    SAFESC_PGVECTOR_DSN:      ${{ secrets.SAFESC_PGVECTOR_DSN }}
    SAFESC_EMBEDDING_API_KEY: ${{ secrets.SAFESC_EMBEDDING_API_KEY }}
    # Both MUST match what the audit workflow uses. `store init` bakes the width into the
    # column as vector(N); omit it and you get vector(1024) whatever your model emits, and
    # every later insert fails on a dimension mismatch.
    SAFESC_EMBEDDING_DIM:     "1024"
    SAFESC_EMBEDDING_MODEL:   voyage-4-large
```

**Step 2 — the audit workflow.** Once the schema exists, point the Action at the same
stores:

```yaml
- uses: JAAAACCCCCCKKKK/SafeSC@v1
  with:
    llm-api-key:       ${{ secrets.SAFESC_LLM_API_KEY }}
    llm-provider:      anthropic
    redis-url:         ${{ secrets.SAFESC_REDIS_URL }}
    pgvector-dsn:      ${{ secrets.SAFESC_PGVECTOR_DSN }}
    embedding-api-key: ${{ secrets.SAFESC_EMBEDDING_API_KEY }}
```

The `memory` extra is installed only when one of those is set, so consumers who do not use
a store pay nothing for it. Gating behaviour is unchanged: the audit still exits `1` on a
failing gate.

If you would rather not run step 1 separately, the Action's `store-init: true` input runs
`safesc store init` before the audit — but it needs DDL privileges on every run, so a
dedicated setup workflow is the better default.

**Step 3 — maintenance.** `safesc gc` belongs on a nightly cron (or a Kubernetes CronJob),
never inside an audit.

Two things that are *not* SafeSC bugs when you see them in the log:

- `postgres checkpointer unavailable (checkpoint tables missing; run `safesc store init`);
  falling back to the Redis checkpointer` — `--resume` still works, on Redis. Run
  `safesc store init` once to move checkpoints to Postgres. Both checkpointers use only
  plain commands, so Upstash and other managed Redis without RediSearch are fine.
- A store that is configured but unreachable prints a warning and the audit continues
  store-free. That is deliberate (§3.3). Set `memory-strict: true` / `SAFESC_MEMORY_STRICT=1`
  if a silently store-free audit should instead be a hard failure.

---

## Supported ecosystems

Python (uv / poetry / pip), npm / pnpm, Cargo (Rust), Go modules, and Maven / Gradle (Java).

## Excluding paths

SafeSC discovers dependency files by walking the target directory. To permanently
exclude paths (e.g. test fixtures, vendored copies, generated directories), add a
`.safescignore` file at the target root — gitignore syntax, auto-discovered with no
flag needed:

```
# .safescignore
tests/fixtures/**
vendor/
```

For a one-off exclusion without committing a file, every entrypoint also accepts a
repeatable `--exclude PATTERN` flag, which layers on top of (never replaces) a
`.safescignore` file:

```bash
safesc audit . --exclude "tests/fixtures/**"
index discover . --exclude "vendor/**"
scan signals . --exclude "vendor/**"
```

The GitHub Action exposes the same thing as the `exclude` input (one pattern per line).
Patterns are gitignore syntax, matched against the path relative to the scanned root.

## Reports

Every run can emit **SARIF** (for GitHub code scanning), **Markdown** (human-readable), and
**JSON** (machine-readable), written as `safesc-report.{sarif,md,json}`.

## Optional extras

| Extra | Installs | Purpose |
|---|---|---|
| `agent` | LangGraph | CI-tier orchestration: spine + LLM specialists (no provider SDK). |
| `anthropic` | Anthropic SDK | Anthropic (Claude) provider. |
| `openai` | OpenAI SDK | OpenAI and OpenAI-compatible providers. |
| `memory` | Redis + Postgres/PGVector | Optional memory layer: checkpointing, fleet-wide rate limiting, signal caching, and retrieval grounding. Never lowers a verdict. |

Without any extra, `pip install safesc` gives you the frozen Stage 0–3 tools (`index`,
`scan`) — deterministic discovery, parsing, hash verification, and cheap signals — but not
the `safesc audit` CI gate, which requires `agent` plus a provider extra.

## Security

SafeSC is a security tool and treats your credentials as load-bearing: keys are held as
`SecretStr`, threaded by injection only, and **never** enter the audit state (which may be
checkpointed to Redis), logs, reports, or the vector store. There is no ambient/shared key
fallback — a missing key is a hard error.

## License

MIT.