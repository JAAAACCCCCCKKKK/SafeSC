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
| `format` | | `all` | Report format(s): `all` \| `json` \| `markdown` \| `sarif`. |
| `report-dir` | | `safesc-reports` | Directory to write JSON / Markdown / SARIF artifacts. |
| `python-version` | | `3.12` | Python version used to run SafeSC. |
| `upload-sarif` | | `true` | Upload the SARIF report to GitHub code scanning. |
| `upload-artifact` | | `true` | Archive `report-dir` as a build artifact. |
| `artifact-name` | | `safesc-reports` | Name for the archived artifact. |

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
| `SAFESC_LLM_API_KEY` | ✅ | BYOK reasoning-LLM key. |
| `SAFESC_LLM_PROVIDER` | ✅ | `anthropic` or `openai` — required, no default. |
| `SAFESC_LLM_MODEL` | | Model id (blank = provider default). |
| `SAFESC_LLM_BASE_URL` | | Override the LLM base URL. |
| `SAFESC_EMBEDDING_API_KEY` | | Only if the optional memory layer is enabled. |
| `SAFESC_EMBEDDING_BASE_URL` / `SAFESC_EMBEDDING_MODEL` | | Embedding provider overrides. |

---

## Supported ecosystems

Python (uv / poetry / pip), npm / pnpm, Cargo (Rust), Go modules, and Maven / Gradle (Java).

## Reports

Every run can emit **SARIF** (for GitHub code scanning), **Markdown** (human-readable), and
**JSON** (machine-readable), written as `safesc-report.{sarif,md,json}`.

## Optional extras

| Extra | Installs | Purpose |
|---|---|---|
| `agent` | LangGraph | CI-tier orchestration: spine + LLM specialists (no provider SDK). |
| `anthropic` | Anthropic SDK | Anthropic (Claude) provider. |
| `openai` | OpenAI SDK | OpenAI and OpenAI-compatible providers. |
| `memory` | Redis + Postgres/PGVector | Optional long-term memory (retrieval grounding only; never changes a verdict). |

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