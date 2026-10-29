# SafeSC

**Agentic supply-chain trust auditing.** SafeSC discovers your dependency lockfiles and
scores every dependency across five trust dimensions: identity, behavior, provenance,
popularity and vulnerability. An orchestrator agent runs the deterministic checks and
sends LLM subagents to investigate what looks wrong, including:

- **account takeovers**: checking whether a release's code was really written by its
  maintainer;
- **unreported vulnerabilities**: hunting for them in the dependency's own source, with a
  second agent verifying each finding independently.

A fixed set of deterministic rules then produces **one score per run**. It is built on
[Strands Agents](https://strandsagents.com).

```bash
pip install safesc
export LLM_PROVIDER=anthropic LLM_MODEL=claude-sonnet-5 LLM_API_KEY=sk-ant-...
safesc
```

- **One install, one command.** `pip install safesc` brings the agent runtime and every
  supported provider. With no arguments, `safesc` inspects the current directory, or the
  checked-out repository in CI. Everything else is a flag.
- **The agent never decides the verdict.** The static checks (discover → parse → verify
  hashes → cheap signals) are tools that only agents invoke, and only in a fixed order.
  Subagent findings go through a fixed fusion table and can only *raise* severity. The
  score comes from deterministic rules, once per run.
- **LLM and memory are required.** Every run validates your model first. Prior verdicts
  and a curated library of known attacks are kept as local memory, with no service to run
  and no second key.

---

## Quick start: GitHub Action

```yaml
name: SafeSC
on: [pull_request, push]
permissions:
  contents: read
  security-events: write   # SARIF upload to code scanning
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: JAAAACCCCCCKKKK/SafeSC@v2
        with:
          llm-provider: anthropic
          llm-model: claude-sonnet-5
          llm-api-key: ${{ secrets.SAFESC_LLM_API_KEY }}
          # with: authorship,vuln-hunt     # optional deeper analyses
```

The action installs SafeSC and audits the repository. It uploads SARIF to code scanning,
archives JSON/Markdown/SARIF reports, and fails the job when the gate fails. It also keeps
SafeSC's memory between runs with the runner cache.

| Input | Default | Purpose |
|---|---|---|
| `llm-provider`, `llm-model`, `llm-api-key` | — (required) | Your model; see [Providers](#providers) |
| `llm-base-url` | — | Proxy / gateway / OpenAI-compatible endpoint |
| `llm-context-window` | — | The model's context window in tokens (tunes context compression) |
| `target` | the repository | Path, lockfile or package spec |
| `with` | — | `authorship`, `vuln-hunt`, `transitive`, `github`, `all` (comma-separated) |
| `exclude` | — | Gitignore patterns, one per line |
| `fail-on` | `HIGH` | Gate threshold |
| `strict` | `false` | Fail when the analysis is incomplete |
| `max-subagents` | `40` | Subagent invocations per run (cost ceiling) |
| `github-token` | job token | GitHub API auth (and the GitHub MCP server with `with: github`) |
| `report-dir` / `format` | `safesc-reports` / `all` | Report output |
| `upload-sarif` / `upload-artifact` | `true` | Publishing |

Output `exit-code`: `0` pass · `1` gate failed · `2` configuration error or no verdict.

---

## CLI

```bash
safesc                              # this directory (in CI: the repository root)
safesc path/to/project              # another project, or a single lockfile
safesc npm:left-pad@1.3.0           # one package (also pkg:pypi/requests@2.31.0, crates:serde@1.0.200)

safesc --with authorship            # + code-style authorship analysis of every direct dependency
safesc --with vuln-hunt             # + unreported-vulnerability hunt and independent verification
safesc --with authorship,vuln-hunt,transitive   # ... extended to transitive dependencies
safesc --with github                # + GitHub MCP tools for subagents (needs GITHUB_TOKEN)
safesc --with all

safesc --report-dir out --format sarif     # write reports (all | json | markdown | sarif)
safesc --fail-on MEDIUM --strict           # stricter gate; incomplete analysis fails
safesc --exclude "tests/fixtures/**"       # skip paths (layers on .safescignore)
safesc --max-subagents 80                  # allow more subagent invocations
safesc --memory-dir ~/.safesc-memory       # memory location
safesc --mcp https://intel.example/mcp     # attach your own read-only MCP server
safesc -q | -v                             # quiet / debug
```

Progress goes to stderr, one line per tool call. The verdict, trust score (0–100, A–F) and
summary go to stdout.

### Environment

| Variable | Required | Meaning |
|---|---|---|
| `LLM_PROVIDER` | **yes** | One of the providers below |
| `LLM_MODEL` | **yes** | A model that provider serves |
| `LLM_API_KEY` | **yes** | Your key for that provider |
| `LLM_BASE_URL` | no | Proxy, gateway, or OpenAI-compatible endpoint |
| `LLM_CONTEXT_WINDOW` | no | Context window in tokens (default assumption: 200k) |
| `SAFESC_MEMORY_DIR` | no | Memory directory (default: the user cache dir) |
| `GITHUB_TOKEN` / `GH_TOKEN` | no | GitHub API rate limits (60/h anonymous vs 1000/h) |
| `AWS_REGION` | no | Bedrock region (default `us-east-1`) |

### Start-up checks

Before any agent runs, SafeSC checks the LLM in this order and stops with exit code 2 and
a precise message at the first failure:

1. all three variables are set;
2. the provider is supported;
3. the model id belongs to that provider (for example `gpt-5` with `LLM_PROVIDER=anthropic`
   is rejected, with a hint);
4. the provider endpoint is reachable. For Ollama, the model must also be pulled;
5. one minimal authenticated call succeeds. A failure is reported as a rejected key, an
   unavailable model, or an unreachable host. The key is scrubbed from every message.

Then the memory directory must be writable.

### Providers

Every model provider Strands ships that authenticates with an API key:

| `LLM_PROVIDER` | Example `LLM_MODEL` | Notes |
|---|---|---|
| `anthropic` | `claude-sonnet-5` | |
| `openai` | `gpt-5`, `o4-mini` | Any model id behind `LLM_BASE_URL` (OpenRouter, Groq, vLLM, Azure, …) |
| `openai_responses` | `gpt-5` | OpenAI Responses API |
| `bedrock` | `us.anthropic.claude-sonnet-5` | Bedrock API key; `AWS_REGION` selects the region |
| `gemini` | `gemini-2.5-pro` | |
| `mistral` | `mistral-large-latest` | |
| `litellm` | `groq/llama-3.3-70b-versatile` | `provider/model` form |
| `llamaapi` | `Llama-3.3-70B-Instruct` | Deprecated upstream (Meta retired the Llama API) |
| `ollama` | `qwen3:32b` | Local server: key unused but required (any value) |
| `llamacpp` | `default` | Local server: key is sent as a bearer token if it requires one |
| `writer` | `palmyra-x5` | |

SageMaker is not supported: its endpoints authenticate with AWS SigV4, not an API key. Use
`bedrock` instead.

---

## How it works

```
safesc ─► validate LLM ─► open memory ─► orchestrator agent
                                           │  discover_lockfiles → parse_dependencies →
                                           │  verify_hashes → collect_signals       (static tools, fixed order)
                                           │  required_analyses                     (what the gate demands)
                                           ├─► identity_analyst    ┐
                                           ├─► behavior_analyst    │ subagents (agents-as-tools):
                                           ├─► provenance_analyst  │ own context, evidence tools,
                                           ├─► authorship_analyst  │ memory, structured output
                                           ├─► vuln_hunter ──► vuln_verifier
                                           └─► finalize_score  ─► deterministic score, once
```

- **Static stages are agent tools.** The orchestrator calls them. They take no target
  argument (it is fixed before any agent starts), refuse to run out of order, and run
  once. A steering handler gives the same rules as feedback before a call is made.
- **The gate decides what must be looked at.** Gray-zone signals (MEDIUM up to below
  CRITICAL, on identity, behavior or provenance) and your `--with` features become
  *required analyses*. `finalize_score` is refused until each one has been attempted or
  the subagent budget is spent. Beyond that, the orchestrator explores what it judges
  risky.
- **Subagents produce evidence, not verdicts.** Each one fills a structured output. Its
  file citations must match evidence its tools actually showed it, or it is asked to
  repair; repeated failure is recorded as a coverage gap. The deterministic fusion table
  maps it to a signal that can only raise severity.
- **Authorship.** `profile_authorship` measures code-style and commit-habit drift between
  the release window and each author's history (or the established maintainers'):
  indentation, quoting, naming, comment density, message style, timezone, hours, signing,
  email domain. The subagent decides whether the drift is a formatter change or different
  hands behind a trusted account.
- **Unreported vulnerabilities.** `vuln_hunter` fetches the published source and starts
  from a deterministic scan for unsafe functions (`strcpy`, `gets`, …), unsalted or fast
  hashing of passwords and tokens, injection and deserialization sinks, disabled TLS,
  predictable randomness for secrets, hard-coded secrets, and imports of modules with
  published problems. It also checks the package's own dependencies against OSV. It only
  registers *candidates*. `vuln_verifier`, a separate agent with a fresh context, must
  confirm each one. A confirmed flaw's severity is capped by its assessed impact; only an
  intentional backdoor fuses as malicious.
- **Tools.** Subagents get read-only evidence tools, the Strands-vended `web_fetch` (in
  agentic mode, so raw pages never enter their context), a read-only `file_editor`
  confined to fetched source, and MCP servers you attach. No agent ever gets a shell or
  code execution: SafeSC reads untrusted code and never runs it.
- **Memory.** Verdicts per exact artifact (`name@version+hash`) and the curated
  known-attack corpus (`fingerprints/`) are injected into subagent prompts as *prior
  findings*. They are context only and can never lower an assessment. Memory is written
  once, after the score exists.
- **Fail closed.** If the orchestrator never finalizes, the run has no verdict and exits 2.

### The score

The **gate** fails when any dependency reaches `--fail-on` (HIGH by default).

The **trust score** is 100 minus a penalty per dependency (LOW 1, MEDIUM 4, HIGH 15,
CRITICAL 40), with these caps:

- any HIGH caps the score at 59;
- any CRITICAL caps it at 19;
- an incomplete analysis caps it at 89.

Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below that. The score never overrides the gate.

---

## Supported ecosystems

Python (uv / poetry / pip / Pipfile), npm / pnpm / yarn, Cargo, Go modules, Maven / Gradle.

## Excluding paths

Add a `.safescignore` (gitignore syntax) at the target root, or pass `--exclude PATTERN`
(repeatable, layered on top). The Action's `exclude` input takes one pattern per line.

## GitHub API rate limits

Popularity checks call the GitHub REST API, which allows only 60 anonymous requests per
hour per IP. The Action authenticates with the job token by default. Outside Actions,
export `GITHUB_TOKEN` or `GH_TOKEN`.

## Reports

`--report-dir` writes `safesc-report.{json,md,sarif}`. Reports include per-dependency
signals with evidence, the trust score and grade, vulnerability candidates with their
verification status, every subagent run, and any coverage gaps.

## Security

Keys are held as `SecretStr`, passed only by injection, and scrubbed from errors. They
never appear in the run ledger, memory, logs or reports. Dependency code is downloaded and
safe-extracted (traversal and link protection) or shallow-cloned with hooks disabled. It is
never installed, built or executed.

## License

MIT.
