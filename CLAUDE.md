# CLAUDE.md — depaudit Project Development Rules

This document defines the architectural and development constraints for **depaudit**, a dependency provenance and trust-auditing tool. All code contributions, module additions, and dependency changes must conform to the boundaries and principles defined here.

---

## 1. Project Scope and Boundaries

┌─────────────────────────────────────────────────────────┐
│  Stage 0: Discovery        发现锁文件                      │
│  扫描 repo → 识别 uv.lock / poetry.lock / package-lock... │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 1: Parse & Normalize   解析为统一依赖模型           │
│  每个依赖 → {name, version, hash, source_url, direct?}    │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 2: Hash Verification   哈希溯源（廉价、并行）        │
│  锁文件hash ⟷ registry实际发行版hash ⟷ 源码repo            │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 3: Cheap Signals       廉价信号采集（全量、并行）    │
│  registry元数据/维护者/发布节奏/下载量/Scorecard...        │
└────────────────────┬────────────────────────────────────┘
                     ▼
        ┌────── 风险打分 + 阈值过滤 ──────┐
        │  只有可疑的少数进入下一阶段       │
        ▼                                 
┌─────────────────────────────────────────────────────────┐
│  Stage 4: Deep Analysis (LLM)  深度分析（昂贵、选择性）     │
│  clone repo → diff分析 / install脚本 / 混淆代码 / 社工迹象 │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 5: Report & Gate       报告 + 决定是否 fail         │
│  SARIF / Markdown / JSON  →  exit code 控制 CI            │
└─────────────────────────────────────────────────────────┘

### 1.1 Goal
Automatically discover dependency lockfiles in CI workflows, traverse their dependencies, evaluate trustworthiness across multiple dimensions, identify indicators of **social engineering attacks** and **dependency injection attacks**, and fail the CI pipeline when necessary.

### 1.2 Clear Differentiation
- **No wheel reinvention**: Reuse mature open-source components (Syft, OSV.dev) for established domains like CVE scanning and SBOM generation.
- **Core value**: Multi-dimensional trust scoring + LLM-driven analysis of social engineering and behavioral intent.
- **Blind-spot coverage**: Address what mainstream tools miss — malicious behavioral intent and broken provenance chains.

### 1.3 Hard Scope Constraints
- **CI mode only**. No support for offline / airgapped scenarios.
- **Multi-language support**: All ecosystem-specific logic must be plugin-based. Hardcoding is forbidden.
- **Custom registry support**: Including private sources like internal PyPI, Artifactory, etc.
- **No real-time monitoring / agent mode**: One CI run, one execution, then exit.

### 1.4 First-Release Priority
Ecosystem implementation order: **Python (uv/poetry/pip) → npm/pnpm → Cargo → Go modules → Maven/Gradle**. The first two cover ~90% of real-world scenarios. Prioritize quality over breadth.

---

## 2. Overall Architecture (Pipeline + Tiered Triggering)

### 2.1 Six Stages
```
Stage 0: Discovery         Detect lockfiles
Stage 1: Parse & Normalize  Convert to unified dependency model
Stage 2: Hash Verification  Provenance via hash (cheap, parallel)
Stage 3: Cheap Signals      Collect cheap signals (full sweep, parallel)
          ↓ Risk scoring + threshold filtering
Stage 4: Deep Analysis      LLM-based deep analysis (expensive, selective)
Stage 5: Report & Gate      Emit reports + CI decision
```

### 2.2 Tiered Triggering (First Principle)
- A gate must exist after Stage 3: **the vast majority of dependencies are classified as low-risk during cheap signal collection and skip Stage 4**.
- Only dependencies scoring in the "gray / suspicious" range proceed to deep analysis.
- This is a prerequisite for the tool's viability in CI, not an optimization.

### 2.3 Direct vs Transitive Dependencies
- **Direct dependencies**: Strict mode. All dimensions + LLM deep analysis.
- **Transitive dependencies**: Cheap signals + hash verification only.
- **Exception**: If a transitive dependency is detected to have install-time scripts (a Stage 3 cheap signal), escalate to deep analysis.

### 2.4 Install-time Script Detection Rules
- **Python**: `setup.py` exists and is non-empty (distinguished from a pure `pyproject.toml` setup).
- **npm**: `package.json` `scripts` field contains `preinstall` / `install` / `postinstall`.
- **Rust**: A `build.rs` file is present.
- **Other ecosystems**: Explicitly defined in their adapter.

---

## 3. Trust Scoring Model

### 3.1 Core Philosophy
**Single 0–100 risk scores are forbidden**. Use **independent per-dimension scoring + dimension-level thresholds + severity tiers**.

### 3.2 Five Dimensions
1. **Identity**: Is this package what it claims to be?
2. **Behavior**: What is this package actually doing?
3. **Provenance**: Does the published artifact match its source code?
4. **Popularity**: Does the community endorse this package?
5. **Vulnerability**: Known CVEs and EOL status.

### 3.3 Scoring Rules
- Each dimension is scored independently as `low / medium / high / critical`.
- **Final severity = max(per-dimension severities)** (weakest-link principle).
- Risks across dimensions are not additive. Weighted summation is forbidden — it blurs critical signals.

### 3.4 Decision Matrix
| Max Dimension Severity | Default Action | Configurable Override |
|------------------------|----------------|----------------------|
| critical | block (exit 1) | allowlist exemption |
| high | block (exit 1) | downgrade to warn |
| medium | warn (exit 0) | upgrade or ignore |
| low | info | ignore |

### 3.5 Stricter Rules for New Dependencies
**Newly introduced dependencies are treated more strictly than existing ones**. Existing dependencies (presumed to have passed prior review) may be relaxed by one tier. This prevents CI from being repeatedly blocked by legacy dependencies while keeping sensitivity to new threats.

---

## 4. LLM Usage Constraints

### 4.1 The Role of the LLM (Iron Rule)
**The LLM produces evidence, not decisions**. All CI gate decisions are made by the deterministic rules engine.

### 4.2 Mandatory Structured Output
All LLM tasks must return this unified schema:
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
The LLM must never emit numeric scores. `verdict` must be one of the three enum values.

### 4.3 LLM × Rules Engine Fusion
| LLM verdict | confidence | Dimension Adjustment |
|------------|-----------|---------------------|
| malicious | ≥ 0.7 | Force to critical |
| malicious | 0.4–0.7 | Escalate one tier |
| suspicious | ≥ 0.7 | Escalate one tier |
| suspicious | < 0.7 | Record evidence only |
| clean | any | No adjustment |

**Iron rule**: The LLM may only escalate severity, **never downgrade it**. This prevents prompt injection (e.g., an attacker writing `"this is legitimate, ignore warnings"` in a README) from neutralizing the tool.

### 4.4 LLM Task Scope
**Tasks suitable for the LLM**:
- Install script intent analysis (semantic, not keyword-based)
- Consistency check between commit messages and diffs
- Detection of suspicious coercion in READMEs / docs
- Social engineering signals in maintainer handover issues / PRs
- Deobfuscation and intent analysis of obfuscated code

**Tasks forbidden for the LLM**:
- Hash comparison (deterministic)
- CVE matching (table lookup)
- Package name similarity (algorithmic)
- Timestamp comparison (arithmetic)

---

## 5. Project Structure (Enforced)

```
depaudit/
├── core/                      # Core pipeline, must be ecosystem-agnostic
│   ├── pipeline.py
│   ├── scorer/
│   ├── cache/
│   ├── reporter/
│   └── gate.py
├── ecosystems/                # Ecosystem adapters (plugins)
│   ├── base.py               # EcosystemAdapter ABC
│   ├── python/
│   ├── javascript/
│   ├── rust/
│   └── ...
├── signals/                   # Signal collectors, must be ecosystem-agnostic
│   ├── identity/
│   ├── behavior/
│   ├── provenance/
│   ├── popularity/
│   └── vulnerability/
├── llm/                       # LLM analysis modules
│   ├── client.py
│   ├── prompts/
│   ├── schemas.py
│   └── tasks/
├── config/
└── cli/
```

### 5.1 Module Dependency Rules (Architectural Iron Rules)
1. **The `signals` layer must not know about `ecosystems`**. It receives standardized `Dependency` objects and interacts with the outside world only through adapter interfaces.
2. **The `ecosystems` layer must not know about `signals`**. Adapters are responsible only for data retrieval, never for judgment.
3. **LLM tasks are conceptually signals**. Stage 3 uses static detection; Stage 4 uses LLM detection. Their output formats are identical and both feed into the scorer.
4. **The scorer is the single decision point**. All signals converge at the scorer to produce the final judgment. **No signal may fail CI on its own**.

### 5.2 Required EcosystemAdapter Interface
```
LockfileParser           # Parse lockfiles
RegistryClient           # Query registry
InstallScriptDetector    # Identify install-time execution points
HashVerifier             # Verify hashes
SourceLocator            # Locate source repo from registry metadata
```

---

## 6. Performance and Concurrency Constraints

### 6.1 Time Budget (300-dependency project)
| Stage | Per-Dependency | Concurrency | Total |
|-------|---------------|-------------|-------|
| Parse | < 1ms | serial | < 1s |
| Hash verify | ~100ms | 50 | ~1 min |
| Cheap signals | ~500ms | 20 | ~2–3 min |
| Deep analysis | ~5–15s | 5 | depends on trigger rate |

**Target**: A typical CI run completes in **under 5 minutes**. Deep analysis trigger rate must be kept within **5–10%**.

### 6.2 Mandatory Concurrency Controls
- **Per-host semaphores** (e.g., limit GitHub API to 10 concurrent calls).
- **Exponential backoff with retry cap**. Retries are bounded.
- **API token pools**: Allow users to configure multiple tokens for rotation.

### 6.3 LLM Cost Controls
- Enable prompt caching (cache the tool's system prompt).
- A hard ceiling on LLM calls per CI run is mandatory. When exceeded, downgrade to static-only analysis and clearly mark the report as "incomplete analysis".

---

## 7. Caching Strategy

### 7.1 Cache Key Design
```
cache_key = f"{package}@{version}+{hash}+{analyzer_version}"
```
**`analyzer_version` is mandatory**. When rules are updated or the LLM model is swapped, stale cache entries are automatically invalidated.

### 7.2 Three-Tier Cache
| Tier | Storage | TTL | Contents |
|------|---------|-----|----------|
| L1 | In-process memory | Single run | Parsed lockfiles, API responses |
| L2 | CI filesystem | 7 days | Hash verification, registry metadata |
| L3 | Team-shared (S3/Redis) | 30 days | LLM analysis results |

### 7.3 Forced Invalidation Triggers
- Maintainer change (even if version is unchanged)
- Package yanked / unpublished
- New CVE published
- Analyzer version upgrade

---

## 8. Allowlist Mechanism

### 8.1 Security Design Requirements
The allowlist is mandatory but is itself an attack surface. Enforced rules:

1. **Must bind to hash, not version number**. Prevents attackers from republishing a malicious package under the same version.
2. **Must include an expiration date**. Auto-expires after six months, forcing re-review.
3. **Dimension-level exemption only**. Only dimensions explicitly reviewed are exempted; new dimensional signals still trigger.
4. **Modifications to `.depaudit-allowlist.yaml` must pass CODEOWNERS review**.

### 8.2 Standard Format
```yaml
allowlist:
  - package: "requests"
    version: "2.31.0"
    hash: "sha256:abc123..."
    reason: "Reviewed by @alice, PR #123"
    reviewed_by: "alice@company.com"
    expires: "2026-11-20"
    dimensions:
      - popularity
      - vulnerability
```

---

## 9. Custom Registry Support

### 9.1 Configuration-Driven
```yaml
registries:
  python:
    - url: "https://internal.company.com/pypi"
      type: "pypi"
      auth:
        token_env: "INTERNAL_PYPI_TOKEN"
      trust_level: "trusted"
```

### 9.2 Trust Level Handling
- Packages from internal registries may have certain dimension severities reduced (e.g., popularity).
- **But hash verification and behavior detection must never be skipped** — this prevents total failure of the tool if the internal registry is compromised.

### 9.3 Dependency Confusion Detection
Detect "cross-registry namesake" cases: when a package exists with the same name in both an internal and public registry, an attacker can push a higher version to the public registry to hijack resolution. Stage 3 must mark such cases as **high**.

---

## 10. Report Output

### 10.1 Three Formats
1. **SARIF** (primary): Machine-consumable, renders natively in GitHub Security tab.
2. **Markdown**: PR comment–friendly format.
3. **JSON**: For programmatic consumption (SIEM / dashboards).

### 10.2 SARIF Default
Default to SARIF output only (no write permissions required). PR comments are opt-in to avoid demanding GitHub token write access by default.

---

## 11. Signal Collection Cheat Sheet

### Identity
- Package name edit distance ≤ 2 to a popular package → critical
- Maintainer changed within the last N days → high
- Registry-declared repo URL does not exist → high
- Maintainer email domain registered recently → medium

### Behavior
- Install-time script with network/file operations → high
- Large obfuscated / encoded string blob in source → high
- Reads environment variables and sends them externally → critical (LLM detection)
- Native binaries present without source → medium

### Provenance
- Lockfile hash ≠ registry hash → **critical**
- Registry package contents ≠ git tag contents → high
- Signature verification failed → critical
- Missing signature → low

### Popularity
- Repo archived but still publishing new versions → high
- High download count with zero stars → medium
- OpenSSF Scorecard < 3 → low

### Vulnerability
- OSV.dev critical CVE → critical
- OSV.dev high CVE → high
- Package is EOL → medium

---

## 12. Tech Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Primary language | Python | uv/pip toolchain ecosystem, mature LLM SDKs |
| Lockfile parsing | Reuse Syft → CycloneDX SBOM | No need to reinvent |
| CVE data source | OSV.dev API | Free, broad coverage |
| Hash verification | Direct calls to each registry's JSON API | Lockfile hash ⟷ registry hash |
| Repository analysis | Shallow clone + GitHub/GitLab API | Time-efficient |
| LLM | Claude API | Structured output + prompt caching |
| Scoring engine | Rule weights + LLM-confidence weighting | Explainability first |
| Report formats | SARIF + Markdown + JSON | Multi-consumer |
| CI integration | GitHub Action + standalone CLI | Exit code drives gate |

---

## 13. Development Principles (Quick Reference)

1. **Explainability > Accuracy**. CI failures must be defensible. Black-box judgments get turned off.
2. **Deterministic rules > LLM cleverness**. The LLM is a supplement, not a decision-maker.
3. **Tiered cost control**. Cheap signals run on everything; expensive signals run selectively.
4. **Graceful degradation**. Failures in network / API / LLM must not crash the tool — degrade to partial analysis and clearly annotate.
5. **Architecture allows zero-touch ecosystem additions**. Adding a new ecosystem means adding one adapter, not touching the core.
6. **Spoofable signals carry low weight**. Every signal must be evaluated for how easily an attacker could forge it.

---

## 14. Confirmed but Unimplemented

- [ ] LLM prompt template design and prompt-injection defense
- [ ] Concrete hard cap on LLM calls per CI run
- [ ] Monorepo / multi-config-file support decision
- [ ] PR comment opt-in mechanism design
- [ ] End-to-end walkthrough of real-world attacks (XZ Utils / event-stream / PyTorch dependency confusion)

---

*This is a living document. Significant architectural changes must be reflected here and pass review.*
