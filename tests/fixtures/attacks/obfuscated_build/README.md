# Fixture: `obfuscated_build` — build-script payload obfuscation (XZ-Utils-style pattern)

**This is a pattern fixture, not a replay of the real incident.** It reproduces the
*structural shape* of the XZ Utils backdoor (CVE-2024-3094) — a build-time script that
decodes a high-entropy blob and hands it to a process-spawn call — with an entirely
inert, harmless payload. No working exploit code, no real CVE, no vendored malware.

## What's here and why

| File | Role |
|---|---|
| `Cargo.lock` | The **audited project's** lockfile, pinning one dependency: `sysinfo-native-helper@0.4.2` (a fictional crate name; not a real crates.io package). This is what makes Stage 0-1 (discovery + parse) produce a real `Dependency`. |
| `Cargo.toml` | Stands in for **`sysinfo-native-helper`'s own manifest** (what an evidence-gathering step would see if it fetched that dependency's source) — declares `build = "build.rs"`. |
| `build.rs` | Stands in for that crate's own build script: a >=200-char base64 blob (entropy >= 3.5) decoded and passed to `Command::new`. Decodes to a harmless `echo`/`touch` no-op. |

`Cargo.toml`/`build.rs` are not themselves discovered as a second lockfile for a second
dependency — they exist so a specialist has real, on-disk evidence content to reason
over in the test, and so a human reviewer can see exactly what pattern this models.

## Why the Stage-3 "behavior" signal is simulated, not collected live

SafeSC's real Stage-3 behavior collector
(`safesc/tools/scan/signals/behavior/install_script.py`) only supports the `javascript`
ecosystem, and even there it decides via a **live npm registry lookup**
(`hasInstallScript`), not by reading a local file. Its own docstring says plainly:

> "Other ecosystems (Python `setup.py`, Rust `build.rs`) require inspecting the artifact
> contents and are handled by a later, download-based stage; this collector emits
> nothing for them."

There is today no static/offline Rust build-script collector at all — build.rs content
is only ever examined by Stage-4's `extract_install_scripts` (`deep_analysis_tool.py`),
which requires cloning the dependency's real source repository. Since these tests are
required to run fully offline with no network access, `tests/test_attack_fixtures.py`
constructs the `tools.scan.signals.models.Signal` such a collector *would* emit and
pushes it through the real `_scan_signal_to_graph` adapter — exercising the adapter
faithfully while documenting that the collection step itself is a stand-in. See that
test module's docstring for the full rationale, including why the simulated severity is
MEDIUM (gray-zone, pending LLM verification) rather than the real `InstallScriptCollector`'s
blunter HIGH.

This is itself a real coverage gap worth a decision — see the new "Still open" items
added to `CLAUDE.md` §9 alongside this fixture.
