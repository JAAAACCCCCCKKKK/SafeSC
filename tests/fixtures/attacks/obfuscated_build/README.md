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

## How the Stage-3 "behavior" signal is produced

`tests/test_attack_fixtures.py` runs the **real** Stage-3 collector
(`safesc/tools/scan/signals/behavior/install_script.py::InstallScriptCollector`) against
this fixture's dependency, with only its one underlying network call
(`get_package_metadata`, a live crates.io lookup in production) mocked to return a
canned response — the same mocking pattern the collector's own unit tests use
(`test_stage3_signals.py::TestInstallScriptCollector`). Everything else — ecosystem
dispatch, dimension, severity (`MEDIUM`), code, message, and evidence — is real,
unmodified production logic. `MEDIUM` rather than `HIGH` is deliberate: declaring a
Cargo `links` key is routine for every `-sys` crate, so the signal lands in the gray
zone for BehaviorAgent verification instead of failing a CI gate on its own (see
`install_script.py`'s "Why severities differ"). This fixture still fails the gate in
the end — but only once the specialist confirms malicious intent, which is exactly the
escalate-only design working as intended.

Rust coverage in `InstallScriptCollector` is itself real, not fixture-only scaffolding:
crates.io exposes a `lib_links` field on each published version, which mirrors the
crate's Cargo.toml `links` key — and Cargo *requires* a build script whenever `links` is
set. A non-null `lib_links` is therefore a sound, zero-false-positive proxy for "this
crate has a build script" (verified live against crates.io while building this:
`openssl-sys`/`libz-sys` are flagged, `serde`/`log` are not). It is, however,
**incomplete**: a crate whose `build.rs` exists purely for codegen — no native linking,
no `links` key — is not caught by this Stage-3 signal at all, and still needs Stage-4's
`extract_install_scripts` (`deep_analysis_tool.py`, which clones the real source repo)
to be seen. This gap is recorded in `CLAUDE.md` §9.
