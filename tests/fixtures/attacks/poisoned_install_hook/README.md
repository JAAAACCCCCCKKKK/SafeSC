# Fixture: `poisoned_install_hook` — postinstall remote-fetch pattern (event-stream-style)

**This is a pattern fixture, not a replay of the real incident.** It reproduces the
*structural shape* of the event-stream / flatmap-stream postinstall attack — a hook that
touches the network, reads environment variables, and `eval()`s a decoded string — with
an entirely inert payload. No working exploit code, no vendored malware.

## What's here and why

| File | Role |
|---|---|
| `package-lock.json` | The **audited project's** lockfile, pinning `fast-json-utilities@3.1.4` (a fictional package name; not a real npm package). `package.json` alone is **not** a discovered lockfile in SafeSC's JavaScript adapter (`lockfile_globs` only covers `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` / `npm-shrinkwrap.json`), so the lockfile is required for Stage 0-1 to produce a real `Dependency`. |
| `package.json` | Stands in for `fast-json-utilities`'s own manifest: declares `"scripts": {"postinstall": "node ./scripts/setup.js"}`. |
| `scripts/setup.js` | The postinstall payload: references `https` (network), `process.env` (env), and `eval()` on a base64-decoded string (dynamic exec on encoded data). All inert — decodes to a harmless `console.log`. |

## How the Stage-3 "behavior" signal is produced

`tests/test_attack_fixtures.py` runs the **real** Stage-3 collector
(`safesc/tools/scan/signals/behavior/install_script.py::InstallScriptCollector`) against
this fixture's dependency, with only its one underlying network call
(`get_package_metadata`, a live npm registry lookup for `hasInstallScript` in
production) mocked to return a canned response — the same mocking pattern the
collector's own unit tests use (`test_stage3_signals.py::TestInstallScriptCollector`).
Everything else — dimension, severity (`HIGH`), code, message, and evidence — is real,
unmodified production logic; only the HTTP round-trip is stood in for, since these tests
must run fully offline with no network access.
