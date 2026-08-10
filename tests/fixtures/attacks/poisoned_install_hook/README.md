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

## Why the Stage-3 "behavior" signal is simulated, not collected live

SafeSC's real Stage-3 collector for this
(`safesc/tools/scan/signals/behavior/install_script.py::InstallScriptCollector`) decides
via a **live npm registry lookup** (`hasInstallScript`), not by reading
`package.json`/`scripts/setup.js` from disk. Since these tests must run fully offline
with no network access, `tests/test_attack_fixtures.py` constructs the
`tools.scan.signals.models.Signal` the real collector would emit for a package the
registry reports as having an install script, and pushes it through the real
`_scan_signal_to_graph` adapter — exercising the adapter faithfully while documenting
that the live registry call itself is stood in for. See that test module's docstring
for the full rationale.
