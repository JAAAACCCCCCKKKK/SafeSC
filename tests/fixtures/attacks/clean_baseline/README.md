# Fixture: `clean_baseline` — negative control

**The most important fixture in this directory.** A small, entirely ordinary
`package-lock.json` pinning three widely-used, real npm packages — `lodash@4.17.21`,
`express@4.19.2`, `chalk@5.3.0` — at their real published versions, with no install
scripts and no name that resembles a typosquat (they *are* the popular names, matched
exactly, so the real `TyposquatCollector`'s "this is the popular package, not a
typosquat" short-circuit applies).

`integrity` values are the real published npm `dist.integrity` hashes for these exact
versions (fetched once while authoring this fixture; the file itself is static
afterwards — no network access is needed to use it). They matter beyond this suite:
SafeSC's *other* tests exercise the legacy CLI against the whole repository working
directory (e.g. `tests/test_cli_scan.py::test_legacy_no_args_uses_cwd`, which calls
`scan --verify` with no path and defaults to `cwd`), so a wrong hash here would trip a
real Stage-2 "critical hash mismatch" against the live registry and fail an unrelated
test. `tests/test_attack_fixtures.py` itself does not exercise Stage 2 (see its module
docstring), so this fixture's own tests do not depend on the hashes being correct — but
keeping them correct is what keeps this fixture a good citizen of the rest of the repo.

A detector that flags this fixture is a false positive. `tests/test_attack_fixtures.py`
asserts the inverse of every attack-fixture assertion against this one: no Stage-3
identity signal, no gate fan-out, the audit gate passes (`exit_code == 0`), and
`degraded_notes` is empty — a clean pass that isn't secretly the product of everything
degrading into silence.
