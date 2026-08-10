# Fixture: `name_confusion` — typosquat / dependency-confusion pattern

**This is a pattern fixture, not a replay of any real incident.** `requirements.txt`
pins `reqeusts==2.31.0` — a two-character transposition of the real, very popular PyPI
package [`requests`](https://pypi.org/project/requests/) (edit distance 2: `u`/`e`
swapped). This is the exact example already used in SafeSC's own
`safesc/tools/scan/signals/identity/typosquat.py` docstring as the canonical "looks like
a squat, could also just be a typo — needs LLM verification" case, so this fixture runs
against the **real, offline `TyposquatCollector`** end-to-end (no network is needed for
this collector: it is pure local Levenshtein-distance comparison against a curated
popular-package list — see `identity/popular_packages.py`).

`reqeusts` is not a real, currently-registered package as far as this fixture is
concerned; the version pin `2.31.0` is chosen only to match a real `requests` release for
readability. No code from any real or fictional package is vendored here — this file is
a single line of lockfile-format text.

Unlike the two behavior fixtures, no Stage-3 signal is simulated here: the identity
dimension's typosquat check is genuinely deterministic and network-free in production, so
this fixture exercises the *real* collector, not a stand-in for one.
