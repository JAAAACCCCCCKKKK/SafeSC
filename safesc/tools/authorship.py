"""tools/authorship.py — deterministic code-style authorship profiling. LLM-free.

Question it serves: *was the code in this release written by the person the account says
wrote it?* An account taken over through social engineering, or a project quietly handed to
a new maintainer, usually still commits under a trusted identity — but the hands on the
keyboard change, and hands leave fingerprints:

* **code style** of the lines each commit adds: indentation, line length, quoting,
  semicolons, brace placement, naming convention, comment density;
* **commit habits**: message length and conventions, capitalisation, trailing periods;
* **operational traits**: timezone offset, hour-of-day, whether commits are signed, whether
  author and committer differ, the email domain.

`profile_repository` splits the history behind the release into a *window* (the most recent
commits leading to it) and a *baseline* (everything older), then compares each window
author against their own baseline — or, for an author with no history, against the
project's established maintainers. It reports raw feature values, normalised drift and the
notable shifts, plus a few code samples for side-by-side reading. It never decides anything:
the AuthorshipAgent weighs the drift, because a refactor, a new formatter or a co-maintainer
legitimately moves these numbers too.
"""

from __future__ import annotations

import os
import re
import statistics
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

GIT_TIMEOUT_S = 60
MAX_ADDED_LINES_PER_COMMIT = 400
MAX_LINES_PER_GROUP = 6_000
MIN_BASELINE_COMMITS = 3
SAMPLE_LINES = 20

CODE_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs", ".go", ".java", ".kt",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".rb", ".php", ".sh",
}
_CONVENTIONAL = re.compile(r"^(feat|fix|chore|docs|refactor|test|tests|ci|build|perf|style|revert)(\([^)]*\))?!?:", re.I)
_DEF_NAME = re.compile(r"\b(?:def|function|fn|func|let|const|var)\s+([A-Za-z_][A-Za-z0-9_]*)")
_SNAKE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$")
_CAMEL = re.compile(r"^[a-z]+([A-Z][a-z0-9]*)+$")
_SEP = "\x1f"


@dataclass
class Commit:
    sha: str
    author: str
    email: str
    committer_email: str
    when: datetime
    signature: str
    subject: str

    @property
    def identity(self) -> str:
        return self.email.lower() or self.author


@dataclass
class StyleFeatures:
    """Numeric fingerprint of a body of added code + its commits. Ratios are in [0, 1]."""

    lines: int = 0
    commits: int = 0
    tab_indent_ratio: float = 0.0
    indent_width: int = 0
    mean_line_length: float = 0.0
    single_quote_ratio: float = 0.0
    semicolon_ratio: float = 0.0
    comment_ratio: float = 0.0
    blank_ratio: float = 0.0
    brace_same_line_ratio: float = 0.0
    snake_case_ratio: float = 0.0
    msg_mean_length: float = 0.0
    msg_conventional_ratio: float = 0.0
    msg_capitalized_ratio: float = 0.0
    msg_trailing_period_ratio: float = 0.0
    signed_ratio: float = 0.0
    committer_differs_ratio: float = 0.0
    night_ratio: float = 0.0
    dominant_utc_offset: str = ""
    email_domains: list[str] = field(default_factory=list)


# Ratio features compared directly; a difference of 1.0 is total drift.
_RATIO_FEATURES = (
    "tab_indent_ratio", "single_quote_ratio", "semicolon_ratio", "comment_ratio", "blank_ratio",
    "brace_same_line_ratio", "snake_case_ratio", "msg_conventional_ratio", "msg_capitalized_ratio",
    "msg_trailing_period_ratio", "signed_ratio", "committer_differs_ratio", "night_ratio",
)


@dataclass
class AuthorComparison:
    author: str
    window_commits: int
    baseline_commits: int
    first_seen: Optional[str]
    compared_against: str  # "own history" | "project maintainers" | "nothing (no baseline)"
    window: StyleFeatures
    baseline: Optional[StyleFeatures]
    drift: dict[str, float] = field(default_factory=dict)
    drift_index: float = 0.0
    notable_shifts: list[str] = field(default_factory=list)
    window_sample: str = ""
    baseline_sample: str = ""


@dataclass
class AuthorshipProfile:
    repository: str
    history_commits: int
    window_size: int
    authors: list[AuthorComparison] = field(default_factory=list)
    project_notes: list[str] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        import dataclasses

        return dataclasses.asdict(self)


def _git(root: Path, *args: str) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "-c", "core.hooksPath=/dev/null", *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=GIT_TIMEOUT_S, check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout if proc.returncode == 0 else None


def read_commits(root: Path, limit: int = 400) -> list[Commit]:
    fmt = _SEP.join(["%H", "%an", "%ae", "%ce", "%aI", "%G?", "%s"])
    out = _git(root, "log", f"-{limit}", "--no-merges", f"--format={fmt}", "--no-color")
    commits: list[Commit] = []
    for line in (out or "").splitlines():
        parts = line.split(_SEP)
        if len(parts) != 7:
            continue
        sha, an, ae, ce, when, sig, subject = parts
        try:
            stamp = datetime.fromisoformat(when)
        except ValueError:
            continue
        commits.append(Commit(sha, an, ae, ce, stamp, sig, subject))
    return commits


def added_lines(root: Path, sha: str) -> list[str]:
    out = _git(root, "show", "--format=", "--unified=0", "--no-color", "--no-ext-diff", sha) or ""
    lines: list[str] = []
    current_is_code = False
    for raw in out.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            current_is_code = Path(path[2:] if path.startswith("b/") else path).suffix.lower() in CODE_SUFFIXES
            continue
        if raw.startswith("+") and current_is_code:
            lines.append(raw[1:])
            if len(lines) >= MAX_ADDED_LINES_PER_COMMIT:
                break
    return lines


def _ratio(n: int, d: int) -> float:
    return round(n / d, 3) if d else 0.0


def features(commits: list[Commit], code: list[str]) -> StyleFeatures:
    f = StyleFeatures(lines=len(code), commits=len(commits))
    nonblank = [ln for ln in code if ln.strip()]
    indented = [ln for ln in nonblank if ln[:1] in (" ", "\t")]
    f.tab_indent_ratio = _ratio(sum(ln.startswith("\t") for ln in indented), len(indented))
    widths = Counter(len(ln) - len(ln.lstrip(" ")) for ln in indented if ln.startswith(" "))
    small = [w for w, _ in widths.most_common() if w in (2, 3, 4, 8)]
    f.indent_width = small[0] if small else 0
    f.mean_line_length = round(statistics.fmean(len(ln) for ln in nonblank), 1) if nonblank else 0.0
    singles = sum(ln.count("'") for ln in nonblank)
    doubles = sum(ln.count('"') for ln in nonblank)
    f.single_quote_ratio = _ratio(singles, singles + doubles)
    stmt = [ln.rstrip() for ln in nonblank if not ln.strip().startswith(("#", "//", "/*", "*"))]
    f.semicolon_ratio = _ratio(sum(ln.endswith(";") for ln in stmt), len(stmt))
    f.comment_ratio = _ratio(sum(ln.strip().startswith(("#", "//", "/*", "*")) for ln in nonblank), len(nonblank))
    f.blank_ratio = _ratio(len(code) - len(nonblank), len(code))
    same = sum(ln.rstrip().endswith("{") and ln.strip() != "{" for ln in nonblank)
    alone = sum(ln.strip() == "{" for ln in nonblank)
    f.brace_same_line_ratio = _ratio(same, same + alone)
    names = [m for ln in nonblank for m in _DEF_NAME.findall(ln)]
    snake = sum(bool(_SNAKE.match(n)) for n in names)
    camel = sum(bool(_CAMEL.match(n)) for n in names)
    f.snake_case_ratio = _ratio(snake, snake + camel)
    if commits:
        subjects = [c.subject for c in commits]
        f.msg_mean_length = round(statistics.fmean(len(s) for s in subjects), 1)
        f.msg_conventional_ratio = _ratio(sum(bool(_CONVENTIONAL.match(s)) for s in subjects), len(subjects))
        f.msg_capitalized_ratio = _ratio(sum(s[:1].isupper() for s in subjects), len(subjects))
        f.msg_trailing_period_ratio = _ratio(sum(s.rstrip().endswith(".") for s in subjects), len(subjects))
        f.signed_ratio = _ratio(sum(c.signature not in ("N", "") for c in commits), len(commits))
        f.committer_differs_ratio = _ratio(
            sum(c.committer_email.lower() != c.email.lower() for c in commits), len(commits)
        )
        f.night_ratio = _ratio(sum(c.when.hour < 6 for c in commits), len(commits))
        offsets = Counter(c.when.strftime("%z") for c in commits)
        f.dominant_utc_offset = offsets.most_common(1)[0][0] if offsets else ""
        f.email_domains = sorted({c.email.split("@")[-1].lower() for c in commits if "@" in c.email})
    return f


def compare(window: StyleFeatures, baseline: StyleFeatures) -> tuple[dict[str, float], float, list[str]]:
    drift: dict[str, float] = {}
    for name in _RATIO_FEATURES:
        drift[name] = round(abs(getattr(window, name) - getattr(baseline, name)), 3)
    if baseline.mean_line_length:
        drift["mean_line_length"] = round(
            min(1.0, abs(window.mean_line_length - baseline.mean_line_length) / max(baseline.mean_line_length, 1.0)), 3
        )
    drift["indent_width"] = 0.0 if not (window.indent_width and baseline.indent_width) else float(
        window.indent_width != baseline.indent_width
    )
    drift["utc_offset"] = float(bool(window.dominant_utc_offset and baseline.dominant_utc_offset
                                     and window.dominant_utc_offset != baseline.dominant_utc_offset))
    index = round(statistics.fmean(drift.values()), 3) if drift else 0.0

    shifts: list[str] = []
    if baseline.signed_ratio >= 0.6 and window.signed_ratio <= 0.2:
        shifts.append(f"commit signing stopped ({baseline.signed_ratio:.0%} signed before, {window.signed_ratio:.0%} now)")
    if drift["utc_offset"]:
        shifts.append(f"timezone changed ({baseline.dominant_utc_offset} -> {window.dominant_utc_offset})")
    if drift["indent_width"]:
        shifts.append(f"indent width changed ({baseline.indent_width} -> {window.indent_width})")
    for name in ("tab_indent_ratio", "single_quote_ratio", "semicolon_ratio", "snake_case_ratio",
                 "brace_same_line_ratio", "msg_conventional_ratio", "msg_capitalized_ratio"):
        if drift[name] >= 0.5:
            shifts.append(f"{name} {getattr(baseline, name)} -> {getattr(window, name)}")
    new_domains = set(window.email_domains) - set(baseline.email_domains)
    if new_domains and baseline.email_domains:
        shifts.append(f"new email domain(s): {', '.join(sorted(new_domains))}")
    return drift, index, shifts


def _sample(code: list[str]) -> str:
    chunk = [ln for ln in code if ln.strip()][:SAMPLE_LINES]
    return "\n".join(ln[:160] for ln in chunk)


def _code_for(root: Path, commits: list[Commit]) -> list[str]:
    code: list[str] = []
    for c in commits:
        code.extend(added_lines(root, c.sha))
        if len(code) >= MAX_LINES_PER_GROUP:
            break
    return code[:MAX_LINES_PER_GROUP]


def profile_repository(root: Path, *, window: int = 25, history: int = 400, repository: str = "") -> AuthorshipProfile:
    """Compare the authors of the most recent `window` commits with the history behind them."""
    commits = read_commits(root, limit=history)
    prof = AuthorshipProfile(repository=repository or str(root), history_commits=len(commits), window_size=0)
    if not commits:
        prof.degraded.append("no readable git history (missing git, shallow/empty clone, or unreadable repository)")
        return prof
    win, base = commits[:window], commits[window:]
    prof.window_size = len(win)
    if len(base) < MIN_BASELINE_COMMITS:
        prof.degraded.append(
            f"only {len(base)} commit(s) older than the release window; the baseline is too thin to compare reliably"
        )

    by_author_win = Counter(c.identity for c in win)
    by_author_base = Counter(c.identity for c in base)
    first_seen: dict[str, datetime] = {}
    for c in commits:
        first_seen[c.identity] = min(first_seen.get(c.identity, c.when), c.when)

    maintainers = [a for a, _ in by_author_base.most_common(3)]
    maint_commits = [c for c in base if c.identity in maintainers]
    maint_features = features(maint_commits, _code_for(root, maint_commits)) if maint_commits else None
    if maintainers:
        prof.project_notes.append("established maintainers: " + ", ".join(maintainers))

    for author, n_win in by_author_win.most_common(5):
        a_win = [c for c in win if c.identity == author]
        a_base = [c for c in base if c.identity == author]
        win_code = _code_for(root, a_win)
        wf = features(a_win, win_code)
        if len(a_base) >= MIN_BASELINE_COMMITS:
            base_code = _code_for(root, a_base)
            bf, against = features(a_base, base_code), "own history"
        elif maint_features is not None and author not in maintainers:
            bf, against = maint_features, "project maintainers"
            base_code = _code_for(root, maint_commits)
        else:
            bf, against, base_code = None, "nothing (no baseline)", []
        cmp = AuthorComparison(
            author=author,
            window_commits=n_win,
            baseline_commits=len(a_base),
            first_seen=first_seen[author].isoformat() if author in first_seen else None,
            compared_against=against,
            window=wf,
            baseline=bf,
            window_sample=_sample(win_code),
            baseline_sample=_sample(base_code),
        )
        if bf is not None:
            cmp.drift, cmp.drift_index, cmp.notable_shifts = compare(wf, bf)
        if not a_base and n_win >= max(2, len(win) // 3):
            cmp.notable_shifts.insert(
                0, f"author has no commits before the release window yet wrote {n_win}/{len(win)} of it"
            )
        prof.authors.append(cmp)
    return prof
