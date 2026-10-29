"""agents/harness/validation.py — the constraint validator for subagent outputs (§2.7.1).

Schema validity is enforced by Strands' structured output (a Pydantic model the model must
fill). What a schema cannot express is checked here, before anything reaches the ledger:

* every **file citation** must name a file the subagent was actually shown — a tool output
  registered as citable for that dependency, or a file in its fetched workspace. This blocks
  hallucinated evidence, and it is what makes memory safe (§3.3): agreeing with a retrieved
  prior verdict still requires citing current evidence;
* a **hunter** may only claim flaws in files that exist in the workspace;
* a **verifier** must address every pending candidate for the dependency and may not
  invent new ones — it confirms or refutes claims, it does not make them.

A violation is fed back to the same subagent for repair, on a counter independent of any
infrastructure retry; on exhaustion the run records a coverage gap rather than a signal.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

_PATH_TOKEN = re.compile(r"[\w./\\-]+\.[A-Za-z0-9]{1,6}")
_PROSE_DOTTED = frozenset({"e.g", "i.e", "etc", "vs", "cf", "et.al", "a.k.a", "aka"})
_FILE_EXTENSIONS = frozenset({
    "py", "pyx", "js", "mjs", "cjs", "ts", "tsx", "jsx", "rs", "go", "java", "kt",
    "json", "toml", "cfg", "ini", "txt", "md", "rst", "sh", "ps1", "bat",
    "yml", "yaml", "lock", "cff", "gradle", "xml", "c", "h", "cc", "cpp", "hpp", "rb", "php", "m4", "in",
})


def _looks_like_file(token: str) -> bool:
    lowered = token.lower()
    if lowered in _PROSE_DOTTED:
        return False
    if "/" in token or "\\" in token:
        return True
    return lowered.rsplit(".", 1)[-1] in _FILE_EXTENSIONS


def _norm(path: str, roots: Iterable[str] = ()) -> str:
    p = path.replace("\\", "/").strip()
    for root in roots:
        r = root.replace("\\", "/").rstrip("/") + "/"
        if p.startswith(r):
            p = p[len(r):]
    return p.removeprefix("./")


def _matches(cited: str, known: Iterable[str]) -> bool:
    return any(cited == k or k.endswith("/" + cited) or cited.endswith("/" + k) or k.endswith(cited) for k in known)


def unresolved_refs(evidence: Iterable[str], citable: set[str], roots: Iterable[str] = ()) -> list[str]:
    """Evidence entries that cite a file absent from everything the agent was shown.
    Prose, versions and refs with no file-like token are not checkable and pass."""
    roots = list(roots)
    known = {_norm(c, roots) for c in citable}
    bad = []
    for ref in evidence:
        cited = {_norm(t, roots) for t in _PATH_TOKEN.findall(ref) if _looks_like_file(t)}
        if cited and not any(_matches(c, known) for c in cited):
            bad.append(ref)
    return bad


def check_judgement(evidence: list[str], citable: set[str], roots: Iterable[str] = ()) -> Optional[str]:
    bad = unresolved_refs(evidence, citable, roots)
    if bad:
        return (
            f"evidence cites file(s) you were never shown: {bad[:5]}. Cite only files returned by "
            "your tools (relative paths) or registry facts, and nothing from prior findings alone."
        )
    return None


def check_hunt(claims, workspace_files: set[str], roots: Iterable[str] = ()) -> Optional[str]:
    roots = list(roots)
    missing = [c.file for c in claims if not _matches(_norm(c.file, roots), workspace_files)]
    if missing:
        return (
            f"candidate file(s) do not exist in the fetched workspace: {missing[:5]}. Use paths "
            "relative to the workspace root, as printed by your tools."
        )
    for c in claims:
        problem = check_judgement(c.evidence, workspace_files, roots)
        if problem:
            return problem
    return None


def check_verification(results, pending_ids: set[str], citable: set[str], roots: Iterable[str] = ()) -> Optional[str]:
    seen = {r.candidate_id for r in results}
    unknown = sorted(seen - pending_ids)
    if unknown:
        return f"unknown candidate id(s) {unknown}: verify only the listed candidates, do not add new ones."
    missing = sorted(pending_ids - seen)
    if missing:
        return f"you did not return a verdict for candidate(s) {missing}; every listed candidate needs one."
    for r in results:
        if r.status == "confirmed" and not r.evidence:
            return f"{r.candidate_id} is 'confirmed' without evidence; cite the file:line lines you read."
        problem = check_judgement(r.evidence, citable, roots)
        if problem:
            return problem
    return None
