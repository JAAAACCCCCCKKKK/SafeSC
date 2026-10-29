"""tools/vulnscan.py — deterministic hidden-risk scanner over a dependency's source. LLM-free.

Finds *candidate* locations of unreported vulnerabilities — not vulnerabilities. Every hit is
a fact ("this line calls strcpy", "this password is hashed with unsalted SHA-1", "this
module imports a package with published advisories") for the VulnHunter subagent to triage
and the VulnVerifier subagent to independently confirm or refute. Nothing here produces a
severity that reaches the gate: per the v2.11 rule, a pattern match is a build/coding fact,
and only a verified finding may escalate.

Three detectors:

* `scan_tree` — line rules for unsafe functions, injection sinks, unsafe deserialisation,
  weak or misapplied cryptography on confidential inputs, disabled TLS verification,
  predictable randomness for secrets, hard-coded secrets and curated unsafe imports;
* `declared_dependencies` — what the dependency itself depends on, from its manifest;
* `search_tree` — a literal (never regex: no attacker-reachable ReDoS) text search the
  subagents use to follow a lead.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 8_000
MAX_FINDINGS = 200
MAX_PER_RULE = 15
SNIPPET_CHARS = 220

LANG_BY_SUFFIX = {
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c", ".hh": "c",
    ".py": "python", ".pyx": "python",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
    ".rs": "rust", ".go": "go", ".java": "java", ".kt": "java",
}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".tox", "target", "dist", "build", "vendor", "third_party"}
_TEST_PATH = re.compile(r"(^|/)(tests?|spec|__tests__|testing|examples?|docs?|benchmarks?|fixtures?)(/|$)|_test\.|\.test\.|\.spec\.", re.I)
_SECRET_WORDS = r"(passw(or)?d|passwd|pwd|secret|token|api[_-]?key|credential|private[_-]?key)"


@dataclass(frozen=True)
class Rule:
    id: str
    languages: frozenset[str]
    pattern: re.Pattern
    cwe: str
    title: str
    category: str
    severity_hint: str  # low | medium | high — a starting point for triage, never a verdict
    requires: Optional[re.Pattern] = None  # must also match the same line
    excludes: Optional[re.Pattern] = None  # a match here makes the line safe (e.g. SafeLoader)


def _r(rid, langs, pattern, cwe, title, category, sev, requires=None, excludes=None) -> Rule:
    return Rule(
        rid, frozenset(langs), re.compile(pattern), cwe, title, category, sev,
        re.compile(requires, re.I) if requires else None,
        re.compile(excludes) if excludes else None,
    )


ALL = ("c", "python", "js", "rust", "go", "java")

RULES: tuple[Rule, ...] = (
    # --- unsafe C library functions -----------------------------------------------------
    _r("C-STRCPY", ["c"], r"\bstrcpy\s*\(", "CWE-120", "Unbounded string copy (strcpy)", "unsafe-function", "high"),
    _r("C-STRCAT", ["c"], r"\bstrcat\s*\(", "CWE-120", "Unbounded string concatenation (strcat)", "unsafe-function", "high"),
    _r("C-SPRINTF", ["c"], r"\bv?sprintf\s*\(", "CWE-120", "Unbounded formatted write (sprintf)", "unsafe-function", "medium"),
    _r("C-GETS", ["c"], r"\bgets\s*\(", "CWE-242", "Inherently dangerous function (gets)", "unsafe-function", "high"),
    _r("C-SCANF-S", ["c"], r"\b[fs]?scanf\s*\([^;]*%s", "CWE-120", "Unbounded %s read (scanf)", "unsafe-function", "high"),
    _r("C-SYSTEM", ["c"], r"\b(system|popen)\s*\(", "CWE-78", "Shell command execution", "command-injection", "medium"),
    _r("C-WEAKHASH", ["c"], r"\b(MD5_Init|MD5\s*\(|SHA1_Init|SHA1\s*\()", "CWE-327", "Weak hash function", "weak-crypto", "low"),
    # --- python ------------------------------------------------------------------------
    _r("PY-EVAL", ["python"], r"(?<![\w.])(eval|exec)\s*\(", "CWE-95", "Dynamic code evaluation", "code-injection", "medium"),
    _r("PY-DESERIALIZE", ["python"], r"\b(pickle|cPickle|dill|marshal|shelve)\.(loads?|Unpickler|open)\b",
       "CWE-502", "Unsafe deserialization", "deserialization", "high"),
    _r("PY-YAML-LOAD", ["python"], r"\byaml\.(load|load_all)\s*\(", "CWE-502", "yaml.load without SafeLoader",
       "deserialization", "high", excludes=r"Loader\s*=\s*(yaml\.)?C?SafeLoader"),
    _r("PY-SHELL", ["python"], r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True|\bos\.(system|popen)\s*\(",
       "CWE-78", "Shell command execution", "command-injection", "medium"),
    _r("PY-TLS-OFF", ["python"], r"verify\s*=\s*False|_create_unverified_context|CERT_NONE",
       "CWE-295", "TLS certificate verification disabled", "tls", "medium"),
    _r("PY-SECRET-HASH", ["python"], r"hashlib\.(md5|sha1|sha224|sha256|sha512|new)\s*\(",
       "CWE-916", "Confidential input hashed with a fast, unsalted hash", "secret-handling", "high", requires=_SECRET_WORDS),
    _r("PY-SECRET-COMPARE", ["python"], r"(?i)" + _SECRET_WORDS + r"\w*\s*(==|!=)",
       "CWE-208", "Secret compared with a non-constant-time operator", "secret-handling", "low"),
    _r("PY-SECRET-RANDOM", ["python"], r"\brandom\.(random|randint|choice|choices|randrange|getrandbits)\s*\(",
       "CWE-338", "Predictable randomness used for a secret", "randomness", "medium", requires=_SECRET_WORDS),
    _r("PY-SECRET-LOG", ["python"], r"\b(log(ger|ging)?\.\w+|print)\s*\(",
       "CWE-532", "Confidential value written to a log", "secret-handling", "low", requires=_SECRET_WORDS),
    _r("PY-MKTEMP", ["python"], r"\btempfile\.mktemp\s*\(", "CWE-377", "Insecure temporary file", "unsafe-function", "low"),
    # --- javascript / typescript -------------------------------------------------------
    _r("JS-EVAL", ["js"], r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(", "CWE-95", "Dynamic code evaluation", "code-injection", "medium"),
    _r("JS-EXEC", ["js"], r"\b(exec|execSync)\s*\(\s*(`|[^,)]*\+)", "CWE-78", "Shell command built from a dynamic string",
       "command-injection", "high"),
    _r("JS-VM", ["js"], r"\bvm\.(runInThisContext|runInNewContext|runInContext)\s*\(", "CWE-95", "Code evaluated through vm", "code-injection", "medium"),
    _r("JS-TLS-OFF", ["js"], r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED",
       "CWE-295", "TLS certificate verification disabled", "tls", "medium"),
    _r("JS-SECRET-HASH", ["js"], r"createHash\(\s*['\"](md5|sha1|sha256)['\"]",
       "CWE-916", "Confidential input hashed with a fast, unsalted hash", "secret-handling", "high", requires=_SECRET_WORDS),
    _r("JS-SECRET-RANDOM", ["js"], r"\bMath\.random\s*\(", "CWE-338", "Predictable randomness used for a secret",
       "randomness", "medium", requires=_SECRET_WORDS),
    _r("JS-UNSERIALIZE", ["js"], r"\bunserialize\s*\(", "CWE-502", "Unsafe deserialization", "deserialization", "high"),
    # --- rust / go / java --------------------------------------------------------------
    _r("RS-TRANSMUTE", ["rust"], r"\bmem::transmute\b", "CWE-843", "Unchecked type reinterpretation", "memory-safety", "medium"),
    _r("RS-RAW-PARTS", ["rust"], r"\bfrom_raw_parts(_mut)?\s*\(", "CWE-119", "Slice built from a raw pointer", "memory-safety", "medium"),
    _r("GO-SHELL", ["go"], r"exec\.Command\(\s*\"(sh|bash|cmd(\.exe)?)\"", "CWE-78", "Shell command execution", "command-injection", "medium"),
    _r("GO-TLS-OFF", ["go"], r"InsecureSkipVerify\s*:\s*true", "CWE-295", "TLS certificate verification disabled", "tls", "medium"),
    _r("GO-WEAKCRYPTO", ["go"], r"\b(md5|sha1|des|rc4)\.(New|Sum)", "CWE-327", "Weak cryptographic primitive", "weak-crypto", "low"),
    _r("JAVA-EXEC", ["java"], r"Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder\s*\(", "CWE-78", "Process execution", "command-injection", "medium"),
    _r("JAVA-DESERIALIZE", ["java"], r"\bnew\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)", "CWE-502", "Unsafe deserialization", "deserialization", "high"),
    _r("JAVA-WEAKHASH", ["java"], r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"", "CWE-327", "Weak hash function", "weak-crypto", "low"),
    _r("JAVA-TLS-OFF", ["java"], r"TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier", "CWE-295",
       "TLS certificate verification disabled", "tls", "medium"),
    # --- every language ----------------------------------------------------------------
    _r("SECRET-AWS-KEY", ALL, r"\bAKIA[0-9A-Z]{16}\b", "CWE-798", "Hard-coded AWS access key", "hardcoded-secret", "high"),
    _r("SECRET-PRIVATE-KEY", ALL, r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "CWE-798",
       "Hard-coded private key", "hardcoded-secret", "high"),
    _r("SECRET-LITERAL", ALL, r"(?i)" + _SECRET_WORDS + r"\w*\s*[:=]\s*['\"][^'\"\s]{12,}['\"]", "CWE-798",
       "Hard-coded credential literal", "hardcoded-secret", "medium"),
)

# Modules with published, unfixed-by-design or long-abandoned security problems. Importing
# one is a lead, not a finding: plenty of code imports pickle safely.
UNSAFE_IMPORTS: dict[str, dict[str, str]] = {
    "python": {
        "pickle": "arbitrary code execution on untrusted input (CWE-502)",
        "cPickle": "arbitrary code execution on untrusted input (CWE-502)",
        "marshal": "not secure against malicious data (CWE-502)",
        "shelve": "pickle-backed; unsafe on untrusted files (CWE-502)",
        "telnetlib": "cleartext protocol, removed in Python 3.13 (CWE-319)",
        "Crypto": "PyCrypto: abandoned since 2013, CVE-2013-7459 (CWE-1104)",
        "md5": "legacy weak-hash module (CWE-327)",
    },
    "js": {
        "node-serialize": "deserialization RCE, CVE-2017-5941 (CWE-502)",
        "vm2": "deprecated sandbox with unfixable escapes, CVE-2023-37466 (CWE-693)",
        "safe-eval": "sandbox escape, CVE-2017-16088 (CWE-95)",
        "static-eval": "sandbox escape, CVE-2017-16226 (CWE-95)",
        "request": "deprecated and unmaintained since 2020 (CWE-1104)",
        "serialize-to-js": "deserialization RCE, CVE-2017-5954 (CWE-502)",
    },
    "go": {
        "crypto/md5": "weak hash (CWE-327)",
        "crypto/des": "weak cipher (CWE-327)",
        "crypto/rc4": "broken cipher (CWE-327)",
    },
}
_PY_IMPORT = re.compile(r"^\s*(?:import\s+([\w.,\s]+?)\s*(?:#.*)?$|from\s+([\w.]+)\s+import)")
_JS_IMPORT = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]""")
_GO_IMPORT = re.compile(r'^\s*(?:import\s+)?(?:\w+\s+)?"([\w./\-]+)"\s*$')


@dataclass
class Finding:
    rule_id: str
    title: str
    cwe: str
    category: str
    severity_hint: str
    file: str
    line: int
    snippet: str
    in_test_code: bool

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class ScanReport:
    files_scanned: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    truncated: bool = False

    def as_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "languages": self.languages,
            "rule_hit_counts": self.counts,
            "truncated": self.truncated,
            "findings": [f.as_dict() for f in self.findings],
        }


def iter_source_files(root: Path) -> Iterable[tuple[Path, str]]:
    count = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(p in _SKIP_DIRS for p in rel_parts[:-1]):
            continue
        lang = LANG_BY_SUFFIX.get(path.suffix.lower())
        if lang is None or path.name.endswith(".min.js"):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        count += 1
        if count > MAX_FILES:
            return
        yield path, lang


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _imports(lang: str, line: str) -> list[str]:
    if lang == "python":
        m = _PY_IMPORT.match(line)
        if m and m.group(2):
            return [m.group(2).split(".")[0]]
        if m:  # `import a, b.c as d` -> ["a", "b"]
            return [part.split()[0].split(".")[0] for part in m.group(1).split(",") if part.strip()]
    elif lang == "js":
        return [a or b for a, b in _JS_IMPORT.findall(line)]
    elif lang == "go":
        m = _GO_IMPORT.match(line)
        if m:
            return [m.group(1)]
    return []


def scan_tree(root: Path) -> ScanReport:
    report = ScanReport()
    per_rule: dict[str, int] = {}
    for path, lang in iter_source_files(root):
        text = _read(path)
        if text is None:
            continue
        report.files_scanned += 1
        report.languages[lang] = report.languages.get(lang, 0) + 1
        rel = path.relative_to(root).as_posix()
        in_test = bool(_TEST_PATH.search(rel))
        rules = [r for r in RULES if lang in r.languages]
        unsafe = UNSAFE_IMPORTS.get(lang, {})
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > 2_000:
                continue  # minified/generated — would only produce noise
            hits: list[tuple[str, str, str, str, str]] = []
            for rule in rules:
                if (rule.pattern.search(line) and (rule.requires is None or rule.requires.search(line))
                        and (rule.excludes is None or not rule.excludes.search(line))):
                    hits.append((rule.id, rule.title, rule.cwe, rule.category, rule.severity_hint))
            for mod in _imports(lang, line):
                if mod in unsafe:
                    hits.append(("IMPORT-UNSAFE", f"Imports {mod}: {unsafe[mod]}", unsafe[mod].rsplit("(", 1)[-1].rstrip(")"),
                                 "unsafe-import", "low"))
            for rid, title, cwe, cat, sev in hits:
                report.counts[rid] = report.counts.get(rid, 0) + 1
                per_rule[rid] = per_rule.get(rid, 0) + 1
                if per_rule[rid] > MAX_PER_RULE or len(report.findings) >= MAX_FINDINGS:
                    report.truncated = True
                    continue
                report.findings.append(Finding(
                    rule_id=rid, title=title, cwe=cwe, category=cat, severity_hint=sev,
                    file=rel, line=lineno, snippet=line.strip()[:SNIPPET_CHARS], in_test_code=in_test,
                ))
    # Production code before test code, then the riskier hints first.
    order = {"high": 0, "medium": 1, "low": 2}
    report.findings.sort(key=lambda f: (f.in_test_code, order.get(f.severity_hint, 3), f.file, f.line))
    return report


def search_tree(root: Path, needle: str, *, max_hits: int = 60, ignore_case: bool = True) -> list[dict]:
    """Literal substring search across every text file under `root`."""
    needle = needle[:200]
    if not needle.strip():
        return []
    probe = needle.lower() if ignore_case else needle
    hits: list[dict] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if text is None or "\x00" in text[:1024]:
            continue
        rel = path.relative_to(root).as_posix()
        for lineno, line in enumerate(text.splitlines(), start=1):
            hay = line.lower() if ignore_case else line
            if probe in hay:
                hits.append({"file": rel, "line": lineno, "text": line.strip()[:SNIPPET_CHARS]})
                if len(hits) >= max_hits:
                    return hits
    return hits


# ----------------------------------------------------------------------------- manifests

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _first(root: Path, *names: str) -> Optional[Path]:
    for name in names:
        hits = sorted(root.rglob(name), key=lambda p: len(p.parts))
        hits = [h for h in hits if not any(part in _SKIP_DIRS for part in h.relative_to(root).parts[:-1])]
        if hits:
            return hits[0]
    return None


def declared_dependencies(root: Path, ecosystem: str, *, limit: int = 50) -> list[dict]:
    """What `root`'s package declares it depends on: ``[{name, spec, source}]``."""
    out: list[dict] = []

    def add(name: str, spec: str, source: str) -> None:
        if name and len(out) < limit:
            out.append({"name": name, "spec": (spec or "").strip(), "source": source})

    try:
        if ecosystem == "javascript":
            pj = _first(root, "package.json")
            if pj:
                data = json.loads(_read(pj) or "{}")
                for section in ("dependencies", "optionalDependencies", "peerDependencies"):
                    for name, spec in (data.get(section) or {}).items():
                        add(name, str(spec), f"{pj.relative_to(root).as_posix()}:{section}")
        elif ecosystem == "python":
            meta = _first(root, "METADATA", "PKG-INFO")
            if meta:
                for line in (_read(meta) or "").splitlines():
                    if line.startswith("Requires-Dist:"):
                        req = line.split(":", 1)[1].split(";", 1)[0]
                        m = _REQ_NAME.match(req)
                        if m:
                            add(m.group(1), m.group(3), meta.relative_to(root).as_posix())
            pp = _first(root, "pyproject.toml")
            if pp and not out:
                data = tomllib.loads(_read(pp) or "")
                for req in (data.get("project") or {}).get("dependencies") or []:
                    m = _REQ_NAME.match(req.split(";", 1)[0])
                    if m:
                        add(m.group(1), m.group(3), pp.relative_to(root).as_posix())
        elif ecosystem == "rust":
            ct = _first(root, "Cargo.toml")
            if ct:
                data = tomllib.loads(_read(ct) or "")
                for name, spec in (data.get("dependencies") or {}).items():
                    version = spec if isinstance(spec, str) else (spec or {}).get("version", "")
                    add(name, str(version), ct.relative_to(root).as_posix())
        elif ecosystem == "go":
            gm = _first(root, "go.mod")
            if gm:
                for line in (_read(gm) or "").splitlines():
                    m = re.match(r"^\s*(?:require\s+)?([\w.\-]+\.[\w./\-]+)\s+(v[\w.\-+]+)", line)
                    if m:
                        add(m.group(1), m.group(2), gm.relative_to(root).as_posix())
        elif ecosystem == "java":
            pom = _first(root, "pom.xml")
            if pom:
                text = _read(pom) or ""
                for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
                    g = re.search(r"<groupId>([^<]+)</groupId>", block)
                    a = re.search(r"<artifactId>([^<]+)</artifactId>", block)
                    v = re.search(r"<version>([^<]+)</version>", block)
                    if g and a:
                        add(f"{g.group(1)}:{a.group(1)}", v.group(1) if v else "", pom.relative_to(root).as_posix())
    except (ValueError, tomllib.TOMLDecodeError) as exc:
        out.append({"name": "", "spec": "", "source": f"manifest parse error: {exc}"})
    return out


def exact_pin(spec: str) -> Optional[str]:
    """The single version a constraint pins, if it pins exactly one."""
    s = spec.strip().strip("'\"")
    m = re.fullmatch(r"(?:==|=)?\s*v?(\d+(?:\.\d+){0,3}(?:[-+.][\w.]+)?)", s)
    return m.group(1) if m else None
