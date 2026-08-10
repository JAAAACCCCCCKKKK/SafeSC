from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

# --- soft LangChain import ----------------------------------------------------
# The pure primitives are usable and testable without LangChain installed; the
# `@tool` wrappers at the bottom degrade to plain functions if it is absent.
try:
    from langchain_core.tools import tool  # type: ignore
except Exception:  # pragma: no cover - fallback for early-build environments

    def tool(fn=None, **_kwargs):  # type: ignore
        def _decorate(f):
            return f

        return _decorate(fn) if callable(fn) else _decorate


logger = logging.getLogger("safesc.deep")

# =============================================================================
# Limits (bounded cost — CLAUDE.md §5.1)
# =============================================================================

CLONE_TIMEOUT_S = 45
DOWNLOAD_TIMEOUT_S = 45
MAX_FILE_BYTES = 1_000_000          # skip files larger than this when scanning text
MAX_EXCERPT_CHARS = 4_000           # truncate any excerpt handed to an LLM later
MAX_ITEMS_PER_KIND = 40             # cap evidence items so one dep can't flood context
MAX_SCAN_FILES = 5_000              # abort a scan that is pathologically large
MAX_COMMITS = 20

# Content-hash comparison ignores files that are legitimately generated at build
# time; they are still surfaced but tagged `generated=True` so the LLM can discount.
GENERATED_PATH_PATTERNS = (
    r"(^|/)PKG-INFO$",
    r"\.egg-info/",
    r"\.dist-info/",
    r"(^|/)METADATA$",
    r"(^|/)RECORD$",
    r"(^|/)Cargo\.toml\.orig$",
    r"(^|/)\.cargo_vcs_info\.json$",
)

TEXT_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".rs", ".go", ".java",
    ".json", ".toml", ".cfg", ".ini", ".txt", ".md", ".rst", ".sh", ".ps1",
    ".yml", ".yaml",
}

Ecosystem = Literal["python", "javascript", "rust", "go", "java"]
Dimension = Literal["behavior", "provenance", "identity"]


# =============================================================================
# Evidence models — NOTE: no verdict / score / severity anywhere. Evidence only.
# =============================================================================


class EvidenceItem(BaseModel):
    """One extracted artifact for an LLM specialist to reason about."""

    kind: str = Field(..., description="e.g. install_script, obfuscation_blob, readme, commit, artifact_only_file")
    path: Optional[str] = Field(None, description="Path within the repo/artifact, if applicable")
    excerpt: str = Field("", description="Bounded extracted text (<= MAX_EXCERPT_CHARS)")
    metadata: dict = Field(default_factory=dict, description="Deterministic facts only — no judgement")


class BehaviorEvidence(BaseModel):
    install_scripts: list[EvidenceItem] = Field(default_factory=list)
    obfuscation_candidates: list[EvidenceItem] = Field(default_factory=list)


class ProvenanceEvidence(BaseModel):
    artifact_only_files: list[EvidenceItem] = Field(
        default_factory=list,
        description="Content present in the published artifact but not traceable to the source tree",
    )
    recent_commits: list[EvidenceItem] = Field(default_factory=list)


class RegistryProvenance(BaseModel):
    """Deterministic registry facts about a package's *identity* — the strongest
    discriminator between a legitimate companion/derived package and a typosquat.

    Facts only, no judgement: the IdentityAgent compares these (publisher, canonical
    repo, maturity/age) against the popular package the name resembles.
    """

    author: Optional[str] = Field(None, description="Publisher/author as the registry reports it")
    repo_url: Optional[str] = Field(None, description="Canonical source repository, if declared")
    homepage: Optional[str] = Field(None, description="Project homepage, if declared")
    summary: Optional[str] = Field(None, description="One-line project description from the registry")
    total_releases: int = Field(0, description="Number of published versions (maturity proxy)")
    first_release_at: Optional[str] = Field(None, description="ISO timestamp of the earliest release")
    latest_release_at: Optional[str] = Field(None, description="ISO timestamp of the most recent release")
    resolved: bool = Field(False, description="True if the registry lookup returned data")


class IdentityEvidence(BaseModel):
    docs: list[EvidenceItem] = Field(default_factory=list, description="README / SECURITY / doc text for coercion analysis")
    nearest_popular: Optional[str] = Field(
        None,
        description="The popular package this name is a near-miss of (from the static typosquat signal), if any",
    )
    registry: RegistryProvenance = Field(
        default_factory=RegistryProvenance,
        description="Registry provenance facts for typosquat vs legitimate-package discrimination",
    )


class DeepAnalysisRequest(BaseModel):
    name: str
    version: str
    ecosystem: Ecosystem
    source_url: Optional[str] = Field(None, description="Git repo URL resolved upstream (SourceLocator)")
    artifact_url: Optional[str] = Field(None, description="Registry download URL for the published artifact")
    expected_hash: Optional[str] = Field(None, description="Lockfile hash; used only to key the cache")
    ref: Optional[str] = Field(None, description="Git tag/commit for this version; else the tool guesses common tag forms")

    @classmethod
    def from_dependency(cls, dep) -> "DeepAnalysisRequest":
        """Map from tools/index/core/models.py:Dependency.

        Expects the Dependency to expose: name, version, ecosystem, source_url,
        hash (and optionally artifact_url / ref). Missing optional fields degrade
        the corresponding dimension rather than failing.
        """
        return cls(
            name=getattr(dep, "name"),
            version=getattr(dep, "version"),
            ecosystem=getattr(dep, "ecosystem"),
            source_url=getattr(dep, "source_url", None),
            artifact_url=getattr(dep, "artifact_url", None),
            expected_hash=getattr(dep, "hash", None),
            ref=getattr(dep, "ref", None),
        )

    def cache_key(self) -> str:
        raw = f"{self.ecosystem}:{self.name}:{self.version}:{self.expected_hash or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class DeepAnalysisEvidence(BaseModel):
    """The complete evidence bundle for one dependency. Consumed by specialists.

    Intentionally has NO verdict/score/severity. See module docstring.
    """

    request: DeepAnalysisRequest
    status: Literal["complete", "partial", "degraded"] = "complete"
    degraded_reasons: list[str] = Field(default_factory=list)
    behavior: BehaviorEvidence = Field(default_factory=BehaviorEvidence)
    provenance: ProvenanceEvidence = Field(default_factory=ProvenanceEvidence)
    identity: IdentityEvidence = Field(default_factory=IdentityEvidence)

    def note_degraded(self, reason: str) -> None:
        self.degraded_reasons.append(reason)
        self.status = "degraded" if not self.degraded_reasons[:-1] else "partial"


# =============================================================================
# Safe filesystem / process helpers
# =============================================================================


def _truncate(text: str, limit: int = MAX_EXCERPT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more chars]"


def _is_generated(rel_path: str) -> bool:
    return any(re.search(p, rel_path) for p in GENERATED_PATH_PATTERNS)


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def _iter_files(root: Path) -> Iterable[Path]:
    count = 0
    for p in root.rglob("*"):
        if p.is_symlink():
            continue  # never follow symlinks out of the tree
        if p.is_file():
            count += 1
            if count > MAX_SCAN_FILES:
                logger.warning("scan file cap reached under %s", root)
                return
            yield p


def _validate_git_url(url: str) -> Optional[str]:
    """Return a safe https git URL or None. Rejects local/ext/file protocols and
    anything with shell-hostile characters. Cloning attacker-controlled URLs is a
    real attack surface, so we allowlist scheme and reject the dangerous transports."""
    if not url or any(c in url for c in "\n\r\t ;|&`$"):
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        return None
    if not parsed.netloc:
        return None
    # git's dangerous transports never appear in a normal https URL, but guard anyway
    lowered = url.lower()
    if lowered.startswith(("file:", "ext::", "-", "--")) or "ext::" in lowered:
        return None
    return url


def _run(cmd: list[str], cwd: Optional[Path] = None, timeout: int = CLONE_TIMEOUT_S) -> subprocess.CompletedProcess:
    """subprocess without a shell. Never runs package code; only git/read ops."""
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"},
    )


@dataclass
class ClonedRepo:
    root: Path
    ref_resolved: Optional[str]


def _cache_root() -> Path:
    root = Path(os.environ.get("SAFESC_DEEP_CACHE", tempfile.gettempdir())) / "safesc-deep"
    root.mkdir(parents=True, exist_ok=True)
    return root


def safe_clone(req: DeepAnalysisRequest, depth: int = 1) -> Optional[ClonedRepo]:
    """Shallow, hook-disabled, dangerous-transport-disabled clone. Reads only.

    Idempotent: reuses an existing valid clone keyed by cache_key + depth.
    Returns None (caller degrades) if the URL is unsafe, git fails, or times out.
    """
    url = _validate_git_url(req.source_url or "")
    if url is None:
        logger.info("no safe source_url for %s@%s", req.name, req.version)
        return None

    dest = _cache_root() / f"{req.cache_key()}-d{depth}"
    if (dest / ".git").exists():
        return ClonedRepo(root=dest, ref_resolved=req.ref)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)

    # protocol.*.allow=never blocks file:// and ext:: transports even if they slip
    # through URL validation; core.hooksPath=/dev/null neutralises any hook.
    base = [
        "git",
        "-c", "protocol.file.allow=never",
        "-c", "protocol.ext.allow=never",
        "-c", "core.hooksPath=/dev/null",
        "clone", "--quiet", "--depth", str(depth), "--no-tags",
    ]
    candidates = [req.ref] if req.ref else _guess_refs(req)
    for ref in candidates:
        cmd = base + (["--branch", ref] if ref else []) + [url, str(dest)]
        try:
            proc = _run(cmd, timeout=CLONE_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            logger.warning("clone timeout %s", req.name)
            shutil.rmtree(dest, ignore_errors=True)
            return None
        if proc.returncode == 0 and (dest / ".git").exists():
            return ClonedRepo(root=dest, ref_resolved=ref)
        shutil.rmtree(dest, ignore_errors=True)

    logger.info("clone failed for %s@%s (%s)", req.name, req.version, req.source_url)
    return None


def _guess_refs(req: DeepAnalysisRequest) -> list[Optional[str]]:
    v = req.version
    return [f"v{v}", v, f"{req.name}-{v}", f"{req.name}@{v}", None]  # None = default branch


# =============================================================================
# Primitive 1 — install-script extraction (BehaviorAgent)
# =============================================================================


def extract_install_scripts(repo: ClonedRepo, ecosystem: Ecosystem) -> list[EvidenceItem]:
    """Surface the *content* of install-time execution points, per ecosystem.

    We only READ these files; we never execute them. Presence/absence is already a
    Stage-3 static signal for javascript (`hasInstallScript`) and, narrowly, rust (a
    crate's `lib_links` implies a build script — see
    `tools/scan/signals/behavior/install_script.py`; a build.rs used purely for codegen,
    with no `links` key, isn't caught there and is only ever seen here). Python has no
    comparable cheap registry signal yet, so its `setup.py` is only ever examined here.
    Here we hand the actual code to the LLM for intent analysis, plus deterministic
    hints (network/file/env access) as metadata."""
    items: list[EvidenceItem] = []
    root = repo.root

    def add(path: Path, kind: str) -> None:
        text = _read_text(path)
        if text is None:
            return
        items.append(
            EvidenceItem(
                kind=kind,
                path=str(path.relative_to(root)),
                excerpt=_truncate(text),
                metadata=_static_op_hints(text),
            )
        )

    if ecosystem == "python":
        for name in ("setup.py",):
            p = root / name
            if p.is_file() and (p.stat().st_size > 0):
                add(p, "install_script")
        # pyproject build hooks are worth surfacing but are not auto-exec like setup.py
        pp = root / "pyproject.toml"
        if pp.is_file():
            txt = _read_text(pp) or ""
            if "build-backend" in txt or "[tool." in txt:
                items.append(
                    EvidenceItem(kind="build_config", path="pyproject.toml", excerpt=_truncate(txt), metadata={})
                )

    elif ecosystem == "javascript":
        pkg = root / "package.json"
        txt = _read_text(pkg) if pkg.is_file() else None
        if txt:
            hooks = _npm_lifecycle_hooks(txt)
            if hooks:
                items.append(
                    EvidenceItem(
                        kind="install_script",
                        path="package.json",
                        excerpt=_truncate(txt),
                        metadata={"lifecycle_hooks": hooks},
                    )
                )
                # pull the referenced script files too, if local
                for ref in _referenced_local_scripts(hooks):
                    sp = (root / ref).resolve()
                    if _within(root, sp) and sp.is_file():
                        add(sp, "install_script_target")

    elif ecosystem == "rust":
        p = root / "build.rs"
        if p.is_file():
            add(p, "install_script")

    # go / java: no auto-executed install scripts in the v1-priority scope

    return items[:MAX_ITEMS_PER_KIND]


def _static_op_hints(code: str) -> dict:
    """Deterministic hints only. NOT a judgement — just 'these tokens are present'."""
    return {
        "references_network": bool(re.search(r"\b(urllib|requests|socket|http|fetch|axios|curl|wget|Net::HTTP)\b", code)),
        "references_filesystem": bool(re.search(r"\b(open|os\.remove|shutil|fs\.|writeFile|std::fs)\b", code)),
        "references_env": bool(re.search(r"\b(os\.environ|getenv|process\.env|std::env)\b", code)),
        "references_exec": bool(re.search(r"\b(os\.system|subprocess|exec|eval|child_process|Command::new|Runtime\.getRuntime)\b", code)),
        "references_encode": bool(re.search(r"\b(base64|b64decode|atob|fromCharCode|hex|codecs\.decode)\b", code)),
    }


def _npm_lifecycle_hooks(package_json_text: str) -> dict:
    hooks: dict = {}
    m = re.search(r'"scripts"\s*:\s*\{', package_json_text)
    if not m:
        return hooks
    for hook in ("preinstall", "install", "postinstall", "prepare"):
        hm = re.search(rf'"{hook}"\s*:\s*"([^"]*)"', package_json_text)
        if hm:
            hooks[hook] = hm.group(1)
    return hooks


def _referenced_local_scripts(hooks: dict) -> list[str]:
    refs: list[str] = []
    for cmd in hooks.values():
        for m in re.finditer(r"(?:node|python3?|sh|bash)\s+([\w./-]+\.(?:js|cjs|mjs|py|sh))", cmd):
            refs.append(m.group(1))
    return refs


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root.resolve())
        return True
    except ValueError:
        return False


# =============================================================================
# Primitive 2 — obfuscation candidate extraction (BehaviorAgent)
# =============================================================================

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_HEX_BLOB_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}")
_EVAL_ENCODED_RE = re.compile(r"\b(eval|exec|Function|compile)\s*\(", re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_obfuscation_candidates(repo: ClonedRepo) -> list[EvidenceItem]:
    """Surface high-entropy blobs, encoded strings, minified code, and
    eval/exec-on-encoded patterns. Deterministic detection; the LLM judges intent."""
    items: list[EvidenceItem] = []
    root = repo.root

    for path in _iter_files(root):
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        text = _read_text(path)
        if not text:
            continue
        rel = str(path.relative_to(root))

        # (a) long base64 / hex blobs
        for pattern, label in ((_BASE64_RE, "base64_blob"), (_HEX_BLOB_RE, "hex_blob")):
            for m in pattern.finditer(text):
                blob = m.group(0)
                if _shannon_entropy(blob[:512]) < 3.5:
                    continue  # low entropy → probably not encoded payload
                items.append(
                    EvidenceItem(
                        kind="obfuscation_blob",
                        path=rel,
                        excerpt=_truncate(blob, 1200),
                        metadata={"pattern": label, "length": len(blob), "entropy": round(_shannon_entropy(blob[:512]), 2)},
                    )
                )
                if len(items) >= MAX_ITEMS_PER_KIND:
                    return items

        # (b) eval/exec/Function/compile present alongside an encoded string
        if _EVAL_ENCODED_RE.search(text) and _static_op_hints(text)["references_encode"]:
            snippet = _context_around(text, _EVAL_ENCODED_RE)
            items.append(
                EvidenceItem(kind="dynamic_exec", path=rel, excerpt=_truncate(snippet, 1500), metadata={"heuristic": "eval+encode"})
            )

        # (c) minified: very long lines with almost no newlines
        lines = text.split("\n")
        longest = max((len(ln) for ln in lines), default=0)
        if longest > 2000 and (len(lines) < max(1, len(text) // 400)):
            items.append(
                EvidenceItem(kind="minified", path=rel, excerpt=_truncate(text[:1500]), metadata={"longest_line": longest})
            )

        if len(items) >= MAX_ITEMS_PER_KIND:
            break

    return items[:MAX_ITEMS_PER_KIND]


def _context_around(text: str, pattern: re.Pattern, radius: int = 400) -> str:
    m = pattern.search(text)
    if not m:
        return text[:radius]
    start = max(0, m.start() - radius)
    end = min(len(text), m.end() + radius)
    return text[start:end]


# =============================================================================
# Primitive 3 — README / doc extraction (IdentityAgent — coercion analysis)
# =============================================================================

_DOC_NAMES = ("README", "SECURITY", "CONTRIBUTING", "INSTALL")


def extract_docs(repo: ClonedRepo) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    root = repo.root
    for path in _iter_files(root):
        stem = path.stem.upper()
        if any(stem.startswith(n) for n in _DOC_NAMES) and path.suffix.lower() in {".md", ".rst", ".txt", ""}:
            text = _read_text(path)
            if text:
                items.append(EvidenceItem(kind="doc", path=str(path.relative_to(root)), excerpt=_truncate(text), metadata={}))
        if len(items) >= MAX_ITEMS_PER_KIND:
            break
    return items


# =============================================================================
# Primitive 3b — registry provenance (IdentityAgent — typosquat discrimination)
# =============================================================================
# The strongest signal for "is this a squat or a legitimate near-name package" is
# registry provenance: who published it, its canonical repo, and how mature it is.
# This bridges to the async Stage-3 registry_meta fetchers via an injectable
# callable so the deep-analysis module stays sync and unit-testable with a fake.

RegistryLookup = "Callable[[str, str, str], Optional[dict]]"  # (name, version, ecosystem) -> facts dict


def _default_registry_lookup(name: str, version: str, ecosystem: str) -> Optional[dict]:
    """Fetch package-level registry metadata for identity analysis.

    Reuses the tested Stage-3 fetchers (`registry_meta.get_package_metadata`) over a
    short-lived rate-limited session, run to completion synchronously. Returns a plain
    dict of identity facts, or None if the registry/ecosystem is unsupported or the
    fetch fails (degrades gracefully — the specialist still has the docs slice)."""
    import asyncio

    try:
        from safesc.tools.index.core.models import Dependency  # type: ignore
        from safesc.tools.scan.signals.provenance.http import RateLimitedSession  # type: ignore
        from safesc.tools.scan.signals.registry_meta import get_package_metadata  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        logger.warning("registry lookup unavailable: %s", exc)
        return None

    async def _run() -> Optional[dict]:
        # lockfile_path is required by the model but irrelevant to a registry lookup.
        dep = Dependency(name=name, version=version, ecosystem=ecosystem, lockfile_path=Path("."))
        async with RateLimitedSession() as session:
            meta = await get_package_metadata(dep, session)
        if meta is None:
            return None
        return {
            "author": meta.author,
            "repo_url": meta.repo_url,
            "homepage": meta.homepage,
            "summary": meta.summary,
            "total_releases": meta.total_releases,
            "first_release_at": meta.first_release_at,
            "latest_release_at": meta.latest_release_at,
        }

    try:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(_run())
        # Already inside a loop (rare for the sync specialist path): use a fresh loop
        # in a worker thread so we never nest asyncio.run().
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(_run())).result()
    except Exception as exc:
        logger.warning("registry lookup failed for %s@%s (%s): %s", name, version, ecosystem, exc)
        return None


def _registry_provenance_from_facts(facts: Optional[dict]) -> RegistryProvenance:
    """Build a RegistryProvenance from a facts dict (or unresolved if None/empty)."""
    if not facts:
        return RegistryProvenance(resolved=False)
    return RegistryProvenance(
        author=facts.get("author"),
        repo_url=facts.get("repo_url"),
        homepage=facts.get("homepage"),
        summary=facts.get("summary"),
        total_releases=int(facts.get("total_releases") or 0),
        first_release_at=facts.get("first_release_at"),
        latest_release_at=facts.get("latest_release_at"),
        resolved=True,
    )


def gather_registry_provenance(
    req: "DeepAnalysisRequest",
    registry_lookup=None,
) -> RegistryProvenance:
    """Populate a RegistryProvenance from the registry, degrading to unresolved."""
    lookup = registry_lookup or _default_registry_lookup
    try:
        facts = lookup(req.name, req.version, req.ecosystem)
    except Exception as exc:
        logger.warning("registry provenance lookup raised for %s: %s", req.name, exc)
        facts = None
    return _registry_provenance_from_facts(facts)


# =============================================================================
# Primitive 4 — artifact-vs-source provenance diff (ProvenanceAgent)
# =============================================================================


def _content_hash_map(root: Path) -> dict[str, tuple[str, bytes]]:
    """Map content-sha256 -> (relative_path, first_bytes). Layout-agnostic on purpose:
    we care whether artifact *content* is traceable to source, not where it sits."""
    out: dict[str, tuple[str, bytes]] = {}
    for path in _iter_files(root):
        try:
            data = path.read_bytes()
        except Exception:
            continue
        if len(data) > MAX_FILE_BYTES:
            continue
        h = hashlib.sha256(data).hexdigest()
        out.setdefault(h, (str(path.relative_to(root)), data[:MAX_EXCERPT_CHARS]))
    return out


def _safe_extract_archive(archive: Path, dest: Path) -> bool:
    """Extract tar/zip with path-traversal (zip/tar-slip) protection. Never executes."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        if archive.suffix == ".zip" or archive.name.endswith(".whl"):
            with zipfile.ZipFile(archive) as zf:
                for member in zf.namelist():
                    target = (dest / member).resolve()
                    if not _within(dest, target):
                        logger.warning("zip-slip blocked: %s", member)
                        return False
                zf.extractall(dest)
        else:
            with tarfile.open(archive) as tf:
                for member in tf.getmembers():
                    target = (dest / member.name).resolve()
                    if not _within(dest, target) or member.issym() or member.islnk():
                        logger.warning("tar-slip/link blocked: %s", member.name)
                        return False
                tf.extractall(dest)
        return True
    except Exception as exc:
        logger.info("archive extract failed: %s", exc)
        return False


def diff_artifact_vs_source(req: DeepAnalysisRequest, source_repo: ClonedRepo, download) -> list[EvidenceItem]:
    """Report content present in the published artifact but NOT traceable to source.

    `download` is a callable (url, dest_path) -> bool provided by the caller (so this
    module stays free of registry-client coupling). Absent artifact_url/download →
    caller degrades this dimension.
    """
    if not req.artifact_url or download is None:
        return []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "artifact"
        if not download(req.artifact_url, archive):
            return []
        extracted = tmp_path / "x"
        if not _safe_extract_archive(archive, extracted):
            return []

        source_hashes = set(_content_hash_map(source_repo.root).keys())
        artifact_map = _content_hash_map(extracted)

        items: list[EvidenceItem] = []
        for h, (rel, first_bytes) in artifact_map.items():
            if h in source_hashes:
                continue
            generated = _is_generated(rel)
            try:
                excerpt = first_bytes.decode("utf-8", errors="replace")
            except Exception:
                excerpt = "<binary>"
            items.append(
                EvidenceItem(
                    kind="artifact_only_file",
                    path=rel,
                    excerpt=_truncate(excerpt, 1500),
                    metadata={"sha256": h, "likely_generated": generated},
                )
            )
            if len(items) >= MAX_ITEMS_PER_KIND:
                break
        # surface non-generated ones first — those are the real provenance red flags
        items.sort(key=lambda it: it.metadata.get("likely_generated", False))
        return items


# =============================================================================
# Primitive 5 — recent commits (Provenance/Identity — commit/diff consistency)
# =============================================================================


def extract_recent_commits(req: DeepAnalysisRequest, depth: int = MAX_COMMITS) -> list[EvidenceItem]:
    repo = safe_clone(req, depth=depth)
    if repo is None:
        return []
    proc = _run(
        ["git", "-C", str(repo.root), "log", f"-{MAX_COMMITS}", "--pretty=format:%H%x1f%an%x1f%ae%x1f%s", "--no-color"],
        timeout=CLONE_TIMEOUT_S,
    )
    if proc.returncode != 0:
        return []
    items: list[EvidenceItem] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\x1f")
        if len(parts) != 4:
            continue
        sha, author, email, subject = parts
        stat = _run(["git", "-C", str(repo.root), "show", "--stat", "--oneline", "--no-color", sha], timeout=CLONE_TIMEOUT_S)
        items.append(
            EvidenceItem(
                kind="commit",
                path=None,
                excerpt=_truncate(stat.stdout if stat.returncode == 0 else subject, 1500),
                metadata={"sha": sha, "author": author, "email": email, "subject": subject},
            )
        )
    return items


# =============================================================================
# Orchestration — gather only what the requested dimensions need
# =============================================================================


def gather_deep_analysis_evidence(
    req: DeepAnalysisRequest,
    dimensions: Iterable[Dimension] = ("behavior", "provenance", "identity"),
    artifact_download=None,
    *,
    nearest_popular: Optional[str] = None,
    registry_lookup=None,
) -> DeepAnalysisEvidence:
    """Run the deterministic primitives needed by the requested specialists.

    A specialist node passes only its own dimension(s) so it doesn't pay for evidence
    it won't read. Every failure degrades a slice, never the whole bundle.

    For the identity dimension, `nearest_popular` (the popular package the name
    resembles, from the static typosquat signal) and registry provenance are added so
    the IdentityAgent can distinguish a legitimate companion package from a squat.
    `registry_lookup` is injectable for testing.
    """
    dims = set(dimensions)
    evidence = DeepAnalysisEvidence(request=req)

    # Registry packages carry an artifact_url (a .whl/.tgz/.jar), not a clonable
    # source_url. Resolve the real source repo from registry metadata so a shallow clone
    # can still gather README/source evidence; without this, every registry dep fails to
    # clone. Facts are fetched once here and reused for identity provenance below.
    needs_clone = bool(dims & {"behavior", "identity", "provenance"})
    registry_facts: Optional[dict] = None
    if (not req.source_url and needs_clone) or "identity" in dims:
        try:
            registry_facts = (registry_lookup or _default_registry_lookup)(
                req.name, req.version, req.ecosystem
            )
        except Exception:
            registry_facts = None

    clone_req = req
    if not req.source_url and needs_clone:
        repo_url = (registry_facts or {}).get("repo_url")
        if repo_url:
            clone_req = req.model_copy(update={"source_url": repo_url})

    # A single shallow clone serves behavior + identity + provenance file comparison.
    repo: Optional[ClonedRepo] = None
    if dims & {"behavior", "identity", "provenance"}:
        repo = safe_clone(clone_req, depth=1)
        if repo is None:
            evidence.note_degraded("source clone unavailable (missing/unsafe source_url or git failure)")

    if "behavior" in dims and repo is not None:
        try:
            evidence.behavior.install_scripts = extract_install_scripts(repo, req.ecosystem)
            evidence.behavior.obfuscation_candidates = extract_obfuscation_candidates(repo)
        except Exception as exc:  # graceful degradation §8.5
            logger.exception("behavior extraction failed")
            evidence.note_degraded(f"behavior extraction error: {exc}")

    if "identity" in dims:
        evidence.identity.nearest_popular = nearest_popular
        if repo is not None:
            try:
                evidence.identity.docs = extract_docs(repo)
            except Exception as exc:
                logger.exception("identity doc extraction failed")
                evidence.note_degraded(f"identity doc extraction error: {exc}")
        # Registry provenance does not need a clone — present even when the source repo
        # is unavailable (a squat often has no real repo, which is itself telling). Reuse
        # the facts already fetched above so we don't hit the registry twice.
        try:
            evidence.identity.registry = _registry_provenance_from_facts(registry_facts)
            if not evidence.identity.registry.resolved:
                evidence.note_degraded("identity registry provenance unavailable")
        except Exception as exc:
            logger.exception("identity registry provenance failed")
            evidence.note_degraded(f"identity registry provenance error: {exc}")

    if "provenance" in dims:
        try:
            if repo is not None:
                evidence.provenance.artifact_only_files = diff_artifact_vs_source(req, repo, artifact_download)
            evidence.provenance.recent_commits = extract_recent_commits(req)
        except Exception as exc:
            logger.exception("provenance extraction failed")
            evidence.note_degraded(f"provenance extraction error: {exc}")

    return evidence


# =============================================================================
# LangChain @tool wrappers — what the specialist ReAct nodes actually call.
# They return JSON strings (agent-friendly). Pure functions above stay importable
# for non-ReAct nodes that call them directly.
# =============================================================================


@tool
def behavior_evidence_tool(request_json: str, artifact_download=None) -> str:
    """Gather install-script and obfuscation evidence for one dependency.
    Input: JSON matching DeepAnalysisRequest. Returns DeepAnalysisEvidence JSON
    (behavior slice populated). Evidence only — contains no verdict."""
    req = DeepAnalysisRequest.model_validate_json(request_json)
    return gather_deep_analysis_evidence(req, dimensions=("behavior",)).model_dump_json()


@tool
def provenance_evidence_tool(request_json: str) -> str:
    """Gather artifact-vs-source and recent-commit evidence for one dependency.
    Input: JSON matching DeepAnalysisRequest. Returns DeepAnalysisEvidence JSON
    (provenance slice populated). Evidence only — contains no verdict."""
    req = DeepAnalysisRequest.model_validate_json(request_json)
    return gather_deep_analysis_evidence(req, dimensions=("provenance",)).model_dump_json()


@tool
def identity_evidence_tool(request_json: str, nearest_popular: Optional[str] = None) -> str:
    """Gather identity evidence for one dependency: README/SECURITY doc text (for
    coercion/social-engineering analysis) AND registry provenance (publisher, canonical
    repo, release history) for typosquat-vs-legitimate discrimination.
    Input: JSON matching DeepAnalysisRequest; optional `nearest_popular` = the popular
    package this name resembles (from the static typosquat signal). Returns
    DeepAnalysisEvidence JSON (identity slice populated). Evidence only — no verdict."""
    req = DeepAnalysisRequest.model_validate_json(request_json)
    return gather_deep_analysis_evidence(
        req, dimensions=("identity",), nearest_popular=nearest_popular
    ).model_dump_json()


# Backwards-compatible alias: the identity tool used to gather docs only; it now also
# fetches registry provenance. Keep the old name working for any existing wiring.
identity_doc_evidence_tool = identity_evidence_tool


__all__ = [
    "DeepAnalysisRequest",
    "DeepAnalysisEvidence",
    "BehaviorEvidence",
    "ProvenanceEvidence",
    "IdentityEvidence",
    "RegistryProvenance",
    "EvidenceItem",
    "gather_deep_analysis_evidence",
    "gather_registry_provenance",
    "safe_clone",
    "extract_install_scripts",
    "extract_obfuscation_candidates",
    "extract_docs",
    "diff_artifact_vs_source",
    "extract_recent_commits",
    "behavior_evidence_tool",
    "provenance_evidence_tool",
    "identity_evidence_tool",
    "identity_doc_evidence_tool",
]