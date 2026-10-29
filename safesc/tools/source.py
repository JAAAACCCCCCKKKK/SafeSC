"""tools/source.py — materialise a dependency's source for static inspection. LLM-free.

`fetch_source` produces a read-only *workspace* for one dependency: preferably the
published artifact itself (what a consumer actually installs — npm tarball, crate, sdist or
wheel, Go module zip, Maven sources jar), falling back to a shallow clone of the declared
source repository. Nothing is ever executed: archives are safe-extracted with traversal and
link protection (`deep_analysis_tool._safe_extract_archive`), and clones run with hooks and
dangerous transports disabled (`deep_analysis_tool.safe_clone`).

Workspaces are keyed by the pinned artifact and reused within and across runs, so asking
twice costs one download.
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Optional
from urllib.parse import quote, urlparse

from safesc.tools.deep_analysis_tool import (
    DeepAnalysisRequest,
    _default_registry_lookup,
    _safe_extract_archive,
    safe_clone,
)

logger = logging.getLogger("safesc.source")

MAX_ARTIFACT_BYTES = 60 * 1024 * 1024
DOWNLOAD_TIMEOUT_S = 60.0

Downloader = Callable[[str, Path], bool]


@dataclass(frozen=True)
class SourceWorkspace:
    root: Path
    origin: Literal["artifact", "repository"]
    detail: str


def workspace_base() -> Path:
    import os

    root = Path(os.environ.get("SAFESC_WORKDIR") or tempfile.gettempdir()) / "safesc-workspaces"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _slug(dep) -> str:
    raw = f"{dep.ecosystem}:{dep.name}@{dep.version}:{getattr(dep, 'hash', '') or ''}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:10]
    safe = re.sub(r"[^\w.\-]+", "_", f"{dep.name}-{dep.version}")[:60]
    return f"{safe}-{digest}"


def _go_escape(path: str) -> str:
    """Go module proxy case-encoding: each uppercase letter becomes '!' + lowercase."""
    return "".join(f"!{c.lower()}" if c.isupper() else c for c in path)


def artifact_url_candidates(dep, *, pypi_files: Optional[list[dict]] = None) -> list[str]:
    """Where the published artifact for `dep` can be downloaded, best first."""
    urls: list[str] = []
    if getattr(dep, "artifact_url", None):
        urls.append(dep.artifact_url)
    name, version, eco = dep.name, dep.version, dep.ecosystem
    if not version:
        return urls
    if eco == "javascript":
        base = name.split("/")[-1]
        urls.append(f"https://registry.npmjs.org/{name}/-/{base}-{version}.tgz")
    elif eco == "rust":
        urls.append(f"https://static.crates.io/crates/{name}/{name}-{version}.crate")
    elif eco == "go":
        urls.append(f"https://proxy.golang.org/{_go_escape(name)}/@v/{_go_escape(version)}.zip")
    elif eco == "java" and ":" in name:
        group, artifact = name.split(":", 1)
        root = f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{artifact}/{version}"
        urls += [f"{root}/{artifact}-{version}-sources.jar", f"{root}/{artifact}-{version}.jar"]
    elif eco == "python":
        files = pypi_files if pypi_files is not None else _pypi_files(name, version)
        # sdist first: it carries the build scripts a wheel omits.
        files = sorted(files, key=lambda f: 0 if f.get("packagetype") == "sdist" else 1)
        urls += [f["url"] for f in files if f.get("url")]
    seen: set[str] = set()
    return [u for u in urls if not (u in seen or seen.add(u))]


def _pypi_files(name: str, version: str) -> list[dict]:
    import httpx

    try:
        resp = httpx.get(
            f"https://pypi.org/pypi/{quote(name)}/{quote(version)}/json",
            timeout=DOWNLOAD_TIMEOUT_S, follow_redirects=True,
        )
        if resp.status_code != 200:
            return []
        return list(resp.json().get("urls") or [])
    except Exception as exc:
        logger.info("pypi file listing failed for %s@%s: %s", name, version, exc)
        return []


def http_download(url: str, dest: Path) -> bool:
    """Stream `url` to `dest` over https only, refusing anything over MAX_ARTIFACT_BYTES."""
    import httpx

    if urlparse(url).scheme != "https":
        return False
    try:
        with httpx.stream("GET", url, timeout=DOWNLOAD_TIMEOUT_S, follow_redirects=True) as resp:
            if resp.status_code != 200:
                return False
            size = 0
            with dest.open("wb") as fh:
                for chunk in resp.iter_bytes():
                    size += len(chunk)
                    if size > MAX_ARTIFACT_BYTES:
                        logger.warning("artifact over %d bytes, abandoned: %s", MAX_ARTIFACT_BYTES, url)
                        return False
                    fh.write(chunk)
        return True
    except Exception as exc:
        logger.info("download failed %s: %s", url, exc)
        return False


def _archive_name(url: str) -> str:
    path = urlparse(url).path.lower()
    if path.endswith((".zip", ".whl", ".jar")):
        return "artifact.zip"
    return "artifact.tar.gz"


def fetch_source(
    dep,
    *,
    base_dir: Optional[Path] = None,
    downloader: Optional[Downloader] = None,
    registry_lookup=None,
    allow_clone: bool = True,
) -> Optional[SourceWorkspace]:
    """Return a workspace holding `dep`'s source, or None when nothing could be fetched."""
    base = base_dir or workspace_base()
    dest = base / _slug(dep)
    marker = dest / ".safesc-origin"
    if marker.is_file():
        origin, _, detail = marker.read_text(encoding="utf-8").partition("\n")
        if origin in ("artifact", "repository"):
            return SourceWorkspace(root=dest / "src", origin=origin, detail=detail)  # type: ignore[arg-type]
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)

    download = downloader or http_download
    for url in artifact_url_candidates(dep):
        archive = dest / _archive_name(url)
        if not download(url, archive):
            continue
        if _safe_extract_archive(archive, dest / "src"):
            archive.unlink(missing_ok=True)
            marker.write_text(f"artifact\n{url}", encoding="utf-8")
            return SourceWorkspace(root=dest / "src", origin="artifact", detail=url)
        shutil.rmtree(dest / "src", ignore_errors=True)
        archive.unlink(missing_ok=True)

    if allow_clone:
        cloned = clone_history(dep, registry_lookup=registry_lookup, depth=1)
        if cloned is not None:
            shutil.copytree(cloned, dest / "src", ignore=shutil.ignore_patterns(".git"), dirs_exist_ok=True)
            marker.write_text(f"repository\n{cloned}", encoding="utf-8")
            return SourceWorkspace(root=dest / "src", origin="repository", detail=str(cloned))

    shutil.rmtree(dest, ignore_errors=True)
    return None


def resolve_repo_url(dep, registry_lookup=None) -> Optional[str]:
    if getattr(dep, "source_url", None):
        return dep.source_url
    try:
        facts = (registry_lookup or _default_registry_lookup)(dep.name, dep.version, dep.ecosystem)
    except Exception:
        facts = None
    return (facts or {}).get("repo_url")


def clone_history(dep, *, registry_lookup=None, depth: int = 1) -> Optional[Path]:
    """A safe clone of `dep`'s source repository at (or near) its release ref."""
    url = resolve_repo_url(dep, registry_lookup)
    if not url:
        return None
    req = DeepAnalysisRequest(
        name=dep.name, version=dep.version or "0", ecosystem=dep.ecosystem or "python",
        source_url=url, expected_hash=getattr(dep, "hash", None), ref=getattr(dep, "ref", None),
    ) if dep.ecosystem in ("python", "javascript", "rust", "go", "java") else None
    if req is None:
        return None
    repo = safe_clone(req, depth=depth)
    return repo.root if repo is not None else None
