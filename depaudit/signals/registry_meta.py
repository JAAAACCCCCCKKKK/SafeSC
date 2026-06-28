"""Ecosystem-dispatched registry metadata fetch (Stage 3 helper).

Collectors stay ecosystem-agnostic by going through this dispatcher rather than
importing ecosystem packages directly.  Two granularities are offered:

* :func:`get_registry_metadata`  — version-specific metadata (repo URL of the
  exact resolved version).  Used by the repo-URL collector.
* :func:`get_package_metadata`   — package-level metadata that is the same for
  every version (full published-version set, per-version yank flags, whether
  the resolved version declares an install script).  Used by the provenance /
  vulnerability / behavior collectors.

Both reuse the shared rate-limited session, whose L1 cache means the underlying
registry document is fetched only once per dependency even though several
collectors ask for it.

Currently implemented for the first-release priority ecosystems plus Rust.
Adding another ecosystem means adding one fetcher and one dispatch entry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from depaudit.core.models import Dependency
from depaudit.signals.provenance.http import RateLimitedSession


# --------------------------------------------------------------------------- #
# Data models
# --------------------------------------------------------------------------- #


@dataclass
class RegistryMetadata:
    """Version-specific registry metadata Stage 3 cheap signals care about."""

    repo_url: str | None = None


@dataclass
class PackageMetadata:
    """Package-level registry metadata (same across versions of a package).

    Every field is best-effort: an unsupported registry or a missing field
    leaves the value at its default so collectors can degrade gracefully.
    """

    published_versions: frozenset[str] = field(default_factory=frozenset)
    yanked_versions: frozenset[str] = field(default_factory=frozenset)
    version_present: bool = True   # is dep.version in published_versions?
    version_yanked: bool = False   # is dep.version yanked/withdrawn?
    has_install_script: bool = False  # resolved version declares install hooks


# --------------------------------------------------------------------------- #
# URL normalisation helpers
# --------------------------------------------------------------------------- #


def _normalise_repo_url(raw: str | None) -> str | None:
    """Turn a VCS/registry repo reference into a plain browsable https URL."""
    if not raw:
        return None
    url = raw.strip()
    if url.startswith("git+"):
        url = url[4:]
    if url.startswith("git://"):
        url = "https://" + url[len("git://"):]
    if url.startswith("ssh://git@"):
        url = "https://" + url[len("ssh://git@"):]
    if url.startswith("git@") and ":" in url:
        host, _, path = url[len("git@"):].partition(":")
        url = f"https://{host}/{path}"
    if url.endswith(".git"):
        url = url[: -len(".git")]
    if url.startswith(("http://", "https://")):
        return url
    return None


def _looks_like_repo(url: str) -> bool:
    lowered = url.lower()
    return any(host in lowered for host in ("github.com", "gitlab.com", "bitbucket.org"))


# --------------------------------------------------------------------------- #
# PyPI
# --------------------------------------------------------------------------- #


async def _pypi_version_json(dep: Dependency, session: RateLimitedSession) -> dict | None:
    url = f"https://pypi.org/pypi/{dep.name}/{dep.version}/json"
    return await session.get_json(url)


async def _pypi_package_json(dep: Dependency, session: RateLimitedSession) -> dict | None:
    url = f"https://pypi.org/pypi/{dep.name}/json"
    return await session.get_json(url)


async def _pypi_metadata(
    dep: Dependency, session: RateLimitedSession
) -> RegistryMetadata | None:
    data = await _pypi_version_json(dep, session)
    if not data:
        return None
    info: dict = data.get("info") or {}

    project_urls: dict = info.get("project_urls") or {}
    for key in ("Source", "Source Code", "Repository", "Code", "GitHub"):
        candidate = _normalise_repo_url(project_urls.get(key))
        if candidate:
            return RegistryMetadata(repo_url=candidate)
    for value in project_urls.values():
        candidate = _normalise_repo_url(value)
        if candidate and _looks_like_repo(candidate):
            return RegistryMetadata(repo_url=candidate)
    home = _normalise_repo_url(info.get("home_page"))
    if home and _looks_like_repo(home):
        return RegistryMetadata(repo_url=home)
    return RegistryMetadata(repo_url=None)


async def _pypi_package_metadata(
    dep: Dependency, session: RateLimitedSession
) -> PackageMetadata | None:
    data = await _pypi_package_json(dep, session)
    if not data:
        return None
    releases: dict = data.get("releases") or {}
    published = frozenset(releases.keys())

    yanked: set[str] = set()
    for ver, files in releases.items():
        if isinstance(files, list) and files and all(f.get("yanked") for f in files):
            yanked.add(ver)

    return PackageMetadata(
        published_versions=published,
        yanked_versions=frozenset(yanked),
        version_present=dep.version in published if published else True,
        version_yanked=dep.version in yanked,
    )


# --------------------------------------------------------------------------- #
# npm
# --------------------------------------------------------------------------- #


async def _npm_version_json(dep: Dependency, session: RateLimitedSession) -> dict | None:
    encoded_name = dep.name.replace("@", "%40").replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded_name}/{dep.version}"
    return await session.get_json(url)


async def _npm_package_json(dep: Dependency, session: RateLimitedSession) -> dict | None:
    encoded_name = dep.name.replace("@", "%40").replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded_name}"
    return await session.get_json(url)


async def _npm_metadata(
    dep: Dependency, session: RateLimitedSession
) -> RegistryMetadata | None:
    data = await _npm_version_json(dep, session)
    if not data:
        return None

    repository = data.get("repository")
    raw: str | None = None
    if isinstance(repository, dict):
        raw = repository.get("url")
    elif isinstance(repository, str):
        raw = repository
    candidate = _normalise_repo_url(raw)
    if candidate:
        return RegistryMetadata(repo_url=candidate)

    home = _normalise_repo_url(data.get("homepage"))
    if home and _looks_like_repo(home):
        return RegistryMetadata(repo_url=home)
    return RegistryMetadata(repo_url=None)


async def _npm_package_metadata(
    dep: Dependency, session: RateLimitedSession
) -> PackageMetadata | None:
    data = await _npm_package_json(dep, session)
    if not data:
        return None
    versions: dict = data.get("versions") or {}
    published = frozenset(versions.keys())

    # npm marks pulled versions via the top-level "time" map with an "unpublished"
    # sentinel, but per-version absence is the reliable cross-registry signal.
    version_doc = versions.get(dep.version) or {}
    has_install = bool(version_doc.get("hasInstallScript"))
    if not has_install:
        scripts = version_doc.get("scripts") or {}
        has_install = any(
            hook in scripts for hook in ("preinstall", "install", "postinstall")
        )

    return PackageMetadata(
        published_versions=published,
        version_present=dep.version in published if published else True,
        has_install_script=has_install,
    )


# --------------------------------------------------------------------------- #
# crates.io
# --------------------------------------------------------------------------- #


async def _crates_package_json(dep: Dependency, session: RateLimitedSession) -> dict | None:
    url = f"https://crates.io/api/v1/crates/{dep.name}"
    return await session.get_json(url)


async def _crates_package_metadata(
    dep: Dependency, session: RateLimitedSession
) -> PackageMetadata | None:
    data = await _crates_package_json(dep, session)
    if not data:
        return None
    versions = data.get("versions") or []
    published: set[str] = set()
    yanked: set[str] = set()
    for v in versions:
        num = v.get("num")
        if not num:
            continue
        published.add(num)
        if v.get("yanked"):
            yanked.add(num)

    published_fs = frozenset(published)
    return PackageMetadata(
        published_versions=published_fs,
        yanked_versions=frozenset(yanked),
        version_present=dep.version in published_fs if published_fs else True,
        version_yanked=dep.version in yanked,
    )


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #


_VERSION_FETCHERS = {
    "python": _pypi_metadata,
    "javascript": _npm_metadata,
}

_PACKAGE_FETCHERS = {
    "python": _pypi_package_metadata,
    "javascript": _npm_package_metadata,
    "rust": _crates_package_metadata,
}


async def get_registry_metadata(
    dep: Dependency, session: RateLimitedSession
) -> RegistryMetadata | None:
    """Fetch version-specific metadata for *dep*, or None if unavailable."""
    fetcher = _VERSION_FETCHERS.get(dep.ecosystem)
    if fetcher is None:
        return None
    return await fetcher(dep, session)


async def get_package_metadata(
    dep: Dependency, session: RateLimitedSession
) -> PackageMetadata | None:
    """Fetch package-level metadata for *dep*, or None if unavailable."""
    fetcher = _PACKAGE_FETCHERS.get(dep.ecosystem)
    if fetcher is None:
        return None
    return await fetcher(dep, session)
