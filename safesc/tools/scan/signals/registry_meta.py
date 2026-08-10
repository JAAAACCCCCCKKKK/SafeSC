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

from safesc.tools.index.core.models import Dependency
from safesc.tools.scan.signals.provenance.http import RateLimitedSession


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
    has_native_build_script: bool = False  # rust: resolved version declares a `links`
    # key. Cargo requires a build script whenever `links` is set (a crate cannot claim
    # to provide a native library link-name without one), so a non-null `lib_links` on
    # the crates.io version record is a sound (zero false-positive), if incomplete,
    # proxy: crates whose build.rs exists purely for codegen and never set `links` are
    # not caught by this field. See behavior/install_script.py.
    requires_source_build: bool = False  # python: the resolved version publishes an
    # sdist but NO wheel, so pip cannot just unpack a built artifact — it must build
    # from source, executing the project's PEP 517 backend (and its `setup.py`, or an
    # in-tree `backend-path` backend). Wheels are only unpacked and never execute
    # project code at install time, so a published wheel makes this False.
    # See behavior/install_script.py.

    # --- Identity / provenance descriptors (used by the IdentityAgent to tell a
    #     legitimate companion package from a typosquat; §2.3). All best-effort. ---
    author: str | None = None          # publisher/author string as the registry reports it
    repo_url: str | None = None        # canonical source repo, if declared
    homepage: str | None = None        # project homepage, if declared
    summary: str | None = None         # one-line project description
    total_releases: int = 0            # number of published versions (age/maturity proxy)
    first_release_at: str | None = None  # ISO timestamp of the earliest release, if known
    latest_release_at: str | None = None  # ISO timestamp of the most recent release, if known


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


def _pypi_contains(published: frozenset[str], pinned: str) -> bool:
    """Is *pinned* among *published*, comparing under PEP 440 (not raw strings)?

    PyPI stores canonical version keys, but a lockfile may pin an *equal* non-canonical
    form (``2.31`` == ``2.31.0``, ``01.2.3`` == ``1.2.3``, trailing-zero/epoch/case
    differences). A raw ``in`` check then reports the version "not published" and the
    provenance collector escalates to HIGH — a false positive that fails the CI gate.
    Fall back to the raw check if `packaging` is unavailable (no regression)."""
    if pinned in published:
        return True
    try:
        from packaging.version import InvalidVersion, Version  # ubiquitous; lazy import
    except Exception:  # pragma: no cover - packaging effectively always present
        return False
    try:
        target = Version(pinned)
    except InvalidVersion:
        return False  # unparseable pin can't be normalised — treat as absent (raw already failed)
    for candidate in published:
        try:
            if Version(candidate) == target:
                return True
        except InvalidVersion:
            continue
    return False


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

    info: dict = data.get("info") or {}
    author = info.get("author") or info.get("author_email") or None
    if not author:
        author = info.get("maintainer") or info.get("maintainer_email") or None
    project_urls: dict = info.get("project_urls") or {}
    repo_url = None
    for key in ("Source", "Source Code", "Repository", "Code", "GitHub"):
        repo_url = _normalise_repo_url(project_urls.get(key))
        if repo_url:
            break
    if not repo_url:
        for value in project_urls.values():
            cand = _normalise_repo_url(value)
            if cand and _looks_like_repo(cand):
                repo_url = cand
                break

    first_at, latest_at = _pypi_release_span(releases)

    # PEP 440-aware membership so an equal-but-non-canonical pin (e.g. 2.31 vs 2.31.0)
    # isn't misreported as absent/not-yanked.
    return PackageMetadata(
        published_versions=published,
        yanked_versions=frozenset(yanked),
        version_present=_pypi_contains(published, dep.version) if published else True,
        version_yanked=_pypi_contains(frozenset(yanked), dep.version),
        # Derived from the `releases` payload already fetched above — costs no extra
        # HTTP request.
        requires_source_build=_pypi_requires_source_build(releases, dep.version),
        author=author,
        repo_url=repo_url,
        homepage=_normalise_repo_url(info.get("home_page")) or (info.get("home_page") or None),
        summary=(info.get("summary") or None),
        total_releases=len(published),
        first_release_at=first_at,
        latest_release_at=latest_at,
    )


def _pypi_files_for(releases: dict, pinned: str) -> list[dict]:
    """The release-file list for *pinned*, matched under PEP 440 like `_pypi_contains`
    (so a non-canonical pin such as ``2.31`` still finds ``2.31.0``'s files)."""
    files = releases.get(pinned)
    if files is not None:
        return files if isinstance(files, list) else []
    try:
        from packaging.version import InvalidVersion, Version  # ubiquitous; lazy import
    except Exception:  # pragma: no cover - packaging effectively always present
        return []
    try:
        target = Version(pinned)
    except InvalidVersion:
        return []
    for candidate, candidate_files in releases.items():
        try:
            if Version(candidate) == target:
                return candidate_files if isinstance(candidate_files, list) else []
        except InvalidVersion:
            continue
    return []


def _pypi_requires_source_build(releases: dict, pinned: str) -> bool:
    """True when installing *pinned* must build from source, executing project code.

    A wheel is only unpacked, so a published ``bdist_wheel`` means no project build
    code runs at install time. An sdist with no wheel forces pip to invoke the PEP 517
    backend (``setup.py``/an in-tree backend) — the Python analogue of an npm install
    hook. Deliberately conservative: an empty or wheel-bearing file list, or an exotic
    set with no sdist at all, returns False rather than guessing.
    """
    files = _pypi_files_for(releases, pinned)
    if not files:
        return False
    kinds = {f.get("packagetype") for f in files if isinstance(f, dict)}
    return "sdist" in kinds and "bdist_wheel" not in kinds


def _pypi_release_span(releases: dict) -> tuple[str | None, str | None]:
    """Earliest and latest upload timestamps across all release files, ISO strings."""
    stamps: list[str] = []
    for files in releases.values():
        if not isinstance(files, list):
            continue
        for f in files:
            ts = f.get("upload_time_iso_8601") or f.get("upload_time")
            if ts:
                stamps.append(ts)
    if not stamps:
        return None, None
    stamps.sort()
    return stamps[0], stamps[-1]


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

    author = data.get("author")
    if isinstance(author, dict):
        author = author.get("name") or author.get("email")
    elif not isinstance(author, str):
        author = None

    repository = data.get("repository")
    raw_repo: str | None = None
    if isinstance(repository, dict):
        raw_repo = repository.get("url")
    elif isinstance(repository, str):
        raw_repo = repository

    time_map = data.get("time") or {}
    stamps = [v for k, v in time_map.items() if k not in ("created", "modified")]
    stamps = [s for s in stamps if isinstance(s, str)]
    stamps.sort()
    first_at = time_map.get("created") or (stamps[0] if stamps else None)
    latest_at = time_map.get("modified") or (stamps[-1] if stamps else None)

    return PackageMetadata(
        published_versions=published,
        version_present=dep.version in published if published else True,
        has_install_script=has_install,
        author=author,
        repo_url=_normalise_repo_url(raw_repo),
        homepage=(data.get("homepage") or None),
        summary=(data.get("description") or None),
        total_releases=len(published),
        first_release_at=first_at,
        latest_release_at=latest_at,
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
    created_stamps: list[str] = []
    version_doc: dict = {}
    for v in versions:
        num = v.get("num")
        if not num:
            continue
        published.add(num)
        if v.get("yanked"):
            yanked.add(num)
        ts = v.get("created_at")
        if isinstance(ts, str):
            created_stamps.append(ts)
        if num == dep.version:
            version_doc = v

    crate: dict = data.get("crate") or {}
    created_stamps.sort()
    first_at = crate.get("created_at") or (created_stamps[0] if created_stamps else None)
    latest_at = crate.get("updated_at") or (created_stamps[-1] if created_stamps else None)

    published_fs = frozenset(published)
    return PackageMetadata(
        published_versions=published_fs,
        yanked_versions=frozenset(yanked),
        version_present=dep.version in published_fs if published_fs else True,
        version_yanked=dep.version in yanked,
        # `lib_links` on the crates.io version record mirrors the crate's Cargo.toml
        # `links` key, which Cargo requires a build script to set (behavior/install_script.py).
        has_native_build_script=bool(version_doc.get("lib_links")),
        repo_url=_normalise_repo_url(crate.get("repository")) or (crate.get("repository") or None),
        homepage=(crate.get("homepage") or None),
        summary=(crate.get("description") or None),
        total_releases=len(published_fs),
        first_release_at=first_at,
        latest_release_at=latest_at,
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
