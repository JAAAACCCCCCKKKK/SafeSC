"""Classify a lockfile URL as a VCS source URL vs. an artifact download URL.

Lockfiles mix two kinds of URL in a single field:

* a **VCS / source-repository** URL (``git+https://…``, ``https://github.com/o/r``)
  that ``git clone`` can read — this belongs in ``Dependency.source_url``; and
* an **artifact download** URL (a ``.whl`` / ``.tgz`` / ``.crate`` / ``.jar`` /
  ``.zip`` on a registry CDN) — this belongs in ``Dependency.artifact_url``.

Historically every ecosystem parser dumped the artifact URL into ``source_url``,
which made the Stage-4 deep-analysis clone (``git clone <artifact_url>``) fail on
every registry dependency. :func:`split_source_artifact` gives parsers one place
to route each URL to the right field.
"""

from __future__ import annotations

from urllib.parse import urlparse

# Known VCS hosts — a plain https URL to one of these is a real source repo, not an
# artifact download. (Registry CDNs like files.pythonhosted.org never appear here.)
_VCS_HOSTS = (
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "sr.ht",
    "git.sr.ht",
    "gitea.com",
)

# VCS scheme prefixes as they appear in requirement specs / lockfile source fields.
_VCS_SCHEME_PREFIXES = ("git+", "hg+", "svn+", "bzr+", "git:", "ssh://git@")

# Artifact filename suffixes: a URL whose path ends in one of these is a download,
# never a clonable repo, even if it happens to be hosted on a VCS-looking domain.
_ARTIFACT_SUFFIXES = (
    ".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip",
    ".crate", ".jar", ".gem", ".nupkg", ".egg",
)


def normalise_vcs_url(raw: str) -> str:
    """Strip a VCS scheme prefix and any ``?query``/``#fragment`` so the result is a
    plain browsable/clonable https URL. Does not validate reachability."""
    url = raw.strip()
    for prefix in ("git+", "hg+", "svn+", "bzr+"):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    url = url.split("?", 1)[0].split("#", 1)[0]
    if url.endswith(".git"):
        url = url[: -len(".git")]
    return url


def is_vcs_url(url: str) -> bool:
    """True if *url* refers to a version-control repository (clonable), not a plain
    artifact download."""
    if not url:
        return False
    lowered = url.strip().lower()
    if lowered.startswith(_VCS_SCHEME_PREFIXES):
        return True
    # An explicit artifact filename is decisive regardless of host.
    path = urlparse(lowered).path
    if any(path.endswith(suffix) for suffix in _ARTIFACT_SUFFIXES):
        return False
    host = urlparse(lowered).netloc
    return any(host == h or host.endswith("." + h) for h in _VCS_HOSTS)


def is_artifact_url(url: str) -> bool:
    """True if *url* is an artifact download (has an artifact filename suffix)."""
    if not url:
        return False
    path = urlparse(url.strip().lower()).path
    return any(path.endswith(suffix) for suffix in _ARTIFACT_SUFFIXES)


def module_path_to_repo_url(module: str) -> str | None:
    """Map a Go module path to a clonable https repo URL, or None if not derivable.

    ``github.com/pkg/errors`` → ``https://github.com/pkg/errors``. A trailing major
    version suffix (``/v2``…) is dropped, since it is not part of the repo path. Only
    known VCS hosts are mapped; vanity/custom domains (which need an HTTP ``go-import``
    meta lookup we don't perform here) return None so the clone degrades gracefully."""
    if not module:
        return None
    parts = module.strip().strip("/").split("/")
    if len(parts) < 3:
        return None
    host = parts[0].lower()
    if not any(host == h or host.endswith("." + h) for h in _VCS_HOSTS):
        return None
    owner, repo = parts[1], parts[2]
    if not owner or not repo:
        return None
    return f"https://{parts[0]}/{owner}/{repo}"


def split_source_artifact(url: str | None) -> tuple[str | None, str | None]:
    """Route a single lockfile URL to ``(source_url, artifact_url)``.

    * A VCS URL → ``(normalised_repo, None)`` (clonable source).
    * An artifact download URL → ``(None, url)``.
    * Anything else (empty/None) → ``(None, None)``.
    """
    if not url:
        return None, None
    if is_vcs_url(url):
        return normalise_vcs_url(url), None
    if is_artifact_url(url):
        return None, url
    # Unknown shape: treat as an artifact/registry reference rather than risk feeding a
    # non-repo URL to `git clone` (which is the bug this module exists to prevent).
    return None, url
