"""core/targets.py — what a run inspects, decided before any agent starts (CLAUDE.md §2.2-A).

Two deterministic, risk-free questions:

* **Where?** With no explicit target, a CI run inspects the checked-out repository and an
  interactive run inspects the current directory (`default_target`).
* **What shape?** A filesystem path / lockfile is a repository scan; a package spec
  (`npm:left-pad@1.3.0`, `pkg:pypi/requests@2.31.0`, `@scope/name@1`) is a single-package
  inspection (`classify_target`). Both feed the same pipeline tools and the same scorer.

Nothing here reads a signal, so nothing here can be steered by package content.
"""

from __future__ import annotations

import os
import re
import subprocess
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional

from safesc.tools.index.core.models import Dependency


class TargetKind(str, Enum):
    REPOSITORY = "repository"
    PACKAGE = "package"


# There is no lockfile for a directly-specified package; a stable sentinel keeps the
# Dependency valid and self-describing without pointing at a real file.
SYNTHETIC_LOCKFILE = "<single-package>"

# purl / registry aliases → the canonical ecosystem names the index+scan layers use.
_ECOSYSTEM_ALIASES = {
    "pypi": "python", "pip": "python", "python": "python",
    "npm": "javascript", "javascript": "javascript", "js": "javascript",
    "cargo": "rust", "crates": "rust", "rust": "rust",
    "golang": "go", "go": "go",
    "maven": "java", "java": "java",
}

_PACKAGE_SPEC_RE = re.compile(r"^(?:[a-z]+:)?@?[\w.\-]+(?:/[\w.\-]+)?(?:@[\w.\-+]+)?$")
_LOCKFILE_NAMES = {
    "requirements.txt", "poetry.lock", "uv.lock", "pipfile.lock",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "cargo.lock", "go.sum", "go.mod", "pom.xml", "build.gradle",
}

# Environment variables that mean "this process is a CI job". `CI` is set by GitHub
# Actions, GitLab, CircleCI, Travis, Buildkite, Azure Pipelines (as TF_BUILD) and more.
_CI_MARKERS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "TF_BUILD", "JENKINS_URL")


def is_ci(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    for marker in _CI_MARKERS:
        value = (env.get(marker) or "").strip().lower()
        if value and value not in ("0", "false", "no", "off"):
            return True
    return False


def _git_toplevel(cwd: Path) -> Optional[Path]:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=str(cwd),
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = proc.stdout.strip()
    return Path(out) if proc.returncode == 0 and out else None


def default_target(env: Mapping[str, str] | None = None, cwd: Path | None = None) -> str:
    """The target a bare `safesc` inspects.

    In CI: the checked-out repository — `GITHUB_WORKSPACE` / `CI_PROJECT_DIR` /
    `BUILD_SOURCESDIRECTORY` when the runner exports one, else the git top-level of the
    working directory. Outside CI: the current directory, exactly as typed.
    """
    env = os.environ if env is None else env
    cwd = cwd or Path.cwd()
    if not is_ci(env):
        return str(cwd)
    for var in ("GITHUB_WORKSPACE", "CI_PROJECT_DIR", "BUILD_SOURCESDIRECTORY", "WORKSPACE"):
        value = (env.get(var) or "").strip()
        if value and Path(value).is_dir():
            return value
    top = _git_toplevel(cwd)
    return str(top or cwd)


def _looks_like_path(target: str) -> bool:
    t = target.strip()
    if t in (".", "./") or t.startswith(("/", "./", "../", "~", ".\\", "..\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", t):  # Windows drive path
        return True
    if Path(t).name.lower() in _LOCKFILE_NAMES:
        return True
    try:
        return Path(t).exists()
    except OSError:
        return False


def classify_target(target: str) -> TargetKind:
    """Structural and deterministic. Never consults risk/signals (§2.2-A)."""
    t = (target or "").strip()
    if not t or t.startswith("pkg:"):
        return TargetKind.REPOSITORY if not t else TargetKind.PACKAGE
    if _looks_like_path(t):
        return TargetKind.REPOSITORY
    if "/" in t and not t.startswith("@") and not re.match(r"^[a-z]+:@", t):
        return TargetKind.REPOSITORY
    if _PACKAGE_SPEC_RE.match(t):
        return TargetKind.PACKAGE
    return TargetKind.REPOSITORY


def _split_name_version(spec: str) -> tuple[str, str]:
    """Split ``name[@version]``. A leading '@' is an npm scope, not a version separator."""
    at = spec.rfind("@")
    if at > 0:
        return spec[:at], spec[at + 1:]
    return spec, ""


def _make_dep(ecosystem: str, name: str, version: str) -> Dependency:
    return Dependency(
        name=name, version=version, ecosystem=ecosystem,
        lockfile_path=Path(SYNTHETIC_LOCKFILE), is_direct=True, layer_number=1,
    )


def parse_package_spec(target: str, default_ecosystem: Optional[str] = None) -> Optional[Dependency]:
    """Turn a package spec into one `Dependency`, or None if unparseable.

    Accepts purl (`pkg:npm/left-pad@1.3.0`), ecosystem-prefixed (`pypi:requests@2.31.0`),
    npm scope (`@angular/core@17.0.0`) and bare `name[@version]` (ecosystem from
    `default_ecosystem`).
    """
    spec = (target or "").strip()
    if not spec:
        return None

    if spec.startswith("pkg:"):
        body = spec[len("pkg:"):]
        if "/" not in body:
            return None
        slash = body.rfind("/")
        at = body.find("@", slash + 1)
        left, version = (body[:at], body[at + 1:]) if at != -1 else (body, "")
        ptype, _, name = left.partition("/")
        name = name.strip("/")
        if not ptype or not name:
            return None
        return _make_dep(_ECOSYSTEM_ALIASES.get(ptype.lower(), ptype.lower()), name, version)

    if ":" in spec and not spec.startswith("@"):
        prefix, rest = spec.split(":", 1)
        if prefix.lower() in _ECOSYSTEM_ALIASES:
            name, version = _split_name_version(rest)
            if name:
                return _make_dep(_ECOSYSTEM_ALIASES[prefix.lower()], name, version)

    name, version = _split_name_version(spec)
    if not name:
        return None
    if spec.startswith("@"):
        ecosystem = "javascript"
    elif default_ecosystem:
        ecosystem = _ECOSYSTEM_ALIASES.get(default_ecosystem.lower(), default_ecosystem)
    else:
        ecosystem = ""
    return _make_dep(ecosystem, name, version)
