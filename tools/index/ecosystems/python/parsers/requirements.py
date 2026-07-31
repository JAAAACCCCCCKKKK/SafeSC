"""Parse requirements*.txt (pip format)."""

from __future__ import annotations

import re
from pathlib import Path

from tools.index.core.models import Dependency

# PEP 503-ish distribution name.
_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"

# A requirement line: name, optional [extras], then the remainder (specifiers/markers).
_LINE_RE = re.compile(rf"^(?P<name>{_NAME})(?:\[(?P<extras>[^\]]+)\])?\s*(?P<rest>.*)$")
# Exact pin inside a specifier set, e.g. "==2.31.0" (also matches the legacy "===").
_EXACT_RE = re.compile(r"===?\s*([^\s,;]+)")
_HASH_RE = re.compile(r"--hash=([^:\s]+:[A-Fa-f0-9]+)")
# name @ url  (PEP 508 direct reference) and  #egg=name / &egg=name  fragments.
_DIRECT_REF_RE = re.compile(rf"^(?P<name>{_NAME})\s*@\s*\S+")
_EGG_RE = re.compile(rf"[#&]egg=(?P<name>{_NAME})")
_INCLUDE_RE = re.compile(r"^(?:-r|--requirement|-c|--constraint)[=\s]+(?P<target>.+?)\s*$")
_UNPINNED = "*"


def parse(path: Path, *, _seen: set | None = None) -> list[Dependency]:
    _seen = _seen if _seen is not None else set()
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if resolved in _seen:  # guard against -r/-c include cycles
        return []
    _seen.add(resolved)

    try:
        # utf-8-sig transparently strips a leading BOM so the first dependency isn't lost.
        raw = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return []

    result: list[Dependency] = []
    for line in _logical_lines(raw):
        stripped = _strip_comment(line).strip()
        if not stripped:
            continue

        include = _INCLUDE_RE.match(stripped)
        if include:  # -r / -c → parse the referenced file relative to this one
            target = (path.parent / include.group("target")).expanduser()
            result.extend(parse(target, _seen=_seen))
            continue

        hashes = _HASH_RE.findall(stripped)

        if stripped.startswith("-"):  # -e / --index-url / other options
            egg = _EGG_RE.search(stripped)
            if egg:  # editable VCS install carrying #egg=name
                result.append(_make(egg.group("name"), _UNPINNED, path, hashes, []))
            continue

        direct = _DIRECT_REF_RE.match(stripped)
        if direct:  # name @ https://... direct reference
            result.append(_make(direct.group("name"), _UNPINNED, path, hashes, []))
            continue

        if re.match(r"^[a-z][a-z0-9+.\-]*://", stripped) or stripped.startswith(
            ("git+", "hg+", "svn+", "bzr+")
        ):  # bare VCS/URL line; salvage the egg name if present
            egg = _EGG_RE.search(stripped)
            if egg:
                result.append(_make(egg.group("name"), _UNPINNED, path, hashes, []))
            continue

        m = _LINE_RE.match(stripped)
        if not m:
            continue
        name = m.group("name").lower()
        extras_raw = m.group("extras")
        extras = [e.strip() for e in extras_raw.split(",")] if extras_raw else []
        rest = _HASH_RE.sub("", m.group("rest") or "").split(";", 1)[0].strip()
        result.append(_make(name, _resolve_version(rest), path, hashes, extras))

    return result


def _logical_lines(raw: str) -> list[str]:
    """Join pip's backslash line-continuations into single logical lines."""
    lines: list[str] = []
    pending = ""
    for line in raw.splitlines():
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
        else:
            pending += line
            lines.append(pending)
            pending = ""
    if pending:
        lines.append(pending)
    return lines


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment. A ``#`` only starts a comment at line start or after
    whitespace, so URL fragments like ``...#egg=name`` are preserved."""
    m = re.search(r"(?:^|\s)#", line)
    return line[: m.start()] if m else line


def _resolve_version(spec: str) -> str:
    """Exact pin when present (``==``/``===``); otherwise ``*`` for a range/unpinned dep."""
    if not spec:
        return _UNPINNED
    if spec.lstrip().startswith(("==", "===")):
        exact = _EXACT_RE.match(spec.lstrip())
        if exact:
            return exact.group(1)
    return _UNPINNED


def _make(name: str, version: str, path: Path, hashes: list[str], extras: list[str]) -> Dependency:
    return Dependency(
        name=name.lower(),
        version=version,
        ecosystem="python",
        lockfile_path=path,
        hash=hashes[0] if hashes else None,
        source_url=None,
        is_direct=True,
        layer_number=1,
        parent_name=None,
        extras=extras,
    )
