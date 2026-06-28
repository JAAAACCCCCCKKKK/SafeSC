"""Identity signal: typosquatting via name edit-distance to a popular package.

Cheat-sheet rule: *package name edit distance <= 2 to a popular package ->
critical*.  This is a purely local, deterministic check — no network — so it is
the cheapest possible signal and runs on every dependency.

False-positive guard: a name whose *canonical* form (case-folded, separators
collapsed) equals a popular package is that package, not a typosquat, and is
skipped.  Very short names are also skipped to avoid noise.
"""

from __future__ import annotations

import re

from depaudit.core.models import Dependency
from depaudit.signals.base import SignalCollector
from depaudit.signals.identity.popular_packages import POPULAR_BY_ECOSYSTEM
from depaudit.signals.models import Dimension, Severity, Signal, Spoofability
from depaudit.signals.provenance.http import RateLimitedSession

_MIN_LEN = 4
_MAX_DISTANCE = 2
_SEP_RUN = re.compile(r"[-_.]+")


def _canonical(name: str) -> str:
    """Case-fold and collapse separator runs so equivalent names compare equal."""
    return _SEP_RUN.sub("-", name.strip().lower())


def bounded_levenshtein(a: str, b: str, max_distance: int) -> int:
    """Levenshtein distance between *a* and *b*, capped at ``max_distance + 1``.

    Returns ``max_distance + 1`` as soon as the distance is known to exceed the
    cap, which lets callers cheaply reject far-apart strings.
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        row_min = current[0]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(
                min(
                    previous[j] + 1,        # deletion
                    current[j - 1] + 1,     # insertion
                    previous[j - 1] + cost,  # substitution
                )
            )
            row_min = min(row_min, current[-1])
        if row_min > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


class TyposquatCollector(SignalCollector):
    """Flags dependency names that are a near-miss of a popular package."""

    @property
    def dimension(self) -> Dimension:
        return Dimension.IDENTITY

    async def collect(
        self, dep: Dependency, session: RateLimitedSession
    ) -> list[Signal]:
        popular = POPULAR_BY_ECOSYSTEM.get(dep.ecosystem)
        if not popular:
            return []

        canon = _canonical(dep.name)
        if len(canon) < _MIN_LEN:
            return []

        best_name: str | None = None
        best_dist = _MAX_DISTANCE + 1
        for pop in popular:
            pop_canon = _canonical(pop)
            if len(pop_canon) < _MIN_LEN:
                continue
            if canon == pop_canon:
                return []  # this *is* the popular package, not a typosquat
            dist = bounded_levenshtein(canon, pop_canon, _MAX_DISTANCE)
            if 1 <= dist < best_dist:
                best_dist, best_name = dist, pop

        if best_name is None or best_dist > _MAX_DISTANCE:
            return []

        return [
            Signal(
                dep=dep,
                dimension=Dimension.IDENTITY,
                code="identity.typosquat",
                severity=Severity.CRITICAL,
                message=(
                    f"Package name {dep.name!r} is within edit distance "
                    f"{best_dist} of popular package {best_name!r}."
                ),
                evidence=[
                    f"nearest_popular={best_name}",
                    f"edit_distance={best_dist}",
                ],
                spoofability=Spoofability.LOW,
                false_positive_hints=[
                    "Confirm this is not a legitimate fork, mirror, or "
                    "namespaced variant of the popular package.",
                ],
            )
        ]
