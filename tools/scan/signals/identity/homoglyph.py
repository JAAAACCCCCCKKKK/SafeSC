"""Identity signal: non-ASCII / homoglyph characters in a package name.

Attacker's-eye view: PyPI, npm, crates.io and Go module paths are, in
practice, ASCII.  An attacker can register a name that is *visually identical*
to a trusted one by swapping a Latin letter for a confusable from another
script — e.g. Cyrillic "а" (U+0430) for Latin "a", or Greek "ο" (U+03BF) for
"o".  Plain Levenshtein on the raw strings sees these as distance 0 (same
codepoint count) yet they are different packages, so the typosquat collector
alone misses them.

This check is purely local and deterministic: any codepoint outside printable
ASCII in a package name is suspicious on its own.  Because legitimate names in
these ecosystems are ASCII, false positives are rare; the offending characters
are reported as evidence for a quick human confirmation.
"""

from __future__ import annotations

import unicodedata

from tools.index.core.models import Dependency
from tools.scan.signals.base import SignalCollector
from tools.scan.signals.models import Dimension, Severity, Signal, Spoofability
from tools.scan.signals.provenance.http import RateLimitedSession


def _non_ascii_chars(name: str) -> list[str]:
    return [ch for ch in name if ord(ch) > 0x7F]


def _describe(ch: str) -> str:
    try:
        label = unicodedata.name(ch)
    except ValueError:
        label = "UNNAMED"
    return f"{ch!r} (U+{ord(ch):04X} {label})"


class HomoglyphCollector(SignalCollector):
    """Flags package names containing non-ASCII (potentially confusable) chars."""

    @property
    def dimension(self) -> Dimension:
        return Dimension.IDENTITY

    async def collect(
        self, dep: Dependency, session: RateLimitedSession
    ) -> list[Signal]:
        offenders = _non_ascii_chars(dep.name)
        if not offenders:
            return []

        described = [_describe(ch) for ch in dict.fromkeys(offenders)]
        return [
            Signal(
                dep=dep,
                dimension=Dimension.IDENTITY,
                code="identity.non_ascii_name",
                severity=Severity.HIGH,
                message=(
                    f"Package name {dep.name!r} contains non-ASCII characters "
                    f"that may be homoglyphs of a trusted package."
                ),
                evidence=[f"suspicious_char={d}" for d in described],
                spoofability=Spoofability.LOW,
                false_positive_hints=[
                    "Confirm the registry actually hosts this exact name; some "
                    "ecosystems permit internationalised names for legitimate "
                    "projects.",
                ],
            )
        ]
