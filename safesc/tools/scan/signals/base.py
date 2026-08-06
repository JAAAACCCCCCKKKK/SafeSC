"""Abstract base for Stage 3 cheap-signal collectors.

A collector is ecosystem-AGNOSTIC: it receives a normalised :class:`Dependency`
and a shared HTTP session, and returns zero or more :class:`Signal` objects.
Ecosystem-specific data retrieval happens behind dispatcher functions (e.g.
``registry_meta``), never inside the collector's judgment logic.

Collectors must never raise for ordinary failures (network, missing data) —
they degrade gracefully by returning an empty list.  The orchestrator adds a
final safety net, but well-behaved collectors handle their own errors.
"""

from __future__ import annotations

import abc

from safesc.tools.index.core.models import Dependency
from safesc.tools.scan.signals.models import Dimension, Signal
from safesc.tools.scan.signals.provenance.http import RateLimitedSession


class SignalCollector(abc.ABC):
    """Plug-in contract for a single cheap-signal collector."""

    @property
    @abc.abstractmethod
    def dimension(self) -> Dimension:
        """The trust dimension this collector contributes to."""

    @abc.abstractmethod
    async def collect(
        self, dep: Dependency, session: RateLimitedSession
    ) -> list[Signal]:
        """Inspect *dep* and return any signals found (possibly empty).

        Implementations that need no network may ignore *session*.  They must
        not raise for routine failure conditions.
        """
