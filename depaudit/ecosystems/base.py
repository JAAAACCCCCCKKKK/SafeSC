"""Abstract base for ecosystem adapters.

Every ecosystem (Python, npm, Cargo, …) must subclass EcosystemAdapter and
implement all abstract methods.  The core pipeline only interacts with this
interface — it never imports ecosystem-specific code directly.
"""

from __future__ import annotations

import abc
from pathlib import Path


class EcosystemAdapter(abc.ABC):
    """Plug-in contract that every ecosystem adapter must fulfil."""

    # ------------------------------------------------------------------ #
    # Identity                                                             #
    # ------------------------------------------------------------------ #

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Short, human-readable ecosystem name, e.g. ``"python"``."""

    @property
    @abc.abstractmethod
    def lockfile_globs(self) -> list[str]:
        """Glob patterns (relative, no leading ``**``) that identify lockfiles.

        Examples::

            ["uv.lock", "poetry.lock", "requirements*.txt"]

        The discovery engine prepends ``**/`` so patterns match anywhere in
        the repository tree.
        """

    # ------------------------------------------------------------------ #
    # Stage 0 helpers                                                      #
    # ------------------------------------------------------------------ #

    def is_lockfile(self, path: Path) -> bool:
        """Return True if *path* is a lockfile managed by this ecosystem.

        The default implementation matches against :attr:`lockfile_globs`
        using :py:meth:`pathlib.Path.match`.  Override for richer heuristics.
        """
        for pattern in self.lockfile_globs:
            if path.match(pattern):
                return True
        return False