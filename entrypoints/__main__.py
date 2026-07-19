"""Enable ``python -m entrypoints`` as an alias for the ``depaudit`` console script.

Delegates to the tier-2 production wiring in ``entrypoints.bootstrap`` so the module and
the installed script share one code path.
"""

from __future__ import annotations

from entrypoints.bootstrap import main

if __name__ == "__main__":
    raise SystemExit(main())
