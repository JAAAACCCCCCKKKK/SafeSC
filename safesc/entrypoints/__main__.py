"""Enable ``python -m safesc.entrypoints`` as an alias for the ``safesc`` console script.

Delegates to the tier-2 production wiring in ``safesc.entrypoints.bootstrap`` so the module
and the installed script share one code path.
"""

from __future__ import annotations

from safesc.entrypoints.bootstrap import main

if __name__ == "__main__":
    raise SystemExit(main())
