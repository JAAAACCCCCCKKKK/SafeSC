"""Stage 2-3 command implementations for the ``scan`` tool.

Each function takes a filesystem *root*, obtains the dependency set by reusing
the ``index`` tool's discovery + parsing, runs exactly one audit stage, emits a
machine-consumable JSON result to stdout, and returns a process exit code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from safesc.tools.index.core.discovery import discover
from safesc.tools.index.core.normalizer import parse_lockfiles


def cmd_verify(root: Path) -> int:
    """Stage 2 — verify lockfile hashes against registry hashes.

    Exit code is 1 when any result is ``critical`` (a hash mismatch), matching
    the pipeline gate defined for this stage.
    """
    from safesc.tools.scan.signals.provenance.verifier import run_verification

    try:
        files = discover(root)
    except NotADirectoryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    deps = parse_lockfiles(files)
    results = run_verification(deps)
    print(json.dumps([r.to_dict() for r in results], indent=2))

    has_critical = any(r.severity.value == "critical" for r in results)
    return 1 if has_critical else 0


def cmd_signals(root: Path) -> int:
    """Stage 3 — collect cheap signals over every dependency.

    Stage 3 only emits evidence; CI gating is the scorer's job (a later stage),
    so this command always returns 0.
    """
    from safesc.tools.scan.signals.collector import run_collection

    try:
        files = discover(root)
    except NotADirectoryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    deps = parse_lockfiles(files)
    signals = run_collection(deps)
    print(json.dumps([s.to_dict() for s in signals], indent=2))
    return 0
