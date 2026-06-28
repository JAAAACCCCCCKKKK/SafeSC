"""Top-level CLI for depaudit.

Stage 0 (discovery) runs by default.
Pass --json to also run Stage 1 (parse) and emit a JSON dependency array.
Pass --verify to run Stage 1 + Stage 2 (hash verification) and emit results.
Pass --signals to run Stage 1 + Stage 3 (cheap signals) and emit signals.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from depaudit.core.discovery import discover, print_discovered
from depaudit.core.normalizer import parse_lockfiles, to_json


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    output_json = "--json" in args
    run_verify = "--verify" in args
    run_signals = "--signals" in args
    positional = [a for a in args if not a.startswith("--")]
    root = Path(positional[0]) if positional else Path.cwd()

    try:
        files = discover(root)
    except NotADirectoryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if run_verify:
        from depaudit.signals.provenance.verifier import run_verification

        deps = parse_lockfiles(files)
        results = run_verification(deps)
        print(json.dumps([r.to_dict() for r in results], indent=2))

        has_critical = any(r.severity.value == "critical" for r in results)
        return 1 if has_critical else 0

    if run_signals:
        from depaudit.signals.collector import run_collection

        deps = parse_lockfiles(files)
        signals = run_collection(deps)
        print(json.dumps([s.to_dict() for s in signals], indent=2))
        # Stage 3 only emits evidence; CI gating is the scorer's job (later stage).
        return 0

    if output_json:
        deps = parse_lockfiles(files)
        print(to_json(deps))
        return 0

    print_discovered(files, root.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())