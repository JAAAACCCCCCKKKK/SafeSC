"""entrypoints/bootstrap.py — production wiring for the ``depaudit`` console script.

This is the concrete wiring that ``entrypoints/cli.py``'s injectable ``main()`` was
designed to receive. It constructs the **tier-2** runtime — the deterministic Stage 0–3
spine plus the Stage-4 LLM specialists — with **no external stores**:

* no Redis (the §5.2/§2.7.3 distributed semaphores exist for fleet-scale rate limiting;
  a single finite CI audit does not need them),
* no Postgres / PGVector (long-term memory, §3, is a cost/grounding optimisation that can
  only *escalate*, never change a verdict — §3.3 — so omitting it is always safe),
* no LangGraph checkpointer (every audit run is finite — §1.3).

The only requirement is a caller-supplied reasoning-LLM key in the environment
(``DEPAUDIT_LLM_API_KEY``, BYOK — §3.5). The graph therefore runs with ``memory=None`` and
``checkpointer=None``.

``cli.py`` stays thin and testable (its ``main()`` takes injected deps); this module owns
the concrete tool construction so importing the library surface stays side-effect-free.
"""

from __future__ import annotations

import sys

from entrypoints.cli import main as cli_main
from graph.harness.session_manager import new_ulid

# Packages whose absence means the optional `agent` extra was not installed.
_AGENT_EXTRA_MODULES = ("langgraph", "anthropic")


class LocalSession:
    """Minimal ``SessionManager`` stand-in for single-run CI use.

    ``graph.build.run`` only calls ``session.new_run()`` to mint a run id; the
    Redis-backed distributed semaphores live on the full ``SessionManager`` (§2.7.3) and
    are unnecessary for one finite audit. Minting a ULID needs no external store.
    """

    def new_run(self) -> str:
        return new_ulid()


def build_local_runtime():
    """Wire the four Stage 0–3 seams to the real frozen tools (§6.1.5).

    Returns the ``(tools, session, memory)`` triple that ``cli.main()`` expects. ``memory``
    is ``None`` — this is the store-free tier-2 path.
    """
    from graph.spine import load_default_tools

    return load_default_tools(), LocalSession(), None


def _explain_missing_extra(module_name: str) -> None:
    print(
        f"depaudit: the tier-2 audit path needs the '{module_name}' package, which is part "
        "of the optional 'agent' extra.\n"
        "Install it with:  pip install 'safesc[agent]'",
        file=sys.stderr,
    )


def main(argv=None) -> int:
    """Console-script entry point for ``depaudit`` (audit | query | gc).

    Builds the store-free runtime and delegates to the injectable ``cli.main``. Missing
    optional dependencies (LangGraph / Anthropic) are reported with an actionable message
    rather than a raw traceback.
    """
    try:
        tools, session, memory = build_local_runtime()
    except ModuleNotFoundError as exc:  # pragma: no cover - defensive
        if exc.name and exc.name.split(".")[0] in _AGENT_EXTRA_MODULES:
            _explain_missing_extra(exc.name.split(".")[0])
            return 2
        raise

    try:
        return cli_main(argv, tools=tools, session=session, memory=memory)
    except ModuleNotFoundError as exc:
        top = exc.name.split(".")[0] if exc.name else ""
        if top in _AGENT_EXTRA_MODULES:
            _explain_missing_extra(top)
            return 2
        raise


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
