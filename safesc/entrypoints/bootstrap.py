"""entrypoints/bootstrap.py — production wiring for the ``safesc`` console script.

This is the concrete wiring that ``entrypoints/cli.py``'s injectable ``main()`` was
designed to receive. It constructs the **tier-2** runtime — the deterministic Stage 0–3
spine plus the Stage-4 LLM specialists — with **no external stores**:

* no Redis (the §5.2/§2.7.3 distributed semaphores exist for fleet-scale rate limiting;
  a single finite CI audit does not need them),
* no Postgres / PGVector (long-term memory, §3, is a cost/grounding optimisation that can
  only *escalate*, never change a verdict — §3.3 — so omitting it is always safe),
* no LangGraph checkpointer (every audit run is finite — §1.3).

The only requirement is a caller-supplied reasoning-LLM key in the environment
(``SAFESC_LLM_API_KEY``, BYOK — §3.5). The graph therefore runs with ``memory=None`` and
``checkpointer=None``.

``cli.py`` stays thin and testable (its ``main()`` takes injected deps); this module owns
the concrete tool construction so importing the library surface stays side-effect-free.
"""

from __future__ import annotations

import logging
import os
import sys

from safesc.entrypoints.cli import main as cli_main
from safesc.graph.harness.session_manager import new_ulid

# Optional modules whose absence should produce a friendly install hint instead of a raw
# traceback, mapped to the extra that provides each: `agent` is the orchestration extra;
# `anthropic` / `openai` are the per-provider SDK extras (install the one you configure).
_OPTIONAL_MODULE_EXTRAS = {
    "langgraph": "agent",
    "anthropic": "anthropic",
    "openai": "openai",
}


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
    from safesc.graph.spine import load_default_tools

    return load_default_tools(), LocalSession(), None


def _explain_missing_extra(module_name: str) -> None:
    extra = _OPTIONAL_MODULE_EXTRAS.get(module_name, module_name)
    # `agent` is orchestration; provider SDKs also need the agent extra alongside them.
    install = "safesc[agent]" if extra == "agent" else f"safesc[agent,{extra}]"
    print(
        f"safesc: the tier-2 audit path needs the '{module_name}' package, which is part "
        f"of the optional '{extra}' extra.\n"
        f"Install it with:  pip install '{install}'",
        file=sys.stderr,
    )


def _configure_logging() -> None:
    """Make SafeSC's own diagnostics (e.g. the LLM request/failure logs in
    ``graph/llm_client.py`` — request URL, HTTP status, response body) visible on the
    console. Without this the console script has no handler, so only WARNING+ leaks via
    Python's last-resort handler and the *reason* an LLM call failed stays hidden.

    Third-party libraries are kept at WARNING to avoid noise; the ``safesc`` logger tree is
    set to ``SAFESC_LOG_LEVEL`` (default INFO, e.g. DEBUG for request/response tracing)."""
    level_name = os.environ.get("SAFESC_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(level=logging.WARNING)  # root/third-party stay quiet
    logging.getLogger("safesc").setLevel(level)  # our own logs at the chosen verbosity


def _make_console_utf8_safe() -> None:
    """Ensure report summaries (which contain non-ASCII markers such as ``⚠``) never crash
    the process on a non-UTF-8 console (e.g. Windows' cp936/GBK CI runners). Report *files*
    are already written UTF-8; this only hardens the stdout/stderr stream printing."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:  # pragma: no cover - platform/stream dependent
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv=None) -> int:
    """Console-script entry point for ``safesc`` (audit | query | gc).

    Builds the store-free runtime and delegates to the injectable ``cli.main``. Missing
    optional dependencies (LangGraph, or the chosen provider SDK) are reported with an
    actionable message rather than a raw traceback.
    """
    _make_console_utf8_safe()
    _configure_logging()

    # Imported here rather than at module scope: `llm_client` pulls in the specialist
    # surface, which may transitively require the `agent` extra. Guarding it keeps the
    # friendly install hint working when that extra is absent.
    try:
        from safesc.graph.llm_client import MissingProviderSDKError
    except ModuleNotFoundError as exc:
        top = exc.name.split(".")[0] if exc.name else ""
        if top in _OPTIONAL_MODULE_EXTRAS:
            _explain_missing_extra(top)
            return 2
        raise

    try:
        tools, session, memory = build_local_runtime()
    except ModuleNotFoundError as exc:  # pragma: no cover - defensive
        if exc.name and exc.name.split(".")[0] in _OPTIONAL_MODULE_EXTRAS:
            _explain_missing_extra(exc.name.split(".")[0])
            return 2
        raise

    try:
        return cli_main(argv, tools=tools, session=session, memory=memory)
    except MissingProviderSDKError as exc:
        # Raised by make_llm before the graph starts, so it reaches us instead of being
        # swallowed as a degraded specialist node (see llm_client.MissingProviderSDKError).
        print(f"safesc: {exc}", file=sys.stderr)
        return 2
    except ModuleNotFoundError as exc:
        top = exc.name.split(".")[0] if exc.name else ""
        if top in _OPTIONAL_MODULE_EXTRAS:
            _explain_missing_extra(top)
            return 2
        raise


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())