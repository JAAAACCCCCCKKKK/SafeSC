"""entrypoints/bootstrap.py — production wiring for the ``safesc`` console script.

This is the concrete wiring that ``entrypoints/cli.py``'s injectable ``main()`` was
designed to receive. It selects between **two deployment tiers** (§3.6) purely from the
caller's environment, so the same console script serves a laptop and a fleet:

**Tier 2 — store-free (the default).** The deterministic Stage 0–3 spine plus the Stage-4
LLM specialists, with no Redis, no Postgres and no checkpointer. A single finite CI audit
needs none of them. The only requirement is a caller-supplied reasoning-LLM key
(``SAFESC_LLM_API_KEY``, BYOK — §3.5).

**Tier 3 — store-backed.** Adds whatever the environment configures:

* ``SAFESC_REDIS_URL`` → the §3.1 short-term store, which brings three things at once: a
  LangGraph checkpointer (so ``--resume`` can reattach), the §2.7.3/§5.2 distributed
  semaphores, and the cross-run cheap-signal cache;
* ``SAFESC_PGVECTOR_DSN`` (+ ``SAFESC_EMBEDDING_API_KEY``) → the §3.2 long-term store, so
  behaviourally *similar* prior findings and the known-attack fingerprint corpus ground
  Stage-4 reasoning.

Half-configured is a legitimate deployment, and Redis alone is the common one: it gives
checkpointing, rate limiting, signal reuse **and** exact-hash verdict recall across runs —
everything except similarity search — with no embedding provider and no second API key.

**Store failure degrades rather than fails.** A configured-but-unreachable store falls the
runtime back a tier with a warning, because everything the stores provide can only
*escalate* a verdict (§3.3) — running without them loses efficiency and grounding, never
correctness. ``SAFESC_MEMORY_STRICT=1`` turns that fallback into a hard error, for
deployments where a silently store-free audit would itself be the incident.

``cli.py`` stays thin and testable (its ``main()`` takes injected deps); this module owns
the concrete construction so importing the library surface stays side-effect-free.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Optional, Sequence

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


class MemoryUnavailableError(RuntimeError):
    """A store was configured but could not be reached, under SAFESC_MEMORY_STRICT."""


@dataclass
class Runtime:
    """Everything ``cli.main()`` needs, plus which tier produced it (for diagnostics)."""

    tools: Any
    session: Any
    memory: Any = None
    checkpointer: Any = None
    tier: str = "local"


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def build_local_runtime(*, exclude: Sequence[str] = ()):
    """Wire the four Stage 0–3 seams to the real frozen tools (§6.1.5).

    Returns the ``(tools, session, memory)`` triple that ``cli.main()`` expects. ``memory``
    is ``None`` — this is the store-free tier-2 path. `exclude` (gitignore-syntax
    patterns, e.g. from ``--exclude``) is baked into the discovery seam at construction
    time — see `graph.spine.load_default_tools`.
    """
    from safesc.graph.spine import load_default_tools

    return load_default_tools(exclude=exclude), LocalSession(), None


def build_store_backed_runtime(
    *,
    redis_url: Optional[str],
    dsn: Optional[str],
    exclude: Sequence[str] = (),
) -> Runtime:
    """Construct the tier-3 runtime from the configured stores (§3.6).

    Each store is optional and independent. Redis failing to answer a ``ping`` is raised
    rather than swallowed here — the caller (``select_runtime``) owns the strict-vs-degrade
    policy, so this function stays a straightforward constructor.
    """
    from safesc.graph.harness.memory_manager import MemoryManager
    from safesc.graph.harness.session_manager import SessionManager
    from safesc.graph.spine import load_default_tools

    store = None
    session: Any = LocalSession()
    checkpointer = None
    vector = None
    embedder = None
    host_gate = None
    tier = "local"

    if redis_url:
        from safesc.memory.short_term import RedisConfig, ShortTermStore

        store = ShortTermStore.from_url(
            RedisConfig(url=redis_url, hot_ttl_s=_int_env("SAFESC_HOT_TTL_S", 7 * 24 * 3600))
        )
        if not store.ping():
            raise MemoryUnavailableError(f"redis at {redis_url} did not respond to PING")
        session = SessionManager(store)
        # Fleet-wide per-registry limiting (§5.2). Shares one budget per host across every
        # concurrently running audit, unlike the in-process per_host semaphore.
        host_gate = session.host_gate(_int_env("SAFESC_HOST_CONCURRENCY", 10))
        # Checkpointing is best-effort: it needs the langgraph-checkpoint-redis extra, and
        # a deployment may well want Redis purely for caching and rate limiting.
        try:
            checkpointer = store.checkpointer()
        except Exception as exc:
            print(f"safesc: checkpointing unavailable ({exc}); --resume will not work", file=sys.stderr)
        tier = "redis"

    if dsn:
        from safesc.memory.embedding_client import make_embedding_client
        from safesc.memory.long_term import PGVectorConfig, PGVectorStore
        from safesc.security.credentials import EmbeddingCredentials

        vector = PGVectorStore.from_dsn(
            PGVectorConfig(
                dsn=dsn,
                embedding_dim=_int_env("SAFESC_EMBEDDING_DIM", PGVectorConfig().embedding_dim),
            )
        )
        embedder = make_embedding_client(EmbeddingCredentials.from_env())
        tier = "redis+pgvector" if store is not None else "pgvector"

    # A MemoryManager as soon as EITHER store exists — not only with pgvector. Redis alone
    # supports the whole exact-hash path (`read_context` returns the exact record and skips
    # similarity when there is no vector/embedder; `persist` writes the hot record and skips
    # the vector upsert), so a Redis-only deployment gets cross-run verdict recall for free,
    # with no embedding provider and no second API key. Only the *similarity* half — and the
    # fingerprint corpus that rides on it (§3.2) — actually needs pgvector.
    memory = (
        MemoryManager(redis=store, vector=vector, embedder=embedder)
        if (store is not None or vector is not None)
        else None
    )

    # The short-term store doubles as the cross-run cheap-signal cache (§3.1); both it and
    # the host gate are baked into the tool seams at construction time, so nothing
    # downstream has to know whether a store exists.
    tools = load_default_tools(exclude=exclude, cache=store, host_gate=host_gate)
    return Runtime(tools=tools, session=session, memory=memory, checkpointer=checkpointer, tier=tier)


def select_runtime(*, exclude: Sequence[str] = ()) -> Runtime:
    """Pick the tier the environment asks for, degrading if a configured store is down."""
    redis_url = os.environ.get("SAFESC_REDIS_URL") or None
    dsn = os.environ.get("SAFESC_PGVECTOR_DSN") or None

    if not redis_url and not dsn:
        tools, session, memory = build_local_runtime(exclude=exclude)
        return Runtime(tools=tools, session=session, memory=memory, tier="local")

    try:
        return build_store_backed_runtime(redis_url=redis_url, dsn=dsn, exclude=exclude)
    except Exception as exc:
        if _flag("SAFESC_MEMORY_STRICT"):
            raise MemoryUnavailableError(
                f"memory layer configured but unavailable ({exc}); "
                f"SAFESC_MEMORY_STRICT is set, refusing to run store-free"
            ) from exc
        print(
            f"safesc: memory layer unavailable ({exc}); continuing store-free. "
            f"Analysis is unaffected — memory can only escalate a verdict, never lower one "
            f"(§3.3) — but caching, rate limiting and prior-finding grounding are off. "
            f"Set SAFESC_MEMORY_STRICT=1 to make this fatal instead.",
            file=sys.stderr,
        )
        tools, session, memory = build_local_runtime(exclude=exclude)
        return Runtime(tools=tools, session=session, memory=memory, tier="local")


def _preparse_exclude(argv: Sequence[str]) -> list[str]:
    """Pull `--exclude PATTERN` occurrences out of argv *before* `cli_main`'s full parse.

    Needed because `tools` (which bakes exclude patterns into the discovery closure, see
    `build_local_runtime`) must be constructed before `cli_main` runs its own
    `parse_args` — so this repo's tool construction can't simply wait for that later,
    stricter parse. `parse_known_args` on a minimal, `add_help=False` parser ignores
    every other flag/subcommand (`audit`/`query`/`gc`, `--report-dir`, ...) rather than
    erroring on them; `cli_main`'s parser separately declares `--exclude` too, purely so
    `--help` documents it and its own `parse_args` doesn't reject the (harmless, already
    consumed) flag as unrecognised.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--exclude", action="append", default=None)
    ns, _unknown = parser.parse_known_args(list(argv))
    return ns.exclude or []


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

    Selects the tier the environment configures (§3.6) and delegates to the injectable
    ``cli.main``. Missing optional dependencies (LangGraph, or the chosen provider SDK) are
    reported with an actionable message rather than a raw traceback.
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

    # tools must be built (with --exclude baked into the discovery closure, if given)
    # before cli_main's own parse_args runs — see _preparse_exclude's docstring.
    resolved_argv = argv if argv is not None else sys.argv[1:]
    exclude = _preparse_exclude(resolved_argv)

    try:
        runtime = select_runtime(exclude=exclude)
    except MemoryUnavailableError as exc:
        print(f"safesc: {exc}", file=sys.stderr)
        return 2
    except ModuleNotFoundError as exc:  # pragma: no cover - defensive
        if exc.name and exc.name.split(".")[0] in _OPTIONAL_MODULE_EXTRAS:
            _explain_missing_extra(exc.name.split(".")[0])
            return 2
        raise
    logging.getLogger("safesc").info("runtime tier: %s", runtime.tier)

    try:
        return cli_main(
            argv, tools=runtime.tools, session=runtime.session, memory=runtime.memory,
            checkpointer=runtime.checkpointer,
        )
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