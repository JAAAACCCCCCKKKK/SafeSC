"""graph/build.py — assembles the graph and exposes `run()`, the one seam the CLI
entrypoint calls (§6.1.4: the graph is the core; entrypoints are thin).

Composes the harness per §2.7: specialist nodes are auto_repaired_node(outer) around a
constraint-validated(inner) LLM call; spine tools are with_retry-wrapped. BYOK creds
(§3.5) become injected specialist deps here and never enter `AuditState`.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from safesc.security.credentials import UserCredentials
from safesc.graph.harness.auto_repair import RetryPolicy, auto_repaired_node, with_retry
from safesc.graph.harness.constraint_validator import ConstraintValidator
from safesc.graph.report_agent import ScoreConfig, add_report
from safesc.graph.router import AuditRequest, route_condition, router_node
from safesc.graph.single_pkg import NODE_RESOLVE_SINGLE, resolve_single_package
from safesc.graph.specialists import SPECIALIST_MODULES
from safesc.graph.spine import (
    GateConfig,
    InjectedTools,
    NODE_CHEAP_SIGNALS,
    NODE_GATE,
    NODE_HASH_VERIFY,
    NODE_INDEX,
    NODE_REPORT,
    SPECIALIST_NODE,
    cheap_signals_node,
    gate_edge,
    gate_node,
    hash_verify_node,
    index_node,
)
from safesc.graph.state import AuditState, GateDecision, RunMode

logger = logging.getLogger("safesc.build")


def retrying_tools(tools: InjectedTools, policy: RetryPolicy = RetryPolicy()) -> InjectedTools:
    """Wrap each Stage 0–3 tool callable with transient-fault retry (§2.7.2)."""
    return InjectedTools(
        discover=with_retry(tools.discover, policy=policy),
        parse=with_retry(tools.parse, policy=policy),
        verify_hash=with_retry(tools.verify_hash, policy=policy),
        collect_signals=with_retry(tools.collect_signals, policy=policy),
    )


@dataclass
class RunConfig:
    llm_call_cap: int = 200
    gate: GateConfig = field(default_factory=GateConfig)
    score: ScoreConfig = field(default_factory=ScoreConfig)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    max_repairs: int = 2


@dataclass
class RunResult:
    run_id: str
    gate_decision: GateDecision
    exit_code: int
    degraded: list
    incomplete: bool
    final_state: object = None  # the run's final AuditState (or dict); feeds the reporter

    @property
    def passed(self) -> bool:
        return self.gate_decision.passed


def build_graph(*, specialist_deps, tools: InjectedTools, config: RunConfig, memory=None, checkpointer=None):
    """Assemble and compile the LangGraph. LangGraph is imported here (not at module
    load) so the rest of the package stays importable/testable without it."""
    from langgraph.graph import END, START, StateGraph

    tools = retrying_tools(tools, config.retry)
    builder = StateGraph(AuditState)

    # entry router (scope only, §2.2-A): route_condition returns the entry node name
    builder.add_node("router", router_node)
    builder.add_edge(START, "router")
    builder.add_conditional_edges("router", route_condition, [NODE_RESOLVE_SINGLE, NODE_INDEX])

    # single-package entry rejoins the shared spine at hash_verify
    builder.add_node(NODE_RESOLVE_SINGLE, resolve_single_package)
    builder.add_edge(NODE_RESOLVE_SINGLE, NODE_HASH_VERIFY)

    # deterministic spine (fixed sequence)
    builder.add_node(NODE_INDEX, functools.partial(index_node, tools=tools))
    builder.add_node(NODE_HASH_VERIFY, functools.partial(hash_verify_node, tools=tools))
    builder.add_node(NODE_CHEAP_SIGNALS, functools.partial(cheap_signals_node, tools=tools))
    builder.add_node(NODE_GATE, functools.partial(gate_node, config=config.gate))
    builder.add_edge(NODE_INDEX, NODE_HASH_VERIFY)
    builder.add_edge(NODE_HASH_VERIFY, NODE_CHEAP_SIGNALS)
    builder.add_edge(NODE_CHEAP_SIGNALS, NODE_GATE)
    builder.add_conditional_edges(
        NODE_GATE, functools.partial(gate_edge, config=config.gate),
        [*SPECIALIST_NODE.values(), NODE_REPORT],
    )

    # Stage-4 specialists: auto_repair(outer) around the constraint-validated(inner) node
    for dimension, module in SPECIALIST_MODULES.items():
        node_name = SPECIALIST_NODE[dimension]
        raw = module.build_node(specialist_deps)
        builder.add_node(node_name, auto_repaired_node(raw, node_name=node_name, policy=config.retry))
        builder.add_edge(node_name, NODE_REPORT)

    # scorer / sole gate writer + single memory write point (§2.4, §2.7.4)
    add_report(builder, config=config.score, memory=memory)
    builder.add_edge(NODE_REPORT, END)

    return builder.compile(checkpointer=checkpointer)


def run(
    request: AuditRequest,
    *,
    credentials: UserCredentials,
    tools: InjectedTools,
    session,
    memory=None,
    config: Optional[RunConfig] = None,
    checkpointer=None,
    graph_factory: Callable = build_graph,
) -> RunResult:
    """The single entrypoint seam: build BYOK deps, assemble the graph, run it, shape a
    RunResult. Credentials become injected deps here and are NEVER written into
    `AuditState` (which is checkpointed) — see §3.5 invariant #2."""
    from safesc.graph.llm_client import build_specialist_deps  # lazy: needs the anthropic seam

    config = config or RunConfig()
    run_id = session.new_run()

    # memory read seam (prompt-only prior findings); resolve dep_key → (artifact_id, query).
    # A deployment supplies a richer resolver (hash + static-signal summary).
    memory_lookup = memory.make_lookup(lambda dk: (dk, dk)) if memory is not None else None

    specialist_deps = build_specialist_deps(
        credentials,
        memory_lookup=memory_lookup,
        validator=ConstraintValidator(max_repairs=config.max_repairs),
    )

    graph = graph_factory(
        specialist_deps=specialist_deps, tools=tools, config=config,
        memory=memory, checkpointer=checkpointer,
    )

    # initial state carries NO credentials (§3.5) — only routing inputs + the cap
    initial = AuditState(
        mode=request.mode,
        target=request.target,
        ecosystem=getattr(request, "ecosystem", None),
        llm_call_cap=config.llm_call_cap,
    )
    final = graph.invoke(initial, {"configurable": {"thread_id": run_id, "run_id": run_id}})

    return _shape_result(run_id, request.mode, final, config)


def _shape_result(run_id: str, mode: RunMode, final, config: RunConfig) -> RunResult:
    """Normalise LangGraph's final state (dict or AuditState) into a RunResult."""
    gd = final.get("gate_decision") if isinstance(final, dict) else getattr(final, "gate_decision", None)
    degraded = final.get("degraded_notes", []) if isinstance(final, dict) else getattr(final, "degraded_notes", [])
    if gd is None:  # defensive: a run that never reached the scorer
        gd = GateDecision(summary="no gate decision produced", passed=False, exit_code=1)
    incomplete = "INCOMPLETE" in (gd.summary or "")
    exit_code = 0 if mode == RunMode.QUERY else gd.exit_code  # query never fails on severity (§1.3)
    return RunResult(
        run_id=run_id, gate_decision=gd, exit_code=exit_code, degraded=list(degraded),
        incomplete=incomplete, final_state=final,
    )
