"""Shared test helpers: a scripted Strands model, ledger/dependency factories, fake backends.

`ScriptedModel` lets a test drive a real Strands `Agent` deterministically and offline: it
answers each model call by popping the next scripted step — a tool call or a text reply —
so the real tool registry, steering, hooks, structured output and GoalLoop all run.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Union

from pydantic import SecretStr
from strands.models.model import Model

from safesc.config.llm import LLMConfig
from safesc.core.ledger import LockfileRef, RunLedger, RunOptions
from safesc.core.signals import Severity, Signal, SignalOrigin, TrustDimension, dep_key
from safesc.tools.index.core.models import Dependency

Step = Union[tuple, Callable[[list, list], tuple]]


class ScriptedModel(Model):
    """Steps are ``("tool", name, input)`` / ``("tools", [(name, input), ...])`` /
    ``("text", str)``, or a callable ``(messages, tool_names) -> step`` for steps that
    depend on what the agent has seen. When the script runs out it replies "done"."""

    def __init__(self, steps: Iterable[Step] = (), *, default: Optional[Step] = None):
        self.steps = list(steps)
        self.default = default
        self.config: dict = {}
        self.calls: list[dict] = []
        self._lock = threading.Lock()
        self._n = 0

    def update_config(self, **kw: Any) -> None:
        self.config.update(kw)

    def get_config(self) -> dict:
        return self.config

    async def structured_output(self, output_model, prompt, system_prompt=None, **kw):  # pragma: no cover
        raise NotImplementedError
        yield

    def _next(self, messages, tool_names):
        with self._lock:
            step = self.steps.pop(0) if self.steps else (self.default or ("text", "done"))
            self._n += 1
            n = self._n
        if callable(step):
            step = step(messages, tool_names)
        return step, n

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kw):
        names = [s["name"] for s in (tool_specs or [])]
        step, n = self._next(messages, names)
        self.calls.append({"system": system_prompt, "tools": names, "messages": messages})
        yield {"messageStart": {"role": "assistant"}}
        if step[0] in ("tool", "tools"):
            calls = [(step[1], step[2])] if step[0] == "tool" else step[1]
            for i, (name, inp) in enumerate(calls):
                yield {"contentBlockStart": {"start": {"toolUse": {"toolUseId": f"tu{n}-{i}", "name": name}}}}
                yield {"contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps(inp)}}}}
                yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use"}}
        else:
            yield {"contentBlockDelta": {"delta": {"text": step[1]}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "end_turn"}}


def tool_results(messages: list) -> list[str]:
    """Every toolResult text in a transcript, in order."""
    out = []
    for m in messages:
        for block in m.get("content", []):
            if "toolResult" in block:
                for c in block["toolResult"].get("content", []):
                    if "text" in c:
                        out.append(c["text"])
    return out


def fake_llm() -> LLMConfig:
    return LLMConfig(provider="anthropic", model="claude-test", api_key=SecretStr("sk-test"))


def dep(name="pkg", version="1.0.0", ecosystem="javascript", *, direct=True, **kw) -> Dependency:
    return Dependency(
        name=name, version=version, ecosystem=ecosystem, lockfile_path=Path(kw.pop("lockfile", "package-lock.json")),
        is_direct=direct, layer_number=1 if direct else 2, **kw,
    )


def sig(d, dimension, severity, *, origin=SignalOrigin.STATIC, source="test.signal", **kw) -> Signal:
    return Signal(dep_key=dep_key(d), dimension=dimension, origin=origin, source=source, severity=severity, **kw)


def ledger(target=".", deps=(), signals=(), **opts) -> RunLedger:
    led = RunLedger("RUNID", RunOptions(target=target, **opts))
    led.set_dependencies(deps)
    led.add_signals(signals)
    return led


def backend(deps: list[Dependency], *, verify: list[Signal] = (), collect: list[Signal] = (), notes: list[str] = ()):
    """A StaticBackend whose four stages return canned results."""
    from safesc.agents.tools.pipeline import StaticBackend

    async def _verify(_deps):
        return list(verify)

    async def _collect(_deps):
        return list(collect), list(notes)

    lockfiles = sorted({(str(d.lockfile_path), d.ecosystem) for d in deps})
    return StaticBackend(
        discover=lambda target, exclude: [LockfileRef(path=p, ecosystem=e) for p, e in lockfiles],
        parse=lambda lockfiles: list(deps),
        verify=_verify,
        collect=_collect,
    )


__all__ = [
    "ScriptedModel", "Severity", "TrustDimension", "SignalOrigin", "backend", "dep", "fake_llm",
    "ledger", "sig", "tool_results",
]
