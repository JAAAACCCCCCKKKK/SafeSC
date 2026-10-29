"""agents/context.py — everything one run's agents and tools share, built once per run.

Tools are closures over an `AgentContext`, so no tool reaches for global state and every
test can swap a seam (the static backend, the model factory, the downloader) without
monkeypatching. Credentials live only in `llm` and are never copied into the ledger (§3.5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from safesc.agents.harness.progress import Progress
from safesc.agents.tools.pipeline import StaticBackend
from safesc.config.llm import LLMConfig
from safesc.core.ledger import RunLedger
from safesc.memory.manager import SafeSCMemory


@dataclass
class AgentContext:
    ledger: RunLedger
    llm: LLMConfig
    memory: SafeSCMemory
    backend: StaticBackend = field(default_factory=StaticBackend)
    progress: Progress = field(default_factory=Progress)
    model_factory: Optional[Callable[[], Any]] = None
    external_tools: list = field(default_factory=list)   # web_fetch + MCP tools (subagents)
    downloader: Optional[Callable[[str, Path], bool]] = None
    registry_lookup: Optional[Callable[[str, str, str], Optional[dict]]] = None
    workspace_base: Optional[Path] = None
    max_repairs: int = 2

    def new_model(self):
        """A fresh model client per agent, so concurrent subagents never share one."""
        return self.model_factory() if self.model_factory is not None else self.llm.build_model()
