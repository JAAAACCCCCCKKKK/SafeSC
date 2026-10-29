"""agents/harness/progress.py — what the user sees while agents work (lesson 4).

Every agent runs with ``callback_handler=None`` (silent — no streamed model text reaches
the terminal), and this hook prints one line per tool call instead, prefixed with the
agent that made it. Output goes to stderr so stdout stays clean for reports.
"""

from __future__ import annotations

import sys
import threading
from typing import TextIO

from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry


class Progress:
    def __init__(self, enabled: bool = False, stream: TextIO | None = None):
        self.enabled = enabled
        self.stream = stream
        self._lock = threading.Lock()

    def say(self, message: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            print(f"[safesc] {message}", file=self.stream or sys.stderr, flush=True)


class ProgressHook(HookProvider):
    def __init__(self, progress: Progress, agent_name: str):
        self.progress = progress
        self.agent_name = agent_name

    def register_hooks(self, registry: HookRegistry, **_kwargs) -> None:
        registry.add_callback(BeforeToolCallEvent, self._before_tool)

    def _before_tool(self, event: BeforeToolCallEvent) -> None:
        tool_input = event.tool_use.get("input") or {}
        target = tool_input.get("dep_key") if isinstance(tool_input, dict) else None
        suffix = f"({target})" if target else ""
        self.progress.say(f"{self.agent_name} -> {event.tool_use.get('name')}{suffix}")
