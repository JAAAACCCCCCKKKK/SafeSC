"""agents/tools/external.py — vended and MCP tools that reach beyond SafeSC (lesson 3).

* **web_fetch** (Strands-vended, agentic mode): subagents read advisories, issue threads
  and repository pages. In agentic mode a separate analyst agent reads the page and answers
  a question about it, so raw page content — attacker-controllable for a malicious package
  — never lands in the subagent's own context.
* **GitHub MCP server** (``--with github``, needs ``GITHUB_TOKEN``): commit history,
  contributors, releases and code search for authorship and provenance questions. Filtered
  to read-only tools by allow-list, so a prompt-injected subagent cannot open issues,
  push, or merge.
* **Custom MCP servers** (``--mcp URL``, repeatable): your own read-only intel sources.

The shell and python-repl vended tools are deliberately **never** given to any agent:
SafeSC analyses untrusted code, and a tool that executes commands would turn a prompt
injection in that code into code execution on the auditor's machine.

An MCP server that fails to start is a warning, not an error: these tools enrich analysis,
and the static pipeline plus the evidence tools still cover every required check.
"""

from __future__ import annotations

import logging
import os
from contextlib import ExitStack
from typing import Sequence

logger = logging.getLogger("safesc.tools.external")

GITHUB_MCP_URL = "https://api.githubcopilot.com/mcp/"
# Read-only GitHub MCP tools that matter for authorship/provenance. Allow-listed so a newly
# added write tool on the server can never appear here by default.
GITHUB_READONLY_TOOLS = [
    "get_commit", "list_commits", "get_file_contents", "search_code", "search_repositories",
    "list_tags", "get_tag", "list_releases", "get_latest_release", "get_release_by_tag",
    "list_branches", "search_users", "get_me",
]


def web_tools(model=None) -> list:
    from strands.vended_tools.web_fetch import make_web_fetch

    return [make_web_fetch(mode="agentic", model=model, max_content_chars=40_000)]


def open_mcp_tools(stack: ExitStack, *, github: bool, extra_urls: Sequence[str] = (), warn=print) -> list:
    """Start the requested MCP clients inside `stack` and return their tools. Each client
    stays open until the stack closes at the end of the run."""
    from strands.tools.mcp import MCPClient

    specs: list[tuple[str, dict]] = []
    if github:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            warn("--with github needs GITHUB_TOKEN (or GH_TOKEN); continuing without the GitHub MCP server.")
        else:
            specs.append(("github", {
                "url": GITHUB_MCP_URL,
                "headers": {"Authorization": f"Bearer {token}", "X-MCP-Readonly": "true"},
                "tool_filters": {"allowed": GITHUB_READONLY_TOOLS},
                "prefix": "github",
            }))
    for i, url in enumerate(extra_urls, start=1):
        specs.append((f"mcp{i}", {"url": url, "prefix": f"mcp{i}"}))

    tools: list = []
    for label, kwargs in specs:
        client = MCPClient(startup_timeout=20, application_name="safesc", **kwargs)
        try:
            stack.enter_context(client)
            found = client.list_tools_sync()
        except Exception as exc:
            warn(f"MCP server '{label}' unavailable ({type(exc).__name__}: {exc}); continuing without it.")
            continue
        logger.info("MCP server %s: %d tool(s)", label, len(found))
        tools.extend(found)
    return tools
