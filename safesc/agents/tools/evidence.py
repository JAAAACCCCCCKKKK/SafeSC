"""agents/tools/evidence.py — Stage-4 evidence tools for subagents. Deterministic, LLM-free.

Each tool wraps a primitive from `safesc/tools/` (deep_analysis_tool, source, vulnscan,
authorship), returns a bounded rendering for the model, and registers what it showed as
citable for that dependency. None of them executes dependency code; none returns a verdict.

`read_source` is SafeSC's instance of the Strands-vended `file_editor`, and
`ReadOnlySourceGuard` (a hook, lesson 5) confines it: only the `view` command, and only
inside a source workspace this run fetched. Anything else is cancelled before it runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from strands import tool
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry

from safesc.agents.tools.inspection import unknown_dep

if TYPE_CHECKING:
    from safesc.agents.context import AgentContext

READ_SOURCE_TOOL = "read_source"
MAX_TOOL_CHARS = 12_000


def _bounded(text: str, limit: int = MAX_TOOL_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n… [truncated {len(text) - limit} chars]"


def _fmt_items(label: str, items) -> str:
    items = list(items or [])
    if not items:
        return f"{label}: (none found)"
    lines = [f"{label} ({len(items)}):"]
    for it in items[:20]:
        meta = f" meta={json.dumps(it.metadata, default=str)}" if it.metadata else ""
        excerpt = (it.excerpt or "").strip()
        if len(excerpt) > 1200:
            excerpt = excerpt[:1200] + " …[truncated]"
        lines.append(f"  - [{it.kind}] {it.path or '-'}{meta}\n    {excerpt}")
    return "\n".join(lines)


class ReadOnlySourceGuard(HookProvider):
    """Cancel any `read_source` call that is not a `view` inside a fetched workspace."""

    def __init__(self, ctx: "AgentContext"):
        self.ctx = ctx

    def register_hooks(self, registry: HookRegistry, **_kwargs) -> None:
        registry.add_callback(BeforeToolCallEvent, self._check)

    def _check(self, event: BeforeToolCallEvent) -> None:
        if event.tool_use.get("name") != READ_SOURCE_TOOL:
            return
        args = event.tool_use.get("input") or {}
        if args.get("command") != "view":
            event.cancel_tool = "read_source is read-only: only the 'view' command is permitted."
            return
        try:
            target = Path(str(args.get("path", ""))).resolve()
        except (OSError, ValueError):
            event.cancel_tool = "read_source: invalid path."
            return
        roots = [p.resolve() for p in self.ctx.ledger.workspaces.values()]
        if not any(target == r or r in target.parents for r in roots):
            event.cancel_tool = (
                "read_source may only view files inside a dependency workspace returned by "
                "fetch_dependency_source (use the absolute path it printed)."
            )


def build_evidence_tools(ctx: "AgentContext") -> list:
    from strands.vended_tools.file_editor import make_file_editor

    from safesc.tools.deep_analysis_tool import (
        DeepAnalysisRequest,
        gather_deep_analysis_evidence,
    )
    from safesc.tools.source import clone_history, fetch_source, http_download, workspace_base

    ledger = ctx.ledger

    def _request(dep):
        eco = dep.ecosystem if dep.ecosystem in ("python", "javascript", "rust", "go", "java") else None
        if eco is None:
            return None
        return DeepAnalysisRequest.from_dependency(dep)

    def _workspace(key: str):
        dep = ledger.get_dependency(key)
        if dep is None:
            return None, unknown_dep(key)
        root = ledger.workspaces.get(key)
        if root is not None and root.is_dir():
            return root, None
        ws = fetch_source(
            dep, base_dir=ctx.workspace_base or workspace_base(),
            downloader=ctx.downloader, registry_lookup=ctx.registry_lookup,
        )
        if ws is None:
            return None, "Source unavailable: no downloadable artifact and no clonable repository."
        ledger.set_workspace(key, ws.root)
        return ws.root, None

    @tool
    def inspect_install_scripts(dep_key: str) -> str:
        """Install-time execution points (setup.py, npm lifecycle hooks and the scripts they
        run, build.rs) and obfuscation candidates (high-entropy blobs, eval-of-encoded,
        minified files) from the dependency's source repository. Read-only; nothing runs.

        Args:
            dep_key: ecosystem:name@version.
        """
        dep = ledger.get_dependency(dep_key)
        if dep is None:
            return unknown_dep(dep_key)
        req = _request(dep)
        if req is None:
            return "Unsupported ecosystem for source inspection."
        ev = gather_deep_analysis_evidence(req, dimensions=("behavior",), registry_lookup=ctx.registry_lookup)
        items = ev.behavior.install_scripts + ev.behavior.obfuscation_candidates
        ledger.register_citable(dep_key, [i.path for i in items if i.path])
        return _bounded("\n\n".join([
            f"[evidence status: {ev.status}{'; ' + '; '.join(ev.degraded_reasons) if ev.degraded_reasons else ''}]",
            _fmt_items("Install scripts", ev.behavior.install_scripts),
            _fmt_items("Obfuscation candidates", ev.behavior.obfuscation_candidates),
        ]))

    @tool
    def inspect_docs(dep_key: str, nearest_popular: str = "") -> str:
        """README / SECURITY / CONTRIBUTING text (for coercive or impersonating
        instructions) plus registry provenance (publisher, canonical repo, release history).

        Args:
            dep_key: ecosystem:name@version.
            nearest_popular: optional popular package this name resembles (typosquat checks).
        """
        dep = ledger.get_dependency(dep_key)
        if dep is None:
            return unknown_dep(dep_key)
        req = _request(dep)
        if req is None:
            return "Unsupported ecosystem for source inspection."
        ev = gather_deep_analysis_evidence(
            req, dimensions=("identity",), nearest_popular=nearest_popular or None,
            registry_lookup=ctx.registry_lookup,
        )
        reg = ev.identity.registry
        facts = {
            k: getattr(reg, k) for k in ("author", "repo_url", "homepage", "summary", "total_releases",
                                         "first_release_at", "latest_release_at")
        } if reg.resolved else {}
        ledger.register_citable(dep_key, [d.path for d in ev.identity.docs if d.path])
        ledger.register_citable(dep_key, [str(v) for v in facts.values() if v])
        return _bounded("\n\n".join([
            f"[evidence status: {ev.status}]",
            "Registry provenance: " + (json.dumps(facts, default=str) if facts else "(unavailable)"),
            _fmt_items("Docs", ev.identity.docs),
        ]))

    @tool
    def compare_artifact_to_source(dep_key: str) -> str:
        """Content present in the PUBLISHED artifact but not traceable to the source
        repository (the XZ-Utils / injected-build pattern), plus the most recent commits.

        Args:
            dep_key: ecosystem:name@version.
        """
        dep = ledger.get_dependency(dep_key)
        if dep is None:
            return unknown_dep(dep_key)
        req = _request(dep)
        if req is None:
            return "Unsupported ecosystem for source inspection."
        from safesc.tools.source import artifact_url_candidates

        urls = artifact_url_candidates(dep)
        if urls and not req.artifact_url:
            req = req.model_copy(update={"artifact_url": urls[0]})
        ev = gather_deep_analysis_evidence(
            req, dimensions=("provenance",), artifact_download=ctx.downloader or http_download,
            registry_lookup=ctx.registry_lookup,
        )
        items = ev.provenance.artifact_only_files
        ledger.register_citable(dep_key, [i.path for i in items if i.path])
        ledger.register_citable(dep_key, [c.metadata.get("sha", "") for c in ev.provenance.recent_commits])
        return _bounded("\n\n".join([
            f"[evidence status: {ev.status}{'; ' + '; '.join(ev.degraded_reasons) if ev.degraded_reasons else ''}]",
            _fmt_items("Artifact-only content (not traceable to source)", items),
            _fmt_items("Recent commits", ev.provenance.recent_commits),
        ]))

    @tool
    def fetch_dependency_source(dep_key: str) -> str:
        """Download and safely extract the dependency's published source (or clone its
        repository) into a read-only workspace. Returns the absolute workspace path for
        read_source, plus a file overview. Required before search/scan tools.

        Args:
            dep_key: ecosystem:name@version.
        """
        root, err = _workspace(dep_key)
        if err:
            return err
        from safesc.tools.vulnscan import iter_source_files

        langs: dict[str, int] = {}
        for _path, lang in iter_source_files(root):
            langs[lang] = langs.get(lang, 0) + 1
        top = sorted(p.name + ("/" if p.is_dir() else "") for p in root.iterdir())[:40]
        return (
            f"Workspace (absolute path, read-only): {root}\n"
            f"Source files by language: {json.dumps(langs)}\n"
            f"Top level: {', '.join(top)}\n"
            f"View files with read_source(command='view', path='{root}/<relative path>')."
        )

    @tool
    def search_source(dep_key: str, text: str) -> str:
        """Literal (case-insensitive) text search across the dependency's fetched source.
        Not a regex. Returns file:line hits.

        Args:
            dep_key: ecosystem:name@version.
            text: the literal text to find (max 200 chars).
        """
        root, err = _workspace(dep_key)
        if err:
            return err
        from safesc.tools.vulnscan import search_tree

        hits = search_tree(root, text)
        if not hits:
            return f"No occurrences of {text!r}."
        return _bounded("\n".join(f"{h['file']}:{h['line']}: {h['text']}" for h in hits))

    @tool
    def scan_source_for_risky_patterns(dep_key: str) -> str:
        """Deterministic scan of the dependency's source for hidden-risk patterns: unsafe C
        functions (strcpy, gets, sprintf…), injection sinks, unsafe deserialization,
        confidential inputs hashed/compared/logged unsafely, disabled TLS verification,
        predictable randomness for secrets, hard-coded secrets and imports of modules with
        published security problems. Hits are LEADS for triage, not findings.

        Args:
            dep_key: ecosystem:name@version.
        """
        root, err = _workspace(dep_key)
        if err:
            return err
        from safesc.tools.vulnscan import scan_tree

        report = scan_tree(root).as_dict()
        return _bounded(json.dumps(report, indent=1))

    @tool
    async def check_declared_dependencies(dep_key: str) -> str:
        """What this dependency itself depends on (from its own manifest), each checked
        against curated lists of unsafe/abandoned modules and against OSV advisories
        (exact pins are checked at that version; ranges report the package's advisory history,
        including MAL- malicious-package reports).

        Args:
            dep_key: ecosystem:name@version.
        """
        import asyncio

        root, err = await asyncio.to_thread(_workspace, dep_key)
        if err:
            return err
        dep = ledger.get_dependency(dep_key)
        from safesc.tools.scan.signals.provenance.http import RateLimitedSession
        from safesc.tools.vulnscan import UNSAFE_IMPORTS, declared_dependencies, exact_pin

        declared = declared_dependencies(root, dep.ecosystem)
        if not declared:
            return "No declared dependencies found in the package manifest."
        osv_eco = {"python": "PyPI", "javascript": "npm", "rust": "crates.io", "go": "Go", "java": "Maven"}.get(dep.ecosystem)
        curated = UNSAFE_IMPORTS.get("js" if dep.ecosystem == "javascript" else dep.ecosystem, {})
        rows = []
        async with RateLimitedSession() as session:
            async def check(item):
                pin = exact_pin(item["spec"])
                payload = {"package": {"name": item["name"], "ecosystem": osv_eco}}
                if pin:
                    payload["version"] = pin
                data = await session.post_json("https://api.osv.dev/v1/query", payload) if osv_eco else None
                vulns = [v for v in ((data or {}).get("vulns") or []) if not v.get("withdrawn")]
                return item, pin, data is not None, vulns

            results = await asyncio.gather(*(check(i) for i in declared if i["name"]))
        for item, pin, answered, vulns in results:
            mal = [v["id"] for v in vulns if str(v.get("id", "")).startswith("MAL-")]
            note = curated.get(item["name"])
            ids = [v.get("id", "?") for v in vulns][:6]
            status = (
                "OSV unavailable" if not answered
                else f"{len(vulns)} advisory(ies){' at pinned ' + pin if pin else ' (any version)'}: {', '.join(ids)}"
                if vulns else ("no advisories" + (f" at {pin}" if pin else ""))
            )
            rows.append(
                f"  - {item['name']} {item['spec'] or '*'} [{item['source']}] — {status}"
                + (f"; MALICIOUS-PACKAGE REPORTS: {', '.join(mal)}" if mal else "")
                + (f"; curated: {note}" if note else "")
            )
            ledger.register_citable(dep_key, [item["name"], *ids])
        return _bounded(f"{len(declared)} declared dependency(ies):\n" + "\n".join(rows))

    @tool
    def profile_authorship(dep_key: str, window: int = 25) -> str:
        """Code-style authorship profile from the source repository's git history: for
        each author of the commits leading to this release, their code style, commit habits,
        signing, timezone and email domain in the release window versus their own history
        (or the project's established maintainers). Reports drift and notable shifts.

        Args:
            dep_key: ecosystem:name@version.
            window: how many most-recent commits form the release window (5-100).
        """
        dep = ledger.get_dependency(dep_key)
        if dep is None:
            return unknown_dep(dep_key)
        from safesc.tools.authorship import profile_repository

        root = clone_history(dep, registry_lookup=ctx.registry_lookup, depth=400)
        if root is None:
            return "No clonable source repository: authorship cannot be profiled from git history."
        prof = profile_repository(root, window=max(5, min(100, window)), repository=str(root))
        ledger.register_citable(dep_key, [a.author for a in prof.authors])
        return _bounded(json.dumps(prof.as_dict(), default=str, indent=1), 16_000)

    read_source = make_file_editor(
        name=READ_SOURCE_TOOL,
        description=(
            "READ-ONLY viewer for a dependency's fetched source. command must be 'view'; path "
            "must be an absolute path inside a workspace printed by fetch_dependency_source. "
            "view_range=[start, end] limits the lines shown. Any other command is rejected."
        ),
    )

    return [
        inspect_install_scripts, inspect_docs, compare_artifact_to_source,
        fetch_dependency_source, read_source, search_source,
        scan_source_for_risky_patterns, check_declared_dependencies, profile_authorship,
    ]


__all__ = ["READ_SOURCE_TOOL", "ReadOnlySourceGuard", "build_evidence_tools"]
