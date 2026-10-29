"""agents/tools/inspection.py — read-only views of the ledger and of public registries.

None of these tools change a verdict; they let agents *look*: browse flagged deps, read a
dep's signals, see what analysis is still required, and fetch the deterministic registry
and advisory facts a subagent may cite. Every fact a tool returns about a dependency is
registered as citable for that dependency, which is what the subagent output validator
checks citations against (§2.7.1).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from strands import tool

from safesc.core.gate import dimension_severity
from safesc.core.ledger import Stage
from safesc.core.signals import Severity, dep_key

if TYPE_CHECKING:
    from safesc.agents.context import AgentContext

_OSV_ECOSYSTEM = {"python": "PyPI", "javascript": "npm", "rust": "crates.io", "go": "Go", "java": "Maven"}
PAGE = 25


def _clip(text: str, n: int = 400) -> str:
    return text if len(text) <= n else text[:n] + "…"


def unknown_dep(key: str) -> str:
    return f"ERROR: unknown dependency {key!r}. Use list_flagged_dependencies for valid dep_key values (ecosystem:name@version)."


def build_ledger_views(ctx: "AgentContext", *, orchestrator: bool) -> list:
    ledger = ctx.ledger

    @tool
    def list_flagged_dependencies(min_severity: str = "LOW", page: int = 1) -> str:
        """List dependencies whose worst signal is at or above a severity, worst first.

        Args:
            min_severity: CLEAN, LOW, MEDIUM, HIGH or CRITICAL.
            page: 1-based page number (25 per page).
        """
        if ledger.missing_stages(Stage.PARSE):
            return "ERROR: no dependencies yet — run the static pipeline first."
        try:
            floor = Severity[min_severity.strip().upper()]
        except KeyError:
            return "ERROR: min_severity must be one of CLEAN, LOW, MEDIUM, HIGH, CRITICAL."
        rows = []
        for dep in ledger.dependencies:
            key = dep_key(dep)
            dims = dimension_severity(ledger.signals, key)
            llm = [s for s in ledger.signals_for(key) if s.origin.value == "llm"]
            worst = max([s.severity for s in ledger.signals_for(key)], default=Severity.CLEAN)
            if worst >= floor:
                rows.append((worst, key, dep, dims, llm))
        rows.sort(key=lambda r: (-int(r[0]), r[1]))
        start = (max(page, 1) - 1) * PAGE
        chunk = rows[start:start + PAGE]
        if not chunk:
            return f"No dependencies at or above {floor.name} on page {page} ({len(rows)} total)."
        lines = [f"{len(rows)} dependency(ies) at or above {floor.name}; page {page}:"]
        for worst, key, dep, dims, llm in chunk:
            dim_text = ", ".join(f"{d.value}={sev.name}" for d, (sev, _) in sorted(dims.items(), key=lambda x: x[0].value))
            direct = "direct" if (dep.is_direct or dep.layer_number == 1) else "transitive"
            llm_text = f"; analysed by {', '.join(sorted({s.source for s in llm}))}" if llm else ""
            lines.append(f"  - {key} [{worst.name}, {direct}] {dim_text}{llm_text}")
        return "\n".join(lines)

    @tool
    def get_dependency_signals(dep_key: str) -> str:
        """Every signal recorded so far for one dependency, with its key facts.

        Args:
            dep_key: ecosystem:name@version, exactly as listed.
        """
        dep = ledger.get_dependency(dep_key)
        if dep is None:
            return unknown_dep(dep_key)
        facts = {
            "dep_key": dep_key,
            "direct": bool(dep.is_direct or dep.layer_number == 1),
            "lockfile": str(dep.lockfile_path),
            "hash": dep.hash,
            "source_url": dep.source_url,
            "artifact_url": dep.artifact_url,
            "parent": dep.parent_name,
        }
        sigs = sorted(ledger.signals_for(dep_key), key=lambda s: (-int(s.severity), s.source))
        ledger.register_citable(dep_key, [e for s in sigs for e in s.evidence])
        out = [json.dumps({k: v for k, v in facts.items() if v not in (None, "")})]
        if not sigs:
            out.append("No signals: every check came back clean (or did not apply).")
        for s in sigs:
            ev = "; ".join(s.evidence[:8])
            out.append(
                f"- [{s.severity.name}] {s.dimension.value} {s.origin.value}:{s.source} — {_clip(s.summary, 300)}"
                + (f"\n    evidence: {_clip(ev, 500)}" if ev else "")
            )
        cands = [c for c in ledger.candidates.values() if c.dep_key == dep_key]
        for c in cands:
            out.append(f"- vulnerability candidate {c.id} [{c.status}] {c.title} at {c.file}:{c.line or '?'}")
        return "\n".join(out)

    tools = [list_flagged_dependencies, get_dependency_signals]

    if orchestrator:
        @tool
        def required_analyses() -> str:
            """The subagent analyses this run still REQUIRES before finalize_score is
            accepted, plus the remaining subagent budget."""
            remaining = ledger.options.max_subagents - ledger.budget_used
            todo = ledger.outstanding_coverage()
            head = f"Subagent budget: {remaining} of {ledger.options.max_subagents} invocation(s) left."
            if not todo:
                return head + " No required analyses outstanding — you may finalize (or explore further)."
            lines = [head, f"{len(todo)} required analysis(es) outstanding:"]
            lines += [f"  - {role.value}(dep_key={k!r})  — {why}" for k, role, why in todo[:40]]
            return "\n".join(lines)

        tools.append(required_analyses)
    return tools


def build_registry_tools(ctx: "AgentContext") -> list:
    ledger = ctx.ledger

    @tool
    async def get_registry_metadata(dep_key: str) -> str:
        """Deterministic registry facts for a dependency: publisher/author, declared source
        repository, homepage, release count and first/latest release dates, install-hook
        flags. Primary evidence for identity and authorship questions.

        Args:
            dep_key: ecosystem:name@version.
        """
        dep = ledger.get_dependency(dep_key)
        if dep is None:
            return unknown_dep(dep_key)
        from safesc.tools.scan.signals.provenance.http import RateLimitedSession
        from safesc.tools.scan.signals.registry_meta import get_package_metadata

        try:
            async with RateLimitedSession() as session:
                meta = await get_package_metadata(dep, session)
        except Exception as exc:
            return f"Registry lookup failed: {exc}"
        if meta is None:
            return "Registry metadata unavailable for this ecosystem/package."
        facts = {
            "author": meta.author, "repo_url": meta.repo_url, "homepage": meta.homepage,
            "summary": meta.summary, "total_releases": meta.total_releases,
            "first_release_at": meta.first_release_at, "latest_release_at": meta.latest_release_at,
            "version_present": meta.version_present, "version_yanked": meta.version_yanked,
            "has_install_script": meta.has_install_script,
            "has_native_build_script": meta.has_native_build_script,
            "requires_source_build": meta.requires_source_build,
        }
        ledger.register_citable(dep_key, [str(v) for v in facts.values() if v not in (None, "", 0, False)])
        return json.dumps({k: v for k, v in facts.items() if v not in (None, "")}, default=str)

    @tool
    async def lookup_known_vulnerabilities(ecosystem: str, name: str, version: str = "") -> str:
        """Published advisories (OSV.dev) for ANY package — a dependency, or something it
        imports. With no version, returns every advisory for the package (including
        MAL- malicious-package reports). Use it to tell an already-reported flaw from a new one.

        Args:
            ecosystem: python, javascript, rust, go or java.
            name: package name as the registry spells it.
            version: optional exact version.
        """
        from safesc.tools.scan.signals.provenance.http import RateLimitedSession
        from safesc.tools.scan.signals.vulnerability.osv import _severity_for_vuln

        osv_eco = _OSV_ECOSYSTEM.get(ecosystem.strip().lower())
        if osv_eco is None:
            return f"ERROR: unsupported ecosystem {ecosystem!r}."
        payload: dict = {"package": {"name": name, "ecosystem": osv_eco}}
        if version:
            payload["version"] = version
        try:
            async with RateLimitedSession() as session:
                data = await session.post_json("https://api.osv.dev/v1/query", payload)
        except Exception as exc:
            return f"OSV lookup failed: {exc}"
        if data is None:
            return "OSV lookup failed (no response); absence of advisories is NOT established."
        vulns = [v for v in (data.get("vulns") or []) if not v.get("withdrawn")]
        if not vulns:
            return f"No published advisories for {name}{'@' + version if version else ''} ({osv_eco})."
        lines = [f"{len(vulns)} advisory(ies) for {name}{'@' + version if version else ''}:"]
        refs: list[str] = []
        for v in vulns[:25]:
            vid = v.get("id", "?")
            refs.append(vid)
            refs += list(v.get("aliases") or [])
            lines.append(
                f"  - {vid} ({_severity_for_vuln(v).value}) aliases={','.join(v.get('aliases') or []) or '-'} "
                f"— {_clip(v.get('summary') or v.get('details') or '', 200)}"
            )
        for key in [dep_key(d) for d in ledger.dependencies if d.name == name]:
            ledger.register_citable(key, refs)
        return "\n".join(lines)

    return [get_registry_metadata, lookup_known_vulnerabilities]
