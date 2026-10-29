"""agents/tools — each tool exercised directly, network mocked, to pin what agents see."""

from __future__ import annotations

import asyncio
import io
import json
import shutil
import subprocess
import tarfile
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from safesc.agents.context import AgentContext
from safesc.agents.tools import external, pipeline
from safesc.agents.tools.evidence import build_evidence_tools
from safesc.agents.tools.inspection import build_ledger_views, build_registry_tools
from safesc.agents.tools.pipeline import StaticBackend, build_pipeline_tools
from safesc.core.ledger import LockfileRef, Stage
from safesc.core.signals import Severity, TrustDimension, dep_key
from safesc.core.targets import TargetKind
from safesc.memory import SafeSCMemory
from tests.helpers import dep, fake_llm, ledger, sig


def _call(tool_obj, **kw):
    out = tool_obj(**kw)
    return asyncio.run(out) if asyncio.iscoroutine(out) else out


def _tools(tools) -> dict:
    return {t.tool_name: t for t in tools}


def _ctx(tmp_path, led, **kw) -> AgentContext:
    return AgentContext(ledger=led, llm=fake_llm(), memory=SafeSCMemory(tmp_path / "mem"),
                        registry_lookup=lambda *a: None, workspace_base=tmp_path / "ws", **kw)


def _complete(led):
    for s in (Stage.DISCOVER, Stage.PARSE, Stage.VERIFY, Stage.COLLECT):
        led.mark_stage(s)
    return led


def _tgz(files: dict[str, str]):
    def download(url: str, dest: Path) -> bool:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        dest.write_bytes(buf.getvalue())
        return True
    return download


# ------------------------------------------------------------------ pipeline


def test_pipeline_degrades_but_never_skips(tmp_path):
    led = ledger(target=str(tmp_path))

    def boom(*_a):
        raise RuntimeError("disk on fire")

    async def boom_async(_deps):
        raise RuntimeError("registry down")

    t = _tools(build_pipeline_tools(_ctx(tmp_path, led, backend=StaticBackend(
        discover=boom, parse=lambda lf: [dep()], verify=boom_async, collect=boom_async))))
    assert "must wait" not in _call(t["discover_lockfiles"]) and Stage.DISCOVER in led.stages
    assert "Parsed 1" in _call(t["parse_dependencies"])
    _call(t["verify_hashes"])
    assert "degraded" in _call(t["collect_signals"])
    notes = " ".join(n.reason for n in led.notes)
    assert "disk on fire" in notes and "registry down" in notes


def test_tools_refuse_out_of_order_even_without_the_guard(tmp_path):
    t = _tools(build_pipeline_tools(_ctx(tmp_path, ledger())))
    assert _call(t["collect_signals"]).startswith("ERROR")
    assert _call(t["parse_dependencies"]).startswith("ERROR")


def test_empty_lockfile_is_a_coverage_gap(tmp_path):
    led = ledger(target=str(tmp_path))
    lf = LockfileRef(path=str(tmp_path / "requirements.txt"), ecosystem="python")
    t = _tools(build_pipeline_tools(_ctx(tmp_path, led, backend=StaticBackend(
        discover=lambda *a: [lf], parse=lambda lfs: []))))
    _call(t["discover_lockfiles"])
    _call(t["parse_dependencies"])
    assert any("parsed to 0 dependencies" in n.reason for n in led.notes)


def test_package_target_parses_the_spec(tmp_path):
    led = ledger(target="pkg:cargo/serde@1.0.200", target_kind=TargetKind.PACKAGE)
    t = _tools(build_pipeline_tools(_ctx(tmp_path, led)))
    assert "single package" in _call(t["discover_lockfiles"])
    _call(t["parse_dependencies"])
    assert [dep_key(d) for d in led.dependencies] == ["rust:serde@1.0.200"]
    bad = ledger(target="pkg:", target_kind=TargetKind.PACKAGE)
    tb = _tools(build_pipeline_tools(_ctx(tmp_path, bad)))
    _call(tb["discover_lockfiles"])
    _call(tb["parse_dependencies"])
    assert bad.dependencies == [] and bad.notes


def test_real_discover_accepts_a_lockfile_path(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    found = pipeline._real_discover(str(tmp_path / "requirements.txt"), ())
    assert [Path(f.path).name for f in found] == ["requirements.txt"] and len(found) == 1
    deps = pipeline._real_parse(found)
    assert [d.name for d in deps] == ["requests"]


def test_real_collect_reports_degraded_collectors_except_popularity(tmp_path):
    from safesc.tools.scan.signals.base import SignalCollector
    from safesc.tools.scan.signals.models import Dimension

    class Broken(SignalCollector):
        def __init__(self, dim):
            self._dim = dim

        @property
        def dimension(self):
            return self._dim

        async def collect(self, dep_, session):
            raise RuntimeError("nope")

    with patch("safesc.tools.scan.signals.collector.default_collectors",
               return_value=[Broken(Dimension.VULNERABILITY), Broken(Dimension.POPULARITY)]):
        signals, notes = asyncio.run(pipeline._real_collect([dep()]))
    assert signals == [] and len(notes) == 1 and "vulnerability" in notes[0]


# ------------------------------------------------------------------ ledger views


def test_views_list_flagged_and_explain_a_dep(tmp_path):
    a, b = dep("a"), dep("b", direct=False, parent_name="a")
    led = _complete(ledger(deps=[a, b], signals=[
        sig(a, TrustDimension.BEHAVIOR, Severity.HIGH, evidence=["hasInstallScript=true"], summary="postinstall"),
        sig(b, TrustDimension.IDENTITY, Severity.LOW),
    ]))
    led.register_candidates(dep_key(a), [{"title": "overflow", "file": "x.c", "line": 2}])
    t = _tools(build_ledger_views(_ctx(tmp_path, led), orchestrator=True))
    listing = _call(t["list_flagged_dependencies"], min_severity="medium")
    assert "javascript:a@1.0.0 [HIGH, direct] behavior=HIGH" in listing and "b@" not in listing
    assert "transitive" in _call(t["list_flagged_dependencies"], min_severity="LOW")
    assert "ERROR" in _call(t["list_flagged_dependencies"], min_severity="bogus")
    detail = _call(t["get_dependency_signals"], dep_key=dep_key(a))
    assert "postinstall" in detail and "vulnerability candidate" in detail
    assert "hasInstallScript=true" in led.citable(dep_key(a))
    assert "unknown dependency" in _call(t["get_dependency_signals"], dep_key="nope")
    todo = _call(t["required_analyses"])
    assert "behavior(dep_key='javascript:a@1.0.0')" in todo and "vuln_verifier" in todo


def test_registry_metadata_is_rendered_and_citable(tmp_path):
    from safesc.tools.scan.signals.registry_meta import PackageMetadata

    d = dep("left-pad")
    led = _complete(ledger(deps=[d]))
    meta = PackageMetadata(author="azer", repo_url="https://github.com/azer/left-pad", total_releases=12,
                           has_install_script=True)
    t = _tools(build_registry_tools(_ctx(tmp_path, led)))
    with patch("safesc.tools.scan.signals.registry_meta.get_package_metadata", new=AsyncMock(return_value=meta)):
        out = json.loads(_call(t["get_registry_metadata"], dep_key=dep_key(d)))
    assert out["author"] == "azer" and out["has_install_script"] is True
    assert "https://github.com/azer/left-pad" in led.citable(dep_key(d))


def test_lookup_known_vulnerabilities(tmp_path):
    d = dep("lodash", "4.17.20")
    led = _complete(ledger(deps=[d]))
    t = _tools(build_registry_tools(_ctx(tmp_path, led)))
    data = {"vulns": [{"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "summary": "Command injection",
                       "database_specific": {"severity": "HIGH"}}, {"id": "OLD", "withdrawn": "2020"}]}
    with patch("safesc.tools.scan.signals.provenance.http.RateLimitedSession.post_json", new=AsyncMock(return_value=data)):
        out = _call(t["lookup_known_vulnerabilities"], ecosystem="javascript", name="lodash", version="4.17.20")
    assert "1 advisory" in out and "CVE-2021-23337" in out and "OLD" not in out
    assert "CVE-2021-23337" in led.citable(dep_key(d))
    with patch("safesc.tools.scan.signals.provenance.http.RateLimitedSession.post_json", new=AsyncMock(return_value=None)):
        assert "NOT established" in _call(t["lookup_known_vulnerabilities"], ecosystem="javascript", name="x")
    assert "unsupported" in _call(t["lookup_known_vulnerabilities"], ecosystem="cobol", name="x")


# ------------------------------------------------------------------ evidence


def test_source_workflow_fetch_search_scan(tmp_path):
    d = dep("hdr")
    led = _complete(ledger(deps=[d]))
    t = _tools(build_evidence_tools(_ctx(tmp_path, led, downloader=_tgz({
        "package/src/a.c": "void f(char*s){char b[4];strcpy(b,s);}\n", "package/README.md": "hi\n"}))))
    fetched = _call(t["fetch_dependency_source"], dep_key=dep_key(d))
    assert "Workspace (absolute path, read-only)" in fetched and '"c": 1' in fetched
    assert "package/src/a.c" in led.citable(dep_key(d))
    assert "a.c:1" in _call(t["search_source"], dep_key=dep_key(d), text="STRCPY")
    report = json.loads(_call(t["scan_source_for_risky_patterns"], dep_key=dep_key(d)))
    assert report["findings"][0]["rule_id"] == "C-STRCPY"


def test_source_unavailable_is_reported(tmp_path):
    d = dep("ghost")
    led = _complete(ledger(deps=[d]))
    t = _tools(build_evidence_tools(_ctx(tmp_path, led, downloader=lambda u, p: False)))
    assert "Source unavailable" in _call(t["scan_source_for_risky_patterns"], dep_key=dep_key(d))
    assert "unknown dependency" in _call(t["fetch_dependency_source"], dep_key="x")


def test_declared_dependencies_checked_against_osv_and_curated_lists(tmp_path):
    d = dep("wrapper")
    led = _complete(ledger(deps=[d]))
    pkg = json.dumps({"dependencies": {"node-serialize": "0.0.4", "evil-pkg": "^1.0.0", "fine": "1.2.3"}})
    t = _tools(build_evidence_tools(_ctx(tmp_path, led, downloader=_tgz({"package/package.json": pkg}))))

    async def post_json(self, url, payload):
        name = payload["package"]["name"]
        if name == "evil-pkg":
            return {"vulns": [{"id": "MAL-2024-1"}]}
        if name == "node-serialize":
            assert payload["version"] == "0.0.4"  # exact pins are checked at that version
            return {"vulns": [{"id": "GHSA-q4v7-4rhw-9hqm"}]}
        return {}

    with patch("safesc.tools.scan.signals.provenance.http.RateLimitedSession.post_json", new=post_json):
        out = _call(t["check_declared_dependencies"], dep_key=dep_key(d))
    assert "MALICIOUS-PACKAGE REPORTS: MAL-2024-1" in out
    assert "curated: deserialization RCE" in out and "GHSA-q4v7-4rhw-9hqm" in out
    assert "fine 1.2.3" in out and "no advisories at 1.2.3" in out


def test_deep_analysis_tools_render_evidence(tmp_path):
    from safesc.tools.deep_analysis_tool import DeepAnalysisEvidence, DeepAnalysisRequest, EvidenceItem

    d = dep("hooky")
    led = _complete(ledger(deps=[d]))
    ev = DeepAnalysisEvidence(request=DeepAnalysisRequest(name="hooky", version="1.0.0", ecosystem="javascript"))
    ev.behavior.install_scripts = [EvidenceItem(kind="install_script", path="scripts/post.js", excerpt="fetch(x).then(eval)")]
    ev.provenance.artifact_only_files = [EvidenceItem(kind="artifact_only_file", path="dist/x.js", excerpt="...")]
    ev.identity.registry.resolved = True
    ev.identity.registry.author = "mallory"
    with patch("safesc.tools.deep_analysis_tool.gather_deep_analysis_evidence", return_value=ev):
        t = _tools(build_evidence_tools(_ctx(tmp_path, led)))
        assert "scripts/post.js" in _call(t["inspect_install_scripts"], dep_key=dep_key(d))
        assert "mallory" in _call(t["inspect_docs"], dep_key=dep_key(d))
        assert "dist/x.js" in _call(t["compare_artifact_to_source"], dep_key=dep_key(d))
    assert {"scripts/post.js", "dist/x.js", "mallory"} <= led.citable(dep_key(d))
    other = ledger(deps=[dep("x", ecosystem="")])
    to = _tools(build_evidence_tools(_ctx(tmp_path, _complete(other))))
    assert "Unsupported ecosystem" in _call(to["inspect_install_scripts"], dep_key=":x@1.0.0")


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_profile_authorship_tool(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=A", "-c", "user.email=a@x.io", "-c", "commit.gpgsign=false",
                    "commit", "-q", "-m", "init"], check=True)
    d = dep("authored")
    led = _complete(ledger(deps=[d]))
    with patch("safesc.tools.source.clone_history", return_value=repo):
        t = _tools(build_evidence_tools(_ctx(tmp_path, led)))
        out = json.loads(_call(t["profile_authorship"], dep_key=dep_key(d), window=5))
    assert out["history_commits"] == 1 and out["authors"][0]["author"] == "a@x.io"
    with patch("safesc.tools.source.clone_history", return_value=None):
        t = _tools(build_evidence_tools(_ctx(tmp_path, led)))
        assert "No clonable" in _call(t["profile_authorship"], dep_key=dep_key(d))


# ------------------------------------------------------------------ external


def test_mcp_needs_a_token_and_failures_are_warnings(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    warnings: list[str] = []
    with ExitStack() as stack:
        assert external.open_mcp_tools(stack, github=True, warn=warnings.append) == []
    assert "GITHUB_TOKEN" in warnings[0]

    class FailingClient:
        def __init__(self, **kw):
            self.kw = kw

        def __enter__(self):
            raise ConnectionError("refused")

        def __exit__(self, *a):
            return False

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    with patch("strands.tools.mcp.MCPClient", FailingClient), ExitStack() as stack:
        assert external.open_mcp_tools(stack, github=True, extra_urls=["https://x/mcp"], warn=warnings.append) == []
    assert sum("unavailable" in w for w in warnings) == 2


def test_github_mcp_is_read_only_by_allow_list(monkeypatch):
    seen = {}

    class Client:
        def __init__(self, **kw):
            seen.update(kw)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def list_tools_sync(self):
            return [SimpleNamespace(tool_name="github_get_commit")]

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    with patch("strands.tools.mcp.MCPClient", Client), ExitStack() as stack:
        tools = external.open_mcp_tools(stack, github=True)
    assert [t.tool_name for t in tools] == ["github_get_commit"]
    allowed = seen["tool_filters"]["allowed"]
    assert all(not name.startswith(("create", "update", "delete", "push", "merge")) for name in allowed)
    assert seen["headers"]["X-MCP-Readonly"] == "true"


def test_web_fetch_is_agentic():
    (wf,) = external.web_tools()
    assert wf.tool_name == "web_fetch" and "prompt" in json.dumps(wf.tool_spec["inputSchema"])
