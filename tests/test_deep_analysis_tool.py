"""Unit tests for tools/deep_analysis_tool.py — Stage-4 evidence primitives
(CLAUDE.md §2.3, §6.1 invariant #2).

Two things matter most here:
  * the primitives are EVIDENCE ONLY — no verdict/score/severity anywhere;
  * clone/network/git are never required for the deterministic helpers, so these
    tests build a fake ClonedRepo over a temp dir and exercise pure logic.
"""

from __future__ import annotations

import base64
import json
import zipfile
from pathlib import Path

import pytest

from tools.deep_analysis_tool import (
    BehaviorEvidence,
    ClonedRepo,
    DeepAnalysisEvidence,
    DeepAnalysisRequest,
    EvidenceItem,
    IdentityEvidence,
    ProvenanceEvidence,
    RegistryProvenance,
    _guess_refs,
    _is_generated,
    _npm_lifecycle_hooks,
    _referenced_local_scripts,
    _safe_extract_archive,
    _shannon_entropy,
    _static_op_hints,
    _truncate,
    _validate_git_url,
    _within,
    extract_docs,
    extract_install_scripts,
    extract_obfuscation_candidates,
    gather_deep_analysis_evidence,
    gather_registry_provenance,
)
from tools.index.core.models import Dependency


# --------------------------------------------------------------------------- #
# Invariant #2: evidence models carry NO verdict/score/severity
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "model",
    [
        EvidenceItem,
        BehaviorEvidence,
        ProvenanceEvidence,
        IdentityEvidence,
        RegistryProvenance,
        DeepAnalysisEvidence,
    ],
)
def test_evidence_models_have_no_verdict_fields(model):
    forbidden = {"verdict", "score", "severity"}
    assert forbidden.isdisjoint(model.model_fields.keys())


def test_tool_output_json_contains_no_verdict(monkeypatch):
    # Force the degraded (no-clone) path so we don't hit git/network.
    from tools import deep_analysis_tool as m

    monkeypatch.setattr(m, "safe_clone", lambda req, depth=1: None)
    req = DeepAnalysisRequest(name="x", version="1", ecosystem="python")
    out = json.loads(m.gather_deep_analysis_evidence(req, dimensions=("behavior",)).model_dump_json())
    assert "verdict" not in out and "severity" not in out and "score" not in out


# --------------------------------------------------------------------------- #
# small pure helpers
# --------------------------------------------------------------------------- #

def test_truncate():
    assert _truncate("abc", 10) == "abc"
    long = "a" * 100
    out = _truncate(long, 10)
    assert out.startswith("a" * 10) and "truncated" in out


def test_is_generated():
    assert _is_generated("pkg/foo.dist-info/METADATA") is True
    assert _is_generated("src/main.py") is False


def test_shannon_entropy():
    assert _shannon_entropy("") == 0.0
    assert _shannon_entropy("aaaa") == 0.0
    assert _shannon_entropy("abcd") == pytest.approx(2.0)


def test_static_op_hints_detects_token_classes():
    hints = _static_op_hints("import os\nos.environ['X']\nsubprocess.run(x)\nbase64.b64decode(y)")
    assert hints["references_env"] is True
    assert hints["references_exec"] is True
    assert hints["references_encode"] is True
    assert hints["references_network"] is False


def test_npm_lifecycle_hooks():
    pkg = '{"name":"x","scripts":{"postinstall":"node evil.js","build":"tsc"}}'
    hooks = _npm_lifecycle_hooks(pkg)
    assert hooks == {"postinstall": "node evil.js"}


def test_referenced_local_scripts():
    assert _referenced_local_scripts({"postinstall": "node ./scripts/setup.js"}) == ["./scripts/setup.js"]
    assert _referenced_local_scripts({"install": "echo hi"}) == []


def test_within(tmp_path):
    inside = tmp_path / "a" / "b"
    assert _within(tmp_path, inside) is True
    assert _within(tmp_path, Path("/somewhere/else")) is False


def test_guess_refs_shapes():
    req = DeepAnalysisRequest(name="pkg", version="1.2.3", ecosystem="python")
    refs = _guess_refs(req)
    assert "v1.2.3" in refs and "1.2.3" in refs and None in refs


# --------------------------------------------------------------------------- #
# _validate_git_url — security surface
# --------------------------------------------------------------------------- #

def test_validate_git_url_accepts_https():
    assert _validate_git_url("https://github.com/psf/requests.git") == "https://github.com/psf/requests.git"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "file:///etc/passwd",
        "ext::sh -c whoami",
        "git://github.com/x/y",
        "http://github.com/x/y",              # not https
        "https://github.com/x/y; rm -rf /",   # shell-hostile char
        "https://github.com/x/y\nmalicious",
        "-oProxyCommand=evil",
    ],
)
def test_validate_git_url_rejects_dangerous(url):
    assert _validate_git_url(url) is None


# --------------------------------------------------------------------------- #
# DeepAnalysisRequest
# --------------------------------------------------------------------------- #

def test_from_dependency_maps_all_fields():
    dep = Dependency(
        name="requests",
        version="2.31.0",
        ecosystem="python",
        lockfile_path=Path("r.txt"),
        source_url="https://github.com/psf/requests",
        artifact_url="https://files.pythonhosted.org/x.whl",
        hash="sha256:abc",
        ref="v2.31.0",
    )
    req = DeepAnalysisRequest.from_dependency(dep)
    assert req.name == "requests"
    assert req.source_url == "https://github.com/psf/requests"
    assert req.artifact_url == "https://files.pythonhosted.org/x.whl"
    assert req.expected_hash == "sha256:abc"
    assert req.ref == "v2.31.0"


def test_cache_key_is_deterministic_and_hash_sensitive():
    base = dict(name="x", version="1", ecosystem="python")
    k1 = DeepAnalysisRequest(**base, expected_hash="h1").cache_key()
    k2 = DeepAnalysisRequest(**base, expected_hash="h1").cache_key()
    k3 = DeepAnalysisRequest(**base, expected_hash="h2").cache_key()
    assert k1 == k2 != k3
    assert len(k1) == 16


def test_note_degraded_sets_status():
    ev = DeepAnalysisEvidence(request=DeepAnalysisRequest(name="x", version="1", ecosystem="python"))
    assert ev.status == "complete"
    ev.note_degraded("clone failed")
    assert ev.status == "degraded"
    ev.note_degraded("second failure")
    assert ev.status == "partial"


# --------------------------------------------------------------------------- #
# file-reading extractors (fake ClonedRepo, no git needed)
# --------------------------------------------------------------------------- #

def test_extract_install_scripts_python(tmp_path):
    (tmp_path / "setup.py").write_text("import os\nos.system('curl evil')\n")
    repo = ClonedRepo(root=tmp_path, ref_resolved=None)
    items = extract_install_scripts(repo, "python")
    kinds = {it.kind for it in items}
    assert "install_script" in kinds
    script = next(it for it in items if it.kind == "install_script")
    assert script.metadata["references_exec"] is True


def test_extract_install_scripts_javascript(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts":{"postinstall":"node ./x.js"}}')
    (tmp_path / "x.js").write_text("require('http')")
    repo = ClonedRepo(root=tmp_path, ref_resolved=None)
    items = extract_install_scripts(repo, "javascript")
    paths = {it.path for it in items}
    assert "package.json" in paths


def test_extract_obfuscation_candidates_flags_high_entropy_blob(tmp_path):
    blob = base64.b64encode(bytes(range(200))).decode()  # high-entropy, >120 chars
    (tmp_path / "payload.py").write_text(f"DATA = '{blob}'\n")
    repo = ClonedRepo(root=tmp_path, ref_resolved=None)
    items = extract_obfuscation_candidates(repo)
    assert any(it.kind == "obfuscation_blob" for it in items)


def test_extract_docs(tmp_path):
    (tmp_path / "README.md").write_text("# hello\ninstall me or else")
    repo = ClonedRepo(root=tmp_path, ref_resolved=None)
    items = extract_docs(repo)
    assert items and items[0].kind == "doc"


# --------------------------------------------------------------------------- #
# archive safety (zip-slip)
# --------------------------------------------------------------------------- #

def test_safe_extract_archive_normal_zip(tmp_path):
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a/b.txt", "hi")
    dest = tmp_path / "out"
    assert _safe_extract_archive(archive, dest) is True
    assert (dest / "a" / "b.txt").read_text() == "hi"


def test_safe_extract_archive_blocks_zip_slip(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", "pwned")
    dest = tmp_path / "out"
    assert _safe_extract_archive(archive, dest) is False
    assert not (tmp_path / "escape.txt").exists()


# --------------------------------------------------------------------------- #
# orchestration degraded path
# --------------------------------------------------------------------------- #

def test_gather_degrades_without_source_url(monkeypatch):
    from tools import deep_analysis_tool as m

    monkeypatch.setattr(m, "safe_clone", lambda req, depth=1: None)
    monkeypatch.setattr(m, "extract_recent_commits", lambda req, depth=20: [])
    req = DeepAnalysisRequest(name="x", version="1", ecosystem="python")
    # Inject a no-op registry lookup so the identity path never touches the network.
    ev = m.gather_deep_analysis_evidence(
        req,
        dimensions=("behavior", "identity", "provenance"),
        registry_lookup=lambda *a, **k: None,
    )
    assert ev.status in ("degraded", "partial")
    assert ev.degraded_reasons
    assert ev.behavior.install_scripts == []
    assert ev.identity.docs == []


# --------------------------------------------------------------------------- #
# identity registry provenance (typosquat discrimination)
# --------------------------------------------------------------------------- #


def test_gather_registry_provenance_maps_facts():
    facts = {
        "author": "Redis Inc.",
        "repo_url": "https://github.com/redis/redis-vl-python",
        "homepage": "https://docs.redisvl.com",
        "summary": "Redis Vector Library",
        "total_releases": 42,
        "first_release_at": "2023-01-01T00:00:00Z",
        "latest_release_at": "2026-01-01T00:00:00Z",
    }
    req = DeepAnalysisRequest(name="redisvl", version="0.25.0", ecosystem="python")
    reg = gather_registry_provenance(req, registry_lookup=lambda *a, **k: facts)
    assert reg.resolved is True
    assert reg.author == "Redis Inc."
    assert reg.repo_url.endswith("redis-vl-python")
    assert reg.total_releases == 42


def test_gather_registry_provenance_unresolved_on_none():
    req = DeepAnalysisRequest(name="whatever", version="1", ecosystem="python")
    reg = gather_registry_provenance(req, registry_lookup=lambda *a, **k: None)
    assert reg.resolved is False
    assert reg.author is None


def test_gather_registry_provenance_degrades_on_lookup_error():
    def boom(*a, **k):
        raise RuntimeError("network down")

    req = DeepAnalysisRequest(name="whatever", version="1", ecosystem="python")
    reg = gather_registry_provenance(req, registry_lookup=boom)
    assert reg.resolved is False


def test_gather_identity_includes_nearest_popular_and_registry(monkeypatch):
    from tools import deep_analysis_tool as m

    # No clone (so no docs); registry lookup injected — never touches the network.
    monkeypatch.setattr(m, "safe_clone", lambda req, depth=1: None)
    facts = {"author": "Redis Inc.", "repo_url": "https://github.com/redis/redis-vl-python",
             "total_releases": 42}
    req = DeepAnalysisRequest(name="redisvl", version="0.25.0", ecosystem="python")
    ev = m.gather_deep_analysis_evidence(
        req,
        dimensions=("identity",),
        nearest_popular="redis",
        registry_lookup=lambda *a, **k: facts,
    )
    assert ev.identity.nearest_popular == "redis"
    assert ev.identity.registry.resolved is True
    assert ev.identity.registry.author == "Redis Inc."
    assert ev.identity.registry.total_releases == 42


def test_clone_uses_registry_repo_url_when_source_url_absent(monkeypatch):
    # A registry dep has an artifact_url (.whl) but no source_url. The gatherer must
    # resolve the real repo from registry metadata and clone THAT, not fail.
    from tools import deep_analysis_tool as m

    cloned_with = {}

    def fake_clone(req, depth=1):
        cloned_with["source_url"] = req.source_url
        return None  # clone still "fails" — we only assert what URL it was given

    monkeypatch.setattr(m, "safe_clone", fake_clone)
    monkeypatch.setattr(m, "extract_recent_commits", lambda req, depth=20: [])
    facts = {"repo_url": "https://github.com/redis/redis-vl-python", "author": "Redis Inc."}
    req = DeepAnalysisRequest(name="redisvl", version="0.25.0", ecosystem="python")  # no source_url
    m.gather_deep_analysis_evidence(
        req, dimensions=("identity",), registry_lookup=lambda *a, **k: facts,
    )
    assert cloned_with["source_url"] == "https://github.com/redis/redis-vl-python"


def test_clone_keeps_existing_source_url(monkeypatch):
    # If the dep already has a VCS source_url, it is used as-is (no registry override).
    from tools import deep_analysis_tool as m

    cloned_with = {}
    monkeypatch.setattr(m, "safe_clone", lambda req, depth=1: cloned_with.setdefault("u", req.source_url) or None)
    monkeypatch.setattr(m, "extract_recent_commits", lambda req, depth=20: [])
    req = DeepAnalysisRequest(
        name="pkg", version="1", ecosystem="python", source_url="https://github.com/o/r"
    )
    m.gather_deep_analysis_evidence(
        req, dimensions=("identity",), registry_lookup=lambda *a, **k: {"repo_url": "https://github.com/evil/other"},
    )
    assert cloned_with["u"] == "https://github.com/o/r"


def test_gather_identity_registry_fetched_without_clone():
    # A squat often has no real repo; registry provenance must still be attempted
    # even when the source clone is unavailable.
    from tools import deep_analysis_tool as m

    called = {"n": 0}

    def lookup(name, version, ecosystem):
        called["n"] += 1
        return None

    req = DeepAnalysisRequest(name="x", version="1", ecosystem="python")
    ev = m.gather_deep_analysis_evidence(
        req, dimensions=("identity",), registry_lookup=lookup,
    )
    assert called["n"] == 1
    assert ev.identity.registry.resolved is False
    assert any("registry provenance unavailable" in r for r in ev.degraded_reasons)
