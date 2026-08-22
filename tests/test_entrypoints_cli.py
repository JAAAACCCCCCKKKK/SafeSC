"""Unit tests for entrypoints/cli.py and entrypoints/bootstrap.py.

The thin CLI surface is exercised with the graph `run()` seam monkeypatched, so no
LangGraph/anthropic/LLM key is required. Covers audit/query/gc routing, BYOK env
handling, the missing-credential error path, and report emission.
"""

from __future__ import annotations

import types

import pytest

from safesc.entrypoints import bootstrap, cli
from safesc.graph.state import GateDecision, Severity


def _fake_result(*, exit_code=0, passed=True, incomplete=False, summary="ok"):
    gd = GateDecision(overall=Severity.CLEAN, passed=passed, exit_code=exit_code, summary=summary)
    return types.SimpleNamespace(
        run_id="01FAKE",
        gate_decision=gd,
        passed=passed,
        exit_code=exit_code,
        incomplete=incomplete,
        final_state=object(),
    )


@pytest.fixture
def _llm_env(monkeypatch):
    monkeypatch.setenv("SAFESC_LLM_API_KEY", "byok-secret")
    monkeypatch.setenv("SAFESC_LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("SAFESC_EMBEDDING_API_KEY", raising=False)


def test_audit_returns_gate_exit_code(monkeypatch, capsys, _llm_env):
    monkeypatch.setattr(cli.graph_build, "run", lambda *a, **k: _fake_result(exit_code=1, passed=False))
    rc = cli.main(["audit", "."], tools=object(), session=object())
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_query_prints_pass(monkeypatch, capsys, _llm_env):
    monkeypatch.setattr(cli.graph_build, "run", lambda *a, **k: _fake_result())
    rc = cli.main(["query", "npm:left-pad@1.3.0"], tools=object(), session=object())
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


def test_incomplete_note_printed(monkeypatch, capsys, _llm_env):
    monkeypatch.setattr(cli.graph_build, "run", lambda *a, **k: _fake_result(incomplete=True))
    cli.main(["audit"], tools=object(), session=object())
    assert "incomplete" in capsys.readouterr().out


def test_missing_credential_returns_2(monkeypatch, capsys):
    monkeypatch.delenv("SAFESC_LLM_API_KEY", raising=False)
    rc = cli.main(["audit", "."], tools=object(), session=object())
    assert rc == 2
    assert "error" in capsys.readouterr().err


def test_report_dir_emits_artifacts(monkeypatch, tmp_path, capsys, _llm_env):
    monkeypatch.setattr(cli.graph_build, "run", lambda *a, **k: _fake_result())
    monkeypatch.setattr("safesc.reporter.build_report", lambda state, run_id: object())
    written = [tmp_path / "safesc-report.json"]
    monkeypatch.setattr("safesc.reporter.write_reports", lambda report, d, formats: written)
    monkeypatch.setattr("safesc.reporter.FORMATS", ["json"])
    rc = cli.main(["audit", ".", "--report-dir", str(tmp_path), "--format", "json"],
                  tools=object(), session=object())
    assert rc == 0
    assert "wrote" in capsys.readouterr().out


def test_gc_without_memory(capsys):
    assert cli.main(["gc"]) == 0
    assert "nothing to do" in capsys.readouterr().out


def test_gc_with_memory_manager(capsys):
    class Mem:
        def gc(self):
            return {"deleted": 3}

    assert cli.main(["gc"], memory=Mem()) == 0
    assert "gc complete" in capsys.readouterr().out


def test_gc_memory_without_gc_method(capsys):
    assert cli.main(["gc"], memory=object()) == 0
    assert "TTL-only" in capsys.readouterr().err


# ---- bootstrap ----


def test_local_session_mints_ulid():
    rid = bootstrap.LocalSession().new_run()
    assert isinstance(rid, str) and len(rid) == 26


def test_build_local_runtime_is_store_free():
    tools, session, memory = bootstrap.build_local_runtime()
    assert memory is None
    assert hasattr(session, "new_run")
    assert tools is not None


def test_explain_missing_extra_orchestration(capsys):
    bootstrap._explain_missing_extra("langgraph")
    err = capsys.readouterr().err
    assert "safesc[agent]" in err


def test_explain_missing_extra_provider(capsys):
    # A provider SDK maps to its own extra, installed alongside the agent extra.
    bootstrap._explain_missing_extra("anthropic")
    err = capsys.readouterr().err
    assert "safesc[agent,anthropic]" in err

    bootstrap._explain_missing_extra("openai")
    assert "safesc[agent,openai]" in capsys.readouterr().err


def test_console_utf8_safe_is_noop_safe():
    bootstrap._make_console_utf8_safe()  # must not raise


def test_bootstrap_main_gc_end_to_end(capsys):
    # store-free runtime + gc subcommand needs no LLM key and no external stores.
    assert bootstrap.main(["gc"]) == 0
    assert "nothing to do" in capsys.readouterr().out


# ---- --exclude plumbing ----


def test_preparse_exclude_extracts_repeated_flags():
    argv = ["audit", ".", "--exclude", "a/**", "--report-dir", "out", "--exclude", "b/**"]
    assert bootstrap._preparse_exclude(argv) == ["a/**", "b/**"]


def test_preparse_exclude_empty_when_absent():
    assert bootstrap._preparse_exclude(["audit", "."]) == []


def test_build_local_runtime_bakes_in_exclude(tmp_path):
    # exclude is a construction-time parameter of load_default_tools (via
    # build_local_runtime), not a per-call one — see graph/spine.py's docstring.
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "requirements.txt").write_text("requests==2.31.0\n")

    tools, _session, _memory = bootstrap.build_local_runtime(exclude=["vendor/**"])
    lockfiles = tools.discover(str(tmp_path))
    assert [str(lf.path) for lf in lockfiles] == [str(tmp_path / "requirements.txt")]


def test_bootstrap_main_exclude_reaches_discovery(monkeypatch, capsys, _llm_env):
    # Full plumbing: --exclude on `safesc audit ...` is pre-parsed in bootstrap.main
    # before graph_build.run is ever called, and reaches the real discovery seam.
    captured = {}

    def _fake_run(req, *, tools, **kwargs):
        captured["tools"] = tools
        return _fake_result()

    monkeypatch.setattr(cli.graph_build, "run", _fake_run)
    assert bootstrap.main(["audit", ".", "--exclude", "everything/**"]) == 0
    assert callable(captured["tools"].discover)


# ============================================================ tier selection (§3.6)


@pytest.fixture
def _no_store_env(monkeypatch):
    for var in ("SAFESC_REDIS_URL", "SAFESC_PGVECTOR_DSN", "SAFESC_MEMORY_STRICT"):
        monkeypatch.delenv(var, raising=False)


def test_select_runtime_defaults_to_the_store_free_tier(_no_store_env):
    rt = bootstrap.select_runtime()
    assert rt.tier == "local"
    assert rt.memory is None and rt.checkpointer is None
    assert isinstance(rt.session, bootstrap.LocalSession)


def test_select_runtime_builds_the_redis_tier(monkeypatch, _no_store_env):
    from safesc.graph.harness.session_manager import SessionManager

    built = {}

    class _Store:
        config = None

        def ping(self):
            return True

        def checkpointer(self):
            return "CHECKPOINTER"

        def cache_get(self, key):
            return None

        def cache_set(self, key, value, ttl=None):
            built["cached"] = key

    monkeypatch.setenv("SAFESC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setattr(
        "safesc.memory.short_term.ShortTermStore.from_url", classmethod(lambda cls, cfg=None: _Store())
    )
    rt = bootstrap.select_runtime()
    assert rt.tier == "redis"
    assert rt.checkpointer == "CHECKPOINTER"
    assert isinstance(rt.session, SessionManager)
    # Redis alone still gets a MemoryManager: the exact-hash path needs no embedder.
    assert rt.memory is not None
    assert rt.memory.vector is None and rt.memory.embedder is None


def test_unreachable_redis_degrades_to_store_free_with_a_warning(monkeypatch, capsys, _no_store_env):
    class _Dead:
        def ping(self):
            return False

    monkeypatch.setenv("SAFESC_REDIS_URL", "redis://nope:6379/0")
    monkeypatch.setattr(
        "safesc.memory.short_term.ShortTermStore.from_url", classmethod(lambda cls, cfg=None: _Dead())
    )
    rt = bootstrap.select_runtime()
    assert rt.tier == "local"
    err = capsys.readouterr().err
    assert "memory layer unavailable" in err
    assert "escalate" in err, "the warning must say why running store-free is still safe"


def test_strict_mode_makes_an_unreachable_store_fatal(monkeypatch, _no_store_env):
    class _Dead:
        def ping(self):
            return False

    monkeypatch.setenv("SAFESC_REDIS_URL", "redis://nope:6379/0")
    monkeypatch.setenv("SAFESC_MEMORY_STRICT", "1")
    monkeypatch.setattr(
        "safesc.memory.short_term.ShortTermStore.from_url", classmethod(lambda cls, cfg=None: _Dead())
    )
    with pytest.raises(bootstrap.MemoryUnavailableError):
        bootstrap.select_runtime()


def test_bootstrap_main_reports_a_strict_failure_as_exit_2(monkeypatch, capsys, _no_store_env, _llm_env):
    monkeypatch.setattr(bootstrap, "select_runtime", lambda **kw: (_ for _ in ()).throw(
        bootstrap.MemoryUnavailableError("redis down")
    ))
    assert bootstrap.main(["audit", "."]) == 2
    assert "redis down" in capsys.readouterr().err


def test_missing_checkpointer_extra_does_not_break_the_redis_tier(monkeypatch, capsys, _no_store_env):
    class _Store:
        def ping(self):
            return True

        def checkpointer(self):
            raise RuntimeError("langgraph-checkpoint-redis is not installed")

        def cache_get(self, key):
            return None

        def cache_set(self, key, value, ttl=None):
            pass

    monkeypatch.setenv("SAFESC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setattr(
        "safesc.memory.short_term.ShortTermStore.from_url", classmethod(lambda cls, cfg=None: _Store())
    )
    rt = bootstrap.select_runtime()
    assert rt.tier == "redis" and rt.checkpointer is None
    assert "checkpointing unavailable" in capsys.readouterr().err


# ============================================================ resume


def test_resume_sets_the_flag_on_the_run_config(monkeypatch, _llm_env):
    captured = {}

    def _fake_run(req, **kwargs):
        captured.update(kwargs)
        return _fake_result()

    monkeypatch.setattr(cli.graph_build, "run", _fake_run)
    assert cli.main(["audit", ".", "--resume"], tools=object(), session=object(),
                    checkpointer="CKPT") == 0
    assert captured["config"].resume is True
    assert captured["checkpointer"] == "CKPT"


def test_resume_without_a_checkpointer_warns_but_still_runs(monkeypatch, capsys, _llm_env):
    monkeypatch.setattr(cli.graph_build, "run", lambda *a, **k: _fake_result())
    assert cli.main(["audit", ".", "--resume"], tools=object(), session=object()) == 0
    assert "--resume has no effect" in capsys.readouterr().err


def test_without_resume_the_injected_config_is_passed_through_untouched(monkeypatch, _llm_env):
    captured = {}
    sentinel = object()

    def _fake_run(req, **kwargs):
        captured.update(kwargs)
        return _fake_result()

    monkeypatch.setattr(cli.graph_build, "run", _fake_run)
    cli.main(["audit", "."], tools=object(), session=object(), config=sentinel)
    assert captured["config"] is sentinel


# ============================================================ store / fingerprint jobs


class _FakeVector:
    def __init__(self):
        self.schema_calls = 0
        self.rows = {}

    def ensure_schema(self):
        self.schema_calls += 1

    def upsert(self, key, embedding, record):
        self.rows[key] = record


class _FakeMemory:
    def __init__(self, vector=None, embedder=None):
        self.vector = vector
        self.embedder = embedder


def test_store_init_creates_the_schema(capsys):
    vector = _FakeVector()
    assert cli.main(["store", "init"], memory=_FakeMemory(vector=vector)) == 0
    assert vector.schema_calls == 1
    assert "schema ready" in capsys.readouterr().out


def test_store_init_without_a_configured_store_exits_2(capsys):
    assert cli.main(["store", "init"], memory=None) == 2
    assert "SAFESC_PGVECTOR_DSN" in capsys.readouterr().err


def test_fingerprint_load_ingests_the_repo_corpus(capsys):
    vector = _FakeVector()
    memory = _FakeMemory(vector=vector, embedder=lambda texts: [[1.0] for _ in texts])
    assert cli.main(["fingerprint", "load", "fingerprints"], memory=memory) == 0
    assert vector.rows and all(k.startswith("fingerprint:") for k in vector.rows)
    assert "ingested" in capsys.readouterr().out


def test_fingerprint_load_requires_an_embedder(capsys):
    assert cli.main(["fingerprint", "load", "fingerprints"], memory=_FakeMemory(vector=_FakeVector())) == 2
    assert "SAFESC_EMBEDDING_API_KEY" in capsys.readouterr().err


def test_fingerprint_load_reports_a_bad_path(capsys):
    memory = _FakeMemory(vector=_FakeVector(), embedder=lambda texts: [[1.0] for _ in texts])
    assert cli.main(["fingerprint", "load", "no/such/dir"], memory=memory) == 2
    assert "fingerprint:" in capsys.readouterr().err


def test_maintenance_jobs_need_no_llm_key(monkeypatch):
    """gc / store init / fingerprint load touch only the stores, so requiring a reasoning
    key would force an operator to hold one just to run a CronJob."""
    monkeypatch.delenv("SAFESC_LLM_API_KEY", raising=False)
    monkeypatch.delenv("SAFESC_LLM_PROVIDER", raising=False)
    assert cli.main(["store", "init"], memory=_FakeMemory(vector=_FakeVector())) == 0


# ============================================================ Redis-only memory


class _KVRedis:
    """Just the `get`/`set` surface the MemoryManager exact-hash path uses."""

    def __init__(self):
        self.kv: dict[str, str] = {}

    def ping(self):
        return True

    def checkpointer(self):
        return "CHECKPOINTER"

    def cache_get(self, key):
        return None

    def cache_set(self, key, value, ttl=None):
        pass

    def get(self, name):
        return self.kv.get(name)

    def set(self, name, value, ex=None):
        self.kv[name] = value


def test_redis_only_gives_exact_hash_recall_without_any_embedding_key(monkeypatch, _no_store_env):
    """The cheapest useful configuration: cross-run verdict recall with one store and no
    second API key. Only *similarity* search needs pgvector."""
    from pathlib import Path

    from safesc.graph.state import AuditState, Dependency, GateDecision, Severity, dep_key

    redis = _KVRedis()
    monkeypatch.setenv("SAFESC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setattr(
        "safesc.memory.short_term.ShortTermStore.from_url", classmethod(lambda cls, cfg=None: redis)
    )
    memory = bootstrap.select_runtime().memory

    dep = Dependency(
        name="evil", version="1.0.0", ecosystem="npm",
        lockfile_path=Path("package-lock.json"), hash="sha256:abc",
    )
    state = AuditState(target=".", dependencies=[dep])
    gate = GateDecision(per_dep={dep_key(dep): Severity.HIGH}, overall=Severity.HIGH,
                        passed=False, exit_code=1)
    report = memory.persist(state, gate)
    assert report.written and not report.anomalies

    from safesc.graph.spine import SpecialistTask
    from safesc.graph.state import TrustDimension

    task = SpecialistTask(
        dep_key=dep_key(dep), dependency=dep, dimension=TrustDimension.BEHAVIOR,
        trigger_severity=Severity.HIGH,
    )
    findings = memory.make_task_lookup()(dep_key(dep), task=task)
    assert any("exact-hash prior" in f for f in findings)


def test_redis_only_audit_does_not_demand_an_embedding_key(monkeypatch, capsys):
    """Regression: `require_embedding` follows the *vector* store, not the mere presence
    of a MemoryManager — otherwise Redis-only would be unusable."""
    monkeypatch.setenv("SAFESC_LLM_API_KEY", "byok-secret")
    monkeypatch.setenv("SAFESC_LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("SAFESC_EMBEDDING_API_KEY", raising=False)
    monkeypatch.setattr(cli.graph_build, "run", lambda *a, **k: _fake_result())

    from safesc.graph.harness.memory_manager import MemoryManager

    rc = cli.main(
        ["audit", "."], tools=object(), session=object(),
        memory=MemoryManager(redis=_KVRedis()),
    )
    assert rc == 0
    assert "SAFESC_EMBEDDING_API_KEY" not in capsys.readouterr().err


def test_pgvector_tier_still_requires_an_embedding_key(monkeypatch, capsys):
    monkeypatch.setenv("SAFESC_LLM_API_KEY", "byok-secret")
    monkeypatch.setenv("SAFESC_LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("SAFESC_EMBEDDING_API_KEY", raising=False)

    from safesc.graph.harness.memory_manager import MemoryManager

    rc = cli.main(
        ["audit", "."], tools=object(), session=object(),
        memory=MemoryManager(redis=_KVRedis(), vector=_FakeVector()),
    )
    assert rc == 2
    assert "SAFESC_EMBEDDING_API_KEY" in capsys.readouterr().err
