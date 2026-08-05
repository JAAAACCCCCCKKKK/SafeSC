"""Unit tests for Stage 3: cheap signal collection (SafeSC.signals).

All network calls are mocked via unittest.mock — no real HTTP requests.
Async tests run under pytest-asyncio (asyncio_mode = "auto").
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.index import Dependency
from tools.scan.signals.base import SignalCollector
from tools.scan.signals.collector import collect_all, default_collectors
from tools.scan.signals.identity.repo_url import RepoUrlCollector
from tools.scan.signals.identity.typosquat import (
    TyposquatCollector,
    bounded_levenshtein,
)
from tools.scan.signals.models import (
    Dimension,
    Severity,
    Signal,
    Spoofability,
    max_severity,
)
from tools.scan.signals.registry_meta import (
    RegistryMetadata,
    _normalise_repo_url,
    get_package_metadata,
    get_registry_metadata,
)
from tools.scan.signals.vulnerability.osv import OsvCollector, _severity_for_vuln


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dep(
    name: str = "mypkg",
    version: str = "1.0.0",
    ecosystem: str = "python",
    source_url: str | None = None,
) -> Dependency:
    return Dependency(
        name=name,
        version=version,
        ecosystem=ecosystem,
        lockfile_path=Path("fake.lock"),
        source_url=source_url,
        is_direct=True,
        layer_number=1,
    )


# ---------------------------------------------------------------------------
# Severity / Signal model
# ---------------------------------------------------------------------------

class TestSeverityModel:
    def test_rank_is_ordered(self):
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        ranks = [s.rank for s in order]
        assert ranks == sorted(ranks)
        assert ranks == [0, 1, 2, 3, 4]

    def test_max_severity_picks_highest(self):
        assert max_severity([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) == Severity.CRITICAL

    def test_max_severity_empty_is_info(self):
        assert max_severity([]) == Severity.INFO


class TestSignalModel:
    def test_to_dict_shape(self):
        sig = Signal(
            dep=_dep(),
            dimension=Dimension.IDENTITY,
            code="identity.typosquat",
            severity=Severity.CRITICAL,
            message="msg",
            evidence=["a"],
            spoofability=Spoofability.LOW,
            false_positive_hints=["hint"],
        )
        d = sig.to_dict()
        assert set(d.keys()) == {
            "name", "version", "ecosystem",
            "dimension", "code", "severity", "message",
            "evidence", "spoofability", "false_positive_hints",
        }
        assert d["dimension"] == "identity"
        assert d["severity"] == "critical"
        assert d["spoofability"] == "low"

    def test_severity_reexported_in_provenance(self):
        # Stage 2 must keep importing the same Severity object.
        from tools.scan.signals.provenance.models import Severity as ProvSeverity

        assert ProvSeverity is Severity


# ---------------------------------------------------------------------------
# bounded_levenshtein
# ---------------------------------------------------------------------------

class TestBoundedLevenshtein:
    def test_identical(self):
        assert bounded_levenshtein("abc", "abc", 2) == 0

    def test_single_insertion(self):
        assert bounded_levenshtein("numpy", "numpyy", 2) == 1

    def test_single_substitution(self):
        assert bounded_levenshtein("requests", "ruquests", 2) == 1

    def test_transposition_is_two(self):
        assert bounded_levenshtein("lodash", "lodahs", 2) == 2

    def test_far_apart_returns_cap_plus_one(self):
        assert bounded_levenshtein("requests", "tensorflow", 2) == 3

    def test_length_gap_shortcut(self):
        # Length difference alone exceeds the cap.
        assert bounded_levenshtein("ab", "abcdef", 2) == 3


# ---------------------------------------------------------------------------
# TyposquatCollector
# ---------------------------------------------------------------------------

class TestTyposquatCollector:
    def setup_method(self):
        self.c = TyposquatCollector()

    def test_dimension(self):
        assert self.c.dimension == Dimension.IDENTITY

    async def test_near_miss_flags_medium(self):
        # Capped at MEDIUM (below the CI/HIGH gate) so the near-miss is routed to
        # the IdentityAgent for LLM verification rather than gating on its own.
        sigs = await self.c.collect(_dep("reqeusts"), None)
        assert len(sigs) == 1
        assert sigs[0].code == "identity.typosquat"
        assert sigs[0].severity == Severity.MEDIUM
        # MEDIUM sits below HIGH in the ordered severity ladder (string enum, so
        # order is via .rank, not <): it must not gate CI on its own.
        assert sigs[0].severity.rank < Severity.HIGH.rank
        assert sigs[0].spoofability == Spoofability.LOW

    async def test_exact_popular_name_no_signal(self):
        assert await self.c.collect(_dep("requests"), None) == []

    async def test_canonical_equivalence_no_signal(self):
        # Separator-only difference is the same package, not a typosquat.
        assert await self.c.collect(_dep("charset_normalizer"), None) == []

    async def test_unrelated_name_no_signal(self):
        assert await self.c.collect(_dep("totally-unique-xyz"), None) == []

    async def test_short_name_no_signal(self):
        assert await self.c.collect(_dep("ab"), None) == []

    async def test_unsupported_ecosystem_no_signal(self):
        assert await self.c.collect(_dep("reqeusts", ecosystem="go"), None) == []

    async def test_javascript_near_miss(self):
        sigs = await self.c.collect(_dep("expres", ecosystem="javascript"), None)
        assert len(sigs) == 1
        assert "express" in sigs[0].message

    async def test_evidence_records_nearest_and_distance(self):
        sigs = await self.c.collect(_dep("numpyy"), None)
        ev = sigs[0].evidence
        assert "nearest_popular=numpy" in ev
        assert "edit_distance=1" in ev

    @pytest.mark.parametrize(
        "name, ecosystem, nearest",
        [
            ("serde_jsom", "rust", "serde_json"),
            ("github.com/pkg/errros", "go", "github.com/pkg/errors"),
            ("com.google.guava:guavaa", "java", "com.google.guava:guava"),
        ],
    )
    async def test_near_miss_per_ecosystem(self, name, ecosystem, nearest):
        sigs = await self.c.collect(_dep(name, ecosystem=ecosystem), None)
        assert len(sigs) == 1
        assert sigs[0].severity == Severity.MEDIUM
        assert f"nearest_popular={nearest}" in sigs[0].evidence

    @pytest.mark.parametrize(
        "name, ecosystem",
        [
            ("serde_json", "rust"),
            ("github.com/pkg/errors", "go"),
            ("com.google.guava:guava", "java"),
        ],
    )
    async def test_exact_match_per_ecosystem_no_signal(self, name, ecosystem):
        assert await self.c.collect(_dep(name, ecosystem=ecosystem), None) == []


class TestPopularPackages:
    def test_covers_all_default_ecosystems(self):
        from tools.scan.signals.identity.popular_packages import POPULAR_BY_ECOSYSTEM

        # Must match the ecosystem names produced by the adapters.
        assert set(POPULAR_BY_ECOSYSTEM) == {
            "python", "javascript", "rust", "go", "java",
        }

    def test_each_list_has_at_least_100(self):
        from tools.scan.signals.identity.popular_packages import POPULAR_BY_ECOSYSTEM

        assert all(len(names) >= 100 for names in POPULAR_BY_ECOSYSTEM.values())


# ---------------------------------------------------------------------------
# registry_meta
# ---------------------------------------------------------------------------

class TestNormaliseRepoUrl:
    def test_none(self):
        assert _normalise_repo_url(None) is None

    def test_plain_https(self):
        assert _normalise_repo_url("https://github.com/a/b") == "https://github.com/a/b"

    def test_strips_git_plus_and_dot_git(self):
        assert _normalise_repo_url("git+https://github.com/a/b.git") == "https://github.com/a/b"

    def test_git_protocol(self):
        assert _normalise_repo_url("git://github.com/a/b.git") == "https://github.com/a/b"

    def test_scp_style(self):
        assert _normalise_repo_url("git@github.com:a/b.git") == "https://github.com/a/b"

    def test_non_url_returns_none(self):
        assert _normalise_repo_url("not a url") is None


class TestRegistryMetadata:
    async def test_pypi_prefers_source_key(self):
        from tools.scan.signals.registry_meta import _pypi_metadata

        data = {"info": {"project_urls": {"Source": "https://github.com/psf/requests"}}}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _pypi_metadata(_dep(), session)
        assert meta.repo_url == "https://github.com/psf/requests"

    async def test_pypi_forge_fallback_from_homepage(self):
        from tools.scan.signals.registry_meta import _pypi_metadata

        data = {"info": {"project_urls": {}, "home_page": "https://github.com/a/b"}}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _pypi_metadata(_dep(), session)
        assert meta.repo_url == "https://github.com/a/b"

    async def test_pypi_no_repo_returns_metadata_with_none(self):
        from tools.scan.signals.registry_meta import _pypi_metadata

        data = {"info": {"project_urls": {"Docs": "https://example.com/docs"}}}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _pypi_metadata(_dep(), session)
        assert meta.repo_url is None

    async def test_npm_repository_object(self):
        from tools.scan.signals.registry_meta import _npm_metadata

        data = {"repository": {"url": "git+https://github.com/a/b.git"}}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _npm_metadata(_dep(ecosystem="javascript"), session)
        assert meta.repo_url == "https://github.com/a/b"

    async def test_npm_repository_string(self):
        from tools.scan.signals.registry_meta import _npm_metadata

        data = {"repository": "https://github.com/a/b"}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _npm_metadata(_dep(ecosystem="javascript"), session)
        assert meta.repo_url == "https://github.com/a/b"

    async def test_dispatch_unsupported_ecosystem_none(self):
        session = MagicMock()
        assert await get_registry_metadata(_dep(ecosystem="go"), session) is None

    async def test_dispatch_registry_unavailable_none(self):
        session = MagicMock()
        session.get_json = AsyncMock(return_value=None)
        meta = await get_registry_metadata(_dep(), session)
        assert meta is None


# ---------------------------------------------------------------------------
# RepoUrlCollector
# ---------------------------------------------------------------------------

class TestRepoUrlCollector:
    def setup_method(self):
        self.c = RepoUrlCollector()

    def test_dimension(self):
        assert self.c.dimension == Dimension.IDENTITY

    async def _collect_with(self, meta, exists):
        session = MagicMock()
        session.url_exists = AsyncMock(return_value=exists)
        with patch(
            "tools.scan.signals.identity.repo_url.get_registry_metadata",
            new=AsyncMock(return_value=meta),
        ):
            return await self.c.collect(_dep(), session)

    async def test_dead_url_flags_high(self):
        sigs = await self._collect_with(RegistryMetadata("https://github.com/a/gone"), exists=False)
        assert len(sigs) == 1
        assert sigs[0].code == "identity.repo_url_missing"
        assert sigs[0].severity == Severity.HIGH

    async def test_live_url_no_signal(self):
        assert await self._collect_with(RegistryMetadata("https://github.com/a/b"), exists=True) == []

    async def test_indeterminate_no_signal(self):
        # url_exists returns None on transient errors -> never a false positive.
        assert await self._collect_with(RegistryMetadata("https://github.com/a/b"), exists=None) == []

    async def test_no_metadata_no_signal(self):
        assert await self._collect_with(None, exists=False) == []

    async def test_no_repo_url_no_signal(self):
        assert await self._collect_with(RegistryMetadata(repo_url=None), exists=False) == []


# ---------------------------------------------------------------------------
# OSV severity mapping + collector
# ---------------------------------------------------------------------------

class TestOsvSeverityMapping:
    def test_database_specific_label(self):
        assert _severity_for_vuln({"database_specific": {"severity": "CRITICAL"}}) == Severity.CRITICAL
        assert _severity_for_vuln({"database_specific": {"severity": "high"}}) == Severity.HIGH
        assert _severity_for_vuln({"database_specific": {"severity": "MODERATE"}}) == Severity.MEDIUM
        assert _severity_for_vuln({"database_specific": {"severity": "LOW"}}) == Severity.LOW

    def test_cvss_numeric_score(self):
        assert _severity_for_vuln({"severity": [{"score": "9.8"}]}) == Severity.CRITICAL
        assert _severity_for_vuln({"severity": [{"score": "7.5"}]}) == Severity.HIGH
        assert _severity_for_vuln({"severity": [{"score": "5.0"}]}) == Severity.MEDIUM
        assert _severity_for_vuln({"severity": [{"score": "2.0"}]}) == Severity.LOW

    def test_unknown_defaults_to_medium(self):
        assert _severity_for_vuln({"id": "OSV-x"}) == Severity.MEDIUM

    def test_cvss_v3_vector_is_scored(self):
        # OSV ships a CVSS *vector*, not a number — it must be computed, not defaulted.
        crit = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        assert _severity_for_vuln(crit) == Severity.CRITICAL
        high = {"severity": [{"score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"}]}  # 7.4
        assert _severity_for_vuln(high) == Severity.HIGH
        med = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}]}   # 5.3
        assert _severity_for_vuln(med) == Severity.MEDIUM
        low = {"severity": [{"score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]}
        assert _severity_for_vuln(low) == Severity.LOW

    def test_label_less_critical_not_undergraded(self):
        # Regression: a label-less high-impact advisory (common for PYSEC records) must not
        # silently drop to MEDIUM — under-grading a critical CVE is the worst failure here.
        vuln = {"id": "PYSEC-x", "severity": [{"type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]}  # 10.0
        assert _severity_for_vuln(vuln) == Severity.CRITICAL

    def test_takes_max_of_multiple_vectors(self):
        vuln = {"severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},  # low
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},  # 9.8
        ]}
        assert _severity_for_vuln(vuln) == Severity.CRITICAL

    def test_uncomputable_v4_vector_defaults_medium(self):
        # No label, and a CVSS v4.0 vector we don't compute → fall back to MEDIUM.
        v4 = {"severity": [{"type": "CVSS_V4",
              "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}]}
        assert _severity_for_vuln(v4) == Severity.MEDIUM

    def test_incomplete_vector_defaults_medium(self):
        # A truncated/invalid vector cannot be scored → MEDIUM fallback (not a crash).
        assert _severity_for_vuln({"severity": [{"score": "CVSS:3.1/AV:N/AC:L"}]}) == Severity.MEDIUM

    def test_label_preferred_over_cvss(self):
        # An explicit curated label wins over the vector (documented behaviour).
        vuln = {"database_specific": {"severity": "HIGH"},
                "severity": [{"score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]}
        assert _severity_for_vuln(vuln) == Severity.HIGH


class TestOsvCollector:
    def setup_method(self):
        self.c = OsvCollector()

    def test_dimension(self):
        assert self.c.dimension == Dimension.VULNERABILITY

    async def _collect(self, response, dep=None):
        session = MagicMock()
        session.post_json = AsyncMock(return_value=response)
        return await self.c.collect(dep or _dep(), session)

    async def test_no_vulns_no_signal(self):
        assert await self._collect({"vulns": []}) == []

    async def test_empty_response_no_signal(self):
        assert await self._collect({}) == []

    async def test_none_response_no_signal(self):
        assert await self._collect(None) == []

    async def test_withdrawn_advisories_are_ignored(self):
        # A retracted advisory must not flag the dependency.
        only_withdrawn = {"vulns": [
            {"id": "OSV-w", "withdrawn": "2024-01-01T00:00:00Z",
             "database_specific": {"severity": "CRITICAL"}},
        ]}
        assert await self._collect(only_withdrawn) == []

    async def test_withdrawn_excluded_from_severity(self):
        mixed = {"vulns": [
            {"id": "OSV-live", "database_specific": {"severity": "LOW"}},
            {"id": "OSV-gone", "withdrawn": "2024-01-01T00:00:00Z",
             "database_specific": {"severity": "CRITICAL"}},
        ]}
        sigs = await self._collect(mixed)
        assert len(sigs) == 1
        assert sigs[0].severity == Severity.LOW
        assert not any("OSV-gone" in e for e in sigs[0].evidence)

    async def test_vulns_produce_single_signal_with_max_severity(self):
        response = {
            "vulns": [
                {"id": "OSV-1", "database_specific": {"severity": "LOW"}},
                {"id": "OSV-2", "database_specific": {"severity": "CRITICAL"}},
            ]
        }
        sigs = await self._collect(response)
        assert len(sigs) == 1
        sig = sigs[0]
        assert sig.code == "vulnerability.osv"
        assert sig.severity == Severity.CRITICAL
        assert sig.spoofability == Spoofability.LOW
        assert any("OSV-1" in e for e in sig.evidence)
        assert any("OSV-2" in e for e in sig.evidence)

    async def test_unsupported_ecosystem_no_query(self):
        session = MagicMock()
        session.post_json = AsyncMock(return_value={"vulns": [{"id": "x"}]})
        sigs = await self.c.collect(_dep(ecosystem="elixir"), session)
        assert sigs == []
        session.post_json.assert_not_called()

    async def test_query_payload_uses_osv_ecosystem_name(self):
        session = MagicMock()
        session.post_json = AsyncMock(return_value={"vulns": []})
        await self.c.collect(_dep(ecosystem="python"), session)
        payload = session.post_json.call_args[0][1]
        assert payload["package"]["ecosystem"] == "PyPI"
        assert payload["version"] == "1.0.0"


# ---------------------------------------------------------------------------
# Orchestrator (collect_all)
# ---------------------------------------------------------------------------

class _DummyCollector(SignalCollector):
    @property
    def dimension(self) -> Dimension:
        return Dimension.IDENTITY

    async def collect(self, dep, session):
        return [
            Signal(
                dep=dep,
                dimension=Dimension.IDENTITY,
                code="test.dummy",
                severity=Severity.LOW,
                message="dummy",
            )
        ]


class _RaisingCollector(SignalCollector):
    @property
    def dimension(self) -> Dimension:
        return Dimension.BEHAVIOR

    async def collect(self, dep, session):
        raise RuntimeError("boom")


class TestCollectAll:
    async def test_empty_deps_returns_empty(self):
        assert await collect_all([], collectors=[_DummyCollector()]) == []

    async def test_runs_all_collectors_over_all_deps(self):
        deps = [_dep("a"), _dep("b")]
        sigs = await collect_all(deps, collectors=[_DummyCollector()])
        assert len(sigs) == 2
        assert {s.dep.name for s in sigs} == {"a", "b"}

    async def test_failing_collector_is_isolated(self):
        deps = [_dep("a")]
        sigs = await collect_all(deps, collectors=[_DummyCollector(), _RaisingCollector()])
        # Dummy still produced its signal; the raising one degraded to nothing.
        assert len(sigs) == 1
        assert sigs[0].code == "test.dummy"

    async def test_no_collectors_returns_empty(self):
        assert await collect_all([_dep("a")], collectors=[]) == []

    def test_default_collectors_set(self):
        codes = {type(c).__name__ for c in default_collectors()}
        assert codes == {
            "TyposquatCollector",
            "HomoglyphCollector",
            "RepoUrlCollector",
            "InstallScriptCollector",
            "VersionPublishedCollector",
            "InsecureUrlCollector",
            "ArchivedRepoCollector",
            "OsvCollector",
            "YankedVersionCollector",
        }

    def test_default_collectors_cover_all_dimensions(self):
        dims = {c.dimension for c in default_collectors()}
        assert dims == set(Dimension)


# ---------------------------------------------------------------------------
# HomoglyphCollector (Identity, local)
# ---------------------------------------------------------------------------

class TestHomoglyphCollector:
    def setup_method(self):
        from tools.scan.signals.identity import HomoglyphCollector

        self.c = HomoglyphCollector()

    def test_dimension(self):
        assert self.c.dimension == Dimension.IDENTITY

    async def test_ascii_name_no_signal(self):
        assert await self.c.collect(_dep("requests"), None) == []

    async def test_cyrillic_homoglyph_flags_high(self):
        # "rаts" with a Cyrillic 'а' (U+0430).
        sigs = await self.c.collect(_dep("r\u0430ts"), None)
        assert len(sigs) == 1
        assert sigs[0].code == "identity.non_ascii_name"
        assert sigs[0].severity == Severity.HIGH
        assert sigs[0].spoofability == Spoofability.LOW
        assert any("U+0430" in e for e in sigs[0].evidence)

    async def test_deduplicates_repeated_char(self):
        sigs = await self.c.collect(_dep("\u0430\u0430bc"), None)
        assert len(sigs) == 1
        assert len(sigs[0].evidence) == 1


# ---------------------------------------------------------------------------
# InsecureUrlCollector (Provenance, local)
# ---------------------------------------------------------------------------

class TestInsecureUrlCollector:
    def setup_method(self):
        from tools.scan import InsecureUrlCollector

        self.c = InsecureUrlCollector()

    def test_dimension(self):
        assert self.c.dimension == Dimension.PROVENANCE

    async def test_http_flags_medium(self):
        sigs = await self.c.collect(_dep(source_url="http://mirror/x.tgz"), None)
        assert len(sigs) == 1
        assert sigs[0].code == "provenance.insecure_source_url"
        assert sigs[0].severity == Severity.MEDIUM

    async def test_https_no_signal(self):
        assert await self.c.collect(_dep(source_url="https://mirror/x.tgz"), None) == []

    async def test_no_url_no_signal(self):
        assert await self.c.collect(_dep(source_url=None), None) == []

    async def test_https_prefix_not_confused_with_http(self):
        # Guard against a naive startswith("http") matching https.
        assert await self.c.collect(_dep(source_url="https://h/x"), None) == []


# ---------------------------------------------------------------------------
# InstallScriptCollector (Behavior, npm metadata)
# ---------------------------------------------------------------------------

class TestInstallScriptCollector:
    def setup_method(self):
        from tools.scan.signals.behavior.install_script import InstallScriptCollector

        self.c = InstallScriptCollector()

    def test_dimension(self):
        assert self.c.dimension == Dimension.BEHAVIOR

    def _patch_meta(self, meta):
        from tools.scan.signals.registry_meta import PackageMetadata  # noqa: F401

        return patch(
            "tools.scan.signals.behavior.install_script.get_package_metadata",
            new=AsyncMock(return_value=meta),
        )

    async def test_install_script_flags_high(self):
        from tools.scan.signals.registry_meta import PackageMetadata

        meta = PackageMetadata(has_install_script=True)
        with self._patch_meta(meta):
            sigs = await self.c.collect(_dep(ecosystem="javascript"), MagicMock())
        assert len(sigs) == 1
        assert sigs[0].code == "behavior.install_script"
        assert sigs[0].severity == Severity.HIGH

    async def test_no_install_script_no_signal(self):
        from tools.scan.signals.registry_meta import PackageMetadata

        with self._patch_meta(PackageMetadata(has_install_script=False)):
            sigs = await self.c.collect(_dep(ecosystem="javascript"), MagicMock())
        assert sigs == []

    async def test_unsupported_ecosystem_no_metadata_call(self):
        with patch(
            "tools.scan.signals.behavior.install_script.get_package_metadata",
            new=AsyncMock(return_value=None),
        ) as m:
            sigs = await self.c.collect(_dep(ecosystem="python"), MagicMock())
        assert sigs == []
        m.assert_not_called()

    async def test_metadata_unavailable_no_signal(self):
        with self._patch_meta(None):
            sigs = await self.c.collect(_dep(ecosystem="javascript"), MagicMock())
        assert sigs == []


# ---------------------------------------------------------------------------
# VersionPublishedCollector (Provenance, metadata)
# ---------------------------------------------------------------------------

class TestVersionPublishedCollector:
    def setup_method(self):
        from tools.scan.signals.provenance.version_published import (
            VersionPublishedCollector,
        )

        self.c = VersionPublishedCollector()

    def test_dimension(self):
        assert self.c.dimension == Dimension.PROVENANCE

    def _patch_meta(self, meta):
        return patch(
            "tools.scan.signals.provenance.version_published.get_package_metadata",
            new=AsyncMock(return_value=meta),
        )

    async def test_absent_version_flags_high(self):
        from tools.scan.signals.registry_meta import PackageMetadata

        meta = PackageMetadata(
            published_versions=frozenset({"1.0.1", "1.0.2"}),
            version_present=False,
        )
        with self._patch_meta(meta):
            sigs = await self.c.collect(_dep(version="1.0.0"), MagicMock())
        assert len(sigs) == 1
        assert sigs[0].code == "provenance.version_not_published"
        assert sigs[0].severity == Severity.HIGH

    async def test_present_version_no_signal(self):
        from tools.scan.signals.registry_meta import PackageMetadata

        meta = PackageMetadata(
            published_versions=frozenset({"1.0.0"}),
            version_present=True,
        )
        with self._patch_meta(meta):
            assert await self.c.collect(_dep(version="1.0.0"), MagicMock()) == []

    async def test_empty_published_set_no_signal(self):
        from tools.scan.signals.registry_meta import PackageMetadata

        # No authoritative list -> cannot conclude absence.
        meta = PackageMetadata(published_versions=frozenset(), version_present=False)
        with self._patch_meta(meta):
            assert await self.c.collect(_dep(version="1.0.0"), MagicMock()) == []

    async def test_metadata_unavailable_no_signal(self):
        with self._patch_meta(None):
            assert await self.c.collect(_dep(), MagicMock()) == []


# ---------------------------------------------------------------------------
# YankedVersionCollector (Vulnerability, metadata)
# ---------------------------------------------------------------------------

class TestYankedVersionCollector:
    def setup_method(self):
        from tools.scan.signals.vulnerability.yanked import YankedVersionCollector

        self.c = YankedVersionCollector()

    def test_dimension(self):
        assert self.c.dimension == Dimension.VULNERABILITY

    def _patch_meta(self, meta):
        return patch(
            "tools.scan.signals.vulnerability.yanked.get_package_metadata",
            new=AsyncMock(return_value=meta),
        )

    async def test_yanked_flags_medium(self):
        from tools.scan.signals.registry_meta import PackageMetadata

        with self._patch_meta(PackageMetadata(version_yanked=True)):
            sigs = await self.c.collect(_dep(), MagicMock())
        assert len(sigs) == 1
        assert sigs[0].code == "vulnerability.yanked_version"
        assert sigs[0].severity == Severity.MEDIUM

    async def test_not_yanked_no_signal(self):
        from tools.scan.signals.registry_meta import PackageMetadata

        with self._patch_meta(PackageMetadata(version_yanked=False)):
            assert await self.c.collect(_dep(), MagicMock()) == []

    async def test_metadata_unavailable_no_signal(self):
        with self._patch_meta(None):
            assert await self.c.collect(_dep(), MagicMock()) == []


# ---------------------------------------------------------------------------
# ArchivedRepoCollector (Popularity, GitHub)
# ---------------------------------------------------------------------------

class TestArchivedRepoCollector:
    def setup_method(self):
        from tools.scan.signals.popularity.archived import ArchivedRepoCollector

        self.c = ArchivedRepoCollector()

    def test_dimension(self):
        assert self.c.dimension == Dimension.POPULARITY

    def _patch(self, meta, repo):
        return (
            patch(
                "tools.scan.signals.popularity.archived.get_registry_metadata",
                new=AsyncMock(return_value=meta),
            ),
            patch(
                "tools.scan.signals.popularity.archived.get_repo",
                new=AsyncMock(return_value=repo),
            ),
        )

    async def test_archived_flags_high(self):
        from tools.scan.signals.github import GitHubRepo

        repo = GitHubRepo(owner="a", repo="b", archived=True, stars=5)
        p_meta, p_repo = self._patch(RegistryMetadata("https://github.com/a/b"), repo)
        with p_meta, p_repo:
            sigs = await self.c.collect(_dep(), MagicMock())
        assert len(sigs) == 1
        assert sigs[0].code == "popularity.repo_archived"
        assert sigs[0].severity == Severity.HIGH

    async def test_active_repo_no_signal(self):
        from tools.scan.signals.github import GitHubRepo

        repo = GitHubRepo(owner="a", repo="b", archived=False, stars=100)
        p_meta, p_repo = self._patch(RegistryMetadata("https://github.com/a/b"), repo)
        with p_meta, p_repo:
            assert await self.c.collect(_dep(), MagicMock()) == []

    async def test_no_repo_url_no_signal(self):
        p_meta, p_repo = self._patch(RegistryMetadata(repo_url=None), None)
        with p_meta, p_repo:
            assert await self.c.collect(_dep(), MagicMock()) == []

    async def test_non_github_repo_no_signal(self):
        # get_repo returns None for non-GitHub hosts.
        p_meta, p_repo = self._patch(RegistryMetadata("https://gitlab.com/a/b"), None)
        with p_meta, p_repo:
            assert await self.c.collect(_dep(), MagicMock()) == []


# ---------------------------------------------------------------------------
# GitHub helper
# ---------------------------------------------------------------------------

class TestGitHubHelper:
    def test_parse_slug_basic(self):
        from tools.scan.signals.github import parse_repo_slug

        assert parse_repo_slug("https://github.com/psf/requests") == ("psf", "requests")

    def test_parse_slug_strips_dot_git_and_extra_path(self):
        from tools.scan.signals.github import parse_repo_slug

        assert parse_repo_slug("https://github.com/a/b.git") == ("a", "b")
        assert parse_repo_slug("https://github.com/a/b/tree/main") == ("a", "b")

    def test_parse_slug_non_github_none(self):
        from tools.scan.signals.github import parse_repo_slug

        assert parse_repo_slug("https://gitlab.com/a/b") is None
        assert parse_repo_slug(None) is None

    async def test_get_repo_maps_fields(self):
        from tools.scan.signals.github import get_repo

        session = MagicMock()
        session.get_json = AsyncMock(
            return_value={"archived": True, "stargazers_count": 42, "pushed_at": "x"}
        )
        repo = await get_repo("https://github.com/a/b", session)
        assert repo.archived is True
        assert repo.stars == 42

    async def test_get_repo_non_github_none(self):
        from tools.scan.signals.github import get_repo

        session = MagicMock()
        session.get_json = AsyncMock(return_value={"archived": True})
        assert await get_repo("https://example.com/a/b", session) is None


# ---------------------------------------------------------------------------
# Enriched registry metadata (package-level)
# ---------------------------------------------------------------------------

class TestPackageMetadata:
    async def test_pypi_published_and_yanked(self):
        from tools.scan.signals.registry_meta import _pypi_package_metadata

        data = {
            "releases": {
                "1.0.0": [{"yanked": False}],
                "1.0.1": [{"yanked": True}],
                "1.0.2": [{"yanked": True}, {"yanked": True}],
            }
        }
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _pypi_package_metadata(_dep(version="1.0.1"), session)
        assert meta.published_versions == frozenset({"1.0.0", "1.0.1", "1.0.2"})
        assert meta.yanked_versions == frozenset({"1.0.1", "1.0.2"})
        assert meta.version_present is True
        assert meta.version_yanked is True

    async def test_pypi_version_present_is_pep440_normalised(self):
        # Regression: a lockfile may pin an equal-but-non-canonical version. Exact-string
        # matching wrongly reported it absent → false HIGH "version_not_published".
        from tools.scan.signals.registry_meta import _pypi_package_metadata

        data = {"releases": {"2.31.0": [{"yanked": False}], "1.2.3": [{"yanked": True}]}}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        for pin in ("2.31.0", "2.31", "2.31.0.0"):  # all PEP 440-equal to 2.31.0
            meta = await _pypi_package_metadata(_dep(version=pin), session)
            assert meta.version_present is True, pin
        # non-canonical yanked pin is still recognised as yanked
        meta = await _pypi_package_metadata(_dep(version="01.2.3"), session)
        assert meta.version_yanked is True
        # a genuinely absent version is still reported absent (true positive preserved)
        meta = await _pypi_package_metadata(_dep(version="9.9.9"), session)
        assert meta.version_present is False

    def test_pypi_contains_helper(self):
        from tools.scan.signals.registry_meta import _pypi_contains

        pub = frozenset({"2.31.0", "1.0"})
        assert _pypi_contains(pub, "2.31.0") is True
        assert _pypi_contains(pub, "2.31") is True        # normalised match
        assert _pypi_contains(pub, "1.0.0") is True        # trailing-zero match
        assert _pypi_contains(pub, "3.0") is False         # genuinely absent
        assert _pypi_contains(pub, "not-a-version") is False  # unparseable → absent

    async def test_npm_install_script_detection(self):
        from tools.scan.signals.registry_meta import _npm_package_metadata

        data = {
            "versions": {
                "1.0.0": {"hasInstallScript": True},
            }
        }
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _npm_package_metadata(_dep(version="1.0.0", ecosystem="javascript"), session)
        assert meta.has_install_script is True
        assert meta.version_present is True

    async def test_npm_install_script_via_scripts_field(self):
        from tools.scan.signals.registry_meta import _npm_package_metadata

        data = {"versions": {"1.0.0": {"scripts": {"postinstall": "node x.js"}}}}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _npm_package_metadata(_dep(version="1.0.0", ecosystem="javascript"), session)
        assert meta.has_install_script is True

    async def test_crates_yanked(self):
        from tools.scan.signals.registry_meta import _crates_package_metadata

        data = {
            "versions": [
                {"num": "1.0.0", "yanked": False},
                {"num": "1.0.1", "yanked": True},
            ]
        }
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _crates_package_metadata(_dep(version="1.0.1", ecosystem="rust"), session)
        assert meta.version_yanked is True
        assert meta.version_present is True

    async def test_get_package_metadata_unsupported_none(self):
        session = MagicMock()
        assert await get_package_metadata(_dep(ecosystem="go"), session) is None

    async def test_pypi_identity_fields_populated(self):
        from tools.scan.signals.registry_meta import _pypi_package_metadata

        data = {
            "info": {
                "author": "Redis Inc.",
                "summary": "Redis Vector Library",
                "home_page": "https://docs.redisvl.com",
                "project_urls": {"Source": "https://github.com/redis/redis-vl-python"},
            },
            "releases": {
                "0.1.0": [{"yanked": False, "upload_time_iso_8601": "2023-01-01T00:00:00Z"}],
                "0.25.0": [{"yanked": False, "upload_time_iso_8601": "2026-01-01T00:00:00Z"}],
            },
        }
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _pypi_package_metadata(_dep(version="0.25.0"), session)
        assert meta.author == "Redis Inc."
        assert meta.repo_url == "https://github.com/redis/redis-vl-python"
        assert meta.summary == "Redis Vector Library"
        assert meta.total_releases == 2
        assert meta.first_release_at == "2023-01-01T00:00:00Z"
        assert meta.latest_release_at == "2026-01-01T00:00:00Z"

    async def test_npm_identity_fields_populated(self):
        from tools.scan.signals.registry_meta import _npm_package_metadata

        data = {
            "author": {"name": "Charles Stover"},
            "description": "React global state",
            "homepage": "https://example.com",
            "repository": {"url": "git+https://github.com/CharlesStover/reactn.git"},
            "time": {"created": "2018-01-01T00:00:00Z", "modified": "2024-01-01T00:00:00Z",
                     "2.2.7": "2020-01-01T00:00:00Z"},
            "versions": {"2.2.7": {}},
        }
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _npm_package_metadata(_dep(version="2.2.7", ecosystem="javascript"), session)
        assert meta.author == "Charles Stover"
        assert meta.repo_url == "https://github.com/CharlesStover/reactn"
        assert meta.summary == "React global state"
        assert meta.first_release_at == "2018-01-01T00:00:00Z"
        assert meta.latest_release_at == "2024-01-01T00:00:00Z"

    async def test_crates_identity_fields_populated(self):
        from tools.scan.signals.registry_meta import _crates_package_metadata

        data = {
            "crate": {
                "repository": "https://github.com/RustCrypto/hashes",
                "homepage": "https://rustcrypto.org",
                "description": "SHA-3 hash",
                "created_at": "2017-01-01T00:00:00Z",
                "updated_at": "2026-05-15T00:00:00Z",
            },
            "versions": [
                {"num": "0.10.0", "yanked": False, "created_at": "2020-01-01T00:00:00Z"},
                {"num": "0.10.8", "yanked": False, "created_at": "2023-01-01T00:00:00Z"},
            ],
        }
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        meta = await _crates_package_metadata(_dep(version="0.10.8", ecosystem="rust"), session)
        assert meta.repo_url == "https://github.com/RustCrypto/hashes"
        assert meta.summary == "SHA-3 hash"
        assert meta.total_releases == 2
        assert meta.first_release_at == "2017-01-01T00:00:00Z"
        assert meta.latest_release_at == "2026-05-15T00:00:00Z"


# ---------------------------------------------------------------------------
# Session L1 cache
# ---------------------------------------------------------------------------

class TestSessionCache:
    async def test_get_json_memoised(self):
        from tools.scan.signals.provenance.http import RateLimitedSession

        sess = RateLimitedSession()
        calls = {"n": 0}

        async def fake_uncached(url, *, as_json, headers=None):
            calls["n"] += 1
            return {"v": calls["n"]}

        sess._get_uncached = fake_uncached  # type: ignore[assignment]
        sess._session = MagicMock()  # bypass the context-manager assert

        first = await sess.get_json("https://x/y")
        second = await sess.get_json("https://x/y")
        assert first == second
        assert calls["n"] == 1  # second call served from cache
