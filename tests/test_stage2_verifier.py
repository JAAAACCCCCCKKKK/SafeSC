"""Unit tests for Stage 2: hash verification (SafeSC.signals.provenance).

All network calls are mocked via unittest.mock — no real HTTP requests.
Async tests run under pytest-asyncio (asyncio_mode = "auto").
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from tools.index import Dependency
from tools.scan.signals.provenance.models import (
    HashVerificationResult,
    Severity,
    VerificationStatus,
)
from tools.scan.signals.provenance.verifier import _normalize_hash, _verify_one, verify_all


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dep(
    name: str = "mypkg",
    version: str = "1.0.0",
    ecosystem: str = "python",
    hash_: str | None = "sha256:abc123",
) -> Dependency:
    return Dependency(
        name=name,
        version=version,
        ecosystem=ecosystem,
        lockfile_path=Path("fake.lock"),
        hash=hash_,
        is_direct=True,
        layer_number=1,
    )


def _mock_session(return_value: str | None) -> MagicMock:
    session = MagicMock()
    session.get_json = AsyncMock(return_value=return_value)
    session.get_text = AsyncMock(return_value=return_value)
    return session


# ---------------------------------------------------------------------------
# _normalize_hash
# ---------------------------------------------------------------------------

class TestNormalizeHash:
    def test_sha256_lowercased(self):
        assert _normalize_hash("sha256:ABCDEF") == "sha256:abcdef"

    def test_sha256_already_lower(self):
        assert _normalize_hash("sha256:abcdef") == "sha256:abcdef"

    def test_sri_passthrough(self):
        h = "sha512-abc+DEF/ghi="
        assert _normalize_hash(h) == h

    def test_go_h1_passthrough(self):
        h = "h1:AbCdEfGh="
        assert _normalize_hash(h) == h

    def test_strips_whitespace(self):
        assert _normalize_hash("  sha256:abc  ") == "sha256:abc"


# ---------------------------------------------------------------------------
# _verify_one
# ---------------------------------------------------------------------------

class TestVerifyOne:
    async def test_match(self):
        dep = _dep(hash_="sha256:abc123")
        session = _mock_session(None)

        async def fake_fetch(d, s):
            return "sha256:abc123"

        with patch(
            "tools.scan.signals.provenance.verifier._fetch_registry_hash",
            side_effect=fake_fetch,
        ):
            result = await _verify_one(dep, session)

        assert result.status == VerificationStatus.MATCH
        assert result.severity == Severity.INFO

    async def test_mismatch(self):
        dep = _dep(hash_="sha256:abc123")
        session = _mock_session(None)

        async def fake_fetch(d, s):
            return "sha256:evil999"

        with patch(
            "tools.scan.signals.provenance.verifier._fetch_registry_hash",
            side_effect=fake_fetch,
        ):
            result = await _verify_one(dep, session)

        assert result.status == VerificationStatus.MISMATCH
        assert result.severity == Severity.CRITICAL
        assert "evil999" in result.detail

    async def test_missing_lockfile_hash(self):
        dep = _dep(hash_=None)
        session = _mock_session(None)
        result = await _verify_one(dep, session)
        assert result.status == VerificationStatus.MISSING_LOCKFILE_HASH
        assert result.severity == Severity.LOW
        assert result.lockfile_hash is None

    async def test_registry_unavailable(self):
        dep = _dep(hash_="sha256:abc123")
        session = _mock_session(None)

        async def fake_fetch(d, s):
            return None

        with patch(
            "tools.scan.signals.provenance.verifier._fetch_registry_hash",
            side_effect=fake_fetch,
        ):
            result = await _verify_one(dep, session)

        assert result.status == VerificationStatus.REGISTRY_UNAVAILABLE
        assert result.severity == Severity.INFO

    async def test_case_insensitive_sha256_match(self):
        dep = _dep(hash_="sha256:ABCDEF")
        session = _mock_session(None)

        async def fake_fetch(d, s):
            return "sha256:abcdef"

        with patch(
            "tools.scan.signals.provenance.verifier._fetch_registry_hash",
            side_effect=fake_fetch,
        ):
            result = await _verify_one(dep, session)

        assert result.status == VerificationStatus.MATCH

    async def test_result_to_dict_shape(self):
        dep = _dep(hash_="sha256:abc")
        session = _mock_session(None)

        async def fake_fetch(d, s):
            return "sha256:abc"

        with patch(
            "tools.scan.signals.provenance.verifier._fetch_registry_hash",
            side_effect=fake_fetch,
        ):
            result = await _verify_one(dep, session)

        d = result.to_dict()
        assert set(d.keys()) == {
            "name", "version", "ecosystem",
            "lockfile_hash", "registry_hash",
            "status", "severity", "detail",
        }


# ---------------------------------------------------------------------------
# verify_all
# ---------------------------------------------------------------------------

class TestVerifyAll:
    async def test_returns_one_result_per_dep(self):
        deps = [_dep("pkg_a"), _dep("pkg_b"), _dep("pkg_c")]

        async def fake_fetch(d, s):
            return d.hash

        with patch(
            "tools.scan.signals.provenance.verifier._fetch_registry_hash",
            side_effect=fake_fetch,
        ):
            results = await verify_all(deps)

        assert len(results) == 3

    async def test_order_preserved(self):
        deps = [_dep(f"pkg_{i}", hash_=f"sha256:{i:064x}") for i in range(5)]

        async def fake_fetch(d, s):
            return d.hash

        with patch(
            "tools.scan.signals.provenance.verifier._fetch_registry_hash",
            side_effect=fake_fetch,
        ):
            results = await verify_all(deps)

        assert [r.dep.name for r in results] == [d.name for d in deps]

    async def test_mixed_statuses(self):
        dep_match = _dep("match_pkg", hash_="sha256:aaa")
        dep_miss = _dep("miss_pkg", hash_=None)
        dep_mismatch = _dep("bad_pkg", hash_="sha256:bbb")

        async def fake_fetch(d, s):
            if d.name == "bad_pkg":
                return "sha256:evil"
            if d.name == "match_pkg":
                return "sha256:aaa"
            return None

        with patch(
            "tools.scan.signals.provenance.verifier._fetch_registry_hash",
            side_effect=fake_fetch,
        ):
            results = await verify_all([dep_match, dep_miss, dep_mismatch])

        by_name = {r.dep.name: r for r in results}
        assert by_name["match_pkg"].status == VerificationStatus.MATCH
        assert by_name["miss_pkg"].status == VerificationStatus.MISSING_LOCKFILE_HASH
        assert by_name["bad_pkg"].status == VerificationStatus.MISMATCH

    async def test_empty_deps_list(self):
        results = await verify_all([])
        assert results == []


# ---------------------------------------------------------------------------
# Registry dispatcher: unsupported ecosystem returns None
# ---------------------------------------------------------------------------

class TestRegistryDispatcher:
    async def test_unsupported_ecosystem_returns_none(self):
        from tools.scan import get_registry_hash

        dep = _dep(ecosystem="unknown_lang")
        session = _mock_session(None)

        result = await get_registry_hash(dep, session)
        assert result is None


# ---------------------------------------------------------------------------
# Registry modules: unit-test each adapter with mocked HTTP
# ---------------------------------------------------------------------------

class TestPyPIRegistry:
    async def test_returns_wheel_sha256(self):
        from tools.scan.signals.provenance.registries import pypi

        data = {
            "urls": [
                {
                    "packagetype": "bdist_wheel",
                    "digests": {"sha256": "deadbeef"},
                }
            ]
        }
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        result = await pypi.get_registry_hash(_dep(), session)
        assert result == "sha256:deadbeef"

    async def test_returns_none_on_404(self):
        from tools.scan.signals.provenance.registries import pypi

        session = MagicMock()
        session.get_json = AsyncMock(return_value=None)

        result = await pypi.get_registry_hash(_dep(), session)
        assert result is None

    async def test_prefers_matching_hash(self):
        from tools.scan.signals.provenance.registries import pypi

        dep = _dep(hash_="sha256:matching")
        data = {
            "urls": [
                {"packagetype": "bdist_wheel", "digests": {"sha256": "other"}},
                {"packagetype": "sdist", "digests": {"sha256": "matching"}},
            ]
        }
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        result = await pypi.get_registry_hash(dep, session)
        assert result == "sha256:matching"


class TestNpmRegistry:
    async def test_returns_integrity(self):
        from tools.scan.signals.provenance.registries import npm

        data = {"dist": {"integrity": "sha512-abc123="}}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        result = await npm.get_registry_hash(_dep(ecosystem="javascript"), session)
        assert result == "sha512-abc123="

    async def test_falls_back_to_shasum(self):
        from tools.scan.signals.provenance.registries import npm

        data = {"dist": {"shasum": "abcdef1234567890abcdef1234567890abcdef12"}}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        result = await npm.get_registry_hash(_dep(ecosystem="javascript"), session)
        assert result == "sha1:abcdef1234567890abcdef1234567890abcdef12"

    async def test_scoped_package_url_encoding(self):
        from tools.scan.signals.provenance.registries import npm

        dep = _dep(name="@scope/pkg", ecosystem="javascript")
        session = MagicMock()
        session.get_json = AsyncMock(return_value=None)

        await npm.get_registry_hash(dep, session)
        call_url = session.get_json.call_args[0][0]
        assert "%40" in call_url
        assert "%2F" in call_url


class TestCratesRegistry:
    async def test_returns_checksum(self):
        from tools.scan.signals.provenance.registries import crates

        data = {"version": {"checksum": "deadbeefcafe"}}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        result = await crates.get_registry_hash(_dep(ecosystem="rust"), session)
        assert result == "sha256:deadbeefcafe"

    async def test_no_prefix_added_if_already_prefixed(self):
        from tools.scan.signals.provenance.registries import crates

        data = {"version": {"checksum": "sha256:already"}}
        session = MagicMock()
        session.get_json = AsyncMock(return_value=data)

        result = await crates.get_registry_hash(_dep(ecosystem="rust"), session)
        assert result == "sha256:already"


class TestGoProxyRegistry:
    async def test_returns_h1_hash_from_ziphash(self):
        from tools.scan.signals.provenance.registries import goproxy

        session = MagicMock()
        # ziphash returns the hash; sum.golang.org is not called
        session.get_text = AsyncMock(return_value="h1:abcdef123=\n")

        result = await goproxy.get_registry_hash(_dep(ecosystem="go"), session)
        assert result == "h1:abcdef123="

    async def test_falls_back_to_sum_db_when_ziphash_404(self):
        from tools.scan.signals.provenance.registries import goproxy

        dep = _dep(name="github.com/foo/bar", version="v1.0.0", ecosystem="go")
        # sum.golang.org response: tree-size line, then module+version+hash lines
        sum_response = (
            "12345\n"
            "github.com/foo/bar v1.0.0 h1:SomeZipHash=\n"
            "github.com/foo/bar v1.0.0/go.mod h1:SomeGoModHash=\n"
            "\ngo.sum database tree\n"
        )
        session = MagicMock()
        # First call (ziphash) returns None; second call (sum.golang.org) returns hash
        session.get_text = AsyncMock(side_effect=[None, sum_response])

        result = await goproxy.get_registry_hash(dep, session)
        assert result == "h1:SomeZipHash="

    async def test_none_when_both_endpoints_fail(self):
        from tools.scan.signals.provenance.registries import goproxy

        session = MagicMock()
        session.get_text = AsyncMock(return_value=None)

        result = await goproxy.get_registry_hash(_dep(ecosystem="go"), session)
        assert result is None


class TestMavenRegistry:
    async def test_returns_sha256(self):
        from tools.scan.signals.provenance.registries import maven

        dep = Dependency(
            name="org.example:lib",
            version="1.0",
            ecosystem="java",
            lockfile_path=Path("pom.xml"),
            source_url="https://repo1.maven.org/maven2/org/example/lib/1.0/lib-1.0.jar",
        )
        session = MagicMock()
        hex64 = "a" * 64
        session.get_text = AsyncMock(return_value=hex64)

        result = await maven.get_registry_hash(dep, session)
        assert result == f"sha256:{hex64}"

    async def test_falls_back_to_sha1(self):
        from tools.scan.signals.provenance.registries import maven

        dep = Dependency(
            name="org.example:lib",
            version="1.0",
            ecosystem="java",
            lockfile_path=Path("pom.xml"),
            source_url="https://repo1.maven.org/maven2/org/example/lib/1.0/lib-1.0.jar",
        )
        hex40 = "b" * 40
        session = MagicMock()
        # sha256 returns None, sha1 returns hex40
        session.get_text = AsyncMock(side_effect=[None, hex40])

        result = await maven.get_registry_hash(dep, session)
        assert result == f"sha1:{hex40}"

    async def test_no_source_url_returns_none(self):
        from tools.scan.signals.provenance.registries import maven

        dep = Dependency(
            name="org.example:lib",
            version="1.0",
            ecosystem="java",
            lockfile_path=Path("pom.xml"),
            source_url=None,
        )
        session = MagicMock()
        session.get_text = AsyncMock(return_value="hex")

        result = await maven.get_registry_hash(dep, session)
        assert result is None


# ---------------------------------------------------------------------------
# HashVerificationResult.to_dict contract
# ---------------------------------------------------------------------------

class TestHashVerificationResultModel:
    def test_severity_derived_from_status(self):
        dep = _dep()
        r = HashVerificationResult(
            dep=dep,
            lockfile_hash="sha256:x",
            registry_hash="sha256:y",
            status=VerificationStatus.MISMATCH,
        )
        assert r.severity == Severity.CRITICAL

    def test_missing_hash_is_low(self):
        dep = _dep()
        r = HashVerificationResult(
            dep=dep,
            lockfile_hash=None,
            registry_hash=None,
            status=VerificationStatus.MISSING_LOCKFILE_HASH,
        )
        assert r.severity == Severity.LOW

    def test_match_is_info(self):
        dep = _dep()
        r = HashVerificationResult(
            dep=dep,
            lockfile_hash="sha256:a",
            registry_hash="sha256:a",
            status=VerificationStatus.MATCH,
        )
        assert r.severity == Severity.INFO
