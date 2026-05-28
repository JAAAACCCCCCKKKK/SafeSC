"""Unit tests for Stage 1 — lockfile parsers and normalizer.

Each parser class is tested for:
  - correct field extraction (name, version, hash, source_url)
  - is_direct / layer_number / parent_name where the format supports it
  - graceful return of [] on malformed or empty input
  - edge cases specific to the format
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depaudit.core.models import Dependency
from depaudit.core.normalizer import parse_lockfiles
from depaudit.core.discovery import discover


# ── shared helper ─────────────────────────────────────────────────────────────

def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ── Python / uv.lock ──────────────────────────────────────────────────────────

_UV_LOCK = """\
version = 1
requires-python = ">=3.12"

[[package]]
name = "myapp"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "certifi" },
]
wheels = [
    { url = "https://files.pythonhosted.org/requests-2.31.0-py3-none-any.whl", hash = "sha256:abc123", size = 62574 },
]

[[package]]
name = "certifi"
version = "2024.2.2"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/certifi-2024.2.2.tar.gz", hash = "sha256:def456", size = 164836 }
"""


class TestUvParser:
    @pytest.fixture
    def deps(self, tmp_path):
        from depaudit.ecosystems.python.parsers.uv import parse
        return parse(write(tmp_path / "uv.lock", _UV_LOCK))

    def test_direct_dep_is_direct(self, deps):
        req = next(d for d in deps if d.name == "requests")
        assert req.is_direct is True
        assert req.layer_number == 1

    def test_transitive_dep_layer_and_parent(self, deps):
        cert = next(d for d in deps if d.name == "certifi")
        assert cert.is_direct is False
        assert cert.layer_number == 2
        assert cert.parent_name == "requests"

    def test_wheel_hash_and_url(self, deps):
        req = next(d for d in deps if d.name == "requests")
        assert req.hash == "sha256:abc123"
        assert "requests-2.31.0" in req.source_url

    def test_sdist_fallback_when_no_wheels(self, deps):
        cert = next(d for d in deps if d.name == "certifi")
        assert cert.hash == "sha256:def456"
        assert "certifi-2024.2.2.tar.gz" in cert.source_url

    def test_root_package_excluded(self, deps):
        assert not any(d.name == "myapp" for d in deps)

    def test_ecosystem_tag(self, deps):
        assert all(d.ecosystem == "python" for d in deps)

    def test_malformed_toml_returns_empty(self, tmp_path):
        from depaudit.ecosystems.python.parsers.uv import parse
        assert parse(write(tmp_path / "uv.lock", "not valid toml ][")) == []

    def test_empty_file_returns_empty(self, tmp_path):
        from depaudit.ecosystems.python.parsers.uv import parse
        assert parse(write(tmp_path / "uv.lock", "")) == []


# ── Python / poetry.lock ──────────────────────────────────────────────────────

_POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.28.2"
description = "Python HTTP"
optional = false
python-versions = ">=3.7"
files = [
    {file = "requests-2.28.2-py3-none-any.whl", hash = "sha256:wheel_hash"},
    {file = "requests-2.28.2.tar.gz", hash = "sha256:sdist_hash"},
]

[package.dependencies]
certifi = ">=2017.4.17"

[[package]]
name = "certifi"
version = "2024.2.2"
description = "Root certs"
optional = false
python-versions = ">=3.6"
files = [
    {file = "certifi-2024.2.2-py3-none-any.whl", hash = "sha256:cert_hash"},
]

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "abc"
"""

_PYPROJECT_WITH_REQUESTS = """\
[tool.poetry]
name = "myapp"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
requests = "^2.28.0"
"""


class TestPoetryParser:
    @pytest.fixture
    def deps(self, tmp_path):
        from depaudit.ecosystems.python.parsers.poetry import parse
        write(tmp_path / "poetry.lock", _POETRY_LOCK)
        write(tmp_path / "pyproject.toml", _PYPROJECT_WITH_REQUESTS)
        return parse(tmp_path / "poetry.lock")

    def test_direct_dep_detected_via_pyproject(self, deps):
        req = next(d for d in deps if d.name == "requests")
        assert req.is_direct is True
        assert req.layer_number == 1

    def test_transitive_dep_via_dep_graph(self, deps):
        cert = next(d for d in deps if d.name == "certifi")
        assert cert.is_direct is False
        assert cert.layer_number == 2
        assert cert.parent_name == "requests"

    def test_hash_from_first_file_entry(self, deps):
        req = next(d for d in deps if d.name == "requests")
        assert req.hash == "sha256:wheel_hash"

    def test_no_pyproject_all_unknown_direct(self, tmp_path):
        from depaudit.ecosystems.python.parsers.poetry import parse
        write(tmp_path / "poetry.lock", _POETRY_LOCK)
        deps = parse(tmp_path / "poetry.lock")
        assert all(d.is_direct is False for d in deps)

    def test_malformed_returns_empty(self, tmp_path):
        from depaudit.ecosystems.python.parsers.poetry import parse
        assert parse(write(tmp_path / "poetry.lock", "[[bad toml")) == []


# ── Python / requirements.txt ─────────────────────────────────────────────────

class TestRequirementsParser:
    def _parse(self, tmp_path, content):
        from depaudit.ecosystems.python.parsers.requirements import parse
        return parse(write(tmp_path / "requirements.txt", content))

    def test_pinned_version(self, tmp_path):
        deps = self._parse(tmp_path, "requests==2.31.0\n")
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31.0"
        assert deps[0].is_direct is True
        assert deps[0].layer_number == 1

    def test_hash_extracted(self, tmp_path):
        deps = self._parse(tmp_path, "requests==2.31.0 --hash=sha256:abc123def\n")
        assert deps[0].hash == "sha256:abc123def"

    def test_extras_captured(self, tmp_path):
        deps = self._parse(tmp_path, "requests[security]==2.31.0\n")
        assert deps[0].extras == ["security"]

    def test_skips_unpinned_dep(self, tmp_path):
        deps = self._parse(tmp_path, "requests>=2.0\n")
        assert deps == []

    def test_skips_option_lines(self, tmp_path):
        deps = self._parse(tmp_path, "-r other.txt\n--index-url https://example.com\nrequests==2.31.0\n")
        assert len(deps) == 1

    def test_skips_comments(self, tmp_path):
        deps = self._parse(tmp_path, "# this is a comment\nrequests==2.31.0\n")
        assert len(deps) == 1

    def test_line_continuation(self, tmp_path):
        deps = self._parse(tmp_path, "requests==2.31.0 \\\n    --hash=sha256:abc\n")
        assert deps[0].hash == "sha256:abc"

    def test_empty_file_returns_empty(self, tmp_path):
        assert self._parse(tmp_path, "") == []


# ── Python / Pipfile.lock ─────────────────────────────────────────────────────

class TestPipfileParser:
    def _parse(self, tmp_path, data: dict):
        from depaudit.ecosystems.python.parsers.pipfile import parse
        path = tmp_path / "Pipfile.lock"
        path.write_text(json.dumps(data), encoding="utf-8")
        return parse(path)

    def test_default_section(self, tmp_path):
        deps = self._parse(tmp_path, {"default": {"requests": {"version": "==2.31.0", "hashes": ["sha256:abc"]}}})
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31.0"
        assert deps[0].hash == "sha256:abc"

    def test_develop_section_included(self, tmp_path):
        deps = self._parse(tmp_path, {
            "default": {"requests": {"version": "==2.31.0", "hashes": []}},
            "develop": {"pytest": {"version": "==8.0.0", "hashes": ["sha256:xyz"]}},
        })
        names = {d.name for d in deps}
        assert "requests" in names
        assert "pytest" in names

    def test_version_equals_stripped(self, tmp_path):
        deps = self._parse(tmp_path, {"default": {"flask": {"version": "==3.0.0", "hashes": []}}})
        assert deps[0].version == "3.0.0"

    def test_all_direct_layer_1(self, tmp_path):
        deps = self._parse(tmp_path, {"default": {"a": {"version": "==1.0", "hashes": []}}})
        assert deps[0].is_direct is True
        assert deps[0].layer_number == 1

    def test_malformed_json_returns_empty(self, tmp_path):
        from depaudit.ecosystems.python.parsers.pipfile import parse
        assert parse(write(tmp_path / "Pipfile.lock", "{bad json")) == []


# ── JavaScript / package-lock.json ────────────────────────────────────────────

def _pkg_lock_v3(direct: dict, packages: dict) -> dict:
    return {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": direct},
            **{f"node_modules/{k}": v for k, v in packages.items()},
        },
    }


class TestPackageLockParser:
    def test_v3_direct_dep(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.package_lock import parse
        data = _pkg_lock_v3(
            {"express": "^4.18.2"},
            {"express": {"version": "4.18.2", "resolved": "https://r.npm/express.tgz", "integrity": "sha512-abc"}},
        )
        deps = parse(write(tmp_path / "package-lock.json", json.dumps(data)))
        exp = next(d for d in deps if d.name == "express")
        assert exp.is_direct is True
        assert exp.layer_number == 1
        assert exp.hash == "sha512-abc"
        assert exp.source_url == "https://r.npm/express.tgz"

    def test_v3_transitive_dep_layer_and_parent(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.package_lock import parse
        data = _pkg_lock_v3(
            {"express": "^4.18.2"},
            {
                "express": {"version": "4.18.2", "resolved": "https://r.npm/express.tgz", "integrity": "sha512-x", "dependencies": {"accepts": "~1.3.8"}},
                "accepts": {"version": "1.3.8", "resolved": "https://r.npm/accepts.tgz", "integrity": "sha512-y"},
            },
        )
        deps = parse(write(tmp_path / "package-lock.json", json.dumps(data)))
        acc = next(d for d in deps if d.name == "accepts")
        assert acc.is_direct is False
        assert acc.layer_number == 2
        assert acc.parent_name == "express"

    def test_v1_nested_deps(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.package_lock import parse
        data = {
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "resolved": "https://r.npm/express.tgz",
                    "integrity": "sha512-x",
                    "requires": {"accepts": "~1.3.8"},
                    "dependencies": {
                        "accepts": {"version": "1.3.8", "resolved": "https://r.npm/accepts.tgz", "integrity": "sha512-y"},
                    },
                }
            },
        }
        deps = parse(write(tmp_path / "package-lock.json", json.dumps(data)))
        assert any(d.name == "express" for d in deps)
        assert any(d.name == "accepts" for d in deps)

    def test_malformed_returns_empty(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.package_lock import parse
        assert parse(write(tmp_path / "package-lock.json", "{bad")) == []


# ── JavaScript / yarn.lock ────────────────────────────────────────────────────

_YARN_LOCK = """\
# yarn lockfile v1

express@^4.18.2:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz#abc"
  integrity sha512-expressIntegrity

accepts@~1.3.8:
  version "1.3.8"
  resolved "https://registry.yarnpkg.com/accepts/-/accepts-1.3.8.tgz#def"
  integrity sha512-acceptsIntegrity
"""

_PACKAGE_JSON_EXPRESS = json.dumps({"dependencies": {"express": "^4.18.2"}})


class TestYarnParser:
    def test_parses_name_version_integrity(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.yarn import parse
        write(tmp_path / "yarn.lock", _YARN_LOCK)
        deps = parse(tmp_path / "yarn.lock")
        exp = next(d for d in deps if d.name == "express")
        assert exp.version == "4.18.2"
        assert exp.hash == "sha512-expressIntegrity"

    def test_resolved_url_hash_stripped(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.yarn import parse
        write(tmp_path / "yarn.lock", _YARN_LOCK)
        deps = parse(tmp_path / "yarn.lock")
        exp = next(d for d in deps if d.name == "express")
        assert exp.source_url == "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"

    def test_direct_via_package_json(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.yarn import parse
        write(tmp_path / "yarn.lock", _YARN_LOCK)
        write(tmp_path / "package.json", _PACKAGE_JSON_EXPRESS)
        deps = parse(tmp_path / "yarn.lock")
        exp = next(d for d in deps if d.name == "express")
        acc = next(d for d in deps if d.name == "accepts")
        assert exp.is_direct is True
        assert acc.is_direct is False

    def test_berry_format_returns_empty(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.yarn import parse
        berry = "__metadata:\n  version: 6\n"
        assert parse(write(tmp_path / "yarn.lock", berry)) == []

    def test_malformed_returns_empty(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.yarn import parse
        assert parse(write(tmp_path / "yarn.lock", "")) == []


# ── JavaScript / pnpm-lock.yaml ───────────────────────────────────────────────

_PNPM_V6 = """\
lockfileVersion: '6.0'

dependencies:
  express:
    specifier: ^4.18.2
    version: 4.18.2

packages:

  /express@4.18.2:
    resolution: {integrity: sha512-expressHash}
    dev: false

  /accepts@1.3.8:
    resolution: {integrity: sha512-acceptsHash}
    dev: false
"""

_PNPM_V9 = """\
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-lodashHash}
"""


class TestPnpmParser:
    def test_v6_direct_dep(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.pnpm import parse
        deps = parse(write(tmp_path / "pnpm-lock.yaml", _PNPM_V6))
        exp = next(d for d in deps if d.name == "express")
        assert exp.is_direct is True
        assert exp.layer_number == 1
        assert exp.hash == "sha512-expressHash"

    def test_v6_transitive_dep(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.pnpm import parse
        deps = parse(write(tmp_path / "pnpm-lock.yaml", _PNPM_V6))
        acc = next(d for d in deps if d.name == "accepts")
        assert acc.is_direct is False

    def test_v9_direct_from_importers(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.pnpm import parse
        deps = parse(write(tmp_path / "pnpm-lock.yaml", _PNPM_V9))
        lod = next(d for d in deps if d.name == "lodash")
        assert lod.is_direct is True
        assert lod.version == "4.17.21"

    def test_malformed_returns_empty(self, tmp_path):
        from depaudit.ecosystems.javascript.parsers.pnpm import parse
        assert parse(write(tmp_path / "pnpm-lock.yaml", "not: valid: yaml: ][")) == []


# ── Rust / Cargo.lock ─────────────────────────────────────────────────────────

_CARGO_LOCK = """\
version = 3

[[package]]
name = "myapp"
version = "0.1.0"
dependencies = [
    "serde 1.0.193",
    "anyhow 1.0.79",
]

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef1234"
dependencies = [
    "serde_derive 1.0.193",
]

[[package]]
name = "serde_derive"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cafebabe5678"

[[package]]
name = "anyhow"
version = "1.0.79"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aabbcc9900"
"""


class TestCargoParser:
    @pytest.fixture
    def deps(self, tmp_path):
        from depaudit.ecosystems.rust.parsers.cargo import parse
        return parse(write(tmp_path / "Cargo.lock", _CARGO_LOCK))

    def test_workspace_root_excluded(self, deps):
        assert not any(d.name == "myapp" for d in deps)

    def test_direct_dep_detected(self, deps):
        serde = next(d for d in deps if d.name == "serde")
        assert serde.is_direct is True
        assert serde.layer_number == 1

    def test_transitive_dep_layer_and_parent(self, deps):
        derive = next(d for d in deps if d.name == "serde_derive")
        assert derive.is_direct is False
        assert derive.layer_number == 2
        assert derive.parent_name == "serde"

    def test_checksum_prefixed_with_sha256(self, deps):
        serde = next(d for d in deps if d.name == "serde")
        assert serde.hash == "sha256:deadbeef1234"

    def test_crates_io_source_url(self, deps):
        serde = next(d for d in deps if d.name == "serde")
        assert serde.source_url == "https://static.crates.io/crates/serde/serde-1.0.193.crate"

    def test_ecosystem_tag(self, deps):
        assert all(d.ecosystem == "rust" for d in deps)

    def test_malformed_returns_empty(self, tmp_path):
        from depaudit.ecosystems.rust.parsers.cargo import parse
        assert parse(write(tmp_path / "Cargo.lock", "not toml ][")) == []


# ── Go / go.mod ───────────────────────────────────────────────────────────────

_GO_MOD = """\
module example.com/myapp

go 1.21

require (
\tgithub.com/pkg/errors v0.9.1
\tgolang.org/x/net v0.19.0 // indirect
)
"""

_GO_SUM = """\
github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt38=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
"""


class TestGoModParser:
    @pytest.fixture
    def deps(self, tmp_path):
        from depaudit.ecosystems.go.parsers.gomod import parse
        write(tmp_path / "go.mod", _GO_MOD)
        write(tmp_path / "go.sum", _GO_SUM)
        return parse(tmp_path / "go.mod")

    def test_direct_dep(self, deps):
        errors = next(d for d in deps if "errors" in d.name)
        assert errors.is_direct is True
        assert errors.layer_number == 1

    def test_indirect_dep_layer_2(self, deps):
        net = next(d for d in deps if "x/net" in d.name)
        assert net.is_direct is False
        assert net.layer_number == 2

    def test_hash_loaded_from_gosum(self, deps):
        errors = next(d for d in deps if "errors" in d.name)
        assert errors.hash == "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt38="

    def test_indirect_dep_no_hash_in_gosum(self, deps):
        net = next(d for d in deps if "x/net" in d.name)
        assert net.hash is None  # not in our go.sum fixture

    def test_source_url_uses_proxy(self, deps):
        errors = next(d for d in deps if "errors" in d.name)
        assert errors.source_url == "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip"

    def test_gosum_defers_when_gomod_present(self, tmp_path):
        from depaudit.ecosystems.go.parsers.gomod import parse
        write(tmp_path / "go.mod", _GO_MOD)
        write(tmp_path / "go.sum", _GO_SUM)
        assert parse(tmp_path / "go.sum") == []

    def test_gosum_standalone_when_no_gomod(self, tmp_path):
        from depaudit.ecosystems.go.parsers.gomod import parse
        write(tmp_path / "go.sum", _GO_SUM)
        deps = parse(tmp_path / "go.sum")
        assert len(deps) == 1  # only the h1: line, not the /go.mod line
        assert deps[0].layer_number == 2

    def test_malformed_returns_empty(self, tmp_path):
        from depaudit.ecosystems.go.parsers.gomod import parse
        assert parse(write(tmp_path / "go.mod", "")) == []


# ── Java / pom.xml ────────────────────────────────────────────────────────────

_POM_XML = """\
<project>
  <properties>
    <spring.version>3.2.0</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>3.2.0</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <version>${spring.version}</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""


class TestMavenParser:
    @pytest.fixture
    def deps(self, tmp_path):
        from depaudit.ecosystems.java.parsers.maven import parse
        return parse(write(tmp_path / "pom.xml", _POM_XML))

    def test_name_is_group_colon_artifact(self, deps):
        assert any(d.name == "org.springframework.boot:spring-boot-starter-web" for d in deps)

    def test_version_extracted(self, deps):
        web = next(d for d in deps if "starter-web" in d.name)
        assert web.version == "3.2.0"

    def test_property_variable_resolved(self, deps):
        test = next(d for d in deps if "starter-test" in d.name)
        assert test.version == "3.2.0"

    def test_scope_in_extras(self, deps):
        test = next(d for d in deps if "starter-test" in d.name)
        assert "test" in test.extras

    def test_default_scope_no_extras(self, deps):
        web = next(d for d in deps if "starter-web" in d.name)
        assert web.extras == []

    def test_maven_central_source_url(self, deps):
        web = next(d for d in deps if "starter-web" in d.name)
        assert "repo1.maven.org" in web.source_url
        assert "spring-boot-starter-web-3.2.0.jar" in web.source_url

    def test_all_direct(self, deps):
        assert all(d.is_direct is True for d in deps)

    def test_malformed_xml_returns_empty(self, tmp_path):
        from depaudit.ecosystems.java.parsers.maven import parse
        assert parse(write(tmp_path / "pom.xml", "<unclosed>")) == []


# ── Java / gradle.lockfile ────────────────────────────────────────────────────

_GRADLE_LOCKFILE = """\
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not allowed.
com.google.guava:guava:32.1.3-jre=compileClasspath,runtimeClasspath
org.springframework.boot:spring-boot:3.2.0=compileClasspath
empty=
"""


class TestGradleParser:
    @pytest.fixture
    def deps(self, tmp_path):
        from depaudit.ecosystems.java.parsers.gradle import parse
        return parse(write(tmp_path / "gradle.lockfile", _GRADLE_LOCKFILE))

    def test_parses_coord(self, deps):
        guava = next(d for d in deps if "guava" in d.name)
        assert guava.name == "com.google.guava:guava"
        assert guava.version == "32.1.3-jre"

    def test_maven_central_source_url(self, deps):
        guava = next(d for d in deps if "guava" in d.name)
        assert "repo1.maven.org" in guava.source_url
        assert "guava-32.1.3-jre.jar" in guava.source_url

    def test_comments_and_empty_skipped(self, deps):
        assert len(deps) == 2

    def test_is_not_direct(self, deps):
        assert all(d.is_direct is False for d in deps)

    def test_non_lockfile_name_returns_empty(self, tmp_path):
        from depaudit.ecosystems.java.parsers.gradle import parse
        assert parse(write(tmp_path / "build.gradle", "")) == []

    def test_malformed_lines_skipped(self, tmp_path):
        from depaudit.ecosystems.java.parsers.gradle import parse
        content = "group:artifact=config\nno-equals-sign\nvalid:group:1.0=cfg\n"
        deps = parse(write(tmp_path / "gradle.lockfile", content))
        assert len(deps) == 1
        assert deps[0].name == "valid:group"


# ── Normalizer ────────────────────────────────────────────────────────────────

class TestNormalizer:
    def test_routes_to_correct_adapter(self, tmp_path):
        write(tmp_path / "requirements.txt", "requests==2.31.0\n")
        write(tmp_path / "Cargo.lock", "[package]\nname=\"app\"\nversion=\"0.1.0\"\n")
        files = discover(tmp_path)
        deps = parse_lockfiles(files)
        ecosystems = {d.ecosystem for d in deps}
        assert "python" in ecosystems

    def test_second_pass_fills_parent_url(self, tmp_path):
        write(tmp_path / "uv.lock", _UV_LOCK)
        files = discover(tmp_path)
        deps = parse_lockfiles(files)
        cert = next(d for d in deps if d.name == "certifi")
        req = next(d for d in deps if d.name == "requests")
        assert cert.parent_url == req.source_url

    def test_parser_exception_swallowed(self, tmp_path):
        # Corrupt file should not crash the pipeline — just yield no deps.
        write(tmp_path / "uv.lock", "not valid toml ][")
        files = discover(tmp_path)
        deps = parse_lockfiles(files)
        assert isinstance(deps, list)

    def test_gosum_not_double_counted(self, tmp_path):
        write(tmp_path / "go.mod", _GO_MOD)
        write(tmp_path / "go.sum", _GO_SUM)
        files = discover(tmp_path)
        deps = parse_lockfiles(files)
        go_deps = [d for d in deps if d.ecosystem == "go"]
        names = [d.name for d in go_deps]
        # Each module must appear exactly once despite two files being discovered
        assert len(names) == len(set(names))