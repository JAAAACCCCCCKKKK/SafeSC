"""Tests for the Java ecosystem adapter (Stage 0 — discovery)."""

from __future__ import annotations

from pathlib import Path

from tools.index import discover
from tools.index.ecosystems.java.adapter import JavaAdapter


# ── Adapter unit tests ─────────────────────────────────────────────────────────


class TestJavaAdapterProperties:
    def test_name(self) -> None:
        assert JavaAdapter().name == "java"

    def test_lockfile_globs_nonempty(self) -> None:
        assert JavaAdapter().lockfile_globs

    def test_is_lockfile_pom(self) -> None:
        assert JavaAdapter().is_lockfile(Path("pom.xml"))

    def test_is_lockfile_build_gradle(self) -> None:
        assert JavaAdapter().is_lockfile(Path("build.gradle"))

    def test_is_lockfile_build_gradle_kts(self) -> None:
        assert JavaAdapter().is_lockfile(Path("build.gradle.kts"))

    def test_is_lockfile_settings_gradle(self) -> None:
        assert JavaAdapter().is_lockfile(Path("settings.gradle"))

    def test_is_lockfile_settings_gradle_kts(self) -> None:
        assert JavaAdapter().is_lockfile(Path("settings.gradle.kts"))

    def test_is_lockfile_gradle_lockfile(self) -> None:
        assert JavaAdapter().is_lockfile(Path("gradle.lockfile"))

    def test_is_lockfile_buildscript_lockfile(self) -> None:
        assert JavaAdapter().is_lockfile(Path("buildscript-gradle.lockfile"))

    def test_is_lockfile_gradle_wrapper_properties(self) -> None:
        assert JavaAdapter().is_lockfile(Path("gradle-wrapper.properties"))

    def test_is_lockfile_maven_wrapper_properties(self) -> None:
        assert JavaAdapter().is_lockfile(Path("maven-wrapper.properties"))

    def test_is_lockfile_unknown_rejected(self) -> None:
        assert not JavaAdapter().is_lockfile(Path("random.xml"))

    def test_is_lockfile_package_json_rejected(self) -> None:
        assert not JavaAdapter().is_lockfile(Path("package.json"))


# ── Discovery integration tests ────────────────────────────────────────────────


def make_tree(root: Path, files: list[str]) -> None:
    for rel in files:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()


class TestMavenDiscovery:
    def test_finds_pom_xml(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["pom.xml"])
        results = discover(tmp_path)
        assert any(f.path.name == "pom.xml" and f.ecosystem == "java" for f in results)

    def test_finds_nested_pom_xml(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["services/auth/pom.xml"])
        results = discover(tmp_path)
        assert any(f.path.name == "pom.xml" and f.ecosystem == "java" for f in results)

    def test_finds_maven_wrapper_properties(self, tmp_path: Path) -> None:
        make_tree(tmp_path, [".mvn/wrapper/maven-wrapper.properties"])
        results = discover(tmp_path)
        assert any(f.path.name == "maven-wrapper.properties" for f in results)


class TestGradleDiscovery:
    def test_finds_build_gradle(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["build.gradle"])
        results = discover(tmp_path)
        assert any(f.path.name == "build.gradle" and f.ecosystem == "java" for f in results)

    def test_finds_build_gradle_kts(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["build.gradle.kts"])
        results = discover(tmp_path)
        assert any(f.path.name == "build.gradle.kts" and f.ecosystem == "java" for f in results)

    def test_finds_settings_gradle(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["settings.gradle"])
        results = discover(tmp_path)
        assert any(f.path.name == "settings.gradle" and f.ecosystem == "java" for f in results)

    def test_finds_settings_gradle_kts(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["settings.gradle.kts"])
        results = discover(tmp_path)
        assert any(f.path.name == "settings.gradle.kts" and f.ecosystem == "java" for f in results)

    def test_finds_gradle_lockfile(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["gradle.lockfile"])
        results = discover(tmp_path)
        assert any(f.path.name == "gradle.lockfile" and f.ecosystem == "java" for f in results)

    def test_finds_buildscript_gradle_lockfile(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["buildscript-gradle.lockfile"])
        results = discover(tmp_path)
        assert any(f.path.name == "buildscript-gradle.lockfile" and f.ecosystem == "java" for f in results)

    def test_finds_gradle_wrapper_properties(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["gradle/wrapper/gradle-wrapper.properties"])
        results = discover(tmp_path)
        assert any(f.path.name == "gradle-wrapper.properties" and f.ecosystem == "java" for f in results)


class TestSpringBootDiscovery:
    def test_maven_spring_project(self, tmp_path: Path) -> None:
        """Typical Spring Boot Maven layout."""
        make_tree(tmp_path, [
            "pom.xml",
            "src/main/java/com/example/Application.java",
        ])
        results = discover(tmp_path)
        java_files = [f for f in results if f.ecosystem == "java"]
        assert len(java_files) == 1
        assert java_files[0].path.name == "pom.xml"

    def test_gradle_spring_project(self, tmp_path: Path) -> None:
        """Typical Spring Boot Gradle layout."""
        make_tree(tmp_path, [
            "build.gradle.kts",
            "settings.gradle.kts",
            "gradle/wrapper/gradle-wrapper.properties",
        ])
        results = discover(tmp_path)
        java_files = {f.path.name for f in results if f.ecosystem == "java"}
        assert java_files == {"build.gradle.kts", "settings.gradle.kts", "gradle-wrapper.properties"}

    def test_multimodule_maven(self, tmp_path: Path) -> None:
        """Multi-module Maven project has a pom.xml in each module."""
        make_tree(tmp_path, [
            "pom.xml",
            "module-a/pom.xml",
            "module-b/pom.xml",
        ])
        results = discover(tmp_path)
        poms = [f for f in results if f.path.name == "pom.xml" and f.ecosystem == "java"]
        assert len(poms) == 3


# ── Pruning ────────────────────────────────────────────────────────────────────


class TestJavaPruning:
    def test_build_dir_pruned(self, tmp_path: Path) -> None:
        """Gradle/Maven output directories must be skipped."""
        make_tree(tmp_path, ["build/tmp/pom.xml"])
        results = discover(tmp_path)
        assert not any("build" in f.path.parts for f in results)

    def test_target_dir_pruned(self, tmp_path: Path) -> None:
        """Maven target/ directory must be skipped."""
        make_tree(tmp_path, ["target/classes/pom.xml"])
        results = discover(tmp_path)
        assert not any("target" in f.path.parts for f in results)


# ── No cross-ecosystem false positives ────────────────────────────────────────


class TestNoFalsePositives:
    def test_cargo_toml_not_claimed(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["Cargo.toml"])
        results = discover(tmp_path)
        assert not any(f.ecosystem == "java" for f in results)

    def test_package_json_not_claimed(self, tmp_path: Path) -> None:
        make_tree(tmp_path, ["package.json"])
        results = discover(tmp_path)
        assert not any(f.ecosystem == "java" for f in results)