"""Java ecosystem adapter — lockfile discovery patterns (Maven, Gradle, Spring Boot)."""

from __future__ import annotations

from pathlib import Path

from tools.index.core.models import Dependency
from tools.index.ecosystems.base import EcosystemAdapter


class JavaAdapter(EcosystemAdapter):
    """Adapter for Java dependency files (Maven, Gradle, Spring Boot)."""

    @property
    def name(self) -> str:
        return "java"

    @property
    def lockfile_globs(self) -> list[str]:
        return [
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradle.lockfile",
            "buildscript-gradle.lockfile",
            "gradle-wrapper.properties",
            "maven-wrapper.properties",
        ]

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        if path.name == "pom.xml":
            from tools.index.ecosystems.java.parsers.maven import parse
            return parse(path)
        if path.name in ("gradle.lockfile", "buildscript-gradle.lockfile"):
            from tools.index.ecosystems.java.parsers.gradle import parse
            return parse(path)
        return []  # build.gradle, settings.gradle, wrapper files: no parseable dep data
