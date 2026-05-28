"""Java ecosystem adapter — lockfile discovery patterns (Maven, Gradle, Spring Boot)."""

from __future__ import annotations

from depaudit.ecosystems.base import EcosystemAdapter


class JavaAdapter(EcosystemAdapter):
    """Adapter for Java dependency files (Maven, Gradle, Spring Boot)."""

    @property
    def name(self) -> str:
        return "java"

    @property
    def lockfile_globs(self) -> list[str]:
        return [
            # Maven
            "pom.xml",
            # Gradle build scripts
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            # Gradle dependency locking (Gradle 6.8+)
            "gradle.lockfile",
            "buildscript-gradle.lockfile",
            # Gradle wrapper — records the exact Gradle distribution URL/hash
            "gradle-wrapper.properties",
            # Maven wrapper
            "maven-wrapper.properties",
        ]