"""reporter/sarif_reporter.py — SARIF 2.1.0 projection of an `AuditReport`.

SARIF is what GitHub code-scanning / other CI dashboards ingest. Each non-clean signal
becomes one `result`; each distinct signal `source` becomes one `rule` (so the UI groups
findings by detector). Severity maps to both the SARIF `level` and the GitHub
`security-severity` numeric so the finding surfaces at the right tier.

Escalate-only stays visible: only signals with severity above CLEAN produce results — a
clean verdict contributes no result, exactly as it contributes no gate escalation (§4.3).
"""

from __future__ import annotations

import json

from safesc.reporter.models import AuditReport, SignalView

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_DRIVER_URI = "https://github.com/JAAAACCCCCCKKKK/SafeSC"

# Severity name -> (SARIF level, GitHub security-severity numeric)
_LEVEL = {
    "CRITICAL": ("error", "9.5"),
    "HIGH": ("error", "8.0"),
    "MEDIUM": ("warning", "5.5"),
    "LOW": ("note", "3.0"),
    "CLEAN": ("none", "0.0"),
}


def _level(sev: str) -> str:
    return _LEVEL.get(sev, ("warning", "5.5"))[0]


def _security_severity(sev: str) -> str:
    return _LEVEL.get(sev, ("warning", "5.5"))[1]


def _rule(source: str, dimension: str, worst: str) -> dict:
    return {
        "id": source,
        "name": source.replace(".", "_"),
        "shortDescription": {"text": f"{dimension} signal: {source}"},
        "fullDescription": {"text": f"SafeSC {dimension}-dimension detector '{source}'."},
        "defaultConfiguration": {"level": _level(worst)},
        "properties": {
            "dimension": dimension,
            "security-severity": _security_severity(worst),
            "tags": ["supply-chain", "dependency", dimension],
        },
    }


def _result(dep_key: str, lockfile: str | None, sig: SignalView) -> dict:
    text = sig.summary or sig.reasoning or f"{sig.dimension} concern on {dep_key}"
    result: dict = {
        "ruleId": sig.source,
        "level": _level(sig.severity),
        "message": {"text": f"[{dep_key}] {text}"},
        "properties": {
            "dep_key": dep_key,
            "dimension": sig.dimension,
            "origin": sig.origin,
            "severity": sig.severity,
            "confidence": sig.confidence,
            "security-severity": _security_severity(sig.severity),
        },
    }
    if sig.evidence:
        result["properties"]["evidence"] = list(sig.evidence)
    # A physical location lets code-scanning anchor the finding; fall back to the lockfile
    # the dependency was declared in, since a package has no single source line.
    if lockfile:
        result["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": _as_uri(lockfile)}}}
        ]
    return result


def _as_uri(path: str) -> str:
    return path.replace("\\", "/")


def build_sarif(report: AuditReport) -> dict:
    """Return the SARIF document as a Python dict (handy for tests / further shaping)."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in report.findings:
        for sig in f.signals:
            if sig.severity == "CLEAN":
                continue
            existing = rules.get(sig.source)
            if existing is None:
                rules[sig.source] = _rule(sig.source, sig.dimension, sig.severity)
            else:
                # keep the highest observed severity for the rule's default level
                cur = existing["properties"]["security-severity"]
                if float(_security_severity(sig.severity)) > float(cur):
                    existing["defaultConfiguration"]["level"] = _level(sig.severity)
                    existing["properties"]["security-severity"] = _security_severity(sig.severity)
            results.append(_result(f.dep_key, f.lockfile_path, sig))

    invocation = {
        "executionSuccessful": not report.incomplete,
        "properties": {
            "mode": report.mode,
            "overall_severity": report.overall_severity,
            "passed": report.passed,
            "incomplete": report.incomplete,
        },
    }
    if report.run_id:
        invocation["properties"]["run_id"] = report.run_id

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SafeSC",
                        "informationUri": _DRIVER_URI,
                        "version": report.schema_version,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }


def render_sarif(report: AuditReport, *, indent: int = 2) -> str:
    return json.dumps(build_sarif(report), indent=indent, sort_keys=False) + "\n"
