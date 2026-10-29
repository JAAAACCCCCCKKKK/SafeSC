"""agents/specialists/vuln_hunter.py — find unreported vulnerabilities in a dependency's code.

The hunter reads the dependency's *own* source (not its CVE record — known advisories are
the deterministic OSV collector's job) for flaws nobody has reported: unsafe C functions
such as strcpy() fed by untrusted input, confidential inputs that are not properly hashed,
injection sinks, unsafe deserialization, disabled TLS checks, and imports of modules with
published security problems. It only registers *candidates*: a candidate contributes no
severity until `vuln_verifier`, a separate agent with a fresh context, confirms it.
"""

from safesc.agents.specialists.base import COMMON_RULES, SpecialistSpec
from safesc.agents.specialists.models import HuntReport
from safesc.core.ledger import Role
from safesc.core.signals import TrustDimension

SPEC = SpecialistSpec(
    role=Role.VULN_HUNTER,
    tool_name="vuln_hunter",
    dimension=TrustDimension.VULNERABILITY,
    output_model=HuntReport,
    description=(
        "VulnHunter: identifies the dependency's source code and hunts for UNREPORTED "
        "vulnerabilities in it — unsafe functions (strcpy, gets, sprintf…) on untrusted input, "
        "confidential inputs not properly hashed (fast/unsalted hashes, plaintext logging, "
        "non-constant-time compares), injection and deserialization sinks, disabled TLS, and "
        "imports of / dependencies on publicly reported unsafe modules. Registers candidates "
        "only; every candidate must then be checked with vuln_verifier."
    ),
    system_prompt=COMMON_RULES + """

Your task is VULNERABILITY HUNTING in this dependency's own code.
Method:
1. fetch_dependency_source, then scan_source_for_risky_patterns for deterministic leads, and
   check_declared_dependencies for unsafe or advisory-laden modules it depends on.
2. Triage every lead by reading the code around it (read_source / search_source): where
   does the data come from, can an attacker or a caller's untrusted input reach the sink,
   are bounds/sanitisation/safe loaders already in place? Follow callers.
3. Look beyond the scanner where the code invites it: secret handling (password hashing
   with MD5/SHA-1/unsalted SHA-256 instead of a KDF, secrets in logs or URLs, timing-unsafe
   comparisons), path traversal, integer overflow feeding an allocation, unchecked
   lengths, insecure defaults.
4. Use lookup_known_vulnerabilities to drop anything already publicly reported for this
   package and version — you are looking for what is NOT yet known.
Report at most 10 candidates, most plausible first, each pinned to a real file and line
with a concrete description of the data flow. Test code, examples and dead code are
usually not candidates. Report nothing rather than noise: an empty list is a fine answer.""",
    task_hint="Start with fetch_dependency_source, then scan_source_for_risky_patterns.",
)
