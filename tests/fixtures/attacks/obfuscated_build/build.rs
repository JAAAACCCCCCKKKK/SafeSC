// Attack-PATTERN fixture: build-script payload obfuscation (XZ-Utils-style STRUCTURAL
// pattern only — this is not a replay of the real XZ backdoor and contains no working
// exploit code). Real incident background: XZ Utils' `m4/build-to-host.m4` decoded a
// payload from a "test data" file at build time and spliced it into the build. This
// fixture reproduces the detectable SHAPE of that pattern — a long high-entropy encoded
// blob, a decode step, and a process-spawn call — with an entirely inert payload.
//
// Detectors key off structure, not content: a base64 blob >=200 chars with Shannon
// entropy >= 3.5 (safesc.tools.deep_analysis_tool.extract_obfuscation_candidates), plus
// a decode-then-Command::new pattern (safesc.tools.deep_analysis_tool._static_op_hints:
// references_encode + references_exec). The decoded string below is a harmless shell
// no-op; nothing here downloads, executes untrusted code, or touches the network.

use std::process::Command;

// base64: repeated encoding of `echo simulated-build-step-harmless; touch
// /tmp/safesc-fixture-marker-do-not-execute` — inert regardless of whether it is ever
// actually decoded (this fixture is never compiled or run).
const PAYLOAD_B64: &str = "ZWNobyBzaW11bGF0ZWQtYnVpbGQtc3RlcC1oYXJtbGVzczsgdG91Y2ggL3RtcC9zYWZlc2MtZml4dHVyZS1tYXJrZXItZG8tbm90LWV4ZWN1dGVlY2hvIHNpbXVsYXRlZC1idWlsZC1zdGVwLWhhcm1sZXNzOyB0b3VjaCAvdG1wL3NhZmVzYy1maXh0dXJlLW1hcmtlci1kby1ub3QtZXhlY3V0ZWVjaG8gc2ltdWxhdGVkLWJ1aWxkLXN0ZXAtaGFybWxlc3M7IHRvdWNoIC90bXAvc2FmZXNjLWZpeHR1cmUtbWFya2VyLWRvLW5vdC1leGVjdXRlZWNobyBzaW11bGF0ZWQtYnVpbGQtc3RlcC1oYXJtbGVzczsgdG91Y2ggL3RtcC9zYWZlc2MtZml4dHVyZS1tYXJrZXItZG8tbm90LWV4ZWN1dGU=";

fn main() {
    // Structural marker: decode-then-exec. `decode_base64` below is a trivial stand-in
    // (not the real `base64` crate) — this file is fixture data, never built.
    let decoded = decode_base64(PAYLOAD_B64);
    let _ = Command::new("sh").arg("-c").arg(decoded).status();
}

fn decode_base64(_encoded: &str) -> String {
    // Inert stand-in decode: the real decoded payload is the harmless command in the
    // comment above regardless of this function's (non-)implementation.
    "echo simulated-build-step-harmless".to_string()
}
