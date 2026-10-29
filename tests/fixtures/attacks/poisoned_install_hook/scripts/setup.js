// Attack-PATTERN fixture: poisoned postinstall hook (event-stream-style STRUCTURAL
// pattern only — this is not a replay of the real event-stream/flatmap-stream incident
// and contains no working exploit code). Real incident background: a postinstall hook
// fetched and ran attacker code that harvested credentials from environment variables.
// This fixture reproduces the detectable SHAPE — a postinstall hook that references a
// network API, reads process.env, and eval()s a decoded string — with an inert payload.
//
// Detectors key off structure, not content: an install-time script exists
// (package.json "scripts".postinstall), it references a network symbol (`https`), an
// env symbol (`process.env`), and eval() on a base64-decoded string
// (safesc.tools.deep_analysis_tool._static_op_hints: references_network /
// references_env / references_exec / references_encode all true for this file).
// Nothing here makes a real network call, reads a real secret, or executes untrusted
// code — the decoded string is a harmless console.log.

const https = require("https");

// base64: repeated encoding of
// `console.log('simulated postinstall action, harmless, no real network or exec occurs')`
const ENCODED_PAYLOAD =
  "Y29uc29sZS5sb2coJ3NpbXVsYXRlZCBwb3N0aW5zdGFsbCBhY3Rpb24sIGhhcm1sZXNzLCBubyByZWFsIG5ldHdvcmsgb3IgZXhlYyBvY2N1cnMnKWNvbnNvbGUubG9nKCdzaW11bGF0ZWQgcG9zdGluc3RhbGwgYWN0aW9uLCBoYXJtbGVzcywgbm8gcmVhbCBuZXR3b3JrIG9yIGV4ZWMgb2NjdXJzJyljb25zb2xlLmxvZygnc2ltdWxhdGVkIHBvc3RpbnN0YWxsIGFjdGlvbiwgaGFybWxlc3MsIG5vIHJlYWwgbmV0d29yayBvciBleGVjIG9jY3Vycycp";

// Structural marker: install-time network reference (never actually invoked below).
function simulatedBeacon() {
  https.get("https://example.invalid/simulated-endpoint", () => {});
}

// Structural marker: install-time env-var read (harvested nothing real).
const maybeToken = process.env.NPM_TOKEN || process.env.HOME;

// Structural marker: eval() on a decoded (base64) string.
const decoded = Buffer.from(ENCODED_PAYLOAD, "base64").toString("utf8");
eval(decoded); // decodes to: console.log('simulated postinstall action, harmless, ...')

void simulatedBeacon;
void maybeToken;
