// raxis-kernel::ipc::log — shared structured-stderr primitives for the
// three IPC dispatchers (operator, planner, gateway).
//
// Why this lives in `ipc/` and not in a top-level kernel logging crate:
// the rest of the kernel (main.rs, bootstrap.rs, recovery.rs) emits
// one-off stderr lines via raw `eprintln!` with format-string JSON.
// Building a full kernel logging facade is a separate refactor; this
// module covers the surface where structured logging matters most —
// every connection on every public socket flows through here, so a
// JSON-escape bug or accidental credential interpolation has high
// blast radius.
//
// **Credential redaction contract (NORMATIVE):**
//
// The dispatchers MUST NEVER pass these values into a log line:
//   * `IntentRequest.session_token`
//   * `EscalationRequest.session_token`
//   * `WitnessSubmission.verifier_token`
//   * `GatewayMessage::GatewayReady.gateway_token`
//   * `GatewayMessage::FetchRequest.gateway_token`
//   * `OperatorResponse::SessionCreated.session_token`
//   * `OperatorResponse::EscalationApproved.approval_token_raw`
//   * Any provider API key, secret env var, or HTTP `Authorization` header.
//
// When a credential needs to be correlated across log lines (e.g.
// "this gateway handshake matched the supervisor's most recently
// minted token"), use [`credential_fingerprint`] to derive a stable
// non-reversible 8-char SHA-256 prefix. Any leak via a fingerprint is
// a 32-bit window into a 256-bit credential — non-recoverable in
// practice but still informative for cross-line correlation.

use serde_json::{json, Value};

/// Standard log levels used across the dispatchers. The strings are
/// the contract — log dashboards and grep recipes downstream depend
/// on them.
pub mod level {
    pub const INFO:  &str = "info";
    pub const WARN:  &str = "warn";
    pub const ERROR: &str = "error";
}

/// Convert a list of `(static_key, owned_value)` pairs into a JSON
/// object body. Order of insertion is preserved by `serde_json::Map`,
/// which keeps related fields adjacent in the output line for
/// human-readable greppability.
pub fn body_from_fields(fields: &[(&'static str, String)]) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::with_capacity(fields.len() + 4);
    for (k, v) in fields {
        map.insert((*k).to_owned(), json!(v));
    }
    map
}

/// Inject the four constant fields every dispatcher line carries
/// (`level`, `module`, `event`, `ts_unix`) and serialise the body to
/// a single stderr line.
///
/// `serde_json::to_string` cannot fail for a `Value` we constructed
/// in-memory (no `Map<NonStringKey,_>` is reachable here), but we
/// handle the theoretical error by emitting a self-describing
/// `log_serialize_failed` line so a future refactor that introduces a
/// new failure mode is still observable.
pub fn finalize_line(
    level: &str,
    module: &str,
    event: &str,
    mut body: serde_json::Map<String, Value>,
    ts_unix: i64,
) -> String {
    body.insert("level".into(),   json!(level));
    body.insert("module".into(),  json!(module));
    body.insert("event".into(),   json!(event));
    body.insert("ts_unix".into(), json!(ts_unix));
    serde_json::to_string(&Value::Object(body))
        .unwrap_or_else(|e| format!(
            "{{\"level\":\"error\",\"module\":\"{module}\",\
              \"event\":\"log_serialize_failed\",\"detail\":\"{e}\"}}"
        ))
}

/// Derive a stable 8-character (32-bit) lowercase hex prefix of the
/// SHA-256 of `credential` for log correlation. The full 64-char hash
/// is intentionally truncated: we want enough entropy to correlate
/// two log lines from the same credential, not enough to enable
/// brute-force recovery if the logs leak.
///
/// **Pre-conditions on the input:** the caller should pass the
/// original credential bytes (or their canonical hex encoding); this
/// helper does NOT validate format. A 64-char hex token and the
/// corresponding 32 bytes will hash to different values — pick one
/// canonical form per credential type and stick with it.
///
/// **Why 8 chars and not 16:** a 32-bit window is enough to
/// distinguish "same handshake" from "different handshake" within a
/// single kernel boot (collision probability is ~1 in 4 billion). A
/// 64-bit window would tighten the collision bound but also leak more
/// of the underlying SHA-256, which an attacker with offline access
/// could combine with a token-format guess. 8 is the sweet spot.
pub fn credential_fingerprint(credential: &str) -> String {
    let full = raxis_crypto::token::sha256_hex(credential.as_bytes());
    full[..8].to_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn parse(line: &str) -> Value {
        serde_json::from_str(line).unwrap_or_else(|e| panic!("invalid JSON: {e}\nline: {line}"))
    }

    #[test]
    fn finalize_line_emits_well_formed_json_with_all_constant_fields() {
        let body = body_from_fields(&[("foo", "bar".to_owned())]);
        let line = finalize_line(level::INFO, "ipc.test", "demo_event", body, 1_700_000_000);
        let v = parse(&line);
        assert_eq!(v["level"],   "info");
        assert_eq!(v["module"],  "ipc.test");
        assert_eq!(v["event"],   "demo_event");
        assert_eq!(v["ts_unix"], 1_700_000_000);
        assert_eq!(v["foo"],     "bar");
    }

    /// **Regression**: any value put through `body_from_fields` /
    /// `finalize_line` MUST be properly JSON-escaped, even when it
    /// contains `"` or `\` or control characters. The pre-existing
    /// hand-rolled `eprintln!("{{\"key\":\"{val}\"}}")` pattern
    /// breaks on these inputs and produces non-parseable JSON.
    #[test]
    fn finalize_line_escapes_quotes_and_backslashes_in_field_values() {
        let payload = "danger: \" inside \\ quotes";
        let body = body_from_fields(&[("payload", payload.to_owned())]);
        let line = finalize_line(level::WARN, "ipc.test", "escape_test", body, 0);
        let v = parse(&line);
        assert_eq!(v["payload"], payload);
    }

    #[test]
    fn finalize_line_escapes_newlines_and_tabs() {
        let payload = "line1\nline2\twith\rcontrol";
        let body = body_from_fields(&[("payload", payload.to_owned())]);
        let line = finalize_line(level::WARN, "ipc.test", "escape_test", body, 0);
        let v = parse(&line);
        assert_eq!(v["payload"], payload);
        // The serialised line must be exactly one physical line — the
        // '\n' inside the value must be escaped as `\\n`, not emitted
        // as a literal newline that breaks downstream line-oriented
        // log readers.
        assert_eq!(line.lines().count(), 1, "log line must remain single-line: {line:?}");
    }

    /// Pin the level constants — these end up in operator dashboards
    /// and grep recipes.
    #[test]
    fn level_constants_are_pinned() {
        assert_eq!(level::INFO,  "info");
        assert_eq!(level::WARN,  "warn");
        assert_eq!(level::ERROR, "error");
    }

    /// `credential_fingerprint` must never echo any prefix of the
    /// raw input. Pre-fix history: gateway/accept.rs was logging the
    /// first 8 chars of the raw token, leaking 32 bits of credential
    /// material on every successful handshake. The fingerprint helper
    /// derives those 32 bits from a SHA-256 instead, so an attacker
    /// who captures the log learns nothing about the underlying token
    /// bytes (one-way function).
    #[test]
    fn credential_fingerprint_does_not_echo_a_prefix_of_the_input() {
        let token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let fp = credential_fingerprint(token);
        assert_eq!(fp.len(), 8);
        assert!(
            !token.starts_with(&fp),
            "fingerprint MUST NOT be a prefix of the raw token; got fp={fp}",
        );
    }

    /// A credential's fingerprint must be deterministic so two log
    /// lines from the same credential correlate.
    #[test]
    fn credential_fingerprint_is_deterministic() {
        let token = "shared-token-string";
        let a = credential_fingerprint(token);
        let b = credential_fingerprint(token);
        assert_eq!(a, b);
    }

    /// Different credentials must have different fingerprints in
    /// practice (collision probability for two distinct strings is
    /// ~1 in 2^32 with the 8-char window).
    #[test]
    fn credential_fingerprint_differs_for_different_inputs() {
        let a = credential_fingerprint("token-a-aaaa");
        let b = credential_fingerprint("token-b-bbbb");
        assert_ne!(a, b, "distinct inputs must hash to distinct fingerprints");
    }

    /// Empty input must still produce a stable 8-char fingerprint
    /// rather than panicking — defensive against the
    /// "credential not yet set" path on the gateway accept side.
    #[test]
    fn credential_fingerprint_handles_empty_string() {
        let fp = credential_fingerprint("");
        assert_eq!(fp.len(), 8);
    }
}
