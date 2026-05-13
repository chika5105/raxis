//! Tool-side audit emission for credential-bearing executor tools.
//!
//! ## Why this lives in the planner crate
//!
//! The host-side credential proxies already emit kernel-class audit
//! events (`DatabaseQueryExecuted`, `MongoCommandExecuted`,
//! `RedisCommandExecuted`, `SmtpMessageRelayed`, ...) the moment a
//! query frame arrives on the loopback listener — those events are
//! the load-bearing source of truth for the audit chain. The planner-
//! side audit sink declared here is a **complementary observability
//! channel**: it records the tool invocation's *agent-visible*
//! shape — schema sha256, duration, result class, error class — so
//! tests can assert that a tool behaved correctly even when no real
//! proxy is wired into the test fixture.
//!
//! Per the V2 `credential-proxy.md §14.5` cross-walk:
//!
//!   * Proxy-side: `DatabaseQueryExecuted` / `RedisCommandExecuted`
//!     / `SmtpMessageRelayed` (emitted **only** when the wire frame
//!     reaches the proxy; carries the canonical `sha256(query)` the
//!     reviewer dashboards key off).
//!   * Tool-side: `ToolAuditEvent` (emitted on every tool invocation,
//!     including ones that fail before the wire-frame ever leaves the
//!     VM, e.g. `ProxyUnreachable` / `MissingEnv`). Carries the same
//!     `query_sha256` so the two events pair on inspection.
//!
//! The sink is a trait so tests can capture events without depending
//! on a tracing subscriber; production binaries install a sink that
//! forwards to `tracing::info!` (or to the planner's IPC for kernel-
//! side reflection). The default `ToolContext` ships with no sink —
//! tools must still complete successfully when no sink is installed,
//! emitting events is best-effort observability and never a load-
//! bearing correctness mechanism.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Stable wire-shape error categories for credential-bearing tools.
///
/// Tools surface a structured-error `ToolOutput` whose `content` is
/// JSON-encoded `{ "error_class": ..., "message": ... }`. The
/// `error_class` is the only string the reviewer dashboards key off
/// — operators do NOT have to grep the human-readable `message`.
///
/// Adding a new variant is forward-compatible: the
/// `Other(&'static str)` arm lets a tool ship a class string that is
/// not (yet) in the canonical enum without breaking
/// `serde::Deserialize` on the test fixture. Production callers
/// SHOULD pick one of the canonical variants below; the `Other` arm
/// exists for forward-compat only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ToolErrorClass {
    /// Could not open a TCP connection to the loopback proxy at all
    /// (ECONNREFUSED / ENOENT / similar). Indicates the credential-
    /// proxy manager did not stamp a listener for this credential —
    /// the kernel + session-spawn path is the right place to look.
    ProxyUnreachable,
    /// The proxy returned a protocol-level authentication failure.
    /// Surface to the operator so they can rotate the credential.
    AuthFailed,
    /// The agent's query had a syntax error — the proxy or upstream
    /// rejected it without running it. The LLM is expected to
    /// observe this and self-correct.
    QuerySyntax,
    /// The query ran but the upstream raised a runtime error
    /// (constraint violation, missing column, type mismatch, ...).
    /// Recoverable from the LLM's perspective.
    QueryRuntime,
    /// The result set exceeded the per-tool row / document / byte
    /// cap. The result body is truncated; the LLM can issue a
    /// narrower query or use a server-side `LIMIT` / `COUNT`.
    ResultTooLarge,
    /// The tool's wall-clock timeout fired before the upstream
    /// returned a terminal frame.
    Timeout,
    /// The tool was missing a required argument or an env var
    /// (`DATABASE_URL` / `MONGO_URL` / `REDIS_URL` / `SMTP_URL`).
    /// The kernel session-spawn path is the right place to look.
    MissingEnv,
    /// Catch-all forward-compat arm. New tools MAY ship a class
    /// string not yet in the canonical enum; the canonical enum
    /// SHOULD then be widened before V3 ships.
    #[serde(rename = "Other")]
    Other(String),
}

impl ToolErrorClass {
    /// Stable wire-shape short string. Round-trips through serde so a
    /// recorded event can be parsed back into the same variant.
    pub fn as_str(&self) -> &str {
        match self {
            Self::ProxyUnreachable => "ProxyUnreachable",
            Self::AuthFailed       => "AuthFailed",
            Self::QuerySyntax      => "QuerySyntax",
            Self::QueryRuntime     => "QueryRuntime",
            Self::ResultTooLarge   => "ResultTooLarge",
            Self::Timeout          => "Timeout",
            Self::MissingEnv       => "MissingEnv",
            Self::Other(s)         => s.as_str(),
        }
    }
}

/// Outcome shape of one tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ToolAuditOutcome {
    /// Tool ran successfully end-to-end. `rows_returned` is the
    /// number of rows / documents / commands / messages the tool
    /// observed (counter semantics are per-tool; see each tool's
    /// inline doc).
    Ok {
        /// Per-tool row/document/message counter. `0` when the tool
        /// has no natural counter (e.g. `redis_query` for a `SET`).
        rows_returned: u64,
        /// Whether the response was truncated to fit the per-tool
        /// cap. Pairs with `error_class: ResultTooLarge` on the
        /// error path; on the OK path it surfaces here as a flag so
        /// audit readers can detect cap-hit without re-running.
        truncated: bool,
    },
    /// Tool surfaced a structured error.
    Err {
        /// Canonical error class.
        error_class: ToolErrorClass,
    },
}

/// One tool-side audit envelope.
///
/// **Sanitization contract.** This envelope MUST NEVER carry query
/// parameter values, credential bytes, raw response rows, or the
/// raw upstream error text. The only payload-shaped field is
/// `query_sha256` (a hex SHA-256 of the canonical query string the
/// tool would have shipped, computed BEFORE any param substitution).
/// The reviewer dashboards and forensic readers cross-correlate this
/// hash with the proxy-side `DatabaseQueryExecuted::sql_sha256` so
/// no plaintext leaves the planner without a paired proxy event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolAuditEvent {
    /// Tool name as registered in the executor registry (e.g.
    /// `"postgres_query"`).
    pub tool: &'static str,
    /// SHA-256 (hex, lowercase) of the canonical query / command /
    /// envelope. Always present so audit chain inspection can pair
    /// the tool event with the proxy event.
    pub query_sha256: String,
    /// Wall-clock duration of the tool invocation, in milliseconds.
    pub duration_ms: u32,
    /// Outcome shape (Ok with counter / Err with error_class).
    pub outcome: ToolAuditOutcome,
}

impl ToolAuditEvent {
    /// Build an Ok event.
    pub fn ok(
        tool:          &'static str,
        query_sha256:  String,
        duration:      Duration,
        rows_returned: u64,
        truncated:     bool,
    ) -> Self {
        Self {
            tool,
            query_sha256,
            duration_ms: duration_ms_u32(duration),
            outcome: ToolAuditOutcome::Ok { rows_returned, truncated },
        }
    }

    /// Build an Err event.
    pub fn err(
        tool:         &'static str,
        query_sha256: String,
        duration:     Duration,
        error_class:  ToolErrorClass,
    ) -> Self {
        Self {
            tool,
            query_sha256,
            duration_ms: duration_ms_u32(duration),
            outcome: ToolAuditOutcome::Err { error_class },
        }
    }
}

/// Saturating cast of `Duration` → `u32` milliseconds. Tools that
/// exceed `u32::MAX` ms (~49 days) are pathologically wedged; the
/// saturating cast keeps the event well-formed rather than panicking.
fn duration_ms_u32(d: Duration) -> u32 {
    let ms = d.as_millis();
    if ms > u32::MAX as u128 { u32::MAX } else { ms as u32 }
}

/// **Tool-side audit sink.** Tools call [`ToolAuditSink::emit`]
/// after every invocation; the sink decides how to surface the
/// event (stderr, kernel IPC, in-memory recorder for tests).
///
/// The trait is intentionally minimal — no async, no error path —
/// so a tool's success path is never gated on the sink. A panicking
/// sink would corrupt the dispatch loop; implementations MUST NOT
/// panic.
pub trait ToolAuditSink: Send + Sync + std::fmt::Debug {
    /// Best-effort emit. Implementations MUST NOT block the caller
    /// (long-running implementations should hand off to a worker
    /// task internally).
    fn emit(&self, event: ToolAuditEvent);
}

/// In-memory audit-sink for tests. Records every emitted event
/// behind a `Mutex<Vec<_>>`. Construct one per test, install it on
/// the [`crate::tools::ToolContext`], drive the tool, then inspect
/// [`RecordingAuditSink::events`] to assert against the recorded
/// envelope.
#[derive(Debug, Default, Clone)]
pub struct RecordingAuditSink {
    inner: Arc<Mutex<Vec<ToolAuditEvent>>>,
}

impl RecordingAuditSink {
    /// Construct an empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every recorded event. The returned `Vec` is a clone;
    /// the internal buffer is left in place so the same recorder can
    /// be inspected multiple times.
    pub fn events(&self) -> Vec<ToolAuditEvent> {
        self.inner
            .lock()
            .expect("audit sink mutex poisoned")
            .clone()
    }
}

impl ToolAuditSink for RecordingAuditSink {
    fn emit(&self, event: ToolAuditEvent) {
        if let Ok(mut g) = self.inner.lock() {
            g.push(event);
        }
        // Poisoned mutex → silently drop. The audit sink MUST NOT
        // surface errors to the tool's hot path; poisoning is a
        // test-fixture bug, not a runtime one.
    }
}

/// Compute the lowercase-hex SHA-256 of the given bytes. Used by
/// every credential-bearing tool to derive `ToolAuditEvent::query_sha256`
/// from the canonical query / command / envelope string.
pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input.as_ref());
    let digest = hasher.finalize();
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_lowercase_64chars() {
        let h = sha256_hex(b"SELECT 1");
        assert_eq!(h.len(), 64,
            "SHA-256 hex digest MUST be 64 chars");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "digest MUST be lowercase hex, got: {h}");
    }

    #[test]
    fn tool_error_class_serializes_as_pascal_case_string() {
        let c = ToolErrorClass::ProxyUnreachable;
        let s = serde_json::to_string(&c).unwrap();
        assert_eq!(s, "\"ProxyUnreachable\"");
        let back: ToolErrorClass = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ToolErrorClass::ProxyUnreachable);
    }

    #[test]
    fn tool_error_class_other_round_trips() {
        let c = ToolErrorClass::Other("CustomVariant".to_owned());
        let s = serde_json::to_string(&c).unwrap();
        // serde external tagging for the Other variant emits
        // `{"Other": "CustomVariant"}`.
        assert!(s.contains("CustomVariant"));
        let back: ToolErrorClass = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn recording_sink_captures_every_event() {
        let sink = RecordingAuditSink::new();
        sink.emit(ToolAuditEvent::ok(
            "test_tool",
            sha256_hex(b"q1"),
            Duration::from_millis(5),
            3,
            false,
        ));
        sink.emit(ToolAuditEvent::err(
            "test_tool",
            sha256_hex(b"q2"),
            Duration::from_millis(7),
            ToolErrorClass::Timeout,
        ));
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].duration_ms, 5);
        match &events[1].outcome {
            ToolAuditOutcome::Err { error_class } => {
                assert_eq!(error_class, &ToolErrorClass::Timeout);
            }
            other => panic!("expected Err outcome, got {other:?}"),
        }
    }

    #[test]
    fn recording_sink_is_thread_safe() {
        // Multiple threads emit concurrently; every event MUST
        // survive the recording (no lost writes from the mutex).
        let sink = RecordingAuditSink::new();
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let s = sink.clone();
                std::thread::spawn(move || {
                    s.emit(ToolAuditEvent::ok(
                        "concurrent",
                        sha256_hex(format!("q{i}").as_bytes()),
                        Duration::from_millis(i as u64),
                        i as u64,
                        false,
                    ));
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(sink.events().len(), 16);
    }

    #[test]
    fn duration_ms_saturates_above_u32_max() {
        let huge = Duration::from_secs(60 * 60 * 24 * 365 * 100);
        assert_eq!(duration_ms_u32(huge), u32::MAX,
            "100-year duration must saturate to u32::MAX rather than panic");
    }

    #[test]
    fn tool_audit_event_serializes_with_outcome_tag() {
        let ev = ToolAuditEvent::ok(
            "postgres_query",
            "deadbeef".to_owned(),
            Duration::from_millis(42),
            7,
            false,
        );
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains("\"tool\":\"postgres_query\""));
        assert!(s.contains("\"kind\":\"ok\""));
        assert!(s.contains("\"rows_returned\":7"));
        assert!(s.contains("\"duration_ms\":42"));
    }
}
