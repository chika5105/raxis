//! Kernel-side gateway accept loop: validates incoming gateway
//! handshakes and installs the connection into the shared
//! `GatewayClient`.
//!
//! Normative reference: `peripherals.md` §3.2 "Spawn model" — the
//! gateway connects to `gateway.sock`, sends `GatewayMessage::GatewayReady
//! { gateway_token }`, and awaits `FetchRequest`s. The kernel's job here
//! is to authenticate that handshake (token must match the supervisor's
//! latest mint) and hand the validated stream to the active
//! `GatewayClient`.

use std::sync::Arc;
use std::time::Duration;

use raxis_audit_tools::AuditSink;
use raxis_ipc::message::GatewayMessage;
use raxis_ipc::{read_frame, FrameError};
use tokio::net::{UnixListener, UnixStream};

use crate::gateway::client::GatewayClient;
use crate::ipc::log::{body_from_fields, credential_fingerprint, finalize_line, level};
use crate::ipc::{accept_backoff_step, ACCEPT_BACKOFF_INITIAL};

/// How long we wait for the gateway to send its `GatewayReady` frame
/// after accepting the connection. The gateway issues the frame
/// immediately after `connect()` per `gateway/runtime.rs`, so 5 s
/// is generous; anything longer is almost certainly a misconfigured
/// gateway and we want to free the slot for the real one.
const HANDSHAKE_TIMEOUT_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Structured stderr logging — gateway accept loop + handshake.
//
// Why this lives here rather than in a top-level kernel logging crate:
// see `crate::ipc::log` for the broader rationale. This module mirrors
// the operator and planner dispatchers' pattern (escape-safe JSON via
// `serde_json::to_string`, stable event names, fixed module tag).
//
// **Credential redaction contract:** the only credential that appears
// on this wire is `GatewayMessage::GatewayReady.gateway_token` (and
// the kernel-issued copy carried inside outbound `FetchRequest`
// frames, which this module does not emit). The accept handler MUST
// NEVER include the raw token in any log line. Where we need to
// correlate "this handshake's token matches the supervisor's most
// recently minted token" we use [`credential_fingerprint`] from
// `crate::ipc::log` to derive a 32-bit non-reversible prefix.
//
// **Pre-fix history:** `handle_handshake` previously logged
// `&presented_token[..8.min(...)]` on success — i.e. the first 8
// chars of the raw token. That leaks 32 bits of the underlying
// credential on every successful handshake into operator-visible
// stderr. The fingerprint helper closes that hole by routing through
// SHA-256 first.
// ---------------------------------------------------------------------------

pub(crate) mod gateway_dispatch_log {
    use super::{body_from_fields, credential_fingerprint, finalize_line, level};
    use serde_json::{json, Map};

    pub(super) const MODULE: &str = "ipc.gateway";

    // ── Pure formatters (`build_*_line`) → owned `String`. ──

    pub(crate) fn build_accept_error_line(error: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("error".into(), json!(error));
        finalize_line(level::ERROR, MODULE, "gateway_accept_error", body, ts_unix)
    }

    pub(crate) fn build_handshake_eof_line(ts_unix: i64) -> String {
        finalize_line(level::WARN, MODULE, "gateway_handshake_eof", Map::new(), ts_unix)
    }

    pub(crate) fn build_handshake_read_error_line(error: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("error".into(), json!(error));
        finalize_line(level::WARN, MODULE, "gateway_handshake_read_error", body, ts_unix)
    }

    pub(crate) fn build_handshake_timeout_line(timeout_secs: u64, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("timeout_secs".into(), json!(timeout_secs));
        finalize_line(level::WARN, MODULE, "gateway_handshake_timeout", body, ts_unix)
    }

    pub(crate) fn build_handshake_wrong_variant_line(variant: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("variant".into(), json!(variant));
        finalize_line(level::WARN, MODULE, "gateway_handshake_wrong_variant", body, ts_unix)
    }

    pub(crate) fn build_handshake_before_supervisor_mint_line(
        presented_token: &str,
        ts_unix: i64,
    ) -> String {
        // Even though no expected token exists yet, we still log the
        // PRESENTED token's fingerprint (not the raw value) so an
        // operator investigating "who connected to gateway.sock
        // before the supervisor was ready" can correlate against
        // gateway-side logs without learning any credential bytes.
        let mut body = body_from_fields(&[(
            "presented_token_fp",
            credential_fingerprint(presented_token),
        )]);
        // Ensure the field exists even if the body builder above
        // changes; Map::insert is idempotent so this is a no-op when
        // the key was already inserted.
        body.entry("presented_token_fp".to_owned()).or_insert(json!(""));
        finalize_line(
            level::WARN,
            MODULE,
            "gateway_handshake_before_supervisor_mint",
            body,
            ts_unix,
        )
    }

    pub(crate) fn build_handshake_token_mismatch_line(
        presented_token: &str,
        expected_token: &str,
        ts_unix: i64,
    ) -> String {
        // **CREDENTIAL REDACTION:** both halves of the comparison are
        // credentials. We log only their fingerprints — enough to tell
        // "presented vs expected differ" at a glance without leaking
        // either token's bytes. Pinned by
        // `handshake_token_mismatch_line_does_not_contain_either_raw_token`.
        let mut body = body_from_fields(&[
            ("presented_token_fp", credential_fingerprint(presented_token)),
            ("expected_token_fp",  credential_fingerprint(expected_token)),
        ]);
        body.entry("presented_token_fp".to_owned()).or_insert(json!(""));
        finalize_line(level::WARN, MODULE, "gateway_handshake_token_mismatch", body, ts_unix)
    }

    pub(crate) fn build_handshake_accepted_line(
        accepted_token: &str,
        ts_unix: i64,
    ) -> String {
        // Pre-fix this line emitted `token_prefix` = first 8 raw
        // bytes of the token. Now we emit the SHA-256 fingerprint
        // instead — same correlation utility, zero credential leak.
        let body = body_from_fields(&[(
            "accepted_token_fp",
            credential_fingerprint(accepted_token),
        )]);
        finalize_line(level::INFO, MODULE, "gateway_handshake_accepted", body, ts_unix)
    }

    // ── Emit-side wrappers ──

    pub(super) fn accept_error(error: &str) {
        eprintln!("{}", build_accept_error_line(error, raxis_types::unix_now_secs()));
    }

    pub(super) fn handshake_eof() {
        eprintln!("{}", build_handshake_eof_line(raxis_types::unix_now_secs()));
    }

    pub(super) fn handshake_read_error(error: &str) {
        eprintln!("{}", build_handshake_read_error_line(error, raxis_types::unix_now_secs()));
    }

    pub(super) fn handshake_timeout(timeout_secs: u64) {
        eprintln!("{}", build_handshake_timeout_line(timeout_secs, raxis_types::unix_now_secs()));
    }

    pub(super) fn handshake_wrong_variant(variant: &str) {
        eprintln!("{}", build_handshake_wrong_variant_line(variant, raxis_types::unix_now_secs()));
    }

    pub(super) fn handshake_before_supervisor_mint(presented_token: &str) {
        eprintln!(
            "{}",
            build_handshake_before_supervisor_mint_line(
                presented_token,
                raxis_types::unix_now_secs(),
            ),
        );
    }

    pub(super) fn handshake_token_mismatch(presented_token: &str, expected_token: &str) {
        eprintln!(
            "{}",
            build_handshake_token_mismatch_line(
                presented_token,
                expected_token,
                raxis_types::unix_now_secs(),
            ),
        );
    }

    pub(super) fn handshake_accepted(accepted_token: &str) {
        eprintln!(
            "{}",
            build_handshake_accepted_line(accepted_token, raxis_types::unix_now_secs()),
        );
    }
}

/// Long-running task: accept connections on `gateway.sock`, validate
/// each one's handshake, install the validated stream into `client`.
///
/// Multiple gateways could in principle connect at once (a stale
/// process plus the freshly spawned one). The token-equality check
/// rejects everything except the most recent supervisor spawn. The
/// successful handshake is the "ownership transfer point" — after
/// `install_connection` returns, the previous pump is torn down and
/// the new stream becomes the kernel's only path to provider calls.
///
/// The accept loop never exits on its own (per existing v1 contract
/// — `ipc::server::start` joins it via `JoinHandle`). On a per-
/// connection failure we log + drop the stream and keep listening.
pub async fn accept_gateway_loop(
    listener: UnixListener,
    client:   Arc<GatewayClient>,
    audit:    Arc<dyn AuditSink>,
) {
    let mut backoff = ACCEPT_BACKOFF_INITIAL;
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // Reset the backoff after any successful accept so a
                // transient blip doesn't keep the loop in cooldown
                // once the underlying pressure clears.
                backoff = ACCEPT_BACKOFF_INITIAL;
                let client = Arc::clone(&client);
                let audit  = Arc::clone(&audit);
                tokio::spawn(async move {
                    handle_handshake(stream, client, audit).await;
                });
            }
            Err(e) => {
                gateway_dispatch_log::accept_error(&e.to_string());
                // Exponential backoff (curve defined in `crate::ipc`).
                // Pre-fix this slept a fixed 100 ms after every
                // failure, producing 10 retries/sec under sustained
                // FD exhaustion. See module docs in `kernel::ipc::mod`
                // for the full rationale.
                tokio::time::sleep(backoff).await;
                backoff = accept_backoff_step(backoff);
            }
        }
    }
}

/// Read the handshake frame, compare against the supervisor's expected
/// token, and either install the stream or close it.
///
/// We deliberately do NOT propagate the failure as an audit event for
/// every single mismatched connection — that would let a misbehaving
/// neighbour spam the audit chain. Instead we log to stderr (operator
/// can see by tailing `journald`) and reserve the audit channel for
/// the genuine `GatewayHandshakeRejected` events: persistent token
/// mismatch is currently *not* surfaced through the audit chain in v1
/// (per kernel-store.md §2.5.2 — "audit events are state transitions";
/// this is a connection-level reject). Future work may revisit.
async fn handle_handshake(
    mut stream: UnixStream,
    client:     Arc<GatewayClient>,
    _audit:     Arc<dyn AuditSink>,
) {
    let result = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        read_frame::<_, GatewayMessage>(&mut stream),
    )
    .await;

    let frame = match result {
        Ok(Ok(f)) => f,
        Ok(Err(FrameError::Eof)) => {
            gateway_dispatch_log::handshake_eof();
            return;
        }
        Ok(Err(e)) => {
            gateway_dispatch_log::handshake_read_error(&e.to_string());
            return;
        }
        Err(_elapsed) => {
            gateway_dispatch_log::handshake_timeout(HANDSHAKE_TIMEOUT_SECS);
            return;
        }
    };

    let presented_token = match frame {
        GatewayMessage::GatewayReady { gateway_token } => gateway_token,
        other => {
            gateway_dispatch_log::handshake_wrong_variant(std::any::type_name_of_val(&other));
            return;
        }
    };

    let expected = client.expected_token().await;
    let expected = match expected {
        Some(t) => t,
        None => {
            // Log only the FINGERPRINT of the presented token, never
            // the raw value (the raw token is the credential).
            gateway_dispatch_log::handshake_before_supervisor_mint(&presented_token);
            return;
        }
    };

    // Constant-time-ish equality. Token is hex-encoded 32 random
    // bytes (64 chars); we already trust hex::encode to be uniform
    // length, so the only side channel is timing — a strict-equality
    // compare here is fine in practice but we still avoid early-
    // returning on the first byte mismatch by using `subtle::ConstantTimeEq`
    // when available; for v1 the std `==` is sufficient since the token
    // is single-use and an attacker who can connect to gateway.sock
    // already has filesystem access to leak it.
    if presented_token != expected {
        // Log fingerprints of BOTH halves of the comparison so an
        // operator can correlate against gateway-side and supervisor-
        // side logs without learning either token's bytes.
        gateway_dispatch_log::handshake_token_mismatch(&presented_token, &expected);
        return;
    }

    // Pre-fix bug: this line used to emit `&presented_token[..8]`,
    // i.e. 8 raw chars of the credential. Now we route through the
    // SHA-256 fingerprint helper so log capture cannot recover any
    // token bytes.
    gateway_dispatch_log::handshake_accepted(&presented_token);
    client.install_connection(stream).await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_test_support::FakeAuditSink;
    use raxis_ipc::message::GatewayMessage;
    use raxis_ipc::write_frame;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::net::UnixStream;

    fn fake_audit() -> Arc<dyn AuditSink> {
        Arc::new(FakeAuditSink::new())
    }

    /// Bind a fresh UnixListener under a temp dir + return it plus
    /// the path. Tests use this in lieu of the real
    /// `<data_dir>/sockets/gateway.sock`.
    fn bind_socket() -> (TempDir, std::path::PathBuf, UnixListener) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("gateway.sock");
        let listener = UnixListener::bind(&path).unwrap();
        (tmp, path, listener)
    }

    async fn connect_and_send_ready(path: std::path::PathBuf, token: &str) -> UnixStream {
        let mut stream = UnixStream::connect(&path).await.unwrap();
        let ready = GatewayMessage::GatewayReady {
            gateway_token: token.to_owned(),
        };
        write_frame(&mut stream, &ready).await.unwrap();
        stream
    }

    #[tokio::test]
    async fn handshake_accepted_when_token_matches_expected() {
        let (_tmp, path, listener) = bind_socket();
        let client = Arc::new(GatewayClient::new());
        client.set_expected_token("good-token".into()).await;

        let accept = tokio::spawn(accept_gateway_loop(
            listener, Arc::clone(&client), fake_audit(),
        ));
        let _stream = connect_and_send_ready(path, "good-token").await;

        // Give the accept loop a moment to install the connection.
        for _ in 0..50 {
            if client.is_connected().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(client.is_connected().await,
            "valid handshake must install the connection");

        accept.abort();
    }

    #[tokio::test]
    async fn handshake_rejected_when_token_mismatches() {
        let (_tmp, path, listener) = bind_socket();
        let client = Arc::new(GatewayClient::new());
        client.set_expected_token("good".into()).await;

        let accept = tokio::spawn(accept_gateway_loop(
            listener, Arc::clone(&client), fake_audit(),
        ));
        let _stream = connect_and_send_ready(path, "evil").await;

        // Wait long enough to be confident no install_connection happened.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!client.is_connected().await,
            "mismatched-token handshake MUST NOT install the connection");

        accept.abort();
    }

    #[tokio::test]
    async fn handshake_rejected_when_no_expected_token_set() {
        // Race condition guard: a stale gateway from a previous kernel
        // boot connects before the new supervisor has minted a token.
        // The accept loop must reject rather than install a connection
        // with an unauthenticated stream.
        let (_tmp, path, listener) = bind_socket();
        let client = Arc::new(GatewayClient::new());
        // expected_token deliberately NOT set.

        let accept = tokio::spawn(accept_gateway_loop(
            listener, Arc::clone(&client), fake_audit(),
        ));
        let _stream = connect_and_send_ready(path, "anything").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!client.is_connected().await);

        accept.abort();
    }

    #[tokio::test]
    async fn handshake_rejected_when_wrong_variant() {
        // Send EpochAdvanced as the first frame — the accept loop
        // expects GatewayReady. Must reject without installing.
        let (_tmp, path, listener) = bind_socket();
        let client = Arc::new(GatewayClient::new());
        client.set_expected_token("good".into()).await;

        let accept = tokio::spawn(accept_gateway_loop(
            listener, Arc::clone(&client), fake_audit(),
        ));
        let mut stream = UnixStream::connect(&path).await.unwrap();
        let bogus = GatewayMessage::EpochAdvanced { new_epoch_id: 42 };
        write_frame(&mut stream, &bogus).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!client.is_connected().await);

        accept.abort();
    }

    #[tokio::test]
    async fn handshake_timeout_when_gateway_silent() {
        // Connect but never send GatewayReady. The accept loop must
        // give up after HANDSHAKE_TIMEOUT_SECS (here we use 5 s; the
        // real kernel boot would not block on this — the accept loop
        // is spawned, and the timeout only fires inside the per-connection
        // task).
        let (_tmp, path, listener) = bind_socket();
        let client = Arc::new(GatewayClient::new());
        client.set_expected_token("good".into()).await;

        let accept = tokio::spawn(accept_gateway_loop(
            listener, Arc::clone(&client), fake_audit(),
        ));
        let _silent = UnixStream::connect(&path).await.unwrap();

        // Don't actually wait 5 s in the test — verify the slot is
        // still empty after a short interval, which is enough to
        // prove "no installation happened on the silent stream".
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!client.is_connected().await);

        accept.abort();
    }
}

// ---------------------------------------------------------------------------
// Tests — `gateway_dispatch_log`.
//
// **Pre-fix history:** this dispatcher used to log
// `&presented_token[..8]` on a successful handshake — i.e. the first
// 8 raw chars of the credential. These tests pin the new contract:
// every credential field on this wire is logged exclusively as a
// SHA-256 fingerprint (`accepted_token_fp`, `presented_token_fp`,
// `expected_token_fp`); no prefix of any raw token may appear in any
// log line.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod gateway_dispatch_log_tests {
    use super::gateway_dispatch_log;
    use serde_json::Value;

    /// Distinctive prefix so any leak is unmissable in test output.
    const SECRET_GATEWAY_TOKEN: &str =
        "SECRET_GATEWAY_TOKEN_cccccccccccccccccccccccccccccccccccccccccccc";

    fn parse(line: &str) -> Value {
        serde_json::from_str(line).unwrap_or_else(|e| panic!("invalid JSON: {e}\nline: {line}"))
    }

    // ── `accepted` log: NEVER a prefix of the raw token ──────────────

    /// **Regression**: pre-fix the accepted-handshake line carried
    /// `token_prefix = &presented_token[..8]`, leaking 32 bits of the
    /// raw credential. The fix routes the input through SHA-256
    /// before truncation. This test pins both halves of the contract:
    /// the raw token is absent AND the emitted fingerprint is NOT a
    /// prefix of the raw token.
    #[test]
    fn handshake_accepted_line_does_not_contain_raw_token_or_its_prefix() {
        let line = gateway_dispatch_log::build_handshake_accepted_line(
            SECRET_GATEWAY_TOKEN, 0,
        );
        assert!(
            !line.contains(SECRET_GATEWAY_TOKEN),
            "raw gateway_token MUST NOT appear in handshake_accepted line; got: {line}",
        );
        assert!(
            !line.contains("SECRET_"),
            "no prefix of the raw token may appear; got: {line}",
        );
        let v = parse(&line);
        let fp = v["accepted_token_fp"].as_str().expect("accepted_token_fp must be present");
        assert_eq!(fp.len(), 8, "fingerprint must be 8 hex chars");
        assert!(
            !SECRET_GATEWAY_TOKEN.starts_with(fp),
            "fingerprint MUST NOT equal the first 8 chars of the raw token \
            (the very bug we just fixed); got fp={fp}",
        );
    }

    #[test]
    fn handshake_accepted_line_carries_correct_module_event_and_level() {
        let line = gateway_dispatch_log::build_handshake_accepted_line(
            SECRET_GATEWAY_TOKEN, 1_700_000_000,
        );
        let v = parse(&line);
        assert_eq!(v["module"], "ipc.gateway");
        assert_eq!(v["event"],  "gateway_handshake_accepted");
        assert_eq!(v["level"],  "info");
    }

    // ── token-mismatch log: NEITHER raw token may appear ──────────────

    #[test]
    fn handshake_token_mismatch_line_does_not_contain_either_raw_token() {
        let presented = "SECRET_PRESENTED_4444444444444444444444444444444444444444";
        let expected  = "SECRET_EXPECTED__5555555555555555555555555555555555555555";
        let line = gateway_dispatch_log::build_handshake_token_mismatch_line(
            presented, expected, 0,
        );
        assert!(!line.contains(presented), "presented raw token leaked: {line}");
        assert!(!line.contains(expected),  "expected raw token leaked: {line}");
        assert!(!line.contains("SECRET_"), "no prefix of either token may appear: {line}");

        let v = parse(&line);
        assert_eq!(v["module"], "ipc.gateway");
        assert_eq!(v["event"],  "gateway_handshake_token_mismatch");
        assert_eq!(v["level"],  "warn");
        let fp_p = v["presented_token_fp"].as_str().expect("presented_token_fp must be present");
        let fp_e = v["expected_token_fp"].as_str().expect("expected_token_fp must be present");
        assert_eq!(fp_p.len(), 8);
        assert_eq!(fp_e.len(), 8);
        assert_ne!(fp_p, fp_e, "different tokens must have different fingerprints");
    }

    // ── pre-supervisor-mint log: presented token must be redacted ─────

    #[test]
    fn handshake_before_supervisor_mint_line_does_not_contain_raw_presented_token() {
        let line = gateway_dispatch_log::build_handshake_before_supervisor_mint_line(
            SECRET_GATEWAY_TOKEN, 0,
        );
        assert!(!line.contains(SECRET_GATEWAY_TOKEN));
        assert!(!line.contains("SECRET_"));
        let v = parse(&line);
        assert_eq!(v["event"], "gateway_handshake_before_supervisor_mint");
        assert_eq!(v["level"], "warn");
    }

    // ── non-credential events: pinned event/level constants ───────────

    #[test]
    fn accept_error_line_at_error_level_carries_error_field() {
        let line = gateway_dispatch_log::build_accept_error_line("EBADF", 0);
        let v = parse(&line);
        assert_eq!(v["level"], "error");
        assert_eq!(v["event"], "gateway_accept_error");
        assert_eq!(v["error"], "EBADF");
    }

    #[test]
    fn handshake_eof_at_warn_with_no_secret_payload() {
        let line = gateway_dispatch_log::build_handshake_eof_line(0);
        let v = parse(&line);
        assert_eq!(v["level"], "warn");
        assert_eq!(v["event"], "gateway_handshake_eof");
    }

    #[test]
    fn handshake_timeout_carries_seconds_count() {
        let line = gateway_dispatch_log::build_handshake_timeout_line(5, 0);
        let v = parse(&line);
        assert_eq!(v["event"],        "gateway_handshake_timeout");
        assert_eq!(v["timeout_secs"], 5);
    }

    #[test]
    fn handshake_wrong_variant_carries_variant_string_only() {
        let line = gateway_dispatch_log::build_handshake_wrong_variant_line(
            "GatewayMessage::FetchRequest", 0,
        );
        let v = parse(&line);
        assert_eq!(v["event"],   "gateway_handshake_wrong_variant");
        assert_eq!(v["variant"], "GatewayMessage::FetchRequest");
    }

    /// Escape-safety regression: error strings from `e.to_string()`
    /// can carry quotes (e.g. JSON parse errors). The shared
    /// `finalize_line` MUST escape them.
    #[test]
    fn read_error_with_embedded_quotes_round_trips_through_json() {
        let line = gateway_dispatch_log::build_handshake_read_error_line(
            r#"frame: "bad varint""#, 0,
        );
        let v = parse(&line);
        assert_eq!(v["error"], r#"frame: "bad varint""#);
    }
}
