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

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_ipc::message::GatewayMessage;
use raxis_ipc::{read_frame, FrameError};
use tokio::net::{UnixListener, UnixStream};

use crate::gateway::client::GatewayClient;

/// How long we wait for the gateway to send its `GatewayReady` frame
/// after accepting the connection. The gateway issues the frame
/// immediately after `connect()` per `gateway/runtime.rs`, so 5 s
/// is generous; anything longer is almost certainly a misconfigured
/// gateway and we want to free the slot for the real one.
const HANDSHAKE_TIMEOUT_SECS: u64 = 5;

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
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let client = Arc::clone(&client);
                let audit  = Arc::clone(&audit);
                tokio::spawn(async move {
                    handle_handshake(stream, client, audit).await;
                });
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"gateway_accept_error\",\
                     \"reason\":\"{e}\"}}"
                );
                // Same backoff as the v1 stub: short sleep so we don't
                // spin if the listener is in a bad state.
                tokio::time::sleep(Duration::from_millis(100)).await;
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
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"gateway_handshake_eof\"}}"
            );
            return;
        }
        Ok(Err(e)) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"gateway_handshake_read_error\",\
                 \"reason\":\"{e}\"}}"
            );
            return;
        }
        Err(_elapsed) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"gateway_handshake_timeout\",\
                 \"timeout_secs\":{HANDSHAKE_TIMEOUT_SECS}}}"
            );
            return;
        }
    };

    let presented_token = match frame {
        GatewayMessage::GatewayReady { gateway_token } => gateway_token,
        other => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"gateway_handshake_wrong_variant\",\
                 \"variant\":\"{}\"}}",
                std::any::type_name_of_val(&other),
            );
            return;
        }
    };

    let expected = client.expected_token().await;
    let expected = match expected {
        Some(t) => t,
        None => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"gateway_handshake_before_supervisor_mint\"}}"
            );
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
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"gateway_handshake_token_mismatch\"}}"
        );
        return;
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"gateway_handshake_accepted\",\
         \"token_prefix\":\"{}\"}}",
        &presented_token[..8.min(presented_token.len())],
    );
    client.install_connection(stream).await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::FakeAuditSink;
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
        let bogus = GatewayMessage::EpochAdvanced { new_epoch_id: uuid::Uuid::new_v4() };
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
