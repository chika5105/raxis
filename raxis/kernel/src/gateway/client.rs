//! Kernel-side gateway client: forwards `FetchRequest`s to the active
//! gateway subprocess and routes `FetchResponse`s back to callers.
//!
//! Normative reference: `peripherals.md` §3.2 "Wire format" and
//! "Crash-and-respawn"; the user-supplied design note that the kernel
//! "forwards them all over a single Unix Domain Socket to that single
//! gateway process. The gateway simply opens async HTTP streams for
//! all of them concurrently."
//!
//! # Multiplexing model
//!
//! Multiple kernel callers can be in-flight against the gateway at the
//! same time. We do NOT serialize them — that would defeat the gateway's
//! tokio-driven concurrency. Instead:
//!
//!   1. Each caller sends a `Pending { fetch_id, request, reply_tx }`
//!      to the **pump task** via an mpsc.
//!   2. The pump task owns the UnixStream + an `inflight: HashMap<Uuid,
//!      oneshot::Sender>`. It runs a `tokio::select!` that races mpsc
//!      receives (write a frame) against stream reads (route a response
//!      by `fetch_id`).
//!   3. When the gateway crashes (or the supervisor swaps the process),
//!      the pump task exits. All pending oneshot senders are dropped,
//!      so every blocked caller's `recv()` immediately returns
//!      `RecvError`, which we map to `GatewayCallError::Unavailable`.
//!
//! # Connection swap on respawn
//!
//! `install_connection(stream)` replaces the active pump. Sequence:
//!
//!   - Old pump is sent a `kill` via dropping the previous mpsc sender.
//!   - The old pump finishes its current select, finds the mpsc closed,
//!     drops its inflight map → blocked callers see Unavailable.
//!   - A new pump is spawned around the new stream.
//!   - Subsequent `fetch()` calls go through the new mpsc.
//!
//! # Why not a single-mutex stream?
//!
//! A `Mutex<UnixStream>` held across `(write, read)` would force serial
//! execution: a 30 s LLM call would block every other fetch from being
//! sent. The pump task lets writes happen back-to-back while responses
//! are read out of order via `fetch_id` correlation.

use std::collections::HashMap;
use std::sync::Arc;

use raxis_ipc::message::{FetchKind, GatewayMessage};
use raxis_ipc::{read_frame, write_frame, FrameError};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Errors callers can see when invoking `GatewayClient::fetch` or
/// `GatewayClient::notify_epoch_advanced`.
#[derive(Debug, Error)]
pub enum GatewayCallError {
    /// No gateway is currently connected (between supervisor spawn and
    /// the gateway's `GatewayReady` handshake, or after the gateway
    /// crashed and before the supervisor's respawn handshake landed).
    /// Callers SHOULD treat this as transient — the supervisor will
    /// re-establish a connection within `respawn_backoff_ms`.
    #[error("gateway is not currently connected")]
    Unavailable,

    /// The gateway returned a typed `FetchResponse.error` field.
    /// Re-surfaced verbatim so callers can match on the strings the
    /// gateway promises in `peripherals.md` §3.2 (`TimeoutExceeded`,
    /// `DomainNotAllowed`, `ResponseTooLarge`, `PolicyReloadFailed`,
    /// `NetworkError`).
    #[error("gateway returned error: {0}")]
    GatewayError(String),

    /// We sent the request but the gateway disappeared before
    /// returning a response. Treat as transient.
    #[error("gateway connection dropped while request was in flight")]
    Dropped,

    /// The gateway sent a frame but it was the wrong variant (not a
    /// `FetchResponse`). This indicates a wire-protocol bug.
    #[error("gateway sent unexpected message variant")]
    UnexpectedReply,
}

impl GatewayCallError {
    /// Stable short-string used by `AuditEventKind::GatewaySignalFailed.reason`
    /// and forensic tooling. Pinned by tests so the wire never drifts.
    pub fn category(&self) -> &'static str {
        match self {
            GatewayCallError::Unavailable     => "unavailable",
            GatewayCallError::Dropped         => "dropped",
            GatewayCallError::GatewayError(_) => "gateway_error",
            GatewayCallError::UnexpectedReply => "unexpected_reply",
        }
    }
}

/// One outstanding fetch waiting on the pump task.
struct Pending {
    fetch_id: Uuid,
    payload:  GatewayMessage, // ALWAYS GatewayMessage::FetchRequest
    reply_tx: oneshot::Sender<Result<FetchResult, GatewayCallError>>,
}

/// A one-way frame the kernel pushes to the gateway with no response
/// expected (e.g. `EpochAdvanced`). The pump writes the frame and
/// signals the caller via `ack_tx` once the bytes are on the wire OR
/// the write failed. We do NOT wait for any reply from the gateway —
/// signal semantics are best-effort fire-and-forget.
struct OneShot {
    payload: GatewayMessage,
    ack_tx:  oneshot::Sender<Result<(), GatewayCallError>>,
}

/// What the pump task accepts. Either an in-flight `Pending` (correlated
/// by `fetch_id`) or a fire-and-forget `OneShot` (no `fetch_id`).
enum PumpJob {
    Fetch(Pending),
    Signal(OneShot),
}

/// What we hand back to the caller on a successful `fetch_id` round trip.
/// Mirrors the `FetchResponse` variant fields verbatim so callers do not
/// need to pattern-match against `GatewayMessage`.
#[derive(Debug, Clone)]
pub struct FetchResult {
    pub fetch_id:    Uuid,
    pub status_code: Option<u16>,
    pub headers:     Vec<(String, String)>,
    pub body_bytes:  Option<Vec<u8>>,
    pub latency_ms:  u32,
}

/// Shared state visible to both the supervisor (which `set_expected_token`s
/// before each spawn) and the kernel-side accept loop (which validates
/// `GatewayReady` against that token, then `install_connection`s the
/// stream).
///
/// Cheap to clone — the inner state is `Arc<Mutex<...>>`.
#[derive(Clone, Default)]
pub struct GatewayClient {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Latest token the supervisor expects the gateway to present in
    /// its `GatewayReady` handshake. `None` between kernel boot and
    /// the very first supervisor spawn.
    expected_token: Mutex<Option<String>>,
    /// Sender into the active pump task. `None` when no gateway is
    /// connected. Dropped to terminate the pump.
    submit:         Mutex<Option<mpsc::UnboundedSender<PumpJob>>>,
}

impl GatewayClient {
    /// Construct an empty client with no expected token and no
    /// active connection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the token the next handshake must present.
    ///
    /// Called by `gateway::supervisor::spawn_and_supervise` immediately
    /// after `mint_token` and immediately before `spawn_child`. The
    /// accept loop reads this on every incoming `GatewayReady`.
    pub async fn set_expected_token(&self, token: String) {
        *self.inner.expected_token.lock().await = Some(token);
    }

    /// Returns the currently expected token (used by the accept loop
    /// to validate the gateway's handshake).
    pub async fn expected_token(&self) -> Option<String> {
        self.inner.expected_token.lock().await.clone()
    }

    /// Returns `true` iff a pump task is currently running. Useful for
    /// `raxis status` and for cheap fast-fail in tests.
    pub async fn is_connected(&self) -> bool {
        self.inner.submit.lock().await.is_some()
    }

    /// Replace the active gateway connection. Spawns a fresh pump task
    /// around `stream`; tears down any pre-existing pump (whose mpsc
    /// will be dropped).
    pub async fn install_connection(&self, stream: UnixStream) {
        let (tx, rx) = mpsc::unbounded_channel::<PumpJob>();
        let mut slot = self.inner.submit.lock().await;
        // Drop the prior sender if any → old pump exits → blocked
        // callers see Unavailable via `RecvError`.
        let _previous = slot.take();
        *slot = Some(tx);
        drop(slot);
        tokio::spawn(pump(stream, rx));
    }

    /// Disconnect the active gateway, if any. Used by the supervisor
    /// on graceful shutdown after it has SIGKILLed the child. Future
    /// `fetch` calls will return `Unavailable` until a new connection
    /// is installed.
    pub async fn disconnect(&self) {
        let mut slot = self.inner.submit.lock().await;
        let _ = slot.take();
    }

    /// Submit a fetch and await its response.
    ///
    /// Errors:
    /// - `Unavailable`     — no gateway is currently connected
    /// - `Dropped`         — gateway crashed while we were waiting
    /// - `GatewayError(s)` — gateway returned `FetchResponse.error = s`
    /// - `UnexpectedReply` — protocol violation
    pub async fn fetch(
        &self,
        gateway_token: String,
        fetch_kind:    FetchKind,
        url:           String,
        method:        String,
        headers:       Vec<(String, String)>,
        body_bytes:    Vec<u8>,
        timeout_ms:    u32,
        session_id:    Option<Uuid>,
        task_id:       Option<String>,
    ) -> Result<FetchResult, GatewayCallError> {
        let fetch_id = Uuid::new_v4();
        let payload  = GatewayMessage::FetchRequest {
            gateway_token,
            fetch_id,
            fetch_kind,
            url,
            method,
            headers,
            body_bytes,
            timeout_ms,
            session_id,
            task_id,
        };

        let (reply_tx, reply_rx) = oneshot::channel();

        // Snapshot the current submit sender (clone Sender; cheap).
        // Holding the mutex across `send` is fine — `send` on an
        // unbounded channel never awaits.
        {
            let slot = self.inner.submit.lock().await;
            let Some(tx) = slot.as_ref() else {
                return Err(GatewayCallError::Unavailable);
            };
            tx.send(PumpJob::Fetch(Pending { fetch_id, payload, reply_tx }))
                .map_err(|_| GatewayCallError::Unavailable)?;
        }

        match reply_rx.await {
            Ok(res) => res,
            Err(_) => Err(GatewayCallError::Dropped),
        }
    }

    /// Best-effort `EpochAdvanced` signal to the gateway.
    ///
    /// Lifecycle (kernel-core.md §`policy_manager.rs` Phase 3):
    ///
    ///   1. Caller is `handlers/operator::handle_rotate_epoch`, AFTER
    ///      `policy_manager::advance_epoch` succeeded (Phases 0-2 are
    ///      already committed and visible to readers).
    ///   2. We push a `GatewayMessage::EpochAdvanced { new_epoch_id }`
    ///      frame onto the pump. No `fetch_id`, no response expected
    ///      — the pump signals `Ok(())` once the bytes are on the wire.
    ///   3. Failure modes (all surface as `Err`):
    ///      - `Unavailable` — no gateway is currently connected. The
    ///        gateway will re-read `policy.toml` on its next handshake
    ///        anyway (it loads at boot + on every signal), so the
    ///        signal is naturally idempotent across respawns.
    ///      - `Dropped` — gateway socket closed mid-write. The
    ///        supervisor will respawn; same idempotency argument.
    ///      - `GatewayError(_)` — the pump never produces this for a
    ///        fire-and-forget signal (no FetchResponse to surface);
    ///        listed for API uniformity only.
    ///
    /// Spec note: per kernel-core.md §`policy_manager.rs`, the caller
    /// MUST NOT roll back the epoch advance on failure here. The
    /// gateway's own failure-closed contract (returns
    /// `PolicyReloadFailed` on its next request when its on-disk
    /// allowlist is stale) is the second line of defence.
    pub async fn notify_epoch_advanced(
        &self,
        new_epoch_id: u64,
    ) -> Result<(), GatewayCallError> {
        let payload = GatewayMessage::EpochAdvanced { new_epoch_id };
        let (ack_tx, ack_rx) = oneshot::channel();

        {
            let slot = self.inner.submit.lock().await;
            let Some(tx) = slot.as_ref() else {
                return Err(GatewayCallError::Unavailable);
            };
            tx.send(PumpJob::Signal(OneShot { payload, ack_tx }))
                .map_err(|_| GatewayCallError::Unavailable)?;
        }

        match ack_rx.await {
            Ok(res) => res,
            Err(_) => Err(GatewayCallError::Dropped),
        }
    }
}

// ---------------------------------------------------------------------------
// Pump task
// ---------------------------------------------------------------------------

/// Long-lived task that owns the gateway UnixStream until either:
///   - the mpsc is closed (a fresh connection replaced this one), OR
///   - the underlying stream returns EOF / read error.
///
/// Either exit reason drops `inflight`, signalling Unavailable to every
/// pending caller via the broken oneshot.
async fn pump(mut stream: UnixStream, mut rx: mpsc::UnboundedReceiver<PumpJob>) {
    let mut inflight: HashMap<Uuid, oneshot::Sender<Result<FetchResult, GatewayCallError>>> =
        HashMap::new();

    loop {
        tokio::select! {
            // ── outbound: a kernel caller wants to send a frame ─────────
            maybe_job = rx.recv() => {
                let Some(job) = maybe_job else {
                    // mpsc closed — a fresh connection replaced us, OR
                    // the GatewayClient was disconnected. Drain inflight
                    // and exit.
                    break;
                };
                match job {
                    PumpJob::Fetch(pending) => {
                        // Track the in-flight fetch BEFORE writing — if
                        // the write succeeds and the gateway races us
                        // with a response, we MUST already be in the map.
                        inflight.insert(pending.fetch_id, pending.reply_tx);
                        if let Err(e) = write_frame(&mut stream, &pending.payload).await {
                            eprintln!(
                                "{{\"level\":\"warn\",\"event\":\"gateway_write_failed\",\
                                 \"kind\":\"FetchRequest\",\"reason\":\"{e}\"}}"
                            );
                            // Notify just this caller and exit; subsequent
                            // sends would also fail.
                            if let Some(reply) = inflight.remove(&pending.fetch_id) {
                                let _ = reply.send(Err(GatewayCallError::Dropped));
                            }
                            break;
                        }
                    }
                    PumpJob::Signal(one_shot) => {
                        // Fire-and-forget: write the frame, then ack the
                        // caller. There is no response correlation slot
                        // — the gateway is expected to act on the signal
                        // (e.g. reload policy_view) without writing back.
                        match write_frame(&mut stream, &one_shot.payload).await {
                            Ok(()) => {
                                let _ = one_shot.ack_tx.send(Ok(()));
                            }
                            Err(e) => {
                                eprintln!(
                                    "{{\"level\":\"warn\",\"event\":\"gateway_write_failed\",\
                                     \"kind\":\"Signal\",\"reason\":\"{e}\"}}"
                                );
                                let _ = one_shot.ack_tx.send(Err(GatewayCallError::Dropped));
                                // Same exit policy as a failed FetchRequest
                                // write — the stream is now suspect.
                                break;
                            }
                        }
                    }
                }
            }

            // ── inbound: gateway sent something ─────────────────────────
            read_result = read_frame::<_, GatewayMessage>(&mut stream) => {
                match read_result {
                    Ok(GatewayMessage::FetchResponse {
                        fetch_id, status_code, headers, body_bytes, latency_ms, error,
                    }) => {
                        let Some(reply) = inflight.remove(&fetch_id) else {
                            // Response for an unknown fetch_id — log
                            // and drop. Could happen during a swap if
                            // the new gateway echoes a stale id.
                            eprintln!(
                                "{{\"level\":\"warn\",\"event\":\"gateway_unknown_fetch_id\",\
                                 \"fetch_id\":\"{fetch_id}\"}}"
                            );
                            continue;
                        };
                        let outcome = match error {
                            Some(s) => Err(GatewayCallError::GatewayError(s)),
                            None => Ok(FetchResult {
                                fetch_id, status_code, headers, body_bytes, latency_ms,
                            }),
                        };
                        let _ = reply.send(outcome);
                    }
                    Ok(other) => {
                        eprintln!(
                            "{{\"level\":\"warn\",\"event\":\"gateway_unexpected_variant\",\
                             \"variant\":\"{}\"}}",
                            std::any::type_name_of_val(&other),
                        );
                    }
                    Err(FrameError::Eof) => {
                        eprintln!(
                            "{{\"level\":\"info\",\"event\":\"gateway_eof\"}}"
                        );
                        break;
                    }
                    Err(e) => {
                        eprintln!(
                            "{{\"level\":\"warn\",\"event\":\"gateway_read_error\",\
                             \"reason\":\"{e}\"}}"
                        );
                        break;
                    }
                }
            }
        }
    }

    // On exit: drop inflight → every blocked caller's oneshot::Receiver
    // resolves to `RecvError`, which `fetch()` maps to `Dropped`. We
    // do NOT explicitly send Err to each one — drop is enough and
    // saves a clone of the error string.
    let drained = inflight.len();
    drop(inflight);
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"gateway_pump_exit\",\
         \"inflight_dropped\":{drained}}}"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_ipc::message::{FetchKind, GatewayMessage};
    use raxis_ipc::{read_frame, write_frame};
    use tokio::net::UnixStream;

    /// Spawn a fake gateway: returns a JoinHandle that, on each
    /// FetchRequest received, immediately writes back a FetchResponse
    /// echoing the fetch_id with status 200 and body `b"OK"`.
    async fn spawn_echo_gateway(mut stream: UnixStream) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let msg: GatewayMessage = match read_frame(&mut stream).await {
                    Ok(m) => m,
                    Err(_) => break,
                };
                if let GatewayMessage::FetchRequest { fetch_id, .. } = msg {
                    let resp = GatewayMessage::FetchResponse {
                        fetch_id,
                        status_code: Some(200),
                        headers:     vec![],
                        body_bytes:  Some(b"OK".to_vec()),
                        latency_ms:  1,
                        error:       None,
                    };
                    let _ = write_frame(&mut stream, &resp).await;
                }
            }
        })
    }

    fn dummy_fetch(client: GatewayClient, token: String, idx: u32)
        -> tokio::task::JoinHandle<Result<FetchResult, GatewayCallError>>
    {
        tokio::spawn(async move {
            client.fetch(
                token,
                FetchKind::DataFetch,
                format!("https://example.com/{idx}"),
                "GET".into(),
                vec![],
                vec![],
                5_000,
                None,
                None,
            ).await
        })
    }

    #[tokio::test]
    async fn fetch_returns_unavailable_when_no_gateway_connected() {
        let client = GatewayClient::new();
        let result = client.fetch(
            "tok".into(), FetchKind::DataFetch, "https://x".into(), "GET".into(),
            vec![], vec![], 1_000, None, None,
        ).await;
        assert!(matches!(result, Err(GatewayCallError::Unavailable)));
    }

    #[tokio::test]
    async fn happy_path_round_trips_one_fetch() {
        let (kernel_side, gateway_side) = UnixStream::pair().unwrap();
        let _gw = spawn_echo_gateway(gateway_side).await;

        let client = GatewayClient::new();
        client.install_connection(kernel_side).await;

        let result = client.fetch(
            "tok".into(),
            FetchKind::DataFetch,
            "https://example.com".into(),
            "GET".into(),
            vec![],
            vec![],
            5_000,
            None,
            None,
        ).await.expect("fetch must succeed");
        assert_eq!(result.status_code, Some(200));
        assert_eq!(result.body_bytes.as_deref(), Some(b"OK".as_ref()));
    }

    #[tokio::test]
    async fn multiple_concurrent_fetches_are_multiplexed() {
        // Verifies the pump dispatches by fetch_id — out-of-order
        // responses must be routed to the right caller.
        let (kernel_side, mut gateway_side) = UnixStream::pair().unwrap();

        // Fake gateway that BUFFERS three requests, then writes
        // responses in REVERSE order. The client must still match
        // each response to the right caller via fetch_id.
        let gw = tokio::spawn(async move {
            let mut buf: Vec<Uuid> = Vec::new();
            while buf.len() < 3 {
                let msg: GatewayMessage = read_frame(&mut gateway_side).await.unwrap();
                if let GatewayMessage::FetchRequest { fetch_id, .. } = msg {
                    buf.push(fetch_id);
                }
            }
            for fetch_id in buf.iter().rev() {
                let resp = GatewayMessage::FetchResponse {
                    fetch_id: *fetch_id,
                    status_code: Some(200),
                    headers: vec![],
                    body_bytes: Some(format!("for-{fetch_id}").into_bytes()),
                    latency_ms: 1,
                    error: None,
                };
                write_frame(&mut gateway_side, &resp).await.unwrap();
            }
        });

        let client = GatewayClient::new();
        client.install_connection(kernel_side).await;

        let h1 = dummy_fetch(client.clone(), "tok".into(), 1);
        let h2 = dummy_fetch(client.clone(), "tok".into(), 2);
        let h3 = dummy_fetch(client.clone(), "tok".into(), 3);

        let r1 = h1.await.unwrap().unwrap();
        let r2 = h2.await.unwrap().unwrap();
        let r3 = h3.await.unwrap().unwrap();
        gw.await.unwrap();

        // Each caller must get the body matching ITS fetch_id, not
        // the body of whichever response arrived first.
        assert!(r1.body_bytes.as_deref().unwrap().starts_with(b"for-"));
        assert!(r2.body_bytes.as_deref().unwrap().starts_with(b"for-"));
        assert!(r3.body_bytes.as_deref().unwrap().starts_with(b"for-"));

        assert!(r1.body_bytes.unwrap().ends_with(r1.fetch_id.to_string().as_bytes()));
        assert!(r2.body_bytes.unwrap().ends_with(r2.fetch_id.to_string().as_bytes()));
        assert!(r3.body_bytes.unwrap().ends_with(r3.fetch_id.to_string().as_bytes()));
    }

    #[tokio::test]
    async fn gateway_error_response_surfaces_as_typed_error() {
        let (kernel_side, mut gateway_side) = UnixStream::pair().unwrap();
        let gw = tokio::spawn(async move {
            let msg: GatewayMessage = read_frame(&mut gateway_side).await.unwrap();
            if let GatewayMessage::FetchRequest { fetch_id, .. } = msg {
                let resp = GatewayMessage::FetchResponse {
                    fetch_id,
                    status_code: None,
                    headers: vec![],
                    body_bytes: None,
                    latency_ms: 0,
                    error: Some("DomainNotAllowed".into()),
                };
                write_frame(&mut gateway_side, &resp).await.unwrap();
            }
        });

        let client = GatewayClient::new();
        client.install_connection(kernel_side).await;

        let result = client.fetch(
            "tok".into(), FetchKind::DataFetch, "https://x".into(), "GET".into(),
            vec![], vec![], 1_000, None, None,
        ).await;
        gw.await.unwrap();

        match result {
            Err(GatewayCallError::GatewayError(s)) => {
                assert_eq!(s, "DomainNotAllowed");
            }
            other => panic!("expected GatewayError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gateway_crash_drops_pending_callers_with_dropped() {
        // Fake gateway: receive ONE request then close the stream
        // without ever responding. The waiting fetch must resolve
        // to `Dropped` instead of hanging.
        let (kernel_side, mut gateway_side) = UnixStream::pair().unwrap();
        let gw = tokio::spawn(async move {
            let _msg: GatewayMessage = read_frame(&mut gateway_side).await.unwrap();
            // dropping `gateway_side` here closes the socket
        });

        let client = GatewayClient::new();
        client.install_connection(kernel_side).await;

        let h = dummy_fetch(client.clone(), "tok".into(), 1);
        gw.await.unwrap();

        match tokio::time::timeout(std::time::Duration::from_secs(5), h).await {
            Ok(Ok(Err(GatewayCallError::Dropped))) => {}
            Ok(other) => panic!("expected Dropped, got {other:?}"),
            Err(_) => panic!("fetch did not unblock after gateway crash"),
        }
    }

    #[tokio::test]
    async fn install_connection_replaces_pump_and_drops_old_inflight() {
        // First connection — never responds. We hold one fetch on it.
        let (kernel_a, mut gateway_a) = UnixStream::pair().unwrap();
        let gw_a = tokio::spawn(async move {
            // Read one frame, then linger forever to keep the socket
            // alive. The kernel-side `install_connection` swap MUST
            // still cancel the in-flight fetch.
            let _ = read_frame::<_, GatewayMessage>(&mut gateway_a).await;
            std::future::pending::<()>().await;
        });

        let client = GatewayClient::new();
        client.install_connection(kernel_a).await;

        let pending = dummy_fetch(client.clone(), "tok".into(), 99);

        // Give the pump a chance to register the fetch_id.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Now install a fresh connection. The old pump's mpsc closes,
        // it exits, the in-flight oneshot is dropped, the awaiting
        // caller resolves to Dropped.
        let (kernel_b, _gateway_b) = UnixStream::pair().unwrap();
        client.install_connection(kernel_b).await;

        match tokio::time::timeout(std::time::Duration::from_secs(2), pending).await {
            Ok(Ok(Err(GatewayCallError::Dropped))) => {}
            Ok(other) => panic!("expected Dropped after swap, got {other:?}"),
            Err(_) => panic!("connection swap did not cancel in-flight fetch"),
        }
        gw_a.abort();
    }

    #[tokio::test]
    async fn expected_token_round_trip() {
        let client = GatewayClient::new();
        assert!(client.expected_token().await.is_none());
        client.set_expected_token("abc123".into()).await;
        assert_eq!(client.expected_token().await.as_deref(), Some("abc123"));
        client.set_expected_token("xyz".into()).await;
        assert_eq!(client.expected_token().await.as_deref(), Some("xyz"));
    }

    #[tokio::test]
    async fn disconnect_makes_subsequent_fetches_unavailable() {
        let (kernel_side, _gateway_side) = UnixStream::pair().unwrap();
        let client = GatewayClient::new();
        client.install_connection(kernel_side).await;
        assert!(client.is_connected().await);
        client.disconnect().await;
        assert!(!client.is_connected().await);
        let result = client.fetch(
            "tok".into(), FetchKind::DataFetch, "https://x".into(), "GET".into(),
            vec![], vec![], 1_000, None, None,
        ).await;
        assert!(matches!(result, Err(GatewayCallError::Unavailable)));
    }

    // ── error category strings (pinned for audit wire stability) ────────

    #[test]
    fn error_category_strings_are_stable() {
        // GatewaySignalFailed.reason consumers (audit JSONL, raxis log
        // forensics) key off these short strings. Pin every variant.
        assert_eq!(GatewayCallError::Unavailable.category(), "unavailable");
        assert_eq!(GatewayCallError::Dropped.category(),     "dropped");
        assert_eq!(GatewayCallError::GatewayError("x".into()).category(), "gateway_error");
        assert_eq!(GatewayCallError::UnexpectedReply.category(), "unexpected_reply");
    }

    // ── notify_epoch_advanced (Phase 3 of policy_manager::advance_epoch) ─

    #[tokio::test]
    async fn notify_epoch_advanced_returns_unavailable_when_no_gateway() {
        let client = GatewayClient::new();
        let result = client.notify_epoch_advanced(7).await;
        assert!(matches!(result, Err(GatewayCallError::Unavailable)),
            "no gateway connected ⇒ Unavailable, got {result:?}");
    }

    #[tokio::test]
    async fn notify_epoch_advanced_writes_frame_and_returns_ok() {
        // Spin up a fake gateway that just reads ONE frame and asserts
        // it's the EpochAdvanced variant carrying the right epoch.
        let (kernel_side, mut gateway_side) = UnixStream::pair().unwrap();
        let server = tokio::spawn(async move {
            let msg: GatewayMessage = read_frame(&mut gateway_side).await.unwrap();
            match msg {
                GatewayMessage::EpochAdvanced { new_epoch_id } => new_epoch_id,
                other => panic!("expected EpochAdvanced, got {other:?}"),
            }
        });

        let client = GatewayClient::new();
        client.install_connection(kernel_side).await;

        client.notify_epoch_advanced(42).await.expect("signal must succeed");
        let observed = server.await.unwrap();
        assert_eq!(observed, 42);
    }

    #[tokio::test]
    async fn notify_epoch_advanced_does_not_block_on_concurrent_fetch_response() {
        // Regression: the pump handles signals on the SAME mpsc as
        // fetches, but a signal must NOT wait for any FetchResponse.
        // We push a fetch (gateway never responds), then a signal
        // (gateway is expected to read it). The signal must complete
        // even though the fetch is still in flight.
        let (kernel_side, mut gateway_side) = UnixStream::pair().unwrap();
        let observed_signal = std::sync::Arc::new(tokio::sync::Notify::new());
        let observer = observed_signal.clone();
        let server = tokio::spawn(async move {
            // Read TWO frames: the FetchRequest then the EpochAdvanced.
            // Neither response is sent. The fetch caller hangs (test
            // does not await it); the signal caller MUST complete.
            let _f1: GatewayMessage = read_frame(&mut gateway_side).await.unwrap();
            let f2: GatewayMessage  = read_frame(&mut gateway_side).await.unwrap();
            assert!(matches!(f2, GatewayMessage::EpochAdvanced { new_epoch_id: 9 }));
            observer.notify_one();
            std::future::pending::<()>().await;
        });

        let client = GatewayClient::new();
        client.install_connection(kernel_side).await;

        // Hanging fetch — we never await its handle.
        let _hanging = dummy_fetch(client.clone(), "tok".into(), 1);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        client.notify_epoch_advanced(9).await.expect("signal must succeed");
        observed_signal.notified().await;
        server.abort();
    }

    #[tokio::test]
    async fn notify_epoch_advanced_returns_dropped_when_gateway_closes_mid_send() {
        // Fake gateway that closes the socket *before* we try to write.
        // The pump's write_frame fails → ack_tx receives Dropped.
        let (kernel_side, gateway_side) = UnixStream::pair().unwrap();
        drop(gateway_side); // close immediately

        let client = GatewayClient::new();
        client.install_connection(kernel_side).await;
        // Give the pump a moment to notice EOF and exit, OR race it
        // and let the write fail. Either path resolves to a non-Ok
        // result.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let result = client.notify_epoch_advanced(5).await;
        assert!(
            matches!(result, Err(GatewayCallError::Dropped))
            || matches!(result, Err(GatewayCallError::Unavailable)),
            "expected Dropped or Unavailable after gateway close, got {result:?}",
        );
    }

    #[tokio::test]
    async fn notify_epoch_advanced_after_disconnect_is_unavailable() {
        let (kernel_side, _gateway_side) = UnixStream::pair().unwrap();
        let client = GatewayClient::new();
        client.install_connection(kernel_side).await;
        client.disconnect().await;
        let result = client.notify_epoch_advanced(1).await;
        assert!(matches!(result, Err(GatewayCallError::Unavailable)));
    }
}
