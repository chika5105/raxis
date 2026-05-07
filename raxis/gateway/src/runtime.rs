//! Gateway runtime — connect to the kernel UDS, send `GatewayReady`,
//! enter the request-reply loop until the connection closes.
//!
//! Normative reference: `peripherals.md` §3.2 "Spawn model" and
//! "Wire format".
//!
//! This is the single I/O shim that ties together `env`, `policy_view`,
//! `backend`, and `dispatch`. Every observable behaviour above this
//! layer is exercised by unit tests; this layer is exercised end-to-end
//! by `tests/gateway_roundtrip.rs` (spawns the binary against a fake
//! kernel) and by Phase A.5 (kernel-spawning supervisor).

use std::path::PathBuf;
use std::sync::Arc;

use raxis_ipc::message::GatewayMessage;
use raxis_ipc::{read_frame, write_frame, FrameError};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::sync::RwLock;

use crate::backend::Backend;
use crate::dispatch::handle_fetch_request;
use crate::env::GatewayEnv;
use crate::http_backend::HttpBackend;
use crate::policy_view::{load_policy_view, PolicyView, PolicyViewError};

/// Fatal errors that abort the gateway process. Anything that should
/// short-circuit a single FetchRequest stays as a `FetchResponse.error`
/// — only true process-level failures land here.
#[derive(Debug, Error)]
pub enum GatewayRunError {
    #[error("connect to kernel UDS at {socket} failed: {source}")]
    Connect {
        socket: PathBuf,
        source: std::io::Error,
    },
    #[error("write GatewayReady handshake failed: {0}")]
    HandshakeWrite(String),
    #[error("initial policy_view load failed: {0}")]
    InitialPolicyLoad(#[source] PolicyViewError),
    #[error("frame read error: {0}")]
    FrameRead(String),
    #[error("frame write error: {0}")]
    FrameWrite(String),
}

/// Run the gateway against the env-supplied UDS socket using the
/// production [`HttpBackend`]. This is what `main.rs` calls.
///
/// Tests that need to exercise the dispatch path without a real
/// network use [`run_gateway_with_backend`] directly with a
/// `MockBackend` from `raxis-test-support`.
///
/// Lifecycle:
/// 1. Load policy_view (FAIL if this fails — the gateway has nothing
///    useful to do without an allowlist or providers).
/// 2. Connect to the kernel's `gateway.sock`.
/// 3. Send `GatewayMessage::GatewayReady { gateway_token }`.
/// 4. Loop:
///    - Read one frame (`FetchRequest` or `EpochAdvanced`).
///    - On `FetchRequest`: dispatch via `dispatch::handle_fetch_request`,
///      write the resulting `FetchResponse`.
///    - On `EpochAdvanced`: re-load policy_view; if reload fails, mark
///      the view as `None` so subsequent `FetchRequests` short-circuit
///      to `error: "PolicyReloadFailed"` (per spec).
///    - On any unexpected variant: log and skip.
/// 5. On EOF / connection error: return `Ok(())`. The kernel supervisor
///    detects the closed socket and respawns us with a fresh token.
pub async fn run_gateway(env: GatewayEnv) -> Result<(), GatewayRunError> {
    let backend: Arc<dyn Backend> = Arc::new(HttpBackend::new());
    run_gateway_with_backend(env, backend).await
}

/// Like [`run_gateway`] but with an externally-supplied backend.
/// Used by integration tests (with `raxis_test_support::MockBackend`)
/// and by future custom-middleware deployments. Production binaries
/// always go through [`run_gateway`], which constructs the
/// `HttpBackend` internally so no operator-controlled env can swap
/// it out.
pub async fn run_gateway_with_backend(
    env:     GatewayEnv,
    backend: Arc<dyn Backend>,
) -> Result<(), GatewayRunError> {
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"gateway_start\",\
         \"socket\":\"{}\",\"data_dir\":\"{}\"}}",
        env.gateway_socket.display(),
        env.data_dir.display(),
    );

    // Step 1: initial policy view. Any failure aborts startup so the
    // kernel supervisor sees the spawn timeout and surfaces a clear
    // BOOT_ERR equivalent in the kernel log.
    let policy_view = load_policy_view(&env.data_dir)
        .map_err(GatewayRunError::InitialPolicyLoad)?;
    let view_slot: Arc<RwLock<Option<PolicyView>>> =
        Arc::new(RwLock::new(Some(policy_view)));

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"policy_view_loaded\",\
         \"providers\":{}}}",
        view_slot.read().await.as_ref().map(|v| v.providers.len()).unwrap_or(0),
    );

    // Step 2: connect.
    let mut stream = UnixStream::connect(&env.gateway_socket).await.map_err(|e| {
        GatewayRunError::Connect {
            socket: env.gateway_socket.clone(),
            source: e,
        }
    })?;

    // Step 3: handshake.
    let ready = GatewayMessage::GatewayReady {
        gateway_token: env.gateway_token.clone(),
    };
    write_frame(&mut stream, &ready)
        .await
        .map_err(|e| GatewayRunError::HandshakeWrite(format!("{e}")))?;
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"handshake_sent\",\
         \"token_prefix\":\"{}\"}}",
        &env.gateway_token[..8.min(env.gateway_token.len())],
    );

    // Step 4: dispatch loop.
    loop {
        let msg: GatewayMessage = match read_frame(&mut stream).await {
            Ok(m) => m,
            Err(FrameError::Eof) => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"kernel_disconnected_clean\"}}"
                );
                return Ok(());
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"frame_read_error\",\
                     \"error\":\"{e}\"}}"
                );
                return Ok(());
            }
        };

        match msg {
            // ── FetchRequest → dispatch → FetchResponse ─────────────────
            req @ GatewayMessage::FetchRequest { .. } => {
                let view_guard = view_slot.read().await;
                let view_ref: Option<&PolicyView> = view_guard.as_ref();
                let resp =
                    handle_fetch_request(req, &env.gateway_token, view_ref, backend.as_ref())
                        .await;
                drop(view_guard);
                if let Err(e) = write_frame(&mut stream, &resp).await {
                    return Err(GatewayRunError::FrameWrite(format!("{e}")));
                }
            }

            // ── EpochAdvanced → reload policy_view ──────────────────────
            GatewayMessage::EpochAdvanced { new_epoch_id } => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"epoch_advanced_signal\",\
                     \"new_epoch_id\":{new_epoch_id}}}"
                );
                match load_policy_view(&env.data_dir) {
                    Ok(new_view) => {
                        let mut slot = view_slot.write().await;
                        let old_epoch = slot.as_ref().map(|v| v.epoch).unwrap_or(0);
                        let new_epoch = new_view.epoch;
                        *slot = Some(new_view);
                        eprintln!(
                            "{{\"level\":\"info\",\"event\":\"policy_view_reloaded\",\
                             \"old_epoch\":{old_epoch},\"new_epoch\":{new_epoch}}}"
                        );
                    }
                    Err(e) => {
                        let mut slot = view_slot.write().await;
                        *slot = None;
                        eprintln!(
                            "{{\"level\":\"error\",\"event\":\"policy_view_reload_failed\",\
                             \"reason\":\"{e}\"}}"
                        );
                    }
                }
            }

            // ── Anything else: log and skip ─────────────────────────────
            other => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"unexpected_message\",\
                     \"variant\":\"{}\"}}",
                    std::any::type_name_of_val(&other),
                );
            }
        }
    }
}
