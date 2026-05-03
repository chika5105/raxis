// raxis-kernel::ipc::server — UDS listener and connection acceptor.
//
// Normative reference: kernel-core.md §2.2 startup step 7 (socket bind)
// and §2.2 `src/ipc/` (dispatch loop structure).
//
// Three sockets are bound at startup:
//   operator.sock  — operator CLI connections (challenge-response auth)
//   planner.sock   — planner subprocess connections (session token auth)
//   gateway.sock   — gateway connections (v1 stub — accepts but drops)
//
// Each accepted connection gets its own Tokio task. The connection task
// runs the auth handshake, then enters a request-reply loop.
//
// File permissions on sockets:
//   operator.sock : 0600 — operator only
//   planner.sock  : 0660 — operator + planner group
//   gateway.sock  : 0660 — operator + gateway group
// (The kernel is responsible for chmod after bind; chown is outside scope.)

use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};

use crate::errors::KernelError;
use crate::handlers;
use crate::ipc::context::HandlerContext;
use crate::ipc::auth;
use crate::ipc::operator;

// ---------------------------------------------------------------------------
// ShutdownReason — why the dispatch loop exited.
// Returned from `start()` so `main.rs` can decide whether to emit
// `KernelStopped` cleanly (Signal{...}) or surface a fatal error
// (AcceptLoopExited). Either way the kernel is exiting; this enum just
// controls the audit + cleanup posture.
// ---------------------------------------------------------------------------

/// Cause of the IPC dispatch loop exiting. Inspected by `main.rs` to choose
/// the audit reason string and exit code.
#[derive(Debug, Clone)]
pub enum ShutdownReason {
    /// Operator sent SIGTERM (normal shutdown — `kill <pid>` or `systemctl stop`).
    SigTerm,
    /// Operator sent SIGINT (Ctrl-C in the foreground).
    SigInt,
    /// One of the three accept loops exited unexpectedly. The string names the
    /// loop ("operator", "planner", or "gateway") for the audit reason.
    /// This is a degraded outcome: the kernel cannot continue serving with a
    /// dead listener, so `main.rs` exits non-zero.
    AcceptLoopExited { which: &'static str },
}

impl ShutdownReason {
    /// Human-readable string for the `KernelStopped { reason }` audit event.
    pub fn audit_reason(&self) -> String {
        match self {
            Self::SigTerm => "SIGTERM".to_owned(),
            Self::SigInt => "SIGINT".to_owned(),
            Self::AcceptLoopExited { which } => format!("accept_loop_exited:{which}"),
        }
    }

    /// Whether the kernel exited at operator request (clean) vs internal failure.
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::SigTerm | Self::SigInt)
    }
}

/// Bind all three UDS sockets and run the dispatch loop until a shutdown
/// signal is received OR an accept loop exits (the latter is fatal).
///
/// **Returned `ShutdownReason`** is the cause of exit:
/// - `SigTerm` / `SigInt` — operator-initiated graceful shutdown. `main.rs`
///   emits `KernelStopped { reason }` and exits 0.
/// - `AcceptLoopExited { which }` — degraded internal outcome. `main.rs`
///   still emits `KernelStopped { reason }` (audit completeness) but exits
///   non-zero so init systems restart the kernel.
///
/// **Cleanup contract:** This function unbinds + removes the three UDS
/// socket files before returning, regardless of exit reason. Without this,
/// stale `operator.sock` / `planner.sock` / `gateway.sock` would survive
/// across restarts and `UnixListener::bind` would fail with
/// `SocketBind { ... already in use ... }` on the next boot.
///
/// Called from `main.rs` step 9 (enter IPC dispatch loop).
pub async fn start(
    data_dir: &PathBuf,
    ctx: Arc<HandlerContext>,
) -> Result<ShutdownReason, KernelError> {
    let sockets_dir = data_dir.join("sockets");
    std::fs::create_dir_all(&sockets_dir)?;

    let operator_path = sockets_dir.join("operator.sock");
    let planner_path = sockets_dir.join("planner.sock");
    let gateway_path = sockets_dir.join("gateway.sock");

    // Remove stale socket files from a previous run.
    for path in &[&operator_path, &planner_path, &gateway_path] {
        let _ = std::fs::remove_file(path);
    }

    // Bind operator socket.
    let operator_listener = UnixListener::bind(&operator_path)
        .map_err(|e| KernelError::SocketBind {
            reason: format!("operator.sock bind failed: {e}"),
        })?;
    set_socket_permissions(&operator_path, 0o600);

    // Bind planner socket.
    let planner_listener = UnixListener::bind(&planner_path)
        .map_err(|e| KernelError::SocketBind {
            reason: format!("planner.sock bind failed: {e}"),
        })?;
    set_socket_permissions(&planner_path, 0o660);

    // Bind gateway socket.
    let gateway_listener = UnixListener::bind(&gateway_path)
        .map_err(|e| KernelError::SocketBind {
            reason: format!("gateway.sock bind failed: {e}"),
        })?;
    set_socket_permissions(&gateway_path, 0o660);

    eprintln!(
        "{{\"level\":\"info\",\"message\":\"sockets bound\",\"operator\":\"{}\",\"planner\":\"{}\",\"gateway\":\"{}\"}}",
        operator_path.display(), planner_path.display(), gateway_path.display()
    );

    // Spawn the three accept loops.
    let operator_ctx = Arc::clone(&ctx);
    let planner_ctx = Arc::clone(&ctx);
    let _gateway_ctx = Arc::clone(&ctx);

    let op_task = tokio::spawn(accept_operator_loop(operator_listener, operator_ctx));
    let pl_task = tokio::spawn(accept_planner_loop(planner_listener, planner_ctx));
    let gw_task = tokio::spawn(accept_gateway_loop(gateway_listener));

    // Wait for either a shutdown signal OR an accept loop to exit.
    // SIGTERM and SIGINT both trigger graceful shutdown (kernel-core.md §2.2
    // step 9 "Signal handler registration"). On non-unix targets we have no
    // SIGTERM equivalent, but the kernel is unix-only by spec
    // (`UnixListener` already gates everything to `cfg(unix)`).
    let reason = wait_for_shutdown(op_task, pl_task, gw_task).await;

    // Cleanup: unbind sockets by removing files. Best-effort — if the
    // operator wiped `<data_dir>` mid-shutdown the removes will simply ENOENT.
    for path in &[&operator_path, &planner_path, &gateway_path] {
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "{{\"level\":\"warn\",\"message\":\"socket file remove failed\",\
                     \"path\":\"{}\",\"error\":\"{e}\"}}",
                    path.display()
                );
            }
        }
    }
    eprintln!(
        "{{\"level\":\"info\",\"message\":\"sockets unbound\",\"reason\":\"{}\"}}",
        reason.audit_reason()
    );

    Ok(reason)
}

/// Race the three accept tasks against SIGTERM and SIGINT. The first
/// terminating arm wins; the others are aborted when this function returns
/// (the `JoinHandle`s are dropped together with the parent task in `start`).
async fn wait_for_shutdown(
    op_task: tokio::task::JoinHandle<()>,
    pl_task: tokio::task::JoinHandle<()>,
    gw_task: tokio::task::JoinHandle<()>,
) -> ShutdownReason {
    use tokio::signal::unix::{signal, SignalKind};

    // Set up signal streams. If `signal()` itself fails (extremely rare —
    // out-of-fd or kernel without signalfd), log and degrade to "wait for
    // accept loop exit only" — Ctrl-C will still tear the process down via
    // the default SIGINT handler.
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"message\":\"SIGTERM handler install failed\",\
                 \"error\":\"{e}\"}}"
            );
            // Still tee SIGINT below; if both fail the process is still alive
            // and `tokio::select!` will fall through to the accept-loop arms.
            return wait_for_accept_exit_only(op_task, pl_task, gw_task).await;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"message\":\"SIGINT handler install failed\",\
                 \"error\":\"{e}\"}}"
            );
            return wait_for_accept_exit_only(op_task, pl_task, gw_task).await;
        }
    };

    tokio::select! {
        _ = sigterm.recv() => {
            eprintln!("{{\"level\":\"info\",\"message\":\"SIGTERM received\"}}");
            ShutdownReason::SigTerm
        }
        _ = sigint.recv() => {
            eprintln!("{{\"level\":\"info\",\"message\":\"SIGINT received\"}}");
            ShutdownReason::SigInt
        }
        result = op_task => {
            eprintln!(
                "{{\"level\":\"error\",\"message\":\"operator accept loop exited\",\
                 \"result\":\"{result:?}\"}}"
            );
            ShutdownReason::AcceptLoopExited { which: "operator" }
        }
        result = pl_task => {
            eprintln!(
                "{{\"level\":\"error\",\"message\":\"planner accept loop exited\",\
                 \"result\":\"{result:?}\"}}"
            );
            ShutdownReason::AcceptLoopExited { which: "planner" }
        }
        result = gw_task => {
            eprintln!(
                "{{\"level\":\"error\",\"message\":\"gateway accept loop exited\",\
                 \"result\":\"{result:?}\"}}"
            );
            ShutdownReason::AcceptLoopExited { which: "gateway" }
        }
    }
}

/// Degraded path: SIGTERM/SIGINT installation failed. Wait only on the three
/// accept loops; the OS default signal disposition still tears the process
/// down on Ctrl-C, just without our `KernelStopped` audit hook.
async fn wait_for_accept_exit_only(
    op_task: tokio::task::JoinHandle<()>,
    pl_task: tokio::task::JoinHandle<()>,
    gw_task: tokio::task::JoinHandle<()>,
) -> ShutdownReason {
    tokio::select! {
        result = op_task => {
            eprintln!(
                "{{\"level\":\"error\",\"message\":\"operator accept loop exited (no signal handler)\",\
                 \"result\":\"{result:?}\"}}"
            );
            ShutdownReason::AcceptLoopExited { which: "operator" }
        }
        result = pl_task => {
            eprintln!(
                "{{\"level\":\"error\",\"message\":\"planner accept loop exited (no signal handler)\",\
                 \"result\":\"{result:?}\"}}"
            );
            ShutdownReason::AcceptLoopExited { which: "planner" }
        }
        result = gw_task => {
            eprintln!(
                "{{\"level\":\"error\",\"message\":\"gateway accept loop exited (no signal handler)\",\
                 \"result\":\"{result:?}\"}}"
            );
            ShutdownReason::AcceptLoopExited { which: "gateway" }
        }
    }
}

// ---------------------------------------------------------------------------
// Operator accept loop
// ---------------------------------------------------------------------------

async fn accept_operator_loop(
    listener: UnixListener,
    ctx: Arc<HandlerContext>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(e) = handle_operator_connection(stream, ctx).await {
                        eprintln!(
                            "{{\"level\":\"warn\",\"message\":\"operator connection error\",\"error\":\"{e}\"}}",
                        );
                    }
                });
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"message\":\"operator accept error\",\"error\":\"{e}\"}}",
                );
                // Brief pause before retrying to prevent busy-spin.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Handle a single operator connection.
///
/// 1. Send challenge.
/// 2. Receive and verify response.
/// 3. Enter request-reply loop, dispatching to operator::dispatch().
async fn handle_operator_connection(
    mut stream: UnixStream,
    ctx: Arc<HandlerContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use raxis_ipc::{read_json_frame_async, write_json_frame_async};

    // Step 1: Send challenge. RNG failure here closes the connection — we
    // refuse to send a degraded challenge whose entropy we cannot vouch for.
    // Framing routes through `raxis-ipc::json_frame` so the kernel and CLI
    // share one source of truth (PR-2 — earlier the kernel used hand-rolled
    // little-endian framing while the CLI used hand-rolled BIG-endian, making
    // the operator socket unusable end-to-end).
    let challenge = auth::make_challenge()?;
    write_json_frame_async(&mut stream, &challenge).await?;

    // Step 2: Read response envelope.
    let response: auth::ResponseEnvelope = read_json_frame_async(&mut stream).await?;

    // Step 3: Verify.
    let operator = match auth::verify_response(&challenge, &response, &ctx.policy) {
        auth::ChallengeResult::Ok(op) => op,
        auth::ChallengeResult::Unauthorized { reason } => {
            let error_msg = serde_json::json!({
                "status": "Unauthorized",
                "reason": reason,
            });
            write_json_frame_async(&mut stream, &error_msg).await?;
            return Ok(());
        }
    };

    // Step 4: Send auth-ok ACK. The CLI's `OperatorConn::connect` matches
    // `status == "Ok"` (cli/src/conn.rs); we keep both keys for forward-
    // compatibility with the older `"AuthOk"` value.
    let ok_msg = serde_json::json!({"status": "Ok"});
    write_json_frame_async(&mut stream, &ok_msg).await?;

    eprintln!(
        "{{\"level\":\"info\",\"message\":\"operator authenticated\",\"fingerprint\":\"{}\"}}",
        operator.fingerprint
    );

    // Step 5: Enter request-reply loop.
    operator::dispatch_loop(stream, operator, ctx).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Planner accept loop — bincode-framed IpcMessage dispatch
// Normative reference: kernel-core.md §2.2 `src/ipc/` dispatch loop.
// Wire format: raxis-ipc::frame (4-byte LE length prefix + bincode body).
// ---------------------------------------------------------------------------

async fn accept_planner_loop(listener: UnixListener, ctx: Arc<HandlerContext>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(e) = handle_planner_connection(stream, ctx).await {
                        eprintln!(
                            "{{\"level\":\"warn\",\"message\":\"planner connection error\",\"error\":\"{e}\"}}",
                        );
                    }
                });
            }
            Err(e) => {
                eprintln!("{{\"level\":\"error\",\"message\":\"planner accept error\",\"error\":\"{e}\"}}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Handle a single planner connection per spec (kernel-core.md §2.2).
///
/// Message routing:
///   IntentRequest     → handlers::intent::handle → KernelIntentResponse
///   WitnessSubmission → handlers::witness::handle → WitnessAckResponse
///   (Other variants)  → warn + drop frame; connection stays open
///
/// Spec §2.2 startup step 7:
///   "there is no separate witness.sock — verifier subprocesses connect to
///   planner.sock and the dispatcher routes by message variant."
async fn handle_planner_connection(
    mut stream: tokio::net::UnixStream,
    ctx: Arc<HandlerContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use raxis_ipc::{read_frame, write_frame, IpcMessage};

    loop {
        let msg: IpcMessage = match read_frame(&mut stream).await {
            Ok(m) => m,
            Err(raxis_ipc::FrameError::Eof) => break, // clean disconnect
            Err(e) => {
                eprintln!("{{\"level\":\"warn\",\"message\":\"planner frame read error\",\"error\":\"{e}\"}}");
                break;
            }
        };

        match msg {
            // ── IntentRequest ────────────────────────────────────────────
            IpcMessage::IntentRequest(req) => {
                let resp = handlers::intent::handle(req, &ctx).await;
                write_frame(&mut stream, &IpcMessage::KernelIntentResponse(resp)).await?;
            }

            // ── WitnessSubmission ─────────────────────────────────────────
            // Spec §2.2: verifiers connect to planner.sock; dispatcher routes
            // by variant. The WitnessAck response is a separate IpcMessage
            // variant so the verifier subprocess gets a typed acknowledgment.
            IpcMessage::WitnessSubmission(sub) => {
                match handlers::witness::handle(sub, &ctx).await {
                    Ok(ack) => {
                        // Map domain WitnessAck → wire IpcMessage::WitnessAck.
                        //
                        // The wire shape (`accepted: bool, reason: Option<String>`)
                        // is intentionally narrower than the domain enum: the
                        // verifier subprocess only needs to know whether the
                        // submission landed and, if not, why. The handler-level
                        // distinction between `Accepted` (cleared a gate) and
                        // `AcceptedNonPass` (recorded a Fail/Inconclusive) is
                        // routed elsewhere (planner via audit / future planner
                        // facing wire types — see kernel-store.md §2.5.6).
                        // For the verifier we collapse both Accepted variants
                        // to `accepted = true` so it knows to release its
                        // worktree lease and exit cleanly. The `reason` field
                        // surfaces the result_class for AcceptedNonPass so the
                        // verifier's own logs can echo it.
                        let (accepted, verifier_run_id, reason) = match ack {
                            handlers::witness::WitnessAck::Accepted { run_id, .. } => {
                                (true, uuid::Uuid::parse_str(&run_id).unwrap_or_default(), None)
                            }
                            handlers::witness::WitnessAck::AcceptedNonPass {
                                run_id, gate_type, result_class,
                            } => (
                                true,
                                uuid::Uuid::parse_str(&run_id).unwrap_or_default(),
                                Some(format!(
                                    "non-pass recorded: gate={} result={}",
                                    gate_type.as_str(),
                                    result_class.as_str(),
                                )),
                            ),
                            handlers::witness::WitnessAck::Rejected { reason } => {
                                (false, uuid::Uuid::nil(), Some(format!("{reason:?}")))
                            }
                        };
                        write_frame(&mut stream, &IpcMessage::WitnessAck {
                            verifier_run_id,
                            accepted,
                            reason,
                        }).await?;
                    }
                    Err(e) => {
                        // HandlerError: transport/auth-level failure.
                        // Log and close — verifier's token remains unconsumed.
                        eprintln!(
                            "{{\"level\":\"error\",\"message\":\"WitnessSubmission handler error\",\"error\":\"{e}\"}}"
                        );
                        break;
                    }
                }
            }

            // ── EscalationRequest ─────────────────────────────────────────
            // Spec §2.3 dispatcher: EscalationRequest lands on planner.sock
            // (same socket as IntentRequest, different IpcMessage variant).
            // The handler returns an EscalationResponse for every input —
            // including malformed ones — so the connection stays open and
            // the planner gets a typed reply it can match on.
            IpcMessage::EscalationRequest(req) => {
                let resp = handlers::escalation::handle(req, &ctx).await;
                write_frame(&mut stream, &IpcMessage::KernelEscalationResponse(resp)).await?;
            }

            _ => {
                eprintln!("{{\"level\":\"warn\",\"message\":\"unexpected IpcMessage on planner socket\"}}");
                // Unknown variant: log and drop frame but keep connection open.
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gateway accept loop (stub)
// ---------------------------------------------------------------------------

async fn accept_gateway_loop(listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((_stream, _addr)) => {
                eprintln!(
                    "{{\"level\":\"debug\",\"message\":\"gateway connection accepted (stub — gateway IPC not yet wired)\"}}",
                );
            }
            Err(e) => {
                eprintln!("{{\"level\":\"error\",\"message\":\"gateway accept error\",\"error\":\"{e}\"}}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Socket permissions helper
// ---------------------------------------------------------------------------

fn set_socket_permissions(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        eprintln!(
            "{{\"level\":\"warn\",\"message\":\"chmod socket failed\",\"path\":\"{}\",\"error\":\"{e}\"}}",
            path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// Tests — `ShutdownReason` semantics. Live signal delivery is exercised by
// `kernel/tests/kernel_signal_shutdown.rs` (an end-to-end test that spawns
// the kernel binary and SIGTERMs it).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod shutdown_reason_tests {
    use super::ShutdownReason;

    #[test]
    fn audit_reason_strings_are_pinned() {
        // These strings appear in the audit segment and in operator log
        // dashboards — they MUST be stable across kernel versions, otherwise
        // existing log alerting and grep recipes break silently. This pins
        // every variant.
        assert_eq!(ShutdownReason::SigTerm.audit_reason(), "SIGTERM");
        assert_eq!(ShutdownReason::SigInt.audit_reason(), "SIGINT");
        assert_eq!(
            ShutdownReason::AcceptLoopExited { which: "operator" }.audit_reason(),
            "accept_loop_exited:operator"
        );
        assert_eq!(
            ShutdownReason::AcceptLoopExited { which: "planner" }.audit_reason(),
            "accept_loop_exited:planner"
        );
        assert_eq!(
            ShutdownReason::AcceptLoopExited { which: "gateway" }.audit_reason(),
            "accept_loop_exited:gateway"
        );
    }

    #[test]
    fn is_clean_separates_operator_request_from_internal_failure() {
        // `main.rs` uses `is_clean()` to choose the process exit code.
        // Operator-initiated → 0; internal failure → non-zero (init system
        // restarts). This test guards against the variants accidentally
        // being reclassified.
        assert!(ShutdownReason::SigTerm.is_clean());
        assert!(ShutdownReason::SigInt.is_clean());
        assert!(!ShutdownReason::AcceptLoopExited { which: "operator" }.is_clean());
        assert!(!ShutdownReason::AcceptLoopExited { which: "planner" }.is_clean());
        assert!(!ShutdownReason::AcceptLoopExited { which: "gateway" }.is_clean());
    }
}
