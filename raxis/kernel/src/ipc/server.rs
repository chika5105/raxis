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

/// Bind all three UDS sockets and spawn the Tokio accept loops.
///
/// This function does not return under normal operation — it runs the main
/// dispatch loop until a shutdown signal is received.
///
/// Called from `main.rs` step 9 (enter IPC dispatch loop).
pub async fn start(
    data_dir: &PathBuf,
    ctx: Arc<HandlerContext>,
) -> Result<(), KernelError> {
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

    // Wait for any task to finish (which indicates a fatal error or shutdown).
    tokio::select! {
        result = op_task => {
            eprintln!("{{\"level\":\"error\",\"message\":\"operator accept loop exited\",\"result\":\"{result:?}\"}}");
        },
        result = pl_task => {
            eprintln!("{{\"level\":\"error\",\"message\":\"planner accept loop exited\",\"result\":\"{result:?}\"}}");
        },
        result = gw_task => {
            eprintln!("{{\"level\":\"error\",\"message\":\"gateway accept loop exited\",\"result\":\"{result:?}\"}}");
        },
    }

    Ok(())
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

            // ── EscalationRequest (Tier 2 stub) ────────────────────────────
            IpcMessage::EscalationRequest(_) => {
                eprintln!("{{\"level\":\"debug\",\"message\":\"EscalationRequest received (Tier 2 stub)\"}}");
                // Do not break — keep connection open; planner may continue.
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
