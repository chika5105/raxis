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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Step 1: Send challenge.
    let challenge = auth::make_challenge();
    let challenge_bytes = serde_json::to_vec(&challenge)?;
    let len = challenge_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&challenge_bytes).await?;

    // Step 2: Read response.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_le_bytes(len_buf) as usize;
    if msg_len > 4 * 1024 {
        return Err("response too large".into());
    }
    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf).await?;
    let response: auth::ResponseEnvelope = serde_json::from_slice(&msg_buf)?;

    // Step 3: Verify.
    let operator = match auth::verify_response(&challenge, &response, &ctx.policy) {
        auth::ChallengeResult::Ok(op) => op,
        auth::ChallengeResult::Unauthorized { reason } => {
            let error_msg = serde_json::json!({
                "status": "Unauthorized",
                "reason": reason,
            });
            let bytes = serde_json::to_vec(&error_msg)?;
            let len = bytes.len() as u32;
            stream.write_all(&len.to_le_bytes()).await?;
            stream.write_all(&bytes).await?;
            return Ok(());
        }
    };

    // Step 4: Send auth-ok.
    let ok_msg = serde_json::json!({"status": "AuthOk"});
    let ok_bytes = serde_json::to_vec(&ok_msg)?;
    let ok_len = ok_bytes.len() as u32;
    stream.write_all(&ok_len.to_le_bytes()).await?;
    stream.write_all(&ok_bytes).await?;

    eprintln!(
        "{{\"level\":\"info\",\"message\":\"operator authenticated\",\"fingerprint\":\"{}\"}}",
        operator.fingerprint
    );

    // Step 5: Enter request-reply loop.
    operator::dispatch_loop(stream, operator, ctx).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Planner accept loop (stub — auth will be wired when planner handlers are done)
// ---------------------------------------------------------------------------

async fn accept_planner_loop(listener: UnixListener, _ctx: Arc<HandlerContext>) {
    loop {
        match listener.accept().await {
            Ok((_stream, _addr)) => {
                // v1 stub: accept connection, log, drop.
                eprintln!(
                    "{{\"level\":\"debug\",\"message\":\"planner connection accepted (stub — planner IPC not yet wired)\"}}",
                );
            }
            Err(e) => {
                eprintln!("{{\"level\":\"error\",\"message\":\"planner accept error\",\"error\":\"{e}\"}}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
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
