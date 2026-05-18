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

use std::path::Path;
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};

use crate::errors::KernelError;
use crate::handlers;
use crate::ipc::auth;
use crate::ipc::context::HandlerContext;
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
    data_dir: &Path,
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
    let operator_listener =
        UnixListener::bind(&operator_path).map_err(|e| KernelError::SocketBind {
            reason: format!("operator.sock bind failed: {e}"),
        })?;
    set_socket_permissions(&operator_path, 0o600);

    // Bind planner socket.
    let planner_listener =
        UnixListener::bind(&planner_path).map_err(|e| KernelError::SocketBind {
            reason: format!("planner.sock bind failed: {e}"),
        })?;
    set_socket_permissions(&planner_path, 0o660);

    // Bind gateway socket.
    let gateway_listener =
        UnixListener::bind(&gateway_path).map_err(|e| KernelError::SocketBind {
            reason: format!("gateway.sock bind failed: {e}"),
        })?;
    set_socket_permissions(&gateway_path, 0o660);

    // Register signal handlers BEFORE logging `sockets_bound`.
    //
    // `tokio::signal::unix::signal(SignalKind::terminate())` calls
    // `sigaction(2)` to replace SIGTERM's default disposition (process
    // termination) with a handler that writes to an internal pipe.
    // This MUST happen before `sockets_bound` is logged because
    // integration tests use that log line as the "kernel is ready"
    // signal and immediately send SIGTERM. If the handler isn't
    // installed yet, the default disposition kills the process and
    // the test sees a signal-terminated exit status instead of
    // exit(0).
    //
    // The streams are passed into `wait_for_shutdown` so they are
    // polled inside `tokio::select!` alongside the accept tasks.
    use tokio::signal::unix::{signal, SignalKind};
    let sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => Some(s),
        Err(e) => {
            server_log::signal_handler_install_failed("SIGTERM", &e.to_string());
            None
        }
    };
    let sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => Some(s),
        Err(e) => {
            server_log::signal_handler_install_failed("SIGINT", &e.to_string());
            None
        }
    };

    server_log::sockets_bound(
        &operator_path.display().to_string(),
        &planner_path.display().to_string(),
        &gateway_path.display().to_string(),
    );

    // Spawn the three accept loops.
    let operator_ctx = Arc::clone(&ctx);
    let planner_ctx = Arc::clone(&ctx);
    let gateway_client = Arc::clone(&ctx.gateway);
    let gateway_audit = Arc::clone(&ctx.audit);

    let op_task = tokio::spawn(accept_operator_loop(operator_listener, operator_ctx));
    let pl_task = tokio::spawn(accept_planner_loop(planner_listener, planner_ctx));
    let gw_task = tokio::spawn(crate::gateway::accept::accept_gateway_loop(
        gateway_listener,
        gateway_client,
        gateway_audit,
    ));

    // Wait for either a shutdown signal OR an accept loop to exit.
    // SIGTERM and SIGINT both trigger graceful shutdown (kernel-core.md §2.2
    // step 9 "Signal handler registration"). On non-unix targets we have no
    // SIGTERM equivalent, but the kernel is unix-only by spec
    // (`UnixListener` already gates everything to `cfg(unix)`).
    //
    // `wait_for_shutdown` returns the chosen reason AND aborts the
    // accept loops that did not win the race so they cannot keep
    // accepting connections during the cleanup window. The unbound
    // socket files are removed below; we explicitly do NOT rely on
    // `Drop` order of the `JoinHandle`s for that (a dropped
    // `JoinHandle` does NOT cancel the underlying task).
    let op_abort = op_task.abort_handle();
    let pl_abort = pl_task.abort_handle();
    let gw_abort = gw_task.abort_handle();
    let reason = wait_for_shutdown(sigterm, sigint, op_task, pl_task, gw_task).await;
    op_abort.abort();
    pl_abort.abort();
    gw_abort.abort();

    // Cleanup: unbind sockets by removing files. Best-effort — if the
    // operator wiped `<data_dir>` mid-shutdown the removes will simply ENOENT.
    for path in &[&operator_path, &planner_path, &gateway_path] {
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                server_log::socket_remove_failed(&path.display().to_string(), &e.to_string());
            }
        }
    }
    server_log::sockets_unbound(&reason);

    Ok(reason)
}

/// Race the three accept tasks against SIGTERM and SIGINT. The first
/// terminating arm wins; the others are aborted when this function returns
/// (the `JoinHandle`s are dropped together with the parent task in `start`).
///
/// Signal streams are created in `start()` BEFORE `sockets_bound` is
/// logged so the `sigaction` disposition is in place before any external
/// observer can send a signal. If either stream failed to create (extremely
/// rare — out-of-fd or kernel without signalfd), the corresponding
/// `Option` is `None` and we degrade to "wait for accept loop exit only"
/// for that signal.
async fn wait_for_shutdown(
    sigterm: Option<tokio::signal::unix::Signal>,
    sigint: Option<tokio::signal::unix::Signal>,
    op_task: tokio::task::JoinHandle<()>,
    pl_task: tokio::task::JoinHandle<()>,
    gw_task: tokio::task::JoinHandle<()>,
) -> ShutdownReason {
    // Wrap the optional streams in futures that pend forever if the
    // stream was `None` (degraded — that signal won't trigger graceful
    // shutdown, but the OS default handler still kills the process).
    let mut sigterm = sigterm;
    let mut sigint = sigint;
    let sigterm_fut = async {
        match sigterm.as_mut() {
            Some(s) => s.recv().await,
            None => std::future::pending().await,
        }
    };
    let sigint_fut = async {
        match sigint.as_mut() {
            Some(s) => s.recv().await,
            None => std::future::pending().await,
        }
    };

    tokio::select! {
        _ = sigterm_fut => {
            server_log::signal_received("SIGTERM");
            ShutdownReason::SigTerm
        }
        _ = sigint_fut => {
            server_log::signal_received("SIGINT");
            ShutdownReason::SigInt
        }
        result = op_task => {
            server_log::accept_loop_exited("operator", &format!("{result:?}"), true);
            ShutdownReason::AcceptLoopExited { which: "operator" }
        }
        result = pl_task => {
            server_log::accept_loop_exited("planner", &format!("{result:?}"), true);
            ShutdownReason::AcceptLoopExited { which: "planner" }
        }
        result = gw_task => {
            server_log::accept_loop_exited("gateway", &format!("{result:?}"), true);
            ShutdownReason::AcceptLoopExited { which: "gateway" }
        }
    }
}

// ---------------------------------------------------------------------------
// Operator accept loop
// ---------------------------------------------------------------------------

async fn accept_operator_loop(listener: UnixListener, ctx: Arc<HandlerContext>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(e) = handle_operator_connection(stream, ctx).await {
                        server_log::operator_connection_error(&e.to_string());
                    }
                });
            }
            Err(e) => {
                server_log::operator_accept_error(&e.to_string());
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

    // Step 3: Verify. We pin one snapshot of the bundle for the
    // duration of the handshake — an in-process epoch advance during
    // a handshake simply means the next handshake re-reads under the
    // new bundle.
    let policy_snapshot = ctx.policy.load_full();
    let operator = match auth::verify_response(&challenge, &response, policy_snapshot.as_ref()) {
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

    server_log::operator_authenticated(&operator.fingerprint);

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
                        planner_dispatch_log::planner_connection_error(&e.to_string());
                    }
                });
            }
            Err(e) => {
                planner_dispatch_log::planner_accept_error(&e.to_string());
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
    stream: tokio::net::UnixStream,
    ctx: Arc<HandlerContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // UDS-substrate connections are not session-bound at the
    // accept layer (`planner.sock` accepts every connection that
    // presents a valid session-token on the first frame; a single
    // VM may even reconnect mid-session in pathological cases).
    // The Mode-B post-exit synthesis hook does not run for the
    // UDS-substrate path (`spawn_planner_dispatcher` is a no-op
    // when `kernel_ipc_stream = None`), so passing `None` here is
    // both correct and the only safe choice — recording activity
    // against a session_id we don't yet know would let one VM's
    // last intent leak into a sibling VM's synthesised reason.
    //
    // The returned `PlannerStreamOutcome` (carrying any received
    // `PlannerExitNotice`) is discarded for the same reason: the
    // UDS-substrate accept loop has no post-exit synthesiser
    // wired in. The notice is still routed through the dispatch
    // match arm so the planner sees a valid
    // `KernelPlannerExitNoticeAck` reply across every substrate.
    drive_planner_stream(stream, ctx, None).await.map(|_| ())
}

/// **The planner dispatch loop, transport-agnostic.**
///
/// Reads length-prefixed bincode `IpcMessage` frames from `stream`,
/// dispatches each through the same handler chain
/// `handle_planner_connection` uses, and writes the response back
/// onto the same stream.
///
/// Used by:
///   * `accept_planner_loop` (`tokio::net::UnixStream` accepted on
///     `planner.sock` — subprocess substrate).
///   * `crate::session_spawn_orchestrator::spawn_planner_dispatcher`
///     (`tokio::net::UnixStream` constructed from the AVF /
///     Firecracker substrate's per-session VSock fd via
///     `Session::take_kernel_ipc_fd`).
///
/// Both paths converge here so a single change to the dispatch
/// matrix (e.g. a new `IpcMessage` variant) lands in exactly one
/// place. `drive_planner_stream` is `pub(crate)` because the
/// session-spawn callsite lives in `kernel/src/session_spawn_*.rs`.
///
/// **`session_id_for_activity`** — when `Some(_)`, the dispatch
/// loop records every successful `IntentRequest` round-trip into
/// [`crate::ipc::context::HandlerContext::session_activity`] keyed
/// by this `session_id`. The Mode-B post-exit synthesis hook in
/// [`crate::session_spawn_orchestrator::spawn_planner_dispatcher`]
/// reads (and consumes) the entry as a *fallback* breadcrumb when
/// the planner exits without sending a `PlannerExitNotice` (see
/// `INV-FAILURE-REASON-MANDATORY-01`). When the planner *does*
/// emit `PlannerExitNotice`, the captured
/// [`PlannerExitOutcome`](raxis_types::PlannerExitOutcome) is the
/// preferred concreteness source (`INV-FAILURE-REASON-CONCRETE-01`).
///
/// Substrate-spawned VM sessions (the only callers that exercise
/// the post-exit hook) pass `Some(session_id)`. UDS-substrate
/// callers pass `None` (see `handle_planner_connection`'s call
/// site for the rationale: the UDS path is not session-bound at
/// accept time, and the post-exit hook does not run for it).
///
/// **`INV-FAILURE-REASON-CONCRETE-01`.** The dispatch loop also
/// captures every `IpcMessage::PlannerExitNotice` frame the
/// planner sends and surfaces the most recent one through the
/// returned [`PlannerStreamOutcome`]. The session-spawn
/// post-exit synthesiser uses that captured outcome to format a
/// CONCRETE `block_reason` instead of falling back to the
/// multi-option umbrella string the invariant forbids.
pub(crate) async fn drive_planner_stream<S>(
    mut stream: S,
    ctx: Arc<HandlerContext>,
    session_id_for_activity: Option<String>,
) -> Result<PlannerStreamOutcome, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
{
    use raxis_ipc::{read_frame, write_frame, IpcMessage};

    // `INV-FAILURE-REASON-CONCRETE-01` — capture the last-seen
    // planner exit notice across every frame the loop reads. The
    // planner emits at most one notice per session (immediately
    // before EOF), but the loop tolerates multiple notices
    // defensively: a buggy planner that ships several updates
    // surfaces only the FINAL one to the Mode-B synthesiser, on
    // the principle that the most-recent state-of-the-world is
    // the most actionable.
    let mut last_exit_notice: Option<raxis_types::PlannerExitOutcome> = None;

    // `INV-PLANNER-IPC-IDLE-WATCHDOG-01` — per-frame deadline.
    // Each iteration's `read_frame` is wrapped in a
    // `tokio::time::timeout` with this duration. When the
    // timer elapses without a frame arriving the loop sets
    // `idle_watchdog_fired = true`, breaks out, and the
    // surrounding `spawn_planner_dispatcher` post-exit hook
    // calls `SessionSpawnService::terminate_session` to
    // forcibly kill the wedged VM. `None` ⇒ watchdog disabled
    // (env override `RAXIS_PLANNER_IPC_IDLE_TIMEOUT_SECS=0`).
    let idle_timeout = planner_ipc_idle_timeout();
    let idle_threshold_secs = idle_timeout.map(|d| d.as_secs()).unwrap_or(0);
    let mut idle_watchdog_fired = false;

    loop {
        // `INV-PLANNER-IPC-IDLE-WATCHDOG-01` — wrap the
        // per-frame read in a timeout. `read_frame` is
        // cancellation-safe (a no-op `tokio::io::AsyncRead`
        // wrapper around `read_exact`), so dropping the future
        // on timeout cleanly tears down its partial state.
        let frame_result: Result<Result<IpcMessage, raxis_ipc::FrameError>, _> = match idle_timeout
        {
            Some(d) => tokio::time::timeout(d, read_frame(&mut stream)).await,
            None => Ok(read_frame(&mut stream).await),
        };
        let msg: IpcMessage = match frame_result {
            Ok(Ok(m)) => m,
            Ok(Err(raxis_ipc::FrameError::Eof)) => break, // clean disconnect
            Ok(Err(e)) => {
                planner_dispatch_log::planner_frame_decode_failed(&e.to_string());
                break;
            }
            Err(_elapsed) => {
                // `INV-PLANNER-IPC-IDLE-WATCHDOG-01` —
                // the planner side has not sent ANY frame for
                // `idle_threshold_secs` seconds. The session is
                // declared wedged; the post-exit hook will
                // forcibly terminate the substrate VM and
                // synthesise a CONCRETE Mode-B failure reason
                // that names the watchdog firing.
                let session_label = session_id_for_activity
                    .as_deref()
                    .unwrap_or("<unbound-session>");
                eprintln!(
                    "{{\"level\":\"warn\",\
                     \"event\":\"planner_ipc_idle_watchdog_fired\",\
                     \"session_id\":\"{session}\",\
                     \"idle_threshold_secs\":{secs}}}",
                    session = session_label,
                    secs = idle_threshold_secs,
                );
                idle_watchdog_fired = true;
                break;
            }
        };

        // iter44 perf-metrics slice 4b — `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01`.
        // The RAII guard owns the inflight gauge + duration histogram
        // + counter for this frame. It is constructed at the top of
        // each match arm with the canonical `(role, message_kind)`
        // static-str pair drawn from
        // `crate::observability::{IPC_ROLE_*, IPC_MSG_KIND_*}` — the
        // same closed lexicon that
        // `crate::observability::kernel_substrate_ipc_route` returns
        // for the borrowed-message witness path. The guard is held
        // until the arm returns or `?`-propagates an error; Drop emits
        // the full metric tuple "regardless of handler outcome" — the
        // discipline the invariant pins.
        match msg {
            // ── IntentRequest ────────────────────────────────────────────
            IpcMessage::IntentRequest(req) => {
                let _ipc_metric = crate::observability::KernelSubstrateIpcRoundtrip::start(
                    ctx.observability.as_ref(),
                    crate::observability::IPC_ROLE_PLANNER,
                    crate::observability::IPC_MSG_KIND_INTENT_REQUEST,
                );
                planner_dispatch_log::intent_request(&req);
                // Capture context BEFORE moving `req` into the handler.
                let task_id_for_log = req.task_id.as_str().to_owned();
                let seq_for_log = req.sequence_number;
                // INV-FAILURE-REASON-MANDATORY-01 — also capture
                // the intent kind here so we can record the
                // last-activity entry post-handle for the
                // Mode-B post-exit synthesis hook. Cheap copy
                // (`IntentKind` is `Copy`).
                let intent_kind_for_activity = req.intent_kind;
                let started = std::time::Instant::now();
                let resp = handlers::intent::handle(req, &ctx).await;
                let latency_ms = started.elapsed().as_millis() as u64;
                planner_dispatch_log::intent_response(
                    &task_id_for_log,
                    seq_for_log,
                    &resp,
                    latency_ms,
                );
                // INV-FAILURE-REASON-MANDATORY-01 — record the
                // last activity entry BEFORE the response write
                // so a write_frame failure (planner socket
                // closed mid-handshake) still leaves a forensic
                // breadcrumb the post-exit hook can quote. The
                // tracker stores at most one entry per session
                // (the most recent intent), so this is a constant
                // cost per intent regardless of session length.
                if let Some(sid) = session_id_for_activity.as_deref() {
                    ctx.session_activity.record(
                        sid,
                        crate::session_activity::SessionActivity {
                            last_intent_kind: intent_kind_for_activity,
                            last_intent_seq: seq_for_log,
                            last_intent_outcome:
                                crate::session_activity::LastIntentOutcome::from_response(
                                    &resp.outcome,
                                ),
                            recorded_at_unix: raxis_types::clock::unix_now_secs(),
                        },
                    );
                }
                write_frame(&mut stream, &IpcMessage::KernelIntentResponse(resp)).await?;
            }

            // ── WitnessSubmission ─────────────────────────────────────────
            // Spec §2.2: verifiers connect to planner.sock; dispatcher routes
            // by variant. The WitnessAck response is a separate IpcMessage
            // variant so the verifier subprocess gets a typed acknowledgment.
            IpcMessage::WitnessSubmission(sub) => {
                let _ipc_metric = crate::observability::KernelSubstrateIpcRoundtrip::start(
                    ctx.observability.as_ref(),
                    crate::observability::IPC_ROLE_VERIFIER,
                    crate::observability::IPC_MSG_KIND_WITNESS_SUBMISSION,
                );
                planner_dispatch_log::witness_request(&sub);
                let task_id_for_log = sub.task_id.as_str().to_owned();
                let started = std::time::Instant::now();
                match handlers::witness::handle(sub, &ctx).await {
                    Ok(ack) => {
                        let latency_ms = started.elapsed().as_millis() as u64;
                        planner_dispatch_log::witness_response(&task_id_for_log, &ack, latency_ms);
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
                            handlers::witness::WitnessAck::Accepted { run_id, .. } => (
                                true,
                                uuid::Uuid::parse_str(&run_id).unwrap_or_default(),
                                None,
                            ),
                            handlers::witness::WitnessAck::AcceptedNonPass {
                                run_id,
                                gate_type,
                                result_class,
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
                        write_frame(
                            &mut stream,
                            &IpcMessage::WitnessAck {
                                verifier_run_id,
                                accepted,
                                reason,
                            },
                        )
                        .await?;
                    }
                    Err(e) => {
                        // HandlerError: transport/auth-level failure.
                        // Log and close — verifier's token remains unconsumed.
                        planner_dispatch_log::witness_handler_error(
                            Some(&task_id_for_log),
                            &e.to_string(),
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
                let _ipc_metric = crate::observability::KernelSubstrateIpcRoundtrip::start(
                    ctx.observability.as_ref(),
                    crate::observability::IPC_ROLE_PLANNER,
                    crate::observability::IPC_MSG_KIND_ESCALATION_REQUEST,
                );
                planner_dispatch_log::escalation_request(&req);
                let task_id_for_log = req.task_id.as_str().to_owned();
                let started = std::time::Instant::now();
                let resp = handlers::escalation::handle(req, &ctx).await;
                let latency_ms = started.elapsed().as_millis() as u64;
                planner_dispatch_log::escalation_response(&task_id_for_log, &resp, latency_ms);
                write_frame(&mut stream, &IpcMessage::KernelEscalationResponse(resp)).await?;
            }

            // ── PlannerFetchRequest ──────────────────────────────────────
            // Kernel-mediated egress: the planner asks the kernel to make
            // an HTTP fetch (typically an LLM Messages API call) on its
            // behalf. The handler validates the session, dispatches to
            // the gateway via `ctx.gateway.fetch(...)`, and returns a
            // typed PlannerFetchResponse. See
            // `provider-failure-handling.md §2.1` for the architecture
            // and `handlers/planner_fetch.rs` for the admission rules.
            IpcMessage::PlannerFetchRequest(req) => {
                let _ipc_metric = crate::observability::KernelSubstrateIpcRoundtrip::start(
                    ctx.observability.as_ref(),
                    crate::observability::IPC_ROLE_PLANNER,
                    crate::observability::IPC_MSG_KIND_PLANNER_FETCH_REQUEST,
                );
                let request_id = req.request_id;
                let started = std::time::Instant::now();
                let resp = handlers::planner_fetch::handle(req, &ctx).await;
                let latency_ms = started.elapsed().as_millis() as u64;
                planner_dispatch_log::planner_fetch_response(request_id, &resp, latency_ms);
                write_frame(&mut stream, &IpcMessage::KernelPlannerFetchResponse(resp)).await?;
            }

            // ── PlannerExitNotice ─────────────────────────────────
            // `INV-FAILURE-REASON-CONCRETE-01`. The planner ships
            // its structured exit outcome (max_turns hit / token
            // cap tripped / idle / explicit give-up / clean
            // completion) immediately before EOF so the kernel's
            // Mode-B premature-exit synthesiser in
            // `session_spawn_orchestrator` can format a CONCRETE
            // `block_reason` like
            //
            //   "executor planner reached max_turns budget
            //    (60 used / 60 limit) without submitting a
            //    terminal intent"
            //
            // instead of the multi-option umbrella the invariant
            // forbids.
            //
            // The frame round-trips with a tiny ack
            // (`KernelPlannerExitNoticeAck`) so the planner's
            // request/reply transport sees a typed reply before
            // the VM powers off. Latency is logged structurally
            // for parity with the other planner-socket frames.
            IpcMessage::PlannerExitNotice { outcome } => {
                let _ipc_metric = crate::observability::KernelSubstrateIpcRoundtrip::start(
                    ctx.observability.as_ref(),
                    crate::observability::IPC_ROLE_PLANNER,
                    crate::observability::IPC_MSG_KIND_PLANNER_EXIT_NOTICE,
                );
                planner_dispatch_log::planner_exit_notice(&outcome);
                last_exit_notice = Some(outcome);
                write_frame(&mut stream, &IpcMessage::KernelPlannerExitNoticeAck).await?;
            }

            other => {
                let _ipc_metric = crate::observability::KernelSubstrateIpcRoundtrip::start(
                    ctx.observability.as_ref(),
                    crate::observability::IPC_ROLE_UNKNOWN,
                    crate::observability::IPC_MSG_KIND_UNEXPECTED,
                );
                planner_dispatch_log::planner_unexpected_message(&other);
                // Unknown variant: log and drop frame but keep connection open.
            }
        }
    }
    Ok(PlannerStreamOutcome {
        last_exit_notice,
        idle_watchdog_fired,
        idle_watchdog_threshold_secs: idle_threshold_secs,
    })
}

/// **`INV-FAILURE-REASON-CONCRETE-01`** — value returned by
/// [`drive_planner_stream`] when the planner-side socket reaches
/// EOF.
///
/// Carries the most recently received
/// [`raxis_types::PlannerExitOutcome`] (when the planner emitted
/// `IpcMessage::PlannerExitNotice` before disconnecting) so the
/// session-spawn premature-exit synthesiser can format a
/// CONCRETE `block_reason` instead of falling back to the multi-
/// option umbrella string.
///
/// `last_exit_notice = None` is the operator-visible gap: it
/// means the planner exited (or was killed) without sending an
/// exit notice. The Mode-B synthesiser still fires, but its
/// formatted reason names the gap explicitly (e.g. `"executor
/// VM exited via clean EOF without a PlannerExitNotice — likely
/// SIGKILL / OOM / panic before exit cleanup"`) rather than the
/// previous multi-cause umbrella.
#[derive(Debug, Default, Clone)]
pub(crate) struct PlannerStreamOutcome {
    /// Most recent `PlannerExitNotice::outcome` observed on the
    /// stream, or `None` if the planner closed the connection
    /// without sending one.
    pub last_exit_notice: Option<raxis_types::PlannerExitOutcome>,

    /// `INV-PLANNER-IPC-IDLE-WATCHDOG-01` — set to `true` when
    /// the kernel-side idle-watchdog timer expired without any
    /// IPC frame arriving from the planner. This is the
    /// canonical signal for a wedged VM (host substrate kept the
    /// VM "running" but the in-guest dispatch is no longer
    /// making progress): the kernel must then forcibly terminate
    /// the substrate session via
    /// `SessionSpawnService::terminate_session` and synthesise a
    /// CONCRETE Mode-B failure reason that names the watchdog
    /// firing explicitly (rather than the generic clean-EOF
    /// branch which would have fired had this happened to be a
    /// genuine clean disconnect).
    ///
    /// Default `false`: the standard clean-EOF / dispatch-error
    /// branches remain unchanged in behaviour. The flag is set
    /// only by the watchdog arm of [`drive_planner_stream`] when
    /// the per-frame `tokio::time::timeout` elapses.
    pub idle_watchdog_fired: bool,

    /// Duration (in seconds) the kernel waited for the next IPC
    /// frame before declaring the session wedged. Surfaced via
    /// the synthesised failure_reason so the operator can see
    /// the exact threshold without checking the kernel
    /// configuration.
    pub idle_watchdog_threshold_secs: u64,
}

/// `INV-PLANNER-IPC-IDLE-WATCHDOG-01` — the maximum time the
/// kernel will wait for the planner to send any IPC frame
/// (IntentRequest, WitnessSubmission, EscalationRequest,
/// PlannerExitNotice) before declaring the substrate-spawned
/// session wedged and forcibly terminating its VM.
///
/// ## Why a watchdog at all
///
/// Before the watchdog, a wedged executor VM (e.g. one whose
/// host-side AVF XPC process survived a SIGKILL of the parent
/// kernel and now shares a vsock CID with a freshly-spawned
/// peer) would block the dispatch loop's `read_frame(...)` call
/// indefinitely. The kernel had no other liveness signal — no
/// heartbeat, no progress event, nothing — so the wedged VM
/// would sit there consuming an admission slot until operator
/// intervention. Multiplied across a few orphaned VMs this
/// silently broke entire initiative DAGs.
///
/// ## The chosen threshold
///
/// 15 minutes (900s) is the production default. The signal
/// budgets are dominated by:
///
/// * LLM gateway round-trip (Anthropic / OpenAI / Gemini big
///   prompts: 60–120s typical, 5 min worst-case at p99 for
///   long-context turns).
/// * In-VM bash tool execution (bounded by a per-task budget;
///   credential-proxy fetches cap at ~90s, general bash at
///   the planner-driver-imposed 300s).
///
/// 900s ⇒ even a worst-case LLM + a worst-case tool round-trip
/// fits within one watchdog window. A genuine stall (no frame
/// for 15 minutes) is almost certainly substrate-level: the
/// guest kernel hung, PID 1 panicked silently, or the AVF host
/// substrate stopped pumping bytes.
///
/// ## Override
///
/// Production callers can override the default via
/// `RAXIS_PLANNER_IPC_IDLE_TIMEOUT_SECS`. The override is
/// per-process (read once per `drive_planner_stream` invocation
/// so unit tests can flip it via `std::env::set_var` before
/// constructing a fixture). Setting it to `0` disables the
/// watchdog entirely (the previous, unbounded behaviour) —
/// used by long-running stress tests that may have many minutes
/// between frames by design.
pub(crate) const PLANNER_IPC_IDLE_TIMEOUT_DEFAULT_SECS: u64 = 900;

/// Read the configured planner-IPC idle timeout. See
/// [`PLANNER_IPC_IDLE_TIMEOUT_DEFAULT_SECS`] for the rationale.
/// Returns `None` when the env var is set to `0` (watchdog
/// disabled).
pub(crate) fn planner_ipc_idle_timeout() -> Option<std::time::Duration> {
    let secs = std::env::var("RAXIS_PLANNER_IPC_IDLE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(PLANNER_IPC_IDLE_TIMEOUT_DEFAULT_SECS);
    if secs == 0 {
        None
    } else {
        Some(std::time::Duration::from_secs(secs))
    }
}

// ---------------------------------------------------------------------------
// Gateway accept loop has moved to `crate::gateway::accept`
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Socket permissions helper
// ---------------------------------------------------------------------------

fn set_socket_permissions(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        server_log::chmod_socket_failed(&path.display().to_string(), &e.to_string());
    }
}

// ---------------------------------------------------------------------------
// Structured stderr logging — listener / accept-loop / planner-dispatch.
//
// Why this lives inline rather than in a top-level kernel logging crate:
// see `crate::ipc::log` for the scope rationale. This file's logging
// covers two modules:
//
//   * `ipc.server`   — listener bind/unbind, signal handling, generic
//                      accept-loop errors, and operator-connection auth
//                      events (post-handshake operator dispatch is
//                      logged separately by `ipc::operator::dispatch_log`
//                      under `ipc.operator`).
//
//   * `ipc.planner`  — planner-socket frame events (intent / witness /
//                      escalation request+response, frame-decode and
//                      handler-level errors).
//
// **Credential redaction contract:** these helpers MUST NEVER receive
// `IntentRequest.session_token`, `EscalationRequest.session_token`, or
// `WitnessSubmission.verifier_token` as a field value. Where a bearer
// token correlation is genuinely useful (e.g. distinguishing two
// concurrent verifier runs in the log), the dispatcher derives a
// `*_fp` field via `crate::ipc::log::credential_fingerprint`. The
// regression tests in this module pin both halves of that contract.
// ---------------------------------------------------------------------------

pub(crate) mod server_log {
    use super::ShutdownReason;
    use crate::ipc::log::{finalize_line, level};
    use serde_json::{json, Map};
    #[cfg(test)]
    use {crate::ipc::log::body_from_fields, serde_json::Value};

    pub(super) const MODULE: &str = "ipc.server";

    // ── Pure formatters (`build_*_line`) → owned `String`. ──

    pub(crate) fn build_sockets_bound_line(
        operator_path: &str,
        planner_path: &str,
        gateway_path: &str,
        ts_unix: i64,
    ) -> String {
        let mut body = Map::new();
        body.insert("operator".into(), json!(operator_path));
        body.insert("planner".into(), json!(planner_path));
        body.insert("gateway".into(), json!(gateway_path));
        finalize_line(level::INFO, MODULE, "sockets_bound", body, ts_unix)
    }

    pub(crate) fn build_sockets_unbound_line(reason: &ShutdownReason, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("reason".into(), json!(reason.audit_reason()));
        finalize_line(level::INFO, MODULE, "sockets_unbound", body, ts_unix)
    }

    pub(crate) fn build_socket_remove_failed_line(path: &str, error: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("path".into(), json!(path));
        body.insert("error".into(), json!(error));
        finalize_line(level::WARN, MODULE, "socket_remove_failed", body, ts_unix)
    }

    pub(crate) fn build_chmod_socket_failed_line(path: &str, error: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("path".into(), json!(path));
        body.insert("error".into(), json!(error));
        finalize_line(level::WARN, MODULE, "chmod_socket_failed", body, ts_unix)
    }

    pub(crate) fn build_signal_handler_install_failed_line(
        signal: &'static str,
        error: &str,
        ts_unix: i64,
    ) -> String {
        let mut body = Map::new();
        body.insert("signal".into(), json!(signal));
        body.insert("error".into(), json!(error));
        finalize_line(
            level::ERROR,
            MODULE,
            "signal_handler_install_failed",
            body,
            ts_unix,
        )
    }

    pub(crate) fn build_signal_received_line(signal: &'static str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("signal".into(), json!(signal));
        finalize_line(level::INFO, MODULE, "signal_received", body, ts_unix)
    }

    pub(crate) fn build_accept_loop_exited_line(
        which: &'static str,
        join_result_debug: &str,
        signal_handler_installed: bool,
        ts_unix: i64,
    ) -> String {
        let mut body = Map::new();
        body.insert("which".into(), json!(which));
        // `join_result_debug` is always a `tokio::task::JoinError`-or-`Ok`
        // Debug rendering. The variants are bounded enums on a unit
        // payload — they cannot carry application credentials — but we
        // route through `serde_json` anyway so embedded quotes can't
        // break the JSON line.
        body.insert("join_result".into(), json!(join_result_debug));
        body.insert(
            "signal_handler_installed".into(),
            json!(signal_handler_installed),
        );
        finalize_line(level::ERROR, MODULE, "accept_loop_exited", body, ts_unix)
    }

    pub(crate) fn build_operator_accept_error_line(error: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("error".into(), json!(error));
        finalize_line(level::ERROR, MODULE, "operator_accept_error", body, ts_unix)
    }

    pub(crate) fn build_operator_connection_error_line(error: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("error".into(), json!(error));
        finalize_line(
            level::WARN,
            MODULE,
            "operator_connection_error",
            body,
            ts_unix,
        )
    }

    pub(crate) fn build_operator_authenticated_line(operator_fp: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        // `operator_fp` is the operator's pubkey fingerprint, which is
        // a public identifier (already in `policy.toml` and audit
        // events). NOT a credential.
        body.insert("operator_fp".into(), json!(operator_fp));
        finalize_line(level::INFO, MODULE, "operator_authenticated", body, ts_unix)
    }

    // ── Emit-side wrappers ──

    pub(super) fn sockets_bound(operator: &str, planner: &str, gateway: &str) {
        eprintln!(
            "{}",
            build_sockets_bound_line(operator, planner, gateway, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn sockets_unbound(reason: &ShutdownReason) {
        eprintln!(
            "{}",
            build_sockets_unbound_line(reason, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn socket_remove_failed(path: &str, error: &str) {
        eprintln!(
            "{}",
            build_socket_remove_failed_line(path, error, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn chmod_socket_failed(path: &str, error: &str) {
        eprintln!(
            "{}",
            build_chmod_socket_failed_line(path, error, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn signal_handler_install_failed(signal: &'static str, error: &str) {
        eprintln!(
            "{}",
            build_signal_handler_install_failed_line(signal, error, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn signal_received(signal: &'static str) {
        eprintln!(
            "{}",
            build_signal_received_line(signal, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn accept_loop_exited(
        which: &'static str,
        join_result_debug: &str,
        signal_handler_installed: bool,
    ) {
        eprintln!(
            "{}",
            build_accept_loop_exited_line(
                which,
                join_result_debug,
                signal_handler_installed,
                raxis_types::unix_now_secs(),
            ),
        );
    }

    pub(super) fn operator_accept_error(error: &str) {
        eprintln!(
            "{}",
            build_operator_accept_error_line(error, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn operator_connection_error(error: &str) {
        eprintln!(
            "{}",
            build_operator_connection_error_line(error, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn operator_authenticated(operator_fp: &str) {
        eprintln!(
            "{}",
            build_operator_authenticated_line(operator_fp, raxis_types::unix_now_secs()),
        );
    }

    // ── Helpers shared inside this module ──

    /// Used by the test suite below — gives a predictable empty body
    /// to test serialisation invariants when a builder takes no
    /// context fields.
    #[cfg(test)]
    pub(crate) fn empty_body() -> Map<String, Value> {
        body_from_fields(&[])
    }
}

pub(crate) mod planner_dispatch_log {
    use super::handlers::witness::WitnessAck;
    use crate::ipc::log::{body_from_fields, credential_fingerprint, finalize_line, level};
    use raxis_ipc::message::IpcMessage;
    use raxis_types::escalation::{EscalationRequest, EscalationResponse};
    use raxis_types::intent::{IntentOutcome, IntentRequest, IntentResponse};
    use raxis_types::witness::WitnessSubmission;
    use serde_json::{json, Map};

    pub(super) const MODULE: &str = "ipc.planner";

    // ── Pure formatters (`build_*_line`) → owned `String`. ──

    pub(crate) fn build_planner_accept_error_line(error: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("error".into(), json!(error));
        finalize_line(level::ERROR, MODULE, "planner_accept_error", body, ts_unix)
    }

    pub(crate) fn build_planner_connection_error_line(error: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("error".into(), json!(error));
        finalize_line(
            level::WARN,
            MODULE,
            "planner_connection_error",
            body,
            ts_unix,
        )
    }

    pub(crate) fn build_planner_frame_decode_failed_line(error: &str, ts_unix: i64) -> String {
        let mut body = Map::new();
        body.insert("error".into(), json!(error));
        finalize_line(
            level::WARN,
            MODULE,
            "planner_frame_decode_failed",
            body,
            ts_unix,
        )
    }

    /// Per-message-variant log emitted whenever the planner socket
    /// receives a frame whose `IpcMessage` discriminant is not
    /// `IntentRequest`, `WitnessSubmission`, or `EscalationRequest`.
    /// The discriminant name only — never the payload — is logged.
    pub(crate) fn build_planner_unexpected_message_line(
        variant: &'static str,
        ts_unix: i64,
    ) -> String {
        let mut body = Map::new();
        body.insert("variant".into(), json!(variant));
        finalize_line(
            level::WARN,
            MODULE,
            "planner_unexpected_message",
            body,
            ts_unix,
        )
    }

    /// Build the `intent_request` line for a received `IntentRequest`.
    ///
    /// **CREDENTIAL REDACTION:** `req.session_token` is read by this
    /// builder ONLY to derive a non-reversible `session_token_fp` for
    /// log correlation. The raw token MUST NOT appear in the output.
    /// The regression test
    /// `intent_request_line_does_not_contain_session_token` pins this.
    pub(crate) fn build_intent_request_line(req: &IntentRequest, ts_unix: i64) -> String {
        let mut body = body_from_fields(&[
            ("task_id", req.task_id.as_str().to_owned()),
            ("intent_kind", req.intent_kind.as_str().to_owned()),
        ]);
        body.insert("sequence_number".into(), json!(req.sequence_number));
        body.insert(
            "session_token_fp".into(),
            json!(credential_fingerprint(&req.session_token)),
        );
        if let Some(idem) = req.idempotency_key {
            body.insert("idempotency_key".into(), json!(idem.to_string()));
        }
        finalize_line(level::INFO, MODULE, "intent_request", body, ts_unix)
    }

    /// Build the `intent_response` line emitted right before the
    /// kernel writes the response frame back to the planner.
    pub(crate) fn build_intent_response_line(
        task_id: &str,
        sequence_number: u64,
        resp: &IntentResponse,
        latency_ms: u64,
        ts_unix: i64,
    ) -> String {
        let mut body = body_from_fields(&[("task_id", task_id.to_owned())]);
        body.insert("sequence_number".into(), json!(sequence_number));
        body.insert("latency_ms".into(), json!(latency_ms));
        body.insert("task_state".into(), json!(resp.task_state.as_sql_str()));

        let log_level = match &resp.outcome {
            IntentOutcome::Accepted {
                warn_delegation_stale,
                remaining_budget,
            } => {
                body.insert("status".into(), json!("accepted"));
                body.insert("warn_delegation_stale".into(), json!(warn_delegation_stale));
                body.insert(
                    "admission_units_remaining".into(),
                    json!(remaining_budget.admission_units),
                );
                level::INFO
            }
            IntentOutcome::Rejected {
                error_code,
                error_detail,
            } => {
                body.insert("status".into(), json!("rejected"));
                body.insert("error_code".into(), json!(format!("{error_code:?}")));
                if let Some(d) = error_detail {
                    body.insert("error_detail".into(), json!(format!("{d:?}")));
                }
                level::WARN
            }
            // V3 iter70 — envelope-level accepted batch. We tag
            // the line as `accepted_batch` with the per-id
            // outcome counts so the dashboard can surface
            // partial-admission turns without needing to
            // re-shape every consumer of the singular path.
            IntentOutcome::AcceptedBatch {
                remaining_budget,
                results,
            } => {
                let total = results.len();
                let accepted = results
                    .iter()
                    .filter(|r| matches!(r.outcome, raxis_types::BatchTaskOutcome::Accepted { .. }))
                    .count();
                let dropped_cap = results
                    .iter()
                    .filter(|r| matches!(r.outcome, raxis_types::BatchTaskOutcome::DroppedAtCap))
                    .count();
                let not_admissible = results
                    .iter()
                    .filter(|r| {
                        matches!(
                            r.outcome,
                            raxis_types::BatchTaskOutcome::NotAdmissible { .. }
                        )
                    })
                    .count();
                let unknown = results
                    .iter()
                    .filter(|r| matches!(r.outcome, raxis_types::BatchTaskOutcome::UnknownTask))
                    .count();
                let duplicate = results
                    .iter()
                    .filter(|r| {
                        matches!(r.outcome, raxis_types::BatchTaskOutcome::DuplicateInBatch)
                    })
                    .count();
                body.insert("status".into(), json!("accepted_batch"));
                body.insert(
                    "admission_units_remaining".into(),
                    json!(remaining_budget.admission_units),
                );
                body.insert("batch_total".into(), json!(total));
                body.insert("batch_accepted".into(), json!(accepted));
                body.insert("batch_dropped_at_cap".into(), json!(dropped_cap));
                body.insert("batch_not_admissible".into(), json!(not_admissible));
                body.insert("batch_unknown".into(), json!(unknown));
                body.insert("batch_duplicate".into(), json!(duplicate));
                level::INFO
            }
        };
        finalize_line(log_level, MODULE, "intent_response", body, ts_unix)
    }

    /// Build the `witness_request` line.
    ///
    /// **CREDENTIAL REDACTION:** `sub.verifier_token` is read ONLY to
    /// derive `verifier_token_fp` for log correlation. The raw token
    /// MUST NOT appear in the output. Pinned by
    /// `witness_request_line_does_not_contain_verifier_token`.
    pub(crate) fn build_witness_request_line(sub: &WitnessSubmission, ts_unix: i64) -> String {
        let mut body = body_from_fields(&[
            ("task_id", sub.task_id.as_str().to_owned()),
            ("gate_type", sub.gate_type.as_str().to_owned()),
            ("evaluation_sha", sub.evaluation_sha.as_str().to_owned()),
            ("result_class", sub.result_class.as_sql_str().to_owned()),
        ]);
        body.insert(
            "verifier_token_fp".into(),
            json!(credential_fingerprint(&sub.verifier_token)),
        );
        finalize_line(level::INFO, MODULE, "witness_request", body, ts_unix)
    }

    /// Build the `witness_response` line. The verifier-side wire
    /// payload (run_id + accepted/rejected) is logged; no credential
    /// passes through this builder.
    pub(crate) fn build_witness_response_line(
        task_id: &str,
        ack: &WitnessAck,
        latency_ms: u64,
        ts_unix: i64,
    ) -> String {
        let mut body = body_from_fields(&[("task_id", task_id.to_owned())]);
        body.insert("latency_ms".into(), json!(latency_ms));
        let log_level = match ack {
            WitnessAck::Accepted { run_id, .. } => {
                body.insert("status".into(), json!("accepted"));
                body.insert("run_id".into(), json!(run_id));
                level::INFO
            }
            WitnessAck::AcceptedNonPass {
                run_id,
                gate_type,
                result_class,
            } => {
                body.insert("status".into(), json!("accepted_non_pass"));
                body.insert("run_id".into(), json!(run_id));
                body.insert("gate_type".into(), json!(gate_type.as_str()));
                body.insert("result_class".into(), json!(result_class.as_str()));
                level::INFO
            }
            WitnessAck::Rejected { reason } => {
                body.insert("status".into(), json!("rejected"));
                body.insert("reason".into(), json!(format!("{reason:?}")));
                level::WARN
            }
        };
        finalize_line(log_level, MODULE, "witness_response", body, ts_unix)
    }

    pub(crate) fn build_witness_handler_error_line(
        task_id: Option<&str>,
        error: &str,
        ts_unix: i64,
    ) -> String {
        let mut body = Map::new();
        if let Some(t) = task_id {
            body.insert("task_id".into(), json!(t));
        }
        body.insert("error".into(), json!(error));
        finalize_line(level::ERROR, MODULE, "witness_handler_error", body, ts_unix)
    }

    /// Build the `escalation_request` line.
    ///
    /// **CREDENTIAL REDACTION:** `req.session_token` is read ONLY to
    /// derive `session_token_fp` for log correlation. The raw token
    /// MUST NOT appear in the output. Pinned by
    /// `escalation_request_line_does_not_contain_session_token`.
    pub(crate) fn build_escalation_request_line(req: &EscalationRequest, ts_unix: i64) -> String {
        let mut body = body_from_fields(&[
            ("task_id", req.task_id.as_str().to_owned()),
            ("class", req.class.as_sql_str().to_owned()),
        ]);
        body.insert(
            "session_token_fp".into(),
            json!(credential_fingerprint(&req.session_token)),
        );
        body.insert(
            "idempotency_key".into(),
            json!(req.idempotency_key.to_string()),
        );
        finalize_line(level::INFO, MODULE, "escalation_request", body, ts_unix)
    }

    /// Build the `escalation_response` line.
    pub(crate) fn build_escalation_response_line(
        task_id: &str,
        resp: &EscalationResponse,
        latency_ms: u64,
        ts_unix: i64,
    ) -> String {
        let mut body = body_from_fields(&[("task_id", task_id.to_owned())]);
        body.insert("latency_ms".into(), json!(latency_ms));
        let log_level = match resp {
            EscalationResponse::Submitted { escalation_id, .. } => {
                body.insert("status".into(), json!("submitted"));
                body.insert("escalation_id".into(), json!(escalation_id.as_str()));
                level::INFO
            }
            EscalationResponse::AlreadyPending { escalation_id } => {
                body.insert("status".into(), json!("already_pending"));
                body.insert("escalation_id".into(), json!(escalation_id.as_str()));
                level::INFO
            }
            EscalationResponse::Rejected { reason } => {
                body.insert("status".into(), json!("rejected"));
                body.insert("reason".into(), json!(format!("{reason:?}")));
                level::WARN
            }
        };
        finalize_line(log_level, MODULE, "escalation_response", body, ts_unix)
    }

    // ── Emit-side wrappers ──

    pub(super) fn planner_accept_error(error: &str) {
        eprintln!(
            "{}",
            build_planner_accept_error_line(error, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn planner_connection_error(error: &str) {
        eprintln!(
            "{}",
            build_planner_connection_error_line(error, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn planner_frame_decode_failed(error: &str) {
        eprintln!(
            "{}",
            build_planner_frame_decode_failed_line(error, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn planner_unexpected_message(msg: &IpcMessage) {
        eprintln!(
            "{}",
            build_planner_unexpected_message_line(
                ipc_message_variant_name(msg),
                raxis_types::unix_now_secs(),
            ),
        );
    }

    pub(super) fn intent_request(req: &IntentRequest) {
        eprintln!(
            "{}",
            build_intent_request_line(req, raxis_types::unix_now_secs())
        );
    }

    pub(super) fn intent_response(
        task_id: &str,
        sequence_number: u64,
        resp: &IntentResponse,
        latency_ms: u64,
    ) {
        eprintln!(
            "{}",
            build_intent_response_line(
                task_id,
                sequence_number,
                resp,
                latency_ms,
                raxis_types::unix_now_secs(),
            ),
        );
    }

    pub(super) fn witness_request(sub: &WitnessSubmission) {
        eprintln!(
            "{}",
            build_witness_request_line(sub, raxis_types::unix_now_secs())
        );
    }

    pub(super) fn witness_response(task_id: &str, ack: &WitnessAck, latency_ms: u64) {
        eprintln!(
            "{}",
            build_witness_response_line(task_id, ack, latency_ms, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn witness_handler_error(task_id: Option<&str>, error: &str) {
        eprintln!(
            "{}",
            build_witness_handler_error_line(task_id, error, raxis_types::unix_now_secs()),
        );
    }

    pub(super) fn escalation_request(req: &EscalationRequest) {
        eprintln!(
            "{}",
            build_escalation_request_line(req, raxis_types::unix_now_secs())
        );
    }

    pub(super) fn escalation_response(task_id: &str, resp: &EscalationResponse, latency_ms: u64) {
        eprintln!(
            "{}",
            build_escalation_response_line(task_id, resp, latency_ms, raxis_types::unix_now_secs()),
        );
    }

    /// One-line structured log for a `PlannerFetchRequest` round
    /// trip. The body is intentionally narrow — `request_id`,
    /// `status_code`, `latency_ms`, and the optional `error` short
    /// string — because we don't want to log URLs or response
    /// bodies on the kernel's stderr (those go to the gateway's
    /// own audit chain and the kernel's audit segment via the
    /// gateway path).
    pub(super) fn planner_fetch_response(
        request_id: uuid::Uuid,
        resp: &raxis_types::PlannerFetchResponse,
        latency_ms: u64,
    ) {
        let status = resp
            .status_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "none".to_owned());
        let error = resp
            .error
            .as_deref()
            .map(|e| format!("\"{e}\""))
            .unwrap_or_else(|| "null".to_owned());
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"planner_fetch_response\",\
             \"request_id\":\"{request_id}\",\
             \"status_code\":{status},\
             \"error\":{error},\
             \"latency_ms\":{latency_ms},\
             \"ts\":{ts}}}",
            ts = raxis_types::unix_now_secs(),
        );
    }

    /// `INV-FAILURE-REASON-CONCRETE-01` — structured-log line
    /// emitted when the planner ships its
    /// `IpcMessage::PlannerExitNotice` frame. Pairs with the
    /// kernel-side `planner_exit_notice_observed` event so the
    /// `kernel.stderr.log` carries the same machine-parseable
    /// shape on both sides of the wire.
    ///
    /// Renders the outcome as JSON via `serde_json::to_string`
    /// so the `kind`/`detail` discriminator round-trips
    /// verbatim. Operators can grep on the `kind` field to
    /// classify exits without writing a per-variant log
    /// scanner.
    pub(super) fn planner_exit_notice(outcome: &raxis_types::PlannerExitOutcome) {
        let outcome_json = serde_json::to_string(outcome).unwrap_or_else(|e| {
            format!("{{\"kind\":\"_serde_error\",\"err\":{:?}}}", e.to_string())
        });
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"planner_exit_notice_observed\",\
              \"outcome\":{outcome_json},\
              \"ts\":{ts}}}",
            ts = raxis_types::unix_now_secs(),
        );
    }

    // ── Helpers ──

    /// Stable variant tag for the `planner_unexpected_message` log
    /// line. Kept as a small standalone fn so the test suite can pin
    /// every variant produces a non-empty string. The `OperatorRequest`
    /// and `OperatorResponse` variants of `IpcMessage` are technically
    /// reachable here only as a wire-shape oddity (they belong on
    /// operator.sock, not planner.sock) — we still produce a stable
    /// tag rather than panicking.
    pub(crate) fn ipc_message_variant_name(msg: &IpcMessage) -> &'static str {
        match msg {
            IpcMessage::IntentRequest(_) => "IntentRequest",
            IpcMessage::EscalationRequest(_) => "EscalationRequest",
            IpcMessage::PlannerFetchRequest(_) => "PlannerFetchRequest",
            IpcMessage::PlannerExitNotice { .. } => "PlannerExitNotice",
            IpcMessage::KernelIntentResponse(_) => "KernelIntentResponse",
            IpcMessage::KernelEscalationResponse(_) => "KernelEscalationResponse",
            IpcMessage::KernelPlannerFetchResponse(_) => "KernelPlannerFetchResponse",
            IpcMessage::KernelPlannerExitNoticeAck => "KernelPlannerExitNoticeAck",
            IpcMessage::WitnessSubmission(_) => "WitnessSubmission",
            IpcMessage::WitnessAck { .. } => "WitnessAck",
            IpcMessage::OperatorRequest(_) => "OperatorRequest",
            IpcMessage::OperatorResponse(_) => "OperatorResponse",
            IpcMessage::TproxyAdmissionRequest(_) => "TproxyAdmissionRequest",
            IpcMessage::KernelTproxyAdmissionResponse(_) => "KernelTproxyAdmissionResponse",
            IpcMessage::DnsResolveRequest(_) => "DnsResolveRequest",
            IpcMessage::KernelDnsResolveResponse(_) => "KernelDnsResolveResponse",
        }
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

// ---------------------------------------------------------------------------
// Tests — `server_log` (listener / accept / signal events).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod server_log_tests {
    use super::server_log;
    use super::ShutdownReason;
    use serde_json::Value;

    fn parse(line: &str) -> Value {
        serde_json::from_str(line).unwrap_or_else(|e| panic!("invalid JSON: {e}\nline: {line}"))
    }

    #[test]
    fn sockets_bound_carries_three_paths_and_module_tag() {
        let line = server_log::build_sockets_bound_line(
            "/d/sockets/operator.sock",
            "/d/sockets/planner.sock",
            "/d/sockets/gateway.sock",
            1_700_000_000,
        );
        let v = parse(&line);
        assert_eq!(v["module"], "ipc.server");
        assert_eq!(v["event"], "sockets_bound");
        assert_eq!(v["level"], "info");
        assert_eq!(v["operator"], "/d/sockets/operator.sock");
        assert_eq!(v["planner"], "/d/sockets/planner.sock");
        assert_eq!(v["gateway"], "/d/sockets/gateway.sock");
    }

    #[test]
    fn sockets_unbound_carries_audit_reason_string() {
        let line = server_log::build_sockets_unbound_line(
            &ShutdownReason::AcceptLoopExited { which: "planner" },
            1_700_000_001,
        );
        let v = parse(&line);
        assert_eq!(v["event"], "sockets_unbound");
        assert_eq!(v["reason"], "accept_loop_exited:planner");
    }

    #[test]
    fn signal_handler_install_failed_at_error_with_signal_name() {
        let line = server_log::build_signal_handler_install_failed_line("SIGTERM", "ENOSYS", 0);
        let v = parse(&line);
        assert_eq!(v["level"], "error");
        assert_eq!(v["event"], "signal_handler_install_failed");
        assert_eq!(v["signal"], "SIGTERM");
        assert_eq!(v["error"], "ENOSYS");
    }

    #[test]
    fn accept_loop_exited_marks_signal_handler_state() {
        let with_handler = server_log::build_accept_loop_exited_line("operator", "Ok(())", true, 0);
        let v = parse(&with_handler);
        assert_eq!(v["which"], "operator");
        assert_eq!(v["signal_handler_installed"], true);

        let without_handler =
            server_log::build_accept_loop_exited_line("planner", "Err(JoinError)", false, 0);
        let v = parse(&without_handler);
        assert_eq!(v["signal_handler_installed"], false);
    }

    #[test]
    fn operator_authenticated_carries_fingerprint_at_info() {
        let line =
            server_log::build_operator_authenticated_line("abcd1234abcd1234abcd1234abcd1234", 0);
        let v = parse(&line);
        assert_eq!(v["level"], "info");
        assert_eq!(v["event"], "operator_authenticated");
        assert_eq!(v["operator_fp"], "abcd1234abcd1234abcd1234abcd1234");
    }

    /// Escape-safety regression: error strings from `e.to_string()`
    /// can carry quotes (e.g. `bind: "address already in use"`).
    /// The shared `finalize_line` MUST escape them.
    #[test]
    fn error_strings_with_embedded_quotes_round_trip_through_json() {
        let line =
            server_log::build_operator_accept_error_line(r#"bind: "address already in use""#, 0);
        let v = parse(&line);
        assert_eq!(v["error"], r#"bind: "address already in use""#);
    }
}

// ---------------------------------------------------------------------------
// Tests — `planner_dispatch_log` (intent / witness / escalation events).
//
// **Most important assertion in this module:** every credential-bearing
// builder MUST NOT include the raw credential value in its output.
// The dispatcher passes through `IntentRequest.session_token`,
// `EscalationRequest.session_token`, and `WitnessSubmission.verifier_token`
// — every one of these is a bearer token that, if logged, would let
// any operator with read access to journald/stderr impersonate the
// session. The `*_does_not_contain_*_token` tests pin that contract.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod planner_dispatch_log_tests {
    use super::handlers::witness::WitnessAck;
    use super::planner_dispatch_log;
    use raxis_ipc::message::IpcMessage;
    use raxis_types::escalation::{
        EscalationClass, EscalationRejectionReason, EscalationRequest, EscalationResponse,
        RequestedEscalationScope,
    };
    use raxis_types::intent::{
        BudgetSnapshot, IntentKind, IntentOutcome, IntentRequest, IntentResponse,
        PlannerErrorTemplate,
    };
    use raxis_types::witness::WitnessResultClass;
    use raxis_types::{
        EscalationId, GateType, PlannerErrorCode, TaskId, TaskState, WitnessSubmission,
    };
    use serde_json::Value;
    use uuid::Uuid;

    // ── shared fixtures ───────────────────────────────────────────────

    /// A token-shaped string that we can grep for. Distinctive prefix
    /// `SECRET_` makes any leak unmissable in test output.
    const SECRET_SESSION_TOKEN: &str =
        "SECRET_SESSION_TOKEN_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_VERIFIER_TOKEN: &str =
        "SECRET_VERIFIER_TOKEN_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn parse(line: &str) -> Value {
        serde_json::from_str(line).unwrap_or_else(|e| panic!("invalid JSON: {e}\nline: {line}"))
    }

    fn fixture_intent_request(token: &str) -> IntentRequest {
        IntentRequest {
            session_token: token.to_owned(),
            sequence_number: 7,
            envelope_nonce: "00000000000000000000000000000001".to_owned(),
            intent_kind: IntentKind::SingleCommit,
            task_id: TaskId::parse("task-alpha").unwrap(),
            base_sha: None,
            head_sha: None,
            submitted_claims: vec![],
            justification: None,
            idempotency_key: None,
            approval_token: None,
            approved: None,
            critique: None,
            resolved_via_escalation: None,
            batch_task_ids: None,
            tokens_used: None,
            structured_output: None,
        }
    }

    fn fixture_witness(token: &str) -> WitnessSubmission {
        WitnessSubmission {
            verifier_token: token.to_owned(),
            task_id: TaskId::parse("task-beta").unwrap(),
            gate_type: GateType::parse("TestCoverage").unwrap(),
            evaluation_sha: raxis_types::CommitSha::parse(&"a".repeat(40)).unwrap(),
            result_class: WitnessResultClass::Pass,
            body: serde_json::json!({}),
        }
    }

    fn fixture_escalation_request(token: &str) -> EscalationRequest {
        EscalationRequest {
            session_token: token.to_owned(),
            task_id: TaskId::parse("task-gamma").unwrap(),
            class: EscalationClass::CapabilityUpgrade,
            requested_scope: RequestedEscalationScope::CapabilityUpgrade {
                capability: raxis_types::CapabilityClass::WriteSecrets,
            },
            justification: "needs to write to vault for prod migration".to_owned(),
            idempotency_key: Uuid::nil(),
        }
    }

    // ── intent_request: credential redaction + structure ──────────────

    #[test]
    fn intent_request_line_does_not_contain_session_token() {
        let req = fixture_intent_request(SECRET_SESSION_TOKEN);
        let line = planner_dispatch_log::build_intent_request_line(&req, 0);
        assert!(
            !line.contains(SECRET_SESSION_TOKEN),
            "session_token MUST NOT appear in intent_request log line; got: {line}",
        );
        assert!(
            !line.contains("SECRET_"),
            "no prefix of the secret token may appear; got: {line}",
        );
    }

    #[test]
    fn intent_request_line_carries_correlation_fingerprint_and_context_fields() {
        let req = fixture_intent_request(SECRET_SESSION_TOKEN);
        let line = planner_dispatch_log::build_intent_request_line(&req, 1_700_000_010);
        let v = parse(&line);
        assert_eq!(v["module"], "ipc.planner");
        assert_eq!(v["event"], "intent_request");
        assert_eq!(v["level"], "info");
        assert_eq!(v["task_id"], "task-alpha");
        assert_eq!(v["intent_kind"], "SingleCommit");
        assert_eq!(v["sequence_number"], 7);
        let fp = v["session_token_fp"]
            .as_str()
            .expect("session_token_fp must be string");
        assert_eq!(fp.len(), 8, "fingerprint must be 8 hex chars");
        assert!(
            !SECRET_SESSION_TOKEN.starts_with(fp),
            "fingerprint MUST NOT be a prefix of the raw token",
        );
    }

    // ── intent_response ──────────────────────────────────────────────

    #[test]
    fn intent_response_accepted_at_info_with_budget_snapshot() {
        let resp = IntentResponse {
            sequence_number: 7,
            task_state: TaskState::Running,
            outcome: IntentOutcome::Accepted {
                remaining_budget: BudgetSnapshot {
                    admission_units: 42,
                },
                warn_delegation_stale: true,
            },
        };
        let line = planner_dispatch_log::build_intent_response_line("task-alpha", 7, &resp, 12, 0);
        let v = parse(&line);
        assert_eq!(v["level"], "info");
        assert_eq!(v["status"], "accepted");
        assert_eq!(v["task_id"], "task-alpha");
        assert_eq!(v["sequence_number"], 7);
        assert_eq!(v["latency_ms"], 12);
        assert_eq!(v["task_state"], "Running");
        assert_eq!(v["warn_delegation_stale"], true);
        assert_eq!(v["admission_units_remaining"], 42);
    }

    #[test]
    fn intent_response_rejected_at_warn_with_error_code() {
        let resp = IntentResponse {
            sequence_number: 7,
            task_state: TaskState::Admitted,
            outcome: IntentOutcome::Rejected {
                error_code: PlannerErrorCode::FailPolicyViolation,
                error_detail: Some(PlannerErrorTemplate::IntentKindNotPermitted),
            },
        };
        let line = planner_dispatch_log::build_intent_response_line("task-alpha", 7, &resp, 3, 0);
        let v = parse(&line);
        assert_eq!(v["level"], "warn");
        assert_eq!(v["status"], "rejected");
        let code = v["error_code"].as_str().expect("error_code must be string");
        assert!(code.contains("FailPolicyViolation"), "got: {code}");
    }

    // ── witness_request: credential redaction + structure ─────────────

    #[test]
    fn witness_request_line_does_not_contain_verifier_token() {
        let sub = fixture_witness(SECRET_VERIFIER_TOKEN);
        let line = planner_dispatch_log::build_witness_request_line(&sub, 0);
        assert!(
            !line.contains(SECRET_VERIFIER_TOKEN),
            "verifier_token MUST NOT appear in witness_request log line; got: {line}",
        );
        assert!(
            !line.contains("SECRET_"),
            "no prefix of the secret token may appear"
        );
    }

    #[test]
    fn witness_request_line_carries_correlation_fingerprint_and_context_fields() {
        let sub = fixture_witness(SECRET_VERIFIER_TOKEN);
        let line = planner_dispatch_log::build_witness_request_line(&sub, 0);
        let v = parse(&line);
        assert_eq!(v["module"], "ipc.planner");
        assert_eq!(v["event"], "witness_request");
        assert_eq!(v["task_id"], "task-beta");
        assert_eq!(v["gate_type"], "TestCoverage");
        assert_eq!(v["result_class"], "Pass");
        assert_eq!(v["evaluation_sha"], "a".repeat(40));
        assert_eq!(
            v["verifier_token_fp"].as_str().unwrap().len(),
            8,
            "verifier_token_fp must be an 8-char fingerprint",
        );
    }

    // ── witness_response ─────────────────────────────────────────────

    #[test]
    fn witness_response_rejected_at_warn_with_reason_string() {
        let ack = WitnessAck::Rejected {
            reason: super::handlers::witness::WitnessRejectionReason::TaskNotGatesPending {
                current_state: "Running".to_owned(),
            },
        };
        let line = planner_dispatch_log::build_witness_response_line("task-beta", &ack, 5, 0);
        let v = parse(&line);
        assert_eq!(v["level"], "warn");
        assert_eq!(v["status"], "rejected");
        assert_eq!(v["task_id"], "task-beta");
    }

    // ── escalation_request: credential redaction + structure ──────────

    #[test]
    fn escalation_request_line_does_not_contain_session_token() {
        let req = fixture_escalation_request(SECRET_SESSION_TOKEN);
        let line = planner_dispatch_log::build_escalation_request_line(&req, 0);
        assert!(
            !line.contains(SECRET_SESSION_TOKEN),
            "session_token MUST NOT appear in escalation_request log line; got: {line}",
        );
    }

    #[test]
    fn escalation_request_line_carries_correlation_fingerprint_and_context_fields() {
        let req = fixture_escalation_request(SECRET_SESSION_TOKEN);
        let line = planner_dispatch_log::build_escalation_request_line(&req, 0);
        let v = parse(&line);
        assert_eq!(v["module"], "ipc.planner");
        assert_eq!(v["event"], "escalation_request");
        assert_eq!(v["task_id"], "task-gamma");
        assert_eq!(v["class"], "CapabilityUpgrade");
        assert_eq!(v["session_token_fp"].as_str().unwrap().len(), 8);
    }

    // ── escalation_response ───────────────────────────────────────────

    #[test]
    fn escalation_response_submitted_carries_escalation_id() {
        let resp = EscalationResponse::Submitted {
            escalation_id: EscalationId::new_v4(),
            timeout_at: raxis_types::id::UnixSeconds(1_700_001_000),
        };
        let line = planner_dispatch_log::build_escalation_response_line("task-gamma", &resp, 4, 0);
        let v = parse(&line);
        assert_eq!(v["status"], "submitted");
        assert!(v["escalation_id"].is_string());
    }

    #[test]
    fn escalation_response_rejected_at_warn_with_reason() {
        let resp = EscalationResponse::Rejected {
            reason: EscalationRejectionReason::LineageQuarantined,
        };
        let line = planner_dispatch_log::build_escalation_response_line("task-gamma", &resp, 4, 0);
        let v = parse(&line);
        assert_eq!(v["level"], "warn");
        assert_eq!(v["status"], "rejected");
    }

    // ── ipc_message_variant_name covers every IpcMessage variant ──────

    #[test]
    fn ipc_message_variant_name_covers_every_planner_socket_variant() {
        // We instantiate one of each variant and check the helper
        // returns a stable tag. New IpcMessage variants will fail the
        // exhaustive match in `ipc_message_variant_name` at compile
        // time; this test pins the strings.
        let intent = IpcMessage::IntentRequest(fixture_intent_request("x"));
        assert_eq!(
            planner_dispatch_log::ipc_message_variant_name(&intent),
            "IntentRequest"
        );

        let escalation = IpcMessage::EscalationRequest(fixture_escalation_request("x"));
        assert_eq!(
            planner_dispatch_log::ipc_message_variant_name(&escalation),
            "EscalationRequest"
        );

        let witness = IpcMessage::WitnessSubmission(fixture_witness("x"));
        assert_eq!(
            planner_dispatch_log::ipc_message_variant_name(&witness),
            "WitnessSubmission"
        );

        let ack = IpcMessage::WitnessAck {
            verifier_run_id: Uuid::nil(),
            accepted: true,
            reason: None,
        };
        assert_eq!(
            planner_dispatch_log::ipc_message_variant_name(&ack),
            "WitnessAck"
        );
    }

    /// **Regression**: the dispatcher's `planner_unexpected_message`
    /// log emits the variant name, NOT the variant payload. If a
    /// malformed planner ever sends a `WitnessSubmission` with a
    /// secret in its `verifier_token` on the wrong socket, the log
    /// line about it landing on the wrong variant arm must still not
    /// echo the token.
    #[test]
    fn planner_unexpected_message_line_carries_variant_only_no_payload() {
        let line =
            planner_dispatch_log::build_planner_unexpected_message_line("WitnessSubmission", 0);
        let v = parse(&line);
        assert_eq!(v["event"], "planner_unexpected_message");
        assert_eq!(v["variant"], "WitnessSubmission");
        // No SECRET_ token should appear in this line — there is no
        // payload reference, only the variant tag.
        assert!(!line.contains("SECRET_"));
    }
}
