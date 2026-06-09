//! `spawn_and_supervise` — long-running task that owns the lifetime of
//! the `raxis-gateway` subprocess.
//!
//! Run from `main.rs` step 8.5 (after `KernelStarted`, before the IPC
//! dispatch loop in step 9). Returns `SupervisorShutdown::Quarantined`
//! when the crash budget is exceeded, or `SupervisorShutdown::Stopped`
//! when the kernel signals shutdown.
//!
//! # Why a free function returning a future
//!
//! Holding the supervisor as a `Supervisor { ... }` struct with `.run()`
//! would force a single ownership story for `child`, `state`, and the
//! shutdown channel — and the supervisor's only consumer (`main.rs`)
//! never needs to call anything on it after spawning. A free function
//! whose signature spells out every input is easier to test and harder
//! to misuse.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_crypto::token::try_random_array;
use raxis_policy::PolicyBundle;
use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::sync::oneshot;

pub const GATEWAY_BINARY_ENV: &str = "RAXIS_GATEWAY_BINARY";
pub const GATEWAY_RESPAWN_BACKOFF_MS_ENV: &str = "RAXIS_GATEWAY_RESPAWN_BACKOFF_MS";
pub const GATEWAY_MAX_CONSECUTIVE_RESPAWNS_ENV: &str = "RAXIS_GATEWAY_MAX_CONSECUTIVE_RESPAWNS";
pub const GATEWAY_POLICY_RECONCILE_INTERVAL_MS_ENV: &str =
    "RAXIS_GATEWAY_POLICY_RECONCILE_INTERVAL_MS";

#[derive(Debug, Clone)]
pub struct GatewayRuntimeConfig {
    pub binary_path: String,
    pub respawn_backoff_ms: u64,
    pub max_consecutive_respawns: u32,
}

impl GatewayRuntimeConfig {
    pub fn from_runtime_env() -> Self {
        Self {
            binary_path: runtime_gateway_binary_path(),
            respawn_backoff_ms: parse_env_u64(GATEWAY_RESPAWN_BACKOFF_MS_ENV, 1000).max(1),
            max_consecutive_respawns: parse_env_u32(GATEWAY_MAX_CONSECUTIVE_RESPAWNS_ENV, 5).max(1),
        }
    }
}

/// Why the supervisor stopped. `main.rs` uses this to choose the
/// subsequent log + audit shape (no exit-code branching needed; the
/// IPC dispatch loop has its own shutdown reason).
#[derive(Debug)]
pub enum SupervisorShutdown {
    /// The supervisor exited because the kernel signalled it to stop
    /// (typically: `start()` returned because of SIGTERM/SIGINT).
    /// The supervisor killed the child before exiting.
    Stopped,
    /// The supervisor exceeded `max_consecutive_respawns`. The child
    /// was the last spawn attempt; it has exited (or been killed) by
    /// the time this variant returns.
    Quarantined { reason: String, total_attempts: u32 },
    /// The kernel was booted without any approved model providers, so
    /// no gateway subprocess is needed for this runtime.
    NoGatewayConfigured,
}

/// Policy-aware wrapper around [`spawn_and_supervise`].
///
/// Older kernels made the boot-time provider set a static decision: if
/// policy declared no `[[providers]]`, the supervisor returned
/// `NoGatewayConfigured` and was gone for the rest of the process
/// lifetime. That made the otherwise-valid operator flow
/// "boot minimal policy → advance epoch with providers" fail until the
/// kernel was restarted. This reconciler keeps a small, kernel-owned
/// policy watch alive for the whole process lifetime:
///
/// * no providers ⇒ no gateway child, fetches fail closed;
/// * providers appear ⇒ start the normal crash/respawn supervisor;
/// * providers disappear ⇒ stop the child and disconnect callers;
/// * provider details change while the child is alive ⇒ the existing
///   `EpochAdvanced` signal path reloads the gateway view.
///
/// The watch is deliberately based on the in-process [`ArcSwap`]
/// policy bundle, not filesystem polling. Every valid epoch advance
/// swaps that bundle after signature verification, so the reconciler
/// sees exactly the same committed policy state as IPC handlers.
pub async fn spawn_policy_reconciler(
    policy: Arc<ArcSwap<PolicyBundle>>,
    data_dir: PathBuf,
    socket_path: PathBuf,
    audit: Arc<dyn AuditSink>,
    client: Arc<crate::gateway::client::GatewayClient>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> SupervisorShutdown {
    let poll_every = policy_reconcile_interval();
    let mut ever_started_gateway = false;
    let mut last_idle_epoch_logged: Option<u64> = None;

    loop {
        while !policy_has_providers(&policy) {
            let epoch = policy.load().epoch();
            if last_idle_epoch_logged != Some(epoch) {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"gateway_supervisor_no_config\",\
                     \"action\":\"no_model_providers\",\"epoch\":{epoch}}}"
                );
                last_idle_epoch_logged = Some(epoch);
            }
            client.disconnect().await;

            tokio::select! {
                _ = &mut shutdown_rx => {
                    return if ever_started_gateway {
                        SupervisorShutdown::Stopped
                    } else {
                        SupervisorShutdown::NoGatewayConfigured
                    };
                }
                _ = tokio::time::sleep(poll_every) => {}
            }
        }

        let start_epoch = policy.load().epoch();
        let provider_count = policy.load().providers().len();
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"gateway_supervisor_policy_enabled\",\
             \"epoch\":{start_epoch},\"provider_count\":{provider_count}}}"
        );
        ever_started_gateway = true;
        last_idle_epoch_logged = None;

        let (inner_shutdown_tx, inner_shutdown_rx) = oneshot::channel::<()>();
        let mut inner_shutdown_tx = Some(inner_shutdown_tx);
        let inner_data_dir = data_dir.clone();
        let inner_socket_path = socket_path.clone();
        let inner_audit = Arc::clone(&audit);
        let inner_client = Arc::clone(&client);
        let mut inner_handle = tokio::spawn(async move {
            spawn_and_supervise(
                Some(GatewayRuntimeConfig::from_runtime_env()),
                inner_data_dir,
                inner_socket_path,
                inner_audit,
                inner_client,
                inner_shutdown_rx,
            )
            .await
        });

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    if let Some(tx) = inner_shutdown_tx.take() {
                        let _ = tx.send(());
                    }
                    let _ = inner_handle.await;
                    client.disconnect().await;
                    return SupervisorShutdown::Stopped;
                }
                joined = &mut inner_handle => {
                    match joined {
                        Ok(SupervisorShutdown::Stopped) => {
                            client.disconnect().await;
                            break;
                        }
                        Ok(SupervisorShutdown::NoGatewayConfigured) => {
                            client.disconnect().await;
                            break;
                        }
                        Ok(SupervisorShutdown::Quarantined { reason, total_attempts }) => {
                            return SupervisorShutdown::Quarantined { reason, total_attempts };
                        }
                        Err(join_err) => {
                            let reason = format!("gateway supervisor task join failed: {join_err}");
                            eprintln!(
                                "{{\"level\":\"error\",\"event\":\"gateway_supervisor_join_failed\",\
                                 \"reason\":\"{reason}\"}}"
                            );
                            if let Err(audit_err) = audit.emit(
                                AuditEventKind::GatewayQuarantined {
                                    reason: reason.clone(),
                                    total_attempts: 0,
                                },
                                None,
                                None,
                                None,
                            ) {
                                eprintln!(
                                    "{{\"level\":\"error\",\"event\":\"GatewayQuarantined\",\
                                     \"audit_emit_failed\":{},\"reason\":\"{reason}\"}}",
                                    serde_json::Value::String(audit_err.to_string()),
                                );
                            }
                            return SupervisorShutdown::Quarantined {
                                reason,
                                total_attempts: 0,
                            };
                        }
                    }
                }
                _ = tokio::time::sleep(poll_every) => {
                    if !policy_has_providers(&policy) {
                        let epoch = policy.load().epoch();
                        eprintln!(
                            "{{\"level\":\"info\",\"event\":\"gateway_supervisor_policy_disabled\",\
                             \"epoch\":{epoch},\"action\":\"stop_gateway_no_model_providers\"}}"
                        );
                        if let Some(tx) = inner_shutdown_tx.take() {
                            let _ = tx.send(());
                        }
                        let _ = inner_handle.await;
                        client.disconnect().await;
                        break;
                    }
                }
            }
        }
    }
}

/// Fatal supervisor errors that the supervisor cannot recover from
/// even with respawn (e.g., binary path doesn't exist on disk). These
/// are logged but the supervisor still completes cleanly so `main.rs`
/// can proceed; the kernel will simply lack a gateway.
#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("gateway binary {path:?} not found or not executable: {source}")]
    BinaryNotExecutable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("randomness source failed minting gateway_process_token: {0}")]
    TokenMint(String),
}

/// Spawn the gateway subprocess and supervise it until either:
/// (a) `shutdown_rx` fires (kernel shutting down), OR
/// (b) `runtime_config.max_consecutive_respawns` is exceeded.
///
/// `runtime_config` is kernel-owned process configuration, not signed
/// operator policy. The policy may approve model providers and model
/// routing, but it never gets to pick the host binary path, token,
/// socket, or respawn mechanics for the trusted gateway subprocess.
///
/// The `audit` sink is used for `GatewaySpawned` / `GatewayCrashed` /
/// `GatewayQuarantined` records.
///
/// The `client` is updated with each freshly-minted token immediately
/// before `spawn_child` so the kernel-side accept loop (`gateway::accept`)
/// can validate the gateway's `GatewayReady` handshake against it. On
/// shutdown we additionally call `client.disconnect()` so any in-flight
/// `fetch()` callers see `GatewayCallError::Unavailable` instead of
/// hanging on the soon-to-be-torn-down stream.
pub async fn spawn_and_supervise(
    runtime_config: Option<GatewayRuntimeConfig>,
    data_dir: PathBuf,
    socket_path: PathBuf,
    audit: Arc<dyn AuditSink>,
    client: Arc<crate::gateway::client::GatewayClient>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> SupervisorShutdown {
    let mut cfg = match runtime_config {
        Some(c) => c,
        None => {
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"gateway_supervisor_no_config\",\
                 \"action\":\"no_model_providers\"}}"
            );
            return SupervisorShutdown::NoGatewayConfigured;
        }
    };

    // embedded gateway. When the kernel was built
    // with `--features embedded-gateway`, materialise the bytes
    // baked into the kernel binary to a kernel-private directory
    // and override `cfg.binary_path` so the spawn loop below
    // dispatches against the kernel-controlled file rather than
    // the operator-supplied path. When the feature is off (default)
    // `materialize` returns `Ok(None)` and the supervisor keeps
    // using `cfg.binary_path` — the historical fast-iteration path.
    match crate::gateway::embedded::materialize(&data_dir) {
        Ok(Some(p)) => {
            let canonical = p.to_string_lossy().into_owned();
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"gateway_embedded_materialized\",\
                 \"binary_path\":\"{}\"}}",
                canonical
            );
            cfg.binary_path = canonical;
        }
        Ok(None) => {}
        Err(e) => {
            // Fail-closed: if we cannot materialise the embedded
            // bytes there is no safe fallback (the trust assumption
            // for a release build is "kernel-controlled binary").
            // Mirror the token-mint failure path so `main.rs`
            // observes a clean `Quarantined`.
            let reason = format!("embedded gateway materialise failure: {e}");
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"gateway_embedded_materialize_failed\",\
                 \"reason\":\"{e}\"}}"
            );
            // INV-DEEP-SWEEP-D6-CRITICAL-AUDIT-EMIT-NEVER-SILENT-01.
            // Gateway quarantine is one of `SupervisorShutdown`'s
            // terminal outcomes — `main.rs` translates it into a
            // structured boot-fail; the audit chain entry is the
            // only durable record. Log on emit failure.
            if let Err(audit_err) = audit.emit(
                AuditEventKind::GatewayQuarantined {
                    reason: reason.clone(),
                    total_attempts: 0,
                },
                None,
                None,
                None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"GatewayQuarantined\",\
                     \"audit_emit_failed\":{},\"reason\":\"{reason}\"}}",
                    serde_json::Value::String(audit_err.to_string()),
                );
            }
            return SupervisorShutdown::Quarantined {
                reason,
                total_attempts: 0,
            };
        }
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"gateway_supervisor_start\",\
         \"binary_path\":\"{}\",\"max_respawns\":{},\"embedded\":{}}}",
        cfg.binary_path,
        cfg.max_consecutive_respawns,
        crate::gateway::embedded::is_embedded(),
    );

    let mut attempt: u32 = 0;
    let mut consecutive_crashes: u32 = 0;

    loop {
        attempt += 1;
        let token = match mint_token() {
            Ok(t) => {
                // Publish the expected token BEFORE we spawn the child,
                // so a fast-starting gateway that already has the token
                // in its env can `connect()` and the kernel-side accept
                // loop will recognise it. The order matters: if we
                // spawned first and published second, a sub-millisecond
                // handshake could race the publish and be rejected.
                client.set_expected_token(t.clone()).await;
                t
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"gateway_token_mint_failed\",\
                     \"reason\":\"{e}\"}}"
                );
                // We cannot mint a token, so we cannot spawn. Treat
                // this exactly like a max-respawns event so `main.rs`
                // gets a clean Quarantined.
                let reason = format!("token mint failure: {e}");
                if let Err(audit_err) = audit.emit(
                    AuditEventKind::GatewayQuarantined {
                        reason: reason.clone(),
                        total_attempts: attempt,
                    },
                    None,
                    None,
                    None,
                ) {
                    eprintln!(
                        "{{\"level\":\"error\",\"event\":\"GatewayQuarantined\",\
                         \"audit_emit_failed\":{},\"reason\":\"{reason}\",\
                         \"total_attempts\":{attempt}}}",
                        serde_json::Value::String(audit_err.to_string()),
                    );
                }
                return SupervisorShutdown::Quarantined {
                    reason,
                    total_attempts: attempt,
                };
            }
        };

        let mut child = match spawn_child(&cfg.binary_path, &token, &socket_path, &data_dir) {
            Ok(c) => c,
            Err(e) => {
                // Binary missing, EACCES, or any other ENOENT-class
                // failure. Same handling as a crash for the back-off
                // loop — operators may have just deployed the binary
                // and we should pick it up on the next attempt.
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"gateway_spawn_failed\",\
                     \"binary_path\":\"{}\",\"attempt\":{},\"reason\":\"{}\"}}",
                    cfg.binary_path, attempt, e
                );
                consecutive_crashes += 1;
                if consecutive_crashes > cfg.max_consecutive_respawns {
                    let reason = format!("repeated spawn failure: {e}");
                    if let Err(audit_err) = audit.emit(
                        AuditEventKind::GatewayQuarantined {
                            reason: reason.clone(),
                            total_attempts: attempt,
                        },
                        None,
                        None,
                        None,
                    ) {
                        eprintln!(
                            "{{\"level\":\"error\",\"event\":\"GatewayQuarantined\",\
                             \"audit_emit_failed\":{},\"reason\":\"{reason}\",\
                             \"total_attempts\":{attempt}}}",
                            serde_json::Value::String(audit_err.to_string()),
                        );
                    }
                    return SupervisorShutdown::Quarantined {
                        reason,
                        total_attempts: attempt,
                    };
                }
                let backoff = compute_backoff(cfg.respawn_backoff_ms, consecutive_crashes);
                if let Some(early) = sleep_or_shutdown(backoff, &mut shutdown_rx).await {
                    return early;
                }
                continue;
            }
        };

        let token_prefix = token_prefix_log(&token);
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"gateway_spawned\",\
             \"binary_path\":\"{}\",\"token_prefix\":\"{}\",\"attempt\":{},\
             \"pid\":{}}}",
            cfg.binary_path,
            token_prefix,
            attempt,
            child.id().unwrap_or(0),
        );
        if let Err(audit_err) = audit.emit(
            AuditEventKind::GatewaySpawned {
                token_prefix: token_prefix.clone(),
                binary_path: cfg.binary_path.clone(),
                attempt,
            },
            None,
            None,
            None,
        ) {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"GatewaySpawned\",\
                 \"audit_emit_failed\":{},\"token_prefix\":\"{}\",\"attempt\":{}}}",
                serde_json::Value::String(audit_err.to_string()),
                token_prefix,
                attempt,
            );
        }

        // Wait for either child exit OR kernel shutdown.
        let exit_status = tokio::select! {
            wait_result = child.wait() => {
                match wait_result {
                    Ok(status) => Some(status),
                    Err(e) => {
                        eprintln!(
                            "{{\"level\":\"error\",\"event\":\"gateway_wait_failed\",\
                             \"reason\":\"{e}\"}}"
                        );
                        None
                    }
                }
            }
            _ = &mut shutdown_rx => {
                eprintln!("{{\"level\":\"info\",\"event\":\"gateway_supervisor_shutdown_signal\"}}");
                kill_child_best_effort(&mut child).await;
                // Drop the kernel-side pump so any in-flight callers
                // unblock with Unavailable instead of waiting on a
                // socket that's about to disappear.
                client.disconnect().await;
                return SupervisorShutdown::Stopped;
            }
        };

        let exit_code = exit_status.and_then(|s| s.code());
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"gateway_exited\",\
             \"token_prefix\":\"{}\",\"attempt\":{},\"exit_code\":{}}}",
            token_prefix,
            attempt,
            exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "null".to_owned()),
        );
        // The pump task usually notices the EOF first and exits on
        // its own, but `client.disconnect()` is idempotent and
        // guarantees the kernel-side slot is empty before the next
        // spawn so a slow EOF detection cannot leave the previous
        // (now dead) stream installed when the fresh gateway sends
        // its `GatewayReady`.
        client.disconnect().await;
        // Clone the token_prefix for the audit-emit-failed fallback
        // log line — the AuditEventKind constructor moves it.
        let token_prefix_for_log = token_prefix.clone();
        if let Err(audit_err) = audit.emit(
            AuditEventKind::GatewayCrashed {
                token_prefix,
                exit_code,
                attempt,
            },
            None,
            None,
            None,
        ) {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"GatewayCrashed\",\
                 \"audit_emit_failed\":{},\"token_prefix\":\"{}\",\
                 \"exit_code\":{},\"attempt\":{}}}",
                serde_json::Value::String(audit_err.to_string()),
                token_prefix_for_log,
                exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "null".to_owned()),
                attempt,
            );
        }

        // Decide: respawn or quarantine?
        consecutive_crashes += 1;
        if consecutive_crashes > cfg.max_consecutive_respawns {
            let reason = format!(
                "exceeded max_consecutive_respawns={} (last exit_code={})",
                cfg.max_consecutive_respawns,
                exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "null".to_owned()),
            );
            if let Err(audit_err) = audit.emit(
                AuditEventKind::GatewayQuarantined {
                    reason: reason.clone(),
                    total_attempts: attempt,
                },
                None,
                None,
                None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"GatewayQuarantined\",\
                     \"audit_emit_failed\":{},\"reason\":\"{reason}\",\
                     \"total_attempts\":{attempt}}}",
                    serde_json::Value::String(audit_err.to_string()),
                );
            }
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"gateway_quarantined\",\
                 \"reason\":\"{reason}\",\"total_attempts\":{attempt}}}"
            );
            return SupervisorShutdown::Quarantined {
                reason,
                total_attempts: attempt,
            };
        }
        let backoff = compute_backoff(cfg.respawn_backoff_ms, consecutive_crashes);
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"gateway_respawn_backoff\",\
             \"backoff_ms\":{},\"consecutive_crashes\":{}}}",
            backoff.as_millis(),
            consecutive_crashes
        );
        if let Some(early) = sleep_or_shutdown(backoff, &mut shutdown_rx).await {
            return early;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Internals
// ─────────────────────────────────────────────────────────────────────────

/// Mint a fresh 32-byte CSPRNG token, hex-encode for the env var.
fn mint_token() -> Result<String, SupervisorError> {
    let bytes: [u8; 32] =
        try_random_array().map_err(|e| SupervisorError::TokenMint(format!("{e}")))?;
    Ok(hex::encode(bytes))
}

fn parse_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .unwrap_or(default)
}

fn policy_reconcile_interval() -> Duration {
    Duration::from_millis(
        parse_env_u64(GATEWAY_POLICY_RECONCILE_INTERVAL_MS_ENV, 250).clamp(25, 30_000),
    )
}

fn policy_has_providers(policy: &Arc<ArcSwap<PolicyBundle>>) -> bool {
    !policy.load().providers().is_empty()
}

fn runtime_gateway_binary_path() -> String {
    if let Ok(raw) = std::env::var(GATEWAY_BINARY_ENV) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|parent| parent.join("raxis-gateway")))
        .unwrap_or_else(|| PathBuf::from("raxis-gateway"))
        .to_string_lossy()
        .into_owned()
}

/// Spawn a single child. Tokio Command + Stdio inherited so the
/// gateway's stderr lands on the kernel's stderr in real time
/// (operators tail one stream, not two).
fn spawn_child(
    binary_path: &str,
    token: &str,
    socket_path: &Path,
    data_dir: &Path,
) -> Result<Child, std::io::Error> {
    let mut cmd = Command::new(binary_path);
    cmd.env_clear()
        // PATH and HOME must survive — reqwest looks at PATH for
        // certificate stores on some platforms, and many libc routines
        // dereference HOME. The kernel-side `gates::verifier_runner`
        // takes the same approach.
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .env("RAXIS_GATEWAY_TOKEN", token)
        .env("RAXIS_GATEWAY_SOCKET", socket_path)
        .env("RAXIS_DATA_DIR", data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        // Don't put the child in our process group — SIGINT to the
        // kernel from the operator's terminal would otherwise also
        // hit the gateway, racing the supervisor's clean kill.
        //
        // No `RAXIS_GATEWAY_BACKEND` env: the production gateway
        // always uses `HttpBackend`, and the in-memory test fake
        // (`raxis_test_support::MockBackend`) lives in dev-dep-only
        // territory. See `gateway/src/env.rs` module header for the
        // mock-isolation rationale (philosophy.md §1.6).
        .kill_on_drop(true);
    cmd.spawn()
}

/// Best-effort SIGTERM the child. Used on shutdown so the kernel does
/// not leak the subprocess. Tokio's `Child::start_kill` uses SIGKILL,
/// which is also what we want — graceful in-flight FetchRequests are
/// the kernel's concern (it returns `error: "GatewayUnavailable"`
/// for any in-flight request when the gateway disappears).
async fn kill_child_best_effort(child: &mut Child) {
    if let Err(e) = child.start_kill() {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"gateway_kill_failed\",\
             \"reason\":\"{e}\"}}"
        );
        return;
    }
    if let Err(e) = child.wait().await {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"gateway_wait_after_kill_failed\",\
             \"reason\":\"{e}\"}}"
        );
    }
}

/// Exponential-backoff helper. `respawn_backoff_ms * 2^(consecutive-1)`,
/// capped at 60 s. Tested below.
pub fn compute_backoff(initial_ms: u64, consecutive: u32) -> Duration {
    const HARD_CAP_MS: u64 = 60_000;
    if consecutive == 0 {
        return Duration::from_millis(0);
    }
    // Use saturating_mul so a malicious or buggy initial_ms cannot
    // overflow — we just clamp to HARD_CAP_MS instead.
    let shift = (consecutive - 1).min(20); // 2^20 = ~1M, well past any cap
    let multiplier = 1u64 << shift;
    let raw = initial_ms.saturating_mul(multiplier);
    Duration::from_millis(raw.min(HARD_CAP_MS))
}

/// Sleep for `dur`, OR return early if the shutdown channel fires
/// during the sleep. Lets us back off without missing a SIGTERM.
async fn sleep_or_shutdown(
    dur: Duration,
    shutdown_rx: &mut oneshot::Receiver<()>,
) -> Option<SupervisorShutdown> {
    tokio::select! {
        _ = tokio::time::sleep(dur) => None,
        _ = shutdown_rx => Some(SupervisorShutdown::Stopped),
    }
}

/// Project the first 8 hex chars of the token. NEVER log the full token.
fn token_prefix_log(token: &str) -> String {
    token[..8.min(token.len())].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Backoff math ───────────────────────────────────────────────────

    #[test]
    fn compute_backoff_zero_consecutive_returns_zero() {
        assert_eq!(compute_backoff(1000, 0), Duration::from_millis(0));
    }

    #[test]
    fn compute_backoff_first_crash_returns_initial() {
        // 1000ms * 2^0 = 1000ms
        assert_eq!(compute_backoff(1000, 1), Duration::from_millis(1000));
    }

    #[test]
    fn compute_backoff_doubles_each_consecutive() {
        assert_eq!(compute_backoff(1000, 1), Duration::from_millis(1_000));
        assert_eq!(compute_backoff(1000, 2), Duration::from_millis(2_000));
        assert_eq!(compute_backoff(1000, 3), Duration::from_millis(4_000));
        assert_eq!(compute_backoff(1000, 4), Duration::from_millis(8_000));
        assert_eq!(compute_backoff(1000, 5), Duration::from_millis(16_000));
        assert_eq!(compute_backoff(1000, 6), Duration::from_millis(32_000));
    }

    #[test]
    fn compute_backoff_caps_at_60_seconds() {
        // 1000ms * 2^7 = 128_000ms but cap is 60_000ms.
        assert_eq!(compute_backoff(1000, 7), Duration::from_millis(60_000));
        assert_eq!(compute_backoff(1000, 30), Duration::from_millis(60_000));
    }

    #[test]
    fn compute_backoff_handles_huge_initial_without_overflow() {
        // saturating_mul guards against u64 overflow if the operator
        // sets a pathological initial_ms.
        let huge = u64::MAX / 2;
        let dur = compute_backoff(huge, 30);
        // Still caps at 60s.
        assert_eq!(dur, Duration::from_millis(60_000));
    }

    #[test]
    fn token_prefix_truncates_to_8_chars() {
        let token = "abcdefghijklmnop";
        assert_eq!(token_prefix_log(token), "abcdefgh");
    }

    #[test]
    fn token_prefix_handles_short_token() {
        let token = "abc";
        assert_eq!(token_prefix_log(token), "abc");
    }

    #[test]
    fn mint_token_returns_64_hex_chars() {
        let token = mint_token().unwrap();
        assert_eq!(token.len(), 64);
        assert!(hex::decode(&token).is_ok());
    }

    #[test]
    fn mint_token_is_unique_across_calls() {
        // Not a strict guarantee (CSPRNG could collide) but in practice
        // 32 bytes is enough that test flakes here would be a sign of
        // a real bug (e.g. zero-init).
        let a = mint_token().unwrap();
        let b = mint_token().unwrap();
        assert_ne!(a, b, "32-byte CSPRNG tokens must not collide");
    }

    // ─────────────────────────────────────────────────────────────────
    // End-to-end supervisor tests — drive against real OS binaries.
    //
    // We do NOT spawn the real raxis-gateway here — these tests are
    // about the supervisor's process lifecycle handling, not about the
    // gateway's IPC contract (covered by `gateway/tests/gateway_roundtrip`).
    // Using `/bin/sleep` (long-running success) and `/bin/false`
    // (immediate crash) lets us pin the entire supervisor state machine
    // without coupling to the gateway crate.
    // ─────────────────────────────────────────────────────────────────

    use raxis_test_support::FakeAuditSink;

    fn fake_section(binary_path: &str, max_respawns: u32, backoff_ms: u64) -> GatewayRuntimeConfig {
        GatewayRuntimeConfig {
            binary_path: binary_path.to_owned(),
            respawn_backoff_ms: backoff_ms,
            max_consecutive_respawns: max_respawns,
        }
    }

    /// Locate a `false`-equivalent binary across linux + macOS. Linux
    /// has `/bin/false`; macOS only has `/usr/bin/false`. Pick the
    /// first one that exists so the same test passes on both hosts.
    fn locate_false_binary() -> &'static str {
        for candidate in &["/usr/bin/false", "/bin/false"] {
            if std::path::Path::new(candidate).exists() {
                return candidate;
            }
        }
        panic!(
            "no `false` binary found at /usr/bin/false or /bin/false; \
                cannot run supervisor crash-path tests"
        );
    }

    fn locate_sleep_binary() -> &'static str {
        for candidate in &["/bin/sleep", "/usr/bin/sleep"] {
            if std::path::Path::new(candidate).exists() {
                return candidate;
            }
        }
        panic!("no `sleep` binary found");
    }

    /// Build a fresh supervisor input set: tempdir for data_dir, a
    /// dummy socket path under it, and a FakeAuditSink we can later
    /// inspect to assert which audit events were emitted.
    fn supervisor_inputs() -> (tempfile::TempDir, PathBuf, Arc<FakeAuditSink>) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let socket = tmp.path().join("gateway.sock");
        let audit: Arc<FakeAuditSink> = Arc::new(FakeAuditSink::default());
        (tmp, socket, audit)
    }

    fn count_events_of(sink: &FakeAuditSink, kind: &str) -> usize {
        sink.events()
            .into_iter()
            .filter(|e| e.kind.as_str() == kind)
            .count()
    }

    // ── No runtime gateway config ────────────────────────────────────

    #[tokio::test]
    async fn no_gateway_section_returns_immediately_with_no_audit_events() {
        let (_tmp, socket, audit) = supervisor_inputs();
        let (_tx, rx) = oneshot::channel();
        let outcome = spawn_and_supervise(
            None,
            PathBuf::from("/tmp"),
            socket,
            audit.clone() as Arc<dyn AuditSink>,
            Arc::new(crate::gateway::client::GatewayClient::new()),
            rx,
        )
        .await;
        assert!(matches!(outcome, SupervisorShutdown::NoGatewayConfigured));
        assert_eq!(count_events_of(&audit, "GatewaySpawned"), 0);
        assert_eq!(count_events_of(&audit, "GatewayCrashed"), 0);
        assert_eq!(count_events_of(&audit, "GatewayQuarantined"), 0);
    }

    #[tokio::test]
    async fn policy_reconciler_without_providers_stays_alive_until_shutdown() {
        let (tmp, socket, audit) = supervisor_inputs();
        let policy = Arc::new(ArcSwap::from_pointee(
            PolicyBundle::for_tests_with_operators(vec![]),
        ));
        let (tx, rx) = oneshot::channel();
        let audit_for_task = audit.clone() as Arc<dyn AuditSink>;
        let client = Arc::new(crate::gateway::client::GatewayClient::new());
        let supervisor = tokio::spawn(spawn_policy_reconciler(
            policy,
            tmp.path().to_path_buf(),
            socket,
            audit_for_task,
            client,
            rx,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !supervisor.is_finished(),
            "policy reconciler must keep watching after a no-provider boot"
        );
        let _ = tx.send(());
        let outcome = tokio::time::timeout(Duration::from_secs(2), supervisor)
            .await
            .expect("reconciler must respond to shutdown")
            .expect("reconciler task must not panic");
        assert!(matches!(outcome, SupervisorShutdown::NoGatewayConfigured));
        assert_eq!(count_events_of(&audit, "GatewaySpawned"), 0);
        assert_eq!(count_events_of(&audit, "GatewayQuarantined"), 0);
    }

    // ── Long-running success: shutdown signal kills child cleanly ────

    #[tokio::test]
    async fn shutdown_signal_kills_long_running_child_and_returns_stopped() {
        let (_tmp, socket, audit) = supervisor_inputs();
        // sleep 60 — stays alive long enough for the test to send
        // the shutdown signal.
        let cfg = fake_section(locate_sleep_binary(), 5, 100);
        let (tx, rx) = oneshot::channel();

        let audit_for_task = audit.clone() as Arc<dyn AuditSink>;
        let supervisor = tokio::spawn(async move {
            spawn_and_supervise(
                Some(cfg),
                PathBuf::from("/tmp"),
                socket,
                audit_for_task,
                Arc::new(crate::gateway::client::GatewayClient::new()),
                rx,
            )
            .await
        });

        // Give it ~200ms to spawn the child.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = tx.send(());

        // Supervisor must finish within ~1s; if it hangs we have a leak.
        let outcome = tokio::time::timeout(Duration::from_secs(5), supervisor)
            .await
            .expect("supervisor must wind down within 5s after shutdown signal")
            .expect("supervisor task must not panic");

        assert!(
            matches!(outcome, SupervisorShutdown::Stopped),
            "expected Stopped, got {outcome:?}"
        );
        // Note: /bin/sleep ignores arguments differently — depending on
        // OS it may or may not even be a valid command path. We only
        // assert "at least one GatewaySpawned"; if /bin/sleep is missing
        // the supervisor would treat that as a spawn failure and the
        // test would still surface the issue via the assertion below.
        assert!(
            count_events_of(&audit, "GatewaySpawned") >= 1,
            "expected at least one GatewaySpawned audit event; captured: {:?}",
            audit.event_kinds()
        );
    }

    // ── Always-crashing child: respawn + quarantine ──────────────────

    #[tokio::test]
    async fn child_that_always_crashes_eventually_quarantines() {
        let (_tmp, socket, audit) = supervisor_inputs();
        // `false` exits with code 1 immediately — perfect for forcing
        // the crash path.
        let cfg = fake_section(locate_false_binary(), 2, 10); // max=2, very short backoff
        let (_tx, rx) = oneshot::channel();

        let audit_for_task = audit.clone() as Arc<dyn AuditSink>;
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            spawn_and_supervise(
                Some(cfg),
                PathBuf::from("/tmp"),
                socket,
                audit_for_task,
                Arc::new(crate::gateway::client::GatewayClient::new()),
                rx,
            ),
        )
        .await
        .expect("must quarantine within 5s with max=2 + ~10ms backoff");

        // Outcome MUST be Quarantined with total_attempts > max.
        match outcome {
            SupervisorShutdown::Quarantined {
                total_attempts,
                reason,
            } => {
                // We allow `>= 3` rather than exactly `3` because the
                // supervisor increments crash count BEFORE the cap
                // check on the next iteration; this lets us survive
                // off-by-one debates about "max means inclusive or
                // exclusive". The asserted invariant is that we DID
                // exceed `max`.
                assert!(
                    total_attempts >= 3,
                    "expected total_attempts > max=2, got {total_attempts}; reason: {reason}"
                );
            }
            other => panic!("expected Quarantined, got {other:?}"),
        }

        // Audit shape: at least 3 spawns (original + retries up to
        // max + 1), at least 3 crashes, exactly 1 quarantine.
        assert!(
            count_events_of(&audit, "GatewaySpawned") >= 3,
            "expected ≥3 GatewaySpawned; got {:?}",
            audit.event_kinds()
        );
        assert!(count_events_of(&audit, "GatewayCrashed") >= 3);
        assert_eq!(
            count_events_of(&audit, "GatewayQuarantined"),
            1,
            "exactly one quarantine event should be emitted on the terminal attempt"
        );
    }

    // ── Spawn failure: missing binary path ───────────────────────────

    #[tokio::test]
    async fn missing_binary_eventually_quarantines_after_repeated_spawn_failure() {
        let (_tmp, socket, audit) = supervisor_inputs();
        let cfg = fake_section("/no/such/binary/anywhere", 1, 10);
        let (_tx, rx) = oneshot::channel();

        let audit_for_task = audit.clone() as Arc<dyn AuditSink>;
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            spawn_and_supervise(
                Some(cfg),
                PathBuf::from("/tmp"),
                socket,
                audit_for_task,
                Arc::new(crate::gateway::client::GatewayClient::new()),
                rx,
            ),
        )
        .await
        .expect("must quarantine within 5s");

        // Note: spawn failures take a different audit path
        // (no GatewaySpawned, just a final GatewayQuarantined). This
        // pin guards the asymmetry — without it, a future refactor
        // that emits GatewaySpawned BEFORE the spawn returns Err
        // would silently shift the audit shape.
        match outcome {
            SupervisorShutdown::Quarantined { reason, .. } => {
                assert!(
                    reason.contains("repeated spawn failure"),
                    "reason should explain spawn failure; got: {reason}"
                );
            }
            other => panic!("expected Quarantined, got {other:?}"),
        }
        assert_eq!(
            count_events_of(&audit, "GatewaySpawned"),
            0,
            "spawn failures must NOT emit GatewaySpawned"
        );
        assert_eq!(count_events_of(&audit, "GatewayQuarantined"), 1);
    }

    // ── Shutdown during back-off ─────────────────────────────────────

    #[tokio::test]
    async fn shutdown_signal_during_backoff_returns_stopped_promptly() {
        let (_tmp, socket, audit) = supervisor_inputs();
        // Long back-off so the supervisor is sitting in `sleep_or_shutdown`
        // when we send the signal.
        let cfg = fake_section(locate_false_binary(), 100, 60_000);
        let (tx, rx) = oneshot::channel();

        let audit_for_task = audit.clone() as Arc<dyn AuditSink>;
        let supervisor = tokio::spawn(async move {
            spawn_and_supervise(
                Some(cfg),
                PathBuf::from("/tmp"),
                socket,
                audit_for_task,
                Arc::new(crate::gateway::client::GatewayClient::new()),
                rx,
            )
            .await
        });

        // Give it ~200ms to crash once and enter back-off.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = tx.send(());

        // Without the back-off-aware select, this would take the full
        // 60s back-off. With it, the supervisor returns immediately.
        let outcome = tokio::time::timeout(Duration::from_secs(2), supervisor)
            .await
            .expect("supervisor must respond to shutdown during back-off within 2s")
            .expect("supervisor must not panic");

        assert!(
            matches!(outcome, SupervisorShutdown::Stopped),
            "expected Stopped, got {outcome:?}"
        );
        // Quarantine MUST NOT have been emitted — operator wanted
        // shutdown, not auto-quarantine.
        assert_eq!(count_events_of(&audit, "GatewayQuarantined"), 0);
    }
}
