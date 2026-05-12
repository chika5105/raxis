//! `raxis-session-spawn` — kernel-side per-session VM spawn orchestration.
//!
//! Normative reference:
//!   * `credential-proxy.md §1, §2`
//!   * `vm-network-isolation.md §3-§5`
//!   * `extensibility-traits.md §3.5`
//!
//! # What this crate ships
//!
//! One service type — [`SessionSpawnService`] — that owns the
//! production wiring of three previously-independent substrates into
//! a single coherent session-lifecycle:
//!
//! 1. **Credential proxies** — `raxis-credential-proxy-manager` binds
//!    one per-session listener per `[[tasks.credentials]]` entry.
//! 2. **Egress admission** — `raxis-egress-admission` binds one
//!    per-session listener that the in-guest tproxy substrate
//!    (`raxis-tproxy`) phones home to for every outbound TLS handshake.
//! 3. **Isolation** — `raxis-isolation::Backend::spawn` boots the VM
//!    (Firecracker / Apple-VZ / subprocess test substrate, etc.).
//!
//! The service is the missing piece between the trait crates (which
//! exist and are integration-tested at the bytes-on-the-wire level)
//! and the kernel's IPC dispatch (which has approve_plan land tasks
//! in the DB but has no callsite that turns one of those tasks into
//! a running VM).
//!
//! # Why a separate crate
//!
//! Three reasons:
//!
//! * **Cross-crate composition.** None of the three substrates know
//!   about each other; folding the composition logic into any one
//!   of them would smear the trait surface. A standalone composer
//!   keeps each substrate's trait tight and testable in isolation.
//!
//! * **Test boundary.** `SubprocessIsolation` (in
//!   `raxis-test-support`) implements the same `Backend` trait as
//!   Firecracker / Apple-VZ. By taking `Arc<dyn Backend>` the
//!   service exercises the full real path against the subprocess
//!   substrate without booting a microVM — the integration test in
//!   `tests/spawn_round_trip.rs` does exactly this.
//!
//! * **Future provenance.** When the kernel's IPC dispatch loop
//!   gains a callsite that says "this task is ready to run," the
//!   only thing the kernel needs is `Arc<SessionSpawnService>` —
//!   no other plumbing. The service holds its own session table and
//!   admission-loop task handles, isolated from the IPC-handler tree.
//!
//! # Lifecycle invariants
//!
//! * `spawn_session` is **atomic on failure**: any failure after
//!   credential-proxies-bound but before VM-spawned causes the
//!   already-bound listeners to be torn down with the paired
//!   `CredentialProxyStopped` audit event. No half-bound state can
//!   escape the call.
//! * `terminate_session` is **idempotent**: calling it twice for the
//!   same session id returns `SpawnError::SessionNotActive` on the
//!   second call rather than firing a second teardown.
//! * The **shutdown order** is fixed: VM-shutdown → admission-loop
//!   abort → credential-proxies-shutdown. This matches the
//!   audit-after-state-mutation discipline (the audit event for
//!   each tier lands AFTER the state mutation it describes).
//!
//! # What this crate does NOT do
//!
//! * **It does not own the IPC dispatch loop.** The kernel calls
//!   `spawn_session` from whatever orchestrator-driven callsite
//!   eventually wires it; the service does not poll work itself.
//!
//! * **It does not own the SQLite store.** Per-task credential
//!   declarations are read by the kernel's `lifecycle::
//!   read_task_credential_proxies_in_tx` helper and passed in as a
//!   `Vec<TaskCredentialDecl>`. The service stays sync-store-free.
//!
//! * **It does not implement the egress decision policy.** A
//!   `Box<dyn AdmissionService>` is supplied per-spawn; production
//!   wires `PolicyAdmissionService` over the active `PolicyBundle`
//!   while tests can wire deterministic queues.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_credential_proxy_manager::{
    CredentialProxyManager, ManagerError, SessionProxyHandles, ShutdownReport,
};
use raxis_egress_admission::{run_admission_loop, AdmissionService};
use raxis_isolation::{
    Backend as IsolationBackend, ExitStatus, IsolationError, Session as IsolationSession,
    VerifiedImage, VmSpec, WorkspaceMount,
};
use raxis_plan_credentials::TaskCredentialDecl;
use thiserror::Error;
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// One request to spawn a VM for a specific (initiative, task) pair.
///
/// The kernel constructs this from the parsed plan + the active
/// policy; the service consumes it and never inspects the plan TOML
/// directly.
pub struct SpawnRequest {
    /// Stable per-session identifier the kernel mints (UUID v4 in
    /// production). Used as the audit-event `session_id`, the
    /// `CredentialProxyManager` session key, and the
    /// `run_admission_loop` `session_id` argument.
    pub session_id:        String,

    /// Owning task id from the signed plan. Used by the credential
    /// proxy manager to scope `CredentialProxyStarted` audit events.
    /// `None` for the canonical Orchestrator session (it has no
    /// `[[tasks]]` row).
    pub task_id:           Option<String>,

    /// Owning initiative id. Forwarded to the in-guest IPC handshake.
    pub initiative_id:     String,

    /// The verified VM image the substrate boots.
    pub image:             VerifiedImage,

    /// Mounts the substrate exposes to the guest. Empty for
    /// substrates that do not support filesystem mounts.
    pub workspace_mounts:  Vec<WorkspaceMount>,

    /// Resource ceiling + boot args the kernel constructs for this
    /// session. The service stamps env entries (credential-proxy
    /// loopback URLs + admission-service address) on top of
    /// `vm_spec.env` *additively*: the caller's existing entries are
    /// preserved unless they collide on key, in which case the
    /// service-supplied value wins (the kernel is the authoritative
    /// source for the loopback URL and admission service address).
    pub vm_spec:           VmSpec,

    /// `[[tasks.credentials]]` declarations for this task. The
    /// service rehydrates one credential proxy per entry.
    pub credentials:       Vec<TaskCredentialDecl>,

    /// Per-session admission decision policy. Production wires
    /// `PolicyAdmissionService` over the active `PolicyBundle`; tests
    /// wire deterministic queues. Boxed because the lifetime is
    /// per-spawn and the type varies between deployments.
    pub admission_service: Box<dyn AdmissionService>,
}

/// Outcome of a successful `spawn_session` call.
///
/// The service retains a `Box<dyn IsolationSession>` internally
/// (for `terminate_session` use); the handle the caller receives is
/// a *summary* of what was bound. The caller does NOT directly drive
/// the isolation session — IPC traffic flows through the kernel's
/// existing transport plumbing. See `extensibility-traits.md §3.4`.
///
/// **Note: not `Clone`.** The handle now owns the kernel-side IPC
/// stream surrendered by the substrate (when the substrate is a
/// microVM and the planner is bound as a vsock listener). That
/// stream is a `tokio::net::UnixStream` and cannot be cloned; the
/// caller is expected to `take()` it once and pass it into a
/// per-session dispatch task.
#[derive(Debug)]
pub struct SpawnHandle {
    /// Echo of the request's `session_id`.
    pub session_id:           String,
    /// VSock CID of the running session (when the substrate uses
    /// vsock; `None` for subprocess / wasm substrates).
    pub vsock_cid:             Option<u32>,
    /// `mount_as → loopback URL` for every credential proxy bound
    /// for this session. The service has already stamped these into
    /// `VmSpec.env` for the substrate; this field is exposed to the
    /// caller for diagnostic logging and for callers that need to
    /// re-expose the values through alternative channels (e.g.
    /// metadata service).
    pub loopback_env:          BTreeMap<String, String>,
    /// `host:port` the in-guest tproxy talks to over loopback (dev)
    /// or the vsock CID at V2 GA. Likewise pre-stamped into
    /// `VmSpec.env` under `RAXIS_TPROXY_KERNEL_TCP`.
    pub admission_loopback:    SocketAddr,
    /// Host-side end of the kernel ↔ guest IPC channel for
    /// substrates that surrender one at spawn time
    /// (`Session::take_kernel_ipc_fd`). The kernel-side caller is
    /// expected to `Option::take` this stream and run its planner
    /// dispatch loop on it (`raxis_kernel::ipc::server::
    /// drive_planner_stream`).
    ///
    /// `None` for substrates where the planner dials the kernel's
    /// UDS planner socket directly (subprocess, wasm) — those
    /// rely on the kernel's existing `accept_planner_loop` to pick
    /// up the connection without per-session bridging.
    pub kernel_ipc_stream:     Option<tokio::net::UnixStream>,
}

/// Outcome of a successful `terminate_session` call.
#[derive(Debug)]
pub struct TerminationReport {
    /// Echo of the session id terminated.
    pub session_id:        String,
    /// Final exit status the substrate reported.
    pub exit_status:       ExitStatus,
    /// Per-proxy stats snapshot from the credential proxies.
    pub credential_proxy_shutdown: ShutdownReport,
}

/// Failure modes surfaced by the service.
#[derive(Debug, Error)]
pub enum SpawnError {
    /// `CredentialProxyManager::start_for_session` failed. The
    /// substrate was *not* booted, no listeners are leaked.
    #[error("credential-proxy bind failed: {0}")]
    CredentialProxy(#[from] ManagerError),

    /// `tokio::net::TcpListener::bind` for the per-session admission
    /// service failed. Already-bound credential proxies are torn down
    /// before this error returns.
    #[error("egress-admission listener bind failed: {0}")]
    AdmissionBind(#[source] std::io::Error),

    /// `IsolationBackend::spawn` rejected the spec. Already-bound
    /// listeners (credential proxies + admission) are torn down
    /// before this error returns.
    #[error("isolation spawn failed: {0}")]
    IsolationSpawn(#[source] IsolationError),

    /// `IsolationSession::shutdown` failed during teardown.
    #[error("isolation shutdown failed: {0}")]
    IsolationShutdown(#[source] IsolationError),

    /// `terminate_session` was called for a session id the service
    /// has no record of. May indicate a double-teardown or a stale
    /// caller.
    #[error("session not active: {session_id}")]
    SessionNotActive {
        /// The session id the caller asked to terminate.
        session_id: String,
    },

    /// Audit emission failed at a paired step (`SessionSpawned` /
    /// `SessionTerminated`). Surfaced fail-closed: the session is
    /// NOT marked active because the audit record could not be
    /// committed.
    #[error("audit emission failed: {0}")]
    Audit(String),
}

/// The composer.
///
/// One instance per kernel boot. Threaded into `HandlerContext` and
/// shared across every IPC handler that needs to spawn or terminate
/// a session. The internal session table is behind a
/// `parking_lot::Mutex` — every callsite acquires the lock, mutates
/// the map (`insert` / `remove` / `contains_key` / `len`), and
/// drops the guard within a single synchronous block. None of the
/// callsites await while holding the lock, so the async runtime
/// would gain nothing from `tokio::sync::Mutex` and pay the
/// async-state-machine overhead for every short critical section.
pub struct SessionSpawnService {
    isolation: Arc<dyn IsolationBackend>,
    proxies:   Arc<CredentialProxyManager>,
    audit:     Arc<dyn AuditSink>,
    /// Per-session live state. Populated by `spawn_session`,
    /// drained by `terminate_session`. Synchronously serialised
    /// because every critical section is map-mutation only — the
    /// VM-shutdown / audit-emit / loop-abort work in
    /// `terminate_session` runs AFTER the guard has been dropped
    /// (`drop(table)` immediately after `remove`).
    sessions:  Mutex<HashMap<String, ActiveSession>>,
}

/// Live state for one running session.
struct ActiveSession {
    session:           Box<dyn IsolationSession>,
    credential_proxy_handles: SessionProxyHandles,
    admission_loop_task:      JoinHandle<()>,
    admission_loopback:       SocketAddr,
}

impl SessionSpawnService {
    /// Construct the service.
    ///
    /// `isolation` is the substrate the kernel admitted at boot
    /// (after `verify_admission_tier`). `proxies` is the kernel's
    /// per-boot credential-proxy manager (one per kernel, shared
    /// across all sessions). `audit` is the kernel's audit sink.
    pub fn new(
        isolation: Arc<dyn IsolationBackend>,
        proxies:   Arc<CredentialProxyManager>,
        audit:     Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            isolation,
            proxies,
            audit,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Borrow the audit sink the service was constructed with.
    ///
    /// Exposed so kernel-side bridges (e.g.
    /// `kernel::session_spawn_orchestrator::spawn_with_transient_retry`)
    /// can emit elastic-scaling audit events
    /// (`SessionVmRespawnAttempted`, `SessionVmFailedFinal`,
    /// `SessionVmScaleEvent`, `SessionVmScaleDeferred`) against the
    /// SAME sink that the service uses for `SessionVmSpawned` /
    /// `SessionVmExited` — keeping the kernel-wide audit chain a
    /// single ordered stream per `audit-paired-writes.md §1`.
    pub fn audit(&self) -> &Arc<dyn AuditSink> {
        &self.audit
    }

    /// Spawn a VM and bind every per-session listener for the given
    /// request. On error, every already-bound listener is torn down
    /// before the error returns.
    ///
    /// Stamps three classes of values into `req.vm_spec.env`:
    ///
    /// * `RAXIS_SESSION_ID` — echo of the request's session_id.
    /// * `RAXIS_TPROXY_KERNEL_TCP` — the per-session admission
    ///   listener address.
    /// * One entry per credential proxy, keyed by the operator-
    ///   declared `mount_as` field, value = the proxy's loopback URL.
    ///
    /// The caller's `vm_spec.env` is preserved on keys that don't
    /// collide; the service-supplied value wins on keys that do.
    pub async fn spawn_session(
        &self,
        mut req: SpawnRequest,
    ) -> Result<SpawnHandle, SpawnError> {
        let session_id = req.session_id.clone();
        let task_id    = req.task_id.clone().unwrap_or_else(|| "<orchestrator>".to_owned());
        tracing::info!(
            session_id = %session_id,
            task_id    = %task_id,
            credentials = req.credentials.len(),
            "session-spawn: starting",
        );

        // ── Step 1: bind credential proxies. ──────────────────────────
        // The manager emits paired CredentialProxyStarted events at
        // bind time and CredentialProxyStopped at handles.shutdown().
        // We hold the handles for the lifetime of the session.
        let cred_handles = self
            .proxies
            .start_for_session(&session_id, &task_id, &req.credentials)
            .await?;

        // ── Step 2: bind per-session egress-admission listener. ──────
        // Failure here MUST tear down the credential proxies bound in
        // step 1 — leaving them bound would leak loopback ports.
        let admission_listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                let _ = cred_handles.shutdown();
                return Err(SpawnError::AdmissionBind(e));
            }
        };
        let admission_addr = match admission_listener.local_addr() {
            Ok(a) => a,
            Err(e) => {
                let _ = cred_handles.shutdown();
                return Err(SpawnError::AdmissionBind(e));
            }
        };
        tracing::info!(
            session_id = %session_id,
            admission_addr = %admission_addr,
            "session-spawn: admission listener bound",
        );

        // ── Step 3: stamp env entries the substrate forwards to the
        //           guest. The credential-proxy URLs land first
        //           (one per `mount_as`), the kernel-injected vars
        //           land afterwards so they win on key conflict.
        let loopback_env = cred_handles.loopback_env();
        for (k, v) in &loopback_env {
            req.vm_spec.env.insert(k.clone(), v.clone());
        }
        req.vm_spec
            .env
            .insert("RAXIS_SESSION_ID".to_owned(), session_id.clone());
        req.vm_spec.env.insert(
            "RAXIS_TPROXY_KERNEL_TCP".to_owned(),
            admission_addr.to_string(),
        );

        // ── Step 4: boot the VM. ─────────────────────────────────────
        //
        // `Backend::spawn` is a synchronous trait method that does not
        // return until the guest is reachable on its primary IPC
        // transport (per the trait's "MUST NOT return until reachable"
        // contract). For microVM substrates (Apple-VZ, Firecracker)
        // that includes the entire kernel-boot + tokio-runtime spin-
        // up + vsock CONNECT retry loop — typically ~250 ms. Calling
        // it directly from the async runtime thread blocks the whole
        // executor for that whole window, starving every other
        // session's IPC handlers, the audit dispatcher, the
        // credential-proxy event loops, and any other in-flight
        // spawns. Wrap in `spawn_blocking` so the runtime thread is
        // free to make progress on those tasks while AVF / Firecracker
        // is wall-clock-blocked on `startWithCompletionHandler:` +
        // `connectToPort:`.
        //
        // Failure here MUST tear down the credential proxies AND the
        // admission listener bound above. Drop on the listener
        // releases the port immediately.
        let isolation_for_spawn = Arc::clone(&self.isolation);
        let image_for_spawn     = req.image.clone();
        let mounts_for_spawn    = req.workspace_mounts.clone();
        let vm_spec_for_spawn   = req.vm_spec.clone();
        let spawn_join = tokio::task::spawn_blocking(move || {
            isolation_for_spawn.spawn(
                &image_for_spawn,
                &mounts_for_spawn,
                &vm_spec_for_spawn,
            )
        })
        .await;
        let mut session = match spawn_join {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                drop(admission_listener);
                let _ = cred_handles.shutdown();
                return Err(SpawnError::IsolationSpawn(e));
            }
            Err(join_err) => {
                drop(admission_listener);
                let _ = cred_handles.shutdown();
                return Err(SpawnError::IsolationSpawn(
                    raxis_isolation::IsolationError::BackendInternal(format!(
                        "session-spawn: Backend::spawn blocking task join: {join_err}",
                    )),
                ));
            }
        };

        // ── Step 4.5: surrender the kernel-side IPC stream. ─────────
        //
        // microVM substrates (Apple-VZ today, Firecracker once it
        // implements `take_kernel_ipc_fd`) negotiate a per-session
        // VSock SOCK_STREAM at spawn time and hand the host-side
        // fd back here. We wrap it as a non-blocking
        // `tokio::net::UnixStream` so the kernel's existing
        // `handle_planner_connection` machinery (length-prefixed
        // bincode `IpcMessage` framing per `peripherals.md §3`) can
        // drive it directly without bouncing every byte through the
        // synchronous `Session::push` / `Session::recv_intent` pair.
        //
        // Any failure to wrap the fd is fail-closed: tear down the
        // VM, the admission listener, and the credential proxies.
        // The kernel cannot proceed without the IPC channel for
        // substrates that produced one — silently dropping the fd
        // would surface as a vsock CONNECT timeout in the guest.
        let kernel_ipc_stream: Option<tokio::net::UnixStream> =
            match session.take_kernel_ipc_fd() {
                Some(fd) => match wrap_ipc_fd_as_unix_stream(fd) {
                    Ok(stream) => Some(stream),
                    Err(e) => {
                        drop(admission_listener);
                        let _ = session.terminate();
                        let _ = cred_handles.shutdown();
                        return Err(SpawnError::IsolationSpawn(
                            raxis_isolation::IsolationError::TransportFault(format!(
                                "session-spawn: wrap kernel IPC fd: {e}"
                            )),
                        ));
                    }
                },
                None => None,
            };
        tracing::info!(
            session_id = %session_id,
            backend    = self.isolation.backend_id(),
            "session-spawn: VM booted",
        );

        // ── Step 5: drive the per-session admission loop. ────────────
        // One spawned task accepts loopback connections from the
        // in-guest tproxy and runs `run_admission_loop` for each.
        // Cancellation is via `JoinHandle::abort()` at terminate time,
        // which drops the futures cleanly (no half-written frames per
        // the trait contract).
        let admission_service: Arc<dyn AdmissionService> = Arc::from(req.admission_service);
        let audit_for_loop    = Arc::clone(&self.audit);
        let session_id_for_loop = session_id.clone();
        let admission_task = tokio::spawn(async move {
            loop {
                let (sock, peer) = match admission_listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(
                            session_id = %session_id_for_loop,
                            error = %e,
                            "egress admission accept failed; closing listener",
                        );
                        return;
                    }
                };
                tracing::debug!(
                    session_id = %session_id_for_loop,
                    peer = %peer,
                    "egress admission: accepted in-guest tproxy connection",
                );
                let (read, write) = sock.into_split();
                let svc = Arc::clone(&admission_service);
                let audit_for_inner = Arc::clone(&audit_for_loop);
                let sid_for_inner   = session_id_for_loop.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_admission_loop(
                        read, write, svc, audit_for_inner, sid_for_inner.clone(),
                    ).await {
                        tracing::warn!(
                            session_id = %sid_for_inner,
                            error = %e,
                            "egress admission loop terminated with error",
                        );
                    }
                });
            }
        });

        // ── Step 6: emit `SessionVmSpawned` audit event. ────────────
        // Same audit-after-state-mutation discipline used elsewhere:
        // the VM is already running and the in-memory live-session
        // table mutation just succeeded; the audit lands now.
        let credential_proxy_count = req.credentials.len() as u32;
        let initiative_for_audit   = req.initiative_id.clone();
        let task_for_audit         = req.task_id.clone();
        if let Err(e) = self.audit.emit(
            AuditEventKind::SessionVmSpawned {
                session_id:         session_id.clone(),
                task_id:            task_for_audit.clone(),
                initiative_id:      initiative_for_audit,
                backend_id:         self.isolation.backend_id().to_owned(),
                egress_tier:        format!("{:?}", req.vm_spec.egress_tier),
                admission_loopback: admission_addr.to_string(),
                credential_proxies: credential_proxy_count,
            },
            Some(&session_id),
            task_for_audit.as_deref(),
            None,
        ) {
            // Audit failure is fail-closed: tear down the VM, the
            // admission loop, and the credential proxies before
            // surfacing the error.
            admission_task.abort();
            let mut sess = session;
            let _ = sess.terminate();
            let _ = cred_handles.shutdown();
            return Err(SpawnError::Audit(e.to_string()));
        }

        // ── Step 7: register the active session. ────────────────────
        let mut table = self.sessions.lock();
        table.insert(
            session_id.clone(),
            ActiveSession {
                session,
                credential_proxy_handles: cred_handles,
                admission_loop_task:      admission_task,
                admission_loopback:       admission_addr,
            },
        );
        drop(table);

        Ok(SpawnHandle {
            session_id,
            vsock_cid:          req.vm_spec.vsock_cid,
            loopback_env,
            admission_loopback: admission_addr,
            kernel_ipc_stream,
        })
    }

    /// Tear down a previously-spawned session.
    ///
    /// Order: `Session::shutdown(grace)` → admission-loop abort →
    /// credential-proxies shutdown. Each step is recorded in the
    /// audit chain at the tier where it lands (`SessionTerminated`,
    /// then per-proxy `CredentialProxyStopped` events emitted by
    /// the manager).
    pub async fn terminate_session(
        &self,
        session_id: &str,
        grace:      Duration,
    ) -> Result<TerminationReport, SpawnError> {
        let mut table = self.sessions.lock();
        let mut entry = table
            .remove(session_id)
            .ok_or_else(|| SpawnError::SessionNotActive {
                session_id: session_id.to_owned(),
            })?;
        drop(table);

        // ── Step 1: shut down the VM. ─────────────────────────────
        let exit_status = entry
            .session
            .shutdown(grace)
            .map_err(SpawnError::IsolationShutdown)?;
        tracing::info!(
            session_id = %session_id,
            ?exit_status,
            "session-terminate: VM shut down",
        );

        // ── Step 2: emit `SessionVmExited` immediately after the
        //           VM-level mutation, before any cleanup of
        //           subsidiary state. This is the
        //           audit-after-state-mutation discipline:
        //           the audit event for each tier lands AFTER the
        //           state mutation it describes, in tier order.
        let (signal_class, exit_code, backend_error) = classify_exit(&exit_status);
        if let Err(e) = self.audit.emit(
            AuditEventKind::SessionVmExited {
                session_id:    session_id.to_owned(),
                signal_class,
                exit_code,
                backend_error,
            },
            Some(session_id),
            None,
            None,
        ) {
            // Audit emission is fail-loud: the VM is already down,
            // we cannot un-mutate it, but we still need to drain
            // the credential proxies so loopback ports and child
            // tasks don't leak. We surface the audit error AFTER
            // best-effort cleanup.
            entry.admission_loop_task.abort();
            let _ = entry.credential_proxy_handles.shutdown();
            return Err(SpawnError::Audit(e.to_string()));
        }

        // ── Step 3: cancel the admission loop. ───────────────────
        // `abort()` is fire-and-forget and the listener fd is
        // dropped when the task is gone, so any in-flight accept()
        // returns the task. The futures driving in-flight
        // run_admission_loop calls drop cleanly (cancel-safe per
        // the crate's trait contract).
        entry.admission_loop_task.abort();
        let _ = entry.admission_loopback;
        tracing::info!(
            session_id = %session_id,
            "session-terminate: admission loop aborted",
        );

        // ── Step 4: shut down credential proxies (emits
        //           CredentialProxyStopped per proxy). ────────────
        let cred_shutdown = entry
            .credential_proxy_handles
            .shutdown()
            .map_err(SpawnError::CredentialProxy)?;

        Ok(TerminationReport {
            session_id: session_id.to_owned(),
            exit_status,
            credential_proxy_shutdown: cred_shutdown,
        })
    }

    /// Whether a session id has an active VM right now.
    ///
    /// Cheap; takes the table lock for the duration of the lookup.
    /// Method stays `async` for API stability — callers `.await` it
    /// today and the body trivially completes synchronously.
    pub async fn is_active(&self, session_id: &str) -> bool {
        self.sessions.lock().contains_key(session_id)
    }

    /// Number of currently-active sessions. Useful for kernel boot
    /// admission tier checks (`MaxConcurrentVms`) and for the
    /// `raxis status` operator command. See [`Self::is_active`] for
    /// the async-signature note.
    pub async fn active_count(&self) -> usize {
        self.sessions.lock().len()
    }
}

/// Reduce `ExitStatus` to the audit-chain triple
/// `(signal_class, exit_code, backend_error)` consumed by
/// `SessionVmExited`.
///
/// The mapping below is **stable** — operator dashboards pin
/// specific values (e.g. -1 for `Timeout`, -2 for `BackendError`).
/// Adding a new variant here is a wire change and must land in
/// lockstep with `IsolationError::ExitStatus` and the
/// `SessionVmExited.signal_class` enum sketch in
/// `audit-paired-writes.md §4.1`.
fn classify_exit(status: &ExitStatus) -> (String, i32, Option<String>) {
    match status {
        ExitStatus::GracefulExit { code }   => ("GracefulExit".into(),  *code,            None),
        ExitStatus::SignalKilled { signum } => ("SignalKilled".into(), -signum.abs(),     None),
        ExitStatus::Timeout                 => ("Timeout".into(),       -1,                None),
        ExitStatus::BackendError(msg)       => ("BackendError".into(),  -2, Some(msg.clone())),
    }
}

/// Wrap a substrate-surrendered SOCK_STREAM file descriptor as a
/// non-blocking [`tokio::net::UnixStream`].
///
/// The contract from [`raxis_isolation::Session::take_kernel_ipc_fd`]:
/// the substrate has already established a connected SOCK_STREAM and
/// transferred ownership of the fd to us. We MUST set `O_NONBLOCK`
/// and hand it to tokio's reactor so the kernel's per-session
/// dispatch loop can `await` reads without blocking the executor.
///
/// `tokio::net::UnixStream::from_std` expects a non-blocking
/// `std::os::unix::net::UnixStream`; the `from_raw_fd` constructor
/// takes ownership of the fd, so on success the fd's lifetime is
/// the returned stream's `Drop`.
///
/// On failure the fd is dropped (closed) by the intermediate
/// `std::os::unix::net::UnixStream` value, so the substrate's `Drop`
/// will not double-close.
fn wrap_ipc_fd_as_unix_stream(
    fd: std::os::unix::io::RawFd,
) -> Result<tokio::net::UnixStream, std::io::Error> {
    use std::os::unix::io::FromRawFd;
    // SAFETY: `fd` is a SOCK_STREAM file descriptor whose ownership
    // was just transferred to us per the
    // `Session::take_kernel_ipc_fd` contract. The substrate
    // promises not to close it again. The crate carries
    // `#![deny(unsafe_code)]` because the rest of the module is
    // pure data flow over already-typed sockets; this single
    // syscall wrapper is the one place where we cross the FFI
    // boundary, and the contract is exhaustively documented at
    // `Session::take_kernel_ipc_fd`.
    #[allow(unsafe_code)]
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(std_stream)
}
