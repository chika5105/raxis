//! Kernel-side production bridge between the IPC dispatch tree and
//! `SessionSpawnService`.
//!
//! Normative references:
//!
//! * `extensibility-traits.md §3.5, §3.8` — `Backend::spawn` is the
//!   only seam between the kernel and the substrate.
//! * `planner-harness.md §4.7` (`INV-PLANNER-HARNESS-05`) — canonical
//!   Orchestrator image digest.
//! * `host-capacity.md §4.2` — admission deferral on capacity
//!   exhaustion (deferred to a follow-up; this module fails closed
//!   for now if capacity is exhausted).
//! * `credential-proxy.md §1, §2` — per-task `[[tasks.credentials]]`
//!   are read from `task_credential_proxies` at spawn time and
//!   handed to the spawn service.
//!
//! **INV-02A** (single-tenant VM) and **INV-02B** (no virtual NIC)
//! are **structurally enforced** here: every call into
//! `SpawnRequest` constructs a fresh per-session VM (one
//! `spawn_session()` call per session — never shared across
//! sessions), and the SpawnRequest's machine config never
//! includes a `NetworkInterface` block (see `firecracker_config`
//! / AVF substrate construction). V2_GAPS.md §13 Category 1 —
//! annotation-only enforcement site.
//!
//! # Why a kernel-side bridge crate (not an IPC handler module)
//!
//! Three callers eventually reach the same SpawnRequest:
//!
//!   1. **Operator IPC** — `OperatorRequest::ApprovePlan` triggers
//!      orchestrator auto-spawn after the SQL transaction commits.
//!   2. **Sub-task activation** — `IntentKind::ActivateSubTask`
//!      triggers Executor / Reviewer spawn for a child task.
//!   3. **Recovery** — `recovery::reconcile` may resume a session
//!      that died across kernel restart.
//!
//! Folding the SpawnRequest plumbing into any of those would create
//! three near-duplicate copies. Putting it here, behind two thin
//! helpers (`spawn_orchestrator_for_initiative` and
//! `spawn_executor_for_task`), keeps the single source of truth for
//! "how does the kernel turn a (initiative_id, task_id) pair into a
//! SessionSpawnService::spawn_session() call?" — including canonical
//! image resolution, credential-decl rehydration from
//! `task_credential_proxies`, lineage-id assignment, and
//! per-spawn admission service construction.
//!
//! # What this module does NOT do
//!
//! * **Does not own the trigger.** The IPC handler / dispatch loop
//!   decides when to call into here. This module is purely
//!   request-shaping plus delegation.
//!
//! * **Does not enforce host-capacity admission.** The capacity
//!   gate (`host-capacity.md §4.2 AdmissionDeferred`) is a follow-
//!   up. This module assumes the caller has already either bypassed
//!   capacity (test fixtures) or admitted the spawn through a
//!   capacity-aware queue.
//!
//! * **Does not pre-verify canonical image digests.** `IsolationBackend
//!   ::spawn` re-checks the digest as defence-in-depth (per
//!   `extensibility-traits.md §3.5`); this module trusts the boot-
//!   time preflight (`canonical_images_preflight.rs`) for the
//!   advisory check.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use raxis_egress_admission::{EgressAllowlist, PolicyAdmissionService};
use raxis_isolation::{
    EgressTier, ImageBody, ImageKind, ImageSignature, SessionToken, VerifiedImage, VmSpec,
};
use raxis_session_spawn::{
    SessionSpawnService, SpawnError, SpawnHandle, SpawnRequest, TerminationReport,
};
use raxis_store::Store;
use thiserror::Error;

use crate::initiatives::lifecycle as kernel_lifecycle;

/// V2 `v2_extended_gaps.md §1.1` — env-var name carrying the
/// operator-authored seed prompt to the spawned planner binary.
///
/// **Single source of truth.** This constant is referenced by:
///
/// 1. `kernel/src/handlers/intent.rs::handle_activate_sub_task`
///    (Executor / Reviewer activation path)
/// 2. `kernel/src/initiatives/lifecycle.rs` orchestrator auto-spawn
///    (Orchestrator activation path)
/// 3. `crates/planner-core/src/driver.rs` (the consuming driver
///    inside the planner binary; see the `var()` helper there)
///
/// **Trust contract.** Presence of a NON-EMPTY value flips the
/// driver out of scaffold/park mode (`INV-DRIVER-01`). The kernel
/// is the single trust boundary that materialises the prompt into
/// the substrate's env table — it is sourced from the
/// operator-signed plan TOML and the agent never observes it
/// before the dispatch loop renders it into the system / user
/// messages.
///
/// **Why a constant, not a string literal.** Keeping the name in
/// one place prevents the kernel and the driver from drifting on
/// the wire shape; a typo on either side would silently keep the
/// binary in scaffold mode (the most common failure mode for
/// "agent did nothing"). The constant is also referenced by the
/// E2E integration test fixtures so a single rename here updates
/// the assertion.
pub const PLANNER_TASK_PROMPT_ENV: &str = "RAXIS_PLANNER_TASK_PROMPT";

/// Failure modes specific to the kernel-side bridge.
///
/// Wraps `SpawnError` for substrate failures and adds the kernel-
/// specific variants (canonical image not found on disk, store read
/// failed when rehydrating credential decls, etc.).
#[derive(Debug, Error)]
pub enum OrchestratorSpawnError {
    /// Could not locate the canonical Orchestrator image at the
    /// expected install-dir path. This is the operator-visible
    /// signal for a half-installed kernel.
    #[error("canonical Orchestrator image not found at {path}")]
    OrchestratorImageMissing { path: PathBuf },

    /// Could not locate the canonical Reviewer image at the
    /// expected install-dir path.
    #[error("canonical Reviewer image not found at {path}")]
    ReviewerImageMissing { path: PathBuf },

    /// Could not locate the canonical Executor-starter image at the
    /// expected install-dir path. Surfaced when a Reviewer-less
    /// Executor activation is attempted on a half-installed kernel
    /// where the operator has not deployed the executor-starter
    /// image (which is opt-in per `system-requirements.md §1`).
    #[error("canonical Executor-starter image not found at {path}")]
    ExecutorStarterImageMissing { path: PathBuf },

    /// `task_credential_proxies` read failed while rehydrating the
    /// credential decls for the spawn. Surfaces underlying SQLite
    /// errors verbatim — these are typically schema-drift bugs.
    #[error("read task_credential_proxies failed: {0}")]
    StoreRead(String),

    /// `SessionSpawnService::spawn_session` rejected the request.
    /// Substrate-level failure modes are carried through verbatim
    /// so operator dashboards can distinguish a `CredentialProxy`
    /// bind error from an `IsolationSpawn` error.
    #[error("session-spawn failed: {0}")]
    Substrate(#[from] SpawnError),
}

/// Resolution context the kernel constructs once at boot and reuses
/// across every orchestrator spawn.
///
/// Keeping the install-dir + kernel-version + isolation/egress
/// defaults in one struct lets the IPC handler call site stay
/// trivial: the handler just supplies `(initiative_id, session_id)`
/// and `OrchestratorSpawnContext` carries everything else.
#[derive(Clone)]
pub struct OrchestratorSpawnContext {
    /// Install dir from which the canonical Orchestrator image is
    /// resolved (e.g. `/usr/local/share/raxis`).
    pub install_dir:    PathBuf,
    /// Kernel version string used to build the canonical image
    /// filename (e.g. `"v2.0.0"`). Pinned per
    /// `system-requirements.md §1`.
    pub kernel_version: String,
    /// Default VM resource budget for the Orchestrator. The
    /// Orchestrator does not run agent code itself; it sequences
    /// other VMs, so the budget is small.
    pub vcpu_count: u32,
    /// Memory ceiling in MiB. Same rationale as `vcpu_count`.
    pub mem_mib:    u32,
    /// V2_GAPS §B1 — kernel data-dir, used to derive the planner
    /// UDS socket path stamped into the guest env at spawn so
    /// `raxis-planner-core::run_role_session` can connect back via
    /// `RAXIS_KERNEL_PLANNER_SOCKET`. `None` ⇒ the env var is not
    /// stamped (live-mode planner contract is not populated;
    /// matches the V2.3 scaffold path).
    pub data_dir:   Option<PathBuf>,
}

impl OrchestratorSpawnContext {
    /// Default orchestrator VM resource budget — 1 vCPU, 256 MiB.
    /// Pinned to match the `extensibility-traits.md §3.5` example
    /// and the `host-capacity.md §4.1` defaults; operators can
    /// override at boot via the `[isolation] orchestrator_*` policy
    /// keys (when those keys land — for now the defaults are the
    /// only path).
    pub fn new(install_dir: PathBuf, kernel_version: String) -> Self {
        Self {
            install_dir,
            kernel_version,
            vcpu_count: 1,
            mem_mib:    256,
            data_dir:   None,
        }
    }

    /// Builder: attach the kernel `data_dir` so the spawn path can
    /// stamp `RAXIS_KERNEL_PLANNER_SOCKET=<data_dir>/sockets/planner.sock`
    /// into the guest env. Production wires this from
    /// `kernel/src/main.rs::data_dir()`.
    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = Some(data_dir);
        self
    }
}

// ---------------------------------------------------------------------------
// Trait surface — what the kernel's IPC handlers call.
// ---------------------------------------------------------------------------

/// Kernel-internal trait that `handle_approve_plan` (and any other
/// orchestrator-driving callsite) drives to boot the canonical
/// Orchestrator VM for a freshly-approved initiative.
///
/// Two production-relevant impls live in this module:
///
/// * [`LiveOrchestratorSpawn`] — the production implementation that
///   delegates to `SessionSpawnService::spawn_session` against the
///   real canonical image bytes resolved via the boot-time
///   install-dir. Wired by `main.rs`.
///
/// * [`NoopOrchestratorSpawn`] (cfg-gated to
///   `debug_assertions || test`) — the test fake that records every
///   call and returns `Ok(())` without binding any listener. Wired
///   by `ipc::context::build_test_orchestrator_spawn` and never
///   reachable from a release-mode binary, mirroring the
///   `FailClosedTestIsolation` / `FakeAuditSink` discipline.
///
/// **Why a trait** (rather than a free function or
/// `Option<OrchestratorSpawnContext>`): test fixtures need a real-
/// shaped substitute that exercises the same `handle_approve_plan`
/// path as production. An `Option` would let the handler quietly
/// branch around the spawn — a trait keeps the call site uniform
/// and lets tests assert on the recorded calls.
pub trait OrchestratorSpawn: Send + Sync {
    /// Spawn the canonical Orchestrator VM for `(session_id,
    /// initiative_id)`. The implementation is responsible for
    /// rehydrating the credential decls (production reads from the
    /// store; the test fake returns an empty list).
    ///
    /// `task_prompt` is the operator-authored seed prompt for the
    /// orchestrator agent (V2 `v2_extended_gaps.md §1.1`). When
    /// non-empty, the implementation MUST stamp it into the spawned
    /// VM's env table under [`PLANNER_TASK_PROMPT_ENV`] so the
    /// orchestrator binary's dispatch driver enters live mode rather
    /// than parking in scaffold mode (`INV-DRIVER-01`). When empty
    /// (the V1 default for plans that omit `[workspace] description`)
    /// the env var MUST NOT be stamped — the driver treats absence
    /// the same as empty and parks.
    fn spawn_for_initiative<'a>(
        &'a self,
        session_id:       &'a str,
        initiative_id:    &'a str,
        egress_allowlist: EgressAllowlist,
        task_prompt:      String,
    ) -> Pin<Box<dyn Future<Output = Result<SpawnHandle, OrchestratorSpawnError>> + Send + 'a>>;

    /// Tear down a previously-spawned Orchestrator VM. Idempotent:
    /// terminating a session that is no longer active surfaces
    /// `OrchestratorSpawnError::Substrate(SpawnError::SessionNotActive)`
    /// from production and `Ok(_)` from the test fake.
    fn terminate_orchestrator<'a>(
        &'a self,
        session_id: &'a str,
        grace:      std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<TerminationReport, OrchestratorSpawnError>> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Production impl — `LiveOrchestratorSpawn`.
// ---------------------------------------------------------------------------

/// Production [`OrchestratorSpawn`] implementation.
///
/// Holds the boot-time install-dir + kernel-version (via
/// [`OrchestratorSpawnContext`]) plus the kernel's
/// `Arc<SessionSpawnService>` and `Arc<Store>`. Constructed once at
/// `main.rs` boot and cloned into `HandlerContext`.
pub struct LiveOrchestratorSpawn {
    ctx:     OrchestratorSpawnContext,
    service: Arc<SessionSpawnService>,
    store:   Arc<Store>,
}

impl LiveOrchestratorSpawn {
    /// Construct the production impl.
    pub fn new(
        ctx:     OrchestratorSpawnContext,
        service: Arc<SessionSpawnService>,
        store:   Arc<Store>,
    ) -> Self {
        Self { ctx, service, store }
    }
}

impl OrchestratorSpawn for LiveOrchestratorSpawn {
    fn spawn_for_initiative<'a>(
        &'a self,
        session_id:       &'a str,
        initiative_id:    &'a str,
        egress_allowlist: EgressAllowlist,
        task_prompt:      String,
    ) -> Pin<Box<dyn Future<Output = Result<SpawnHandle, OrchestratorSpawnError>> + Send + 'a>> {
        Box::pin(async move {
            spawn_orchestrator_for_initiative(
                &self.ctx,
                session_id,
                initiative_id,
                egress_allowlist,
                task_prompt,
                Arc::clone(&self.service),
                &self.store,
            )
            .await
        })
    }

    fn terminate_orchestrator<'a>(
        &'a self,
        session_id: &'a str,
        grace:      std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<TerminationReport, OrchestratorSpawnError>> + Send + 'a>> {
        Box::pin(async move {
            terminate_orchestrator(session_id, grace, Arc::clone(&self.service)).await
        })
    }
}

// ---------------------------------------------------------------------------
// Test fake — `NoopOrchestratorSpawn`.
// ---------------------------------------------------------------------------

/// In-process unit-test fake [`OrchestratorSpawn`].
///
/// Records every `(session_id, initiative_id)` pair the kernel
/// asks to spawn so tests can assert that
/// `handle_approve_plan` reached the orchestrator-spawn callsite.
/// Returns `Ok(_)` synchronously without binding any listener,
/// without touching the substrate, and without emitting any audit
/// event — mirroring the `FailClosedTestIsolation` /
/// `FakeAuditSink` discipline.
///
/// **Layer-1 enforcement.** This type is `cfg`-gated to
/// `debug_assertions || test`: in a release build, the type does
/// not exist and any consumer that mistakenly references it fails
/// to compile.
#[cfg(any(debug_assertions, test))]
pub struct NoopOrchestratorSpawn {
    /// Sequence of `(session_id, initiative_id, task_prompt)` triples
    /// the kernel asked to spawn, in call order. The third element
    /// lets V2 `v2_extended_gaps.md §1.1` tests assert that the
    /// activation handler propagated the operator-authored seed
    /// prompt verbatim to the spawn callsite.
    spawn_calls:     std::sync::Mutex<Vec<(String, String, String)>>,
    /// Sequence of `session_id`s the kernel asked to terminate.
    terminate_calls: std::sync::Mutex<Vec<String>>,
}

#[cfg(any(debug_assertions, test))]
impl NoopOrchestratorSpawn {
    /// Construct a fresh fake.
    pub fn new() -> Self {
        Self {
            spawn_calls:     std::sync::Mutex::new(Vec::new()),
            terminate_calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Snapshot of `(session_id, initiative_id, task_prompt)`
    /// triples the kernel has asked to spawn so far. Tests use
    /// this to assert that `handle_approve_plan` reached the
    /// orchestrator-spawn callsite AND that V2
    /// `v2_extended_gaps.md §1.1` propagated the operator-authored
    /// seed prompt unchanged to the spawn boundary.
    pub fn spawn_calls(&self) -> Vec<(String, String, String)> {
        self.spawn_calls.lock().expect("spawn_calls poisoned").clone()
    }

    /// Snapshot of session ids the kernel has asked to terminate.
    pub fn terminate_calls(&self) -> Vec<String> {
        self.terminate_calls.lock().expect("terminate_calls poisoned").clone()
    }
}

#[cfg(any(debug_assertions, test))]
impl Default for NoopOrchestratorSpawn {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(debug_assertions, test))]
impl OrchestratorSpawn for NoopOrchestratorSpawn {
    fn spawn_for_initiative<'a>(
        &'a self,
        session_id:        &'a str,
        initiative_id:     &'a str,
        _egress_allowlist: EgressAllowlist,
        task_prompt:       String,
    ) -> Pin<Box<dyn Future<Output = Result<SpawnHandle, OrchestratorSpawnError>> + Send + 'a>> {
        let session_owned    = session_id.to_owned();
        let initiative_owned = initiative_id.to_owned();
        Box::pin(async move {
            self.spawn_calls
                .lock()
                .expect("spawn_calls poisoned")
                .push((session_owned.clone(), initiative_owned, task_prompt));
            Ok(SpawnHandle {
                session_id:         session_owned,
                vsock_cid:          None,
                loopback_env:       BTreeMap::new(),
                // Placeholder; tests that assert on this value should
                // wire `LiveOrchestratorSpawn` against a real
                // substrate instead.
                admission_loopback: "127.0.0.1:0".parse().expect("static ipv4 literal"),
            })
        })
    }

    fn terminate_orchestrator<'a>(
        &'a self,
        session_id: &'a str,
        _grace:     std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<TerminationReport, OrchestratorSpawnError>> + Send + 'a>> {
        let session_owned = session_id.to_owned();
        Box::pin(async move {
            self.terminate_calls
                .lock()
                .expect("terminate_calls poisoned")
                .push(session_owned.clone());
            Ok(TerminationReport {
                session_id:                session_owned,
                exit_status:               raxis_isolation::ExitStatus::GracefulExit { code: 0 },
                credential_proxy_shutdown:
                    raxis_credential_proxy_manager::ShutdownReport { stopped: Vec::new() },
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Free-function helpers used by `LiveOrchestratorSpawn` (kept private
// to this module so the trait remains the only callsite the rest of
// the kernel ever sees).
// ---------------------------------------------------------------------------

async fn spawn_orchestrator_for_initiative(
    spawn_ctx:        &OrchestratorSpawnContext,
    session_id:       &str,
    initiative_id:    &str,
    egress_allowlist: EgressAllowlist,
    task_prompt:      String,
    service:          Arc<SessionSpawnService>,
    store:            &Arc<Store>,
) -> Result<SpawnHandle, OrchestratorSpawnError> {
    // ── Step 1: locate canonical orchestrator image. ─────────────
    // We don't re-verify the digest here; the boot-time preflight
    // (`canonical_images_preflight::verify_canonical_images_at_boot`)
    // is the advisory check, and the `IsolationBackend::spawn` impl
    // does the defence-in-depth re-verify per the trait contract.
    let image_path = crate::canonical_images_preflight::orchestrator_image_path(
        &spawn_ctx.install_dir,
        &spawn_ctx.kernel_version,
    );
    if !image_path.exists() {
        return Err(OrchestratorSpawnError::OrchestratorImageMissing {
            path: image_path,
        });
    }
    let verified_image = VerifiedImage {
        kind:      ImageKind::RootfsErofs,
        body:      ImageBody::Path(image_path),
        // The signature is verified at the kernel boot-time preflight
        // by digest; we hand a placeholder here for the trait contract
        // and the substrate's `spawn` impl re-verifies the digest.
        signature: ImageSignature(Vec::new()),
        image_id:  format!(
            "raxis-orchestrator-core-{kernel_version}",
            kernel_version = spawn_ctx.kernel_version,
        ),
    };

    // ── Step 2: rehydrate credential decls. ──────────────────────
    // The orchestrator session typically has no `[[tasks]]` row
    // (the kernel auto-creates it), so this read returns an empty
    // Vec. We still go through the uniform path for forward
    // compat. The read happens off the tokio worker via
    // `spawn_blocking` so the SQLite mutex stays sync.
    let store_for_read = Arc::clone(store);
    let session_id_for_read = session_id.to_owned();
    let credentials = tokio::task::spawn_blocking(move || -> Result<_, String> {
        let conn = store_for_read.lock_sync();
        kernel_lifecycle::read_task_credential_proxies_in_tx(&conn, &session_id_for_read)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| OrchestratorSpawnError::StoreRead(e.to_string()))?
    .map_err(OrchestratorSpawnError::StoreRead)?;

    // ── Step 3: build the spawn spec. ────────────────────────────
    // Egress tier is `Tier1Tproxy` for the Orchestrator: it has no
    // credential-proxy traffic of its own (the agent code that
    // consumes credentials runs in Executor VMs), but it MAY make
    // outbound LLM calls (gateway path) and so still needs the
    // tproxy admission gate.
    // V2_GAPS §B1 — stamp the planner UDS env contract into the
    // guest env so `raxis-planner-core::run_role_session` can
    // connect back. `RAXIS_KERNEL_PLANNER_SOCKET` is set when a
    // data_dir is configured.
    //
    // V2 `v2_extended_gaps.md §1.1` — additionally stamp
    // `RAXIS_PLANNER_TASK_PROMPT` unconditionally. The plan-side
    // validator (`parse_plan_orchestrator`) already rejected plans
    // whose `[workspace]` table omits or empty-strings
    // `description`, so by construction `task_prompt` is non-empty
    // here. We assert defensively — reaching this point with an
    // empty prompt indicates a parser regression and must surface
    // loudly in test builds rather than silently spawning an idle
    // orchestrator.
    debug_assert!(
        !task_prompt.is_empty(),
        "INV §1.1: parser guarantees non-empty [workspace] description; \
         reaching orchestrator spawn with an empty prompt is a parser bug",
    );
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    if let Some(data_dir) = &spawn_ctx.data_dir {
        let sock = data_dir.join("sockets").join("planner.sock");
        env.insert(
            "RAXIS_KERNEL_PLANNER_SOCKET".to_owned(),
            sock.display().to_string(),
        );
    }
    env.insert(PLANNER_TASK_PROMPT_ENV.to_owned(), task_prompt);
    let vm_spec = VmSpec {
        vcpu_count:       spawn_ctx.vcpu_count,
        mem_mib:          spawn_ctx.mem_mib,
        egress_tier:      EgressTier::Tier1Tproxy,
        cgroup_quota:     None,
        boot_args:        Vec::new(),
        entrypoint_argv:  vec![
            "/usr/local/bin/raxis-orchestrator".to_owned(),
            "--initiative-id".to_owned(),
            initiative_id.to_owned(),
        ],
        // Per-session token; the substrate stamps it into the
        // guest env under `RAXIS_SESSION_TOKEN`. Production wires
        // this from the V2 `sessions.session_token` column; we
        // use a deterministic-but-opaque shape here.
        session_token:    SessionToken(format!("orch-{}", session_id)),
        vsock_cid:        None,
        virtio_fs_mounts: Vec::new(),
        env,
    };

    let req = SpawnRequest {
        session_id:        session_id.to_owned(),
        task_id:           None, // orchestrator: no `[[tasks]]` row
        initiative_id:     initiative_id.to_owned(),
        image:             verified_image,
        workspace_mounts:  Vec::new(),
        vm_spec,
        credentials,
        admission_service: Box::new(PolicyAdmissionService::new(egress_allowlist)),
    };

    // ── Step 4: delegate. ─────────────────────────────────────────
    Ok(service.spawn_session(req).await?)
}

/// Tear down a previously-spawned Orchestrator VM. Returns the
/// substrate's exit summary; emits paired `SessionVmExited` +
/// `CredentialProxyStopped` audit events.
///
/// Idempotent at the bridge level: if the session has already been
/// terminated, the underlying call returns
/// `SpawnError::SessionNotActive` which the bridge surfaces verbatim.
async fn terminate_orchestrator(
    session_id: &str,
    grace:      std::time::Duration,
    service:    Arc<SessionSpawnService>,
) -> Result<TerminationReport, OrchestratorSpawnError> {
    Ok(service.terminate_session(session_id, grace).await?)
}

// ---------------------------------------------------------------------------
// Executor / Reviewer spawn — `spawn_executor_for_task` (free fn).
// ---------------------------------------------------------------------------

/// Resource-budget knobs for an Executor / Reviewer activation. Kept
/// alongside `OrchestratorSpawnContext` so callers can construct one
/// shared "spawn defaults" struct at boot. The path-templating logic
/// lives in `canonical_images_preflight`; this struct only supplies
/// the per-VM ceilings + the install-dir/kernel-version pair the
/// path templates need.
#[derive(Clone)]
pub struct ExecutorSpawnContext {
    /// Install dir from which the Executor-starter / Reviewer-core
    /// canonical images are resolved.
    pub install_dir:    PathBuf,
    /// Kernel version pinned per `system-requirements.md §1`.
    pub kernel_version: String,
    /// Default Executor VM resource budget.
    /// `host-capacity.md §4.1` — Executor budgets are sized for
    /// agent code, not orchestration. 2 vCPU / 1 GiB matches the
    /// reference deployment; operators override at boot when those
    /// policy keys land.
    pub executor_vcpu_count: u32,
    /// Memory ceiling in MiB for Executor VMs.
    pub executor_mem_mib:    u32,
    /// Default Reviewer VM resource budget — Reviewers run pure-
    /// static `ripgrep` / `read_file` workflows so the budget is
    /// smaller than the Executor's. Matches `planner-harness.md
    /// §4.2 Pure-Static Reviewer`.
    pub reviewer_vcpu_count: u32,
    /// Memory ceiling in MiB for Reviewer VMs.
    pub reviewer_mem_mib:    u32,
    /// V2_GAPS §B1 — kernel data-dir, used to derive the planner
    /// UDS socket path stamped into the guest env so
    /// `raxis-planner-core::run_role_session` can connect back via
    /// `RAXIS_KERNEL_PLANNER_SOCKET`. `None` ⇒ env var not stamped.
    pub data_dir: Option<PathBuf>,
}

impl ExecutorSpawnContext {
    /// Default Executor / Reviewer VM resource budgets. Pinned to
    /// match `host-capacity.md §4.1`; operators override at boot.
    pub fn new(install_dir: PathBuf, kernel_version: String) -> Self {
        Self {
            install_dir,
            kernel_version,
            executor_vcpu_count: 2,
            executor_mem_mib:    1024,
            reviewer_vcpu_count: 1,
            reviewer_mem_mib:    512,
            data_dir:            None,
        }
    }

    /// Builder: attach the kernel `data_dir` for planner-socket env
    /// stamping. See [`OrchestratorSpawnContext::with_data_dir`].
    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = Some(data_dir);
        self
    }
}

/// Which canonical image + budget profile to spawn for an
/// `IntentKind::ActivateSubTask` activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorAgentKind {
    /// Executor-starter image, larger resource budget. Requires
    /// `raxis-executor-starter-<kernel_version>.img` to be present.
    Executor,
    /// Reviewer-core image, smaller resource budget. Requires
    /// `raxis-reviewer-core-<kernel_version>.img` to be present.
    Reviewer,
}

/// Free-function helper: spawn the Executor / Reviewer VM for a
/// V2 sub-task activation directly through `SessionSpawnService`.
///
/// **Why a free function (not a trait).** The kernel already owns
/// `Arc<SessionSpawnService>` at every IPC handler call site
/// (`HandlerContext::session_spawn`). Adding a second
/// trait — analogous to [`OrchestratorSpawn`] — would just wrap
/// `service.spawn_session()` once more without giving fixtures a
/// distinct test seam (the existing
/// `Arc<dyn IsolationBackend>` already provides one). Per the V2
/// `executor-spawn-callsite` design note: the
/// activation handler calls this helper, which calls
/// `service.spawn_session()` directly. Production tests that need a
/// substrate fake wire `SubprocessIsolation`; in-process unit tests
/// wire `FailClosedTestIsolation` and assert on the spawn-error
/// surface.
///
/// **What this helper does:**
///   1. Resolves the canonical image path for `agent_kind`
///      (`raxis-executor-starter-<v>.img` or
///      `raxis-reviewer-core-<v>.img`).
///   2. Reads `task_credential_proxies` rows for `task_id` so the
///      `SessionSpawnService` can rehydrate per-session credential
///      proxies (`credential-proxy.md §3`).
///   3. Builds a `SpawnRequest` shaped per `extensibility-traits.md
///      §3.5` — Executor egress on `Tier1Tproxy` (full admission
///      enforcement) and Reviewer egress on `Tier0NoEgress` (the
///      Pure-Static Reviewer mandate, `INV-PLANNER-HARNESS-02`).
///   4. Delegates to `service.spawn_session(req).await` and
///      surfaces the resulting `SpawnHandle`.
///
/// **What this helper deliberately does NOT do:**
///   * Worktree provisioning. The kernel's intent handler is
///     responsible for calling
///     `raxis_worktree_provision::provision_executor` /
///     `provision_reviewer` BEFORE this helper, then passing the
///     materialised `WorkspaceMount` through `workspace_mounts`.
///   * Activation-FSM transitions. The handler updates the
///     `subtask_activations` row PendingActivation → Active under
///     the same SQL transaction as the `sessions` row update on
///     successful spawn.
///   * `evaluation_sha` plumbing for Reviewer activations. That
///     value lives on the activation row at this point; the helper
///     receives it through `extra_env` if needed.
///
/// **Egress tiering.** Reviewer VMs run with `EgressTier::None`
/// (no tap device in the guest, the substrate-layer enforcement
/// of `INV-NETISO-01`): any outbound TCP attempt is denied because
/// the guest has no network adapter. This matches
/// `policy-plan-authority.md §Reviewer authority` — the Reviewer
/// cannot make HTTP calls, gateway calls, or credential-proxy
/// calls because its only authorised output is `SubmitReview`
/// against an in-memory `evaluation_sha`. Executor VMs run with
/// `Tier1Tproxy` so the per-session admission listener arbitrates
/// every egress request against the active `EgressAllowlist`.
#[allow(clippy::too_many_arguments)]
pub async fn spawn_executor_for_task(
    spawn_ctx:        &ExecutorSpawnContext,
    agent_kind:       ExecutorAgentKind,
    session_id:       &str,
    task_id:          &str,
    initiative_id:    &str,
    egress_allowlist: EgressAllowlist,
    workspace_mounts: Vec<raxis_isolation::WorkspaceMount>,
    extra_env:        BTreeMap<String, String>,
    service:          Arc<SessionSpawnService>,
    store:            &Arc<Store>,
    // V2.5 §13 — operator-published `[[vm_images]]` override.
    // When `Some`, the spawn path uses this image instead of the
    // canonical Executor-starter / Reviewer-core. The activation
    // handler is responsible for resolving the alias against the
    // active policy, fetching the rootfs blob via
    // `ImageResolver`, and constructing the [`VerifiedImage`]
    // with the resolved path + the alias as `image_id`. Reviewer
    // tasks MUST NOT supply an override (the validator rejects
    // any `vm_image` on a Reviewer per
    // `INV-PLANNER-HARNESS-02`); this function still enforces
    // that defensively to avoid a regression upstream from
    // booting a non-canonical Reviewer.
    image_override:   Option<VerifiedImage>,
) -> Result<SpawnHandle, OrchestratorSpawnError> {
    // ── Step 1: resolve image path for the agent. ─────────────────
    //
    // V2.5: when the activation handler hands us an
    // `image_override`, that replaces the canonical-starter
    // resolution below. We still defensively reject overrides on
    // Reviewer kinds (operator-published Reviewer images are
    // structurally forbidden per `INV-PLANNER-HARNESS-02`).
    let verified_image = if let Some(override_img) = image_override {
        if matches!(agent_kind, ExecutorAgentKind::Reviewer) {
            return Err(OrchestratorSpawnError::Substrate(SpawnError::Audit(format!(
                "reviewer task `{task_id}` received an operator-published \
                 vm_image override `{image_id}`; the Reviewer image is \
                 kernel-canonical (INV-PLANNER-HARNESS-02). The plan-side \
                 validator should have rejected this; failing closed at \
                 spawn time.",
                image_id = override_img.image_id,
            ))));
        }
        override_img
    } else {
        let (image_path, image_id, missing_err): (PathBuf, String, fn(PathBuf) -> OrchestratorSpawnError) =
            match agent_kind {
                ExecutorAgentKind::Executor => {
                    let p = crate::canonical_images_preflight::executor_starter_image_path(
                        &spawn_ctx.install_dir,
                        &spawn_ctx.kernel_version,
                    );
                    (
                        p,
                        format!(
                            "raxis-executor-starter-{kernel_version}",
                            kernel_version = spawn_ctx.kernel_version,
                        ),
                        |path| OrchestratorSpawnError::ExecutorStarterImageMissing { path },
                    )
                }
                ExecutorAgentKind::Reviewer => {
                    let p = crate::canonical_images_preflight::reviewer_image_path(
                        &spawn_ctx.install_dir,
                        &spawn_ctx.kernel_version,
                    );
                    (
                        p,
                        format!(
                            "raxis-reviewer-core-{kernel_version}",
                            kernel_version = spawn_ctx.kernel_version,
                        ),
                        |path| OrchestratorSpawnError::ReviewerImageMissing { path },
                    )
                }
            };
        if !image_path.exists() {
            return Err(missing_err(image_path));
        }
        VerifiedImage {
            kind:      ImageKind::RootfsErofs,
            body:      ImageBody::Path(image_path),
            signature: ImageSignature(Vec::new()),
            image_id,
        }
    };

    // ── Step 2: rehydrate credential decls. ──────────────────────
    // `read_task_credential_proxies_in_tx` is keyed by `task_id`,
    // not `session_id`, because the `[[tasks.credentials]]` block
    // is plan-side configuration. Reviewer activations always
    // return an empty Vec (Pure-Static Reviewer cannot consume
    // credentials, `INV-PLANNER-HARNESS-02`); we still call through
    // the uniform path so a future regression in plan validation
    // does not silently slip past.
    let store_for_read = Arc::clone(store);
    let task_id_for_read = task_id.to_owned();
    let credentials = tokio::task::spawn_blocking(move || -> Result<_, String> {
        let conn = store_for_read.lock_sync();
        kernel_lifecycle::read_task_credential_proxies_in_tx(&conn, &task_id_for_read)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| OrchestratorSpawnError::StoreRead(e.to_string()))?
    .map_err(OrchestratorSpawnError::StoreRead)?;

    // Defense-in-depth: refuse any `[[tasks.credentials]]` decl
    // attached to a Reviewer task. The plan-side validator
    // (`raxis-plan-validator`) already rejects this combination
    // because the Reviewer image ships without a tproxy capable of
    // brokering credential-proxy upstreams; we re-check here so a
    // future plan-validator regression cannot silently boot a
    // Reviewer with credential bindings.
    if matches!(agent_kind, ExecutorAgentKind::Reviewer) && !credentials.is_empty() {
        return Err(OrchestratorSpawnError::Substrate(SpawnError::Audit(format!(
            "reviewer task `{task_id}` has {n} credential decl(s); \
             the Pure-Static Reviewer image cannot consume credentials \
             (planner-harness.md §INV-PLANNER-HARNESS-02)",
            n = credentials.len(),
        ))));
    }

    // ── Step 3: build the spawn spec. ────────────────────────────
    let (vcpu_count, mem_mib, egress_tier, entrypoint_argv) = match agent_kind {
        ExecutorAgentKind::Executor => (
            spawn_ctx.executor_vcpu_count,
            spawn_ctx.executor_mem_mib,
            EgressTier::Tier1Tproxy,
            vec![
                "/usr/local/bin/raxis-executor".to_owned(),
                "--task-id".to_owned(),
                task_id.to_owned(),
                "--initiative-id".to_owned(),
                initiative_id.to_owned(),
            ],
        ),
        ExecutorAgentKind::Reviewer => (
            spawn_ctx.reviewer_vcpu_count,
            spawn_ctx.reviewer_mem_mib,
            EgressTier::None,
            vec![
                "/usr/local/bin/raxis-reviewer".to_owned(),
                "--task-id".to_owned(),
                task_id.to_owned(),
                "--initiative-id".to_owned(),
                initiative_id.to_owned(),
            ],
        ),
    };

    // V2_GAPS §B1 — merge planner UDS env contract into `extra_env`
    // so the spawned planner binary can reach the kernel. The call
    // site (`handlers/intent.rs::handle_activate_subtask`) passes
    // `BTreeMap::new()` today; this is the single chokepoint that
    // owns the env stamp without forcing every IPC handler to know
    // the kernel's socket layout. Per `crates/planner-core/src/
    // driver.rs` Live-mode env contract, presence of
    // `RAXIS_KERNEL_PLANNER_SOCKET` is required for live mode but
    // absence of `RAXIS_PLANNER_TASK_PROMPT` keeps the binary in
    // scaffold/park mode — so populating only the socket here is
    // backward-compatible with every existing kernel test.
    let mut env = extra_env;
    if let Some(data_dir) = &spawn_ctx.data_dir {
        let sock = data_dir.join("sockets").join("planner.sock");
        env.entry("RAXIS_KERNEL_PLANNER_SOCKET".to_owned())
            .or_insert(sock.display().to_string());
    }
    let vm_spec = VmSpec {
        vcpu_count,
        mem_mib,
        egress_tier,
        cgroup_quota:     None,
        boot_args:        Vec::new(),
        entrypoint_argv,
        // Per-session token; the substrate stamps it into the
        // guest env under `RAXIS_SESSION_TOKEN`. Production wires
        // this from `sessions.session_token`; the trait round-trip
        // accepts a deterministic-but-opaque shape here.
        session_token:    SessionToken(format!(
            "{kind}-{session}",
            kind    = match agent_kind {
                ExecutorAgentKind::Executor => "exec",
                ExecutorAgentKind::Reviewer => "rev",
            },
            session = session_id,
        )),
        vsock_cid:        None,
        virtio_fs_mounts: Vec::new(),
        env,
    };

    let req = SpawnRequest {
        session_id:        session_id.to_owned(),
        task_id:           Some(task_id.to_owned()),
        initiative_id:     initiative_id.to_owned(),
        image:             verified_image,
        workspace_mounts,
        vm_spec,
        credentials,
        admission_service: Box::new(PolicyAdmissionService::new(egress_allowlist)),
    };

    // ── Step 4: delegate to `ctx.session_spawn`. ─────────────────
    Ok(service.spawn_session(req).await?)
}

#[cfg(test)]
mod tests {
    //! Inline tests for the kernel-side bridge.
    //!
    //! These tests exercise the full real path:
    //!
    //!   * Real `Store` opened against a tempfile SQLite DB.
    //!   * Real `CredentialProxyManager` with a real
    //!     `FileCredentialBackend`.
    //!   * Real `SessionSpawnService` (no fakes).
    //!   * Real `SubprocessIsolation` substrate.
    //!
    //! The only fake is `FakeAuditSink` — that's the same fake every
    //! kernel integration test uses.
    //!
    //! Why inline rather than under `kernel/tests/`: `raxis-kernel`
    //! is a bin-only crate, so integration tests under `tests/` cannot
    //! see the bridge's internal API. Inline tests get full module
    //! visibility and link against the production code path.
    //!
    //! These tests deliberately use a tempfile-built fake "image" to
    //! pass the canonical-image existence check; the substrate
    //! ignores image bytes (it boots /bin/cat as the "guest") so the
    //! fake bytes don't affect the trait round-trip the test
    //! exercises.

    use std::sync::{Arc, Mutex};

    use raxis_audit_tools::AuditEventKind;
    use raxis_credential_proxy_manager::CredentialProxyManager;
    use raxis_egress_admission::EgressAllowlist;
    use raxis_session_spawn::SessionSpawnService;
    use raxis_test_support::audit_sink::FakeAuditSink;
    use raxis_test_support::SubprocessIsolation;

    use super::*;

    // Process-global guard: `SubprocessIsolation::new` reads
    // `RAXIS_TEST_HARNESS=1`. Co-running tests in this module
    // serialise on this lock so the env-var flip can't race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn enable_test_harness() {
        unsafe { std::env::set_var("RAXIS_TEST_HARNESS", "1") };
    }

    fn write_canonical_image_fake(install_dir: &std::path::Path, kernel_version: &str) {
        let images = install_dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        std::fs::write(
            images.join(format!("raxis-orchestrator-core-{kernel_version}.img")),
            b"fake-orchestrator-image-bytes-for-test",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn live_orchestrator_spawn_full_round_trip_through_trait_surface() {
        let _g = ENV_LOCK.lock().unwrap();
        enable_test_harness();

        // ── Wire real SessionSpawnService over a real
        //    SubprocessIsolation + real CredentialProxyManager. ──
        let creds_dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(
            raxis_credentials_file::FileCredentialBackend::open_without_uid_check(
                creds_dir.path(),
            ),
        );
        let audit = Arc::new(FakeAuditSink::new());
        let proxy_manager = Arc::new(CredentialProxyManager::new(
            Arc::clone(&backend) as _,
            Arc::clone(&audit) as _,
        ));
        let isolation = Arc::new(
            SubprocessIsolation::new("kernel-orchestrator-bridge").unwrap(),
        );
        let service = Arc::new(SessionSpawnService::new(
            isolation as _,
            Arc::clone(&proxy_manager),
            Arc::clone(&audit) as _,
        ));

        // ── Real SQLite store. ─────────────────────────────────
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            raxis_store::Store::open(&store_dir.path().join("test.db")).unwrap(),
        );

        // ── Real install dir with a fake canonical image. ─────
        let install = tempfile::tempdir().unwrap();
        let kernel_version = "v2-test";
        write_canonical_image_fake(install.path(), kernel_version);

        let spawn_ctx = OrchestratorSpawnContext::new(
            install.path().to_path_buf(),
            kernel_version.to_owned(),
        );

        let allowlist = EgressAllowlist {
            exact_hosts: vec!["api.anthropic.com".into()],
            ..Default::default()
        };

        let session_id = "kernel-orch-test-1";
        let initiative_id = "init-kernel-orch-test-1";

        // Drive the production trait impl exactly as `handle_approve_plan` does.
        let live: Arc<dyn OrchestratorSpawn> = Arc::new(
            LiveOrchestratorSpawn::new(spawn_ctx, Arc::clone(&service), Arc::clone(&store))
        );
        let handle = live
            .spawn_for_initiative(
                session_id,
                initiative_id,
                allowlist,
                "fixture: drive the orchestrator agent for round-trip test"
                    .to_owned(),
            )
            .await
            .expect("orchestrator spawn");

        assert_eq!(handle.session_id, session_id);
        // Orchestrator has no credential decls -> empty loopback env.
        assert!(handle.loopback_env.is_empty());
        assert!(service.is_active(session_id).await);

        // ── Tear down. ────────────────────────────────────────
        let report = live
            .terminate_orchestrator(session_id, std::time::Duration::from_secs(2))
            .await
            .expect("terminate");
        assert_eq!(report.session_id, session_id);

        // ── Audit chain: paired SessionVmSpawned / SessionVmExited. ──
        let events = audit.events();
        let saw_spawn = events.iter().any(|e| match &e.kind {
            AuditEventKind::SessionVmSpawned { session_id: sid, .. } => sid == session_id,
            _ => false,
        });
        let saw_exit = events.iter().any(|e| match &e.kind {
            AuditEventKind::SessionVmExited { session_id: sid, .. } => sid == session_id,
            _ => false,
        });
        assert!(
            saw_spawn,
            "expected SessionVmSpawned for {session_id}; events: {:?}",
            events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
        );
        assert!(
            saw_exit,
            "expected SessionVmExited for {session_id}",
        );
    }

    #[tokio::test]
    async fn live_orchestrator_spawn_with_missing_canonical_image_surfaces_typed_error() {
        let _g = ENV_LOCK.lock().unwrap();
        enable_test_harness();

        let creds_dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(
            raxis_credentials_file::FileCredentialBackend::open_without_uid_check(
                creds_dir.path(),
            ),
        );
        let audit = Arc::new(FakeAuditSink::new());
        let proxy_manager = Arc::new(CredentialProxyManager::new(
            Arc::clone(&backend) as _,
            Arc::clone(&audit) as _,
        ));
        let isolation = Arc::new(
            SubprocessIsolation::new("kernel-orch-missing-image").unwrap(),
        );
        let service = Arc::new(SessionSpawnService::new(
            isolation as _,
            Arc::clone(&proxy_manager),
            Arc::clone(&audit) as _,
        ));
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            raxis_store::Store::open(&store_dir.path().join("test.db")).unwrap(),
        );

        // Empty install dir — image is intentionally missing.
        let install = tempfile::tempdir().unwrap();
        let spawn_ctx = OrchestratorSpawnContext::new(
            install.path().to_path_buf(),
            "v2-missing".to_owned(),
        );

        let live: Arc<dyn OrchestratorSpawn> = Arc::new(
            LiveOrchestratorSpawn::new(spawn_ctx, service, store),
        );
        let err = live
            .spawn_for_initiative(
                "sess-missing-1",
                "init-missing-1",
                EgressAllowlist::default(),
                "fixture: missing-image case".to_owned(),
            )
            .await
            .expect_err("must error when image missing");

        match err {
            OrchestratorSpawnError::OrchestratorImageMissing { path } => {
                assert!(path.ends_with("raxis-orchestrator-core-v2-missing.img"));
            }
            other => panic!("expected OrchestratorImageMissing; got {other:?}"),
        }
    }

    #[tokio::test]
    async fn noop_orchestrator_spawn_records_calls_and_returns_ok_without_substrate() {
        // The test fake must not require RAXIS_TEST_HARNESS — it
        // never touches a substrate. Verify it works without the
        // env-var flip that LiveOrchestratorSpawn needs.
        let fake = NoopOrchestratorSpawn::new();
        let dyn_fake: &dyn OrchestratorSpawn = &fake;

        let h1 = dyn_fake
            .spawn_for_initiative(
                "sess-A",
                "init-A",
                EgressAllowlist::default(),
                "fixture: orchestrator A".to_owned(),
            )
            .await
            .expect("fake spawn always Ok");
        assert_eq!(h1.session_id, "sess-A");
        assert!(h1.loopback_env.is_empty());

        let h2 = dyn_fake
            .spawn_for_initiative(
                "sess-B",
                "init-B",
                EgressAllowlist::default(),
                "Coordinate the migration".to_owned(),
            )
            .await
            .expect("fake spawn always Ok");
        assert_eq!(h2.session_id, "sess-B");

        let report = dyn_fake
            .terminate_orchestrator("sess-A", std::time::Duration::from_millis(1))
            .await
            .expect("fake terminate always Ok");
        assert_eq!(report.session_id, "sess-A");

        assert_eq!(
            fake.spawn_calls(),
            vec![
                (
                    "sess-A".to_owned(),
                    "init-A".to_owned(),
                    "fixture: orchestrator A".to_owned(),
                ),
                (
                    "sess-B".to_owned(),
                    "init-B".to_owned(),
                    "Coordinate the migration".to_owned(),
                ),
            ],
            "V2 §1.1 — fake must record the operator-authored seed prompt verbatim",
        );
        assert_eq!(fake.terminate_calls(), vec!["sess-A".to_owned()]);
    }

    /// V2_GAPS §B1 — `with_data_dir` is the only path through which
    /// the spawn helpers can derive the planner UDS env stamp. If
    /// the builder regresses (drops the path, ignores it, etc.) the
    /// guest binary loses its kernel transport and silently falls
    /// back to scaffold/park mode. Lock the contract here so the
    /// regression surfaces at compile/unit-test time rather than in
    /// a downstream live-e2e debugging session.
    #[test]
    fn orchestrator_spawn_context_with_data_dir_is_recorded() {
        let ctx = OrchestratorSpawnContext::new(
            std::path::PathBuf::from("/tmp/install"),
            "v2-test".to_owned(),
        );
        assert!(ctx.data_dir.is_none());
        let dd = std::path::PathBuf::from("/var/lib/raxis-test");
        let ctx = ctx.with_data_dir(dd.clone());
        assert_eq!(ctx.data_dir.as_ref(), Some(&dd));
        // Defaults survive the builder.
        assert_eq!(ctx.vcpu_count, 1);
        assert_eq!(ctx.mem_mib, 256);
    }

    #[test]
    fn executor_spawn_context_with_data_dir_is_recorded() {
        let ctx = ExecutorSpawnContext::new(
            std::path::PathBuf::from("/tmp/install"),
            "v2-test".to_owned(),
        );
        assert!(ctx.data_dir.is_none());
        let dd = std::path::PathBuf::from("/var/lib/raxis-test");
        let ctx = ctx.with_data_dir(dd.clone());
        assert_eq!(ctx.data_dir.as_ref(), Some(&dd));
        // Defaults survive the builder.
        assert_eq!(ctx.executor_vcpu_count, 2);
        assert_eq!(ctx.executor_mem_mib, 1024);
        assert_eq!(ctx.reviewer_vcpu_count, 1);
        assert_eq!(ctx.reviewer_mem_mib, 512);
    }
}
