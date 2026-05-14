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
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use raxis_egress_admission::{EgressAllowlist, PolicyAdmissionService};
use raxis_types::clock::unix_now_secs;
use raxis_isolation::{
    EgressTier, ImageBody, ImageSignature, SessionToken, VerifiedImage, VmSpec,
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
///
/// **V2.5 cleanup.** The canonical declaration moved to
/// [`raxis_types::planner_env::PLANNER_TASK_PROMPT_ENV`] so the
/// kernel and `raxis-planner-core` can share the wire contract via
/// `raxis-types` (the only crate both already depend on; pulling
/// `raxis-planner-core` into the kernel would drag `reqwest` and
/// the model HTTP path into the kernel build). This re-export
/// preserves every existing import path (`use
/// crate::session_spawn_orchestrator::PLANNER_TASK_PROMPT_ENV`).
pub use raxis_types::planner_env::PLANNER_TASK_PROMPT_ENV;

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
    /// V2 `elastic-vm-scaling.md §4.4` — per-role rolling window
    /// of recent utilisation samples. Consulted at spawn time so a
    /// run of consistently under-used Orchestrator sessions biases
    /// the next spawn smaller. Allowed regardless of the elastic
    /// flag (`§6` — never raises capacity).
    ///
    /// **Default** is a fresh empty tracker — when the host kernel
    /// boots without sharing one across the orchestrator and
    /// executor contexts, both windows fill independently. The
    /// `with_scale_down_history` builder lets `main.rs` /
    /// `ipc/context.rs` thread a single shared tracker through
    /// both spawn contexts so e.g. an Executor activation can
    /// read its own history alongside the orchestrator's.
    pub scale_down_history: Arc<crate::elastic::ScaleDownHistory>,
    /// V2 `elastic-vm-scaling.md §5` — sliding 60-second window
    /// of admitted scaling events. Consulted before a scale-down
    /// bias or a scale-up respawn lands; on overflow the
    /// decision is deferred via
    /// `SessionVmScaleDeferred { reason: "RateLimit" }`
    /// (INV-ELASTIC-04 — soft event).
    ///
    /// Default is a fresh empty limiter; production wires a
    /// shared `Arc` across both spawn contexts via
    /// `with_rate_limiter` so up- and down-events on the same
    /// host share the same budget.
    pub rate_limiter: Arc<crate::elastic::ScalingRateLimiter>,
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
            // The dev-host orchestrator-core initramfs image expands to
            // ~217 MiB in tmpfs (full Debian rootfs + planner binary);
            // the production EROFS image is much smaller but mem_mib
            // here MUST cover the worst-case dev image so the live-e2e
            // path doesn't OOM the guest kernel. 1 GiB leaves headroom
            // for the planner's tokio runtime, gateway streaming, and
            // the guest kernel's page cache. Operators override at
            // boot via the `[isolation] orchestrator_mem_mib` policy
            // key (when those keys land — for now this is the only
            // path).
            mem_mib:    1024,
            data_dir:   None,
            scale_down_history: Arc::new(crate::elastic::ScaleDownHistory::new()),
            rate_limiter:       Arc::new(crate::elastic::ScalingRateLimiter::new()),
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

    /// Builder: share an externally-owned scale-down tracker so
    /// the orchestrator and executor spawn contexts read /
    /// write the SAME windows. `main.rs` constructs ONE
    /// [`crate::elastic::ScaleDownHistory`] at boot and threads
    /// the same `Arc` through both contexts.
    pub fn with_scale_down_history(
        mut self,
        history: Arc<crate::elastic::ScaleDownHistory>,
    ) -> Self {
        self.scale_down_history = history;
        self
    }

    /// Builder: share an externally-owned rate limiter. See
    /// [`with_scale_down_history`](Self::with_scale_down_history).
    pub fn with_rate_limiter(
        mut self,
        rl: Arc<crate::elastic::ScalingRateLimiter>,
    ) -> Self {
        self.rate_limiter = rl;
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
    /// orchestrator agent (V2 `v2_extended_gaps.md §1.1`). The plan
    /// validator (`parse_plan_orchestrator`) rejects any plan whose
    /// `[plan.initiative]` block omits or empty-strings
    /// `description` with `LifecycleError::PlanInvalid`, so by
    /// construction `task_prompt` is **always non-empty** when
    /// reaching this trait. Implementations MUST unconditionally
    /// stamp it into the spawned VM's env table under
    /// [`PLANNER_TASK_PROMPT_ENV`] (`INV-DRIVER-01`); there is no
    /// scaffold-mode fallback and the driver treats absence as a
    /// hard error.
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
/// `Arc<SessionSpawnService>`, `Arc<Store>`,
/// `Arc<PlanRegistry>` (V2 §2.4 KSB assembly), and the policy
/// `ArcSwap` (V2 §2.5 token-cap stamping). Constructed once at
/// `main.rs` boot and cloned into `HandlerContext`.
pub struct LiveOrchestratorSpawn {
    ctx:           OrchestratorSpawnContext,
    service:       Arc<SessionSpawnService>,
    store:         Arc<Store>,
    plan_registry: Arc<crate::initiatives::PlanRegistry>,
    policy:        Arc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>>,
}

impl LiveOrchestratorSpawn {
    /// Construct the production impl.
    pub fn new(
        ctx:           OrchestratorSpawnContext,
        service:       Arc<SessionSpawnService>,
        store:         Arc<Store>,
        plan_registry: Arc<crate::initiatives::PlanRegistry>,
        policy:        Arc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>>,
    ) -> Self {
        Self { ctx, service, store, plan_registry, policy }
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
            // V2 `v2_extended_gaps.md §2.5` — read the live policy
            // snapshot once at the spawn boundary so token caps
            // honour the most recent operator-signed bundle.
            let policy_snapshot = self.policy.load_full();
            spawn_orchestrator_for_initiative(
                &self.ctx,
                session_id,
                initiative_id,
                egress_allowlist,
                task_prompt,
                Arc::clone(&self.service),
                &self.store,
                &self.plan_registry,
                &policy_snapshot,
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
                // Noop fake never bridges a real IPC stream — the
                // production bridging path (`drive_planner_stream`)
                // is exercised by the live-e2e harness, not by
                // unit tests against this fake.
                kernel_ipc_stream:  None,
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
    plan_registry:    &Arc<crate::initiatives::PlanRegistry>,
    policy:           &raxis_policy::PolicyBundle,
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
    // V2 SCHEMA_VERSION=3 — load the rootfs shape (EROFS vs.
    // initramfs cpio.gz) from the signed manifest. The substrate
    // dispatches on this to decide whether the .img bytes attach as
    // a virtio-blk device (EROFS) or as the boot loader's initial
    // ramdisk (initramfs). Falls back to RootfsErofs with a
    // structured warning when the manifest is missing or the trust
    // anchor is the all-zero placeholder; the substrate's own
    // `spawn` impl re-verifies the bytes either way.
    let (image_kind, _kind_is_trusted) =
        crate::canonical_images_preflight::resolve_image_kind_for_role(
            &image_path,
            raxis_canonical_images::CanonicalImageKind::Orchestrator,
            &spawn_ctx.kernel_version,
        );
    let verified_image = VerifiedImage {
        kind:      image_kind,
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

    // ── Step 2: rehydrate credential decls + session token AND assemble
    //    the KSB snapshot **concurrently**. Both are independent
    //    reads against the live store + plan registry; nothing in the
    //    KSB pipeline depends on the credentials or session token, and
    //    the token read does not depend on the KSB. We launch both as
    //    `spawn_blocking` futures and `tokio::join!` them so the second
    //    read does not pay for the first read's `spawn_blocking` task-
    //    launch round-trip on every spawn. The two tasks do contend for
    //    the SQLite mutex internally, but interleaving the two
    //    pipelines saves the per-spawn task-launch + scheduler-wakeup
    //    overhead (~1-3 ms) that used to be paid serially. The KSB
    //    assembly itself is the slower of the two (multiple queries +
    //    plan-registry reads), so co-scheduling it with the token read
    //    means the env-build phase sees the KSB ready as soon as the
    //    token comes back rather than starting its blocking round-trip
    //    only after token + env build complete.
    //
    // The session token is the CSPRNG-generated 64-char hex value
    // emitted by `raxis_crypto::token::generate_session_token` and
    // persisted to `sessions.session_token`. It is the SAME value
    // the kernel-mediated egress handler validates on every
    // `IpcMessage::PlannerFetchRequest` via
    // `authority::session::get_session_by_token`. Minting a
    // synthetic token at the spawn boundary (the V0 placeholder
    // shape `format!("orch-{session_id}")`) would put the planner
    // and the kernel out of sync — every egress fetch would fail
    // closed with `FAIL_SESSION_TOKEN_MISMATCH` and the planner
    // would never reach the LLM. The audit chain would log a
    // SessionVmSpawned event followed by an unbounded fetch-retry
    // storm, which is exactly the regression mode this read closes.
    //
    // The credential decls list is empty for the canonical
    // orchestrator session (no `[[tasks]]` row), but we still go
    // through the uniform path for forward compat with sessions
    // that gain credentials in V3.
    let token_read_fut = {
        let store_for_read      = Arc::clone(store);
        let session_id_for_read = session_id.to_owned();
        tokio::task::spawn_blocking(move || -> Result<_, String> {
            let conn = store_for_read.lock_sync();
            let creds = kernel_lifecycle::read_task_credential_proxies_in_tx(
                &conn,
                &session_id_for_read,
            )
            .map_err(|e| e.to_string())?;
            let token: String = conn
                .query_row(
                    "SELECT session_token FROM sessions WHERE session_id = ?1",
                    rusqlite::params![&session_id_for_read],
                    |row| row.get(0),
                )
                .map_err(|e| {
                    format!(
                        "session row missing for session_id {session_id_for_read}: {e}",
                    )
                })?;
            Ok((creds, token))
        })
    };
    // KSB assembly co-scheduled with the token read. Failure here
    // is non-fatal — the spawn proceeds with a fallback snapshot so
    // a transient SQLite lock contention does not block initiative
    // activation; the absence of the live KSB is logged in the
    // env-stamp branch below so an operator can correlate.
    // V2.7 `INV-KSB-MAX-TURNS-VISIBILITY-01` — resolve the per-session
    // planner turn ceiling here so the SAME value reaches both the
    // KSB capabilities projection (this spawn-blocking task) and the
    // `RAXIS_PLANNER_MAX_TURNS` env stamp emitted just below by
    // `populate_planner_max_turns_env`. The orchestrator passes
    // `task_fields = None` (per-initiative role, no per-task override).
    let (planner_max_turns_resolved, _) =
        resolve_planner_max_turns_for(None, policy.gateway());
    let ksb_fut = {
        let store_for_ksb     = Arc::clone(store);
        let registry_for_ksb  = Arc::clone(plan_registry);
        let initiative_owned  = initiative_id.to_owned();
        let session_owned     = session_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = store_for_ksb.lock_sync();
            crate::initiatives::ksb_assembly::assemble_ksb_snapshot(
                &*conn,
                &registry_for_ksb,
                &crate::initiatives::ksb_assembly::KsbInputs {
                    initiative_id: &initiative_owned,
                    task_id:       None,
                    role:          crate::initiatives::ksb_assembly::KsbRole::Orchestrator,
                    token_budget_remaining:        0,
                    wallclock_budget_remaining_s:  0,
                    credential_ports:              Vec::new(),
                    // Slice C — capabilities envelope identity. The
                    // orchestrator session_id is the row this spawn
                    // path is provisioning against and is stamped
                    // verbatim into `capabilities.session.session_id`.
                    session_id:                    &session_owned,
                    planner_max_turns:             planner_max_turns_resolved,
                },
            )
        })
    };
    let (token_join, ksb_join) = tokio::join!(token_read_fut, ksb_fut);
    let (credentials, session_token_db) = token_join
        .map_err(|e| OrchestratorSpawnError::StoreRead(e.to_string()))?
        .map_err(OrchestratorSpawnError::StoreRead)?;

    // ── Step 2b: V2 §Step 24b — host-side orchestrator worktree
    //    provisioning. Idempotent on respawn (re-attach to the
    //    existing per-initiative worktree). The path is keyed by
    //    `initiative_id` so a respawned orchestrator session
    //    inherits the previous session's tree (including any
    //    Executor commits already merged into it). The
    //    orchestrator-VM does NOT need /workspace mounted to do
    //    its job (its task is pure planning + IPC), but the
    //    orchestrator's worktree MUST exist on the host so:
    //
    //      * Executor / Reviewer activations can clone from it.
    //      * The IntegrationMerge handler can call
    //        `domain_git::commit_merge_to_target_ref` against it
    //        (passing it as `orch_worktree_root`).
    //
    //    The worktree_root + base_sha + base_tracking_ref are
    //    persisted into the orchestrator session row below so
    //    `pre_state.worktree_path` (set by
    //    `handlers::intent::run_phase_a` from
    //    `session.worktree_root`) resolves correctly at
    //    IntegrationMerge admission.
    let data_dir = spawn_ctx
        .data_dir
        .as_ref()
        .ok_or_else(|| OrchestratorSpawnError::StoreRead(
            "OrchestratorSpawnContext is missing data_dir; \
             worktree provisioning requires <data_dir>/repositories/main \
             to exist (boot wires data_dir via `with_data_dir`)".to_owned(),
        ))?
        .clone();
    let target_ref = plan_registry
        .orchestrator(initiative_id)
        .map(|o| o.target_ref)
        .unwrap_or_else(|| {
            crate::initiatives::OrchestratorPlanFields::DEFAULT_TARGET_REF.to_owned()
        });
    let initiative_owned = initiative_id.to_owned();
    let target_ref_owned = target_ref.clone();
    let data_dir_for_provision = data_dir.clone();
    let anchor = tokio::task::spawn_blocking(move || {
        crate::worktree_provisioning::provision_orchestrator_worktree(
            &data_dir_for_provision,
            &initiative_owned,
            &target_ref_owned,
        )
    })
    .await
    .map_err(|e| OrchestratorSpawnError::StoreRead(format!(
        "orchestrator worktree provisioning task join failed: {e}",
    )))?
    .map_err(|e| OrchestratorSpawnError::StoreRead(format!(
        "orchestrator worktree provisioning failed: {e}",
    )))?;

    // Persist the anchor onto the orchestrator session row so
    // the kernel-side IntegrationMerge handler reads
    // `session.worktree_root` consistently with where this
    // function provisioned. Best-effort within the spawn path —
    // a failure here would surface downstream as
    // `pre_state.worktree_path = ""` and IntegrationMerge would
    // reject with `FailPolicyViolation`; we surface it
    // structurally as `StoreRead` so the operator sees the
    // diagnostic immediately.
    {
        let store_for_update = Arc::clone(store);
        let session_id_for_update = session_id.to_owned();
        let worktree_root_str = anchor.worktree_root.display().to_string();
        let base_sha_str      = anchor.base_sha.clone();
        let tracking_ref_str  = anchor.base_tracking_ref.clone();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = store_for_update.lock_sync();
            conn.execute(
                "UPDATE sessions
                    SET worktree_root      = ?1,
                        base_sha           = ?2,
                        base_tracking_ref  = ?3
                  WHERE session_id = ?4",
                rusqlite::params![
                    worktree_root_str,
                    base_sha_str,
                    tracking_ref_str,
                    session_id_for_update,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| OrchestratorSpawnError::StoreRead(format!(
            "orchestrator session row update task join failed: {e}",
        )))?
        .map_err(|e| OrchestratorSpawnError::StoreRead(format!(
            "UPDATE sessions worktree_root failed: {e}",
        )))?;
    }

    // ── Step 3: build the spawn spec. ────────────────────────────
    // Egress tier is `EgressTier::None` for the Orchestrator. Per
    // the user-clarified invariant ("the Orchestrator has no
    // credential proxies and no egress"), the Orchestrator's job
    // is pure coordination: it issues `IntentRequest::ActivateSubTask`
    // and `IntentRequest::RetrySubTask` over the planner socket
    // and emits `StructuredOutput`. It MUST NOT reach external
    // services — both as principle of least privilege (R-5) and to
    // bound the prompt-injection blast radius. The credential
    // proxies that Executor sessions get are NEVER bound to the
    // Orchestrator's session.
    //
    // LLM calls reach the upstream provider via the kernel-mediated
    // egress path: `KernelMediatedHttpFetch` → planner socket →
    // `IpcMessage::PlannerFetchRequest` → kernel
    // `handlers::planner_fetch::handle` → gateway subprocess →
    // upstream (per `provider-failure-handling.md §2.1`).
    //
    // V2_GAPS §B1 — stamp the planner UDS env contract into the
    // guest env so `raxis-planner-core::run_role_session` can
    // connect back. `RAXIS_KERNEL_PLANNER_SOCKET` is set when a
    // data_dir is configured. (The AVF substrate stamps
    // `RAXIS_KERNEL_VSOCK_LISTEN_PORT` instead via
    // `raxis-isolation-apple-vz::config::translate`.)
    //
    // V2 `v2_extended_gaps.md §1.1` — additionally stamp
    // `RAXIS_PLANNER_TASK_PROMPT` unconditionally. The plan-side
    // validator (`parse_plan_orchestrator`) already rejected plans
    // whose `[plan.initiative]` table omits or empty-strings
    // `description`, so by construction `task_prompt` is non-empty
    // here. We assert defensively — reaching this point with an
    // empty prompt indicates a parser regression and must surface
    // loudly in test builds rather than silently spawning an idle
    // orchestrator.
    debug_assert!(
        !task_prompt.is_empty(),
        "INV §1.1: parser guarantees non-empty [plan.initiative] description; \
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
    // The task prompt is folded into the meta sidecar below
    // (`provision_meta_sidecar`) when a `data_dir` is available so
    // it stays out of the AVF cmdline budget. We hold the value
    // here and stamp the right channel after the sidecar attempt.
    let task_prompt_for_sidecar = task_prompt;

    // V2 `v2_extended_gaps.md §2.5` — stamp per-session LLM token
    // caps from `policy.budget.token_caps` into the guest env. The
    // in-VM dispatch loop reads them via `parse_u64_env` and folds
    // them into `DispatchConfig::max_tokens_*_total`. Absent caps
    // ⇒ env vars stay unset ⇒ uncapped on that axis.
    populate_token_cap_env(&mut env, policy.token_caps());
    populate_sleep_cap_env(&mut env, policy.sleep_caps());

    // V2.7 `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` — explicit env
    // stamp for the planner hard turn ceiling. Orchestrator spawns
    // pass `task_fields = None` (orchestrator is per-initiative,
    // not per-task) so the resolution short-circuits the per-task
    // arm and uses `[gateway].planner_max_turns_default` first,
    // then the compiled `DEFAULT_PLANNER_MAX_TURNS`. Pre-V2.7
    // kernel revisions inherited the value from the kernel's
    // parent process env which left a per-task override mechanism
    // structurally impossible — explicit stamp closes that gap.
    populate_planner_max_turns_env(
        &mut env,
        None,
        policy.gateway(),
        "<orchestrator>",
        session_id,
        initiative_id,
    );

    // V2 `v2_extended_gaps.md §2.4` — stamp the KSB snapshot we
    // co-scheduled at the top of this function into
    // `RAXIS_PLANNER_KSB`. The driver reads the env var and renders
    // it via `raxis_ksb::assemble_system_prompt(NNSP, snap)` so the
    // model sees authoritative kernel context inside the
    // `[RAXIS:KERNEL_STATE … :KERNEL_STATE_END]` delimiters every
    // turn. Failure of the assembly task is non-fatal — the spawn
    // proceeds with a fallback snapshot so a transient SQLite lock
    // contention does not block initiative activation; the absence
    // of the live KSB is logged here so an operator can correlate.
    let ksb_snapshot = ksb_join
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_else(|| {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"orchestrator_ksb_assembly_fallback\",\
                 \"initiative_id\":\"{initiative_id}\",\"session_id\":\"{session_id}\"}}",
            );
            crate::initiatives::ksb_assembly::fallback_snapshot(
                initiative_id,
                None,
                crate::initiatives::ksb_assembly::KsbRole::Orchestrator,
            )
        });
    let ksb_json = serde_json::to_string(&ksb_snapshot)
        .expect("KsbSnapshot is Serialize-derived; serialization cannot fail");
    // Prefer the virtiofs sidecar channel (small `RAXIS_PLANNER_KSB_PATH`
    // env, KSB JSON in a per-session file) for both the KSB and the
    // operator-authored task prompt so the AVF cmdline budget is not
    // consumed by the snapshot bytes. Falls back to the legacy inline
    // `RAXIS_PLANNER_KSB` / `RAXIS_PLANNER_TASK_PROMPT` envs when
    // there is no on-disk meta dir to write into (in-process tests
    // with `data_dir = None`). See `provision_meta_sidecar` for the
    // cmdline-overflow rationale.
    let meta_sidecar = provision_meta_sidecar(
        spawn_ctx.data_dir.as_deref(),
        session_id,
        Some(&ksb_json),
        Some(&task_prompt_for_sidecar),
    );
    let extra_workspace_mounts: Vec<raxis_isolation::WorkspaceMount> = match &meta_sidecar {
        Some(s) => {
            if let Some(p) = &s.ksb_guest_path {
                env.insert(raxis_ksb::PLANNER_KSB_PATH_ENV.to_owned(), p.clone());
            } else {
                env.insert(raxis_ksb::PLANNER_KSB_ENV.to_owned(), ksb_json.clone());
            }
            if let Some(p) = &s.task_prompt_guest_path {
                env.insert(
                    raxis_types::planner_env::PLANNER_TASK_PROMPT_PATH_ENV.to_owned(),
                    p.clone(),
                );
            } else {
                env.insert(
                    PLANNER_TASK_PROMPT_ENV.to_owned(),
                    task_prompt_for_sidecar.clone(),
                );
            }
            vec![s.mount.clone()]
        }
        None => {
            env.insert(raxis_ksb::PLANNER_KSB_ENV.to_owned(), ksb_json);
            env.insert(
                PLANNER_TASK_PROMPT_ENV.to_owned(),
                task_prompt_for_sidecar.clone(),
            );
            Vec::new()
        }
    };
    let vm_spec = VmSpec {
        vcpu_count:        spawn_ctx.vcpu_count,
        mem_mib:           spawn_ctx.mem_mib,
        // Orchestrator runs in `EgressTier::None` (no NIC, no
        // host-network access). Per the user-clarified invariant
        // and `kernel-mediated-egress.md`: "the Orchestrator has
        // no credential proxies and no egress" — its job is pure
        // coordination over the planner-socket IPC. LLM calls go
        // through `IpcMessage::PlannerFetchRequest` (kernel
        // dispatches to gateway), and INV-PROVIDER-04 ensures
        // every model client supports the
        // `KernelMediatedHttpFetch` substrate via the
        // `with_http_fetch` constructor.
        egress_tier:       EgressTier::None,
        cgroup_quota:      None,
        boot_args:         Vec::new(),
        entrypoint_argv:   vec![
            "/usr/local/bin/raxis-orchestrator".to_owned(),
            "--initiative-id".to_owned(),
            initiative_id.to_owned(),
        ],
        // Per-session token; the substrate stamps it into the
        // guest env under `RAXIS_SESSION_TOKEN`. Sourced from the
        // canonical `sessions.session_token` column inserted by
        // `lifecycle::approve_plan` (see Step 2 above) — same
        // 64-char hex value the kernel-mediated egress handler
        // re-validates on every `IpcMessage::PlannerFetchRequest`.
        session_token:     SessionToken(session_token_db.clone()),
        vsock_cid:         None,
        virtio_fs_mounts:  Vec::new(),
        // Host-canonical Linux kernel binary. The microVM substrates
        // (AVF, Firecracker) hand this to their boot loaders. The
        // SubprocessIsolation substrate ignores the field per the
        // `VmSpec::linux_kernel_path` contract.
        linux_kernel_path: crate::canonical_images_preflight::linux_kernel_path(
            &spawn_ctx.install_dir,
        ),
        env,
        guest_console_log: spawn_ctx
            .data_dir
            .as_ref()
            .map(|d| d.join("guests").join(session_id).join("console.log")),
    };

    // V2 §Step 24b — the Orchestrator gets `/workspace` mounted RW
    // off the per-initiative anchor we provisioned in Step 2b. The
    // orchestrator agent itself is a pure-coordination role — it
    // does not need to write files in the worktree to do its job
    // (it dispatches sub-tasks through the planner-IPC) — but the
    // mount lets the orchestrator plan the IntegrationMerge by
    // observing the same bytes the host kernel will fetch into
    // main at merge time, which keeps the agent / kernel views
    // coherent under prompt-injection-class anomalies.
    let orch_mount = raxis_isolation::WorkspaceMount {
        host_path:    anchor.worktree_root.clone(),
        guest_path:   raxis_worktree_staging::GUEST_WORKSPACE_PATH.to_owned(),
        mode:         raxis_isolation::MountMode::ReadWrite,
        content_hash: None,
    };
    let mut workspace_mounts = vec![orch_mount];
    workspace_mounts.extend(extra_workspace_mounts);

    // ── Step 3.5: consult the per-role scale-down history. ────────
    //
    // V2 `elastic-vm-scaling.md §4.4` — when the recent rolling
    // window of orchestrator sessions all reported low utilisation,
    // bias this spawn smaller. Allowed even when `elastic = false`
    // (`§6` — never raises capacity). The §5 rate limiter is
    // consulted INSIDE `maybe_apply_scale_down`; on overflow the
    // bias is silently skipped and `SessionVmScaleDeferred`
    // lands instead (INV-ELASTIC-04 — soft event).
    let (vm_spec, scale_down_decision) = maybe_apply_scale_down(
        vm_spec,
        crate::elastic::RoleKey::Orchestrator,
        &spawn_ctx.scale_down_history,
        &spawn_ctx.rate_limiter,
        policy.elastic(),
        service.audit(),
        session_id,
        None,
        initiative_id,
        &crate::elastic::PlanElasticOverrides::default(),
    );

    // ── Step 4: delegate via the bounded-retry helper. ────────────
    //
    // V2 `elastic-vm-scaling.md §3.2` — every kernel-side spawn is
    // wrapped in `spawn_with_transient_retry`. Transient failures
    // (per `IsolationError::classify`) are retried with exponential
    // backoff up to `policy.[elastic].transient_retry_max_attempts`;
    // permanent failures short-circuit to `SessionVmFailedFinal`.
    // Successful spawns still emit `SessionVmSpawned` from inside
    // `SessionSpawnService::spawn_session` (unchanged).
    let proto = SpawnRequestProto {
        session_id:       session_id.to_owned(),
        task_id:          None, // orchestrator: no `[[tasks]]` row
        initiative_id:    initiative_id.to_owned(),
        image:            verified_image,
        workspace_mounts,
        vm_spec,
        credentials,
        egress_allowlist,
    };
    let handle = spawn_with_transient_retry(
        &service,
        policy.elastic(),
        proto,
    ).await?;

    // ── Step 5: emit SessionVmScaleEvent on a successful down-bias.
    //
    // INV-ELASTIC-03 write-then-emit ordering: the new VM is
    // bound (SessionVmSpawned was emitted inside spawn_session),
    // and the scale event lands AFTER the spawn so audit replay
    // attributes the smaller spec to the §4.4 bias. On audit-emit
    // failure we log + clear the tracker (so a future spawn does
    // not also wedge on the same condition) and return Ok — the
    // VM is already running.
    if let Some((prev_vcpus, prev_mb, new_vcpus, new_mb, reason)) = scale_down_decision {
        if let Err(e) = crate::elastic::emit_scale_event_audit(
            service.audit(),
            session_id,
            None,
            initiative_id,
            crate::elastic::ScaleDirection::Down,
            prev_vcpus,
            new_vcpus,
            prev_mb,
            new_mb,
            &reason,
        ) {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"orchestrator_scale_down_audit_emit_failed\",\
                 \"session_id\":\"{session_id}\",\"error\":\"{e}\"}}",
            );
        }
        spawn_ctx.scale_down_history.clear(crate::elastic::RoleKey::Orchestrator);
    }

    Ok(handle)
}

/// Apply the §4.4 next-spawn down-bias to `vm_spec` when the
/// rolling window for `role` says the recent N sessions were
/// under-used AND the §5 rate limiter admits the new event.
///
/// Returns `(vm_spec_after_bias, Some((prev_vcpus, prev_mb,
/// new_vcpus, new_mb, reason)))` when the bias was applied, or
/// `(vm_spec_unchanged, None)` when the history did not justify
/// a bias OR the rate limiter deferred. In the rate-limit-defer
/// case the helper itself emits `SessionVmScaleDeferred { reason:
/// "RateLimit" }` so callers do not have to track the deferral
/// path separately (INV-ELASTIC-04 — soft event, no hard
/// failure).
///
/// **Why a free function** (rather than inlined): the orchestrator
/// and executor spawn paths share the exact same shape — consult,
/// rebuild, return + capture for the post-spawn audit emit. The
/// helper keeps both spawn paths aligned without duplicating the
/// logic.
#[allow(clippy::too_many_arguments)]
fn maybe_apply_scale_down(
    vm_spec:          VmSpec,
    role:             crate::elastic::RoleKey,
    history:          &Arc<crate::elastic::ScaleDownHistory>,
    rate_limiter:     &Arc<crate::elastic::ScalingRateLimiter>,
    elastic:          &raxis_policy::ElasticConfig,
    audit:            &Arc<dyn raxis_audit_tools::AuditSink>,
    session_id:       &str,
    task_id:          Option<&str>,
    initiative_id:    &str,
    plan:             &crate::elastic::PlanElasticOverrides,
) -> (VmSpec, Option<(u32, u32, u32, u32, String)>) {
    match crate::elastic::decide_scale_down(&vm_spec, elastic, plan, history.as_ref(), role) {
        crate::elastic::ScaleDecision::Apply {
            new_spec, prev_vcpus, new_vcpus,
            prev_memory_mb, new_memory_mb, reason, ..
        } => {
            // §5 rate-limit gate — INV-ELASTIC-04 soft deferral.
            // `clock::unix_now_secs()` returns `i64` (audit-chain
            // canon), the rate limiter takes `u64`. Unix seconds
            // are always positive, so saturating cast is safe.
            let now = unix_now_secs().max(0) as u64;
            match rate_limiter.try_admit(
                now,
                elastic.max_concurrent_scaling_events_per_minute,
            ) {
                crate::elastic::RateLimitDecision::Admit => (
                    new_spec,
                    Some((prev_vcpus, prev_memory_mb, new_vcpus, new_memory_mb, reason)),
                ),
                crate::elastic::RateLimitDecision::Defer => {
                    if let Err(e) = crate::elastic::emit_scale_deferred_audit(
                        audit,
                        session_id,
                        task_id,
                        initiative_id,
                        crate::elastic::ScaleDirection::Down,
                        "RateLimit",
                    ) {
                        eprintln!(
                            "{{\"level\":\"warn\",\"event\":\"scale_deferred_audit_emit_failed\",\
                             \"session_id\":\"{session_id}\",\"direction\":\"Down\",\
                             \"error\":\"{e}\"}}",
                        );
                    }
                    // Skip the bias for this spawn; the next tick
                    // re-evaluates the trigger.
                    (vm_spec, None)
                }
            }
        }
        crate::elastic::ScaleDecision::Skip { .. } => (vm_spec, None),
    }
}

/// **Drive the kernel ↔ guest IPC channel for a freshly-spawned
/// session.**
///
/// When the substrate hands the kernel a host-side IPC stream via
/// [`raxis_session_spawn::SpawnHandle::kernel_ipc_stream`] (today:
/// every microVM substrate that surrenders its per-session VSock fd
/// through [`raxis_isolation::Session::take_kernel_ipc_fd`]), the
/// kernel needs to start reading length-prefixed bincode
/// `IpcMessage` frames from it and routing them through the same
/// handler chain `accept_planner_loop` uses for UDS connections.
///
/// This function takes the stream out of the [`SpawnHandle`] (when
/// present) and spawns a detached tokio task that runs
/// [`crate::ipc::server::drive_planner_stream`] on it. The task
/// terminates naturally when the guest disconnects (clean EOF) or
/// when the host-side stream is dropped (e.g. on session
/// teardown). No join handle is retained — the dispatch loop does
/// not need to be cancelled explicitly because the only way to
/// outlive the session is to hold the stream, and the kernel never
/// shares it.
///
/// **Invariant.** Substrates that do NOT surrender an IPC fd
/// (subprocess substrate, where the planner dials the kernel's UDS
/// `planner.sock` directly) leave `kernel_ipc_stream = None`; this
/// function is a no-op in that case and the existing
/// `accept_planner_loop` handles the connection on the UDS side.
/// Calling this function is therefore safe regardless of substrate.
pub fn spawn_planner_dispatcher(
    handle: &mut SpawnHandle,
    ctx: Arc<crate::ipc::context::HandlerContext>,
) {
    let Some(stream) = handle.kernel_ipc_stream.take() else {
        return;
    };
    let session_id = handle.session_id.clone();
    tokio::spawn(async move {
        let dispatch_result = crate::ipc::server::drive_planner_stream(stream, Arc::clone(&ctx)).await;
        if let Err(e) = &dispatch_result {
            // Per the planner-dispatch logging convention, the
            // structured log keys on `step:"planner-dispatch"` so a
            // post-mortem can correlate a session_id to a dispatch
            // failure surfaced here. The substrate-level
            // `SessionVmExited` event is emitted independently when
            // the guest exits.
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"planner_dispatch_terminated\",\
                 \"session_id\":\"{session_id}\",\"error\":\"{err}\"}}",
                err = e,
            );
        }

        // V2 §Step 6 — finalize the session when the IPC channel
        // closes.
        //
        // `drive_planner_stream` returns when the planner-side
        // socket reaches EOF (clean disconnect after the planner's
        // PID 1 issues `LINUX_REBOOT_CMD_POWER_OFF`) or when the
        // first frame fails decode. In both cases the in-guest
        // execution tier is gone — the kernel must mark the
        // session row as revoked so:
        //
        //   1. A future planner that somehow obtains this token
        //      cannot replay it (`get_session_by_token` rejects
        //      `revoked = 1` rows in `handle_inner` Step 1).
        //   2. The orchestrator continuation re-spawn check in
        //      `respawn_orchestrator_for_initiative` (which keys on
        //      "is there a non-revoked orchestrator session for
        //      this initiative?") sees the prior session as gone
        //      and proceeds to spawn a successor.
        //
        // Idempotent: the SQL is `WHERE revoked = 0`, so a session
        // already revoked by an operator (`raxis sessions revoke`)
        // is a no-op here and the operator's `revoked_at` timestamp
        // is preserved verbatim.
        let store = Arc::clone(&ctx.store);
        let session_for_revoke = session_id.clone();
        let revoke_result = tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            conn.execute(
                "UPDATE sessions SET revoked = 1, revoked_at = ?1 \
                  WHERE session_id = ?2 AND revoked = 0",
                rusqlite::params![
                    raxis_types::clock::unix_now_secs(),
                    session_for_revoke,
                ],
            )
        })
        .await;

        match revoke_result {
            Ok(Ok(rows)) if rows > 0 => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"planner_session_revoked_on_exit\",\
                     \"session_id\":\"{session_id}\"}}",
                );
            }
            Ok(Ok(_))   => { /* already revoked — no-op, see comment above. */ }
            Ok(Err(e))  => eprintln!(
                "{{\"level\":\"warn\",\"event\":\"planner_session_revoke_failed\",\
                 \"session_id\":\"{session_id}\",\"error\":\"{err}\"}}",
                err = e,
            ),
            Err(e) => eprintln!(
                "{{\"level\":\"warn\",\"event\":\"planner_session_revoke_failed\",\
                 \"session_id\":\"{session_id}\",\"error\":\"join: {err}\"}}",
                err = e,
            ),
        }

        // ── V2 §Step 6 — post-exit recovery dispatch. ─────────────
        //
        // Two distinct recovery modes are folded into this single
        // post-revoke chokepoint, branched by the just-revoked
        // session's `session_agent_type`:
        //
        // **Mode A — Orchestrator post-exit respawn.**
        //
        // The Orchestrator is short-lived per decision: it boots,
        // calls one terminal DAG tool (`activate_subtask` /
        // `retry_subtask` / `integration_merge`), and exits. The
        // EarlyResponse dispatch in `handlers/intent.rs` already
        // handles the respawn for `CompleteTask` / `SubmitReview`
        // / `ReportFailure` (worker-tier intents that fire AFTER
        // the prior orchestrator already exited). But
        // `RetrySubTask` is fired BY the orchestrator itself — it
        // mints a fresh `subtask_activations` row in
        // `PendingActivation`, resets the executor's
        // `tasks.state = Admitted`, and exits. No worker intent
        // fires afterwards (the next executor only spawns when the
        // follow-up `ActivateSubTask` lands), so without a
        // post-exit hook here the chain DEAD-ENDS at the retry
        // edge: kernel CPU goes to 0% and the DAG silently stalls.
        //
        // The matching `IntegrationMerge` exit is also covered by
        // this hook for free — if it leaves nothing PendingActivation
        // (the normal terminal path), we skip; if it leaves the
        // initiative pending another sub-task (legal for
        // multi-merge plans), we respawn.
        //
        // Symptom this hook fixes (live e2e iter 6, after `c986e6d`
        // + `3e3605e` landed): every `RetrySubTaskAdmitted` event
        // landed cleanly, the orchestrator session exited via
        // `planner_session_revoked_on_exit`, and then NOTHING
        // happened. `sample(1)` of the kernel pid showed only
        // detached terminate_session tasks parked on the AVF
        // shutdown sync call (the `3e3605e` watchdog correctly
        // freed the retry handler workers); the orchestrator
        // workers were idle because no respawn was scheduled.
        //
        // **Guard.** Respawn only when ALL of:
        //   * The just-revoked session was an `Orchestrator`.
        //   * The session row carries a non-empty `initiative_id`
        //     (defensive — orchestrator rows are guaranteed to
        //     have one by `auto_spawn_orchestrator_session_in_tx`).
        //   * At least one `subtask_activations` row for the
        //     initiative is in `PendingActivation`. If every row
        //     is `Active` (worker is running) or terminal
        //     (Completed / Failed), the EarlyResponse dispatch on
        //     a worker terminal intent will eventually pick up
        //     the chain — no need to spawn a no-op orchestrator
        //     turn here.
        //
        // `respawn_orchestrator_for_initiative` is itself
        // idempotent on the active-orchestrator preflight, so even
        // if the EarlyResponse dispatch fires concurrently for a
        // late-arriving worker intent, only one respawn wins.
        // Errors are logged structurally and never propagate.
        //
        // **Mode B — Worker (Executor / Reviewer) premature-exit
        // failure synthesis.**
        //
        // The Executor / Reviewer contract is that the planner
        // dispatch loop ends by submitting a terminal intent —
        // `CompleteTask` / `SubmitReview` / `ReportFailure` — and
        // the EarlyResponse dispatch on that intent transitions the
        // task FSM (Running → Completed / Failed) AND triggers an
        // orchestrator respawn so the DAG can advance.
        //
        // But a planner CAN exit without submitting a terminal
        // intent. Documented failure modes that surface this:
        //
        //   * `DispatchOutcome::MaxTurnsExceeded` — the dispatch
        //     loop hit `RAXIS_PLANNER_MAX_TURNS` without selecting
        //     a terminal tool. `planner-executor` returns
        //     `PlannerError::MaxTurnsExceeded` (exit code 4) and
        //     PID 1 `reboot(POWER_OFF)`s the VM.
        //   * `DispatchOutcome::TokensExceeded` — the cumulative
        //     token-cap ceiling tripped. Exit code 6.
        //   * `DispatchOutcome::Idle` — the model emitted no tool
        //     call. Exit code 5.
        //   * Process death — the planner crashed (SIGSEGV / panic
        //     / OOM-killed), or the substrate observed an
        //     abnormal shutdown without a paired terminal intent.
        //
        // In every one of these cases the kernel-side state pre-
        // this-hook was:
        //
        //   * Session row: `revoked = 1` (the revoke step above).
        //   * Subtask activation row: still `Active` (no terminal
        //     intent fired, so the cascade in
        //     `transition_task_in_tx` never ran).
        //   * Task row: still `Admitted` or `Running`.
        //   * Orchestrator session: gone (the matching
        //     ActivateSubTask's orchestrator exited normally).
        //
        // The orchestrator post-exit hook's Mode-A guard
        // (`pending_exists && !active_exists`) is `false` because
        // the stranded `Active` activation row blocks the respawn.
        // No EarlyResponse dispatch fires because no terminal
        // intent arrives. The DAG deadlocks.
        //
        // Mode B closes the loop: when an Executor / Reviewer
        // session is revoked, the kernel synthesises the
        // `ReportFailure` shape — bumps `crash_retry_count`,
        // walks the FSM Admitted → Running → Failed (mirroring
        // `handle_report_failure`'s Admitted-fold), and triggers
        // an orchestrator respawn so the Orchestrator can decide
        // whether to `retry_subtask` (subject to
        // `max_crash_retries`) or settle the initiative as
        // `Blocked`.
        //
        // Symptom this hook fixes (live e2e iter25): the
        // `credential-substitution-canary` realistic-scenario
        // executor (parse `.env` → connect via credential proxy
        // → SELECT → write/commit → `task_complete`)
        // reproducibly hit `MaxTurnsExceeded` on natural tool-
        // error retry cycles; the executor VM exited with code 4
        // and the kernel went idle (0.0% CPU) waiting for an
        // orchestrator respawn that never arrived.
        //
        // **Guard.** Synthesise only when ALL of:
        //   * The just-revoked session was an `Executor` or
        //     `Reviewer`.
        //   * The session row carries a non-empty `initiative_id`.
        //   * There is exactly one `subtask_activations` row with
        //     `session_id = <this session>` and
        //     `activation_state = 'Active'` (defensive — the
        //     EarlyResponse dispatch on a normal terminal intent
        //     would have closed it, so an `Active` row here is
        //     proof the exit was premature).
        //   * The task's current state is `Admitted` or `Running`
        //     (anything terminal — Completed / Failed / Aborted /
        //     Cancelled — means the EarlyResponse dispatch did
        //     fire and we should not double-transition).
        //
        // Like Mode A, errors are logged structurally and never
        // propagate; the audit chain still has the matching
        // `SessionVmExited` from the substrate.
        let store_for_post_exit = Arc::clone(&ctx.store);
        let session_for_post_exit = session_id.clone();
        let preflight = tokio::task::spawn_blocking(
            move || -> Option<PostExitAction> {
                use raxis_store::Table;
                let mut conn = store_for_post_exit.lock_sync();
                let row: Option<(String, String)> = conn
                    .query_row(
                        &format!(
                            "SELECT session_agent_type, COALESCE(initiative_id, '') \
                               FROM {sessions} WHERE session_id = ?1",
                            sessions = Table::Sessions.as_str(),
                        ),
                        rusqlite::params![&session_for_post_exit],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                    )
                    .ok();
                let (agent_type, session_initiative_id) = row?;
                // Mode A (Orchestrator) requires `sessions.initiative_id` to
                // be populated — the orchestrator-spawn path always sets it.
                // Mode B (Executor/Reviewer), however, must NOT depend on
                // `sessions.initiative_id`: the executor-spawn path does
                // not currently populate the column, so the canonical
                // source of truth for the initiative binding of a worker
                // session is the `subtask_activations.initiative_id`
                // column on the row that holds this session_id (the
                // schema enforces `Active` rows always carry a non-null
                // `session_id`, and the row is created by the same
                // `activate_subtask` transaction that booted the VM).
                // Without this distinction Mode B never fires for the
                // realistic-scenario executors (iter27 reproduced the
                // exact iter15/iter20 deadlock — 4 sessions revoked,
                // 0 `worker_post_exit_respawn_trigger` events,
                // kernel CPU 0% with `Active` activation rows stranded).
                if agent_type
                    == raxis_types::SessionAgentType::Orchestrator.as_sql_str()
                {
                    let initiative_id = session_initiative_id;
                    if initiative_id.is_empty() {
                        return None;
                    }
                    // ── Mode A: Orchestrator post-exit respawn. ──
                    let pending_exists: bool = conn
                        .query_row(
                            &format!(
                                "SELECT 1 FROM {sa} \
                                   WHERE initiative_id   = ?1 \
                                     AND activation_state = 'PendingActivation' \
                                   LIMIT 1",
                                sa = Table::SubtaskActivations.as_str(),
                            ),
                            rusqlite::params![&initiative_id],
                            |_| Ok(true),
                        )
                        .unwrap_or(false);
                    let active_exists: bool = conn
                        .query_row(
                            &format!(
                                "SELECT 1 FROM {sa} \
                                   WHERE initiative_id   = ?1 \
                                     AND activation_state = 'Active' \
                                   LIMIT 1",
                                sa = Table::SubtaskActivations.as_str(),
                            ),
                            rusqlite::params![&initiative_id],
                            |_| Ok(true),
                        )
                        .unwrap_or(false);
                    // INV-RESPAWN-STORM: only respawn from post-exit hook
                    // when there is at least one PendingActivation AND
                    // NO Active worker. An Active worker's terminal
                    // intent (CompleteTask / SubmitReview / ReportFailure)
                    // will trigger an EarlyResponse respawn anyway, and
                    // letting both paths fire ends up in a respawn-storm
                    // when an LLM session keeps emitting rejected
                    // ActivateSubTask intents (live e2e iter 7 reproduced
                    // ~30 respawns in 90s with the unconditional version).
                    if pending_exists && !active_exists {
                        return Some(PostExitAction::OrchestratorRespawn { initiative_id });
                    }
                    return None;
                }

                // ── Mode B: worker (Executor/Reviewer) premature-exit
                //    failure synthesis. ─────────────────────────────
                let is_executor = agent_type
                    == raxis_types::SessionAgentType::Executor.as_sql_str();
                let is_reviewer = agent_type
                    == raxis_types::SessionAgentType::Reviewer.as_sql_str();
                if !(is_executor || is_reviewer) {
                    // Unknown agent type — defensively skip rather than
                    // risk synthesising a transition on an unsupported
                    // session class.
                    return None;
                }
                // Find the Active activation row bound to THIS session
                // (not just any active row on the initiative — a
                // sibling executor on the same initiative is its own
                // story). The activation row is also the canonical
                // source of truth for the worker's initiative binding
                // — `sessions.initiative_id` is empty on executor /
                // reviewer rows by current spawn-path convention, but
                // the activation row's `initiative_id` is NOT NULL by
                // schema and was set in the same transaction that
                // booted the VM.
                let row: Option<(String, String)> = conn
                    .query_row(
                        &format!(
                            "SELECT task_id, initiative_id FROM {sa} \
                               WHERE session_id      = ?1 \
                                 AND activation_state = 'Active' \
                               LIMIT 1",
                            sa = Table::SubtaskActivations.as_str(),
                        ),
                        rusqlite::params![&session_for_post_exit],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                    )
                    .ok();
                let (task_id, initiative_id) = row?;
                let task_state_str: String = conn
                    .query_row(
                        &format!(
                            "SELECT state FROM {tasks} WHERE task_id = ?1",
                            tasks = Table::Tasks.as_str(),
                        ),
                        rusqlite::params![&task_id],
                        |r| r.get::<_, String>(0),
                    )
                    .ok()?;
                let task_state = raxis_types::TaskState::from_sql_str(&task_state_str)?;
                if !matches!(
                    task_state,
                    raxis_types::TaskState::Admitted | raxis_types::TaskState::Running
                ) {
                    // Terminal — EarlyResponse already drove the FSM
                    // through its terminal transition.
                    return None;
                }

                // Perform the synthetic Failed transition in a single
                // SQLite transaction so the bump + FSM walk + activation-
                // row close commit atomically. Matches the
                // `handle_report_failure` shape verbatim.
                use crate::initiatives::task_transitions::{
                    transition_task_in_tx, TransitionActor,
                };
                let tx = match conn.transaction() {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!(
                            "{{\"level\":\"warn\",\
                             \"event\":\"worker_post_exit_synth_tx_open_failed\",\
                             \"session_id\":\"{sid}\",\"task_id\":\"{tid}\",\
                             \"error\":\"{err}\"}}",
                            sid = &session_for_post_exit,
                            tid = &task_id,
                            err = e,
                        );
                        return None;
                    }
                };
                if matches!(task_state, raxis_types::TaskState::Admitted) {
                    if let Err(e) = transition_task_in_tx(
                        &tx,
                        &task_id,
                        raxis_types::TaskState::Running,
                        None,
                        TransitionActor::Kernel,
                    ) {
                        eprintln!(
                            "{{\"level\":\"warn\",\
                             \"event\":\"worker_post_exit_synth_admitted_to_running_failed\",\
                             \"session_id\":\"{sid}\",\"task_id\":\"{tid}\",\
                             \"error\":\"{err}\"}}",
                            sid = &session_for_post_exit,
                            tid = &task_id,
                            err = e,
                        );
                        return None;
                    }
                }
                // V2 §Step 12 crash-retry bump — must land BEFORE the
                // Failed cascade closes the activation row.
                if let Err(e) = crate::handlers::intent::bump_executor_crash_retry_count_in_tx(
                    &tx,
                    &task_id,
                ) {
                    eprintln!(
                        "{{\"level\":\"warn\",\
                         \"event\":\"worker_post_exit_synth_crash_bump_failed\",\
                         \"session_id\":\"{sid}\",\"task_id\":\"{tid}\",\
                         \"error\":\"{err}\"}}",
                        sid = &session_for_post_exit,
                        tid = &task_id,
                        err = e,
                    );
                    // Continue: the FSM transition is the structural
                    // unstall; a missed counter increment is forensic.
                }
                let justification = format!(
                    "session_spawn_orchestrator: {role} VM exited without \
                     submitting a terminal intent (MaxTurnsExceeded / \
                     TokensExceeded / DispatchIdle / process death). \
                     Kernel synthesised Running → Failed so the orchestrator \
                     can decide retry_subtask vs. settle Blocked.",
                    role = if is_executor { "executor" } else { "reviewer" },
                );
                if let Err(e) = transition_task_in_tx(
                    &tx,
                    &task_id,
                    raxis_types::TaskState::Failed,
                    Some(justification.as_str()),
                    TransitionActor::Kernel,
                ) {
                    eprintln!(
                        "{{\"level\":\"warn\",\
                         \"event\":\"worker_post_exit_synth_failed_transition_failed\",\
                         \"session_id\":\"{sid}\",\"task_id\":\"{tid}\",\
                         \"error\":\"{err}\"}}",
                        sid = &session_for_post_exit,
                        tid = &task_id,
                        err = e,
                    );
                    return None;
                }
                if let Err(e) = tx.commit() {
                    eprintln!(
                        "{{\"level\":\"warn\",\
                         \"event\":\"worker_post_exit_synth_commit_failed\",\
                         \"session_id\":\"{sid}\",\"task_id\":\"{tid}\",\
                         \"error\":\"{err}\"}}",
                        sid = &session_for_post_exit,
                        tid = &task_id,
                        err = e,
                    );
                    return None;
                }
                eprintln!(
                    "{{\"level\":\"info\",\
                     \"event\":\"TaskFailedOnWorkerPrematureExit\",\
                     \"session_id\":\"{sid}\",\"task_id\":\"{tid}\",\
                     \"role\":\"{role}\"}}",
                    sid = &session_for_post_exit,
                    tid = &task_id,
                    role = if is_executor { "executor" } else { "reviewer" },
                );
                Some(PostExitAction::WorkerFailureRespawn {
                    initiative_id,
                    task_id,
                    role: if is_executor { "executor" } else { "reviewer" },
                })
            },
        )
        .await;

        match preflight {
            Ok(Some(PostExitAction::OrchestratorRespawn { initiative_id })) => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"orchestrator_post_exit_respawn_trigger\",\
                     \"session_id\":\"{session_id}\",\"initiative_id\":\"{initiative_id}\"}}",
                );
                // iter44 — pair the structured trigger log with a metric
                // increment labelled `respawn_kind=orchestrator_no_progress`
                // so the dashboard taxonomy disambiguates this from
                // VM-crash transient retries.
                crate::observability::record_isolation_respawn_attempted(
                    ctx.observability.as_ref(),
                    "kernel_post_exit",
                    "orchestrator",
                    crate::observability::RESPAWN_KIND_ORCHESTRATOR_NO_PROGRESS,
                    1,
                );
                respawn_orchestrator_for_initiative(&initiative_id, Arc::clone(&ctx)).await;
            }
            Ok(Some(PostExitAction::WorkerFailureRespawn {
                initiative_id,
                task_id,
                role,
            })) => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"worker_post_exit_respawn_trigger\",\
                     \"session_id\":\"{session_id}\",\"initiative_id\":\"{initiative_id}\",\
                     \"task_id\":\"{task_id}\",\"role\":\"{role}\"}}",
                );
                // iter44 — Mode-B premature-exit failure synthesis
                // also drives an orchestrator continuation respawn
                // (`respawn_orchestrator_for_initiative` below); count
                // it under the same `orchestrator_no_progress` lexeme
                // because from the dashboard's perspective it is the
                // same "the DAG would deadlock without us" pathology.
                crate::observability::record_isolation_respawn_attempted(
                    ctx.observability.as_ref(),
                    "kernel_post_exit",
                    "orchestrator",
                    crate::observability::RESPAWN_KIND_ORCHESTRATOR_NO_PROGRESS,
                    1,
                );
                respawn_orchestrator_for_initiative(&initiative_id, Arc::clone(&ctx)).await;
            }
            Ok(None) => { /* nothing to do */ }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"post_exit_preflight_join_failed\",\
                     \"session_id\":\"{session_id}\",\"error\":\"{err}\"}}",
                    err = e,
                );
            }
        }
    });
}

/// Internal: the action the post-exit hook decided to take after
/// reading the just-revoked session's bookkeeping. Returned from
/// the blocking preflight so the async-side dispatch can fire
/// `respawn_orchestrator_for_initiative` outside the SQLite mutex.
enum PostExitAction {
    /// Mode A — see `spawn_planner_dispatcher` comments.
    OrchestratorRespawn { initiative_id: String },
    /// Mode B — see `spawn_planner_dispatcher` comments.
    /// `role` is the string used in the structured log
    /// (`"executor"` / `"reviewer"`).
    WorkerFailureRespawn {
        initiative_id: String,
        task_id:       String,
        role:          &'static str,
    },
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
// V2 §Step 6 — Orchestrator continuation re-spawn after a DAG event.
// ---------------------------------------------------------------------------

/// **Re-spawn the canonical Orchestrator VM for an in-flight initiative
/// after a DAG-progressing lifecycle event.**
///
/// V2.4's Orchestrator is short-lived per decision: it boots, reads
/// the KSB, calls one of the terminal DAG tools (`activate_subtask` /
/// `retry_subtask` / `integration_merge`), submits the matching
/// intent, and exits cleanly. Each spawn handles exactly one DAG
/// edge — the orchestrator does NOT poll. The kernel is responsible
/// for re-spawning a fresh orchestrator session on every event that
/// can advance the DAG:
///
///   * `IntentKind::CompleteTask` accepted → an Executor task
///     transitioned `Running → Completed`. The next pending sub-task
///     may now be admissible, or (if the just-completed task had no
///     reviewers) the initiative may be ready for `integration_merge`.
///   * `IntentKind::SubmitReview` accepted with the cross-Reviewer
///     aggregator returning `AllPassed` → the predecessor Executor
///     task is fully approved. The orchestrator must decide whether
///     to activate the next sub-task or fast-forward
///     `integration_merge`.
///   * `IntentKind::ReportFailure` accepted → an Executor task
///     transitioned `Running → Failed`. The orchestrator may choose
///     to `retry_subtask` (subject to the operator-declared
///     `max_crash_retries` ceiling) or to give up and let the
///     initiative settle into a non-terminal `Blocked` state.
///
/// **Idempotent on concurrency.** The function aborts before spawning
/// when:
///
///   * The initiative is no longer `Executing` (a parallel
///     `OperatorRequest::AbortInitiative` won the race, or
///     `IntegrationMerge` already terminated the lifecycle).
///   * An Orchestrator session for `initiative_id` is already
///     present in `sessions` AND has neither been revoked nor
///     expired. The Orchestrator from the prior decision-cycle is
///     still mid-run; spawning a second one would race for the same
///     authority.
///
/// **Failure mode.** Errors are logged structurally on stderr but
/// never propagate — the caller already committed the lifecycle
/// transition that motivated the re-spawn. A re-spawn failure
/// leaves the initiative in a recoverable state (the operator can
/// retry via `OperatorRequest::AbortInitiative` + a fresh
/// `ApprovePlan`); refusing to log and swallow would mask the real
/// failure under a misleading SQL rollback.
///
/// Returns `Ok(Some(session_id))` on a successful spawn, `Ok(None)`
/// when the precondition checks elected to skip, and never panics.
pub async fn respawn_orchestrator_for_initiative(
    initiative_id: &str,
    ctx:           Arc<crate::ipc::context::HandlerContext>,
) -> Option<String> {
    use raxis_store::Table;
    use raxis_types::SessionAgentType;

    // ── Step 1: skip-checks. Both reads hit SQLite, so we hop onto
    //    the blocking pool for atomicity with the surrounding
    //    transaction model. The two reads share one mutex acquisition
    //    so we avoid an "is_executing flipped just after our second
    //    read" TOCTOU window — which would be benign here (we'd
    //    spawn a doomed orchestrator) but keeping the read in one
    //    transaction makes the preflight log unambiguous.
    let store_for_check = Arc::clone(&ctx.store);
    let init_for_check  = initiative_id.to_owned();
    let preflight = tokio::task::spawn_blocking(move || -> Result<(bool, bool), rusqlite::Error> {
        let conn = store_for_check.lock_sync();
        let is_executing: bool = conn.query_row(
            &format!(
                "SELECT state = 'Executing' FROM {init} WHERE initiative_id = ?1",
                init = Table::Initiatives.as_str(),
            ),
            rusqlite::params![&init_for_check],
            |r| r.get::<_, i64>(0).map(|v| v != 0),
        ).unwrap_or(false);

        // An orchestrator is "live" if there's a row with
        // session_agent_type='Orchestrator', initiative_id=this,
        // revoked=0, AND expires_at > now. Migration 18 stamps
        // `initiative_id` on coordinator rows so the lookup is O(1)
        // against the supporting index.
        let now = unix_now_secs();
        let active_orchestrator: bool = conn.query_row(
            &format!(
                "SELECT 1 FROM {sessions}
                  WHERE initiative_id     = ?1
                    AND session_agent_type = ?2
                    AND revoked            = 0
                    AND expires_at         > ?3
                  LIMIT 1",
                sessions = Table::Sessions.as_str(),
            ),
            rusqlite::params![
                &init_for_check,
                SessionAgentType::Orchestrator.as_sql_str(),
                now,
            ],
            |_| Ok(true),
        ).unwrap_or(false);
        Ok((is_executing, active_orchestrator))
    })
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or((false, false));

    let (is_executing, active_orchestrator) = preflight;
    if !is_executing {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"orchestrator_respawn_skipped\",\
             \"initiative_id\":\"{initiative_id}\",\"reason\":\"not_executing\"}}",
        );
        return None;
    }

    // ── Step 1b: `INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01` ──────────
    //
    // Increment the per-initiative
    // `orchestrator_no_progress_respawn_count` and compare against
    // `MAX_ORCH_NO_PROGRESS_RESPAWNS` (default 3). The counter resets
    // to zero on every legal task FSM transition (see
    // `initiatives::task_transitions::transition_task_in_tx` end-of-
    // function reset hook), so honest DAG progress always clears the
    // loop counter. A clean orchestrator exit on a kernel-rejected
    // intent (e.g. `RetrySubTaskRejectedNotRetryable` per
    // `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`) keeps the
    // counter and walks it toward the ceiling.
    //
    // On exceedance, three writes land in ONE SQLite transaction:
    //   1. INSERT escalations (class='LogicalDeadlock', initiator='Kernel')
    //      via `orch_respawn_ceiling::insert_logical_deadlock_escalation_in_tx`
    //      so the operator can either approve a counter-reset retry or
    //      deny and preserve the Failed terminal state
    //      (`INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01`).
    //   2. UPDATE initiatives SET state='Failed', completed_at=now
    //      (`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`).
    //   3. (already done by step 0: increment counter)
    //
    // Order matters: escalation INSERT before initiatives UPDATE so the
    // operator-actionable surface lands before the terminal-state
    // marker. A crash between either pair leaves the store internally
    // consistent — both rolled back, never half-applied.
    let policy_epoch_for_escalation: i64 = ctx
        .policy
        .load_full()
        .epoch() as i64;
    let escalation_timeout_secs = ctx
        .policy
        .load_full()
        .escalation_timeout()
        .as_secs() as i64;
    let store_for_ceiling   = Arc::clone(&ctx.store);
    let init_for_ceiling    = initiative_id.to_owned();
    let ceiling_outcome = tokio::task::spawn_blocking(move || -> Result<
        Option<(crate::orch_respawn_ceiling::CeilingOutcome, Option<String>)>,
        rusqlite::Error,
    > {
        let mut conn = store_for_ceiling.lock_sync();
        let tx = conn.transaction()?;
        let outcome = crate::orch_respawn_ceiling::increment_no_progress_count_in_tx(
            &tx, &init_for_ceiling,
        )?;
        let mut escalation_id: Option<String> = None;
        if let crate::orch_respawn_ceiling::CeilingOutcome::Exceeded {
            count_after_increment, ..
        } = outcome
        {
            // Step 1 of the paired-write order
            // (`INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01`): create the
            // operator-actionable escalation row before the terminal
            // initiative-state flip so the operator UI is non-empty
            // for any reader who races the ceiling event. The
            // `last_intent_kind` / `last_rejection_reason` placeholder
            // values are the structurally-by-construction values for
            // the iter42 pathology (the only loop class this ceiling
            // can reach in V2.5b is "rejected RetrySubTask while
            // aggregate=Pending"); the audit chain immediately
            // preceding this event carries the wire-exact
            // `IntentRejected` rows for forensic readers.
            // TODO(post-iter44): per-session "last rejected intent"
            // tracking so we can fill these in at admission time
            // rather than relying on the audit-chain join.
            let now_secs = unix_now_secs();
            let timeout_at = now_secs.saturating_add(escalation_timeout_secs);
            // Window-secs approximation: the spec asks for the
            // wall-clock window from the FIRST no-progress respawn
            // through the ceiling-exceedance respawn. We approximate
            // by reading `initiatives.created_at` minus `now` —
            // strictly an upper bound (the ceiling could have been
            // reached after honest progress earlier), but the
            // operator UI wants a "this loop has been running for ~X
            // minutes" rough number, not a precise wall-clock.
            let window_secs: u64 = tx.query_row(
                &format!(
                    "SELECT COALESCE(strftime('%s','now') - created_at, 0)
                       FROM {init} WHERE initiative_id = ?1",
                    init = raxis_store::Table::Initiatives.as_str(),
                ),
                rusqlite::params![&init_for_ceiling],
                |r| r.get::<_, i64>(0),
            )
            .map(|secs| secs.max(0) as u64)
            .unwrap_or(0);

            escalation_id = crate::orch_respawn_ceiling::insert_logical_deadlock_escalation_in_tx(
                &tx,
                &init_for_ceiling,
                count_after_increment,
                window_secs,
                "RetrySubTask",
                "RetrySubTaskRejectedNotRetryable",
                timeout_at,
                now_secs,
                policy_epoch_for_escalation,
            )?;

            // Step 2: mark the initiative `Failed` per
            // `InitiativeState::Failed` (`fsm.rs`). The on-the-wire
            // reason ("orchestrator no-progress respawn ceiling
            // exceeded") lives in the `OrchestratorRespawnCeilingExceeded`
            // audit event the caller emits post-commit — the
            // `initiatives` table itself does not carry a
            // `failure_reason` column at the V2 baseline schema
            // (kernel-store.md §2.5.1 Table 2). The dashboard's
            // failure-surface joins `initiatives.state = 'Failed'`
            // against the chain-side audit row for the operator-
            // facing string.
            tx.execute(
                &format!(
                    "UPDATE {init}
                        SET state        = 'Failed',
                            completed_at = strftime('%s','now')
                      WHERE initiative_id = ?1",
                    init = raxis_store::Table::Initiatives.as_str(),
                ),
                rusqlite::params![&init_for_ceiling],
            )?;
        }
        tx.commit()?;
        Ok(Some((outcome, escalation_id)))
    })
    .await
    .ok()
    .and_then(Result::ok)
    .flatten();

    let (ceiling_outcome, escalation_id_opt) = match ceiling_outcome {
        None => (None, None),
        Some((o, eid)) => (Some(o), eid),
    };
    let _ = escalation_id_opt; // chain-side audit anchor; surfaced via the audit event below.

    match ceiling_outcome {
        None => {
            eprintln!(
                "{{\"level\":\"warn\",\
                 \"event\":\"orchestrator_respawn_ceiling_check_failed\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"reason\":\"sql_error_treated_as_fail_closed\"}}",
            );
            return None;
        }
        Some(crate::orch_respawn_ceiling::CeilingOutcome::Exceeded {
            count_after_increment, max_attempts,
        }) => {
            eprintln!(
                "{{\"level\":\"error\",\
                 \"event\":\"orchestrator_respawn_ceiling_exceeded\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"attempts\":{count_after_increment},\
                 \"max_attempts\":{max_attempts}}}",
            );
            // Audit emission is the chain-side half of the paired
            // write. The SQLite-side state mutation
            // (`initiatives.state = 'Failed' + failure_reason`)
            // already committed in the spawn_blocking above; this
            // emission runs post-commit per `audit-paired-writes.md
            // §4`. A crash between commit + emit leaves a
            // consistent SQLite state (`Failed`, no further
            // respawns) with a missing audit anchor; the recovery
            // sweep is advisory per `INV-AUDIT-PAIRED-06`.
            if let Err(e) = ctx.audit.emit(
                raxis_audit_tools::AuditEventKind::OrchestratorRespawnCeilingExceeded {
                    initiative_id: initiative_id.to_owned(),
                    attempts:      count_after_increment,
                    max_attempts,
                },
                None,
                None,
                Some(initiative_id),
            ) {
                eprintln!(
                    "{{\"level\":\"warn\",\
                     \"event\":\"OrchestratorRespawnCeilingExceededAuditEmitFailed\",\
                     \"initiative_id\":\"{initiative_id}\",\
                     \"error\":\"{e}\"}}",
                );
            }
            return None;
        }
        Some(crate::orch_respawn_ceiling::CeilingOutcome::Permitted {
            count_after_increment,
        }) => {
            eprintln!(
                "{{\"level\":\"info\",\
                 \"event\":\"orchestrator_no_progress_respawn_count_incremented\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"count\":{count_after_increment},\
                 \"max\":{max}}}",
                max = crate::orch_respawn_ceiling::MAX_ORCH_NO_PROGRESS_RESPAWNS,
            );
        }
    }

    if active_orchestrator {
        // Common case for tightly-clustered DAG events — e.g. the
        // executor's `task_complete` admission, then a reviewer's
        // `submit_review` admission, fire within milliseconds and
        // the prior orchestrator session has not been revoked yet.
        // The next reviewer/executor admission will trigger another
        // re-spawn check; if THAT one finds no live orchestrator,
        // it picks up the work.
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"orchestrator_respawn_skipped\",\
             \"initiative_id\":\"{initiative_id}\",\
             \"reason\":\"orchestrator_already_active\"}}",
        );
        return None;
    }

    // ── Step 2: read the operator-authored task prompt for this
    //    initiative's orchestrator. The plan registry is the
    //    canonical V2 source — `approve_plan` populated it from the
    //    signed plan TOML's `[plan.initiative].description` field.
    //    A miss here means the registry forgot the entry, which is
    //    structurally impossible for an `Executing` initiative
    //    (`repopulate_plan_registry` would have re-loaded it on a
    //    kernel restart) — log + skip rather than fabricate one.
    let task_prompt = match ctx.plan_registry.orchestrator(initiative_id) {
        Some(orch) if !orch.description.is_empty() => orch.description,
        Some(_) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"orchestrator_respawn_skipped\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"reason\":\"empty_orchestrator_prompt\"}}",
            );
            return None;
        }
        None => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"orchestrator_respawn_skipped\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"reason\":\"plan_registry_miss\"}}",
            );
            return None;
        }
    };

    // ── Step 3: mint a fresh Orchestrator session row keyed to the
    //    same initiative_id. Migration 18 keeps the back-edge so
    //    `IntentKind::StructuredOutput` from the new session routes
    //    to the same initiative-scoped path. Each re-spawn owns a
    //    new lineage (the orchestrator session is the root of a
    //    fresh lineage tree per decision-cycle, mirroring
    //    `auto_spawn_orchestrator_session_in_tx`).
    let store_for_insert = Arc::clone(&ctx.store);
    let init_for_insert  = initiative_id.to_owned();
    let new_session = tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
        use raxis_types::SessionId;

        let session_id_s = SessionId::new_v4().as_str().to_owned();
        let lineage_id   = uuid::Uuid::new_v4().to_string();
        let session_token = match raxis_crypto::token::generate_session_token() {
            Ok(t)  => t,
            Err(_) => return Ok(None),
        };
        let now_secs   = unix_now_secs();
        let expires_at = now_secs + 86_400;

        let conn = store_for_insert.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {sessions} (
                    session_id, role_id, session_token, sequence_number,
                    worktree_root, base_sha, base_tracking_ref,
                    lineage_id, fetch_quota, created_at, expires_at, revoked,
                    session_agent_type, can_delegate, initiative_id
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,?12,1,?13)",
                sessions = Table::Sessions.as_str(),
            ),
            rusqlite::params![
                session_id_s,
                "Planner",
                session_token,
                0i64,
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
                lineage_id,
                1000i64,
                now_secs,
                expires_at,
                SessionAgentType::Orchestrator.as_sql_str(),
                init_for_insert,
            ],
        )?;
        Ok(Some(session_id_s))
    })
    .await;

    let new_session_id = match new_session {
        Ok(Ok(Some(id))) => id,
        Ok(Ok(None)) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"orchestrator_respawn_failed\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"stage\":\"token_rng\"}}",
            );
            return None;
        }
        Ok(Err(e)) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"orchestrator_respawn_failed\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"stage\":\"insert_session\",\"error\":\"{e}\"}}",
            );
            return None;
        }
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"orchestrator_respawn_failed\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"stage\":\"spawn_blocking\",\"error\":\"{e}\"}}",
            );
            return None;
        }
    };

    // ── Step 4: substrate spawn. Mirror the post-commit boot in
    //    `OperatorRequest::ApprovePlan` (`ipc/operator.rs` lines
    //    1397+). Egress allowlist comes from the live policy
    //    snapshot so a credential rotation between admission and
    //    re-spawn is observed.
    let policy_snapshot = ctx.policy.load_full();
    // V2 reviewer-egress-defaults-decision.md §5: the Tier-1
    // transparent-proxy admission service receives the EFFECTIVE
    // allowlist (operator `[egress] domains` ∪ implicit-provider
    // FQDNs). Mirrors the gateway URL allowlist so direct VM
    // egress and kernel-mediated fetches share one source of
    // truth and an executor reaching `api.anthropic.com` succeeds
    // without an explicit `[egress]` entry.
    let allowlist = raxis_egress_admission::EgressAllowlist {
        exact_hosts: policy_snapshot.effective_egress_domains(),
        patterns:    policy_snapshot.effective_egress_patterns(),
        credential_proxy_real_targets: Default::default(),
    };

    match ctx
        .orchestrator_spawn
        .spawn_for_initiative(
            new_session_id.as_str(),
            initiative_id,
            allowlist,
            task_prompt,
        )
        .await
    {
        Ok(mut handle) => {
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"orchestrator_respawn_ok\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"session_id\":\"{session_id}\",\
                 \"kernel_ipc_bridged\":{bridged}}}",
                session_id = handle.session_id,
                bridged    = handle.kernel_ipc_stream.is_some(),
            );
            // Same dispatcher wiring as the approve_plan boot path —
            // the substrate-surrendered IPC stream needs a tokio
            // task driving `drive_planner_stream` so the new
            // orchestrator's intents reach the kernel.
            spawn_planner_dispatcher(&mut handle, Arc::clone(&ctx));
            Some(handle.session_id)
        }
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"orchestrator_respawn_failed\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"session_id\":\"{session_id}\",\
                 \"stage\":\"substrate_spawn\",\"error\":\"{err}\"}}",
                session_id = new_session_id,
                err        = e,
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// KSB virtiofs sidecar — writes `ksb.json` to a per-session
// host directory and returns the matching `WorkspaceMount` +
// guest-side path env value the caller stamps into `spec.env` /
// `workspace_mounts`. Pinned by `raxis_ksb::PLANNER_KSB_PATH_ENV`.
// ---------------------------------------------------------------------------

/// Per-session sidecar provisioning result. The mount is shared
/// between the KSB JSON file and the task-prompt file (both live
/// under `<data_dir>/guests/<session_id>/meta/` on the host and
/// surface as `/raxis-meta/<filename>` inside the guest), so the
/// substrate only ever sees a single virtiofs share entry per
/// session for kernel-injected metadata.
struct MetaSidecar {
    /// One read-only virtiofs mount carrying every meta file the
    /// kernel writes. Always present when this struct is returned.
    mount: raxis_isolation::WorkspaceMount,

    /// Guest-visible absolute path of the KSB JSON file when the
    /// caller asked for one. Stamped into
    /// `RAXIS_PLANNER_KSB_PATH`.
    ksb_guest_path: Option<String>,

    /// Guest-visible absolute path of the task-prompt file when
    /// the caller asked for one. Stamped into
    /// `RAXIS_PLANNER_TASK_PROMPT_PATH`.
    task_prompt_guest_path: Option<String>,
}

/// Provision the per-session metadata sidecar — the single virtiofs
/// share that carries the kernel-projected KSB snapshot AND the
/// operator-authored task prompt out of the AVF cmdline budget.
///
/// **Why a sidecar.** The Apple-VZ substrate lacks a `Command::env`
/// analogue and folds every `VmSpec::env` entry into the Linux
/// `/proc/cmdline` as a single base64-encoded `raxis.envb64=<b64>`
/// token. Linux's `COMMAND_LINE_SIZE` ceiling on aarch64 (default
/// 2048 bytes) silently truncates anything past that boundary,
/// including the trailing `-- --task-id <ID> --initiative-id <ID>`
/// argv tail the planner binary needs to boot. Two payload classes
/// historically blew the budget:
///
///   * the reviewer's per-initiative KSB JSON (~1 KiB once the DAG
///     view lands), and
///
///   * the executor's operator-authored task prompt (the realistic
///     scenario's `materializer.md` / `service_round_trip.md` /
///     `transparent_proxy_real_scripts.md` are 2.7–6.9 KiB which
///     after base64 expansion (4/3 + delimiter) reliably exceeds
///     2048 bytes on its own — every other env axis is incidental).
///
/// Both classes are now routed through a per-session virtiofs file
/// under `<data_dir>/guests/<session_id>/meta/` mounted read-only at
/// [`raxis_ksb::PLANNER_KSB_GUEST_MOUNT`] (`/raxis-meta`). The env
/// payload then carries only the tiny `…_PATH=/raxis-meta/<name>`
/// pointers (~40 bytes each) plus the substrate-default keys —
/// well under the 2048-byte ceiling regardless of prompt size.
///
/// **Driver-side fallback.** Both the KSB and the task prompt have
/// matching legacy inline env vars ([`raxis_ksb::PLANNER_KSB_ENV`]
/// and `RAXIS_PLANNER_TASK_PROMPT`). The driver
/// (`raxis-planner-core::driver::run_role_session_with_env_fn`)
/// prefers the `…_PATH` channel when set and falls back to the
/// inline env, so subprocess-isolation tests with `data_dir = None`
/// and pre-sidecar kernel revisions keep working unchanged.
///
/// **Idempotency.** Repeated calls for the same session reuse the
/// existing meta dir; each file write is a fresh truncate so a
/// retried spawn always observes the latest projection.
fn provision_meta_sidecar(
    data_dir:    Option<&Path>,
    session_id:  &str,
    ksb_json:    Option<&str>,
    task_prompt: Option<&str>,
) -> Option<MetaSidecar> {
    let data_dir = data_dir?;
    let meta_dir = data_dir
        .join("guests")
        .join(session_id)
        .join("meta");
    if let Err(e) = std::fs::create_dir_all(&meta_dir) {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"planner_meta_sidecar_mkdir_failed\",\
             \"session_id\":\"{session_id}\",\"path\":\"{path}\",\"err\":\"{e}\"}}",
            path = meta_dir.display(),
        );
        return None;
    }

    let mut ksb_guest_path = None;
    if let Some(json) = ksb_json {
        let file_path = meta_dir.join(raxis_ksb::PLANNER_KSB_FILE_NAME);
        if let Err(e) = std::fs::write(&file_path, json.as_bytes()) {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"planner_ksb_sidecar_write_failed\",\
                 \"session_id\":\"{session_id}\",\"path\":\"{path}\",\"err\":\"{e}\"}}",
                path = file_path.display(),
            );
            return None;
        }
        ksb_guest_path = Some(format!(
            "{mount}/{file}",
            mount = raxis_ksb::PLANNER_KSB_GUEST_MOUNT,
            file  = raxis_ksb::PLANNER_KSB_FILE_NAME,
        ));
    }

    let mut task_prompt_guest_path = None;
    if let Some(prompt) = task_prompt {
        let file_path = meta_dir.join(raxis_ksb::PLANNER_TASK_PROMPT_FILE_NAME);
        if let Err(e) = std::fs::write(&file_path, prompt.as_bytes()) {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"planner_task_prompt_sidecar_write_failed\",\
                 \"session_id\":\"{session_id}\",\"path\":\"{path}\",\"err\":\"{e}\"}}",
                path = file_path.display(),
            );
            return None;
        }
        task_prompt_guest_path = Some(format!(
            "{mount}/{file}",
            mount = raxis_ksb::PLANNER_KSB_GUEST_MOUNT,
            file  = raxis_ksb::PLANNER_TASK_PROMPT_FILE_NAME,
        ));
    }

    let mount = raxis_isolation::WorkspaceMount {
        host_path:    meta_dir,
        guest_path:   raxis_ksb::PLANNER_KSB_GUEST_MOUNT.to_owned(),
        mode:         raxis_isolation::MountMode::ReadOnly,
        content_hash: None,
    };
    Some(MetaSidecar {
        mount,
        ksb_guest_path,
        task_prompt_guest_path,
    })
}

// ---------------------------------------------------------------------------
// V2 `v2_extended_gaps.md §2.5` — token-cap env stamping.
// ---------------------------------------------------------------------------

/// Stamp the per-session LLM token caps from `[budget.token_caps]`
/// into the spawned VM's env. Three independent vars; absent caps
/// leave the corresponding axis uncapped at the in-VM dispatch loop
/// (matches `DispatchConfig::max_tokens_*_total = None`).
///
/// Used on the orchestrator path where the env table is freshly
/// allocated and there is no caller-supplied override to defer to.
fn populate_token_cap_env(
    env:  &mut BTreeMap<String, String>,
    caps: Option<&raxis_policy::TokenCapsSection>,
) {
    use raxis_types::planner_env::{
        PLANNER_MAX_TOKENS_INPUT_TOTAL_ENV,
        PLANNER_MAX_TOKENS_OUTPUT_TOTAL_ENV,
        PLANNER_MAX_TOKENS_TOTAL_ENV,
    };
    let Some(caps) = caps else { return; };
    if let Some(n) = caps.max_input_tokens_per_session {
        env.insert(PLANNER_MAX_TOKENS_INPUT_TOTAL_ENV.to_owned(), n.to_string());
    }
    if let Some(n) = caps.max_output_tokens_per_session {
        env.insert(PLANNER_MAX_TOKENS_OUTPUT_TOTAL_ENV.to_owned(), n.to_string());
    }
    if let Some(n) = caps.max_total_tokens_per_session {
        env.insert(PLANNER_MAX_TOKENS_TOTAL_ENV.to_owned(), n.to_string());
    }
}

/// Same as [`populate_token_cap_env`] but uses `entry().or_insert`
/// so a caller-supplied override (e.g. a test rewiring the env)
/// wins over the policy default. Used on the executor path where
/// `extra_env` is the caller's BTreeMap.
fn populate_token_cap_env_or_insert(
    env:  &mut BTreeMap<String, String>,
    caps: Option<&raxis_policy::TokenCapsSection>,
) {
    use raxis_types::planner_env::{
        PLANNER_MAX_TOKENS_INPUT_TOTAL_ENV,
        PLANNER_MAX_TOKENS_OUTPUT_TOTAL_ENV,
        PLANNER_MAX_TOKENS_TOTAL_ENV,
    };
    let Some(caps) = caps else { return; };
    if let Some(n) = caps.max_input_tokens_per_session {
        env.entry(PLANNER_MAX_TOKENS_INPUT_TOTAL_ENV.to_owned())
            .or_insert_with(|| n.to_string());
    }
    if let Some(n) = caps.max_output_tokens_per_session {
        env.entry(PLANNER_MAX_TOKENS_OUTPUT_TOTAL_ENV.to_owned())
            .or_insert_with(|| n.to_string());
    }
    if let Some(n) = caps.max_total_tokens_per_session {
        env.entry(PLANNER_MAX_TOKENS_TOTAL_ENV.to_owned())
            .or_insert_with(|| n.to_string());
    }
}

/// V2.7 `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` — resolve the effective
/// `max_turns` for a planner session against the precedence chain and
/// return both the resolved integer AND a stable `source` label that
/// names the resolution arm verbatim (`"task"` / `"policy"` /
/// `"compiled-default"`).
///
/// Used by both the env-stamp helpers below ([`populate_planner_max_turns_env`]
/// / [`populate_planner_max_turns_env_or_insert`]) and by KSB assembly
/// (`crate::initiatives::ksb_assembly::assemble_ksb_snapshot`), so the
/// planner-VM env stamp and the KSB-projected `planner_max_turns` field
/// are guaranteed to carry the SAME value (single source of truth for
/// the resolution).
///
/// The `task_fields` argument is `None` for orchestrator spawns (the
/// orchestrator is per-initiative, not per-task — the per-task
/// `[[tasks]].max_turns` field never applies). For executor / reviewer
/// spawns it carries the registry-projected
/// [`crate::initiatives::PlanRegistry::get`] result for the activating
/// task.
pub(crate) fn resolve_planner_max_turns_for(
    task_fields: Option<&crate::initiatives::TaskPlanFields>,
    gateway:     Option<&raxis_policy::GatewaySection>,
) -> (u32, &'static str) {
    let policy_default = gateway.and_then(|g| g.planner_max_turns_default);
    match task_fields {
        Some(tf) => tf.effective_max_turns(policy_default),
        None     => match policy_default {
            Some(d) => (d, "policy"),
            None    => (
                crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                "compiled-default",
            ),
        },
    }
}

/// V2.7 `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` — stamp the resolved
/// `RAXIS_PLANNER_MAX_TURNS` into the spawned VM's env table AND emit
/// the audit-friendly `PlannerMaxTurnsResolved` structured log line.
///
/// `task_fields` is `None` for orchestrator spawns; the resolver
/// short-circuits the per-task arm in that case.
///
/// `task_id_for_log` is the per-task id (executor / reviewer) or
/// `"<orchestrator>"` (orchestrator). It is rendered verbatim into the
/// log line's `task_id` field so an operator can grep the resolution
/// trail on a per-task basis.
///
/// Used on the orchestrator path where the env table is freshly
/// allocated; uses unconditional `insert` so a stray pre-existing
/// value cannot mask the kernel-resolved one.
fn populate_planner_max_turns_env(
    env:             &mut BTreeMap<String, String>,
    task_fields:     Option<&crate::initiatives::TaskPlanFields>,
    gateway:         Option<&raxis_policy::GatewaySection>,
    task_id_for_log: &str,
    session_id:      &str,
    initiative_id:   &str,
) {
    let (resolved, source) = resolve_planner_max_turns_for(task_fields, gateway);
    env.insert(
        raxis_types::planner_env::PLANNER_MAX_TURNS_ENV.to_owned(),
        resolved.to_string(),
    );
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"PlannerMaxTurnsResolved\",\
         \"task_id\":{:?},\"session_id\":{:?},\"initiative_id\":{:?},\
         \"source\":{:?},\"resolved\":{},\
         \"invariant\":\"INV-PLANNER-MAX-TURNS-PRECEDENCE-01\"}}",
        task_id_for_log, session_id, initiative_id, source, resolved,
    );
}

/// `entry().or_insert` variant of [`populate_planner_max_turns_env`].
/// Used on the executor / reviewer path where the caller-supplied env
/// (test rewiring) may declare an override that should win over the
/// kernel-resolved value. Only emits the log line if the kernel
/// actually stamped the env (i.e. there was no prior override),
/// matching the semantics of the token-cap `_or_insert` helpers.
fn populate_planner_max_turns_env_or_insert(
    env:             &mut BTreeMap<String, String>,
    task_fields:     Option<&crate::initiatives::TaskPlanFields>,
    gateway:         Option<&raxis_policy::GatewaySection>,
    task_id_for_log: &str,
    session_id:      &str,
    initiative_id:   &str,
) {
    let (resolved, source) = resolve_planner_max_turns_for(task_fields, gateway);
    let key = raxis_types::planner_env::PLANNER_MAX_TURNS_ENV.to_owned();
    if let std::collections::btree_map::Entry::Vacant(slot) = env.entry(key) {
        slot.insert(resolved.to_string());
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"PlannerMaxTurnsResolved\",\
             \"task_id\":{:?},\"session_id\":{:?},\"initiative_id\":{:?},\
             \"source\":{:?},\"resolved\":{},\
             \"invariant\":\"INV-PLANNER-MAX-TURNS-PRECEDENCE-01\"}}",
            task_id_for_log, session_id, initiative_id, source, resolved,
        );
    }
}

/// V2 `v2_extended_gaps.md §3.1` — stamp the `[budget.sleep_caps]`
/// per-call and cumulative ceilings into the spawned VM env.
/// Absent ⇒ the in-VM `SleepTool::disabled()` refuses every
/// invocation; opting in requires both keys to be present
/// (validated at policy load).
fn populate_sleep_cap_env(
    env:  &mut BTreeMap<String, String>,
    caps: Option<&raxis_policy::SleepCapsSection>,
) {
    use raxis_types::planner_env::{
        PLANNER_MAX_SLEEP_CUMULATIVE_ENV, PLANNER_MAX_SLEEP_PER_CALL_ENV,
    };
    let Some(caps) = caps else { return; };
    env.insert(
        PLANNER_MAX_SLEEP_PER_CALL_ENV.to_owned(),
        caps.max_seconds_per_call.to_string(),
    );
    env.insert(
        PLANNER_MAX_SLEEP_CUMULATIVE_ENV.to_owned(),
        caps.max_cumulative_seconds.to_string(),
    );
}

/// `entry().or_insert` variant of [`populate_sleep_cap_env`] for the
/// executor path where the caller-supplied env may already declare
/// overrides (test rewiring).
fn populate_sleep_cap_env_or_insert(
    env:  &mut BTreeMap<String, String>,
    caps: Option<&raxis_policy::SleepCapsSection>,
) {
    use raxis_types::planner_env::{
        PLANNER_MAX_SLEEP_CUMULATIVE_ENV, PLANNER_MAX_SLEEP_PER_CALL_ENV,
    };
    let Some(caps) = caps else { return; };
    env.entry(PLANNER_MAX_SLEEP_PER_CALL_ENV.to_owned())
        .or_insert_with(|| caps.max_seconds_per_call.to_string());
    env.entry(PLANNER_MAX_SLEEP_CUMULATIVE_ENV.to_owned())
        .or_insert_with(|| caps.max_cumulative_seconds.to_string());
}

// ---------------------------------------------------------------------------
// Bounded retry on transient VM spawn failure — `spawn_with_transient_retry`.
// ---------------------------------------------------------------------------
//
// V2 `elastic-vm-scaling.md §3.1 / §3.2 / §3.3` — the kernel-side
// bridge wraps every VM-spawn call in a bounded retry loop driven by
// `policy.[elastic].transient_retry_*`. The loop:
//
//   * Re-builds a fresh [`SpawnRequest`] per attempt (the request is
//     consumed by `SessionSpawnService::spawn_session`; cloning the
//     prototype + freshly boxing a per-attempt admission service is
//     cheaper than threading the whole 2 KiB request through the
//     loop by `Clone`).
//   * Classifies each [`SpawnError`] via [`classify_spawn_error`].
//     `IsolationFailureClass::Permanent` short-circuits to
//     `SessionVmFailedFinal` per **INV-ELASTIC-02** (no silent
//     retry on permanent failures).
//   * Bounds retries at `transient_retry_max_attempts` per
//     **INV-ELASTIC-06**; exhaustion emits `SessionVmFailedFinal`.
//   * Emits `SessionVmRespawnAttempted` for each retry with the
//     previous attempt's `failure_class` projection (always
//     `"Transient"` for emitted respawn events, by construction).
//
// The success path is unchanged: on `Ok(handle)` the loop returns
// immediately and `SessionVmSpawned` lands inside
// `SessionSpawnService::spawn_session` exactly as before.

/// Bundle of cloneable inputs needed to construct a fresh
/// [`SpawnRequest`] per retry attempt.
///
/// The fields are split out from the inline struct literal at each
/// call site so the retry helper can re-clone and re-box the per-
/// attempt admission service without consuming any of the upstream
/// preparation work (image resolution, credential rehydration, KSB
/// assembly, env stamping). All fields except `egress_allowlist` are
/// `Clone`-derived in their owning crates; `egress_allowlist` is
/// declared `#[derive(Clone)]` in `raxis-egress-admission`.
///
/// **Public** so the dynamic-resource-adjustment respawn helper
/// (`respawn_with_larger_resources`) can be called from a future
/// signal-observer / scaling decision engine module without
/// duplicating the spawn-request construction shape.
pub struct SpawnRequestProto {
    /// Stable per-session identifier minted by the kernel.
    pub session_id:        String,
    /// Owning task id (`None` for the canonical Orchestrator
    /// session, which has no `[[tasks]]` row).
    pub task_id:           Option<String>,
    /// Owning initiative id.
    pub initiative_id:     String,
    /// Verified image bytes the substrate boots.
    pub image:             VerifiedImage,
    /// Mounts the substrate exposes to the guest.
    pub workspace_mounts:  Vec<raxis_isolation::WorkspaceMount>,
    /// Resource envelope + boot args. The dynamic-resource-
    /// adjustment path mutates `vcpu_count` / `mem_mib` via the
    /// `crate::elastic::build_scaled_vm_spec` chokepoint.
    pub vm_spec:           VmSpec,
    /// Credential decls the spawn service rehydrates per attempt.
    pub credentials:       Vec<raxis_plan_credentials::TaskCredentialDecl>,
    /// Egress allowlist — cloned per attempt to construct a fresh
    /// per-spawn `PolicyAdmissionService`.
    pub egress_allowlist:  EgressAllowlist,
}

impl SpawnRequestProto {
    /// Clone the prototype into a fresh [`SpawnRequest`]. Boxes a
    /// new per-attempt [`PolicyAdmissionService`] — admission
    /// services hold per-session listener state and are not reusable
    /// across attempts.
    pub fn build_request(&self) -> SpawnRequest {
        SpawnRequest {
            session_id:        self.session_id.clone(),
            task_id:           self.task_id.clone(),
            initiative_id:     self.initiative_id.clone(),
            image:             self.image.clone(),
            workspace_mounts:  self.workspace_mounts.clone(),
            vm_spec:           self.vm_spec.clone(),
            credentials:       self.credentials.clone(),
            admission_service: Box::new(PolicyAdmissionService::new(
                self.egress_allowlist.clone(),
            )),
        }
    }
}

/// Project a [`SpawnError`] onto an
/// [`raxis_isolation::IsolationFailureClass`].
///
/// **Mapping rationale.** Only `SpawnError::IsolationSpawn(err)`
/// carries an [`raxis_isolation::IsolationError`] whose classification
/// is documented in `elastic-vm-scaling.md §3.1`. Every other
/// `SpawnError` variant is structurally pre-substrate (credential
/// proxy bind, admission listener bind, audit-emit) or
/// post-substrate teardown, and is treated as **Permanent** —
/// retrying a port-bind race or an audit-fsync error would just
/// hammer the same fault, and INV-ELASTIC-07 forbids implicit
/// fall-through to "retry on any error".
fn classify_spawn_error(err: &SpawnError) -> raxis_isolation::IsolationFailureClass {
    match err {
        SpawnError::IsolationSpawn(iso) => iso.classify(),
        // INV-ELASTIC-07: every non-IsolationSpawn variant is
        // explicitly Permanent. Adding a new SpawnError variant
        // requires updating this match (the compiler enforces it).
        SpawnError::CredentialProxy(_)
        | SpawnError::AdmissionBind(_)
        | SpawnError::IsolationShutdown(_)
        | SpawnError::SessionNotActive { .. }
        | SpawnError::Audit(_) => raxis_isolation::IsolationFailureClass::Permanent,
    }
}

/// Compute the backoff for retry attempt `attempt` (1-indexed:
/// `attempt = 1` is the first respawn after the original failed
/// spawn). Exponential schedule clamped to
/// `transient_retry_max_backoff_ms`:
///
/// ```text
/// backoff = min(initial * 2^(attempt-1), max)
/// ```
///
/// All arithmetic is `u64` internally to avoid overflow when an
/// operator misconfigures the initial backoff close to `u32::MAX`;
/// the final clamp is the policy ceiling, which the validator
/// already constrained to `≤ ELASTIC_MAX_RETRY_BACKOFF_CEILING_MS`.
fn compute_backoff_ms(initial_ms: u32, max_ms: u32, attempt: u32) -> u32 {
    debug_assert!(attempt >= 1, "attempt is 1-indexed; caller invariant");
    let shift = attempt.saturating_sub(1).min(31);
    let scaled: u64 = (initial_ms as u64).saturating_mul(1u64 << shift);
    let capped = scaled.min(max_ms as u64);
    u32::try_from(capped).unwrap_or(max_ms)
}

/// Wrap [`SessionSpawnService::spawn_session`] in a bounded retry
/// loop driven by `policy.[elastic].transient_retry_*`.
///
/// **Audit emission contract.**
///
/// * `Ok(handle)` ⇒ `SessionVmSpawned` was emitted by
///   `spawn_session` itself (unchanged from before this commit).
///   This helper emits nothing on the happy path.
/// * Transient failure with `attempt < max_attempts` ⇒
///   `SessionVmRespawnAttempted` with `attempt = N` (1-indexed,
///   i.e. the FIRST retry is `attempt = 1`) and the previous
///   attempt's `failure_class = "Transient"` projection.
/// * Transient failure with `attempt >= max_attempts` ⇒
///   `SessionVmFailedFinal` with `total_attempts = max_attempts + 1`
///   and `failure_class = "Transient"`.
/// * Permanent failure (any attempt) ⇒ `SessionVmFailedFinal` with
///   `total_attempts = N` and `failure_class = "Permanent"`,
///   short-circuiting the retry loop (INV-ELASTIC-02).
///
/// Audit-emit failures are logged but do **not** mask the
/// underlying spawn error — the original `SpawnError` is propagated
/// to the caller verbatim so operator dashboards see the substrate
/// reason rather than an audit-disk-full surrogate.
async fn spawn_with_transient_retry(
    service:       &SessionSpawnService,
    elastic:       &raxis_policy::ElasticConfig,
    proto:         SpawnRequestProto,
) -> Result<SpawnHandle, SpawnError> {
    use raxis_audit_tools::AuditEventKind;

    let max_attempts            = elastic.transient_retry_max_attempts;
    let initial_backoff_ms      = elastic.transient_retry_initial_backoff_ms;
    let max_backoff_ms          = elastic.transient_retry_max_backoff_ms;

    // 1-indexed attempt counter for the audit projection. Attempt 0
    // is the original spawn (the one that just failed when we land
    // in the `Err` arm); attempt 1 is the FIRST retry.
    let mut retry_attempt: u32 = 0;

    loop {
        let req = proto.build_request();
        match service.spawn_session(req).await {
            Ok(handle) => return Ok(handle),
            Err(err) => {
                let class      = classify_spawn_error(&err);
                let prev_reason = err.to_string();

                // Permanent ⇒ short-circuit. INV-ELASTIC-02.
                if matches!(class, raxis_isolation::IsolationFailureClass::Permanent) {
                    let total_attempts = retry_attempt.saturating_add(1);
                    if let Err(e) = service.audit().emit(
                        AuditEventKind::SessionVmFailedFinal {
                            session_id:    proto.session_id.clone(),
                            task_id:       proto.task_id.clone(),
                            initiative_id: proto.initiative_id.clone(),
                            total_attempts,
                            failure_class: class.as_str().to_owned(),
                            final_reason:  prev_reason.clone(),
                        },
                        Some(&proto.session_id),
                        proto.task_id.as_deref(),
                        Some(&proto.initiative_id),
                    ) {
                        eprintln!(
                            "{{\"level\":\"warn\",\"event\":\"session_vm_failed_final_audit_emit_failed\",\
                             \"session_id\":\"{sid}\",\"phase\":\"permanent\",\"error\":\"{err}\"}}",
                            sid = proto.session_id,
                            err = e,
                        );
                    }
                    return Err(err);
                }

                // Transient: are we at the retry ceiling?
                // INV-ELASTIC-06: `transient_retry_max_attempts` is
                // a hard ceiling. `retry_attempt` already counts
                // completed retries; we admit the next one only when
                // `retry_attempt < max_attempts`.
                if retry_attempt >= max_attempts {
                    // total_attempts = original (1) + completed retries.
                    let total_attempts = retry_attempt.saturating_add(1);
                    if let Err(e) = service.audit().emit(
                        AuditEventKind::SessionVmFailedFinal {
                            session_id:    proto.session_id.clone(),
                            task_id:       proto.task_id.clone(),
                            initiative_id: proto.initiative_id.clone(),
                            total_attempts,
                            failure_class: class.as_str().to_owned(),
                            final_reason:  prev_reason.clone(),
                        },
                        Some(&proto.session_id),
                        proto.task_id.as_deref(),
                        Some(&proto.initiative_id),
                    ) {
                        eprintln!(
                            "{{\"level\":\"warn\",\"event\":\"session_vm_failed_final_audit_emit_failed\",\
                             \"session_id\":\"{sid}\",\"phase\":\"exhausted\",\"error\":\"{err}\"}}",
                            sid = proto.session_id,
                            err = e,
                        );
                    }
                    return Err(err);
                }

                // Schedule the next retry. attempt counter for the
                // audit event is 1-indexed (the first retry is
                // attempt = 1).
                let next_attempt = retry_attempt.saturating_add(1);
                let backoff_ms   = compute_backoff_ms(
                    initial_backoff_ms,
                    max_backoff_ms,
                    next_attempt,
                );

                if let Err(e) = service.audit().emit(
                    AuditEventKind::SessionVmRespawnAttempted {
                        session_id:      proto.session_id.clone(),
                        task_id:         proto.task_id.clone(),
                        initiative_id:   proto.initiative_id.clone(),
                        attempt:         next_attempt,
                        max_attempts,
                        failure_class:   class.as_str().to_owned(),
                        previous_reason: prev_reason.clone(),
                        backoff_ms,
                    },
                    Some(&proto.session_id),
                    proto.task_id.as_deref(),
                    Some(&proto.initiative_id),
                ) {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"session_vm_respawn_attempted_audit_emit_failed\",\
                         \"session_id\":\"{sid}\",\"attempt\":{attempt},\"error\":\"{err}\"}}",
                        sid = proto.session_id,
                        attempt = next_attempt,
                        err = e,
                    );
                }

                // iter44 perf-metrics — `INV-OBS-RESPAWN-KIND-LABEL-01`.
                // Pair the audit emission with a labelled metric increment
                // so the `10-isolation` dashboard can split healthy
                // transient-retry churn from logical-deadlock respawns.
                // Backend + image_kind mirror the existing perf-telemetry
                // shape so dashboards can join on either label.
                if let Some(hub) = service.observability_hub() {
                    let image_kind_str = match proto.image.kind {
                        raxis_isolation::ImageKind::RootfsErofs         => "rootfs_erofs",
                        raxis_isolation::ImageKind::RootfsInitramfsCpio => "rootfs_initramfs_cpio",
                        raxis_isolation::ImageKind::EnclaveSigStruct    => "enclave_sigstruct",
                        raxis_isolation::ImageKind::WasmModule          => "wasm_module",
                    };
                    crate::observability::record_isolation_respawn_attempted(
                        hub.as_ref(),
                        service.backend_id(),
                        image_kind_str,
                        crate::observability::RESPAWN_KIND_VM_CRASH,
                        next_attempt as i64,
                    );
                }

                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"session_vm_transient_retry\",\
                     \"session_id\":\"{sid}\",\"attempt\":{attempt},\
                     \"max_attempts\":{max_attempts},\"backoff_ms\":{backoff_ms},\
                     \"failure_class\":\"{class}\",\"previous_reason\":\"{reason}\"}}",
                    sid = proto.session_id,
                    attempt = next_attempt,
                    class = class.as_str(),
                    reason = prev_reason.replace('"', "\\\""),
                );

                tokio::time::sleep(std::time::Duration::from_millis(
                    backoff_ms as u64,
                ))
                .await;

                retry_attempt = next_attempt;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dynamic resource adjustment — `respawn_with_larger_resources`.
// ---------------------------------------------------------------------------
//
// V2 `elastic-vm-scaling.md §4.2` — the scale-up event flow. The
// signal observer (future wiring; see `crate::elastic::ScaleSignal`)
// produces a `ScaleDecision::Apply` from
// `crate::elastic::decide_scale_up`; this helper consumes that
// decision and orchestrates the audit-and-respawn dance:
//
//   terminate_session(prev)               (emits SessionVmExited)
//     → emit SessionVmScaleEvent          (INV-ELASTIC-03 write-then-emit
//                                           ordering: between Exit and Spawn)
//     → spawn_with_transient_retry(new)   (emits SessionVmSpawned)
//
// The new `VmSpec` is already produced by `build_scaled_vm_spec`,
// which is the **single mechanical chokepoint** that honours
// INV-ELASTIC-05 (no upward scaling when `elastic = false`).
// Callers MUST NOT post-process the spec returned by the chokepoint
// — doing so would route around the INV-ELASTIC-05 guarantee.

/// Outcome of a [`respawn_with_larger_resources`] call.
///
/// Pre-existing `OrchestratorSpawnError` does not cleanly express
/// the "old session terminated but new spawn failed" case; this
/// dedicated enum surfaces it as `Respawn { drain_ok: true,
/// spawn_err }` so the caller can decide whether to retry the
/// scaling decision next tick or surface the failure verbatim.
#[derive(Debug)]
pub enum RespawnWithLargerOutcome {
    /// Successful respawn. The new session is bound; the audit
    /// chain shows `SessionVmExited` → `SessionVmScaleEvent` →
    /// `SessionVmSpawned`.
    Ok(SpawnHandle),

    /// Failed to terminate the previous session before the
    /// respawn. The new session was NOT bound; the previous
    /// session is in an unknown state (the substrate may still
    /// have a live VM). The caller should surface the error to
    /// the operator and avoid re-entering the scaling loop until
    /// the old session is reconciled.
    DrainFailed(SpawnError),

    /// Terminated the previous session but the new spawn failed
    /// (after the §3.2 retry loop exhausted). The kernel is now
    /// without a live session for this `(initiative_id, task_id)`
    /// pair; the caller is responsible for the operator-visible
    /// recovery (typically: surface a structured log + let the
    /// next signal-observer tick request a fresh scale decision
    /// against the baseline spec).
    SpawnFailed(SpawnError),
}

/// Drain the previous session, emit `SessionVmScaleEvent`, and
/// spawn the new session with the scaled-up `VmSpec`.
///
/// **Audit ordering** (`elastic-vm-scaling.md §4.2`,
/// INV-ELASTIC-03):
///
///   1. `service.terminate_session(prev_session_id)` ⇒
///      `SessionVmExited` lands.
///   2. `emit_scale_event_audit(direction = Up, ...)` ⇒
///      `SessionVmScaleEvent` lands BEFORE the new spawn so
///      audit-replay attributes the new VM to the scaling
///      decision (write-then-emit).
///   3. `spawn_with_transient_retry(new_proto)` ⇒
///      `SessionVmSpawned` lands.
///
/// **`elastic = false` semantics.** The chokepoint
/// (`crate::elastic::build_scaled_vm_spec`) clamps the new spec
/// to the baseline when `elastic = false`, so this function
/// *cannot* admit an upward scale even if a buggy caller
/// constructs a `proto` with a bumped `vm_spec`. This is the
/// "mechanically enforced" leg of INV-ELASTIC-05.
///
/// The helper is intentionally **public** so the future signal
/// observer (`ScalingDecisionEngine::tick`) can call it without
/// re-implementing the audit-emit ordering.
///
/// **§5 rate-limit gate.** The function consults `rate_limiter`
/// FIRST. On `Defer`, it emits
/// `SessionVmScaleDeferred { reason: "RateLimit" }` and returns
/// `RespawnWithLargerOutcome::DrainFailed` with a synthetic
/// `SpawnError::Audit("rate-limited")` so the caller surfaces
/// the deferral to its observer loop the same way it surfaces
/// any other deferred decision. The previous session is **NOT**
/// drained (the kernel never starts the respawn ceremony when
/// the budget is full); the next signal-observer tick
/// re-evaluates the trigger.
#[allow(clippy::too_many_arguments)]
pub async fn respawn_with_larger_resources(
    service:           Arc<SessionSpawnService>,
    elastic:           &raxis_policy::ElasticConfig,
    rate_limiter:      &Arc<crate::elastic::ScalingRateLimiter>,
    prev_session_id:   &str,
    drain_grace:       std::time::Duration,
    new_proto:         SpawnRequestProto,
    direction:         crate::elastic::ScaleDirection,
    prev_vcpus:        u32,
    new_vcpus:         u32,
    prev_memory_mb:    u32,
    new_memory_mb:     u32,
    reason:            &str,
) -> RespawnWithLargerOutcome {
    // ── Step 0: §5 rate-limit gate. INV-ELASTIC-04 soft event. ──
    // See sibling call-site comment: `i64`→`u64` saturating cast.
    let now = unix_now_secs().max(0) as u64;
    match rate_limiter.try_admit(
        now,
        elastic.max_concurrent_scaling_events_per_minute,
    ) {
        crate::elastic::RateLimitDecision::Admit => {}
        crate::elastic::RateLimitDecision::Defer => {
            if let Err(e) = crate::elastic::emit_scale_deferred_audit(
                service.audit(),
                &new_proto.session_id,
                new_proto.task_id.as_deref(),
                &new_proto.initiative_id,
                direction,
                "RateLimit",
            ) {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"respawn_with_larger_deferred_audit_failed\",\
                     \"session_id\":\"{sid}\",\"error\":\"{err}\"}}",
                    sid = new_proto.session_id,
                    err = e,
                );
            }
            // The caller distinguishes deferral from a real
            // drain-failure via a synthetic `SpawnError::Audit`.
            return RespawnWithLargerOutcome::DrainFailed(SpawnError::Audit(format!(
                "scale event deferred: rate limit ({max}/min) exceeded",
                max = elastic.max_concurrent_scaling_events_per_minute,
            )));
        }
    }

    // ── Step 1: drain + terminate the previous session. ──────────
    //
    // `terminate_session` emits `SessionVmExited` internally; the
    // helper here just propagates the outcome so a drain-failure
    // can be surfaced distinctly from a spawn-failure.
    if let Err(err) = service
        .terminate_session(prev_session_id, drain_grace)
        .await
    {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"respawn_with_larger_drain_failed\",\
             \"prev_session_id\":\"{sid}\",\"error\":\"{err}\"}}",
            sid = prev_session_id,
            err = err,
        );
        return RespawnWithLargerOutcome::DrainFailed(err);
    }

    // ── Step 2: emit `SessionVmScaleEvent`. ───────────────────────
    //
    // INV-ELASTIC-03: the scale event is emitted AFTER the
    // `SessionVmExited` (terminate) and BEFORE the new
    // `SessionVmSpawned` (the spawn helper below). Audit-emit
    // failure is logged but never aborts the scaling flow — the
    // VM lifecycle continues against the new VmSpec.
    if let Err(e) = crate::elastic::emit_scale_event_audit(
        service.audit(),
        &new_proto.session_id,
        new_proto.task_id.as_deref(),
        &new_proto.initiative_id,
        direction,
        prev_vcpus,
        new_vcpus,
        prev_memory_mb,
        new_memory_mb,
        reason,
    ) {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"session_vm_scale_event_audit_emit_failed\",\
             \"session_id\":\"{sid}\",\"direction\":\"{dir}\",\"error\":\"{err}\"}}",
            sid = new_proto.session_id,
            dir = direction.as_str(),
            err = e,
        );
    }

    // ── Step 3: spawn the new session with the scaled-up spec.
    //    Wraps in the §3.2 bounded-retry loop so transient
    //    substrate noise on the new spawn does not abandon the
    //    scaling decision.
    match spawn_with_transient_retry(&service, elastic, new_proto).await {
        Ok(handle) => RespawnWithLargerOutcome::Ok(handle),
        Err(err)   => RespawnWithLargerOutcome::SpawnFailed(err),
    }
}

#[cfg(test)]
mod retry_tests {
    //! Unit tests for [`compute_backoff_ms`] and
    //! [`classify_spawn_error`]. The end-to-end retry semantics are
    //! exercised by the `tests` module below against a real
    //! `SessionSpawnService` + `FakeAuditSink`.

    use super::{classify_spawn_error, compute_backoff_ms};
    use raxis_isolation::{IsolationError, IsolationFailureClass};
    use raxis_session_spawn::SpawnError;

    #[test]
    fn compute_backoff_grows_exponentially() {
        // initial = 100ms, max = 4000ms.
        assert_eq!(compute_backoff_ms(100, 4_000, 1),  100);
        assert_eq!(compute_backoff_ms(100, 4_000, 2),  200);
        assert_eq!(compute_backoff_ms(100, 4_000, 3),  400);
        assert_eq!(compute_backoff_ms(100, 4_000, 4),  800);
        assert_eq!(compute_backoff_ms(100, 4_000, 5),  1_600);
        assert_eq!(compute_backoff_ms(100, 4_000, 6),  3_200);
        // Clamped:
        assert_eq!(compute_backoff_ms(100, 4_000, 7),  4_000);
        assert_eq!(compute_backoff_ms(100, 4_000, 30), 4_000);
    }

    #[test]
    fn compute_backoff_handles_zero_initial() {
        // 0 initial ⇒ 0 backoff at every attempt (operator opted
        // for tight retry; the policy validator allows this).
        assert_eq!(compute_backoff_ms(0, 4_000, 1), 0);
        assert_eq!(compute_backoff_ms(0, 4_000, 5), 0);
    }

    #[test]
    fn compute_backoff_clamps_at_u32_overflow() {
        // u32::MAX initial + a long retry chain MUST NOT panic; the
        // clamp keeps the result inside the policy ceiling.
        let initial = u32::MAX;
        let max     = 5_000;
        assert_eq!(compute_backoff_ms(initial, max, 31), max);
        assert_eq!(compute_backoff_ms(initial, max, 64), max);
    }

    #[test]
    fn classify_spawn_isolation_spawn_uses_isolation_classify() {
        let transient = SpawnError::IsolationSpawn(
            IsolationError::SpawnFailed("noisy neighbour".into()),
        );
        assert_eq!(
            classify_spawn_error(&transient),
            IsolationFailureClass::Transient,
        );

        let permanent = SpawnError::IsolationSpawn(IsolationError::SignatureMismatch);
        assert_eq!(
            classify_spawn_error(&permanent),
            IsolationFailureClass::Permanent,
        );
    }

    #[test]
    fn classify_spawn_audit_is_permanent() {
        // Audit failures are fail-closed; never retried.
        let err = SpawnError::Audit("disk full".into());
        assert_eq!(classify_spawn_error(&err), IsolationFailureClass::Permanent);
    }

    #[test]
    fn classify_spawn_admission_bind_is_permanent() {
        let err = SpawnError::AdmissionBind(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "EADDRINUSE",
        ));
        assert_eq!(classify_spawn_error(&err), IsolationFailureClass::Permanent);
    }
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
    /// V2 `elastic-vm-scaling.md §4.4` — per-role rolling window
    /// of recent utilisation samples. Mirror of
    /// [`OrchestratorSpawnContext::scale_down_history`]; production
    /// wires the same `Arc` through both contexts so executor and
    /// reviewer activations consult the shared tracker.
    pub scale_down_history: Arc<crate::elastic::ScaleDownHistory>,
    /// V2 `elastic-vm-scaling.md §5` — sliding 60-second rate
    /// limiter for admitted scaling events. See
    /// [`OrchestratorSpawnContext::rate_limiter`].
    pub rate_limiter: Arc<crate::elastic::ScalingRateLimiter>,
}

impl ExecutorSpawnContext {
    /// Default Executor / Reviewer VM resource budgets. Pinned to
    /// match `host-capacity.md §4.1`; operators override at boot.
    pub fn new(install_dir: PathBuf, kernel_version: String) -> Self {
        Self {
            install_dir,
            kernel_version,
            // `host-capacity.md §4.1` reference Executor budget:
            // 2 vCPU. Executor agents routinely run cargo / npm /
            // pytest builds whose make-style parallelism saturates
            // a single vCPU, so a 1-vCPU pin would directly bottleneck
            // tool latency. The AVF SMP timer issue we previously
            // observed (`rcu_sched detected stalls on CPUs/tasks` on
            // early boot) is mitigated below in [`ExecutorSpawnContext`]'s
            // kernel-cmdline path through the `[isolation]`-tuneable
            // boot args declared in `kernel/src/main.rs`. The next
            // iteration moves this constant under operator control
            // via `[isolation]` policy keys validated in
            // `raxis-policy::IsolationConfig`; until then this
            // hardcoded default matches the spec reference.
            executor_vcpu_count: 2,
            // The dev-host executor-starter initramfs cpio.gz is
            // currently ~560 MiB on disk (full Debian + Node + Python
            // + Rust + Go + Git CLI). The Linux initramfs unpacker
            // needs simultaneous host capacity for **three** copies:
            //
            //   * the compressed payload mapped into guest RAM by the
            //     loader (`initrd memory` line in the kernel log),
            //   * the decompressed cpio stream walked by `gen_init_cpio`
            //     in kernel mode, and
            //   * the unpacked tmpfs rootfs the running guest mounts
            //     as `/`.
            //
            // With a 2 GiB ceiling the 560 MiB compressed payload
            // triggers `tmpfs: incomplete write (-28 != …)` on the
            // dev-host stack — the kernel fills its rootfs tmpfs
            // budget partway through `unpack_to_rootfs` and panics
            // with `Kernel panic - not syncing: VFS: Unable to mount
            // root fs on unknown-block(0,0)`. 6 GiB is the smallest
            // round number that survives the worst-case dev image
            // plus a working agent (cargo + rustc + node) without
            // dropping the panic, and still fits comfortably in the
            // 16 GiB-ceiling MacBook Pro reference dev host. Production
            // EROFS images skip the unpacker entirely (the rootfs is a
            // virtio-blk drive), so the production budget remains the
            // 1 GiB documented in `host-capacity.md §4.1`.
            executor_mem_mib:    6 * 1024,
            reviewer_vcpu_count: 1,
            // The dev-host reviewer-core initramfs cpio.gz is ~5 MiB
            // on disk and decompresses to ~127 MiB in tmpfs (planner
            // binary only, no toolchain). 1 GiB covers the image plus
            // the reviewer's static-analysis working set.
            reviewer_mem_mib:    1024,
            data_dir:            None,
            scale_down_history:  Arc::new(crate::elastic::ScaleDownHistory::new()),
            rate_limiter:        Arc::new(crate::elastic::ScalingRateLimiter::new()),
        }
    }

    /// Builder: attach the kernel `data_dir` for planner-socket env
    /// stamping. See [`OrchestratorSpawnContext::with_data_dir`].
    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = Some(data_dir);
        self
    }

    /// Builder: share an externally-owned scale-down tracker. See
    /// [`OrchestratorSpawnContext::with_scale_down_history`].
    pub fn with_scale_down_history(
        mut self,
        history: Arc<crate::elastic::ScaleDownHistory>,
    ) -> Self {
        self.scale_down_history = history;
        self
    }

    /// Builder: share an externally-owned rate limiter. See
    /// [`OrchestratorSpawnContext::with_rate_limiter`].
    pub fn with_rate_limiter(
        mut self,
        rl: Arc<crate::elastic::ScalingRateLimiter>,
    ) -> Self {
        self.rate_limiter = rl;
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
///      §3.5` — Executor egress on `Mediated` (Path A3
///      universal-airgap, the only non-`None` tier shipped in V2
///      after the Tier1Tproxy deletion) and Reviewer egress on
///      `Tier0NoEgress` (the Pure-Static Reviewer mandate,
///      `INV-PLANNER-HARNESS-02`).
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
/// `EgressTier::Mediated` so the kernel-side admission listener
/// arbitrates every egress request over the per-VM vsock device
/// against the active `EgressAllowlist`. (Path A3 universal-airgap;
/// see `specs/v2/airgap-architecture.md`.)
#[allow(clippy::too_many_arguments)]
pub async fn spawn_executor_for_task(
    spawn_ctx:        &ExecutorSpawnContext,
    agent_kind:       ExecutorAgentKind,
    session_id:       &str,
    task_id:          &str,
    initiative_id:    &str,
    egress_allowlist: EgressAllowlist,
    mut workspace_mounts: Vec<raxis_isolation::WorkspaceMount>,
    extra_env:        BTreeMap<String, String>,
    service:          Arc<SessionSpawnService>,
    plan_registry:    &Arc<crate::initiatives::PlanRegistry>,
    store:            &Arc<Store>,
    policy:           &raxis_policy::PolicyBundle,
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
        let (image_path, image_id, canonical_kind, missing_err): (
            PathBuf,
            String,
            raxis_canonical_images::CanonicalImageKind,
            fn(PathBuf) -> OrchestratorSpawnError,
        ) = match agent_kind {
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
                    raxis_canonical_images::CanonicalImageKind::ExecutorStarter,
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
                    raxis_canonical_images::CanonicalImageKind::Reviewer,
                    |path| OrchestratorSpawnError::ReviewerImageMissing { path },
                )
            }
        };
        if !image_path.exists() {
            return Err(missing_err(image_path));
        }
        // V2 SCHEMA_VERSION=3 — see the matching note on the
        // orchestrator-spawn path. Same fall-back semantics: if the
        // manifest is missing or the trust anchor is unpopulated we
        // default to RootfsErofs and let the substrate's spawn-time
        // verifier surface tamper at activation time.
        let (image_kind, _kind_is_trusted) =
            crate::canonical_images_preflight::resolve_image_kind_for_role(
                &image_path,
                canonical_kind,
                &spawn_ctx.kernel_version,
            );
        VerifiedImage {
            kind:      image_kind,
            body:      ImageBody::Path(image_path),
            signature: ImageSignature(Vec::new()),
            image_id,
        }
    };

    // ── Step 2: rehydrate credential decls AND the session token. ──
    //
    // Two reads off the same `spawn_blocking` so the SQLite mutex is
    // acquired exactly once. The token is read by `session_id` from
    // the canonical `sessions.session_token` column inserted by the
    // activation handler (`handle_activate_subtask` in
    // `kernel/src/handlers/intent.rs`); using a synthesized fake
    // here would put the planner and the kernel out of sync — every
    // egress fetch would fail closed with
    // `FAIL_SESSION_TOKEN_MISMATCH` because `resolve_session` looks
    // the token up in `sessions.session_token` and would find no
    // matching row. The same audit-chain wedge that the orchestrator
    // path's Step 2 comment block describes applies here verbatim.
    //
    // `read_task_credential_proxies_in_tx` is keyed by `task_id`
    // because the `[[tasks.credentials]]` block is plan-side
    // configuration. Reviewer activations always return an empty
    // Vec (Pure-Static Reviewer cannot consume credentials per
    // `INV-PLANNER-HARNESS-02`); we still call through the uniform
    // path so a future regression in plan validation does not
    // silently slip past.
    let store_for_read = Arc::clone(store);
    let task_id_for_read = task_id.to_owned();
    let session_id_for_read = session_id.to_owned();
    let (credentials, session_token_db) =
        tokio::task::spawn_blocking(move || -> Result<_, String> {
            let conn = store_for_read.lock_sync();
            let creds = kernel_lifecycle::read_task_credential_proxies_in_tx(
                &conn,
                &task_id_for_read,
            )
            .map_err(|e| e.to_string())?;
            let token: String = conn
                .query_row(
                    "SELECT session_token FROM sessions WHERE session_id = ?1",
                    rusqlite::params![&session_id_for_read],
                    |row| row.get(0),
                )
                .map_err(|e| {
                    format!(
                        "session row missing for session_id {session_id_for_read}: {e}",
                    )
                })?;
            Ok((creds, token))
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
    //
    // Executor egress is unconditionally `EgressTier::Mediated` after
    // the Tier1Tproxy deletion (TODO
    // `tier1-deletion-fold-into-cleanup-sweep`). The previous
    // `runtime-airgap-a3` cargo feature + `RAXIS_AIRGAP_A3` env-var
    // double-gate were removed in the same sweep — Mediated is now
    // the only sanctioned non-`None` tier in V2 (see
    // `specs/v2/airgap-architecture.md`,
    // `INV-NETISO-A3-UNIVERSAL-NO-NIC-01`).
    let (vcpu_count, mem_mib, egress_tier, entrypoint_argv) = match agent_kind {
        ExecutorAgentKind::Executor => (
            spawn_ctx.executor_vcpu_count,
            spawn_ctx.executor_mem_mib,
            EgressTier::Mediated,
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

    // V2 `v2_extended_gaps.md §2.5` — stamp per-session LLM token
    // caps from `policy.budget.token_caps` into the guest env, same
    // contract as the orchestrator spawn path. `entry().or_insert`
    // semantics: an existing override stamped by the caller wins
    // (gives integration tests a knob to override the policy
    // ceiling without rewriting the bundle).
    populate_token_cap_env_or_insert(&mut env, policy.token_caps());
    populate_sleep_cap_env_or_insert(&mut env, policy.sleep_caps());

    // V2.7 `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` +
    // `INV-KSB-MAX-TURNS-VISIBILITY-01` — resolve the per-task hard
    // turn ceiling here so the SAME value reaches both the
    // `RAXIS_PLANNER_MAX_TURNS` env stamp (this `_or_insert` call)
    // and the KSB capabilities projection
    // (`KsbInputs::planner_max_turns` populated below). Single source
    // of truth: env stamp + KSB project from one resolver call.
    let task_fields_for_max_turns = {
        let key = crate::initiatives::TaskKey::new(initiative_id, task_id);
        plan_registry.get(&key)
    };
    let (planner_max_turns_resolved, _) = resolve_planner_max_turns_for(
        task_fields_for_max_turns.as_ref(),
        policy.gateway(),
    );
    populate_planner_max_turns_env_or_insert(
        &mut env,
        task_fields_for_max_turns.as_ref(),
        policy.gateway(),
        task_id,
        session_id,
        initiative_id,
    );

    // V2 `v2_extended_gaps.md §2.4` — assemble the per-task KSB
    // and stamp into `RAXIS_PLANNER_KSB`. Same fallback policy as
    // the orchestrator path: if the SQLite read fails the spawn
    // proceeds with a minimum-bootable snapshot so a transient
    // contention does not block task activation. Reviewers and
    // executors get the same DAG view (per-initiative tasks) so
    // the model can reason about predecessor / successor state.
    let role = match agent_kind {
        ExecutorAgentKind::Executor => crate::initiatives::ksb_assembly::KsbRole::Executor,
        ExecutorAgentKind::Reviewer => crate::initiatives::ksb_assembly::KsbRole::Reviewer,
    };
    let ksb_snapshot = {
        let store_for_ksb     = Arc::clone(store);
        let registry_for_ksb  = Arc::clone(plan_registry);
        let initiative_owned  = initiative_id.to_owned();
        let task_owned        = task_id.to_owned();
        let session_owned     = session_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = store_for_ksb.lock_sync();
            crate::initiatives::ksb_assembly::assemble_ksb_snapshot(
                &*conn,
                &registry_for_ksb,
                &crate::initiatives::ksb_assembly::KsbInputs {
                    initiative_id: &initiative_owned,
                    task_id:       Some(&task_owned),
                    role,
                    token_budget_remaining:        0,
                    wallclock_budget_remaining_s:  0,
                    credential_ports:              Vec::new(),
                    // Slice C — stamp the executor / reviewer
                    // session id (already minted at this call
                    // site) into the capabilities envelope.
                    session_id:                    &session_owned,
                    planner_max_turns:             planner_max_turns_resolved,
                },
            )
        })
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_else(|| {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"executor_ksb_assembly_fallback\",\
                 \"initiative_id\":\"{initiative_id}\",\"task_id\":\"{task_id}\",\
                 \"session_id\":\"{session_id}\"}}",
            );
            crate::initiatives::ksb_assembly::fallback_snapshot(
                initiative_id,
                Some(task_id),
                role,
            )
        })
    };
    let ksb_json = serde_json::to_string(&ksb_snapshot)
        .expect("KsbSnapshot is Serialize-derived; serialization cannot fail");
    // Same channel selection as the orchestrator path: prefer the
    // virtiofs sidecar so the AVF cmdline budget stays under
    // `COMMAND_LINE_SIZE`. Two payload classes blow the budget
    // when inlined: the reviewer KSB (per-initiative DAG, ~1 KiB),
    // and the operator-authored task prompt the caller stamped
    // into `extra_env` under `RAXIS_PLANNER_TASK_PROMPT` (the
    // realistic-scenario `materializer.md` / `service_round_trip.md`
    // / `transparent_proxy_real_scripts.md` are 2.7–6.9 KiB which
    // after base64 (4/3) consistently truncates the
    // `-- --task-id <ID> --initiative-id <ID>` argv tail and
    // produces guest-side `bad-env-token` + `missing value for
    // flag: --initiative-id` boot failures). We move the prompt
    // into the same per-session meta sidecar that already holds
    // the KSB so a single virtiofs share covers both, and stamp
    // the corresponding `…_PATH` env values back into `env`.
    //
    // Falls back to the legacy inline channels when no `data_dir`
    // is available (in-process subprocess-isolation tests).
    let task_prompt_for_sidecar =
        env.remove(PLANNER_TASK_PROMPT_ENV);
    let meta_sidecar = provision_meta_sidecar(
        spawn_ctx.data_dir.as_deref(),
        session_id,
        Some(&ksb_json),
        task_prompt_for_sidecar.as_deref(),
    );
    match &meta_sidecar {
        Some(s) => {
            if let Some(p) = &s.ksb_guest_path {
                env.insert(raxis_ksb::PLANNER_KSB_PATH_ENV.to_owned(), p.clone());
            } else {
                env.insert(raxis_ksb::PLANNER_KSB_ENV.to_owned(), ksb_json.clone());
            }
            if let Some(p) = &s.task_prompt_guest_path {
                env.insert(
                    raxis_types::planner_env::PLANNER_TASK_PROMPT_PATH_ENV.to_owned(),
                    p.clone(),
                );
            } else if let Some(prompt) = &task_prompt_for_sidecar {
                // Sidecar attempt skipped task prompt write (caller
                // passed `None` or the file write failed silently).
                // Keep the inline env so the planner still boots.
                env.insert(PLANNER_TASK_PROMPT_ENV.to_owned(), prompt.clone());
            }
            workspace_mounts.push(s.mount.clone());
        }
        None => {
            env.insert(raxis_ksb::PLANNER_KSB_ENV.to_owned(), ksb_json);
            if let Some(prompt) = task_prompt_for_sidecar {
                env.insert(PLANNER_TASK_PROMPT_ENV.to_owned(), prompt);
            }
        }
    }
    let vm_spec = VmSpec {
        vcpu_count,
        mem_mib,
        egress_tier,
        cgroup_quota:      None,
        boot_args:         Vec::new(),
        entrypoint_argv,
        // Per-session token; the substrate stamps it into the
        // guest env under `RAXIS_SESSION_TOKEN`. Sourced from the
        // canonical `sessions.session_token` column inserted by the
        // activation handler — same 64-char hex value the kernel-
        // mediated egress handler revalidates on every
        // `IpcMessage::PlannerFetchRequest`. INV-IPC-AUTH-01.
        session_token:     SessionToken(session_token_db.clone()),
        vsock_cid:         None,
        virtio_fs_mounts:  Vec::new(),
        // Same host-canonical kernel binary as the orchestrator path.
        // SubprocessIsolation ignores; AVF/Firecracker hand it to
        // their boot loaders.
        linux_kernel_path: crate::canonical_images_preflight::linux_kernel_path(
            &spawn_ctx.install_dir,
        ),
        env,
        guest_console_log: spawn_ctx
            .data_dir
            .as_ref()
            .map(|d| d.join("guests").join(session_id).join("console.log")),
    };

    // ── Step 3.5: consult the per-role scale-down history. ────────
    //
    // V2 `elastic-vm-scaling.md §4.4` — bias the next spawn smaller
    // when the recent rolling window for this role is under-used.
    // The bias is allowed even when `elastic = false` (`§6` —
    // scale-down never raises capacity).
    let role = match agent_kind {
        ExecutorAgentKind::Executor => crate::elastic::RoleKey::Executor,
        ExecutorAgentKind::Reviewer => crate::elastic::RoleKey::Reviewer,
    };
    let plan_overrides = plan_elastic_overrides_for_task(
        plan_registry,
        initiative_id,
        task_id,
    );
    let (vm_spec, scale_down_decision) = maybe_apply_scale_down(
        vm_spec,
        role,
        &spawn_ctx.scale_down_history,
        &spawn_ctx.rate_limiter,
        policy.elastic(),
        service.audit(),
        session_id,
        Some(task_id),
        initiative_id,
        &plan_overrides,
    );

    // ── Step 4: delegate via the bounded-retry helper. ────────────
    //
    // V2 `elastic-vm-scaling.md §3.2` — see the matching block on
    // the orchestrator-spawn path. Same retry semantics apply to
    // Executor / Reviewer activations: transient
    // `IsolationError`s are retried with exponential backoff
    // bounded by `policy.[elastic].transient_retry_max_attempts`,
    // permanent failures short-circuit to `SessionVmFailedFinal`.
    let proto = SpawnRequestProto {
        session_id:       session_id.to_owned(),
        task_id:          Some(task_id.to_owned()),
        initiative_id:    initiative_id.to_owned(),
        image:            verified_image,
        workspace_mounts,
        vm_spec,
        credentials,
        egress_allowlist,
    };
    let handle = spawn_with_transient_retry(
        &service,
        policy.elastic(),
        proto,
    ).await?;

    // ── Step 5: emit SessionVmScaleEvent on a successful down-bias.
    //
    // INV-ELASTIC-03 write-then-emit ordering: the new VM is
    // bound (SessionVmSpawned was emitted inside spawn_session);
    // the scale event lands AFTER so audit replay attributes the
    // smaller spec to the §4.4 bias. Audit-emit failure is logged
    // and the tracker is cleared so a future spawn does not also
    // wedge on the same condition.
    if let Some((prev_vcpus, prev_mb, new_vcpus, new_mb, reason)) = scale_down_decision {
        if let Err(e) = crate::elastic::emit_scale_event_audit(
            service.audit(),
            session_id,
            Some(task_id),
            initiative_id,
            crate::elastic::ScaleDirection::Down,
            prev_vcpus,
            new_vcpus,
            prev_mb,
            new_mb,
            &reason,
        ) {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"executor_scale_down_audit_emit_failed\",\
                 \"session_id\":\"{session_id}\",\"task_id\":\"{task_id}\",\"error\":\"{e}\"}}",
            );
        }
        spawn_ctx.scale_down_history.clear(role);
    }

    Ok(handle)
}

/// Project the `[[plan.tasks]]` elastic overrides for
/// `(initiative_id, task_id)` into the
/// [`crate::elastic::PlanElasticOverrides`] shape consumed by the
/// §4.4 chokepoint.
///
/// Returns `Default` when the registry has no entry for the task
/// (e.g. an orchestrator spawn that pre-dates the registry write,
/// or a test fixture that hasn't populated the registry). The
/// default produces no plan-level narrowing, so the policy
/// ceiling alone governs the spawn.
fn plan_elastic_overrides_for_task(
    registry:      &Arc<crate::initiatives::PlanRegistry>,
    initiative_id: &str,
    task_id:       &str,
) -> crate::elastic::PlanElasticOverrides {
    let key = crate::initiatives::TaskKey::new(initiative_id, task_id);
    match registry.get(&key) {
        Some(fields) => crate::elastic::PlanElasticOverrides {
            elastic:        fields.elastic,
            min_vcpus:      fields.min_vcpus,
            max_vcpus:      fields.max_vcpus,
            min_memory_mb:  fields.min_memory_mb,
            max_memory_mb:  fields.max_memory_mb,
        },
        None => crate::elastic::PlanElasticOverrides::default(),
    }
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

    /// Initialise a real source repository at
    /// `<data_dir>/repositories/main` with one commit on the
    /// requested branch. Mirrors the
    /// `worktree_provisioning::tests::bootstrap_source` shape and uses
    /// the version-agnostic `init` + `symbolic-ref HEAD` pair so the
    /// fixture works on git binaries that predate the `init -b` flag
    /// (git ≥ 2.28).
    fn bootstrap_source_repo(data_dir: &std::path::Path, branch: &str) {
        use std::process::Command;
        let main_repo = data_dir.join("repositories").join("main");
        std::fs::create_dir_all(&main_repo).expect("mkdir main repo");
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(&main_repo)
                .output()
                .unwrap_or_else(|e| panic!("git {args:?}: {e}"));
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr),
            );
        };
        run(&["init", "-q"]);
        run(&["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")]);
        run(&["config", "user.email", "test@raxis.local"]);
        run(&["config", "user.name", "raxis-test"]);
        std::fs::write(main_repo.join("README.md"), b"hello\n").unwrap();
        run(&["add", "README.md"]);
        run(&["commit", "-q", "-m", "initial"]);
    }

    /// Insert an Orchestrator session row keyed to `(session_id,
    /// initiative_id)` with a freshly-minted CSPRNG `session_token`.
    ///
    /// `spawn_orchestrator_for_initiative` (the production spawn
    /// path covered by these round-trip tests) reads the session row
    /// via `SELECT session_token … WHERE session_id = ?1` so it can
    /// stamp the **real** kernel-issued token into the spawned VM's
    /// env (`RAXIS_SESSION_TOKEN`) — INV-IPC-AUTH-01: the VM and the
    /// kernel must share the SAME token, never a synthetic spawn-
    /// boundary placeholder. The caller responsible for inserting
    /// the row is `auto_spawn_orchestrator_session_in_tx` in the
    /// production approve_plan / re-spawn paths; the test fixture
    /// reproduces that contract here so the spawn helper can find
    /// the row it expects.
    async fn insert_orchestrator_session_row(
        store: Arc<raxis_store::Store>,
        session_id: &str,
        initiative_id: &str,
    ) {
        // The raw `Store::lock_sync()` call below acquires
        // `tokio::sync::Mutex::blocking_lock`, which panics when
        // called from a runtime worker thread. Hop onto the
        // blocking pool — same pattern the kernel intent handlers
        // use (`run_phase_a`-style spawn_blocking wrap).
        let session = session_id.to_owned();
        let init    = initiative_id.to_owned();
        tokio::task::spawn_blocking(move || {
            insert_orchestrator_session_row_blocking(&store, &session, &init);
        })
        .await
        .expect("blocking insert must not panic");
    }

    fn insert_orchestrator_session_row_blocking(
        store: &raxis_store::Store,
        session_id: &str,
        initiative_id: &str,
    ) {
        use raxis_store::Table;
        use raxis_types::clock::unix_now_secs;
        use raxis_types::SessionAgentType;

        let token = raxis_crypto::token::generate_session_token()
            .expect("test session token generation must succeed");
        let lineage = uuid::Uuid::new_v4().to_string();
        let now      = unix_now_secs();
        let expires  = now + 3600;
        let conn = store.lock_sync();
        // FK guard: `sessions.initiative_id REFERENCES
        // initiatives(initiative_id)` (Migration 18); insert the
        // parent row first so the test fixture matches the
        // production order (`approve_plan` always inserts the
        // initiative before the orchestrator session). Use the
        // canonical `Executing` state — the spawn helper also runs
        // on the resume path against an `Executing` initiative.
        let _ = conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {init} (
                    initiative_id, state, terminal_criteria_json,
                    plan_artifact_sha256, created_at, approved_at
                 ) VALUES (?1, 'Executing', '[]', ?2, ?3, ?3)",
                init = Table::Initiatives.as_str(),
            ),
            rusqlite::params![
                initiative_id,
                hex::encode([0u8; 32]),
                now,
            ],
        );
        conn.execute(
            &format!(
                "INSERT INTO {sessions} (
                    session_id, role_id, session_token, sequence_number,
                    worktree_root, base_sha, base_tracking_ref,
                    lineage_id, fetch_quota, created_at, expires_at, revoked,
                    session_agent_type, can_delegate, initiative_id
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,?12,1,?13)",
                sessions = Table::Sessions.as_str(),
            ),
            rusqlite::params![
                session_id,
                "Planner",
                token,
                0i64,
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
                lineage,
                1000i64,
                now,
                expires,
                SessionAgentType::Orchestrator.as_sql_str(),
                initiative_id,
            ],
        )
        .expect("test fixture must insert orchestrator session row");
    }

    /// Test fixture: build the live `Arc<ArcSwap<PolicyBundle>>` the
    /// production wire feeds into `LiveOrchestratorSpawn`. Uses
    /// `PolicyBundle::for_tests_with_operators(vec![])` so the spawn
    /// path stamps no optional `RAXIS_PLANNER_MAX_TOKENS_*` env vars
    /// (the test fixture has no `[budget.token_caps]` section),
    /// keeping these spawn-trait round-trips focused on the trait
    /// surface rather than token-cap stamping (which has its own
    /// dedicated unit tests on `populate_token_cap_env`).
    fn test_policy_arcswap()
        -> Arc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>>
    {
        Arc::new(arc_swap::ArcSwap::from_pointee(
            raxis_policy::PolicyBundle::for_tests_with_operators(vec![]),
        ))
    }

    #[tokio::test]
    async fn live_orchestrator_spawn_full_round_trip_through_trait_surface() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
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

        // ── Real data_dir with a bootstrapped source repository at
        //    `<data_dir>/repositories/main`. Production
        //    `spawn_orchestrator_for_initiative` requires `data_dir`
        //    to be wired via `with_data_dir` so the Step 24b
        //    worktree-provisioning gix clone has a real source repo
        //    to attach to (see the `OrchestratorSpawnContext is
        //    missing data_dir` guard around line 705). The
        //    bootstrap mirrors the
        //    `worktree_provisioning::tests::bootstrap_source` shape
        //    and uses the version-agnostic `init` + `symbolic-ref`
        //    pair so the fixture works on older git binaries too.
        let data_dir = tempfile::tempdir().unwrap();
        bootstrap_source_repo(data_dir.path(), "main");

        let spawn_ctx = OrchestratorSpawnContext::new(
            install.path().to_path_buf(),
            kernel_version.to_owned(),
        )
        .with_data_dir(data_dir.path().to_path_buf());

        let allowlist = EgressAllowlist {
            exact_hosts: vec!["api.anthropic.com".into()],
            ..Default::default()
        };

        let session_id = "kernel-orch-test-1";
        let initiative_id = "init-kernel-orch-test-1";

        // V2 INV-IPC-AUTH-01: the spawn path reads
        // `sessions.session_token` for `session_id` so the spawned
        // VM gets the SAME CSPRNG token the kernel will validate
        // against subsequent IPC. Production
        // (`auto_spawn_orchestrator_session_in_tx`) inserts this row
        // BEFORE calling `spawn_for_initiative`; the test reproduces
        // that ordering.
        insert_orchestrator_session_row(
            Arc::clone(&store),
            session_id,
            initiative_id,
        )
        .await;

        // Drive the production trait impl exactly as `handle_approve_plan` does.
        let live: Arc<dyn OrchestratorSpawn> = Arc::new(
            LiveOrchestratorSpawn::new(
                spawn_ctx,
                Arc::clone(&service),
                Arc::clone(&store),
                Arc::new(crate::initiatives::PlanRegistry::new()),
                test_policy_arcswap(),
            )
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
        // Poison tolerance: if a sibling test in this module panicked
        // before releasing `ENV_LOCK` (e.g. an `expect()` blew up after
        // grabbing the guard), the std mutex marks the lock poisoned
        // and the next `.lock().unwrap()` would itself panic with
        // `PoisonError`. The guard here only serialises an env-var
        // flip — no shared state is left in an inconsistent state on
        // panic — so recovering the inner guard with `into_inner` is
        // safe and keeps this test independently runnable.
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
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
            LiveOrchestratorSpawn::new(
                spawn_ctx,
                service,
                store,
                Arc::new(crate::initiatives::PlanRegistry::new()),
                test_policy_arcswap(),
            ),
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
        // Defaults survive the builder. The orchestrator runs a
        // single-stream model loop so 1 vCPU is sufficient; mem
        // is sized for the dev-host initramfs (~217 MiB unpacked)
        // plus headroom for the planner runtime.
        assert_eq!(ctx.vcpu_count, 1);
        assert_eq!(ctx.mem_mib, 1024);
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
        // Defaults survive the builder. Values pinned to
        // `host-capacity.md §4.1` reference + `dev-host` initramfs
        // image-size budget (executor 2 vCPU / 2 GiB; reviewer
        // 1 vCPU / 1 GiB).
        assert_eq!(ctx.executor_vcpu_count, 2);
        // 6 GiB — see `ExecutorSpawnContext::new` for the dev-host
        // initramfs unpacker capacity rationale (560 MiB cpio.gz +
        // decompressor working set + tmpfs rootfs); the floor is
        // pinned because dropping it back to 2 GiB regresses every
        // realistic-scenario dev-host run with a kernel-mode panic
        // (`VFS: Unable to mount root fs on unknown-block(0,0)`).
        assert_eq!(ctx.executor_mem_mib, 6 * 1024);
        assert_eq!(ctx.reviewer_vcpu_count, 1);
        assert_eq!(ctx.reviewer_mem_mib, 1024);
    }

    /// `provision_meta_sidecar` writes BOTH the KSB JSON and the
    /// task prompt into a single per-session meta dir, returns one
    /// virtiofs mount, and surfaces guest-visible `/raxis-meta/<name>`
    /// paths for both. This is the kernel-side half of the
    /// cmdline-overflow workaround documented on
    /// [`raxis_types::planner_env::PLANNER_TASK_PROMPT_PATH_ENV`].
    #[test]
    fn provision_meta_sidecar_writes_both_files_into_one_mount() {
        let dir = tempfile::tempdir().unwrap();
        let session_id = "test-session-7";
        let s = provision_meta_sidecar(
            Some(dir.path()),
            session_id,
            Some("{\"version\":1}"),
            Some("operator-prompt-bytes"),
        )
        .expect("sidecar provisioning succeeds against a real tempdir");
        let host_meta = dir.path()
            .join("guests")
            .join(session_id)
            .join("meta");
        assert_eq!(s.mount.host_path, host_meta);
        assert_eq!(s.mount.guest_path, raxis_ksb::PLANNER_KSB_GUEST_MOUNT);
        assert!(matches!(s.mount.mode, raxis_isolation::MountMode::ReadOnly));

        let ksb_file = host_meta.join(raxis_ksb::PLANNER_KSB_FILE_NAME);
        let prompt_file = host_meta.join(raxis_ksb::PLANNER_TASK_PROMPT_FILE_NAME);
        assert_eq!(std::fs::read_to_string(&ksb_file).unwrap(), "{\"version\":1}");
        assert_eq!(std::fs::read_to_string(&prompt_file).unwrap(), "operator-prompt-bytes");

        assert_eq!(
            s.ksb_guest_path.as_deref(),
            Some(format!(
                "{m}/{f}",
                m = raxis_ksb::PLANNER_KSB_GUEST_MOUNT,
                f = raxis_ksb::PLANNER_KSB_FILE_NAME,
            ).as_str()),
        );
        assert_eq!(
            s.task_prompt_guest_path.as_deref(),
            Some(format!(
                "{m}/{f}",
                m = raxis_ksb::PLANNER_KSB_GUEST_MOUNT,
                f = raxis_ksb::PLANNER_TASK_PROMPT_FILE_NAME,
            ).as_str()),
        );
    }

    /// Asking for only the task prompt (KSB = None) still produces
    /// the mount and writes only the prompt file. Pins the
    /// independent-channel contract — the orchestrator path uses
    /// both, but a future caller could request just one.
    #[test]
    fn provision_meta_sidecar_supports_partial_writes() {
        let dir = tempfile::tempdir().unwrap();
        let s = provision_meta_sidecar(
            Some(dir.path()),
            "session-prompt-only",
            None,
            Some("just the prompt"),
        )
        .expect("sidecar provisioning succeeds with prompt-only");
        assert!(s.ksb_guest_path.is_none());
        assert!(s.task_prompt_guest_path.is_some());
        let host_meta = dir.path()
            .join("guests")
            .join("session-prompt-only")
            .join("meta");
        assert!(host_meta.join(raxis_ksb::PLANNER_TASK_PROMPT_FILE_NAME).exists());
        assert!(!host_meta.join(raxis_ksb::PLANNER_KSB_FILE_NAME).exists());
    }

    /// `data_dir = None` ⇒ `None` ⇒ caller falls back to inline
    /// envs. Pins the subprocess-isolation test contract: those
    /// tests construct a spawn context without a data_dir and
    /// expect the legacy inline env channels to keep working.
    #[test]
    fn provision_meta_sidecar_returns_none_without_data_dir() {
        let s = provision_meta_sidecar(
            None,
            "session-none",
            Some("ignored"),
            Some("ignored"),
        );
        assert!(s.is_none());
    }

    // ─────────────────────────────────────────────────────────────────
    // V2.7 `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` witness tests
    //
    // These tests exercise the pure resolver `resolve_planner_max_turns_for`
    // directly — that helper is what BOTH the env stamp
    // (`populate_planner_max_turns_env`) AND the KSB projection
    // (`assemble_capabilities` via `KsbInputs::planner_max_turns`) call
    // through. Pinning the resolver pins both surfaces by construction.
    // ─────────────────────────────────────────────────────────────────

    /// Helper: minimal `GatewaySection` with only the
    /// `planner_max_turns_default` field varying. The other fields
    /// are inert for this resolver — `resolve_planner_max_turns_for`
    /// reads only `planner_max_turns_default`.
    fn gateway_with_default(d: Option<u32>) -> raxis_policy::GatewaySection {
        raxis_policy::GatewaySection {
            binary_path:                "/bin/raxis-gateway".to_owned(),
            spawn_timeout_secs:         5,
            respawn_backoff_ms:         1000,
            max_consecutive_respawns:   5,
            planner_max_turns_default:  d,
        }
    }

    /// Helper: `TaskPlanFields` with only `max_turns` overridden.
    fn task_with_max_turns(c: Option<u32>) -> crate::initiatives::TaskPlanFields {
        let mut tf = crate::initiatives::TaskPlanFields::default();
        tf.max_turns = c;
        tf
    }

    /// `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` arm 1: a `Some(c)` on
    /// the per-task field MUST short-circuit the policy + compiled
    /// arms. The `source` label MUST read `"task"`.
    #[test]
    fn inv_planner_max_turns_precedence_01_per_task_wins_over_policy() {
        let task = task_with_max_turns(Some(7));
        let gw   = gateway_with_default(Some(42));
        let (resolved, source) = resolve_planner_max_turns_for(Some(&task), Some(&gw));
        assert_eq!(resolved, 7,
            "per-task `max_turns = Some(7)` MUST win over policy default 42");
        assert_eq!(source, "task",
            "resolver MUST label the per-task arm `task` for log parity");
    }

    /// `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` arm 2: `None` on the
    /// per-task field + `Some(d)` on the policy default MUST resolve
    /// to `d` with `source = "policy"`.
    #[test]
    fn inv_planner_max_turns_precedence_01_policy_wins_over_compiled() {
        let task = task_with_max_turns(None);
        let gw   = gateway_with_default(Some(42));
        let (resolved, source) = resolve_planner_max_turns_for(Some(&task), Some(&gw));
        assert_eq!(resolved, 42,
            "policy default 42 MUST win when per-task is None");
        assert_eq!(source, "policy",
            "resolver MUST label the policy arm `policy` for log parity");
    }

    /// `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` arm 3: both `None` ⇒
    /// the compiled `DEFAULT_PLANNER_MAX_TURNS` with
    /// `source = "compiled-default"`.
    #[test]
    fn inv_planner_max_turns_precedence_01_compiled_default_when_both_absent() {
        let task = task_with_max_turns(None);
        let gw   = gateway_with_default(None);
        let (resolved, source) = resolve_planner_max_turns_for(Some(&task), Some(&gw));
        assert_eq!(
            resolved,
            crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
            "both arms None ⇒ compiled fallback DEFAULT_PLANNER_MAX_TURNS",
        );
        assert_eq!(source, "compiled-default",
            "resolver MUST label the compiled-fallback arm `compiled-default`");
    }

    /// `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` orchestrator-spawn
    /// invariant: orchestrator sessions are per-initiative (no task
    /// fields), so the resolver MUST be called with
    /// `task_fields = None` and the per-task arm is structurally
    /// unreachable. This test pins that contract: even if a task
    /// fields struct existed with a `Some(c)` override, passing
    /// `None` MUST still resolve via the policy / compiled arms.
    #[test]
    fn inv_planner_max_turns_precedence_01_orchestrator_path_ignores_task_arm() {
        // Policy wins (compiled would be 100, policy is 33).
        let gw_with_policy = gateway_with_default(Some(33));
        let (resolved, source) = resolve_planner_max_turns_for(None, Some(&gw_with_policy));
        assert_eq!(resolved, 33);
        assert_eq!(source, "policy",
            "orchestrator-spawn path MUST label `policy` when task_fields=None and policy is Some");

        // No policy ⇒ compiled fallback.
        let gw_no_policy = gateway_with_default(None);
        let (resolved, source) = resolve_planner_max_turns_for(None, Some(&gw_no_policy));
        assert_eq!(
            resolved,
            crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
        );
        assert_eq!(source, "compiled-default",
            "orchestrator-spawn path MUST fall through to compiled-default when both task and policy are absent");

        // No gateway at all ⇒ also compiled fallback.
        let (resolved, source) = resolve_planner_max_turns_for(None, None);
        assert_eq!(
            resolved,
            crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
        );
        assert_eq!(source, "compiled-default");
    }

    /// `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` constant-parity guard:
    /// the kernel-side `DEFAULT_PLANNER_MAX_TURNS` MUST be bit-equal
    /// to `raxis_planner_core::DEFAULT_PLANNER_MAX_TURNS`. The two
    /// constants live in different crates because the kernel cannot
    /// take `raxis-planner-core` as a regular dependency (that crate
    /// pulls in `reqwest` and the HTTP-tier deps the kernel
    /// deliberately keeps out of its production tree). The constants
    /// MUST agree because the kernel resolves the value at spawn
    /// time and the planner-core dispatch loop reads the resolved
    /// value back from `RAXIS_PLANNER_MAX_TURNS`; if the two
    /// fallbacks diverged, an env-stamp gap on the kernel side
    /// would silently downgrade to the planner-core default and the
    /// operator's intended budget would be ignored.
    #[test]
    fn inv_planner_max_turns_compiled_default_matches_planner_core() {
        assert_eq!(
            crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
            raxis_planner_core::DEFAULT_PLANNER_MAX_TURNS,
            "kernel-side DEFAULT_PLANNER_MAX_TURNS MUST equal planner-core's; \
             bump them in lock-step",
        );
    }
}
