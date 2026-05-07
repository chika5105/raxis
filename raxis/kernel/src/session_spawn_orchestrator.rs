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
use std::path::PathBuf;
use std::sync::Arc;

use raxis_egress_admission::{EgressAllowlist, PolicyAdmissionService};
use raxis_isolation::{
    EgressTier, ImageBody, ImageKind, ImageSignature, SessionToken, VerifiedImage, VmSpec,
};
use raxis_session_spawn::{SessionSpawnService, SpawnError, SpawnHandle, SpawnRequest};
use raxis_store::Store;
use thiserror::Error;

use crate::initiatives::lifecycle as kernel_lifecycle;

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
        }
    }
}

/// Spawn the canonical Orchestrator VM for a freshly-approved
/// initiative.
///
/// Inputs:
///
/// * `spawn_ctx` — install-dir + kernel-version + resource ceilings.
/// * `session_id` — pre-allocated by `auto_spawn_orchestrator_session_in_tx`
///   and returned in `PlanApproved::orchestrator_session_id`.
/// * `initiative_id` — passed straight through to the SpawnRequest
///   for audit attribution.
/// * `egress_allowlist` — the operator's policy bundle's egress
///   surface, lifted into an `EgressAllowlist` for the per-session
///   `PolicyAdmissionService`.
/// * `service` — the kernel's `SessionSpawnService` (typically
///   `Arc::clone(&ctx.session_spawn)`).
/// * `store` — needed to read `task_credential_proxies`. The
///   orchestrator session has no `[[tasks]]` row of its own (the
///   canonical orchestrator is auto-created), so the credential
///   decls returned here are always empty — but we read through the
///   uniform path for forward compat (a future spec extension may
///   permit operator-declared orchestrator credentials).
///
/// Side effects:
///
/// * One per-session credential-proxy listener per declared
///   credential (typically zero for the orchestrator).
/// * One per-session egress-admission TCP listener on loopback.
/// * One subprocess / Firecracker / AVF VM running the canonical
///   Orchestrator image.
/// * Audit chain: one `CredentialProxyStarted` per credential plus
///   one `SessionVmSpawned` paired with a future `SessionVmExited`.
///
/// Failure mode: every failure path tears down already-bound
/// listeners before returning the error (handled inside
/// `SessionSpawnService::spawn_session`). The kernel can safely
/// retry a failed orchestrator spawn without leaking ports.
pub async fn spawn_orchestrator_for_initiative(
    spawn_ctx:        &OrchestratorSpawnContext,
    session_id:       &str,
    initiative_id:    &str,
    egress_allowlist: EgressAllowlist,
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
        env:              BTreeMap::new(),
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
pub async fn terminate_orchestrator(
    session_id: &str,
    grace:      std::time::Duration,
    service:    Arc<SessionSpawnService>,
) -> Result<raxis_session_spawn::TerminationReport, OrchestratorSpawnError> {
    Ok(service.terminate_session(session_id, grace).await?)
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
    async fn spawn_orchestrator_for_initiative_full_round_trip() {
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

        let handle = spawn_orchestrator_for_initiative(
            &spawn_ctx,
            session_id,
            initiative_id,
            allowlist,
            Arc::clone(&service),
            &store,
        )
        .await
        .expect("orchestrator spawn");

        assert_eq!(handle.session_id, session_id);
        // Orchestrator has no credential decls -> empty loopback env.
        assert!(handle.loopback_env.is_empty());
        assert!(service.is_active(session_id).await);

        // ── Tear down. ────────────────────────────────────────
        let report = terminate_orchestrator(
            session_id,
            std::time::Duration::from_secs(2),
            Arc::clone(&service),
        )
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
    async fn spawn_orchestrator_with_missing_canonical_image_surfaces_typed_error() {
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

        let err = spawn_orchestrator_for_initiative(
            &spawn_ctx,
            "sess-missing-1",
            "init-missing-1",
            EgressAllowlist::default(),
            service,
            &store,
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
}
