// raxis-kernel — entry point.
//
// Normative reference: kernel-core.md §2.2 `src/main.rs` and the
// Kernel Startup Sequence table (9 steps).
//
// This file is intentionally thin — no policy logic, no IPC logic, no
// authority logic. Only: step sequencing + signal handling + error dispatch.
// Each step calls a subsystem function; this file is the call list.
//
// **INV-LIFECYCLE-01..07** (boot sequence, kernel-core.md §2.2)
// are **structurally enforced** by the linear ordering below: the
// 9-step startup sequence runs as one synchronous chain, so each
// invariant ("disk verified before keys loaded", "audit chain
// opened before any audit emission", etc.) holds by construction.
// V2_GAPS.md §13 Category 1 — annotation-only enforcement site.
//
// V2 scaffolding note: many sibling modules expose structs / enum
// variants / functions that the V2 hot path does not call yet
// (V3 reachability — orchestrator restart, witness recovery,
// scheduler re-entry, etc.). These are pinned by spec but intent-
// ionally unwired in the V2 binary. We allow `dead_code` at the
// crate root so the binary build is clean while the API surface
// stays stable for the V3 patches that will wire each in turn.
#![allow(dead_code)]

mod errors;
mod banner;
mod bootstrap;
mod authority;
mod canonical_images_preflight;
mod capacity;
mod dashboard_glue;
mod ipc;
mod recovery;
mod initiatives;
mod scheduler;
mod vcs;
mod witness_index;
mod gates;
mod gateway;
mod handlers;
mod isolation_select;
mod notifications;
mod path_scope;
mod policy_manager;
mod prompt;
mod push;
mod runtime;
mod session_spawn_orchestrator;
mod worktree_gc;

use std::sync::Arc;

use errors::{exit_with_code, KernelError};
use raxis_audit_tools::{
    last_chain_state, AuditEventKind, AuditSink, AuditWriter, FileAuditSink,
};
use raxis_policy::load_policy;
use raxis_store::Store;

/// Kernel data directory. Sourced from RAXIS_DATA_DIR env var, defaulting to ~/.raxis.
fn data_dir() -> std::path::PathBuf {
    if let Ok(val) = std::env::var("RAXIS_DATA_DIR") {
        std::path::PathBuf::from(val)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
        std::path::PathBuf::from(home).join(".raxis")
    }
}

#[tokio::main]
async fn main() {
    // Step 0: Print the boot banner.
    if std::env::var("RAXIS_LOG_FORMAT").as_deref() == Ok("json") {
        banner::print_boot_banner_json();
    } else {
        banner::print_boot_banner();
    }

    // Step 1: Parse CLI flags and environment.
    let data_dir = data_dir();
    let bootstrap_mode = std::env::var("RAXIS_BOOTSTRAP").is_ok();

    // Step 2: If bootstrap mode — enter bootstrap::run(). Does not return.
    //
    // Bootstrap is a synchronous, ceremony-driven path that opens the
    // kernel.db (Step 6.5: install the genesis `policy_epoch_history`
    // row) and therefore reaches `Store::lock_sync()`. Calling
    // `blocking_lock` from the `#[tokio::main]` thread panics with
    // "Cannot block the current thread from within a runtime", so we
    // delegate the entire bootstrap into `spawn_blocking`. On success
    // bootstrap calls `std::process::exit(0)` from inside the blocking
    // pool worker, which exits the whole process — control never
    // returns here.
    if bootstrap_mode {
        // Cert-mandatory (INV-CERT-01): the kernel only ever consumes a
        // pre-minted operator cert; the operator-private-key + cert-mint
        // flow lives offline (typically `raxis cert mint` on an
        // air-gapped workstation). The env var is `RAXIS_OPERATOR_CERT`
        // pointing at the resulting `*.cert.toml`.
        let config = bootstrap::BootstrapConfig {
            data_dir: data_dir.clone(),
            operator_cert_path: std::env::var("RAXIS_OPERATOR_CERT").ok().map(Into::into),
            force: std::env::var("RAXIS_FORCE").is_ok(),
        };
        let join_outcome =
            tokio::task::spawn_blocking(move || bootstrap::run(&config)).await;
        match join_outcome {
            Ok(Ok(())) => unreachable!("bootstrap::run must exit the process"),
            Ok(Err(e)) => exit_with_code(e),
            Err(join_err) => exit_with_code(KernelError::BootstrapFailed {
                reason: format!("bootstrap spawn_blocking join failed: {join_err}"),
            }),
        }
    }

    // Step 3: Load and verify signed policy artifact.
    let policy_path = data_dir.join("policy").join("policy.toml");
    let (policy, _raw_bytes, _sha256) = load_policy(&policy_path).unwrap_or_else(|e| {
        exit_with_code(KernelError::PolicyInvalid {
            reason: e.to_string(),
        })
    });
    // Wrap the policy bundle in an `Arc<ArcSwap<_>>` so the kernel can
    // flip the visible epoch in-process via `policy_manager::advance_epoch`
    // (kernel-core.md §`policy_manager.rs`). Every reader goes through
    // `policy.load()` which is wait-free.
    let policy_epoch_at_boot = policy.epoch();
    // V2_GAPS §D2 — boot-time FD limit check (host-capacity.md §12.1).
    //
    // The check runs BEFORE we wrap the policy in `ArcSwap` so we can
    // touch `policy.host_capacity()` directly without going through
    // a snapshot. Refusing to boot here is far cheaper than letting
    // the kernel start and discover the floor breach when the 17th
    // microVM tries (and fails) to grab a FD.
    {
        let cap = policy.host_capacity();
        match capacity::check_fd_limit_at_boot(cap.required_min_fd_limit) {
            capacity::FdLimitOutcome::Ok { current_soft, required } => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"FdLimitCheckOk\",\
                     \"current_soft\":{current_soft},\"required\":{required}}}",
                );
            }
            capacity::FdLimitOutcome::Insufficient { current_soft, required } => {
                exit_with_code(KernelError::HostCapacity {
                    reason: format!(
                        "FAIL_INSUFFICIENT_FD_LIMIT: RLIMIT_NOFILE soft \
                         limit {current_soft} is below floor {required}; \
                         raise via service manager (`LimitNOFILE=` for \
                         systemd) or `ulimit -n` before launching \
                         (host-capacity.md §12.1)"
                    ),
                });
            }
            capacity::FdLimitOutcome::Unknown => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"FdLimitCheckUnknown\",\
                     \"message\":\"getrlimit unavailable; skipping FD floor check\"}}",
                );
            }
        }
    }
    let policy: Arc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(policy));
    eprintln!(
        "{{\"level\":\"info\",\"message\":\"policy loaded\",\"epoch\":{policy_epoch_at_boot}}}"
    );

    // Step 4: Initialize key registry.
    let registry = match authority::load_key_registry(&data_dir) {
        Ok(r) => {
            eprintln!(
                "{{\"level\":\"info\",\"message\":\"key registry loaded\",\"authority_fp\":\"{}\"}}",
                authority::authority_pubkey_fingerprint(&r)
            );
            Arc::new(r)
        }
        Err(e) => exit_with_code(e),
    };

    // Step 5: Open kernel state store.
    let db_path = data_dir.join("kernel.db");
    let store = match Store::open(&db_path) {
        Ok(s) => {
            eprintln!("{{\"level\":\"info\",\"message\":\"store opened\"}}");
            Arc::new(s)
        }
        Err(e) => {
            exit_with_code(KernelError::StoreSchema {
                reason: e.to_string(),
            })
        }
    };

    // Step 6: Run recovery::reconcile — verify audit chain, sweep in-flight
    // tasks. recovery::reconcile internally calls Store::lock_sync() (it is
    // a synchronous API by design — see kernel-core.md §4.6); calling it
    // directly from `#[tokio::main]` would invoke `Mutex::blocking_lock()`
    // on the runtime thread and panic with "Cannot block the current
    // thread from within a runtime". Wrap in `spawn_blocking` to move the
    // sync work onto a dedicated blocking-pool thread. Same pattern as
    // `handlers/witness::handle` (kernel-core.md async-safety contract).
    let audit_dir = data_dir.join("audit");
    {
        let store_for_recovery = Arc::clone(&store);
        let audit_dir_for_recovery = audit_dir.clone();
        let recovery_outcome = tokio::task::spawn_blocking(move || {
            recovery::reconcile(&store_for_recovery, &audit_dir_for_recovery)
        })
        .await
        .unwrap_or_else(|join_err| {
            exit_with_code(KernelError::AuditChainBroken {
                reason: format!("recovery::reconcile spawn_blocking join failed: {join_err}"),
            })
        });
        match recovery_outcome {
            Ok(result) => {
                if result.swept_tasks > 0 {
                    eprintln!(
                        "{{\"level\":\"warn\",\"message\":\"recovery swept tasks\",\"count\":{}}}",
                        result.swept_tasks
                    );
                }
                if result.folded_integration_merge_attempts > 0 {
                    // V2 pre-merge verifier attempt rows folded by the
                    // §11.10.4 boot-time sweep. Surfaced separately
                    // from `swept_tasks` because they live in a
                    // strictly earlier pipeline phase (candidate-merge-
                    // tree → pre-merge-verifier) than the eventual
                    // main advance the V1 task FSM tracks.
                    eprintln!(
                        "{{\"level\":\"warn\",\
                         \"message\":\"recovery folded integration merge attempts\",\
                         \"count\":{}}}",
                        result.folded_integration_merge_attempts
                    );
                }
            }
            Err(e) => exit_with_code(e),
        }
    }

    // Step 7a: Open the AuditWriter on segment-000.jsonl. Per
    // kernel-store.md §2.5.2 this is the only writer to the JSONL chain;
    // no other module opens the file.
    //
    // Chain-resume: scan the existing segment to recover the last seq +
    // prev_sha256 so a kernel restart does NOT reset the chain. Without
    // this, every restart would emit a `KernelStarted` with seq=0 and
    // genesis prev_sha256, which `recovery::verify_audit_chain` would
    // immediately fail-close on at the next boot. `last_chain_state`
    // returns Ok(None) for missing/empty files (genesis case) and
    // Err(...) for any chain corruption (gap, prev_sha256 break,
    // malformed JSON). We treat any error as a fatal AuditChainBroken
    // — fail-closed parity with `recovery::verify_audit_chain`.
    let audit_path = audit_dir.join("segment-000.jsonl");
    let resume_info = match last_chain_state(&audit_path) {
        Ok(maybe) => maybe,
        Err(e) => exit_with_code(KernelError::AuditChainBroken {
            reason: format!("cannot resume audit segment {audit_path:?}: {e}"),
        }),
    };
    let (starting_seq, starting_prev) = match resume_info {
        Some(info) => {
            eprintln!(
                "{{\"level\":\"info\",\"message\":\"audit chain resumed\",\
                 \"next_seq\":{},\"prev_sha256\":\"{}\"}}",
                info.next_seq, info.prev_sha256
            );
            (info.next_seq, Some(info.prev_sha256))
        }
        None => {
            eprintln!(
                "{{\"level\":\"info\",\"message\":\"audit chain genesis\",\
                 \"path\":\"{}\"}}",
                audit_path.display()
            );
            (0, None)
        }
    };
    let writer = AuditWriter::open(&audit_path, starting_seq, starting_prev).unwrap_or_else(|e| {
        exit_with_code(KernelError::AuditChainBroken {
            reason: format!("cannot open audit segment {audit_path:?}: {e}"),
        })
    });
    // Two layers:
    //   inner  — `FileAuditSink`: the single owner of the JSONL writer.
    //            Used directly for the `KernelStarted` genesis emit
    //            below (no notifications — no operator could have
    //            subscribed to a kernel that hasn't started yet).
    //   audit  — `NotifyingAuditSink` decorator that fans every emit
    //            into the notification dispatcher (cli-readonly.md §5.6).
    //            Stored on `HandlerContext` so every IPC handler emits
    //            through the wrapped sink without remembering to call
    //            `notifications::dispatch` themselves.
    let inner_audit: Arc<dyn AuditSink> = Arc::new(FileAuditSink::new(writer));
    // V2_GAPS §C4 — the per-kernel `SidecarRegistry` lives here so the
    // notification dispatcher and `HandlerContext` share the same
    // per-channel state (concurrency caps, circuit breakers, drop
    // counters). Owned by an `Arc` so both the audit sink decorator
    // and the IPC context point at the same registry.
    let sidecar_registry = Arc::new(notifications::SidecarRegistry::new());
    let audit: Arc<dyn AuditSink> = Arc::new(
        notifications::NotifyingAuditSink::new(
            Arc::clone(&inner_audit),
            Arc::clone(&policy),
            data_dir.clone(),
        )
        .with_sidecar_registry(Arc::clone(&sidecar_registry))
        .with_store(Arc::clone(&store)),
    );

    // Step 8: Emit the canonical KernelStarted record. This is the very
    // first event in this kernel-process lifetime; with the v1 reset
    // policy above it is also the genesis event of the segment.
    //
    // We deliberately bypass the notifying wrapper here:
    //   - the inbox JSONL lives at `<data_dir>/notifications/inbox.jsonl`
    //     which the notifications dispatcher creates on first use;
    //   - operators don't need a `KernelStarted` line in the inbox to
    //     observe boot (the kernel's own stderr says it).
    // Sending through the wrapper would still work — it just produces
    // an inbox line nobody reads.
    let started_at = raxis_runtime::unix_now_secs();
    if let Err(e) = inner_audit.emit(
        AuditEventKind::KernelStarted {
            data_dir: data_dir.display().to_string(),
            policy_epoch: policy.load().epoch(),
            schema_version: 1,
        },
        None, None, None,
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"KernelStarted\",\"audit_emit_failed\":\"{e}\"}}"
        );
    }

    // Step 8a (V2.5 `integration-merge.md §11.3`): git_apply_pending
    // recovery sweep. Cases A/B/C — see
    // `recovery::reconcile_git_apply_pending`. Runs AFTER the audit
    // writer is open (so Cases A/B/C can emit
    // `GitConsistencyRepaired` / `GitConsistencyVerified` /
    // `GitStateInconsistent`), AFTER the canonical `KernelStarted`
    // event (so the recovery events are chained off it), and BEFORE
    // IPC accept (so a fresh IntegrationMerge admission cannot race
    // recovery — the pre-flight in `handlers/intent.rs` Step 3c
    // observes `git_apply_pending = 1` until recovery clears it).
    //
    // Synchronous + spawn_blocking like the existing
    // `recovery::reconcile` entry point above (uses `lock_sync()`
    // and synchronous git operations).
    {
        let store_for_git_recovery = Arc::clone(&store);
        let inner_audit_for_git_recovery = Arc::clone(&inner_audit);
        let audit_dir_for_git_recovery = audit_dir.clone();
        let data_dir_for_git_recovery = data_dir.clone();
        let recovery_outcome = tokio::task::spawn_blocking(move || {
            recovery::reconcile_git_apply_pending(
                &store_for_git_recovery,
                inner_audit_for_git_recovery.as_ref(),
                &audit_dir_for_git_recovery,
                &data_dir_for_git_recovery,
            )
        })
        .await;
        match recovery_outcome {
            Ok(report) => {
                if report.repaired + report.verified + report.inconsistent > 0 {
                    eprintln!(
                        "{{\"level\":\"info\",\"step\":\"git_apply_recovery\",\
                         \"repaired\":{},\"verified\":{},\"inconsistent\":{}}}",
                        report.repaired, report.verified, report.inconsistent,
                    );
                }
            }
            Err(join_err) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"git_apply_recovery\",\
                     \"error\":\"spawn_blocking join failed: {join_err}\"}}",
                );
            }
        }
    }

    // Step 8a': V2_GAPS §D2 — start the disk-full watchdog. The
    // watchdog polls `statvfs(disk_root)` every 5 seconds and
    // updates an atomic `DiskState` read by every write-class
    // intent handler. V2 ships only `halt_admit` behavior; the
    // watchdog therefore only flips the atomic state and emits
    // transition audit events — actual `FAIL_DISK_FULL` rejection
    // is handled by the intent handlers consulting
    // `DiskWatchdog::is_full()`. (Operators using V2 must size
    // disk capacity explicitly; the watchdog does not GC.)
    let disk_watchdog = {
        let cap = policy.load().host_capacity().clone();
        let root = cap.disk_root.clone()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| data_dir.clone());
        let w = capacity::DiskWatchdog::new(
            root,
            cap.min_free_disk_mb,
            cap.disk_full_behavior.clone(),
        );
        w.spawn(Arc::clone(&audit));
        Arc::new(w)
    };

    // Step 8b: V2 canonical-image digest preflight per
    // `INV-PLANNER-HARNESS-02` (Reviewer image) and
    // `INV-PLANNER-HARNESS-05` (Orchestrator image).
    //
    // Resolves `$RAXIS_INSTALL_DIR/images/raxis-{reviewer,orchestrator}-core-<version>.img`,
    // streams the SHA-256 of each present file, and surfaces:
    //   * `Ok` — digest matches the kernel-binary-pinned constant; no
    //     audit event needed (the absence of a violation IS the
    //     pass).
    //   * `Missing` — the image file is not on disk yet (early-deployment
    //     case, before `raxis-image-builder` lands or before the
    //     operator runs `raxis doctor canonical-images`); logged at
    //     warn level. The kernel boots; activations that need the
    //     image will fail-closed at `IsolationBackend::launch` time.
    //   * `ManifestMissing` — the `.img` is on disk but the sibling
    //     `<role>-<kernel_version>.manifest.toml` is not. Logged at
    //     warn level; activations that need the image fail-closed at
    //     launch time.
    //   * `TrustAnchorUnpopulated` — kernel binary was built before
    //     the release pipeline committed the
    //     `EXPECTED_KERNEL_SIGNING_KEY_BYTES` trust anchor (all-zero
    //     placeholder). Logged at warn level; activations fail-closed
    //     until the kernel is rebuilt against a populated trust anchor.
    //   * `ManifestRejected` — the manifest signature failed to verify
    //     against the trust anchor, was malformed, or did not match
    //     the on-disk image bytes. Treated as `Tampered` and emits
    //     `SecurityViolationDetected`.
    //   * `Tampered` — digest mismatch is real. The preflight emits
    //     `SecurityViolationDetected { violation_kind:
    //     "ReviewerImageDigestMismatch" | "OrchestratorImageDigestMismatch",
    //     expected, actual, path }` and the kernel continues so
    //     `IsolationBackend::launch` can fail-closed at the matching
    //     activation surface (defense-in-depth — preflight surfaces
    //     the audit event eagerly, the launch path enforces the
    //     gate).
    //
    // `RAXIS_INSTALL_DIR` is the operator-supplied bundle root
    // (default: `/usr/local/lib/raxis` for system installs;
    // `~/.local/share/raxis` for user installs). Falls back to
    // `data_dir` so dev workstations without a configured install
    // dir still see consistent preflight output.
    let install_dir = std::env::var("RAXIS_INSTALL_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| data_dir.clone());
    let kernel_version = env!("CARGO_PKG_VERSION");
    let canonical_image_outcomes =
        canonical_images_preflight::verify_canonical_images_at_boot(
            &install_dir,
            kernel_version,
            &*inner_audit,
        );
    for (kind, outcome) in &canonical_image_outcomes {
        match outcome {
            canonical_images_preflight::PreflightOutcome::Ok { path } => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"canonical_image_ok\",\
                     \"kind\":\"{}\",\"path\":\"{}\"}}",
                    kind.audit_kind(),
                    path.display(),
                );
            }
            canonical_images_preflight::PreflightOutcome::Missing { path } => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"canonical_image_missing\",\
                     \"kind\":\"{}\",\"path\":\"{}\",\
                     \"hint\":\"install the kernel-bundled image; \
                       Reviewer / Orchestrator activations cannot start without it\"}}",
                    kind.audit_kind(),
                    path.display(),
                );
            }
            canonical_images_preflight::PreflightOutcome::ManifestMissing {
                image_path, manifest_path,
            } => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"canonical_image_manifest_missing\",\
                     \"kind\":\"{}\",\"image_path\":\"{}\",\"manifest_path\":\"{}\",\
                     \"hint\":\"the .img is on disk but the sibling \
                        <role>-<kernel_version>.manifest.toml is not; \
                        Reviewer / Orchestrator activations cannot start \
                        until raxis-image-builder publishes the signed manifest\"}}",
                    kind.audit_kind(),
                    image_path.display(),
                    manifest_path.display(),
                );
            }
            canonical_images_preflight::PreflightOutcome::TrustAnchorUnpopulated { path } => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"canonical_image_trust_anchor_unpopulated\",\
                     \"kind\":\"{}\",\"path\":\"{}\",\
                     \"hint\":\"this kernel was built before the release pipeline \
                        committed the signing-key trust anchor; rebuild the kernel \
                        once raxis-canonical-images::EXPECTED_KERNEL_SIGNING_KEY_BYTES \
                        is populated\"}}",
                    kind.audit_kind(),
                    path.display(),
                );
            }
            canonical_images_preflight::PreflightOutcome::Tampered {
                path, expected, actual,
            } => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"BOOT_ERR_CANONICAL_IMAGE_TAMPERED\",\
                     \"kind\":\"{}\",\"path\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\",\
                     \"hint\":\"reinstall raxis from a verified source; \
                        operator remediation in system-requirements.md §3\"}}",
                    kind.audit_kind(),
                    path.display(),
                    expected,
                    actual,
                );
            }
            canonical_images_preflight::PreflightOutcome::ManifestRejected {
                image_path, manifest_path, reason,
            } => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"BOOT_ERR_CANONICAL_IMAGE_MANIFEST_REJECTED\",\
                     \"kind\":\"{}\",\"image_path\":\"{}\",\"manifest_path\":\"{}\",\"reason\":\"{}\",\
                     \"hint\":\"the manifest could not be loaded, parsed, or its signature/role/kernel-version \
                        failed the kernel's trust contract; reinstall from a verified source\"}}",
                    kind.audit_kind(),
                    image_path.display(),
                    manifest_path.display(),
                    reason,
                );
            }
        }
    }

    // Step 8c: Select + admit the V2 agent-runtime isolation substrate.
    //
    // Per `extensibility-traits.md §3.8` the kernel picks the
    // platform-default substrate (Firecracker on Linux, AVF on macOS)
    // and admits it through `verify_admission_tier`. The selector
    // returns the boxed backend + the verified tier so we can record
    // a single canonical `IsolationSubstrateSelected` audit row right
    // here. If the substrate self-reports `FallbackOnly` we ALSO
    // emit `IsolationFallbackBypass` (paired-write contract is
    // documented in `audit-paired-writes.md §4`: both events are
    // single, non-paired, and produced sequentially within this
    // boot block).
    //
    // `--unsafe-fallback-isolation`: V2 sources this from
    // `RAXIS_UNSAFE_FALLBACK_ISOLATION` (a kernel-internal env var,
    // not a user-facing CLI flag) so the substrate selector stays
    // pure-data and unit-testable. Operators that need to bypass the
    // R-1 admission bar set this in their systemd unit per
    // `system-requirements.md §11`.
    let runtime_subdir = data_dir.join("runtime");
    let _ = std::fs::create_dir_all(&runtime_subdir);
    let allow_fallback = std::env::var("RAXIS_UNSAFE_FALLBACK_ISOLATION").is_ok();
    let allow_wasm     = false;
    let isolation_backend: Arc<dyn raxis_isolation::Backend> = match
        isolation_select::select_isolation_backend(&isolation_select::SelectorInputs {
            runtime_dir:        runtime_subdir,
            allow_fallback,
            allow_wasm_sandbox: allow_wasm,
        })
    {
        Ok(selected) => {
            if let Err(e) = inner_audit.emit(
                AuditEventKind::IsolationSubstrateSelected {
                    backend_id:      selected.backend.backend_id().to_owned(),
                    tier:            serde_json::to_value(&selected.tier)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_else(|| "Unknown".to_owned()),
                    fallback_bypass: selected.fallback_bypass_required,
                },
                None, None, None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"IsolationSubstrateSelected\",\
                     \"audit_emit_failed\":\"{e}\"}}",
                );
            }
            if selected.fallback_bypass_required {
                let reason = std::env::var("RAXIS_UNSAFE_FALLBACK_ISOLATION_REASON")
                    .unwrap_or_default();
                if let Err(e) = inner_audit.emit(
                    AuditEventKind::IsolationFallbackBypass {
                        reason,
                        backend_id: selected.backend.backend_id().to_owned(),
                    },
                    None, None, None,
                ) {
                    eprintln!(
                        "{{\"level\":\"error\",\"event\":\"IsolationFallbackBypass\",\
                         \"audit_emit_failed\":\"{e}\"}}",
                    );
                }
            }
            eprintln!(
                "{{\"level\":\"info\",\"message\":\"isolation substrate admitted\",\
                 \"backend_id\":\"{}\",\"tier\":{}}}",
                selected.backend.backend_id(),
                serde_json::to_string(&selected.tier).unwrap_or_else(|_| "\"?\"".to_owned()),
            );
            selected.backend
        }
        Err(e) => {
            // V2 fail-closed boot. The previous degraded-mode path
            // ("kernel boots with isolation = None and rejects every
            // spawn at session-creation time") is removed: a kernel
            // without an admissible substrate cannot honour
            // `[[tasks]]` admission, and the V2 architecture relies
            // on `ctx.isolation` being a non-Optional
            // `Arc<dyn IsolationBackend>` so the dispatch sites do
            // not have to re-prove substrate availability at every
            // call site.
            //
            // Operators who need to run RAXIS on a substrate with
            // `IsolationLevel::FallbackOnly` set
            // `RAXIS_UNSAFE_FALLBACK_ISOLATION=1` (handled by
            // `select_isolation_backend` above). Hosts with no
            // admissible substrate at all surface the same error
            // here as a hard exit.
            let _ = inner_audit.emit(
                AuditEventKind::IsolationSubstrateRefused {
                    reason: e.to_string(),
                },
                None, None, None,
            );
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"BOOT_ERR_ISOLATION_UNAVAILABLE\",\
                 \"reason\":\"{e}\",\"hint\":\"V2 requires an admissible isolation \
                 substrate (Linux+KVM Firecracker or macOS Virtualization.framework). \
                 Set RAXIS_UNSAFE_FALLBACK_ISOLATION=1 + RAXIS_UNSAFE_FALLBACK_ISOLATION_REASON \
                 to admit FallbackOnly substrates on hosts without R-1 hardware.\"}}",
            );
            std::process::exit(64);
        }
    };

    // Step 8a: Spawn the heartbeat loop. cli-readonly.md §5.2.1 contract:
    //   - one initial write IMMEDIATELY (handled inside `run_loop`),
    //   - periodic writes every 5s thereafter,
    //   - one final `state = "Stopping"` write at shutdown.
    //
    // The loop owns no kernel state; it borrows `policy` (for the
    // current epoch number) and reaches into
    // `gates::verifier_runner::active_verifier_count()` for the
    // in-memory counter. Termination is driven by a oneshot we wire
    // into the post-IPC-shutdown step (10a) below — the same pattern
    // used by `gateway_shutdown_tx` for the gateway supervisor.
    //
    // Defensive `create_dir_all`: bootstrap creates `runtime/` at
    // genesis time (Phase A1 contract), but operators upgrading from
    // a pre-A1 kernel may not have it on disk. The cost of a no-op
    // mkdir at boot is one syscall.
    let _ = std::fs::create_dir_all(data_dir.join(raxis_runtime::RUNTIME_DIR));
    let (heartbeat_shutdown_tx, heartbeat_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let heartbeat_handle = {
        let data_dir_for_hb = data_dir.clone();
        let policy_for_hb = Arc::clone(&policy);
        let pid = std::process::id();
        tokio::spawn(async move {
            runtime::heartbeat_loop(
                data_dir_for_hb,
                pid,
                started_at,
                policy_for_hb,
                heartbeat_shutdown_rx,
            )
            .await
        })
    };

    // Step 8b: Spawn the V2.1 plan-bundle nonce sweep loop. Per
    // `plan-bundle-sealing.md §8.4` the kernel periodically reaps
    // rows from `plan_bundle_nonces_seen` whose
    // `first_seen_at_unix_secs` is older than
    // `[plan_signing].max_plan_bundle_age_secs +
    //  max_clock_skew_secs +
    //  nonce_retention_grace_secs`. The cadence comes from the same
    // `[plan_signing].nonce_sweep_interval_secs` field (default 1 h).
    //
    // Replay protection (`INV-PLAN-BUNDLE-FRESH`) survives the sweep:
    // a row that is eligible for deletion has, by construction, a
    // `signed_at_unix_secs` outside the freshness window already, so
    // any future re-submission of its bundle would be rejected by
    // admission step 10a (`FAIL_PLAN_BUNDLE_EXPIRED`) before step 10b
    // even queries the table.
    let (nonce_sweep_shutdown_tx, nonce_sweep_shutdown_rx) =
        tokio::sync::oneshot::channel::<()>();
    let nonce_sweep_handle = {
        let store_for_sweep  = Arc::clone(&store);
        let policy_for_sweep = Arc::clone(&policy);
        tokio::spawn(async move {
            runtime::nonce_sweeper_loop(
                store_for_sweep,
                policy_for_sweep,
                nonce_sweep_shutdown_rx,
            )
            .await;
        })
    };

    // Step 7b: Construct the in-memory PlanRegistry and repopulate it from
    // every non-terminal initiative's signed plan artifact. Per
    // kernel-store.md §2.5.8 the four path-scope plan fields live only
    // in memory; without this hook every intent submitted after a
    // restart would fail-closed with `FAIL_PATH_POLICY_VIOLATION`.
    //
    // Like `recovery::reconcile`, `repopulate_plan_registry` calls
    // `Store::lock_sync()` and MUST run via `spawn_blocking` to avoid
    // panicking the tokio runtime (`Cannot block the current thread from
    // within a runtime`). Pinned by
    // `kernel/tests/kernel_signal_shutdown.rs::sigterm_triggers_*`.
    let plan_registry = Arc::new(initiatives::PlanRegistry::new());
    {
        let store_for_repopulate = Arc::clone(&store);
        let registry_for_repopulate = Arc::clone(&plan_registry);
        // V2 `v2_extended_gaps.md §1.2` — repopulate also needs the
        // operator policy's `[git] default_target_ref` /
        // `target_ref_locked` so it can re-resolve every initiative's
        // per-initiative target_ref against the *current* policy and
        // stamp it back into `OrchestratorPlanFields::target_ref`.
        let snapshot = policy.load();
        let policy_default_target_ref = snapshot.git_default_target_ref().to_owned();
        let policy_target_ref_locked  = snapshot.git_target_ref_locked();
        let repopulate_outcome = tokio::task::spawn_blocking(move || {
            initiatives::lifecycle::repopulate_plan_registry(
                &store_for_repopulate,
                &registry_for_repopulate,
                &policy_default_target_ref,
                policy_target_ref_locked,
            )
        })
        .await;
        match repopulate_outcome {
            Ok(Ok(n)) => {
                eprintln!(
                    "{{\"level\":\"info\",\"message\":\"plan registry repopulated\",\
                     \"task_entries\":{n}}}"
                );
            }
            Ok(Err(e)) => {
                // Repopulate is best-effort: the per-initiative loop already
                // logs and skips on parse/missing-artifact failures, so an
                // overall error here would have to be a SQL/lock failure.
                // Surface it loudly but do not abort boot — fail-closed at
                // intent time is still safe.
                eprintln!(
                    "{{\"level\":\"error\",\"message\":\"plan_registry_repopulate failed\",\
                     \"reason\":\"{e}\"}}",
                );
            }
            Err(join_err) => {
                eprintln!(
                    "{{\"level\":\"error\",\"message\":\"plan_registry_repopulate join failed\",\
                     \"reason\":\"{join_err}\"}}",
                );
            }
        }
    }

    // Step 7c: Build the HandlerContext now that the audit sink AND the
    // plan registry exist.
    //
    // The `gateway_client` is created here too — it is shared between
    // the supervisor (which calls `set_expected_token` before each
    // spawn), the gateway accept loop (which calls `install_connection`
    // after a valid handshake), and any IPC handler that needs to
    // forward a fetch via `ctx.gateway.fetch(...)`. A single Arc is
    // cloned three ways below; cheap.
    let gateway_client = Arc::new(gateway::client::GatewayClient::new());
    // The EpochBinding is the in-memory v1 substitute for the spec's
    // `sessions.prompt_epoch_valid` column. Read by `prompt::assemble`,
    // written by `policy_manager::advance_epoch` after every epoch
    // rotation. A single Arc is shared across handlers via `ctx`.
    let epoch_binding = Arc::new(prompt::EpochBinding::new());

    // Step 8.0a — V2 credential backend (extensibility-traits.md §4.4).
    // The active selector lives in `policy.toml [credential_backend]`
    // and defaults to `File` when omitted. We construct the concrete
    // backend, wrap it in `AuditingBackend` so every resolve emits a
    // `CredentialAccessed` event, and inject it into `HandlerContext`
    // so the gateway and the credential proxies share one audited
    // seam. The wrapping is unconditional — the audit decorator owns
    // the `AuditSink` once, freeing concrete impls from repeating the
    // emit step in their own `resolve` / `rotate` bodies.
    let credentials: Arc<dyn raxis_credentials::CredentialBackend> = {
        use raxis_credentials::{AuditingBackend, CredentialBackendKind};
        let bundle = policy.load();
        let kind = bundle.credential_backend_kind();
        let inner: Arc<dyn raxis_credentials::CredentialBackend> = match kind {
            CredentialBackendKind::File => Arc::new(
                raxis_credentials_file::FileCredentialBackend::open(data_dir.clone()),
            ),
            other => {
                eprintln!(
                    "BOOT_ERR_CREDENTIAL_BACKEND_NOT_IMPLEMENTED: \
                     policy.toml selects credential_backend.kind = {} but only \
                     `file` is implemented in V2; future Vault / AWS-SM / \
                     Azure-KV / PKCS#11 backends are out of scope for V2 GA.",
                    other.as_str(),
                );
                std::process::exit(64);
            }
        };
        Arc::new(AuditingBackend::new(inner, Arc::clone(&audit)))
    };

    // Step 8.0c — V2 DomainAdapter selection.
    //
    // Spec: `extensibility-traits.md §2.6` (boot-order step). The
    // kernel binary monomorphises against the SE-domain binding in
    // V2; future trading / healthcare / robotics kernels swap the
    // adapter behind a `cfg`-gated boot-time selector. The three
    // host-side roots — main repo, per-session worktrees,
    // transfer staging — anchor under `<data_dir>/`; the
    // `worktree-provision` and `worktree-staging` crates own the
    // actual content laid down inside them.
    let domain: Arc<
        dyn raxis_domain::DomainAdapter<
            IntentKind       = raxis_domain_git::SeIntentKind,
            TerminalArtefact = raxis_domain_git::SeTerminalArtefact,
        >,
    > = {
        let main_root     = data_dir.join("repositories").join("main");
        let sessions_root = data_dir.join("worktrees");
        let transfer_root = data_dir.join("transfer");
        // Lay down the three roots if they are missing — the
        // worktree-provision crate expects them to exist before the
        // first session is admitted.
        for p in [&main_root, &sessions_root, &transfer_root] {
            if !p.exists() {
                if let Err(e) = std::fs::create_dir_all(p) {
                    eprintln!(
                        "BOOT_ERR_DOMAIN_DIR_CREATE: failed to create {}: {e}",
                        p.display(),
                    );
                    std::process::exit(64);
                }
            }
        }
        Arc::new(raxis_domain_git::GitAdapter::new(
            main_root,
            sessions_root,
            transfer_root,
        ))
    };

    // V2_GAPS §C5 — open the content-addressed artifact store
    // rooted at `<data_dir>/artifacts/`. The store is `O_CREAT |
    // O_EXCL` write-once and on-read SHA-256 verified; consumers
    // are `policy_manager::advance_epoch` (policy bytes),
    // `initiatives::lifecycle::approve_plan` (plan bytes + `.sig`),
    // and the operator-cert install path (operator pubkeys). On
    // open failure we exit closed — the artifact store is a
    // forensic backbone, and starting without it would silently
    // disable every spec-mandated write site.
    let artifact_store = match raxis_artifact_store::ArtifactStore::open(&data_dir) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"ArtifactStoreOpenFailed\",\
                 \"data_dir\":\"{}\",\"reason\":\"{e}\"}}",
                data_dir.display(),
            );
            std::process::exit(64);
        }
    };
    // Boot-time backfill: write the currently-active policy bytes
    // to the store so a fresh kernel has the matching artifact on
    // disk even before the first `advance_epoch`. Idempotent on
    // identical bytes; logs and continues on I/O failure (the
    // operator may be in a degraded `0700` state and we don't want
    // to refuse boot for an artifact-store hiccup).
    if let Ok(policy_bytes) = std::fs::read(&policy_path) {
        if let Err(e) = artifact_store.write(
            raxis_artifact_store::Category::Policy,
            &policy_bytes,
        ) {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"ArtifactStoreBackfillFailed\",\
                 \"category\":\"policy\",\"reason\":\"{e}\"}}",
            );
        }
    }

    let ctx_inner = ipc::context::HandlerContext::new(
        Arc::clone(&policy),
        Arc::clone(&registry),
        Arc::clone(&store),
        Arc::clone(&audit),
        data_dir.clone(),
        Arc::clone(&plan_registry),
        Arc::clone(&gateway_client),
        Arc::clone(&epoch_binding),
        Arc::clone(&credentials),
        Arc::clone(&isolation_backend),
        // Production wires the live orchestrator-spawn impl that
        // drives the canonical Orchestrator VM via the kernel's
        // `SessionSpawnService` (the same Arc that lands on
        // `ctx.session_spawn` for future executor-spawn handlers).
        // The boot-time install-dir + kernel-version are the only
        // values the bridge needs that aren't already on
        // `HandlerContext`. The pre-pass here clones the same
        // `(isolation, proxy, audit)` trio that `HandlerContext::new`
        // builds internally, so the bridge sees an equivalent
        // service; both will be unified in a follow-up so there's
        // a single SessionSpawnService instance shared across
        // orchestrator + executor spawn paths.
        {
            let proxy_manager_for_orch = Arc::new(
                raxis_credential_proxy_manager::CredentialProxyManager::new(
                    Arc::clone(&credentials),
                    Arc::clone(&audit),
                ),
            );
            let session_spawn_for_orch = Arc::new(
                raxis_session_spawn::SessionSpawnService::new(
                    Arc::clone(&isolation_backend),
                    proxy_manager_for_orch,
                    Arc::clone(&audit),
                ),
            );
            Arc::new(
                crate::session_spawn_orchestrator::LiveOrchestratorSpawn::new(
                    crate::session_spawn_orchestrator::OrchestratorSpawnContext::new(
                        install_dir.clone(),
                        kernel_version.to_owned(),
                    )
                    // V2_GAPS §B1 — wire data_dir so the spawn path
                    // can stamp `RAXIS_KERNEL_PLANNER_SOCKET` into
                    // the guest env (otherwise the planner binary
                    // has no transport to dial back to the kernel
                    // and falls through to scaffold/park mode).
                    .with_data_dir(data_dir.clone()),
                    session_spawn_for_orch,
                    Arc::clone(&store),
                    Arc::clone(&plan_registry),
                    // V2 `v2_extended_gaps.md §2.5` — share the live
                    // policy ArcSwap so the spawn path always reads
                    // the most-recent operator-signed
                    // `[budget.token_caps]` when stamping the
                    // per-session token caps into the planner-VM
                    // env. Hot-reloads land within one spawn cycle.
                    Arc::clone(&policy),
                ),
            )
        },
        // V2 — Executor / Reviewer spawn-context. Reuses the same
        // boot-time install-dir + kernel-version as the orchestrator
        // spawn so all three canonical images
        // (`raxis-{reviewer,orchestrator,executor-starter}-core`)
        // resolve through one root. Per-VM resource budgets default
        // to `host-capacity.md §4.1` reference values
        // (`ExecutorSpawnContext::new`).
        Arc::new(
            crate::session_spawn_orchestrator::ExecutorSpawnContext::new(
                install_dir.clone(),
                kernel_version.to_owned(),
            )
            // V2_GAPS §B1 — same data_dir wire-through for the
            // executor / reviewer path so activations carry the
            // planner UDS env stamp without each IPC handler having
            // to thread the path itself.
            .with_data_dir(data_dir.clone()),
        ),
        Arc::clone(&domain),
    )
    // V2_GAPS §D2 — install the disk-full watchdog so write-class
    // intent handlers see disk pressure on every poll. Tests that
    // do NOT spawn through the production boot path leave this
    // `None` and the handlers treat that as "always healthy"
    // (`HandlerContext::disk_watchdog`).
    .with_disk_watchdog(Arc::clone(&disk_watchdog))
    // V2_GAPS §C5 — install the content-addressed immutable
    // artifact store so policy-push / plan-approve / cert-install
    // call sites land their bytes under `<data_dir>/artifacts/`.
    .with_artifact_store(Arc::clone(&artifact_store))
    // V2_GAPS §C4 — share the per-kernel `SidecarRegistry`
    // between the audit-sink dispatcher and `HandlerContext`. One
    // semaphore per channel, one circuit breaker per channel, one
    // counter set surfaced to `raxis status`.
    .with_sidecar_registry(Arc::clone(&sidecar_registry));
    let ctx = Arc::new(ctx_inner);

    // Step 8.5: Spawn the gateway supervisor. The supervisor runs as a
    // long-lived tokio task: it spawns one `raxis-gateway` subprocess,
    // waits for it to exit, applies back-off, respawns. After
    // `[gateway].max_consecutive_respawns` it emits `GatewayQuarantined`
    // and stops. If `policy.gateway()` is None, the supervisor logs
    // and returns `NoGatewayConfigured` immediately (degraded mode).
    //
    // We hold a `oneshot::Sender<()>` so the post-IPC-dispatch shutdown
    // path (step 11 below) can ask the supervisor to kill the child
    // and exit cleanly. Without this signal a SIGTERM-shutdown of the
    // kernel would leave an orphaned `raxis-gateway` running until
    // its UDS read returned EOF — eventually fine, but not the clean
    // shutdown the spec mandates.
    let (gateway_shutdown_tx, gateway_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let supervisor_handle = {
        let gateway_section = policy.load().gateway().cloned();
        let socket_path = data_dir.join("sockets/gateway.sock");
        let data_dir_for_sup = data_dir.clone();
        let audit_for_sup = Arc::clone(&audit);
        let client_for_sup = Arc::clone(&gateway_client);
        tokio::spawn(async move {
            gateway::spawn_and_supervise(
                gateway_section,
                data_dir_for_sup,
                socket_path,
                audit_for_sup,
                client_for_sup,
                gateway_shutdown_rx,
            )
            .await
        })
    };

    // Step 8.6: v2_extended_gaps.md §4 — start the operator
    // dashboard HTTP server if `policy.toml [dashboard].enabled =
    // true`. Absent / disabled ⇒ no listener bound (zero
    // runtime cost). The handle is held until the orderly
    // shutdown path so `serve_with_shutdown` drains in-flight
    // requests cleanly.
    let dashboard_handle = match raxis_dashboard_kernel::load_dashboard_config(&policy_path) {
        Ok(Some(cfg)) => {
            // Wire the kernel-resident policy advancer so the
            // dashboard's `PUT /api/policy/toml` write surface
            // can drive the same `advance_epoch` pipeline as
            // the CLI. The dashboard NEVER holds the authority
            // private key — the operator signs offline and
            // pastes the detached signature into the editor.
            let advancer: Arc<dyn raxis_dashboard_kernel::PolicyAdvancer> =
                Arc::new(crate::dashboard_glue::KernelPolicyAdvancer::new(
                    Arc::clone(&registry),
                    Arc::clone(&store),
                    Arc::clone(&audit),
                    Arc::clone(&policy),
                    Arc::clone(&epoch_binding),
                    Some(Arc::clone(&artifact_store)),
                    policy_path.clone(),
                ));
            // Reuse the data layer's stream capture for the
            // gateway bridge by allocating it here so both
            // surfaces (file ring + broadcast channel) point
            // at the same `<data_dir>/streams/` directory.
            let stream_capture = raxis_dashboard_kernel::SessionStreamCapture::new(
                &data_dir,
                raxis_dashboard_kernel::CaptureConfig::default(),
            )
            .expect("create streams dir");
            match raxis_dashboard_kernel::start_dashboard_with_advancer(
                cfg.clone(),
                Arc::clone(&store),
                Arc::clone(&policy),
                data_dir.clone(),
                policy_path.clone(),
                started_at,
                stream_capture,
                advancer,
            )
            .await
            {
                Ok(h) => {
                    eprintln!(
                        "{{\"level\":\"info\",\"event\":\"dashboard_started\",\
                         \"local_addr\":\"{}\"}}",
                        h.local_addr()
                    );
                    Some(h)
                }
                Err(e) => {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"dashboard_start_failed\",\
                         \"reason\":\"{e}\"}}"
                    );
                    None
                }
            }
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"dashboard_config_parse_failed\",\
                 \"reason\":\"{e}\"}}"
            );
            None
        }
    };

    // Step 9: Enter IPC dispatch loop. Returns when SIGTERM or SIGINT is
    // received OR when one of the three accept loops dies. Either way we
    // emit `KernelStopped` for audit completeness; exit code differs.
    let shutdown = match ipc::server::start(&data_dir, ctx).await {
        Ok(reason) => reason,
        Err(e) => {
            // Try to tell the supervisor + heartbeat + nonce sweep to
            // clean up before bailing out. All channels are
            // best-effort — if a receiver was already dropped the
            // send returns Err, which we discard.
            let _ = gateway_shutdown_tx.send(());
            let _ = heartbeat_shutdown_tx.send(());
            let _ = nonce_sweep_shutdown_tx.send(());
            exit_with_code(e);
        }
    };

    // Step 9.5: Tell the gateway supervisor + heartbeat loop + nonce
    // sweeper to wind down. The supervisor sends SIGKILL to the child
    // (Tokio `Command::start_kill`) and waits for reap; the heartbeat
    // loop writes one final `state = "Stopping"` snapshot before
    // returning; the nonce sweeper exits on its current `select!`
    // arm without running a final sweep. Errors inside each are
    // logged from inside; we just need to know they're done before
    // emitting `KernelStopped`.
    let _ = gateway_shutdown_tx.send(());
    let _ = heartbeat_shutdown_tx.send(());
    let _ = nonce_sweep_shutdown_tx.send(());
    if let Some(h) = dashboard_handle {
        match h.shutdown().await {
            Ok(()) => eprintln!(
                "{{\"level\":\"info\",\"event\":\"dashboard_shutdown\"}}"
            ),
            Err(e) => eprintln!(
                "{{\"level\":\"warn\",\"event\":\"dashboard_shutdown_failed\",\
                 \"reason\":\"{e}\"}}"
            ),
        }
    }
    match supervisor_handle.await {
        Ok(reason) => eprintln!(
            "{{\"level\":\"info\",\"event\":\"gateway_supervisor_done\",\
             \"reason\":\"{:?}\"}}",
            reason
        ),
        Err(join_err) => eprintln!(
            "{{\"level\":\"warn\",\"event\":\"gateway_supervisor_join_failed\",\
             \"reason\":\"{join_err}\"}}"
        ),
    }
    match heartbeat_handle.await {
        Ok(Ok(())) => eprintln!(
            "{{\"level\":\"info\",\"event\":\"heartbeat_loop_done\"}}"
        ),
        Ok(Err(e)) => eprintln!(
            "{{\"level\":\"warn\",\"event\":\"heartbeat_loop_failed\",\
             \"reason\":\"{e}\"}}"
        ),
        Err(join_err) => eprintln!(
            "{{\"level\":\"warn\",\"event\":\"heartbeat_loop_join_failed\",\
             \"reason\":\"{join_err}\"}}"
        ),
    }
    match nonce_sweep_handle.await {
        Ok(()) => eprintln!(
            "{{\"level\":\"info\",\"event\":\"plan_bundle_nonce_sweep_loop_done\"}}"
        ),
        Err(join_err) => eprintln!(
            "{{\"level\":\"warn\",\
             \"event\":\"plan_bundle_nonce_sweep_loop_join_failed\",\
             \"reason\":\"{join_err}\"}}"
        ),
    }

    // Step 10: Emit `KernelStopped` audit event. This MUST be the last
    // record in the segment for this kernel-process lifetime; without it,
    // `recovery::verify_audit_chain` on the next boot still passes (the
    // chain is intact), but the operator cannot tell whether the previous
    // exit was clean. Per `kernel-core.md` startup-sequence step 9
    // sub-bullet "Signal handler registration".
    if let Err(e) = audit.emit(
        AuditEventKind::KernelStopped {
            reason: shutdown.audit_reason(),
        },
        None, None, None,
    ) {
        // Same dual-write fallback rationale as KernelStarted: if the chain
        // refuses our final record, log loudly so the operator can spot the
        // gap by inspecting both stderr and the segment.
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"KernelStopped\",\
             \"audit_emit_failed\":\"{e}\",\"reason\":\"{}\"}}",
            shutdown.audit_reason()
        );
    } else {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"KernelStopped\",\"reason\":\"{}\"}}",
            shutdown.audit_reason()
        );
    }

    // Step 11: Exit code reflects WHY we stopped:
    //   - SIGTERM / SIGINT  → operator-initiated; exit 0
    //   - AcceptLoopExited  → degraded; exit non-zero so init systems restart
    if shutdown.is_clean() {
        std::process::exit(0);
    } else {
        std::process::exit(KernelError::SocketBind {
            reason: format!("dispatch loop exited unexpectedly: {}", shutdown.audit_reason()),
        }.exit_code());
    }
}
