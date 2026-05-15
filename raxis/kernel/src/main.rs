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

mod authority;
mod banner;
mod bootstrap;
mod canonical_images_preflight;
mod capacity;
mod dashboard_glue;
mod errors;
// `concurrency-and-locking.md §INV-LOCK-07` /
// `self-healing-supervisor.md §3.1` — forensic-dump writer the
// deadlock watcher invokes before exiting non-zero. Lives in its
// own module so the watcher pipeline has zero dependency on the
// audit machinery (which may itself be wedged on the deadlocked
// mutex).
mod deadlock_dump;
// `self-healing-supervisor.md §3.3` — boot-time rehydration of
// the supervisor's restart context into the audit chain. Lives in
// its own module so the helper is testable in isolation (the
// witness for `INV-SUPERVISOR-RESTART-AUDIT-01` lives in the
// module's own `#[cfg(test)] mod tests`).
mod breakglass;
mod elastic;
mod gates;
mod gateway;
mod handlers;
mod initiatives;
mod ipc;
mod isolation_select;
mod notifications;
mod observability;
mod observability_boot;
mod orch_respawn_ceiling;
mod path_scope;
mod policy_manager;
mod prompt;
mod push;
mod recovery;
mod restart_lifecycle;
mod runtime;
mod scheduler;
mod session_activity;
mod session_spawn_orchestrator;
mod vcs;
mod witness_index;
mod worktree_gc;
// V2 §Step 24 / §Step 24b — host-side worktree provisioning seam.
// Composes `raxis-worktree-provision` + `raxis-domain-git` into the
// three role-specific operations the spawn / activation /
// completion handlers invoke. See module doc-comment.
mod worktree_provisioning;

use std::sync::Arc;

use errors::{exit_with_code, KernelError};
use raxis_audit_tools::{last_chain_state, AuditEventKind, AuditSink, AuditWriter, FileAuditSink};
use raxis_policy::load_policy;
use raxis_store::Store;

// `concurrency-and-locking.md §INV-LOCK-07` — runtime deadlock
// watcher. Forwards `parking_lot/deadlock_detection`'s lock-graph
// tracker through a 2-second-cadence background thread so a cycle
// across any kernel `parking_lot::Mutex` / `RwLock` is converted
// into a `panic!` (and, with `panic = "abort"` pinned in
// `raxis/Cargo.toml [profile.release]`, a non-zero process exit)
// in less than 3 seconds — vs the historical "wait until the
// 30-minute live-e2e wall-clock fires and the operator notices the
// missing heartbeat" failure mode that motivated this surface.
//
// Inert when `runtime-deadlock-detection` is off (no thread, no
// per-lock bookkeeping, no panic surface). The default feature set
// turns it ON for dev / CI / live-e2e; production release builds
// can opt out via `cargo build --release --no-default-features`
// (see `raxis/kernel/Cargo.toml [features]` for the full
// rationale).
#[cfg(feature = "runtime-deadlock-detection")]
fn spawn_deadlock_watcher(data_dir: std::path::PathBuf) {
    std::thread::Builder::new()
        .name("raxis-deadlock-watcher".to_owned())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let deadlocks = parking_lot::deadlock::check_deadlock();
            if deadlocks.is_empty() {
                continue;
            }
            // Surface the cycle on stderr in the same JSON-line
            // shape the rest of the kernel uses so log tail
            // consumers (live-e2e harness `iter*.log`,
            // `raxis status`, dashboard SSE) catch the cycle
            // immediately. We DO NOT route through the audit
            // sink: the sink itself takes locks
            // (`NotifyingAuditSink::with_store` holds an
            // `Arc<Store>`; `StreamingAuditSink` holds the
            // per-session capture mutex), and any of those
            // could be the very mutex that deadlocked. The
            // watcher MUST be the one path that exits
            // unconditionally, even from inside a wedged audit
            // pipeline.
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"deadlock_detected\",\
                 \"cycle_count\":{}}}",
                deadlocks.len(),
            );
            // Aggregate the cycle into a `DeadlockDump` while we
            // walk the per-cycle / per-thread surface — the dump
            // file is the structured forensic record the boot-
            // time rehydration path reads back to synthesise a
            // `KernelDeadlockDetected` audit event. The same
            // walk produces the per-thread stderr lines so the
            // structured-log + dump-file paths stay in sync.
            //
            // `self-healing-supervisor.md §3.2`: dump-write is
            // BEST-EFFORT. Disk-full / EROFS surfaces as a
            // structured stderr line and the watcher proceeds to
            // `process::exit(70)` regardless — the *exit signal*
            // is the unconditional contract; the dump is
            // best-effort persisted forensics.
            let detected_at_unix_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let mut total_threads: u32 = 0;
            let mut total_locks: u32 = 0;
            let mut cycles_out: Vec<deadlock_dump::DeadlockCycle> =
                Vec::with_capacity(deadlocks.len());
            for (cycle_idx, threads) in deadlocks.iter().enumerate() {
                let mut threads_out: Vec<deadlock_dump::DeadlockThread> =
                    Vec::with_capacity(threads.len());
                for t in threads {
                    eprintln!(
                        "{{\"level\":\"error\",\
                         \"event\":\"deadlock_cycle_member\",\
                         \"cycle\":{cycle_idx},\
                         \"thread_id\":{thread_id:?},\
                         \"backtrace\":{backtrace}}}",
                        thread_id = t.thread_id(),
                        backtrace = serde_json::to_string(&format!("{:?}", t.backtrace()))
                            .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
                    );
                    threads_out.push(deadlock_dump::DeadlockThread {
                        thread_id: format!("{:?}", t.thread_id()),
                        backtrace: format!("{:?}", t.backtrace()),
                    });
                    total_threads = total_threads.saturating_add(1);
                    // `t.backtrace()` reports one parked-frame
                    // per held lock acquisition; we don't have a
                    // first-class lock counter from parking_lot
                    // here, so we use the per-thread `1`
                    // contribution as a conservative proxy. The
                    // dump file's per-thread `backtrace` field
                    // is the source of truth for forensic
                    // analysis.
                    total_locks = total_locks.saturating_add(1);
                }
                cycles_out.push(deadlock_dump::DeadlockCycle {
                    cycle_index: cycle_idx as u32,
                    threads: threads_out,
                });
            }
            let dump = deadlock_dump::DeadlockDump {
                kernel_version: env!("CARGO_PKG_VERSION").to_owned(),
                detected_at_unix_secs,
                cycle_count: cycles_out.len() as u32,
                thread_count: total_threads,
                lock_count: total_locks,
                cycles: cycles_out,
            };
            match deadlock_dump::write_dump(&data_dir, &dump) {
                Ok(path) => eprintln!(
                    "{{\"level\":\"error\",\"event\":\"deadlock_dump_written\",\
                     \"path\":{path}}}",
                    path = serde_json::to_string(&path.display().to_string())
                        .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
                ),
                Err(e) => eprintln!(
                    "{{\"level\":\"error\",\"event\":\"deadlock_dump_write_failed\",\
                     \"reason\":{reason}}}",
                    reason = serde_json::to_string(&e.to_string())
                        .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
                ),
            }
            // `self-healing-supervisor.md §3.2` /
            // `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`:
            // exit 70 is the stable, supervisor-recognised
            // discriminator for "deadlock detected — restart
            // me". With `panic = "abort"` we used to surface
            // whatever the host's panic-abort code happened to
            // be (137 / 134 depending on platform); a
            // structured `process::exit(70)` is the wire
            // contract every supervisor (raxis-supervisor +
            // future launchd / systemd) classifies on.
            std::process::exit(70);
        })
        .expect("spawn raxis-deadlock-watcher thread");
}

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

    // `concurrency-and-locking.md §INV-LOCK-07` /
    // `self-healing-supervisor.md §3.2` — install the runtime
    // deadlock watcher BEFORE any kernel subsystem takes its first
    // `parking_lot::Mutex` (so the lock-graph tracker observes every
    // acquire from cycle-1 onward) and BEFORE bootstrap mode short-
    // circuits via `std::process::exit(0)` (so cert-mint / genesis
    // ceremony failures that wedge on a re-entrant `Mutex<Connection>`
    // are also covered, not just the long-running daemon path).
    //
    // The watcher needs `data_dir` so it can drop a forensic
    // `<data_dir>/deadlock_dump_<unix_ts>.json` next to the audit
    // chain on detection — but `data_dir` is already resolved
    // above (we hoisted the `data_dir = data_dir()` call above the
    // watcher spawn for this purpose).
    //
    // The watcher itself is `cfg(feature = "runtime-deadlock-detection")`
    // — release builds with the feature disabled get a no-op stub call
    // (the inner function is `cfg`'d away entirely; the call site stays
    // compiled but expands to nothing).
    #[cfg(feature = "runtime-deadlock-detection")]
    spawn_deadlock_watcher(data_dir.clone());

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
        let join_outcome = tokio::task::spawn_blocking(move || bootstrap::run(&config)).await;
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
            capacity::FdLimitOutcome::Ok {
                current_soft,
                required,
            } => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"FdLimitCheckOk\",\
                     \"current_soft\":{current_soft},\"required\":{required}}}",
                );
            }
            capacity::FdLimitOutcome::Insufficient {
                current_soft,
                required,
            } => {
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
        Err(e) => exit_with_code(KernelError::StoreSchema {
            reason: e.to_string(),
        }),
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
    // V2.5 (`self-healing-supervisor.md §3.5`): hoist the per-task
    // pre-sweep records out of Step 6 so the supervisor-aware
    // auto-resume codepath at Step 8a''' can consume them. Empty
    // when the sweep finds nothing to sweep — that's the
    // common-case kernel boot.
    let swept_tasks_detail: Vec<recovery::SweptTaskRecord> = {
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
                result.swept_tasks_detail
            }
            Err(e) => exit_with_code(e),
        }
    };

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

    // V2 `v2_extended_gaps.md §4.3` — allocate the dashboard's
    // session-stream capture EARLY so the audit sink can be
    // wrapped in `StreamingAuditSink` and every session-scoped
    // emit becomes a live SSE frame on the matching session's
    // stream. Without this bridge, the SSE endpoint subscribes
    // to an empty broadcast channel and the dashboard's session-
    // detail view sits forever on "Waiting for stream events…".
    //
    // Construction failure (read-only data dir / EROFS / ENOSPC)
    // logs and yields `None` — the audit sink is then wired
    // unwrapped and the dashboard SSE surface returns 404 on
    // subscribe, but every other kernel surface stays up.
    let dashboard_stream_capture: Option<Arc<raxis_dashboard_kernel::SessionStreamCapture>> =
        match raxis_dashboard_kernel::SessionStreamCapture::new(
            &data_dir,
            raxis_dashboard_kernel::CaptureConfig::default(),
        ) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"DashboardStreamCaptureInitFailed\",\
                     \"reason\":\"{e}\"}}"
                );
                None
            }
        };

    // Per-task LLM-turn capture (`task-llm-capture.md`). Sibling
    // to the session-stream capture above; keyed by `task_id` so
    // raw provider responses survive VM restarts within the same
    // task and an operator debugging a Failed task can read the
    // exact bytes the planner saw across every session that
    // worked on it. Construction failure (read-only data dir /
    // EROFS / ENOSPC) logs and yields `None` — the dashboard
    // route then returns 404 on `GET /api/tasks/:task_id/llm-turns`
    // but every other kernel surface stays up.
    let task_llm_capture: Option<Arc<raxis_dashboard_kernel::TaskLlmCapture>> =
        match raxis_dashboard_kernel::TaskLlmCapture::new(
            &data_dir,
            raxis_dashboard_kernel::TaskCaptureConfig::default(),
        ) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"TaskLlmCaptureInitFailed\",\
                     \"reason\":\"{e}\"}}"
                );
                None
            }
        };

    // Hoist the observability hub construction so the
    // `NotifyingAuditSink` can hold a reference and bridge V3 §3
    // metrics (egress admit/deny/default-grant/stall, credential-proxy
    // substitution) at the same moment the matching audit event lands.
    // `build_obs_hub` is a pure function of `policy`, `data_dir`,
    // and the `CARGO_PKG_VERSION` constant — all available here —
    // so this hoist costs only a single re-clone of the resulting
    // `Arc` at the original construction site below. The previous
    // `kernel_version` binding stays where it is (a few hundred lines
    // down) so other call sites that already use it don't have to
    // move; we re-derive the literal here from the same `env!` macro.
    let observability_hub: Arc<raxis_observability::ObservabilityHub> =
        observability_boot::build_obs_hub(&policy, &data_dir, env!("CARGO_PKG_VERSION"));

    // Chain the streaming-audit bridge on top of the notifying
    // decorator so:
    //   1. every audit emit reaches the JSONL writer first
    //      (FileAuditSink, innermost) — durability;
    //   2. then fans into the notification dispatcher
    //      (NotifyingAuditSink) — inbox + sidecars + V3 §3 metric bridge;
    //   3. then mirrors per-session events onto the dashboard
    //      capture (StreamingAuditSink, outermost) — live SSE.
    let notifying_audit: Arc<dyn AuditSink> = Arc::new(
        notifications::NotifyingAuditSink::new(
            Arc::clone(&inner_audit),
            Arc::clone(&policy),
            data_dir.clone(),
        )
        .with_sidecar_registry(Arc::clone(&sidecar_registry))
        .with_store(Arc::clone(&store))
        .with_observability(Arc::clone(&observability_hub)),
    );
    let audit: Arc<dyn AuditSink> = match dashboard_stream_capture.as_ref() {
        Some(cap) => Arc::new(raxis_dashboard_kernel::StreamingAuditSink::new(
            Arc::clone(&notifying_audit),
            Arc::clone(cap),
        )),
        None => notifying_audit,
    };

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
        None,
        None,
        None,
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"KernelStarted\",\"audit_emit_failed\":\"{e}\"}}"
        );
    }

    // V2 reviewer-egress-defaults-decision.md §5: emit one
    // `DefaultProviderEgressApplied` per implicit-provider grant
    // applied by the active policy bundle. No-op when the operator
    // opted out via `[egress] implicit_provider_grants = false`.
    // Bypass the notifying wrapper for the same reason
    // `KernelStarted` does — boot-time audit emits don't need to
    // dispatch to inboxes nobody has subscribed to yet.
    {
        let bundle_at_boot = policy.load();
        policy_manager::emit_default_provider_egress_applied(inner_audit.as_ref(), &bundle_at_boot);
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

    // Step 8a'' (V2.5 `self-healing-supervisor.md §3.3`): rehydrate
    // forensic deadlock dumps left behind by the previous kernel
    // run, AND synthesise the matching restart-lifecycle audit
    // events into the chain.
    //
    // **Order rationale.** Runs AFTER the canonical `KernelStarted`
    // (so the new event sequences chain off the fresh `prev_sha256`
    // computed by `last_chain_state` at Step 7a, keeping
    // `verify-chain` hash-clean across the restart boundary). Runs
    // AFTER the `reconcile_git_apply_pending` sweep so
    // `KernelRestartCompleted.recovery_sweep_ms` reflects the
    // *complete* boot recovery cost (Step 6 + Step 8a). Runs
    // BEFORE the disk-watchdog and IPC accept so the audit chain
    // already records the restart context if a downstream subsystem
    // refuses to come up.
    //
    // **Best-effort emit.** All audit emits below use `inner_audit`
    // (bypassing the notification wrapper) and *log* failures
    // rather than aborting boot — a kernel that successfully booted
    // a replacement after a deadlock is more useful than one that
    // refuses to boot because the prior dump file has a stale
    // schema. The supervisor's structured stderr log + the on-disk
    // dump file remain forensic backups.
    //
    // **Default-off compatibility (`INV-SUPERVISOR-OPT-IN-01`).**
    // The kernel reads dump files unconditionally (they may exist
    // because the kernel exited 70 in a non-supervised
    // configuration too — operator could re-launch manually after
    // a deadlock). The opt-in env var only gates the
    // *supervisor's* spawn loop, not the kernel's own bookkeeping.
    {
        let unix_now = raxis_runtime::unix_now_secs();
        // Wall-clock approximation of the boot-recovery sweep.
        // Measured from `started_at` (the canonical KernelStarted
        // timestamp captured at Step 8) to now. Sub-second
        // precision isn't required for the audit row; a future
        // PR can hoist an `Instant` if a tighter reading is
        // needed.
        let recovery_sweep_ms = unix_now.saturating_sub(started_at).saturating_mul(1000) as u64;
        let sentinel_path = data_dir.join("kernel_lifecycle_status.json");
        let sentinel = restart_lifecycle::read_sentinel_for_restart(&sentinel_path);
        let supervisor_restart_id = sentinel.as_ref().map(|s| {
            // Stable per-restart-episode identifier — multiple
            // `TaskAutoResumedAfterSupervisorRestart` events from
            // the SAME boot share this string, so the dashboard
            // can group them as a single restart episode. Falls
            // back to "supervisor-restart-unknown-N" if either
            // sentinel field is absent (forward-compat — older
            // supervisor revisions may omit one or both fields).
            let ts = s.attempt_n.map(|n| n as i64).unwrap_or(0);
            // The sentinel does not currently surface a
            // last_restart_unix_ts on its `SentinelView` — use
            // `unix_now` as a reasonable proxy bounded to this
            // boot (the restart's wall-clock `unix_now`).
            format!("supervisor-restart-{}-{}", unix_now, ts.max(1))
        });
        let outcome = restart_lifecycle::rehydrate_restart_context(
            inner_audit.as_ref(),
            &data_dir,
            sentinel,
            recovery_sweep_ms,
        );
        if outcome.dumps_processed > 0
            || outcome.kernel_restart_initiated_emits > 0
            || outcome.kernel_restart_completed_emits > 0
        {
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"restart_lifecycle_rehydrated\",\
                 \"dumps_processed\":{},\"deadlock_detected\":{},\
                 \"restart_initiated\":{},\"restart_completed\":{}}}",
                outcome.dumps_processed,
                outcome.kernel_deadlock_detected_emits,
                outcome.kernel_restart_initiated_emits,
                outcome.kernel_restart_completed_emits,
            );
        }

        // iter44 / `INV-OBS-KERNEL-RESPAWN-COVERAGE-01` — emit the
        // self-healing supervisor metrics paired with the audit
        // events the rehydration above just wrote. Reads the
        // sentinel a second time (fresh — the rehydration call
        // consumed the moved value) regardless of status so we can
        // distinguish:
        //
        //   * sentinel.status == "Restarting" → the supervisor just
        //     restarted us; emit one `KernelRespawnTotal` increment
        //     plus one `KernelRespawnDuration` observation. The
        //     duration is wallclock from sentinel
        //     `last_restart_unix_ts` to `unix_now` — supervisor
        //     decision-to-kernel-up.
        //
        //   * sentinel.status == "Halted" → the supervisor
        //     previously refused to spawn us (`CircuitOpen`) or was
        //     deliberately stopped by the operator
        //     (`OperatorStop[Forced]`); the operator manually
        //     started this kernel by-passing the halted supervisor.
        //     Emit one `SupervisorRefusedRestartTotal` increment so
        //     the dashboard surfaces the operational fact.
        //
        //   * sentinel.status == "Healthy" or sentinel absent → the
        //     supervisor is in steady state (or never ran); no
        //     metric to emit. The next `Healthy` sentinel write the
        //     supervisor performs after this kernel-up establishes
        //     dashboard ground truth via the existing
        //     `kernel_lifecycle_status.json` handler.
        let any_status_sentinel = restart_lifecycle::read_sentinel_any_status(&sentinel_path);
        if let Some(s) = any_status_sentinel {
            match s.status.as_str() {
                "Restarting" => {
                    let trigger = observability::classify_respawn_trigger(
                        s.last_restart_reason.as_deref(),
                        s.prev_run_exit_code,
                    );
                    let unix_now_i64 = unix_now as i64;
                    let duration_ms = s
                        .last_restart_unix_ts
                        .map(|ts| unix_now_i64.saturating_sub(ts).saturating_mul(1000));
                    observability::record_kernel_respawn(
                        observability_hub.as_ref(),
                        trigger,
                        observability::RESPAWN_OUTCOME_OK,
                        duration_ms,
                    );
                }
                "Halted" => {
                    let reason = observability::supervisor_refused_reason(s.sub_state.as_deref());
                    observability::record_supervisor_refused_restart(
                        observability_hub.as_ref(),
                        reason,
                    );
                }
                _ => {}
            }
        }

        // Step 8a''' (V2.5 `self-healing-supervisor.md §3.5`,
        // `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`):
        // supervisor-aware auto-resume sweep.
        //
        // Runs ONLY when the rehydration above emitted at least one
        // `KernelRestartCompleted` event (i.e. the supervisor's
        // sentinel said `status = "Restarting"` AND the kernel just
        // booted). A non-supervised restart, an operator-initiated
        // shutdown, or a fresh kernel boot all produce
        // `kernel_restart_completed_emits == 0` and short-circuit
        // here, leaving any swept tasks in `BlockedRecoveryPending`
        // for normal operator-resume disposition.
        //
        // **Order rationale.** Runs AFTER the
        // `KernelRestart{Initiated,Completed}` pair so the chain
        // reads left-to-right as
        // `KernelDeadlockDetected? → KernelStarted → KernelRestartInitiated →
        //  KernelRestartCompleted → TaskAutoResumedAfterSupervisorRestart{N}`.
        // Runs BEFORE IPC accept so the orchestrator never observes
        // the transient `BlockedRecoveryPending` window — by the
        // time the first IPC frame arrives, every auto-resumable
        // task is already back in `Admitted` and the scheduler
        // picks up exactly where it left off.
        if outcome.kernel_restart_completed_emits > 0 {
            let restart_id = supervisor_restart_id
                .clone()
                .unwrap_or_else(|| format!("supervisor-restart-{unix_now}-1"));
            let store_for_resume = Arc::clone(&store);
            let inner_audit_for_resume = Arc::clone(&inner_audit);
            let swept_for_resume = swept_tasks_detail.clone();
            let resume_report = tokio::task::spawn_blocking(move || {
                recovery::reconcile_after_supervisor_restart(
                    &store_for_resume,
                    inner_audit_for_resume.as_ref(),
                    &swept_for_resume,
                    &restart_id,
                )
            })
            .await
            .unwrap_or_else(|join_err| {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"supervisor_auto_resume\",\
                     \"action\":\"join_failed\",\"error\":\"{join_err}\"}}"
                );
                recovery::AutoResumeReport::default()
            });
            if !resume_report.outcomes.is_empty() {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"supervisor_auto_resume_completed\",\
                     \"resumed\":{},\"quarantined\":{},\
                     \"pre_existing_block\":{},\"transition_failed\":{},\
                     \"supervisor_restart_id\":{}}}",
                    resume_report.resumed,
                    resume_report.quarantined,
                    resume_report.pre_existing_block,
                    resume_report.transition_failed,
                    serde_json::to_string(&resume_report.supervisor_restart_id)
                        .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
                );
                // V2.5 (`self-healing-supervisor.md §3.5`):
                // surface the auto-resume summary on the
                // dashboard's `/api/health/kernel-lifecycle`
                // endpoint by writing a small summary file
                // alongside the supervisor sentinel. The
                // dashboard handler reads this file and folds
                // it into `KernelLifecycleResponse.auto_resume`
                // for the banner pill. Best-effort: a failed
                // write is logged but never aborts boot — the
                // audit chain already carries the per-task
                // events; this file is observability only.
                let summary = serde_json::json!({
                    "resumed":                    resume_report.resumed as u32,
                    "skipped_quarantined":        resume_report.quarantined as u32,
                    "skipped_pre_existing_block": resume_report.pre_existing_block as u32,
                    "transition_failed":          resume_report.transition_failed as u32,
                    "supervisor_restart_id":      &resume_report.supervisor_restart_id,
                    "recorded_at_unix_secs":      raxis_runtime::unix_now_secs(),
                });
                let summary_path =
                    data_dir.join(raxis_dashboard::routes::health::AUTO_RESUME_STATUS_FILENAME);
                if let Err(e) = std::fs::write(
                    &summary_path,
                    serde_json::to_vec_pretty(&summary).unwrap_or_default(),
                ) {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"auto_resume_status_write_failed\",\
                         \"path\":\"{}\",\"error\":\"{e}\"}}",
                        summary_path.display(),
                    );
                }
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
        let root = cap
            .disk_root
            .clone()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| data_dir.clone());
        let w =
            capacity::DiskWatchdog::new(root, cap.min_free_disk_mb, cap.disk_full_behavior.clone());
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
    let canonical_image_outcomes = canonical_images_preflight::verify_canonical_images_at_boot(
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
                image_path,
                manifest_path,
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
                path,
                expected,
                actual,
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
                image_path,
                manifest_path,
                reason,
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

    // Step 8b.1 — Probe the host-canonical Linux kernel binary
    // (`<install_dir>/kernel/vmlinux`). Distinct from the per-role
    // rootfs preflight above because the kernel binary is NOT
    // covered by an Ed25519-signed manifest in V2 — its trust model
    // is "operator-protected install root" (see
    // `canonical_images_preflight::linux_kernel_path` doc). The
    // outcome is therefore binary: present or missing. Substrates
    // that don't boot a Linux kernel (SubprocessIsolation, used in
    // tests + on hosts without microVM support) ignore the
    // `Missing` outcome; AVF / Firecracker activations surface
    // `SpawnFailed` at first session-spawn time when the binary is
    // absent.
    match canonical_images_preflight::probe_linux_kernel_binary_at_boot(&install_dir) {
        canonical_images_preflight::KernelBinaryOutcome::Present { path } => {
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"linux_kernel_binary_ok\",\
                 \"path\":\"{}\"}}",
                path.display(),
            );
        }
        canonical_images_preflight::KernelBinaryOutcome::Missing { path } => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"linux_kernel_binary_missing\",\
                 \"path\":\"{}\",\
                 \"hint\":\"the host-canonical Linux kernel binary is absent; \
                    AVF / Firecracker substrates will surface SpawnFailed at first \
                    session-spawn. Install via `cargo xtask images dev-kernel` \
                    (developer flow) or your distribution's raxis bundle (operator \
                    flow). Hosts running only the SubprocessIsolation substrate may \
                    safely ignore this warning.\"}}",
                path.display(),
            );
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
    let allow_wasm = false;
    let isolation_backend: Arc<dyn raxis_isolation::Backend> =
        match isolation_select::select_isolation_backend(&isolation_select::SelectorInputs {
            runtime_dir: runtime_subdir,
            allow_fallback,
            allow_wasm_sandbox: allow_wasm,
        }) {
            Ok(selected) => {
                if let Err(e) = inner_audit.emit(
                    AuditEventKind::IsolationSubstrateSelected {
                        backend_id: selected.backend.backend_id().to_owned(),
                        tier: serde_json::to_value(&selected.tier)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_owned))
                            .unwrap_or_else(|| "Unknown".to_owned()),
                        fallback_bypass: selected.fallback_bypass_required,
                    },
                    None,
                    None,
                    None,
                ) {
                    eprintln!(
                        "{{\"level\":\"error\",\"event\":\"IsolationSubstrateSelected\",\
                     \"audit_emit_failed\":\"{e}\"}}",
                    );
                }
                if selected.fallback_bypass_required {
                    let reason =
                        std::env::var("RAXIS_UNSAFE_FALLBACK_ISOLATION_REASON").unwrap_or_default();
                    if let Err(e) = inner_audit.emit(
                        AuditEventKind::IsolationFallbackBypass {
                            reason,
                            backend_id: selected.backend.backend_id().to_owned(),
                        },
                        None,
                        None,
                        None,
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
                    None,
                    None,
                    None,
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
        let store_for_hb = Arc::clone(&store);
        let hub_for_hb = Arc::clone(&observability_hub);
        let pid = std::process::id();
        tokio::spawn(async move {
            runtime::heartbeat_loop(
                data_dir_for_hb,
                pid,
                started_at,
                policy_for_hb,
                store_for_hb,
                hub_for_hb,
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
    let (nonce_sweep_shutdown_tx, nonce_sweep_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let nonce_sweep_handle = {
        let store_for_sweep = Arc::clone(&store);
        let policy_for_sweep = Arc::clone(&policy);
        tokio::spawn(async move {
            runtime::nonce_sweeper_loop(store_for_sweep, policy_for_sweep, nonce_sweep_shutdown_rx)
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
        let policy_target_ref_locked = snapshot.git_target_ref_locked();
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

    /// Adapter from [`gateway::client::LlmTurnObserver`] to
    /// [`raxis_dashboard_kernel::TaskLlmCapture`]. The observer
    /// trait lives in `kernel::gateway::client` (so it can be
    /// `install_observer`-ed against the pump without inverting
    /// the dep), and the canonical impl in main.rs forwards to
    /// the per-task on-disk file ring.
    struct GatewayLlmTurnObserver {
        capture: Arc<raxis_dashboard_kernel::TaskLlmCapture>,
    }
    impl gateway::client::LlmTurnObserver for GatewayLlmTurnObserver {
        fn observe(
            &self,
            task_id: &str,
            session_id: Option<&str>,
            fetch_id: uuid::Uuid,
            status_code: Option<u16>,
            latency_ms: u32,
            body_bytes: Option<&[u8]>,
            error: Option<&str>,
        ) {
            let body = body_bytes
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default();
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let record = raxis_dashboard_kernel::LlmTurnRecord {
                at_ms: now_ms,
                task_id: task_id.to_owned(),
                session_id: session_id.map(str::to_owned),
                fetch_id: fetch_id.to_string(),
                status_code,
                latency_ms,
                body,
                body_truncated: false,
                original_body_bytes: 0,
                error: error.map(str::to_owned),
            };
            if let Err(e) = self.capture.append(task_id, record) {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"TaskLlmCaptureAppendFailed\",\
                     \"task_id\":\"{task_id}\",\"reason\":\"{e}\"}}"
                );
            }
        }
    }

    // Wire the per-task LLM-turn capture into the gateway pump.
    // Every successful + failed `FetchResponse` that carried a
    // `task_id` in its corresponding `FetchRequest` will fan to
    // the capture's per-task file ring (see `task_llm_capture.rs`
    // for the bounded-disk + truncation contract). The observer
    // is installed BEFORE any gateway connection is set up so
    // even the very first `GatewayReady`-handshake-driven fetch
    // is captured. Falls back to a no-op when the capture failed
    // to construct above (read-only data dir / EROFS / ENOSPC).
    if let Some(cap) = task_llm_capture.as_ref() {
        gateway_client
            .install_observer(Arc::new(GatewayLlmTurnObserver {
                capture: Arc::clone(cap),
            }))
            .await;
    }
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
            IntentKind = raxis_domain_git::SeIntentKind,
            TerminalArtefact = raxis_domain_git::SeTerminalArtefact,
        >,
    > = {
        let main_root = data_dir.join("repositories").join("main");
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
        if let Err(e) = artifact_store.write(raxis_artifact_store::Category::Policy, &policy_bytes)
        {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"ArtifactStoreBackfillFailed\",\
                 \"category\":\"policy\",\"reason\":\"{e}\"}}",
            );
        }
    }

    // V2 `elastic-vm-scaling.md §5` — INV-ELASTIC-04 requires a
    // SINGLE global budget for substrate-visible scaling events
    // (`max_concurrent_scaling_events_per_minute`). The rate
    // limiter is **role-independent** and **direction-independent**;
    // splitting it into one instance per spawn context (orchestrator
    // vs executor / reviewer) would silently double the operator-
    // signed budget, which is exactly the "weakened invariant
    // disguised as a default" anti-pattern. One shared
    // `Arc<ScalingRateLimiter>` flows through both
    // `OrchestratorSpawnContext` and `ExecutorSpawnContext` below
    // so every admitted scale event — orchestrator scale-down,
    // executor scale-up, reviewer scale-down — consumes the same
    // sliding-60-second budget the policy bundle declares.
    //
    // The §4.4 `ScaleDownHistory` does NOT need to be shared:
    // its windows are keyed by `RoleKey` and each spawn context
    // only spawns within its own role family (Orchestrator vs
    // Executor / Reviewer), so the two trackers fill disjoint
    // partitions of the per-role table. Keeping them separate
    // avoids any cross-context lock contention on the spawn hot
    // path; sharing would only matter if a future signal
    // observer reaches across role families.
    let elastic_rate_limiter = Arc::new(crate::elastic::ScalingRateLimiter::new());

    // V3 `specs/v3/observability-prometheus.md` — observability hub
    // was built earlier (above the audit-sink wiring) so the
    // `NotifyingAuditSink` can bridge audit→metric events. The same
    // `Arc` flows into the SessionSpawnService below for the four-tier
    // VM cold-boot histograms; no second hub is built.

    // V2 reviewer-egress-defaults-decision.md §7 — hoisted shared
    // `EgressStallTracker`. The same `Arc` is wired into:
    //
    //   1. the orchestrator-spawn `SessionSpawnService` (built
    //      below) so its admission-loop chokepoint emits
    //      `SessionEgressStallDetected { source: "tproxy" }`;
    //   2. the `HandlerContext` (via `with_egress_stall_tracker`)
    //      so the executor/reviewer-spawn `SessionSpawnService`
    //      AND the kernel-mediated `planner_fetch` handler share
    //      the same sliding-window state.
    //
    // Without this hoist each spawn path would auto-allocate its
    // own tracker and the per-session bucket counts would
    // segregate by chokepoint — a stall observed across both
    // chokepoints would emit twice (once per tracker) and the
    // first-bucket-trip would understate the actual denial
    // velocity.
    let egress_stall_tracker: Arc<raxis_egress_admission::EgressStallTracker> =
        Arc::new(raxis_egress_admission::EgressStallTracker::with_defaults());

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
            let proxy_manager_for_orch =
                Arc::new(raxis_credential_proxy_manager::CredentialProxyManager::new(
                    Arc::clone(&credentials),
                    Arc::clone(&audit),
                ));
            let session_spawn_for_orch = Arc::new(
                raxis_session_spawn::SessionSpawnService::new(
                    Arc::clone(&isolation_backend),
                    proxy_manager_for_orch,
                    Arc::clone(&audit),
                )
                // V3 perf-telemetry: stamp the four-tier VM cold-boot
                // histograms from the very first spawn.
                .with_observability(Arc::clone(&observability_hub))
                // V2 reviewer-egress-defaults-decision.md §7 —
                // share the kernel-wide tracker so every per-
                // session admission loop emits
                // `SessionEgressStallDetected` against one
                // shared sliding-window state.
                .with_egress_stall_tracker(Arc::clone(&egress_stall_tracker)),
            );
            // V2 `elastic-vm-scaling.md §4.4` — fresh scale-down
            // tracker for the orchestrator-spawn context. The
            // Executor / Reviewer spawn context owns its own
            // tracker (see below); each tracker's windows key by
            // `RoleKey` and the spawn contexts spawn disjoint
            // roles, so two instances are semantically equivalent
            // to one shared instance for the orchestrator's role.
            //
            // The §5 rate limiter, in contrast, is the SAME
            // `Arc` for both contexts (hoisted to
            // `elastic_rate_limiter` above) so the budget remains
            // a single global cap per INV-ELASTIC-04.
            let scale_down_history = Arc::new(crate::elastic::ScaleDownHistory::new());
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
                    .with_data_dir(data_dir.clone())
                    .with_scale_down_history(Arc::clone(&scale_down_history))
                    .with_rate_limiter(Arc::clone(&elastic_rate_limiter)),
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
            .with_data_dir(data_dir.clone())
            // V2 `elastic-vm-scaling.md §4.4` — own scale-down
            // tracker for the executor / reviewer spawn context;
            // disjoint `RoleKey` partitions from the orchestrator
            // tracker above.
            //
            // V2 `elastic-vm-scaling.md §5` — share the SAME
            // `elastic_rate_limiter` Arc as the orchestrator
            // context so admitted scale events from BOTH spawn
            // paths consume the single global budget the
            // operator declared in
            // `policy.[elastic].max_concurrent_scaling_events_per_minute`
            // (INV-ELASTIC-04).
            .with_scale_down_history(Arc::new(crate::elastic::ScaleDownHistory::new()))
            .with_rate_limiter(Arc::clone(&elastic_rate_limiter)),
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

    // V3 `specs/v3/observability-prometheus.md` — the hub itself
    // was constructed earlier (just before the orchestrator-spawn
    // service) so the four-tier VM cold-boot histograms can stamp
    // from the very first spawn. Here we just install it onto the
    // HandlerContext so every handler sees the same Arc.
    let ctx_inner = ctx_inner.with_observability(Arc::clone(&observability_hub));
    // V2 reviewer-egress-defaults-decision.md §7 — install the
    // kernel-wide shared `EgressStallTracker` so the executor /
    // reviewer-spawn admission-loop chokepoint AND the kernel-
    // mediated `planner_fetch` handler share one sliding-window
    // state with the orchestrator-spawn service wired above.
    let ctx_inner = ctx_inner.with_egress_stall_tracker(Arc::clone(&egress_stall_tracker));

    // Step 8.6: Boot-time break-glass state (v1 Tier 4,
    // kernel-core.md §2.3 src/breakglass.rs). Opens the
    // single-record TOML at `<data_dir>/breakglass/active.toml` and
    // proactively prunes any expired record so admission never
    // honours a stale activation. A missing / unreadable file
    // logs and falls back to `BreakglassState::disabled` —
    // breakglass is fail-closed: an unreachable record file means
    // `Inactive`, never `Active`.
    let breakglass_state: Arc<breakglass::BreakglassState> = {
        let record_path = breakglass::default_record_path(&data_dir);
        match breakglass::BreakglassState::open(record_path) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"BreakglassOpenFailed\",\
                     \"reason\":\"{e}\"}}",
                );
                Arc::new(breakglass::BreakglassState::disabled())
            }
        }
    };
    let ctx_inner = ctx_inner.with_breakglass(Arc::clone(&breakglass_state));

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
        Ok(Some(mut cfg)) => {
            // Pin the kernel's data_dir into the dashboard config so
            // `GET /api/health/kernel-lifecycle` can locate the
            // supervisor's sentinel file (`<data_dir>/kernel_lifecycle_status.json`).
            // Without this the handler returns a static `Healthy { fresh: true }`
            // response — which is the correct fallback when the operator has
            // not opted into the supervisor (RAXIS_SUPERVISOR_AUTO_RESTART unset),
            // but is wrong when the supervisor IS in play.
            // See `INV-DASHBOARD-KERNEL-LIFECYCLE-01` (specs/v2/self-healing-supervisor.md §4.6).
            if cfg.data_dir.is_none() {
                cfg.data_dir = Some(data_dir.to_string_lossy().into_owned());
            }
            // INV-DASHBOARD-JWT-SECRET-PERSISTENT-01 /
            // INV-SUPERVISOR-OPERATOR-CONTINUITY-01: probe the
            // persisted JWT secret BEFORE handing the config to
            // `build_auth_state` so we can surface a structured
            // boot log line (Minted / Reloaded). The
            // `build_auth_state` call inside the dashboard
            // server will hit the same file moments later via
            // `JwtSigner::load_or_mint`, but its outcome value
            // is currently swallowed (the function builds an
            // `AuthState` and discards the bool). Doing the
            // probe here lets the operator see "first boot
            // mint" vs "subsequent boot reload" in the kernel
            // stderr — the audit-trail equivalent for the
            // supervisor-triggered restart story.
            //
            // Probe failures are LOGGED but NOT FATAL: if the
            // file system is broken in a way that defeats the
            // dashboard auth path, the downstream
            // `build_auth_state` call inside
            // `start_dashboard_with_advancer` will surface the
            // same error with full context. This probe is purely
            // a logging convenience.
            match raxis_dashboard::jwt_secret::load_or_mint(&data_dir) {
                Ok((file, raxis_dashboard::jwt_secret::LoadOutcome::Minted)) => {
                    eprintln!(
                        "raxis-kernel: dashboard JWT secret minted \
                         (generation={}) at <data_dir>/auth/dashboard_jwt.secret",
                        file.generation,
                    );
                }
                Ok((file, raxis_dashboard::jwt_secret::LoadOutcome::Reloaded)) => {
                    eprintln!(
                        "raxis-kernel: dashboard JWT secret reloaded \
                         (generation={}) — operator JWTs from prior boot \
                         remain valid (INV-SUPERVISOR-OPERATOR-CONTINUITY-01)",
                        file.generation,
                    );
                }
                Err(e) => {
                    eprintln!(
                        "raxis-kernel: dashboard JWT secret probe failed: {e} \
                         (build_auth_state will retry — non-fatal here)",
                    );
                }
            }
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
            // Reuse the SAME `SessionStreamCapture` instance
            // that the audit-sink `StreamingAuditSink` bridge
            // was wrapped around earlier (so audit→SSE mirror
            // and the dashboard data layer share one
            // `<data_dir>/streams/` directory + one broadcast
            // channel per session). If early allocation
            // failed (logged at boot) we attempt one more init
            // here so the dashboard still has a usable capture
            // — at worst, audit→SSE mirroring stays disabled
            // and the operator only sees the persistent tail.
            let stream_capture_attempt = match dashboard_stream_capture.as_ref() {
                Some(c) => Ok(Arc::clone(c)),
                None => raxis_dashboard_kernel::SessionStreamCapture::new(
                    &data_dir,
                    raxis_dashboard_kernel::CaptureConfig::default(),
                ),
            };
            match stream_capture_attempt {
                Ok(stream_capture) => {
                    match raxis_dashboard_kernel::start_dashboard_with_advancer(
                        cfg.clone(),
                        Arc::clone(&store),
                        Arc::clone(&policy),
                        data_dir.clone(),
                        policy_path.clone(),
                        started_at,
                        stream_capture,
                        advancer,
                        Arc::clone(&audit),
                        // V3 §3.14 seam: thread the boot-time
                        // ObservabilityHub through to
                        // `DashboardServer::bind_with_observability`
                        // so the dashboard HTTP middleware + SSE
                        // handlers can fire record_dashboard_* in
                        // the live boot path. The same hub already
                        // backs the periodic flush, the
                        // notification-sink bridge, and the IPC
                        // handler context — there is exactly one
                        // hub per kernel process.
                        Some(Arc::clone(&observability_hub)),
                        // Task-LLM capture (`task_llm_capture.rs`) —
                        // shared with the gateway pump so dashboard
                        // routes read the SAME on-disk file ring the
                        // pump writes. `None` ⇒ early init failed
                        // (logged at boot); the dashboard route
                        // returns 404 in that case.
                        task_llm_capture.clone(),
                    )
                    .await
                    {
                        Ok(h) => {
                            let addr = h.local_addr();
                            let scheme =
                                if !cfg.tls_cert_path.is_empty() && !cfg.tls_key_path.is_empty() {
                                    "https"
                                } else {
                                    "http"
                                };
                            // Human-readable line: most modern terminals
                            // (Cursor, VS Code, iTerm2, Terminal.app,
                            // Ghostty, Kitty, Alacritty, tmux) auto-detect
                            // `scheme://host:port` URLs and make them
                            // cmd/ctrl-clickable. When the listener is
                            // bound to `0.0.0.0` / `::` the printed URL is
                            // not directly clickable; print a `localhost`
                            // hint alongside so the operator can still
                            // click through.
                            let ip = addr.ip();
                            let primary = format!("{scheme}://{addr}");
                            if ip.is_unspecified() {
                                eprintln!(
                                    "RAXIS dashboard: {primary}  (click: {scheme}://localhost:{})",
                                    addr.port(),
                                );
                            } else {
                                eprintln!("RAXIS dashboard: {primary}");
                            }
                            // Keep the structured log line for tooling that
                            // captures stderr (CI, log shippers, the
                            // `raxis status` parser).
                            eprintln!(
                                "{{\"level\":\"info\",\"event\":\"dashboard_started\",\
                                 \"scheme\":\"{scheme}\",\"local_addr\":\"{addr}\",\
                                 \"url\":\"{primary}\"}}",
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
                Err(e) => {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"dashboard_streams_init_failed\",\
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
            Ok(()) => eprintln!("{{\"level\":\"info\",\"event\":\"dashboard_shutdown\"}}"),
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
        Ok(Ok(())) => eprintln!("{{\"level\":\"info\",\"event\":\"heartbeat_loop_done\"}}"),
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
        Ok(()) => {
            eprintln!("{{\"level\":\"info\",\"event\":\"plan_bundle_nonce_sweep_loop_done\"}}")
        }
        Err(join_err) => eprintln!(
            "{{\"level\":\"warn\",\
             \"event\":\"plan_bundle_nonce_sweep_loop_join_failed\",\
             \"reason\":\"{join_err}\"}}"
        ),
    }

    // V3 §3 — flush + shutdown the observability hub before
    // emitting `KernelStopped` so any final spans/metrics for the
    // shutdown sequence land on disk before the kernel disappears.
    // Idempotent; cheap when the hub is disabled.
    observability_hub.shutdown();

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
        None,
        None,
        None,
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
        std::process::exit(
            KernelError::SocketBind {
                reason: format!(
                    "dispatch loop exited unexpectedly: {}",
                    shutdown.audit_reason()
                ),
            }
            .exit_code(),
        );
    }
}

// ---------------------------------------------------------------------------
// `concurrency-and-locking.md §INV-LOCK-07` /
// `self-healing-supervisor.md §3.2` — deadlock-watcher self-test.
//
// Pinned `#[ignore]` because it INTENTIONALLY induces the
// process-terminating exit the watcher exists to surface — running
// it under `cargo test`'s normal path would terminate the test
// runner before any other test in the binary could start. Run
// manually:
//
//   cargo test -p raxis-kernel --features runtime-deadlock-detection \
//     raxis_deadlock_watcher_exits_70_on_intentional_cycle \
//     -- --ignored --nocapture --test-threads=1
//
// The test forks (a) two contender threads each acquiring two
// `parking_lot::Mutex`es in opposite order (the canonical AB / BA
// deadlock shape), and (b) the production `spawn_deadlock_watcher`
// thread. We then `sleep` past the watcher's 2-second cadence and
// expect the test process to be terminated by the watcher's
// `process::exit(70)` (V2.5 contract — was `panic!` pre-V2.5, now
// a stable supervisor-recognised exit code per
// `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`) before the sleep
// returns. A clean wake-up (no abort within the sleep window) is a
// regression — either the watcher feature was silently disabled
// at the cargo level, or the parking_lot `deadlock_detection`
// lock-graph tracker stopped seeing the cycle.
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "runtime-deadlock-detection"))]
mod deadlock_watcher_self_test {
    use super::spawn_deadlock_watcher;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    #[ignore = "intentionally exits the test process with code 70; run with --ignored"]
    fn raxis_deadlock_watcher_exits_70_on_intentional_cycle() {
        // Install the production watcher first so it observes both
        // contender threads' lock acquisitions. We pass a tempdir
        // so the dump-write side-effect lands in scratch rather
        // than the developer's `~/.raxis/`.
        let data_dir = tempfile::tempdir().expect("tempdir for watcher dump file");
        spawn_deadlock_watcher(data_dir.path().to_path_buf());

        let a: Arc<parking_lot::Mutex<()>> = Arc::new(parking_lot::Mutex::new(()));
        let b: Arc<parking_lot::Mutex<()>> = Arc::new(parking_lot::Mutex::new(()));

        let a1 = Arc::clone(&a);
        let b1 = Arc::clone(&b);
        let _t1 = thread::Builder::new()
            .name("self-test-AB".to_owned())
            .spawn(move || {
                let _ga = a1.lock();
                // Stagger so the second thread can grab `b` before
                // we try to acquire it (the cycle requires both
                // outer guards to be held when the inner acquires
                // park).
                thread::sleep(Duration::from_millis(50));
                let _gb = b1.lock();
                // Unreachable in the deadlock case; included so a
                // missing-cycle regression doesn't double-panic.
                drop(_gb);
                drop(_ga);
            })
            .expect("spawn AB contender");

        let a2 = Arc::clone(&a);
        let b2 = Arc::clone(&b);
        let _t2 = thread::Builder::new()
            .name("self-test-BA".to_owned())
            .spawn(move || {
                let _gb = b2.lock();
                thread::sleep(Duration::from_millis(50));
                let _ga = a2.lock();
                drop(_ga);
                drop(_gb);
            })
            .expect("spawn BA contender");

        // Sleep 5 seconds — well past the watcher's 2-second
        // cadence. If the watcher is wired correctly the process
        // exits with code 70 (V2.5 contract) before we wake.
        //
        // If we DO wake, the assert below fails: either the
        // `runtime-deadlock-detection` feature wasn't really enabled
        // at build time, or the parking_lot lock-graph tracker
        // stopped surfacing this canonical cycle shape.
        thread::sleep(Duration::from_secs(5));
        panic!(
            "raxis-deadlock-watcher did NOT terminate the test \
             process with exit code 70 within 5 seconds — \
             either the `runtime-deadlock-detection` cargo feature \
             was silently disabled, or parking_lot's lock-graph \
             tracker no longer detects the canonical AB/BA cycle. \
             Re-check `kernel/Cargo.toml [features]` and run \
             `cargo tree -p raxis-kernel -i parking_lot --features \
             runtime-deadlock-detection` to verify the feature \
             reaches every consumer."
        );
    }
}
