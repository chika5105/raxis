// raxis-kernel — entry point.
//
// Normative reference: kernel-core.md §2.2 `src/main.rs` and the
// Kernel Startup Sequence table (9 steps).
//
// This file is intentionally thin — no policy logic, no IPC logic, no
// authority logic. Only: step sequencing + signal handling + error dispatch.
// Each step calls a subsystem function; this file is the call list.

mod errors;
mod bootstrap;
mod authority;
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
mod runtime;

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
    let audit: Arc<dyn AuditSink> = Arc::new(notifications::NotifyingAuditSink::new(
        Arc::clone(&inner_audit),
        Arc::clone(&policy),
        data_dir.clone(),
    ));

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
        let repopulate_outcome = tokio::task::spawn_blocking(move || {
            initiatives::lifecycle::repopulate_plan_registry(
                &store_for_repopulate,
                &registry_for_repopulate,
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
    );
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
