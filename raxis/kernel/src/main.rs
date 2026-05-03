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
mod handlers;
mod path_scope;

use std::sync::Arc;

use errors::{exit_with_code, KernelError};
use raxis_audit_tools::{AuditEventKind, AuditSink, AuditWriter, FileAuditSink};
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
    if bootstrap_mode {
        let config = bootstrap::BootstrapConfig {
            data_dir: data_dir.clone(),
            operator_pubkey_path: std::env::var("RAXIS_OPERATOR_PUBKEY").ok().map(Into::into),
            force: std::env::var("RAXIS_FORCE").is_ok(),
        };
        // bootstrap::run calls std::process::exit(0) on success.
        if let Err(e) = bootstrap::run(&config) {
            exit_with_code(e);
        }
        unreachable!("bootstrap::run must exit the process");
    }

    // Step 3: Load and verify signed policy artifact.
    let policy_path = data_dir.join("policy").join("policy.toml");
    let (policy, _raw_bytes, _sha256) = load_policy(&policy_path).unwrap_or_else(|e| {
        exit_with_code(KernelError::PolicyInvalid {
            reason: e.to_string(),
        })
    });
    let policy = Arc::new(policy);
    eprintln!(
        "{{\"level\":\"info\",\"message\":\"policy loaded\",\"epoch\":{}}}",
        policy.epoch()
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

    // Step 6: Run recovery::reconcile — verify audit chain, sweep in-flight tasks.
    let audit_dir = data_dir.join("audit");
    match recovery::reconcile(&store, &audit_dir) {
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

    // Step 7a: Open the AuditWriter on segment-000.jsonl. Per
    // kernel-store.md §2.5.2 this is the only writer to the JSONL chain;
    // no other module opens the file.
    //
    // v1 simplification: starting_seq=0 / starting_prev_sha256=None on
    // every kernel start. A future PR will scan the segment for the last
    // line + recompute its prev_sha256 to resume the chain across
    // restarts. The current behaviour is the same as the previous
    // `eprintln!`-only path: every restart begins a fresh chain segment.
    let audit_path = audit_dir.join("segment-000.jsonl");
    let writer = AuditWriter::open(&audit_path, 0, None).unwrap_or_else(|e| {
        exit_with_code(KernelError::AuditChainBroken {
            reason: format!("cannot open audit segment {audit_path:?}: {e}"),
        })
    });
    let audit: Arc<dyn AuditSink> = Arc::new(FileAuditSink::new(writer));

    // Step 8: Emit the canonical KernelStarted record. This is the very
    // first event in this kernel-process lifetime; with the v1 reset
    // policy above it is also the genesis event of the segment.
    if let Err(e) = audit.emit(
        AuditEventKind::KernelStarted {
            data_dir: data_dir.display().to_string(),
            policy_epoch: policy.epoch(),
            schema_version: 1,
        },
        None, None, None,
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"KernelStarted\",\"audit_emit_failed\":\"{e}\"}}"
        );
    }

    // Step 7b: Construct the in-memory PlanRegistry and repopulate it from
    // every non-terminal initiative's signed plan artifact. Per
    // kernel-store.md §2.5.8 the four path-scope plan fields live only
    // in memory; without this hook every intent submitted after a
    // restart would fail-closed with `FAIL_PATH_POLICY_VIOLATION`.
    let plan_registry = Arc::new(initiatives::PlanRegistry::new());
    match initiatives::lifecycle::repopulate_plan_registry(&store, &plan_registry) {
        Ok(n) => {
            eprintln!(
                "{{\"level\":\"info\",\"message\":\"plan registry repopulated\",\
                 \"task_entries\":{n}}}"
            );
        }
        Err(e) => {
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
    }

    // Step 7c: Build the HandlerContext now that the audit sink AND the
    // plan registry exist.
    let ctx = Arc::new(ipc::context::HandlerContext::new(
        Arc::clone(&policy),
        Arc::clone(&registry),
        Arc::clone(&store),
        Arc::clone(&audit),
        data_dir.clone(),
        Arc::clone(&plan_registry),
    ));

    // Step 9: Enter IPC dispatch loop (runs forever or until fatal error).
    if let Err(e) = ipc::server::start(&data_dir, ctx).await {
        exit_with_code(e);
    }
}
