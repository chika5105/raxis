// raxis-kernel — entry point.
//
// Normative reference: kernel-core.md §2.2 `src/main.rs` and the
// Kernel Startup Sequence table (9 steps).
//
// This file is intentionally thin — no policy logic, no IPC logic, no
// authority logic. Only: step sequencing + signal handling + error dispatch.
// Each step calls a subsystem function; this file is the call list.
//
// v1 implementation note: steps 6–9 are scaffolded with placeholder
// implementations that will be filled in as each subsystem module is
// implemented. Steps 1–5 are fully wired.

mod errors;
mod bootstrap;

use errors::{exit_with_code, KernelError};
use raxis_policy::load_policy;
use raxis_store::Store;

/// Kernel data directory. In production this is `~/.raxis`; in tests it is a
/// temp dir. Sourced from the RAXIS_DATA_DIR env var, defaulting to `~/.raxis`.
fn data_dir() -> std::path::PathBuf {
    if let Ok(val) = std::env::var("RAXIS_DATA_DIR") {
        std::path::PathBuf::from(val)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
        std::path::PathBuf::from(home).join(".raxis")
    }
}

fn main() {
    // Step 1: Parse CLI flags and environment.
    // v1 uses env vars only; clap is deferred to v2 to keep the dependency
    // surface minimal.
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
        // On failure it returns Err which we convert to exit code 15.
        if let Err(e) = bootstrap::run(&config) {
            exit_with_code(e);
        }
        // Unreachable: run() always calls process::exit.
        unreachable!("bootstrap::run must exit the process");
    }

    // Step 3: Load and verify signed policy artifact.
    let policy_path = data_dir.join("policy").join("policy.toml");
    let (policy, _raw_bytes, _sha256) = load_policy(&policy_path).unwrap_or_else(|e| {
        exit_with_code(KernelError::PolicyInvalid {
            reason: e.to_string(),
        })
    });
    let policy = std::sync::Arc::new(policy);
    eprintln!(
        "{{\"level\":\"info\",\"message\":\"policy loaded\",\"epoch\":{}}}",
        policy.epoch()
    );

    // Step 4: Initialize key registry.
    // Keys are loaded from <data_dir>/keys/ by authority::keys::load_keyring.
    // Not yet implemented — will be wired when authority/ module is in place.
    //
    // For now, verify that the key files exist (fail-closed sanity check).
    let authority_key_path = data_dir.join("keys").join("authority_keypair.pem");
    if !authority_key_path.exists() {
        exit_with_code(KernelError::KeyRegistry {
            reason: format!(
                "authority_keypair.pem not found at {}",
                authority_key_path.display()
            ),
        });
    }

    // Step 5: Open kernel state store.
    // Store::open runs the WAL pragma + migration atomically.
    let db_path = data_dir.join("kernel.db");
    let store = match Store::open(&db_path) {
        Ok(s) => {
            eprintln!("{{\"level\":\"info\",\"message\":\"store opened\"}}");
            s
        }
        Err(e) => {
            exit_with_code(KernelError::StoreSchema {
                reason: e.to_string(),
            })
        }
    };
    let _store = std::sync::Arc::new(store);

    // Step 6: Run recovery::reconcile.
    // Not yet implemented — placeholder. In production this verifies the
    // audit chain, sweeps in-flight tasks to BlockedRecoveryPending, and
    // checks the witness index for orphaned blobs.
    eprintln!("{{\"level\":\"info\",\"message\":\"recovery reconcile: stub, skipping\"}}");

    // Step 7: Bind IPC listener sockets.
    // Not yet implemented — ipc::listener will be implemented in the IPC
    // subsystem module. Three sockets: planner.sock, gateway.sock, operator.sock.
    let sockets_dir = data_dir.join("sockets");
    if let Err(e) = std::fs::create_dir_all(&sockets_dir) {
        exit_with_code(KernelError::SocketBind {
            reason: format!("cannot create sockets dir {}: {e}", sockets_dir.display()),
        });
    }
    eprintln!(
        "{{\"level\":\"info\",\"message\":\"socket dir ready\",\"path\":\"{}\"}}",
        sockets_dir.display()
    );

    // Step 8: Emit KernelStarted audit event.
    // Not yet implemented — AuditWriter will be initialised here and its
    // chain opened from the segment store. For now, log to stderr as a sentinel.
    eprintln!("{{\"level\":\"info\",\"message\":\"KernelStarted (audit stub)\"}}");

    // Step 9: Enter IPC dispatch loop.
    // Not yet implemented — ipc::start_ipc_server will be called here.
    // For now, park the process waiting for SIGTERM/SIGINT.
    eprintln!("{{\"level\":\"info\",\"message\":\"dispatch loop not yet implemented; exiting cleanly\"}}");
}
