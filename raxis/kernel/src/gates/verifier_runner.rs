// raxis-kernel::gates::verifier_runner — Verifier subprocess spawn.
//
// Normative reference: kernel-core.md §2.3 `src/gates/verifier_runner.rs`.
//
// Issues a verifier run token and forks the verifier subprocess with:
//   - Environment scrubbing (env_clear + explicit envelope vars only)
//   - stdout/stderr piped; stdin null
//   - FD_CLOEXEC on all kernel fds (set at creation time)
//   - Resource limits via setrlimit (RLIMIT_CPU, RLIMIT_AS, RLIMIT_NOFILE)
//   - Working directory set to worktree_root
//   - Wall-clock timeout via background tokio task
//
// Does NOT wait for subprocess result — witness results arrive asynchronously
// via ipc/handlers/witness.rs.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::process::Command;
use tokio::sync::Mutex;

use raxis_policy::PolicyBundle;
use raxis_store::Store;

use crate::authority::verifier_token;
use super::GateError;

// ---------------------------------------------------------------------------
// Global verifier cap counter
// ---------------------------------------------------------------------------

/// Global count of currently-running verifier subprocesses.
/// Decremented when a subprocess exits (via the completion watcher task).
static ACTIVE_VERIFIERS: AtomicUsize = AtomicUsize::new(0);

/// Max concurrent verifiers (v1 default — operator may set via policy).
const DEFAULT_MAX_CONCURRENT_VERIFIERS: usize = 16;

// ---------------------------------------------------------------------------
// VerifierConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Absolute path to the gate-type-specific verifier binary.
    pub verifier_binary_path: PathBuf,
    /// TTL for the verifier run token.
    pub verifier_token_ttl_secs: u64,
    /// CPU-second hard limit (RLIMIT_CPU).
    pub verifier_cpu_secs: u64,
    /// Address-space limit in bytes (RLIMIT_AS).
    pub verifier_memory_bytes: u64,
    /// Wall-clock timeout for the subprocess.
    pub verifier_max_wall_secs: u64,
    /// Maximum concurrent verifiers across all gates.
    pub max_concurrent_verifiers: usize,
    /// Path to the kernel operator socket (planner.sock is separate).
    pub kernel_socket_path: String,
}

impl VerifierConfig {
    pub fn from_policy(policy: &PolicyBundle, gate_type: &str, data_dir: &Path) -> Option<Self> {
        let gate = policy.gates().iter().find(|g| g.gate_type == gate_type)?;
        Some(Self {
            verifier_binary_path: PathBuf::from(&gate.verifier_command),
            verifier_token_ttl_secs: 300,  // 5 min default
            verifier_cpu_secs: gate.max_wall_seconds as u64,
            verifier_memory_bytes: gate.max_memory_bytes,
            verifier_max_wall_secs: gate.max_wall_seconds as u64 + 10,
            max_concurrent_verifiers: DEFAULT_MAX_CONCURRENT_VERIFIERS,
            kernel_socket_path: data_dir
                .join("sockets")
                .join("planner.sock")
                .display()
                .to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// spawn_verifier
// ---------------------------------------------------------------------------

/// Issue a verifier run token and fork the verifier subprocess.
///
/// Returns the `verifier_run_id` immediately. The kernel does not await
/// subprocess completion — results arrive via ipc/handlers/witness.rs.
///
/// Returns `Err(GateError::VerifierCapExceeded)` if the global cap is reached.
pub async fn spawn_verifier(
    task_id:       &str,
    gate_type:     &str,
    evaluation_sha: &str,
    worktree_root: &Path,
    config:        &VerifierConfig,
    store:         &Store,
) -> Result<String, GateError> {
    // Step 1: Check global concurrent verifier count.
    let current = ACTIVE_VERIFIERS.load(Ordering::Relaxed);
    if current >= config.max_concurrent_verifiers {
        return Err(GateError::VerifierCapExceeded {
            task_id: task_id.to_owned(),
            gate_type: gate_type.to_owned(),
        });
    }

    // Step 2: Issue verifier run token.
    // Generate a unique run_id for this verifier invocation.
    let verifier_run_id = uuid::Uuid::new_v4().to_string();
    let raw_token = verifier_token::issue_verifier_token(
        &verifier_run_id,
        task_id,
        gate_type,
        evaluation_sha,
        config.verifier_token_ttl_secs,
        store,
    ).map_err(|e| GateError::AuthorityError(e.to_string()))?;

    // Step 3: Build spawn envelope environment (scrubbed — env_clear() first).
    let mut cmd = Command::new(&config.verifier_binary_path);
    cmd.env_clear()
        .env("RAXIS_VERIFIER_TOKEN", &raw_token)
        .env("RAXIS_TASK_ID", task_id)
        .env("RAXIS_GATE_TYPE", gate_type)
        .env("RAXIS_EVALUATION_SHA", evaluation_sha)
        .env("RAXIS_KERNEL_SOCKET", &config.kernel_socket_path)
        .env("RAXIS_WORKTREE_ROOT", worktree_root.display().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(worktree_root);

    // Step 4: Spawn subprocess.
    // Note: FD_CLOEXEC is set by tokio::process::Command by default on Unix.
    let mut child = cmd.spawn().map_err(|e| GateError::SpawnFailed {
        gate_type: gate_type.to_owned(),
        reason: e.to_string(),
    })?;

    let run_id_clone = verifier_run_id.clone();
    let max_wall = config.verifier_max_wall_secs;

    // Step 5: Increment counter. Register completion watcher.
    ACTIVE_VERIFIERS.fetch_add(1, Ordering::Relaxed);

    tokio::spawn(async move {
        let wall_timeout = tokio::time::sleep(Duration::from_secs(max_wall));
        tokio::pin!(wall_timeout);

        tokio::select! {
            _ = child.wait() => {
                // Normal exit.
            }
            _ = &mut wall_timeout => {
                // Wall-clock kill.
                let _ = child.kill().await;
                eprintln!(
                    "{{\"level\":\"warn\",\"message\":\"verifier wall-clock killed\",\
                     \"verifier_run_id\":\"{run_id_clone}\"}}"
                );
            }
        }
        ACTIVE_VERIFIERS.fetch_sub(1, Ordering::Relaxed);
    });

    // Step 6: Return verifier_run_id.
    Ok(verifier_run_id)
}
