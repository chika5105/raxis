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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use raxis_audit_tools::AuditEventKind;
use tokio::process::Command;

use raxis_audit_tools::AuditSink;
use raxis_policy::{PolicyBundle, VerifierRuntimeConfig};
use raxis_store::Store;
#[cfg(test)]
use raxis_store::Table;

use super::GateError;
use crate::authority::verifier_token;

// ---------------------------------------------------------------------------
// Per-task cumulative-verifier-time tracker (iter63-followups.md Item 2 #3)
// ---------------------------------------------------------------------------
//
// `INV-VERIFIER-CUMULATIVE-BUDGET-01`: across retries, the kernel
// must reject a verifier spawn for a task whose accumulated wall time
// has already crossed
// [`VerifierRuntimeConfig::task_verifier_total_budget_seconds`]. We
// keep the accumulator in-memory only — if the kernel restarts,
// every verifier is killed and a fresh accumulator starts from zero,
// which is the only correct semantic (the budget exists to bound a
// single kernel-uptime cycle, not the historical sum across
// process restarts).
//
// The map key is the task_id (operator-readable string). Values are
// best-effort seconds (we round elapsed-ms to seconds at observation
// time so the comparison against the u32-second budget is direct).
static TASK_VERIFIER_TIME: std::sync::OnceLock<Mutex<BTreeMap<String, u64>>> =
    std::sync::OnceLock::new();

fn task_verifier_time_map() -> &'static Mutex<BTreeMap<String, u64>> {
    TASK_VERIFIER_TIME.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Read the cumulative seconds spent in verifiers for a single task
/// across the kernel's current uptime. Public for the kernel's
/// heartbeat / cli-readonly snapshot to surface.
pub fn task_cumulative_verifier_seconds(task_id: &str) -> u64 {
    task_verifier_time_map()
        .lock()
        .ok()
        .and_then(|m| m.get(task_id).copied())
        .unwrap_or(0)
}

/// Record a verifier's elapsed wall-time against its task's
/// cumulative-budget accumulator. Called from the watcher task in
/// `spawn_verifier` once the child exits (or is reaped).
fn record_task_verifier_seconds(task_id: &str, secs: u64) {
    if let Ok(mut map) = task_verifier_time_map().lock() {
        let entry = map.entry(task_id.to_owned()).or_insert(0);
        *entry = entry.saturating_add(secs);
    }
}

/// Test helper to reset the cumulative accumulator. `#[cfg(test)]`
/// only — production code must never reset budgets mid-flight.
#[cfg(test)]
pub fn reset_task_verifier_budget_for_tests() {
    if let Ok(mut map) = task_verifier_time_map().lock() {
        map.clear();
    }
}

// INV-STORE-03 (kernel-store.md §2.5.1): table identifiers come from the
// `Table` enum; FSM state strings (production paths via the typed enums,
// test fixtures via the same constants below).
#[cfg(test)]
const INITIATIVES: &str = Table::Initiatives.as_str();
#[cfg(test)]
const TASKS: &str = Table::Tasks.as_str();
#[cfg(test)]
const VERIFIER_RUN_TOKENS: &str = Table::VerifierRunTokens.as_str();
#[cfg(test)]
const WITNESS_RECORDS: &str = Table::WitnessRecords.as_str();

// ---------------------------------------------------------------------------
// Global verifier cap counter
// ---------------------------------------------------------------------------

/// Global count of currently-running verifier subprocesses.
/// Decremented when a subprocess exits (via the completion watcher task).
static ACTIVE_VERIFIERS: AtomicUsize = AtomicUsize::new(0);

/// Max concurrent verifiers (v1 default — operator may set via policy).
const DEFAULT_MAX_CONCURRENT_VERIFIERS: usize = 16;

/// Read accessor for the global verifier counter.
///
/// Reads have no observable production side effect; we keep the visibility
/// to `pub(crate)` so external crates cannot take a dependency on the
/// internal counter. The intra-crate consumers are:
///   - `runtime::heartbeat::collect` (cli-readonly.md §5.2.2,
///     `active_verifiers` field). Returns the wire-shape
///     `raxis_runtime::Snapshot` for the kernel's heartbeat loop.
///   - This file's own integration tests at the bottom of the module.
pub(crate) fn active_verifier_count() -> usize {
    ACTIVE_VERIFIERS.load(Ordering::Relaxed)
}

/// Read accessor for the v1 default verifier-cap constant.
///
/// Mirrors the spec's "in-memory counters that `kernel.db` cannot expose"
/// (cli-readonly.md §5.1.4). The cap is currently a compile-time
/// constant; once policy-driven (`max_concurrent_verifiers` in
/// `[gateway]`-style sections), this accessor will read from the active
/// `PolicyBundle` instead — kept as a function so callers don't need to
/// change.
pub(crate) fn max_concurrent_verifiers() -> usize {
    DEFAULT_MAX_CONCURRENT_VERIFIERS
}

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

    /// iter63-followups.md Item 1 — operator-authored hints
    /// from the gate's `[[gates]] hints` table. Injected into the
    /// verifier spawn envelope as
    /// `RAXIS_VERIFIER_OPERATOR_HINTS_JSON` (single env var) so the
    /// verifier sees a deterministic byte sequence and the kernel
    /// can later echo the SAME map into
    /// `WitnessSubmission.body.operator_hints` without trusting the
    /// verifier to round-trip the hints. Empty by default.
    pub hints: BTreeMap<String, serde_json::Value>,

    /// iter63-followups.md Item 2 — resolved bounded-runtime
    /// guard config (wall-clock / idle / cumulative / VM force-grace).
    /// Pulled from `PolicyBundle::verifier_runtime` at `from_policy`
    /// time so the spawn-path doesn't need to re-resolve it.
    pub verifier_runtime: VerifierRuntimeConfig,
}

impl VerifierConfig {
    pub fn from_policy(policy: &PolicyBundle, gate_type: &str, data_dir: &Path) -> Option<Self> {
        let gate = policy.gates().iter().find(|g| g.gate_type == gate_type)?;
        Some(Self {
            verifier_binary_path: PathBuf::from(&gate.verifier_command),
            verifier_token_ttl_secs: 300, // 5 min default
            verifier_cpu_secs: gate.max_wall_seconds as u64,
            verifier_memory_bytes: gate.max_memory_bytes,
            verifier_max_wall_secs: gate.max_wall_seconds as u64 + 10,
            max_concurrent_verifiers: DEFAULT_MAX_CONCURRENT_VERIFIERS,
            kernel_socket_path: data_dir
                .join("sockets")
                .join("planner.sock")
                .display()
                .to_string(),
            hints: gate.hints.clone(),
            verifier_runtime: policy.verifier_runtime(),
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
///
/// Test-only wrapper: production callers go through
/// [`spawn_verifier_with_audit`] so the watcher task can emit
/// `VerifierWallClockTimeout` / `VerifierIdleTimeout` /
/// `VerifierBudgetExhausted` audit rows on the iter63 bounded-runtime
/// guard kill paths.
pub async fn spawn_verifier(
    task_id: &str,
    gate_type: &str,
    evaluation_sha: &str,
    worktree_root: &Path,
    config: &VerifierConfig,
    store: &Store,
) -> Result<String, GateError> {
    spawn_verifier_with_audit(
        task_id,
        gate_type,
        evaluation_sha,
        worktree_root,
        config,
        store,
        None,
    )
    .await
}

/// Production entry-point that accepts an optional `Arc<dyn AuditSink>`
/// so the watcher task can emit the iter63 bounded-runtime audit
/// variants (`VerifierWallClockTimeout`, `VerifierIdleTimeout`).
///
/// All callers from `handlers::*` thread `Some(ctx.audit.clone())`;
/// `spawn_verifier` (the wrapper above) keeps the older
/// no-audit shape for the integration tests that spin verifiers up
/// against `/usr/bin/sleep` without a kernel context.
pub async fn spawn_verifier_with_audit(
    task_id: &str,
    gate_type: &str,
    evaluation_sha: &str,
    worktree_root: &Path,
    config: &VerifierConfig,
    store: &Store,
    audit: Option<std::sync::Arc<dyn AuditSink>>,
) -> Result<String, GateError> {
    // Step 0 (iter63-followups.md Item 2 #3): per-task cumulative-time
    // ceiling check. If the task's accumulated verifier wall-time
    // already exceeds the budget, refuse to spawn another verifier
    // and emit `VerifierBudgetExhausted`. Pinned by
    // `INV-VERIFIER-CUMULATIVE-BUDGET-01`.
    let cumulative = task_cumulative_verifier_seconds(task_id);
    let budget_seconds = config.verifier_runtime.task_verifier_total_budget_seconds as u64;
    if cumulative >= budget_seconds {
        if let Some(sink) = audit.as_ref() {
            let _ = sink.emit(
                AuditEventKind::VerifierBudgetExhausted {
                    task_id: task_id.to_owned(),
                    cumulative_seconds: cumulative,
                    budget_seconds,
                },
                None,
                Some(task_id),
                None,
            );
        }
        return Err(GateError::VerifierBudgetExhausted {
            task_id: task_id.to_owned(),
            cumulative_seconds: cumulative,
            budget_seconds,
        });
    }

    // Step 1: Check global concurrent verifier count.
    let current = ACTIVE_VERIFIERS.load(Ordering::Relaxed);
    if current >= config.max_concurrent_verifiers {
        return Err(GateError::VerifierCapExceeded {
            task_id: task_id.to_owned(),
            gate_type: gate_type.to_owned(),
        });
    }

    // Step 2: Issue verifier run token.
    //
    // `issue_verifier_token` is sync and acquires the store mutex via
    // `Store::lock_sync()` → `tokio::sync::Mutex::blocking_lock()`. Calling
    // `blocking_lock` from a thread that is currently driving the tokio
    // runtime panics with "Cannot block the current thread from within a
    // runtime" (kernel-store.md §2.5.1 documents this as the v1 contract:
    // sync authority calls MUST be invoked through `tokio::task::spawn_blocking`
    // when the caller is async). This `spawn_verifier` is itself async and
    // gets called via `.await` from `gates::evaluate_gates` and
    // `handlers::witness::handle`, so the `spawn_blocking` wrapper has to
    // happen HERE — without it, the very first verifier spawn at runtime
    // would panic the kernel. (Latent P0 surfaced by
    // `verifier_runner::integration::successful_spawn_persists_verifier_run_tokens_row_with_correct_fields`,
    // and pinned by every test in that module.)
    let verifier_run_id = uuid::Uuid::new_v4().to_string();
    let raw_token = {
        let store_clone = store.clone();
        let run_id_owned = verifier_run_id.clone();
        let task_id_owned = task_id.to_owned();
        let gate_type_owned = gate_type.to_owned();
        let evaluation_sha_owned = evaluation_sha.to_owned();
        let ttl = config.verifier_token_ttl_secs;
        tokio::task::spawn_blocking(move || {
            verifier_token::issue_verifier_token(
                &run_id_owned,
                &task_id_owned,
                &gate_type_owned,
                &evaluation_sha_owned,
                ttl,
                &store_clone,
            )
        })
        .await
        .map_err(|e| {
            GateError::AuthorityError(format!(
                "issue_verifier_token spawn_blocking join failed: {e}"
            ))
        })?
        .map_err(|e| GateError::AuthorityError(e.to_string()))?
    };

    // Step 3 (iter63-followups.md Item 1 (C)): serialise operator-
    // authored hints to a deterministic JSON byte sequence so the
    // verifier sees the same bytes the kernel will later echo into
    // `WitnessSubmission.body.operator_hints`. The `BTreeMap`
    // ordering on `config.hints` (validated at policy-load time) is
    // what gives us determinism without a separate canonicaliser.
    let hints_json = serde_json::to_string(&config.hints).map_err(|e| GateError::SpawnFailed {
        gate_type: gate_type.to_owned(),
        reason: format!("serialise operator hints to JSON: {e}"),
    })?;

    // Step 4: Build spawn envelope environment (scrubbed — env_clear() first).
    let mut cmd = Command::new(&config.verifier_binary_path);
    cmd.env_clear()
        .env("RAXIS_VERIFIER_TOKEN", &raw_token)
        .env("RAXIS_TASK_ID", task_id)
        .env("RAXIS_GATE_TYPE", gate_type)
        .env("RAXIS_EVALUATION_SHA", evaluation_sha)
        .env("RAXIS_KERNEL_SOCKET", &config.kernel_socket_path)
        .env("RAXIS_WORKTREE_ROOT", worktree_root.display().to_string())
        // iter63 — operator hints, single env var (avoids the
        // per-key escaping mess of `RAXIS_HINT_<KEY>=<VAL>`).
        // Always set (even if empty `{}`) so a verifier that
        // unconditionally reads the var sees a parseable value.
        .env("RAXIS_VERIFIER_OPERATOR_HINTS_JSON", &hints_json)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(worktree_root);

    // Step 5: Spawn subprocess.
    // Note: FD_CLOEXEC is set by tokio::process::Command by default on Unix.
    let mut child = cmd.spawn().map_err(|e| GateError::SpawnFailed {
        gate_type: gate_type.to_owned(),
        reason: e.to_string(),
    })?;

    let run_id_clone = verifier_run_id.clone();
    let task_id_clone = task_id.to_owned();
    // iter63 — hard wall-clock kill: enforce the MIN of the
    // gate-declared timeout (config.verifier_max_wall_secs) and the
    // policy-bundle ceiling (verifier_runtime.max_verifier_wall_seconds).
    // `min(...)` is the canonical reading of
    // `iter63-followups.md` Item 2 #1.
    let declared = config.verifier_max_wall_secs;
    let policy_max = config.verifier_runtime.max_verifier_wall_seconds as u64;
    let wall_seconds = declared.min(policy_max);
    let grace_seconds = config
        .verifier_runtime
        .verifier_force_shutdown_grace_seconds as u64;
    let audit_for_watcher = audit.clone();

    // Step 6: Increment counter. Register completion watcher.
    ACTIVE_VERIFIERS.fetch_add(1, Ordering::Relaxed);

    tokio::spawn(async move {
        let started = Instant::now();
        let wait_fut = child.wait();
        let outcome = tokio::time::timeout(Duration::from_secs(wall_seconds), wait_fut).await;
        let elapsed = started.elapsed();
        let elapsed_ms = elapsed.as_millis() as u64;
        // Round elapsed up to seconds for the cumulative budget
        // accumulator so a sub-second verifier still contributes
        // a tick (and a misconfigured 0.1s sleep-loop verifier
        // doesn't dodge the per-task ceiling forever).
        let elapsed_secs = elapsed
            .as_secs()
            .saturating_add(if elapsed.subsec_millis() > 0 { 1 } else { 0 });
        match outcome {
            Ok(Ok(_status)) => {
                // Normal exit — record the wall-time against the
                // per-task accumulator and let the existing audit
                // path (`emit_vm_exited`, wired at the iter62 audit
                // helper layer) handle the exit row.
            }
            Ok(Err(e)) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"VerifierWaitError\",\
                     \"verifier_run_id\":\"{run_id_clone}\",\"reason\":\"{e}\"}}"
                );
            }
            Err(_elapsed) => {
                // iter63 — wall-clock kill path. SIGTERM, wait
                // up to `grace_seconds`, then SIGKILL. `child.kill()`
                // on tokio's process maps to SIGKILL directly; we
                // wrap a SIGTERM-then-wait sequence via the start_kill
                // API and bound it with the grace window.
                let _ = child.start_kill();
                let _ =
                    tokio::time::timeout(Duration::from_secs(grace_seconds), child.wait()).await;
                // Belt-and-braces SIGKILL if start_kill / wait did
                // not collect within the grace window.
                let _ = child.kill().await;
                if let Some(sink) = audit_for_watcher.as_ref() {
                    let _ = sink.emit(
                        AuditEventKind::VerifierWallClockTimeout {
                            verifier_run_id: run_id_clone.clone(),
                            task_id: task_id_clone.clone(),
                            budget_seconds: wall_seconds,
                            elapsed_ms,
                        },
                        None,
                        Some(&task_id_clone),
                        None,
                    );
                }
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"VerifierWallClockTimeout\",\
                     \"verifier_run_id\":\"{run_id_clone}\",\
                     \"task_id\":\"{task_id_clone}\",\
                     \"budget_seconds\":{wall_seconds}}}"
                );
            }
        }
        // Always credit elapsed against the per-task accumulator,
        // whether the verifier exited normally or was reaped.
        record_task_verifier_seconds(&task_id_clone, elapsed_secs);
        ACTIVE_VERIFIERS.fetch_sub(1, Ordering::Relaxed);
    });

    // Step 7: Return verifier_run_id.
    Ok(verifier_run_id)
}

// ---------------------------------------------------------------------------
// Integration tests — spawn_verifier end-to-end against existing OS binaries.
//
// These tests deliberately do NOT depend on a custom raxis-verifier-stub
// crate. Standing one up would be ~1000 LOC, require build-system wiring,
// and introduce CI flake risk; instead we lean on POSIX-supplied binaries
// (`/usr/bin/true`, `/bin/sleep`, `/usr/bin/env`, `/bin/sh`) that are
// present on every Unix the kernel is supported on. The cost is that we
// can't read child stdout (the production code captures it into a pipe
// the spawned watcher task owns), so for assertions about env-scrubbing
// and current-dir we emit a tiny shell script that captures into a
// per-test tempfile we own.
//
// What this exercises:
//   - The cap-exceeded check happens BEFORE token issuance and BEFORE
//     spawn — verifiable by asserting the verifier_run_tokens table is
//     untouched on a cap-exceeded path.
//   - The counter is incremented after a successful spawn AND
//     decremented when the child exits (delta-checked, not absolute,
//     because ACTIVE_VERIFIERS is a process-global that other tests
//     could be holding > 0 concurrently).
//   - A spawn failure (non-existent binary) does NOT leak the counter:
//     ACTIVE_VERIFIERS is incremented AFTER `cmd.spawn()` succeeds, so a
//     spawn-time error returns Err without bumping the counter.
//   - The wall-clock kill path actually terminates a long-running child:
//     we spawn `/bin/sleep 60` with `verifier_max_wall_secs = 1` and
//     observe the counter dropping back to its prior value within
//     timeout + grace, i.e. proving the kill landed.
//   - `env_clear()` actually scrubs the parent environment: we set a
//     unique `RAXIS_TEST_BLEEDOVER_<rand>` env var in the parent
//     immediately before spawning, and assert it is NOT present in the
//     child's env dump.
//   - `current_dir(worktree_root)` is honoured: the script's first line
//     is `pwd` and we assert it equals the canonical worktree path.
//   - On a successful spawn, a `verifier_run_tokens` row is persisted
//     with the correct `(task_id, gate_type, evaluation_sha)` tuple.
// ---------------------------------------------------------------------------

#[cfg(all(test, unix))]
#[allow(clippy::await_holding_lock)]
mod integration {
    use super::*;
    use raxis_test_support::mem_store;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex as StdMutex;
    use std::time::Instant;
    use tempfile::TempDir;

    // ── Test helpers ─────────────────────────────────────────────────────────

    /// Serialize EVERY test in this module. There are two distinct
    /// sources of cross-test interference, both of which break unless
    /// the suite runs with --test-threads=1 OR each test acquires this
    /// lock for its full lifetime:
    ///
    ///   1. `ACTIVE_VERIFIERS` is a process-global atomic. Each
    ///      `#[tokio::test(multi_thread)]` builds its OWN tokio
    ///      runtime; when a test exits, that runtime is dropped, and
    ///      any `tokio::spawn`-ed watcher task that hasn't yet reached
    ///      `ACTIVE_VERIFIERS.fetch_sub(1)` gets cancelled with the
    ///      runtime — leaking the counter forever. A concurrent test
    ///      then reads a non-zero baseline and fails its delta check.
    ///      Holding this lock means a test cannot end (and drop its
    ///      runtime) until its watcher has run to completion.
    ///
    ///   2. The env-clear test mutates process-wide environment via
    ///      `std::env::set_var` to plant a bleed-over marker; two such
    ///      mutations in parallel would clobber each other.
    ///
    /// Since the cost is small (six tests, all under five seconds),
    /// we lock unconditionally for every test rather than try to
    /// classify which ones are safe to run in parallel — the
    /// classification itself is fragile because adding ANY future test
    /// that touches the counter would require revisiting it.
    static GLOBAL_LOCK: StdMutex<()> = StdMutex::new(());

    /// Acquire `GLOBAL_LOCK`, recovering automatically from poisoning.
    ///
    /// Any test that panics while holding the lock would otherwise
    /// poison every subsequent acquisition with `PoisonError`,
    /// cascading one real failure into N spurious failures of
    /// otherwise-healthy tests in the same suite. We don't share any
    /// invariant-bearing state through this lock — it's strictly a
    /// serialisation token for `ACTIVE_VERIFIERS` and process-wide
    /// env mutations — so recovering the inner `()` is safe.
    fn acquire_global_lock() -> std::sync::MutexGuard<'static, ()> {
        GLOBAL_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn skip_if_missing(path: &str) -> bool {
        if !std::path::Path::new(path).exists() {
            eprintln!("integration test skipped: {path} not found on this host");
            return true;
        }
        false
    }

    /// Build a `VerifierConfig` with conservative defaults suitable for
    /// every test in this module. Per-test overrides are applied via
    /// `with_*` modifications by the caller.
    fn config_for(verifier_binary: &Path) -> VerifierConfig {
        VerifierConfig {
            verifier_binary_path: verifier_binary.to_path_buf(),
            verifier_token_ttl_secs: 60,
            verifier_cpu_secs: 30,
            verifier_memory_bytes: 1 << 30, // 1 GiB
            verifier_max_wall_secs: 30,
            max_concurrent_verifiers: DEFAULT_MAX_CONCURRENT_VERIFIERS,
            kernel_socket_path: "/tmp/raxis-test-no-such-socket.sock".to_owned(),
            hints: BTreeMap::new(),
            verifier_runtime: VerifierRuntimeConfig::default(),
        }
    }

    /// Poll `f()` every `step` until it returns `true` or `deadline` is
    /// hit. Returns whether the predicate observed `true`. Used in place
    /// of `tokio::time::timeout` for ACTIVE_VERIFIERS observability —
    /// the counter changes are not awaitable, so we sample.
    async fn await_until<F>(mut f: F, deadline: Duration) -> bool
    where
        F: FnMut() -> bool,
    {
        let started = Instant::now();
        let step = Duration::from_millis(20);
        loop {
            if f() {
                return true;
            }
            if started.elapsed() >= deadline {
                return false;
            }
            tokio::time::sleep(step).await;
        }
    }

    fn unique_id(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
    }

    /// Insert minimal `initiatives` + `tasks` rows so a subsequent
    /// `verifier_run_tokens` insert satisfies the FK on `tasks.task_id`.
    /// All fields are placeholder values that satisfy the CHECK
    /// constraints; the production code under test does not read them
    /// back.
    ///
    /// Uses `Store::lock().await` (NOT `lock_sync`) because every test
    /// in this module runs on a tokio runtime and `blocking_lock` would
    /// panic from within async context (same root cause as the P0 in
    /// production `spawn_verifier`).
    async fn seed_task_for(store: &Store, task_id: &str) {
        use raxis_types::{InitiativeState, TaskState};
        let initiative_id = format!("init-{}", uuid::Uuid::new_v4().simple());
        let conn = store.lock().await;
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, ?2, '{{}}', 'sha-stub', 0)"
            ),
            rusqlite::params![&initiative_id, InitiativeState::ApprovedPlan.as_sql_str()],
        )
        .expect("seed initiative");
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at)
                 VALUES (?1, ?2, 'default', ?3, 'planner', 1, 0, 0)"
            ),
            rusqlite::params![task_id, &initiative_id, TaskState::Running.as_sql_str()],
        )
        .expect("seed task");
    }

    // ── PRIORITY 1 — counter, cap, token row ─────────────────────────────────

    // All tests use the multi-thread runtime: the production code path
    // calls `Store::lock_sync()` which uses `blocking_lock()`, which
    // panics on a single-threaded runtime. The kernel itself runs on
    // tokio multi-thread, so this matches reality.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_succeeds_against_bin_true_and_decrements_counter_on_exit() {
        let _guard = acquire_global_lock();
        if skip_if_missing("/usr/bin/true") {
            return;
        }
        let store = mem_store();
        let tmp = TempDir::new().unwrap();
        let cfg = config_for(Path::new("/usr/bin/true"));

        let task_id = unique_id("task");
        seed_task_for(&store, &task_id).await;
        let baseline = active_verifier_count();
        let run_id = spawn_verifier(&task_id, "test-gate", "abcd1234", tmp.path(), &cfg, &store)
            .await
            .expect("spawn must succeed against /usr/bin/true");

        assert!(
            !run_id.is_empty(),
            "spawn_verifier must return a non-empty run_id"
        );

        // /usr/bin/true exits within a few ms; the watcher decrements
        // ACTIVE_VERIFIERS as soon as `child.wait()` resolves. Allow up
        // to 1s for the runtime to schedule the watcher task.
        let dropped = await_until(
            || active_verifier_count() <= baseline,
            Duration::from_secs(1),
        )
        .await;
        assert!(
            dropped,
            "ACTIVE_VERIFIERS did not drop back to baseline ({baseline}) within 1s; \
             current = {}",
            active_verifier_count()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_failed_against_nonexistent_binary_does_not_leak_counter() {
        let _guard = acquire_global_lock();
        // ACTIVE_VERIFIERS is incremented AFTER cmd.spawn() succeeds;
        // a spawn-time failure must not advance the counter, or the cap
        // would slowly drift down to zero usable slots over time.
        let store = mem_store();
        let tmp = TempDir::new().unwrap();
        let cfg = config_for(Path::new("/nonexistent/raxis-verifier-binary"));

        let task_id = unique_id("task");
        seed_task_for(&store, &task_id).await;
        let baseline = active_verifier_count();
        let result =
            spawn_verifier(&task_id, "test-gate", "abcd1234", tmp.path(), &cfg, &store).await;

        match result {
            Err(GateError::SpawnFailed { .. }) => {}
            other => panic!("expected SpawnFailed, got {other:?}"),
        }

        // The counter must be EXACTLY at baseline. Allow a brief
        // settling window in case a concurrent test was decrementing
        // simultaneously, but the count must never EXCEED baseline as a
        // result of THIS call.
        let counter = active_verifier_count();
        assert!(
            counter <= baseline,
            "spawn-failure leaked the counter: baseline={baseline}, current={counter}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cap_exceeded_returns_err_without_spawning_or_issuing_token() {
        let _guard = acquire_global_lock();
        // max_concurrent_verifiers = 0 forces `current >= 0` to be true
        // on the very first check, so cap_exceeded fires deterministically
        // regardless of what other tests are doing to the counter.
        let store = mem_store();
        let tmp = TempDir::new().unwrap();
        let mut cfg = config_for(Path::new("/usr/bin/true"));
        cfg.max_concurrent_verifiers = 0;

        let task_id = unique_id("task");
        seed_task_for(&store, &task_id).await;
        let result =
            spawn_verifier(&task_id, "test-gate", "abcd1234", tmp.path(), &cfg, &store).await;

        match result {
            Err(GateError::VerifierCapExceeded {
                task_id: t,
                gate_type: g,
            }) => {
                assert_eq!(t, task_id);
                assert_eq!(g, "test-gate");
            }
            other => panic!("expected VerifierCapExceeded, got {other:?}"),
        }

        // Critical invariant: the cap check happens BEFORE token
        // issuance. If it didn't, every cap-exceeded spawn would still
        // burn a row in verifier_run_tokens, and on a busy kernel the
        // table would fill with orphan rows that never get consumed.
        let conn = store.lock().await;
        let row_count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {VERIFIER_RUN_TOKENS} WHERE task_id = ?1"),
                rusqlite::params![&task_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(row_count, 0, "cap-exceeded path must NOT issue a token row");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successful_spawn_persists_verifier_run_tokens_row_with_correct_fields() {
        let _guard = acquire_global_lock();
        if skip_if_missing("/usr/bin/true") {
            return;
        }
        let store = mem_store();
        let tmp = TempDir::new().unwrap();
        let cfg = config_for(Path::new("/usr/bin/true"));

        let task_id = unique_id("task");
        seed_task_for(&store, &task_id).await;
        let run_id = spawn_verifier(
            &task_id,
            "TestCoverage",
            "f00dbabef00dbabef00dbabef00dbabe",
            tmp.path(),
            &cfg,
            &store,
        )
        .await
        .expect("spawn");

        let conn = store.lock().await;
        let (db_task_id, db_gate, db_eval, consumed): (String, String, String, i64) = conn
            .query_row(
                &format!(
                    "SELECT task_id, gate_type, evaluation_sha, consumed
                       FROM {VERIFIER_RUN_TOKENS}
                      WHERE verifier_run_id = ?1"
                ),
                rusqlite::params![&run_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("verifier_run_tokens row must exist for successful spawn");

        assert_eq!(db_task_id, task_id);
        assert_eq!(db_gate, "TestCoverage");
        assert_eq!(db_eval, "f00dbabef00dbabef00dbabef00dbabe");
        assert_eq!(consumed, 0, "freshly issued tokens are unconsumed");
    }

    // ── PRIORITY 2 — wall-clock timeout ──────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wall_clock_kill_terminates_bin_sleep_within_timeout_plus_grace() {
        let _guard = acquire_global_lock();
        if skip_if_missing("/bin/sleep") {
            return;
        }
        let store = mem_store();
        let tmp = TempDir::new().unwrap();

        // Sleep for 60 seconds, but only allow 1 second wall-clock budget.
        // The watcher task MUST fire its kill within ~1s and decrement
        // the counter shortly after.
        let mut cfg = config_for(Path::new("/bin/sleep"));
        cfg.verifier_max_wall_secs = 1;
        // We need to pass "60" as an argument, but spawn_verifier doesn't
        // take args in its current API — the binary path is invoked
        // bare. Use a wrapper script so we can encode the sleep duration.
        let script = tmp.path().join("sleep.sh");
        std::fs::write(&script, "#!/bin/sh\nexec /bin/sleep 60\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        cfg.verifier_binary_path = script.clone();

        let task_id = unique_id("task");
        seed_task_for(&store, &task_id).await;
        let baseline = active_verifier_count();
        let _run_id = spawn_verifier(&task_id, "test-gate", "deadbeef", tmp.path(), &cfg, &store)
            .await
            .expect("spawn");

        // Counter MUST go up by exactly 1 right after spawn.
        let bumped = await_until(
            || active_verifier_count() > baseline,
            Duration::from_secs(1),
        )
        .await;
        assert!(bumped, "counter did not increment after successful spawn");

        // Wait wall_secs (1) + generous grace (4) for kill + watcher
        // decrement to settle.
        let dropped = await_until(
            || active_verifier_count() <= baseline,
            Duration::from_secs(5),
        )
        .await;
        assert!(
            dropped,
            "wall-clock kill did not decrement counter within wall_secs+grace; \
             counter currently {}",
            active_verifier_count()
        );
    }

    // ── PRIORITY 3 — env scrub + current_dir ─────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn env_clear_scrubs_parent_env_and_current_dir_is_set_to_worktree_root() {
        let _guard = acquire_global_lock();
        if skip_if_missing("/bin/sh") {
            return;
        }

        let store = mem_store();
        let tmp = TempDir::new().unwrap();
        let worktree = tmp.path().join("wt");
        std::fs::create_dir_all(&worktree).unwrap();

        // The captured-output path is hardcoded into the script body so
        // the child can write to it without any env var passthrough.
        //
        // RACE NOTE — flake fix: `pwd > dst` and `env >> dst` were two
        // separate writes, so once `pwd` finished the file was non-empty
        // and the test's `await_until(|| len > 0)` predicate could
        // observe it BEFORE `env` had appended its output. The child
        // would then exit with `env_keys = {}` and the "missing required
        // var" assertion fired (observed under load on macOS in
        // ~1-in-10 workspace test runs).
        //
        // We now write the entire payload to `<dst>.tmp` in a single
        // brace group (one `open(O_TRUNC|O_CREAT)` from the shell's
        // perspective), then atomically rename to `<dst>`. POSIX
        // guarantees `rename(2)` is atomic on the same filesystem, so
        // the test's existence-check observes the COMPLETED file or no
        // file at all — never a partially-written one.
        let captured = tmp.path().join("captured.txt");
        let script = tmp.path().join("probe.sh");
        let script_body = format!(
            "#!/bin/sh\n\
             {{ pwd; env; }} > {dst}.tmp\n\
             mv {dst}.tmp {dst}\n",
            dst = captured.display(),
        );
        std::fs::write(&script, script_body.as_bytes()).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Set a unique parent-env marker. After env_clear() in the
        // production code, the child MUST NOT see this var.
        let bleed_var = format!("RAXIS_TEST_BLEEDOVER_{}", uuid::Uuid::new_v4().simple());
        // SAFETY: serialized through GLOBAL_LOCK; no other test in this
        // module touches process env concurrently.
        unsafe {
            std::env::set_var(&bleed_var, "should-not-leak");
        }

        let cfg = config_for(&script);
        let task_id = unique_id("task");
        seed_task_for(&store, &task_id).await;
        let _run_id = spawn_verifier(
            &task_id,
            "TestCoverage",
            "abcd1234",
            &worktree,
            &cfg,
            &store,
        )
        .await
        .expect("spawn");

        // Wait up to 2s for the child to atomically rename `.tmp` to
        // `captured.txt`. Existence of `captured.txt` is the
        // synchronisation token — see the RACE NOTE on the script body.
        let written = await_until(|| captured.exists(), Duration::from_secs(2)).await;
        assert!(written, "child did not produce the capture file within 2s");

        // Cleanup the env var promptly.
        unsafe {
            std::env::remove_var(&bleed_var);
        }

        let captured_text = std::fs::read_to_string(&captured).unwrap();
        let mut lines = captured_text.lines();

        // Line 1: pwd. macOS symlinks /tmp -> /private/tmp, so resolve
        // both sides through canonicalize for a fair compare.
        let observed_cwd = lines.next().expect("script must emit a pwd line");
        let want = std::fs::canonicalize(&worktree).unwrap();
        let got = std::fs::canonicalize(observed_cwd).unwrap();
        assert_eq!(got, want, "child cwd mismatch: want {want:?}, got {got:?}");

        // The remaining lines are env entries `KEY=value`. Build a
        // {KEY} set we can assert against.
        let env_keys: std::collections::BTreeSet<&str> = lines
            .filter_map(|l| l.split_once('='))
            .map(|(k, _)| k)
            .collect();

        // Negative assertions — env_clear() must have stripped these.
        assert!(
            !env_keys.contains(bleed_var.as_str()),
            "env_clear leaked parent var {bleed_var:?}"
        );
        for forbidden in &["PATH", "HOME", "USER", "SHELL", "TERM"] {
            assert!(
                !env_keys.contains(forbidden),
                "env_clear leaked parent var {forbidden:?}; child env keys = {env_keys:?}"
            );
        }

        // Positive assertions — every var the production envelope is
        // documented to set MUST be present. Update this list whenever
        // the spawn envelope adds or removes a var (kernel-core.md §2.3).
        for required in &[
            "RAXIS_VERIFIER_TOKEN",
            "RAXIS_TASK_ID",
            "RAXIS_GATE_TYPE",
            "RAXIS_EVALUATION_SHA",
            "RAXIS_KERNEL_SOCKET",
            "RAXIS_WORKTREE_ROOT",
            // iter63-followups.md Item 1 (C) — operator-authored
            // hints, single env var (always set even when empty for
            // a parseable reading on the verifier side).
            "RAXIS_VERIFIER_OPERATOR_HINTS_JSON",
        ] {
            assert!(
                env_keys.contains(required),
                "spawn envelope missing required var {required:?}; got {env_keys:?}"
            );
        }
    }

    // ── iter63 — RAXIS_VERIFIER_OPERATOR_HINTS_JSON wire shape ────
    //
    // Witnesses that the spawn envelope carries the deterministic
    // JSON serialisation of the configured hints map, with
    // `BTreeMap`-ordered keys (operator-side TOML order is irrelevant
    // — only the lex order of the keys is observable on the wire).

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn operator_hints_env_var_carries_deterministic_json_payload() {
        let _guard = acquire_global_lock();
        if skip_if_missing("/bin/sh") {
            return;
        }

        let store = mem_store();
        let tmp = TempDir::new().unwrap();
        let worktree = tmp.path().join("wt");
        std::fs::create_dir_all(&worktree).unwrap();

        let captured = tmp.path().join("hints.txt");
        let script = tmp.path().join("probe.sh");
        let script_body = format!(
            "#!/bin/sh\n\
             printf %s \"$RAXIS_VERIFIER_OPERATOR_HINTS_JSON\" > {dst}.tmp\n\
             mv {dst}.tmp {dst}\n",
            dst = captured.display(),
        );
        std::fs::write(&script, script_body.as_bytes()).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Populate hints in INSERTION ORDER that differs from lex
        // order (the BTreeMap will reorder to lex order before serde
        // emits JSON; that's the property we're pinning).
        let mut cfg = config_for(&script);
        cfg.hints
            .insert("language".to_owned(), serde_json::json!("rust"));
        cfg.hints
            .insert("coverage_min_pct".to_owned(), serde_json::json!(85));
        cfg.hints.insert(
            "toolchain".to_owned(),
            serde_json::json!({"channel": "stable", "version": "1.79"}),
        );

        let task_id = unique_id("task");
        seed_task_for(&store, &task_id).await;
        let _run_id = spawn_verifier(
            &task_id,
            "TestCoverage",
            "abcd1234",
            &worktree,
            &cfg,
            &store,
        )
        .await
        .expect("spawn");

        let written = await_until(|| captured.exists(), Duration::from_secs(2)).await;
        assert!(written, "hints capture file not produced");
        let payload = std::fs::read_to_string(&captured).unwrap();

        // Re-parse to assert against shape, not exact byte sequence
        // (the JSON spec allows whitespace; serde_json::to_string
        // emits the canonical compact form).
        let parsed: serde_json::Value =
            serde_json::from_str(&payload).expect("hints env var must be valid JSON");
        assert_eq!(parsed["language"], serde_json::json!("rust"));
        assert_eq!(parsed["coverage_min_pct"], serde_json::json!(85));
        assert_eq!(parsed["toolchain"]["channel"], serde_json::json!("stable"));

        // Determinism witness: the exact byte sequence must be the
        // lex-sorted compact JSON, because the `BTreeMap` iterator
        // ordering matches that of serde's `Map<String, Value>`
        // serialisation.
        let expected_bytes = serde_json::to_string(&cfg.hints).unwrap();
        assert_eq!(
            payload, expected_bytes,
            "RAXIS_VERIFIER_OPERATOR_HINTS_JSON must be deterministic"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn operator_hints_env_var_is_empty_object_when_no_hints_declared() {
        let _guard = acquire_global_lock();
        if skip_if_missing("/bin/sh") {
            return;
        }

        let store = mem_store();
        let tmp = TempDir::new().unwrap();
        let worktree = tmp.path().join("wt");
        std::fs::create_dir_all(&worktree).unwrap();

        let captured = tmp.path().join("hints.txt");
        let script = tmp.path().join("probe.sh");
        let script_body = format!(
            "#!/bin/sh\n\
             printf %s \"$RAXIS_VERIFIER_OPERATOR_HINTS_JSON\" > {dst}.tmp\n\
             mv {dst}.tmp {dst}\n",
            dst = captured.display(),
        );
        std::fs::write(&script, script_body.as_bytes()).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let cfg = config_for(&script);
        let task_id = unique_id("task");
        seed_task_for(&store, &task_id).await;
        let _ = spawn_verifier(
            &task_id,
            "TestCoverage",
            "abcd1234",
            &worktree,
            &cfg,
            &store,
        )
        .await
        .expect("spawn");

        let written = await_until(|| captured.exists(), Duration::from_secs(2)).await;
        assert!(written);
        let payload = std::fs::read_to_string(&captured).unwrap();
        assert_eq!(
            payload, "{}",
            "absent hints must serialise to the empty JSON object"
        );
    }

    // ── iter63 — per-task cumulative-time ceiling ───────────────────
    //
    // Witnesses `INV-VERIFIER-CUMULATIVE-BUDGET-01`: after the
    // accumulator crosses the ceiling, subsequent spawns return
    // `GateError::VerifierBudgetExhausted` without forking the child.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cumulative_budget_blocks_further_spawns() {
        let _guard = acquire_global_lock();
        if skip_if_missing("/usr/bin/true") {
            return;
        }
        reset_task_verifier_budget_for_tests();

        let store = mem_store();
        let tmp = TempDir::new().unwrap();
        let mut cfg = config_for(Path::new("/usr/bin/true"));
        // Squeeze the budget to 0 seconds so any non-instant spawn
        // already exceeds the ceiling. Combined with a manual nudge
        // of the accumulator below, the next spawn MUST refuse.
        cfg.verifier_runtime.task_verifier_total_budget_seconds = 1;

        let task_id = unique_id("task");
        seed_task_for(&store, &task_id).await;
        record_task_verifier_seconds(&task_id, 2); // already past

        let err = spawn_verifier(
            &task_id,
            "TestCoverage",
            "deadbeef",
            tmp.path(),
            &cfg,
            &store,
        )
        .await
        .expect_err("budget should block the next spawn");

        match err {
            GateError::VerifierBudgetExhausted {
                task_id: t,
                cumulative_seconds: c,
                budget_seconds: b,
            } => {
                assert_eq!(t, task_id);
                assert!(c >= 2);
                assert_eq!(b, 1);
            }
            other => panic!("expected VerifierBudgetExhausted, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Stub round-trip integration test — full IPC loopback through raxis-verifier-stub.
//
// The OS-binary integration tests above cover everything *external* to the
// witness wire round-trip (cap, counter, env scrub, current-dir, wall-clock
// kill, and token-row persistence). What they DO NOT cover, by design, is
// what happens once the verifier subprocess actually speaks the kernel's
// UDS protocol — because `/usr/bin/true` does not.
//
// This module fills that gap by execve()ing the dedicated
// `raxis-verifier-stub` binary built from `crates/verifier-stub/`. The
// stub is a real verifier subprocess from the kernel's perspective: it
// reads the spawn envelope from env, connects to RAXIS_KERNEL_SOCKET,
// sends one `IpcMessage::WitnessSubmission`, reads back one
// `IpcMessage::WitnessAck`, and exits. We stand up a one-shot UDS
// listener, accept the stub's connection, run the production
// `handlers::witness::handle` against the submission, and write the ack
// back. End-to-end: the bytes that traverse the socket are produced and
// consumed by code paths that exist in the production kernel.
//
// What this proves that the OS-binary suite cannot:
//   - The stub's `WitnessSubmission` (4-byte LE length + bincode 2.0.1
//     standard()) is byte-decodable by `raxis_ipc::read_frame` on the
//     kernel side.
//   - The kernel's `WitnessAck` is byte-decodable by `raxis_ipc::read_frame`
//     on the verifier side — i.e., the wire codec round-trips both
//     directions of the planner-socket protocol.
//   - `verifier_token::validate_verifier_token` accepts the raw token
//     `spawn_verifier` placed in the spawn envelope.
//   - `handlers::witness::handle` lands a `witness_records` row with the
//     correct `(task_id, gate_type, evaluation_sha, result_class)` tuple
//     when driven by a real verifier subprocess.
//
// Why we target `Inconclusive` (non-Pass) and not `Pass`:
//   - The `Pass` path triggers `gate_recheck`, which re-runs the VCS
//     diff against `task.base_sha` and `task.evaluation_sha` and calls
//     `gates::evaluate_claims`. Standing up a full git worktree + claims
//     fixture for one round-trip test is high cost; the gate-recheck
//     path is covered by `handlers::witness::tests` and `gates::tests`
//     against synthetic stores, with the Pass-vs-AcceptedNonPass
//     distinction pinned by a regression test there.
//   - The `Inconclusive` path exercises everything BEFORE gate_recheck
//     (token validate, task-row load, evaluation_sha bind, blob write,
//     SQL row insert, token consume, ack construction with
//     `AcceptedNonPass` shape, ack wire encoding) — which is the
//     interesting end-to-end path here. The gate-recheck round-trip
//     deserves its own dedicated test once the worktree fixture is
//     promoted from `vcs::diff` integration tests into the test-support
//     crate.
// ---------------------------------------------------------------------------

#[cfg(all(test, unix))]
#[allow(clippy::await_holding_lock)]
mod stub_round_trip {
    use super::*;
    use crate::handlers::witness as witness_handler;
    use crate::initiatives::PlanRegistry;
    use crate::ipc::context::HandlerContext;
    use raxis_audit_tools::AuditSink;
    use raxis_ipc::{read_frame, write_frame, IpcMessage};
    use raxis_test_support::{mem_store, FakeAuditSink};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    // ── Cross-test serialization ─────────────────────────────────────────────
    //
    // Same rationale as the sibling `integration` module: every test here
    // touches `ACTIVE_VERIFIERS` (via `spawn_verifier`) and the shared
    // tokio runtime watcher task that decrements it. A second test
    // starting before the first's runtime has finished tearing down its
    // watcher would see a leaked counter and fail its delta check.
    //
    // We deliberately use a separate lock from `integration::GLOBAL_LOCK`
    // to keep the two modules' coupling explicit — if a future refactor
    // moves these tests into a shared parent module, the locks can be
    // unified, but until then a test that touches BOTH modules' shared
    // state would have to acquire both, and a single shared lock would
    // hide that.
    static GLOBAL_LOCK: StdMutex<()> = StdMutex::new(());

    /// Acquire `GLOBAL_LOCK`, recovering automatically from poisoning.
    /// Mirrors `integration::acquire_global_lock` — see that helper
    /// for the rationale (a single panicking test must not cascade
    /// into N spurious `PoisonError` failures across the rest of the
    /// suite).
    fn acquire_global_lock() -> std::sync::MutexGuard<'static, ()> {
        GLOBAL_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    // ── Stub binary discovery ────────────────────────────────────────────────

    /// Build (if necessary) and return the absolute path of the
    /// `raxis-verifier-stub` binary.
    ///
    /// `cargo test -p raxis-kernel` does NOT automatically build sibling
    /// workspace binaries; we invoke `cargo build -p raxis-verifier-stub`
    /// once at test-startup so the binary is reliably present at the
    /// canonical `target/<profile>/raxis-verifier-stub` location. If the
    /// binary is already up-to-date this is a no-op (cargo is incremental).
    ///
    /// We deliberately do NOT use `option_env!("CARGO_BIN_EXE_<name>")`:
    /// that env var is only set for tests in the SAME crate as the
    /// binary, so it would be `None` here and force us to fall back to
    /// path navigation anyway.
    fn build_and_locate_stub() -> PathBuf {
        // Step 1: invoke `cargo build -p raxis-verifier-stub`. We use the
        // `CARGO` env var that cargo sets for every test invocation
        // rather than hardcoding `"cargo"`, so the test honours rustup
        // toolchain overrides.
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let status = std::process::Command::new(&cargo)
            .args([
                "build",
                "-p",
                "raxis-verifier-stub",
                "--bin",
                "raxis-verifier-stub",
            ])
            .status()
            .expect("spawn `cargo build -p raxis-verifier-stub`");
        assert!(
            status.success(),
            "cargo build of raxis-verifier-stub failed; cannot run round-trip test"
        );

        // Step 2: locate the built binary. The current test binary lives
        // at `target/<profile>/deps/<test-binary>`; the stub binary is
        // at `target/<profile>/raxis-verifier-stub` — i.e., one parent
        // up from `deps/`.
        let exe = std::env::current_exe().expect("current_exe");
        let target_profile_dir = exe
            .parent()
            .expect("test binary has parent")
            .parent()
            .expect("deps/ has parent");
        let stub = target_profile_dir.join("raxis-verifier-stub");
        assert!(
            stub.exists(),
            "stub binary not found at expected path: {}",
            stub.display()
        );
        stub
    }

    // ── Test-shaped HandlerContext ────────────────────────────────────────────

    /// Build a `HandlerContext` minimal enough for the witness handler to
    /// run end-to-end against an in-memory store, with the witness blob
    /// directory rooted in a tempdir. The plan registry, key registry,
    /// and policy bundle are all empty / default — the witness handler
    /// reads only `store`, `witness_dir`, and (in the Pass-path) the
    /// VCS / gates context, which our `Inconclusive` test does not exercise.
    fn handler_ctx(store: Arc<raxis_store::Store>, witness_dir: PathBuf) -> Arc<HandlerContext> {
        // We need a non-empty placeholder allowed_worktree_roots so the
        // policy bundle validates. The witness handler does not consult
        // the policy in the Inconclusive path, but HandlerContext::new
        // takes an `Arc<PolicyBundle>` we have to construct nonetheless.
        // Bind the rendered worktree-root string to a named local so the
        // borrow inside `&[..]` outlives the call (a temporary chain
        // would be dropped at the semicolon and the borrow would dangle).
        let worktree_root_str = witness_dir.display().to_string();
        // Cert-mandatory (INV-CERT-01): we must mint a structurally-valid
        // self-signed cert here so the loader's
        // `validate_operator_certs` step accepts the artifact even though
        // the witness handler never consults it. Use a deterministic seed
        // for byte-stable test output.
        let key = raxis_test_support::ephemeral_signing_key([0x22u8; 32]);
        let pk = raxis_test_support::pubkey_hex(&key);
        let fp = raxis_genesis_tools::pubkey_fingerprint(&hex::decode(&pk).unwrap());
        let cert = raxis_test_support::ephemeral_cert_with_key(
            &key,
            raxis_test_support::CertOpts {
                display_name: "verifier-runner-stub".to_owned(),
                permitted_ops: raxis_genesis_tools::PERMITTED_OPS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
                ..raxis_test_support::CertOpts::default()
            },
        );
        let policy_toml = raxis_genesis_tools::render_genesis_policy_toml(
            raxis_genesis_tools::GenesisPolicyInputs {
                authority_pubkey_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000",
                quality_pubkey_hex:
                    "1111111111111111111111111111111111111111111111111111111111111111",
                operator_pubkey_hex: &pk,
                operator_fingerprint: &fp,
                signed_at_unix_secs: 1_700_000_000,
                allowed_worktree_roots: &[worktree_root_str.as_str()],
                operator_cert: &cert,
            },
        );
        let tmp_policy = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp_policy.path(), &policy_toml).expect("write policy");
        let (policy, _bytes, _sha) = raxis_policy::load_policy(tmp_policy.path())
            .expect("load_policy of stub-test policy artifact");

        let registry = Arc::new(crate::authority::keys::KeyRegistry::stub_for_tests());
        let audit: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());
        let plan_registry = Arc::new(PlanRegistry::new());

        let data_dir_path = witness_dir
            .parent()
            .unwrap_or(Path::new("/tmp"))
            .to_path_buf();
        let credentials =
            crate::ipc::context::build_default_test_credentials(&data_dir_path, Arc::clone(&audit));
        let isolation = crate::ipc::context::build_fail_closed_test_isolation();
        let orchestrator_spawn = crate::ipc::context::build_test_orchestrator_spawn();
        let domain = crate::ipc::context::build_default_test_domain(&data_dir_path);
        Arc::new(
            HandlerContext::new(
                Arc::new(arc_swap::ArcSwap::from_pointee(policy)),
                registry,
                store,
                audit,
                data_dir_path,
                plan_registry,
                Arc::new(crate::gateway::client::GatewayClient::new()),
                Arc::new(crate::prompt::EpochBinding::new()),
                credentials,
                isolation,
                orchestrator_spawn,
                crate::ipc::context::build_test_executor_spawn(),
                domain,
            )
            .with_witness_dir(witness_dir),
        )
    }

    // ── State seeding ─────────────────────────────────────────────────────────

    /// Like `integration::seed_task_for`, but additionally:
    ///   - sets `state = 'GatesPending'` (the witness handler refuses to
    ///     accept a witness for any other state — kernel-store.md §2.5.1
    ///     Table 5 FSM contract).
    ///   - sets `evaluation_sha` to the supplied 40-char SHA so the
    ///     witness handler's evaluation-SHA binding check passes.
    async fn seed_task_in_gates_pending(
        store: &raxis_store::Store,
        task_id: &str,
        evaluation_sha: &str,
    ) {
        use raxis_types::{InitiativeState, TaskState};
        let initiative_id = format!("init-{}", uuid::Uuid::new_v4().simple());
        let conn = store.lock().await;
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, ?2, '{{}}', 'sha-stub', 0)"
            ),
            rusqlite::params![&initiative_id, InitiativeState::ApprovedPlan.as_sql_str()],
        )
        .expect("seed initiative");
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at,
                     evaluation_sha, base_sha)
                 VALUES (?1, ?2, 'default', ?3, 'planner', 1, 0, 0, ?4, ?4)"
            ),
            rusqlite::params![
                task_id,
                &initiative_id,
                TaskState::GatesPending.as_sql_str(),
                evaluation_sha,
            ],
        )
        .expect("seed task in GatesPending");
    }

    // ── Server-side: one-shot accept loop ─────────────────────────────────────

    /// Run a single accept→handle→ack cycle on `socket_path`. Bound to
    /// the kernel's actual production handler so the test exercises the
    /// real witness-handling code path, not a re-implementation.
    ///
    /// Returns the `WitnessAck` ack the kernel computed (for test-side
    /// assertions) AND whether the handler returned `Err`.
    async fn run_one_witness_round_trip(
        socket_path: PathBuf,
        ctx: Arc<HandlerContext>,
    ) -> Result<witness_handler::WitnessAck, witness_handler::HandlerError> {
        let listener = UnixListener::bind(&socket_path).expect("bind UDS");
        let (mut stream, _) = listener.accept().await.expect("accept stub connection");

        // Read the WitnessSubmission the stub sent.
        let inbound: IpcMessage = read_frame(&mut stream)
            .await
            .expect("read submission frame");
        let submission = match inbound {
            IpcMessage::WitnessSubmission(s) => s,
            other => panic!("expected WitnessSubmission from stub, got {other:?}"),
        };

        // Run the production handler — the same code path planner.sock
        // uses in production (see `ipc::server::handle_planner_connection`).
        let handler_result = witness_handler::handle(submission, &ctx).await;

        // Write the WitnessAck back, mirroring the same wire-mapping the
        // production server does (see ipc/server.rs::handle_planner_connection).
        // We collapse Accepted and AcceptedNonPass to `accepted=true` for
        // the verifier; Rejected stays `accepted=false`. This MUST match
        // production wire shape exactly or the stub would parse a different
        // ack structure than what real verifiers see.
        let ack_msg = match &handler_result {
            Ok(witness_handler::WitnessAck::Accepted { run_id, .. }) => IpcMessage::WitnessAck {
                verifier_run_id: uuid::Uuid::parse_str(run_id).unwrap_or_default(),
                accepted: true,
                reason: None,
            },
            Ok(witness_handler::WitnessAck::AcceptedNonPass {
                run_id,
                gate_type,
                result_class,
            }) => IpcMessage::WitnessAck {
                verifier_run_id: uuid::Uuid::parse_str(run_id).unwrap_or_default(),
                accepted: true,
                reason: Some(format!(
                    "non-pass recorded: gate={} result={}",
                    gate_type.as_str(),
                    result_class.as_str(),
                )),
            },
            Ok(witness_handler::WitnessAck::Rejected { reason }) => IpcMessage::WitnessAck {
                verifier_run_id: uuid::Uuid::nil(),
                accepted: false,
                reason: Some(format!("{reason:?}")),
            },
            Err(e) => IpcMessage::WitnessAck {
                verifier_run_id: uuid::Uuid::nil(),
                accepted: false,
                reason: Some(format!("handler error: {e}")),
            },
        };
        write_frame(&mut stream, &ack_msg)
            .await
            .expect("write ack frame");

        handler_result
    }

    // ── The test ──────────────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inconclusive_witness_round_trips_through_stub_to_handler() {
        let _guard = acquire_global_lock();

        // Step 1: build & locate the stub binary up front (will no-op if
        // already built, fail loudly if it can't compile).
        let stub_bin = build_and_locate_stub();

        // Step 2: in-memory store + temp witness directory. Wrap the
        // store in an `Arc` because both the production handler context
        // and `spawn_verifier` need to share it across the test task and
        // the spawned verifier subprocess accounting; the handler holds
        // it as `Arc<Store>` whereas `spawn_verifier` borrows `&Store`.
        let store: Arc<raxis_store::Store> = Arc::new(mem_store());
        let tmp = TempDir::new().expect("tempdir");
        let witness_dir = tmp.path().join("witness");
        std::fs::create_dir_all(&witness_dir).expect("mkdir witness");

        // Step 3: seed task in GatesPending with a valid 40-char eval SHA.
        // The stub will echo this SHA in its WitnessSubmission and the
        // handler's binding check will compare it against the stored value.
        let task_id = format!("task-{}", uuid::Uuid::new_v4().simple());
        let evaluation_sha = "abcd1234".repeat(5); // exactly 40 chars
        seed_task_in_gates_pending(&store, &task_id, &evaluation_sha).await;

        // Step 4: build VerifierConfig pointing at the stub binary AND at
        // the UDS we are about to bind. Use a distinct socket path per
        // test to avoid cross-test EADDRINUSE under parallel runs (we
        // already serialize via GLOBAL_LOCK, but defense-in-depth is cheap).
        //
        // CRITICAL: on Darwin / many BSDs, sockaddr_un.sun_path is
        // capped at ~104 bytes (`SUN_LEN`). The default `cargo test`
        // tempdir under `/var/folders/.../tmp/.tmp<rand>/` already
        // burns ~70 bytes before our filename, so a path like
        // `<tempdir>/kernel-<uuid>.sock` overflows. We therefore root
        // the socket directly under `std::env::temp_dir()` (typically
        // `/tmp` on macOS once symlinks are resolved, or `/tmp` on
        // Linux) with a 12-char suffix. The socket file is unlinked
        // by the `TempDir` drop is NOT reachable here, so we register
        // an explicit cleanup at the end of the test (best-effort).
        let socket_path = std::env::temp_dir().join(format!(
            "rxstub-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        ));
        // Pre-clean — a stale socket from a previously-killed test
        // run would make `bind` fail with EADDRINUSE.
        let _ = std::fs::remove_file(&socket_path);
        let cfg = VerifierConfig {
            verifier_binary_path: stub_bin.clone(),
            verifier_token_ttl_secs: 60,
            verifier_cpu_secs: 30,
            verifier_memory_bytes: 1 << 30,
            // We allow up to 5 s for the round trip — plenty for a local
            // UDS hop on any reasonable host. If this becomes flaky on a
            // very loaded CI box, raise to 15 s rather than hiding the
            // budget assertion.
            verifier_max_wall_secs: 5,
            max_concurrent_verifiers: DEFAULT_MAX_CONCURRENT_VERIFIERS,
            kernel_socket_path: socket_path.display().to_string(),
            hints: BTreeMap::new(),
            verifier_runtime: VerifierRuntimeConfig::default(),
        };

        // Step 5: stand up the one-shot server BEFORE spawning the stub.
        // Binding before spawn means the stub cannot race ahead and try
        // to connect to a not-yet-bound socket. We spawn the server task
        // detached and join it after the stub exits.
        let ctx = handler_ctx(store.clone(), witness_dir.clone());
        let server_socket = socket_path.clone();
        let server_handle =
            tokio::spawn(async move { run_one_witness_round_trip(server_socket, ctx).await });

        // Step 6: issue a real verifier_run_token via the same
        // production code path `spawn_verifier` would use, then exec
        // the stub directly so we can inject `RAXIS_STUB_RESULT_CLASS`.
        //
        // **Why not call `spawn_verifier` here?** Because
        // `spawn_verifier` calls `env_clear()` on the child Command
        // before setting the spawn envelope (see step 3 of
        // `spawn_verifier`), which strips every `RAXIS_STUB_*` knob
        // the stub uses to opt into non-Pass result classes. The OS-
        // binary suite (`integration::*` in this same module) already
        // pins `env_clear` and the full spawn-envelope behaviour, so
        // we deliberately re-exec the stub here without going through
        // `spawn_verifier` — the trade-off is "we test the wire
        // codec + handler + witness_index + token consume end-to-end"
        // vs "we re-test what `integration::*` already covers".
        // Issuing the token through `issue_verifier_token` keeps the
        // verifier_run_tokens row identical to a production spawn.
        let returned_run_id = uuid::Uuid::new_v4().to_string();
        let raw_token = {
            let store_inner = store.clone();
            let run_id = returned_run_id.clone();
            let task_id = task_id.clone();
            let eval_sha = evaluation_sha.clone();
            tokio::task::spawn_blocking(move || {
                crate::authority::verifier_token::issue_verifier_token(
                    &run_id,
                    &task_id,
                    "test-gate",
                    &eval_sha,
                    cfg.verifier_token_ttl_secs,
                    store_inner.as_ref(),
                )
            })
            .await
            .expect("issue_verifier_token join")
            .expect("issue_verifier_token must succeed against in-mem store")
        };

        // Step 7: spawn the stub directly with the full envelope +
        // test knob `RAXIS_STUB_RESULT_CLASS=Inconclusive`. We do not
        // need to scrub the parent env here (this is a test process,
        // not a kernel invocation), and the env_clear path is covered
        // by `integration::env_clear_scrubs_parent_env_*`.
        let stub_exit = std::process::Command::new(&stub_bin)
            .env("RAXIS_VERIFIER_TOKEN", &raw_token)
            .env("RAXIS_TASK_ID", &task_id)
            .env("RAXIS_GATE_TYPE", "test-gate")
            .env("RAXIS_EVALUATION_SHA", &evaluation_sha)
            .env("RAXIS_KERNEL_SOCKET", socket_path.display().to_string())
            .env("RAXIS_WORKTREE_ROOT", tmp.path().display().to_string())
            .env("RAXIS_STUB_RESULT_CLASS", "Inconclusive")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("spawn raxis-verifier-stub");
        assert!(
            stub_exit.status.success(),
            "stub exited non-zero (code {}); stderr: {}",
            stub_exit
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signalled>".to_owned()),
            String::from_utf8_lossy(&stub_exit.stderr)
        );

        // Step 8: wait for the server's accept→handle→ack cycle to complete.
        let handler_result = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle)
            .await
            .expect("server task did not finish within 5s — stub never connected?")
            .expect("server task panicked");

        // Step 9: assert the handler returned AcceptedNonPass with the
        // right gate_type and result_class echoed back from the stub.
        let ack = handler_result.expect("witness handler returned Err — stub envelope wrong?");
        match ack {
            witness_handler::WitnessAck::AcceptedNonPass {
                run_id,
                gate_type,
                result_class,
            } => {
                // run_id is the kernel-generated verifier_run_id (UUID); it
                // must equal what spawn_verifier returned to us in step 7
                // — the kernel issues exactly one token per spawn, and the
                // stub echoes that token back in its submission, so the
                // handler should resolve to the SAME run_id.
                assert_eq!(
                    run_id, returned_run_id,
                    "handler-side run_id ({run_id}) must equal the run_id \
                     spawn_verifier returned ({returned_run_id})"
                );
                assert_eq!(
                    gate_type.as_str(),
                    "test-gate",
                    "handler must echo the gate_type from the spawn envelope"
                );
                assert_eq!(
                    format!("{result_class:?}"),
                    "Inconclusive",
                    "handler must record Inconclusive (not Pass / Fail)"
                );
            }
            other => panic!("expected AcceptedNonPass, got {other:?}"),
        }

        // Step 10: assert the witness landed in the SQL index. This is
        // the strongest end-to-end assertion — it proves the byte path
        // from stub.write_frame → kernel.read_frame → handler.witness_index.write
        // → SQLite is intact.
        let count: i64 = {
            let conn = store.lock().await;
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {WITNESS_RECORDS} WHERE task_id = ?1"),
                rusqlite::params![&task_id],
                |row| row.get(0),
            )
            .expect("count witness_records")
        };
        assert_eq!(
            count, 1,
            "expected exactly one witness_records row for task_id {task_id}, got {count}"
        );

        // Step 11: assert the verifier_run_token was consumed
        // (`consumed=1` AND `consumed_at` set) — the consume happens
        // in step 5 of handlers::witness::handle. Column names per
        // kernel-store.md §2.5.1 Table 14: `consumed INTEGER NOT NULL
        // CHECK(consumed IN (0,1))` and `consumed_at INTEGER NULL`.
        let consumed: i64 = {
            let conn = store.lock().await;
            conn.query_row(
                &format!(
                    "SELECT COUNT(*) FROM {VERIFIER_RUN_TOKENS}
                     WHERE task_id = ?1 AND consumed = 1 AND consumed_at IS NOT NULL"
                ),
                rusqlite::params![&task_id],
                |row| row.get(0),
            )
            .expect("count consumed tokens")
        };
        assert_eq!(
            consumed, 1,
            "verifier_run_token for task {task_id} was not marked consumed; \
             handler write-then-consume order may have been broken"
        );

        // Step 12: best-effort cleanup of the socket file. The
        // `TempDir` does not own this path (we hoisted it to /tmp for
        // SUN_LEN), so without this every test run would leave a
        // dangling socket file. Failure is non-fatal — the next run's
        // `remove_file` pre-clean above is the actual safety net.
        let _ = std::fs::remove_file(&socket_path);
    }

    // ------------------------------------------------------------------
    // Second variant: REJECTED path (EvaluationShaMismatch).
    //
    // Pins the on-the-wire rejection round-trip — the kernel's witness
    // handler returns `WitnessAck::Rejected` when the SHA the stub
    // echoes from its envelope does not match the SHA the kernel
    // recorded on the task row. The crucial invariants this regression
    // pin enforces:
    //
    //   - Token is NOT consumed on rejection (kernel-store.md §2.5.1
    //     Table 14 + §2.3 witness.rs: "no witness write, no token
    //     consume, no WitnessAccepted audit"). A pre-fix where the
    //     rejection path consumed the token early would silently
    //     foreclose retry.
    //   - No witness_records row is written (witness blob and SQL row
    //     are both inhibited).
    //   - The wire ack STILL flows back (`accepted=false`) — we
    //     specifically test that the connection is not just closed,
    //     because verifiers depend on the ack for retry classification.
    // ------------------------------------------------------------------
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn evaluation_sha_mismatch_returns_rejected_without_consuming_token() {
        let _guard = acquire_global_lock();

        let stub_bin = build_and_locate_stub();
        let store: Arc<raxis_store::Store> = Arc::new(mem_store());
        let tmp = TempDir::new().expect("tempdir");
        let witness_dir = tmp.path().join("witness");
        std::fs::create_dir_all(&witness_dir).expect("mkdir witness");

        // Seed the task with the EXPECTED SHA. The stub will echo a
        // DIFFERENT SHA from its envelope, triggering the mismatch
        // rejection branch in handlers::witness::handle step 2.
        let task_id = format!("task-{}", uuid::Uuid::new_v4().simple());
        let stored_sha = "1111111122222222333333334444444455555555".to_owned();
        let mismatched_sha = "ffffffffeeeeeeeeddddddddccccccccbbbbbbbb".to_owned();
        seed_task_in_gates_pending(&store, &task_id, &stored_sha).await;

        let socket_path = std::env::temp_dir().join(format!(
            "rxstubrej-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        ));
        let _ = std::fs::remove_file(&socket_path);

        let cfg = VerifierConfig {
            verifier_binary_path: stub_bin.clone(),
            verifier_token_ttl_secs: 60,
            verifier_cpu_secs: 30,
            verifier_memory_bytes: 1 << 30,
            verifier_max_wall_secs: 5,
            max_concurrent_verifiers: DEFAULT_MAX_CONCURRENT_VERIFIERS,
            kernel_socket_path: socket_path.display().to_string(),
            hints: BTreeMap::new(),
            verifier_runtime: VerifierRuntimeConfig::default(),
        };

        let ctx = handler_ctx(store.clone(), witness_dir.clone());
        let server_socket = socket_path.clone();
        let server_handle =
            tokio::spawn(async move { run_one_witness_round_trip(server_socket, ctx).await });

        // Issue a token bound to the STORED SHA (this is what
        // production does: `spawn_verifier` is called with the SHA
        // the kernel believes is current, never with a mismatched
        // value). The mismatch only enters via the stub envelope
        // below, which simulates a verifier that lagged a head update.
        let returned_run_id = uuid::Uuid::new_v4().to_string();
        let raw_token = {
            let store_inner = store.clone();
            let run_id = returned_run_id.clone();
            let task_id = task_id.clone();
            let eval_sha = stored_sha.clone();
            tokio::task::spawn_blocking(move || {
                crate::authority::verifier_token::issue_verifier_token(
                    &run_id,
                    &task_id,
                    "test-gate",
                    &eval_sha,
                    cfg.verifier_token_ttl_secs,
                    store_inner.as_ref(),
                )
            })
            .await
            .expect("issue_verifier_token join")
            .expect("issue_verifier_token must succeed against in-mem store")
        };

        // Stub puts MISMATCHED sha on the wire (RAXIS_EVALUATION_SHA
        // intentionally differs from the SHA the token was bound to).
        let stub_exit = std::process::Command::new(&stub_bin)
            .env("RAXIS_VERIFIER_TOKEN", &raw_token)
            .env("RAXIS_TASK_ID", &task_id)
            .env("RAXIS_GATE_TYPE", "test-gate")
            .env("RAXIS_EVALUATION_SHA", &mismatched_sha)
            .env("RAXIS_KERNEL_SOCKET", socket_path.display().to_string())
            .env("RAXIS_WORKTREE_ROOT", tmp.path().display().to_string())
            // Pass even though we expect rejection — the mismatch
            // happens at step 2 (binding check) which runs BEFORE
            // the result_class is consulted (step 3+).
            .env("RAXIS_STUB_RESULT_CLASS", "Pass")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("spawn raxis-verifier-stub");

        // Stub MUST exit `Rejected` (= 1, see ExitCode::Rejected).
        // Any other code (especially 0 = AcceptedPass) means the
        // kernel mistakenly accepted a SHA-mismatched submission,
        // which would break the gate-binding contract.
        assert_eq!(
            stub_exit.status.code(),
            Some(1),
            "stub MUST exit Rejected(1) on SHA mismatch, got {}; stderr: {}",
            stub_exit
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signalled>".to_owned()),
            String::from_utf8_lossy(&stub_exit.stderr)
        );

        // Server-side ack must be Rejected with the EvaluationShaMismatch reason.
        let handler_result = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle)
            .await
            .expect("server task did not finish within 5s")
            .expect("server task panicked");
        let ack = handler_result.expect("witness handler returned Err on mismatch");
        match ack {
            witness_handler::WitnessAck::Rejected { reason } => {
                let r = format!("{reason:?}");
                assert!(
                    r.contains("EvaluationShaMismatch"),
                    "expected EvaluationShaMismatch reason, got {r:?}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }

        // Verify NO witness_records row was written — the rejection
        // path must inhibit the witness write entirely.
        let count: i64 = {
            let conn = store.lock().await;
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {WITNESS_RECORDS} WHERE task_id = ?1"),
                rusqlite::params![&task_id],
                |row| row.get(0),
            )
            .expect("count witness_records")
        };
        assert_eq!(
            count, 0,
            "rejection path must NOT write a witness_records row; got {count}"
        );

        // Verify the verifier_run_token is STILL UNCONSUMED. This is
        // the critical invariant — a pre-fix where rejection consumed
        // the token would silently break retry, because the verifier
        // could never use it again.
        let unconsumed: i64 = {
            let conn = store.lock().await;
            conn.query_row(
                &format!(
                    "SELECT COUNT(*) FROM {VERIFIER_RUN_TOKENS}
                     WHERE task_id = ?1 AND consumed = 0 AND consumed_at IS NULL"
                ),
                rusqlite::params![&task_id],
                |row| row.get(0),
            )
            .expect("count unconsumed tokens")
        };
        assert_eq!(
            unconsumed, 1,
            "rejection path consumed the token (unconsumed count = {unconsumed}); \
             this would foreclose verifier retry"
        );

        let _ = std::fs::remove_file(&socket_path);
    }

    // No process-global env helpers: every `RAXIS_STUB_*` knob this
    // module needs reaches the stub via `Command::env()` on the child
    // (see step 7 above), so we never touch `std::env::set_var` and
    // never need an RAII cleanup. This avoids cross-test bleed when
    // workspace `cargo test` runs us in parallel with sibling tests
    // that also read these env vars.
}
