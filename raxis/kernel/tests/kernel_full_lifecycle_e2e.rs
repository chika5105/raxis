//! Full-lifecycle end-to-end tests for the `raxis-kernel` binary.
//!
//! ## Why this file exists
//!
//! The pre-existing integration tests pin specific surfaces:
//!
//!   * `mock_planner_end_to_end.rs` — planner-socket framing.
//!   * `kernel_signal_shutdown.rs`  — SIGTERM/SIGINT graceful exit.
//!   * `operator_handshake_smoke.rs` — operator-socket auth.
//!
//! None of them pin the **whole** lifecycle: bootstrap → spawn → drive
//! traffic → graceful shutdown → spawn AGAIN → audit chain still
//! verifies → graceful shutdown again. That is the contract the
//! kernel as a "real" production daemon depends on, and is exactly
//! what `T0.5 — AuditWriter resume across restarts` (Phase A) was
//! introduced to support. This file is the regression guard for
//! that contract.
//!
//! ## What each test covers (one invariant per test)
//!
//! 1. **Heartbeat freshness during runtime.** The kernel writes
//!    `<data_dir>/runtime/heartbeat.json` on a periodic tick
//!    (cli-readonly.md §5.2). Pin: after spawn the file exists,
//!    deserialises into the canonical `Snapshot`, and reports the
//!    correct PID + a `state` of `Running`.
//!
//! 2. **Audit chain monotonicity across a restart (T0.5).** Spawn,
//!    drive a few intent frames, SIGTERM. Re-spawn against the SAME
//!    data dir, drive more intents, SIGTERM. Run a chain walk over
//!    the now-grown segment with `raxis_audit_tools::ChainReader`
//!    and assert the chain is intact end-to-end (no `seq` gap, no
//!    `prev_sha256` break) — i.e. the "starting_seq=0 every restart"
//!    bug from Phase A is not back.
//!
//! 3. **Read-only CLI surface works against a live kernel.** Boot
//!    the kernel, then spawn `raxis status --json` as a subprocess
//!    pointing at the same data dir. Pin that the JSON parses, has
//!    `liveness == "running"`, and reports the kernel's PID. This
//!    exercises the CLI ⇄ heartbeat ⇄ kernel.db path that landed in
//!    Phase B/X1/X2; any drift in the heartbeat schema or in
//!    `raxis_store::open_ro` would surface here.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use raxis_audit_tools::{verify_chain_full, ChainReader};
use raxis_ipc::{read_frame, write_frame, IpcMessage};
use raxis_runtime::{read as read_heartbeat, KernelLifecycleState};
use raxis_types::{IntentKind, IntentRequest, TaskId};
use tokio::net::UnixStream;
use uuid::Uuid;

use common::kernel_harness::KernelInstance;

const READY_DEADLINE:    Duration = Duration::from_secs(10);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

const FAKE_TOKEN: &str =
    "deadbeefcafebabefeedfacefadedfeed1122334455667788abcd1234efef0011";

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

/// Build one `IntentRequest` whose only purpose is to make the kernel
/// emit one audit row through the rejection path. We don't need the
/// happy path here — every reject also writes an audit record, and
/// "audit row appears" is the only thing this file's test cares about.
fn build_bogus_intent(seq: u64) -> IntentRequest {
    let nonce = format!("{:032x}", u128::from(seq).wrapping_add(0xc0de_d00d));
    IntentRequest {
        session_token:    FAKE_TOKEN.to_owned(),
        sequence_number:  seq,
        envelope_nonce:   nonce,
        intent_kind:      IntentKind::SingleCommit,
        task_id:          TaskId::parse(
            &format!("e2e-task-{}", Uuid::new_v4().simple()),
        )
        .expect("synthesized TaskId"),
        base_sha:         None,
        head_sha:         None,
        submitted_claims: vec![],
        justification:    None,
        idempotency_key:  None,
        approval_token:   None,
        approved:         None,
        critique:         None,
        resolved_via_escalation: None,
        tokens_used:      None,
    }
}

/// Open the planner UDS, fire one bogus IntentRequest, and read one
/// reply frame. Drops the connection. Used by tests that want to
/// generate audit-row activity without caring about the response.
async fn fire_one_intent(socket_path: &std::path::Path, seq: u64) {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .expect("connect to planner.sock");
    let req = IpcMessage::IntentRequest(build_bogus_intent(seq));
    write_frame(&mut stream, &req)
        .await
        .expect("write intent frame");
    let _reply: IpcMessage = read_frame(&mut stream)
        .await
        .expect("read intent reply");
}

/// Locate the `raxis` CLI binary built by Cargo for this test.
///
/// We deliberately do NOT shell out to `cargo build -p raxis-cli` from
/// inside the test, because that recursive cargo invocation contends
/// with the parent `cargo test --workspace` build lock and can wedge
/// the entire workspace test run for tens of minutes (observed in
/// practice for `gateway/tests/gateway_roundtrip.rs` and
/// `kernel/tests/common/kernel_harness.rs` before P1-A landed).
///
/// Cargo's `CARGO_BIN_EXE_<name>` env var is only set for binaries in
/// the *same* crate as the integration test, so we cannot use it to
/// reach the `raxis` binary from inside the kernel crate's tests.
/// Instead we derive the path from `current_exe()`: integration test
/// binaries always live under `<target>/<profile>/deps/<test-name>`,
/// so `<target>/<profile>/raxis` is the sibling we need.
///
/// `cargo test --workspace` builds every workspace binary before
/// launching test binaries, so the path lookup is race-free in CI.
/// For local single-package iteration (`cargo test -p raxis-kernel`),
/// the panic below carries an actionable hint.
fn build_and_locate_cli() -> PathBuf {
    let exe = std::env::current_exe().expect("test binary current_exe");
    let target_profile_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("test binary is at <target>/<profile>/deps/<name>");
    let bin = target_profile_dir.join("raxis");
    assert!(
        bin.exists(),
        "raxis CLI binary not found at {} — run `cargo build -p raxis-cli` first \
         (or use `cargo test --workspace`, which builds every binary before \
         launching test binaries)",
        bin.display(),
    );
    bin
}

// ────────────────────────────────────────────────────────────────────
// Test 1 — heartbeat is fresh and well-formed during runtime
// ────────────────────────────────────────────────────────────────────

/// Pin cli-readonly.md §5.2 (heartbeat writer). After "sockets bound"
/// is reported, the kernel must have written `runtime/heartbeat.json`
/// AT LEAST once and the file must:
///
///   * deserialise into the canonical `Snapshot`,
///   * report the kernel's PID,
///   * report state `Running`,
///   * report `last_heartbeat_at` within the staleness threshold of
///     "now" (i.e. is_live() returns true).
///
/// We give the kernel a small extra grace window to actually write
/// the first heartbeat; the writer is on a periodic tick (currently
/// 1s) and "sockets bound" only proves the listeners are up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heartbeat_is_fresh_and_well_formed_after_boot() {
    let mut kernel = KernelInstance::bootstrap_and_spawn();
    kernel.wait_until_ready_or_panic(READY_DEADLINE);

    // Allow up to 5 seconds for the first heartbeat to land. Polling
    // every 100ms keeps the test fast on a warm machine but tolerant
    // of CI load.
    let data_dir = kernel.data_dir().to_owned();
    let snapshot = poll_for_heartbeat(&data_dir, Duration::from_secs(5))
        .unwrap_or_else(|| {
            panic!(
                "heartbeat.json never appeared; kernel stderr:\n{}",
                kernel.captured_stderr()
            )
        });

    assert_eq!(
        snapshot.kernel_pid as i32, kernel.pid(),
        "heartbeat must report the kernel's actual PID"
    );
    assert_eq!(
        snapshot.state,
        KernelLifecycleState::Running.as_str(),
        "kernel state must be Running after sockets bound"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        snapshot.is_live(now),
        "heartbeat must be is_live() at boot time; \
         last_heartbeat_at={}, now={now}",
        snapshot.last_heartbeat_at,
    );

    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(status.success(), "kernel must exit cleanly");
}

fn poll_for_heartbeat(
    data_dir: &std::path::Path,
    deadline: Duration,
) -> Option<raxis_runtime::Snapshot> {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if let Ok(snap) = read_heartbeat(data_dir) {
            return Some(snap);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

// ────────────────────────────────────────────────────────────────────
// Test 2 — audit chain monotonicity survives a restart (T0.5)
// ────────────────────────────────────────────────────────────────────

/// The hardest invariant in v1: a kernel restart MUST resume the
/// audit chain rather than reset `starting_seq` to 0. Any regression
/// here would surface at the next `recovery::verify_audit_chain` call
/// as a fail-closed boot.
///
/// Test plan:
///
///   1. Bootstrap data_dir; spawn kernel; wait for ready.
///   2. Drive 3 bogus IntentRequests on the planner socket. Each
///      rejection emits at least one audit row, so the chain grows.
///   3. SIGTERM; assert clean exit.
///   4. Spawn AGAIN against the same data_dir (manually — the
///      harness owns the original tempdir).
///   5. Drive 2 more bogus intents.
///   6. SIGTERM again.
///   7. Walk the resulting `audit/segment-000.jsonl` with
///      `ChainReader::open` + `verify_full` and assert the chain is
///      intact across the entire range, including the boundary
///      between the two boots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_chain_resumes_monotonically_across_restart() {
    let mut kernel = KernelInstance::bootstrap_and_spawn();
    kernel.wait_until_ready_or_panic(READY_DEADLINE);

    let data_dir = kernel.data_dir().to_owned();
    let planner = kernel.planner_socket();

    // ── Boot 1 ───────────────────────────────────────────────────────
    for seq in 1..=3 {
        fire_one_intent(&planner, seq).await;
    }
    let status1 = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(status1.success(), "boot 1 must exit cleanly");

    // Capture the highest-seq value at the boot-1 boundary so we can
    // assert on monotonicity across the boundary explicitly later.
    let mid_chain = walk_chain_or_panic(&data_dir);
    let boot1_max_seq = mid_chain.last().map(|r| r.seq).unwrap_or(0);
    assert!(
        boot1_max_seq > 0,
        "after boot 1 + traffic, audit chain must contain at least one row"
    );

    // ── Boot 2 — re-spawn against the SAME data dir ───────────────
    let kernel2 = respawn_kernel_against(&data_dir);
    let mut kernel2 = kernel2;
    kernel2.wait_until_ready_or_panic(READY_DEADLINE);

    for seq in 1..=2 {
        fire_one_intent(&planner, seq).await;
    }
    let status2 = kernel2.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(status2.success(), "boot 2 must exit cleanly");

    // ── Final chain walk ─────────────────────────────────────────────
    let final_chain = walk_chain_or_panic(&data_dir);
    assert!(
        final_chain.len() > mid_chain.len(),
        "boot 2 must have appended at least one new audit row \
         (mid={}, final={})",
        mid_chain.len(),
        final_chain.len(),
    );

    // The chain reader's verify_full would already have caught any
    // gap or prev_sha256 break, but we ALSO assert the boot boundary
    // is monotonic by hand so a future regression in the chain
    // walker doesn't silently mask a kernel-side reset.
    let across_boundary = final_chain
        .iter()
        .find(|r| r.seq == boot1_max_seq + 1);
    assert!(
        across_boundary.is_some(),
        "boot 2's first row must have seq = boot1_max_seq + 1 = {}; \
         final chain seqs: {:?}",
        boot1_max_seq + 1,
        final_chain.iter().map(|r| r.seq).collect::<Vec<_>>(),
    );
}

/// Walk `<data_dir>/audit/` with the full chain verifier (sequence
/// monotonicity + prev_sha256 link integrity end-to-end), then enumerate
/// every record so callers can also assert on the boundary `seq` value.
/// Panics with a friendly diagnostic on any chain break.
fn walk_chain_or_panic(
    data_dir: &std::path::Path,
) -> Vec<raxis_audit_tools::ChainRecord> {
    let audit_dir = data_dir.join("audit");
    verify_chain_full(&audit_dir)
        .unwrap_or_else(|e| panic!("verify_chain_full({audit_dir:?}) failed: {e:?}"));
    let reader = ChainReader::open(&audit_dir).unwrap_or_else(|e| {
        panic!("ChainReader::open({audit_dir:?}) failed: {e:?}")
    });
    reader
        .records()
        .map(|r| r.unwrap_or_else(|e| panic!("chain record decode failed: {e:?}")))
        .collect()
}

/// Spawn a fresh `raxis-kernel` subprocess against an existing
/// `data_dir` (already-bootstrapped). This is the manual equivalent
/// of `KernelInstance::bootstrap_and_spawn` for the case where
/// bootstrap has already run — we cannot call the latter twice
/// because each call creates a new TempDir.
fn respawn_kernel_against(data_dir: &std::path::Path) -> KernelInstance {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};

    let _build_lock = common::kernel_harness::acquire_test_lock();
    let kernel_bin = common::kernel_harness::build_and_locate_kernel();

    let mut child = Command::new(&kernel_bin)
        .env("RAXIS_DATA_DIR", data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("re-spawn kernel against existing data dir");

    let stderr = child.stderr.take().expect("kernel stderr");
    let stderr_lines = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let lines = Arc::clone(&stderr_lines);
        std::thread::spawn(move || {
            let r = BufReader::new(stderr);
            for line in r.lines().map_while(Result::ok) {
                lines.lock().unwrap().push(line);
            }
        });
    }

    KernelInstance::from_parts(child, stderr_lines, data_dir.to_owned())
}

// ────────────────────────────────────────────────────────────────────
// Test 3 — `raxis status --json` works against a live kernel
// ────────────────────────────────────────────────────────────────────

/// Pins the CLI ⇄ heartbeat ⇄ kernel.db read path landed in
/// Phases X1/X2. We boot a real kernel, run `raxis status --json`
/// pointing at the SAME data dir (via `RAXIS_DATA_DIR`), parse the
/// stdout JSON, and assert:
///
///   * exit code 0 (live);
///   * `liveness.state == "running"`;
///   * `liveness.kernel_pid == kernel.pid()`.
///
/// If `raxis_store::open_ro`'s schema-pin check or the heartbeat
/// schema drift, this is the test that catches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raxis_status_json_against_live_kernel_reports_running() {
    let mut kernel = KernelInstance::bootstrap_and_spawn();
    kernel.wait_until_ready_or_panic(READY_DEADLINE);

    // Wait for the first heartbeat so `raxis status` doesn't see a
    // missing-heartbeat condition.
    poll_for_heartbeat(kernel.data_dir(), Duration::from_secs(5))
        .expect("heartbeat must land before raxis status runs");

    let cli = build_and_locate_cli();
    let output = std::process::Command::new(&cli)
        .env("RAXIS_DATA_DIR", kernel.data_dir())
        .args(["status", "--json"])
        .output()
        .expect("spawn raxis status");

    assert!(
        output.status.success(),
        "raxis status should exit 0 against a healthy kernel; \
         exit={:?}, stdout={}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
            panic!(
                "raxis status --json must emit valid JSON: {e}; raw stdout:\n{}",
                String::from_utf8_lossy(&output.stdout),
            )
        });

    // The status JSON shape (cli/src/commands/status.rs):
    //
    //   { "liveness": "Running",
    //     "heartbeat": { "kernel_pid": <int>, "state": "Running", ... },
    //     ... }
    let liveness = json
        .get("liveness")
        .and_then(|s| s.as_str())
        .expect("status JSON must have a top-level `liveness` string");
    assert_eq!(
        liveness, "Running",
        "expected liveness=Running, got {liveness:?}; full status:\n{json:#}"
    );

    let reported_pid = json
        .get("heartbeat")
        .and_then(|hb| hb.get("kernel_pid"))
        .and_then(|n| n.as_i64())
        .expect("status JSON must include heartbeat.kernel_pid");
    assert_eq!(
        reported_pid as i32,
        kernel.pid(),
        "raxis status must report the kernel's PID"
    );

    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(status.success(), "kernel must exit cleanly");
}
