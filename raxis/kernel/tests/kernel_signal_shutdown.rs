//! End-to-end SIGTERM / SIGINT graceful shutdown test.
//!
//! Builds the kernel binary, bootstraps a fresh data dir, spawns the
//! kernel under tokio, waits for it to log "sockets bound", sends a real
//! POSIX signal, and asserts the post-conditions:
//!
//!   1. The kernel exits with code 0 within a 10-second deadline.
//!   2. The audit segment ends with `KernelStopped { reason }` whose
//!      `reason` matches the signal we sent ("SIGTERM" or "SIGINT").
//!   3. The three UDS socket files (`operator.sock`, `planner.sock`,
//!      `gateway.sock`) no longer exist after exit (cleanup contract).
//!
//! Together these pin the contract documented in `kernel-core.md` §2.2
//! step 9 sub-bullet "Signal handler registration: SIGTERM and SIGINT
//! both trigger graceful shutdown — drain the IPC handler queue, flush
//! pending audit writes, close the UDS socket, emit `KernelStopped`
//! audit event."
//!
//! Why an end-to-end test (and not a unit test of the signal future)?
//! Tokio's `signal::unix::signal` wires into the kernel's signalfd; you
//! cannot mock it without re-implementing the runtime. The only way to
//! exercise the actual code path operators rely on is to spawn the real
//! binary and `kill` it. Unit tests for the small pieces around the
//! signal future (`ShutdownReason::audit_reason`, `is_clean`) live in
//! `src/ipc/server.rs::shutdown_reason_tests`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

// Serialise these tests so they don't race over `cargo build` invocations
// or the (per-process) signal disposition. Each test gets its own
// TempDir so file-system isolation is fine, but the build helper below
// can race other tests in the binary if invoked in parallel.
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// `TEST_LOCK.lock()` that survives a poisoned mutex. If a previous test
/// panicked while holding the guard, `lock()` returns `Err(PoisonError)`;
/// every other test in the file would then fail with a non-deterministic
/// "PoisonError" instead of its real error. We don't share any state
/// across tests through the mutex (it's just a serialisation token), so
/// it is safe to recover the inner `()` and proceed.
fn acquire_test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Locate the `raxis-kernel` binary built by Cargo for this test.
///
/// We rely on `CARGO_BIN_EXE_raxis-kernel`, which Cargo defines for
/// integration tests inside the same crate as the binary
/// (https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates).
///
/// We deliberately do NOT shell out to `cargo build -p raxis-kernel`
/// from inside the test, because that recursive cargo invocation
/// contends with the parent `cargo test --workspace` build lock and
/// can wedge the entire workspace test run for tens of minutes
/// (observed in practice for `gateway_roundtrip.rs` and
/// `kernel_harness.rs` before P1-A landed). Cargo always builds every
/// binary that integration tests depend on before launching the test
/// binary, so the env-var lookup is sufficient and race-free.
///
/// The function name is preserved for backward compatibility with
/// existing call sites; the "build" portion is now performed by Cargo
/// itself before this function is reached.
fn build_and_locate_kernel() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_raxis-kernel"))
}

/// Mint a deterministic, self-signed operator cert and write its TOML
/// body to `<dir>/operator.cert.toml`, returning the file path. The
/// kernel's bootstrap reads this via the `RAXIS_OPERATOR_CERT` env var
/// (per `bootstrap::BootstrapConfig::operator_cert_path`).
///
/// We use a deterministic test seed rather than `OsRng`. The signal test
/// never re-uses the resulting key for anything that interacts with the
/// real world; it just needs *some* well-formed cert for the kernel's
/// genesis ceremony to accept. Determinism makes test failures
/// reproducible from the byte level.
fn write_operator_cert(dir: &Path) -> PathBuf {
    let signing = SigningKey::from_bytes(&[0xA5u8; 32]);
    let cert = raxis_test_support::ephemeral_cert_with_key(
        &signing,
        raxis_test_support::CertOpts {
            now_unix_secs: 1_700_000_000,
            ..raxis_test_support::CertOpts::default()
        },
    );
    let path = dir.join("operator.cert.toml");
    let toml_body = toml::to_string(&cert).expect("serialise cert");
    std::fs::write(&path, toml_body).expect("write operator cert toml");
    path
}

fn move_dashboard_to_ephemeral_port(data_dir: &Path) {
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("reserve ephemeral dashboard port")
        .local_addr()
        .expect("read ephemeral dashboard port")
        .port();
    let policy_path = data_dir.join("policy/policy.toml");
    let body = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", policy_path.display()));
    let updated = body.replacen(
        "bind_port    = 9820\n",
        &format!("bind_port    = {port}\n"),
        1,
    );
    assert_ne!(
        body,
        updated,
        "genesis dashboard bind_port shape changed in {}",
        policy_path.display()
    );
    std::fs::write(&policy_path, updated)
        .unwrap_or_else(|e| panic!("write {}: {e}", policy_path.display()));
}

/// Bootstrap a fresh data dir by running the kernel binary in
/// `RAXIS_BOOTSTRAP=1` mode. Returns the data dir on success.
fn bootstrap_data_dir(kernel_bin: &Path) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir for kernel data dir");
    let data_dir = tmp.path();
    let cert_path = write_operator_cert(data_dir);

    let output = Command::new(kernel_bin)
        .env("RAXIS_BOOTSTRAP", "1")
        .env("RAXIS_DATA_DIR", data_dir)
        .env("RAXIS_OPERATOR_CERT", &cert_path)
        .output()
        .expect("spawn kernel in bootstrap mode");

    assert!(
        output.status.success(),
        "kernel bootstrap failed (exit code {}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "<signalled>".to_owned()),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Sanity-check the bootstrap left the artifacts we need.
    assert!(
        data_dir.join("policy/policy.toml").exists(),
        "policy.toml missing after bootstrap"
    );
    assert!(
        data_dir.join("audit/segment-000.jsonl").exists(),
        "audit segment missing after bootstrap"
    );
    assert!(
        data_dir.join("keys/authority_keypair.pem").exists(),
        "authority key missing after bootstrap"
    );
    move_dashboard_to_ephemeral_port(data_dir);

    tmp
}

/// Spawn the kernel in normal (non-bootstrap) mode against the given
/// data dir. Streams stderr through a background thread that records
/// every line into a shared `Vec<String>`, and signals the test once
/// "sockets bound" appears.
struct KernelHandle {
    child: std::process::Child,
    stderr_lines: Arc<Mutex<Vec<String>>>,
    /// Stored for forensic context only — the test asserts on
    /// stderr lines, not on the data dir's contents — but we
    /// keep the path on the handle so future shutdown tests
    /// (V3 will add coverage for the kernel.db rollover ledger)
    /// have it without re-reading env vars.
    #[allow(dead_code)]
    data_dir: PathBuf,
}

impl KernelHandle {
    fn spawn(kernel_bin: &Path, data_dir: &Path) -> Self {
        let mut child = Command::new(kernel_bin)
            .env("RAXIS_DATA_DIR", data_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn kernel in normal mode");

        let stderr = child.stderr.take().expect("kernel stderr captured");
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));

        let lines_clone = Arc::clone(&lines);
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                match line {
                    Ok(l) => lines_clone.lock().unwrap().push(l),
                    Err(_) => break,
                }
            }
        });

        Self {
            child,
            stderr_lines: lines,
            data_dir: data_dir.to_owned(),
        }
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    /// Block until the kernel logs the `sockets_bound` event or
    /// `deadline` elapses. Returns true on observation, false on
    /// timeout.
    ///
    /// **Wire-shape note:** matches the post-refactor structured log
    /// shape `{"event":"sockets_bound", "module":"ipc.server", ...}`
    /// emitted by `ipc::server::server_log::sockets_bound`.
    fn wait_for_ready(&self, deadline: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if self
                .stderr_lines
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("\"event\":\"sockets_bound\""))
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn send_signal(&self, signum: libc::c_int) {
        let pid = self.pid();
        // SAFETY: `pid` is captured from a child we spawned above; it is
        // alive and uniquely ours for the lifetime of `self`. `signum`
        // is a constant from libc. `kill(2)` is async-signal-safe.
        let rc = unsafe { libc::kill(pid, signum) };
        assert!(
            rc == 0,
            "kill({pid}, {signum}) returned {rc}, errno set by libc"
        );
    }

    /// Wait up to `deadline` for the child to exit. Returns the exit
    /// status on observation, or panics on timeout (after killing the
    /// child so the test process doesn't leak it).
    fn wait_with_timeout(&mut self, deadline: Duration) -> std::process::ExitStatus {
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return status,
                Ok(None) => {
                    if start.elapsed() > deadline {
                        let _ = self.child.kill();
                        panic!(
                            "kernel did not exit within {:?}; stderr so far:\n{}",
                            deadline,
                            self.stderr_lines.lock().unwrap().join("\n"),
                        );
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("try_wait failed: {e}"),
            }
        }
    }

    fn captured_stderr(&self) -> String {
        self.stderr_lines.lock().unwrap().join("\n")
    }
}

/// Read the audit segment and return parsed records as `serde_json::Value`s.
fn read_audit_segment(data_dir: &Path) -> Vec<serde_json::Value> {
    let path = data_dir.join("audit/segment-000.jsonl");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read audit segment {path:?}: {e}"));
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("parse audit line {l:?}: {e}")))
        .collect()
}

// ---------------------------------------------------------------------------
// SIGTERM happy path
// ---------------------------------------------------------------------------

#[test]
fn sigterm_triggers_graceful_shutdown_and_kernel_stopped_audit() {
    let _guard = acquire_test_lock();
    let kernel_bin = build_and_locate_kernel();
    let data_dir = bootstrap_data_dir(&kernel_bin);

    let mut kernel = KernelHandle::spawn(&kernel_bin, data_dir.path());

    // Wait for the kernel to bind sockets — it is now in the dispatch loop.
    assert!(
        kernel.wait_for_ready(Duration::from_secs(10)),
        "kernel never reported 'sockets_bound' within 10s; stderr:\n{}",
        kernel.captured_stderr(),
    );

    // Deliver SIGTERM and wait for clean exit.
    kernel.send_signal(libc::SIGTERM);
    let status = kernel.wait_with_timeout(Duration::from_secs(10));
    assert!(
        status.success(),
        "kernel exited non-zero after SIGTERM (status: {:?}); stderr:\n{}",
        status,
        kernel.captured_stderr(),
    );

    // Audit segment must end with KernelStopped { reason: "SIGTERM" }.
    // Note on payload shape: `AuditEventKind` uses
    // `#[serde(tag = "kind", rename_all = "PascalCase")]`, so the wire
    // projection of `KernelStopped { reason }` is
    // `{ "kind": "KernelStopped", "reason": "SIGTERM" }` — flattened
    // under `payload`, NOT nested as `payload.KernelStopped.reason`.
    let records = read_audit_segment(data_dir.path());
    let last = records
        .last()
        .expect("audit segment must have at least one record after shutdown");
    assert_eq!(
        last["event_kind"].as_str(),
        Some("KernelStopped"),
        "last audit event must be KernelStopped; full last record: {last}"
    );
    assert_eq!(
        last["payload"]["kind"].as_str(),
        Some("KernelStopped"),
        "payload.kind discriminant must match event_kind; full last record: {last}"
    );
    let reason = last["payload"]["reason"]
        .as_str()
        .expect("KernelStopped record must have payload.reason");
    assert_eq!(
        reason, "SIGTERM",
        "KernelStopped reason should match the signal we sent; full last record: {last}"
    );

    // Cleanup contract: the three UDS socket files must be removed on exit.
    for name in &["operator.sock", "planner.sock", "gateway.sock"] {
        let p = data_dir.path().join("sockets").join(name);
        assert!(
            !p.exists(),
            "socket file {name} must be removed on graceful shutdown; still at {}",
            p.display()
        );
    }
}

// ---------------------------------------------------------------------------
// SIGINT (Ctrl-C) variant — same contract, different signal.
// ---------------------------------------------------------------------------

#[test]
fn sigint_also_triggers_graceful_shutdown_with_distinct_audit_reason() {
    let _guard = acquire_test_lock();
    let kernel_bin = build_and_locate_kernel();
    let data_dir = bootstrap_data_dir(&kernel_bin);

    let mut kernel = KernelHandle::spawn(&kernel_bin, data_dir.path());

    assert!(
        kernel.wait_for_ready(Duration::from_secs(10)),
        "kernel never reported 'sockets_bound' within 10s; stderr:\n{}",
        kernel.captured_stderr(),
    );

    kernel.send_signal(libc::SIGINT);
    let status = kernel.wait_with_timeout(Duration::from_secs(10));
    assert!(
        status.success(),
        "kernel exited non-zero after SIGINT (status: {:?}); stderr:\n{}",
        status,
        kernel.captured_stderr(),
    );

    let records = read_audit_segment(data_dir.path());
    let last = records.last().expect("audit segment must have last record");
    assert_eq!(last["event_kind"].as_str(), Some("KernelStopped"));
    let reason = last["payload"]["reason"].as_str().unwrap();
    assert_eq!(
        reason, "SIGINT",
        "the audit reason MUST distinguish SIGINT from SIGTERM so operators can grep"
    );
}

// ---------------------------------------------------------------------------
// Audit chain INTEGRITY across the shutdown: the KernelStopped record
// must chain correctly from KernelStarted (no gaps, prev_sha256 valid).
// This is the cross-cut between Phase A.1 (chain resume) and Phase A.2
// (graceful shutdown). The shutdown emit MUST go through the same
// AuditWriter that Phase A.1 set up; if it bypassed it (or skipped flush)
// the chain would silently break.
// ---------------------------------------------------------------------------

#[test]
fn audit_chain_intact_across_kernel_started_and_kernel_stopped() {
    let _guard = acquire_test_lock();
    let kernel_bin = build_and_locate_kernel();
    let data_dir = bootstrap_data_dir(&kernel_bin);

    let mut kernel = KernelHandle::spawn(&kernel_bin, data_dir.path());
    assert!(kernel.wait_for_ready(Duration::from_secs(10)));
    kernel.send_signal(libc::SIGTERM);
    let _ = kernel.wait_with_timeout(Duration::from_secs(10));

    // Re-scan via the resume function — this is exactly what the *next*
    // kernel boot would do. Any chain corruption here would cause
    // cross-restart fail-closed at the next boot.
    let segment = data_dir.path().join("audit/segment-000.jsonl");
    let resume =
        raxis_audit_tools::last_chain_state(&segment).expect("post-shutdown chain MUST be intact");
    let info = resume.expect("segment is non-empty after a clean run");

    // V2 fail-closed boot: the chain MUST contain
    //
    //   seq=0  GenesisRecord                    (written by bootstrap)
    //   seq=1  KernelStarted                    (step 8)
    //   seq=2  IsolationSubstrateSelected       (step 8c — V2 substrate)
    //   seq=3  IsolationFallbackBypass          (step 8c — only if the
    //                                            substrate self-reported
    //                                            FallbackOnly AND the
    //                                            operator passed
    //                                            `RAXIS_UNSAFE_FALLBACK_ISOLATION`)
    //   seq=N  KernelStopped                    (step 10)
    //
    // The previous "no substrate admissible → degraded boot"
    // shape is V2-removed: a kernel without an admissible
    // substrate exits with `BOOT_ERR_ISOLATION_UNAVAILABLE` (code
    // 64) and emits `IsolationSubstrateRefused` instead, so the
    // resulting chain never reaches `KernelStarted` at all.
    // Test hosts run on macOS (AVF) or Linux+KVM, both of which
    // admit; this assertion pins the V2 happy-path shape.
    let records = read_audit_segment(data_dir.path());
    let event_kinds: Vec<&str> = records
        .iter()
        .filter_map(|r| r["event_kind"].as_str())
        .collect();
    let valid_shapes: &[&[&str]] = &[
        // Substrate admitted (Linux+KVM or macOS); no fallback bypass.
        &[
            "GenesisRecord",
            "KernelStarted",
            "IsolationSubstrateSelected",
            "KernelStopped",
        ],
        // Substrate admitted under the unsafe-fallback flag.
        &[
            "GenesisRecord",
            "KernelStarted",
            "IsolationSubstrateSelected",
            "IsolationFallbackBypass",
            "KernelStopped",
        ],
    ];
    assert!(
        valid_shapes.iter().any(|shape| event_kinds == *shape),
        "event_kind sequence must match one of {valid_shapes:?}; got {event_kinds:?}",
    );
    assert_eq!(
        info.next_seq as usize,
        records.len(),
        "next_seq must match record count after a clean shutdown",
    );
}

// ---------------------------------------------------------------------------
// Restart cycle: shutdown, start again, shutdown again. Pins that Phase
// A.1's chain-resume + Phase A.2's clean shutdown compose correctly.
// Without resume, the second start would emit `KernelStarted` with seq=0
// + genesis prev_sha256, which `last_chain_state` would reject; the
// child would never even reach "sockets bound".
// ---------------------------------------------------------------------------

#[test]
fn kernel_can_restart_cleanly_and_chain_persists() {
    let _guard = acquire_test_lock();
    let kernel_bin = build_and_locate_kernel();
    let data_dir = bootstrap_data_dir(&kernel_bin);

    // Boot 1
    {
        let mut kernel = KernelHandle::spawn(&kernel_bin, data_dir.path());
        assert!(
            kernel.wait_for_ready(Duration::from_secs(10)),
            "first boot never bound sockets; stderr:\n{}",
            kernel.captured_stderr()
        );
        kernel.send_signal(libc::SIGTERM);
        let status = kernel.wait_with_timeout(Duration::from_secs(10));
        assert!(status.success(), "first boot exit non-zero: {status:?}");
    }

    // Boot 2 — this is the meaty assertion. If chain resume is broken,
    // the second boot will exit with BOOT_ERR_AUDIT_CHAIN.
    {
        let mut kernel = KernelHandle::spawn(&kernel_bin, data_dir.path());
        assert!(
            kernel.wait_for_ready(Duration::from_secs(10)),
            "second boot never bound sockets — likely chain-resume failure; stderr:\n{}",
            kernel.captured_stderr(),
        );
        kernel.send_signal(libc::SIGTERM);
        let status = kernel.wait_with_timeout(Duration::from_secs(10));
        assert!(status.success(), "second boot exit non-zero: {status:?}");
    }

    // Final chain shape (V2):
    //   seq=0  GenesisRecord
    //   seq=1  KernelStarted               (boot 1)
    //   seq=2  IsolationSubstrateSelected  (boot 1, optional — see below)
    //   seq=3  KernelStopped               (boot 1, SIGTERM)
    //   seq=4  KernelStarted               (boot 2)
    //   seq=5  IsolationSubstrateSelected  (boot 2, optional)
    //   seq=6  KernelStopped               (boot 2, SIGTERM)
    //
    // The `IsolationSubstrateSelected` row is present only on hosts
    // where `select_isolation_backend` admitted a substrate
    // (Linux+KVM or macOS); on hosts without an admissible substrate
    // the chain collapses to the v1 5-record shape. The test pins
    // the per-boot sub-shape so we catch substrate selection
    // regressions without making the whole test host-fragile.
    let records = read_audit_segment(data_dir.path());
    for (i, r) in records.iter().enumerate() {
        assert_eq!(
            r["seq"].as_u64().unwrap(),
            i as u64,
            "seq monotonicity must hold across restart boundary; record {i}: {r}"
        );
    }
    let kinds: Vec<&str> = records
        .iter()
        .filter_map(|r| r["event_kind"].as_str())
        .collect();

    // The two boots must produce identical sub-shapes (same admit
    // outcome each time).
    let valid_shapes: &[&[&str]] = &[
        // Substrate admitted on both boots.
        &[
            "GenesisRecord",
            "KernelStarted",
            "IsolationSubstrateSelected",
            "KernelStopped",
            "KernelStarted",
            "IsolationSubstrateSelected",
            "KernelStopped",
        ],
        // No substrate admissible on either boot.
        &[
            "GenesisRecord",
            "KernelStarted",
            "KernelStopped",
            "KernelStarted",
            "KernelStopped",
        ],
    ];
    assert!(
        valid_shapes.iter().any(|shape| kinds == *shape),
        "two-boot chain must match one of {valid_shapes:?}; got {kinds:?}",
    );
}
