//! End-to-end kernel harness — build, bootstrap, spawn, observe, signal, reap.
//!
//! Used by integration tests that need to drive the *real* `raxis-kernel`
//! binary over its UDS sockets, not a tokio-duplex stand-in. The harness
//! exists for two reasons that the duplex-based smoke tests cannot cover:
//!
//!   1. **Socket binding contract** — `kernel-core.md` §2.2 step 7 promises
//!      that `<data_dir>/sockets/{operator,planner,gateway}.sock` exist with
//!      the documented mode bits after "sockets bound" appears in stderr.
//!      The only way to pin that contract is to spawn the binary, wait for
//!      the log line, and `connect()` to the path.
//!
//!   2. **Process lifecycle** — graceful shutdown, signal handling, and
//!      crash-resilience invariants live in the kernel binary's `main.rs`
//!      and `bootstrap.rs`. Running the binary as a subprocess is the only
//!      way to exercise them.
//!
//! ## Lifetime / cleanup contract
//!
//! `KernelInstance` owns both the spawned `Child` and the `TempDir` backing
//! `<data_dir>`. On `Drop`:
//!   - if the kernel is still alive, `SIGKILL` is sent and we `wait()` the
//!     child. We use `SIGKILL` rather than `SIGTERM` because Drop is the
//!     panic / unwind path; we do not want a buggy Drop to block.
//!   - the `TempDir` is removed.
//!
//! Tests that want to exercise *graceful* shutdown call
//! `KernelInstance::shutdown_with(libc::SIGTERM)` BEFORE drop and assert on
//! the resulting exit status / audit segment. The Drop fallback is the
//! safety net for panicking tests, not the happy path.
//!
//! ## Test serialisation
//!
//! Multiple integration tests in the same binary run in parallel by default.
//! `cargo build` is internally serialised but `cargo test`'s test-runner is
//! not. Each kernel spawn opens its own `TempDir` so socket paths never
//! collide, BUT every test still races on `cargo build -p raxis-kernel`
//! resolution — we acquire `TEST_LOCK` once at the start of each spawn so at
//! most one build + one bootstrap runs at a time within a test binary. The
//! lock is poison-tolerant; a panicked previous test does not poison the
//! whole file.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use raxis_test_support::{ephemeral_cert_with_key, CertOpts};

// ---------------------------------------------------------------------------
// File-scope serialisation
// ---------------------------------------------------------------------------

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Take the file-scope serialisation lock, recovering from a previous test's
/// panic so we don't fail every subsequent test in the binary with a
/// `PoisonError`. We share no state through this mutex — it is purely a
/// "run my kernel-build/bootstrap step alone" token.
pub fn acquire_test_lock() -> MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

// ---------------------------------------------------------------------------
// Build + bootstrap helpers
// ---------------------------------------------------------------------------

/// Locate the `raxis-kernel` binary built by Cargo for this test.
///
/// We rely on `CARGO_BIN_EXE_raxis-kernel`, which Cargo defines for
/// integration tests inside the same crate as the binary
/// (https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates).
///
/// We deliberately do NOT shell out to `cargo build -p raxis-kernel` from
/// inside the test, because that recursive cargo invocation contends with
/// the parent `cargo test --workspace` build lock and can wedge the entire
/// workspace test run for tens of minutes (observed in practice). Cargo
/// always builds every binary that integration tests depend on before
/// launching the test binary, so the env-var lookup is sufficient and
/// race-free.
///
/// The function is named `build_and_locate_kernel` for backward
/// compatibility with existing call sites; the "build" portion is now
/// performed by Cargo itself before this function is reached.
pub fn build_and_locate_kernel() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_raxis-kernel"))
}

/// Mint a deterministic, self-signed operator cert and write the TOML
/// body to `<dir>/operator.cert.toml`.
///
/// The kernel reads this in bootstrap mode (`bootstrap::BootstrapConfig::
/// operator_cert_path`, threaded through the `RAXIS_OPERATOR_CERT` env
/// var). We use a fixed seed so failures reproduce byte-identically; this
/// key is never used for anything that touches the outside world.
///
/// Cert-mandatory (INV-CERT-01): the harness no longer writes a
/// pubkey-only file because the kernel no longer accepts one.
fn write_operator_cert(dir: &Path) -> PathBuf {
    let key = SigningKey::from_bytes(&[0xA5u8; 32]);
    let cert = ephemeral_cert_with_key(
        &key,
        CertOpts {
            // Same fixed `now` every harness run produces ⇒ same cert
            // bytes, which keeps integration-test fixtures byte-stable.
            now_unix_secs: 1_700_000_000,
            ..CertOpts::default()
        },
    );
    let path = dir.join("operator.cert.toml");
    let toml_body = toml::to_string(&cert).expect("serialise cert");
    std::fs::write(&path, toml_body).expect("write operator cert toml");
    path
}

/// Bootstrap a fresh data dir by running `RAXIS_BOOTSTRAP=1 raxis-kernel`.
/// Returns a `TempDir` owning the data dir. Panics on any error so the
/// failure is loud and actionable.
///
/// `#[allow(dead_code)]`: Cargo runs dead-code analysis per integration
/// test binary. Some binaries (e.g. `full_e2e_session_lifecycle`) drive
/// the kernel through the live-e2e harness which provisions its own
/// `RAXIS_INSTALL_DIR`-backed data directory and never calls into this
/// helper. Other binaries (e.g. `worktree_staging_substrate`) DO use it
/// transitively through `bootstrap_and_spawn`. The suppression keeps a
/// shared harness function genuinely shared without forcing every
/// binary to import it.
#[allow(dead_code)]
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

    // Sanity: the artefacts the next phase relies on.
    assert!(
        data_dir.join("policy/policy.toml").exists(),
        "policy.toml missing after bootstrap"
    );
    assert!(
        data_dir.join("audit/segment-000.jsonl").exists(),
        "audit segment missing after bootstrap"
    );

    tmp
}

// ---------------------------------------------------------------------------
// KernelInstance — owning handle to a running kernel
// ---------------------------------------------------------------------------

/// A spawned kernel subprocess plus the `TempDir` backing its data dir.
///
/// All lifetime concerns live here:
///   - the `TempDir` is held by `_data_dir` so the directory survives until
///     after the kernel exits and we have read its audit segment.
///   - the `Child` is held by `child` and reaped on `Drop` (with `SIGKILL`
///     fallback if the test forgot to `shutdown_with`).
///
/// Stderr is tee'd into `stderr_lines` by a background thread so that
/// `wait_for_ready` and post-mortem assertions can grep without contending
/// with the child's pipe buffer.
pub struct KernelInstance {
    child: Child,
    stderr_lines: Arc<Mutex<Vec<String>>>,
    data_dir: PathBuf,
    /// Owns the `<data_dir>` lifetime. Dropping this removes the directory.
    /// Held in an `Option` so the explicit `into_data_dir()` consumer can
    /// reclaim ownership for tests that want to inspect the directory after
    /// the kernel has exited (e.g. read the audit segment).
    _data_dir: Option<tempfile::TempDir>,
}

impl KernelInstance {
    /// Build the binary, bootstrap a fresh data dir, and spawn the kernel in
    /// normal (non-bootstrap) mode. Blocks until the process is launched but
    /// does NOT wait for it to be ready — call `wait_for_ready()` for that.
    ///
    /// This is the single entry point for end-to-end tests: it captures the
    /// full bootstrap-then-run dance and the kernel binary's lifetime in
    /// one RAII handle.
    ///
    /// `#[allow(dead_code)]`: see `bootstrap_data_dir` — per-binary dead
    /// code analysis flags this as unused for binaries that never invoke
    /// the harness's bootstrap path (e.g. `full_e2e_session_lifecycle`,
    /// which uses the live-e2e harness instead).
    #[allow(dead_code)]
    pub fn bootstrap_and_spawn() -> Self {
        let _build_lock = acquire_test_lock();
        let kernel_bin = build_and_locate_kernel();
        let tempdir = bootstrap_data_dir(&kernel_bin);
        let data_dir = tempdir.path().to_owned();

        let mut child = Command::new(&kernel_bin)
            .env("RAXIS_DATA_DIR", &data_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn kernel in normal mode");

        let stderr = child.stderr.take().expect("kernel stderr captured");
        let stderr_lines = Arc::new(Mutex::new(Vec::<String>::new()));
        {
            let lines = Arc::clone(&stderr_lines);
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    match line {
                        Ok(l) => lines.lock().unwrap().push(l),
                        Err(_) => break,
                    }
                }
            });
        }

        Self {
            child,
            stderr_lines,
            data_dir,
            _data_dir: Some(tempdir),
        }
    }

    /// Construct a `KernelInstance` directly from a spawned child + its
    /// stderr-capture sink + the data dir it's running against. Used by
    /// integration tests that need to spawn a SECOND kernel against an
    /// already-bootstrapped data dir (e.g. cross-restart audit-chain
    /// tests). The data_dir is owned by the original instance and is
    /// NOT recreated here — this constructor takes a borrow-free
    /// `PathBuf` and does NOT take ownership of any TempDir, so the
    /// caller is responsible for keeping the original instance alive
    /// long enough for the directory to outlive both kernels.
    ///
    /// `#[allow(dead_code)]` because not every integration-test binary
    /// uses this entry point, but the harness is shared across all of
    /// them and unused-fn lints are per-binary.
    #[allow(dead_code)]
    pub fn from_parts(
        child: std::process::Child,
        stderr_lines: Arc<Mutex<Vec<String>>>,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            child,
            stderr_lines,
            data_dir,
            _data_dir: None,
        }
    }

    /// Subprocess PID (cast to `i32` for `libc::kill`).
    pub fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    /// Absolute path to `<data_dir>` for callers that want to read the audit
    /// segment, point a UnixStream at `sockets/planner.sock`, etc.
    ///
    /// `#[allow(dead_code)]`: Cargo runs dead-code analysis per integration
    /// test binary. This method is part of the harness's intended public
    /// surface but the current test binary only goes through the typed
    /// `planner_socket()` / `operator_socket()` helpers; we keep the
    /// general accessor available for future tests that need to grep the
    /// audit segment or read `policy.toml` directly.
    #[allow(dead_code)]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Convenience: full path to `<data_dir>/sockets/planner.sock`.
    ///
    /// `#[allow(dead_code)]`: see `bootstrap_data_dir`.
    #[allow(dead_code)]
    pub fn planner_socket(&self) -> PathBuf {
        self.data_dir.join("sockets").join("planner.sock")
    }

    /// Convenience: full path to `<data_dir>/sockets/operator.sock`.
    #[allow(dead_code)]
    pub fn operator_socket(&self) -> PathBuf {
        self.data_dir.join("sockets").join("operator.sock")
    }

    /// Block (busy-poll) until "sockets bound" appears in stderr, or until
    /// `deadline` elapses. The kernel logs this line at the end of step 7,
    /// the moment all three UDS sockets are bound and accept loops are
    /// running — the earliest moment a test can `connect()`.
    ///
    /// **Wire-shape note:** the kernel's structured-logging refactor
    /// emits `{"event":"sockets_bound", "module":"ipc.server", ...}`
    /// rather than the pre-refactor `{"message":"sockets bound"}`
    /// shape. This matcher accepts the current shape; it is the
    /// canonical "kernel ready" signal per `kernel/src/ipc/server.rs::server_log::sockets_bound`.
    pub fn wait_for_ready(&self, deadline: Duration) -> bool {
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

    /// Block until the `sockets_bound` event appears or panic with the
    /// captured stderr. Most tests want this (they cannot proceed
    /// without a bound socket); the generic `wait_for_ready` is
    /// exposed for the rare test that wants to assert the *negative*
    /// (e.g. degraded boot path).
    pub fn wait_until_ready_or_panic(&self, deadline: Duration) {
        if !self.wait_for_ready(deadline) {
            panic!(
                "kernel never reported 'sockets_bound' within {deadline:?}; stderr:\n{}",
                self.captured_stderr()
            );
        }
    }

    /// Send a POSIX signal to the kernel via `libc::kill`. Used by the
    /// signal-shutdown tests for SIGTERM/SIGINT and by the safety-net
    /// `Drop` impl for SIGKILL.
    pub fn send_signal(&self, signum: libc::c_int) {
        let pid = self.pid();
        // SAFETY: `pid` came from a child we spawned; it is alive and uniquely
        // ours for the lifetime of `&self`. `signum` is a libc constant.
        // `kill(2)` is async-signal-safe.
        let rc = unsafe { libc::kill(pid, signum) };
        assert!(rc == 0, "kill({pid}, {signum}) returned {rc}");
    }

    /// Wait up to `deadline` for the child to exit. Panics on timeout
    /// (after killing the child so the test process doesn't leak it).
    pub fn wait_with_timeout(&mut self, deadline: Duration) -> std::process::ExitStatus {
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
                            self.captured_stderr(),
                        );
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("try_wait failed: {e}"),
            }
        }
    }

    /// Send `signum` and wait up to `deadline` for the kernel to exit
    /// gracefully. Returns the process exit status. Used by tests that want
    /// to drive the graceful-shutdown audit path explicitly.
    pub fn shutdown_with(
        &mut self,
        signum: libc::c_int,
        deadline: Duration,
    ) -> std::process::ExitStatus {
        self.send_signal(signum);
        self.wait_with_timeout(deadline)
    }

    /// Snapshot the captured stderr as a single newline-joined string.
    /// Use sparingly — pulls a copy of every line under the mutex.
    pub fn captured_stderr(&self) -> String {
        self.stderr_lines.lock().unwrap().join("\n")
    }
}

impl Drop for KernelInstance {
    fn drop(&mut self) {
        // If the test forgot to shutdown_with (or panicked on the way), the
        // child is still running. Kill -9 it so the test binary doesn't hang
        // waiting for the OS to reap an orphan. We do not try a graceful
        // SIGTERM here because Drop runs on the panic path and we cannot
        // afford to block on a misbehaving child.
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
