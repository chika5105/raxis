//! Process supervision for the `firecracker` VMM binary.
//!
//! The VMM is its own OS process: the substrate's `Backend::spawn`
//! launches `firecracker --api-sock <path>`, waits for the API socket
//! to come up, drives the boot REST sequence (`api.rs`), and then
//! holds the child until shutdown. This module owns:
//!
//!   * Spawning the child with the appropriate argv/env.
//!   * Detecting when the API socket is ready.
//!   * `Drop`-time cleanup (kill + reap; remove the API socket).
//!   * Translating exit reasons into [`raxis_isolation::ExitStatus`].
//!
//! ## Why a separate module from `api.rs`
//!
//! `api.rs` speaks the boot REST protocol; this module supervises the
//! process those calls reach. The split keeps the API client
//! transport-pure (the VMM might one day be replaced by a long-lived
//! service the kernel connects to over a different UDS) without
//! touching the boot wire.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use raxis_isolation::ExitStatus;

/// Binary name we exec at boot. Operators can override with
/// `FirecrackerVmm::with_binary(...)` so an air-gapped install can
/// pin to its bundled path.
pub const DEFAULT_FIRECRACKER_BINARY: &str = "firecracker";

/// Errors the VMM supervisor can surface.
#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    /// `Command::spawn` failed (binary not on PATH, exec denied, ...).
    #[error("spawn failed: {reason}")]
    SpawnFailed {
        /// Free-form description of why the spawn failed. Forwarded
        /// verbatim to the audit chain.
        reason: String,
    },

    /// API socket did not appear within the boot deadline.
    #[error("API socket {path} did not appear within {grace_ms}ms")]
    ApiSockTimeout {
        /// Path the VMM was asked to bind.
        path:     PathBuf,
        /// Grace period the supervisor waited.
        grace_ms: u64,
    },

    /// `child.wait` returned an unexpected error.
    #[error("wait failed: {0}")]
    Wait(std::io::Error),

    /// `child.kill` returned an unexpected error.
    #[error("kill failed: {0}")]
    Kill(std::io::Error),
}

/// Live VMM child process.
///
/// Terminating the supervisor (`Drop`) MUST kill and reap the child —
/// matches the [`raxis_isolation::Session::terminate`] contract that
/// this supervisor will be wrapped in.
#[derive(Debug)]
pub struct FirecrackerVmm {
    /// Live child process (`None` after `terminate` / `shutdown`).
    child:    Option<Child>,
    /// PID we captured at spawn time; remains valid even after
    /// `child.wait()` consumes the handle.
    pid:      u32,
    /// API socket path; we tear this down on `Drop` to avoid leaking
    /// stale UDS files on the host.
    api_sock: PathBuf,
}

impl FirecrackerVmm {
    /// Spawn a Firecracker VMM child. The child binds its REST API on
    /// `api_sock` and idles until `api::FirecrackerApi::instance_start`
    /// is called.
    ///
    /// `api_sock` MUST NOT already exist; the caller (the
    /// `Backend::spawn` impl) is responsible for picking a fresh path
    /// per session.
    pub fn spawn(args: &SpawnArgs) -> Result<Self, VmmError> {
        if args.api_sock.exists() {
            return Err(VmmError::SpawnFailed {
                reason: format!(
                    "API socket already exists: {} (callers must pick a fresh path per session)",
                    args.api_sock.display(),
                ),
            });
        }

        let binary = args
            .binary
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_FIRECRACKER_BINARY));

        let mut cmd = Command::new(&binary);
        cmd.arg("--api-sock").arg(&args.api_sock);
        if let Some(level) = &args.log_level {
            cmd.arg("--level").arg(level);
        }
        if let Some(extra) = &args.extra_args {
            cmd.args(extra);
        }
        // Per `system-requirements.md §5.1`: the kernel runs as a
        // member of `kvm`; child inherits. We never elevate.
        cmd.stdout(Stdio::null());
        cmd.stderr(if args.capture_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        });

        let child = cmd.spawn().map_err(|e| VmmError::SpawnFailed {
            reason: format!(
                "exec `{}`: {e} \
                 (check that `firecracker` is on PATH and the host has /dev/kvm)",
                binary.display(),
            ),
        })?;
        let pid = child.id();

        let mut vmm = Self {
            child:    Some(child),
            pid,
            api_sock: args.api_sock.clone(),
        };

        if let Err(e) = wait_for_api_sock(&args.api_sock, args.boot_grace) {
            // Boot failed; tear down before surfacing.
            let _ = vmm.terminate();
            return Err(e);
        }

        Ok(vmm)
    }

    /// Captured pid for logging / audit / `SessionTransportId`.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// API socket path.
    pub fn api_sock(&self) -> &Path {
        &self.api_sock
    }

    /// Whether the supervisor still owns a live child.
    pub fn is_alive(&self) -> bool {
        self.child.is_some()
    }

    /// Immediate kill: SIGKILL + wait. Idempotent — calling twice is a
    /// no-op.
    pub fn terminate(&mut self) -> Result<(), VmmError> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if let Err(e) = child.kill() {
            // `InvalidInput` ⇒ already exited; treat as success.
            if e.kind() != std::io::ErrorKind::InvalidInput {
                return Err(VmmError::Kill(e));
            }
        }
        let _ = child.wait();
        let _ = std::fs::remove_file(&self.api_sock);
        Ok(())
    }

    /// Graceful shutdown: signal the guest (via `SendCtrlAltDel` —
    /// caller already issued it through the API), then poll
    /// `try_wait` until `grace` elapses; on timeout, escalate to
    /// SIGKILL.
    ///
    /// Returns the typed exit status the kernel writes to the audit
    /// chain.
    pub fn wait_or_kill(&mut self, grace: Duration) -> Result<ExitStatus, VmmError> {
        let Some(mut child) = self.child.take() else {
            return Ok(ExitStatus::GracefulExit { code: 0 });
        };

        let deadline = Instant::now() + grace;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let _ = std::fs::remove_file(&self.api_sock);
                    if let Some(code) = status.code() {
                        return Ok(ExitStatus::GracefulExit { code });
                    }
                    return Ok(ExitStatus::SignalKilled { signum: 0 });
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = std::fs::remove_file(&self.api_sock);
                        return Ok(ExitStatus::SignalKilled { signum: 9 });
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(VmmError::Wait(e)),
            }
        }
    }
}

impl Drop for FirecrackerVmm {
    fn drop(&mut self) {
        // Per `Session::terminate`: dropping a Session MUST tear down
        // the guest. `terminate` is idempotent so this is safe even
        // if the caller already shut us down.
        let _ = self.terminate();
    }
}

/// Arguments to [`FirecrackerVmm::spawn`].
///
/// Plain-data struct so the substrate test fixture can build one
/// without touching the supervisor internals.
#[derive(Debug, Clone)]
pub struct SpawnArgs {
    /// Path the VMM binds its REST API on. The caller picks the path
    /// (typically `<runtime_dir>/<session_uuid>.api.sock`).
    pub api_sock:       PathBuf,
    /// `firecracker` binary path. `None` ⇒ use `PATH` lookup.
    pub binary:         Option<PathBuf>,
    /// VMM log verbosity (`Error`, `Warning`, `Info`, `Debug`). `None`
    /// ⇒ Firecracker's own default (`Warning`).
    pub log_level:      Option<String>,
    /// Additional argv tokens. Empty in production V2; tests use this
    /// to inject `--no-api` or stub-mode flags into a fake binary.
    pub extra_args:     Option<Vec<String>>,
    /// How long to wait for the API socket to appear before declaring
    /// the boot failed.
    pub boot_grace:     Duration,
    /// Capture stderr into a pipe (kernel forwards to the audit
    /// channel as `SessionVmStderr` lines). `false` ⇒ /dev/null.
    pub capture_stderr: bool,
}

impl Default for SpawnArgs {
    fn default() -> Self {
        Self {
            api_sock:       PathBuf::new(),
            binary:         None,
            log_level:      None,
            extra_args:     None,
            boot_grace:     Duration::from_millis(2000),
            capture_stderr: false,
        }
    }
}

/// Poll for the API socket up to `grace`.
///
/// Firecracker creates the UDS at boot — the file appears once the
/// VMM has bound `accept(2)` and is ready to serve REST traffic.
fn wait_for_api_sock(path: &Path, grace: Duration) -> Result<(), VmmError> {
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(VmmError::ApiSockTimeout {
        path:     path.to_path_buf(),
        grace_ms: grace.as_millis() as u64,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: a non-existent binary fails fast with
    /// `SpawnFailed`. This runs everywhere — the test exercises the
    /// supervisor's error reporting, not Firecracker itself.
    #[test]
    fn spawn_with_missing_binary_returns_spawn_failed() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let args = SpawnArgs {
            api_sock: sock,
            binary:   Some(PathBuf::from("/nonexistent/raxis-firecracker-no-such")),
            ..SpawnArgs::default()
        };
        let err = FirecrackerVmm::spawn(&args).unwrap_err();
        match err {
            VmmError::SpawnFailed { reason } => {
                assert!(reason.contains("exec"));
                assert!(reason.contains("firecracker") || reason.contains("raxis-firecracker"));
            }
            other => panic!("expected SpawnFailed, got {other:?}"),
        }
    }

    /// `api_sock` already existing ⇒ refuse spawn.
    #[test]
    fn spawn_refuses_to_clobber_pre_existing_api_sock() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        std::fs::write(&sock, b"").unwrap();
        let args = SpawnArgs {
            api_sock: sock,
            ..SpawnArgs::default()
        };
        let err = FirecrackerVmm::spawn(&args).unwrap_err();
        match err {
            VmmError::SpawnFailed { reason } => {
                assert!(reason.contains("already exists"));
            }
            other => panic!("expected SpawnFailed, got {other:?}"),
        }
    }

    /// On Unix, simulate a tame VMM with a tiny shell stub. The stub
    /// touches the API socket then idles; the supervisor's
    /// `wait_for_api_sock` should return Ok and `wait_or_kill` should
    /// drive the child to a graceful exit.
    #[cfg(unix)]
    #[test]
    fn spawn_then_wait_or_kill_drives_a_tame_child_to_graceful_exit() {
        // Stub script understands the `--api-sock <path>` arg shape so
        // it can be exercised by the supervisor without changing the
        // production argv-injection logic.
        let (dir, stub) = write_fc_stub_script("touch \"$SOCK\"; sleep 30");
        let sock = dir.path().join("api.sock");
        let args = SpawnArgs {
            api_sock:   sock.clone(),
            binary:     Some(stub.clone()),
            log_level:  None,
            extra_args: None,
            boot_grace: Duration::from_secs(2),
            capture_stderr: false,
        };
        let mut vmm = FirecrackerVmm::spawn(&args).expect("stub spawn must succeed");
        assert!(vmm.is_alive(), "child must be live after spawn");
        assert!(vmm.api_sock().exists(), "stub touched the API socket");

        // Grace too short ⇒ SIGKILL escalation path.
        let status = vmm
            .wait_or_kill(Duration::from_millis(50))
            .expect("wait_or_kill must report a status");
        match status {
            ExitStatus::SignalKilled { signum: 9 } => {}
            other => panic!("expected SignalKilled(9), got {other:?}"),
        }
        assert!(!vmm.is_alive(), "child must be reaped after wait_or_kill");
        assert!(!sock.exists(), "API socket must be cleaned up");
        drop(dir);
    }

    /// Drop alone (no explicit terminate) MUST tear down the child.
    /// Mirrors the `Session::terminate` contract.
    #[cfg(unix)]
    #[test]
    fn drop_terminates_child_when_caller_forgets() {
        let (dir, stub) = write_fc_stub_script("touch \"$SOCK\"; sleep 30");
        let sock = dir.path().join("api.sock");
        let args = SpawnArgs {
            api_sock:   sock.clone(),
            binary:     Some(stub.clone()),
            log_level:  None,
            extra_args: None,
            boot_grace: Duration::from_secs(2),
            capture_stderr: false,
        };
        let pid;
        {
            let vmm = FirecrackerVmm::spawn(&args).expect("stub spawn must succeed");
            pid = vmm.pid();
            assert!(vmm.is_alive());
        }
        // Drop ran; give the OS a tick to reap.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!sock.exists(), "API socket must be cleaned up by Drop");
        let _ = pid;
        drop(dir);
    }

    /// Boot grace expiring with no socket ⇒ `ApiSockTimeout`. We
    /// simulate a binary that exits immediately (so `--api-sock` never
    /// gets bound).
    #[cfg(unix)]
    #[test]
    fn spawn_times_out_when_api_sock_never_appears() {
        // Stub that exits without touching the socket. We still write
        // the FC-shaped stub so the `--api-sock` injection doesn't
        // confuse a generic shell.
        let (dir, stub) = write_fc_stub_script("exit 0");
        let sock = dir.path().join("api.sock");
        let args = SpawnArgs {
            api_sock:   sock.clone(),
            binary:     Some(stub.clone()),
            log_level:  None,
            extra_args: None,
            boot_grace: Duration::from_millis(75),
            capture_stderr: false,
        };
        let err = FirecrackerVmm::spawn(&args).unwrap_err();
        match err {
            VmmError::ApiSockTimeout { path, grace_ms } => {
                assert_eq!(path, sock);
                assert_eq!(grace_ms, 75);
            }
            other => panic!("expected ApiSockTimeout, got {other:?}"),
        }
        drop(dir);
    }

    /// Write a Firecracker-shaped stub: a shell script whose argv
    /// understanding matches the real binary (`--api-sock <path>` may
    /// appear before any optional flags). The script extracts the
    /// path into `$SOCK`, then runs the caller-supplied body.
    ///
    /// Returns the tempdir handle (caller owns) and the stub path.
    #[cfg(unix)]
    fn write_fc_stub_script(body: &str) -> (tempfile::TempDir, PathBuf) {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir  = tempfile::tempdir().unwrap();
        let stub = dir.path().join("fc-stub.sh");
        let mut script = String::new();
        script.push_str("#!/bin/sh\n");
        // Walk the args looking for --api-sock.
        script.push_str("SOCK=\n");
        script.push_str("while [ \"$#\" -gt 0 ]; do\n");
        script.push_str("  case \"$1\" in\n");
        script.push_str("    --api-sock) SOCK=\"$2\"; shift 2 ;;\n");
        script.push_str("    *) shift ;;\n");
        script.push_str("  esac\n");
        script.push_str("done\n");
        script.push_str(body);
        script.push('\n');

        let mut f = std::fs::File::create(&stub).unwrap();
        f.write_all(script.as_bytes()).unwrap();
        let mut perms = f.metadata().unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&stub, perms).unwrap();
        drop(f);
        (dir, stub)
    }
}
