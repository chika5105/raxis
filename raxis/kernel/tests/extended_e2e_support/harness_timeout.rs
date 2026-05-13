//! Bounded child-process wait helpers for the live-e2e harness.
//!
//! ## Why this module exists
//!
//! Every `seed_*` helper in [`super::service_evidence`] (and the
//! preflight / reseed helpers in [`super::seeds`]) shells out to a
//! database client (`psql` / `mongosh` / `redis-cli` / `mysql` /
//! `sqlcmd`) over a TCP socket against a docker-compose container.
//!
//! The historical implementation called
//! `std::process::Child::wait_with_output()` on those clients with
//! NO timeout. When the docker stack is not up — or the target
//! container is unhealthy — the client hangs in its own connect
//! retry loop, the harness's `wait_with_output()` blocks on the
//! pipe `read2 → poll`, and the entire test runner hangs
//! indefinitely (witnessed in iter 17 of the realistic-scenario
//! fix-loop: `seed_postgres` was the single thread, 0% CPU, no
//! progress, no AVF VMs spawned).
//!
//! The wrappers here close that hole. Every `seed_*` and
//! `verify_*` site routes its `Child::wait_*` through one of
//! these helpers and surfaces a typed [`BoundedWaitError`] on
//! timeout instead of hanging the test runner. The matching
//! [`super::service_evidence::ServiceEvidenceError::SeedTimedOut`]
//! variant lifts the harness-level timeout into the test-facing
//! failure taxonomy so the panic message names the seed AND the
//! target service URL.
//!
//! ## Invariant
//!
//! Spec parity:
//! [`raxis/specs/invariants.md`] — `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`:
//!
//! > Every external-process spawn in the live-e2e harness MUST be
//! > wrapped in a bounded timeout (30 s default for seeding, 5 s
//! > default for health probes). The harness MUST NOT contain any
//! > unbounded `Child::wait()`, `Child::wait_with_output()`, or
//! > pipe `read_to_end()` call. Witnessed by a regression test
//! > that spawns a `sleep 9999` child and asserts it is killed
//! > within `timeout + 5 s`.
//!
//! ## Implementation notes
//!
//! * `wait_with_output_timeout` drains stdout + stderr in
//!   background threads so a backed-up OS pipe buffer cannot pin
//!   the child after it has otherwise finished. Without this the
//!   `try_wait` loop would race a `WriteAll` blocked in the child
//!   against the kernel's pipe-buffer limit.
//! * On timeout we SIGKILL the child via `Child::kill()` and
//!   reap it via `Child::wait()` so the process table never grows
//!   a zombie — important for re-runs that share the same docker
//!   container set.
//! * The poll interval is 50 ms — long enough that the loop is
//!   essentially zero-cost on a 30 s seed, short enough that the
//!   wrapper returns within a handful of ms after the child
//!   exits cleanly.
//! * No new third-party crate dependency. The `wait-timeout`
//!   crate would be a clean fit, but pulling it in would expand
//!   the workspace dependency graph for a pattern we can express
//!   with `try_wait` + `thread::sleep` in ~40 lines.

#![allow(dead_code)]

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Default seeding timeout. The longest legitimate seed path is
/// the `mssql` one (sqlcmd cold-cache against a tmpfs-backed SQL
/// Server container); 30 s is a comfortable safety net for that
/// AND short enough that an operator notices a stuck call within
/// one coffee break.
pub const SEED_TIMEOUT: Duration = Duration::from_secs(30);

/// Default health-probe timeout. Pre-seed probes are expected to
/// complete in tens of milliseconds against a healthy container;
/// 5 s is a generous safety net.
pub const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default docker-compose probe / preflight timeout. `docker
/// compose ps` must complete fast on a quiet host, but on a
/// fully-saturated CI runner the daemon can take a few seconds
/// to settle; 30 s keeps the harness tolerant of that without
/// hiding a genuine hang.
pub const DOCKER_PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default docker-compose auto-bring-up timeout. `docker compose
/// up -d --wait` against the extended stack (`postgres`, `mongo`,
/// `redis`, `smtp`, `mysql`, `mssql`) needs minutes on a cold
/// machine that has to pull every image; 240 s covers the
/// healthcheck `start_period` totals plus a generous slack.
pub const DOCKER_BRINGUP_TIMEOUT: Duration = Duration::from_secs(240);

/// Failure modes for [`wait_with_output_timeout`] and friends.
#[derive(Debug)]
pub enum BoundedWaitError {
    /// `Command::spawn` failed (binary missing, exec EACCES, …).
    SpawnFailed { label: String, reason: String },

    /// The child did not exit within `timeout`. The wrapper has
    /// already SIGKILLed and reaped the child by the time this
    /// variant is constructed; the caller does not need to
    /// retain the [`Child`] handle for cleanup.
    Timeout { label: String, timeout: Duration },

    /// `try_wait` / `wait` returned an unexpected `io::Error`.
    /// Distinct from `Timeout` so a regression test can assert
    /// the timeout path was exercised rather than a generic
    /// kernel-side wait failure.
    WaitFailed { label: String, reason: String },
}

impl std::fmt::Display for BoundedWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpawnFailed { label, reason } => {
                write!(f, "[bounded-wait:{label}] spawn failed: {reason}")
            }
            Self::Timeout { label, timeout } => {
                write!(
                    f,
                    "[bounded-wait:{label}] child did not exit within {:?}; \
                     SIGKILLed",
                    timeout,
                )
            }
            Self::WaitFailed { label, reason } => {
                write!(f, "[bounded-wait:{label}] wait failed: {reason}")
            }
        }
    }
}

impl std::error::Error for BoundedWaitError {}

/// Wait for `child` to exit, capturing stdout + stderr, with a
/// hard upper bound on wall-clock time. On expiry the child is
/// SIGKILLed + reaped and the function returns
/// [`BoundedWaitError::Timeout`].
///
/// Spawning convention: the caller must have configured stdout +
/// stderr as `Stdio::piped()` for the captured-output path to
/// work; if a pipe is absent the corresponding `Output` field is
/// returned empty.
pub fn wait_with_output_timeout(
    mut child: Child,
    timeout: Duration,
    label: impl Into<String>,
) -> Result<Output, BoundedWaitError> {
    let label = label.into();

    // Drain stdout / stderr in parallel threads so a backed-up
    // OS pipe does not pin the child after it has otherwise
    // finished. Without this, a process that exits cleanly but
    // had its stderr full would still cause `wait_with_output`
    // to hang reading the unread bytes.
    let stdout_handle = child.stdout.take().map(|mut s| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut s| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);

    let poll_interval = Duration::from_millis(50);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_handle
                    .map(|h| h.join().unwrap_or_default())
                    .unwrap_or_default();
                let stderr = stderr_handle
                    .map(|h| h.join().unwrap_or_default())
                    .unwrap_or_default();
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    // SIGKILL + reap so we never leak a zombie.
                    let _ = child.kill();
                    let _ = child.wait();
                    // Join the drainer threads so their pipe FDs
                    // close before we drop the `Child`. Errors
                    // are intentionally ignored — the child is
                    // already dead and any `read_to_end` partial
                    // failure is irrelevant to the timeout
                    // surface.
                    if let Some(h) = stdout_handle {
                        let _ = h.join();
                    }
                    if let Some(h) = stderr_handle {
                        let _ = h.join();
                    }
                    return Err(BoundedWaitError::Timeout { label, timeout });
                }
                thread::sleep(poll_interval);
            }
            Err(e) => {
                // Best-effort cleanup of pipe drainer threads.
                if let Some(h) = stdout_handle {
                    let _ = h.join();
                }
                if let Some(h) = stderr_handle {
                    let _ = h.join();
                }
                return Err(BoundedWaitError::WaitFailed {
                    label,
                    reason: e.to_string(),
                });
            }
        }
    }
}

/// Spawn `cmd` (forcing `Stdio::piped()` on stdout + stderr) and
/// drive it through [`wait_with_output_timeout`]. The
/// (very common) "spawn → capture → bounded wait" pattern
/// expressed as a single call.
pub fn run_command_output_timeout(
    cmd: &mut Command,
    timeout: Duration,
    label: impl Into<String>,
) -> Result<Output, BoundedWaitError> {
    let label = label.into();
    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| BoundedWaitError::SpawnFailed {
            label: label.clone(),
            reason: e.to_string(),
        })?;
    wait_with_output_timeout(child, timeout, label)
}

/// `cmd.status()`-equivalent, bounded. Convenience for the
/// reseed paths that don't care about captured output but DO
/// care about the exit code.
pub fn run_command_status_timeout(
    cmd: &mut Command,
    timeout: Duration,
    label: impl Into<String>,
) -> Result<ExitStatus, BoundedWaitError> {
    let out = run_command_output_timeout(cmd, timeout, label)?;
    Ok(out.status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Regression test for `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`:
    /// a child that would otherwise block for 9999 s MUST be
    /// killed within `timeout + 5 s` and surface the typed
    /// [`BoundedWaitError::Timeout`] variant.
    #[test]
    fn sleep_9999_killed_by_timeout_wrapper() {
        let mut cmd = Command::new("sleep");
        cmd.arg("9999");
        let timeout = Duration::from_secs(2);
        let started = Instant::now();
        let err = run_command_status_timeout(&mut cmd, timeout, "sleep-regression")
            .expect_err("must time out, not succeed");
        let elapsed = started.elapsed();
        match &err {
            BoundedWaitError::Timeout {
                label,
                timeout: t,
            } => {
                assert_eq!(label, "sleep-regression");
                assert_eq!(*t, timeout);
            }
            other => panic!("expected Timeout variant, got: {other:?}"),
        }
        assert!(
            elapsed < timeout + Duration::from_secs(5),
            "wrapper must return within timeout + 5s; elapsed={elapsed:?} \
             (regression: unbounded wait reintroduced)",
        );
    }

    #[test]
    fn fast_command_returns_normally_with_captured_output() {
        let mut cmd = Command::new("printf");
        cmd.arg("hello stdout");
        let out = run_command_output_timeout(
            &mut cmd,
            Duration::from_secs(5),
            "printf-fast",
        )
        .expect("printf must succeed within 5s");
        assert!(out.status.success(), "printf exit: {:?}", out.status);
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hello stdout");
    }

    #[test]
    fn missing_binary_surfaces_spawn_failed() {
        let mut cmd = Command::new("/definitely/not/a/real/binary-xyz-9c1");
        let err = run_command_output_timeout(
            &mut cmd,
            Duration::from_secs(2),
            "missing-bin",
        )
        .expect_err("missing binary must fail to spawn");
        match &err {
            BoundedWaitError::SpawnFailed { label, .. } => {
                assert_eq!(label, "missing-bin");
            }
            other => panic!("expected SpawnFailed, got: {other:?}"),
        }
    }
}
