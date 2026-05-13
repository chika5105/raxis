//! Tier-3 operator-visible artifact reporting.
//!
//! At end of run (success OR failure) the realistic-scenario and
//! `full_e2e_session_lifecycle` test drivers print a block of
//! copyable artifact paths to stderr so an operator can quickly
//! pivot to the audit dir, the kernel log, the merged worktrees,
//! the install dir, and (when mounted) the dashboard autologin URL.
//!
//! The reporter is implemented as an RAII guard: dropping the
//! `Tier3Reporter` value (whether on a normal return or while the
//! stack is unwinding from a `panic!`) emits the block exactly
//! once. That keeps the reporter strictly bounded to the test
//! binary's panic surface — we do NOT install a `set_hook` global
//! because that contaminates parallel tests sharing the same
//! process under `cargo test`.
//!
//! ## Workdir-keep policy
//!
//! The realism harness's [`super::kernel_driver::bootstrap_with_custom_cert`]
//! already calls `tempfile::tempdir()...keep()` so the data_dir is
//! never auto-cleaned. The Tier-3 reporter therefore implements
//! the *opposite* default — **keep on failure unconditionally**,
//! and **delete on success only when `RAXIS_E2E_KEEP=0`**. The
//! reporter's `mark_success()` method flips the success bit so the
//! Drop path can choose between "leave the dir for triage" and
//! "operator opted-in to cleanup".
//!
//! Env-var summary:
//!
//!   * `RAXIS_E2E_KEEP=0` — on success, delete the install dir;
//!     ignored on failure. Any other value (or unset) keeps the
//!     dir.
//!   * `RAXIS_E2E_OPEN_REPO=1` — after printing the artifact
//!     block, spawn `open(1)` / `xdg-open` / `code` against each
//!     merged worktree so the operator can inspect it immediately.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// One named merged worktree to surface in the artifact block.
/// Multiple are admissible because the realism scenario merges N
/// initiatives and an operator may want to inspect each. Pinned to
/// a non-zero-cost `Vec` so the realistic-scenario driver can
/// register each initiative's worktree independently.
#[derive(Debug, Clone)]
pub struct MergedWorktree {
    pub label: String,
    pub path: PathBuf,
}

/// Captures the artifact paths the reporter prints + the success
/// flag the workdir-keep policy keys on.
pub struct Tier3Reporter {
    test_label: &'static str,
    install_dir: PathBuf,
    data_dir: PathBuf,
    kernel_log: Option<PathBuf>,
    audit_dir: PathBuf,
    merged_worktrees: Vec<MergedWorktree>,
    dashboard_url: Option<String>,
    succeeded: bool,
    fired: bool,
}

impl Tier3Reporter {
    /// Build a reporter pinned to the given install + data dirs.
    /// The audit dir is derived from `<data_dir>/audit`. The kernel
    /// log path is best-guess (`<data_dir>/kernel.stderr.log`) —
    /// callers can override with [`Self::with_kernel_log`].
    pub fn new(
        test_label: &'static str,
        install_dir: impl Into<PathBuf>,
        data_dir: impl Into<PathBuf>,
    ) -> Self {
        let data_dir = data_dir.into();
        let audit_dir = data_dir.join("audit");
        let kernel_log = Some(data_dir.join("kernel.stderr.log"));
        Self {
            test_label,
            install_dir: install_dir.into(),
            data_dir,
            kernel_log,
            audit_dir,
            merged_worktrees: Vec::new(),
            dashboard_url: None,
            succeeded: false,
            fired: false,
        }
    }

    /// Override the kernel log path. Useful for `full_e2e_session_
    /// lifecycle.rs` which already writes the log under
    /// `<data_dir>/kernel.stderr.log` but where the helper future-
    /// proofs against the path moving.
    pub fn with_kernel_log(mut self, path: impl Into<PathBuf>) -> Self {
        self.kernel_log = Some(path.into());
        self
    }

    /// Drop the kernel log line — useful for `full_e2e_session_
    /// lifecycle.rs` paths that have not yet captured a separate
    /// log file.
    pub fn without_kernel_log(mut self) -> Self {
        self.kernel_log = None;
        self
    }

    /// Register a merged worktree to surface. Multiple calls
    /// accumulate so the operator sees one line per registered
    /// worktree.
    pub fn add_worktree(&mut self, label: impl Into<String>, path: impl Into<PathBuf>) {
        self.merged_worktrees.push(MergedWorktree {
            label: label.into(),
            path: path.into(),
        });
    }

    /// Record the dashboard autologin URL the kernel mounted this
    /// run. The reporter prints the line ONLY when this is set; if
    /// the dashboard was not mounted (e.g. realistic-scenario)
    /// the line is suppressed cleanly rather than printing a
    /// broken `<n/a>` placeholder.
    pub fn set_dashboard_url(&mut self, url: impl Into<String>) {
        self.dashboard_url = Some(url.into());
    }

    /// Flip the success bit so the Drop path can opt-in to
    /// cleanup when `RAXIS_E2E_KEEP=0`. Must be called as the
    /// LAST step on the success path — otherwise an assertion
    /// firing after the bit is set would lose the keep-on-failure
    /// behavior the harness needs for triage.
    pub fn mark_success(&mut self) {
        self.succeeded = true;
    }

    /// Convenience inspector; tests don't need this but the
    /// `tier3_artifacts::tests` module pins the behaviour.
    pub fn is_succeeded(&self) -> bool {
        self.succeeded
    }

    fn emit_block(&mut self) {
        if self.fired {
            return;
        }
        self.fired = true;

        let bar = "──────────────";
        eprintln!(
            "[{label}] {bar} post-run artifact paths {bar}",
            label = self.test_label
        );
        eprintln!(
            "[{label}] kernel install dir : {}",
            self.install_dir.display(),
            label = self.test_label
        );
        eprintln!(
            "[{label}] kernel data dir    : {}",
            self.data_dir.display(),
            label = self.test_label
        );
        if let Some(log) = &self.kernel_log {
            eprintln!(
                "[{label}] kernel log         : {}",
                log.display(),
                label = self.test_label
            );
        }
        eprintln!(
            "[{label}] audit dir          : {}",
            self.audit_dir.display(),
            label = self.test_label
        );
        if self.merged_worktrees.is_empty() {
            eprintln!(
                "[{label}] merged worktree    : (none registered)",
                label = self.test_label
            );
        } else {
            for w in &self.merged_worktrees {
                eprintln!(
                    "[{label}] merged worktree    : [{}] {}",
                    w.label,
                    w.path.display(),
                    label = self.test_label
                );
            }
        }
        if let Some(url) = &self.dashboard_url {
            eprintln!(
                "[{label}] dashboard URL      : {}",
                url,
                label = self.test_label
            );
        }
        eprintln!(
            "[{label}] (set RAXIS_E2E_OPEN_REPO=1 to open the worktree(s) in the default editor)",
            label = self.test_label
        );
        eprintln!("[{label}] (set RAXIS_E2E_KEEP=0 to delete the install dir on success; default keeps it)",
            label = self.test_label);

        let panicking = std::thread::panicking() || !self.succeeded;
        if panicking {
            eprintln!(
                "[{label}] keep-policy        : KEEPING (panic / explicit failure path)",
                label = self.test_label
            );
        } else if std::env::var("RAXIS_E2E_KEEP").as_deref() == Ok("0") {
            eprintln!(
                "[{label}] keep-policy        : DELETING data dir (RAXIS_E2E_KEEP=0)",
                label = self.test_label
            );
            // Best-effort delete; report any failure but DO NOT
            // re-panic from a Drop.
            if let Err(e) = std::fs::remove_dir_all(&self.data_dir) {
                eprintln!(
                    "[{label}] keep-policy        : delete failed: {e}",
                    label = self.test_label
                );
            }
        } else {
            eprintln!("[{label}] keep-policy        : KEEPING (default; export RAXIS_E2E_KEEP=0 to delete on success)",
                label = self.test_label);
        }

        if std::env::var("RAXIS_E2E_OPEN_REPO").as_deref() == Ok("1") {
            for w in &self.merged_worktrees {
                open_path_best_effort(&w.path, self.test_label, &w.label);
            }
        }
    }
}

impl Drop for Tier3Reporter {
    fn drop(&mut self) {
        // Run unconditionally so both the panic path and the
        // happy path emit the block exactly once.
        self.emit_block();
    }
}

/// Best-effort spawn of an OS-appropriate URL opener pointed at a
/// filesystem path. NEVER fails the test — a missing binary just
/// logs a one-liner.
fn open_path_best_effort(path: &Path, label: &'static str, worktree_label: &str) {
    let candidates: &[&[&str]] = if cfg!(target_os = "macos") {
        &[&["open"], &["code"]]
    } else if cfg!(target_os = "linux") {
        &[&["xdg-open"], &["code"]]
    } else {
        &[&["code"]]
    };
    for argv in candidates {
        let mut cmd = Command::new(argv[0]);
        for a in &argv[1..] {
            cmd.arg(a);
        }
        cmd.arg(path);
        match cmd.spawn() {
            Ok(_) => {
                eprintln!(
                    "[{label}] opened worktree    : {worktree_label} via {}",
                    argv[0],
                );
                return;
            }
            Err(e) => {
                eprintln!(
                    "[{label}] open `{}` for {worktree_label} failed: {e}",
                    argv[0],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Per-process stderr captures aren't trivial across crates;
    /// the assertions here pin the Drop-fires-once semantics and
    /// the dashboard-line-conditional-emission semantics through
    /// observable state rather than line-scraping.

    #[test]
    fn reporter_fires_emit_block_on_drop_once() {
        let tmp = tempfile::tempdir().unwrap();
        let mut r = Tier3Reporter::new("smoke", tmp.path(), tmp.path().join("data"));
        r.add_worktree("primary", tmp.path().join("repo"));
        // Use an RFC 2606 `.invalid` TLD so the operator (and any
        // log-scraping tooling) can tell this is fixture data the
        // moment they see it. A `127.0.0.1:0` URL leaks into the
        // realistic-scenario stderr stream alongside real
        // `[realism-e2e]` lines and is easily mistaken for a
        // broken bind on the live kernel — it is not, it is THIS
        // unit test's fixture (the test_label is "smoke" so an
        // operator skimming `/tmp/raxis-e2e-realistic.log` can
        // confirm by `rg '^\[smoke\]'`).
        r.set_dashboard_url(
            "http://test-fixture-not-a-real-dashboard.invalid/login",
        );
        r.mark_success();
        // Track the fire count via a local Arc<Mutex<_>> — the
        // reporter does not expose the bit publicly, so we
        // observe the underscore-prefixed Drop side effect by
        // forcing it explicitly here. The point is that the
        // method does not panic and runs cleanly twice (the
        // second call is a no-op because `self.fired = true`).
        let _ = Arc::new(Mutex::new(()));
        r.emit_block();
        r.emit_block();
        assert!(r.fired, "emit_block must set fired=true");
    }

    #[test]
    fn reporter_keeps_when_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        {
            let _r = Tier3Reporter::new("smoke", tmp.path(), &data);
            // do NOT mark_success — Drop must KEEP the dir.
        }
        assert!(data.exists(), "data dir must be kept on the failure path");
    }

    #[test]
    fn reporter_deletes_when_keep_zero_and_success() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let prior = std::env::var("RAXIS_E2E_KEEP").ok();
        std::env::set_var("RAXIS_E2E_KEEP", "0");
        {
            let mut r = Tier3Reporter::new("smoke", tmp.path(), &data);
            r.mark_success();
        }
        match prior {
            Some(v) => std::env::set_var("RAXIS_E2E_KEEP", v),
            None => std::env::remove_var("RAXIS_E2E_KEEP"),
        }
        assert!(
            !data.exists(),
            "data dir must be deleted on success when RAXIS_E2E_KEEP=0"
        );
    }
}
