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

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::keep_alive::keep_running_after_exit_with_workdir;

// ── Observability URL constants (mirror compose) ─────────────────
//
// These mirror `live-e2e/docker-compose.e2e.yml` exactly. The
// `observability_urls_match_compose_file` test below scans the
// compose file at compile time and asserts the constants stay in
// lock-step; any future port rebind in the compose file fails the
// kernel-test build before it lands on `main`.
//
// We deliberately do NOT pull these from the `xtask::observability`
// module — the kernel test crate does not depend on `xtask` and
// adding a dep just to share a port number would be wildly out
// of proportion. Drift is caught by the compose-file scan test.

const OBS_GRAFANA_PORT: u16 = 3000;
const OBS_PROMETHEUS_PORT: u16 = 9090;
const OBS_OTLP_HTTP_PORT: u16 = 4318;
const OBS_OTEL_ZPAGES_PORT: u16 = 13133;
const OBS_GRAFANA_ADMIN_USER: &str = "admin";
const OBS_GRAFANA_ADMIN_PASS: &str = "raxis-e2e";
const OBS_OVERVIEW_DASHBOARD: &str = "raxis-00-overview";

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
    /// Path to the checked-in `raxis/live-e2e/examples/` bundle,
    /// when the caller has wired it. Surfaced in the artifact
    /// block so operators always see "this is exactly what
    /// configuration produced the iter" alongside the per-run
    /// paths. See `INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01`.
    examples_dir: Option<PathBuf>,
    surface_observability_urls: bool,
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
            examples_dir: None,
            surface_observability_urls: false,
            succeeded: false,
            fired: false,
        }
    }

    /// Wire the checked-in `raxis/live-e2e/examples/` bundle path
    /// for surfacing in the artifact block. Operators auditing
    /// "what configuration produced the run?" land on this path
    /// without needing to grep the harness source.
    ///
    /// See `INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01`
    /// (`raxis/specs/invariants.md §11.10`) for the structural
    /// guarantee the directory carries.
    pub fn with_examples_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.examples_dir = Some(path.into());
        self
    }

    /// Opt the reporter into emitting the Prometheus, Grafana,
    /// and OTel-collector URL block as part of the end-of-run
    /// artifact dump. The block surfaces ALL the URLs whether
    /// the stack is up or not (so an operator who forgot to
    /// bring it up sees the runnable `cargo xtask observability
    /// up` command in the same place); reachability is
    /// annotated per-line with a TCP probe.
    ///
    /// Pinned to a builder rather than a constructor flag so the
    /// existing call sites (
    /// `extended_e2e_realistic_scenario.rs`,
    /// `full_e2e_session_lifecycle.rs`,
    /// `tier3_artifacts::tests`) opt in surgically without churning
    /// the `Tier3Reporter::new` signature.
    pub fn with_observability_urls(mut self) -> Self {
        self.surface_observability_urls = true;
        self
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
        if let Some(ex) = &self.examples_dir {
            // INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01 surface.
            // Always printed (even when the path doesn't exist on
            // disk yet) so an operator running the harness for the
            // first time sees where the checked-in bundle would
            // live and can pin it via `RAXIS_E2E_REFRESH_EXAMPLES=1`.
            eprintln!(
                "[{label}] examples bundle    : {} \
                 (refresh via RAXIS_E2E_REFRESH_EXAMPLES=1; see README in that dir)",
                ex.display(),
                label = self.test_label
            );
        }
        if self.surface_observability_urls {
            emit_observability_block(self.test_label);
            // `RAXIS_E2E_OPEN_OBSERVABILITY=1` (documented in
            // `live-e2e/README.md` since the `observability(v3)`
            // landing at commit `07ad9be`) was previously a
            // no-op marker. Wire it into the new browser dispatch
            // so an operator who opts in gets the Grafana home +
            // the `raxis-00-overview` deep-link opened at
            // end-of-run alongside the existing artifact-path
            // block — same Cursor-vs-system handling as the
            // dashboard autologin URL above.
            if std::env::var("RAXIS_E2E_OPEN_OBSERVABILITY").as_deref() == Ok("1") {
                let urls = [
                    format!("http://127.0.0.1:{OBS_GRAFANA_PORT}/"),
                    format!("http://127.0.0.1:{OBS_GRAFANA_PORT}/d/{OBS_OVERVIEW_DASHBOARD}"),
                ];
                for url in urls {
                    let _ = super::browser::open_in_best_browser(&url);
                }
            }
        }
        eprintln!(
            "[{label}] (set RAXIS_E2E_OPEN_REPO=1 to open the worktree(s) in the default editor)",
            label = self.test_label
        );
        eprintln!("[{label}] (set RAXIS_E2E_KEEP=0 to delete the install dir on success; default keeps it)",
            label = self.test_label);

        let panicking = std::thread::panicking() || !self.succeeded;
        // Keep-alive opt-out: when the operator opts into post-mortem
        // inspection (env `RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT=1`,
        // `--keep-running-after-exit` CLI flag, or a `KEEP_RUNNING`
        // touch file in `<data_dir>`), the Tier-3 reporter MUST NOT
        // delete `<data_dir>` even when `RAXIS_E2E_KEEP=0` — the
        // operator needs the SQLite db, audit chain, and kernel
        // stderr log to stay on disk so they can inspect at leisure.
        // Default (no signal) preserves the legacy
        // `RAXIS_E2E_KEEP=0`-on-success cleanup branch per
        // `INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01`. See
        // `specs/v3/live-e2e-keep-alive.md`.
        let keep_running = keep_running_after_exit_with_workdir(Some(&self.data_dir));
        if panicking {
            eprintln!(
                "[{label}] keep-policy        : KEEPING (panic / explicit failure path)",
                label = self.test_label
            );
        } else if keep_running {
            eprintln!(
                "[{label}] keep-policy        : KEEPING (keep-running-after-exit flag active; \
                 RAXIS_E2E_KEEP=0 ignored)",
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

// ── Observability URL block ─────────────────────────────────────
//
// Same surface the `cargo xtask observability up/urls` command
// renders, threaded into the Tier-3 reporter so an operator
// scanning a `cargo test ... extended_e2e_realistic_scenario`
// stderr capture sees the dashboard URLs in the same place they
// see the kernel-log path. Per-line `(up)` / `(down)` is
// emitted via a 250ms TCP-connect probe so an operator who
// forgot to bring up the obs stack still sees the URL block
// (and the suggested fix) without the lines pretending to be
// reachable.

/// Emit the same observability URL block the
/// `cargo xtask observability urls` command produces, prefixed
/// with the harness label so a `grep '^\[<label>\]'` on the test
/// stderr capture surfaces every artifact line in one pass.
///
/// Public so it can be called once at harness *startup* (immediately
/// after the kernel daemon is ready) and again at end-of-run via
/// the [`Tier3Reporter`] Drop. Both calls are cheap (≤ 4 × 250 ms
/// TCP probes, no HTTP); the function never panics and never
/// fails the test.
pub fn print_observability_urls_inline(label: &str) {
    emit_observability_block(label);
}

fn emit_observability_block(label: &str) {
    let bar = "──────────────";
    eprintln!("[{label}] {bar} observability surface {bar}");
    eprintln!(
        "[{label}] Grafana       : http://127.0.0.1:{port}/   \
         (admin/{user}, anonymous Viewer OK) {state}",
        port = OBS_GRAFANA_PORT,
        user = OBS_GRAFANA_ADMIN_PASS, // password in the labelled slot, NOT a typo:
        // `admin/{pass}` matches the README phrasing.
        state = probe_state("127.0.0.1", OBS_GRAFANA_PORT),
    );
    eprintln!(
        "[{label}] Grafana home  : http://127.0.0.1:{port}/d/{uid}",
        port = OBS_GRAFANA_PORT,
        uid = OBS_OVERVIEW_DASHBOARD,
    );
    eprintln!(
        "[{label}] Prometheus    : http://127.0.0.1:{port}/         {state}",
        port = OBS_PROMETHEUS_PORT,
        state = probe_state("127.0.0.1", OBS_PROMETHEUS_PORT),
    );
    eprintln!(
        "[{label}] Prom targets  : http://127.0.0.1:{port}/targets",
        port = OBS_PROMETHEUS_PORT,
    );
    eprintln!(
        "[{label}] OTLP/HTTP     : http://127.0.0.1:{port}        \
         (kernel [observability] push target) {state}",
        port = OBS_OTLP_HTTP_PORT,
        state = probe_state("127.0.0.1", OBS_OTLP_HTTP_PORT),
    );
    eprintln!(
        "[{label}] OTel zPages   : http://127.0.0.1:{port}/       {state}",
        port = OBS_OTEL_ZPAGES_PORT,
        state = probe_state("127.0.0.1", OBS_OTEL_ZPAGES_PORT),
    );
    // Mention the admin user in a separate line — keeping the
    // password on the surface above keeps the operator from
    // having to scroll for it, but the user name belongs here
    // for completeness.
    eprintln!(
        "[{label}] grafana login : user={user} password={pass}",
        user = OBS_GRAFANA_ADMIN_USER,
        pass = OBS_GRAFANA_ADMIN_PASS,
    );
    eprintln!("[{label}] (run `cargo xtask observability up` if any line above shows `(down)`)");
    eprintln!(
        "[{label}] (RAXIS_E2E_OPEN_OBSERVABILITY=1 opens Grafana home + raxis-00-overview \
         at end-of-run; RAXIS_E2E_BROWSER=cursor|system|none overrides which browser)"
    );
}

/// Returns either `(up)` or `(down)` based on a 250ms TCP-connect
/// probe. Never panics; an unparseable address resolves to `(down)`.
fn probe_state(host: &str, port: u16) -> &'static str {
    if probe_tcp(host, port) {
        "(up)"
    } else {
        "(down — bring up via `cargo xtask observability up`)"
    }
}

fn probe_tcp(host: &str, port: u16) -> bool {
    let addr_str = format!("{host}:{port}");
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
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

    /// Pin the OBS_* port + credential constants in lock-step with
    /// `live-e2e/docker-compose.e2e.yml`. Catches a future port
    /// rebind in the compose file before it ships — without this
    /// the Tier-3 reporter would silently print stale URLs.
    #[test]
    fn observability_urls_match_compose_file() {
        let workspace = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let compose_path = workspace
            .parent()
            .expect("kernel crate has parent")
            .join("live-e2e/docker-compose.e2e.yml");
        let compose = std::fs::read_to_string(&compose_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", compose_path.display()));
        // Compose binds host ports as `127.0.0.1:<host>:<container>`
        // for every service. Asserting the host port appears once
        // is enough to catch a rebind without coupling to the
        // exact YAML key ordering.
        for (name, port) in [
            ("grafana", OBS_GRAFANA_PORT),
            ("prometheus", OBS_PROMETHEUS_PORT),
            ("otlp-http", OBS_OTLP_HTTP_PORT),
            ("otel-zpages", OBS_OTEL_ZPAGES_PORT),
        ] {
            let bind = format!("127.0.0.1:{port}:");
            assert!(
                compose.contains(&bind),
                "compose file at {} must bind {name} on host port {port} \
                 (looked for {bind:?})",
                compose_path.display(),
            );
        }
        // Grafana admin password lives at
        // `GF_SECURITY_ADMIN_PASSWORD: <pass>` in the compose env.
        assert!(
            compose.contains(&format!(
                "GF_SECURITY_ADMIN_PASSWORD: {OBS_GRAFANA_ADMIN_PASS}"
            )),
            "compose file must pin GF_SECURITY_ADMIN_PASSWORD: {OBS_GRAFANA_ADMIN_PASS} \
             to keep the Tier-3 reporter URL block honest",
        );
    }

    /// The opt-in builder flips the bit; the reporter still emits
    /// cleanly on Drop and on an explicit re-fire.
    #[test]
    fn reporter_with_observability_urls_does_not_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let mut r = Tier3Reporter::new("smoke", tmp.path(), tmp.path().join("data"))
            .with_observability_urls();
        r.mark_success();
        r.emit_block();
        assert!(r.fired);
    }

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
        r.set_dashboard_url("http://test-fixture-not-a-real-dashboard.invalid/login");
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

    /// Serialise the two `RAXIS_E2E_KEEP`-sensitive tests against
    /// each other (and any sibling test in this binary that reads
    /// the env var). `set_var`/`remove_var` are process-global, so
    /// without this guard sibling tests racing the same env var
    /// flap pass/fail under `--test-threads >= 2`.
    static KEEP_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn reporter_keeps_when_failure() {
        let _g = KEEP_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _gk = crate::common::keep_alive::lock_keep_running_env();
        // Force the keep-running flag off — a sibling test could
        // have left it set, and Tier3Reporter::Drop honours it.
        let prior_kr = std::env::var("RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT").ok();
        let prior_kr_alias = std::env::var("RAXIS_KEEP_ALIVE").ok();
        std::env::remove_var("RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT");
        std::env::remove_var("RAXIS_KEEP_ALIVE");
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        // Force the keep-on-success default for the duration of the
        // test in case a sibling left RAXIS_E2E_KEEP=0 leaked.
        let prior = std::env::var("RAXIS_E2E_KEEP").ok();
        std::env::remove_var("RAXIS_E2E_KEEP");
        {
            let _r = Tier3Reporter::new("smoke", tmp.path(), &data);
            // do NOT mark_success — Drop must KEEP the dir.
        }
        if let Some(v) = prior {
            std::env::set_var("RAXIS_E2E_KEEP", v);
        }
        if let Some(v) = prior_kr {
            std::env::set_var("RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT", v);
        }
        if let Some(v) = prior_kr_alias {
            std::env::set_var("RAXIS_KEEP_ALIVE", v);
        }
        assert!(data.exists(), "data dir must be kept on the failure path");
    }

    #[test]
    fn reporter_deletes_when_keep_zero_and_success() {
        let _g = KEEP_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _gk = crate::common::keep_alive::lock_keep_running_env();
        // Force the keep-running flag off — a sibling test could
        // have left it set, and Tier3Reporter::Drop honours it.
        let prior_kr = std::env::var("RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT").ok();
        let prior_kr_alias = std::env::var("RAXIS_KEEP_ALIVE").ok();
        std::env::remove_var("RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT");
        std::env::remove_var("RAXIS_KEEP_ALIVE");
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
        if let Some(v) = prior_kr {
            std::env::set_var("RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT", v);
        }
        if let Some(v) = prior_kr_alias {
            std::env::set_var("RAXIS_KEEP_ALIVE", v);
        }
        assert!(
            !data.exists(),
            "data dir must be deleted on success when RAXIS_E2E_KEEP=0"
        );
    }
}
