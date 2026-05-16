//! Live-e2e "keep running after exit" flag — operator post-mortem
//! ergonomics for the realism-scenario harness.
//!
//! ## What this module owns
//!
//! Reading the operator's "do not tear down at end of test" intent
//! and exposing it as a single `bool` so every cleanup site in the
//! live-e2e harness can branch on the SAME signal. Three control
//! surfaces compose:
//!
//!   1. **Env var (primary)** — [`ENV_KEEP_RUNNING_AFTER_EXIT`]
//!      `=1`/`=true`/`=yes` (case-insensitive) activates. Empty,
//!      `0`, `false`, `no`, unset all leave it off. Easiest to
//!      compose with `cargo test`:
//!
//!      ```bash
//!      RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT=1 cargo test --release \
//!          --test extended_e2e_realistic_scenario -- --nocapture
//!      ```
//!
//!   2. **Touch file (workdir-anchored)** — presence of
//!      `<work_dir>/KEEP_RUNNING` at the moment the test reaches
//!      its teardown phase. Lets an operator flip the flag from
//!      another shell mid-run (`touch /tmp/raxis-e2e-data/KEEP_RUNNING`)
//!      after the test has already started.
//!
//!   3. **CLI flag** — when the test binary takes args, the
//!      `--keep-running-after-exit` flag activates. The current
//!      `cargo test`-driven binaries do NOT take args, so the
//!      flag is exposed via [`cli_flag_present`] for any future
//!      caller; in practice the env var carries the same intent
//!      and is what `cargo test` plumbs through cleanly.
//!
//! Any one of the three signals being "on" activates keep-alive.
//! The default (no signal) MUST leave behavior identical to
//! pre-keep-alive — invariant
//! [`INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01`].
//!
//! ## What "keep running" means in this harness
//!
//! When the flag is on, every cleanup site in the kernel-test
//! binary (the explicit `kernel.shutdown_with(SIGTERM, …)` call,
//! the `KernelInstance::Drop` SIGKILL, the `OtelPusherSupervisor::
//! Drop` SIGTERM-then-SIGKILL, the `Tier3Reporter::Drop`
//! `remove_dir_all(<data_dir>)` cleanup branch under
//! `RAXIS_E2E_KEEP=0`) MUST be skipped. The test still emits its
//! ACTUAL verdict code — keep-alive does NOT change pass/fail
//! signaling, only what happens to the spawned services after
//! the verdict is known.
//!
//! ## What stays running, what does not
//!
//! Stays running (when the flag is on AND the test process keeps
//! running):
//!
//!   * `raxis-kernel` daemon (operator dashboard at
//!     `http://127.0.0.1:<dashboard_port>`).
//!   * `raxis-otel-pusher` sidecar (forwarding metrics to OTLP
//!     `http://127.0.0.1:4318`).
//!   * The docker-compose backing stack (postgres/mongo/redis/
//!     smtp/mysql/mssql + Grafana + Prometheus + OTel collector)
//!     — note the harness never auto-tears this down anyway, so
//!     the flag is a no-op for that path.
//!   * The kernel-managed AVF/Firecracker guest VMs that were
//!     mid-task at the moment the test reached teardown.
//!   * `<work_dir>` (`<data_dir>` in the realism-e2e harness) —
//!     not deleted by the Tier-3 reporter.
//!
//! Tears down regardless:
//!
//!   * The test harness's own state machine (assertions still
//!     fire, the test still panics on a failed witness, the
//!     verdict still propagates to `cargo test`'s exit code).
//!
//! ## Why dev-only
//!
//! This is an operator post-mortem affordance for a test
//! harness. It explicitly leaves long-lived processes around
//! without supervision and is NOT a production posture: a
//! production deployment runs the kernel under launchd / systemd
//! / ECS, never under a test binary. The flag exists to stop
//! the harness from hiding the dashboard URL from an operator
//! who needs to inspect a failure for ten more minutes.
//!
//! ## Spec home
//!
//! `specs/v3/live-e2e-keep-alive.md` — full operator-facing
//! contract, env-var precedence, manual teardown commands.
//! Invariant pinned in `specs/invariants.md` as
//! [`INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01`].

#![allow(dead_code)]

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

// ─── Operator-facing surface ─────────────────────────────────────

/// Primary env var. Composes naturally with `cargo test`:
///
/// ```bash
/// RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT=1 cargo test --release \
///     --test extended_e2e_realistic_scenario -- --nocapture
/// ```
pub const ENV_KEEP_RUNNING_AFTER_EXIT: &str = "RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT";

/// Filename the helper looks for under `<work_dir>` to flip the
/// flag from another shell mid-run.
pub const KEEP_RUNNING_TOUCH_FILE: &str = "KEEP_RUNNING";

/// Long-form CLI flag spelling the test-binary callers pass when
/// they DO take args. Not currently consumed by any test binary
/// — the env var is the canonical surface — but pinned here so
/// the spelling is single-sourced.
pub const CLI_FLAG_KEEP_RUNNING_AFTER_EXIT: &str = "--keep-running-after-exit";

// ─── CLI-flag override (for future test-binary callers) ──────────
//
// Test binaries that DO take args (e.g. a future `live-e2e`
// subcommand) can call `set_cli_flag(true)` after argument
// parsing; the helper composes the bit with the env-var and
// touch-file signals in [`keep_running_after_exit_with_workdir`].
// The bit defaults `false` and is process-global so the various
// Drop sites can read it without threading state through. Tests
// that flip the bit MUST restore it on the unwind path
// (see [`CliFlagGuard`]).

static CLI_FLAG: AtomicBool = AtomicBool::new(false);

/// Programmatic equivalent of [`CLI_FLAG_KEEP_RUNNING_AFTER_EXIT`]
/// for callers that have already parsed their argv. Setting the
/// bit `true` adds the CLI signal to the OR-tree of activation
/// sources.
pub fn set_cli_flag(on: bool) {
    CLI_FLAG.store(on, Ordering::SeqCst);
}

/// Read the in-process CLI bit. Test-only, exposed for the
/// witness coverage below.
pub fn cli_flag_present() -> bool {
    CLI_FLAG.load(Ordering::SeqCst)
}

/// RAII guard that snapshots the CLI bit on construction and
/// restores it on Drop. Used by the witness tests below to
/// keep the per-test mutation hermetic against a shared
/// `cargo test` process.
pub struct CliFlagGuard {
    prior: bool,
}

impl CliFlagGuard {
    pub fn set(on: bool) -> Self {
        let prior = CLI_FLAG.swap(on, Ordering::SeqCst);
        Self { prior }
    }
}

impl Drop for CliFlagGuard {
    fn drop(&mut self) {
        CLI_FLAG.store(self.prior, Ordering::SeqCst);
    }
}

// ─── Pure parsing layer ──────────────────────────────────────────

/// Parse a candidate env-var value as a truthy / falsy token.
///
/// Truthy (case-insensitive): `1`, `true`, `yes`, `on`. Anything
/// else — including empty string, `0`, `false`, `no`, `off`,
/// `garbage`, or `None` — is falsy. The parser is intentionally
/// lenient on the truthy side so a copy-paste from a CI yaml
/// (`KEEP_RUNNING: "true"`) JustWorks; conservative on the
/// falsy side so an unset / typo'd value never accidentally
/// keeps services running.
pub fn parse_truthy_env_value(value: Option<&str>) -> bool {
    match value {
        None => false,
        Some(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            _ => false,
        },
    }
}

// ─── Activation reads ────────────────────────────────────────────

/// Env-var signal only. Safe to call from any Drop site that does
/// NOT have a `<work_dir>` handy (e.g. a test that has not yet
/// constructed one).
pub fn keep_running_after_exit() -> bool {
    keep_running_via_env() || cli_flag_present()
}

fn keep_running_via_env() -> bool {
    parse_truthy_env_value(std::env::var(ENV_KEEP_RUNNING_AFTER_EXIT).ok().as_deref())
}

/// Full read: env var OR CLI flag OR touch-file
/// (`<work_dir>/KEEP_RUNNING`). The touch-file branch is
/// best-effort — a non-readable work_dir or a broken symlink is
/// treated as "no touch file" without panicking, so a Drop site
/// that has only a borrowed path never trips a late-error
/// surface.
///
/// Argument is `Option<&Path>` so the function composes with
/// supervisors that store the work_dir indirectly (e.g. as a
/// log path, with the work_dir derivable via `parent()`).
/// `None` skips the touch-file probe entirely.
pub fn keep_running_after_exit_with_workdir(work_dir: Option<&Path>) -> bool {
    if keep_running_via_env() || cli_flag_present() {
        return true;
    }
    let Some(dir) = work_dir else { return false };
    let touch = dir.join(KEEP_RUNNING_TOUCH_FILE);
    // `try_exists` swallows the not-readable case as `Ok(false)`
    // on platforms that support it; `exists()` does the same on
    // older targets. Either way a Drop site cannot panic from
    // here.
    touch.try_exists().unwrap_or_else(|_| touch.exists())
}

// ─── Operator-facing banner ──────────────────────────────────────

/// Compose-stack metadata threaded into the keep-alive banner.
/// Callers wire this with the realism-e2e canonical pair via
/// `extended_e2e_support::docker_stack::ComposeStackGuard::for_extended_stack()`
/// — see the `Docker compose stack` section of
/// `specs/v3/live-e2e-keep-alive.md`.
#[derive(Debug, Clone)]
pub struct ComposeStackBanner<'a> {
    pub project: &'a str,
    pub compose_file: &'a Path,
}

/// Print the keep-alive block to stderr. The harness driver calls
/// this exactly once at end-of-test when keep-alive is active so
/// an operator scanning the cargo log finds the dashboard URL,
/// SQLite path, and copy-pastable teardown commands at the bottom
/// of the run.
///
/// `dashboard_port` is `Option<u16>` because some harnesses (the
/// realism-e2e flow) bind the dashboard explicitly while others
/// (the simpler integration tests) do not. The banner suppresses
/// the dashboard line cleanly when `None` rather than printing a
/// broken `<n/a>` placeholder.
///
/// `compose_stack` carries the canonical `(project, compose_file)`
/// pair so the banner renders the operator's
/// `docker compose -p <project> -f <file> ps` / `down -v` lines.
/// `None` falls back to a generic compose-stack hint that points
/// at `cargo xtask observability ps` / `down -v` instead — the
/// kernel-test harness's manual teardown surface for the
/// observability stack.
pub fn print_keep_alive_banner(
    work_dir: &Path,
    dashboard_port: Option<u16>,
    compose_stack: Option<ComposeStackBanner<'_>>,
) {
    let bar = "============================================================";
    eprintln!("{bar}");
    eprintln!("RAXIS E2E KEEP-ALIVE: services left running for post-mortem");
    eprintln!("{bar}");
    if let Some(port) = dashboard_port {
        eprintln!("  Dashboard      http://127.0.0.1:{port}");
    } else {
        eprintln!("  Dashboard      (not mounted by this harness)");
    }
    eprintln!("  Grafana        http://127.0.0.1:3000");
    eprintln!("  Prometheus     http://127.0.0.1:9090");
    eprintln!("  OTel HTTP      http://127.0.0.1:4318");
    eprintln!(
        "  Kernel stderr  tail -f {}/kernel.stderr.log",
        work_dir.display(),
    );
    eprintln!(
        "  SQLite         sqlite3 {}/kernel.db",
        work_dir.display(),
    );
    eprintln!(
        "  Audit chain    cat {}/audit/segment-000.jsonl",
        work_dir.display(),
    );
    eprintln!("  Work-dir       {}", work_dir.display());
    if let Some(cs) = &compose_stack {
        eprintln!(
            "  Compose stack  docker compose -p {project} -f {file} ps",
            project = cs.project,
            file = cs.compose_file.display(),
        );
    } else {
        eprintln!(
            "  Compose stack  cargo xtask observability ps  \
             (postgres + mongo + redis + smtp + mysql + mssql \
             + Grafana + Prometheus + OTel collector)"
        );
    }
    eprintln!();
    eprintln!("To tear down:");
    eprintln!(
        "  pkill -f raxis-kernel; pkill -f extended_e2e_realistic_scenario; \
         pkill -f otelcol; pkill -f prometheus; pkill -f grafana-server"
    );
    eprintln!("  rm -rf {}", work_dir.display());
    if let Some(cs) = &compose_stack {
        eprintln!();
        eprintln!("To tear down compose:");
        eprintln!(
            "  docker compose -p {project} -f {file} down -v",
            project = cs.project,
            file = cs.compose_file.display(),
        );
    } else {
        eprintln!();
        eprintln!("To tear down compose:");
        eprintln!(
            "  cargo xtask observability down -- -v   \
             (or `docker compose -f live-e2e/docker-compose.extended.e2e.yml \
             -p raxis-live-e2e-test down -v`)"
        );
    }
    eprintln!();
    eprintln!("{bar}");
}

// ─── Witness coverage ────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Serialise every test that mutates the env var so parallel
    /// `cargo test` runs in the same binary cannot poison each
    /// other. Mirrors the discipline in `docker_stack.rs::tests`
    /// (RAII `SetEnvGuard`).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// RAII env-var guard: snapshot prior value, set / unset for
    /// the test, restore on drop. Edition 2021 keeps `set_var` /
    /// `remove_var` safe; matches the docker_stack pattern.
    struct SetEnvGuard {
        key: &'static str,
        prior: Option<String>,
    }

    impl SetEnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prior = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prior }
        }
        fn unset(key: &'static str) -> Self {
            let prior = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prior }
        }
    }

    impl Drop for SetEnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// `INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01` — absent any signal
    /// the helper MUST return false. This is the structural
    /// guarantee the invariant pins: the keep-alive flag is
    /// off-by-default at every dispatch site.
    #[test]
    fn keep_running_after_exit_default_is_false() {
        let _g = lock();
        let _env = SetEnvGuard::unset(ENV_KEEP_RUNNING_AFTER_EXIT);
        let _cli = CliFlagGuard::set(false);
        let tmp = tempfile::tempdir().expect("tempdir");
        // No env, no CLI bit, no touch-file → off.
        assert!(!keep_running_after_exit());
        assert!(!keep_running_after_exit_with_workdir(None));
        assert!(!keep_running_after_exit_with_workdir(Some(tmp.path())));
    }

    /// Env-var truthy/falsy parsing — every spelling the brief
    /// promises, plus the negative cases that MUST NOT activate.
    #[test]
    fn keep_running_after_exit_env_var_activates() {
        let _g = lock();
        let _cli = CliFlagGuard::set(false);
        // Truthy spellings.
        for v in ["1", "true", "TRUE", "True", "yes", "YES", "on", "ON"] {
            let _env = SetEnvGuard::set(ENV_KEEP_RUNNING_AFTER_EXIT, v);
            assert!(
                keep_running_after_exit(),
                "value {v:?} MUST activate keep-alive",
            );
        }
        // Falsy / unset / garbage spellings — all MUST stay off.
        for v in ["0", "false", "FALSE", "no", "off", "", "garbage", "  "] {
            let _env = SetEnvGuard::set(ENV_KEEP_RUNNING_AFTER_EXIT, v);
            assert!(
                !keep_running_after_exit(),
                "value {v:?} MUST NOT activate keep-alive",
            );
        }
        let _env = SetEnvGuard::unset(ENV_KEEP_RUNNING_AFTER_EXIT);
        assert!(
            !keep_running_after_exit(),
            "unset env var MUST NOT activate keep-alive",
        );
    }

    /// Pure-parser witness: every truthy / falsy token resolves
    /// the way the invariant promises. Pinned alongside the
    /// integration witness above so a future maintainer can
    /// mutation-test the parser without spawning a process.
    #[test]
    fn parse_truthy_env_value_canonical_cases() {
        for v in ["1", "true", "TRUE", "True", "yes", "YES", "on", "ON", " 1 ", "  true\t"] {
            assert!(
                parse_truthy_env_value(Some(v)),
                "value {v:?} MUST parse truthy",
            );
        }
        for v in ["0", "false", "FALSE", "no", "off", "", "garbage", "    "] {
            assert!(
                !parse_truthy_env_value(Some(v)),
                "value {v:?} MUST parse falsy",
            );
        }
        assert!(
            !parse_truthy_env_value(None),
            "absent value (None) MUST parse falsy",
        );
    }

    /// Touch-file activation — write `<dir>/KEEP_RUNNING`,
    /// point the helper at that dir, assert true. The env var
    /// is unset for the duration so the touch-file branch is
    /// the ONLY positive signal.
    #[test]
    fn keep_running_after_exit_touch_file_activates() {
        let _g = lock();
        let _env = SetEnvGuard::unset(ENV_KEEP_RUNNING_AFTER_EXIT);
        let _cli = CliFlagGuard::set(false);
        let tmp = tempfile::tempdir().expect("tempdir");
        // Before the touch file exists, no activation.
        assert!(!keep_running_after_exit_with_workdir(Some(tmp.path())));
        // Drop the touch file; activation flips to true.
        let touch = tmp.path().join(KEEP_RUNNING_TOUCH_FILE);
        std::fs::write(&touch, b"").expect("write touch file");
        assert!(keep_running_after_exit_with_workdir(Some(tmp.path())));
        // Removing the touch file flips back to false.
        std::fs::remove_file(&touch).expect("rm touch file");
        assert!(!keep_running_after_exit_with_workdir(Some(tmp.path())));
    }

    /// CLI-flag activation — composes with env / touch-file via
    /// OR (any one signal activates). Pin the precedence so a
    /// future refactor flipping it to AND would trip the witness.
    #[test]
    fn keep_running_after_exit_cli_flag_activates() {
        let _g = lock();
        let _env = SetEnvGuard::unset(ENV_KEEP_RUNNING_AFTER_EXIT);
        let _cli = CliFlagGuard::set(true);
        // Env unset, no touch file, but CLI bit on → keep-alive on.
        assert!(keep_running_after_exit());
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(keep_running_after_exit_with_workdir(Some(tmp.path())));
    }

    /// CLI-flag-name spelling — pinned so a typo in the long-form
    /// flag (`--keep-running-after-exit`) trips the witness rather
    /// than silently breaking the operator-facing surface in a
    /// future test binary that consumes the constant.
    #[test]
    fn cli_flag_name_pinned() {
        assert_eq!(
            CLI_FLAG_KEEP_RUNNING_AFTER_EXIT,
            "--keep-running-after-exit",
        );
        assert_eq!(
            ENV_KEEP_RUNNING_AFTER_EXIT,
            "RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT",
        );
        assert_eq!(KEEP_RUNNING_TOUCH_FILE, "KEEP_RUNNING");
    }

    /// `INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01` Drop-side witness —
    /// drives a mock harness whose Drop tracks "did teardown
    /// run?" against both branches of the keep-alive bit and
    /// asserts the bit faithfully gates teardown. The mock
    /// stands in for `KernelInstance::Drop`,
    /// `OtelPusherSupervisor::Drop`, and the `Tier3Reporter`
    /// cleanup branch — every cleanup site in the harness
    /// composes the same way (env-var read at Drop time;
    /// branch on the result).
    #[test]
    fn harness_drop_skips_teardown_when_keep_running() {
        struct MockHarness {
            work_dir: PathBuf,
            tore_down: std::rc::Rc<std::cell::Cell<bool>>,
        }
        impl Drop for MockHarness {
            fn drop(&mut self) {
                if keep_running_after_exit_with_workdir(Some(&self.work_dir)) {
                    return;
                }
                self.tore_down.set(true);
            }
        }
        let _g = lock();

        // Default (no signal): teardown MUST run.
        let _env = SetEnvGuard::unset(ENV_KEEP_RUNNING_AFTER_EXIT);
        let _cli = CliFlagGuard::set(false);
        let tmp = tempfile::tempdir().expect("tempdir");
        let tore_down = std::rc::Rc::new(std::cell::Cell::new(false));
        {
            let _h = MockHarness {
                work_dir: tmp.path().to_path_buf(),
                tore_down: tore_down.clone(),
            };
        }
        assert!(
            tore_down.get(),
            "default branch MUST run teardown (no signal active)",
        );
        drop(_env);
        drop(_cli);

        // Env-var on: teardown MUST be skipped.
        let _env = SetEnvGuard::set(ENV_KEEP_RUNNING_AFTER_EXIT, "1");
        let _cli = CliFlagGuard::set(false);
        let tmp = tempfile::tempdir().expect("tempdir");
        let tore_down = std::rc::Rc::new(std::cell::Cell::new(false));
        {
            let _h = MockHarness {
                work_dir: tmp.path().to_path_buf(),
                tore_down: tore_down.clone(),
            };
        }
        assert!(
            !tore_down.get(),
            "env-var branch MUST skip teardown (RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT=1)",
        );
        drop(_env);
        drop(_cli);

        // Touch-file on, env unset: teardown MUST be skipped.
        let _env = SetEnvGuard::unset(ENV_KEEP_RUNNING_AFTER_EXIT);
        let _cli = CliFlagGuard::set(false);
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join(KEEP_RUNNING_TOUCH_FILE), b"")
            .expect("write touch file");
        let tore_down = std::rc::Rc::new(std::cell::Cell::new(false));
        {
            let _h = MockHarness {
                work_dir: tmp.path().to_path_buf(),
                tore_down: tore_down.clone(),
            };
        }
        assert!(
            !tore_down.get(),
            "touch-file branch MUST skip teardown (work_dir/KEEP_RUNNING present)",
        );
        drop(_env);
        drop(_cli);

        // CLI-flag on, env unset, no touch file: teardown MUST
        // be skipped. Composes with the other signals via OR.
        let _env = SetEnvGuard::unset(ENV_KEEP_RUNNING_AFTER_EXIT);
        let _cli = CliFlagGuard::set(true);
        let tmp = tempfile::tempdir().expect("tempdir");
        let tore_down = std::rc::Rc::new(std::cell::Cell::new(false));
        {
            let _h = MockHarness {
                work_dir: tmp.path().to_path_buf(),
                tore_down: tore_down.clone(),
            };
        }
        assert!(
            !tore_down.get(),
            "CLI-flag branch MUST skip teardown",
        );
    }

    /// Banner emission MUST NOT panic on any reasonable input
    /// (work_dir present-or-missing, dashboard_port present-or-
    /// missing, compose-stack present-or-missing). The banner
    /// runs in a panic-likely surface (end of a failed test run);
    /// a panic from the banner itself would mask the underlying
    /// failure.
    #[test]
    fn print_keep_alive_banner_never_panics() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let compose_file = PathBuf::from("/tmp/synthetic-compose.yml");
        let compose = ComposeStackBanner {
            project: "raxis-live-e2e-test",
            compose_file: &compose_file,
        };
        // Every arm of the optional parameters MUST emit cleanly.
        print_keep_alive_banner(tmp.path(), Some(19820), Some(compose.clone()));
        print_keep_alive_banner(tmp.path(), None, Some(compose.clone()));
        print_keep_alive_banner(tmp.path(), Some(19820), None);
        print_keep_alive_banner(tmp.path(), None, None);
        // Even if the work_dir is non-existent, the banner just
        // prints the path — no FS access for the rendering itself.
        let nonexistent = PathBuf::from("/dev/null/no-such-data-dir");
        print_keep_alive_banner(&nonexistent, Some(9820), None);
    }
}
