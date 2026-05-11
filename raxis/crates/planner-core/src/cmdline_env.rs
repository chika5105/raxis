//! Cmdline-based env hydration for guest planner-harness binaries.
//!
//! The Apple-VZ substrate cannot inherit a process environment into
//! the guest (there is no `Command::env` analogue at the AVF surface;
//! the `VZLinuxBootLoader` only exposes a kernel command-line). The
//! substrate therefore folds the kernel-stamped
//! [`raxis_isolation::VmSpec::env`] into the kernel command-line as a
//! single base64-encoded token —
//!
//! ```text
//! raxis.envb64=<base64(KEY1=VAL1\nKEY2=VAL2\n…)>
//! ```
//!
//! — and the in-guest /init binary runs [`hydrate_from_proc_cmdline`]
//! (typically from inside `main`, **before** any tokio runtime is
//! constructed) to recover those KV pairs into the process
//! environment. After hydration, `BootContext::from_process` and
//! `KernelTransportConfig::from_process_env` see the same envelope
//! that `Command::env` would produce on the subprocess substrate.
//!
//! ## Why a separate module
//!
//! * Hosts the only `unsafe` surface in the planner-core crate
//!   (`std::env::set_var` is unsafe under `unsafe-op-in-unsafe-fn`),
//!   keeping the rest of `lib.rs` strictly safe code.
//! * Lives behind a Linux-only cfg gate at the consumer end: on
//!   non-Linux hosts (the dev macOS workstation building unit
//!   tests) the function reads no `/proc/cmdline` and falls
//!   silently through.
//!
//! ## Wire-shape pin
//!
//! The token name (`raxis.envb64=`) and the base64 alphabet
//! (`base64::engine::general_purpose::STANDARD`) are pinned by
//! [`isolation-apple-vz/src/config.rs`]. Any change in either side
//! must land in a single commit so the guest can never see a
//! cmdline shape it does not know how to parse.
//!
//! ## Idempotency + precedence
//!
//! Variables already set in the inherited environment **win** over
//! the cmdline token. This is the right precedence because:
//!
//! 1. The kernel-side substrate is the only writer of the cmdline
//!    token, so `set_var` collisions only happen if a buggy /init
//!    wrapper or test harness pre-populated the env. In that case
//!    the existing value is the operator's intent and must not be
//!    silently overwritten.
//! 2. Test fixtures can set env vars directly without losing them
//!    on a subsequent `hydrate_from_proc_cmdline` no-op call.

#![allow(unsafe_code)]

use std::path::Path;

/// Cmdline token the AVF substrate prefixes its base64 env payload
/// with. Pinned by `isolation-apple-vz/src/config.rs`.
pub const CMDLINE_ENV_TOKEN: &str = "raxis.envb64=";

/// Outcome of [`hydrate_from_proc_cmdline`] — surfaced so callers
/// can structured-log success or failure without poking at
/// /proc directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrationOutcome {
    /// `/proc/cmdline` was unreadable (typical on macOS or any
    /// host without a procfs). No env vars were set.
    NoProcCmdline {
        /// I/O error string (for log surfacing).
        reason: String,
    },
    /// `/proc/cmdline` was read but did not contain the
    /// `raxis.envb64=` token. No env vars were set.
    NoEnvToken,
    /// `/proc/cmdline` contained a malformed token (bad base64 or
    /// non-UTF-8 payload). No env vars were set; the malformed
    /// token is surfaced verbatim for debugging.
    BadEnvToken {
        /// Failure reason (base64 / utf-8 decode error).
        reason: String,
    },
    /// Hydration succeeded.
    Hydrated {
        /// Number of env vars that were *newly* set by this call
        /// (i.e. not already present in the inherited environment).
        applied: usize,
        /// Number of env vars that were already present and
        /// therefore **kept** at their existing value.
        skipped_already_set: usize,
    },
}

/// Read the guest's `/proc/cmdline` and apply any `raxis.envb64=`
/// envelope into the process environment.
///
/// ## Safety
///
/// Calls `std::env::set_var`, which is `unsafe` since Rust 1.78
/// (Linux's man page for `setenv(3)` warns that concurrent reads
/// from another thread can race). The contract this function pins
/// is that the planner-harness `main` calls it **before** the
/// tokio runtime spins up, so the process is still single-threaded
/// at the call site. The caller is responsible for honouring that
/// contract — this is a load-bearing invariant of the AVF guest
/// boot path documented in [`raxis_planner_orchestrator::main`].
pub fn hydrate_from_proc_cmdline() -> HydrationOutcome {
    hydrate_from_path(Path::new("/proc/cmdline"))
}

/// Path-overridable variant — exists exclusively for the unit
/// tests in this module which point at a tempdir-backed fixture
/// instead of the live `/proc/cmdline`.
pub fn hydrate_from_path(path: &Path) -> HydrationOutcome {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            return HydrationOutcome::NoProcCmdline {
                reason: e.to_string(),
            };
        }
    };
    let token = match raw
        .split_whitespace()
        .find(|tok| tok.starts_with(CMDLINE_ENV_TOKEN))
    {
        Some(tok) => tok,
        None => return HydrationOutcome::NoEnvToken,
    };
    let b64 = &token[CMDLINE_ENV_TOKEN.len()..];
    apply_envb64_payload(b64)
}

/// Decode a single `raxis.envb64=` payload (without the prefix)
/// and apply it. Pulled out of `hydrate_from_path` so unit tests
/// can hammer the parser without standing up a tempdir.
pub fn apply_envb64_payload(b64: &str) -> HydrationOutcome {
    use base64::Engine as _;

    let bytes = match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            return HydrationOutcome::BadEnvToken {
                reason: format!("base64 decode: {e}"),
            };
        }
    };
    let payload = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_owned(),
        Err(e) => {
            return HydrationOutcome::BadEnvToken {
                reason: format!("utf-8 decode: {e}"),
            };
        }
    };

    let mut applied:             usize = 0;
    let mut skipped_already_set: usize = 0;
    for line in payload.split('\n') {
        if line.is_empty() {
            continue;
        }
        let (k, v) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if k.is_empty() {
            continue;
        }
        if std::env::var_os(k).is_some() {
            skipped_already_set += 1;
            continue;
        }
        // SAFETY: documented in the module-level header — the
        // planner-harness `main` calls hydration before its tokio
        // runtime spins up, so the process is single-threaded at
        // the call site. We restrict writes to vars not already
        // in env to keep the function idempotent and avoid
        // stomping on test-harness overrides.
        unsafe {
            std::env::set_var(k, v);
        }
        applied += 1;
    }

    HydrationOutcome::Hydrated {
        applied,
        skipped_already_set,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Synchronisation primitive — these tests mutate the
    /// process-global env, so they MUST NOT interleave. Tokio's
    /// default test runner (`#[test]`) is multithreaded by default,
    /// hence the lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper: clear a key from env safely (the workspace lints
    /// `unsafe_code = deny` so we shadow the unsafe call here).
    fn clear_env(key: &str) {
        // SAFETY: tests are single-threaded under ENV_LOCK.
        unsafe {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn no_proc_cmdline_returns_no_proc_cmdline_outcome() {
        let _g = ENV_LOCK.lock().unwrap();
        let p = std::path::PathBuf::from("/this-does-not-exist-anywhere/cmdline");
        match hydrate_from_path(&p) {
            HydrationOutcome::NoProcCmdline { .. } => {}
            other => panic!("expected NoProcCmdline; got {other:?}"),
        }
    }

    #[test]
    fn cmdline_without_envb64_token_returns_no_env_token() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cmdline");
        std::fs::write(&path, "console=hvc0 reboot=k panic=1\n").unwrap();
        assert_eq!(hydrate_from_path(&path), HydrationOutcome::NoEnvToken);
    }

    #[test]
    fn malformed_base64_returns_bad_env_token() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cmdline");
        std::fs::write(&path, "console=hvc0 raxis.envb64=!!!not-base64!!!\n").unwrap();
        match hydrate_from_path(&path) {
            HydrationOutcome::BadEnvToken { .. } => {}
            other => panic!("expected BadEnvToken; got {other:?}"),
        }
    }

    #[test]
    fn happy_path_hydrates_kvs_into_env() {
        let _g = ENV_LOCK.lock().unwrap();
        // Pre-clean every key the test will write so reruns are
        // deterministic.
        for k in &[
            "RAXIS_TEST_HYDRATE_A",
            "RAXIS_TEST_HYDRATE_B",
            "RAXIS_TEST_HYDRATE_WITH_EQ",
        ] {
            clear_env(k);
        }
        let payload = "RAXIS_TEST_HYDRATE_A=alpha\n\
                       RAXIS_TEST_HYDRATE_B=beta\n\
                       RAXIS_TEST_HYDRATE_WITH_EQ=foo=bar=baz\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cmdline");
        std::fs::write(&path, format!("console=hvc0 raxis.envb64={b64}\n")).unwrap();

        let out = hydrate_from_path(&path);
        match out {
            HydrationOutcome::Hydrated { applied, skipped_already_set } => {
                assert_eq!(applied, 3);
                assert_eq!(skipped_already_set, 0);
            }
            other => panic!("expected Hydrated; got {other:?}"),
        }

        assert_eq!(std::env::var("RAXIS_TEST_HYDRATE_A").unwrap(), "alpha");
        assert_eq!(std::env::var("RAXIS_TEST_HYDRATE_B").unwrap(), "beta");
        // Values legally carry `=`; the parser must split only on the
        // first `=`.
        assert_eq!(
            std::env::var("RAXIS_TEST_HYDRATE_WITH_EQ").unwrap(),
            "foo=bar=baz",
        );

        for k in &[
            "RAXIS_TEST_HYDRATE_A",
            "RAXIS_TEST_HYDRATE_B",
            "RAXIS_TEST_HYDRATE_WITH_EQ",
        ] {
            clear_env(k);
        }
    }

    #[test]
    fn already_set_env_var_wins_over_cmdline_token() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env("RAXIS_TEST_HYDRATE_PRECEDENCE");
        // Pre-set the env var.
        // SAFETY: single-threaded test under ENV_LOCK.
        unsafe {
            std::env::set_var("RAXIS_TEST_HYDRATE_PRECEDENCE", "kept-by-process-env");
        }
        let payload = "RAXIS_TEST_HYDRATE_PRECEDENCE=cmdline-value\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cmdline");
        std::fs::write(&path, format!("raxis.envb64={b64}\n")).unwrap();

        let out = hydrate_from_path(&path);
        match out {
            HydrationOutcome::Hydrated { applied, skipped_already_set } => {
                assert_eq!(applied, 0);
                assert_eq!(skipped_already_set, 1);
            }
            other => panic!("expected Hydrated; got {other:?}"),
        }
        assert_eq!(
            std::env::var("RAXIS_TEST_HYDRATE_PRECEDENCE").unwrap(),
            "kept-by-process-env",
        );
        clear_env("RAXIS_TEST_HYDRATE_PRECEDENCE");
    }

    #[test]
    fn empty_payload_lines_are_skipped() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env("RAXIS_TEST_HYDRATE_EMPTY_LINE_OK");
        let payload = "\n\nRAXIS_TEST_HYDRATE_EMPTY_LINE_OK=value\n\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        let out = apply_envb64_payload(&b64);
        match out {
            HydrationOutcome::Hydrated { applied, skipped_already_set } => {
                assert_eq!(applied, 1);
                assert_eq!(skipped_already_set, 0);
            }
            other => panic!("expected Hydrated; got {other:?}"),
        }
        assert_eq!(
            std::env::var("RAXIS_TEST_HYDRATE_EMPTY_LINE_OK").unwrap(),
            "value",
        );
        clear_env("RAXIS_TEST_HYDRATE_EMPTY_LINE_OK");
    }
}
