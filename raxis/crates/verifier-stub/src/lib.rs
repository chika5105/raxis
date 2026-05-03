// raxis-verifier-stub — Test-only verifier subprocess.
//
// Why this crate exists
// ─────────────────────
// The kernel's `gates::verifier_runner::spawn_verifier` execve()s an
// operator-supplied verifier binary, hands it a spawn envelope through the
// process environment, and expects it to connect back over UDS, send one
// `IpcMessage::WitnessSubmission`, and read one `IpcMessage::WitnessAck` in
// reply (peripherals.md §3.3 + kernel-core.md §2.3). Until this crate landed,
// no test exercised that full round-trip — the cheaper OS-binary suite in
// `kernel/src/gates/verifier_runner.rs::integration` covered the cap, counter,
// env scrub, current-dir, wall-clock kill, and token-row paths, but skipped
// the wire layer entirely because `/usr/bin/true` does not speak the kernel's
// UDS protocol. This crate fills that gap.
//
// Crate split
// ───────────
//   - `lib.rs` (this file): the env parser, exit-code mapper, and submission
//     builder. Pure functions; no I/O. Unit-testable below without spawning
//     a subprocess.
//   - `main.rs`: the binary entry point. A thin `#[tokio::main]` shim that
//     calls into `lib.rs`, opens the UDS, sends the submission, reads the
//     ack, and exits with the lib-supplied code.
//
// Wire shape
// ──────────
// The bytes the stub puts on the socket MUST be identical to what a
// production verifier would put: 4-byte little-endian length prefix +
// `bincode::config::standard()` body, with the body being
// `IpcMessage::WitnessSubmission(WitnessSubmission { ... })`. We get that
// for free by routing through `raxis_ipc::write_frame` (the same helper
// the kernel's planner accept loop uses on the receiving side); reinventing
// the framing here would defeat the purpose of having a single source of
// truth for the wire codec.
//
// Spawn-envelope contract
// ───────────────────────
// `spawn_verifier` sets these env vars (kernel/src/gates/verifier_runner.rs):
//
//   RAXIS_VERIFIER_TOKEN     ← the single-use token (also goes into the body)
//   RAXIS_TASK_ID            ← echo into WitnessSubmission.task_id
//   RAXIS_GATE_TYPE          ← echo into WitnessSubmission.gate_type
//   RAXIS_EVALUATION_SHA     ← echo into WitnessSubmission.evaluation_sha
//   RAXIS_KERNEL_SOCKET      ← path to the UDS we connect to
//   RAXIS_WORKTREE_ROOT      ← unused by the stub; production verifiers cd here
//
// Test knobs (NOT part of the production verifier contract — these are the
// dials tests use to make the stub do something specific):
//
//   RAXIS_STUB_RESULT_CLASS  ← "Pass" | "Fail" | "Inconclusive"; default Pass
//   RAXIS_STUB_BODY_JSON     ← raw JSON body; default `{}`
//   RAXIS_STUB_SLEEP_MS      ← pre-connect sleep in ms (for wall-clock-kill
//                              tests that need the stub to outlive the timeout)
//   RAXIS_STUB_SKIP_SEND     ← if "1", connect but do not send (tests for
//                              kernel-side EOF handling)

#![forbid(unsafe_code)]

use std::env;

use raxis_types::{
    CommitSha, GateType, TaskId, WitnessResultClass, WitnessSubmission,
};

// ---------------------------------------------------------------------------
// Exit codes — narrow surface, every variant has a dedicated test.
// ---------------------------------------------------------------------------

/// Process exit codes the stub returns. Every variant is observable by the
/// test harness — keep them stable; tests assert on these literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Witness was submitted AND the kernel acked with `accepted = true`.
    /// This is the "happy path" production verifiers also follow on success.
    AcceptedPass = 0,
    /// Witness was submitted AND the kernel acked with `accepted = false`
    /// (typed rejection — `EvaluationShaMismatch`, `TaskNotGatesPending`,
    /// or transport-level error). The stub exits non-zero so the kernel's
    /// watcher task and any test harness can distinguish "we sent something
    /// but the kernel said no" from a clean accept.
    Rejected = 1,
    /// One or more REQUIRED env vars were missing. We exit early WITHOUT
    /// touching the socket — the kernel will see the child exit and the
    /// witness handler will never see a submission. Distinct from
    /// `IoError` so tests can pin the missing-env path independently.
    MissingEnv = 2,
    /// Connect, send, or read failed at the syscall level. Includes
    /// "kernel rejected the framing" cases (`FrameError::Eof` mid-read,
    /// short reads, etc.). The stub does NOT retry — production verifiers
    /// re-enter via `RetryTask`, not by reconnecting.
    IoError = 3,
    /// We were told via `RAXIS_STUB_SKIP_SEND=1` to connect but not send.
    /// Production verifiers do not use this path; it exists so tests can
    /// cover the kernel-side EOF / partial-submission code.
    SkippedSend = 4,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

// ---------------------------------------------------------------------------
// Env parsing — separated from I/O for testability.
// ---------------------------------------------------------------------------

/// All inputs the stub harvests from the process environment, in one place.
///
/// Keeping the parsed shape behind a struct (rather than scattering `env::var`
/// calls across the binary) gives us:
///   - One canonical error variant for each missing env var (`MissingEnv`).
///   - A unit test surface that does not need `std::env::set_var` (which is
///     process-global and would force every env test to serialize through
///     a mutex). Tests build `StubEnv` literals instead.
#[derive(Debug, Clone)]
pub struct StubEnv {
    pub verifier_token: String,
    pub task_id:        String,
    pub gate_type:      String,
    pub evaluation_sha: String,
    pub socket_path:    String,
    /// `RAXIS_STUB_RESULT_CLASS` parsed via [`parse_result_class`]; defaults
    /// to `Pass` when the env var is absent or empty.
    pub result_class:   WitnessResultClass,
    /// `RAXIS_STUB_BODY_JSON` parsed as JSON; defaults to `{}` when the env
    /// var is absent. A malformed JSON body short-circuits to `IoError`
    /// (parse error is observable via stderr).
    pub body:           serde_json::Value,
    /// `RAXIS_STUB_SLEEP_MS` parsed as `u64`; defaults to 0. The stub
    /// `tokio::time::sleep`s this long BEFORE the connect, useful for
    /// wall-clock-kill tests that need the stub to outlive the kernel's
    /// `verifier_max_wall_secs` timer.
    pub sleep_ms:       u64,
    /// `RAXIS_STUB_SKIP_SEND` — when `Some("1")`, the stub connects to
    /// the kernel socket and then drops the connection without sending.
    /// Anything else → false (false positives here would break the
    /// happy-path test suite).
    pub skip_send:      bool,
}

/// Errors the env parser can surface. Distinct from runtime I/O errors so
/// tests can pin missing-env vs malformed-env vs socket-failure separately.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StubEnvError {
    #[error("required environment variable {0} is not set or is empty")]
    Missing(&'static str),
    #[error("environment variable {var} has invalid value {value:?}: {reason}")]
    Invalid {
        var:    &'static str,
        value:  String,
        reason: String,
    },
}

/// Read the spawn envelope from the process environment.
///
/// Returns `Err(StubEnvError::Missing)` if any of the FIVE required vars
/// (`RAXIS_VERIFIER_TOKEN`, `RAXIS_TASK_ID`, `RAXIS_GATE_TYPE`,
/// `RAXIS_EVALUATION_SHA`, `RAXIS_KERNEL_SOCKET`) is absent or empty.
///
/// Optional vars (`RAXIS_STUB_*`) get sensible defaults so a test that
/// only sets the five required envelope vars still works.
pub fn parse_stub_env_from_process() -> Result<StubEnv, StubEnvError> {
    let verifier_token = require_env("RAXIS_VERIFIER_TOKEN")?;
    let task_id        = require_env("RAXIS_TASK_ID")?;
    let gate_type      = require_env("RAXIS_GATE_TYPE")?;
    let evaluation_sha = require_env("RAXIS_EVALUATION_SHA")?;
    let socket_path    = require_env("RAXIS_KERNEL_SOCKET")?;

    // RAXIS_STUB_RESULT_CLASS — defaults to Pass for the happy path.
    let result_class = match env::var("RAXIS_STUB_RESULT_CLASS").ok().as_deref() {
        None | Some("") => WitnessResultClass::Pass,
        Some(other) => parse_result_class(other).map_err(|reason| StubEnvError::Invalid {
            var:    "RAXIS_STUB_RESULT_CLASS",
            value:  other.to_owned(),
            reason,
        })?,
    };

    // RAXIS_STUB_BODY_JSON — defaults to `{}`. A malformed body is fatal
    // here because the wire codec (bincode-over-serde) would also reject
    // it and produce a confusing error downstream.
    let body = match env::var("RAXIS_STUB_BODY_JSON").ok().as_deref() {
        None | Some("") => serde_json::json!({}),
        Some(raw) => serde_json::from_str(raw).map_err(|e| StubEnvError::Invalid {
            var:    "RAXIS_STUB_BODY_JSON",
            value:  raw.to_owned(),
            reason: format!("invalid JSON: {e}"),
        })?,
    };

    // RAXIS_STUB_SLEEP_MS — pre-connect sleep, defaults to 0.
    let sleep_ms = match env::var("RAXIS_STUB_SLEEP_MS").ok().as_deref() {
        None | Some("") => 0u64,
        Some(raw) => raw.parse::<u64>().map_err(|e| StubEnvError::Invalid {
            var:    "RAXIS_STUB_SLEEP_MS",
            value:  raw.to_owned(),
            reason: e.to_string(),
        })?,
    };

    // RAXIS_STUB_SKIP_SEND — strictly "1". Anything else (including "true",
    // "yes") is treated as false to avoid false positives.
    let skip_send = matches!(env::var("RAXIS_STUB_SKIP_SEND").as_deref(), Ok("1"));

    Ok(StubEnv {
        verifier_token,
        task_id,
        gate_type,
        evaluation_sha,
        socket_path,
        result_class,
        body,
        sleep_ms,
        skip_send,
    })
}

fn require_env(var: &'static str) -> Result<String, StubEnvError> {
    match env::var(var) {
        Ok(v) if !v.is_empty() => Ok(v),
        // Both "missing" and "empty" land in the same bucket; the kernel's
        // spawn envelope never sets either to "". Distinguishing them
        // would not change the recovery path (operator must re-spawn).
        _ => Err(StubEnvError::Missing(var)),
    }
}

/// Parse the `RAXIS_STUB_RESULT_CLASS` env-var value into a `WitnessResultClass`.
///
/// Pulled out as a free function so the unit tests can exercise it without
/// touching the process environment.
pub fn parse_result_class(raw: &str) -> Result<WitnessResultClass, String> {
    // Match against the canonical `as_sql_str` output (the DDL spelling
    // per kernel-store.md §2.5.1 Table 13). We intentionally do NOT
    // accept lowercase or aliases; production code paths always use the
    // canonical form, and accepting fuzzy variants here would mask real
    // bugs in the test harness.
    match raw {
        "Pass"         => Ok(WitnessResultClass::Pass),
        "Fail"         => Ok(WitnessResultClass::Fail),
        "Inconclusive" => Ok(WitnessResultClass::Inconclusive),
        other => Err(format!(
            "expected one of 'Pass', 'Fail', 'Inconclusive'; got {other:?}",
        )),
    }
}

// ---------------------------------------------------------------------------
// Submission construction
// ---------------------------------------------------------------------------

/// Errors `build_submission` can surface — distinct from `StubEnvError`
/// so tests can pin "envelope-is-malformed-but-parseable" cases (e.g. a
/// 39-char `evaluation_sha`) separately from "envelope is missing".
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("RAXIS_TASK_ID is invalid: {0}")]
    BadTaskId(#[from] raxis_types::TaskIdError),
    #[error("RAXIS_GATE_TYPE is invalid: {0}")]
    BadGateType(#[from] raxis_types::GateTypeError),
    #[error("RAXIS_EVALUATION_SHA is invalid: {0}")]
    BadEvaluationSha(#[from] raxis_types::CommitShaError),
}

/// Build the `WitnessSubmission` the stub will put on the wire from a
/// parsed `StubEnv`.
///
/// Pure function; the env→submission mapping is one-to-one for the four
/// echo fields and routes the result class + body through the test knobs.
/// Validation goes through the canonical `raxis_types::*::parse` constructors,
/// so the stub's wire-shape is the same one a production verifier would
/// emit — a malformed task_id from the env is fatal here rather than
/// silently encoded into a `WitnessSubmission` the kernel would refuse.
pub fn build_submission(env: &StubEnv) -> Result<WitnessSubmission, BuildError> {
    Ok(WitnessSubmission {
        verifier_token: env.verifier_token.clone(),
        task_id:        TaskId::parse(&env.task_id)?,
        gate_type:      GateType::parse(&env.gate_type)?,
        evaluation_sha: CommitSha::parse(&env.evaluation_sha)?,
        result_class:   env.result_class,
        body:           env.body.clone(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_env() -> StubEnv {
        StubEnv {
            verifier_token: "tok".to_owned(),
            task_id:        "task-1".to_owned(),
            gate_type:      "test-gate".to_owned(),
            evaluation_sha: "abcd1234abcd1234abcd1234abcd1234abcd1234".to_owned(),
            socket_path:    "/tmp/kernel.sock".to_owned(),
            result_class:   WitnessResultClass::Pass,
            body:           serde_json::json!({}),
            sleep_ms:       0,
            skip_send:      false,
        }
    }

    // ── parse_result_class ──────────────────────────────────────────────────

    #[test]
    fn parse_result_class_accepts_each_canonical_variant() {
        // The three values the DDL CHECK constraint allows (kernel-store.md
        // §2.5.1 Table 13). Pinned literally — accepting fuzzy variants
        // here would mask test-harness bugs that send unexpected wire
        // values to the kernel.
        assert_eq!(parse_result_class("Pass").unwrap(),         WitnessResultClass::Pass);
        assert_eq!(parse_result_class("Fail").unwrap(),         WitnessResultClass::Fail);
        assert_eq!(parse_result_class("Inconclusive").unwrap(), WitnessResultClass::Inconclusive);
    }

    #[test]
    fn parse_result_class_is_case_sensitive() {
        // Production callers always emit the canonical spelling. Accepting
        // "PASS", "pass", "fail" etc. would let bugs in the test harness
        // pass silently — make them loud.
        for bad in &["PASS", "pass", "fail", "FAIL", "inconclusive"] {
            assert!(parse_result_class(bad).is_err(),
                "case-insensitive accept of {bad:?} would mask harness bugs");
        }
    }

    #[test]
    fn parse_result_class_rejects_unknown_variants_with_diagnostic() {
        let err = parse_result_class("Maybe").unwrap_err();
        // Spec contract: error string lists the three accepted values so
        // a failing test prints a useful message.
        assert!(err.contains("'Pass'") && err.contains("'Fail'") && err.contains("'Inconclusive'"),
            "diagnostic must enumerate accepted values; got {err:?}");
        assert!(err.contains("Maybe"),
            "diagnostic must echo the offending value; got {err:?}");
    }

    // ── build_submission ────────────────────────────────────────────────────

    #[test]
    fn build_submission_echoes_envelope_fields_verbatim() {
        // The four echo fields (`task_id`, `gate_type`, `evaluation_sha`,
        // `verifier_token`) MUST equal what `spawn_verifier` set in the
        // env — the kernel binds the witness to the task by re-checking
        // these against the verifier_run_tokens row, and any munging here
        // would make the stub useless for round-trip tests.
        let env = fixture_env();
        let sub = build_submission(&env).expect("happy-path env must build");
        assert_eq!(sub.verifier_token,            env.verifier_token);
        assert_eq!(sub.task_id.as_str(),          env.task_id);
        assert_eq!(sub.gate_type.as_str(),        env.gate_type);
        assert_eq!(sub.evaluation_sha.as_str(),   env.evaluation_sha);
        assert_eq!(sub.result_class,              env.result_class);
        assert_eq!(sub.body,                      env.body);
    }

    #[test]
    fn build_submission_threads_each_result_class_variant() {
        // Pin all three variants so a future refactor of `WitnessResultClass`
        // (e.g. adding a fourth variant) breaks here and forces a parse
        // change rather than silently sending the wrong byte.
        for class in [
            WitnessResultClass::Pass,
            WitnessResultClass::Fail,
            WitnessResultClass::Inconclusive,
        ] {
            let env = StubEnv { result_class: class, ..fixture_env() };
            let sub = build_submission(&env).expect("class variant must build");
            assert_eq!(sub.result_class, class, "result_class threading broken for {class:?}");
        }
    }

    #[test]
    fn build_submission_threads_arbitrary_body_json() {
        let env = StubEnv {
            body: serde_json::json!({
                "coverage_pct": 92.5,
                "lines_uncovered": 14,
                "evidence": ["src/foo.rs:42", "src/bar.rs:108"],
            }),
            ..fixture_env()
        };
        let sub = build_submission(&env).expect("arbitrary body must build");
        // Round-trip via serde_json::Value::==.
        assert_eq!(sub.body["coverage_pct"], serde_json::json!(92.5));
        assert_eq!(sub.body["lines_uncovered"], serde_json::json!(14));
        assert_eq!(sub.body["evidence"][0], serde_json::json!("src/foo.rs:42"));
    }

    #[test]
    fn build_submission_rejects_short_evaluation_sha() {
        // Negative pin: the kernel's witness handler rejects a 39-char
        // evaluation_sha at admission time, but the stub catches the
        // shape error earlier so a misconfigured test fails with a clear
        // env-side message rather than a confusing kernel-side rejection.
        let env = StubEnv {
            evaluation_sha: "abcd".to_owned(), // 4 chars — way too short
            ..fixture_env()
        };
        let err = build_submission(&env).expect_err("4-char SHA must fail");
        assert!(matches!(err, BuildError::BadEvaluationSha(_)),
            "expected BadEvaluationSha, got {err:?}");
    }

    #[test]
    fn build_submission_rejects_empty_task_id() {
        let env = StubEnv { task_id: String::new(), ..fixture_env() };
        let err = build_submission(&env).expect_err("empty task_id must fail");
        assert!(matches!(err, BuildError::BadTaskId(_)),
            "expected BadTaskId, got {err:?}");
    }

    #[test]
    fn build_submission_rejects_invalid_gate_type_chars() {
        // GateType::parse rejects characters outside [A-Za-z0-9_-].
        let env = StubEnv {
            gate_type: "test-gate!".to_owned(),
            ..fixture_env()
        };
        let err = build_submission(&env).expect_err("gate type with '!' must fail");
        assert!(matches!(err, BuildError::BadGateType(_)),
            "expected BadGateType, got {err:?}");
    }

    // ── ExitCode ────────────────────────────────────────────────────────────

    #[test]
    fn exit_codes_are_stable_integers() {
        // Pinned because the integration test in
        // `kernel/tests/witness_round_trip_via_stub.rs` asserts on these
        // literal values to distinguish the stub's outcome from spawn /
        // shell errors. Renumbering any of these breaks that test loudly.
        assert_eq!(ExitCode::AcceptedPass.as_i32(), 0);
        assert_eq!(ExitCode::Rejected.as_i32(),     1);
        assert_eq!(ExitCode::MissingEnv.as_i32(),   2);
        assert_eq!(ExitCode::IoError.as_i32(),      3);
        assert_eq!(ExitCode::SkippedSend.as_i32(),  4);
    }

    // ── parse_stub_env_from_process ─────────────────────────────────────────
    //
    // These tests touch process-wide state via `std::env::set_var` /
    // `remove_var`, so they MUST serialize through one mutex. Running them
    // in parallel would have one test reading a partially-mutated env.
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_all_stub_env_vars() {
        for var in &[
            "RAXIS_VERIFIER_TOKEN", "RAXIS_TASK_ID", "RAXIS_GATE_TYPE",
            "RAXIS_EVALUATION_SHA", "RAXIS_KERNEL_SOCKET", "RAXIS_WORKTREE_ROOT",
            "RAXIS_STUB_RESULT_CLASS", "RAXIS_STUB_BODY_JSON",
            "RAXIS_STUB_SLEEP_MS", "RAXIS_STUB_SKIP_SEND",
        ] {
            std::env::remove_var(var);
        }
    }

    fn set_minimal_required_env() {
        std::env::set_var("RAXIS_VERIFIER_TOKEN", "tok");
        std::env::set_var("RAXIS_TASK_ID",        "task-1");
        std::env::set_var("RAXIS_GATE_TYPE",      "test-gate");
        std::env::set_var("RAXIS_EVALUATION_SHA", "abcd1234abcd1234abcd1234abcd1234abcd1234");
        std::env::set_var("RAXIS_KERNEL_SOCKET",  "/tmp/kernel.sock");
    }

    #[test]
    fn parse_env_succeeds_with_minimal_required_set() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all_stub_env_vars();
        set_minimal_required_env();
        let env = parse_stub_env_from_process().expect("minimal env must parse");
        assert_eq!(env.verifier_token, "tok");
        assert_eq!(env.task_id, "task-1");
        assert_eq!(env.gate_type, "test-gate");
        assert_eq!(env.socket_path, "/tmp/kernel.sock");
        assert_eq!(env.result_class, WitnessResultClass::Pass, "default class is Pass");
        assert_eq!(env.body, serde_json::json!({}), "default body is empty object");
        assert_eq!(env.sleep_ms, 0, "default sleep is 0");
        assert!(!env.skip_send, "default skip_send is false");
        clear_all_stub_env_vars();
    }

    #[test]
    fn parse_env_fails_on_each_missing_required_var() {
        // For every required var, set the other four and confirm we get
        // back exactly that var's name in the error. This is the strongest
        // shape pin possible — it survives renaming any single var.
        let required = [
            "RAXIS_VERIFIER_TOKEN", "RAXIS_TASK_ID", "RAXIS_GATE_TYPE",
            "RAXIS_EVALUATION_SHA", "RAXIS_KERNEL_SOCKET",
        ];
        for missing_var in &required {
            let _g = ENV_LOCK.lock().unwrap();
            clear_all_stub_env_vars();
            set_minimal_required_env();
            std::env::remove_var(missing_var);
            let err = parse_stub_env_from_process().unwrap_err();
            assert_eq!(err, StubEnvError::Missing(missing_var),
                "expected Missing({missing_var}), got {err:?}");
            clear_all_stub_env_vars();
        }
    }

    #[test]
    fn empty_required_var_is_treated_as_missing() {
        // Setting an env var to "" is the same as not setting it for our
        // purposes — production spawn envelopes never set "", and a
        // false-positive (treating "" as a real value) would forward
        // garbage to the kernel.
        let _g = ENV_LOCK.lock().unwrap();
        clear_all_stub_env_vars();
        set_minimal_required_env();
        std::env::set_var("RAXIS_TASK_ID", "");
        let err = parse_stub_env_from_process().unwrap_err();
        assert_eq!(err, StubEnvError::Missing("RAXIS_TASK_ID"));
        clear_all_stub_env_vars();
    }

    #[test]
    fn parse_env_accepts_optional_result_class_override() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all_stub_env_vars();
        set_minimal_required_env();
        std::env::set_var("RAXIS_STUB_RESULT_CLASS", "Inconclusive");
        let env = parse_stub_env_from_process().unwrap();
        assert_eq!(env.result_class, WitnessResultClass::Inconclusive);
        clear_all_stub_env_vars();
    }

    #[test]
    fn parse_env_rejects_invalid_result_class_with_named_var() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all_stub_env_vars();
        set_minimal_required_env();
        std::env::set_var("RAXIS_STUB_RESULT_CLASS", "BogusValue");
        let err = parse_stub_env_from_process().unwrap_err();
        match err {
            StubEnvError::Invalid { var, value, .. } => {
                assert_eq!(var, "RAXIS_STUB_RESULT_CLASS");
                assert_eq!(value, "BogusValue");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        clear_all_stub_env_vars();
    }

    #[test]
    fn parse_env_accepts_arbitrary_json_body() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all_stub_env_vars();
        set_minimal_required_env();
        std::env::set_var("RAXIS_STUB_BODY_JSON", r#"{"k": 42, "nested": {"v": [1, 2, 3]}}"#);
        let env = parse_stub_env_from_process().unwrap();
        assert_eq!(env.body["k"], serde_json::json!(42));
        assert_eq!(env.body["nested"]["v"][2], serde_json::json!(3));
        clear_all_stub_env_vars();
    }

    #[test]
    fn parse_env_rejects_malformed_json_body() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all_stub_env_vars();
        set_minimal_required_env();
        std::env::set_var("RAXIS_STUB_BODY_JSON", "{not valid json");
        let err = parse_stub_env_from_process().unwrap_err();
        match err {
            StubEnvError::Invalid { var, .. } => {
                assert_eq!(var, "RAXIS_STUB_BODY_JSON");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        clear_all_stub_env_vars();
    }

    #[test]
    fn parse_env_only_treats_literal_one_as_skip_send() {
        // Hardened against false positives: "true", "yes", "y", anything
        // other than literal "1" must NOT enable skip_send. A test that
        // accidentally enables it would silently drop the witness and
        // every assertion downstream would fail in confusing ways.
        let _g = ENV_LOCK.lock().unwrap();
        clear_all_stub_env_vars();
        set_minimal_required_env();
        for non_one in &["true", "yes", "Y", "0", "TRUE", "1.0"] {
            std::env::set_var("RAXIS_STUB_SKIP_SEND", non_one);
            let env = parse_stub_env_from_process().unwrap();
            assert!(!env.skip_send,
                "skip_send must be false for value {non_one:?}, got true");
        }
        // Sanity: the literal "1" actually flips it on.
        std::env::set_var("RAXIS_STUB_SKIP_SEND", "1");
        let env = parse_stub_env_from_process().unwrap();
        assert!(env.skip_send);
        clear_all_stub_env_vars();
    }

    #[test]
    fn parse_env_rejects_non_numeric_sleep_ms() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all_stub_env_vars();
        set_minimal_required_env();
        std::env::set_var("RAXIS_STUB_SLEEP_MS", "soon");
        let err = parse_stub_env_from_process().unwrap_err();
        assert!(matches!(err, StubEnvError::Invalid { var: "RAXIS_STUB_SLEEP_MS", .. }));
        clear_all_stub_env_vars();
    }
}
