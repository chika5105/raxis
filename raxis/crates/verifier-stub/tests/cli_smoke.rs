// raxis-verifier-stub::tests::cli_smoke — Process-level smoke tests.
//
// These tests `execve()` the actual stub binary the kernel would spawn,
// rather than calling the lib functions in-process, so we exercise the
// real `#[tokio::main]` boot path, env-var ingestion, and process exit
// codes. They cover a much narrower surface than the kernel's
// `witness_round_trip_via_stub.rs` integration test (which stands up a
// real UDS server and asserts the kernel-side handler effects); their
// purpose is to catch regressions in the stub's standalone behaviour
// — missing-env handling, skip-send branch, malformed body — without
// pulling in the kernel.
//
// Path discovery: cargo sets `CARGO_BIN_EXE_<name>` for tests in the
// SAME crate as the binary, which is exactly our setup. We use
// `env!("CARGO_BIN_EXE_raxis-verifier-stub")` rather than navigating
// `current_exe()` parents, because the latter is brittle to changes in
// `target/` layout.

use std::process::Command;

const STUB_BIN: &str = env!("CARGO_BIN_EXE_raxis-verifier-stub");

/// Build a `Command` that executes the stub binary with EVERY env var
/// from the parent stripped except the ones we explicitly set. Mirrors
/// the production spawn envelope (`Command::env_clear()` in the
/// kernel's `verifier_runner.rs`), so a test that depends on inherited
/// PATH (or any other parent env) cannot pass here by accident.
fn empty_envelope() -> Command {
    let mut cmd = Command::new(STUB_BIN);
    cmd.env_clear();
    cmd
}

#[test]
fn exit_code_2_when_no_env_vars_are_set() {
    // The stub MUST refuse to send anything if it cannot identify the
    // task / token / socket, regardless of what the operator-supplied
    // verifier binary thinks it should do. Pin exit code 2 (MissingEnv)
    // so the integration test can distinguish "envelope is wrong" from
    // "everything was right but the kernel rejected the witness" (1).
    let status = empty_envelope().status().expect("spawn stub");
    assert_eq!(
        status.code(),
        Some(2),
        "expected MissingEnv exit code 2 with empty env, got {status:?}"
    );
}

#[test]
fn exit_code_2_when_only_socket_is_missing() {
    // Pin that even with four of five required vars set, missing the
    // socket path is fatal. Tests the per-var error precision.
    let status = empty_envelope()
        .env("RAXIS_VERIFIER_TOKEN", "tok")
        .env("RAXIS_TASK_ID", "task-1")
        .env("RAXIS_GATE_TYPE", "test-gate")
        .env(
            "RAXIS_EVALUATION_SHA",
            "abcd1234abcd1234abcd1234abcd1234abcd1234",
        )
        .status()
        .expect("spawn stub");
    assert_eq!(
        status.code(),
        Some(2),
        "expected MissingEnv exit code 2, got {status:?}"
    );
}

#[test]
fn exit_code_3_when_socket_path_does_not_exist() {
    // All env is correct, but the kernel socket simply doesn't exist —
    // the stub should fail at connect() with IoError (3), not panic and
    // not fall back to MissingEnv (2). Pinning this lets the integration
    // test trust that exit code 2 means "the test harness did not set
    // env correctly", which is a much more actionable signal than "exit
    // 3 means something I/O-shaped happened".
    let status = empty_envelope()
        .env("RAXIS_VERIFIER_TOKEN", "tok")
        .env("RAXIS_TASK_ID", "task-1")
        .env("RAXIS_GATE_TYPE", "test-gate")
        .env(
            "RAXIS_EVALUATION_SHA",
            "abcd1234abcd1234abcd1234abcd1234abcd1234",
        )
        .env(
            "RAXIS_KERNEL_SOCKET",
            "/tmp/raxis-stub-no-such-socket-9f2c7b.sock",
        )
        .status()
        .expect("spawn stub");
    assert_eq!(
        status.code(),
        Some(3),
        "expected IoError exit code 3 for missing socket, got {status:?}"
    );
}

#[test]
fn exit_code_2_when_result_class_env_var_is_invalid() {
    // We deliberately picked a value that's CLOSE to a real one ("Passed"
    // vs "Pass") to catch a future loosening of `parse_result_class`
    // that would silently accept the wrong spelling.
    let status = empty_envelope()
        .env("RAXIS_VERIFIER_TOKEN", "tok")
        .env("RAXIS_TASK_ID", "task-1")
        .env("RAXIS_GATE_TYPE", "test-gate")
        .env(
            "RAXIS_EVALUATION_SHA",
            "abcd1234abcd1234abcd1234abcd1234abcd1234",
        )
        .env("RAXIS_KERNEL_SOCKET", "/tmp/whatever.sock")
        .env("RAXIS_STUB_RESULT_CLASS", "Passed") // close to "Pass" — must NOT be accepted
        .status()
        .expect("spawn stub");
    // We exit BEFORE attempting to connect, so this stays at MissingEnv.
    assert_eq!(
        status.code(),
        Some(2),
        "expected MissingEnv exit code 2 for invalid RAXIS_STUB_RESULT_CLASS, got {status:?}"
    );
}
