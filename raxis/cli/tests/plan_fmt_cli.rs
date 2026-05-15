//! Integration tests for `raxis plan fmt`.
//!
//! Normative reference: `specs/v2/operator-ergonomics.md §10`.
//!
//! Exercises the full subprocess path (argv parsing → dispatch →
//! canonicalize → file write / stdout / --check). Local-only — no
//! kernel, no IPC, no operator key required.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn raxis_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_raxis"))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(raxis_bin())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn raxis")
}

const NON_CANONICAL: &str = "[workspace]   \nlane_id = \"x\"  \n\n\n[[tasks]]\ntask_id = \"a\"";

#[test]
fn check_passes_on_canonical_file() {
    let dir = tempfile::tempdir().unwrap();
    let plan = dir.path().join("plan.toml");
    let canonical = "[workspace]\nlane_id = \"x\"\n\n[[tasks]]\ntask_id = \"a\"\n";
    std::fs::write(&plan, canonical).unwrap();

    let out = run(&["plan", "fmt", plan.to_str().unwrap(), "--check"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn check_fails_on_non_canonical_file() {
    let dir = tempfile::tempdir().unwrap();
    let plan = dir.path().join("plan.toml");
    std::fs::write(&plan, NON_CANONICAL).unwrap();

    let out = run(&["plan", "fmt", plan.to_str().unwrap(), "--check"]);
    assert!(
        !out.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not in canonical form"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn rewrites_in_place_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let plan = dir.path().join("plan.toml");
    std::fs::write(&plan, NON_CANONICAL).unwrap();

    let out = run(&["plan", "fmt", plan.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = std::fs::read_to_string(&plan).unwrap();
    assert!(!after.contains("\n\n\n"), "after: {after:?}");
    assert!(after.ends_with('\n'));
    assert!(!after.contains("   \n"), "after: {after:?}");
}

#[test]
fn stdout_does_not_modify_file() {
    let dir = tempfile::tempdir().unwrap();
    let plan = dir.path().join("plan.toml");
    std::fs::write(&plan, NON_CANONICAL).unwrap();

    let out = run(&["plan", "fmt", plan.to_str().unwrap(), "--stdout"]);
    assert!(out.status.success());

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout_str.contains("\n\n\n"), "stdout: {stdout_str:?}");

    let unchanged = std::fs::read_to_string(&plan).unwrap();
    assert_eq!(
        unchanged, NON_CANONICAL,
        "file was modified despite --stdout"
    );
}

#[test]
fn check_and_stdout_are_mutually_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let plan = dir.path().join("plan.toml");
    std::fs::write(&plan, "[workspace]\nlane_id = \"x\"\n").unwrap();

    let out = run(&["plan", "fmt", plan.to_str().unwrap(), "--check", "--stdout"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("mutually exclusive"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn missing_path_argument_is_rejected() {
    let out = run(&["plan", "fmt"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("requires <plan.toml>"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn invalid_toml_returns_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let plan = dir.path().join("broken.toml");
    std::fs::write(&plan, "[broken\nx = ").unwrap();

    let out = run(&["plan", "fmt", plan.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("invalid TOML"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn preserves_at_raxis_default_annotation() {
    let dir = tempfile::tempdir().unwrap();
    let plan = dir.path().join("plan.toml");
    let with_annotation = "[workspace]\nlane_id = \"x\" # @raxis-default v0.4.0\n";
    std::fs::write(&plan, with_annotation).unwrap();

    let out = run(&["plan", "fmt", plan.to_str().unwrap()]);
    assert!(out.status.success());

    let after = std::fs::read_to_string(&plan).unwrap();
    assert!(
        after.contains("@raxis-default v0.4.0"),
        "annotation lost: after = {after:?}",
    );
}
