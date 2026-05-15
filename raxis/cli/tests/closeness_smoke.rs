// raxis-cli — End-to-end smoke test for the "did you mean" closeness
// suggestion machinery.
//
// Spawns the actual `raxis` binary against an empty data dir and a
// known-bogus subcommand, then asserts the rendered stderr line
// contains both:
//
//   * the canonical `unknown subcommand: "<typo>"` prefix, AND
//   * a `Did you mean ...` suggestion that names the expected
//     correction.
//
// We intentionally exercise the binary (not the in-process `run`
// function) so this test catches regressions in the dispatcher
// wiring AND in the `Display` impl of `CliError::Usage`. The
// catalog-vs-dispatcher consistency is already pinned by unit tests
// in `cli/src/main.rs::catalog_consistency_tests`.

use std::process::Command;

fn raxis_bin() -> std::path::PathBuf {
    // `cargo test` builds binaries into `<target>/<profile>/<binary>`
    // and exposes the path via `CARGO_BIN_EXE_<bin_name>`.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_raxis"))
}

fn empty_data_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir for empty data dir")
}

fn run_with_args(args: &[&str]) -> (i32, String, String) {
    let data_dir = empty_data_dir();
    let out = Command::new(raxis_bin())
        .args(["--data-dir", &data_dir.path().display().to_string()])
        .args(args)
        .output()
        .expect("spawn raxis binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn typo_for_top_level_command_emits_did_you_mean_line() {
    // "ceert" -> "cert" via single-insertion. Output goes to stderr
    // with exit code 1 (see `fn main` in cli/src/main.rs).
    let (code, _stdout, stderr) = run_with_args(&["ceert"]);
    assert_eq!(
        code, 1,
        "raxis should exit 1 on usage error; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("unknown subcommand: \"ceert\""),
        "stderr should label the unknown subcommand verbatim; got {stderr:?}",
    );
    assert!(
        stderr.contains("Did you mean `cert`"),
        "stderr should suggest the closest match; got {stderr:?}",
    );
}

#[test]
fn typo_for_cert_subcommand_emits_did_you_mean_line() {
    // `mintt` -> `mint`.
    let (code, _stdout, stderr) = run_with_args(&["cert", "mintt"]);
    assert_eq!(
        code, 1,
        "raxis should exit 1 on usage error; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("unknown cert sub-command: \"mintt\""),
        "stderr should label the unknown sub-command verbatim; got {stderr:?}",
    );
    assert!(
        stderr.contains("`mint`"),
        "stderr should suggest `mint`; got {stderr:?}",
    );
}

#[test]
fn typo_for_initiative_subcommand_suggests_quarantine() {
    let (code, _stdout, stderr) = run_with_args(&["initiative", "quaratine"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("unknown initiative sub-command: \"quaratine\""),
        "got {stderr:?}",
    );
    assert!(
        stderr.contains("`quarantine`"),
        "expected `quarantine` suggestion; got {stderr:?}",
    );
}

#[test]
fn typo_for_plan_subcommand_suggests_approve() {
    // `apporve` -> `approve` via Damerau transposition.
    let (code, _stdout, stderr) = run_with_args(&["plan", "apporve"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("unknown plan sub-command: \"apporve\""),
        "got {stderr:?}",
    );
    assert!(stderr.contains("`approve`"), "got {stderr:?}",);
}

#[test]
fn unknown_subcommand_with_no_close_matches_omits_did_you_mean() {
    let (code, _stdout, stderr) = run_with_args(&["xyzzy"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("unknown subcommand: \"xyzzy\""),
        "got {stderr:?}",
    );
    assert!(
        !stderr.contains("Did you mean"),
        "should NOT suggest anything for far-from-everything input; got {stderr:?}",
    );
}
