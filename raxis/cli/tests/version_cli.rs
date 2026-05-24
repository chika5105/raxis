// raxis-cli — smoke tests for the conventional top-level version flags.

use std::process::Command;

fn raxis_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_raxis"))
}

fn expected_version() -> String {
    let raw = option_env!("RAXIS_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    raw.strip_prefix('v').unwrap_or(raw).to_owned()
}

fn run_with_arg(arg: &str) -> (i32, String, String) {
    let out = Command::new(raxis_bin())
        .arg(arg)
        .output()
        .expect("spawn raxis binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn long_version_flag_prints_installed_version() {
    let (code, stdout, stderr) = run_with_arg("--version");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, format!("raxis {}\n", expected_version()));
    assert!(
        stderr.is_empty(),
        "version should not write stderr: {stderr:?}"
    );
}

#[test]
fn short_version_flag_prints_installed_version() {
    let (code, stdout, stderr) = run_with_arg("-V");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, format!("raxis {}\n", expected_version()));
    assert!(
        stderr.is_empty(),
        "version should not write stderr: {stderr:?}"
    );
}
