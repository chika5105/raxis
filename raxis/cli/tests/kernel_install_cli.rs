//! Integration tests for `raxis kernel install` and
//! `raxis kernel uninstall` (user-level only — `--system` requires
//! root and would fail closed in CI; that path is exercised
//! manually).
//!
//! Normative reference: `specs/v2/kernel-lifecycle.md §3` (daemon
//! mode), §4.1 (Linux user-level systemd unit), §5.1 (macOS
//! user-level launch agent).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn raxis_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_raxis"))
}

fn run_in(home: &Path, data_dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(raxis_bin())
        .env("HOME", home)
        // The CLI auto-detects `raxis-kernel` next to itself, in
        // $PATH, and at /usr/local/bin/raxis-kernel. In CI we want
        // the test to pass without `raxis-kernel` being installed,
        // so we always pass --binary explicitly.
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn raxis")
}

fn fake_kernel_binary(tmp: &Path) -> PathBuf {
    // The `kernel install` path requires the binary to exist so
    // the auto-detector can validate it. We create an empty
    // executable file in the test sandbox.
    let path = tmp.join("fake-raxis-kernel");
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .unwrap();
    f.write_all(b"#!/bin/sh\nexec /bin/false\n").unwrap();
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

#[cfg(target_os = "linux")]
fn expected_unit_path(home: &Path) -> PathBuf {
    home.join(".config/systemd/user/raxis-kernel.service")
}

#[cfg(target_os = "macos")]
fn expected_unit_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents/com.raxis.kernel.plist")
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn install_writes_unit_file_to_user_path_with_binary_and_data_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let data_dir = tmp.path().join("data");
    let bin = fake_kernel_binary(tmp.path());

    let out = run_in(
        &home,
        &data_dir,
        &[
            "kernel", "install",
            "--binary", bin.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let unit = expected_unit_path(&home);
    assert!(unit.exists(), "unit file not at {}", unit.display());
    let body = std::fs::read_to_string(&unit).unwrap();
    assert!(body.contains(bin.to_str().unwrap()), "body missing binary: {body}");
    assert!(body.contains(data_dir.to_str().unwrap()), "body missing data_dir: {body}");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn install_refuses_to_overwrite_without_force_then_succeeds_with_force() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let data_dir = tmp.path().join("data");
    let bin = fake_kernel_binary(tmp.path());
    let bin2_dir = tmp.path().join("bin2-dir");
    std::fs::create_dir_all(&bin2_dir).unwrap();
    let bin2 = fake_kernel_binary(&bin2_dir);

    let out1 = run_in(
        &home,
        &data_dir,
        &["kernel", "install", "--binary", bin.to_str().unwrap()],
    );
    assert!(out1.status.success());

    let out2 = run_in(
        &home,
        &data_dir,
        &["kernel", "install", "--binary", bin2.to_str().unwrap()],
    );
    assert!(!out2.status.success(), "second install must refuse without --force");
    let stderr = String::from_utf8_lossy(&out2.stderr);
    assert!(stderr.contains("--force"), "stderr should mention --force: {stderr}");

    let unit = expected_unit_path(&home);
    let body_after = std::fs::read_to_string(&unit).unwrap();
    assert!(body_after.contains(bin.to_str().unwrap()),
        "second install must NOT have overwritten the unit file");

    // Now retry with --force.
    let out3 = run_in(
        &home,
        &data_dir,
        &["kernel", "install", "--binary", bin2.to_str().unwrap(), "--force"],
    );
    assert!(out3.status.success(), "stderr: {}", String::from_utf8_lossy(&out3.stderr));
    let body_forced = std::fs::read_to_string(&unit).unwrap();
    assert!(
        body_forced.contains(bin2.to_str().unwrap()),
        "after --force the unit must reflect the new binary path",
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn uninstall_removes_unit_file() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let data_dir = tmp.path().join("data");
    let bin = fake_kernel_binary(tmp.path());

    let out = run_in(
        &home,
        &data_dir,
        &["kernel", "install", "--binary", bin.to_str().unwrap()],
    );
    assert!(out.status.success());

    let unit = expected_unit_path(&home);
    assert!(unit.exists());

    let out = run_in(&home, &data_dir, &["kernel", "uninstall"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(!unit.exists(), "unit file should be removed");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn uninstall_when_not_installed_succeeds_with_friendly_message() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let data_dir = tmp.path().join("data");
    let out = run_in(&home, &data_dir, &["kernel", "uninstall"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Not installed"), "stdout: {stdout}");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn unknown_kernel_subcommand_suggests_install_or_uninstall() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let data_dir = tmp.path().join("data");
    let out = run_in(&home, &data_dir, &["kernel", "instal"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("install") || stderr.contains("uninstall"),
        "stderr should mention install/uninstall via closeness: {stderr}",
    );
}
