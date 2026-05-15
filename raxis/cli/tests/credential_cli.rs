//! Integration tests for `raxis credential list` and
//! `raxis credential rotate <name>`.
//!
//! Normative reference: `specs/v2/extensibility-traits.md §4.4` (CLI
//! surface) and `specs/v2/credential-proxy.md §12.1` (input
//! discipline — `--value <bytes>` is rejected).
//!
//! The tests build the `raxis` binary via cargo and invoke it as a
//! subprocess so the test exercises the actual end-to-end shape
//! (argv parsing → dispatch → file backend → output formatting).
//! We avoid kernel / IPC code paths because both `list` and
//! `rotate` are local-only.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn raxis_bin() -> PathBuf {
    // Cargo sets `CARGO_BIN_EXE_<name>` for every `[[bin]]` target
    // in the same crate at integration-test compile time.
    PathBuf::from(env!("CARGO_BIN_EXE_raxis"))
}

fn make_data_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("credentials")).unwrap();
    std::fs::create_dir_all(dir.path().join("providers")).unwrap();
    dir
}

#[cfg(unix)]
fn write_cred_file(dir: &Path, sub: &str, name_and_ext: &str, body: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join(sub).join(name_and_ext);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .expect("create cred file");
    f.write_all(body).unwrap();
    f.sync_all().unwrap();
}

#[cfg(not(unix))]
fn write_cred_file(dir: &Path, sub: &str, name_and_ext: &str, body: &[u8]) {
    let path = dir.join(sub).join(name_and_ext);
    std::fs::write(path, body).unwrap();
}

fn run_raxis(args: &[&str], data_dir: &Path) -> std::process::Output {
    Command::new(raxis_bin())
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn raxis")
}

fn run_raxis_with_stdin(args: &[&str], data_dir: &Path, stdin: &[u8]) -> std::process::Output {
    let mut child = Command::new(raxis_bin())
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn raxis");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

// ---------------------------------------------------------------------------
// `credential list`
// ---------------------------------------------------------------------------

#[test]
fn list_on_empty_data_dir_prints_no_credentials_message() {
    let tmp = make_data_dir();
    let out = run_raxis(&["credential", "list"], tmp.path());
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("(no credentials registered)"),
        "stdout: {stdout}"
    );
}

#[test]
fn list_renders_credentials_and_providers_alphabetically() {
    let tmp = make_data_dir();
    write_cred_file(
        tmp.path(),
        "credentials",
        "zeta-staging.env",
        b"stage-secret",
    );
    write_cred_file(tmp.path(), "credentials", "alpha-prod.env", b"prod-secret");
    write_cred_file(tmp.path(), "providers", "anthropic.toml", b"api_key=...\n");

    let out = run_raxis(&["credential", "list"], tmp.path());
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let alpha_pos = stdout.find("alpha-prod").expect("alpha-prod in output");
    let providers_pos = stdout
        .find("providers.anthropic")
        .expect("providers.anthropic in output");
    let zeta_pos = stdout.find("zeta-staging").expect("zeta-staging in output");
    assert!(
        alpha_pos < providers_pos && providers_pos < zeta_pos,
        "expected alphabetical ordering. stdout: {stdout}"
    );
    assert!(stdout.contains("NAME"), "stdout has header: {stdout}");
    assert!(stdout.contains("KIND"), "stdout has header: {stdout}");
}

#[test]
fn list_json_emits_valid_json_array() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "x.env", b"shh");
    let out = run_raxis(&["credential", "list", "--json"], tmp.path());
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "x");
    assert_eq!(arr[0]["kind"], "credential");
}

#[test]
fn list_skips_rotation_temp_files() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "real.env", b"real");
    // Simulate a stranded rotation tempfile (the file backend names
    // these `<stem>.<ext>.tmp.<pid>.<nanos>`). The lister must not
    // surface these as credentials.
    write_cred_file(
        tmp.path(),
        "credentials",
        "real.env.tmp.12345.6789",
        b"orphaned",
    );
    let out = run_raxis(&["credential", "list"], tmp.path());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("real"), "stdout: {stdout}");
    assert!(
        !stdout.contains(".tmp."),
        "tmp files must not appear: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// `credential rotate`
// ---------------------------------------------------------------------------

#[test]
fn rotate_replaces_an_existing_credential_atomically() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "pg-staging.env", b"old-password");

    let out = run_raxis_with_stdin(
        &["credential", "rotate", "pg-staging", "--stdin"],
        tmp.path(),
        b"new-password",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let on_disk = std::fs::read(tmp.path().join("credentials/pg-staging.env")).unwrap();
    assert_eq!(on_disk, b"new-password");
}

#[test]
fn rotate_strips_one_trailing_newline_from_stdin() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "x.env", b"old");

    // `printf 'foo\n' | raxis credential rotate x` should write `foo`,
    // not `foo\n`. This matches the behavior of `pbpaste`-style
    // consumers and avoids accidentally introducing trailing
    // whitespace into JWT / API-key style credentials.
    let out = run_raxis_with_stdin(
        &["credential", "rotate", "x", "--stdin"],
        tmp.path(),
        b"new\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let on_disk = std::fs::read(tmp.path().join("credentials/x.env")).unwrap();
    assert_eq!(on_disk, b"new");
}

#[test]
fn rotate_fails_when_credential_does_not_exist() {
    let tmp = make_data_dir();
    let out = run_raxis_with_stdin(
        &["credential", "rotate", "nonexistent", "--stdin"],
        tmp.path(),
        b"new",
    );
    assert!(
        !out.status.success(),
        "rotate must fail when credential is missing"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("nonexistent"),
        "stderr should explain the missing credential: {stderr}",
    );
}

#[test]
fn rotate_rejects_value_argv_flag_to_protect_secret_from_ps_aux() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "x.env", b"old");
    let out = run_raxis(
        &["credential", "rotate", "x", "--value", "the-actual-secret"],
        tmp.path(),
    );
    assert!(
        !out.status.success(),
        "INV-CRED-CLI-01: --value must be rejected"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--value") && (stderr.contains("rejected") || stderr.contains("ps aux")),
        "stderr should mention the rejection reason: {stderr}",
    );
}

#[test]
fn rotate_refuses_empty_input() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "x.env", b"old");
    let out = run_raxis_with_stdin(&["credential", "rotate", "x", "--stdin"], tmp.path(), b"");
    assert!(!out.status.success(), "empty input must be refused");
    let on_disk = std::fs::read(tmp.path().join("credentials/x.env")).unwrap();
    assert_eq!(on_disk, b"old", "credential must not have been touched");
}

#[test]
fn rotate_with_two_input_modes_is_rejected() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "x.env", b"old");
    let out = run_raxis(
        &["credential", "rotate", "x", "--stdin", "--interactive"],
        tmp.path(),
    );
    assert!(!out.status.success(), "ambiguous input mode must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("only one of"), "stderr: {stderr}");
}

#[test]
fn rotate_via_file_input_writes_exact_bytes() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "x.env", b"old");
    let value_path = tmp.path().join("new-value.bin");
    std::fs::write(&value_path, b"binary\x00bytes\xff").unwrap();
    let out = run_raxis(
        &[
            "credential",
            "rotate",
            "x",
            "--file",
            value_path.to_str().unwrap(),
        ],
        tmp.path(),
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let on_disk = std::fs::read(tmp.path().join("credentials/x.env")).unwrap();
    assert_eq!(on_disk, b"binary\x00bytes\xff");
}

// ---------------------------------------------------------------------------
// Subcommand discovery — ensures the help text and the dispatcher
// remain wired together
// ---------------------------------------------------------------------------

#[test]
fn unknown_credential_subcommand_suggests_list_or_rotate() {
    let tmp = make_data_dir();
    let out = run_raxis(&["credential", "lst"], tmp.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("list") || stderr.contains("rotate"),
        "closeness suggester should mention list/rotate. stderr: {stderr}",
    );
}

// ---------------------------------------------------------------------------
// V2_GAPS §C7 — `credential add`
// ---------------------------------------------------------------------------

#[test]
fn add_writes_a_new_credential_with_mode_0600() {
    let tmp = make_data_dir();
    let out = run_raxis_with_stdin(
        &[
            "credential",
            "add",
            "newpg",
            "--type",
            "postgres",
            "--env",
            "staging",
            "--stdin",
        ],
        tmp.path(),
        b"PGHOST=db\nPGPASSWORD=hunter2\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let on_disk = std::fs::read(tmp.path().join("credentials/newpg.env")).unwrap();
    assert_eq!(on_disk, b"PGHOST=db\nPGPASSWORD=hunter2");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(tmp.path().join("credentials/newpg.env")).unwrap();
        assert_eq!(md.mode() & 0o777, 0o600, "add must write 0600");
    }
}

#[test]
fn add_emits_a_credential_registered_record_in_the_local_trail() {
    let tmp = make_data_dir();
    let out = run_raxis_with_stdin(
        &[
            "credential",
            "add",
            "trailpg",
            "--type",
            "postgres",
            "--env",
            "staging",
            "--stdin",
        ],
        tmp.path(),
        b"hello",
    );
    assert!(out.status.success());

    let trail =
        std::fs::read_to_string(tmp.path().join("audit/credential-cli.jsonl")).expect("trail file");
    let line = trail.lines().last().expect("at least one line");
    let v: serde_json::Value = serde_json::from_str(line).expect("valid json");
    assert_eq!(v["kind"], "CredentialRegistered");
    assert_eq!(v["name"], "trailpg");
    assert_eq!(v["proxy_type"], "postgres");
    assert_eq!(v["environment"], "staging");
    assert_eq!(v["backend_kind"], "file");
    assert!(v["emitted_at"].is_i64());
}

#[test]
fn add_refuses_when_credential_already_exists() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "dup.env", b"existing");
    let out = run_raxis_with_stdin(
        &["credential", "add", "dup", "--stdin"],
        tmp.path(),
        b"replacement",
    );
    assert!(!out.status.success(), "must refuse to overwrite via add");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already exists") || stderr.contains("rotate"),
        "stderr should redirect to rotate: {stderr}"
    );
    let on_disk = std::fs::read(tmp.path().join("credentials/dup.env")).unwrap();
    assert_eq!(on_disk, b"existing", "add must not have touched the file");
}

#[test]
fn add_rejects_value_argv_flag() {
    let tmp = make_data_dir();
    let out = run_raxis(
        &["credential", "add", "x", "--value", "the-actual-secret"],
        tmp.path(),
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--value") && stderr.contains("rejected"),
        "stderr: {stderr}"
    );
}

#[test]
fn add_refuses_path_traversal_in_name() {
    let tmp = make_data_dir();
    let out = run_raxis_with_stdin(
        &["credential", "add", "../escape", "--stdin"],
        tmp.path(),
        b"data",
    );
    assert!(!out.status.success(), "must refuse traversal segments");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("traversal") || stderr.contains("path separator"),
        "stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// V2_GAPS §C7 — `credential show`
// ---------------------------------------------------------------------------

#[test]
fn show_prints_metadata_without_revealing_value() {
    let tmp = make_data_dir();
    write_cred_file(
        tmp.path(),
        "credentials",
        "shown.env",
        b"super-secret-value",
    );
    let out = run_raxis(&["credential", "show", "shown"], tmp.path());
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Name:"), "stdout: {stdout}");
    assert!(stdout.contains("File path:"), "stdout: {stdout}");
    assert!(stdout.contains("Permissions:"), "stdout: {stdout}");
    assert!(
        !stdout.contains("super-secret-value"),
        "show MUST NOT reveal the value"
    );
}

#[test]
fn show_json_emits_metadata_object() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "j.env", b"abc");
    let out = run_raxis(&["credential", "show", "j", "--json"], tmp.path());
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(v["name"], "j");
    assert_eq!(v["kind"], "credential");
    assert_eq!(v["size_bytes"], 3);
}

#[test]
fn show_fails_for_unknown_credential() {
    let tmp = make_data_dir();
    let out = run_raxis(&["credential", "show", "missing"], tmp.path());
    assert!(!out.status.success());
}

// ---------------------------------------------------------------------------
// V2_GAPS §C7 — `credential remove`
// ---------------------------------------------------------------------------

#[test]
fn remove_without_force_refuses_and_keeps_file() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "keep.env", b"keep-me");
    let out = run_raxis(&["credential", "remove", "keep"], tmp.path());
    assert!(!out.status.success(), "remove without --force must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--force"),
        "stderr should explain --force: {stderr}"
    );
    assert!(
        tmp.path().join("credentials/keep.env").exists(),
        "file must still exist"
    );
}

#[test]
fn remove_with_force_deletes_file_and_emits_audit_record() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "gone.env", b"goodbye");
    let out = run_raxis(&["credential", "remove", "gone", "--force"], tmp.path());
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !tmp.path().join("credentials/gone.env").exists(),
        "file must be unlinked"
    );

    let trail =
        std::fs::read_to_string(tmp.path().join("audit/credential-cli.jsonl")).expect("trail file");
    let line = trail.lines().last().expect("at least one line");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["kind"], "CredentialRemoved");
    assert_eq!(v["name"], "gone");
    assert_eq!(v["forced"], true);
}

#[test]
fn remove_unknown_credential_fails() {
    let tmp = make_data_dir();
    let out = run_raxis(&["credential", "remove", "ghost", "--force"], tmp.path());
    assert!(!out.status.success());
}

// ---------------------------------------------------------------------------
// V2_GAPS §C7 — `credential verify`
// ---------------------------------------------------------------------------

#[test]
fn verify_passes_for_well_formed_env_credential() {
    let tmp = make_data_dir();
    write_cred_file(
        tmp.path(),
        "credentials",
        "vpg.env",
        b"PGHOST=x\nPGPASSWORD=y\n",
    );
    let out = run_raxis(&["credential", "verify", "vpg"], tmp.path());
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Status:") && stdout.contains("OK"),
        "stdout: {stdout}"
    );
}

#[test]
fn verify_fails_for_empty_body() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "empty.env", b"");
    let out = run_raxis(&["credential", "verify", "empty"], tmp.path());
    assert!(!out.status.success(), "empty body must fail verification");
}

#[test]
fn verify_emits_audit_record_with_success_field() {
    let tmp = make_data_dir();
    write_cred_file(tmp.path(), "credentials", "v.env", b"hello");
    let out = run_raxis(&["credential", "verify", "v"], tmp.path());
    assert!(out.status.success());
    let trail =
        std::fs::read_to_string(tmp.path().join("audit/credential-cli.jsonl")).expect("trail file");
    let line = trail.lines().last().expect("at least one line");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["kind"], "CredentialVerified");
    assert_eq!(v["name"], "v");
    assert_eq!(v["success"], true);
    assert!(v["latency_ms"].is_u64() || v["latency_ms"].is_i64());
}

// ---------------------------------------------------------------------------
// V2_GAPS §C7 — `credential audit`
// ---------------------------------------------------------------------------

#[test]
fn audit_shows_records_for_a_credential() {
    let tmp = make_data_dir();
    // Seed by adding + verifying.
    let _ = run_raxis_with_stdin(
        &[
            "credential",
            "add",
            "trail",
            "--type",
            "postgres",
            "--env",
            "staging",
            "--stdin",
        ],
        tmp.path(),
        b"PGHOST=h\n",
    );
    let _ = run_raxis(&["credential", "verify", "trail"], tmp.path());

    let out = run_raxis(&["credential", "audit", "trail"], tmp.path());
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("CredentialRegistered"), "stdout: {stdout}");
    assert!(stdout.contains("CredentialVerified"), "stdout: {stdout}");
}

#[test]
fn audit_for_unknown_credential_returns_zero_lines() {
    let tmp = make_data_dir();
    let out = run_raxis(&["credential", "audit", "ghost"], tmp.path());
    assert!(out.status.success(), "no-events case must exit zero");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("(no audit events found"),
        "stdout: {stdout}"
    );
}

#[test]
fn audit_json_output_is_array() {
    let tmp = make_data_dir();
    let _ = run_raxis_with_stdin(
        &["credential", "add", "j2", "--type", "postgres", "--stdin"],
        tmp.path(),
        b"PGHOST=h\n",
    );
    let out = run_raxis(&["credential", "audit", "j2", "--json"], tmp.path());
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert!(v.is_array());
    let arr = v.as_array().unwrap();
    assert!(arr.iter().any(|e| e["kind"] == "CredentialRegistered"));
}
