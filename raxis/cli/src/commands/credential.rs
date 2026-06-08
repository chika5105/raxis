// raxis-cli::commands::credential — `raxis credential
// {list,rotate,add,show,remove,verify,audit}`.
//
// Normative reference: `specs/v2/extensibility-traits.md §4.4` (the
// CLI surface for the V2 `CredentialBackend`) and
// `specs/v2/credential-proxy.md §12` (the operator-facing UX).
//
// V2 GA scope:
//   - `list` (read-only, never reveals values).
//   - `rotate <name>` (atomic replace through the file backend).
//   - `add <name>`     — write a NEW credential file.
//   - `show <name>`    — print metadata for one credential.
//   - `remove <name>`  — delete an existing credential file.
//   - `verify <name>`  — V2 structural verification (mode/uid/parse).
//                        Live network probe deferred to V3 once
//                        the per-proxy-type runtimes are wired.
//   - `audit <name>`   — replay the operator-local CLI audit trail
//                        and the kernel's main audit chain to show
//                        every event matching `<name>`.
//
// All commands are local-only: they operate on
// `<data_dir>/credentials/`, `<data_dir>/providers/`, and
// `<data_dir>/audit/credential-cli.jsonl` directly through
// `FileCredentialBackend` and never open the kernel's operator
// socket. The kernel itself does not need to be running to run
// these commands — they are administrative filesystem ops bound by
// 0600 perms + UID match.
//
// Input discipline (INV-CRED-CLI-01 from credential-proxy.md §12.1):
//   - The new value for `add` / `rotate` is read via `--stdin`
//     (default), `--file <path>`, or `--interactive` (terminal
//     prompt with hidden echo).
//   - `--value <bytes>` is REJECTED — see the `[FAIL]` arm below.
//   - The CLI never writes the value to stdout, stderr, the audit
//     event payload, or the shell history.
//
// Audit:
//   - The CLI does NOT emit into the kernel's chained audit segment
//     (it cannot recompute prev_sha256 safely while the kernel is
//     mutating segments). Instead each write subcommand
//     (`add`, `rotate`, `remove`, `verify`) appends a single JSONL
//     record to the operator-local trail at
//     `<data_dir>/audit/credential-cli.jsonl`. The kernel ingests
//     this file on next boot (V3 — design pinned by the wire
//     shape pinned in `audit/src/event.rs::AuditEventKind`).
//   - `list` and `show` are intentionally NOT audited — they read
//     only file metadata that is already visible to the operator
//     UID via `ls -la`.
//   - `actor_fingerprint` is populated from the operator pubkey
//     resolved via `--operator-key` / `RAXIS_OPERATOR_KEY`.
//
// Per-proxy-type validation (kubeconfig YAML, AWS JSON, postgres
// URI, etc.) is intentionally NOT performed by `add` for V2: the
// validators live next to each proxy implementation in
// `crates/credential-proxy-*/`, several of which are still
// `synthesize_response`-only. V2 stores the bytes verbatim and
// accepts a free-form `--type` label that is recorded in the
// audit event for forensic queries. V3 will dispatch on `--type`
// and call the corresponding validator before the write.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use raxis_credentials::{CredentialBackend, CredentialName, CredentialValue, OperatorId};
use raxis_credentials_file::FileCredentialBackend;
use serde::{Deserialize, Serialize};

use crate::errors::CliError;
use crate::GlobalFlags;

// ---------------------------------------------------------------------------
// Sub-command dispatch
// ---------------------------------------------------------------------------

/// `raxis credential list [--json]`.
///
/// Walks `<data_dir>/credentials/*.env` and `<data_dir>/providers/*.toml`
/// and prints one line per credential. The output deliberately
/// omits the value and includes only the metadata reachable
/// through `stat(2)` (size, mtime, mode, owning UID).
pub fn run_list(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut json = false;
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                print_list_help();
                return Ok(());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "credential list: unknown flag {other:?} (try --json)"
                )));
            }
        }
    }

    let data_dir = flags.data_dir();
    let entries = collect_entries(data_dir)?;

    if json {
        let arr: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name":           e.name,
                    "kind":           e.kind.as_str(),
                    "proxy_type":     e.proxy_type,
                    "environment":    e.environment,
                    "description":    e.description,
                    "size_bytes":     e.size_bytes,
                    "modified_unix":  e.modified_unix,
                    "mode_octal":     format!("{:o}", e.mode),
                    "uid":            e.uid,
                })
            })
            .collect();
        let v = serde_json::Value::Array(arr);
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(CliError::from)?
        );
        return Ok(());
    }

    if entries.is_empty() {
        println!("(no credentials registered)");
        println!("  data_dir: {}", data_dir.display());
        println!(
            "  expected layout: {}/credentials/<name>.env  and  {}/providers/<name>.toml",
            data_dir.display(),
            data_dir.display(),
        );
        return Ok(());
    }

    println!(
        "{:<32}  {:<10}  {:<12}  {:<12}  {:>10}  {:<20}  {:>4}  {:>6}",
        "NAME", "KIND", "TYPE", "ENV", "BYTES", "MTIME", "MODE", "UID",
    );
    for e in &entries {
        let mtime = format_mtime(e.modified_unix);
        let mode_warn = if e.mode & 0o177 != 0 { "*" } else { " " };
        println!(
            "{:<32}  {:<10}  {:<12}  {:<12}  {:>10}  {:<20}  {:>4o}{mode_warn} {:>6}",
            e.name,
            e.kind.as_str(),
            blank_or_dash(&e.proxy_type),
            blank_or_dash(&e.environment),
            e.size_bytes,
            mtime,
            e.mode & 0o777,
            e.uid,
        );
    }
    if entries.iter().any(|e| e.mode & 0o177 != 0) {
        eprintln!("\nwarning: entries marked `*` are NOT chmod 0600 — fix with:");
        eprintln!(
            "    chmod 0600 {}/credentials/<name>.env",
            data_dir.display()
        );
        eprintln!(
            "    chmod 0600 {}/providers/<name>.toml",
            data_dir.display()
        );
    }
    Ok(())
}

/// `raxis credential rotate <name> [--stdin | --file <path> | --interactive]`.
///
/// Reads the new credential bytes via the chosen input method,
/// then drives `FileCredentialBackend::rotate` (atomic temp-write
/// followed by `rename` and a parent-dir fsync). The `actor`
/// field of the audit event is the operator's pubkey fingerprint
/// resolved from the CLI flags, so forensic queries can attribute
/// the rotation to a specific operator certificate.
pub fn run_rotate(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut name: Option<String> = None;
    let mut input: InputMode = InputMode::Stdin;
    let mut input_explicit = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_rotate_help();
                return Ok(());
            }
            "--stdin" => {
                if input_explicit {
                    return Err(CliError::Usage(
                        "credential rotate: pick only one of --stdin / --file / --interactive"
                            .into(),
                    ));
                }
                input = InputMode::Stdin;
                input_explicit = true;
            }
            "--file" => {
                if input_explicit {
                    return Err(CliError::Usage(
                        "credential rotate: pick only one of --stdin / --file / --interactive"
                            .into(),
                    ));
                }
                i += 1;
                let path = args.get(i).ok_or_else(|| {
                    CliError::Usage("credential rotate: --file requires a path".into())
                })?;
                input = InputMode::File(PathBuf::from(path));
                input_explicit = true;
            }
            "--interactive" => {
                if input_explicit {
                    return Err(CliError::Usage(
                        "credential rotate: pick only one of --stdin / --file / --interactive"
                            .into(),
                    ));
                }
                input = InputMode::Interactive;
                input_explicit = true;
            }
            "--value" => {
                // INV-CRED-CLI-01: secret-value-on-argv is the
                // single thing this CLI must NEVER allow. Hard
                // reject with an explanatory error so the operator
                // cannot accidentally bypass via copy-paste.
                return Err(CliError::Usage(
                    "credential rotate: --value <bytes> is rejected (would expose the value \
                     in `ps aux`, shell history, and process logs). \
                     Use --stdin (e.g. `cat secret | raxis credential rotate <name>`), \
                     --file <path>, or --interactive instead."
                        .into(),
                ));
            }
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "credential rotate: unknown flag {other:?}"
                )));
            }
            other => {
                if name.is_some() {
                    return Err(CliError::Usage(format!(
                        "credential rotate: unexpected positional {other:?} (the command takes one <name>)"
                    )));
                }
                name = Some(other.to_owned());
            }
        }
        i += 1;
    }

    let name_str = name.ok_or_else(|| {
        CliError::Usage(
            "credential rotate: <name> is required (e.g. `raxis credential rotate postgres-staging --stdin`)"
                .into(),
        )
    })?;
    let cred_name = CredentialName::from(name_str.as_str());

    let data_dir = flags.data_dir();
    let backend = FileCredentialBackend::open(data_dir);

    if !backend.exists(&cred_name) {
        return Err(CliError::Usage(format!(
            "credential rotate: {name_str:?} does not exist under {} \
             (use `raxis credential list` to inspect; rotate is for existing credentials only)",
            data_dir.display(),
        )));
    }

    let new_bytes = read_new_value(&input)?;
    if new_bytes.is_empty() {
        return Err(CliError::Usage(
            "credential rotate: empty input (refusing to rotate to empty bytes)".into(),
        ));
    }
    let new_value = CredentialValue::from_bytes(new_bytes);

    let actor = resolve_actor(flags)?;
    backend
        .rotate(&cred_name, new_value, actor.clone())
        .map_err(|e| {
            CliError::Policy(format!(
                "credential rotate failed for {name_str:?}: {e} (code: {})",
                e.error_code(),
            ))
        })?;
    if let Err(e) = refresh_credential_sidecar_after_rotate(data_dir, &cred_name, &name_str, &actor)
    {
        eprintln!("warning: credential rotated but metadata sidecar refresh failed: {e}");
    }

    println!("Rotated: {name_str}");
    println!(
        "  actor_fingerprint: {}",
        if actor.0.is_empty() {
            "(no operator key supplied; pass --operator-key for forensic attribution)"
        } else {
            actor.0.as_str()
        }
    );
    println!("  data_dir:          {}", data_dir.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredKind {
    Credential,
    Provider,
}

impl CredKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Provider => "provider",
        }
    }
}

#[derive(Debug)]
struct ListEntry {
    name: String,
    kind: CredKind,
    proxy_type: String,
    environment: String,
    description: String,
    size_bytes: u64,
    modified_unix: i64,
    mode: u32,
    uid: u32,
}

fn collect_entries(data_dir: &Path) -> Result<Vec<ListEntry>, CliError> {
    let mut out = Vec::new();
    push_dir(
        &mut out,
        data_dir,
        &data_dir.join("credentials"),
        CredKind::Credential,
        "env",
    )?;
    push_dir(
        &mut out,
        data_dir,
        &data_dir.join("providers"),
        CredKind::Provider,
        "toml",
    )?;
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn push_dir(
    out: &mut Vec<ListEntry>,
    data_dir: &Path,
    dir: &Path,
    kind: CredKind,
    ext: &str,
) -> Result<(), CliError> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(CliError::Io {
                path: dir.display().to_string(),
                source: e,
            });
        }
    };
    for entry in rd {
        let entry = entry.map_err(|e| CliError::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !ft.is_file() {
            continue;
        }
        let path = entry.path();
        let stem_ext = path.extension().and_then(|s| s.to_str());
        if stem_ext != Some(ext) {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if file_name.ends_with(".metadata.toml") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        // Skip rotation tmp files (pattern: <name>.<ext>.tmp.<pid>.<nanos>).
        // The file backend names them under `parent.join(<stem>.<ext>.tmp.<pid>.<nanos>)`,
        // so they end up with a `<stem>.<ext>.tmp.<pid>` *file_stem*. Defensive:
        // skip anything whose stem contains `.tmp.` or `.new`.
        if stem.contains(".tmp.") || stem.ends_with(".new") {
            continue;
        }

        let md = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let (mode, uid) = file_mode_and_uid(&md);
        let modified_unix = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let display_name = match kind {
            CredKind::Credential => stem.to_owned(),
            CredKind::Provider => format!("providers.{stem}"),
        };
        let cred_name = CredentialName::from(display_name.as_str());
        let metadata = read_credential_sidecar(data_dir, &cred_name).unwrap_or_default();
        out.push(ListEntry {
            name: display_name,
            kind,
            proxy_type: metadata.proxy_type,
            environment: metadata.environment,
            description: metadata.description,
            size_bytes: md.len(),
            modified_unix,
            mode,
            uid,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn file_mode_and_uid(md: &std::fs::Metadata) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    (md.mode(), md.uid())
}

#[cfg(not(unix))]
fn file_mode_and_uid(_md: &std::fs::Metadata) -> (u32, u32) {
    (0o600, 0)
}

fn format_mtime(unix: i64) -> String {
    if unix <= 0 {
        return "—".into();
    }
    let secs = unix as u64;
    let days = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    let (y, mo, d) = epoch_days_to_ymd(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Convert "days since 1970-01-01" to a (year, month, day) triple.
/// Pure arithmetic; no chrono dep — the CLI keeps a tight dep
/// closure and the only consumer here is the `list` table.
fn epoch_days_to_ymd(days: i64) -> (i32, u32, u32) {
    // Algorithm from Howard Hinnant's date library (public domain,
    // adapted for i64). Handles all 4-digit years without leap-second
    // weirdness; we don't care about pre-1970 dates here but the
    // formula handles them correctly.
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_final = if m <= 2 { y + 1 } else { y } as i32;
    (y_final, m, d)
}

// ---------------------------------------------------------------------------
// Rotate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum InputMode {
    Stdin,
    File(PathBuf),
    Interactive,
}

fn read_new_value(mode: &InputMode) -> Result<Vec<u8>, CliError> {
    match mode {
        InputMode::Stdin => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| CliError::Io {
                    path: "<stdin>".into(),
                    source: e,
                })?;
            Ok(strip_trailing_newline(buf))
        }
        InputMode::File(path) => {
            let bytes = std::fs::read(path).map_err(|e| CliError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
            Ok(bytes)
        }
        InputMode::Interactive => read_interactive(),
    }
}

fn strip_trailing_newline(mut buf: Vec<u8>) -> Vec<u8> {
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    buf
}

#[cfg(unix)]
fn read_interactive() -> Result<Vec<u8>, CliError> {
    use std::os::unix::io::AsRawFd;

    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(CliError::Usage(
            "credential rotate --interactive requires a terminal on stdin (use --stdin or --file otherwise)"
                .into(),
        ));
    }
    eprint!("Enter new credential value (input hidden, ENTER to commit): ");
    std::io::stderr().flush().ok();

    let fd = stdin.as_raw_fd();
    let saved = disable_echo(fd)?;
    let mut line = String::new();
    let read_res = std::io::stdin().read_line(&mut line);
    restore_termios(fd, &saved);
    eprintln!();
    read_res.map_err(|e| CliError::Io {
        path: "<stdin>".into(),
        source: e,
    })?;

    Ok(strip_trailing_newline(line.into_bytes()))
}

#[cfg(not(unix))]
fn read_interactive() -> Result<Vec<u8>, CliError> {
    Err(CliError::Usage(
        "credential rotate --interactive is only supported on Unix; use --stdin or --file".into(),
    ))
}

#[cfg(unix)]
fn disable_echo(fd: std::os::unix::io::RawFd) -> Result<libc::termios, CliError> {
    #[allow(unsafe_code)]
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return Err(CliError::Usage(format!(
                "credential rotate --interactive: tcgetattr failed: {}",
                std::io::Error::last_os_error(),
            )));
        }
        let saved = t;
        t.c_lflag &= !(libc::ECHO | libc::ECHONL);
        if libc::tcsetattr(fd, libc::TCSANOW, &t) != 0 {
            return Err(CliError::Usage(format!(
                "credential rotate --interactive: tcsetattr failed: {}",
                std::io::Error::last_os_error(),
            )));
        }
        Ok(saved)
    }
}

#[cfg(unix)]
fn restore_termios(fd: std::os::unix::io::RawFd, saved: &libc::termios) {
    #[allow(unsafe_code)]
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, saved);
    }
}

// ---------------------------------------------------------------------------
// Operator-key resolution for the audit `actor_fingerprint`
// ---------------------------------------------------------------------------

fn resolve_actor(flags: &GlobalFlags) -> Result<OperatorId, CliError> {
    // INV-CERT-01: rotations should be attributable. We compute
    // the pubkey fingerprint by reading the operator key file
    // (if supplied) and SHA-256-truncating to the 32-hex-char form
    // pinned by `policy.toml [meta].signed_by`. When no key is
    // provided we still succeed — the audit event records an
    // empty fingerprint and the operator is responsible for
    // calling with --operator-key in production runbooks.
    let path = match &flags.operator_key_path {
        Some(p) => p,
        None => return Ok(OperatorId(String::new())),
    };
    let signing_key = crate::signing::load_operator_key(path)?;
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let full = raxis_crypto::token::sha256_hex(&pubkey_bytes);
    // signed_by uses the SHA-256[:16]-byte = 32-hex-char form
    // (kernel-store.md §2.5.5; mirrors `policy.toml [meta].signed_by`).
    let truncated: String = full.chars().take(32).collect();
    Ok(OperatorId(truncated))
}

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

fn print_list_help() {
    println!(
        r#"raxis credential list — list registered credentials (metadata only).

USAGE:
    raxis [--data-dir <path>] credential list [--json]

FLAGS:
    --json    Emit a JSON array. The text form is the default.

The command reads <data-dir>/credentials/*.env and
<data-dir>/providers/*.toml directly. The kernel does not need
to be running. Values are NEVER printed; only the on-disk
metadata (size, mtime, mode, uid) is reported.
"#,
    );
}

fn print_rotate_help() {
    println!(
        r#"raxis credential rotate — replace a credential's bytes (atomic).

USAGE:
    raxis [--data-dir <path>] [--operator-key <path>] credential rotate <name>
        [--stdin | --file <path> | --interactive]

INPUT METHODS (PICK ONE; --stdin is the default):
    --stdin           Read the new value from stdin (e.g. `cat secret | raxis credential rotate ...`).
    --file <path>     Read the new value from a file on disk.
    --interactive     Prompt with hidden echo (sudo-style).

REJECTED:
    --value <bytes>   The CLI refuses on-argv secrets — they leak into
                      ps aux, shell history, /proc/<pid>/environ, and
                      logs. Use one of the methods above.

The rotate path:
  1. Validates the credential exists at <data-dir>/credentials/<name>.env or <data-dir>/providers/<name>.toml.
  2. Writes a temp file with mode 0600, fsync()s, atomic-renames over the existing path.
  3. fsync()s the parent directory.
  4. Emits one CredentialRotated audit event (when wired with an operator key).

The kernel does not need to be running.
"#,
    );
}

// =========================================================================
// `add`, `show`, `remove`, `verify`, `audit`
// =========================================================================
//
// Shape decisions:
//
//   * `add` writes to `<data_dir>/credentials/<name>.env` (or
//     `<data_dir>/providers/<id>.toml` when the operator passes a
//     `providers.<id>` name) using the same atomic-rename ceremony
//     as `rotate`, and refuses to overwrite an existing file. Per
//     V2 the bytes are stored verbatim — per-type structural
//     validation (kubeconfig YAML, AWS JSON env, etc.) is V3.
//   * `remove` requires `--force` because we cannot probe active
//     sessions from CLI without a live kernel IPC; `--force`
//     records `forced=true` in the audit event.
//   * `verify` performs structural-only checks for V2: file
//     present, mode 0600, uid match, body non-empty, and (for the
//     `env` form) a basic `KEY=VALUE` sanity parse. The audit
//     event's `success` field tracks that outcome. Live network
//     verification is V3.
//   * `audit` reads the operator-local trail at
//     `<data_dir>/audit/credential-cli.jsonl` plus every
//     `<data_dir>/audit/segment-NNN.jsonl` and prints the lines
//     whose payload mentions `<name>`.

/// Filename of the operator-local credential-CLI audit trail.
/// One JSONL record per CLI write subcommand
/// (`add` / `rotate` / `remove` / `verify`).
const CRED_CLI_AUDIT_FILE: &str = "credential-cli.jsonl";

/// `raxis credential add <name>`.
///
/// Decisions:
///   * The credential MUST NOT already exist (operator uses
///     `rotate` to update an existing entry; `add` is for first
///     registration).
///   * The bytes come from `--stdin` (default) / `--file <path>`
///     / `--interactive`. `--value <bytes>` is rejected for the
///     same reason as `rotate`.
///   * `--type <label>` and `--env <label>` are recorded verbatim
///     in the audit event for forensic queries; V2 does not
///     dispatch any per-type validators yet.
pub fn run_add(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut name: Option<String> = None;
    let mut input: InputMode = InputMode::Stdin;
    let mut input_explicit = false;
    let mut proxy_type: String = String::new();
    let mut environment: String = String::new();
    let mut description: String = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_add_help();
                return Ok(());
            }
            "--stdin" => {
                if input_explicit {
                    return Err(CliError::Usage(
                        "credential add: pick only one of --stdin / --file / --interactive".into(),
                    ));
                }
                input = InputMode::Stdin;
                input_explicit = true;
            }
            "--file" => {
                if input_explicit {
                    return Err(CliError::Usage(
                        "credential add: pick only one of --stdin / --file / --interactive".into(),
                    ));
                }
                i += 1;
                let path = args.get(i).ok_or_else(|| {
                    CliError::Usage("credential add: --file requires a path".into())
                })?;
                input = InputMode::File(PathBuf::from(path));
                input_explicit = true;
            }
            "--interactive" => {
                if input_explicit {
                    return Err(CliError::Usage(
                        "credential add: pick only one of --stdin / --file / --interactive".into(),
                    ));
                }
                input = InputMode::Interactive;
                input_explicit = true;
            }
            "--value" => {
                return Err(CliError::Usage(
                    "credential add: --value <bytes> is rejected (would expose the value \
                     in `ps aux`, shell history, and process logs). \
                     Use --stdin (e.g. `cat secret | raxis credential add <name>`), \
                     --file <path>, or --interactive instead."
                        .into(),
                ));
            }
            "--type" => {
                i += 1;
                proxy_type = args
                    .get(i)
                    .ok_or_else(|| {
                        CliError::Usage("credential add: --type requires a label".into())
                    })?
                    .clone();
            }
            "--env" => {
                i += 1;
                environment = args
                    .get(i)
                    .ok_or_else(|| {
                        CliError::Usage("credential add: --env requires a label".into())
                    })?
                    .clone();
            }
            "--desc" => {
                i += 1;
                description = args
                    .get(i)
                    .ok_or_else(|| {
                        CliError::Usage("credential add: --desc requires a string".into())
                    })?
                    .clone();
            }
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "credential add: unknown flag {other:?} (V2 supports \
                     --type / --env / --desc / --stdin / --file / --interactive; \
                     per-proxy-type flags like --host / --role-arn are V3)"
                )));
            }
            other => {
                if name.is_some() {
                    return Err(CliError::Usage(format!(
                        "credential add: unexpected positional {other:?} (one <name> only)"
                    )));
                }
                name = Some(other.to_owned());
            }
        }
        i += 1;
    }
    let name_str = name.ok_or_else(|| {
        CliError::Usage(
            "credential add: <name> is required (e.g. `cat secret | raxis credential add postgres-staging --type postgres --env staging`)"
                .into(),
        )
    })?;
    if name_str.contains('/') || name_str.contains('\\') || name_str.contains("..") {
        return Err(CliError::Usage(format!(
            "credential add: refusing name {name_str:?} (path separators / traversal segments not allowed)"
        )));
    }

    let cred_name = CredentialName::from(name_str.as_str());
    let data_dir = flags.data_dir();
    let backend = FileCredentialBackend::open(data_dir);

    if backend.exists(&cred_name) {
        return Err(CliError::Usage(format!(
            "credential add: {name_str:?} already exists under {} \
             (use `raxis credential rotate {name_str}` to update; \
             `add` is for first registration only)",
            data_dir.display(),
        )));
    }

    let bytes = read_new_value(&input)?;
    if bytes.is_empty() {
        return Err(CliError::Usage(
            "credential add: empty input (refusing to register empty bytes)".into(),
        ));
    }

    // Compute the on-disk path the file backend will store at, and
    // make sure the parent directory exists. The backend itself
    // does not create `credentials/` or `providers/` (the kernel
    // bootstrap does); from the CLI we tolerate a fresh data dir.
    let path = raxis_credentials_file::credential_file_path(data_dir, &cred_name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CliError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }

    write_new_credential(&path, &bytes).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    let actor = resolve_actor(flags)?;
    if let Err(e) = write_credential_sidecar(
        data_dir,
        &cred_name,
        &name_str,
        &proxy_type,
        &environment,
        &description,
        &actor,
        true,
    ) {
        let _ = std::fs::remove_file(&path);
        return Err(CliError::Io {
            path: raxis_credentials_file::credential_metadata_file_path(data_dir, &cred_name)
                .display()
                .to_string(),
            source: e,
        });
    }
    let _ = append_cli_audit_event(
        data_dir,
        &serde_json::json!({
            "kind":              "CredentialRegistered",
            "name":              name_str,
            "proxy_type":        proxy_type,
            "environment":       environment,
            "description":       description,
            "actor_fingerprint": actor.0,
            "backend_kind":      "file",
            "emitted_at":        unix_seconds(),
        }),
    );

    println!("Registered: {name_str}");
    println!(
        "  type:              {}",
        if proxy_type.is_empty() {
            "(unspecified)"
        } else {
            proxy_type.as_str()
        }
    );
    println!(
        "  environment:       {}",
        if environment.is_empty() {
            "(unspecified)"
        } else {
            environment.as_str()
        }
    );
    println!(
        "  actor_fingerprint: {}",
        if actor.0.is_empty() {
            "(no operator key supplied; pass --operator-key for forensic attribution)"
        } else {
            actor.0.as_str()
        }
    );
    println!("  on-disk path:      {}", path.display());
    Ok(())
}

/// `raxis credential show <name>`.
///
/// Prints metadata for a single credential. Never prints the value.
/// V2 omits the spec's "policy match" and "times-used" lines —
/// both require live policy + audit replay we don't have here.
pub fn run_show(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut name: Option<String> = None;
    let mut json = false;
    for a in args {
        match a.as_str() {
            "--help" | "-h" => {
                print_show_help();
                return Ok(());
            }
            "--json" => json = true,
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "credential show: unknown flag {other:?}"
                )));
            }
            other => {
                if name.is_some() {
                    return Err(CliError::Usage(format!(
                        "credential show: unexpected positional {other:?} (one <name> only)"
                    )));
                }
                name = Some(other.to_owned());
            }
        }
    }

    let name_str =
        name.ok_or_else(|| CliError::Usage("credential show: <name> is required".into()))?;
    let cred_name = CredentialName::from(name_str.as_str());
    let data_dir = flags.data_dir();
    let path = raxis_credentials_file::credential_file_path(data_dir, &cred_name);

    if !path.exists() {
        return Err(CliError::Usage(format!(
            "credential show: {name_str:?} not found under {}",
            data_dir.display(),
        )));
    }

    let md = std::fs::metadata(&path).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let (mode, uid) = file_mode_and_uid(&md);
    let modified_unix = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let kind_str = if name_str.starts_with("providers.") {
        "provider"
    } else {
        "credential"
    };
    let metadata = read_credential_sidecar(data_dir, &cred_name).unwrap_or_default();

    if json {
        let v = serde_json::json!({
            "name":           name_str,
            "kind":           kind_str,
            "proxy_type":     metadata.proxy_type,
            "environment":    metadata.environment,
            "description":    metadata.description,
            "path":           path.display().to_string(),
            "size_bytes":     md.len(),
            "mode_octal":     format!("{:o}", mode & 0o777),
            "uid":            uid,
            "modified_unix":  modified_unix,
            "modified_iso":   format_mtime(modified_unix),
            "mode_warn":      mode & 0o177 != 0,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(CliError::from)?
        );
        return Ok(());
    }

    println!("Name:          {name_str}");
    println!("Kind:          {kind_str}");
    if !metadata.proxy_type.is_empty() {
        println!("Type:          {}", metadata.proxy_type);
    }
    if !metadata.environment.is_empty() {
        println!("Environment:   {}", metadata.environment);
    }
    if !metadata.description.is_empty() {
        println!("Description:   {}", metadata.description);
    }
    println!("File path:     {}", path.display());
    println!("File size:     {} bytes", md.len());
    println!(
        "Permissions:   {:04o}{}",
        mode & 0o777,
        if mode & 0o177 != 0 {
            "  (warn: not 0600)"
        } else {
            ""
        }
    );
    println!("Owner UID:     {uid}");
    println!("Modified:      {}", format_mtime(modified_unix));
    Ok(())
}

/// `raxis credential remove <name> [--force]`.
///
/// V2 requires `--force` because the CLI cannot probe active
/// sessions without a live kernel IPC. Without `--force` the
/// command exits non-zero with an explanatory message rather than
/// silently removing.
pub fn run_remove(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut name: Option<String> = None;
    let mut force = false;
    for a in args {
        match a.as_str() {
            "--help" | "-h" => {
                print_remove_help();
                return Ok(());
            }
            "--force" => force = true,
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "credential remove: unknown flag {other:?}"
                )));
            }
            other => {
                if name.is_some() {
                    return Err(CliError::Usage(format!(
                        "credential remove: unexpected positional {other:?} (one <name> only)"
                    )));
                }
                name = Some(other.to_owned());
            }
        }
    }

    let name_str =
        name.ok_or_else(|| CliError::Usage("credential remove: <name> is required".into()))?;
    let cred_name = CredentialName::from(name_str.as_str());
    let data_dir = flags.data_dir();
    let backend = FileCredentialBackend::open(data_dir);

    if !backend.exists(&cred_name) {
        return Err(CliError::Usage(format!(
            "credential remove: {name_str:?} does not exist under {}",
            data_dir.display(),
        )));
    }

    if !force {
        return Err(CliError::Usage(format!(
            "credential remove: refusing to remove {name_str:?} without --force \
             (V2 cannot probe active sessions from the CLI; pass --force \
             to override and emit a CredentialRemoved{{forced=true}} audit event)"
        )));
    }

    let path = raxis_credentials_file::credential_file_path(data_dir, &cred_name);
    std::fs::remove_file(&path).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let metadata_path = raxis_credentials_file::credential_metadata_file_path(data_dir, &cred_name);
    match std::fs::remove_file(&metadata_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!(
                "warning: removed credential but metadata sidecar cleanup failed at {}: {e}",
                metadata_path.display()
            );
        }
    }

    let actor = resolve_actor(flags)?;
    let _ = append_cli_audit_event(
        data_dir,
        &serde_json::json!({
            "kind":              "CredentialRemoved",
            "name":              name_str,
            "actor_fingerprint": actor.0,
            "backend_kind":      "file",
            "forced":            force,
            "emitted_at":        unix_seconds(),
        }),
    );

    println!("Removed: {name_str}");
    println!("  forced:            {force}");
    println!(
        "  actor_fingerprint: {}",
        if actor.0.is_empty() {
            "(no operator key supplied; pass --operator-key for forensic attribution)"
        } else {
            actor.0.as_str()
        }
    );
    println!("  on-disk path:      {}", path.display());
    Ok(())
}

/// `raxis credential verify <name>`.
///
/// V2 performs structural verification only: file present, mode
/// 0600, uid matches, non-empty body, optional `KEY=VALUE` parse
/// for `.env` files. Live network verification is deferred to V3.
/// The audit event's `success` field tracks the structural outcome
/// so V3 verification can keep the same wire shape.
pub fn run_verify(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut name: Option<String> = None;
    let mut proxy_type = String::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_verify_help();
                return Ok(());
            }
            "--type" => {
                i += 1;
                proxy_type = args
                    .get(i)
                    .ok_or_else(|| {
                        CliError::Usage("credential verify: --type requires a label".into())
                    })?
                    .clone();
            }
            "--timeout" => {
                // Accepted for forward-compat with V3's live probe;
                // V2 has no network step so the value is ignored.
                i += 1;
                let _ = args.get(i).ok_or_else(|| {
                    CliError::Usage("credential verify: --timeout requires a value".into())
                })?;
            }
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "credential verify: unknown flag {other:?}"
                )));
            }
            other => {
                if name.is_some() {
                    return Err(CliError::Usage(format!(
                        "credential verify: unexpected positional {other:?} (one <name> only)"
                    )));
                }
                name = Some(other.to_owned());
            }
        }
        i += 1;
    }

    let name_str =
        name.ok_or_else(|| CliError::Usage("credential verify: <name> is required".into()))?;
    let cred_name = CredentialName::from(name_str.as_str());
    let data_dir = flags.data_dir();

    let started = std::time::Instant::now();
    let result = verify_structurally(data_dir, &cred_name, &name_str);
    let latency_ms = started.elapsed().as_millis() as u64;

    let success = result.is_ok();
    let actor = resolve_actor(flags)?;
    let _ = append_cli_audit_event(
        data_dir,
        &serde_json::json!({
            "kind":              "CredentialVerified",
            "name":              name_str,
            "proxy_type":        proxy_type,
            "success":           success,
            "latency_ms":        latency_ms,
            "actor_fingerprint": actor.0,
            "backend_kind":      "file",
            "emitted_at":        unix_seconds(),
        }),
    );

    println!("Verifying {name_str}...");
    println!("  Mode:    structural-only (V2; live probe is V3)");
    match result {
        Ok(notes) => {
            println!("  Status:  OK ({latency_ms}ms)");
            for n in &notes {
                println!("           - {n}");
            }
            Ok(())
        }
        Err(reason) => {
            println!("  Status:  FAILED ({latency_ms}ms)");
            println!("  Error:   {reason}");
            Err(CliError::Policy(format!(
                "credential verify failed for {name_str:?}: {reason}"
            )))
        }
    }
}

/// `raxis credential audit <name> [--since <duration>] [--limit <n>]`.
///
/// Reads the operator-local trail at
/// `<data_dir>/audit/credential-cli.jsonl` and (optionally) every
/// `<data_dir>/audit/segment-NNN.jsonl` and prints the records
/// whose payload mentions `<name>`. V2 only matches on the `name`
/// field; structured filtering on event kinds is V3.
pub fn run_audit(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut name: Option<String> = None;
    let mut limit: usize = 50;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_audit_help();
                return Ok(());
            }
            "--limit" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    CliError::Usage("credential audit: --limit requires a number".into())
                })?;
                limit = raw.parse().map_err(|_| {
                    CliError::Usage(format!(
                        "credential audit: --limit must be a positive integer, got {raw:?}"
                    ))
                })?;
            }
            "--since" => {
                // Accepted for forward-compat; V2's filter is
                // name-only because trail entries already carry
                // `emitted_at` and the operator can pipe through
                // `awk` if needed.
                i += 1;
                let _ = args.get(i).ok_or_else(|| {
                    CliError::Usage("credential audit: --since requires a duration".into())
                })?;
            }
            "--json" => json = true,
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "credential audit: unknown flag {other:?}"
                )));
            }
            other => {
                if name.is_some() {
                    return Err(CliError::Usage(format!(
                        "credential audit: unexpected positional {other:?} (one <name> only)"
                    )));
                }
                name = Some(other.to_owned());
            }
        }
        i += 1;
    }

    let name_str =
        name.ok_or_else(|| CliError::Usage("credential audit: <name> is required".into()))?;
    let data_dir = flags.data_dir();

    let mut hits: Vec<serde_json::Value> = Vec::new();
    collect_audit_hits(data_dir, &name_str, &mut hits);

    if hits.is_empty() {
        println!("(no audit events found for {name_str:?})");
        println!(
            "  searched: {}/audit/{CRED_CLI_AUDIT_FILE}",
            data_dir.display()
        );
        println!("  searched: {}/audit/segment-*.jsonl", data_dir.display());
        return Ok(());
    }

    if hits.len() > limit {
        hits.truncate(limit);
    }

    if json {
        let v = serde_json::Value::Array(hits);
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(CliError::from)?
        );
        return Ok(());
    }

    println!("Credential: {name_str}");
    println!("Events ({} matching, showing up to {limit}):", hits.len());
    for evt in &hits {
        let when_s = evt
            .get("emitted_at")
            .and_then(|v| v.as_i64())
            .map(format_mtime)
            .unwrap_or_else(|| "—".into());
        let kind = evt
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("UnknownKind");
        let actor = evt
            .get("actor_fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or("(no actor)");
        let proxy_type = evt.get("proxy_type").and_then(|v| v.as_str()).unwrap_or("");
        let extra = if proxy_type.is_empty() {
            String::new()
        } else {
            format!("  type={proxy_type}")
        };
        println!("  {when_s}  {kind:<24}  actor={actor}{extra}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// V2 §C7 — internal helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct CredentialSidecar {
    #[serde(default = "credential_sidecar_version")]
    version: u8,
    #[serde(default)]
    name: String,
    #[serde(default)]
    proxy_type: String,
    #[serde(default)]
    environment: String,
    #[serde(default)]
    description: String,
    #[serde(default = "credential_sidecar_backend_kind")]
    backend_kind: String,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    updated_at: i64,
    #[serde(default)]
    actor_fingerprint: String,
}

fn credential_sidecar_version() -> u8 {
    1
}

fn credential_sidecar_backend_kind() -> String {
    "file".to_owned()
}

fn read_credential_sidecar(data_dir: &Path, name: &CredentialName) -> Option<CredentialSidecar> {
    let path = raxis_credentials_file::credential_metadata_file_path(data_dir, name);
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

fn write_credential_sidecar(
    data_dir: &Path,
    cred_name: &CredentialName,
    raw_name: &str,
    proxy_type: &str,
    environment: &str,
    description: &str,
    actor: &OperatorId,
    fresh_registration: bool,
) -> std::io::Result<()> {
    let now = unix_seconds();
    let previous = read_credential_sidecar(data_dir, cred_name).unwrap_or_default();
    let created_at = if fresh_registration || previous.created_at <= 0 {
        now
    } else {
        previous.created_at
    };
    let sidecar = CredentialSidecar {
        version: credential_sidecar_version(),
        name: raw_name.to_owned(),
        proxy_type: proxy_type.to_owned(),
        environment: environment.to_owned(),
        description: description.to_owned(),
        backend_kind: credential_sidecar_backend_kind(),
        created_at,
        updated_at: now,
        actor_fingerprint: actor.0.clone(),
    };
    let bytes = toml::to_string_pretty(&sidecar)
        .map_err(|e| std::io::Error::other(format!("serialize credential sidecar: {e}")))?
        .into_bytes();
    let path = raxis_credentials_file::credential_metadata_file_path(data_dir, cred_name);
    write_replace_file_mode_0600(&path, &bytes)
}

fn refresh_credential_sidecar_after_rotate(
    data_dir: &Path,
    cred_name: &CredentialName,
    raw_name: &str,
    actor: &OperatorId,
) -> std::io::Result<()> {
    let existing = read_credential_sidecar(data_dir, cred_name).unwrap_or_else(|| {
        let proxy_type = if raw_name.starts_with("providers.") {
            "provider"
        } else {
            ""
        };
        CredentialSidecar {
            version: credential_sidecar_version(),
            name: raw_name.to_owned(),
            proxy_type: proxy_type.to_owned(),
            environment: String::new(),
            description: String::new(),
            backend_kind: credential_sidecar_backend_kind(),
            created_at: unix_seconds(),
            updated_at: 0,
            actor_fingerprint: String::new(),
        }
    });
    write_credential_sidecar(
        data_dir,
        cred_name,
        raw_name,
        &existing.proxy_type,
        &existing.environment,
        &existing.description,
        actor,
        false,
    )
}

fn blank_or_dash(value: &str) -> &str {
    if value.trim().is_empty() {
        "-"
    } else {
        value
    }
}

fn write_new_credential(final_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = final_path
        .parent()
        .ok_or_else(|| std::io::Error::other("credential path has no parent"))?;
    let tmp_name = format!(
        "{}.tmp.{}.{}",
        final_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("cred"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    let tmp = parent.join(tmp_name);
    write_file_mode_0600(&tmp, bytes)?;
    if let Err(e) = std::fs::rename(&tmp, final_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    fsync_dir(parent)?;
    Ok(())
}

fn write_replace_file_mode_0600(final_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = final_path
        .parent()
        .ok_or_else(|| std::io::Error::other("credential metadata path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let tmp_name = format!(
        "{}.tmp.{}.{}",
        final_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("credential.metadata.toml"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    let tmp = parent.join(tmp_name);
    write_file_mode_0600(&tmp, bytes)?;
    if let Err(e) = std::fs::rename(&tmp, final_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    fsync_dir(parent)?;
    Ok(())
}

#[cfg(unix)]
fn write_file_mode_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_mode_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    let f = std::fs::OpenOptions::new().read(true).open(dir)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Append a single JSONL record to
/// `<data_dir>/audit/credential-cli.jsonl`. Best-effort: failure
/// to append is logged to stderr but does NOT fail the calling
/// command (the on-disk credential write already succeeded; we
/// surface "audit emit failed" diagnostically rather than
/// rolling back).
fn append_cli_audit_event(data_dir: &Path, record: &serde_json::Value) -> std::io::Result<()> {
    let dir = data_dir.join("audit");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(CRED_CLI_AUDIT_FILE);

    let mut line = serde_json::to_string(record).unwrap_or_else(|_| "{}".into());
    line.push('\n');

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(line.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)?;
        f.write_all(line.as_bytes())?;
        f.sync_all()?;
    }
    Ok(())
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Structural verification: file present, mode 0600, uid match,
/// non-empty body, and (for `.env` files) a `KEY=VALUE` parse.
/// Returns `Ok(notes)` on success or `Err(reason)` on failure.
fn verify_structurally(
    data_dir: &Path,
    cred_name: &CredentialName,
    raw_name: &str,
) -> Result<Vec<String>, String> {
    let path = raxis_credentials_file::credential_file_path(data_dir, cred_name);
    let md = std::fs::metadata(&path).map_err(|e| format!("stat {}: {e}", path.display()))?;

    let mut notes: Vec<String> = Vec::new();

    let (mode, uid) = file_mode_and_uid(&md);
    if md.len() == 0 {
        return Err(format!("{} is empty", path.display()));
    }
    if mode & 0o177 != 0 {
        return Err(format!(
            "{} has mode 0{:o}, expected 0600 — chmod 0600 the file",
            path.display(),
            mode & 0o777,
        ));
    }
    notes.push("mode 0600 OK".to_string());

    if let Some(want) = current_uid() {
        if uid != want {
            return Err(format!(
                "{} owned by uid {uid}, expected uid {want} — run `chown {want} <path>`",
                path.display(),
            ));
        }
        notes.push(format!("owner uid {uid} matches kernel uid"));
    }

    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;

    // Best-effort `KEY=VALUE` parse for the env form. We only run
    // this when the on-disk path ends in `.env` (i.e. credentials
    // not providers); failures here are reported as warnings, not
    // errors, because some operators put binary blobs in .env
    // (e.g. raw SCRAM auth secrets).
    if !raw_name.starts_with("providers.") {
        match std::str::from_utf8(&bytes) {
            Ok(text) => {
                let mut lines_total = 0usize;
                let mut lines_kv = 0usize;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    lines_total += 1;
                    if let Some((k, _v)) = trimmed.split_once('=') {
                        if !k.trim().is_empty() {
                            lines_kv += 1;
                        }
                    }
                }
                if lines_total > 0 {
                    notes.push(format!(
                        "env-form parse: {lines_kv}/{lines_total} non-empty lines look like KEY=VALUE"
                    ));
                } else {
                    notes.push("body is non-empty but contains no env-style lines (binary or single-secret form)".into());
                }
            }
            Err(_) => notes.push("body is binary (non-UTF8) — parse skipped".into()),
        }
    }

    Ok(notes)
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    #[allow(unsafe_code)]
    let uid = unsafe { libc::getuid() };
    Some(uid)
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// Read every JSONL file under `<data_dir>/audit/` and append to
/// `out` the records whose `name` field equals `target_name`.
/// Silently tolerates missing files and malformed records (the
/// kernel chain reader handles parse-errors with hard failure;
/// the operator-local trail is best-effort).
fn collect_audit_hits(data_dir: &Path, target_name: &str, out: &mut Vec<serde_json::Value>) {
    let audit_dir = data_dir.join("audit");

    // 1. Operator-local CLI trail.
    let cli_trail = audit_dir.join(CRED_CLI_AUDIT_FILE);
    if let Ok(text) = std::fs::read_to_string(&cli_trail) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if v.get("name").and_then(|n| n.as_str()) == Some(target_name) {
                    out.push(v);
                }
            }
        }
    }

    // 2. Kernel chain segments (`segment-NNN.jsonl`).
    if let Ok(rd) = std::fs::read_dir(&audit_dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            let name = match path.file_name().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => continue,
            };
            if !(name.starts_with("segment-") && name.ends_with(".jsonl")) {
                continue;
            }
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let v: serde_json::Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let payload = v.get("payload");
                let mentions = match payload.and_then(|p| p.get("name")).and_then(|n| n.as_str()) {
                    Some(n) => n == target_name,
                    None => false,
                };
                if !mentions {
                    continue;
                }
                let mut flat = serde_json::json!({
                    "kind":              v.get("event_kind").cloned().unwrap_or(serde_json::Value::Null),
                    "name":              target_name,
                    "emitted_at":        v.get("emitted_at").cloned().unwrap_or(serde_json::Value::Null),
                    "actor_fingerprint": payload.and_then(|p| p.get("actor_fingerprint")).cloned().unwrap_or(serde_json::Value::Null),
                });
                if let Some(t) = payload.and_then(|p| p.get("proxy_type")) {
                    flat["proxy_type"] = t.clone();
                }
                out.push(flat);
            }
        }
    }

    out.sort_by(|a, b| {
        let aa = a.get("emitted_at").and_then(|v| v.as_i64()).unwrap_or(0);
        let bb = b.get("emitted_at").and_then(|v| v.as_i64()).unwrap_or(0);
        bb.cmp(&aa)
    });
}

// ---------------------------------------------------------------------------
// V2 §C7 — help
// ---------------------------------------------------------------------------

fn print_add_help() {
    println!(
        r#"raxis credential add — register a NEW credential.

USAGE:
    raxis [--data-dir <path>] [--operator-key <path>] credential add <name>
        [--type <label>] [--env <label>] [--desc <text>]
        [--stdin | --file <path> | --interactive]

INPUT METHODS (PICK ONE; --stdin is the default):
    --stdin           Read the new value from stdin.
    --file <path>     Read the new value from a file on disk.
    --interactive     Prompt with hidden echo (sudo-style).

REJECTED:
    --value <bytes>   The CLI refuses on-argv secrets — they leak into
                      ps aux, shell history, /proc/<pid>/environ, and
                      logs. Use one of the methods above.

The add path:
  1. Refuses if the credential already exists (use `rotate` to update).
  2. Writes a temp file with mode 0600, fsync()s, atomic-renames to the final path.
  3. Writes a non-secret <name>.metadata.toml sidecar with type/env/description.
  4. fsync()s the parent directory.
  5. Appends a CredentialRegistered record to <data-dir>/audit/credential-cli.jsonl.

V2 stores the bytes verbatim. Per-type validation
(kubeconfig / AWS JSON / postgres URI / etc.) is V3.
"#,
    );
}

fn print_show_help() {
    println!(
        r#"raxis credential show — print metadata for one credential.

USAGE:
    raxis [--data-dir <path>] credential show <name> [--json]

The command reads the on-disk credential file's `stat(2)` metadata
(size, mode, uid, mtime). Values are NEVER printed.
"#,
    );
}

fn print_remove_help() {
    println!(
        r#"raxis credential remove — delete a credential file.

USAGE:
    raxis [--data-dir <path>] [--operator-key <path>] credential remove <name> --force

V2 requires --force because the CLI cannot probe active sessions
(no live kernel IPC). With --force the file is unlinked
atomically and a CredentialRemoved{{forced=true}} record is
appended to <data-dir>/audit/credential-cli.jsonl.
"#,
    );
}

fn print_verify_help() {
    println!(
        r#"raxis credential verify — structural verification (V2; live probe is V3).

USAGE:
    raxis [--data-dir <path>] [--operator-key <path>] credential verify <name>
        [--type <label>] [--timeout <ms>]

V2 verifies:
  * the file exists at the resolved path;
  * mode is 0600;
  * uid matches the running process;
  * body is non-empty;
  * for `.env` form, lines parse as KEY=VALUE (warning-level only).

A CredentialVerified{{success=...,latency_ms=...}} record is
appended to <data-dir>/audit/credential-cli.jsonl regardless of
outcome.
"#,
    );
}

fn print_audit_help() {
    println!(
        r#"raxis credential audit — show the audit trail for a credential.

USAGE:
    raxis [--data-dir <path>] credential audit <name> [--limit <n>] [--since <duration>] [--json]

The command merges:
  * <data-dir>/audit/credential-cli.jsonl  — operator-local CLI trail
  * <data-dir>/audit/segment-NNN.jsonl     — kernel main audit chain

filters to records whose `name` field matches <name>, sorts by
emitted_at descending, and prints up to --limit (default 50).
--since is accepted for forward-compat with V3 but ignored today.
"#,
    );
}
