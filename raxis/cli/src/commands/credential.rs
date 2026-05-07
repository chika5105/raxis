// raxis-cli::commands::credential — `raxis credential list` /
// `raxis credential rotate <name>`.
//
// Normative reference: `specs/v2/extensibility-traits.md §4.4` (the
// CLI surface for the V2 `CredentialBackend`) and
// `specs/v2/credential-proxy.md §12` (the operator-facing UX).
//
// V2 GA scope: the two MVP operations called out by the trait spec
// — `list` (read-only, never reveals values) and `rotate` (replace
// the bytes for an existing credential through the file backend's
// atomic-rename ceremony). Both commands are local-only: they
// operate on `<data_dir>/credentials/` and `<data_dir>/providers/`
// directly through `FileCredentialBackend` and never open the
// kernel's operator socket. The kernel itself does not need to be
// running to run these commands — they are administrative
// filesystem ops bound by 0600 perms + UID match, and the kernel
// re-validates on next `resolve` regardless.
//
// `add`, `show`, `remove`, `verify`, and `audit` from the
// credential-proxy.md §12 catalogue are deferred — `add` requires
// the per-proxy-type validators (postgres URI parsing, kubeconfig
// YAML, AWS JSON, etc.) and `verify` requires the credential proxy
// runtime, neither of which has landed yet. `show` overlaps mostly
// with `list --json`; `audit` is `raxis log` with a filter.
//
// Input discipline (INV-CRED-CLI-01 from credential-proxy.md §12.1):
//   - The new value for `rotate` is read via `--stdin` (default),
//     `--file <path>`, or `--interactive` (terminal prompt with
//     hidden echo).
//   - `--value <bytes>` is REJECTED — see the `[FAIL]` arm below.
//   - The CLI never writes the value to stdout, stderr, the audit
//     event payload, or the shell history.
//
// Audit:
//   - `rotate` emits one `CredentialRotated` audit event per call
//     (via the `FileCredentialBackend`'s built-in audit-emitter
//     wrapper). The CLI is the operator-facing actor; the
//     `actor_fingerprint` field is populated from the operator
//     pubkey resolved via `--operator-key` / `RAXIS_OPERATOR_KEY`.
//   - `list` is intentionally NOT audited — it reads only file
//     metadata that is already visible to the operator UID via
//     `ls -la`.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use raxis_credentials::{
    CredentialBackend, CredentialName, CredentialValue, OperatorId,
};
use raxis_credentials_file::FileCredentialBackend;

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
        "{:<32}  {:<10}  {:>10}  {:<20}  {:>4}  {:>6}",
        "NAME", "KIND", "BYTES", "MTIME", "MODE", "UID",
    );
    for e in &entries {
        let mtime = format_mtime(e.modified_unix);
        let mode_warn = if e.mode & 0o177 != 0 { "*" } else { " " };
        println!(
            "{:<32}  {:<10}  {:>10}  {:<20}  {:>4o}{mode_warn} {:>6}",
            e.name, e.kind.as_str(), e.size_bytes, mtime, e.mode & 0o777, e.uid,
        );
    }
    if entries.iter().any(|e| e.mode & 0o177 != 0) {
        eprintln!("\nwarning: entries marked `*` are NOT chmod 0600 — fix with:");
        eprintln!("    chmod 0600 {}/credentials/<name>.env", data_dir.display());
        eprintln!("    chmod 0600 {}/providers/<name>.toml",   data_dir.display());
    }
    Ok(())
}

/// `raxis credential rotate <name> [--stdin | --file <path> | --interactive]`.
///
/// Reads the new credential bytes via the chosen input method,
/// then drives `FileCredentialBackend::rotate` (atomic temp-write
/// + rename + parent-dir fsync). The `actor` field of the audit
/// event is the operator's pubkey fingerprint resolved from the
/// CLI flags, so forensic queries can attribute the rotation to a
/// specific operator certificate.
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
    backend.rotate(&cred_name, new_value, actor.clone()).map_err(|e| {
        CliError::Policy(format!(
            "credential rotate failed for {name_str:?}: {e} (code: {})",
            e.error_code(),
        ))
    })?;

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
            Self::Provider   => "provider",
        }
    }
}

#[derive(Debug)]
struct ListEntry {
    name:          String,
    kind:          CredKind,
    size_bytes:    u64,
    modified_unix: i64,
    mode:          u32,
    uid:           u32,
}

fn collect_entries(data_dir: &Path) -> Result<Vec<ListEntry>, CliError> {
    let mut out = Vec::new();
    push_dir(&mut out, &data_dir.join("credentials"), CredKind::Credential, "env")?;
    push_dir(&mut out, &data_dir.join("providers"),   CredKind::Provider,   "toml")?;
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn push_dir(
    out: &mut Vec<ListEntry>,
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
        if !ft.is_file() { continue; }
        let path = entry.path();
        let stem_ext = path.extension().and_then(|s| s.to_str());
        if stem_ext != Some(ext) { continue; }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None    => continue,
        };
        // Skip rotation tmp files (pattern: <name>.<ext>.tmp.<pid>.<nanos>).
        // The file backend names them under `parent.join(<stem>.<ext>.tmp.<pid>.<nanos>)`,
        // so they end up with a `<stem>.<ext>.tmp.<pid>` *file_stem*. Defensive:
        // skip anything whose stem contains `.tmp.` or `.new`.
        if stem.contains(".tmp.") || stem.ends_with(".new") { continue; }

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
            CredKind::Provider   => format!("providers.{stem}"),
        };
        out.push(ListEntry {
            name:          display_name,
            kind,
            size_bytes:    md.len(),
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
fn file_mode_and_uid(_md: &std::fs::Metadata) -> (u32, u32) { (0o600, 0) }

fn format_mtime(unix: i64) -> String {
    if unix <= 0 { return "—".into(); }
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
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
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
            std::io::stdin().read_to_end(&mut buf).map_err(|e| CliError::Io {
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
    if buf.last() == Some(&b'\n') { buf.pop(); }
    if buf.last() == Some(&b'\r') { buf.pop(); }
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
    read_res.map_err(|e| CliError::Io { path: "<stdin>".into(), source: e })?;

    Ok(strip_trailing_newline(line.into_bytes()))
}

#[cfg(not(unix))]
fn read_interactive() -> Result<Vec<u8>, CliError> {
    Err(CliError::Usage(
        "credential rotate --interactive is only supported on Unix; use --stdin or --file"
            .into(),
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
        None    => return Ok(OperatorId(String::new())),
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
