// raxis-cli::commands::session — session create / revoke.
//
// Normative reference: cli-ceremony.md §4.1 `session create`, `session revoke`.
//
// Wire shape: every operator op is constructed as a typed
// `raxis_types::operator_wire::OperatorRequest` and serialised via
// `serde_json::to_value`. This guarantees the CLI's outgoing JSON shape
// is byte-equal to what the kernel's deserialiser expects (the wire
// shape is locked by `operator_wire::tests`). Hand-built `serde_json::json!`
// blocks for OperatorRequest are FORBIDDEN — they bypass the type
// system and have caused protocol drift in the past.

use std::path::PathBuf;

use raxis_types::operator_wire::OperatorRequest;

use crate::commands::plan::{handle_response, open_conn};
use crate::errors::CliError;
use crate::GlobalFlags;

// ---------------------------------------------------------------------------
// session create
// ---------------------------------------------------------------------------

pub fn run_create(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut role = String::from("planner");
    let mut worktree_root: Option<PathBuf> = None;
    let mut base_tracking_ref: Option<String> = None;
    let mut task_id: Option<String> = None;
    let mut lineage_id: Option<String> = None;
    // Sensitive-output gate: the raw `session_token` is a bearer
    // credential. v1.x adopts the `--reveal-paths` precedent
    // (cli-readonly.md §5.4.2) for credentials too: the operator must
    // opt in explicitly. Default prints only the SHA-256 fingerprint
    // of the token plus a hint instructing how to re-run with
    // `--reveal-token` to capture the raw value (typically via
    // `2>session.env`). This makes a copy-paste of `raxis session
    // create` into a recorded shell session safe by default.
    let mut reveal_token = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--role" => {
                i += 1;
                role = args
                    .get(i)
                    .ok_or_else(|| CliError::Usage("--role requires a value".to_owned()))?
                    .clone();
            }
            "--worktree-root" => {
                i += 1;
                worktree_root = Some(PathBuf::from(args.get(i).ok_or_else(|| {
                    CliError::Usage("--worktree-root requires a path".to_owned())
                })?));
            }
            "--base-tracking-ref" => {
                i += 1;
                base_tracking_ref = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            CliError::Usage("--base-tracking-ref requires a value".to_owned())
                        })?
                        .clone(),
                );
            }
            "--task" => {
                i += 1;
                task_id = Some(
                    args.get(i)
                        .ok_or_else(|| CliError::Usage("--task requires a task_id".to_owned()))?
                        .clone(),
                );
            }
            "--lineage-id" => {
                i += 1;
                lineage_id = Some(
                    args.get(i)
                        .ok_or_else(|| CliError::Usage("--lineage-id requires a uuid".to_owned()))?
                        .clone(),
                );
            }
            "--reveal-token" => {
                reveal_token = true;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown session create flag: {other:?}"
                )))
            }
        }
        i += 1;
    }

    if role != "planner" {
        return Err(CliError::Usage(
            "FAIL_ROLE_NOT_OPERATOR_CREATABLE: only --role planner is supported in v1".to_owned(),
        ));
    }
    let worktree_root = worktree_root.ok_or_else(|| {
        CliError::Usage("session create requires --worktree-root <path>".to_owned())
    })?;

    // Generate lineage_id if not provided. `uuid::Uuid::new_v4()` routes to
    // `getrandom` and panics on RNG failure (acceptable here — the rest of the
    // CLI is also synchronous and we have no recovery path; we do not want to
    // emit a degraded lineage_id).
    let lineage_id = lineage_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let (mut conn, _fingerprint) = open_conn(flags)?;
    // The kernel infers the creating operator from the authenticated
    // session, NOT from a wire-supplied field — so we don't echo
    // `created_by_operator` here (the field doesn't exist in the
    // kernel-side OperatorRequest enum).
    let req = OperatorRequest::CreateSession {
        role: role.clone(),
        worktree_root: Some(worktree_root.display().to_string()),
        base_sha: None,
        base_tracking_ref: base_tracking_ref.clone(),
        lineage_id: lineage_id.clone(),
        task_id: task_id.clone(),
    };
    let req_json = serde_json::to_value(&req)
        .map_err(|e| CliError::Usage(format!("could not serialise CreateSession request: {e}")))?;

    let resp = conn.send_request(&req_json)?;
    handle_response(resp, |ok| {
        let session_id = ok["session_id"].as_str().unwrap_or("?");
        let token = ok["session_token"].as_str().unwrap_or("?");
        let expires_at = ok["expires_at"].as_i64().unwrap_or(0);
        let lineage = ok["lineage_id"].as_str().unwrap_or(&lineage_id);

        // All non-secret fields → stdout.
        println!("Session created:");
        println!("  session_id:   {session_id}");
        println!("  role:         planner");
        println!("  worktree:     {}", worktree_root.display());
        println!("  expires_at:   {expires_at}");
        println!("  lineage_id:   {lineage}");
        emit_session_token(token, reveal_token);
    })
}

/// Emit the session token (or a redacted placeholder) on stderr per
/// the `--reveal-token` gate. Stderr is the canonical channel here so
/// `raxis session create ... 2>session.env` continues to work
/// unchanged when `--reveal-token` is set; without the flag the
/// operator only sees a fingerprint plus a hint.
fn emit_session_token(token: &str, reveal: bool) {
    eprintln!("{}", build_session_token_line(token, reveal));
}

/// Build the session-token stderr line. Pure — no I/O. The unit
/// tests at the bottom of this file exercise both the redacted and
/// revealed branches without needing to capture stderr.
pub(crate) fn build_session_token_line(token: &str, reveal: bool) -> String {
    if reveal {
        return format!("RAXIS_SESSION_TOKEN={token}");
    }
    let fingerprint = credential_fingerprint(token);
    format!(
        "session_token: <redacted; sha256_fp={fingerprint}> \
        (re-run with --reveal-token to print RAXIS_SESSION_TOKEN to stderr; \
        capture with `2>session.env` to keep it out of shell history)"
    )
}

/// Short, non-reversible 8-char SHA-256 prefix of `credential` for
/// display correlation (e.g. matching the redacted CLI line against
/// a kernel-side `session_token_fp` log entry on `ipc.planner`).
/// Mirrors the kernel-side `crate::ipc::log::credential_fingerprint`
/// helper byte-for-byte: both compute `sha256(token.as_bytes())[..8]`
/// in lowercase hex.
fn credential_fingerprint(credential: &str) -> String {
    let full = raxis_crypto::token::sha256_hex(credential.as_bytes());
    full[..8].to_owned()
}

// ---------------------------------------------------------------------------
// session revoke
// ---------------------------------------------------------------------------

pub fn run_revoke(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let session_id = args
        .first()
        .ok_or_else(|| CliError::Usage("session revoke requires <session_id>".to_owned()))?;

    let (mut conn, _) = open_conn(flags)?;
    let req = OperatorRequest::RevokeSession {
        session_id: session_id.clone(),
    };
    let req_json = serde_json::to_value(&req)
        .map_err(|e| CliError::Usage(format!("could not serialise RevokeSession request: {e}")))?;
    let resp = conn.send_request(&req_json)?;
    handle_response(resp, |ok| {
        let revoked_at = ok["revoked_at"].as_i64().unwrap_or(0);
        println!("Session {session_id} revoked at {revoked_at}");
    })
}

// (UUID minting moved to `uuid::Uuid::new_v4()` — see usage in `run_create`.)

// ---------------------------------------------------------------------------
// Tests — `--reveal-token` redaction contract.
//
// The session_token is a bearer credential; v1.x mandates explicit
// `--reveal-token` opt-in to print it to stderr. Pre-flag default
// MUST emit only the SHA-256 fingerprint plus a hint. These tests
// pin both halves so an accidental flag flip in `run_create` (e.g.
// inverting a boolean) is caught at unit-test time.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod reveal_token_tests {
    use super::build_session_token_line;

    /// Distinctive token so any leak is unmissable in test output.
    const SECRET_TOKEN: &str = "SECRET_SESSION_TOKEN_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn default_redacted_line_does_not_contain_raw_token() {
        let line = build_session_token_line(SECRET_TOKEN, false);
        assert!(
            !line.contains(SECRET_TOKEN),
            "redacted line MUST NOT contain raw session_token; got: {line}",
        );
        assert!(
            !line.contains("SECRET_"),
            "no prefix of the secret token may appear; got: {line}",
        );
    }

    #[test]
    fn default_redacted_line_carries_fingerprint_and_reveal_hint() {
        let line = build_session_token_line(SECRET_TOKEN, false);
        assert!(line.contains("sha256_fp="),
            "redacted line must explain WHY the token is hidden via the fingerprint marker; got: {line}");
        assert!(
            line.contains("--reveal-token"),
            "redacted line must point operators to the explicit opt-in flag; got: {line}"
        );
    }

    #[test]
    fn reveal_flag_emits_raw_token_in_env_var_format() {
        let line = build_session_token_line(SECRET_TOKEN, true);
        assert_eq!(
            line,
            format!("RAXIS_SESSION_TOKEN={SECRET_TOKEN}"),
            "explicit --reveal-token must produce the canonical env-var line so \
             `2>session.env` capture continues to work"
        );
    }

    /// Cross-check: the redacted fingerprint must match what the
    /// kernel-side `ipc::log::credential_fingerprint` would emit for
    /// the same token, so a redacted CLI line and a kernel
    /// `session_token_fp` log entry can be eyeballed against one
    /// another by an operator triaging a session.
    #[test]
    fn redacted_fingerprint_matches_kernel_side_helper() {
        let line = build_session_token_line(SECRET_TOKEN, false);
        let cli_fp = line
            .split("sha256_fp=")
            .nth(1)
            .expect("redacted line must contain sha256_fp= marker")
            .split('>')
            .next()
            .expect("marker must be terminated by '>'")
            .to_owned();
        let kernel_fp = raxis_crypto::token::sha256_hex(SECRET_TOKEN.as_bytes())[..8].to_owned();
        assert_eq!(
            cli_fp, kernel_fp,
            "CLI redacted fingerprint must equal the kernel-side log fingerprint \
             so an operator can correlate the two without guesswork"
        );
    }
}
