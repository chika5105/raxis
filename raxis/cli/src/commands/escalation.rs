// raxis-cli::commands::escalation — escalation approve / deny.
//
// Normative reference:
//   - cli-ceremony.md §4.1 `escalation approve`, `escalation deny`
//   - kernel-store.md §2.5.5 "Escalation approval on the operator socket"
//   - kernel-core.md §2.3 `handle_approve_escalation` / `handle_deny_escalation`
//
// Both handlers are fully implemented kernel-side as of phase A.6:
// `OperatorRequest::ApproveEscalation` / `DenyEscalation` are typed
// variants of the wire enum (see `raxis-types::operator_wire`), and the
// canonical signing input is constructed via
// `raxis_crypto::escalation::approval_scope_signing_input`, which is
// shared with the kernel — drift between the two halves is impossible
// because both sides go through the same function.

use raxis_types::operator_wire::{ApprovalScopeWire, OperatorRequest};

use crate::commands::plan::{handle_response, open_conn, to_wire};
use crate::errors::CliError;
use crate::GlobalFlags;

// ---------------------------------------------------------------------------
// escalation approve <escalation_id> --scope <capability_class> --max-uses <n> --valid-for <secs>
// ---------------------------------------------------------------------------

pub fn run_approve(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let escalation_id = args.first()
        .ok_or_else(|| CliError::Usage("escalation approve requires <escalation_id>".to_owned()))?
        .clone();

    let mut scope: Option<String> = None;
    let mut max_uses: Option<i64> = None;
    let mut valid_for_secs: Option<u64> = None;
    // Sensitive-output gate: the raw `approval_token_raw` is a bearer
    // credential the planner must present to consume the escalation.
    // Default-redact per the same v1.x credential-handling convention
    // as `session create --reveal-token` (cli-readonly.md §5.4.2
    // precedent for `--reveal-paths`); the operator must opt in
    // explicitly to print the raw token to stdout.
    let mut reveal_token = false;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--scope" => {
                i += 1;
                scope = Some(args.get(i).ok_or_else(|| CliError::Usage("--scope requires a value".to_owned()))?.clone());
            }
            "--max-uses" => {
                i += 1;
                let s = args.get(i).ok_or_else(|| CliError::Usage("--max-uses requires a number".to_owned()))?;
                max_uses = Some(s.parse().map_err(|_| CliError::Usage(format!("--max-uses must be an integer, got {s:?}")))?);
            }
            "--valid-for" => {
                i += 1;
                let s = args.get(i).ok_or_else(|| CliError::Usage("--valid-for requires a number".to_owned()))?;
                valid_for_secs = Some(s.parse().map_err(|_| CliError::Usage(format!("--valid-for must be an integer, got {s:?}")))?);
            }
            "--reveal-token" => {
                reveal_token = true;
            }
            other => return Err(CliError::Usage(format!("unknown escalation approve flag: {other:?}"))),
        }
        i += 1;
    }

    let capability_class = scope.ok_or_else(|| CliError::Usage("escalation approve requires --scope <capability_class>".to_owned()))?;
    let max_uses = max_uses.ok_or_else(|| CliError::Usage("escalation approve requires --max-uses <n>".to_owned()))?;
    let valid_for_seconds = valid_for_secs.ok_or_else(|| CliError::Usage("escalation approve requires --valid-for <secs>".to_owned()))?;

    let approval_scope = ApprovalScopeWire {
        capability_class: capability_class.clone(),
        max_uses,
        valid_for_seconds,
    };

    // Sign with the operator's private key over the canonical bytes
    // produced by the SHARED helper (raxis-crypto::escalation). The
    // kernel reconstructs the same bytes inside
    // authority::escalation::approve_escalation; if the two halves
    // disagree on layout, the round-trip test in raxis-crypto fails at
    // build time and the IPC handler returns FAIL_OPERATOR_SIGNATURE_INVALID.
    let key_path = flags.operator_key_path.as_deref()
        .ok_or_else(|| CliError::Usage("--operator-key is required for escalation approve".to_owned()))?;
    let signing_key = crate::signing::load_operator_key(key_path)?;
    let signing_input = raxis_crypto::escalation::approval_scope_signing_input(
        &escalation_id,
        &approval_scope.capability_class,
        approval_scope.max_uses,
        approval_scope.valid_for_seconds,
    );
    let sig_hex = crate::signing::sign_bytes(&signing_key, &signing_input);

    let (mut conn, _fingerprint) = open_conn(flags)?;
    let req = OperatorRequest::ApproveEscalation {
        escalation_id:    escalation_id.clone(),
        approval_scope,
        operator_sig_hex: sig_hex,
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        // Typed `EscalationApproved` payload exposes the raw token
        // directly — but the CLI only prints it when the operator
        // has explicitly passed `--reveal-token`. Without the flag
        // we print only the SHA-256 fingerprint so the operator can
        // see a successful approval landed without leaking the
        // bearer credential into shell history / screencasts.
        let token = ok["approval_token_raw"].as_str().unwrap_or("?");
        let token_id = ok["approval_token_id"].as_str().unwrap_or("?");
        let expires_at = ok["expires_at"].as_i64().unwrap_or(0);
        println!("Escalation {escalation_id} approved.");
        println!("approval_token_id:  {token_id}");
        emit_approval_token(token, reveal_token);
        println!("expires_at:         {expires_at}");
    })
}

/// Emit the approval token (or a redacted placeholder) per the
/// `--reveal-token` gate. Stdout is the canonical channel here so the
/// existing operator UX (`raxis escalation approve ... | grep
/// approval_token_raw`) keeps working when the operator opts in.
/// Without the flag we print the fingerprint so the operator can
/// correlate against kernel-side audit logs without disclosing the
/// raw bearer token.
fn emit_approval_token(token: &str, reveal: bool) {
    for line in build_approval_token_lines(token, reveal) {
        println!("{line}");
    }
}

/// Build the lines that `emit_approval_token` will print. Pure — no
/// I/O. The unit tests at the bottom of this file exercise both
/// branches without needing to capture stdout.
pub(crate) fn build_approval_token_lines(token: &str, reveal: bool) -> Vec<String> {
    if reveal {
        return vec![
            format!("approval_token_raw: {token}"),
            "(Pass approval_token_raw to the planner out-of-band — this is a secret.)"
                .to_owned(),
        ];
    }
    let fingerprint = credential_fingerprint(token);
    vec![format!(
        "approval_token_raw: <redacted; sha256_fp={fingerprint}> \
        (re-run with --reveal-token to print the raw token to stdout)"
    )]
}

/// Same helper as `commands::session::credential_fingerprint`: short
/// 8-char SHA-256 prefix in lowercase hex. Kept inlined per command
/// rather than promoted to a shared helper because it's two lines and
/// the CLI command modules are otherwise dependency-free of each
/// other; introducing a shared `crate::secrets` module is a separate
/// refactor.
fn credential_fingerprint(credential: &str) -> String {
    let full = raxis_crypto::token::sha256_hex(credential.as_bytes());
    full[..8].to_owned()
}

// ---------------------------------------------------------------------------
// escalation deny <escalation_id> [--reason <text>]
// ---------------------------------------------------------------------------

pub fn run_deny(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let escalation_id = args.first()
        .ok_or_else(|| CliError::Usage("escalation deny requires <escalation_id>".to_owned()))?
        .clone();

    let mut reason: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--reason" => {
                i += 1;
                reason = Some(args.get(i).ok_or_else(|| CliError::Usage("--reason requires a value".to_owned()))?.clone());
            }
            other => return Err(CliError::Usage(format!("unknown escalation deny flag: {other:?}"))),
        }
        i += 1;
    }

    // The CLI mirrors the kernel-side 512-character cap so operators
    // get a useful error before the round-trip even happens.
    if let Some(r) = reason.as_ref() {
        if r.chars().count() > 512 {
            return Err(CliError::Usage(format!(
                "--reason exceeds 512-character limit (was {} chars)",
                r.chars().count(),
            )));
        }
    }

    let (mut conn, _fingerprint) = open_conn(flags)?;
    let req = OperatorRequest::DenyEscalation {
        escalation_id: escalation_id.clone(),
        reason,
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        let denied_at = ok["denied_at"].as_i64().unwrap_or(0);
        println!("Escalation {escalation_id} denied (denied_at={denied_at}).");
    })
}

// ---------------------------------------------------------------------------
// Tests — `--reveal-token` redaction contract for `escalation approve`.
//
// Mirror of `commands::session::reveal_token_tests`. Pre-flag default
// MUST emit only the SHA-256 fingerprint plus a hint; the operator
// must opt in explicitly via `--reveal-token` to print
// `approval_token_raw` to stdout.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod reveal_token_tests {
    use super::build_approval_token_lines;

    /// Distinctive token so any leak is unmissable in test output.
    const SECRET_TOKEN: &str =
        "SECRET_APPROVAL_TOKEN_dddddddddddddddddddddddddddddddddddddddd";

    #[test]
    fn default_redacted_lines_do_not_contain_raw_token() {
        let lines = build_approval_token_lines(SECRET_TOKEN, false);
        for line in &lines {
            assert!(
                !line.contains(SECRET_TOKEN),
                "redacted line MUST NOT contain raw approval_token_raw; got: {line}",
            );
            assert!(
                !line.contains("SECRET_"),
                "no prefix of the secret token may appear; got: {line}",
            );
        }
    }

    #[test]
    fn default_redacted_output_carries_fingerprint_and_reveal_hint() {
        let lines = build_approval_token_lines(SECRET_TOKEN, false);
        let joined = lines.join("\n");
        assert!(joined.contains("sha256_fp="),
            "redacted output must explain WHY the token is hidden via the fingerprint marker; got: {joined}");
        assert!(joined.contains("--reveal-token"),
            "redacted output must point operators to the explicit opt-in flag; got: {joined}");
    }

    #[test]
    fn reveal_flag_emits_raw_token_and_secret_warning() {
        let lines = build_approval_token_lines(SECRET_TOKEN, true);
        let joined = lines.join("\n");
        assert!(joined.contains(&format!("approval_token_raw: {SECRET_TOKEN}")),
            "explicit --reveal-token must produce the canonical raw-token line; got: {joined}");
        assert!(joined.contains("this is a secret"),
            "explicit reveal must keep the operator-facing secret-handling reminder; got: {joined}");
    }

    /// Cross-check against the kernel-side fingerprint helper. See
    /// the matching test in `commands::session::reveal_token_tests`.
    #[test]
    fn redacted_fingerprint_matches_kernel_side_helper() {
        let lines = build_approval_token_lines(SECRET_TOKEN, false);
        let line = lines.first().expect("redacted output must have at least one line");
        let cli_fp = line
            .split("sha256_fp=").nth(1).expect("redacted line must contain sha256_fp= marker")
            .split('>').next().expect("marker must be terminated by '>'")
            .to_owned();
        let kernel_fp =
            raxis_crypto::token::sha256_hex(SECRET_TOKEN.as_bytes())[..8].to_owned();
        assert_eq!(cli_fp, kernel_fp,
            "CLI redacted fingerprint must equal the kernel-side log fingerprint");
    }
}
