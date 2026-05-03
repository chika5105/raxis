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
        // directly — the CLI prints it verbatim so the operator can
        // hand it to the planner out-of-band. The token itself is the
        // secret; the kernel only stored sha256(token).
        let token = ok["approval_token_raw"].as_str().unwrap_or("?");
        let token_id = ok["approval_token_id"].as_str().unwrap_or("?");
        let expires_at = ok["expires_at"].as_i64().unwrap_or(0);
        println!("Escalation {escalation_id} approved.");
        println!("approval_token_id:  {token_id}");
        println!("approval_token_raw: {token}");
        println!("expires_at:         {expires_at}");
        println!("(Pass approval_token_raw to the planner out-of-band — this is a secret.)");
    })
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
