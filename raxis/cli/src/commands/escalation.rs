// raxis-cli::commands::escalation — escalation approve / deny.
//
// Normative reference: cli-ceremony.md §4.1 `escalation approve`, `escalation deny`.
//
// **Tier-2 status:** the kernel's escalation handlers are stubs in v1
// (peripherals.md §3 lists ApproveEscalation / DenyEscalation as
// "stub responses" today). The CLI side wraps the operator-level
// payload (escalation_id, scope, sig, …) inside the typed enum's
// `payload: serde_json::Value` slot so the operator can already
// exercise the round-trip; once the handlers go live the typed
// payload variants will replace the JSON `Value` and the CLI will
// be updated to construct them directly.

use raxis_types::operator_wire::OperatorRequest;
use serde_json::json;

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
    let mut max_uses: Option<u32> = None;
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
    let valid_for_secs = valid_for_secs.ok_or_else(|| CliError::Usage("escalation approve requires --valid-for <secs>".to_owned()))?;

    // Build approval scope canonical bytes and sign.
    // Format: escalation_id (UUID) || 0x00 || capability_class || 0x00 || max_uses_le_u32 || 0x00 || valid_for_le_u64
    let key_path = flags.operator_key_path.as_deref()
        .ok_or_else(|| CliError::Usage("--operator-key is required for escalation approve".to_owned()))?;
    let signing_key = crate::signing::load_operator_key(key_path)?;

    let mut signing_input = Vec::new();
    signing_input.extend_from_slice(escalation_id.as_bytes());
    signing_input.push(0x00);
    signing_input.extend_from_slice(capability_class.as_bytes());
    signing_input.push(0x00);
    signing_input.extend_from_slice(&max_uses.to_le_bytes());
    signing_input.push(0x00);
    signing_input.extend_from_slice(&valid_for_secs.to_le_bytes());
    let sig_hex = crate::signing::sign_bytes(&signing_key, &signing_input);

    let (mut conn, fingerprint) = open_conn(flags)?;
    let req = OperatorRequest::ApproveEscalation {
        payload: json!({
            "escalation_id": escalation_id,
            "approval_scope": {
                "capability_class": capability_class,
                "max_uses": max_uses,
                "valid_for_seconds": valid_for_secs,
            },
            "operator_sig": sig_hex,
            "approved_by": fingerprint,
        }),
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        let token = ok["approval_token"].as_str().unwrap_or("?");
        println!("Escalation {escalation_id} approved.");
        println!("approval_token: {token}");
        println!("(Pass this token to the planner out-of-band.)");
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

    let (mut conn, fingerprint) = open_conn(flags)?;
    let req = OperatorRequest::DenyEscalation {
        payload: json!({
            "escalation_id": escalation_id,
            "reason": reason,
            "denied_by": fingerprint,
        }),
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |_| {
        println!("Escalation {escalation_id} denied.");
    })
}
