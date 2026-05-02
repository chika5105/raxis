// raxis-cli::commands::delegation — delegation grant.
//
// Normative reference: cli-ceremony.md §4.1 `delegation grant`.

use std::path::PathBuf;

use serde_json::json;

use crate::commands::plan::{handle_response, open_conn};
use crate::errors::CliError;
use crate::GlobalFlags;

pub fn run_grant(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut session_id: Option<String> = None;
    let mut capability: Option<String> = None;
    let mut role_id: Option<String> = None;
    let mut ttl_secs: Option<u64> = None;
    let mut scope_json: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--session" => {
                i += 1;
                session_id = Some(args.get(i).ok_or_else(|| CliError::Usage("--session requires a value".to_owned()))?.clone());
            }
            "--capability" => {
                i += 1;
                capability = Some(args.get(i).ok_or_else(|| CliError::Usage("--capability requires a value".to_owned()))?.clone());
            }
            "--role" => {
                i += 1;
                role_id = Some(args.get(i).ok_or_else(|| CliError::Usage("--role requires a value".to_owned()))?.clone());
            }
            "--ttl" => {
                i += 1;
                let ttl_str = args.get(i).ok_or_else(|| CliError::Usage("--ttl requires a number".to_owned()))?;
                ttl_secs = Some(ttl_str.parse::<u64>().map_err(|_| CliError::Usage(format!("--ttl must be an integer, got {ttl_str:?}")))?);
            }
            "--scope-json" => {
                i += 1;
                scope_json = Some(args.get(i).ok_or_else(|| CliError::Usage("--scope-json requires a value".to_owned()))?.clone());
            }
            other => return Err(CliError::Usage(format!("unknown delegation grant flag: {other:?}"))),
        }
        i += 1;
    }

    let session_id = session_id.ok_or_else(|| CliError::Usage("delegation grant requires --session <id>".to_owned()))?;
    let capability = capability.ok_or_else(|| CliError::Usage("delegation grant requires --capability <class>".to_owned()))?;
    let role_id = role_id.ok_or_else(|| CliError::Usage("delegation grant requires --role <role_id>".to_owned()))?;
    let ttl_secs = ttl_secs.ok_or_else(|| CliError::Usage("delegation grant requires --ttl <seconds>".to_owned()))?;

    let expires_at = now_unix_secs() + ttl_secs;

    // Build canonical signing domain and sign.
    let key_path = flags.operator_key_path.as_deref()
        .ok_or_else(|| CliError::Usage("--operator-key is required for delegation grant".to_owned()))?;
    let signing_key = crate::signing::load_operator_key(key_path)?;

    let signing_domain = crate::signing::delegation_grant_signing_domain(
        &session_id,
        &capability,
        &role_id,
        expires_at,
        scope_json.as_deref(),
    );
    let signing_input = raxis_crypto::token::sha256_hex(&signing_domain);
    let sig_hex = crate::signing::sign_bytes(&signing_key, signing_input.as_bytes());

    let (mut conn, fingerprint) = open_conn(flags)?;
    let req = json!({
        "op": "GrantDelegation",
        "session_id": session_id,
        "capability_class": capability,
        "delegating_role_id": role_id,
        "expires_at": expires_at,
        "scope_json": scope_json,
        "operator_sig": sig_hex,
        "granted_by": fingerprint,
    });

    let resp = conn.send_request(&req)?;
    handle_response(resp, |ok| {
        let delegation_id = ok["delegation_id"].as_str().unwrap_or("?");
        println!("Delegation {delegation_id} granted: session={session_id} capability={capability} role={role_id} expires={expires_at}");
    })
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
