// raxis-cli::commands::epoch — epoch advance.
//
// Normative reference: cli-ceremony.md §4.1 `epoch advance`.

use std::path::PathBuf;

use raxis_types::operator_wire::OperatorRequest;
use serde_json::json;

use crate::commands::plan::{handle_response, open_conn, to_wire};
use crate::errors::CliError;
use crate::GlobalFlags;

pub fn run_advance(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut policy_path: Option<PathBuf> = None;
    let mut sig_path: Option<PathBuf> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--policy" => {
                i += 1;
                policy_path = Some(PathBuf::from(
                    args.get(i).ok_or_else(|| CliError::Usage("--policy requires a path".to_owned()))?,
                ));
            }
            "--sig" => {
                i += 1;
                sig_path = Some(PathBuf::from(
                    args.get(i).ok_or_else(|| CliError::Usage("--sig requires a path".to_owned()))?,
                ));
            }
            other => return Err(CliError::Usage(format!("unknown epoch advance flag: {other:?}"))),
        }
        i += 1;
    }

    let policy_path = policy_path
        .ok_or_else(|| CliError::Usage("epoch advance requires --policy <path>".to_owned()))?
        .canonicalize()
        .map_err(|e| CliError::Io { path: "policy path".to_owned(), source: e })?;

    let sig_path = sig_path
        .ok_or_else(|| CliError::Usage("epoch advance requires --sig <path>".to_owned()))?
        .canonicalize()
        .map_err(|e| CliError::Io { path: "sig path".to_owned(), source: e })?;

    let (mut conn, fingerprint) = open_conn(flags)?;
    // RotateEpoch is a tier-2 stub in v1; the kernel-side enum carries
    // an opaque `payload: serde_json::Value`. The CLI keeps the same
    // field names it always used so the existing operator scripts
    // continue to work; once the handler goes live the typed payload
    // variant will replace this stub.
    let req = OperatorRequest::RotateEpoch {
        payload: json!({
            "policy_path":  policy_path.display().to_string(),
            "sig_path":     sig_path.display().to_string(),
            "triggered_by": fingerprint,
        }),
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        println!("Epoch advanced:");
        println!("  new_epoch_id:             {}", ok["new_epoch_id"].as_u64().unwrap_or(0));
        println!("  n_delegations_marked_stale: {}", ok["n_delegations_marked_stale"].as_u64().unwrap_or(0));
        println!("  n_sessions_invalidated:    {}", ok["n_sessions_invalidated"].as_u64().unwrap_or(0));
        println!("  policy_sha256:             {}", ok["policy_sha256"].as_str().unwrap_or("?"));
    })
}
