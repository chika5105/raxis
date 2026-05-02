// raxis-cli::commands::session — session create / revoke.
//
// Normative reference: cli-ceremony.md §4.1 `session create`, `session revoke`.

use std::path::PathBuf;

use serde_json::json;

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
                worktree_root = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| CliError::Usage("--worktree-root requires a path".to_owned()))?,
                ));
            }
            "--base-tracking-ref" => {
                i += 1;
                base_tracking_ref = Some(
                    args.get(i)
                        .ok_or_else(|| CliError::Usage("--base-tracking-ref requires a value".to_owned()))?
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
            other => return Err(CliError::Usage(format!("unknown session create flag: {other:?}"))),
        }
        i += 1;
    }

    if role != "planner" {
        return Err(CliError::Usage(
            "FAIL_ROLE_NOT_OPERATOR_CREATABLE: only --role planner is supported in v1".to_owned(),
        ));
    }
    let worktree_root = worktree_root
        .ok_or_else(|| CliError::Usage("session create requires --worktree-root <path>".to_owned()))?;

    // Generate lineage_id if not provided. `uuid::Uuid::new_v4()` routes to
    // `getrandom` and panics on RNG failure (acceptable here — the rest of the
    // CLI is also synchronous and we have no recovery path; we do not want to
    // emit a degraded lineage_id).
    let lineage_id = lineage_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let (mut conn, fingerprint) = open_conn(flags)?;
    let req = json!({
        "op": "CreateSession",
        "role": role,
        "worktree_root": worktree_root.display().to_string(),
        "base_tracking_ref": base_tracking_ref,
        "task_id": task_id,
        "lineage_id": lineage_id,
        "created_by_operator": fingerprint,
    });

    let resp = conn.send_request(&req)?;
    handle_response(resp, |ok| {
        let session_id = ok["session_id"].as_str().unwrap_or("?");
        let token = ok["session_token"].as_str().unwrap_or("?");
        let expires_at = ok["expires_at"].as_i64().unwrap_or(0);
        let lineage = ok["lineage_id"].as_str().unwrap_or(&lineage_id);

        // Token → stderr for secure capture.
        // All other fields → stdout.
        println!("Session created:");
        println!("  session_id:   {session_id}");
        println!("  role:         planner");
        println!("  worktree:     {}", worktree_root.display());
        println!("  expires_at:   {expires_at}");
        println!("  lineage_id:   {lineage}");
        eprintln!("RAXIS_SESSION_TOKEN={token}");
    })
}

// ---------------------------------------------------------------------------
// session revoke
// ---------------------------------------------------------------------------

pub fn run_revoke(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let session_id = args
        .first()
        .ok_or_else(|| CliError::Usage("session revoke requires <session_id>".to_owned()))?;

    let (mut conn, _) = open_conn(flags)?;
    let req = json!({ "op": "RevokeSession", "session_id": session_id });
    let resp = conn.send_request(&req)?;
    handle_response(resp, |ok| {
        let revoked_at = ok["revoked_at"].as_i64().unwrap_or(0);
        println!("Session {session_id} revoked at {revoked_at}");
    })
}

// (UUID minting moved to `uuid::Uuid::new_v4()` — see usage in `run_create`.)
