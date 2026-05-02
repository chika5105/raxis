// raxis-cli::commands::plan — plan submit / approve / reject.
//
// Normative reference: cli-ceremony.md §4.1 `plan submit`, `plan approve`, `plan reject`.

use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::errors::CliError;
use crate::GlobalFlags;

// ---------------------------------------------------------------------------
// plan submit <initiative_id> <plan_dir>
// ---------------------------------------------------------------------------

pub fn run_submit(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.len() < 2 {
        return Err(CliError::Usage(
            "plan submit requires <initiative_id> <plan_dir>".to_owned(),
        ));
    }
    let initiative_id = &args[0];
    let plan_dir = PathBuf::from(&args[1]);

    let plan_toml_path = plan_dir.join("plan.toml");
    let plan_sig_path = plan_dir.join("plan.sig");

    // Load plan content.
    let plan_toml = fs::read_to_string(&plan_toml_path).map_err(|e| CliError::Io {
        path: plan_toml_path.display().to_string(),
        source: e,
    })?;
    let plan_sig_toml: toml::Value = toml::from_str(
        &fs::read_to_string(&plan_sig_path).map_err(|e| CliError::Io {
            path: plan_sig_path.display().to_string(),
            source: e,
        })?,
    )
    .map_err(|e| CliError::Policy(format!("plan.sig parse error: {e}")))?;

    let plan_sig_hex = plan_sig_toml["signature_hex"]
        .as_str()
        .ok_or_else(|| CliError::Policy("plan.sig missing signature_hex".to_owned()))?
        .to_owned();
    let submitted_by = plan_sig_toml["signed_by"]
        .as_str()
        .ok_or_else(|| CliError::Policy("plan.sig missing signed_by".to_owned()))?
        .to_owned();

    let conn = open_conn(flags)?;
    let (mut conn, _) = conn;

    let req = json!({
        "op": "CreateInitiative",
        "initiative_id": initiative_id,
        "plan_toml": plan_toml,
        "plan_sig_hex": plan_sig_hex,
        "submitted_by": submitted_by,
    });

    let resp = conn.send_request(&req)?;
    handle_response(resp, |ok| {
        println!(
            "Initiative {} created. Status: {}",
            initiative_id,
            ok["status"].as_str().unwrap_or("PlanSubmitted")
        );
    })
}

// ---------------------------------------------------------------------------
// plan approve <initiative_id>
// ---------------------------------------------------------------------------

pub fn run_approve(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let initiative_id = args
        .first()
        .ok_or_else(|| CliError::Usage("plan approve requires <initiative_id>".to_owned()))?;

    let (mut conn, fingerprint) = open_conn(flags)?;

    let req = json!({
        "op": "ApprovePlan",
        "initiative_id": initiative_id,
        "approving_operator": fingerprint,
    });
    let resp = conn.send_request(&req)?;
    handle_response(resp, |ok| {
        println!(
            "Initiative {} approved. Tasks admitted: {}",
            initiative_id,
            ok["tasks_admitted"].as_u64().unwrap_or(0)
        );
    })
}

// ---------------------------------------------------------------------------
// plan reject <initiative_id>
// ---------------------------------------------------------------------------

pub fn run_reject(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let initiative_id = args
        .first()
        .ok_or_else(|| CliError::Usage("plan reject requires <initiative_id>".to_owned()))?;

    let (mut conn, _) = open_conn(flags)?;

    let req = json!({
        "op": "RejectPlan",
        "initiative_id": initiative_id,
    });
    let resp = conn.send_request(&req)?;
    handle_response(resp, |_| {
        println!("Initiative {initiative_id} rejected.");
    })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub fn open_conn(
    flags: &GlobalFlags,
) -> Result<(crate::conn::OperatorConn, String), CliError> {
    let key_path = flags
        .operator_key_path
        .as_deref()
        .ok_or_else(|| CliError::Usage("--operator-key <path> is required for this command".to_owned()))?;

    let signing_key = crate::signing::load_operator_key(key_path)?;
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let fingerprint = crate::conn::pubkey_fingerprint(&pubkey_bytes);

    let conn = crate::conn::OperatorConn::connect(
        &flags.socket_path(),
        key_path,
        &fingerprint,
    )?;
    Ok((conn, fingerprint))
}

pub fn handle_response(
    resp: Value,
    on_ok: impl FnOnce(&Value),
) -> Result<(), CliError> {
    match resp["status"].as_str() {
        Some("Ok") | Some("ok") => {
            on_ok(&resp);
            Ok(())
        }
        _ => {
            let code = resp["code"].as_str().unwrap_or("UNKNOWN");
            let detail = resp["detail"].to_string();
            Err(CliError::KernelError {
                code: code.to_owned(),
                detail,
            })
        }
    }
}
