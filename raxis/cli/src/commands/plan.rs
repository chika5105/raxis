// raxis-cli::commands::plan — plan submit / approve / reject.
//
// Normative reference: cli-ceremony.md §4.1 `plan submit`, `plan approve`, `plan reject`.
//
// Wire shape: see `commands/session.rs` header — every operator op is
// constructed as a `raxis_types::operator_wire::OperatorRequest` and
// serialised with `serde_json::to_value`. The kernel decodes into the
// same type. Wire-shape contract tests live in
// `raxis_types::operator_wire::tests`.

use raxis_types::operator_wire::OperatorRequest;
use serde_json::Value;

use crate::errors::CliError;
use crate::GlobalFlags;

// ---------------------------------------------------------------------------
// plan approve <initiative_id>
//
// Note: the V1 `plan submit <initiative_id> <plan_dir>` form is removed
// in V2 (forward-only — no tombstone, no helpful-error fallback). The
// only path to admit a plan is `raxis submit plan <plan.toml>` per
// `plan-bundle-sealing.md §4`. An operator who types the old form gets
// the standard "did you mean…" closeness suggester pointing at the
// remaining `plan` sub-commands.
// ---------------------------------------------------------------------------

pub fn run_approve(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let initiative_id = parse_approve_args(args)?;

    let (mut conn, fingerprint) = open_conn(flags)?;

    // The canonical operator pubkey is looked up server-side from
    // `policy.operators` keyed by the authenticated fingerprint
    // (kernel-store.md §2.5.3); the wire never carries it. The
    // legacy `operator_pubkey_hex` field that earlier V2 builds
    // accepted-and-ignored was removed in V2.5.
    let req = OperatorRequest::ApprovePlan {
        initiative_id: initiative_id.to_owned(),
        approving_operator: fingerprint,
    };
    let req_json = to_wire(&req)?;

    let resp = conn.send_request(&req_json)?;
    handle_response(resp, |ok| {
        println!(
            "Initiative {} approved. Tasks admitted: {}",
            initiative_id,
            ok["tasks_admitted"].as_u64().unwrap_or(0)
        );
    })
}

// ---------------------------------------------------------------------------
// plan reject <initiative_id> [--reason <text>]
// ---------------------------------------------------------------------------

pub fn run_reject(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let RejectArgs {
        initiative_id,
        reason,
    } = parse_reject_args(args)?;

    let (mut conn, fingerprint) = open_conn(flags)?;

    let req = OperatorRequest::RejectPlan {
        initiative_id: initiative_id.clone(),
        rejected_by: fingerprint,
        reason,
    };
    let req_json = to_wire(&req)?;

    let resp = conn.send_request(&req_json)?;
    handle_response(resp, |_| {
        println!("Initiative {initiative_id} rejected.");
    })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn parse_approve_args(args: &[String]) -> Result<&str, CliError> {
    let initiative_id = args
        .first()
        .ok_or_else(|| CliError::Usage("plan approve requires <initiative_id>".to_owned()))?;
    if args.len() != 1 {
        return Err(CliError::Usage(
            "usage: raxis plan approve <initiative_id>".to_owned(),
        ));
    }
    Ok(initiative_id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RejectArgs {
    initiative_id: String,
    reason: Option<String>,
}

fn parse_reject_args(args: &[String]) -> Result<RejectArgs, CliError> {
    let initiative_id = args
        .first()
        .ok_or_else(|| CliError::Usage("plan reject requires <initiative_id>".to_owned()))?
        .to_owned();
    let mut reason: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--reason" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| CliError::Usage("--reason requires a value".to_owned()))?;
                if value.trim().is_empty() {
                    return Err(CliError::Usage("--reason must be non-empty".to_owned()));
                }
                reason = Some(value.to_owned());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown plan reject flag: {other:?} (try --reason TEXT)"
                )))
            }
        }
        i += 1;
    }
    Ok(RejectArgs {
        initiative_id,
        reason,
    })
}

pub fn open_conn(flags: &GlobalFlags) -> Result<(crate::conn::OperatorConn, String), CliError> {
    let key_path = flags.operator_key_path.as_deref().ok_or_else(|| {
        CliError::Usage("--operator-key <path> is required for this command".to_owned())
    })?;

    let signing_key = crate::signing::load_operator_key(key_path)?;
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let fingerprint = crate::conn::pubkey_fingerprint(&pubkey_bytes);

    let conn = crate::conn::OperatorConn::connect(&flags.socket_path(), key_path, &fingerprint)?;
    Ok((conn, fingerprint))
}

/// Serialise a typed `OperatorRequest` into the JSON value that goes on
/// the wire. Wrapping `serde_json::to_value` in this helper keeps the
/// failure mode consistent across CLI commands: a serialisation error
/// here is *always* a kernel-side bug (the type is statically known
/// to be serialisable), so we surface it as a usage error rather than
/// a kernel-comm error.
pub fn to_wire(req: &OperatorRequest) -> Result<Value, CliError> {
    serde_json::to_value(req)
        .map_err(|e| CliError::Usage(format!("could not serialise operator request: {e}")))
}

/// Pattern-match the kernel's `OperatorResponse` envelope. The wire
/// shape (locked by `raxis_types::operator_wire::tests`) is:
///
///   `{ "status": "<Variant>", "payload": {...} }`
///
/// `status = "Error"` collapses to `CliError::KernelError`; every other
/// status is treated as success and the inner `payload` object is
/// passed to `on_ok` (so callers index payload fields directly,
/// e.g. `ok["session_id"]`).
pub fn handle_response(resp: Value, on_ok: impl FnOnce(&Value)) -> Result<(), CliError> {
    let status = resp["status"].as_str();
    let payload = &resp["payload"];

    match status {
        Some("Error") => {
            let code = payload["code"].as_str().unwrap_or("UNKNOWN").to_owned();
            let detail = payload["detail"]
                .as_str()
                .unwrap_or("(no detail)")
                .to_owned();
            Err(CliError::KernelError { code, detail })
        }
        Some(_) => {
            on_ok(payload);
            Ok(())
        }
        None => Err(CliError::KernelError {
            code: "MALFORMED_RESPONSE".to_owned(),
            detail: format!("kernel response missing `status` field: {resp}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_parser_rejects_extra_args() {
        let err = parse_approve_args(&["init-1".to_owned(), "extra".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn reject_parser_accepts_reason() {
        let args = parse_reject_args(&[
            "init-1".to_owned(),
            "--reason".to_owned(),
            "bad scope".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            args,
            RejectArgs {
                initiative_id: "init-1".to_owned(),
                reason: Some("bad scope".to_owned()),
            }
        );
    }

    #[test]
    fn reject_parser_rejects_unknown_args() {
        let err = parse_reject_args(&["init-1".to_owned(), "extra".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }
}
