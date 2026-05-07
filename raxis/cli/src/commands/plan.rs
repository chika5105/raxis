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
// plan submit <initiative_id> <plan_dir>
// ---------------------------------------------------------------------------

pub fn run_submit(_flags: &GlobalFlags, _args: &[String]) -> Result<(), CliError> {
    // V2 hard-reject (plan-bundle-sealing.md §4.5).
    //
    // The V1 two-arg `plan submit <initiative_id> <plan_dir>` form is
    // rejected at argument-parse time with a hint pointing to
    // `submit plan <plan.toml>` — the V2 atomic sign+submit workflow.
    //
    // This rejection lands together with kernel admission (§8.1) so the
    // V2 functional replacement and the V1 hard-reject ship in the same
    // commit: an operator typing `plan submit foo bar` has the new path
    // available the moment the old path stops working.
    //
    // No host-disk I/O happens before this check: we do NOT want a
    // missing plan.toml / plan.sig path or a permission error to mask
    // the actual signal (V1 is gone). The reject also covers the case
    // where the operator passes the V2 invocation against the wrong
    // top-level subcommand (`plan submit` instead of `submit plan`) —
    // a common typo for muscle-memory operators.
    Err(CliError::Usage(v1_plan_submit_removal_message()))
}

/// Operator-facing migration text emitted by `plan submit`.
///
/// Pulled out into a standalone function so the test suite can pin the
/// exact message: any drift here means an operator-visible behaviour
/// change and forces a corresponding spec update in
/// `plan-bundle-sealing.md §4.5`.
pub(crate) fn v1_plan_submit_removal_message() -> String {
    "V1 `plan submit <initiative_id> <plan_dir>` is removed in V2.\n\
     \n\
     Use the V2.1 atomic sign+submit workflow instead:\n\
     \n\
     \traxis submit plan <plan.toml> [--initiative-id <id>] \\\n\
     \t                              [--no-dry-run]\n\
     \n\
     The V2 path takes a `plan.toml` *file* (not a directory), no\n\
     intermediate `plan.sig` is written, and the kernel admits the\n\
     signed bundle in a single IPC call. See plan-bundle-sealing.md\n\
     §4 for the full ceremony and §4.5 for the migration guide."
        .to_owned()
}

// ---------------------------------------------------------------------------
// plan approve <initiative_id>
// ---------------------------------------------------------------------------

pub fn run_approve(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let initiative_id = args
        .first()
        .ok_or_else(|| CliError::Usage("plan approve requires <initiative_id>".to_owned()))?;

    let (mut conn, fingerprint) = open_conn(flags)?;

    // `operator_pubkey_hex` is preserved on the wire for backward
    // compatibility but the kernel IGNORES it (kernel-store.md §2.5.3).
    // The canonical pubkey is looked up server-side from
    // `policy.operators` keyed by the authenticated fingerprint.
    let req = OperatorRequest::ApprovePlan {
        initiative_id:       initiative_id.clone(),
        approving_operator:  fingerprint,
        operator_pubkey_hex: String::new(),
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
// plan reject <initiative_id>
// ---------------------------------------------------------------------------

pub fn run_reject(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let initiative_id = args
        .first()
        .ok_or_else(|| CliError::Usage("plan reject requires <initiative_id>".to_owned()))?;

    let (mut conn, fingerprint) = open_conn(flags)?;

    let req = OperatorRequest::RejectPlan {
        initiative_id: initiative_id.clone(),
        rejected_by:   fingerprint,
        reason:        None,
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

/// Serialise a typed `OperatorRequest` into the JSON value that goes on
/// the wire. Wrapping `serde_json::to_value` in this helper keeps the
/// failure mode consistent across CLI commands: a serialisation error
/// here is *always* a kernel-side bug (the type is statically known
/// to be serialisable), so we surface it as a usage error rather than
/// a kernel-comm error.
pub fn to_wire(req: &OperatorRequest) -> Result<Value, CliError> {
    serde_json::to_value(req).map_err(|e| {
        CliError::Usage(format!("could not serialise operator request: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Tests — V1 plan-submit hard-reject (plan-bundle-sealing.md §4.5)
// ---------------------------------------------------------------------------
//
// The reject message is pinned by tests so any drift here forces a
// corresponding spec update in `plan-bundle-sealing.md §4.5`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_plan_submit_removal_message_pins_operator_facing_text() {
        let msg = v1_plan_submit_removal_message();
        // V2 invocation appears verbatim so a copy-paste lands on the
        // right command.
        assert!(msg.contains("raxis submit plan"), "msg = {msg:?}");
        // Spec back-reference is present so the operator can read up.
        assert!(msg.contains("plan-bundle-sealing.md"), "msg = {msg:?}");
        // The literal V1 invocation appears so a CI grep on
        // "plan submit" still matches the reject hint.
        assert!(
            msg.contains("V1 `plan submit <initiative_id> <plan_dir>`"),
            "msg = {msg:?}",
        );
        // The reject explicitly names the V2 atomic-sign+submit ceremony
        // (this is the operator's mental model for the migration).
        assert!(msg.contains("atomic sign+submit"), "msg = {msg:?}");
    }
}

/// Pattern-match the kernel's `OperatorResponse` envelope. The wire
/// shape (locked by `raxis_types::operator_wire::tests`) is:
///
///   { "status": "<Variant>", "payload": {...} }
///
/// `status = "Error"` collapses to `CliError::KernelError`; every other
/// status is treated as success and the inner `payload` object is
/// passed to `on_ok` (so callers index payload fields directly,
/// e.g. `ok["session_id"]`).
pub fn handle_response(
    resp: Value,
    on_ok: impl FnOnce(&Value),
) -> Result<(), CliError> {
    let status = resp["status"].as_str();
    let payload = &resp["payload"];

    match status {
        Some("Error") => {
            let code   = payload["code"].as_str().unwrap_or("UNKNOWN").to_owned();
            let detail = payload["detail"].as_str().unwrap_or("(no detail)").to_owned();
            Err(CliError::KernelError { code, detail })
        }
        Some(_) => {
            on_ok(payload);
            Ok(())
        }
        None => Err(CliError::KernelError {
            code:   "MALFORMED_RESPONSE".to_owned(),
            detail: format!("kernel response missing `status` field: {resp}"),
        }),
    }
}
