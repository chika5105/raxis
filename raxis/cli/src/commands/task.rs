// raxis-cli::commands::task — task abort / resume / retry.
//
// Normative reference: cli-ceremony.md §4.1 task operations.
//
// Wire shape: see `commands/session.rs` header. Every operator op
// goes through `raxis_types::operator_wire::OperatorRequest` so the
// CLI and kernel share one source of truth.

use raxis_types::operator_wire::OperatorRequest;

use crate::commands::plan::{handle_response, open_conn, to_wire};
use crate::errors::CliError;
use crate::GlobalFlags;

pub fn run_abort(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let task_id = args
        .first()
        .ok_or_else(|| CliError::Usage("task abort requires <task_id>".to_owned()))?;

    let (mut conn, fingerprint) = open_conn(flags)?;
    let req = OperatorRequest::AbortTask {
        task_id:    task_id.clone(),
        aborted_by: fingerprint,
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        // The kernel emits OperatorResponse::Ack { message } for
        // task ops today (no structured success payload yet);
        // `state` will not be present, so we fall back to the
        // post-condition we expect.
        let state = ok["state"].as_str().unwrap_or("Aborted");
        println!("Task {task_id} aborted. New state: {state}");
    })
}

pub fn run_resume(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let task_id = args
        .first()
        .ok_or_else(|| CliError::Usage("task resume requires <task_id>".to_owned()))?;

    let (mut conn, fingerprint) = open_conn(flags)?;
    let req = OperatorRequest::ResumeTask {
        task_id:    task_id.clone(),
        resumed_by: fingerprint,
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        println!(
            "Task {} resumed at {}. Prior state: {}",
            task_id,
            ok["transitioned_at"].as_i64().unwrap_or(0),
            ok["prior_state"].as_str().unwrap_or("BlockedRecoveryPending")
        );
    })
}

pub fn run_retry(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let task_id = args
        .first()
        .ok_or_else(|| CliError::Usage("task retry requires <task_id>".to_owned()))?;

    let (mut conn, _) = open_conn(flags)?;
    let req = OperatorRequest::RetryTask { task_id: task_id.clone() };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        println!(
            "Task {} retried. Status: {} at {}",
            task_id,
            ok["state"].as_str().unwrap_or("Admitted"),
            ok["transitioned_at"].as_i64().unwrap_or(0)
        );
    })
}
