// raxis-cli::commands::task — task abort / resume / retry.
//
// Normative reference: cli-ceremony.md §4.1 task operations.

use serde_json::json;

use crate::commands::plan::{handle_response, open_conn};
use crate::errors::CliError;
use crate::GlobalFlags;

pub fn run_abort(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let task_id = args
        .first()
        .ok_or_else(|| CliError::Usage("task abort requires <task_id>".to_owned()))?;

    let (mut conn, _) = open_conn(flags)?;
    let req = json!({ "op": "AbortTask", "task_id": task_id });
    let resp = conn.send_request(&req)?;
    handle_response(resp, |ok| {
        println!(
            "Task {} aborted. New state: {}",
            task_id,
            ok["state"].as_str().unwrap_or("Aborted")
        );
    })
}

pub fn run_resume(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let task_id = args
        .first()
        .ok_or_else(|| CliError::Usage("task resume requires <task_id>".to_owned()))?;

    let (mut conn, _) = open_conn(flags)?;
    let req = json!({ "op": "ResumeTask", "task_id": task_id });
    let resp = conn.send_request(&req)?;
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
    let req = json!({ "op": "RetryTask", "task_id": task_id });
    let resp = conn.send_request(&req)?;
    handle_response(resp, |ok| {
        println!(
            "Task {} retried. Status: {} at {}",
            task_id,
            ok["state"].as_str().unwrap_or("Admitted"),
            ok["transitioned_at"].as_i64().unwrap_or(0)
        );
    })
}
