// raxis-cli::commands::task — task abort / resume / retry / outputs.
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
        task_id: task_id.clone(),
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
        task_id: task_id.clone(),
        resumed_by: fingerprint,
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        println!(
            "Task {} resumed at {}. Prior state: {}",
            task_id,
            ok["transitioned_at"].as_i64().unwrap_or(0),
            ok["prior_state"]
                .as_str()
                .unwrap_or("BlockedRecoveryPending")
        );
    })
}

pub fn run_retry(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let task_id = args
        .first()
        .ok_or_else(|| CliError::Usage("task retry requires <task_id>".to_owned()))?;

    let (mut conn, _) = open_conn(flags)?;
    let req = OperatorRequest::RetryTask {
        task_id: task_id.clone(),
    };
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

/// `raxis task outputs <task_id>` — list every typed structured
/// output emitted by sessions under `task_id`, ordered oldest →
/// newest. Implements the CLI surface for V2 §3.2 (StructuredOutput
/// tool).
///
/// Pretty-prints one line per row:
///   `<emitted_at>  <kind>[<severity>]  <output_id>  <one-line summary>`
/// followed by an indented JSON pretty-print of the payload so the
/// operator can grep severities, file lists, or tests counts. The
/// payload comes from the kernel verbatim — it has already been
/// validated and normalised at admission time
/// (`StructuredOutputKind::validate_and_normalise`), so this CLI does
/// no further validation.
pub fn run_outputs(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let task_id = args
        .first()
        .ok_or_else(|| CliError::Usage("task outputs requires <task_id>".to_owned()))?;

    let (mut conn, _) = open_conn(flags)?;
    let req = OperatorRequest::ListTaskOutputs {
        task_id: task_id.clone(),
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        let outputs = ok["outputs"].as_array().cloned().unwrap_or_default();
        if outputs.is_empty() {
            println!("(no structured outputs emitted for task {task_id})");
            return;
        }
        println!("{} structured outputs for task {task_id}:", outputs.len());
        for entry in &outputs {
            let emitted_at = entry["emitted_at"].as_i64().unwrap_or(0);
            let kind = entry["kind"].as_str().unwrap_or("unknown");
            let severity = entry["severity"]
                .as_str()
                .map(|s| format!("/{s}"))
                .unwrap_or_default();
            let output_id = entry["output_id"].as_str().unwrap_or("?");
            let session = entry["session_id"].as_str().unwrap_or("?");

            println!("  [{emitted_at}] {kind}{severity}  {output_id}  (session {session})");

            let payload_str = entry["payload_json"].as_str().unwrap_or("{}");
            // Indent the payload JSON two more spaces so it groups
            // visually under the heading line. If the kernel ever
            // hands us malformed JSON (it shouldn't — validated at
            // admission), fall back to printing the raw string so
            // the operator still gets the bytes.
            match serde_json::from_str::<serde_json::Value>(payload_str)
                .and_then(|v| serde_json::to_string_pretty(&v))
            {
                Ok(pp) => {
                    for line in pp.lines() {
                        println!("      {line}");
                    }
                }
                Err(_) => println!("      {payload_str}"),
            }
        }
    })
}
