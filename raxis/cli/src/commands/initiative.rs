// raxis-cli::commands::initiative — initiative abort / quarantine / watch.
//
// Normative reference: cli-ceremony.md §4.1 `initiative abort`,
// §4.6 `initiative quarantine` (step-10 quarantine primitives),
// `v2_extended_gaps.md §2.1 SubscribeInitiative` for `initiative watch`.

use raxis_types::operator_wire::OperatorRequest;

use crate::commands::plan::{handle_response, open_conn, to_wire};
use crate::errors::CliError;
use crate::GlobalFlags;

pub fn run_abort(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let initiative_id = args.first().ok_or_else(|| {
        CliError::Usage("initiative abort requires <initiative_id>".to_owned())
    })?;

    let (mut conn, fingerprint) = open_conn(flags)?;
    let req = OperatorRequest::AbortInitiative {
        initiative_id: initiative_id.clone(),
        aborted_by:    fingerprint,
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |_| {
        println!("Initiative {initiative_id} aborted. All non-terminal tasks cancelled.");
    })
}

// ---------------------------------------------------------------------------
// initiative quarantine <initiative_id> [--reason <text>]
//
// Spec: cli-ceremony.md §4.6 (step-10), kernel-store.md §2.5.8 quarantine.
//
// Quarantine is a one-way curtain: every subsequent IntentRequest against
// `initiative_id` will be rejected by the kernel with the terminal error
// `FAIL_INITIATIVE_QUARANTINED` (see
// `raxis-types::PlannerErrorCode::FailInitiativeQuarantined`). Existing
// in-flight tasks remain in their current state — quarantine does not
// abort, it freezes. Use `initiative abort` for the destructive path.
//
// `--reason` is optional and capped server-side at 512 bytes
// (`kernel/src/ipc/operator.rs::cap_reason`). It is mirrored verbatim
// into the `InitiativeQuarantined` audit event.
// ---------------------------------------------------------------------------
pub fn run_quarantine(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let parsed = parse_quarantine_args(args)?;

    let (mut conn, _fp) = open_conn(flags)?;
    let initiative_id = parsed.initiative_id.clone();
    let req = OperatorRequest::QuarantineInitiative {
        initiative_id: parsed.initiative_id,
        reason:        parsed.reason,
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        let was_already = ok["was_already_quarantined"].as_bool().unwrap_or(false);
        let at          = ok["quarantined_at"].as_i64().unwrap_or(0);
        if was_already {
            println!(
                "Initiative {initiative_id} was already quarantined (no-op). \
                 Existing quarantined_at={at}.",
            );
        } else {
            println!(
                "Initiative {initiative_id} quarantined at unix={at}. \
                 Subsequent IntentRequests will be rejected with FAIL_INITIATIVE_QUARANTINED.",
            );
        }
    })
}

/// `raxis initiative watch <initiative_id>` — subscribe to the
/// realtime event stream for `initiative_id` and pretty-print
/// each frame as it arrives. Implements `v2_extended_gaps.md §2.1`.
///
/// Wire flow:
///   1. Send `OperatorRequest::SubscribeInitiative`.
///   2. Read the kernel's `OperatorResponse::InitiativeSubscribed`
///      ack — confirms the upgrade succeeded.
///   3. Read frames in a loop (each is an
///      `raxis_types::InitiativeEvent`) and pretty-print them.
///   4. Exit cleanly when the kernel writes a `Closed` frame
///      (initiative reached terminal state) or closes the
///      connection.
///
/// The CLI does NOT enforce a timeout — operators terminate the
/// watch with Ctrl-C (the `read_frame` blocking call surfaces the
/// closed connection on the next iteration).
pub fn run_watch(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let initiative_id = args.first().ok_or_else(|| {
        CliError::Usage("initiative watch requires <initiative_id>".to_owned())
    })?;

    let (mut conn, _fp) = open_conn(flags)?;
    let req = OperatorRequest::SubscribeInitiative {
        initiative_id: initiative_id.clone(),
    };
    let ack = conn.send_request(&to_wire(&req)?)?;

    // Surface kernel-side admission errors (e.g.
    // FAIL_INITIATIVE_NOT_FOUND, FAIL_INITIATIVE_TERMINAL) before
    // we drop into the event loop — `handle_response` would print
    // and return immediately on Error.
    let status = ack["status"].as_str().unwrap_or("");
    if status == "Error" {
        let code   = ack["payload"]["code"].as_str().unwrap_or("UNKNOWN");
        let detail = ack["payload"]["detail"].as_str().unwrap_or("(no detail)");
        return Err(CliError::KernelError { code: code.to_owned(), detail: detail.to_owned() });
    }
    if status != "InitiativeSubscribed" {
        return Err(CliError::Usage(format!(
            "kernel did not ack with InitiativeSubscribed: got status={status:?}"
        )));
    }

    println!("Watching initiative {initiative_id}. Press Ctrl-C to stop.");

    loop {
        let frame = match conn.read_frame()? {
            Some(v) => v,
            None    => {
                println!("(stream closed by kernel)");
                return Ok(());
            }
        };

        let kind = frame["kind"].as_str().unwrap_or("?");
        let payload = &frame["payload"];

        match kind {
            "TaskStateChanged" => println!(
                "  [{}] task={} {}→{}",
                payload["transitioned_at"].as_i64().unwrap_or(0),
                payload["task_id"].as_str().unwrap_or("?"),
                payload["from_state"].as_str().unwrap_or("None"),
                payload["to_state"].as_str().unwrap_or("?"),
            ),
            "InitiativeStateChanged" => println!(
                "  [{}] initiative {}→{}",
                payload["transitioned_at"].as_i64().unwrap_or(0),
                payload["from_state"].as_str().unwrap_or("None"),
                payload["to_state"].as_str().unwrap_or("?"),
            ),
            "ReviewAggregationCompleted" => println!(
                "  reviewers for task {} all_passed={}",
                payload["task_id"].as_str().unwrap_or("?"),
                payload["all_passed"].as_bool().unwrap_or(false),
            ),
            "EscalationRaised" => println!(
                "  escalation {} raised on task {} (capability {})",
                payload["escalation_id"].as_str().unwrap_or("?"),
                payload["task_id"].as_str().unwrap_or("(none)"),
                payload["capability"].as_str().unwrap_or("?"),
            ),
            "EscalationResolved" => println!(
                "  escalation {} resolved → {}",
                payload["escalation_id"].as_str().unwrap_or("?"),
                payload["outcome"].as_str().unwrap_or("?"),
            ),
            "IntegrationMergeCompleted" => println!(
                "  integration merge succeeded: task={} head_sha={}",
                payload["task_id"].as_str().unwrap_or("?"),
                payload["head_sha"].as_str().unwrap_or("?"),
            ),
            "StructuredOutputEmitted" => {
                let sev = payload["severity"].as_str()
                    .map(|s| format!("/{s}"))
                    .unwrap_or_default();
                println!(
                    "  structured_output {}{} on task {}",
                    payload["output_kind"].as_str().unwrap_or("?"),
                    sev,
                    payload["task_id"].as_str().unwrap_or("?"),
                );
            }
            "Closed" => {
                let reason = payload["reason"].as_str().unwrap_or("?");
                println!("(stream closed by kernel: {reason})");
                return Ok(());
            }
            other => {
                println!("  [unrecognised event kind={other}]");
            }
        }
    }
}

/// Parsed CLI shape for `initiative quarantine`. Split out so the
/// arg-parser is testable without `open_conn` opening a real socket.
#[derive(Debug, PartialEq, Eq)]
struct ParsedQuarantineArgs {
    initiative_id: String,
    reason:        Option<String>,
}

fn parse_quarantine_args(args: &[String]) -> Result<ParsedQuarantineArgs, CliError> {
    let mut iter = args.iter();
    let initiative_id = iter
        .next()
        .ok_or_else(|| {
            CliError::Usage(
                "initiative quarantine requires <initiative_id> [--reason <text>]".to_owned(),
            )
        })?
        .clone();

    let mut reason: Option<String> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--reason" => {
                let v = iter.next().ok_or_else(|| {
                    CliError::Usage("--reason requires a value".to_owned())
                })?;
                reason = Some(v.clone());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown flag for `initiative quarantine`: {other:?}"
                )));
            }
        }
    }

    Ok(ParsedQuarantineArgs {
        initiative_id,
        reason,
    })
}

// ---------------------------------------------------------------------------
// Tests — arg-parsing only. Wire-shape and kernel-side semantics are
// covered by `raxis-types::operator_wire::tests` and
// `raxis-store::views::initiative_quarantines::tests` respectively.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn quarantine_without_initiative_id_is_a_usage_error() {
        let err = parse_quarantine_args(&[]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        if let CliError::Usage(m) = err {
            assert!(m.contains("initiative quarantine"));
            assert!(m.contains("<initiative_id>"));
        }
    }

    #[test]
    fn quarantine_id_only_yields_no_reason() {
        let parsed = parse_quarantine_args(&s(&["init-abc"])).unwrap();
        assert_eq!(
            parsed,
            ParsedQuarantineArgs {
                initiative_id: "init-abc".to_owned(),
                reason:        None,
            }
        );
    }

    #[test]
    fn quarantine_with_reason_captures_value() {
        let parsed =
            parse_quarantine_args(&s(&["init-abc", "--reason", "leaked key in #ops"])).unwrap();
        assert_eq!(
            parsed,
            ParsedQuarantineArgs {
                initiative_id: "init-abc".to_owned(),
                reason:        Some("leaked key in #ops".to_owned()),
            }
        );
    }

    #[test]
    fn quarantine_reason_without_value_is_usage_error() {
        let err = parse_quarantine_args(&s(&["init-abc", "--reason"])).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        if let CliError::Usage(m) = err {
            assert!(m.contains("--reason requires a value"));
        }
    }

    #[test]
    fn quarantine_unknown_flag_is_usage_error() {
        let err = parse_quarantine_args(&s(&["init-abc", "--bogus"])).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        if let CliError::Usage(m) = err {
            assert!(m.contains("--bogus") || m.contains("unknown flag"));
        }
    }
}
