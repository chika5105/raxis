// raxis-cli::commands::initiative — initiative abort / quarantine.
//
// Normative reference: cli-ceremony.md §4.1 `initiative abort`,
// §4.6 `initiative quarantine` (step-10 quarantine primitives).

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
