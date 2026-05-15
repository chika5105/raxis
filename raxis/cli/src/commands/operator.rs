// raxis-cli::commands::operator — operator-targeted privileged commands.
//
// Normative reference: cli-ceremony.md §4.7 (step-10 quarantine
// primitives) and kernel-store.md §2.5.8 quarantine.
//
// Today this module hosts only `operator quarantine-plans-by`, the
// big-red-button revocation primitive that sweeps every initiative
// whose plan was approved by a now-compromised operator fingerprint.
// It is the operator-scoped counterpart to `initiative quarantine`,
// which targets a single initiative_id.
//
// Wire shape: `raxis_types::operator_wire::OperatorRequest::QuarantinePlansBy`
// with response `OperatorResponse::QuarantineSwept`. The kernel emits
// one `InitiativeQuarantined` audit event per newly-quarantined row
// plus a single rollup `OperatorQuarantineSwept` event so the audit
// chain answers both "what did this command touch?" and "did the
// operator press the big red button?" without a JOIN.

use raxis_types::operator_wire::OperatorRequest;

use crate::commands::plan::{handle_response, open_conn, to_wire};
use crate::errors::CliError;
use crate::GlobalFlags;

// ---------------------------------------------------------------------------
// operator quarantine-plans-by <target_fingerprint> [--reason <text>]
//
// `target_fingerprint` is the SHA-256[:16] hex prefix that identifies a
// policy operator (matches `policy.operators[].pubkey_fingerprint` and
// `signed_plan_artifacts.signed_by_fingerprint`). The kernel will:
//   1. SELECT every initiative whose `signed_plan_artifacts.signed_by_fingerprint`
//      equals the target.
//   2. INSERT a row into `initiative_quarantines` for each initiative
//      not already quarantined (the call is idempotent — re-running
//      quarantines new plans only).
//   3. Emit per-initiative `InitiativeQuarantined` audit events plus
//      one rollup `OperatorQuarantineSwept` event.
//
// `--reason` is optional and capped at 512 bytes server-side. It is
// mirrored verbatim into every emitted audit event for forensic
// continuity.
//
// IMPORTANT: this command does NOT revoke the target's operator key
// or scrub their entry from `policy.operators`. Per security-model.md,
// operator-key removal is a separate ceremony that requires
// `policy sign` + `epoch advance`. Quarantine is the immediate
// containment primitive that buys time for the slower revocation
// ceremony to land.
// ---------------------------------------------------------------------------
pub fn run_quarantine_plans_by(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let parsed = parse_quarantine_plans_by_args(args)?;
    let target_fingerprint = parsed.target_fingerprint.clone();

    let (mut conn, _fp) = open_conn(flags)?;
    let req = OperatorRequest::QuarantinePlansBy {
        target_fingerprint: parsed.target_fingerprint,
        reason: parsed.reason,
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        let at = ok["quarantined_at"].as_i64().unwrap_or(0);
        let ids = ok["newly_quarantined_ids"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if ids.is_empty() {
            println!(
                "No initiatives newly quarantined for fingerprint {target_fingerprint} \
                 (either none exist or all are already quarantined)."
            );
        } else {
            println!(
                "Quarantined {n} initiative(s) signed by {target_fingerprint} at unix={at}:",
                n = ids.len(),
            );
            for v in ids {
                if let Some(s) = v.as_str() {
                    println!("  - {s}");
                }
            }
        }
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedQuarantinePlansByArgs {
    target_fingerprint: String,
    reason: Option<String>,
}

fn parse_quarantine_plans_by_args(
    args: &[String],
) -> Result<ParsedQuarantinePlansByArgs, CliError> {
    let mut iter = args.iter();
    let target_fingerprint = iter
        .next()
        .ok_or_else(|| {
            CliError::Usage(
                "operator quarantine-plans-by requires <target_fingerprint> [--reason <text>]"
                    .to_owned(),
            )
        })?
        .clone();

    let mut reason: Option<String> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--reason" => {
                let v = iter
                    .next()
                    .ok_or_else(|| CliError::Usage("--reason requires a value".to_owned()))?;
                reason = Some(v.clone());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown flag for `operator quarantine-plans-by`: {other:?}"
                )));
            }
        }
    }

    // Light client-side validation; see security note in the run_*
    // doc comment above.
    if target_fingerprint.is_empty() {
        return Err(CliError::Usage(
            "target_fingerprint must be non-empty (16-hex SHA-256[:16] of the operator pubkey)"
                .to_owned(),
        ));
    }

    Ok(ParsedQuarantinePlansByArgs {
        target_fingerprint,
        reason,
    })
}

// ---------------------------------------------------------------------------
// Tests — arg-parsing only. Wire-shape coverage lives in
// `raxis-types::operator_wire::tests`; sweep semantics live in
// `raxis-store::views::initiative_quarantines::tests`.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn missing_target_fingerprint_is_usage_error() {
        let err = parse_quarantine_plans_by_args(&[]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        if let CliError::Usage(m) = err {
            assert!(m.contains("operator quarantine-plans-by"));
            assert!(m.contains("<target_fingerprint>"));
        }
    }

    #[test]
    fn fingerprint_only_parses_with_no_reason() {
        let parsed = parse_quarantine_plans_by_args(&s(&["abcdef0123456789"])).unwrap();
        assert_eq!(
            parsed,
            ParsedQuarantinePlansByArgs {
                target_fingerprint: "abcdef0123456789".to_owned(),
                reason: None,
            }
        );
    }

    #[test]
    fn fingerprint_with_reason_captures_value() {
        let parsed = parse_quarantine_plans_by_args(&s(&[
            "abcdef0123456789",
            "--reason",
            "key suspected leaked",
        ]))
        .unwrap();
        assert_eq!(
            parsed,
            ParsedQuarantinePlansByArgs {
                target_fingerprint: "abcdef0123456789".to_owned(),
                reason: Some("key suspected leaked".to_owned()),
            }
        );
    }

    #[test]
    fn empty_string_fingerprint_is_usage_error() {
        // Edge case: a user passes `""` literally on the shell to test
        // robustness. We reject pre-flight rather than letting the
        // kernel emit an opaque error.
        let err = parse_quarantine_plans_by_args(&s(&[""])).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        if let CliError::Usage(m) = err {
            assert!(m.contains("non-empty"));
        }
    }

    #[test]
    fn unknown_flag_is_usage_error() {
        let err =
            parse_quarantine_plans_by_args(&s(&["abcdef0123456789", "--whatever"])).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        if let CliError::Usage(m) = err {
            assert!(m.contains("--whatever") || m.contains("unknown flag"));
        }
    }

    #[test]
    fn reason_without_value_is_usage_error() {
        let err =
            parse_quarantine_plans_by_args(&s(&["abcdef0123456789", "--reason"])).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        if let CliError::Usage(m) = err {
            assert!(m.contains("--reason requires a value"));
        }
    }
}
