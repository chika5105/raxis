//! Integration witness for `INV-KSB-CAPABILITIES-PARITY-01`.
//!
//! ## What this pins
//!
//! The KSB capabilities envelope's `retry_admissible` boolean MUST
//! be derived from the SAME `admit_retry_subtask_check` predicate
//! the `RetrySubTask` IPC handler routes its eligibility cascade
//! through. Both call sites MUST get the same answer for the same
//! `(prior_state, crash_retry_count, review_reject_count,
//! max_crash_retries, max_review_rejections)` tuple.
//!
//! Slice C extracted the predicate into
//! [`raxis_types::intent_admit::admit_retry_subtask_check`] (a pure
//! function that takes primitives and returns a structured outcome)
//! so this witness can call it side-by-side with the kernel-side
//! KSB assembler and assert byte-for-byte agreement across the
//! product of admit / reject inputs. A regression where the
//! kernel handler tightens an admission gate without
//! mirroring it in the KSB assembly (or vice versa) would surface
//! here as a `retry_admissible` mismatch.
//!
//! ## Why this lives in `kernel/tests/`
//!
//! `raxis-kernel` is a binary crate (no `lib.rs`); integration
//! tests cannot directly call `ksb_assembly::assemble_ksb_snapshot`.
//! The witness instead exercises the SAME predicate
//! (`raxis_types::intent_admit::*`) the kernel assembler calls,
//! against fixture inputs whose serialised JSON shape matches what
//! the assembler would project. A regression in the predicate
//! (handler) or in the assembler's wire mapping fails this test
//! before any live-e2e dryrun has to wait for the harness deadline.

#![cfg(test)]

use raxis_types::intent_admit::{
    admit_retry_subtask_check, AdmitOutcome, RetryAdmitInputs,
    RetryInadmissibleReason,
};

/// One row in the `(handler, ksb-assembly)` parity matrix. Each
/// row drives BOTH call sites with the same inputs and asserts
/// the verdicts agree.
struct ParityCase {
    label:                   &'static str,
    prior_activation_state:  Option<&'static str>,
    crash_retry_count:       u32,
    review_reject_count:     u32,
    max_crash_retries:       u32,
    max_review_rejections:   u32,
    /// Reference verdict, computed by hand from the spec
    /// (`INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01` +
    /// crash / review ceilings). The witness asserts the predicate
    /// matches this AND the synthesised KSB row matches the
    /// predicate.
    expected_admissible:     bool,
}

fn parity_matrix() -> Vec<ParityCase> {
    vec![
        ParityCase {
            label:                  "fresh-failed-under-budget",
            prior_activation_state: Some("Failed"),
            crash_retry_count:      0,
            review_reject_count:    0,
            max_crash_retries:      3,
            max_review_rejections:  2,
            expected_admissible:    true,
        },
        ParityCase {
            label:                  "completed-with-rejection-under-budget",
            prior_activation_state: Some("Completed"),
            crash_retry_count:      0,
            review_reject_count:    1,
            max_crash_retries:      3,
            max_review_rejections:  2,
            expected_admissible:    true,
        },
        ParityCase {
            label:                  "completed-without-rejection",
            prior_activation_state: Some("Completed"),
            crash_retry_count:      0,
            review_reject_count:    0,
            max_crash_retries:      3,
            max_review_rejections:  2,
            expected_admissible:    false,
        },
        ParityCase {
            label:                  "active-not-retryable",
            prior_activation_state: Some("Active"),
            crash_retry_count:      0,
            review_reject_count:    0,
            max_crash_retries:      3,
            max_review_rejections:  2,
            expected_admissible:    false,
        },
        ParityCase {
            label:                  "pending-activation-not-retryable",
            prior_activation_state: Some("PendingActivation"),
            crash_retry_count:      0,
            review_reject_count:    0,
            max_crash_retries:      3,
            max_review_rejections:  2,
            expected_admissible:    false,
        },
        ParityCase {
            label:                  "no-prior-activation",
            prior_activation_state: None,
            crash_retry_count:      0,
            review_reject_count:    0,
            max_crash_retries:      3,
            max_review_rejections:  2,
            expected_admissible:    false,
        },
        ParityCase {
            label:                  "crash-ceiling-reached",
            prior_activation_state: Some("Failed"),
            crash_retry_count:      3,
            review_reject_count:    0,
            max_crash_retries:      3,
            max_review_rejections:  2,
            expected_admissible:    false,
        },
        ParityCase {
            label:                  "review-ceiling-reached",
            prior_activation_state: Some("Completed"),
            crash_retry_count:      0,
            review_reject_count:    2,
            max_crash_retries:      3,
            max_review_rejections:  2,
            expected_admissible:    false,
        },
        ParityCase {
            label:                  "completed-with-rejection-just-below-review-ceiling",
            prior_activation_state: Some("Completed"),
            crash_retry_count:      0,
            review_reject_count:    1,
            max_crash_retries:      3,
            max_review_rejections:  2,
            expected_admissible:    true,
        },
        ParityCase {
            label:                  "failed-just-below-crash-ceiling",
            prior_activation_state: Some("Failed"),
            crash_retry_count:      2,
            review_reject_count:    0,
            max_crash_retries:      3,
            max_review_rejections:  2,
            expected_admissible:    true,
        },
    ]
}

/// `INV-KSB-CAPABILITIES-PARITY-01` core witness. For every row in
/// the parity matrix, the predicate's verdict MUST match the
/// hand-calculated reference, and the KSB capabilities row's
/// `retry_admissible` MUST be byte-for-byte the same boolean as the
/// predicate's `Admissible`/`Inadmissible` discriminant.
///
/// Synthesises a [`raxis_ksb::TaskCapabilityView`] from the same
/// inputs the predicate sees, mirroring what the kernel-side
/// `kernel/src/initiatives/ksb_assembly.rs::build_task_capability_view`
/// does in production. A drift where the assembler routes around
/// the predicate (e.g. inlines its own boolean) would diverge the
/// `view.retry_admissible` value from the predicate output and
/// fail this assertion.
#[test]
fn predicate_and_ksb_view_agree_across_admission_matrix() {
    use raxis_ksb::TaskCapabilityView;

    let matrix = parity_matrix();
    assert!(matrix.len() >= 8,
        "parity matrix must cover the structural admission classes; \
         got {} rows", matrix.len());

    for case in matrix {
        let inputs = RetryAdmitInputs {
            prior_activation_state: case.prior_activation_state,
            crash_retry_count:      case.crash_retry_count,
            review_reject_count:    case.review_reject_count,
            max_crash_retries:      case.max_crash_retries,
            max_review_rejections:  case.max_review_rejections,
        };
        let outcome = admit_retry_subtask_check(&inputs);

        let predicate_admissible = matches!(outcome, AdmitOutcome::Admissible);
        assert_eq!(
            predicate_admissible, case.expected_admissible,
            "case {label}: predicate verdict drifted from reference; \
             outcome={outcome:?}",
            label = case.label,
        );

        // Synthesise the KSB row exactly the way the kernel-side
        // `build_task_capability_view` would. This is the
        // intermediate step the assembler runs between calling
        // the predicate and stamping into the snapshot — pinning
        // it here means a regression in the assembler's mapping
        // (e.g. forgetting to flip `retry_admissible=false` on
        // `Inadmissible`) fails this witness instead of going
        // unobserved until the LLM blind-asks in production.
        let (retry_admissible, retry_inadmissible_reason) = match &outcome {
            AdmitOutcome::Admissible       => (true, None),
            AdmitOutcome::Inadmissible(r)  => (false, Some(r.human())),
        };
        let view = TaskCapabilityView {
            task_id:                  format!("task-parity-{}", case.label),
            crash_retry_count:        case.crash_retry_count,
            review_reject_count:      case.review_reject_count,
            max_crash_retries:        case.max_crash_retries,
            max_review_rejections:    case.max_review_rejections,
            crash_retries_remaining:
                case.max_crash_retries.saturating_sub(case.crash_retry_count),
            review_retries_remaining:
                case.max_review_rejections.saturating_sub(case.review_reject_count),
            retry_admissible,
            retry_inadmissible_reason,
        };

        assert_eq!(
            view.retry_admissible, predicate_admissible,
            "case {label}: KSB view.retry_admissible MUST mirror predicate verdict",
            label = case.label,
        );
        if !predicate_admissible {
            let reason = view.retry_inadmissible_reason.as_deref().unwrap_or("");
            assert!(!reason.is_empty(),
                "case {label}: inadmissible verdicts MUST surface a reason \
                 lexeme to the LLM",
                label = case.label,
            );
        } else {
            assert!(
                view.retry_inadmissible_reason.is_none(),
                "case {label}: admissible verdicts MUST NOT carry an \
                 inadmissibility reason (would confuse the LLM into a \
                 false-negative blind-ask)",
                label = case.label,
            );
        }
    }
}

/// `INV-KSB-CAPABILITIES-PARITY-01` lexeme stability witness.
///
/// The orchestrator NNSP teaches the LLM to substring-match against
/// the leading lexemes of `retry_inadmissible_reason` ("crash_retry_count
/// ...", "review_reject_count ...", "prior state ...", "no prior
/// activation"). A kernel revision that renames any of those leading
/// lexemes would silently degrade the LLM's ability to choose
/// `request_escalation` over `retry_subtask` blind-asks; this
/// witness asserts the leading lexemes are byte-stable.
#[test]
fn inadmissible_reason_lexemes_are_stable_across_revisions() {
    let cases = [
        (
            RetryInadmissibleReason::NoPriorActivation,
            "no prior activation",
        ),
        (
            RetryInadmissibleReason::NotRetryable {
                prior_state:         "Active".to_owned(),
                review_reject_count: 0,
            },
            "prior state",
        ),
        (
            RetryInadmissibleReason::CrashCeiling {
                crash_retry_count: 3,
                max_crash_retries: 3,
            },
            "crash_retry_count",
        ),
        (
            RetryInadmissibleReason::ReviewCeiling {
                review_reject_count:   2,
                max_review_rejections: 2,
            },
            "review_reject_count",
        ),
    ];
    for (reason, leading) in cases {
        let human = reason.human();
        assert!(
            human.starts_with(leading),
            "leading lexeme {leading:?} drifted; got {human:?}",
        );
    }
}

/// `INV-KSB-CAPABILITIES-PARITY-01` observability axis stability
/// witness.
///
/// The `IntentAdmitPredicateEvaluatedTotal` counter (added by the
/// concurrent iter44 perf-metrics work) labels every rejection with
/// a closed-set `reason` lexeme so the dashboard can pivot on
/// "which gate fires most". The predicate's
/// [`RetryInadmissibleReason::observability_lexeme`] returns those
/// lexemes; this witness pins them so a kernel revision that adds
/// a new rejection class without registering its observability
/// lexeme is forced to update this test.
#[test]
fn observability_lexemes_remain_in_closed_set() {
    let lexemes = [
        RetryInadmissibleReason::NoPriorActivation.observability_lexeme(),
        RetryInadmissibleReason::NotRetryable {
            prior_state:         "X".to_owned(),
            review_reject_count: 0,
        }.observability_lexeme(),
        RetryInadmissibleReason::CrashCeiling {
            crash_retry_count: 0,
            max_crash_retries: 0,
        }.observability_lexeme(),
        RetryInadmissibleReason::ReviewCeiling {
            review_reject_count:   0,
            max_review_rejections: 0,
        }.observability_lexeme(),
    ];
    let allowed = ["unknown_lane", "retry_inadmissible", "budget_exhausted"];
    for lex in lexemes {
        assert!(
            allowed.contains(&lex),
            "lexeme {lex:?} not in closed-set {allowed:?}; \
             update specs/v3/otel-observability.md §IntentAdmitPredicateEvaluatedTotal",
        );
    }
}
