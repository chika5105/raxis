//! Pure intent-admission predicates.
//!
//! Slice C (`INV-KSB-CAPABILITIES-PARITY-01`) — these predicates are
//! the SHARED source of truth for two call paths that MUST agree on
//! whether an intent would be admitted right now:
//!
//!   1. **IPC handler.** `kernel/src/handlers/intent.rs::
//!      handle_retry_sub_task` runs the predicate inside its
//!      transaction-bounded admission gate; the rejection branches
//!      log the matching `IntentAdmitPredicateEvaluatedTotal{
//!      admissible="false"}` counter increment.
//!   2. **KSB capabilities assembly.** `kernel/src/initiatives/
//!      ksb_assembly.rs::assemble_capabilities` runs the predicate
//!      against the same row reads it uses for the rest of the KSB
//!      projection (turn-coherent, `INV-KSB-CAPABILITIES-TURN-
//!      COHERENT-01`) and stamps the verdict into
//!      [`raxis_ksb::TaskCapabilityView::retry_admissible`] /
//!      [`raxis_ksb::TaskCapabilityView::retry_inadmissible_reason`].
//!
//! The parity contract is: given the same `(prior_state,
//! crash_retry_count, review_reject_count, max_crash_retries,
//! max_review_rejections)` tuple, both call paths MUST return the
//! same answer. The witness test `kernel/tests/
//! ksb_capabilities_parity.rs` pins this by driving a fixture
//! through both paths and asserting the booleans agree across the
//! product of admit / reject inputs.
//!
//! ## Predicate purity
//!
//! These functions take primitives (already-read counters) and
//! return primitives — no `Connection`, no I/O, no async. Side
//! effects (eprintln, audit emit, observability counter increment)
//! belong to the call site. This keeps the parity contract
//! mechanical: both call sites pass the same inputs ⇒ both call
//! sites get the same output.

/// Outcome of an intent-admission predicate. The `Inadmissible`
/// variant carries the closed-set reason lexeme so the caller can
/// (a) emit the matching observability counter and (b) surface the
/// human-readable string into the KSB capabilities envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// The intent would be admitted by the kernel right now.
    Admissible,
    /// The intent would be REJECTED by the kernel right now. The
    /// reason is the closed-set
    /// [`RetryInadmissibleReason`] discriminant — call sites
    /// dispatch on the discriminant for the wire `reason` label
    /// and use [`RetryInadmissibleReason::human`] for the KSB
    /// capabilities `retry_inadmissible_reason` string.
    Inadmissible(RetryInadmissibleReason),
}

/// Closed-set rejection reasons for `RetrySubTask`. Mirrors the
/// `eprintln!` event names in `handle_retry_sub_task` (kept in
/// sync by the parity witness test).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryInadmissibleReason {
    /// No prior activation row exists for this task. The task has
    /// never been activated; `RetrySubTask` is meaningless.
    /// Wire counterpart: `eprintln "RetrySubTaskRejectedUnknownTask"`.
    NoPriorActivation,
    /// The most-recent activation's `activation_state` is neither
    /// `Failed` nor `Completed-with-review_reject_count > 0`.
    /// Wire counterpart: `eprintln "RetrySubTaskRejectedNotRetryable"`.
    NotRetryable {
        /// The actual prior state (verbatim, lowercase per the
        /// activation_state column convention).
        prior_state:         String,
        /// The accompanying `review_reject_count` (informational —
        /// the predicate already considered it).
        review_reject_count: u32,
    },
    /// `crash_retry_count >= max_crash_retries`.
    /// Wire counterpart: `eprintln "RetrySubTaskRejectedCrashCeiling"`.
    CrashCeiling {
        /// Current `subtask_activations.crash_retry_count`.
        crash_retry_count: u32,
        /// Plan-effective ceiling.
        max_crash_retries: u32,
    },
    /// `review_reject_count >= max_review_rejections`.
    /// Wire counterpart: `eprintln "RetrySubTaskRejectedReviewCeiling"`.
    ReviewCeiling {
        /// Current `subtask_activations.review_reject_count`.
        review_reject_count:   u32,
        /// Plan-effective ceiling.
        max_review_rejections: u32,
    },
}

impl RetryInadmissibleReason {
    /// Human-readable form for the
    /// [`raxis_ksb::TaskCapabilityView::retry_inadmissible_reason`]
    /// projection. Substring-stable across kernel revisions — the
    /// orchestrator NNSP MAY pattern-match against the leading
    /// lexeme (`prior state`, `crash_retry_count`,
    /// `review_reject_count`, `no prior activation`) but MUST NOT
    /// pattern-match against trailing numbers.
    pub fn human(&self) -> String {
        match self {
            RetryInadmissibleReason::NoPriorActivation =>
                "no prior activation".to_owned(),
            RetryInadmissibleReason::NotRetryable { prior_state, review_reject_count } =>
                format!(
                    "prior state {prior_state}; need Failed or Completed-with-review-rejection \
                     (review_reject_count={review_reject_count})"
                ),
            RetryInadmissibleReason::CrashCeiling { crash_retry_count, max_crash_retries } =>
                format!(
                    "crash_retry_count {crash_retry_count} >= max_crash_retries {max_crash_retries}"
                ),
            RetryInadmissibleReason::ReviewCeiling { review_reject_count, max_review_rejections } =>
                format!(
                    "review_reject_count {review_reject_count} >= max_review_rejections {max_review_rejections}"
                ),
        }
    }

    /// Closed-set wire lexeme for observability counter labels.
    /// One of `unknown_lane`, `retry_inadmissible`,
    /// `budget_exhausted` per
    /// `crates/observability/src/intent_admit.rs` (the
    /// `IntentAdmitPredicateEvaluatedTotal` reason axis).
    pub fn observability_lexeme(&self) -> &'static str {
        match self {
            RetryInadmissibleReason::NoPriorActivation       => "unknown_lane",
            RetryInadmissibleReason::NotRetryable { .. }     => "retry_inadmissible",
            RetryInadmissibleReason::CrashCeiling { .. }
            | RetryInadmissibleReason::ReviewCeiling { .. }  => "budget_exhausted",
        }
    }
}

/// Inputs for the `RetrySubTask` admission predicate. Bundled into a
/// struct so future fields (per-initiative escalation budget, etc.)
/// can be appended without breaking every call-site.
///
/// `prior_activation_state` carries the verbatim `subtask_activations.
/// activation_state` row value (lowercase per V2 DDL convention) or
/// `None` when no activation row exists for the task.
#[derive(Debug, Clone)]
pub struct RetryAdmitInputs<'a> {
    /// `subtask_activations.activation_state` of the most-recent
    /// activation row for the task, or `None` if no row exists.
    pub prior_activation_state: Option<&'a str>,
    /// Most-recent activation's `crash_retry_count`.
    pub crash_retry_count:      u32,
    /// Most-recent activation's `review_reject_count`.
    pub review_reject_count:    u32,
    /// Plan-effective `max_crash_retries` (kernel default substituted
    /// when the plan omits the field).
    pub max_crash_retries:      u32,
    /// Plan-effective `max_review_rejections`.
    pub max_review_rejections:  u32,
}

/// Pure predicate: would `RetrySubTask` for this task be ADMITTED by
/// the kernel right now?
///
/// Mirrors the gate-cascade in `handle_retry_sub_task` (kernel/src/
/// handlers/intent.rs §"Step 2 + 3"):
///
///   1. No prior activation ⇒
///      [`RetryInadmissibleReason::NoPriorActivation`].
///   2. Prior state ≠ `"Failed"` AND not `(Completed +
///      review_reject_count > 0)` ⇒
///      [`RetryInadmissibleReason::NotRetryable`] —
///      `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`.
///   3. `crash_retry_count >= max_crash_retries` ⇒
///      [`RetryInadmissibleReason::CrashCeiling`].
///   4. `review_reject_count >= max_review_rejections` ⇒
///      [`RetryInadmissibleReason::ReviewCeiling`].
///   5. Otherwise: [`AdmitOutcome::Admissible`].
///
/// The IPC handler enforces additional gates (envelope replay
/// protection, session revocation, FSM transactionality) that are
/// out-of-scope for the parity contract — the predicate covers the
/// load-bearing eligibility gates the LLM needs to pre-evaluate.
pub fn admit_retry_subtask_check(inputs: &RetryAdmitInputs<'_>) -> AdmitOutcome {
    let prior_state = match inputs.prior_activation_state {
        Some(s) => s,
        None    => return AdmitOutcome::Inadmissible(RetryInadmissibleReason::NoPriorActivation),
    };
    let allow_from_completed_review_rejection =
        prior_state == "Completed" && inputs.review_reject_count > 0;
    if prior_state != "Failed" && !allow_from_completed_review_rejection {
        return AdmitOutcome::Inadmissible(RetryInadmissibleReason::NotRetryable {
            prior_state:         prior_state.to_owned(),
            review_reject_count: inputs.review_reject_count,
        });
    }
    if inputs.crash_retry_count >= inputs.max_crash_retries {
        return AdmitOutcome::Inadmissible(RetryInadmissibleReason::CrashCeiling {
            crash_retry_count: inputs.crash_retry_count,
            max_crash_retries: inputs.max_crash_retries,
        });
    }
    if inputs.review_reject_count >= inputs.max_review_rejections {
        return AdmitOutcome::Inadmissible(RetryInadmissibleReason::ReviewCeiling {
            review_reject_count:   inputs.review_reject_count,
            max_review_rejections: inputs.max_review_rejections,
        });
    }
    AdmitOutcome::Admissible
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> RetryAdmitInputs<'static> {
        RetryAdmitInputs {
            prior_activation_state: Some("Failed"),
            crash_retry_count:      0,
            review_reject_count:    0,
            max_crash_retries:      3,
            max_review_rejections:  2,
        }
    }

    #[test]
    fn admits_when_prior_failed_and_under_both_ceilings() {
        assert_eq!(admit_retry_subtask_check(&base()), AdmitOutcome::Admissible);
    }

    #[test]
    fn admits_when_completed_with_review_rejection() {
        let inputs = RetryAdmitInputs {
            prior_activation_state: Some("Completed"),
            review_reject_count:    1,
            ..base()
        };
        assert_eq!(admit_retry_subtask_check(&inputs), AdmitOutcome::Admissible);
    }

    #[test]
    fn rejects_when_completed_without_review_rejection() {
        let inputs = RetryAdmitInputs {
            prior_activation_state: Some("Completed"),
            review_reject_count:    0,
            ..base()
        };
        match admit_retry_subtask_check(&inputs) {
            AdmitOutcome::Inadmissible(RetryInadmissibleReason::NotRetryable { prior_state, review_reject_count }) => {
                assert_eq!(prior_state, "Completed");
                assert_eq!(review_reject_count, 0);
            }
            other => panic!("expected NotRetryable, got {other:?}"),
        }
    }

    #[test]
    fn rejects_when_no_prior_activation() {
        let inputs = RetryAdmitInputs { prior_activation_state: None, ..base() };
        assert_eq!(
            admit_retry_subtask_check(&inputs),
            AdmitOutcome::Inadmissible(RetryInadmissibleReason::NoPriorActivation),
        );
    }

    #[test]
    fn rejects_when_crash_ceiling_reached() {
        let inputs = RetryAdmitInputs { crash_retry_count: 3, ..base() };
        assert_eq!(
            admit_retry_subtask_check(&inputs),
            AdmitOutcome::Inadmissible(RetryInadmissibleReason::CrashCeiling {
                crash_retry_count: 3,
                max_crash_retries: 3,
            }),
        );
    }

    #[test]
    fn rejects_when_review_ceiling_reached() {
        let inputs = RetryAdmitInputs { review_reject_count: 2, ..base() };
        assert_eq!(
            admit_retry_subtask_check(&inputs),
            AdmitOutcome::Inadmissible(RetryInadmissibleReason::ReviewCeiling {
                review_reject_count:   2,
                max_review_rejections: 2,
            }),
        );
    }

    #[test]
    fn human_strings_carry_load_bearing_lexemes() {
        assert!(RetryInadmissibleReason::NoPriorActivation.human()
                .starts_with("no prior activation"));
        assert!(RetryInadmissibleReason::NotRetryable {
            prior_state:         "PendingActivation".to_owned(),
            review_reject_count: 0,
        }.human().starts_with("prior state PendingActivation"));
        assert!(RetryInadmissibleReason::CrashCeiling {
            crash_retry_count: 3,
            max_crash_retries: 3,
        }.human().starts_with("crash_retry_count 3"));
        assert!(RetryInadmissibleReason::ReviewCeiling {
            review_reject_count:   2,
            max_review_rejections: 2,
        }.human().starts_with("review_reject_count 2"));
    }

    #[test]
    fn observability_lexemes_match_handler_emission_axis() {
        assert_eq!(
            RetryInadmissibleReason::NoPriorActivation.observability_lexeme(),
            "unknown_lane",
        );
        assert_eq!(
            RetryInadmissibleReason::NotRetryable {
                prior_state:         "Active".to_owned(),
                review_reject_count: 0,
            }.observability_lexeme(),
            "retry_inadmissible",
        );
        assert_eq!(
            RetryInadmissibleReason::CrashCeiling {
                crash_retry_count: 0,
                max_crash_retries: 0,
            }.observability_lexeme(),
            "budget_exhausted",
        );
        assert_eq!(
            RetryInadmissibleReason::ReviewCeiling {
                review_reject_count:   0,
                max_review_rejections: 0,
            }.observability_lexeme(),
            "budget_exhausted",
        );
    }
}
