//! Step 30 — Audit attribution for operator-assisted IntegrationMerge.
//!
//! Normative reference:
//!   - `v2-deep-spec.md §Step 30` — "Audit Attribution for Operator-Assisted Commits"
//!   - `integration-merge.md §4 Check 6b` — Conflict Escalation Verification
//!
//! When the Orchestrator submits `IntentKind::IntegrationMerge` with
//! `IntentRequest.resolved_via_escalation = Some(esc_id)`, the kernel
//! must verify that `esc_id`:
//!
//!   1. exists in the `escalations` table,
//!   2. is in `Consumed` status (the operator has resolved it via
//!      `raxis escalate resolve <id> --message "..."`),
//!   3. carries `class = MergeConflict`, and
//!   4. belongs to the submitting Orchestrator's session.
//!
//! Failure of any predicate must reject the merge so an attacker
//! cannot fabricate operator attribution by quoting an arbitrary
//! escalation ID. Successful verification permits the merge to admit
//! AND tags the resulting `IntegrationMergeCompleted` audit event
//! with `operator_assisted: true, escalation_id: Some(id)`.
//!
//! The `git log --author` of the Path-2 manual-commit is unchanged;
//! the audit chain provides the structural attribution that an
//! external auditor can verify in-band without correlating the
//! repo against `git log` (preserves INV-05 self-containment).

use raxis_store::{Store, Table};
use raxis_types::{EscalationClass, EscalationId, EscalationStatus, SessionId};
use thiserror::Error;

const ESCALATIONS: &str = Table::Escalations.as_str();
const INITIATIVES: &str = Table::Initiatives.as_str();
const SESSIONS: &str = Table::Sessions.as_str();
const TASKS: &str = Table::Tasks.as_str();

/// Reasons the escalation link in `IntentRequest.resolved_via_escalation`
/// fails Check 6b. Each variant maps to a distinct error code so the
/// audit chain (and operator UI in a future iteration) can tell the
/// failure modes apart; the planner wire surface remains a single
/// `FAIL_POLICY_VIOLATION` to comply with INV-08.
#[derive(Debug, Error)]
pub enum EscalationVerificationError {
    /// No row exists in `escalations` with the supplied id. The
    /// Orchestrator quoted a fabricated or recycled identifier.
    #[error("escalation '{escalation_id}' does not exist")]
    NotFound { escalation_id: String },

    /// The escalation row exists but is not in the `Consumed` state.
    /// V2 (Step 30) requires operator action before the merge can be
    /// attributed: only `Consumed` indicates that
    /// `raxis escalate resolve` has run. Any other state — `Pending`,
    /// `Approved`, `Denied`, `TimedOut`, `TokenExpired` — reflects an
    /// unresolved or rejected escalation and must not unlock the
    /// merge admission gate.
    #[error(
        "escalation '{escalation_id}' has status '{actual}'; \
         Step 30 requires 'Consumed' (operator has resolved the conflict)"
    )]
    NotConsumed {
        escalation_id: String,
        actual: String,
    },

    /// The escalation exists and is Consumed but belongs to a
    /// different escalation class. Step 30 only authorises merge
    /// attribution under `MergeConflict`; reusing an unrelated
    /// `BudgetException` or `CapabilityUpgrade` consumption would
    /// erode INV-05 attribution semantics.
    #[error(
        "escalation '{escalation_id}' has class '{actual}'; \
         Step 30 requires 'MergeConflict'"
    )]
    ClassMismatch {
        escalation_id: String,
        actual: String,
    },

    /// The escalation belongs to a different Orchestrator session.
    /// Cross-session reuse would let one Orchestrator inherit
    /// attribution from another initiative's resolved escalation;
    /// the spec's third predicate forbids this.
    #[error(
        "escalation '{escalation_id}' belongs to session \
         '{owning_session}', not submitting session '{submitting_session}'"
    )]
    SessionMismatch {
        escalation_id: String,
        owning_session: String,
        submitting_session: String,
    },

    /// Underlying SQL error. The kernel cannot prove the predicate
    /// holds, so it must reject (fail-closed posture). Treat as a
    /// transient infrastructure error in the operator UI; the
    /// Orchestrator may safely retry after the kernel recovers.
    #[error("sqlite error during Check 6b: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

impl EscalationVerificationError {
    /// Stable diagnostic code for the audit chain. The wire surface
    /// to the planner is always `FAIL_POLICY_VIOLATION` (INV-08); the
    /// codes below are emitted into the kernel-internal log and into
    /// the eventual `IntegrationMergeRejected` audit variant.
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "FAIL_ESCALATION_NOT_FOUND",
            Self::NotConsumed { .. } => "FAIL_ESCALATION_NOT_CONSUMED",
            Self::ClassMismatch { .. } => "FAIL_ESCALATION_CLASS_MISMATCH",
            Self::SessionMismatch { .. } => "FAIL_ESCALATION_SESSION_MISMATCH",
            Self::Sqlite(_) => "FAIL_STORE",
        }
    }
}

/// Run Check 6b on the supplied escalation id against the supplied
/// submitting Orchestrator session. Returns `Ok(())` iff all four
/// predicates hold; any failure aborts admission.
///
/// **Fail-closed:** an unknown SQL error or a missing row both
/// reject the merge. This is the secure default: an attacker must
/// not benefit from infrastructure transients.
///
/// **Read-only:** this function performs only `SELECT` against
/// `escalations`. It does NOT mutate any row. The escalation's
/// status update to `Consumed` happens earlier in the operator
/// resolve flow (`raxis escalate resolve`); the kernel here only
/// witnesses that update has been performed by the operator.
pub fn verify_merge_conflict_resolution(
    escalation_id: &EscalationId,
    submitting_session: &SessionId,
    store: &Store,
) -> Result<(), EscalationVerificationError> {
    let guard = store.lock_sync();
    let mut stmt = guard.prepare_cached(&format!(
        "SELECT class, status, session_id FROM {ESCALATIONS} \
         WHERE escalation_id = ?1"
    ))?;
    let row = stmt.query_row([escalation_id.as_str()], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    });
    let (class_raw, status_raw, owning_session_raw) = match row {
        Ok(tuple) => tuple,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Err(EscalationVerificationError::NotFound {
                escalation_id: escalation_id.as_str().to_owned(),
            });
        }
        Err(e) => return Err(e.into()),
    };

    // Predicate 1: class must be MergeConflict. We compare on the
    // canonical SQL string rather than parsing into the enum first
    // because the row may carry a class string we do not yet
    // recognise (forward compat) — that is still a class mismatch
    // for Step 30's purposes.
    if class_raw.as_str() != EscalationClass::MergeConflict.as_sql_str() {
        return Err(EscalationVerificationError::ClassMismatch {
            escalation_id: escalation_id.as_str().to_owned(),
            actual: class_raw,
        });
    }

    // Predicate 2: status must be Consumed.
    if status_raw.as_str() != EscalationStatus::Consumed.as_sql_str() {
        return Err(EscalationVerificationError::NotConsumed {
            escalation_id: escalation_id.as_str().to_owned(),
            actual: status_raw,
        });
    }

    // Predicate 3: the escalation belongs to the submitting session.
    if owning_session_raw.as_str() != submitting_session.as_str() {
        return Err(EscalationVerificationError::SessionMismatch {
            escalation_id: escalation_id.as_str().to_owned(),
            owning_session: owning_session_raw,
            submitting_session: submitting_session.as_str().to_owned(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_store::Store;

    /// Insert an `escalations` row with the chosen field values. We
    /// bypass `escalation_request::handle` because that handler only
    /// admits `Pending` rows; Step 30 needs a row in `Consumed` (and
    /// other states) to exercise the verifier directly.
    fn insert_escalation(store: &Store, esc_id: &str, class: &str, status: &str, session: &str) {
        // Required FK targets — the schema enforces FKs even when the
        // value strings are not real UUIDs; we satisfy them with bare
        // sentinel rows so the test stays focused on the verifier
        // predicates.
        let g = store.lock_sync();
        g.execute(
            &format!(
                "INSERT OR IGNORE INTO {INITIATIVES} \
             (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
             VALUES ('init-1', 'Executing', '{{}}', 'sha-1', 1)"
            ),
            [],
        )
        .unwrap();
        g.execute(
            &format!(
                "INSERT OR IGNORE INTO {SESSIONS} \
             (session_id, role_id, session_token, lineage_id, fetch_quota, \
              created_at, expires_at, revoked) \
             VALUES (?1, 'planner', 'tok', 'lin-1', 0, 1, 9999, 0)"
            ),
            [session],
        )
        .unwrap();
        g.execute(
            &format!(
                "INSERT OR IGNORE INTO {TASKS} \
             (task_id, initiative_id, lane_id, state, actor, \
              policy_epoch, admitted_at, transitioned_at) \
             VALUES ('task-1', 'init-1', 'default', 'Running', 'op', 1, 1, 1)"
            ),
            [],
        )
        .unwrap();

        g.execute(
            &format!(
                "INSERT INTO {ESCALATIONS} \
             (escalation_id, session_id, task_id, lineage_id, initiative_id, \
              class, requested_scope_json, justification, idempotency_key, \
              status, created_at, timeout_at) \
             VALUES (?1, ?2, 'task-1', 'lin-1', 'init-1', \
                     ?3, '{{}}', 'why', ?1, ?4, 1, 9999)"
            ),
            rusqlite::params![esc_id, session, class, status],
        )
        .unwrap();
    }

    fn fixture_session() -> SessionId {
        SessionId::parse("11111111-1111-1111-1111-111111111111").unwrap()
    }

    fn fixture_escalation_id() -> EscalationId {
        EscalationId::parse("22222222-2222-2222-2222-222222222222").unwrap()
    }

    /// Happy path: row exists, class = MergeConflict, status =
    /// Consumed, session matches → OK.
    #[test]
    fn verify_passes_when_all_four_predicates_hold() {
        let store = Store::open_in_memory().unwrap();
        let esc = fixture_escalation_id();
        let sess = fixture_session();
        insert_escalation(
            &store,
            esc.as_str(),
            "MergeConflict",
            "Consumed",
            sess.as_str(),
        );

        verify_merge_conflict_resolution(&esc, &sess, &store).expect("all four predicates hold");
    }

    /// Missing row: a fabricated id returns NotFound. Defence
    /// against an Orchestrator submitting fake attribution.
    #[test]
    fn verify_rejects_unknown_escalation_id() {
        let store = Store::open_in_memory().unwrap();
        let esc = fixture_escalation_id();
        let sess = fixture_session();
        // Note: NO row inserted.
        let err = verify_merge_conflict_resolution(&esc, &sess, &store)
            .expect_err("missing row must reject");
        assert!(matches!(err, EscalationVerificationError::NotFound { .. }));
        assert_eq!(err.diagnostic_code(), "FAIL_ESCALATION_NOT_FOUND");
    }

    /// Wrong status: every non-Consumed value rejects. Pending,
    /// Approved, Denied, TimedOut, TokenExpired are all attempts to
    /// short-circuit the operator-resolve gate.
    #[test]
    fn verify_rejects_when_status_is_not_consumed() {
        for forbidden in ["Pending", "Approved", "Denied", "TimedOut", "TokenExpired"] {
            let store = Store::open_in_memory().unwrap();
            let esc = fixture_escalation_id();
            let sess = fixture_session();
            insert_escalation(
                &store,
                esc.as_str(),
                "MergeConflict",
                forbidden,
                sess.as_str(),
            );

            let err = verify_merge_conflict_resolution(&esc, &sess, &store)
                .expect_err(&format!("{forbidden} must reject"));
            match &err {
                EscalationVerificationError::NotConsumed { actual, .. } => {
                    assert_eq!(
                        actual, forbidden,
                        "error must surface the actual rejected status"
                    );
                }
                other => panic!("expected NotConsumed for {forbidden}, got {other:?}"),
            }
            assert_eq!(err.diagnostic_code(), "FAIL_ESCALATION_NOT_CONSUMED");
        }
    }

    /// Wrong class: a Consumed BudgetException (or any other class)
    /// must NOT unlock a MergeConflict-attributed merge. Rejecting
    /// preserves INV-05 attribution semantics.
    #[test]
    fn verify_rejects_when_class_is_not_merge_conflict() {
        for forbidden in [
            "BudgetException",
            "CapabilityUpgrade",
            "DelegationRenewal",
            "QualityGateException",
        ] {
            let store = Store::open_in_memory().unwrap();
            let esc = fixture_escalation_id();
            let sess = fixture_session();
            insert_escalation(&store, esc.as_str(), forbidden, "Consumed", sess.as_str());

            let err = verify_merge_conflict_resolution(&esc, &sess, &store)
                .expect_err(&format!("class={forbidden} must reject"));
            match &err {
                EscalationVerificationError::ClassMismatch { actual, .. } => {
                    assert_eq!(actual, forbidden);
                }
                other => panic!("expected ClassMismatch for {forbidden}, got {other:?}"),
            }
            assert_eq!(err.diagnostic_code(), "FAIL_ESCALATION_CLASS_MISMATCH");
        }
    }

    /// Wrong session: an Orchestrator from initiative A cannot reuse
    /// initiative B's resolved escalation to attribute its own
    /// commit. The third spec predicate enforces session identity.
    #[test]
    fn verify_rejects_when_session_does_not_match() {
        let store = Store::open_in_memory().unwrap();
        let esc = fixture_escalation_id();
        let owner = fixture_session();
        let attacker = SessionId::parse("99999999-9999-9999-9999-999999999999").unwrap();
        insert_escalation(
            &store,
            esc.as_str(),
            "MergeConflict",
            "Consumed",
            owner.as_str(),
        );

        let err = verify_merge_conflict_resolution(&esc, &attacker, &store)
            .expect_err("cross-session reuse must reject");
        match &err {
            EscalationVerificationError::SessionMismatch {
                owning_session,
                submitting_session,
                ..
            } => {
                assert_eq!(owning_session, owner.as_str());
                assert_eq!(submitting_session, attacker.as_str());
            }
            other => panic!("expected SessionMismatch, got {other:?}"),
        }
        assert_eq!(err.diagnostic_code(), "FAIL_ESCALATION_SESSION_MISMATCH");
    }

    /// Predicate ordering matters for diagnostics: when class is
    /// wrong AND status is wrong, the error reports `ClassMismatch`
    /// (the first failing predicate). This is deterministic so
    /// audit-replay tooling can pattern-match without ambiguity.
    #[test]
    fn verify_reports_first_failing_predicate_class_before_status() {
        let store = Store::open_in_memory().unwrap();
        let esc = fixture_escalation_id();
        let sess = fixture_session();
        insert_escalation(
            &store,
            esc.as_str(),
            "BudgetException",
            "Pending",
            sess.as_str(),
        );
        let err = verify_merge_conflict_resolution(&esc, &sess, &store).unwrap_err();
        assert!(
            matches!(err, EscalationVerificationError::ClassMismatch { .. }),
            "class is checked before status; got {err:?}"
        );
    }
}
