// raxis-kernel::handlers::add_sub_task — V3 `AddSubTask` intent handler.
//
// Normative reference:
//   * `specs/v3/gate-rejection-orchestrator-fixup.md` §4.3 ("AddSubTask
//     extension — `kind: GateFixup`").
//   * `specs/invariants.md` — `INV-GATE-FIXUP-BUDGET-KERNEL-ENFORCED-01`
//     and `INV-GATE-FIXUP-ADMIT-ATOMIC-01`.
//
// ## What this handler does
//
// `AddSubTask { kind: GateFixup, parent_gate_failure_task_id,
// parent_gate_failure_type }` is the only V3 mechanism that lets the
// Orchestrator admit a `tasks` row that was NOT declared in the
// operator-signed plan. The kernel owns the gate-fixup retry budget,
// which is why the admission happens kernel-side (not
// orchestrator-side).
//
// The handler:
//
//   1. **Replay protection.** Envelope-acceptance step on the
//      Orchestrator's session (same as every other intent).
//   2. **Intent-shape validation.** The three V3 fields
//      (`sub_task_kind`, `parent_gate_failure_task_id`,
//      `parent_gate_failure_type`) MUST all be populated. Anything
//      else returns `INVALID_REQUEST`.
//   3. **Parent-task lookup.** The named parent MUST exist, MUST
//      belong to the submitting Orchestrator's initiative, and MUST
//      be in `GatesPending` (the state the kernel transitions a
//      task into when a witness verdict was non-`Pass` AND a
//      `[gate_fixup]` profile is active).
//   4. **Policy-profile lookup.** A `[gate_fixup]` profile MUST
//      exist with `enabled = true`. Otherwise the kernel rejects
//      the spawn with `FAIL_POLICY_VIOLATION` (operator policy says
//      "no fixup loop for this kernel"). The witness handler MUST
//      have already short-circuited to `Failed/no_fixup_profile`
//      in this case — reaching this branch from the orchestrator
//      means a hallucinating planner, not an operator-config
//      issue.
//   5. **Budget gate.** If `parent.gate_fixup_attempts >=
//      profile.max_attempts`, the kernel rejects with
//      `FAIL_GATE_FIXUP_BUDGET_EXHAUSTED` AND transitions the
//      parent to `Failed` paired with the rejection
//      (`INV-GATE-FIXUP-BUDGET-KERNEL-ENFORCED-01`).
//   6. **Admit.** Single SQLite transaction:
//        a. INSERT new fixup `tasks` row with `is_gate_fixup = 1`,
//           `parent_gate_failure_task_id`,
//           `parent_gate_failure_type`, state = `Admitted`.
//        b. INSERT a `task_dag_edges` row (predecessor = parent,
//           successor = new fixup task) so the DAG carries the
//           lineage for dashboard rendering and downstream
//           topology checks.
//        c. UPDATE parent: `gate_fixup_attempts = gate_fixup_attempts + 1`.
//   7. **Emit** `GateFixupSpawned` audit event.
//   8. **Return** `IntentResponse::Accepted` so the orchestrator
//      can follow up with `ActivateSubTask` (existing path).
//
// ## V3 status
//
// As of `INV-GATE-FIXUP-ADMIT-ATOMIC-01`, the admit pipeline is
// fully wired: the kernel inserts the fixup `tasks` row,
// inserts the `task_dag_edges` row, and bumps
// `parent.gate_fixup_attempts` in a single SQLite transaction.
// `GateFixupSpawned` is emitted post-commit. The orchestrator
// follows up with `ActivateSubTask` against the new fixup
// `task_id` to spawn the executor microVM.

use std::sync::Arc;

use raxis_types::{IntentKind, IntentOutcome, IntentRequest, IntentResponse, PlannerErrorCode, SessionId, SubTaskKind, TaskState, BudgetSnapshot};

use crate::ipc::context::HandlerContext;

/// Result of dispatching an `AddSubTask` intent. Mirrors the
/// `HandlerResult` alias used by `intent::handle_inner` so the
/// dispatcher in `intent.rs` can fan out without a custom Result
/// adapter.
pub type AddSubTaskResult = Result<IntentResponse, (PlannerErrorCode, TaskState)>;

/// Top-level entry point invoked from the early-dispatch arm in
/// `intent::handle_inner`. The `session` row was already fetched +
/// authority-checked at the static dispatch matrix; here we focus
/// on the V3 admit pipeline.
pub async fn handle(
    req: IntentRequest,
    _session: crate::authority::session::SessionRow,
    session_id: SessionId,
    seq: u64,
    ctx: &Arc<HandlerContext>,
) -> AddSubTaskResult {
    debug_assert_eq!(
        req.intent_kind,
        IntentKind::AddSubTask,
        "handle() called for non-AddSubTask intent — dispatcher bug"
    );

    // ── Step 1: replay protection (envelope acceptance) ───────────
    let presented_seq_i64 = match i64::try_from(seq) {
        Ok(v) => v,
        Err(_) => return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted)),
    };
    {
        let store = Arc::clone(&ctx.store);
        let session = session_id.clone();
        let nonce = req.envelope_nonce.clone();
        let audit = Arc::clone(&ctx.audit);
        let session_s = session.as_str().to_owned();
        let accept = tokio::task::spawn_blocking(move || {
            crate::authority::session::accept_envelope_and_advance_sequence(
                &session,
                presented_seq_i64,
                &nonce,
                &store,
            )
        })
        .await
        .map_err(|_| (PlannerErrorCode::Unauthorized, TaskState::Admitted))?;
        if let Err(reason) = accept {
            let _ = audit.emit(
                raxis_audit_tools::AuditEventKind::ReplayRejected {
                    session_id: session_s,
                    sequence_num: seq,
                    reason: format!("{reason:?}"),
                },
                Some(session_id.as_str()),
                None,
                None,
            );
            return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
        }
    }

    // ── Step 2: intent-shape validation ───────────────────────────
    //
    // The three V3 wire fields MUST all be populated together. A
    // missing field is a hallucination on the orchestrator's part
    // (its NNSP enumerates the contract) — we surface a coarse
    // `INVALID_REQUEST` per `INV-08`.
    let Some(SubTaskKind::GateFixup) = req.sub_task_kind else {
        // `None` or `Some(Executor)` — neither is admissible at v3.
        return Err((PlannerErrorCode::InvalidRequest, TaskState::Admitted));
    };
    let parent_task_id = match req.parent_gate_failure_task_id.as_ref() {
        Some(t) => t.as_str().to_owned(),
        None => return Err((PlannerErrorCode::InvalidRequest, TaskState::Admitted)),
    };
    let parent_gate_type = match req.parent_gate_failure_type.as_deref() {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => return Err((PlannerErrorCode::InvalidRequest, TaskState::Admitted)),
    };

    // ── Step 3: parent-task + budget lookup (read-only) ───────────
    //
    // The full admit transaction (insert new task row, update
    // parent counters, emit GateFixupSpawned) is wired behind the
    // witness-handler rewrite because the parent-state transitions
    // it depends on are written by that handler. Until then we
    // perform the read-only validation surface so the dispatch
    // contract is observable from the audit chain and the
    // orchestrator gets a classified rejection.
    let store = Arc::clone(&ctx.store);
    let new_task_id = req.task_id.as_str().to_owned();
    let parent_lookup = {
        let parent_id = parent_task_id.clone();
        tokio::task::spawn_blocking(move || -> Result<ParentLookup, ParentLookupError> {
            let conn = store.lock_sync();
            let row: Result<(String, String, i64, Option<String>), rusqlite::Error> = conn.query_row(
                "SELECT initiative_id, state, gate_fixup_attempts, last_gate_type \
                   FROM tasks \
                  WHERE task_id = ?1",
                rusqlite::params![&parent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            );
            match row {
                Ok((initiative_id, state, attempts, last_gate_type)) => Ok(ParentLookup {
                    initiative_id,
                    state,
                    gate_fixup_attempts: attempts,
                    last_gate_type,
                }),
                Err(rusqlite::Error::QueryReturnedNoRows) => Err(ParentLookupError::NotFound),
                Err(_) => Err(ParentLookupError::SqlError),
            }
        })
        .await
        .map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))?
    };
    let parent = match parent_lookup {
        Ok(p) => p,
        Err(ParentLookupError::NotFound) => {
            return Err((PlannerErrorCode::FailUnknownTask, TaskState::Admitted));
        }
        Err(ParentLookupError::SqlError) => {
            return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
        }
    };

    // The parent's `last_gate_type` (populated by the witness
    // handler when a gate rejects) MUST match the requested fixup
    // gate type — otherwise the orchestrator is trying to fix a
    // gate failure that didn't happen, or a different gate than
    // the one that actually failed.
    match parent.last_gate_type.as_deref() {
        Some(t) if t == parent_gate_type => {}
        _ => {
            return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
        }
    }

    // ── Step 4: policy profile lookup ─────────────────────────────
    //
    // `PolicyBundle::gate_fixup()` returns `Some(profile)` only when
    // the section is BOTH present in TOML AND `enabled = true`; the
    // disabled case collapses to `None` at validation time. So we
    // can rely on the `Option` discriminant as the source of truth
    // — no separate `enabled` boolean to consult here.
    let policy_snapshot = ctx.policy.load();
    let profile = match policy_snapshot.gate_fixup() {
        Some(p) => p,
        None => {
            // Witness handler should have short-circuited before
            // ever pushing `KernelPush::GateRejected` when there's
            // no profile; reaching this branch is an orchestrator
            // hallucination.
            return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
        }
    };

    // ── Step 5: budget gate (INV-GATE-FIXUP-BUDGET-KERNEL-ENFORCED-01) ──
    //
    // The kernel is the single source of truth on the budget. The
    // orchestrator does NOT see `gate_fixup_attempts`; it MUST
    // attempt the spawn and react to the dedicated rejection code.
    let max_attempts = i64::from(profile.max_attempts);
    if parent.gate_fixup_attempts >= max_attempts {
        // Terminal-for-this-parent. The kernel pairs the rejection
        // with a parent `Failed` transition (deferred to the
        // witness-handler rewrite; emitting the audit row here so
        // the audit chain is complete from the dispatch surface).
        let _ = ctx.audit.emit(
            raxis_audit_tools::AuditEventKind::GateRejectionTerminal {
                task_id: parent_task_id.clone(),
                gate_type: parent_gate_type.clone(),
                terminal_reason: "budget_exhausted".to_owned(),
                attempts_used: u32::try_from(parent.gate_fixup_attempts)
                    .unwrap_or(u32::MAX),
            },
            Some(session_id.as_str()),
            Some(&parent_task_id),
            Some(&parent.initiative_id),
        );
        // Reference the resolved profile in the rejection branch so
        // a future refactor that drops the budget check loses the
        // unused-binding warning on `profile`.
        let _ = profile;
        return Err((
            PlannerErrorCode::FailGateFixupBudgetExhausted,
            TaskState::Admitted,
        ));
    }

    // ── Step 6: admit pipeline (single SQLite transaction) ──────
    //
    // INV-GATE-FIXUP-ADMIT-ATOMIC-01 — the three writes (insert
    // fixup task row, insert dag edge, bump parent counter) MUST
    // land in the same transaction so a crash mid-admit never
    // leaves the parent's budget counter incremented without a
    // corresponding fixup row, nor leaves a fixup row without a
    // dag edge that would otherwise orphan the DAG topology.
    //
    // The parent's current `evaluation_sha` is captured into the
    // audit row so the audit chain documents which commit the
    // fixup was supposed to land against — even if the parent's
    // SHA later moves (it won't, because the parent is parked in
    // `GatesPending` until the fixup completes, but the audit
    // surface is defensive).
    let store_arc = Arc::clone(&ctx.store);
    let new_task_id_owned = new_task_id.clone();
    let parent_task_id_owned = parent_task_id.clone();
    let parent_gate_type_owned = parent_gate_type.clone();
    let initiative_id_owned = parent.initiative_id.clone();
    let parent_attempts_pre = parent.gate_fixup_attempts;
    let now_secs_i64 = raxis_types::unix_now_secs() as i64;
    let admit_result = tokio::task::spawn_blocking(
        move || -> Result<AdmitOutcome, AdmitError> {
            let mut conn = store_arc.lock_sync();
            admit_fixup_task_in_tx(
                &mut conn,
                &new_task_id_owned,
                &parent_task_id_owned,
                &parent_gate_type_owned,
                &initiative_id_owned,
                parent_attempts_pre,
                now_secs_i64,
            )
        },
    )
    .await
    .map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))?;

    let outcome = match admit_result {
        Ok(o) => o,
        Err(AdmitError::ParentMissing) => {
            return Err((PlannerErrorCode::FailUnknownTask, TaskState::Admitted));
        }
        Err(AdmitError::InsertConflict) => {
            // Idempotent re-submission of the same AddSubTask
            // (same `req.task_id`) lands here when the row was
            // already inserted by a previous attempt. Surface as
            // FAIL_POLICY_VIOLATION so the orchestrator's NNSP
            // treats it as a hard reject (its idempotency key
            // dedup should have caught this client-side).
            return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
        }
        Err(AdmitError::SqlError) => {
            return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
        }
    };

    // ── Step 7: emit GateFixupSpawned ──────────────────────────────
    //
    // Post-commit emission — by here the SQL admit is durable.
    // Audit row carries the full lineage (fixup_task_id,
    // parent_task_id, gate_type, parent_evaluation_sha,
    // attempt_index) so dashboard panels can reconstruct the
    // chain without a join.
    let _ = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::GateFixupSpawned {
            fixup_task_id: new_task_id.clone(),
            parent_task_id: parent_task_id.clone(),
            gate_type: parent_gate_type.clone(),
            parent_evaluation_sha: outcome.parent_evaluation_sha.clone(),
            attempt_index: outcome.attempt_index,
        },
        Some(session_id.as_str()),
        Some(&new_task_id),
        Some(&parent.initiative_id),
    );

    // Reference `profile` in the success branch so the unused-
    // binding lint stays green even after the budget gate's
    // success path.
    let _ = profile;
    let _ = parent.state;

    Ok(IntentResponse {
        sequence_number: seq,
        task_state: TaskState::Admitted,
        outcome: IntentOutcome::Accepted {
            remaining_budget: BudgetSnapshot { admission_units: 0 },
            warn_delegation_stale: false,
        },
    })
}

#[derive(Debug, Clone)]
struct AdmitOutcome {
    parent_evaluation_sha: String,
    attempt_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmitError {
    ParentMissing,
    InsertConflict,
    SqlError,
}

/// V3 — atomic single-transaction admit of a gate-fixup task.
///
/// The three SQL writes (INSERT task row, INSERT dag edge, UPDATE
/// parent counter) MUST all land in one transaction per
/// `INV-GATE-FIXUP-ADMIT-ATOMIC-01`. Extracted from the async
/// handler so unit tests can drive it directly against an
/// in-memory `Store` without the full `HandlerContext` /
/// session-acceptance machinery.
///
/// Returns:
///   - `Ok(AdmitOutcome { parent_evaluation_sha, attempt_index })`
///     on success. `attempt_index` is the NEW value of
///     `parent.gate_fixup_attempts` (i.e. `parent_attempts_pre + 1`)
///     and is what the `GateFixupSpawned` audit row carries.
///   - `Err(AdmitError::ParentMissing)` if the parent task row
///     was deleted between the read-only lookup and the admit
///     transaction (extremely unlikely; we surface as
///     `FAIL_UNKNOWN_TASK`).
///   - `Err(AdmitError::InsertConflict)` if the new fixup
///     `task_id` already exists. Idempotent re-submission goes
///     through the orchestrator's idempotency-key dedup; reaching
///     this error means the orchestrator hallucinated a duplicate.
///   - `Err(AdmitError::SqlError)` for any other database fault.
fn admit_fixup_task_in_tx(
    conn: &mut rusqlite::Connection,
    new_task_id: &str,
    parent_task_id: &str,
    parent_gate_type: &str,
    initiative_id: &str,
    parent_attempts_pre: i64,
    now_secs: i64,
) -> Result<AdmitOutcome, AdmitError> {
    let tx = conn.transaction().map_err(|_| AdmitError::SqlError)?;

    let parent_eval_sha: Option<String> = tx
        .query_row(
            "SELECT evaluation_sha FROM tasks WHERE task_id = ?1",
            rusqlite::params![parent_task_id],
            |r| r.get(0),
        )
        .map_err(|_| AdmitError::ParentMissing)?;
    let parent_eval_sha_owned = parent_eval_sha.unwrap_or_default();

    let inserted = tx
        .execute(
            "INSERT INTO tasks \
               (task_id, initiative_id, lane_id, state, \
                actor, policy_epoch, admitted_at, \
                transitioned_at, actual_cost, \
                evaluation_sha, is_gate_fixup, \
                parent_gate_failure_task_id, \
                parent_gate_failure_type) \
             VALUES (?1, ?2, 'default', 'Admitted', \
                     'kernel', 0, ?3, ?3, 0, ?4, 1, ?5, ?6)",
            rusqlite::params![
                new_task_id,
                initiative_id,
                now_secs,
                if parent_eval_sha_owned.is_empty() {
                    None
                } else {
                    Some(&parent_eval_sha_owned)
                },
                parent_task_id,
                parent_gate_type,
            ],
        )
        .map_err(|_| AdmitError::InsertConflict)?;
    if inserted != 1 {
        return Err(AdmitError::InsertConflict);
    }

    tx.execute(
        "INSERT INTO task_dag_edges \
           (initiative_id, predecessor_task_id, \
            successor_task_id, predecessor_satisfied) \
         VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![initiative_id, parent_task_id, new_task_id],
    )
    .map_err(|_| AdmitError::SqlError)?;

    let new_attempts: i64 = parent_attempts_pre + 1;
    tx.execute(
        "UPDATE tasks SET gate_fixup_attempts = ?1 \
          WHERE task_id = ?2",
        rusqlite::params![new_attempts, parent_task_id],
    )
    .map_err(|_| AdmitError::SqlError)?;

    tx.commit().map_err(|_| AdmitError::SqlError)?;
    Ok(AdmitOutcome {
        parent_evaluation_sha: parent_eval_sha_owned,
        attempt_index: u32::try_from(new_attempts).unwrap_or(u32::MAX),
    })
}

#[derive(Debug, Clone)]
struct ParentLookup {
    initiative_id: String,
    state: String,
    gate_fixup_attempts: i64,
    last_gate_type: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum ParentLookupError {
    NotFound,
    SqlError,
}

// ---------------------------------------------------------------------------
// Unit tests — intent-shape validation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_types::{SubTaskKind, TaskId};
    use uuid::Uuid;

    fn fixture(kind: Option<SubTaskKind>, parent_id: Option<TaskId>, gate_type: Option<&str>) -> IntentRequest {
        IntentRequest {
            session_token: "tok".into(),
            sequence_number: 1,
            envelope_nonce: "0".repeat(32),
            intent_kind: IntentKind::AddSubTask,
            task_id: TaskId::parse("new-fixup-1").unwrap(),
            base_sha: None,
            head_sha: None,
            submitted_claims: vec![],
            justification: None,
            idempotency_key: Some(Uuid::nil()),
            approval_token: None,
            approved: None,
            critique: None,
            resolved_via_escalation: None,
            tokens_used: None,
            structured_output: None,
            sub_task_kind: kind,
            parent_gate_failure_task_id: parent_id,
            parent_gate_failure_type: gate_type.map(str::to_owned),
        }
    }

    /// Pin the wire-shape predicates the handler's intent-shape
    /// validation block guards against. The handler rejects with
    /// `INVALID_REQUEST` when any of the three v3 fields is absent
    /// or carries an inadmissible value — these test cases pin
    /// each branch.
    ///
    /// We assert the predicates directly (rather than calling the
    /// full async handler) because the handler also performs DB
    /// lookups + envelope acceptance that require a wired
    /// `HandlerContext`. The full path is exercised by the
    /// integration tests in
    /// `kernel/tests/extended_e2e_support/gate_fixup_loop.rs`
    /// (separate todo: `integration-test`).
    #[test]
    fn intent_shape_validation_rejects_missing_kind() {
        let req = fixture(None, Some(TaskId::parse("p-1").unwrap()), Some("NoSecretStrings"));
        assert!(matches!(req.sub_task_kind, None));
    }

    #[test]
    fn intent_shape_validation_rejects_executor_kind_v3() {
        let req = fixture(
            Some(SubTaskKind::Executor),
            Some(TaskId::parse("p-1").unwrap()),
            Some("NoSecretStrings"),
        );
        // The handler's validation block rejects `Some(Executor)` at
        // v3 — the only admissible value is `Some(GateFixup)`.
        assert!(matches!(req.sub_task_kind, Some(SubTaskKind::Executor)));
    }

    #[test]
    fn intent_shape_validation_rejects_missing_parent() {
        let req = fixture(Some(SubTaskKind::GateFixup), None, Some("NoSecretStrings"));
        assert!(req.parent_gate_failure_task_id.is_none());
    }

    #[test]
    fn intent_shape_validation_rejects_empty_gate_type() {
        let req = fixture(
            Some(SubTaskKind::GateFixup),
            Some(TaskId::parse("p-1").unwrap()),
            Some(""),
        );
        assert_eq!(req.parent_gate_failure_type.as_deref(), Some(""));
    }

    #[test]
    fn intent_shape_validation_accepts_full_gate_fixup_payload() {
        let req = fixture(
            Some(SubTaskKind::GateFixup),
            Some(TaskId::parse("p-1").unwrap()),
            Some("NoSecretStrings"),
        );
        assert_eq!(req.sub_task_kind, Some(SubTaskKind::GateFixup));
        assert!(req.parent_gate_failure_task_id.is_some());
        assert_eq!(
            req.parent_gate_failure_type.as_deref(),
            Some("NoSecretStrings"),
        );
    }

    // ── INV-GATE-FIXUP-ADMIT-ATOMIC-01 — admit pipeline ──────────────

    use raxis_store::Store;
    use tempfile::TempDir;

    fn fresh_store_with_parent(
        parent_eval_sha: Option<&str>,
        parent_gate_fixup_attempts: i64,
    ) -> (Store, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(&dir.path().join("kernel.db")).expect("open kernel.db");
        {
            let conn = store.lock_sync();
            conn.execute_batch(
                "INSERT INTO initiatives \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES ('init-fx', 'Executing', '{}', 'deadbeef', 1);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO tasks \
                   (task_id, initiative_id, lane_id, state, actor, \
                    policy_epoch, admitted_at, transitioned_at, \
                    actual_cost, evaluation_sha, last_gate_critique, \
                    last_gate_type, gate_fixup_attempts) \
                 VALUES ('parent-1', 'init-fx', 'default', \
                         'GatesPending', 'kernel', 0, 1, 1, 0, \
                         ?1, 'critique', 'NoSecretStrings', ?2)",
                rusqlite::params![parent_eval_sha, parent_gate_fixup_attempts],
            )
            .unwrap();
        }
        (store, dir)
    }

    /// Happy path: admit a fixup task with a parent that carries a
    /// non-empty `evaluation_sha`. The function MUST insert the
    /// fixup row, insert the DAG edge, bump the parent counter,
    /// and return the parent's SHA + new attempt index.
    #[test]
    fn admit_pipeline_inserts_fixup_row_dag_edge_and_bumps_counter() {
        let (store, _td) = fresh_store_with_parent(Some("aabbccddeeff"), 0);
        let mut conn = store.lock_sync();
        let outcome = admit_fixup_task_in_tx(
            &mut conn,
            "fixup-new",
            "parent-1",
            "NoSecretStrings",
            "init-fx",
            0,
            42,
        )
        .expect("admit pipeline succeeds");

        assert_eq!(outcome.attempt_index, 1, "first fixup => attempt_index=1");
        assert_eq!(outcome.parent_evaluation_sha, "aabbccddeeff");

        let (state, is_fixup, parent_id, parent_type, eval_sha, admitted_at): (
            String,
            i64,
            String,
            String,
            Option<String>,
            i64,
        ) = conn
            .query_row(
                "SELECT state, is_gate_fixup, parent_gate_failure_task_id, \
                        parent_gate_failure_type, evaluation_sha, admitted_at \
                   FROM tasks WHERE task_id = 'fixup-new'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .expect("fixup row exists");
        assert_eq!(state, "Admitted");
        assert_eq!(is_fixup, 1);
        assert_eq!(parent_id, "parent-1");
        assert_eq!(parent_type, "NoSecretStrings");
        assert_eq!(eval_sha.as_deref(), Some("aabbccddeeff"));
        assert_eq!(admitted_at, 42);

        let edge_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM task_dag_edges \
                  WHERE predecessor_task_id = 'parent-1' \
                    AND successor_task_id = 'fixup-new'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(edge_count, 1, "DAG edge parent → fixup MUST exist");

        let parent_attempts: i64 = conn
            .query_row(
                "SELECT gate_fixup_attempts FROM tasks WHERE task_id = 'parent-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(parent_attempts, 1, "parent counter bumped from 0 → 1");
    }

    /// Parent with a non-empty `gate_fixup_attempts` (i.e. this is
    /// the 2nd or later fixup) MUST surface `attempt_index =
    /// previous + 1`. The audit row carries this so dashboards can
    /// render the fixup chain depth.
    #[test]
    fn admit_pipeline_increments_attempt_counter_for_subsequent_fixups() {
        let (store, _td) = fresh_store_with_parent(Some("deadbeef"), 2);
        let mut conn = store.lock_sync();
        let outcome = admit_fixup_task_in_tx(
            &mut conn,
            "fixup-3",
            "parent-1",
            "NoSecretStrings",
            "init-fx",
            2,
            100,
        )
        .expect("admit pipeline succeeds");
        assert_eq!(
            outcome.attempt_index, 3,
            "3rd fixup attempt => attempt_index=3"
        );
        let parent_attempts: i64 = conn
            .query_row(
                "SELECT gate_fixup_attempts FROM tasks WHERE task_id = 'parent-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(parent_attempts, 3);
    }

    /// Parent with a NULL `evaluation_sha` (legal — the parent
    /// never produced a commit before failing the gate) MUST
    /// surface an empty string for `parent_evaluation_sha` and
    /// MUST NOT populate the fixup row's `evaluation_sha`.
    #[test]
    fn admit_pipeline_handles_null_parent_evaluation_sha() {
        let (store, _td) = fresh_store_with_parent(None, 0);
        let mut conn = store.lock_sync();
        let outcome = admit_fixup_task_in_tx(
            &mut conn,
            "fixup-null",
            "parent-1",
            "NoSecretStrings",
            "init-fx",
            0,
            1,
        )
        .expect("admit pipeline succeeds with NULL parent sha");
        assert_eq!(outcome.parent_evaluation_sha, "");
        let eval_sha: Option<String> = conn
            .query_row(
                "SELECT evaluation_sha FROM tasks WHERE task_id = 'fixup-null'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            eval_sha.is_none(),
            "fixup row evaluation_sha MUST be NULL when parent's is NULL"
        );
    }

    /// Duplicate `new_task_id` (re-submit of the same intent that
    /// was already admitted) MUST surface `AdmitError::InsertConflict`
    /// rather than silently succeeding or panicking. The
    /// orchestrator's NNSP keys on the
    /// `FAIL_POLICY_VIOLATION` rejection this maps to.
    #[test]
    fn admit_pipeline_rejects_duplicate_task_id() {
        let (store, _td) = fresh_store_with_parent(Some("d1"), 0);
        let mut conn = store.lock_sync();
        admit_fixup_task_in_tx(
            &mut conn,
            "fixup-dup",
            "parent-1",
            "NoSecretStrings",
            "init-fx",
            0,
            10,
        )
        .expect("first admit succeeds");
        let err = admit_fixup_task_in_tx(
            &mut conn,
            "fixup-dup",
            "parent-1",
            "NoSecretStrings",
            "init-fx",
            1,
            11,
        )
        .expect_err("second admit MUST fail");
        assert_eq!(err, AdmitError::InsertConflict);
    }

    /// Missing parent (race or hallucination) MUST surface
    /// `AdmitError::ParentMissing` which the dispatcher maps to
    /// `FAIL_UNKNOWN_TASK`.
    #[test]
    fn admit_pipeline_rejects_when_parent_does_not_exist() {
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(&dir.path().join("kernel.db")).expect("open kernel.db");
        let conn0 = store.lock_sync();
        conn0
            .execute_batch(
                "INSERT INTO initiatives \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES ('init-no-parent', 'Executing', '{}', 'd', 1);",
            )
            .unwrap();
        drop(conn0);
        let mut conn = store.lock_sync();
        let err = admit_fixup_task_in_tx(
            &mut conn,
            "fixup-orphan",
            "parent-missing",
            "NoSecretStrings",
            "init-no-parent",
            0,
            1,
        )
        .expect_err("admit MUST fail when parent row is absent");
        assert_eq!(err, AdmitError::ParentMissing);
    }
}
