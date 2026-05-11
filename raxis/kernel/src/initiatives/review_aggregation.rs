// raxis-kernel::initiatives::review_aggregation — V2 Step 25 Logical-AND
// verdict aggregation across N parallel Reviewers of one Executor.
//
// Normative reference: v2-deep-spec.md §Step 25 ("Parallel Reviewers
// and the Logical AND Verdict").
//
// At Executor `CompleteTask` time, the Kernel activates ALL Reviewer
// sub-tasks that depend on the Executor (`task_dag_edges` successors).
// Each Reviewer evaluates the same `evaluation_sha` and submits
// `IntentKind::SubmitReview` independently. The Executor's sub-task
// is considered passing IFF every Reviewer approves; a single
// `approved=false` verdict is enough to fail the pipeline.
//
// This module owns the pure-data aggregation predicate: given an
// Executor `task_id`, return one of three states by inspecting every
// successor's `review_verdict` column on `tasks`.
//
// **Why the verdict lives on `tasks` rather than on
// `subtask_activations`.** See `raxis_types::ReviewVerdict` doc — the
// short version is that `tasks` carries the LATEST verdict (mirroring
// `tasks.last_critique`), so the aggregation query is a single
// `task_dag_edges → tasks` join with no per-activation history scan.
//
// **Design constraint: agent-type filtering at the call site, not in SQL.**
// Step 25 specifies that this aggregation considers only Reviewer
// successors. Plan-bundle sealing (V2 §Step 1.2 /
// `0008_v2_plan_bundle_sealing.sql`) has shipped, so
// `subtask_activations` rows now exist for every Executor /
// Reviewer task admitted under V2 — the substrate that future
// SQL-level filtering would join against (`subtask_activations`
// has no `session_agent_type` column today; the agent type lives
// on `sessions` via `subtask_activations.session_id` after
// activation).
//
// We deliberately keep the predicate plan-shape-agnostic for two
// reasons:
//
//   * V1 plans never produce SubmitReview intents (the dispatch
//     matrix rejects them) so `review_verdict` stays NULL on V1
//     successors and they are reported as `Pending` — consistent
//     with the "still has unsubmitted reviewers" semantic.
//   * V2 plans mix Executor and Reviewer successors of one
//     Executor only via the explicit Reviewer dependency model
//     described in `v2-deep-spec.md §Step 23`. The Step-17
//     plan-shape validators (`validate_reviewer_dependencies` and
//     friends) already reject any sub-task whose `predecessors`
//     point at a non-Executor; reaching this aggregator with a
//     non-Reviewer successor is therefore a structural bug in the
//     plan substrate, not a runtime mis-classification — and the
//     `Pending` fall-through is the safe posture.
//
// The aggregator is therefore safe to ship today: it returns
// `Pending` when ANY successor lacks a verdict, which is exactly
// the "wait-for-the-last-reviewer" pre-condition for the
// `KernelPush::AllReviewersPassed` push.

use raxis_store::{Store, Table};
use raxis_types::ReviewVerdict;

const TASKS:           &str = Table::Tasks.as_str();
const TASK_DAG_EDGES:  &str = Table::TaskDagEdges.as_str();

/// The three states the Step 25 aggregator can be in.
///
/// The state is computed from the union of successors' verdicts:
/// * Any NULL verdict → `Pending` (a Reviewer is still working).
/// * Every verdict `Approved` → `AllPassed` (logical-AND of `true`).
/// * No NULL and at least one `Rejected` → `AtLeastOneRejected`.
///
/// The "no successors" case is reported as `NoSuccessors` so callers
/// can distinguish it from `Pending` — a malformed plan that
/// declares an Executor with no Reviewer dependents would otherwise
/// be silently mapped to `AllPassed`, which is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AggregateReviewVerdict {
    /// One or more successors have not yet submitted a verdict.
    /// Caller MUST NOT advance the Executor or emit
    /// `KernelPush::AllReviewersPassed` — wait for the next
    /// `SubmitReview` from a sibling Reviewer.
    Pending,
    /// Every successor submitted `Approved`. Caller emits
    /// `KernelPush::AllReviewersPassed` and progresses the Executor.
    AllPassed,
    /// Every successor submitted, and at least one rejected. Caller
    /// emits `KernelPush::ReviewRejected` (with the aggregated
    /// `tasks.last_critique` text on the Executor) and prepares the
    /// Orchestrator for `RetrySubTask`.
    AtLeastOneRejected,
    /// The Executor task has no successors in `task_dag_edges`. This
    /// is malformed under V2 (every Executor sub-task should have at
    /// least one Reviewer dependent) but we surface it as a distinct
    /// variant so the caller can decide policy: typically
    /// fail-closed at the kernel layer rather than silently treat
    /// "no reviewers" as "all reviewers passed".
    NoSuccessors,
}

/// Aggregator outcome plus the cardinality the kernel observed.
///
/// `count` is the number of Reviewer successor rows folded in; it is
/// surfaced alongside `verdict` so the post-commit audit emitter
/// (`AuditEventKind::ReviewAggregationCompleted`) can record it
/// without re-running the join. `count == 0` if and only if the
/// verdict is `NoSuccessors` (defense-in-depth on a malformed plan).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AggregateOutcome {
    /// The folded verdict; see [`AggregateReviewVerdict`].
    pub verdict: AggregateReviewVerdict,
    /// Number of Reviewer successor rows the aggregator inspected.
    /// Equal to the count of `task_dag_edges` rows whose
    /// `predecessor_task_id == executor_task_id`.
    pub count:   u32,
}

/// Compute the Step 25 logical-AND verdict for an Executor task.
///
/// Convenience shim that drops the cardinality field; equivalent to
/// `compute_aggregate_review_outcome(...).map(|o| o.verdict)`. New
/// call sites that need the count for audit emission MUST call
/// [`compute_aggregate_review_outcome`] directly.
pub fn compute_aggregate_review_verdict(
    executor_task_id: &str,
    store:            &Store,
) -> Result<AggregateReviewVerdict, rusqlite::Error> {
    compute_aggregate_review_outcome(executor_task_id, store)
        .map(|o| o.verdict)
}

/// Compute the Step 25 logical-AND verdict AND the successor count.
///
/// Reads `tasks.review_verdict` for every successor of
/// `executor_task_id` in `task_dag_edges` and folds them into a
/// [`AggregateOutcome`]. Pure read path — does NOT mutate the
/// database; safe to call from any read-write context that needs the
/// predicate.
///
/// **Why a separate count.** The audit event
/// `ReviewAggregationCompleted` carries the cardinality so operators
/// can confirm the aggregator inspected the expected number of
/// Reviewer rows (catches a malformed `task_dag_edges` join that
/// silently drops rows). Returning it from the same query removes a
/// second SELECT in the hot post-commit path.
///
/// Returns a SQLite error only when the DB layer itself fails (rare
/// — typically a malformed schema or a poisoned mutex). The verdict
/// path itself is total: every (NULL | Approved | Rejected | unknown
/// CHECK-constraint-rejected) input row maps to exactly one
/// `AggregateReviewVerdict` variant.
pub fn compute_aggregate_review_outcome(
    executor_task_id: &str,
    store:            &Store,
) -> Result<AggregateOutcome, rusqlite::Error> {
    let conn = store.lock_sync();

    // Pull every successor's verdict in a single query. NULL is
    // SQL-side, so we read into Option<String> and parse to enum at
    // the Rust layer (matches the `ReviewVerdict::from_sql_str`
    // contract — NULL is not a value of the enum, it's a sentinel).
    let mut stmt = conn.prepare(&format!(
        "SELECT t.review_verdict \
         FROM {TASK_DAG_EDGES} e \
         JOIN {TASKS} t ON t.task_id = e.successor_task_id \
         WHERE e.predecessor_task_id = ?1"
    ))?;

    let mut rows = stmt.query(rusqlite::params![executor_task_id])?;

    let mut count           = 0u32;
    let mut any_pending     = false;
    let mut any_rejected    = false;
    let mut all_approved    = true;

    while let Some(row) = rows.next()? {
        count += 1;
        let raw: Option<String> = row.get(0)?;
        match raw.as_deref().and_then(ReviewVerdict::from_sql_str) {
            None => {
                // Either NULL (no submission yet) or an unknown string
                // that the CHECK should have rejected. Treat both as
                // "pending" — failing closed against database
                // corruption is the same posture as failing closed
                // against a slow Reviewer.
                any_pending  = true;
                all_approved = false;
            }
            Some(ReviewVerdict::Approved) => {
                // Hold for the AND.
            }
            Some(ReviewVerdict::Rejected) => {
                any_rejected = true;
                all_approved = false;
            }
        }
    }

    let verdict = if count == 0 {
        AggregateReviewVerdict::NoSuccessors
    } else if any_pending {
        AggregateReviewVerdict::Pending
    } else if any_rejected {
        AggregateReviewVerdict::AtLeastOneRejected
    } else {
        debug_assert!(all_approved);
        AggregateReviewVerdict::AllPassed
    };

    Ok(AggregateOutcome { verdict, count })
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_store::Store;
    use raxis_types::{InitiativeState, TaskState, unix_now_secs};

    /// Insert one initiative, one Executor task, and N Reviewer
    /// successor tasks all linked to the Executor via
    /// `task_dag_edges`. Returns the Executor's task_id.
    fn seed_executor_with_n_reviewers(
        store:           &Store,
        n_reviewers:     usize,
    ) -> String {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        conn.execute(
            &format!(
                "INSERT INTO {initiatives} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES ('init-agg', ?1, '{{}}', 'deadbeef', ?2)",
                initiatives = Table::Initiatives.as_str(),
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        ).unwrap();
        // Executor.
        conn.execute(
            &format!(
                "INSERT INTO {tasks} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at) \
                 VALUES ('exe-1', 'init-agg', 'default', ?1, 'kernel', \
                         1, ?2, ?2)",
                tasks = Table::Tasks.as_str(),
            ),
            rusqlite::params![TaskState::Running.as_sql_str(), now],
        ).unwrap();
        // Reviewers + edges.
        for i in 0..n_reviewers {
            let rid = format!("rev-{i}");
            conn.execute(
                &format!(
                    "INSERT INTO {tasks} \
                        (task_id, initiative_id, lane_id, state, actor, \
                         policy_epoch, admitted_at, transitioned_at) \
                     VALUES (?1, 'init-agg', 'default', ?2, 'kernel', \
                             1, ?3, ?3)",
                    tasks = Table::Tasks.as_str(),
                ),
                rusqlite::params![rid, TaskState::Running.as_sql_str(), now],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {dag} \
                        (initiative_id, predecessor_task_id, \
                         successor_task_id, predecessor_satisfied) \
                     VALUES ('init-agg', 'exe-1', ?1, 1)",
                    dag = Table::TaskDagEdges.as_str(),
                ),
                rusqlite::params![rid],
            ).unwrap();
        }
        "exe-1".to_owned()
    }

    fn set_verdict(store: &Store, task_id: &str, v: ReviewVerdict) {
        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "UPDATE {} SET review_verdict = ?1 WHERE task_id = ?2",
                Table::Tasks.as_str(),
            ),
            rusqlite::params![v.as_sql_str(), task_id],
        ).unwrap();
    }

    /// No successors → `NoSuccessors`. Distinct from `AllPassed` so
    /// the caller can fail-closed on a malformed plan.
    #[test]
    fn no_successors_returns_no_successors_variant() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 0);
        let v = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(v, AggregateReviewVerdict::NoSuccessors);
    }

    /// All successors NULL → `Pending`. The wait-for-reviewers gate.
    #[test]
    fn all_pending_returns_pending() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 3);
        let v = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(v, AggregateReviewVerdict::Pending);
    }

    /// Mix of submitted + unsubmitted → `Pending`. Even N-1 approvals
    /// stall on the missing N'th — the AND requires every voter.
    #[test]
    fn partial_submissions_stay_pending() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 3);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        set_verdict(&store, "rev-1", ReviewVerdict::Approved);
        // rev-2 still NULL.
        let v = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(v, AggregateReviewVerdict::Pending);
    }

    /// All Approved → `AllPassed`. The success edge.
    #[test]
    fn all_approved_returns_all_passed() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 3);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        set_verdict(&store, "rev-1", ReviewVerdict::Approved);
        set_verdict(&store, "rev-2", ReviewVerdict::Approved);
        let v = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(v, AggregateReviewVerdict::AllPassed);
    }

    /// Single Rejected among Approved → `AtLeastOneRejected`. The
    /// "logical AND" property: one false breaks the chain.
    #[test]
    fn one_rejection_among_approvals_returns_rejected() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 3);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        set_verdict(&store, "rev-1", ReviewVerdict::Rejected);
        set_verdict(&store, "rev-2", ReviewVerdict::Approved);
        let v = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(v, AggregateReviewVerdict::AtLeastOneRejected);
    }

    /// Pending takes priority over Rejected: if any reviewer hasn't
    /// submitted yet, the verdict is Pending regardless of others'
    /// submissions. This is the canonical "wait for everyone" rule.
    #[test]
    fn pending_takes_priority_over_rejected() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 3);
        set_verdict(&store, "rev-0", ReviewVerdict::Rejected);
        // rev-1, rev-2 NULL.
        let v = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(v, AggregateReviewVerdict::Pending);
    }

    /// Single reviewer with Approved — N=1 boundary case.
    #[test]
    fn single_reviewer_approved_returns_all_passed() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 1);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        let v = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(v, AggregateReviewVerdict::AllPassed);
    }

    /// Single reviewer with Rejected — N=1 boundary case.
    #[test]
    fn single_reviewer_rejected_returns_rejected() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 1);
        set_verdict(&store, "rev-0", ReviewVerdict::Rejected);
        let v = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(v, AggregateReviewVerdict::AtLeastOneRejected);
    }

    /// All Rejected — exhausts the AtLeastOneRejected path.
    #[test]
    fn all_rejected_returns_rejected() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 3);
        set_verdict(&store, "rev-0", ReviewVerdict::Rejected);
        set_verdict(&store, "rev-1", ReviewVerdict::Rejected);
        set_verdict(&store, "rev-2", ReviewVerdict::Rejected);
        let v = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(v, AggregateReviewVerdict::AtLeastOneRejected);
    }

    /// Verdicts on a DIFFERENT executor must not bleed into this
    /// executor's aggregation. Pin the reverse-DAG scope.
    #[test]
    fn verdicts_are_scoped_to_predecessor_task_id() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 1);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);

        // Insert a SECOND executor + reviewer (different initiative
        // not necessary for the predicate, but cleaner) and reject
        // its reviewer. The first executor's aggregation must not
        // observe the second.
        let conn = store.lock_sync();
        let now = unix_now_secs();
        conn.execute(
            &format!(
                "INSERT INTO {tasks} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at) \
                 VALUES ('exe-2', 'init-agg', 'default', ?1, 'kernel', \
                         1, ?2, ?2)",
                tasks = Table::Tasks.as_str(),
            ),
            rusqlite::params![TaskState::Running.as_sql_str(), now],
        ).unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {tasks} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at, \
                     review_verdict) \
                 VALUES ('rev-99', 'init-agg', 'default', ?1, 'kernel', \
                         1, ?2, ?2, 'Rejected')",
                tasks = Table::Tasks.as_str(),
            ),
            rusqlite::params![TaskState::Running.as_sql_str(), now],
        ).unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {dag} \
                    (initiative_id, predecessor_task_id, \
                     successor_task_id, predecessor_satisfied) \
                 VALUES ('init-agg', 'exe-2', 'rev-99', 1)",
                dag = Table::TaskDagEdges.as_str(),
            ),
            [],
        ).unwrap();
        drop(conn);

        // exe-1 sees only rev-0 (Approved) → AllPassed; the rejected
        // reviewer of exe-2 does NOT contaminate.
        let v1 = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(v1, AggregateReviewVerdict::AllPassed);

        let v2 = compute_aggregate_review_verdict("exe-2", &store).unwrap();
        assert_eq!(v2, AggregateReviewVerdict::AtLeastOneRejected);
    }

    /// Aggregation against a non-existent executor returns
    /// `NoSuccessors` (the reverse-join finds no rows). Pin this so
    /// callers can rely on the variant for malformed-input handling.
    #[test]
    fn unknown_executor_returns_no_successors() {
        let store = Store::open_in_memory().unwrap();
        let _exe = seed_executor_with_n_reviewers(&store, 0);
        let v = compute_aggregate_review_verdict("does-not-exist", &store).unwrap();
        assert_eq!(v, AggregateReviewVerdict::NoSuccessors);
    }

    /// `compute_aggregate_review_outcome` returns the same verdict
    /// the bare `compute_aggregate_review_verdict` shim returns AND
    /// reports the cardinality the audit emitter consumes. Pins the
    /// (verdict, count) contract so the audit row's `reviewer_count`
    /// field cannot silently drift from the join the aggregator
    /// performs.
    #[test]
    fn outcome_returns_verdict_and_count_in_lock_step() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 4);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        set_verdict(&store, "rev-1", ReviewVerdict::Approved);
        set_verdict(&store, "rev-2", ReviewVerdict::Approved);
        set_verdict(&store, "rev-3", ReviewVerdict::Approved);

        let outcome = compute_aggregate_review_outcome(&exe, &store).unwrap();
        assert_eq!(outcome.verdict, AggregateReviewVerdict::AllPassed);
        assert_eq!(outcome.count, 4);

        // Shim must agree with the rich variant.
        let bare = compute_aggregate_review_verdict(&exe, &store).unwrap();
        assert_eq!(bare, outcome.verdict);
    }

    /// `count == 0` if and only if the verdict is `NoSuccessors`.
    /// The audit emitter relies on this invariant to skip the
    /// `ReviewAggregationCompleted` event for malformed plans
    /// without re-running a count query.
    #[test]
    fn outcome_count_is_zero_iff_no_successors() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 0);

        let outcome = compute_aggregate_review_outcome(&exe, &store).unwrap();
        assert_eq!(outcome.verdict, AggregateReviewVerdict::NoSuccessors);
        assert_eq!(outcome.count, 0);
    }

    /// Pending verdicts still report the full successor count — the
    /// aggregator inspected every row, it just hasn't reached a
    /// terminal AND yet. This pins that the count is not gated on
    /// the verdict.
    #[test]
    fn outcome_count_is_total_even_when_pending() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 3);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        // rev-1, rev-2 NULL.

        let outcome = compute_aggregate_review_outcome(&exe, &store).unwrap();
        assert_eq!(outcome.verdict, AggregateReviewVerdict::Pending);
        assert_eq!(outcome.count, 3);
    }
}
