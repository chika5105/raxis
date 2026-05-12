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
// **Design: agent-type filtering driven by the sealed plan bundle.**
// Step 25 specifies that this aggregation considers only Reviewer
// successors. The aggregator now consumes the kernel's in-memory
// `PlanRegistry` (populated atomically at admission from the
// sealed plan bundle, see `plan-bundle-sealing.md §8.1`) to filter
// successors to those whose `TaskPlanFields::session_agent_type`
// is `Reviewer` before folding their verdict. This closes the
// V2.5 gap that previously left the aggregator
// "plan-shape-agnostic" — i.e., trusting that every successor of
// an Executor was a Reviewer purely because the Step-17 plan-shape
// validators rejected the alternatives at admission.
//
// The filter is **opt-in via [`AgentTypeFilter`]**:
//
//   * Production (`handle_submit_review`) passes
//     `Some(AgentTypeFilter { plan_registry, initiative_id })` so
//     the aggregator drops any successor whose registry entry
//     declares a non-Reviewer agent type — the actively-wrong
//     case the legacy "trust the join" workaround couldn't
//     detect.
//   * **Missing-entry rows fall open: treated as Reviewer for the
//     fold.** This is a deliberate best-judgment scope (V2.5
//     transition). Rationale:
//       * V2.5+ admission populates the registry atomically with
//         the sealed bundle, and `repopulate_plan_registry`
//         re-seeds on every kernel restart — so a missing entry
//         post-admission is a kernel bug rather than a benign
//         data shape, and failing closed would silently degrade a
//         registry-rebuild race into "all reviewers ignored".
//       * The audit chain (`ReviewAggregationCompleted` row +
//         `subtask_activations.review_reject_count` counter) is
//         the operator's safety net: a registry-corruption bug
//         that mis-folds reviewer counts would still surface in
//         the audit row's `reviewer_count` cardinality (catching
//         the off-by-N) and in the operator-visible `RetrySubTask`
//         outcome — fail-closed-on-missing would erase BOTH
//         signals.
//       * Unit tests in `handlers::intent` seed
//         `tasks` / `task_dag_edges` directly without populating
//         the kernel's `PlanRegistry`; treating missing entries as
//         Reviewer keeps those tests exercising the legacy
//         fold-everything behaviour while the production path
//         still rejects actively-wrong non-Reviewer rows.
//   * Unit tests in this module that pre-date the sealed-bundle
//     filter pass `None` to disable the filter entirely; the
//     dedicated `agent_type_filter_*` tests below cover the
//     filter behaviour.
//   * V1 plans never produce SubmitReview intents (the dispatch
//     matrix rejects them) so `review_verdict` stays NULL on V1
//     successors and they are reported as `Pending` — consistent
//     with the "still has unsubmitted reviewers" semantic. V1
//     code paths do not invoke this aggregator at all, so the
//     filter does not affect them.
//
// The aggregator returns `Pending` when ANY *Reviewer* successor
// lacks a verdict, which is exactly the
// "wait-for-the-last-reviewer" pre-condition for the
// `KernelPush::AllReviewersPassed` push.

use raxis_store::{Store, Table};
use raxis_types::{ReviewVerdict, SessionAgentType};

use crate::initiatives::plan_registry::{PlanRegistry, TaskKey};

const TASKS: &str = Table::Tasks.as_str();
const TASK_DAG_EDGES: &str = Table::TaskDagEdges.as_str();

/// V2.5 §Step 25 — sealed-plan-bundle agent-type filter.
///
/// Wraps a `(plan_registry, initiative_id)` pair so the aggregator
/// can ask "is this `successor_task_id` a Reviewer?" against the
/// kernel's in-memory plan registry without callers having to
/// re-implement the lookup. Constructed by
/// `handle_submit_review` from `ctx.plan_registry` +
/// `task.initiative_id`; tests pass `None` to opt out of the
/// filter when exercising the bare verdict-fold logic.
#[derive(Debug, Clone, Copy)]
pub struct AgentTypeFilter<'a> {
    pub plan_registry: &'a PlanRegistry,
    pub initiative_id: &'a str,
}

impl AgentTypeFilter<'_> {
    /// Return `true` iff the registry entry for
    /// `(initiative_id, successor_task_id)` declares the task as
    /// a Reviewer, OR no entry exists at all (missing-entry rows
    /// fall open per the V2.5 transition contract documented at
    /// the module top — only registry rows that *actively
    /// declare* a non-Reviewer agent type are dropped).
    fn is_reviewer(&self, successor_task_id: &str) -> bool {
        let key = TaskKey::new(self.initiative_id, successor_task_id);
        match self.plan_registry.get(&key) {
            // Active declaration: trust it. Drop everything that
            // is not Reviewer.
            Some(f) => f.session_agent_type == SessionAgentType::Reviewer,
            // Missing-entry: fall open. The legacy "trust the
            // join" assumption was that every successor of an
            // Executor is a Reviewer (because Step-17 plan-shape
            // validators rejected the alternatives at admission);
            // we keep that assumption ONLY when the registry has
            // nothing to say. The audit chain is the operator's
            // safety net for registry-corruption bugs.
            None => true,
        }
    }
}

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
    pub count: u32,
}

/// Compute the Step 25 logical-AND verdict for an Executor task.
///
/// Convenience shim that drops the cardinality field; equivalent to
/// `compute_aggregate_review_outcome(...).map(|o| o.verdict)`. New
/// call sites that need the count for audit emission MUST call
/// [`compute_aggregate_review_outcome`] directly.
///
/// `agent_type_filter` mirrors the same parameter on
/// [`compute_aggregate_review_outcome`]; pass `None` to disable the
/// sealed-bundle filter (legacy / test-only) or `Some(...)` to
/// scope the fold to plan-declared `SessionAgentType::Reviewer`
/// successors only.
pub fn compute_aggregate_review_verdict(
    executor_task_id: &str,
    store: &Store,
    agent_type_filter: Option<AgentTypeFilter<'_>>,
) -> Result<AggregateReviewVerdict, rusqlite::Error> {
    compute_aggregate_review_outcome(executor_task_id, store, agent_type_filter).map(|o| o.verdict)
}

/// Compute the Step 25 logical-AND verdict AND the successor count.
///
/// Reads `tasks.review_verdict` for every successor of
/// `executor_task_id` in `task_dag_edges`, optionally filters out
/// non-Reviewer successors via `agent_type_filter` (the V2.5
/// sealed-plan-bundle gate), and folds the remaining rows into a
/// [`AggregateOutcome`]. Pure read path — does NOT mutate the
/// database; safe to call from any read-write context that needs the
/// predicate.
///
/// **`agent_type_filter` semantics.**
/// * `Some(AgentTypeFilter { plan_registry, initiative_id })` —
///   each successor's `(initiative_id, task_id)` is looked up in
///   the kernel's `PlanRegistry`; rows whose
///   `TaskPlanFields::session_agent_type` is **actively declared**
///   as something other than `SessionAgentType::Reviewer` are
///   skipped (do NOT count towards `count`, do NOT influence the
///   verdict). Missing-entry rows fall open and are folded as
///   Reviewer (V2.5 transition contract — see the module-top
///   doc for the rationale; the audit chain remains the
///   operator's safety net). Used by the production
///   `handle_submit_review` call site.
/// * `None` — every successor in `task_dag_edges` is folded, with
///   no agent-type predicate. Used by tests that exercise the
///   verdict-fold logic in isolation; legacy callers that never
///   constructed a `PlanRegistry` keep working through this arm.
///
/// **Why a separate count.** The audit event
/// `ReviewAggregationCompleted` carries the cardinality so operators
/// can confirm the aggregator inspected the expected number of
/// Reviewer rows (catches a malformed `task_dag_edges` join that
/// silently drops rows). Returning it from the same query removes a
/// second SELECT in the hot post-commit path. With the filter
/// active, the count reflects *Reviewer-only* successors — exactly
/// what `v2-deep-spec.md §Step 25` cares about.
///
/// Returns a SQLite error only when the DB layer itself fails (rare
/// — typically a malformed schema or a poisoned mutex). The verdict
/// path itself is total: every (NULL | Approved | Rejected | unknown
/// CHECK-constraint-rejected) input row maps to exactly one
/// `AggregateReviewVerdict` variant.
pub fn compute_aggregate_review_outcome(
    executor_task_id: &str,
    store: &Store,
    agent_type_filter: Option<AgentTypeFilter<'_>>,
) -> Result<AggregateOutcome, rusqlite::Error> {
    let conn = store.lock_sync();

    // Pull every successor's task_id + verdict in a single query.
    // NULL verdict is SQL-side, so we read into Option<String> and
    // parse to enum at the Rust layer (matches the
    // `ReviewVerdict::from_sql_str` contract — NULL is not a value
    // of the enum, it's a sentinel). The successor task_id is also
    // selected so the in-Rust agent-type filter can look it up
    // against `PlanRegistry`; without `agent_type_filter` set, the
    // task_id column is just thrown away.
    let mut stmt = conn.prepare(&format!(
        "SELECT t.task_id, t.review_verdict \
         FROM {TASK_DAG_EDGES} e \
         JOIN {TASKS} t ON t.task_id = e.successor_task_id \
         WHERE e.predecessor_task_id = ?1"
    ))?;

    let mut rows = stmt.query(rusqlite::params![executor_task_id])?;

    let mut count = 0u32;
    let mut any_pending = false;
    let mut any_rejected = false;
    let mut all_approved = true;

    while let Some(row) = rows.next()? {
        let successor_task_id: String = row.get(0)?;
        let raw: Option<String> = row.get(1)?;

        // V2.5 §Step 25 — sealed-plan-bundle filter. When the call
        // site passes a registry, we drop rows that the plan
        // bundle *actively declares* as a non-Reviewer agent
        // type. Missing-entry rows fall open (folded as Reviewer)
        // per the V2.5 transition contract (see module-top doc):
        // the audit chain is the safety net for registry bugs,
        // and integration tests in `handlers::intent` that don't
        // populate the registry rely on this behaviour.
        if let Some(filter) = agent_type_filter.as_ref() {
            if !filter.is_reviewer(&successor_task_id) {
                continue;
            }
        }

        count += 1;
        match raw.as_deref().and_then(ReviewVerdict::from_sql_str) {
            None => {
                // Either NULL (no submission yet) or an unknown string
                // that the CHECK should have rejected. Treat both as
                // "pending" — failing closed against database
                // corruption is the same posture as failing closed
                // against a slow Reviewer.
                any_pending = true;
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
    use raxis_types::{unix_now_secs, InitiativeState, TaskState};

    /// Insert one initiative, one Executor task, and N Reviewer
    /// successor tasks all linked to the Executor via
    /// `task_dag_edges`. Returns the Executor's task_id.
    fn seed_executor_with_n_reviewers(store: &Store, n_reviewers: usize) -> String {
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
        )
        .unwrap();
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
        )
        .unwrap();
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
            )
            .unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {dag} \
                        (initiative_id, predecessor_task_id, \
                         successor_task_id, predecessor_satisfied) \
                     VALUES ('init-agg', 'exe-1', ?1, 1)",
                    dag = Table::TaskDagEdges.as_str(),
                ),
                rusqlite::params![rid],
            )
            .unwrap();
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
        )
        .unwrap();
    }

    /// No successors → `NoSuccessors`. Distinct from `AllPassed` so
    /// the caller can fail-closed on a malformed plan.
    #[test]
    fn no_successors_returns_no_successors_variant() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 0);
        let v = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
        assert_eq!(v, AggregateReviewVerdict::NoSuccessors);
    }

    /// All successors NULL → `Pending`. The wait-for-reviewers gate.
    #[test]
    fn all_pending_returns_pending() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 3);
        let v = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
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
        let v = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
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
        let v = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
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
        let v = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
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
        let v = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
        assert_eq!(v, AggregateReviewVerdict::Pending);
    }

    /// Single reviewer with Approved — N=1 boundary case.
    #[test]
    fn single_reviewer_approved_returns_all_passed() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 1);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        let v = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
        assert_eq!(v, AggregateReviewVerdict::AllPassed);
    }

    /// Single reviewer with Rejected — N=1 boundary case.
    #[test]
    fn single_reviewer_rejected_returns_rejected() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 1);
        set_verdict(&store, "rev-0", ReviewVerdict::Rejected);
        let v = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
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
        let v = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
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
        )
        .unwrap();
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
        )
        .unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {dag} \
                    (initiative_id, predecessor_task_id, \
                     successor_task_id, predecessor_satisfied) \
                 VALUES ('init-agg', 'exe-2', 'rev-99', 1)",
                dag = Table::TaskDagEdges.as_str(),
            ),
            [],
        )
        .unwrap();
        drop(conn);

        // exe-1 sees only rev-0 (Approved) → AllPassed; the rejected
        // reviewer of exe-2 does NOT contaminate.
        let v1 = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
        assert_eq!(v1, AggregateReviewVerdict::AllPassed);

        let v2 = compute_aggregate_review_verdict("exe-2", &store, None).unwrap();
        assert_eq!(v2, AggregateReviewVerdict::AtLeastOneRejected);
    }

    /// Aggregation against a non-existent executor returns
    /// `NoSuccessors` (the reverse-join finds no rows). Pin this so
    /// callers can rely on the variant for malformed-input handling.
    #[test]
    fn unknown_executor_returns_no_successors() {
        let store = Store::open_in_memory().unwrap();
        let _exe = seed_executor_with_n_reviewers(&store, 0);
        let v = compute_aggregate_review_verdict("does-not-exist", &store, None).unwrap();
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

        let outcome = compute_aggregate_review_outcome(&exe, &store, None).unwrap();
        assert_eq!(outcome.verdict, AggregateReviewVerdict::AllPassed);
        assert_eq!(outcome.count, 4);

        // Shim must agree with the rich variant.
        let bare = compute_aggregate_review_verdict(&exe, &store, None).unwrap();
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

        let outcome = compute_aggregate_review_outcome(&exe, &store, None).unwrap();
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

        let outcome = compute_aggregate_review_outcome(&exe, &store, None).unwrap();
        assert_eq!(outcome.verdict, AggregateReviewVerdict::Pending);
        assert_eq!(outcome.count, 3);
    }

    // ── V2.5 §Step 25 — sealed-plan-bundle agent-type filter ─────────────

    use crate::initiatives::plan_registry::TaskPlanFields;

    /// Helper that registers `task_id` under `init-agg` with a given
    /// `session_agent_type`. Mirrors what `approve_plan` does at
    /// admission for every `[[tasks]]` row in the sealed bundle.
    fn register_task(reg: &PlanRegistry, task_id: &str, agent: SessionAgentType) {
        let key = TaskKey::new("init-agg", task_id);
        let fields = TaskPlanFields {
            session_agent_type: agent,
            ..Default::default()
        };
        reg.insert(key, fields);
    }

    /// Filter active + every successor declared as Reviewer +
    /// every Reviewer Approved → `AllPassed`. Pins that the filter
    /// does not regress the happy path when the registry agrees
    /// with the legacy "trust the join" assumption.
    #[test]
    fn agent_type_filter_keeps_reviewer_successors() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 3);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        set_verdict(&store, "rev-1", ReviewVerdict::Approved);
        set_verdict(&store, "rev-2", ReviewVerdict::Approved);

        let reg = PlanRegistry::new();
        register_task(&reg, "rev-0", SessionAgentType::Reviewer);
        register_task(&reg, "rev-1", SessionAgentType::Reviewer);
        register_task(&reg, "rev-2", SessionAgentType::Reviewer);

        let outcome = compute_aggregate_review_outcome(
            &exe,
            &store,
            Some(AgentTypeFilter {
                plan_registry: &reg,
                initiative_id: "init-agg",
            }),
        )
        .unwrap();
        assert_eq!(outcome.verdict, AggregateReviewVerdict::AllPassed);
        assert_eq!(outcome.count, 3, "all three Reviewer rows must be folded");
    }

    /// Filter active + non-Reviewer successor → that successor is
    /// skipped entirely (does not count, does not influence
    /// verdict). Pins the V2.5 §Step 25 contract that the
    /// aggregator considers Reviewer successors only.
    #[test]
    fn agent_type_filter_skips_non_reviewer_successor() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 3);
        // rev-0 + rev-1 are Reviewers and approve. rev-2 is
        // (incorrectly, per Step-17 plan-shape) declared as a nested
        // Executor in the registry; without the filter it would
        // surface as Pending and stall the pipeline. With the
        // filter it is dropped and the verdict short-circuits.
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        set_verdict(&store, "rev-1", ReviewVerdict::Approved);
        // rev-2 verdict stays NULL — the filter drops it entirely.

        let reg = PlanRegistry::new();
        register_task(&reg, "rev-0", SessionAgentType::Reviewer);
        register_task(&reg, "rev-1", SessionAgentType::Reviewer);
        register_task(&reg, "rev-2", SessionAgentType::Executor);

        let outcome = compute_aggregate_review_outcome(
            &exe,
            &store,
            Some(AgentTypeFilter {
                plan_registry: &reg,
                initiative_id: "init-agg",
            }),
        )
        .unwrap();
        assert_eq!(outcome.verdict, AggregateReviewVerdict::AllPassed);
        assert_eq!(
            outcome.count, 2,
            "only the two Reviewer successors must be folded; the \
             non-Reviewer row is dropped before the count"
        );
    }

    /// Filter active + missing-entry successor → that successor is
    /// **folded as Reviewer** (fall open per the V2.5 transition
    /// contract; the audit chain is the safety net for registry
    /// bugs). Pin this against an accidental flip to fail-closed
    /// semantics, which would silently break the integration
    /// tests in `handlers::intent` that don't populate the
    /// registry.
    #[test]
    fn agent_type_filter_falls_open_on_missing_registry_entry() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 2);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        set_verdict(&store, "rev-1", ReviewVerdict::Approved);

        let reg = PlanRegistry::new();
        register_task(&reg, "rev-0", SessionAgentType::Reviewer);
        // rev-1 intentionally NOT registered — fall-open MUST keep
        // it in the fold.

        let outcome = compute_aggregate_review_outcome(
            &exe,
            &store,
            Some(AgentTypeFilter {
                plan_registry: &reg,
                initiative_id: "init-agg",
            }),
        )
        .unwrap();
        assert_eq!(outcome.verdict, AggregateReviewVerdict::AllPassed);
        assert_eq!(
            outcome.count, 2,
            "both rows must be folded — registered Reviewer + \
             fall-open missing-entry"
        );
    }

    /// Filter active + a registry entry that is BOTH missing-entry
    /// AND has approved → still folded (fall open). Pairs with
    /// `agent_type_filter_falls_open_on_missing_registry_entry`
    /// to pin that the fall-open path does not require a
    /// peer-registered Reviewer to anchor it.
    #[test]
    fn agent_type_filter_fall_open_alone_can_terminate_aggregator() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 1);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);

        // Empty registry — every successor falls open.
        let reg = PlanRegistry::new();

        let outcome = compute_aggregate_review_outcome(
            &exe,
            &store,
            Some(AgentTypeFilter {
                plan_registry: &reg,
                initiative_id: "init-agg",
            }),
        )
        .unwrap();
        assert_eq!(outcome.verdict, AggregateReviewVerdict::AllPassed);
        assert_eq!(outcome.count, 1);
    }

    /// Filter active + every successor *actively declared* as a
    /// non-Reviewer → `NoSuccessors`. Pins the strict-drop
    /// posture: a structurally malformed plan that explicitly
    /// puts the wrong agent type on every successor does NOT
    /// silently advance the Executor. (Distinct from the
    /// fall-open `missing-entry` arm above — fall-open only
    /// applies when the registry has nothing to say.)
    #[test]
    fn agent_type_filter_no_reviewer_successors_returns_no_successors() {
        let store = Store::open_in_memory().unwrap();
        let exe = seed_executor_with_n_reviewers(&store, 2);
        set_verdict(&store, "rev-0", ReviewVerdict::Approved);
        set_verdict(&store, "rev-1", ReviewVerdict::Approved);

        // Both successors are wrongly declared as Executors.
        let reg = PlanRegistry::new();
        register_task(&reg, "rev-0", SessionAgentType::Executor);
        register_task(&reg, "rev-1", SessionAgentType::Executor);

        let outcome = compute_aggregate_review_outcome(
            &exe,
            &store,
            Some(AgentTypeFilter {
                plan_registry: &reg,
                initiative_id: "init-agg",
            }),
        )
        .unwrap();
        assert_eq!(outcome.verdict, AggregateReviewVerdict::NoSuccessors);
        assert_eq!(outcome.count, 0);
    }
}
