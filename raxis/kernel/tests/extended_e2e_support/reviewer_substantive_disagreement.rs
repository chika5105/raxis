//! Reviewer **substantive** disagreement witness.
//!
//! The extended scenario already exercises the reviewer-
//! disagreement re-review path
//! ([`super::witnesses::ReviewerDisagreementWitness`]), but it
//! does so via DIRECTIVE prompts — reviewer-A is hard-coded to
//! reject "to exercise the disagreement round", reviewer-B is
//! hard-coded to approve. That covers the round-trip mechanics
//! (re-spawn between two `SubmitReview` intents, final
//! `ReviewAggregationCompleted{AllPassed}`) but does NOT prove
//! the reviewer can produce a substantive critique against a
//! real defect.
//!
//! This module closes that hole by pairing the realistic
//! scenario's lint-defect executor task
//! ([`super::plan_realistic::TASK_LINT_DEFECT`]) with two
//! reviewer tasks
//! (`review-lint-defect-A`, `review-lint-defect-B`) configured
//! with plain prompts (no directive). Because the Reviewer VM
//! image (`raxis-reviewer-core`) is barred from executing
//! language linters (no shell, no language runtimes —
//! `INV-PLANNER-HARNESS-02`; `specs/v2/planner-harness.md
//! §4.5`), an in-image Executor task
//! [`super::plan_realistic::TASK_LINT_RUNNER_PYTHON`] sits
//! between the diff-author Executor and the two Reviewers: it
//! runs `python -m ruff check` against `py-pkg/`, commits the
//! captured stdout + stderr + exit-code at
//! `out/lint/check-python.txt`, and that committed artifact is
//! what the Reviewers `read_file` to derive their verdict. The
//! reviewers must detect the executor's deliberately-introduced
//! Python lint defect by reading the captured output, reject
//! with a critique that names the defective file (`greet.py`),
//! and approve on the round following the lint-runner-python
//! Executor's re-spawn (the kernel's
//! `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01` anchor fires
//! against the Reviewer's *immediate* Executor predecessor —
//! `lint-runner-python`, not `lint-defect` — and
//! `lint-runner-python`'s `path_allowlist` covers `py-pkg/` so
//! the Round-2 path can land the corrective edit there).
//!
//! **Iter55 per-language split — `lint-runner-python`, not
//! `lint-runner`.** Pre-iter55 the realistic plan carried a
//! single monolithic `lint-runner` task that ran the full
//! `scripts/check.sh` (Rust + TS + Python) against any defect
//! the executor introduced. Iter54 surfaced the over-broad
//! budget: the repair path deterministically exhausted
//! `max_crash_retries=3` on every review-rejection retry. The
//! structural fix splits the monolithic task into three
//! per-language children — `lint-runner-python`,
//! `lint-runner-rust`, `lint-runner-js` — each scoped to ONE
//! language's lint + source tree. The dual-Reviewer
//! disagreement pair is pinned to `lint-runner-python` (the
//! upstream `lint-defect` prompt is correspondingly pinned to
//! the Python F401 unused-import target), and this witness's
//! `executor_task_id` mirrors that pin. The Rust and JS
//! children carry single rubber-stamp Reviewers that don't
//! drive a disagreement scenario.
//!
//! ## What [`ReviewerSubstantiveDisagreementWitness`] asserts
//!
//! Combined chain-side + SQLite-side predicate:
//!
//! 1. **Chain-side (Option-A wire surface — see
//!    `agent-disagreement.md §3.6`).** The audit chain contains,
//!    in order:
//!    The chain carries
//!    `IntentAccepted{SubmitReview, task=reviewer_a_task_id}`,
//!    then `ExecutorRespawnFromReviewRejection{task_id=
//!    executor_task_id}` — the
//!    `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01` chain anchor
//!    emitted by `handle_retry_sub_task` when the
//!    Orchestrator's `RetrySubTask` is admitted off a Completed
//!    activation whose `review_reject_count > 0`. This event is
//!    strictly stronger than the prior `SessionVmSpawned`
//!    predicate it replaced: a round-1 spawn fires
//!    `SessionVmSpawned` too, so the older witness had to join
//!    `subtask_activations` to count prior rows;
//!    `ExecutorRespawnFromReviewRejection` carries
//!    `(prior_activation_id, new_activation_id,
//!    review_reject_count)` inline, removing the SQLite coupling
//!    (and satisfying `INV-AUDIT-04`). It is followed by
//!    `IntentAccepted{SubmitReview, task=reviewer_b_task_id}`
//!    and finally
//!    `ReviewAggregationCompleted{executor_task_id, verdict=AllPassed}`.
//!
//! 2. **SQLite-side (substantive critique).** The `last_critique`
//!    column on the executor's `tasks` row is non-empty AND
//!    contains at least one of the lint-defect target file
//!    basenames (`greeting.rs`, `greet.ts`, `greet.py`). A
//!    critique that only says "rejected for vibes" or "the diff
//!    looks bad" does NOT satisfy this check; the reviewer must
//!    name the offending file the executor touched.
//!
//! The SQLite read uses `raxis_store::Table::Tasks.as_str()` per
//! `INV-STORE-03` (no raw table-name literals).
//! `tasks.last_critique` is APPEND-only (`COALESCE(last_critique,
//! '') || ?1`) and the approval path does NOT clear it, so the
//! round-1 rejection critique survives until the test reads it
//! after the full scenario completes.
//!
//! ## Why both checks
//!
//! Chain-side alone covers the round-trip mechanics; SQLite-side
//! alone could be satisfied by any non-empty critique containing
//! the right substring (a reviewer that gets the wrong PR and
//! incidentally mentions a matching filename). Together they
//! pin the contract: a substantive critique against the right
//! executor's diff that referenced the right file AND resulted
//! in the right re-spawn AND ultimately produced an AllPassed
//! aggregation.

use std::path::{Path, PathBuf};

use raxis_audit_tools::{AuditEvent, AuditEventKind};
use raxis_store::Table;

use super::witnesses::typed;

// ---------------------------------------------------------------------------
// Pinned task ids.
// ---------------------------------------------------------------------------

/// Lint-defect reviewer A — round-1 reviewer for the lint-defect
/// executor task. Configured with a plain prompt (no directive)
/// in [`super::plan_realistic`].
pub const TASK_REVIEW_LINT_A: &str = "review-lint-defect-A";

/// Lint-defect reviewer B — round-2 reviewer for the lint-defect
/// executor task.
pub const TASK_REVIEW_LINT_B: &str = "review-lint-defect-B";

/// Set of file basenames the witness recognizes as a valid
/// substantive critique target. The reviewer critique MUST
/// mention at least one of these for the substantive check to
/// pass.
///
/// **Iter55 note.** Pre-iter55, all three basenames were live
/// — the lint-defect prompt offered the executor a choice of
/// Rust / TS / Python defects, and any of the three could surface
/// in the captured `out/lint/check-output.txt`. Post-iter55, the
/// lint-defect prompt is PINNED to Python
/// (`py-pkg/src/sample_py/greet.py` ruff F401 unused-import) so
/// the dual-Reviewer disagreement pair on `lint-runner-python`
/// fires deterministically. In practice only `greet.py` will
/// match here; the other two basenames remain in the set as a
/// non-narrow witness — the substantive check is "the critique
/// names ONE of the canonical lint-defect targets", not "the
/// critique names exactly the Python target" — so unit-test
/// fixtures synthesising Rust / TS critique strings (for
/// historical regression of the witness's matching logic
/// itself) still evaluate. A future iter that re-broadens the
/// pin or rotates the pinned target needs only to update the
/// `lint_defect.md` prompt; the witness keeps matching as long
/// as the chosen target's basename is in this set.
pub const LINT_DEFECT_TARGET_BASENAMES: &[&str] = &["greeting.rs", "greet.ts", "greet.py"];

// ---------------------------------------------------------------------------
// ReviewerSubstantiveDisagreementWitness.
// ---------------------------------------------------------------------------

/// Combined chain-side + SQLite-side witness. See module docs.
pub struct ReviewerSubstantiveDisagreementWitness {
    pub executor_task_id: String,
    pub reviewer_a_task_id: String,
    pub reviewer_b_task_id: String,
    /// Path to `kernel.db` for the run under test. The witness
    /// opens a read-only connection at evaluation time.
    pub sqlite_path: PathBuf,
}

/// Report shape returned by `evaluate`. Mirrors
/// `MaterializationReport` so the test driver can pretty-print
/// failures with the same formatter shape.
#[derive(Debug, Default)]
pub struct ReviewerSubstantiveReport {
    pub saw_reviewer_a: bool,
    pub saw_executor_respawn: bool,
    pub saw_reviewer_b: bool,
    pub saw_aggregation_pass: bool,
    /// The actual `last_critique` text read from SQLite (if any).
    pub last_critique: Option<String>,
    /// Subset of [`LINT_DEFECT_TARGET_BASENAMES`] matched in
    /// `last_critique` (empty if none matched).
    pub matched_basenames: Vec<&'static str>,
    /// Surfaced read errors (sqlite, IO) rather than panicking.
    pub error: Option<String>,
}

impl ReviewerSubstantiveReport {
    /// All-greens predicate. The test driver asserts this; the
    /// `Debug` print on failure surfaces every individual field
    /// so an operator can see which piece broke.
    pub fn is_pass(&self) -> bool {
        self.saw_reviewer_a
            && self.saw_executor_respawn
            && self.saw_reviewer_b
            && self.saw_aggregation_pass
            && !self.matched_basenames.is_empty()
            && self.error.is_none()
    }
}

impl ReviewerSubstantiveDisagreementWitness {
    /// The Reviewer's immediate Executor predecessor is
    /// `lint-runner-python` (the iter55 per-language in-image
    /// execution stage for `python -m ruff check`; see
    /// [`super::plan_realistic::TASK_LINT_RUNNER_PYTHON`] and
    /// the module docs above for the `INV-PLANNER-HARNESS-02`
    /// rationale + iter55 split context). The kernel's
    /// `ExecutorRespawnFromReviewRejection` anchor and
    /// `ReviewAggregationCompleted` aggregator both key on the
    /// Reviewer's immediate predecessor, so the witness's
    /// `executor_task_id` mirrors that: a substantive critique
    /// against `lint-runner-python`'s commit (which surfaces
    /// the upstream `lint-defect` Python F401 defect via the
    /// captured `out/lint/check-python.txt`) drives the chain
    /// shape this witness asserts.
    #[must_use]
    pub fn for_realistic_plan(sqlite_path: &Path) -> Self {
        Self {
            executor_task_id: super::plan_realistic::TASK_LINT_RUNNER_PYTHON.to_owned(),
            reviewer_a_task_id: TASK_REVIEW_LINT_A.to_owned(),
            reviewer_b_task_id: TASK_REVIEW_LINT_B.to_owned(),
            sqlite_path: sqlite_path.to_path_buf(),
        }
    }

    /// Run all checks; return a populated report.
    pub fn evaluate(&self, chain: &[AuditEvent]) -> ReviewerSubstantiveReport {
        let mut report = ReviewerSubstantiveReport::default();
        self.evaluate_chain(chain, &mut report);
        self.evaluate_sqlite(&mut report);
        report
    }

    fn evaluate_chain(&self, chain: &[AuditEvent], report: &mut ReviewerSubstantiveReport) {
        for ev in chain {
            match typed(ev) {
                Some(AuditEventKind::IntentAccepted {
                    task_id,
                    intent_kind,
                    ..
                }) if intent_kind == "SubmitReview" => {
                    if task_id == self.reviewer_a_task_id {
                        report.saw_reviewer_a = true;
                    } else if task_id == self.reviewer_b_task_id && report.saw_reviewer_a {
                        report.saw_reviewer_b = true;
                    }
                }
                // `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`
                // chain anchor. The event is emitted by
                // `handle_retry_sub_task` precisely when the
                // Orchestrator's `RetrySubTask` is admitted off a
                // Completed activation with `review_reject_count
                // > 0` — i.e. exactly the
                // "respawn-after-review-rejection" condition this
                // witness wants to assert. Round-1 spawn fires
                // `SessionVmSpawned` but NOT this event, so the
                // first-spawn / retry-spawn ambiguity that
                // forced the prior witness to count activation
                // rows is gone. The `saw_reviewer_a` guard
                // remains for ordering — `RetrySubTask` MUST
                // follow at least one Reviewer rejection.
                Some(AuditEventKind::ExecutorRespawnFromReviewRejection { task_id, .. })
                    if task_id == self.executor_task_id && report.saw_reviewer_a =>
                {
                    report.saw_executor_respawn = true;
                }
                Some(AuditEventKind::ReviewAggregationCompleted {
                    executor_task_id,
                    verdict,
                    ..
                }) if executor_task_id == self.executor_task_id && verdict == "AllPassed" => {
                    report.saw_aggregation_pass = true;
                }
                _ => {}
            }
        }
    }

    fn evaluate_sqlite(&self, report: &mut ReviewerSubstantiveReport) {
        match rusqlite::Connection::open_with_flags(
            &self.sqlite_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        ) {
            Ok(conn) => {
                let tasks = Table::Tasks.as_str();
                let sql = format!("SELECT last_critique FROM {tasks} WHERE task_id = ?1",);
                let critique = conn
                    .query_row(&sql, rusqlite::params![&self.executor_task_id], |row| {
                        row.get::<_, Option<String>>(0)
                    })
                    .unwrap_or(None);
                if let Some(text) = &critique {
                    for name in LINT_DEFECT_TARGET_BASENAMES {
                        if text.contains(name) {
                            report.matched_basenames.push(name);
                        }
                    }
                }
                report.last_critique = critique;
            }
            Err(e) => {
                report.error = Some(format!(
                    "open kernel.db at {} failed: {e}",
                    self.sqlite_path.display(),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests — drive the chain-side predicate and the SQLite read
// against hand-built fixtures so the predicate stays calibrated.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use raxis_audit_tools::AuditEvent;
    use uuid::Uuid;

    fn ev(seq: u64, kind: AuditEventKind, task_id: Option<&str>) -> AuditEvent {
        let event_kind = match &kind {
            AuditEventKind::IntentAccepted { .. } => "IntentAccepted",
            AuditEventKind::SessionVmSpawned { .. } => "SessionVmSpawned",
            AuditEventKind::ExecutorRespawnFromReviewRejection { .. } => {
                "ExecutorRespawnFromReviewRejection"
            }
            AuditEventKind::ReviewAggregationCompleted { .. } => "ReviewAggregationCompleted",
            _ => "Other",
        }
        .to_owned();
        AuditEvent {
            seq,
            event_id: Uuid::nil(),
            event_kind,
            session_id: None,
            task_id: task_id.map(str::to_owned),
            initiative_id: None,
            payload: serde_json::to_value(&kind).unwrap(),
            emitted_at: 1700000000 + seq as i64,
            prev_sha256: "0".repeat(64),
        }
    }

    fn submit_review_intent(seq: u64, task_id: &str) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::IntentAccepted {
                task_id: task_id.to_owned(),
                session_id: format!("sess-{task_id}"),
                intent_kind: "SubmitReview".to_owned(),
                base_sha: None,
                head_sha: None,
                sequence_number: 1,
                remaining_units: 99,
            },
            Some(task_id),
        )
    }

    fn vm_spawn(seq: u64, task_id: &str) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::SessionVmSpawned {
                session_id: format!("sess-{task_id}-respawn"),
                task_id: Some(task_id.to_owned()),
                initiative_id: "init-realistic".to_owned(),
                backend_id: "test-backend".to_owned(),
                egress_tier: "Mediated".to_owned(),
                admission_loopback: "127.0.0.1:0".to_owned(),
                credential_proxies: 0,
            },
            Some(task_id),
        )
    }

    /// Fixture builder for the `ExecutorRespawnFromReviewRejection`
    /// audit event the witness now matches on per
    /// `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`. Synthesises
    /// stable activation-id strings derived from `task_id` and the
    /// chain seq so the witness's "second match" path (round-3 retry
    /// on a still-disagreed task) sees distinct ids.
    fn respawn_review(seq: u64, task_id: &str, review_reject_count: u32) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::ExecutorRespawnFromReviewRejection {
                task_id: task_id.to_owned(),
                prior_activation_id: format!("prior-{task_id}-{seq}"),
                new_activation_id: format!("new-{task_id}-{seq}"),
                review_reject_count,
            },
            Some(task_id),
        )
    }

    fn aggregation_pass(seq: u64, executor_task_id: &str) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::ReviewAggregationCompleted {
                executor_task_id: executor_task_id.to_owned(),
                triggered_by_reviewer_task_id: TASK_REVIEW_LINT_B.to_owned(),
                reviewer_count: 2,
                verdict: "AllPassed".to_owned(),
            },
            Some(executor_task_id),
        )
    }

    fn seed_tasks_db(tmpdir: &Path, executor_task: &str, critique: Option<&str>) -> PathBuf {
        let db_path = tmpdir.join("kernel.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let tasks = Table::Tasks.as_str();
        conn.execute_batch(&format!(
            "CREATE TABLE {tasks} (\
                task_id TEXT PRIMARY KEY,\
                last_critique TEXT\
            );",
        ))
        .unwrap();
        conn.execute(
            &format!("INSERT INTO {tasks} (task_id, last_critique) VALUES (?1, ?2)",),
            rusqlite::params![executor_task, critique],
        )
        .unwrap();
        db_path
    }

    fn witness(sqlite_path: &Path) -> ReviewerSubstantiveDisagreementWitness {
        ReviewerSubstantiveDisagreementWitness {
            executor_task_id: "lint-defect".to_owned(),
            reviewer_a_task_id: TASK_REVIEW_LINT_A.to_owned(),
            reviewer_b_task_id: TASK_REVIEW_LINT_B.to_owned(),
            sqlite_path: sqlite_path.to_path_buf(),
        }
    }

    fn clean_chain() -> Vec<AuditEvent> {
        vec![
            submit_review_intent(0, TASK_REVIEW_LINT_A),
            respawn_review(1, "lint-defect", 1),
            submit_review_intent(2, TASK_REVIEW_LINT_B),
            aggregation_pass(3, "lint-defect"),
        ]
    }

    #[test]
    fn clean_chain_with_substantive_critique_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seed_tasks_db(
            tmp.path(),
            "lint-defect",
            Some("rejected: greeting.rs introduces clippy::useless_conversion"),
        );
        let w = witness(&db);
        let report = w.evaluate(&clean_chain());
        assert!(report.is_pass(), "expected pass; got {report:#?}");
        assert!(report.matched_basenames.contains(&"greeting.rs"));
    }

    #[test]
    fn empty_critique_fails_substantive_check() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seed_tasks_db(tmp.path(), "lint-defect", None);
        let w = witness(&db);
        let report = w.evaluate(&clean_chain());
        assert!(!report.is_pass());
        assert!(report.matched_basenames.is_empty());
        assert!(report.last_critique.is_none());
    }

    #[test]
    fn vibes_only_critique_fails_substantive_check() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seed_tasks_db(
            tmp.path(),
            "lint-defect",
            Some("rejected: the diff just looks bad"),
        );
        let w = witness(&db);
        let report = w.evaluate(&clean_chain());
        assert!(!report.is_pass());
        assert!(report.matched_basenames.is_empty());
    }

    #[test]
    fn missing_respawn_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seed_tasks_db(
            tmp.path(),
            "lint-defect",
            Some("rejected: greet.ts has a prefer-const violation"),
        );
        let w = witness(&db);
        let chain = vec![
            submit_review_intent(0, TASK_REVIEW_LINT_A),
            // No `ExecutorRespawnFromReviewRejection` — reviewer-B
            // fires immediately. A round-1 `SessionVmSpawned`
            // (if present) does NOT satisfy the witness anymore;
            // only the `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`
            // anchor counts.
            vm_spawn(1, "lint-defect"),
            submit_review_intent(2, TASK_REVIEW_LINT_B),
            aggregation_pass(3, "lint-defect"),
        ];
        let report = w.evaluate(&chain);
        assert!(!report.is_pass());
        assert!(report.saw_reviewer_a);
        assert!(
            !report.saw_executor_respawn,
            "round-1 SessionVmSpawned alone must NOT satisfy \
             saw_executor_respawn — only \
             ExecutorRespawnFromReviewRejection does (INV-AUDIT-04 + \
             INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01)"
        );
        assert!(report.matched_basenames.contains(&"greet.ts"));
    }

    /// Regression guard: a round-1 `SessionVmSpawned` AND the
    /// round-2 `ExecutorRespawnFromReviewRejection` must coexist
    /// cleanly. The witness must lock onto the latter and ignore
    /// the former.
    #[test]
    fn round_1_session_vm_spawn_does_not_mask_round_2_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seed_tasks_db(
            tmp.path(),
            "lint-defect",
            Some("rejected: greet.py adds an unused import"),
        );
        let w = witness(&db);
        let chain = vec![
            // Round-1: initial executor spawn fires SessionVmSpawned
            // (does NOT satisfy the witness on its own).
            vm_spawn(0, "lint-defect"),
            // Round-1 review cycle.
            submit_review_intent(1, TASK_REVIEW_LINT_A),
            // Round-2 retry: the canonical chain anchor.
            respawn_review(2, "lint-defect", 1),
            // Round-2 review cycle.
            submit_review_intent(3, TASK_REVIEW_LINT_B),
            aggregation_pass(4, "lint-defect"),
        ];
        let report = w.evaluate(&chain);
        assert!(
            report.is_pass(),
            "round-1 spawn + round-2 retry-anchor chain must pass: {report:#?}"
        );
        assert!(
            report.saw_executor_respawn,
            "ExecutorRespawnFromReviewRejection at seq=2 must drive \
             saw_executor_respawn regardless of the earlier round-1 \
             SessionVmSpawned at seq=0"
        );
    }

    #[test]
    fn missing_aggregation_pass_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seed_tasks_db(
            tmp.path(),
            "lint-defect",
            Some("rejected: greet.py adds an unused import"),
        );
        let w = witness(&db);
        let chain = vec![
            submit_review_intent(0, TASK_REVIEW_LINT_A),
            vm_spawn(1, "lint-defect"),
            submit_review_intent(2, TASK_REVIEW_LINT_B),
            // No aggregation pass.
        ];
        let report = w.evaluate(&chain);
        assert!(!report.is_pass());
        assert!(!report.saw_aggregation_pass);
    }

    #[test]
    fn missing_db_surfaces_error() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("does-not-exist.db");
        let w = witness(&db_path);
        let report = w.evaluate(&clean_chain());
        assert!(!report.is_pass());
        assert!(
            report.error.is_some(),
            "missing db must surface as error: {report:#?}"
        );
    }
}
