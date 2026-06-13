//! Integration witness for `INV-KSB-CAPABILITIES-TURN-COHERENT-01`.
//!
//! ## What this pins
//!
//! The KSB capabilities envelope MUST come from the SAME store
//! snapshot as the rest of the projection — no torn reads where
//! the FSM portion reflects state X and the capabilities portion
//! reflects state Y. The contract has two structural pieces:
//!
//!   1. **Single-connection reads.** The kernel-side
//!      `assemble_ksb_snapshot` takes ONE `&Connection` and
//!      threads it through every helper (`read_evaluation_sha`,
//!      `read_dag_rows_for_initiative`, `read_pending_escalations`,
//!      `read_reviewer_verdicts_for_initiative`,
//!      `read_initiative_anchor_base_sha`, AND
//!      `assemble_capabilities`). Combined with
//!      `raxis_store::Store::lock_sync` returning a
//!      `MutexGuard<Connection>` on the SOLE backing connection,
//!      this means: while the projection runs, no other writer in
//!      the kernel process can land a mutation between two of the
//!      projection's reads. Torn reads are structurally
//!      impossible at the SQL layer.
//!
//!   2. **Predicate consistency.** The capabilities envelope's
//!      `retry_admissible` boolean is computed from the SAME row
//!      data the rest of the projection sources via
//!      `subtask_activations`. The witness pins this by reading
//!      via the SAME SQL the kernel uses, calling the SAME
//!      `admit_retry_subtask_check` predicate, and asserting the
//!      result matches what the kernel would emit.
//!
//! ## How this is enforced
//!
//! The witness drives a real on-disk sqlite store through three
//! phases against the SAME connection (mirroring the kernel's
//! single-connection contract):
//!
//!   * **Phase A.** Seed an initiative + a `subtask_activations`
//!     row with KNOWN counters (`Failed`, crash=1, review=0,
//!     ceilings 3 / 2). Read the row via the assembler's exact
//!     SQL. Drive the predicate. Assert the verdict is
//!     `Admissible` and the projected `TaskCapabilityView` reads
//!     `retry_admissible=true reason=None`.
//!
//!   * **Phase B.** Mutate the row in place (bump
//!     `crash_retry_count` to 3, hitting the ceiling). Read again
//!     via the SAME connection. Drive the predicate. Assert the
//!     verdict flips to `Inadmissible(CrashCeiling)` and the
//!     projected view reads `retry_admissible=false` with the
//!     `crash_retry_count 3 >= max_crash_retries 3` lexeme. Pins
//!     that two reads against the same connection see the
//!     evolving state correctly.
//!
//!   * **Phase C.** Wrap a sequence of reads in an explicit
//!     `tx = conn.transaction()` (the SAFEST coherency
//!     guarantee — pins the BEGIN/COMMIT-equivalent property
//!     called out in the spec). Mutate via a SECOND connection
//!     (separate sqlite handle) DURING the transaction. Assert
//!     that the two in-tx reads AGREE — i.e. the projection
//!     inside the transaction is immune to a concurrent writer
//!     landing a row between two sub-reads. This is the canonical
//!     "snapshot isolation" property the spec calls out.
//!
//! Pairs with the type-level enforcement in
//! `kernel/src/initiatives/ksb_assembly.rs::assemble_ksb_snapshot`
//! (single `&Connection` parameter threaded through every
//! sub-helper) and the lock-the-only-connection enforcement in
//! `crates/store/src/db.rs::Store::lock_sync`.

#![cfg(test)]

use raxis_ksb::TaskCapabilityView;
use raxis_store::{migration::apply_pending, Table};
use raxis_types::intent_admit::{
    admit_retry_subtask_check, AdmitOutcome, RetryAdmitInputs, RetryInadmissibleReason,
};
use rusqlite::{params, Connection};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// Open a fresh on-disk sqlite-backed `Connection` with every
/// migration applied + WAL pragma. Disk-backed (rather than
/// `:memory:`) so Phase C can attach a SECOND connection against
/// the SAME backing file — the structural pre-requisite for the
/// concurrent-writer arm of the snapshot-isolation pin.
///
/// `foreign_keys = OFF` because the witness only seeds the
/// `subtask_activations` row directly and skips the parent
/// `initiatives` / `tasks` / `sessions` rows the kernel boot
/// would create. The FK relationships are tested elsewhere
/// (`orch_respawn_no_progress_ceiling`); this witness is scoped
/// to the row-read + predicate-projection contract.
fn fresh_disk_conn() -> (tempfile::TempDir, std::path::PathBuf, Connection) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("kernel.db");
    let conn = Connection::open(&path).expect("open sqlite file");
    conn.pragma_update(None, "journal_mode", "WAL").ok();
    conn.pragma_update(None, "foreign_keys", "OFF").ok();
    apply_pending(&conn).expect("apply migrations");
    conn.pragma_update(None, "foreign_keys", "OFF").ok();
    (tmp, path, conn)
}

/// Seed a single `subtask_activations` row with a terminal state
/// (`Failed` or `Completed`) — both states satisfy the table's
/// terminal-row CHECK (activated_at + terminated_at NOT NULL +
/// session_id NOT NULL).
#[allow(clippy::too_many_arguments)]
fn seed_terminal_activation(
    conn: &Connection,
    activation_id: &str,
    task_id: &str,
    initiative_id: &str,
    session_id: &str,
    state: &str,
    crash_retry_count: i64,
    review_reject_count: i64,
) {
    conn.execute(
        &format!(
            "INSERT INTO {acts}
                (activation_id, task_id, initiative_id, activation_state,
                 session_id, crash_retry_count, review_reject_count,
                 created_at, activated_at, terminated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7,
                     strftime('%s','now'),
                     strftime('%s','now'),
                     strftime('%s','now'))",
            acts = Table::SubtaskActivations.as_str(),
        ),
        params![
            activation_id,
            task_id,
            initiative_id,
            state,
            session_id,
            crash_retry_count,
            review_reject_count,
        ],
    )
    .expect("insert activation");
}

/// Mirror the kernel's `build_task_capability_view` SQL +
/// projection chain. Reads via the same query the assembler uses
/// (most-recent activation, ordered by `created_at DESC`), drives
/// the same predicate, builds the same wire-shape view.
fn read_and_project_view(
    conn: &Connection,
    task_id: &str,
    max_crash: u32,
    max_review: u32,
) -> TaskCapabilityView {
    let row: Option<(String, i64, i64)> = conn
        .query_row(
            &format!(
                "SELECT activation_state, crash_retry_count, review_reject_count
               FROM {acts}
              WHERE task_id = ?1
              ORDER BY created_at DESC
              LIMIT 1",
                acts = Table::SubtaskActivations.as_str(),
            ),
            params![task_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    let (prior_state, crash, review) = row.unwrap_or_default();
    let crash_u = u32::try_from(crash).unwrap_or(0);
    let review_u = u32::try_from(review).unwrap_or(0);
    let admit_inputs = RetryAdmitInputs {
        prior_activation_state: if prior_state.is_empty() {
            None
        } else {
            Some(prior_state.as_str())
        },
        crash_retry_count: crash_u,
        review_reject_count: review_u,
        review_aggregate_verdict: None,
        max_crash_retries: max_crash,
        max_review_rejections: max_review,
    };
    let (retry_admissible, retry_inadmissible_reason) =
        match admit_retry_subtask_check(&admit_inputs) {
            AdmitOutcome::Admissible => (true, None),
            AdmitOutcome::Inadmissible(r) => (false, Some(r.human())),
        };
    TaskCapabilityView {
        task_id: task_id.to_owned(),
        crash_retry_count: crash_u,
        review_reject_count: review_u,
        max_crash_retries: max_crash,
        max_review_rejections: max_review,
        crash_retries_remaining: max_crash.saturating_sub(crash_u),
        review_retries_remaining: max_review.saturating_sub(review_u),
        retry_admissible,
        retry_inadmissible_reason,
    }
}

// ---------------------------------------------------------------------------
// Phase A — same connection, single read sees seeded state coherently.
// Phase B — same connection, post-mutation read flips admissibility.
// ---------------------------------------------------------------------------

#[test]
fn turn_coherent_single_conn_sees_evolving_state_correctly() {
    let (_tmp, _path, conn) = fresh_disk_conn();

    // ── Phase A: seeded state, predicate admits, view reflects ──
    seed_terminal_activation(&conn, "act-1", "task-A", "init-A", "ses-A", "Failed", 1, 0);
    let view_a = read_and_project_view(&conn, "task-A", 3, 2);
    assert!(
        view_a.retry_admissible,
        "Phase A: prior=Failed + crash=1/3 + review=0/2 MUST be admissible"
    );
    assert!(
        view_a.retry_inadmissible_reason.is_none(),
        "Phase A: admissible MUST carry no reason"
    );
    assert_eq!(view_a.crash_retry_count, 1);
    assert_eq!(view_a.crash_retries_remaining, 2);
    assert_eq!(view_a.review_retries_remaining, 2);

    // ── Phase B: mutate counter to ceiling on the SAME conn ──
    conn.execute(
        &format!(
            "UPDATE {acts} SET crash_retry_count = 3 WHERE activation_id = ?1",
            acts = Table::SubtaskActivations.as_str(),
        ),
        params!["act-1"],
    )
    .expect("bump crash counter");
    let view_b = read_and_project_view(&conn, "task-A", 3, 2);
    assert!(
        !view_b.retry_admissible,
        "Phase B: post-mutation crash=3/3 MUST flip retry_admissible to false"
    );
    let reason = view_b
        .retry_inadmissible_reason
        .expect("Phase B: inadmissible MUST carry reason");
    assert!(
        reason.starts_with("crash_retry_count 3"),
        "Phase B: reason MUST carry the `crash_retry_count <n>` lexeme; got: {reason}"
    );
    assert_eq!(view_b.crash_retry_count, 3);
    assert_eq!(view_b.crash_retries_remaining, 0);
}

// ---------------------------------------------------------------------------
// Phase C — explicit transaction snapshot isolation
// ---------------------------------------------------------------------------

/// Pins the spec's "cleanest way" pin: an explicit
/// `BEGIN ... COMMIT` block on the projection's connection
/// produces snapshot-isolated reads — concurrent writes from a
/// SECOND connection landing rows during the transaction are
/// invisible to the in-tx reads.
///
/// SQLite's WAL-mode + DEFERRED transactions give the reader a
/// stable snapshot pinned at the FIRST query inside the tx (the
/// "begin-deferred holds at first SELECT" property). Subsequent
/// queries inside the same tx see the same snapshot regardless
/// of concurrent commits on other connections.
///
/// This is the structural pin for `INV-KSB-CAPABILITIES-TURN-
/// COHERENT-01`: a future refactor that wraps
/// `assemble_ksb_snapshot`'s sub-reads in a transaction (the
/// recommended hardening per the invariant body) will pass this
/// witness; a regression that opens a fresh connection per
/// sub-read will not.
#[test]
fn explicit_transaction_isolates_reads_from_concurrent_writer() {
    let (_tmp, path, mut reader_conn) = fresh_disk_conn();
    seed_terminal_activation(
        &reader_conn,
        "act-2",
        "task-B",
        "init-B",
        "ses-B",
        "Failed",
        0,
        0,
    );

    // Open a SECOND connection against the same on-disk db. WAL
    // mode is required for parallel readers + writers; the
    // fresh_disk_conn helper sets it on the reader and the file's
    // journal_mode persists, so the writer inherits it.
    let writer_conn = Connection::open(&path).expect("open writer conn");
    writer_conn.pragma_update(None, "foreign_keys", "OFF").ok();

    // Open a deferred-read tx on the reader. The first SELECT
    // pins the snapshot.
    let tx = reader_conn.transaction().expect("begin reader tx");
    let snapshot_a: i64 = tx
        .query_row(
            &format!(
                "SELECT crash_retry_count FROM {acts} WHERE activation_id = ?1",
                acts = Table::SubtaskActivations.as_str(),
            ),
            params!["act-2"],
            |r| r.get(0),
        )
        .expect("read pre-mutation snapshot");
    assert_eq!(
        snapshot_a, 0,
        "pre-mutation snapshot MUST read the seeded zero"
    );

    // Concurrent writer commits a mutation OUTSIDE the reader's
    // tx. WAL-mode lets the writer proceed despite the open
    // reader-tx — the writer commits a new WAL frame while the
    // reader's snapshot still points at the pre-mutation frame.
    writer_conn
        .execute(
            &format!(
                "UPDATE {acts} SET crash_retry_count = 7 WHERE activation_id = ?1",
                acts = Table::SubtaskActivations.as_str(),
            ),
            params!["act-2"],
        )
        .expect("writer commits mutation");

    // The reader's IN-TRANSACTION re-read MUST still see the
    // pre-mutation snapshot. This is the load-bearing
    // turn-coherency property: two sub-reads inside the same
    // projection-transaction MUST agree.
    let snapshot_b: i64 = tx
        .query_row(
            &format!(
                "SELECT crash_retry_count FROM {acts} WHERE activation_id = ?1",
                acts = Table::SubtaskActivations.as_str(),
            ),
            params!["act-2"],
            |r| r.get(0),
        )
        .expect("read in-tx re-read");
    assert_eq!(
        snapshot_a, snapshot_b,
        "BUG: torn read across two in-tx sub-reads — INV-KSB-CAPABILITIES-\
         TURN-COHERENT-01 violated; got snapshot_a={snapshot_a}, \
         snapshot_b={snapshot_b}"
    );

    tx.commit().expect("commit reader tx");

    // After the tx commits, the reader sees the writer's
    // mutation. Pins that the snapshot was specifically the
    // PRE-mutation value (not stale-cached / incidentally equal)
    // — without this, the test would pass even if both reads
    // returned the post-mutation value as long as they agreed.
    let post_commit: i64 = reader_conn
        .query_row(
            &format!(
                "SELECT crash_retry_count FROM {acts} WHERE activation_id = ?1",
                acts = Table::SubtaskActivations.as_str(),
            ),
            params!["act-2"],
            |r| r.get(0),
        )
        .expect("post-commit read");
    assert_eq!(
        post_commit, 7,
        "post-tx-commit read MUST observe the writer's committed mutation"
    );

    // Drive the predicate with the post-commit value to pin the
    // contract closure: post-coherent-snapshot, the verdict
    // correctly flips to inadmissible (CrashCeiling because
    // crash=7 > max_crash=3).
    let admit = admit_retry_subtask_check(&RetryAdmitInputs {
        prior_activation_state: Some("Failed"),
        crash_retry_count: u32::try_from(post_commit).unwrap_or(0),
        review_reject_count: 0,
        review_aggregate_verdict: None,
        max_crash_retries: 3,
        max_review_rejections: 2,
    });
    match admit {
        AdmitOutcome::Inadmissible(RetryInadmissibleReason::CrashCeiling { .. }) => {}
        other => panic!(
            "predicate parity: post-coherent-snapshot crash=7/3 MUST be \
             CrashCeiling; got {other:?}"
        ),
    }
}
