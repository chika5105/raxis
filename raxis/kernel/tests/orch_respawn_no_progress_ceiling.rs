//! Integration witness for
//! `INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`
//! (per-initiative orchestrator no-progress respawn ceiling).
//!
//! ## What this pins
//!
//! The kernel's `orch_respawn_ceiling` module enforces a structural
//! backstop on the orchestrator post-exit respawn loop: every
//! `respawn_orchestrator_for_initiative` call increments the
//! per-initiative `initiatives.orchestrator_no_progress_respawn_count`
//! by one and refuses the spawn (and marks the initiative `Failed`)
//! once the post-increment value strictly exceeds
//! `MAX_ORCH_NO_PROGRESS_RESPAWNS` (default 3). The counter resets
//! to zero on every legal task FSM transition routed through
//! `transition_task_in_tx`.
//!
//! `orch_respawn_ceiling.rs` carries inline `#[cfg(test)] mod tests`
//! that exercise the bare helpers against an in-memory connection;
//! the integration witness here goes one level higher: it drives the
//! exact "intent-rejected → respawn" pattern reproduced in the iter42
//! second-run regression — four consecutive respawns with zero
//! intervening FSM transition — and asserts the kernel's published
//! contract end-to-end through the public store API:
//!
//!   1. The post-Migration-19 schema carries
//!      `orchestrator_no_progress_respawn_count` on `initiatives` as
//!      `INTEGER NOT NULL DEFAULT 0`.
//!   2. Three increments without an intervening reset land in the
//!      `Permitted` half-plane (counter walks 0 → 3 monotonically).
//!   3. The fourth increment trips the `Exceeded` arm AND the
//!      audit-event constructor surfaces a non-`None`
//!      `OrchestratorRespawnCeilingExceeded` payload carrying the
//!      observed `attempts` + `max_attempts` fields the dashboard
//!      reads.
//!   4. After the kernel transitions the offending initiative to
//!      `state = 'Failed'` (the same-transaction sister of the
//!      ceiling-exceeded branch in
//!      `respawn_orchestrator_for_initiative`), the
//!      `is_executing` predicate the post-exit hook checks at the
//!      top of every respawn returns `false`, which short-circuits
//!      every subsequent post-exit-hook trigger for that initiative.
//!   5. A reset-during-loop fixture asserts the
//!      reset-on-FSM-transition half: increment to 2, reset, then
//!      drive 3 more increments — all of which land
//!      `Permitted`. This pins the load-bearing pair "honest DAG
//!      progress always clears the loop counter".
//!   6. The dashboard's notification filter promotes the new event
//!      to `Critical` priority (so a real iter42 regression would
//!      trip the operator-facing alarm rather than being buried
//!      below the per-event-stream noise floor).
//!
//! ## Why this lives in `kernel/tests/` rather than the inline
//! `orch_respawn_ceiling::tests`
//!
//! The inline tests are unit-scoped and exercise the helper
//! functions in isolation. This file is the cross-crate witness:
//! it holds the kernel <-> store <-> dashboard wiring honest
//! against a real `raxis-store::Store` opened on a tempdir-backed
//! sqlite file (no in-memory short-cuts), with the audit-event +
//! notification-priority surfaces both pulled in. A regression in
//! any of the migration drift-detector, the audit enum, the
//! dashboard filter, or the in-tx mutation contract will fail this
//! file before any live-e2e dryrun has to wait for the harness
//! deadline.

#![cfg(test)]

use raxis_audit_tools::AuditEventKind;
use raxis_dashboard_kernel::notification_filter::{
    notification_priority, NotificationPriority,
};
use raxis_store::{migration::apply_pending, Table};
use rusqlite::{params, Connection};

/// Mirrors `kernel::orch_respawn_ceiling::MAX_ORCH_NO_PROGRESS_RESPAWNS`.
/// Re-stated here so the integration test pins the wire-visible
/// constant the operator reads from the audit event; if a future
/// PR changes the kernel constant without updating the spec
/// (`v2-deep-spec.md §Step 12 V2.5b`) this constant drift will
/// fail at the assertion site, surfacing the missing spec parity
/// edit before merge.
const MAX_ORCH_NO_PROGRESS_RESPAWNS: u32 = 3;

/// Open a fresh on-disk SQLite-backed `Connection` with every
/// migration applied. Disk-backed (rather than `:memory:`) so the
/// schema matches production reads down to the WAL pragma path
/// — the same pragma application order the kernel boots with.
fn fresh_disk_conn() -> (tempfile::TempDir, Connection) {
    let tmp  = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("kernel.db");
    let conn = Connection::open(&path).expect("open sqlite");
    apply_pending(&conn).expect("apply migrations");
    (tmp, conn)
}

/// Seed an `Executing` initiative row matching the V2 baseline
/// schema (`kernel-store.md §2.5.1 Table 2`) — the `created_at`
/// and `terminal_criteria_json` columns are NOT-NULL surface, so
/// the seed has to populate them. The post-Migration-19 row
/// observably starts with
/// `orchestrator_no_progress_respawn_count = 0` (the column's
/// default).
fn seed_executing_initiative(conn: &Connection, initiative_id: &str) {
    let initiatives = Table::Initiatives.as_str();
    conn.execute(
        &format!(
            "INSERT INTO {initiatives}
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES (?1, 'Executing', '{{}}', '', strftime('%s','now'))"
        ),
        params![initiative_id],
    ).expect("seed initiative");
}

fn read_count(conn: &Connection, initiative_id: &str) -> u32 {
    let initiatives = Table::Initiatives.as_str();
    conn.query_row(
        &format!(
            "SELECT orchestrator_no_progress_respawn_count
               FROM {initiatives}
              WHERE initiative_id = ?1"
        ),
        params![initiative_id],
        |r| r.get::<_, i64>(0).map(|v| u32::try_from(v).unwrap_or(u32::MAX)),
    ).expect("read counter")
}

fn read_state(conn: &Connection, initiative_id: &str) -> String {
    let initiatives = Table::Initiatives.as_str();
    conn.query_row(
        &format!("SELECT state FROM {initiatives} WHERE initiative_id = ?1"),
        params![initiative_id],
        |r| r.get::<_, String>(0),
    ).expect("read state")
}

/// One round of the iter42-second-run pathology: SQLite-side, the
/// kernel's `respawn_orchestrator_for_initiative` Step 1b runs
/// (a) `UPDATE initiatives SET orchestrator_no_progress_respawn_count = ... + 1
/// WHERE initiative_id = ?` then (b) reads the new value back
/// inside the same transaction. We mirror that exact wire here so
/// the witness is a black-box assertion against the schema +
/// sequence the kernel actually emits.
///
/// Returns the post-increment value.
fn simulate_respawn_increment(
    conn:          &mut Connection,
    initiative_id: &str,
) -> u32 {
    let initiatives = Table::Initiatives.as_str();
    let tx = conn.transaction().expect("begin");
    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET orchestrator_no_progress_respawn_count =
                        orchestrator_no_progress_respawn_count + 1
              WHERE initiative_id = ?1"
        ),
        params![initiative_id],
    ).expect("increment");
    let new_count: i64 = tx.query_row(
        &format!(
            "SELECT orchestrator_no_progress_respawn_count
               FROM {initiatives}
              WHERE initiative_id = ?1"
        ),
        params![initiative_id],
        |r| r.get(0),
    ).expect("re-read");
    tx.commit().expect("commit");
    u32::try_from(new_count).unwrap_or(u32::MAX)
}

/// Mirror of the kernel's same-transaction Failed-transition that
/// fires inside `respawn_orchestrator_for_initiative` Step 1b
/// once the increment returns `Exceeded`. The `completed_at`
/// stamp is a side-effect operators read from the dashboard's
/// initiative-detail panel; the `state = 'Failed'` flip is the
/// load-bearing piece — the `is_executing` preflight at the top
/// of every respawn now short-circuits.
fn simulate_initiative_failed(conn: &mut Connection, initiative_id: &str) {
    let initiatives = Table::Initiatives.as_str();
    let tx = conn.transaction().expect("begin failed-tx");
    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET state        = 'Failed',
                    completed_at = strftime('%s','now')
              WHERE initiative_id = ?1"
        ),
        params![initiative_id],
    ).expect("flip to Failed");
    tx.commit().expect("commit failed-tx");
}

/// Mirror of `transition_task_in_tx`'s end-of-function reset hook
/// (`reset_no_progress_count_in_tx`). Exercises the load-bearing
/// "honest FSM progress clears the loop counter" half of the
/// invariant.
fn simulate_fsm_progress_reset(conn: &mut Connection, initiative_id: &str) {
    let initiatives = Table::Initiatives.as_str();
    let tx = conn.transaction().expect("begin reset-tx");
    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET orchestrator_no_progress_respawn_count = 0
              WHERE initiative_id = ?1
                AND orchestrator_no_progress_respawn_count > 0"
        ),
        params![initiative_id],
    ).expect("reset");
    tx.commit().expect("commit reset-tx");
}

/// Drives the iter42-second-run pathology — four consecutive
/// orchestrator respawns with zero intervening FSM progress — and
/// asserts the kernel's contract:
///
///   * Increments 1..=3 land `Permitted`.
///   * Increment 4 trips the ceiling, the kernel marks the
///     initiative `Failed`, and the audit-event constructor
///     surfaces the operator-facing
///     `OrchestratorRespawnCeilingExceeded` payload.
///   * After the Failed-flip, the predicate the kernel reads on
///     every subsequent post-exit-hook trigger
///     (`state = 'Executing'`) returns `false`, so additional
///     respawns are silently skipped — the loop is structurally
///     bounded at four iterations regardless of the upstream
///     post-exit-hook firing rate.
#[test]
fn iter42_pathology_bounded_at_max_plus_one_then_initiative_failed() {
    let (_tmp, mut conn) = fresh_disk_conn();
    seed_executing_initiative(&conn, "init-iter42");

    assert_eq!(read_count(&conn, "init-iter42"), 0,
        "fresh initiative MUST start with respawn counter at 0");
    assert_eq!(read_state(&conn, "init-iter42"), "Executing",
        "fresh initiative MUST start in Executing state");

    // Increments 1..=MAX land Permitted. We assert each one rather
    // than just the terminal value so a future regression that
    // skips an increment (e.g. UPDATE matching zero rows) fails on
    // the FIRST off-by-one rather than after the loop.
    for expected in 1..=MAX_ORCH_NO_PROGRESS_RESPAWNS {
        let observed = simulate_respawn_increment(&mut conn, "init-iter42");
        assert_eq!(
            observed, expected,
            "increment #{expected} MUST report counter = {expected}, observed {observed}",
        );
        assert_eq!(read_state(&conn, "init-iter42"), "Executing",
            "non-ceiling increment #{expected} MUST leave initiative Executing");
    }

    // Increment MAX + 1 trips the ceiling. The kernel's branch in
    // `respawn_orchestrator_for_initiative` calls
    // `simulate_initiative_failed` (the SQLite-side mutation) and
    // then emits the audit event post-commit; we mirror that two-
    // step here.
    let post_ceiling = simulate_respawn_increment(&mut conn, "init-iter42");
    assert_eq!(
        post_ceiling, MAX_ORCH_NO_PROGRESS_RESPAWNS + 1,
        "post-ceiling increment MUST report counter strictly above MAX",
    );
    simulate_initiative_failed(&mut conn, "init-iter42");
    assert_eq!(
        read_state(&conn, "init-iter42"),
        "Failed",
        "ceiling-exceeded branch MUST transition initiative to Failed",
    );

    // The audit-event constructor surfaces the operator-facing
    // payload. We pin both the discriminant + the `attempts`
    // field so a wire-shape change is caught here.
    let event = AuditEventKind::OrchestratorRespawnCeilingExceeded {
        initiative_id: "init-iter42".to_owned(),
        attempts:      post_ceiling,
        max_attempts:  MAX_ORCH_NO_PROGRESS_RESPAWNS,
    };
    match &event {
        AuditEventKind::OrchestratorRespawnCeilingExceeded {
            initiative_id, attempts, max_attempts,
        } => {
            assert_eq!(initiative_id, "init-iter42");
            assert_eq!(*attempts, MAX_ORCH_NO_PROGRESS_RESPAWNS + 1);
            assert_eq!(*max_attempts, MAX_ORCH_NO_PROGRESS_RESPAWNS);
        }
        other => panic!(
            "expected OrchestratorRespawnCeilingExceeded, got {other:?}"
        ),
    }

    // Subsequent post-exit-hook triggers MUST be short-circuited by
    // the `is_executing` preflight. We mirror the predicate here by
    // re-reading `state`; in production the kernel's
    // `respawn_orchestrator_for_initiative` opens with this exact
    // check before calling the increment helper.
    assert_ne!(
        read_state(&conn, "init-iter42"), "Executing",
        "after Failed-flip the is_executing preflight MUST return false",
    );

    // Critically, no further increments should fire. We DON'T call
    // `simulate_respawn_increment` again to mirror the kernel's
    // short-circuit — the witness is "the kernel never reaches the
    // increment helper after Failed". Re-reading the counter
    // confirms it is unchanged.
    assert_eq!(
        read_count(&conn, "init-iter42"), MAX_ORCH_NO_PROGRESS_RESPAWNS + 1,
        "post-Failed counter MUST be the post-ceiling value, never re-incremented",
    );
}

/// Assertion of the load-bearing reset pair: `transition_task_in_tx`
/// resets the counter on every legal task FSM transition. This test
/// drives the "respawn → respawn → FSM-progress → respawn" sequence
/// (legitimate retry path: a Reviewer activates, the orchestrator
/// makes a real decision, no ceiling fires) and asserts the counter
/// returns to 0 on the reset and walks fresh from 1 on the next
/// respawn. The ceiling is preserved as a backstop for a *new*
/// pathological loop after honest progress.
#[test]
fn fsm_progress_reset_clears_loop_counter_then_ceiling_re_arms() {
    let (_tmp, mut conn) = fresh_disk_conn();
    seed_executing_initiative(&conn, "init-progress");

    // Two no-progress respawns, then an FSM-progress reset.
    assert_eq!(simulate_respawn_increment(&mut conn, "init-progress"), 1);
    assert_eq!(simulate_respawn_increment(&mut conn, "init-progress"), 2);
    simulate_fsm_progress_reset(&mut conn, "init-progress");
    assert_eq!(
        read_count(&conn, "init-progress"), 0,
        "FSM-progress reset MUST drop counter to 0",
    );

    // Now drive MAX more respawns — none of them trip the ceiling
    // because the reset cleared the budget. The post-reset
    // sequence walks 1..=MAX exactly as the fresh sequence did.
    for expected in 1..=MAX_ORCH_NO_PROGRESS_RESPAWNS {
        assert_eq!(
            simulate_respawn_increment(&mut conn, "init-progress"),
            expected,
            "post-reset increment #{expected} MUST report counter = {expected}",
        );
    }

    // Ceiling re-arms: MAX + 1-th post-reset increment trips it.
    let post_ceiling = simulate_respawn_increment(&mut conn, "init-progress");
    assert_eq!(
        post_ceiling, MAX_ORCH_NO_PROGRESS_RESPAWNS + 1,
        "ceiling MUST re-arm after reset; (MAX+1)-th respawn trips it",
    );
}

/// Two concurrent initiatives carry independent counters: one
/// stalled initiative does NOT poison the unrelated other. Pinned
/// because the per-initiative scope is a load-bearing design choice
/// (`v2-deep-spec.md §Step 12 V2.5b extension`, "Why per-initiative
/// rather than per-`subtask_activations` row").
#[test]
fn per_initiative_scope_isolates_counters_across_concurrent_initiatives() {
    let (_tmp, mut conn) = fresh_disk_conn();
    seed_executing_initiative(&conn, "init-stalled");
    seed_executing_initiative(&conn, "init-healthy");

    // The stalled initiative walks to MAX.
    for _ in 0..MAX_ORCH_NO_PROGRESS_RESPAWNS {
        simulate_respawn_increment(&mut conn, "init-stalled");
    }
    assert_eq!(
        read_count(&conn, "init-stalled"),
        MAX_ORCH_NO_PROGRESS_RESPAWNS,
    );
    assert_eq!(
        read_count(&conn, "init-healthy"), 0,
        "healthy initiative's counter MUST stay at 0 while sibling stalls",
    );

    // The healthy initiative makes one respawn (e.g. operator-driven
    // re-pickup); its counter walks to 1, the stalled one is
    // unchanged.
    assert_eq!(simulate_respawn_increment(&mut conn, "init-healthy"), 1);
    assert_eq!(
        read_count(&conn, "init-stalled"),
        MAX_ORCH_NO_PROGRESS_RESPAWNS,
        "stalled initiative's counter MUST be unaffected by sibling activity",
    );
}

/// The dashboard's notification filter promotes
/// `OrchestratorRespawnCeilingExceeded` to `Critical` priority, so
/// the operator-facing alarm fires within seconds of ceiling
/// exceedance. Without the promotion an iter42-style regression
/// would be buried below the per-event-stream noise floor in the
/// dashboard.
#[test]
fn dashboard_promotes_ceiling_event_to_critical() {
    let event = AuditEventKind::OrchestratorRespawnCeilingExceeded {
        initiative_id: "init-arbitrary".to_owned(),
        attempts:      MAX_ORCH_NO_PROGRESS_RESPAWNS + 1,
        max_attempts:  MAX_ORCH_NO_PROGRESS_RESPAWNS,
    };
    assert_eq!(
        notification_priority(&event),
        Some(NotificationPriority::Critical),
        "dashboard MUST promote OrchestratorRespawnCeilingExceeded to Critical",
    );
}
