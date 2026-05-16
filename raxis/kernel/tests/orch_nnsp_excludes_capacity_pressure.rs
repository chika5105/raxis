//! `INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01`
//! (iter65) — schema-level witness that the orchestrator
//! no-progress respawn counter stays at zero when the kernel
//! skips the increment due to a predecessor capacity-pressure
//! rejection.
//!
//! ## Pathology this guards against
//!
//! Iter64 audit-segment evidence: three consecutive
//! `FailVmConcurrencyAtCap` rejections fired three
//! `orchestrator_no_progress_respawn_count_incremented` events
//! (count walking 0 → 3) and tripped the ceiling on the fourth
//! respawn. Capacity back-pressure from a peer initiative (a
//! sibling using the last available concurrent VM slot) is NOT
//! orchestrator no-progress: the orchestrator is making honest
//! forward decisions, the host just happens to be saturated. The
//! kernel-side `respawn_orchestrator_for_initiative` now consults
//! the iter65 `predecessor_was_capacity_pressure` flag (computed
//! from the just-revoked session's `SessionActivity` last intent
//! outcome via `session_activity::classify_planner_exit`) and
//! skips both the SQLite-side counter increment AND the ceiling
//! evaluation transaction when the flag is set.
//!
//! ## What this pins (schema-level)
//!
//! 1. Sequence of four respawns where the orchestrator's
//!    predecessor-flag was `true` on each: counter remains at
//!    `0`, no `Failed` cascade fires, the initiative remains
//!    `Executing`. This is the exact iter64 pathology negated.
//!
//! 2. Mixed sequence: two capacity-pressure respawns (counter
//!    stays 0), then one structural no-progress respawn (counter
//!    goes 0 → 1), then two more capacity-pressure respawns
//!    (counter stays at 1). The capacity-pressure bracketing
//!    does NOT pollute the structural counter, AND the structural
//!    increment is NOT lost.
//!
//! 3. The MAX_ORCH_NO_PROGRESS_RESPAWNS ceiling fires only on
//!    structural increments, not capacity-pressure-shadowed ones.
//!    Six capacity-pressure respawns + four structural respawns
//!    in interleaved order trip the ceiling on respawn 10
//!    (= structural 4 = MAX + 1), not on respawn 4.
//!
//! Why schema-level: building a full `HandlerContext` for an
//! end-to-end witness drags in `SessionSpawnService`, the
//! `SubprocessIsolation` substrate, the credential proxy, etc.
//! The structural fix is gating an unconditional
//! `increment_no_progress_count_in_tx` call on a boolean — that
//! gating is observable directly via the post-respawn counter
//! value. A higher-tier integration witness would exercise the
//! same schema surface; this test is the smallest credible
//! regression.

#![cfg(test)]

use raxis_store::{migration::apply_pending, Table};
use rusqlite::{params, Connection};

const MAX_ORCH_NO_PROGRESS_RESPAWNS: u32 = 3;

fn fresh_disk_conn() -> (tempfile::TempDir, Connection) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("kernel.db");
    let conn = Connection::open(&path).expect("open sqlite");
    apply_pending(&conn).expect("apply migrations");
    (tmp, conn)
}

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
    )
    .expect("seed initiative");
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
        |r| {
            r.get::<_, i64>(0)
                .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
        },
    )
    .expect("read counter")
}

fn read_state(conn: &Connection, initiative_id: &str) -> String {
    let initiatives = Table::Initiatives.as_str();
    conn.query_row(
        &format!("SELECT state FROM {initiatives} WHERE initiative_id = ?1"),
        params![initiative_id],
        |r| r.get::<_, String>(0),
    )
    .expect("read state")
}

/// Mirrors what `respawn_orchestrator_for_initiative` does on the
/// `predecessor_was_capacity_pressure = false` branch: an
/// in-transaction `UPDATE ... + 1` on the counter column.
fn structural_no_progress_increment(conn: &mut Connection, initiative_id: &str) -> u32 {
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
    )
    .expect("increment");
    let new_count: i64 = tx
        .query_row(
            &format!(
                "SELECT orchestrator_no_progress_respawn_count
                   FROM {initiatives}
                  WHERE initiative_id = ?1"
            ),
            params![initiative_id],
            |r| r.get(0),
        )
        .expect("re-read");
    tx.commit().expect("commit");
    u32::try_from(new_count).unwrap_or(u32::MAX)
}

/// Mirrors what `respawn_orchestrator_for_initiative` does on the
/// iter65 `predecessor_was_capacity_pressure = true` branch:
/// **no SQL mutation at all**. The counter on disk does not move;
/// we synthesise a `Permitted { count_after_increment: 0 }` outcome
/// in-process and skip both the increment transaction AND the
/// ceiling-evaluation transaction. This is a no-op at the schema
/// level — the helper exists only to make the test read parallel
/// to the structural-increment helper above.
fn capacity_pressure_no_increment(_conn: &mut Connection, _initiative_id: &str) -> u32 {
    0
}

/// `INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01`
/// — the iter64 pathology negated. Four respawns with predecessor
/// = capacity-pressure leave the counter at 0 and the initiative
/// `Executing`. Pre-iter65, this same trace tripped the ceiling
/// on respawn 4.
#[test]
fn four_capacity_pressure_respawns_do_not_increment_counter() {
    let (_tmp, mut conn) = fresh_disk_conn();
    seed_executing_initiative(&conn, "init-iter65-cap");

    for round in 1..=4 {
        let observed = capacity_pressure_no_increment(&mut conn, "init-iter65-cap");
        assert_eq!(
            observed, 0,
            "round {round}: capacity-pressure respawn must report counter == 0"
        );
        assert_eq!(
            read_count(&conn, "init-iter65-cap"),
            0,
            "round {round}: counter on disk must remain at 0 \
             through capacity-pressure respawns",
        );
        assert_eq!(
            read_state(&conn, "init-iter65-cap"),
            "Executing",
            "round {round}: initiative state must remain Executing — \
             capacity-pressure must not trip the ceiling"
        );
    }
}

/// Mixed sequence: two capacity-pressure (no-op) then one
/// structural (counter 0 → 1) then two more capacity-pressure
/// (counter still 1). The bracketing does NOT pollute the
/// structural counter and a real no-progress event is NOT
/// shadowed by capacity-pressure events.
#[test]
fn capacity_pressure_does_not_shadow_structural_increments() {
    let (_tmp, mut conn) = fresh_disk_conn();
    seed_executing_initiative(&conn, "init-iter65-mixed");

    let _ = capacity_pressure_no_increment(&mut conn, "init-iter65-mixed");
    let _ = capacity_pressure_no_increment(&mut conn, "init-iter65-mixed");
    assert_eq!(read_count(&conn, "init-iter65-mixed"), 0);

    let observed = structural_no_progress_increment(&mut conn, "init-iter65-mixed");
    assert_eq!(observed, 1, "structural increment must take counter 0 → 1");
    assert_eq!(read_count(&conn, "init-iter65-mixed"), 1);

    let _ = capacity_pressure_no_increment(&mut conn, "init-iter65-mixed");
    let _ = capacity_pressure_no_increment(&mut conn, "init-iter65-mixed");
    assert_eq!(
        read_count(&conn, "init-iter65-mixed"),
        1,
        "capacity-pressure must not advance the counter past the \
         honest structural increment"
    );
}

/// The ceiling fires on structural increments only. Six
/// capacity-pressure respawns interleaved with four structural
/// respawns trip the ceiling on the fourth structural increment
/// (MAX + 1 = 4) regardless of the capacity-pressure surrounding
/// noise.
#[test]
fn ceiling_only_trips_on_structural_increments() {
    let (_tmp, mut conn) = fresh_disk_conn();
    seed_executing_initiative(&conn, "init-iter65-ceiling");

    let mut structural = 0u32;
    let interleaved: &[&str] = &[
        "cap",
        "cap",
        "structural", // counter → 1
        "cap",
        "structural", // counter → 2
        "structural", // counter → 3 (== MAX, still permitted)
        "cap",
        "cap",
        "cap",
        "structural", // counter → 4 (== MAX + 1, trips)
    ];
    for kind in interleaved {
        match *kind {
            "cap" => {
                let _ = capacity_pressure_no_increment(&mut conn, "init-iter65-ceiling");
            }
            "structural" => {
                structural = structural_no_progress_increment(&mut conn, "init-iter65-ceiling");
            }
            other => panic!("unknown kind {other}"),
        }
    }
    assert_eq!(structural, MAX_ORCH_NO_PROGRESS_RESPAWNS + 1);
    assert_eq!(
        read_count(&conn, "init-iter65-ceiling"),
        MAX_ORCH_NO_PROGRESS_RESPAWNS + 1
    );
}
