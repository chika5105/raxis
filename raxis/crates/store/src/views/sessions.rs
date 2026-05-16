//! Session-table query catalog (cli-readonly.md §5.4.1 `sessions.rs`).
//!
//! Surface:
//!   * [`active_counts`] — Active vs Revoked vs Expired count for the
//!     `raxis status` workload-summary block.
//!   * [`active_list`] — `raxis sessions` paged list.
//!
//! Note: the kernel does not maintain a per-channel
//! (planner / gateway / verifier) session-type tag in v1 — every row
//! shares the same `sessions` table. The CLI-spec `active_planner_sessions`
//! / `active_gateway_sessions` heartbeat fields are best-effort and
//! published from the kernel's in-memory IPC accept loops; the SQL
//! view here only knows "active vs not".

use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One session row in the shape `raxis sessions` needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub session_id: String,
    pub role_id: String,
    pub lineage_id: String,
    pub worktree_root: Option<String>,
    pub sequence_number: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
    pub revoked_at: Option<u64>,
}

/// Three-bucket projection of all session rows.
///
/// `active = revoked == 0 AND expires_at > now`,
/// `expired = revoked == 0 AND expires_at <= now`,
/// `revoked = revoked == 1`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SessionStateCounts {
    pub active: u64,
    pub expired: u64,
    pub revoked: u64,
    pub total: u64,
}

#[derive(Debug, Error)]
pub enum SessionViewError {
    #[error("sqlite error during session view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Count sessions split into active / expired / revoked using `now`
/// as the cut-off. `now` is a parameter (not `SystemTime::now()`
/// internal) so tests can drive the function deterministically.
pub fn active_counts_at(
    conn: &RoConn,
    now_secs: u64,
) -> Result<SessionStateCounts, SessionViewError> {
    let mut counts = SessionStateCounts::default();
    let now_i = now_secs.min(i64::MAX as u64) as i64;

    // One scan with a CASE to bucket; faster than three separate
    // queries on any v1 table size.
    let mut stmt = conn.prepare(&format!(
        "SELECT \
            CASE \
                WHEN revoked = 1 THEN 'revoked' \
                WHEN expires_at <= ?1 THEN 'expired' \
                ELSE 'active' \
            END AS bucket, \
            COUNT(*) \
         FROM {} GROUP BY bucket",
        Table::Sessions.as_str(),
    ))?;
    let rows = stmt.query_map(rusqlite::params![now_i], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (bucket, count) = row?;
        let n = count.max(0) as u64;
        match bucket.as_str() {
            "active" => counts.active = n,
            "expired" => counts.expired = n,
            "revoked" => counts.revoked = n,
            _ => {}
        }
        counts.total = counts.total.saturating_add(n);
    }
    Ok(counts)
}

/// Convenience wrapper that uses the host `SystemTime`. Tests that
/// need determinism call [`active_counts_at`] directly.
pub fn active_counts(conn: &RoConn) -> Result<SessionStateCounts, SessionViewError> {
    active_counts_at(conn, unix_now_secs())
}

/// Count the un-revoked rows in `sessions`. Distinct from
/// [`active_counts_at`] in two ways:
///   1. Takes a `&rusqlite::Connection` so the kernel-side write
///      handle (`Store::lock_sync` / `Store::lock`) can call it
///      from within a write transaction without first opening a
///      separate read-only handle.
///   2. Ignores `expires_at` — for VM-concurrency cap admission
///      the kernel cares about live sessions whose revoke-on-exit
///      hook has not yet fired, regardless of the policy-level
///      session-token expiry. A revoked-but-unexpired row never
///      holds a live VM (the `SessionSpawnService::terminate_session`
///      path has run); an unrevoked-but-expired row may still
///      hold a live VM (the planner has not yet self-disconnected
///      and the kernel has not yet reaped it). The cap MUST count
///      the latter.
///
/// Pinned by `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01` as the
/// canonical "alive sessions" projection consumed by
/// [`raxis_session_spawn::SessionSpawnService::active_count`].
/// Adding any other `WHERE` clause here is a wire-shape change
/// that requires updating the matching invariant + the cap-
/// admission test in
/// `kernel/tests/session_spawn_cap_uses_db_truth.rs`.
pub fn count_unrevoked_sessions(conn: &rusqlite::Connection) -> Result<u64, SessionViewError> {
    let count: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM {} WHERE revoked = 0",
            Table::Sessions.as_str(),
        ),
        [],
        |r| r.get(0),
    )?;
    Ok(count.max(0) as u64)
}

/// Count active sessions split by `session_agent_type` (Orchestrator /
/// Executor / Reviewer). Returns one entry per agent type that has at
/// least one row in the `sessions` table whose `revoked = 0 AND
/// expires_at > now` predicate evaluates to true. Agent types with
/// zero active sessions do NOT appear in the returned vec — callers
/// that want a stable three-row gauge (one per type) MUST iterate
/// the closed set themselves and look up the count from this map.
///
/// The label values returned are exactly the SQL strings stored in
/// `sessions.session_agent_type`, which by the migration-5 CHECK
/// constraint are drawn from the closed lexicon
/// `{"Orchestrator", "Executor", "Reviewer"}` (mirroring
/// `raxis_types::fsm::SessionAgentType::as_sql_str`). Rows with NULL
/// `session_agent_type` (V1-legacy) are omitted from the result.
///
/// Wired by the kernel heartbeat loop
/// (`kernel/src/runtime/heartbeat.rs::run_loop`) which emits a
/// `raxis.session.active` gauge per agent type on every tick. Without
/// this query the gauge would have to poll a per-role atomic counter
/// maintained at every spawn / terminate site — a significantly more
/// invasive wiring whose only advantage is millisecond-level
/// freshness, which the dashboard does not need (HEARTBEAT_INTERVAL =
/// 5 s is well below the dashboard scrape cadence).
pub fn active_counts_by_agent_type_at(
    conn: &rusqlite::Connection,
    now_secs: u64,
) -> Result<Vec<(String, u64)>, SessionViewError> {
    let now_i = now_secs.min(i64::MAX as u64) as i64;
    let mut stmt = conn.prepare(&format!(
        "SELECT session_agent_type, COUNT(*) \
         FROM {} \
         WHERE revoked = 0 \
           AND expires_at > ?1 \
           AND session_agent_type IS NOT NULL \
         GROUP BY session_agent_type",
        Table::Sessions.as_str(),
    ))?;
    let rows = stmt.query_map(rusqlite::params![now_i], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (kind, count) = row?;
        out.push((kind, count.max(0) as u64));
    }
    Ok(out)
}

/// Wall-clock-driven wrapper around
/// [`active_counts_by_agent_type_at`].
pub fn active_counts_by_agent_type(
    conn: &rusqlite::Connection,
) -> Result<Vec<(String, u64)>, SessionViewError> {
    active_counts_by_agent_type_at(conn, unix_now_secs())
}

/// List currently-active sessions, ordered newest-first.
///
/// Active = `revoked == 0 AND expires_at > now`. The CLI uses this
/// for the `raxis sessions` table; revoked / expired rows are
/// excluded because they are not actionable.
pub fn active_list(conn: &RoConn, limit: usize) -> Result<Vec<SessionRow>, SessionViewError> {
    let now_i = unix_now_secs().min(i64::MAX as u64) as i64;
    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, role_id, lineage_id, worktree_root, \
                sequence_number, created_at, expires_at, revoked, revoked_at \
         FROM {} \
         WHERE revoked = 0 AND expires_at > ?1 \
         ORDER BY created_at DESC LIMIT ?2",
        Table::Sessions.as_str(),
    ))?;
    let rows = stmt
        .query_map(rusqlite::params![now_i, limit as i64], |r| {
            Ok(SessionRow {
                session_id: r.get(0)?,
                role_id: r.get(1)?,
                lineage_id: r.get(2)?,
                worktree_root: r.get(3)?,
                sequence_number: r.get::<_, i64>(4)?.max(0) as u64,
                created_at: r.get::<_, i64>(5)?.max(0) as u64,
                expires_at: r.get::<_, i64>(6)?.max(0) as u64,
                revoked: r.get::<_, i64>(7)? != 0,
                revoked_at: r.get::<_, Option<i64>>(8)?.map(|v| v.max(0) as u64),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Look up ONE session by `session_id`, regardless of its current
/// state (active / revoked / expired). Returns `Ok(None)` only when
/// no row exists for the id.
///
/// The dashboard's detail view (`GET /api/sessions/:id`) needs this:
/// an operator who clicked a session row in the list page MUST see
/// the detail page render, even if the session has since terminated
/// (V2.5 originally pinned this surface to [`active_list`], so any
/// session that crossed `expires_at` between the list fetch and the
/// detail click surfaced as a misleading `FAIL_DASHBOARD_NOT_FOUND`
/// for a row the operator literally just saw —
/// `INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01`).
///
/// The forensic-detail contract: terminated sessions surface as
/// read-only (the FE renders `state="Revoked"` or `state="Expired"`
/// via `failure: None` for V2.5; V3 walks the audit chain for the
/// matching `SessionRevoked` / `SessionVmFailedFinal` row).
pub fn by_id(conn: &RoConn, session_id: &str) -> Result<Option<SessionRow>, SessionViewError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, role_id, lineage_id, worktree_root, \
                sequence_number, created_at, expires_at, revoked, revoked_at \
         FROM {} \
         WHERE session_id = ?1 \
         LIMIT 1",
        Table::Sessions.as_str(),
    ))?;
    let row = stmt
        .query_row(rusqlite::params![session_id], |r| {
            Ok(SessionRow {
                session_id: r.get(0)?,
                role_id: r.get(1)?,
                lineage_id: r.get(2)?,
                worktree_root: r.get(3)?,
                sequence_number: r.get::<_, i64>(4)?.max(0) as u64,
                created_at: r.get::<_, i64>(5)?.max(0) as u64,
                expires_at: r.get::<_, i64>(6)?.max(0) as u64,
                revoked: r.get::<_, i64>(7)? != 0,
                revoked_at: r.get::<_, Option<i64>>(8)?.map(|v| v.max(0) as u64),
            })
        })
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;
    Ok(row)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Worktree-GC helpers — V2.5 `integration-merge.md §11.4`
// (INV-MERGE-WORKTREE-RETAIN). The kernel-side worktree garbage
// collector consults these two helpers under the store mutex before
// removing a session worktree from disk; both must succeed (no
// pending merge AND a recorded worktree path) for removal to proceed.
// ---------------------------------------------------------------------------

/// Look up `sessions.worktree_root` for a session, returning the
/// stored absolute path string or `None` when the row is missing or
/// the column is NULL (the session was reserved but never received
/// a staged worktree).
///
/// Used by both `kernel::recovery::reconcile_git_apply_pending`
/// (Case A re-applies Phase 2 against this path) and the worktree
/// GC sweep (which calls `worktree_staging::destroy` on this path
/// after [`pending_initiative_for_session`] returns `None`).
pub fn worktree_root_for_session(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    conn.query_row(
        &format!(
            "SELECT worktree_root FROM {} WHERE session_id = ?1",
            Table::Sessions.as_str(),
        ),
        rusqlite::params![session_id],
        |r| r.get::<_, Option<String>>(0),
    )
    .map(Some)
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        other => Err(other),
    })
    .map(Option::flatten)
}

/// Return the `initiative_id` of any initiative still holding the
/// given session's worktree under `git_apply_pending = 1`
/// (INV-MERGE-WORKTREE-RETAIN, `integration-merge.md §11.4`).
///
/// The session→initiative edge runs through `tasks.session_id`:
///
/// ```sql
/// SELECT i.initiative_id
///   FROM initiatives i
///   JOIN tasks t ON t.initiative_id = i.initiative_id
///  WHERE t.session_id        = :session_id
///    AND i.git_apply_pending = 1
///  LIMIT 1;
/// ```
///
/// Returns `Ok(None)` when no blocking initiative is found — the
/// caller (worktree GC) is then free to delete the worktree from
/// disk. Returns `Ok(Some(initiative_id))` when at least one match
/// exists; the caller MUST skip removal and surface the retention
/// in its decision report so a follow-up sweep retries after
/// recovery clears the flag.
pub fn pending_initiative_for_session(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    conn.query_row(
        &format!(
            "SELECT i.initiative_id \
               FROM {initiatives} i \
               JOIN {tasks}       t ON t.initiative_id = i.initiative_id \
              WHERE t.session_id        = ?1 \
                AND i.git_apply_pending = 1 \
              LIMIT 1",
            initiatives = Table::Initiatives.as_str(),
            tasks = Table::Tasks.as_str(),
        ),
        rusqlite::params![session_id],
        |r| r.get::<_, String>(0),
    )
    .map(Some)
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        other => Err(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    /// Three sessions: active, expired (in the past), revoked. Each
    /// is created with explicit timestamps so the test does not race
    /// the wall clock.
    fn fresh_store_with_seed_sessions() -> TempDir {
        const SESSIONS: &str = Table::Sessions.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        // SQLite does not accept Rust-style `_` digit separators
        // inside numeric literals (`9_999_999_999` parses as a token,
        // not an integer); spell out big numbers instead.
        guard
            .execute(
                &format!(
                    "INSERT INTO {SESSIONS} \
                 (session_id, role_id, session_token, lineage_id, fetch_quota, \
                  created_at, expires_at, revoked) \
                 VALUES \
                 ('s-active',  'planner', 'tok-a', 'lin', 0, 100, 9999999999, 0), \
                 ('s-expired', 'planner', 'tok-e', 'lin', 0, 100, 200,        0), \
                 ('s-revoked', 'planner', 'tok-r', 'lin', 0, 100, 9999999999, 1)"
                ),
                [],
            )
            .unwrap();
        guard
            .execute(
                &format!("UPDATE {SESSIONS} SET revoked_at = 150 WHERE session_id = 's-revoked'"),
                [],
            )
            .unwrap();
        tmp
    }

    #[test]
    fn active_counts_at_buckets_each_session_correctly() {
        let tmp = fresh_store_with_seed_sessions();
        let conn = open_ro(tmp.path()).unwrap();
        let counts = active_counts_at(&conn, 500).unwrap();
        assert_eq!(counts.active, 1);
        assert_eq!(counts.expired, 1);
        assert_eq!(counts.revoked, 1);
        assert_eq!(counts.total, 3);
    }

    #[test]
    fn active_list_excludes_expired_and_revoked() {
        let tmp = fresh_store_with_seed_sessions();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = active_list(&conn, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_id, "s-active");
        assert!(!rows[0].revoked);
    }

    // `INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01`: the dashboard
    // detail surface needs to find ANY session, including ones
    // that have already terminated (revoked / expired). The
    // previous lookup path used [`active_list`], which silently
    // returned 404 for sessions an operator had just seen in the
    // list (because `expires_at` had since elapsed). [`by_id`]
    // ignores the active-window filter so terminated rows render
    // in a read-only forensic detail view.
    #[test]
    fn by_id_finds_active_session() {
        let tmp = fresh_store_with_seed_sessions();
        let conn = open_ro(tmp.path()).unwrap();
        let row = by_id(&conn, "s-active").unwrap();
        assert!(row.is_some());
        let r = row.unwrap();
        assert_eq!(r.session_id, "s-active");
        assert!(!r.revoked);
    }

    #[test]
    fn by_id_finds_revoked_session() {
        let tmp = fresh_store_with_seed_sessions();
        let conn = open_ro(tmp.path()).unwrap();
        let row = by_id(&conn, "s-revoked").unwrap();
        assert!(
            row.is_some(),
            "INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01: revoked \
             session must be visible to the detail handler"
        );
        let r = row.unwrap();
        assert_eq!(r.session_id, "s-revoked");
        assert!(r.revoked);
        assert_eq!(r.revoked_at, Some(150));
    }

    #[test]
    fn by_id_finds_expired_session() {
        let tmp = fresh_store_with_seed_sessions();
        let conn = open_ro(tmp.path()).unwrap();
        let row = by_id(&conn, "s-expired").unwrap();
        assert!(
            row.is_some(),
            "INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01: expired \
             session must be visible to the detail handler"
        );
        let r = row.unwrap();
        assert_eq!(r.session_id, "s-expired");
        assert!(!r.revoked);
        // expires_at = 200 in the seed; that's clearly in the past
        // (long before any reasonable `now`) — the row is still
        // returned because `by_id` does NOT apply the active-window
        // filter.
        assert_eq!(r.expires_at, 200);
    }

    #[test]
    fn by_id_returns_none_for_unknown() {
        let tmp = fresh_store_with_seed_sessions();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(by_id(&conn, "no-such-session").unwrap().is_none());
    }

    /// `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01`. The seed has
    /// three sessions (active, expired, revoked). The DB-side
    /// "alive" predicate keyed on `revoked = 0` returns 2 (active +
    /// expired), NOT 1 (`active_counts_at` minus revoked) and NOT
    /// 3 (every row). The cap-admission gate calls THIS helper.
    #[test]
    fn count_unrevoked_sessions_excludes_only_revoked_rows() {
        let tmp = fresh_store_with_seed_sessions();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let g = store.lock_sync();
        let count = count_unrevoked_sessions(&g).unwrap();
        assert_eq!(
            count, 2,
            "INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01: \
             cap-admission counts every un-revoked row \
             regardless of expires_at (the policy-level token \
             expiry is independent of whether the substrate \
             still holds a live VM for that session)"
        );
    }

    /// `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01`. After every
    /// row has been revoked the count goes to zero; this is the
    /// regression witness for the iter65 root cause where the
    /// in-memory ledger leaked entries on `planner_self_exit` so
    /// the cap pinned at `cap=N` indefinitely.
    #[test]
    fn count_unrevoked_sessions_drops_to_zero_after_revoke_sweep() {
        const SESSIONS: &str = Table::Sessions.as_str();
        let tmp = fresh_store_with_seed_sessions();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let g = store.lock_sync();
        g.execute(&format!("UPDATE {SESSIONS} SET revoked = 1"), [])
            .unwrap();
        let count = count_unrevoked_sessions(&g).unwrap();
        assert_eq!(
            count, 0,
            "every row revoked ⇒ cap-admission projection MUST \
             collapse to zero (regression for the iter65 leak)"
        );
    }

    // ── Worktree-GC helper tests (V2.5 §11.4) ─────────────────────

    /// Seed an `initiatives + tasks + sessions` triangle so the
    /// `JOIN tasks ON ... JOIN sessions ON ...` walk in
    /// [`pending_initiative_for_session`] has rows to traverse.
    fn fresh_store_for_gc() -> (TempDir, Store) {
        const INITIATIVES: &str = Table::Initiatives.as_str();
        const TASKS: &str = Table::Tasks.as_str();
        const SESSIONS: &str = Table::Sessions.as_str();
        let tmp = TempDir::new().unwrap();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let g = store.lock_sync();
        g.execute(
            &format!(
                "INSERT INTO {INITIATIVES} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at, git_apply_pending) \
                 VALUES \
                    ('init-pending', 'Executing', '{{}}', 'deadbeef', 100, 1), \
                    ('init-clear',   'Executing', '{{}}', 'deadbeef', 100, 0)"
            ),
            [],
        )
        .unwrap();
        g.execute(
            &format!(
                "INSERT INTO {SESSIONS} \
                    (session_id, role_id, session_token, lineage_id, fetch_quota, \
                     worktree_root, created_at, expires_at) \
                 VALUES \
                    ('sess-pending',   'orch', 'tok-p', 'lin', 0, '/tmp/wt-pending',   100, 9999999999), \
                    ('sess-clear',     'orch', 'tok-c', 'lin', 0, '/tmp/wt-clear',     100, 9999999999), \
                    ('sess-orphaned',  'orch', 'tok-o', 'lin', 0, NULL,                100, 9999999999), \
                    ('sess-no-task',   'orch', 'tok-n', 'lin', 0, '/tmp/wt-no-task',   100, 9999999999)"
            ),
            [],
        ).unwrap();
        g.execute(
            &format!(
                "INSERT INTO {TASKS} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at, session_id) \
                 VALUES \
                    ('t-pending', 'init-pending', 'lane-1', 'Running', 'orch', \
                     1, 100, 100, 'sess-pending'), \
                    ('t-clear',   'init-clear',   'lane-1', 'Running', 'orch', \
                     1, 100, 100, 'sess-clear')"
            ),
            [],
        )
        .unwrap();
        drop(g);
        (tmp, store)
    }

    #[test]
    fn worktree_root_for_session_returns_path_when_present() {
        let (_tmp, store) = fresh_store_for_gc();
        let g = store.lock_sync();
        let path = worktree_root_for_session(&g, "sess-pending").unwrap();
        assert_eq!(path.as_deref(), Some("/tmp/wt-pending"));
    }

    #[test]
    fn worktree_root_for_session_returns_none_when_session_missing() {
        let (_tmp, store) = fresh_store_for_gc();
        let g = store.lock_sync();
        assert_eq!(worktree_root_for_session(&g, "ghost").unwrap(), None);
    }

    #[test]
    fn worktree_root_for_session_returns_none_when_column_null() {
        let (_tmp, store) = fresh_store_for_gc();
        let g = store.lock_sync();
        assert_eq!(
            worktree_root_for_session(&g, "sess-orphaned").unwrap(),
            None
        );
    }

    #[test]
    fn pending_initiative_for_session_finds_blocking_initiative() {
        let (_tmp, store) = fresh_store_for_gc();
        let g = store.lock_sync();
        let blocker = pending_initiative_for_session(&g, "sess-pending").unwrap();
        assert_eq!(
            blocker.as_deref(),
            Some("init-pending"),
            "INV-MERGE-WORKTREE-RETAIN: GC must see the pending initiative"
        );
    }

    #[test]
    fn pending_initiative_for_session_returns_none_when_flag_clear() {
        let (_tmp, store) = fresh_store_for_gc();
        let g = store.lock_sync();
        assert_eq!(
            pending_initiative_for_session(&g, "sess-clear").unwrap(),
            None,
            "git_apply_pending=0 ⇒ no retention; GC may proceed"
        );
    }

    #[test]
    fn pending_initiative_for_session_returns_none_when_session_has_no_tasks() {
        let (_tmp, store) = fresh_store_for_gc();
        let g = store.lock_sync();
        assert_eq!(
            pending_initiative_for_session(&g, "sess-no-task").unwrap(),
            None,
            "session not yet bound to any task ⇒ cannot block any merge"
        );
    }

    #[test]
    fn pending_initiative_for_session_returns_none_when_session_unknown() {
        let (_tmp, store) = fresh_store_for_gc();
        let g = store.lock_sync();
        assert_eq!(pending_initiative_for_session(&g, "ghost").unwrap(), None);
    }

    #[test]
    fn pending_initiative_for_session_clears_after_flag_drops() {
        let (_tmp, store) = fresh_store_for_gc();
        let g = store.lock_sync();
        assert!(pending_initiative_for_session(&g, "sess-pending")
            .unwrap()
            .is_some());
        crate::views::initiatives::clear_git_apply_pending(&g, "init-pending").unwrap();
        assert_eq!(
            pending_initiative_for_session(&g, "sess-pending").unwrap(),
            None,
            "once Phase 3 / recovery clears the flag, GC must be unblocked"
        );
    }
}
