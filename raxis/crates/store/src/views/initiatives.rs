//! Initiative-table query catalog (cli-readonly.md §5.4.1
//! `initiatives.rs`).
//!
//! Surface:
//!   * [`counts_by_state`] — the second block of `raxis status`.
//!   * [`by_id`] — `raxis initiative show <initiative_id>`.
//!   * [`list`] — paged list with optional exact-state SQL filter.
//!   * [`list_filtered`] — the bucketed list backing
//!     `raxis initiative list` (cli-readonly.md §5.5.6b). Joins
//!     `initiative_quarantines` so each row carries a `quarantined`
//!     flag without a per-row follow-up query.
//!   * [`InitiativeListFilter`] — typed bucket used by §5.5.6b's
//!     `--state` flag (`active|recovery|completed|quarantined|all`).

use rusqlite::OptionalExtension;
use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One initiative row in the shape `inspect` and `list` need. Fields
/// 1:1 with the `initiatives` DDL (kernel-store.md §2.5.1 Table 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiativeRow {
    pub initiative_id: String,
    pub state: String,
    pub plan_artifact_sha256: String,
    pub created_at: u64,
    pub approved_at: Option<u64>,
    pub completed_at: Option<u64>,
}

/// Per-state row count. All initiative FSM states from kernel-store.md
/// §2.5.1 Table 2 + a `total` aggregate.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct InitiativeStateCounts {
    pub draft: u64,
    pub approved_plan: u64,
    pub executing: u64,
    pub blocked: u64,
    pub recovery_required: u64,
    pub completed: u64,
    pub failed: u64,
    pub aborted: u64,
    pub total: u64,
}

#[derive(Debug, Error)]
pub enum InitiativeViewError {
    #[error("sqlite error during initiative view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// One-shot per-state row counter for `initiatives`.
pub fn counts_by_state(conn: &RoConn) -> Result<InitiativeStateCounts, InitiativeViewError> {
    let mut counts = InitiativeStateCounts::default();
    let mut stmt = conn.prepare(&format!(
        "SELECT state, COUNT(*) FROM {} GROUP BY state",
        Table::Initiatives.as_str(),
    ))?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;

    for row in rows {
        let (state, count) = row?;
        let n = count.max(0) as u64;
        match state.as_str() {
            "Draft" => counts.draft = n,
            "ApprovedPlan" => counts.approved_plan = n,
            "Executing" => counts.executing = n,
            "Blocked" => counts.blocked = n,
            "RecoveryRequired" => counts.recovery_required = n,
            "Completed" => counts.completed = n,
            "Failed" => counts.failed = n,
            "Aborted" => counts.aborted = n,
            // Future states migrate gracefully — see tasks.rs note.
            _ => {}
        }
        counts.total = counts.total.saturating_add(n);
    }
    Ok(counts)
}

/// Return the V2 plan-bundle SHA-256 for one initiative, or `None`
/// when (a) the initiative does not exist, or (b) the initiative was
/// admitted via the V1 `plan submit` path and so has a NULL
/// `plan_bundle_sha256`.
///
/// Distinguishing "no initiative" from "V1 initiative" is the caller's
/// responsibility: pair this with [`by_id`] when the difference
/// matters. The dual lookup keeps the SQL columns each accessor
/// touches narrow — `by_id` does not need to widen its row shape just
/// to hand out a forensic field.
///
/// V2 admission stores `plan_bundle_sha256` as a 32-byte BLOB, which
/// this function decodes into a typed [`raxis_types::BundleSha256`].
/// A column with the wrong width surfaces as
/// [`InitiativeViewError::Sqlite`] (rusqlite's `FromSqlError`).
pub fn plan_bundle_sha256_by_id(
    conn: &RoConn,
    initiative_id: &str,
) -> Result<Option<raxis_types::BundleSha256>, InitiativeViewError> {
    let row = conn
        .query_row(
            &format!(
                "SELECT plan_bundle_sha256 \
             FROM {} WHERE initiative_id = ?1",
                Table::Initiatives.as_str(),
            ),
            rusqlite::params![initiative_id],
            |r| r.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?;

    let Some(blob_opt) = row else {
        return Ok(None);
    };
    let Some(blob) = blob_opt else {
        return Ok(None);
    };

    let arr: [u8; 32] = blob.as_slice().try_into().map_err(|_| {
        // Surface as a structured rusqlite error: the DDL CHECK
        // constraint pins the BLOB to exactly 32 bytes, so a
        // wrong-width payload is a corrupted row.
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("plan_bundle_sha256 is {} bytes, expected 32", blob.len()),
            )),
        )
    })?;
    Ok(Some(raxis_types::BundleSha256::new(arr)))
}

/// Whether the given initiative has `git_apply_pending = 1`.
///
/// Phase 1 of the IntegrationMerge three-phase commit
/// (integration-merge.md §11.1) sets this flag inside the same SQLite
/// transaction that records the intent. Phase 3 clears it after the
/// host-side fast-forward of the operator-configured `target_ref`
/// completes. Between Phase 1 commit and Phase 3 clear, this returns
/// `Ok(true)` and:
///   * the IntegrationMerge admission pre-flight rejects with
///     `FAIL_GIT_APPLY_PENDING`,
///   * worktree GC retains the worktree until the flag clears (so
///     recovery still has the merge commit reachable), and
///   * boot recovery re-runs the host-side merge.
///
/// Returns `Ok(false)` when the initiative does not exist (callers
/// already validate existence via [`by_id`]) so the recovery scan can
/// stay narrow.
pub fn git_apply_pending(conn: &RoConn, initiative_id: &str) -> Result<bool, InitiativeViewError> {
    let pending: Option<i64> = conn
        .query_row(
            &format!(
                "SELECT git_apply_pending FROM {} WHERE initiative_id = ?1",
                Table::Initiatives.as_str(),
            ),
            rusqlite::params![initiative_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(pending.unwrap_or(0) != 0)
}

/// Initiative ids whose IntegrationMerge committed Phase 1 but never
/// observed Phase 3 (kernel crashed between the SQLite commit and the
/// host-side `commit_merge_to_target_ref` returning).
///
/// Backed by the partial index `idx_initiatives_pending_git`
/// (migration 16) so this scan is O(pending) rather than
/// O(initiatives). Boot recovery iterates this list and, for each
/// id, looks up the most recent `IntegrationMergeCompleted` audit
/// event to recover the merge commit SHA + target ref to re-apply.
pub fn pending_git_apply_ids(conn: &RoConn) -> Result<Vec<String>, InitiativeViewError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT initiative_id FROM {} WHERE git_apply_pending = 1 \
         ORDER BY created_at ASC",
        Table::Initiatives.as_str(),
    ))?;
    let rows: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Look up a single initiative by id. Returns `None` when missing.
pub fn by_id(
    conn: &RoConn,
    initiative_id: &str,
) -> Result<Option<InitiativeRow>, InitiativeViewError> {
    let row = conn
        .query_row(
            &format!(
                "SELECT initiative_id, state, plan_artifact_sha256, \
                    created_at, approved_at, completed_at \
             FROM {} WHERE initiative_id = ?1",
                Table::Initiatives.as_str(),
            ),
            rusqlite::params![initiative_id],
            |r| {
                Ok(InitiativeRow {
                    initiative_id: r.get(0)?,
                    state: r.get(1)?,
                    plan_artifact_sha256: r.get(2)?,
                    created_at: r.get::<_, i64>(3)?.max(0) as u64,
                    approved_at: r.get::<_, Option<i64>>(4)?.map(|v| v.max(0) as u64),
                    completed_at: r.get::<_, Option<i64>>(5)?.map(|v| v.max(0) as u64),
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// List initiatives. When `state_filter` is `Some`, restrict to that
/// state. Ordered by `created_at DESC` so the newest initiative
/// appears first in CLI output (operators almost always want "what's
/// been kicked off lately").
pub fn list(
    conn: &RoConn,
    state_filter: Option<&str>,
    limit: usize,
) -> Result<Vec<InitiativeRow>, InitiativeViewError> {
    let mut sql = format!(
        "SELECT initiative_id, state, plan_artifact_sha256, \
                created_at, approved_at, completed_at \
         FROM {}",
        Table::Initiatives.as_str(),
    );
    if state_filter.is_some() {
        sql.push_str(" WHERE state = ?1");
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT ?");
    sql.push_str(if state_filter.is_some() { "2" } else { "1" });

    let mut stmt = conn.prepare(&sql)?;
    let limit_i = limit as i64;
    let rows = if let Some(state) = state_filter {
        stmt.query_map(rusqlite::params![state, limit_i], map_row)?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        stmt.query_map(rusqlite::params![limit_i], map_row)?
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(rows)
}

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<InitiativeRow> {
    Ok(InitiativeRow {
        initiative_id: r.get(0)?,
        state: r.get(1)?,
        plan_artifact_sha256: r.get(2)?,
        created_at: r.get::<_, i64>(3)?.max(0) as u64,
        approved_at: r.get::<_, Option<i64>>(4)?.map(|v| v.max(0) as u64),
        completed_at: r.get::<_, Option<i64>>(5)?.map(|v| v.max(0) as u64),
    })
}

// ────────────────────────────────────────────────────────────────────
// `raxis initiative list` — bucketed list with quarantine join.
//
// Backs cli-readonly.md §5.5.6b. The semantics of each bucket are
// chosen for the operator's recurring at-a-glance question:
//
//   * Active     — "what is currently being worked on?" =
//                  admitted/running states (ApprovedPlan | Executing |
//                  Blocked). Draft plans are not in flight: they have
//                  no approved work and may have no task rows yet.
//   * Recovery   — "what requires operator action before it can make
//                  progress?" = RecoveryRequired only. This is
//                  deliberately not Active because no VM/session should
//                  be running work for it.
//   * Completed  — "what shipped?" = the Completed terminal state
//                  ONLY. Failed / Aborted are deliberately omitted
//                  because the operator's natural follow-up after
//                  "completed" is "tag and announce", which is wrong
//                  for the failure terminals. Power users reach
//                  Failed / Aborted via `--state all` + grep, or
//                  via the forensic `raxis initiative show <id>`.
//   * Quarantined — "what is frozen for security?" = any initiative
//                  with a row in `initiative_quarantines`,
//                  regardless of FSM state. This bucket overlaps
//                  with Active and Completed; it answers an
//                  orthogonal question and must therefore be a
//                  first-class filter.
//   * All        — no WHERE predicate. Newest-first, capped by
//                  `limit`.
//
// EVERY row, regardless of bucket, carries the `quarantined` flag so
// operators reading the Active or All buckets can spot frozen rows
// at a glance.
// ────────────────────────────────────────────────────────────────────

/// Operator-facing bucket for `raxis initiative list --state ...`.
///
/// Modelled as a Rust enum (not a free-form string) so the CLI parser
/// fails-closed on typos and the SQL planner sees a stable predicate
/// shape per bucket. Mirrors `views::escalations::EscalationStatusFilter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiativeListFilter {
    /// Every initiative; no `WHERE` predicate.
    All,
    /// In-flight states: `ApprovedPlan | Executing | Blocked`.
    Active,
    /// Recoverable pause: operator recovery decision required.
    Recovery,
    /// `state = 'Completed'` only — the successful terminal.
    Completed,
    /// Any initiative with a row in `initiative_quarantines`.
    Quarantined,
}

/// The bucketed-list row shape. Wraps [`InitiativeRow`] with the
/// joined `quarantined` flag so a single SQL round-trip answers both
/// "what initiatives match the filter?" and "is each one frozen?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiativeListRow {
    pub initiative: InitiativeRow,
    /// `true` iff a row exists in `initiative_quarantines` for this
    /// `initiative_id`. The CLI surfaces this as a `[Q]` marker (or
    /// `quarantined: true` in JSON) on every row.
    pub quarantined: bool,
}

/// List initiatives matching the given operator-facing bucket,
/// newest-first by `created_at`. Capped at `limit` rows.
///
/// The query LEFT-JOINs `initiative_quarantines` to surface the
/// quarantine flag in a single round-trip. The optional bucket
/// predicate is appended to the same statement so the SQL planner
/// always uses the `idx_initiatives_state` covering index when the
/// filter is `Active` / `Completed`, and the `initiative_quarantines`
/// PRIMARY KEY when the filter is `Quarantined`.
pub fn list_filtered(
    conn: &RoConn,
    filter: InitiativeListFilter,
    limit: usize,
) -> Result<Vec<InitiativeListRow>, InitiativeViewError> {
    let initiatives = Table::Initiatives.as_str();
    let quarantines = Table::InitiativeQuarantines.as_str();

    let where_clause = match filter {
        InitiativeListFilter::All => String::new(),
        InitiativeListFilter::Active => " WHERE i.state IN \
            ('ApprovedPlan', 'Executing', 'Blocked')"
            .to_owned(),
        InitiativeListFilter::Recovery => " WHERE i.state = 'RecoveryRequired'".to_owned(),
        InitiativeListFilter::Completed => " WHERE i.state = 'Completed'".to_owned(),
        InitiativeListFilter::Quarantined => " WHERE q.initiative_id IS NOT NULL".to_owned(),
    };

    let sql = format!(
        "SELECT i.initiative_id, i.state, i.plan_artifact_sha256, \
                i.created_at, i.approved_at, i.completed_at, \
                CASE WHEN q.initiative_id IS NOT NULL THEN 1 ELSE 0 END AS quarantined \
         FROM {initiatives} AS i \
         LEFT JOIN {quarantines} AS q \
                ON q.initiative_id = i.initiative_id\
         {where_clause} \
         ORDER BY i.created_at DESC \
         LIMIT ?1"
    );

    let mut stmt = conn.prepare(&sql)?;
    let limit_i = limit as i64;
    let rows = stmt
        .query_map(rusqlite::params![limit_i], map_list_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ────────────────────────────────────────────────────────────────────
// Write-side helpers for `git_apply_pending` (integration-merge.md
// §11.1). These take a `&rusqlite::Connection` because they are
// invoked from inside an `IMMEDIATE` transaction inside the kernel
// IntegrationMerge handler — Phase 1 sets the flag inside the same
// transaction that records the intent; Phase 3 clears it after the
// host-side fast-forward returns.
//
// They are not on `RoConn` because they mutate. They are not on
// `Store` either because the kernel needs to compose them inside a
// pre-existing transaction. Returning `usize` (rows affected) lets
// the caller assert "exactly one row updated".
// ────────────────────────────────────────────────────────────────────

/// Set `git_apply_pending = 1` for one initiative. Returns the number
/// of rows affected (0 if the initiative does not exist; 1 on
/// success). MUST be called inside the kernel's Phase 1 SQLite
/// transaction so the flag flips atomically with the intent record.
pub fn set_git_apply_pending(
    conn: &rusqlite::Connection,
    initiative_id: &str,
) -> Result<usize, rusqlite::Error> {
    conn.execute(
        &format!(
            "UPDATE {} SET git_apply_pending = 1 WHERE initiative_id = ?1",
            Table::Initiatives.as_str(),
        ),
        rusqlite::params![initiative_id],
    )
}

/// Clear `git_apply_pending` (set to 0) for one initiative. Returns
/// the number of rows affected. Called either:
///   * by the IntegrationMerge handler after the host-side merge
///     succeeds (Phase 3), OR
///   * by boot recovery after the merge is verified or successfully
///     re-applied.
pub fn clear_git_apply_pending(
    conn: &rusqlite::Connection,
    initiative_id: &str,
) -> Result<usize, rusqlite::Error> {
    conn.execute(
        &format!(
            "UPDATE {} SET git_apply_pending = 0 WHERE initiative_id = ?1",
            Table::Initiatives.as_str(),
        ),
        rusqlite::params![initiative_id],
    )
}

fn map_list_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<InitiativeListRow> {
    let initiative = InitiativeRow {
        initiative_id: r.get(0)?,
        state: r.get(1)?,
        plan_artifact_sha256: r.get(2)?,
        created_at: r.get::<_, i64>(3)?.max(0) as u64,
        approved_at: r.get::<_, Option<i64>>(4)?.map(|v| v.max(0) as u64),
        completed_at: r.get::<_, Option<i64>>(5)?.map(|v| v.max(0) as u64),
    };
    let quarantined: i64 = r.get(6)?;
    Ok(InitiativeListRow {
        initiative,
        quarantined: quarantined != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store_with_seed() -> TempDir {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        const INITIATIVES: &str = Table::Initiatives.as_str();
        for (id, state, created) in [
            ("init-old", "Completed", 100_i64),
            ("init-mid", "Executing", 200),
            ("init-fresh", "Draft", 300),
            ("init-recovery", "RecoveryRequired", 225),
            ("init-fail", "Failed", 150),
            ("init-other", "Executing", 250),
        ] {
            guard.execute(
                &format!(
                    "INSERT INTO {INITIATIVES} \
                     (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES (?1, ?2, '{{}}', 'sha-' || ?1, ?3)"
                ),
                rusqlite::params![id, state, created],
            ).unwrap();
        }
        tmp
    }

    /// Like `fresh_store_with_seed` but also seeds two
    /// `initiative_quarantines` rows so the bucketed-list join paths
    /// (`Quarantined`, plus the per-row `quarantined` flag) are
    /// exercised. We pick `init-other` (active) and `init-old`
    /// (terminal) so the Active and Completed buckets each surface
    /// at least one quarantined row, plus the Quarantined bucket
    /// returns exactly the expected two rows.
    fn fresh_store_with_seed_and_quarantines() -> TempDir {
        let tmp = fresh_store_with_seed();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        const QUARANTINES: &str = Table::InitiativeQuarantines.as_str();
        for (id, qa) in [("init-other", 310_i64), ("init-old", 105)] {
            guard
                .execute(
                    &format!(
                        "INSERT INTO {QUARANTINES} \
                     (initiative_id, quarantined_at, quarantined_by, reason) \
                     VALUES (?1, ?2, '00112233445566778899aabbccddeeff', 'test')"
                    ),
                    rusqlite::params![id, qa],
                )
                .unwrap();
        }
        tmp
    }

    #[test]
    fn counts_by_state_aggregates_each_label_independently() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let counts = counts_by_state(&conn).unwrap();
        assert_eq!(counts.executing, 2);
        assert_eq!(counts.draft, 1);
        assert_eq!(counts.completed, 1);
        assert_eq!(counts.recovery_required, 1);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.total, 6);
        assert_eq!(counts.aborted, 0);
    }

    #[test]
    fn by_id_returns_none_for_missing_initiative() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(by_id(&conn, "nope").unwrap().is_none());
    }

    #[test]
    fn by_id_returns_initiative_with_correct_fields() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let row = by_id(&conn, "init-fresh").unwrap().expect("present");
        assert_eq!(row.state, "Draft");
        assert_eq!(row.created_at, 300);
        assert_eq!(row.completed_at, None);
    }

    // ── plan_bundle_sha256_by_id ────────────────────────────────────────

    #[test]
    fn plan_bundle_sha256_by_id_returns_none_for_missing_initiative() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(plan_bundle_sha256_by_id(&conn, "nope").unwrap().is_none());
    }

    #[test]
    fn plan_bundle_sha256_by_id_returns_none_for_v1_initiative() {
        // The seed function inserts every row without `plan_bundle_sha256`
        // (V1 admission path). The accessor MUST NOT confuse that with
        // "missing initiative" — return None for both, but the
        // operator distinguishes via `by_id` paired with this helper.
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(plan_bundle_sha256_by_id(&conn, "init-fresh")
            .unwrap()
            .is_none());
    }

    #[test]
    fn plan_bundle_sha256_by_id_round_trips_a_v2_admission_blob() {
        // Insert one V2-shaped initiative directly (no kernel admission
        // dependency in this view crate) and confirm the BLOB
        // round-trips into a typed BundleSha256. The DDL puts a FK
        // from `initiatives.plan_bundle_sha256` onto `plan_bundles`,
        // so the test seeds the parent row first via the typed
        // helpers in `crate::plan_bundles`.
        let tmp = TempDir::new().unwrap();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let bundle_sha_arr = [0xABu8; 32];
        let bundle_sha = raxis_types::BundleSha256::new(bundle_sha_arr);
        let bundle = raxis_types::PlanBundle::new_v2_1(
            100,
            200,
            raxis_types::BundleNonce::new([0xCDu8; 16]),
            "myplan".to_owned(),
            vec![raxis_types::BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: b"[orchestrator]\n".to_vec(),
                sha256: {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(b"[orchestrator]\n");
                    raxis_types::BundleSha256::new(h.finalize().into())
                },
            }],
        );
        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            crate::plan_bundles::insert_bundle(
                &tx,
                &bundle_sha,
                b"placeholder-canonical-bytes",
                &[0x77u8; 64],
                &raxis_types::OperatorFingerprint::new([0x88u8; 8]),
                &bundle,
                1_700_000_999,
            )
            .unwrap();
            crate::plan_bundles::insert_artifacts(&tx, &bundle_sha, &bundle.artifacts).unwrap();
            const INITIATIVES: &str = Table::Initiatives.as_str();
            tx.execute(
                &format!(
                    "INSERT INTO {INITIATIVES} \
                     (initiative_id, state, terminal_criteria_json, \
                      plan_artifact_sha256, plan_bundle_sha256, created_at) \
                     VALUES ('init-v2', 'Draft', '{{}}', 'fallback-sha', ?1, 1700000000)"
                ),
                rusqlite::params![bundle_sha_arr.as_slice()],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let conn = open_ro(tmp.path()).unwrap();
        let sha = plan_bundle_sha256_by_id(&conn, "init-v2")
            .unwrap()
            .expect("V2 bundle sha should round-trip");
        assert_eq!(sha.as_bytes(), &[0xABu8; 32]);
    }

    #[test]
    fn list_orders_by_created_at_descending() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, None, 10).unwrap();
        let ids: Vec<&str> = rows.iter().map(|r| r.initiative_id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "init-fresh",
                "init-other",
                "init-recovery",
                "init-mid",
                "init-fail",
                "init-old"
            ]
        );
    }

    #[test]
    fn list_filters_by_state_when_requested() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, Some("Executing"), 10).unwrap();
        assert_eq!(rows.len(), 2);
        // Newest-first inside the filter too.
        assert_eq!(rows[0].initiative_id, "init-other");
        assert_eq!(rows[1].initiative_id, "init-mid");
    }

    // ── list_filtered: bucketed list backing `raxis initiative list` ────

    #[test]
    fn list_filtered_all_returns_every_row_newest_first() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_filtered(&conn, InitiativeListFilter::All, 10).unwrap();
        let ids: Vec<&str> = rows
            .iter()
            .map(|r| r.initiative.initiative_id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec![
                "init-fresh",
                "init-other",
                "init-recovery",
                "init-mid",
                "init-fail",
                "init-old"
            ]
        );
        assert!(
            rows.iter().all(|r| !r.quarantined),
            "no quarantine rows seeded => every row.quarantined must be false"
        );
    }

    #[test]
    fn list_filtered_active_omits_terminal_states() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_filtered(&conn, InitiativeListFilter::Active, 10).unwrap();
        let ids: Vec<&str> = rows
            .iter()
            .map(|r| r.initiative.initiative_id.as_str())
            .collect();
        // Active = ApprovedPlan + Executing + Blocked. Seed has one
        // Draft (init-fresh) and RecoveryRequired (init-recovery) are
        // intentionally omitted because neither is in flight, plus two
        // Executing rows and terminal Completed / Failed rows.
        assert_eq!(ids, vec!["init-other", "init-mid"]);
    }

    #[test]
    fn list_filtered_recovery_returns_only_recovery_required_rows() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_filtered(&conn, InitiativeListFilter::Recovery, 10).unwrap();
        let ids: Vec<&str> = rows
            .iter()
            .map(|r| r.initiative.initiative_id.as_str())
            .collect();
        assert_eq!(ids, vec!["init-recovery"]);
    }

    #[test]
    fn list_filtered_completed_only_returns_the_completed_terminal() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_filtered(&conn, InitiativeListFilter::Completed, 10).unwrap();
        let ids: Vec<&str> = rows
            .iter()
            .map(|r| r.initiative.initiative_id.as_str())
            .collect();
        // `Failed` and `Aborted` MUST NOT leak into the Completed bucket.
        // The semantic is "what shipped", not "what ended".
        assert_eq!(ids, vec!["init-old"]);
    }

    #[test]
    fn list_filtered_quarantined_returns_only_quarantined_rows() {
        let tmp = fresh_store_with_seed_and_quarantines();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_filtered(&conn, InitiativeListFilter::Quarantined, 10).unwrap();
        let ids: Vec<&str> = rows
            .iter()
            .map(|r| r.initiative.initiative_id.as_str())
            .collect();
        assert_eq!(ids, vec!["init-other", "init-old"]);
        assert!(
            rows.iter().all(|r| r.quarantined),
            "every row of the Quarantined bucket MUST carry quarantined=true"
        );
    }

    #[test]
    fn list_filtered_active_surfaces_quarantine_flag_on_overlap() {
        // `init-other` is Executing (active) AND quarantined — the
        // bucket is "active", but the per-row flag MUST be true so the
        // CLI can render `[Q]` on the row.
        let tmp = fresh_store_with_seed_and_quarantines();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_filtered(&conn, InitiativeListFilter::Active, 10).unwrap();
        let other = rows
            .iter()
            .find(|r| r.initiative.initiative_id == "init-other")
            .expect("init-other must appear in the Active bucket");
        assert!(
            other.quarantined,
            "Active row MUST surface quarantined=true when overlap holds"
        );
        let mid = rows
            .iter()
            .find(|r| r.initiative.initiative_id == "init-mid")
            .expect("init-mid must appear in the Active bucket");
        assert!(
            !mid.quarantined,
            "non-quarantined Active row MUST surface quarantined=false"
        );
    }

    #[test]
    fn list_filtered_respects_limit() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_filtered(&conn, InitiativeListFilter::All, 2).unwrap();
        assert_eq!(rows.len(), 2);
        // Newest-first ordering MUST hold under LIMIT — never random.
        assert_eq!(rows[0].initiative.initiative_id, "init-fresh");
        assert_eq!(rows[1].initiative.initiative_id, "init-other");
    }

    // ── git_apply_pending: read + write helpers ─────────────────────────

    #[test]
    fn git_apply_pending_returns_false_for_fresh_initiative() {
        // A newly-inserted initiative has the migration-16 default
        // `git_apply_pending = 0` and so the read helper returns false.
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(!git_apply_pending(&conn, "init-fresh").unwrap());
    }

    #[test]
    fn git_apply_pending_returns_false_for_missing_initiative() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        // Recovery scan must not blow up on missing rows; the
        // pre-flight check treats missing-as-not-pending so the
        // outer FK / existence check stays the source of truth for
        // "initiative exists".
        assert!(!git_apply_pending(&conn, "no-such-init").unwrap());
    }

    #[test]
    fn set_then_read_then_clear_then_read_round_trips() {
        let tmp = fresh_store_with_seed();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();

        // Set inside an IMMEDIATE transaction, mimicking the kernel's
        // Phase 1 commit shape.
        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            assert_eq!(set_git_apply_pending(&tx, "init-mid").unwrap(), 1);
            tx.commit().unwrap();
        }

        let ro = open_ro(tmp.path()).unwrap();
        assert!(git_apply_pending(&ro, "init-mid").unwrap());

        // Clear (Phase 3 / recovery success).
        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            assert_eq!(clear_git_apply_pending(&tx, "init-mid").unwrap(), 1);
            tx.commit().unwrap();
        }

        let ro = open_ro(tmp.path()).unwrap();
        assert!(!git_apply_pending(&ro, "init-mid").unwrap());
    }

    #[test]
    fn pending_git_apply_ids_returns_only_flagged_rows_oldest_first() {
        let tmp = fresh_store_with_seed();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();

        // Flip two of the seeded initiatives to pending. Their
        // `created_at` order is init-old=100, init-mid=200, so the
        // recovery scan returns them in that order regardless of
        // the order we set the flag.
        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            assert_eq!(set_git_apply_pending(&tx, "init-mid").unwrap(), 1);
            assert_eq!(set_git_apply_pending(&tx, "init-old").unwrap(), 1);
            tx.commit().unwrap();
        }

        let ro = open_ro(tmp.path()).unwrap();
        let ids = pending_git_apply_ids(&ro).unwrap();
        assert_eq!(ids, vec!["init-old", "init-mid"]);
    }

    #[test]
    fn set_git_apply_pending_returns_zero_rows_for_missing_initiative() {
        // The kernel asserts on the rows-affected count to surface a
        // bug that would otherwise silently lose the flag (e.g. the
        // initiative was concurrently deleted). Confirm the helper
        // really does return 0 in that case rather than masking it.
        let tmp = fresh_store_with_seed();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let mut conn = store.lock_sync();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(set_git_apply_pending(&tx, "no-such-init").unwrap(), 0);
    }

    #[test]
    fn list_filtered_returns_empty_when_no_match() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        // No quarantine rows seeded => Quarantined bucket is empty.
        let rows = list_filtered(&conn, InitiativeListFilter::Quarantined, 10).unwrap();
        assert!(
            rows.is_empty(),
            "Quarantined bucket MUST be empty when no rows; got {rows:?}"
        );
    }
}
