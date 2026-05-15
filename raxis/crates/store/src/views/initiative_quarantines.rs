//! Initiative-quarantine view-table: typed reads + writers used by the
//! operator IPC handlers `QuarantineInitiative` and
//! `QuarantinePlansBy`, and by the planner intent gate that rejects
//! `IntentRequest`s against quarantined initiatives with
//! `FAIL_INITIATIVE_QUARANTINED`.
//!
//! Normative reference (forthcoming): kernel-store.md §2.5.8
//! "Initiative quarantine" (added in step 12).
//!
//! # Module shape
//!
//! Matches `views::operator_certificates`: this module exposes BOTH
//! readers (which take `&RoConn`) AND writers (which take a write
//! `&Connection` and run inside a transaction the caller opened). The
//! readers are the planner-side fast-path (`is_quarantined`); the
//! writers are the operator command handlers (`insert_single`,
//! `sweep_for_operator`).
//!
//! # Atomicity contract
//!
//! `sweep_for_operator` MUST run inside a `BEGIN EXCLUSIVE`
//! transaction the caller opened: a sweep that inserts N rows must
//! either commit all of them (every collateral initiative is
//! quarantined) or none (the operator sees the typed error and can
//! retry without partial state). The single-initiative
//! `insert_single` is atomic in the sqlite-statement sense; callers
//! still wrap it in a transaction so the audit-event emission can
//! join the same `BEGIN/COMMIT` window per kernel-store.md §2.5.2
//! "audit-after-commit" rule.
//!
//! Quarantine is APPEND-ONLY in v1: there is no `delete()` writer
//! exposed here. The operator recovers from a false-positive
//! quarantine by aborting the initiative entirely (the abort path
//! already exists; the quarantine row stays as the audit trail of
//! the original decision).

use rusqlite::{params, Connection};
use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

// ---------------------------------------------------------------------------
// InitiativeQuarantineRow — one denormalised row.
// ---------------------------------------------------------------------------

/// Typed read-side row of `initiative_quarantines`. Mirrors the
/// migration-3 column shape exactly. Returned by
/// [`get_by_initiative_id`] and [`list_all`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiativeQuarantineRow {
    pub initiative_id: String,
    pub quarantined_at: i64,
    /// Operator pubkey_fingerprint that issued the command; 32 hex
    /// chars (`SHA-256[:16]` of the operator's Ed25519 pubkey, per
    /// peripherals.md §3 'operator socket').
    pub quarantined_by: String,
    /// Free-form operator-supplied label; capped to 512 bytes by the
    /// CLI before submission.
    pub reason: Option<String>,
    /// `Some(fingerprint)` ⇒ this row was inserted as collateral by
    /// `sweep_for_operator` for the named operator. `None` ⇒
    /// individually quarantined via `insert_single`.
    pub sweep_target: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum QuarantineViewError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

// ---------------------------------------------------------------------------
// Reads (RoConn)
// ---------------------------------------------------------------------------

const SELECT_ALL_COLS: &str = "initiative_id, quarantined_at, quarantined_by, reason, sweep_target";

fn row_to_quarantine_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<InitiativeQuarantineRow> {
    Ok(InitiativeQuarantineRow {
        initiative_id: row.get::<_, String>(0)?,
        quarantined_at: row.get::<_, i64>(1)?,
        quarantined_by: row.get::<_, String>(2)?,
        reason: row.get::<_, Option<String>>(3)?,
        sweep_target: row.get::<_, Option<String>>(4)?,
    })
}

fn collect_rows<I>(rows: I) -> Result<Vec<InitiativeQuarantineRow>, QuarantineViewError>
where
    I: Iterator<Item = rusqlite::Result<InitiativeQuarantineRow>>,
{
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Hot-path predicate: is `initiative_id` quarantined? Used by the
/// planner intent gate before any heavy admission work.
///
/// Returns `Ok(true)` when there is a row, `Ok(false)` when there
/// isn't. `Err` on a real sqlite error (corruption, etc.) — callers
/// MUST treat the error as "fail-safe deny" rather than "no
/// quarantine" so a transient DB hiccup never silently re-opens a
/// frozen initiative to writes.
pub fn is_quarantined(conn: &RoConn, initiative_id: &str) -> Result<bool, QuarantineViewError> {
    let table = Table::InitiativeQuarantines.as_str();
    let n: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE initiative_id = ?1"),
        params![initiative_id],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Same predicate but on a write `&Connection` — used by the
/// `QuarantineInitiative` handler to make the insert idempotent
/// (a no-op when the initiative is already quarantined). Mirrors
/// `is_quarantined` exactly so a future schema change touches one
/// SQL string in two callers.
pub fn is_quarantined_rw(
    conn: &Connection,
    initiative_id: &str,
) -> Result<bool, QuarantineViewError> {
    let table = Table::InitiativeQuarantines.as_str();
    let n: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE initiative_id = ?1"),
        params![initiative_id],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Fetch a single row by initiative_id (for `raxis inspect` and
/// future doctor surfaces).
pub fn get_by_initiative_id(
    conn: &RoConn,
    initiative_id: &str,
) -> Result<Option<InitiativeQuarantineRow>, QuarantineViewError> {
    let table = Table::InitiativeQuarantines.as_str();
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_ALL_COLS} FROM {table} WHERE initiative_id = ?1"
    ))?;
    let mapped = stmt.query_map(params![initiative_id], row_to_quarantine_row)?;
    let rows = collect_rows(mapped)?;
    Ok(rows.into_iter().next())
}

/// All quarantine rows, ordered by `quarantined_at DESC` (newest
/// first — matches the operator's `raxis inspect` mental model of
/// "what got quarantined recently?").
pub fn list_all(conn: &RoConn) -> Result<Vec<InitiativeQuarantineRow>, QuarantineViewError> {
    let table = Table::InitiativeQuarantines.as_str();
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_ALL_COLS} FROM {table} ORDER BY quarantined_at DESC"
    ))?;
    let mapped = stmt.query_map([], row_to_quarantine_row)?;
    collect_rows(mapped)
}

// ---------------------------------------------------------------------------
// Writes (raw &Connection)
// ---------------------------------------------------------------------------

/// Insert a single quarantine row. Idempotent: if a row already
/// exists for `initiative_id`, returns `Ok(false)` (the caller
/// suppresses the audit-event emission). Returns `Ok(true)` on a
/// fresh insert.
///
/// Caller MUST hold a write transaction. The sole caller in the
/// kernel is `handle_quarantine_initiative` in
/// `kernel/src/ipc/operator.rs`.
pub fn insert_single(
    conn: &Connection,
    initiative_id: &str,
    quarantined_by: &str,
    quarantined_at: i64,
    reason: Option<&str>,
) -> Result<bool, QuarantineViewError> {
    if is_quarantined_rw(conn, initiative_id)? {
        return Ok(false);
    }
    let table = Table::InitiativeQuarantines.as_str();
    conn.execute(
        &format!(
            "INSERT INTO {table}
                 (initiative_id, quarantined_at, quarantined_by, reason, sweep_target)
             VALUES (?1, ?2, ?3, ?4, NULL)"
        ),
        params![initiative_id, quarantined_at, quarantined_by, reason],
    )?;
    Ok(true)
}

/// Sweep every initiative whose plan was approved by
/// `target_fingerprint` and quarantine each one. Returns the list of
/// newly-quarantined initiative_ids (i.e. those that were NOT already
/// quarantined). The caller emits one `InitiativeQuarantined` audit
/// event per id and one rollup `OperatorQuarantineSwept` event with
/// the count.
///
/// The match join goes through
/// `signed_plan_artifacts.signed_by_fingerprint` — populated by the
/// kernel's `lifecycle::approve_plan` (added in migration 3).
/// Initiatives whose plan predates migration 3 carry NULL there; they
/// are silently skipped because the sweep can't prove who approved
/// them. The audit-chain entries from those approvals remain the
/// authoritative record for the operator to consult by hand.
///
/// Initiatives without ANY signed plan (e.g. plans uploaded but never
/// approved) cannot be implicated by this sweep because they have no
/// `signed_plan_artifacts` row; v1 keeps the contract narrow to
/// "plans that were actually approved".
pub fn sweep_for_operator(
    conn: &Connection,
    target_fingerprint: &str,
    quarantined_by: &str,
    quarantined_at: i64,
    reason: Option<&str>,
) -> Result<Vec<String>, QuarantineViewError> {
    let initiatives = Table::Initiatives.as_str();
    let signed_plans = Table::SignedPlanArtifacts.as_str();
    let quarantines = Table::InitiativeQuarantines.as_str();

    // Step 1: gather candidate initiative_ids. We materialise into a
    // Vec<String> rather than driving the INSERT off the SELECT
    // because the same connection cannot have a live SELECT statement
    // and an INSERT cursor open at the same time on this table.
    let mut stmt = conn.prepare(&format!(
        "SELECT i.initiative_id
           FROM {initiatives}        AS i
           JOIN {signed_plans}       AS p ON p.initiative_id = i.initiative_id
          WHERE p.signed_by_fingerprint = ?1"
    ))?;
    let candidates: Vec<String> = stmt
        .query_map(params![target_fingerprint], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt); // release the read borrow before INSERTing.

    // Step 2: insert one row per candidate, skipping any already
    // quarantined. Each insert sets `sweep_target = target_fingerprint`
    // so the row's provenance is queryable later (via
    // `idx_initiative_quarantines_sweep_target`).
    let mut newly_quarantined = Vec::new();
    for initiative_id in &candidates {
        if is_quarantined_rw(conn, initiative_id)? {
            continue;
        }
        conn.execute(
            &format!(
                "INSERT INTO {quarantines}
                     (initiative_id, quarantined_at, quarantined_by,
                      reason, sweep_target)
                 VALUES (?1, ?2, ?3, ?4, ?5)"
            ),
            params![
                initiative_id,
                quarantined_at,
                quarantined_by,
                reason,
                target_fingerprint,
            ],
        )?;
        newly_quarantined.push(initiative_id.clone());
    }
    Ok(newly_quarantined)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// The reader functions take `&RoConn`; we create one via `open_ro`
// against the real on-disk `kernel.db` after the writer (which uses
// `&Connection` from `Store::lock_sync`) has committed. Mirrors the
// pattern in `views::operator_certificates::tests`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store_with_initiatives() -> TempDir {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("kernel.db");
        let store = Store::open(&db_path).expect("Store::open");
        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        // Two initiatives signed by Chika, one by Jinanwa. Minimum shape
        // the sweep query joins against.
        const INITIATIVES: &str = Table::Initiatives.as_str();
        const SIGNED_PLAN_ARTIFACTS: &str = Table::SignedPlanArtifacts.as_str();
        tx.execute_batch(&format!(
            "INSERT INTO {INITIATIVES} \
                (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
             VALUES \
                ('init-chika-1', 'Draft', '{{}}', 'aa', 0), \
                ('init-chika-2', 'Draft', '{{}}', 'aa', 0), \
                ('init-jinanwa-1',   'Draft', '{{}}', 'bb', 0); \
             INSERT INTO {SIGNED_PLAN_ARTIFACTS} \
                (initiative_id, plan_bytes, plan_sig, stored_at, signed_by_fingerprint) \
             VALUES \
                ('init-chika-1', x'00', x'00', 0, 'chika-fp'), \
                ('init-chika-2', x'00', x'00', 0, 'chika-fp'), \
                ('init-jinanwa-1',   x'00', x'00', 0, 'jinanwa-fp');"
        ))
        .unwrap();
        tx.commit().unwrap();
        drop(conn);
        drop(store);
        tmp
    }

    fn with_writer<F, R>(tmp: &TempDir, f: F) -> R
    where
        F: FnOnce(&Connection) -> R,
    {
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let conn = store.lock_sync();
        let r = f(&conn);
        drop(conn);
        drop(store);
        r
    }

    #[test]
    fn fresh_db_has_no_quarantines() {
        let tmp = fresh_store_with_initiatives();
        let ro = open_ro(tmp.path()).unwrap();
        assert!(list_all(&ro).unwrap().is_empty());
        assert!(!is_quarantined(&ro, "init-chika-1").unwrap());
        assert!(get_by_initiative_id(&ro, "init-chika-1").unwrap().is_none());
    }

    #[test]
    fn insert_single_writes_a_row_and_is_idempotent() {
        let tmp = fresh_store_with_initiatives();

        let was_new = with_writer(&tmp, |c| {
            insert_single(c, "init-chika-1", "op-fp", 1700, Some("compromised")).unwrap()
        });
        assert!(was_new);

        let ro = open_ro(tmp.path()).unwrap();
        assert!(is_quarantined(&ro, "init-chika-1").unwrap());

        // Second insert MUST be a no-op (returns false) and MUST NOT
        // overwrite the original row.
        let was_new = with_writer(&tmp, |c| {
            insert_single(c, "init-chika-1", "different-op", 9999, Some("other")).unwrap()
        });
        assert!(!was_new);
        let ro = open_ro(tmp.path()).unwrap();
        let row = get_by_initiative_id(&ro, "init-chika-1").unwrap().unwrap();
        assert_eq!(row.quarantined_by, "op-fp");
        assert_eq!(row.quarantined_at, 1700);
        assert_eq!(row.reason.as_deref(), Some("compromised"));
        assert!(
            row.sweep_target.is_none(),
            "single insert leaves sweep_target NULL"
        );
    }

    #[test]
    fn sweep_for_operator_quarantines_every_matching_initiative() {
        let tmp = fresh_store_with_initiatives();
        let newly = with_writer(&tmp, |c| {
            sweep_for_operator(c, "chika-fp", "rotator-fp", 2000, Some("compromised key")).unwrap()
        });
        assert_eq!(newly.len(), 2);
        assert!(newly.iter().any(|s| s == "init-chika-1"));
        assert!(newly.iter().any(|s| s == "init-chika-2"));

        let ro = open_ro(tmp.path()).unwrap();
        assert!(!is_quarantined(&ro, "init-jinanwa-1").unwrap());
        let row = get_by_initiative_id(&ro, "init-chika-1").unwrap().unwrap();
        assert_eq!(row.sweep_target.as_deref(), Some("chika-fp"));
        assert_eq!(row.quarantined_by, "rotator-fp");

        // Re-running the sweep against the same operator returns an
        // empty newly-quarantined list (idempotent).
        let again = with_writer(&tmp, |c| {
            sweep_for_operator(c, "chika-fp", "rotator-fp", 3000, None).unwrap()
        });
        assert!(
            again.is_empty(),
            "sweep is idempotent over already-quarantined ids"
        );
    }

    #[test]
    fn sweep_for_operator_with_no_matching_plans_returns_empty() {
        let tmp = fresh_store_with_initiatives();
        let newly = with_writer(&tmp, |c| {
            sweep_for_operator(c, "ghost-fp", "rotator-fp", 2000, None).unwrap()
        });
        assert!(newly.is_empty());
        let ro = open_ro(tmp.path()).unwrap();
        assert!(list_all(&ro).unwrap().is_empty());
    }

    #[test]
    fn list_all_returns_rows_newest_first() {
        let tmp = fresh_store_with_initiatives();
        with_writer(&tmp, |c| {
            insert_single(c, "init-chika-1", "op-fp", 100, None).unwrap();
            insert_single(c, "init-chika-2", "op-fp", 999, None).unwrap();
        });
        let ro = open_ro(tmp.path()).unwrap();
        let rows = list_all(&ro).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].initiative_id, "init-chika-2"); // newest first
        assert_eq!(rows[1].initiative_id, "init-chika-1");
    }

    #[test]
    fn is_quarantined_after_a_sweep_returns_true_for_swept_targets() {
        let tmp = fresh_store_with_initiatives();
        with_writer(&tmp, |c| {
            sweep_for_operator(c, "chika-fp", "rotator-fp", 5000, None).unwrap();
        });
        let ro = open_ro(tmp.path()).unwrap();
        assert!(is_quarantined(&ro, "init-chika-1").unwrap());
        assert!(is_quarantined(&ro, "init-chika-2").unwrap());
        assert!(!is_quarantined(&ro, "init-jinanwa-1").unwrap());
    }
}
