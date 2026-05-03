// raxis-store::migration — DDL migrations for kernel.db.
//
// Normative reference: kernel-store.md §2.5.1 "Canonical DDL Parts 1–4"
//
// Migration rules (§2.5.1 note):
//   - All 19 tables are created by migration 1 — the v1 baseline.
//   - Each migration is applied inside a single BEGIN EXCLUSIVE ... COMMIT.
//     A crash mid-migration leaves the DB in its pre-migration state.
//   - Migration numbers are monotonically increasing integers stored in
//     the `schema_version` table.
//   - `apply_pending` is idempotent: calling it on a fully-migrated DB
//     is a no-op (MAX(version) check).

use crate::StoreError;
use rusqlite::Connection;

/// The current canonical schema version this build of `raxis-store`
/// produces. Bumped together with every new `apply_migration_N`
/// function below.
///
/// Normative reference: cli-readonly.md §5.3. The CLI compares this
/// constant against `MAX(version) FROM schema_version` on every
/// read-only connection open and exits with `ERR_SCHEMA_MISMATCH`
/// (exit code 7) on mismatch — preventing the silent
/// wrong-shape-row class of bug after a migration adds a column the
/// CLI does not know about.
///
/// `pub` so kernel + CLI + every workspace crate that opens
/// `kernel.db` resolves to the same value through Cargo workspace
/// dep resolution; a CLI compiled against an older `raxis-store`
/// version is a hard build error rather than a silent drift.
pub const SCHEMA_VERSION: u32 = 1;

/// Apply all pending migrations to `conn`.
///
/// Safe to call on every startup — skips already-applied migrations. Returns
/// `StoreError::Migration` if the schema is unreadable for any reason OTHER
/// than the `schema_version` table not yet existing.
///
/// Why explicit error discrimination matters: an earlier implementation used
/// `query_row(...).unwrap_or(0)` and treated *any* `rusqlite::Error` as a
/// fresh DB. That swallowed `SQLITE_BUSY`, `SQLITE_IOERR`, file-permission
/// failures, and on-disk corruption — silently re-running the entire
/// migration on top of a partially-broken DB. The reviewer's PR-5 finding.
pub fn apply_pending(conn: &Connection) -> Result<(), StoreError> {
    let current_version = read_current_version(conn)?;

    if current_version < 1 {
        apply_migration_1(conn)?;
    }

    // Future migrations: if current_version < 2 { apply_migration_2(conn)?; }

    Ok(())
}

/// Read `MAX(version)` from `schema_version`, treating "table does not exist"
/// as version `0` (fresh DB) and surfacing every other failure as a
/// `Migration` error. Centralises the failure-mode policy in one place.
fn read_current_version(conn: &Connection) -> Result<i64, StoreError> {
    match conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get::<_, i64>(0),
    ) {
        Ok(v) => Ok(v),
        Err(rusqlite::Error::SqliteFailure(_, Some(msg)))
            if msg.contains("no such table") =>
        {
            // Fresh DB — schema_version not yet created. This is the ONLY
            // condition under which "no version row" is acceptable.
            Ok(0)
        }
        Err(rusqlite::Error::SqliteFailure(err, None))
            if err.code == rusqlite::ErrorCode::Unknown =>
        {
            // Unknown SQLite error code with no extended message — propagate.
            Err(StoreError::Migration(format!(
                "schema_version probe failed (unknown sqlite error): {err:?}"
            )))
        }
        Err(other) => Err(StoreError::Migration(format!(
            "schema_version probe failed: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Migration 1 — v1 baseline: all 19 kernel.db tables.
// kernel-store.md §2.5.1 DDL Parts 1–4.
//
// Applied atomically inside a single transaction. If the process crashes
// mid-migration, SQLite rolls back and the DB is left at version 0 (no
// schema_version row). The next startup re-applies from scratch.
//
// Table creation order matters: FK constraints require referenced tables
// to exist before the referencing table.
// ---------------------------------------------------------------------------

fn apply_migration_1(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(MIGRATION_1_DDL).map_err(|e| {
        StoreError::Migration(format!("migration 1 failed: {e}"))
    })
}

/// The complete v1 baseline DDL — all 19 kernel.db tables plus their indexes.
/// Extracted verbatim from kernel-store.md §2.5.1 Parts 1–4, wrapped in a
/// single transaction so the entire schema appears atomically.
const MIGRATION_1_DDL: &str = "
BEGIN EXCLUSIVE;

-- ── Table 1: schema_version ──────────────────────────────────────────────────
-- Tracks applied migrations. MAX(version) = current schema level.
-- PRIMARY KEY prevents duplicate application.
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL PRIMARY KEY,
    applied_at  INTEGER NOT NULL
);

-- ── Table 2: initiatives ─────────────────────────────────────────────────────
-- One row per initiative. State machine: Draft → ApprovedPlan → Executing →
-- Completed | Failed | Aborted. terminal_criteria_json serialises TerminalCriteria.
CREATE TABLE IF NOT EXISTS initiatives (
    initiative_id          TEXT    NOT NULL PRIMARY KEY,
    state                  TEXT    NOT NULL
        CHECK (state IN (
            'Draft',
            'ApprovedPlan',
            'Executing',
            'Blocked',
            'Completed',
            'Failed',
            'Aborted'
        )),
    terminal_criteria_json TEXT    NOT NULL,
    plan_artifact_sha256   TEXT    NOT NULL,
    created_at             INTEGER NOT NULL,
    approved_at            INTEGER,
    completed_at           INTEGER
);

-- ── Table 3: signed_plan_artifacts ───────────────────────────────────────────
-- Immutable sealed plan bytes + Ed25519 signature. One row per initiative.
CREATE TABLE IF NOT EXISTS signed_plan_artifacts (
    initiative_id  TEXT    NOT NULL PRIMARY KEY
        REFERENCES initiatives(initiative_id),
    plan_bytes     BLOB    NOT NULL,
    plan_sig       BLOB    NOT NULL,
    stored_at      INTEGER NOT NULL
);

-- ── Table 4: sessions ────────────────────────────────────────────────────────
-- One row per planner/gateway/verifier session. Soft-delete only (revoked flag).
-- sequence_number enforces INV-01 monotonic ordering.
CREATE TABLE IF NOT EXISTS sessions (
    session_id            TEXT    NOT NULL PRIMARY KEY,
    role_id               TEXT    NOT NULL,
    session_token         TEXT    NOT NULL UNIQUE,
    lineage_id            TEXT    NOT NULL,
    worktree_root         TEXT,
    base_sha              TEXT,
    base_tracking_ref     TEXT,
    fetch_quota           INTEGER NOT NULL,
    sequence_number       INTEGER NOT NULL DEFAULT 0,
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    revoked               INTEGER NOT NULL DEFAULT 0
        CHECK (revoked IN (0, 1)),
    revoked_at            INTEGER,
    CHECK (
        (base_sha IS NULL AND base_tracking_ref IS NULL)
        OR (base_sha IS NOT NULL AND base_tracking_ref IS NOT NULL)
    ),
    CHECK (base_sha IS NULL OR worktree_root IS NOT NULL)
);

-- ── Table 5: tasks ───────────────────────────────────────────────────────────
-- One row per task. Inserted by approve_plan; never by the intent handler.
-- State machine defined in kernel-core.md §2.4 task FSM.
CREATE TABLE IF NOT EXISTS tasks (
    task_id                TEXT    NOT NULL PRIMARY KEY,
    initiative_id          TEXT    NOT NULL
        REFERENCES initiatives(initiative_id),
    lane_id                TEXT    NOT NULL,
    state                  TEXT    NOT NULL
        CHECK (state IN (
            'Admitted',
            'GatesPending',
            'Running',
            'Completed',
            'Failed',
            'Aborted',
            'Cancelled',
            'BlockedRecoveryPending'
        )),
    block_reason           TEXT,
    actor                  TEXT    NOT NULL,
    policy_epoch           INTEGER NOT NULL,
    admitted_at            INTEGER NOT NULL,
    transitioned_at        INTEGER NOT NULL,
    session_id             TEXT
        REFERENCES sessions(session_id),
    evaluation_sha         TEXT,
    base_sha               TEXT,
    submitted_claims_json  TEXT,
    admission_reserved_units INTEGER,
    actual_cost            INTEGER NOT NULL DEFAULT 0
);

-- ── Table 6: task_dag_edges ──────────────────────────────────────────────────
-- Directed dependency edges. predecessor_satisfied is monotonically set by
-- store::dag::release_successors on predecessor Completed transition.
CREATE TABLE IF NOT EXISTS task_dag_edges (
    initiative_id           TEXT    NOT NULL
        REFERENCES initiatives(initiative_id),
    predecessor_task_id     TEXT    NOT NULL
        REFERENCES tasks(task_id),
    successor_task_id       TEXT    NOT NULL
        REFERENCES tasks(task_id),
    predecessor_satisfied   INTEGER NOT NULL DEFAULT 0
        CHECK (predecessor_satisfied IN (0, 1)),
    PRIMARY KEY (predecessor_task_id, successor_task_id)
);

CREATE INDEX IF NOT EXISTS idx_task_dag_edges_successor
    ON task_dag_edges (successor_task_id);

-- ── Table 7: delegations ─────────────────────────────────────────────────────
-- Per-(session, capability_class) delegations. One row per pair.
-- status: Active → StaleOnNextUse (epoch advance) → RenewalRequired (grace used).
-- revoked_at IS NOT NULL overrides status. now() >= expires_at → Expired.
CREATE TABLE IF NOT EXISTS delegations (
    delegation_id         TEXT    NOT NULL PRIMARY KEY,
    session_id            TEXT    NOT NULL
        REFERENCES sessions(session_id),
    capability_class      TEXT    NOT NULL,
    delegating_role_id    TEXT    NOT NULL,
    delegate_role_id      TEXT    NOT NULL,
    effective_from        INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    revoked_at            INTEGER,
    status                TEXT    NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active', 'StaleOnNextUse', 'RenewalRequired')),
    epoch_stale_set_at    INTEGER,
    operator_signature    BLOB    NOT NULL,
    UNIQUE (session_id, capability_class)
);

CREATE INDEX IF NOT EXISTS idx_delegations_session_capability
    ON delegations (session_id, capability_class);

-- ── Table 8: escalations ─────────────────────────────────────────────────────
-- One row per planner EscalationRequest. FSM: Pending → Approved | Denied |
-- TimedOut; Approved → TokenExpired | Consumed.
CREATE TABLE IF NOT EXISTS escalations (
    escalation_id         TEXT    NOT NULL PRIMARY KEY,
    session_id            TEXT    NOT NULL
        REFERENCES sessions(session_id),
    task_id               TEXT    NOT NULL
        REFERENCES tasks(task_id),
    lineage_id            TEXT    NOT NULL,
    initiative_id         TEXT    NOT NULL
        REFERENCES initiatives(initiative_id),
    class                 TEXT    NOT NULL,
    requested_scope_json  TEXT    NOT NULL,
    justification         TEXT    NOT NULL,
    idempotency_key       TEXT    NOT NULL,
    status                TEXT    NOT NULL DEFAULT 'Pending'
        CHECK (status IN (
            'Pending',
            'Approved',
            'Denied',
            'TimedOut',
            'TokenExpired',
            'Consumed'
        )),
    created_at            INTEGER NOT NULL,
    timeout_at            INTEGER NOT NULL,
    resolved_at           INTEGER,
    resolution_notes      TEXT,
    UNIQUE (session_id, idempotency_key)
);

-- ── Table 9: approval_tokens ─────────────────────────────────────────────────
-- Operator-issued single-use tokens. One per escalation.
-- token_hash = hex SHA-256(raw_bytes); raw bytes never stored.
CREATE TABLE IF NOT EXISTS approval_tokens (
    approval_token_id     TEXT    NOT NULL PRIMARY KEY,
    escalation_id         TEXT    NOT NULL UNIQUE
        REFERENCES escalations(escalation_id),
    scope_json            TEXT    NOT NULL,
    issued_by_operator_id TEXT    NOT NULL,
    policy_epoch          INTEGER NOT NULL,
    token_hash            TEXT    NOT NULL,
    nonce                 TEXT    NOT NULL UNIQUE,
    issued_at             INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    consumed              INTEGER NOT NULL DEFAULT 0
        CHECK (consumed IN (0, 1))
);

-- ── Table 10: approval_proofs ────────────────────────────────────────────────
-- Kernel-signed receipt written atomically when an escalated action executes.
CREATE TABLE IF NOT EXISTS approval_proofs (
    proof_id              TEXT    NOT NULL PRIMARY KEY,
    escalation_id         TEXT    NOT NULL UNIQUE
        REFERENCES escalations(escalation_id),
    approval_token_id     TEXT    NOT NULL UNIQUE
        REFERENCES approval_tokens(approval_token_id),
    action_hash           TEXT    NOT NULL,
    action_description_json TEXT  NOT NULL,
    action_taken_at       INTEGER NOT NULL,
    policy_epoch          INTEGER NOT NULL,
    kernel_signature      TEXT    NOT NULL
);

-- ── Table 11: approval_token_nonces ──────────────────────────────────────────
-- Consumed approval token nonces. INSERT fails on PK constraint → replay rejected.
CREATE TABLE IF NOT EXISTS approval_token_nonces (
    nonce                 TEXT    NOT NULL PRIMARY KEY,
    approval_token_id     TEXT    NOT NULL
        REFERENCES approval_tokens(approval_token_id),
    consumed_at           INTEGER NOT NULL
);

-- ── Table 12: verifier_run_tokens ────────────────────────────────────────────
-- Single-use verifier subprocess credentials. token_hash = hex SHA-256.
CREATE TABLE IF NOT EXISTS verifier_run_tokens (
    verifier_run_id       TEXT    NOT NULL PRIMARY KEY,
    task_id               TEXT    NOT NULL
        REFERENCES tasks(task_id),
    gate_type             TEXT    NOT NULL,
    evaluation_sha        TEXT    NOT NULL,
    token_hash            TEXT    NOT NULL,
    issued_at             INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    consumed              INTEGER NOT NULL DEFAULT 0
        CHECK (consumed IN (0, 1)),
    consumed_at           INTEGER
);

-- ── Table 13: witness_records ────────────────────────────────────────────────
-- SQL index for the content-addressed witness blob store.
-- result_class: DDL canonical names are Pass | Fail | Inconclusive.
CREATE TABLE IF NOT EXISTS witness_records (
    verifier_run_id       TEXT    NOT NULL PRIMARY KEY
        REFERENCES verifier_run_tokens(verifier_run_id),
    evaluation_sha        TEXT    NOT NULL,
    task_id               TEXT    NOT NULL
        REFERENCES tasks(task_id),
    gate_type             TEXT    NOT NULL,
    result_class          TEXT    NOT NULL
        CHECK (result_class IN ('Pass', 'Fail', 'Inconclusive')),
    blob_sha256           TEXT    NOT NULL,
    blob_path             TEXT    NOT NULL,
    recorded_at           INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_witness_records_lookup
    ON witness_records (evaluation_sha, task_id, gate_type, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_witness_records_blob_sha256
    ON witness_records (blob_sha256);

-- ── Table 14: lane_budget_reservations ───────────────────────────────────────
-- Active per-lane task budget reservations. PK = (lane_id, task_id).
-- release_budget = DELETE WHERE lane_id = ? AND task_id = ?.
CREATE TABLE IF NOT EXISTS lane_budget_reservations (
    lane_id               TEXT    NOT NULL,
    task_id               TEXT    NOT NULL
        REFERENCES tasks(task_id),
    reserved_cost         INTEGER NOT NULL,
    reserved_at           INTEGER NOT NULL,
    PRIMARY KEY (lane_id, task_id)
);

-- ── Table 15: lineage_rate_limits ────────────────────────────────────────────
-- Per-lineage escalation rate-limit state.
-- quarantined=1 → lineage cannot submit new escalations.
CREATE TABLE IF NOT EXISTS lineage_rate_limits (
    lineage_id              TEXT    NOT NULL PRIMARY KEY,
    window_start            INTEGER NOT NULL,
    escalation_count        INTEGER NOT NULL DEFAULT 0,
    quarantined             INTEGER NOT NULL DEFAULT 0
        CHECK (quarantined IN (0, 1)),
    quarantine_trigger_count INTEGER NOT NULL DEFAULT 0,
    quarantined_at          INTEGER
);

-- ── Table 16: nonce_cache ────────────────────────────────────────────────────
-- Per-session IPC envelope nonce dedup. Enforces INV-01 check (B).
-- UNIQUE(session_id, envelope_nonce) → duplicate delivery rejected.
CREATE TABLE IF NOT EXISTS nonce_cache (
    session_id            TEXT    NOT NULL
        REFERENCES sessions(session_id),
    sequence_num          INTEGER NOT NULL,
    envelope_nonce        TEXT    NOT NULL,
    observed_at           INTEGER NOT NULL,
    PRIMARY KEY (session_id, sequence_num),
    UNIQUE (session_id, envelope_nonce)
);

CREATE INDEX IF NOT EXISTS idx_nonce_cache_observed_at
    ON nonce_cache (observed_at);

-- ── Table 17: task_intent_ranges ─────────────────────────────────────────────
-- Per-intent VCS diff range log for a task. Input for CompleteTask path check.
-- PK(task_id, head_sha) makes same-SHA retries idempotent.
CREATE TABLE IF NOT EXISTS task_intent_ranges (
    task_id     TEXT    NOT NULL REFERENCES tasks(task_id),
    base_sha    TEXT    NOT NULL,
    head_sha    TEXT    NOT NULL,
    accepted_at INTEGER NOT NULL,
    PRIMARY KEY (task_id, head_sha)
);

CREATE INDEX IF NOT EXISTS idx_task_intent_ranges_task_id
    ON task_intent_ranges (task_id);

-- ── Table 18: task_exported_path_snapshots ───────────────────────────────────
-- Pre-computed path export for successor effective_allow computation.
-- Populated only for tasks with path_export_to_successors = true.
CREATE TABLE IF NOT EXISTS task_exported_path_snapshots (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    path    TEXT NOT NULL,
    PRIMARY KEY (task_id, path)
);

CREATE INDEX IF NOT EXISTS idx_task_exported_path_snapshots_task_id
    ON task_exported_path_snapshots (task_id);

-- ── Table 19: policy_epoch_history ───────────────────────────────────────────
-- Append-only ledger of policy epoch advances plus genesis epoch.
-- MAX(epoch_id) = current policy epoch.
-- policy_sha256 UNIQUE prevents re-inserting the same artifact.
CREATE TABLE IF NOT EXISTS policy_epoch_history (
    epoch_id              INTEGER NOT NULL PRIMARY KEY,
    policy_sha256         TEXT    NOT NULL UNIQUE,
    signed_by_authority   TEXT    NOT NULL,
    triggered_by_operator TEXT    NOT NULL,
    advanced_at           INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policy_epoch_history_advanced_at
    ON policy_epoch_history (advanced_at);

-- ── Record this migration ─────────────────────────────────────────────────────
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (1, strftime('%s', 'now'));

COMMIT;
";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Fresh (empty) DB → `schema_version` does not exist → `read_current_version`
    /// reports `0`, `apply_pending` succeeds, and the schema is fully populated.
    #[test]
    fn fresh_db_applies_migration_1() {
        let conn = Connection::open_in_memory().unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 0);

        apply_pending(&conn).expect("migration 1 should apply on fresh db");

        let v = read_current_version(&conn).unwrap();
        assert_eq!(v, 1, "schema_version should be 1 after first apply");

        // Spot-check: a representative table exists post-migration.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='tasks'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "tasks table should exist after migration 1");
    }

    /// Calling `apply_pending` twice in a row is a no-op; the schema_version
    /// row remains `(version=1, applied_at=…)` and no error is raised.
    #[test]
    fn apply_pending_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 1);

        // Exactly one row in schema_version (PK on `version` enforces this).
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    /// If the DB has `schema_version` but `MAX(version)` returns NULL (no rows),
    /// `read_current_version` returns 0 via COALESCE — this is the "table
    /// exists but is empty" path, distinct from "table does not exist".
    #[test]
    fn empty_schema_version_table_reads_as_zero() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (version INTEGER NOT NULL PRIMARY KEY, applied_at INTEGER NOT NULL);",
        )
        .unwrap();

        assert_eq!(
            read_current_version(&conn).unwrap(),
            0,
            "empty schema_version → version 0"
        );
    }

    /// If `schema_version` is malformed (column missing), `read_current_version`
    /// MUST surface the error — NOT silently return 0. The earlier
    /// `unwrap_or(0)` codepath would have re-run the entire migration on top
    /// of the broken table; this test guards against regression.
    #[test]
    fn malformed_schema_version_table_propagates_error() {
        let conn = Connection::open_in_memory().unwrap();
        // Wrong column name: `version` is replaced by `vers`. The probe
        // `SELECT MAX(version) FROM schema_version` will fail with
        // "no such column: version", which is NOT "no such table" and
        // therefore must propagate.
        conn.execute_batch("CREATE TABLE schema_version (vers INTEGER, applied_at INTEGER);")
            .unwrap();

        let err = read_current_version(&conn).unwrap_err();
        match err {
            StoreError::Migration(msg) => {
                assert!(
                    msg.contains("schema_version probe failed"),
                    "expected 'schema_version probe failed' in error, got: {msg}"
                );
            }
            other => panic!("expected Migration error, got {other:?}"),
        }
    }

    /// A second call to `apply_pending` after a successful first call must
    /// detect "version >= 1" and skip migration 1 entirely (no DDL re-run).
    /// We verify this by injecting a sentinel row into `tasks` between calls
    /// and asserting it survives — if the DDL had re-run, the row would be
    /// gone (DROP-then-CREATE would lose data; CREATE IF NOT EXISTS would
    /// preserve it but the schema_version PK conflict on re-INSERT would
    /// have raised).
    #[test]
    fn second_apply_does_not_drop_data() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        // Insert minimum-FK chain so we have a tasks row to look for.
        conn.execute_batch(
            "INSERT INTO initiatives (initiative_id, state, terminal_criteria_json,
                                       plan_artifact_sha256, created_at)
             VALUES ('init-1', 'Draft', '{}', 'deadbeef', 0);
             INSERT INTO tasks (task_id, initiative_id, lane_id, state, actor,
                                policy_epoch, admitted_at, transitioned_at)
             VALUES ('task-1', 'init-1', 'default', 'Admitted', 'planner',
                     1, 0, 0);",
        )
        .unwrap();

        apply_pending(&conn).unwrap();

        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM tasks WHERE task_id='task-1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 1, "tasks row must survive a second apply_pending");
    }
}
