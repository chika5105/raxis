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

/// Apply all pending migrations to `conn`.
/// Safe to call on every startup — skips already-applied migrations.
pub fn apply_pending(conn: &Connection) -> Result<(), StoreError> {
    // Determine current schema version.
    // On a fresh DB, schema_version does not yet exist, so we catch that case.
    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0); // table doesn't exist yet → version 0

    if current_version < 1 {
        apply_migration_1(conn)?;
    }

    // Future migrations: if current_version < 2 { apply_migration_2(conn)?; }

    Ok(())
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
