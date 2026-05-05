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
//
// ## Type-safe DDL composition (INV-STORE-03)
//
// Per kernel-store.md §2.5.1 INV-STORE-03 "no raw SQL table-name
// literals", every table reference in this file's DDL is rendered
// from `crate::Table` and every CHECK-constraint enum list is rendered
// from the corresponding `raxis_types` enum's `ALL` (or `STORED`) array.
// `render_migration_1_ddl` is the single point of substitution; the DDL
// is rebuilt once per `apply_migration_1` call (negligible cost — the
// kernel applies it at most once per boot on a fresh DB).
//
// **Drift safety.** Migration 1 is the historical v1 schema; its
// rendered text MUST stay byte-identical across builds for a given
// set of enum variants. The
// `tests::migration_1_ddl_fingerprint_is_pinned` SHA-256 guard
// surfaces any unintended drift in code review (e.g. an enum variant
// silently appended without a corresponding new migration). The
// per-enum `ALL` arrays carry "spec drift contract" doc-comments
// pointing back at this guard so anyone touching them sees the
// downstream impact before sending the diff for review.

use crate::table::Table;
use crate::StoreError;
use raxis_types::{
    DelegationStatus, EscalationStatus, InitiativeState, TaskState, WitnessResultClass,
};
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
pub const SCHEMA_VERSION: u32 = 4;

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
    if current_version < 2 {
        apply_migration_2(conn)?;
    }
    if current_version < 3 {
        apply_migration_3(conn)?;
    }
    if current_version < 4 {
        apply_migration_4(conn)?;
    }

    Ok(())
}

/// Read `MAX(version)` from `schema_version`, treating "table does not exist"
/// as version `0` (fresh DB) and surfacing every other failure as a
/// `Migration` error. Centralises the failure-mode policy in one place.
fn read_current_version(conn: &Connection) -> Result<i64, StoreError> {
    match conn.query_row(
        &format!(
            "SELECT COALESCE(MAX(version), 0) FROM {schema_version}",
            schema_version = Table::SchemaVersion.as_str(),
        ),
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
    let ddl = render_migration_1_ddl();
    conn.execute_batch(&ddl).map_err(|e| {
        StoreError::Migration(format!("migration 1 failed: {e}"))
    })
}

/// Render an `IN ('A','B','C')` value list from a slice of `as_sql_str()`
/// outputs. The output is **just** the parenthesised value list (caller
/// provides the surrounding `CHECK (column IN ...)` framing) so the
/// helper composes naturally inside `format!` substitutions.
fn check_in_list(values: &[&'static str]) -> String {
    let mut out = String::with_capacity(values.len() * 16 + 4);
    out.push('(');
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('\'');
        out.push_str(v);
        out.push('\'');
    }
    out.push(')');
    out
}

/// Convenience: render a CHECK list directly from an enum's canonical
/// `ALL`/`STORED` constant by mapping each variant through
/// `as_sql_str()`. Generic over a small adapter closure so callers can
/// handle both the plain `as_sql_str()` (returns `&'static str`) and
/// the `DelegationStatus` shape (returns `Option<&'static str>`).
fn check_in_clause<E: Copy>(variants: &[E], to_sql: impl Fn(E) -> &'static str) -> String {
    let mapped: Vec<&'static str> = variants.iter().copied().map(to_sql).collect();
    check_in_list(&mapped)
}

/// The complete v1 baseline DDL — all 19 kernel.db tables plus their
/// indexes. Extracted verbatim from kernel-store.md §2.5.1 Parts 1–4,
/// wrapped in a single transaction so the entire schema appears
/// atomically. Table names come from `Table::X.as_str()`; CHECK-constraint
/// value lists come from each enum's `ALL` (or `STORED`) array — there
/// are NO raw SQL identifier or enum-value literals in this function
/// (kernel-store.md §2.5.1 INV-STORE-03).
fn render_migration_1_ddl() -> String {
    // ── Table-name substitutions (Table::X is the authoritative registry) ──
    let schema_version              = Table::SchemaVersion.as_str();
    let initiatives                 = Table::Initiatives.as_str();
    let signed_plan_artifacts       = Table::SignedPlanArtifacts.as_str();
    let sessions                    = Table::Sessions.as_str();
    let tasks                       = Table::Tasks.as_str();
    let task_dag_edges              = Table::TaskDagEdges.as_str();
    let delegations                 = Table::Delegations.as_str();
    let escalations                 = Table::Escalations.as_str();
    let approval_tokens             = Table::ApprovalTokens.as_str();
    let approval_proofs             = Table::ApprovalProofs.as_str();
    let approval_token_nonces       = Table::ApprovalTokenNonces.as_str();
    let verifier_run_tokens         = Table::VerifierRunTokens.as_str();
    let witness_records             = Table::WitnessRecords.as_str();
    let lane_budget_reservations    = Table::LaneBudgetReservations.as_str();
    let lineage_rate_limits         = Table::LineageRateLimits.as_str();
    let nonce_cache                 = Table::NonceCache.as_str();
    let task_intent_ranges          = Table::TaskIntentRanges.as_str();
    let task_exported_path_snapshots = Table::TaskExportedPathSnapshots.as_str();
    let policy_epoch_history        = Table::PolicyEpochHistory.as_str();

    // ── CHECK-constraint enum substitutions (raxis_types is authoritative) ─
    let initiative_state_check = check_in_clause(&InitiativeState::ALL, InitiativeState::as_sql_str);
    let task_state_check       = check_in_clause(&TaskState::ALL,       TaskState::as_sql_str);
    let escalation_status_check = check_in_clause(&EscalationStatus::ALL, EscalationStatus::as_sql_str);
    let witness_result_class_check = check_in_clause(&WitnessResultClass::ALL, WitnessResultClass::as_sql_str);
    // `DelegationStatus::STORED` carries the subset that actually appears
    // at-rest (kernel-store.md §2.5.1 Table 7); the runtime-derived
    // `Expired` and synthetic `NotGranted` do NOT belong in the CHECK.
    let delegation_status_check = check_in_clause(
        &DelegationStatus::STORED,
        |s| DelegationStatus::as_sql_str(s).expect("STORED variants must serialise"),
    );

    // ── DEFAULT-clause enum substitutions (newly-inserted-row state) ──────
    // The DDL `DEFAULT '...'` clauses on `delegations.status` and
    // `escalations.status` MUST match the canonical "newly created"
    // variant of each FSM enum. Pulling them from the enum (rather
    // than hard-coding 'Active' / 'Pending') closes the same drift
    // window as the CHECK lists above.
    let delegation_default_status = DelegationStatus::Active
        .as_sql_str()
        .expect("Active is a stored variant");
    let escalation_default_status = EscalationStatus::Pending.as_sql_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- ── Table 1: schema_version ──────────────────────────────────────────────────
-- Tracks applied migrations. MAX(version) = current schema level.
-- PRIMARY KEY prevents duplicate application.
CREATE TABLE IF NOT EXISTS {schema_version} (
    version     INTEGER NOT NULL PRIMARY KEY,
    applied_at  INTEGER NOT NULL
);

-- ── Table 2: initiatives ─────────────────────────────────────────────────────
-- One row per initiative. State machine: Draft → ApprovedPlan → Executing →
-- Completed | Failed | Aborted. terminal_criteria_json serialises TerminalCriteria.
CREATE TABLE IF NOT EXISTS {initiatives} (
    initiative_id          TEXT    NOT NULL PRIMARY KEY,
    state                  TEXT    NOT NULL
        CHECK (state IN {initiative_state_check}),
    terminal_criteria_json TEXT    NOT NULL,
    plan_artifact_sha256   TEXT    NOT NULL,
    created_at             INTEGER NOT NULL,
    approved_at            INTEGER,
    completed_at           INTEGER
);

-- ── Table 3: signed_plan_artifacts ───────────────────────────────────────────
-- Immutable sealed plan bytes + Ed25519 signature. One row per initiative.
CREATE TABLE IF NOT EXISTS {signed_plan_artifacts} (
    initiative_id  TEXT    NOT NULL PRIMARY KEY
        REFERENCES {initiatives}(initiative_id),
    plan_bytes     BLOB    NOT NULL,
    plan_sig       BLOB    NOT NULL,
    stored_at      INTEGER NOT NULL
);

-- ── Table 4: sessions ────────────────────────────────────────────────────────
-- One row per planner/gateway/verifier session. Soft-delete only (revoked flag).
-- sequence_number enforces INV-01 monotonic ordering.
CREATE TABLE IF NOT EXISTS {sessions} (
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
CREATE TABLE IF NOT EXISTS {tasks} (
    task_id                TEXT    NOT NULL PRIMARY KEY,
    initiative_id          TEXT    NOT NULL
        REFERENCES {initiatives}(initiative_id),
    lane_id                TEXT    NOT NULL,
    state                  TEXT    NOT NULL
        CHECK (state IN {task_state_check}),
    block_reason           TEXT,
    actor                  TEXT    NOT NULL,
    policy_epoch           INTEGER NOT NULL,
    admitted_at            INTEGER NOT NULL,
    transitioned_at        INTEGER NOT NULL,
    session_id             TEXT
        REFERENCES {sessions}(session_id),
    evaluation_sha         TEXT,
    base_sha               TEXT,
    submitted_claims_json  TEXT,
    admission_reserved_units INTEGER,
    actual_cost            INTEGER NOT NULL DEFAULT 0
);

-- ── Table 6: task_dag_edges ──────────────────────────────────────────────────
-- Directed dependency edges. predecessor_satisfied is monotonically set by
-- store::dag::release_successors on predecessor Completed transition.
CREATE TABLE IF NOT EXISTS {task_dag_edges} (
    initiative_id           TEXT    NOT NULL
        REFERENCES {initiatives}(initiative_id),
    predecessor_task_id     TEXT    NOT NULL
        REFERENCES {tasks}(task_id),
    successor_task_id       TEXT    NOT NULL
        REFERENCES {tasks}(task_id),
    predecessor_satisfied   INTEGER NOT NULL DEFAULT 0
        CHECK (predecessor_satisfied IN (0, 1)),
    PRIMARY KEY (predecessor_task_id, successor_task_id)
);

CREATE INDEX IF NOT EXISTS idx_task_dag_edges_successor
    ON {task_dag_edges} (successor_task_id);

-- ── Table 7: delegations ─────────────────────────────────────────────────────
-- Per-(session, capability_class) delegations. One row per pair.
-- status: Active → StaleOnNextUse (epoch advance) → RenewalRequired (grace used).
-- revoked_at IS NOT NULL overrides status. now() >= expires_at → Expired.
CREATE TABLE IF NOT EXISTS {delegations} (
    delegation_id         TEXT    NOT NULL PRIMARY KEY,
    session_id            TEXT    NOT NULL
        REFERENCES {sessions}(session_id),
    capability_class      TEXT    NOT NULL,
    delegating_role_id    TEXT    NOT NULL,
    delegate_role_id      TEXT    NOT NULL,
    effective_from        INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    revoked_at            INTEGER,
    status                TEXT    NOT NULL DEFAULT '{delegation_default_status}'
        CHECK (status IN {delegation_status_check}),
    epoch_stale_set_at    INTEGER,
    operator_signature    BLOB    NOT NULL,
    UNIQUE (session_id, capability_class)
);

-- NOTE (spec/migration parity audit, 2026-05): this explicit index is
-- REDUNDANT with the implicit `sqlite_autoindex_delegations_*` that
-- SQLite creates from the `UNIQUE (session_id, capability_class)`
-- constraint above (per sqlite.org/lang_createtable.html). It is
-- preserved here unchanged because (a) v1 deployed databases already
-- carry it and dropping it would force a no-op rebuild on every
-- running kernel, (b) IF NOT EXISTS makes the redundancy harmless,
-- and (c) the spec DDL block in kernel-store.md §2.5.1 Table 7
-- documents the same redundancy. New tables MUST NOT add a duplicate
-- explicit index when a UNIQUE constraint already covers the same
-- column tuple.
CREATE INDEX IF NOT EXISTS idx_delegations_session_capability
    ON {delegations} (session_id, capability_class);

-- ── Table 8: escalations ─────────────────────────────────────────────────────
-- One row per planner EscalationRequest. FSM: Pending → Approved | Denied |
-- TimedOut; Approved → TokenExpired | Consumed.
CREATE TABLE IF NOT EXISTS {escalations} (
    escalation_id         TEXT    NOT NULL PRIMARY KEY,
    session_id            TEXT    NOT NULL
        REFERENCES {sessions}(session_id),
    task_id               TEXT    NOT NULL
        REFERENCES {tasks}(task_id),
    lineage_id            TEXT    NOT NULL,
    initiative_id         TEXT    NOT NULL
        REFERENCES {initiatives}(initiative_id),
    class                 TEXT    NOT NULL,
    requested_scope_json  TEXT    NOT NULL,
    justification         TEXT    NOT NULL,
    idempotency_key       TEXT    NOT NULL,
    status                TEXT    NOT NULL DEFAULT '{escalation_default_status}'
        CHECK (status IN {escalation_status_check}),
    created_at            INTEGER NOT NULL,
    timeout_at            INTEGER NOT NULL,
    resolved_at           INTEGER,
    resolution_notes      TEXT,
    UNIQUE (session_id, idempotency_key)
);

-- ── Table 9: approval_tokens ─────────────────────────────────────────────────
-- Operator-issued single-use tokens. One per escalation.
-- token_hash = hex SHA-256(raw_bytes); raw bytes never stored.
CREATE TABLE IF NOT EXISTS {approval_tokens} (
    approval_token_id     TEXT    NOT NULL PRIMARY KEY,
    escalation_id         TEXT    NOT NULL UNIQUE
        REFERENCES {escalations}(escalation_id),
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
CREATE TABLE IF NOT EXISTS {approval_proofs} (
    proof_id              TEXT    NOT NULL PRIMARY KEY,
    escalation_id         TEXT    NOT NULL UNIQUE
        REFERENCES {escalations}(escalation_id),
    approval_token_id     TEXT    NOT NULL UNIQUE
        REFERENCES {approval_tokens}(approval_token_id),
    action_hash           TEXT    NOT NULL,
    action_description_json TEXT  NOT NULL,
    action_taken_at       INTEGER NOT NULL,
    policy_epoch          INTEGER NOT NULL,
    kernel_signature      TEXT    NOT NULL
);

-- ── Table 11: approval_token_nonces ──────────────────────────────────────────
-- Consumed approval token nonces. INSERT fails on PK constraint → replay rejected.
CREATE TABLE IF NOT EXISTS {approval_token_nonces} (
    nonce                 TEXT    NOT NULL PRIMARY KEY,
    approval_token_id     TEXT    NOT NULL
        REFERENCES {approval_tokens}(approval_token_id),
    consumed_at           INTEGER NOT NULL
);

-- ── Table 12: verifier_run_tokens ────────────────────────────────────────────
-- Single-use verifier subprocess credentials. token_hash = hex SHA-256.
CREATE TABLE IF NOT EXISTS {verifier_run_tokens} (
    verifier_run_id       TEXT    NOT NULL PRIMARY KEY,
    task_id               TEXT    NOT NULL
        REFERENCES {tasks}(task_id),
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
CREATE TABLE IF NOT EXISTS {witness_records} (
    verifier_run_id       TEXT    NOT NULL PRIMARY KEY
        REFERENCES {verifier_run_tokens}(verifier_run_id),
    evaluation_sha        TEXT    NOT NULL,
    task_id               TEXT    NOT NULL
        REFERENCES {tasks}(task_id),
    gate_type             TEXT    NOT NULL,
    result_class          TEXT    NOT NULL
        CHECK (result_class IN {witness_result_class_check}),
    blob_sha256           TEXT    NOT NULL,
    blob_path             TEXT    NOT NULL,
    recorded_at           INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_witness_records_lookup
    ON {witness_records} (evaluation_sha, task_id, gate_type, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_witness_records_blob_sha256
    ON {witness_records} (blob_sha256);

-- ── Table 14: lane_budget_reservations ───────────────────────────────────────
-- Active per-lane task budget reservations. PK = (lane_id, task_id).
-- release_budget = DELETE WHERE lane_id = ? AND task_id = ?.
CREATE TABLE IF NOT EXISTS {lane_budget_reservations} (
    lane_id               TEXT    NOT NULL,
    task_id               TEXT    NOT NULL
        REFERENCES {tasks}(task_id),
    reserved_cost         INTEGER NOT NULL,
    reserved_at           INTEGER NOT NULL,
    PRIMARY KEY (lane_id, task_id)
);

-- ── Table 15: lineage_rate_limits ────────────────────────────────────────────
-- Per-lineage escalation rate-limit state.
-- quarantined=1 → lineage cannot submit new escalations.
CREATE TABLE IF NOT EXISTS {lineage_rate_limits} (
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
CREATE TABLE IF NOT EXISTS {nonce_cache} (
    session_id            TEXT    NOT NULL
        REFERENCES {sessions}(session_id),
    sequence_num          INTEGER NOT NULL,
    envelope_nonce        TEXT    NOT NULL,
    observed_at           INTEGER NOT NULL,
    PRIMARY KEY (session_id, sequence_num),
    UNIQUE (session_id, envelope_nonce)
);

CREATE INDEX IF NOT EXISTS idx_nonce_cache_observed_at
    ON {nonce_cache} (observed_at);

-- ── Table 17: task_intent_ranges ─────────────────────────────────────────────
-- Per-intent VCS diff range log for a task. Input for CompleteTask path check.
-- PK(task_id, head_sha) makes same-SHA retries idempotent.
CREATE TABLE IF NOT EXISTS {task_intent_ranges} (
    task_id     TEXT    NOT NULL REFERENCES {tasks}(task_id),
    base_sha    TEXT    NOT NULL,
    head_sha    TEXT    NOT NULL,
    accepted_at INTEGER NOT NULL,
    PRIMARY KEY (task_id, head_sha)
);

CREATE INDEX IF NOT EXISTS idx_task_intent_ranges_task_id
    ON {task_intent_ranges} (task_id);

-- ── Table 18: task_exported_path_snapshots ───────────────────────────────────
-- Pre-computed path export for successor effective_allow computation.
-- Populated only for tasks with path_export_to_successors = true.
CREATE TABLE IF NOT EXISTS {task_exported_path_snapshots} (
    task_id TEXT NOT NULL REFERENCES {tasks}(task_id),
    path    TEXT NOT NULL,
    PRIMARY KEY (task_id, path)
);

CREATE INDEX IF NOT EXISTS idx_task_exported_path_snapshots_task_id
    ON {task_exported_path_snapshots} (task_id);

-- ── Table 19: policy_epoch_history ───────────────────────────────────────────
-- Append-only ledger of policy epoch advances plus genesis epoch.
-- MAX(epoch_id) = current policy epoch.
-- policy_sha256 UNIQUE prevents re-inserting the same artifact.
CREATE TABLE IF NOT EXISTS {policy_epoch_history} (
    epoch_id              INTEGER NOT NULL PRIMARY KEY,
    policy_sha256         TEXT    NOT NULL UNIQUE,
    signed_by_authority   TEXT    NOT NULL,
    triggered_by_operator TEXT    NOT NULL,
    advanced_at           INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policy_epoch_history_advanced_at
    ON {policy_epoch_history} (advanced_at);

-- ── Record this migration ─────────────────────────────────────────────────────
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (1, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 2 — v1.x: operator_certificates view table.
//
// Normative reference (forthcoming): kernel-store.md §2.5.7
// "Operator Certificates".
//
// **Why a denormalised view table?**
//
//   The canonical source of truth for an operator's cert is the
//   `[[operators.entries.cert]]` sub-table inside the currently-
//   installed `policy.toml`. The kernel's `cert_check` runtime path
//   needs three queries on every operator IPC dispatch:
//
//     - lookup-by-fingerprint:  `WHERE pubkey_fingerprint = ?`
//     - expiry sweep:           `WHERE not_after < ? AND kind = 'Standard'`
//     - kind filter:            `WHERE kind = 'EmergencyRecovery'`
//
//   Doing those three from the in-memory `Arc<PolicyBundle>` would
//   require iterating the operator-entry array on every dispatch.
//   That's tolerable when there are 3 operators, painful when there
//   are 30, and the kernel already has a SQLite database per the
//   architecture — using the table for bulk filters and the bundle
//   for the wire response is the right factoring.
//
// **Atomicity contract.** This table is repopulated by `advance_epoch`
// in the SAME transaction that updates `policy_epoch_history`. A
// power-loss between `policy_epoch_history` insert and the cert table
// rebuild would leave the kernel running with stale certs — the
// transaction boundary closes that window. The repopulation is a
// `DELETE FROM operator_certificates` followed by a fresh `INSERT`
// per cert, scoped to the new epoch_id; we do not maintain history
// of past certs in this table (the audit chain is the historical
// record).
//
// **Rows captured.** Every operator entry (cert is mandatory —
// INV-CERT-01 — so there is no cert-less / "legacy" flow). An empty
// table at boot indicates the genesis ceremony was incomplete and is
// itself a `raxis doctor` failure rather than a permitted state.
// ---------------------------------------------------------------------------

fn apply_migration_2(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_2_ddl();
    conn.execute_batch(&ddl).map_err(|e| {
        StoreError::Migration(format!("migration 2 failed: {e}"))
    })
}

/// The complete migration-2 DDL — adds `operator_certificates` plus
/// its lookup indexes. Same INV-STORE-03 contract as migration 1:
/// no raw table-name literals.
fn render_migration_2_ddl() -> String {
    let operator_certificates = Table::OperatorCertificates.as_str();
    let policy_epoch_history  = Table::PolicyEpochHistory.as_str();
    let schema_version        = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- ── Table 20: operator_certificates ──────────────────────────────────────────
-- Denormalised view of [[operators.entries.cert]] from the currently-
-- installed policy.toml. Repopulated atomically on every advance_epoch.
--
-- Columns:
--   pubkey_fingerprint    — SHA-256[:16] of the operator's pubkey;
--                           UNIQUE (one cert per operator at any time).
--   epoch_id              — policy_epoch_history.epoch_id this cert was
--                           installed under. FK enforces that the
--                           denormalised view cannot reference an epoch
--                           that no longer exists in the history table.
--   kind                  — 'Standard' | 'EmergencyRecovery' (from
--                           CertKind::as_str). CHECK constraint pins
--                           the universe of accepted values; a
--                           future kind requires a new migration.
--   display_name          — operator label (denormalised from cert).
--   pubkey_hex            — 64-char raw Ed25519 pubkey (denormalised).
--   not_before            — Unix seconds. 0 sentinel for emergency.
--   not_after             — Unix seconds. 0 sentinel for emergency.
--   warn_before_expiry_days — width of the Expiring zone.
--   grace_period_days     — width of the Grace zone.
--   permitted_ops_json    — JSON array of op names. Stored as JSON
--                           rather than a separate child table so the
--                           cert is always queryable as a single row
--                           (no joins for the common path).
--   contact_info          — optional free-form string; NULL when
--                           absent.
--   self_sig_hex          — 128-char self-signature for
--                           re-verification on demand.
--   force_misconfig_bypass — 0 or 1; mirrors the entry-level flag so
--                           audit / doctor queries can `SELECT *
--                           WHERE force_misconfig_bypass = 1` without
--                           re-reading the policy bundle.
--   installed_at          — Unix seconds when this row was rebuilt.
CREATE TABLE IF NOT EXISTS {operator_certificates} (
    pubkey_fingerprint      TEXT    NOT NULL PRIMARY KEY,
    epoch_id                INTEGER NOT NULL
        REFERENCES {policy_epoch_history}(epoch_id),
    kind                    TEXT    NOT NULL
        CHECK (kind IN ('Standard', 'EmergencyRecovery')),
    display_name            TEXT    NOT NULL,
    pubkey_hex              TEXT    NOT NULL UNIQUE,
    not_before              INTEGER NOT NULL,
    not_after               INTEGER NOT NULL,
    warn_before_expiry_days INTEGER NOT NULL,
    grace_period_days       INTEGER NOT NULL,
    permitted_ops_json      TEXT    NOT NULL,
    contact_info            TEXT,
    self_sig_hex            TEXT    NOT NULL,
    force_misconfig_bypass  INTEGER NOT NULL DEFAULT 0
        CHECK (force_misconfig_bypass IN (0, 1)),
    installed_at            INTEGER NOT NULL
);

-- Lookup: expiry sweep. Standard certs only — emergency certs have
-- not_after = 0 sentinel and would always sort first; partial index
-- on kind = 'Standard' keeps the index small and the sweep precise.
CREATE INDEX IF NOT EXISTS idx_operator_certificates_expiry_sweep
    ON {operator_certificates} (not_after, kind)
    WHERE kind = 'Standard';

-- Lookup: enumerate emergency certs without scanning the whole table.
CREATE INDEX IF NOT EXISTS idx_operator_certificates_emergency
    ON {operator_certificates} (kind)
    WHERE kind = 'EmergencyRecovery';

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (2, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 3 — initiative_quarantines (kernel-store.md §2.5.8).
//
// Adds the `initiative_quarantines` table. A row in this table marks an
// initiative as frozen: the planner intent dispatcher rejects every
// subsequent `IntentRequest` against it with `FAIL_INITIATIVE_QUARANTINED`.
//
// Two operator commands populate this table:
//
//   * `raxis initiative quarantine <id>` inserts a single row.
//   * `raxis operator quarantine-plans-by <fingerprint>` sweeps all
//     initiatives whose plan was signed by the named operator (joining
//     `initiatives` against `signed_plan_artifacts.signed_by`) and
//     inserts one row per match in a single transaction.
//
// The table is append-only in v1 (no "unquarantine"). To recover from a
// false positive, the operator aborts the initiative entirely and starts
// a fresh one — the quarantine row is left in place as the audit-trail
// record of the decision.
// ---------------------------------------------------------------------------

fn apply_migration_3(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_3_ddl();
    conn.execute_batch(&ddl).map_err(|e| {
        StoreError::Migration(format!("migration 3 failed: {e}"))
    })
}

/// The complete migration-3 DDL — adds `initiative_quarantines` and
/// extends `signed_plan_artifacts` with the operator fingerprint that
/// signed the plan (needed by `quarantine-plans-by`'s sweep query).
/// Same INV-STORE-03 contract as earlier migrations: no raw table-name
/// literals.
fn render_migration_3_ddl() -> String {
    let initiative_quarantines = Table::InitiativeQuarantines.as_str();
    let initiatives            = Table::Initiatives.as_str();
    let signed_plan_artifacts  = Table::SignedPlanArtifacts.as_str();
    let schema_version         = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- ── signed_plan_artifacts.signed_by_fingerprint ─────────────────────────────
-- The operator pubkey_fingerprint that approved this plan (the operator
-- whose Ed25519 signature `lifecycle::approve_plan` verified). Needed by
-- `quarantine-plans-by` to sweep every initiative whose plan was approved
-- by a now-compromised operator.
--
-- NULLABLE for backward compatibility with rows inserted under
-- migration 1/2 (pre-step-10). Application code MUST set this column
-- on every new INSERT going forward; the sweep skips NULL rows on the
-- premise that v1 approvals predate this column entirely.
ALTER TABLE {signed_plan_artifacts}
    ADD COLUMN signed_by_fingerprint TEXT;

-- Lookup: enumerate all initiatives a given operator approved.
CREATE INDEX IF NOT EXISTS idx_signed_plan_artifacts_signed_by
    ON {signed_plan_artifacts} (signed_by_fingerprint)
    WHERE signed_by_fingerprint IS NOT NULL;

-- ── Table 21: initiative_quarantines ────────────────────────────────────────
-- Quarantine markers. One row per quarantined initiative. The kernel
-- intent path rejects new IntentRequests against any initiative with a
-- row here.
--
-- Columns:
--   initiative_id      — PK; FK into initiatives so a quarantine row
--                        cannot reference an unknown initiative.
--   quarantined_at     — Unix seconds; clock-injected at insert time.
--   quarantined_by     — operator pubkey_fingerprint that issued the
--                        command (peripherals.md §3 'operator socket'
--                        fingerprint format: SHA-256[:16] of the raw
--                        Ed25519 pubkey, 32 hex chars).
--   reason             — free-form operator-supplied label; capped at
--                        the application layer to 512 bytes.
--   sweep_target       — NULL for single-initiative quarantines;
--                        carries the pubkey_fingerprint of the
--                        operator whose plans were swept when this
--                        row originated from the
--                        `quarantine-plans-by` sweep. Lets `raxis
--                        inspect` distinguish individually-quarantined
--                        initiatives from collateral sweep entries
--                        without joining against the audit chain.
CREATE TABLE IF NOT EXISTS {initiative_quarantines} (
    initiative_id   TEXT    NOT NULL PRIMARY KEY
        REFERENCES {initiatives}(initiative_id),
    quarantined_at  INTEGER NOT NULL,
    quarantined_by  TEXT    NOT NULL,
    reason          TEXT,
    sweep_target    TEXT
);

-- Lookup: enumerate all initiatives a given operator quarantined.
-- NOTE (spec/migration parity audit, 2026-05): no v1 kernel code
-- path filters by `quarantined_by` yet — the column is populated for
-- forensics, but the only reader (`views::initiative_quarantines::
-- list_all`) does an unfiltered scan ordered by `quarantined_at`. The
-- index is preserved as it supports the obvious future
-- `raxis inspect --quarantined-by <op-fp>` surface and is small (one
-- entry per quarantined initiative). The spec DDL block in
-- kernel-store.md §2.5.8 documents this index with the same future-
-- use note.
CREATE INDEX IF NOT EXISTS idx_initiative_quarantines_by_operator
    ON {initiative_quarantines} (quarantined_by);

-- Lookup: enumerate sweep-collateral entries for a given operator.
CREATE INDEX IF NOT EXISTS idx_initiative_quarantines_sweep_target
    ON {initiative_quarantines} (sweep_target)
    WHERE sweep_target IS NOT NULL;

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (3, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 4 — spec/migration index parity (kernel-store.md §2.5.8).
//
// Adds `idx_initiative_quarantines_quarantined_at` to support the
// `views::initiative_quarantines::list_all` reader, which executes
//   `SELECT ... FROM initiative_quarantines ORDER BY quarantined_at DESC`
// on the operator-side `raxis inspect` surface. Without this index
// SQLite must scan + sort the full table on every list; the table is
// small in v1 but listing is the read-side hot path for forensics, so
// we pay the index cost upfront rather than re-tuning later.
//
// The spec DDL block (kernel-store.md §2.5.8 "initiative_quarantines
// schema") has always listed this index. Migration 3 shipped without
// it (the historical v1 install had `idx_initiative_quarantines_by_
// operator` instead, which targets a different — currently unused —
// query). This migration brings deployed databases into parity with
// the spec without removing the legacy index (legacy is harmless and
// dropping it would force every running kernel to rebuild a perfectly
// good index for no benefit).
//
// Why a separate migration rather than editing migration 3?
// Migration 3 is HISTORICAL: changing its rendered DDL would force
// already-installed v1 databases to re-run a migration they already
// completed, which they cannot. New indexes for already-migrated DBs
// MUST land as a fresh migration step.
// ---------------------------------------------------------------------------

fn apply_migration_4(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_4_ddl();
    conn.execute_batch(&ddl).map_err(|e| {
        StoreError::Migration(format!("migration 4 failed: {e}"))
    })
}

/// The complete migration-4 DDL — one new index, identical column
/// shape and naming to the spec's §2.5.8 DDL block. Same INV-STORE-03
/// contract as earlier migrations: no raw table-name literals.
fn render_migration_4_ddl() -> String {
    let initiative_quarantines = Table::InitiativeQuarantines.as_str();
    let schema_version         = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- Lookup: ORDER BY quarantined_at DESC for `list_all` (operator
-- inspect / doctor surfaces). See kernel-store.md §2.5.8.
CREATE INDEX IF NOT EXISTS idx_initiative_quarantines_quarantined_at
    ON {initiative_quarantines} (quarantined_at);

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (4, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Fresh (empty) DB → `schema_version` does not exist → `read_current_version`
    /// reports `0`, `apply_pending` succeeds, and every migration's schema
    /// is fully populated up to the current `SCHEMA_VERSION`.
    #[test]
    fn fresh_db_applies_all_pending_migrations() {
        let conn = Connection::open_in_memory().unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 0);

        apply_pending(&conn).expect("all migrations should apply on fresh db");

        let v = read_current_version(&conn).unwrap();
        assert_eq!(v, SCHEMA_VERSION as i64,
            "schema_version should be SCHEMA_VERSION ({SCHEMA_VERSION}) after first apply");

        // Spot-check: a representative table exists post-migration.
        // We use `Table::Tasks.as_str()` here too — keeping the test
        // consistent with the production INV-STORE-03 contract.
        let count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                ),
                [Table::Tasks.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "tasks table should exist after migration 1");
    }

    /// Calling `apply_pending` twice in a row is a no-op; schema_version
    /// holds exactly one row per applied migration and no error is raised.
    #[test]
    fn apply_pending_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        // One row per applied migration (PK on `version` prevents duplicates).
        let n: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::SchemaVersion.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, SCHEMA_VERSION as i64,
            "expected one row per applied migration");
    }

    /// If the DB has `schema_version` but `MAX(version)` returns NULL (no rows),
    /// `read_current_version` returns 0 via COALESCE — this is the "table
    /// exists but is empty" path, distinct from "table does not exist".
    #[test]
    fn empty_schema_version_table_reads_as_zero() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE {} (version INTEGER NOT NULL PRIMARY KEY, applied_at INTEGER NOT NULL);",
            Table::SchemaVersion.as_str(),
        ))
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
        conn.execute_batch(&format!(
            "CREATE TABLE {} (vers INTEGER, applied_at INTEGER);",
            Table::SchemaVersion.as_str(),
        ))
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
    /// detect every migration is already applied and skip them entirely
    /// (no DDL re-run). We verify this by injecting a sentinel row into
    /// `tasks` between calls and asserting it survives — if the DDL had
    /// re-run, the row would be gone (DROP-then-CREATE would lose data;
    /// CREATE IF NOT EXISTS would preserve it but the schema_version PK
    /// conflict on re-INSERT would have raised).
    #[test]
    fn second_apply_does_not_drop_data() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        // Insert minimum-FK chain so we have a tasks row to look for.
        // Use `Table` enum + `as_sql_str` to keep test SQL aligned with
        // production INV-STORE-03 contract.
        let initiatives_t = Table::Initiatives.as_str();
        let tasks_t       = Table::Tasks.as_str();
        let draft         = InitiativeState::Draft.as_sql_str();
        let admitted      = TaskState::Admitted.as_sql_str();
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives_t} (initiative_id, state, terminal_criteria_json,
                                       plan_artifact_sha256, created_at)
             VALUES ('init-1', '{draft}', '{{}}', 'deadbeef', 0);
             INSERT INTO {tasks_t} (task_id, initiative_id, lane_id, state, actor,
                                policy_epoch, admitted_at, transitioned_at)
             VALUES ('task-1', 'init-1', 'default', '{admitted}', 'planner',
                     1, 0, 0);",
        ))
        .unwrap();

        apply_pending(&conn).unwrap();

        let n: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {tasks_t} WHERE task_id='task-1'"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "tasks row must survive a second apply_pending");
    }

    // ── Type-safe DDL composition guards (INV-STORE-03) ──────────────────────

    /// `check_in_list` produces the exact `'A', 'B', 'C'` shape the
    /// CHECK constraint syntax expects. Pin the format so a future
    /// "let's prettify" refactor doesn't accidentally produce
    /// `('A','B')` or `[A,B,C]` — both of which compile but mean
    /// nothing useful inside `CHECK (col IN ...)`.
    #[test]
    fn check_in_list_uses_single_quoted_comma_space_format() {
        let got = check_in_list(&["Pass", "Fail", "Inconclusive"]);
        assert_eq!(got, "('Pass', 'Fail', 'Inconclusive')");
    }

    /// `check_in_list` of a single value still emits a valid
    /// parenthesised list (no trailing comma, no missing parens).
    #[test]
    fn check_in_list_handles_single_value() {
        assert_eq!(check_in_list(&["Only"]), "('Only')");
    }

    /// All five enum-driven CHECK clauses emit the exact strings the
    /// kernel-store.md §2.5.1 DDL requires. Locks the rendered shape
    /// in code review so a downstream refactor that reorders an enum
    /// or renames a variant fails this test BEFORE the migration
    /// hash test below — giving a precise diff in the failure message.
    #[test]
    fn enum_driven_check_clauses_match_v1_spec() {
        // initiatives.state — kernel-store.md §2.5.1 Table 2.
        assert_eq!(
            check_in_clause(&InitiativeState::ALL, InitiativeState::as_sql_str),
            "('Draft', 'ApprovedPlan', 'Executing', 'Blocked', \
              'Completed', 'Failed', 'Aborted')"
                .replace("              ", ""),
        );
        // tasks.state — kernel-store.md §2.5.1 Table 5.
        assert_eq!(
            check_in_clause(&TaskState::ALL, TaskState::as_sql_str),
            "('Admitted', 'GatesPending', 'Running', 'Completed', \
              'Failed', 'Aborted', 'Cancelled', 'BlockedRecoveryPending')"
                .replace("              ", ""),
        );
        // delegations.status — only STORED variants. kernel-store.md Table 7.
        assert_eq!(
            check_in_clause(
                &DelegationStatus::STORED,
                |s| DelegationStatus::as_sql_str(s).expect("STORED variants must serialise"),
            ),
            "('Active', 'StaleOnNextUse', 'RenewalRequired')",
        );
        // escalations.status — kernel-store.md §2.5.1 Table 9.
        assert_eq!(
            check_in_clause(&EscalationStatus::ALL, EscalationStatus::as_sql_str),
            "('Pending', 'Approved', 'Denied', 'TimedOut', \
              'TokenExpired', 'Consumed')"
                .replace("              ", ""),
        );
        // witness_records.result_class — kernel-store.md §2.5.1 Table 13.
        assert_eq!(
            check_in_clause(&WitnessResultClass::ALL, WitnessResultClass::as_sql_str),
            "('Pass', 'Fail', 'Inconclusive')",
        );
    }

    /// All v1 + v1.x tables created by all applied migrations are
    /// reachable through the `Table` enum — i.e. there are no DDL-
    /// only tables that would be invisible to the kernel's
    /// INV-STORE-03 type-safe accessors.
    #[test]
    fn all_tables_are_in_table_enum() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let observed: std::collections::BTreeSet<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();

        let expected: std::collections::BTreeSet<String> = [
            // Migration 1 — v1 baseline (19 tables)
            Table::SchemaVersion,
            Table::Initiatives,
            Table::SignedPlanArtifacts,
            Table::Sessions,
            Table::Tasks,
            Table::TaskDagEdges,
            Table::Delegations,
            Table::Escalations,
            Table::ApprovalTokens,
            Table::ApprovalProofs,
            Table::ApprovalTokenNonces,
            Table::VerifierRunTokens,
            Table::WitnessRecords,
            Table::LaneBudgetReservations,
            Table::LineageRateLimits,
            Table::NonceCache,
            Table::TaskIntentRanges,
            Table::TaskExportedPathSnapshots,
            Table::PolicyEpochHistory,
            // Migration 2 — v1.x: operator certificates
            Table::OperatorCertificates,
            // Migration 3 — v1.x: initiative quarantines
            Table::InitiativeQuarantines,
        ]
        .iter()
        .map(|t| t.as_str().to_owned())
        .collect();

        assert_eq!(
            observed, expected,
            "set of tables created by all migrations must equal `Table` enum (INV-STORE-03)",
        );
    }

    // ── Migration 2 — operator_certificates ──────────────────────────

    /// Migration 2 creates the cert view table with the expected
    /// column shape; columns / indexes are reachable from a fresh DB.
    #[test]
    fn migration_2_creates_operator_certificates_table() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64,
            "schema_version must be SCHEMA_VERSION after applying all migrations");

        // Column metadata sanity check via PRAGMA — every column
        // we documented in the migration MUST be present.
        let cols: Vec<String> = conn
            .prepare(&format!(
                "SELECT name FROM pragma_table_info('{}')",
                Table::OperatorCertificates.as_str(),
            ))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for required in [
            "pubkey_fingerprint",   "epoch_id",        "kind",
            "display_name",         "pubkey_hex",      "not_before",
            "not_after",            "warn_before_expiry_days",
            "grace_period_days",    "permitted_ops_json",
            "contact_info",         "self_sig_hex",
            "force_misconfig_bypass", "installed_at",
        ] {
            assert!(cols.iter().any(|c| c == required),
                "operator_certificates is missing column {required:?}; \
                 got columns: {cols:?}");
        }

        // Both partial indexes registered.
        let idx_count: i64 = conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type='index' AND tbl_name='{}'",
                Table::OperatorCertificates.as_str(),
            ),
            [],
            |r| r.get(0),
        ).unwrap();
        assert!(idx_count >= 2,
            "expected at least 2 indexes on operator_certificates, got {idx_count}");
    }

    /// Migration 2 enforces CHECK (kind IN ('Standard', 'EmergencyRecovery')).
    /// A malformed kind value MUST be rejected at INSERT time so we
    /// can never drift into a state where the table holds rows the
    /// kernel's `cert_check` cannot interpret.
    #[test]
    fn operator_certificates_rejects_unknown_kind() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        // First insert a parent epoch row (FK requirement).
        conn.execute(
            &format!(
                "INSERT INTO {ph}(epoch_id, policy_sha256, signed_by_authority, \
                 triggered_by_operator, advanced_at) VALUES (1, 'sha', 'auth', 'op', 0)",
                ph = Table::PolicyEpochHistory.as_str(),
            ),
            [],
        ).unwrap();

        let result = conn.execute(
            &format!(
                "INSERT INTO {oc}(pubkey_fingerprint, epoch_id, kind, display_name, \
                 pubkey_hex, not_before, not_after, warn_before_expiry_days, \
                 grace_period_days, permitted_ops_json, self_sig_hex, installed_at) \
                 VALUES ('fp', 1, 'NotARealKind', 'op', 'pk', 0, 0, 0, 0, '[]', 'sig', 0)",
                oc = Table::OperatorCertificates.as_str(),
            ),
            [],
        );
        assert!(result.is_err(),
            "INSERT with kind='NotARealKind' must violate CHECK constraint");
    }

    /// Migration 2's FK on epoch_id MUST point at policy_epoch_history.
    /// PRAGMA foreign_keys is off by default in sqlite-rs, so we
    /// explicitly enable it here to verify the constraint is wired.
    #[test]
    fn operator_certificates_epoch_fk_resolves_to_policy_epoch_history() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        apply_pending(&conn).unwrap();

        // INSERT with a non-existent epoch_id MUST fail the FK constraint.
        let result = conn.execute(
            &format!(
                "INSERT INTO {oc}(pubkey_fingerprint, epoch_id, kind, display_name, \
                 pubkey_hex, not_before, not_after, warn_before_expiry_days, \
                 grace_period_days, permitted_ops_json, self_sig_hex, installed_at) \
                 VALUES ('fp', 999, 'Standard', 'op', 'pk', 0, 0, 0, 0, '[]', 'sig', 0)",
                oc = Table::OperatorCertificates.as_str(),
            ),
            [],
        );
        assert!(result.is_err(),
            "INSERT referencing missing epoch_id MUST trip the FK constraint");
    }

    // ── Migration 3 — initiative_quarantines ─────────────────────────

    /// Migration 3 creates the quarantine table AND adds the
    /// `signed_by_fingerprint` column on `signed_plan_artifacts`.
    /// Both are reachable from a fresh DB after `apply_pending`.
    #[test]
    fn migration_3_creates_initiative_quarantines_table_and_signer_column() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64,
            "schema_version must be SCHEMA_VERSION after applying all migrations");

        // Quarantine table columns.
        let cols: Vec<String> = conn
            .prepare(&format!(
                "SELECT name FROM pragma_table_info('{}')",
                Table::InitiativeQuarantines.as_str(),
            ))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for required in [
            "initiative_id", "quarantined_at", "quarantined_by",
            "reason",        "sweep_target",
        ] {
            assert!(cols.iter().any(|c| c == required),
                "initiative_quarantines is missing column {required:?}; got: {cols:?}");
        }

        // signed_plan_artifacts now carries signed_by_fingerprint.
        let plan_cols: Vec<String> = conn
            .prepare(&format!(
                "SELECT name FROM pragma_table_info('{}')",
                Table::SignedPlanArtifacts.as_str(),
            ))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(plan_cols.iter().any(|c| c == "signed_by_fingerprint"),
            "migration 3 must add signed_by_fingerprint; got: {plan_cols:?}");
    }

    // ── Migration 4 — quarantined_at index for spec parity ──────────

    /// Migration 4 adds `idx_initiative_quarantines_quarantined_at` so
    /// the `views::initiative_quarantines::list_all` reader (which
    /// `ORDER BY quarantined_at DESC`) does not need a temp-btree
    /// sort. The index existed in the kernel-store.md §2.5.8 DDL
    /// block from day one but the original migration 3 shipped
    /// without it; this test pins the parity fix.
    #[test]
    fn migration_4_creates_quarantined_at_index() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64,
            "schema_version must be SCHEMA_VERSION after applying all migrations");

        // `sqlite_master` is the authoritative inventory of indexes; we
        // verify both the index name and its target table to catch
        // accidental rename or misplaced ON-clause regressions.
        let row: (String, String) = conn
            .query_row(
                "SELECT name, tbl_name FROM sqlite_master \
                 WHERE type = 'index' AND name = ?1",
                ["idx_initiative_quarantines_quarantined_at"],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .expect("idx_initiative_quarantines_quarantined_at should exist after migration 4");
        assert_eq!(row.0, "idx_initiative_quarantines_quarantined_at");
        assert_eq!(row.1, Table::InitiativeQuarantines.as_str(),
            "index must be on the initiative_quarantines table");

        // The PRAGMA index_info confirms the index targets the right
        // column — protects against a future "fix" that points the
        // index at quarantined_by by mistake.
        let cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_index_info('idx_initiative_quarantines_quarantined_at')")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(cols, vec!["quarantined_at".to_string()],
            "index must be on the quarantined_at column only");
    }

    /// Upgrade scenario: a database that completed migration 3 but
    /// not migration 4 (i.e. installed under a build prior to this
    /// patch) must pick up the new index when `apply_pending` runs.
    /// Pinning this guards against the class of bug where a future
    /// `apply_pending` refactor accidentally short-circuits when the
    /// schema_version row says 3 even though the on-disk schema lacks
    /// the index — by manually setting schema_version to 3 and
    /// confirming the index appears after re-apply we exercise the
    /// `current_version < 4` gate in `apply_pending`.
    #[test]
    fn migration_4_applies_to_a_v3_database() {
        let conn = Connection::open_in_memory().unwrap();

        // Simulate a database that completed migration 3. We get
        // there by running `apply_pending` and then deleting the
        // migration_4 artifacts (the index + the v=4 schema_version
        // row). This is a closer simulation of an upgraded install
        // than running just migrations 1–3 by hand.
        apply_pending(&conn).unwrap();
        conn.execute_batch(
            "DROP INDEX IF EXISTS idx_initiative_quarantines_quarantined_at;
             DELETE FROM schema_version WHERE version = 4;"
        ).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 3,
            "test pre-condition: database must be at version 3");
        let n_before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'index' AND name = 'idx_initiative_quarantines_quarantined_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_before, 0, "test pre-condition: index must be absent");

        // Now run apply_pending — it must apply ONLY migration 4
        // (the gate `current_version < 4` should skip 1–3).
        apply_pending(&conn).unwrap();

        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);
        let n_after: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'index' AND name = 'idx_initiative_quarantines_quarantined_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_after, 1,
            "migration 4 must add the index when re-running on a v3 database");
    }

    /// `apply_pending` followed by a second `apply_pending` MUST be
    /// idempotent for migration 4 too — the `IF NOT EXISTS` clause on
    /// the index plus the `INSERT OR IGNORE` on schema_version make
    /// re-running a no-op rather than a constraint violation. The
    /// generic `apply_pending_is_idempotent` test above covers this
    /// at the table level; this one pins the index specifically.
    #[test]
    fn migration_4_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();

        // Exactly one index row by this name — re-running must not
        // produce a duplicate (which would be a SQLite error anyway,
        // but the assert is the regression pin).
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'index' AND name = 'idx_initiative_quarantines_quarantined_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "exactly one index row expected after re-apply");
    }

    /// FK on `initiative_id` MUST refer to the `initiatives` table.
    /// PRAGMA foreign_keys is off by default in sqlite-rs, so we
    /// explicitly enable it here.
    #[test]
    fn initiative_quarantines_initiative_id_fk_resolves() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        apply_pending(&conn).unwrap();

        let result = conn.execute(
            &format!(
                "INSERT INTO {iq}(initiative_id, quarantined_at, quarantined_by, reason, sweep_target) \
                 VALUES ('does-not-exist', 0, 'op', NULL, NULL)",
                iq = Table::InitiativeQuarantines.as_str(),
            ),
            [],
        );
        assert!(result.is_err(),
            "INSERT referencing missing initiative_id MUST trip the FK constraint");
    }

    /// Hash-pin the rendered Migration 1 DDL.
    ///
    /// **Why this test exists.** Migration 1 is the historical v1
    /// schema; once a database has been migrated to v1 it never
    /// re-runs Migration 1, so changing this DDL silently is a real
    /// risk: fresh installs would get a different schema than already-
    /// installed databases. By pinning the SHA-256 here we force any
    /// change — whether intentional (you bumped a `Self::ALL` array,
    /// renamed a table, fixed a comment) or accidental (a
    /// reformatter touched the heredoc) — to surface in code review.
    ///
    /// **What to do when this test fails.**
    ///
    ///   1. Inspect the diff against the previous Migration 1 DDL.
    ///   2. If the change is *cosmetic only* (whitespace, comment),
    ///      update the pinned hash in this test.
    ///   3. If the change is *structural* (new column, new CHECK
    ///      value, table renamed), DO NOT just update the hash —
    ///      add a NEW migration (`apply_migration_2`) that ALTERs
    ///      already-installed databases to match. Migration 1 is a
    ///      historical record; its rendered output should change
    ///      only when intentional.
    #[test]
    fn migration_1_ddl_fingerprint_is_pinned() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let ddl = render_migration_1_ddl();
        let mut hasher = DefaultHasher::new();
        ddl.hash(&mut hasher);
        let observed = hasher.finish();

        // Pinned fingerprint of the v1 baseline DDL after the
        // INV-STORE-03 type-safe-rendering refactor. If you intend to
        // change Migration 1, see the "What to do when this test
        // fails" guidance in this test's doc comment.
        const PINNED: u64 = MIGRATION_1_DDL_PINNED_HASH;

        assert_eq!(
            observed, PINNED,
            "Migration 1 DDL drifted from the pinned hash. \
             If this is intentional and cosmetic-only, update PINNED \
             to {observed:#x}. If this is a structural schema change, \
             add a new migration_2 instead — see test doc comment.",
        );
    }

    /// Pinned hash of the v1 baseline DDL produced by
    /// `render_migration_1_ddl()`. Captured on a 64-bit Unix host
    /// after the INV-STORE-03 type-safe-rendering refactor landed.
    ///
    /// **Stability contract.** `DefaultHasher` is a `SipHash` with a
    /// fixed initial state; the digest is deterministic across
    /// builds and platforms FOR A GIVEN STD LIBRARY VERSION. If a
    /// future Rust release bumps the hasher's seed (rare but
    /// possible), this constant will need a one-time refresh.
    /// That refresh is itself a "cosmetic-only" change and does NOT
    /// require a new migration.
    /// Refresh history:
    ///   - 2026-05: spec/migration parity audit added a SQL comment
    ///     above `idx_delegations_session_capability` documenting its
    ///     redundancy with the implicit `UNIQUE (session_id,
    ///     capability_class)` autoindex. Comment-only — no schema
    ///     change in `sqlite_master`. Old hash 0xe3ec_727b_574e_cb66.
    const MIGRATION_1_DDL_PINNED_HASH: u64 = 0xfeb2_8c71_a42f_649f;

    /// Variant counts of every enum the DDL renders are pinned. A
    /// future PR that adds a new `TaskState` variant (etc.) MUST
    /// touch both this test AND a new migration that ALTERs the
    /// already-installed CHECK constraint — the count assertion
    /// makes the first half visible at the test level so a reviewer
    /// notices the schema-touching change before the hash assertion
    /// above does.
    #[test]
    fn enum_variant_counts_are_pinned_to_v1() {
        assert_eq!(InitiativeState::ALL.len(), 7,
            "InitiativeState v1 has 7 variants; bumping this requires migration_2");
        assert_eq!(TaskState::ALL.len(), 8,
            "TaskState v1 has 8 variants; bumping this requires migration_2");
        assert_eq!(EscalationStatus::ALL.len(), 6,
            "EscalationStatus v1 has 6 variants; bumping this requires migration_2");
        assert_eq!(WitnessResultClass::ALL.len(), 3,
            "WitnessResultClass v1 has 3 variants; bumping this requires migration_2");
        assert_eq!(DelegationStatus::STORED.len(), 3,
            "DelegationStatus v1 STORED has 3 variants; bumping this requires migration_2");
    }
}
