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
    CloneStrategy, DelegationStatus, EscalationStatus, InitiativeState,
    IntegrationMergeAttemptDiscardReason, IntegrationMergeAttemptState, PlanBundleNonceOutcome,
    ReviewVerdict, SessionAgentType, SubtaskActivationState, TaskState, WitnessResultClass,
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
pub const SCHEMA_VERSION: u32 = 20;

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
    if current_version < 5 {
        apply_migration_5(conn)?;
    }
    if current_version < 6 {
        apply_migration_6(conn)?;
    }
    if current_version < 7 {
        apply_migration_7(conn)?;
    }
    if current_version < 8 {
        apply_migration_8(conn)?;
    }
    if current_version < 9 {
        apply_migration_9(conn)?;
    }
    if current_version < 10 {
        apply_migration_10(conn)?;
    }
    if current_version < 11 {
        apply_migration_11(conn)?;
    }
    if current_version < 12 {
        apply_migration_12(conn)?;
    }
    if current_version < 13 {
        apply_migration_13(conn)?;
    }
    if current_version < 14 {
        apply_migration_14(conn)?;
    }
    if current_version < 15 {
        apply_migration_15(conn)?;
    }
    if current_version < 16 {
        apply_migration_16(conn)?;
    }
    if current_version < 17 {
        apply_migration_17(conn)?;
    }
    if current_version < 18 {
        apply_migration_18(conn)?;
    }
    if current_version < 19 {
        apply_migration_19(conn)?;
    }
    if current_version < 20 {
        apply_migration_20(conn)?;
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
        Err(rusqlite::Error::SqliteFailure(_, Some(msg))) if msg.contains("no such table") => {
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
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 1 failed: {e}")))
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
pub fn render_migration_1_ddl() -> String {
    // ── Table-name substitutions (Table::X is the authoritative registry) ──
    let schema_version = Table::SchemaVersion.as_str();
    let initiatives = Table::Initiatives.as_str();
    let signed_plan_artifacts = Table::SignedPlanArtifacts.as_str();
    let sessions = Table::Sessions.as_str();
    let tasks = Table::Tasks.as_str();
    let task_dag_edges = Table::TaskDagEdges.as_str();
    let delegations = Table::Delegations.as_str();
    let escalations = Table::Escalations.as_str();
    let approval_tokens = Table::ApprovalTokens.as_str();
    let approval_proofs = Table::ApprovalProofs.as_str();
    let approval_token_nonces = Table::ApprovalTokenNonces.as_str();
    let verifier_run_tokens = Table::VerifierRunTokens.as_str();
    let witness_records = Table::WitnessRecords.as_str();
    let lane_budget_reservations = Table::LaneBudgetReservations.as_str();
    let lineage_rate_limits = Table::LineageRateLimits.as_str();
    let nonce_cache = Table::NonceCache.as_str();
    let task_intent_ranges = Table::TaskIntentRanges.as_str();
    let task_exported_path_snapshots = Table::TaskExportedPathSnapshots.as_str();
    let policy_epoch_history = Table::PolicyEpochHistory.as_str();

    // ── CHECK-constraint enum substitutions (raxis_types is authoritative) ─
    let initiative_state_check =
        check_in_clause(&InitiativeState::ALL, InitiativeState::as_sql_str);
    let task_state_check = check_in_clause(&TaskState::ALL, TaskState::as_sql_str);
    let escalation_status_check =
        check_in_clause(&EscalationStatus::ALL, EscalationStatus::as_sql_str);
    let witness_result_class_check =
        check_in_clause(&WitnessResultClass::ALL, WitnessResultClass::as_sql_str);
    // `DelegationStatus::STORED` carries the subset that actually appears
    // at-rest (kernel-store.md §2.5.1 Table 7); the runtime-derived
    // `Expired` and synthetic `NotGranted` do NOT belong in the CHECK.
    let delegation_status_check = check_in_clause(&DelegationStatus::STORED, |s| {
        DelegationStatus::as_sql_str(s).expect("STORED variants must serialise")
    });

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
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 2 failed: {e}")))
}

/// The complete migration-2 DDL — adds `operator_certificates` plus
/// its lookup indexes. Same INV-STORE-03 contract as migration 1:
/// no raw table-name literals.
pub fn render_migration_2_ddl() -> String {
    let operator_certificates = Table::OperatorCertificates.as_str();
    let policy_epoch_history = Table::PolicyEpochHistory.as_str();
    let schema_version = Table::SchemaVersion.as_str();

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
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 3 failed: {e}")))
}

/// The complete migration-3 DDL — adds `initiative_quarantines` and
/// extends `signed_plan_artifacts` with the operator fingerprint that
/// signed the plan (needed by `quarantine-plans-by`'s sweep query).
/// Same INV-STORE-03 contract as earlier migrations: no raw table-name
/// literals.
pub fn render_migration_3_ddl() -> String {
    let initiative_quarantines = Table::InitiativeQuarantines.as_str();
    let initiatives = Table::Initiatives.as_str();
    let signed_plan_artifacts = Table::SignedPlanArtifacts.as_str();
    let schema_version = Table::SchemaVersion.as_str();

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
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 4 failed: {e}")))
}

/// The complete migration-4 DDL — one new index, identical column
/// shape and naming to the spec's §2.5.8 DDL block. Same INV-STORE-03
/// contract as earlier migrations: no raw table-name literals.
pub fn render_migration_4_ddl() -> String {
    let initiative_quarantines = Table::InitiativeQuarantines.as_str();
    let schema_version = Table::SchemaVersion.as_str();

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
// Migration 5 — V2 hierarchical orchestration substrate.
// v2-deep-spec.md §1.2 (Steps 5, 6, 12, 16) and INV-DELEGATE-01.
//
// This single migration covers four V2 schema additions that arrive as
// one atomic step because they collectively unlock the V2 sub-task
// authority chain — partial application would leave the kernel
// rejecting V2 plans at approve_plan time anyway:
//
//   1. `sessions.session_agent_type TEXT` — Orchestrator | Executor |
//      Reviewer; NULL for V1-style legacy sessions (V1 path stays
//      working).
//   2. `sessions.can_delegate INTEGER NOT NULL DEFAULT 0` — INV-DELEGATE-01
//      gate (only Orchestrator may submit ActivateSubTask). The CHECK
//      constraint at the column level forbids stray non-{0,1} values
//      from a SQL-level write, while a row-level CHECK enforces
//      INV-DELEGATE-01 directly: can_delegate=1 ⇒ session_agent_type=
//      'Orchestrator'.
//   3. `sessions.vsock_cid INTEGER` — VSock context id for the planner
//      VM. NULL for V1 UDS sessions; populated by V2 create_session
//      when the kernel spawns the microVM. Read on hot-restart to
//      rebuild the in-memory CID allowlist (v2-deep-spec.md §Step 16).
//   4. `subtask_activations` table — separate FSM from `tasks.state`
//      so V2 pre-activation rows do not pollute the V1 operational FSM
//      and the recovery::reconcile_tasks sweep
//      (v2-deep-spec.md §Step 5). Carries `crash_retry_count` and
//      `review_reject_count` per v2-deep-spec.md §Step 12 (dual retry
//      counters), plus `evaluation_sha` for Reviewer activations.
//
// **V1 backward compatibility.** Every column added to `sessions` is
// either NULLable or has a default; existing V1 rows survive without
// modification and existing V1 handlers continue to read the row
// without observing any new fields. The new `subtask_activations`
// table is created empty; V1 initiatives never insert into it.
//
// Why a single migration rather than four: each piece is
// individually trivial and they share the same review cycle. Splitting
// them would force four separate hash pins on the rendered DDL with
// no operational benefit.
// ---------------------------------------------------------------------------

fn apply_migration_5(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_5_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 5 failed: {e}")))
}

/// The complete migration-5 DDL. Same INV-STORE-03 contract as earlier
/// migrations: every table identifier is rendered through `Table::...
/// .as_str()` and every CHECK-constraint enum list is rendered through
/// `check_in_clause` over the corresponding `raxis_types` enum.
pub fn render_migration_5_ddl() -> String {
    let sessions = Table::Sessions.as_str();
    let tasks = Table::Tasks.as_str();
    let initiatives = Table::Initiatives.as_str();
    let subtask_activations = Table::SubtaskActivations.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    let session_agent_type_check =
        check_in_clause(&SessionAgentType::ALL, SessionAgentType::as_sql_str);
    let activation_state_check = check_in_clause(
        &SubtaskActivationState::ALL,
        SubtaskActivationState::as_sql_str,
    );

    format!(
        "
BEGIN EXCLUSIVE;

-- ── sessions: V2 hierarchical orchestration columns ─────────────────────────
-- session_agent_type: NULL for V1 sessions, NOT NULL on every V2 row
-- (enforced at the application layer in create_session — column level
-- stays NULLable for V1 backward compatibility). The CHECK constraint
-- pins the universe of legal V2 values.
ALTER TABLE {sessions}
    ADD COLUMN session_agent_type TEXT
        CHECK (session_agent_type IS NULL
               OR session_agent_type IN {session_agent_type_check});

-- can_delegate: gate for ActivateSubTask. Defaults to 0 so V1 rows are
-- unaffected. The row-level CHECK enforces INV-DELEGATE-01 directly:
-- can_delegate=1 implies session_agent_type='Orchestrator'. The
-- bidirectional guarantee (Orchestrator ⇒ can_delegate=1) is enforced
-- at the application layer in create_session because a SQL CHECK
-- cannot reference a default-derivation rule.
ALTER TABLE {sessions}
    ADD COLUMN can_delegate INTEGER NOT NULL DEFAULT 0
        CHECK (can_delegate IN (0, 1)
               AND (can_delegate = 0 OR session_agent_type = 'Orchestrator'));

-- vsock_cid: context id for the planner microVM. NULL for V1 UDS
-- sessions and for V2 sessions before the VM is spawned (the kernel
-- writes it AFTER the hypervisor returns the assigned CID). Read on
-- hot-restart by bootstrap.rs to rebuild the in-memory CID allowlist
-- BEFORE opening the VSock listener.
ALTER TABLE {sessions}
    ADD COLUMN vsock_cid INTEGER;

-- Lookup: bootstrap.rs hot-restart query — rebuild the CID allowlist
-- in O(active V2 sessions). V1 sessions (vsock_cid IS NULL) are not
-- in this index thanks to the partial-index predicate.
CREATE INDEX IF NOT EXISTS idx_sessions_vsock_cid
    ON {sessions} (vsock_cid)
    WHERE vsock_cid IS NOT NULL AND revoked = 0;

-- ── Table 22: subtask_activations ───────────────────────────────────────────
-- Per-(initiative, sub-task) activation FSM. One row per activation
-- attempt — a retry inserts a NEW row, never updates the prior one.
-- Inserted by approve_plan → admit_in_tx in the same transaction
-- that inserts the corresponding `tasks` row (INV-STORE-02).
--
-- Columns:
--   activation_id       — UUID; PK. New uuid per (re)activation.
--   task_id             — FK to tasks.task_id. The (V2 Executor or
--                         Reviewer) sub-task this activation is for.
--   initiative_id       — denormalised FK for fast per-initiative
--                         queries on the recovery sweep.
--   activation_state    — PendingActivation | Active | Completed |
--                         Failed (CHECK constraint, drift-pinned in
--                         tests below).
--   session_id          — FK to sessions.session_id once a VM is
--                         spawned and the session row is bound. NULL
--                         while activation_state = 'PendingActivation'.
--   evaluation_sha      — for Reviewer activations: the Executor's
--                         CompleteTask head_sha captured at admission
--                         time. NULL for Executor activations and for
--                         Reviewer rows in PendingActivation (it is
--                         filled by the Kernel when the predecessor
--                         Executor's CompleteTask is admitted).
--   crash_retry_count   — incremented by the Kernel on OS-level VM
--                         death (SIGCHLD / non-zero exit). Ceiling:
--                         `max_crash_retries` from the signed plan.
--                         Per v2-deep-spec.md §Step 12.
--   review_reject_count — incremented by the Kernel when a Reviewer
--                         submits `approved: false` for this sub-task.
--                         Ceiling: `max_review_rejections` from the
--                         signed plan. Per v2-deep-spec.md §Step 12.
--   created_at          — Unix seconds, clock-injected at insert.
--   activated_at        — set when state transitions to Active.
--   terminated_at       — set when state transitions to terminal
--                         (Completed | Failed).
--
-- The dual retry counters are deliberately separate: a VM that
-- OOM-crashes shares NO counter with a sub-task whose code review
-- failed, because the two failure modes have different remediation
-- strategies (crash → just retry, review-fail → planner is
-- consistently producing wrong code → human escalation).
CREATE TABLE IF NOT EXISTS {subtask_activations} (
    activation_id        TEXT    NOT NULL PRIMARY KEY,
    task_id              TEXT    NOT NULL
        REFERENCES {tasks}(task_id),
    initiative_id        TEXT    NOT NULL
        REFERENCES {initiatives}(initiative_id),
    activation_state     TEXT    NOT NULL
        CHECK (activation_state IN {activation_state_check}),
    session_id           TEXT
        REFERENCES {sessions}(session_id),
    evaluation_sha       TEXT,
    crash_retry_count    INTEGER NOT NULL DEFAULT 0
        CHECK (crash_retry_count >= 0),
    review_reject_count  INTEGER NOT NULL DEFAULT 0
        CHECK (review_reject_count >= 0),
    created_at           INTEGER NOT NULL,
    activated_at         INTEGER,
    terminated_at        INTEGER,
    -- Cross-column invariants:
    --   * Active rows always have a session_id.
    --   * Terminal rows always have a terminated_at.
    --   * activated_at is set ⇔ state has reached Active or beyond.
    CHECK (
        (activation_state = 'PendingActivation' AND session_id IS NULL
         AND activated_at IS NULL AND terminated_at IS NULL)
        OR (activation_state = 'Active' AND session_id IS NOT NULL
            AND activated_at IS NOT NULL AND terminated_at IS NULL)
        OR (activation_state IN ('Completed', 'Failed')
            AND activated_at IS NOT NULL AND terminated_at IS NOT NULL)
    )
);

-- Lookup: \"all activations for this task\" — used by RetrySubTask to
-- find the most-recent terminal row, and by audit replay tools.
CREATE INDEX IF NOT EXISTS idx_subtask_activations_task_id
    ON {subtask_activations} (task_id, created_at DESC);

-- Lookup: \"all V2 sub-tasks pending activation in this initiative\" —
-- the Orchestrator prompt assembler (Layer 2 prompt-hiding) consults
-- this on every InferenceRequest to filter the visible activatable
-- list.
CREATE INDEX IF NOT EXISTS idx_subtask_activations_pending
    ON {subtask_activations} (initiative_id, activation_state)
    WHERE activation_state = 'PendingActivation';

-- Lookup: \"every active V2 session\" — used by recovery::reconcile_tasks
-- to find activations whose underlying VM died with the kernel and
-- need crash_retry_count incremented during boot.
CREATE INDEX IF NOT EXISTS idx_subtask_activations_active
    ON {subtask_activations} (initiative_id, activation_state)
    WHERE activation_state = 'Active';

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (5, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 6 — V2 critique routing column on `tasks`.
// v2-deep-spec.md §Step 22 ("Critique routing") and §Step 25 ("Parallel
// reviewer aggregation").
//
// Adds a single nullable text column:
//
//   tasks.last_critique TEXT  — most recent reviewer-rejection critique,
//                               aggregated across N parallel reviewers
//                               for the SAME activation; cleared at the
//                               next activation. The Kernel writes it
//                               on `IntentKind::SubmitReview` with
//                               `approved=false`; the Executor's retry
//                               prompt assembler reads it to prepend
//                               into the system prompt (Step 22).
//
// **Why on `tasks` rather than `subtask_activations`.** v2-deep-spec.md
// is internally inconsistent here: §Step 22 sketches the Kernel writing
// to `tasks.last_critique` (singular, per-task), while the activation
// recovery sweep contemplates per-activation critiques. We resolve in
// favor of `tasks.last_critique` because:
//   1. The Executor only ever consumes the LATEST critique on retry —
//      historical critiques are append-only audit material, never
//      prompt material. Putting it on `tasks` matches the consumer.
//   2. Aggregation across N parallel reviewers (Step 25) writes ONE
//      logical-AND verdict; the natural shape is a single row that
//      mutates, not a per-reviewer history table.
//   3. The aspirational DDL in v2-deep-spec.md §Part 8 places it on
//      `tasks`; the working DDL in §1.2 was a transcription drift.
// Spec drift is corrected in this migration's spec reference (Part 8
// is now authoritative for this column).
//
// **V1 backward compatibility.** The new column is NULLable with no
// default; every V1 row gets `NULL` and every V1 read continues to
// work because no V1 code reads `last_critique`.
// ---------------------------------------------------------------------------

fn apply_migration_6(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_6_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 6 failed: {e}")))
}

/// The complete migration-6 DDL. INV-STORE-03: every table identifier
/// is rendered through `Table::...as_str()`.
pub fn render_migration_6_ddl() -> String {
    let tasks = Table::Tasks.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- ── tasks: V2 critique routing column ─────────────────────────────────────
-- last_critique: most-recent aggregated reviewer critique for this
-- (sub)task. NULL for V1 tasks and for V2 tasks that have never been
-- rejected. Hard-capped at MAX_CRITIQUE_BYTES at the application layer
-- (v2-deep-spec.md §Step 22) — the database does NOT enforce length so
-- a forensic dump can preserve the full payload that the kernel
-- accepted. Cleared (set NULL) on every fresh activation by the
-- subtask activation handler.
ALTER TABLE {tasks}
    ADD COLUMN last_critique TEXT;

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (6, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 7 — V2 per-Reviewer verdict column on `tasks`.
// v2-deep-spec.md §Step 25 ("Parallel Reviewers and the Logical AND Verdict").
//
// Adds a single nullable text column with a CHECK constraint:
//
//   tasks.review_verdict TEXT CHECK (review_verdict IN ('Approved',
//                                                        'Rejected'))
//
//     NULL  — no SubmitReview accepted for this task yet.
//     'Approved' — Reviewer submitted `approved=true`.
//     'Rejected' — Reviewer submitted `approved=false`.
//
// Why on `tasks` rather than `subtask_activations`. The Step 25
// aggregation pass joins `task_dag_edges → tasks.review_verdict` to
// answer the question "have all sibling Reviewers of this Executor
// submitted, and what's the AND verdict?" — putting the column on
// `tasks` makes that a single one-row-per-Reviewer query without a
// per-activation history scan. The PER-ACTIVATION verdict signal lives
// on `subtask_activations.activation_state` (Completed = kernel
// accepted the verdict; the actual approve/reject signal is the
// per-task `review_verdict` column added here). See doc on
// `raxis_types::ReviewVerdict` for the full reasoning.
//
// V1 backward compatibility: NULLable, no DEFAULT — every V1 row keeps
// `NULL`, every V1 read continues to work.
// ---------------------------------------------------------------------------

fn apply_migration_7(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_7_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 7 failed: {e}")))
}

/// The complete migration-7 DDL. INV-STORE-03: every table identifier
/// is rendered through `Table::...as_str()`; the CHECK clause is
/// rendered through the `ReviewVerdict` enum.
pub fn render_migration_7_ddl() -> String {
    let tasks = Table::Tasks.as_str();
    let schema_version = Table::SchemaVersion.as_str();
    let review_verdict_check = check_in_clause(&ReviewVerdict::ALL, ReviewVerdict::as_sql_str);

    format!(
        "
BEGIN EXCLUSIVE;

-- ── tasks: V2 per-Reviewer verdict column ─────────────────────────────────
-- review_verdict: latest verdict for this (Reviewer) task. NULL for
-- pre-V2 tasks and for Reviewer tasks that have not yet submitted.
-- Written by `handlers/intent::handle_submit_review` on accept of a
-- SubmitReview, alongside the FSM transition Running → Completed (one
-- SQLite tx, INV-STORE-02 Pattern B). Cleared (set NULL) on every fresh
-- activation by the subtask activation handler — same lifecycle as
-- `last_critique`.
ALTER TABLE {tasks}
    ADD COLUMN review_verdict TEXT
        CHECK (review_verdict IS NULL
               OR review_verdict IN {review_verdict_check});

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (7, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 8 — V2 Plan Bundle Sealing storage layout (§8.2)
//
// Normative reference: plan-bundle-sealing.md §8.2 ("Storage layout").
//
// Adds three V2 tables and one V1-table column:
//   1. `plan_bundles`             — content-addressed store of every
//                                    operator-signed plan bundle, keyed by
//                                    bundle_sha256. Retained indefinitely
//                                    (§10 / D8).
//   2. `plan_bundle_artifacts`    — per-artifact rows (artifact_seq=0 ⇒
//                                    plan.toml; 1.. ⇒ host-path artifacts).
//   3. `plan_bundle_nonces_seen`  — replay-protection state (§3.5). The
//                                    only `plan_bundle_*` table that
//                                    participates in periodic GC (§8.4).
//   4. `initiatives.plan_bundle_sha256` — V2 admission's reference into
//                                    `plan_bundles`. NULLable for V1 rows;
//                                    every V2 row carries a non-NULL
//                                    bundle reference (enforced at
//                                    admission time, NOT in DDL — V1
//                                    rows that pre-date the column must
//                                    keep working unchanged).
//
// V1 backward compatibility: every existing `initiatives` row keeps its
// `plan_artifact_sha256` (the V1 reference into `signed_plan_artifacts`)
// and gets `plan_bundle_sha256 = NULL`. The V1 admission path is removed
// for new initiatives (handled at the kernel-level `OperatorRequest`
// dispatcher), but V1 reads (audit replay, recovery of pre-V2 history)
// continue to work against the unchanged `signed_plan_artifacts` table.
//
// Replay-protection sweep cadence is implemented in
// `kernel-lifecycle.md`'s maintenance loop, NOT in this migration.
// Migration only creates the table + supporting index. The sweep query
// itself (§8.4) lives in the kernel runtime path.
// ---------------------------------------------------------------------------

fn apply_migration_8(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_8_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 8 failed: {e}")))
}

/// The complete migration-8 DDL. INV-STORE-03: every table identifier
/// is rendered through `Table::...as_str()`; the CHECK clause is
/// rendered through the `PlanBundleNonceOutcome` enum.
pub fn render_migration_8_ddl() -> String {
    let initiatives = Table::Initiatives.as_str();
    let plan_bundles = Table::PlanBundles.as_str();
    let plan_bundle_artifacts = Table::PlanBundleArtifacts.as_str();
    let plan_bundle_nonces_seen = Table::PlanBundleNoncesSeen.as_str();
    let schema_version = Table::SchemaVersion.as_str();
    let outcome_check = check_in_clause(
        &PlanBundleNonceOutcome::ALL,
        PlanBundleNonceOutcome::as_sql_str,
    );

    format!(
        "
BEGIN EXCLUSIVE;

-- ── plan_bundles ─────────────────────────────────────────────────────────
-- Content-addressed store of admitted V2 plan bundles. Keyed by the
-- canonical bundle_sha256 (32 bytes, the hash the operator signed); two
-- initiatives that happen to use byte-identical bundles share a single
-- row here.
--
-- Retained indefinitely per plan-bundle-sealing.md §10 (D8): the bundle
-- bytes are foundational cryptographic input to the initiative state
-- machine, and audit-chain replay needs to be able to re-derive the
-- exact plan the kernel executed.
--
-- Schema-1 envelopes (V2.0 cutover bundles) carry NULL for
-- signed_at_unix_secs / bundle_nonce. Schema-2 envelopes (V2.1 default)
-- carry both. The kernel admission path enforces the schema-vs-fields
-- contract at decode time.
CREATE TABLE IF NOT EXISTS {plan_bundles} (
    bundle_sha256          BLOB    NOT NULL PRIMARY KEY,
    bundle_bytes           BLOB    NOT NULL,
    signature              BLOB    NOT NULL,
    signed_by              BLOB    NOT NULL,
    schema_version         INTEGER NOT NULL,
    artifact_count         INTEGER NOT NULL,
    bundle_bytes_len       INTEGER NOT NULL,
    sealed_at_unix_secs    INTEGER NOT NULL,
    signed_at_unix_secs    INTEGER,
    bundle_nonce           BLOB,
    CHECK (length(bundle_sha256) = 32),
    CHECK (length(signature)     = 64),
    CHECK (length(signed_by)     = 8),
    CHECK (schema_version IN (1, 2)),
    CHECK (artifact_count   >= 1),
    CHECK (bundle_bytes_len >= 0),
    CHECK (
        (schema_version = 1
         AND signed_at_unix_secs IS NULL
         AND bundle_nonce        IS NULL)
        OR
        (schema_version = 2
         AND signed_at_unix_secs IS NOT NULL
         AND bundle_nonce        IS NOT NULL
         AND length(bundle_nonce) = 16)
    )
);

-- ── plan_bundle_artifacts ────────────────────────────────────────────────
-- Per-artifact rows. artifact_seq=0 is always plan.toml; subsequent rows
-- (1..) are operator-declared host-path artifacts. The composite PK
-- gives the kernel an O(1) lookup by (bundle, seq) without a secondary
-- index, and ON DELETE is moot here because `plan_bundles` rows are
-- never deleted (§10).
CREATE TABLE IF NOT EXISTS {plan_bundle_artifacts} (
    bundle_sha256        BLOB    NOT NULL
        REFERENCES {plan_bundles}(bundle_sha256),
    artifact_seq         INTEGER NOT NULL,
    artifact_name        TEXT    NOT NULL,
    artifact_sha256      BLOB    NOT NULL,
    artifact_bytes       BLOB    NOT NULL,
    artifact_bytes_len   INTEGER NOT NULL,
    PRIMARY KEY (bundle_sha256, artifact_seq),
    CHECK (length(artifact_sha256) = 32),
    CHECK (artifact_seq        >= 0),
    CHECK (artifact_bytes_len  >= 0)
);

-- ── plan_bundle_nonces_seen ──────────────────────────────────────────────
-- Replay-protection state (plan-bundle-sealing.md §3.5). One row per
-- consumed bundle_nonce. `outcome` distinguishes whether the nonce was
-- consumed by a successful admission (`Admitted`, with a non-NULL
-- initiative_id) or a terminal rejection (`TerminallyRejected`,
-- initiative_id is NULL).
--
-- Sweep schedule: rows older than (max_plan_bundle_age_secs +
-- max_clock_skew_secs + nonce_retention_grace_secs) are reaped by the
-- kernel's maintenance loop (§8.4). The freshness window in §3.5
-- guarantees a reaped row's nonce is no longer admissible (step 10a
-- rejects with FAIL_PLAN_BUNDLE_EXPIRED before step 10b queries this
-- table).
CREATE TABLE IF NOT EXISTS {plan_bundle_nonces_seen} (
    bundle_nonce             BLOB    NOT NULL PRIMARY KEY,
    bundle_sha256            BLOB    NOT NULL,
    signed_at_unix_secs      INTEGER NOT NULL,
    first_seen_at_unix_secs  INTEGER NOT NULL,
    outcome                  TEXT    NOT NULL
        CHECK (outcome IN {outcome_check}),
    initiative_id            TEXT,
    CHECK (length(bundle_nonce)   = 16),
    CHECK (length(bundle_sha256) = 32),
    -- Admitted rows MUST carry an initiative_id; TerminallyRejected
    -- rows MUST carry NULL. Enforces the §8.1 step 12b contract at the
    -- DDL layer so a future code path that forgets the join-key cannot
    -- silently violate it.
    CHECK (
        (outcome = 'Admitted'           AND initiative_id IS NOT NULL)
        OR
        (outcome = 'TerminallyRejected' AND initiative_id IS NULL)
    )
);

-- Sweep-driver index. The §8.4 retention DELETE filters on
-- first_seen_at_unix_secs; without this index it'd be a full scan.
CREATE INDEX IF NOT EXISTS idx_plan_bundle_nonces_first_seen
    ON {plan_bundle_nonces_seen}(first_seen_at_unix_secs);

-- ── initiatives.plan_bundle_sha256 ───────────────────────────────────────
-- V2 admissions populate this column with the bundle's canonical hash,
-- which joins back to plan_bundles. V1 admissions kept plan_artifact_sha256
-- and leave this NULL.
ALTER TABLE {initiatives}
    ADD COLUMN plan_bundle_sha256 BLOB
        REFERENCES {plan_bundles}(bundle_sha256);

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (8, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 9 — `tasks.clone_strategy` column for V2 worktree provisioning.
//
// Normative references:
//   * v2-deep-spec.md §Step 27 ("Sparse-clone strategies")
//   * worktree-provision/src/lib.rs — the §Step 27 doc-comments at the
//     top of that crate name `tasks.clone_strategy` as the persistence
//     target for the strategy chosen at admission time.
//
// Adds a single nullable text column with a CHECK constraint pinning
// the universe of legal values to `CloneStrategy::ALL`:
//
//   tasks.clone_strategy TEXT
//       — `full` | `blobless` | `sparse`. NULL on every V1 row (V1
//         knows nothing about clone strategies); NOT NULL on every V2
//         row, enforced at the application layer in admission rather
//         than in DDL so V1 tasks already on disk continue to read
//         cleanly after the column is added.
//
// **Why on `tasks` rather than `subtask_activations`.** The clone
// strategy is a property of the *task* (declared once at admission
// time and re-used on every retry of that task), not of an individual
// activation attempt. Putting it on `tasks` matches the producer
// (admission writes once) and the consumer (worktree provisioning
// reads it whenever it materialises a new sandbox for a fresh
// activation of the same task). `subtask_activations` rows already
// reference `tasks.task_id`, so the strategy is one JOIN away when
// per-activation queries need it.
//
// **V1 backward compatibility.** The new column is NULLable with no
// default, so every existing V1 row gets `NULL` automatically and
// every V1 read continues to work unchanged. The CHECK clause
// permits NULL explicitly; admission rejects V2 tasks that fail to
// supply a strategy at the application layer.
// ---------------------------------------------------------------------------

fn apply_migration_9(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_9_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 9 failed: {e}")))
}

/// The complete migration-9 DDL. INV-STORE-03: every table identifier
/// is rendered through `Table::...as_str()`; the CHECK clause is
/// rendered through the `CloneStrategy` enum's `ALL` array.
pub fn render_migration_9_ddl() -> String {
    let tasks = Table::Tasks.as_str();
    let schema_version = Table::SchemaVersion.as_str();
    let clone_strategy_check = check_in_clause(&CloneStrategy::ALL, CloneStrategy::as_sql_str);

    format!(
        "
BEGIN EXCLUSIVE;

-- ── tasks: V2 worktree clone strategy column ──────────────────────────────
-- clone_strategy: chosen at admission time per v2-deep-spec.md §Step 27.
-- One of `full`, `blobless`, `sparse`. NULL on every V1 row; NOT NULL
-- on every V2 row (enforced at the application layer in admit_in_tx —
-- column-level NULLability is preserved here for V1 backward
-- compatibility). The CHECK clause pins the universe of legal V2
-- values through `CloneStrategy::ALL`, drift-protected by
-- `tests::migration_9_clone_strategy_check_pins_known_variants` below.
ALTER TABLE {tasks}
    ADD COLUMN clone_strategy TEXT
        CHECK (clone_strategy IS NULL
               OR clone_strategy IN {clone_strategy_check});

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (9, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 10 — `task_credential_proxies` table: per-task credential-proxy
// declarations persisted at approve_plan time.
//
// Normative references:
//   * credential-proxy.md §3 ("Plan-level declarations")
//   * v2-deep-spec.md §Step 17 ("approve_plan shift-left validation")
//
// ⚠ THIS TABLE DOES NOT STORE CREDENTIAL VALUES.
//
// `task_credential_proxies` is a metadata-only registry of which
// credential proxies should be bound for each task. Each row carries:
//
//   task_credential_proxies(task_id, credential_name, mount_as,
//                           proxy_type, proxy_json,
//                           created_at_unix_secs)
//       — one row per `[[tasks.credentials]]` block declared on a
//         V2 task. Inserted by `approve_plan` in the SAME
//         transaction that inserts the parent `tasks` row
//         (INV-STORE-02). Read once at session-spawn time by the
//         kernel's `CredentialProxyManager`, which deserialises
//         `proxy_json` back into
//         `raxis_plan_credentials::TaskCredentialDecl` and uses the
//         resulting decl to bind a fresh proxy listener.
//
// The credential bytes themselves (postgres URL with password,
// bearer tokens, kubeconfig YAML, …) are NEVER persisted in
// `kernel.db`. They live with the kernel's `CredentialBackend`. The
// reference `FileCredentialBackend` stores them on disk in
// `~/.config/raxis/credentials/<name>.env` with `0600` perms
// enforced. Production deployments may swap in a `VaultBackend`,
// `AwsSecretsManagerBackend`, or similar — but the kernel.db schema
// stays the same: it only holds the *names* of credentials and the
// proxy restrictions to apply.
//
// **Naming.** The table is `task_credential_proxies`, NOT
// `task_credentials`. The shorter name was rejected because it
// would falsely imply that credential bytes are persisted here.
//
// **Why a JSON column for `proxy_json`** (vs. a normalised
// per-proxy-type column set):
//   * Per-proxy-type fields drift independently:
//     - postgres has `allow_only_select`
//     - http  has `auth_mode`, `upstream_url`, allowed_methods,
//             allowed_path_prefixes
//     - k8s   reuses http restrictions but is auditing-distinct
//     - smtp  (future) adds rate-limit fields
//   * The kernel never UPDATEs this column outside of the approve_plan
//     transaction — it is a write-once, read-once property of the
//     admitted task.
//   * JSON keeps the schema flat across proxy types while preserving
//     per-proxy fidelity. The `proxy_type` column is projected out of
//     the JSON for index/query convenience and to enable a CHECK
//     clause that pins the legal proxy-type universe.
//
// **Composite primary key.** `(task_id, credential_name)` is unique
// per task; `raxis-plan-credentials` already enforces this in its
// parser (`parse_for_task` rejects duplicate `name` within a task),
// but pinning it in DDL also as the PK gives us a hard backstop.
//
// **V1 backward compatibility.** New table; no V1 rows. Migration 10
// is idempotent on a fresh DB *and* on a DB already at version 9.
// ---------------------------------------------------------------------------

fn apply_migration_10(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_10_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 10 failed: {e}")))
}

/// The complete migration-10 DDL. INV-STORE-03: every table
/// identifier is rendered through `Table::...as_str()`. The
/// `proxy_type` CHECK clause is hand-pinned to the four MVP
/// variants declared by `raxis-plan-credentials::ProxyDecl` —
/// drift-protected by
/// `tests::migration_10_proxy_type_check_pins_known_variants`.
pub fn render_migration_10_ddl() -> String {
    let tasks = Table::Tasks.as_str();
    let task_credential_proxies = Table::TaskCredentialProxies.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- ── Table: task_credential_proxies ───────────────────────────────────────
-- METADATA ONLY. One row per [[tasks.credentials]] block per task,
-- describing WHICH credential proxy should be bound for that task.
--
-- ⚠ Credential VALUES (passwords, tokens, kubeconfig bytes, etc.)
--   are NEVER stored in this table — or anywhere else in kernel.db.
--   They live with the kernel's CredentialBackend
--   (FileCredentialBackend on disk with 0600 perms; or a VaultBackend
--   / AwsSecretsManagerBackend in production).
--
--   * task_id          — FK to tasks(task_id).
--   * credential_name  — the policy-declared NAME of the credential
--                        the proxy will resolve at bind time
--                        (e.g. \"db-prod\"). NOT the secret bytes.
--   * mount_as         — the env-var the proxy injects into the
--                        agent VM (e.g. \"DB_URL\").
--   * proxy_type       — postgres | http | k8s | smtp. CHECK-pinned.
--   * proxy_json       — the per-proxy restriction blob (allow-lists,
--                        upstream URL, etc.). NOT the secret bytes.
--
-- Inserted by approve_plan in the same transaction that admits the
-- parent task. Read once at session-spawn time by
-- CredentialProxyManager.
-- See credential-proxy.md §3 and v2-deep-spec.md §Step 17.
CREATE TABLE IF NOT EXISTS {task_credential_proxies} (
    task_id              TEXT    NOT NULL
        REFERENCES {tasks}(task_id),
    credential_name      TEXT    NOT NULL,
    mount_as             TEXT    NOT NULL,
    proxy_type           TEXT    NOT NULL
        CHECK (proxy_type IN ('postgres', 'http', 'k8s', 'smtp', 'redis', 'aws', 'gcp', 'azure')),
    proxy_json           TEXT    NOT NULL,
    created_at_unix_secs INTEGER NOT NULL,
    PRIMARY KEY (task_id, credential_name)
);

-- Lookup index. CredentialProxyManager queries by task_id at
-- session-spawn time; the composite PK already covers this prefix
-- but the explicit index makes the query plan self-documenting in
-- EXPLAIN output and survives any future PK refactor.
CREATE INDEX IF NOT EXISTS idx_task_credential_proxies_task_id
    ON {task_credential_proxies} (task_id);

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (10, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 11 — V2 pre-merge verifier attempt tracking.
// integration-merge.md §11.10.1 + §11.10.4; verifier-processes.md §16.
//
// Adds one new table:
//
//   integration_merge_attempts — one row per IntegrationMerge intent
//                                 that reaches Check 5d. Tracks the
//                                 candidate-merge-tree → pre-merge-verifier
//                                 → main-advance pipeline FSM and is
//                                 swept at boot per §11.10.4.
//
// The table is **strictly distinct** from `initiatives.git_apply_pending`
// (which gates the §11.1 phase 1→2 boundary for the actual main advance);
// `integration_merge_attempts` governs the strictly *earlier* candidate-
// merge-tree → pre-merge-verifier boundary (§11.10).
//
// Atomicity: rows are inserted at Check 5d.1 in the same `BEGIN
// IMMEDIATE` transaction that records the IntegrationMerge intent
// acceptance, so a concurrent re-submission of the same merge cannot
// race past the check. The `as_str()` literal for this table appears
// in the recovery sweep at §11.10.4 — `Table::IntegrationMergeAttempts`
// is the single point of truth (INV-STORE-03).
// ---------------------------------------------------------------------------

fn apply_migration_11(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_11_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 11 failed: {e}")))
}

/// The complete migration-11 DDL. Same INV-STORE-03 contract as
/// earlier migrations: every table identifier is rendered through
/// `Table::...as_str()` and every CHECK-constraint enum list is
/// rendered through `check_in_clause` over the corresponding
/// `raxis_types` enum. Drift between the Rust enums and the rendered
/// CHECK constraints is caught by the
/// `tests::migration_11_*_check_pins_known_variants` guards below.
pub fn render_migration_11_ddl() -> String {
    let initiatives = Table::Initiatives.as_str();
    let integration_merge_attempts = Table::IntegrationMergeAttempts.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    let attempt_state_check = check_in_clause(
        &IntegrationMergeAttemptState::ALL,
        IntegrationMergeAttemptState::as_sql_str,
    );
    let discard_reason_check = check_in_clause(
        &IntegrationMergeAttemptDiscardReason::ALL,
        IntegrationMergeAttemptDiscardReason::as_sql_str,
    );

    format!(
        "
BEGIN EXCLUSIVE;

-- ── Table: integration_merge_attempts ────────────────────────────────────
-- One row per IntegrationMerge intent that reaches Check 5d. Tracks
-- the candidate-merge-tree → pre-merge-verifier → main-advance
-- pipeline FSM and is swept at boot per integration-merge.md §11.10.4.
--
-- ⚠ Distinct from initiatives.git_apply_pending. The existing flag
--   gates the SQLite-intent → git-apply boundary for the eventual
--   main advance (§11.1); this table governs the strictly *earlier*
--   candidate-merge-tree → pre-merge-verifier boundary (§11.10).
--
--   * id                       — uuid; matches the IntegrationMerge
--                                  intent's request_id. PK.
--   * initiative_id            — FK to initiatives(initiative_id).
--   * orchestrator_session_id  — the Orchestrator session that
--                                  submitted the IntegrationMerge intent.
--   * requested_commit_sha     — the head sha the orchestrator wants
--                                  fast-forwarded onto main.
--   * candidate_merge_sha      — orphan commit that would become main
--                                  if all block_merge verifiers pass.
--                                  NULL until Check 5d.2 succeeds.
--   * state                    — IntegrationMergeAttemptState
--                                  (CHECK-pinned).
--   * discard_reason           — IntegrationMergeAttemptDiscardReason
--                                  (CHECK-pinned). NULL when state ∈
--                                  {{ AwaitingPreMergeVerifiers,
--                                     PreMergeVerifiersPassed,
--                                     CompletedAdvanceApplied }}.
--   * created_at               — Unix epoch ms; set on insert.
--   * finalized_at             — Unix epoch ms; set on transition to
--                                  any terminal state. NULL ⟺ state
--                                  is non-terminal (the recovery
--                                  sweep at §11.10.4 keys off this).
CREATE TABLE IF NOT EXISTS {integration_merge_attempts} (
    id                       TEXT    NOT NULL PRIMARY KEY,
    initiative_id            TEXT    NOT NULL
        REFERENCES {initiatives}(initiative_id),
    orchestrator_session_id  TEXT    NOT NULL,
    requested_commit_sha     TEXT    NOT NULL,
    candidate_merge_sha      TEXT,
    state                    TEXT    NOT NULL
        CHECK (state IN {attempt_state_check}),
    discard_reason           TEXT
        CHECK (discard_reason IS NULL
               OR discard_reason IN {discard_reason_check}),
    created_at               INTEGER NOT NULL,
    finalized_at             INTEGER,
    -- Cross-column invariants:
    --   * Non-terminal rows always have NULL finalized_at and NULL
    --     discard_reason.
    --   * BlockedByPreMergeVerifier / DiscardedCandidateOnly /
    --     DiscardedCrashRecovery rows always have NON-NULL
    --     discard_reason and finalized_at.
    --   * CompletedAdvanceApplied rows always have NULL discard_reason
    --     and NON-NULL finalized_at + candidate_merge_sha.
    --   * PreMergeVerifiersPassed rows have a candidate_merge_sha set
    --     (Check 5d.2 succeeded by definition of the transition).
    CHECK (
        (state = 'AwaitingPreMergeVerifiers'
            AND discard_reason IS NULL
            AND finalized_at IS NULL)
        OR (state = 'PreMergeVerifiersPassed'
            AND discard_reason IS NULL
            AND finalized_at IS NULL
            AND candidate_merge_sha IS NOT NULL)
        OR (state = 'CompletedAdvanceApplied'
            AND discard_reason IS NULL
            AND finalized_at IS NOT NULL
            AND candidate_merge_sha IS NOT NULL)
        OR (state IN ('BlockedByPreMergeVerifier',
                      'DiscardedCandidateOnly',
                      'DiscardedCrashRecovery')
            AND discard_reason IS NOT NULL
            AND finalized_at IS NOT NULL)
    )
);

-- Lookup: \"every pre-merge attempt for this initiative\" — joins
-- through audit replay and operator forensics. Keeps the per-
-- initiative scan O(rows-for-this-initiative) without a full
-- table scan.
CREATE INDEX IF NOT EXISTS idx_imerge_attempts_initiative
    ON {integration_merge_attempts} (initiative_id);

-- Lookup: \"every non-terminal attempt for this initiative\" — the
-- boot-time recovery sweep at integration-merge.md §11.10.4 reads
-- this index to fold mid-flight verifier runs whose VMs were killed
-- with the kernel. Partial index keeps the sweep O(non-terminal
-- rows) rather than O(all rows ever).
CREATE INDEX IF NOT EXISTS idx_imerge_attempts_open
    ON {integration_merge_attempts} (initiative_id)
    WHERE state IN ('AwaitingPreMergeVerifiers',
                    'PreMergeVerifiersPassed');

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (11, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 12 — V2 §2.5 per-task LLM token-usage accounting.
//
// `v2_extended_gaps.md §2.5` admission gate requires the kernel to
// know each task's cumulative LLM input/output token consumption
// AND the corresponding micro-dollar cost (derived from the
// operator-declared `[providers.<id>.pricing]` tables) to enforce
// `policy.max_cost_per_task` as a real dollar ceiling rather than a
// flat admission-units heuristic.
//
// We add three columns to `tasks`:
//
//   * cumulative_input_tokens         — INTEGER NOT NULL DEFAULT 0
//   * cumulative_output_tokens        — INTEGER NOT NULL DEFAULT 0
//   * cumulative_token_cost_micros    — INTEGER NOT NULL DEFAULT 0
//
// Why these live on `tasks` and not on a separate event table:
// admission is a per-task decision — the kernel needs the
// running totals at sub-millisecond cost on every intent
// admission. A separate event table would force an aggregate
// query (`SUM(...) WHERE task_id = ?1`) inside the admission hot
// path; co-locating the running totals on the task row keeps
// admission O(1).
//
// Audit reconstruction still works: `IntentAccepted` audit
// events carry the per-intent `tokens_used` payload (V2 §2.5
// phase D), so the full per-turn history is replayable from the
// audit chain alone.
//
// Defaults: NOT NULL DEFAULT 0 means existing rows on a V2.4 DB
// being migrated forward see "no LLM tokens charged yet" — which
// is correct because pre-migration tasks predate the
// `IntentRequest::tokens_used` field.
// ---------------------------------------------------------------------------

fn apply_migration_12(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_12_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 12 failed: {e}")))
}

/// The complete migration-12 DDL. Two `ALTER TABLE` statements add
/// the cumulative token-usage and dollar-cost columns to `tasks`.
pub fn render_migration_12_ddl() -> String {
    let tasks = Table::Tasks.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- ── tasks: V2 §2.5 cumulative LLM token accounting ───────────────────────
ALTER TABLE {tasks}
    ADD COLUMN cumulative_input_tokens INTEGER NOT NULL DEFAULT 0;

ALTER TABLE {tasks}
    ADD COLUMN cumulative_output_tokens INTEGER NOT NULL DEFAULT 0;

-- Cumulative micro-dollar cost = sum over every accepted intent of
-- `provider_pricing.cost_micro_dollars(input_tokens, output_tokens, ...)`.
-- The kernel re-computes the increment per intent from the planner-
-- reported `tokens_used` delta and the policy's worst-of-N LLM
-- pricing (matches the `EstimateCost` upper-bound contract).
ALTER TABLE {tasks}
    ADD COLUMN cumulative_token_cost_micros INTEGER NOT NULL DEFAULT 0;

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (12, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 13 — V2 §3.2 `structured_outputs` table.
//
// `v2_extended_gaps.md §3.2` typed mid-session outputs (progress
// reports, diagnostic flags, task summaries) emitted by executor /
// orchestrator agents via the `structured_output` planner tool.
//
// Schema:
//   * output_id        UUID v4 (PK), kernel-generated.
//   * initiative_id    text, FK to `initiatives.initiative_id`.
//   * task_id          text, FK to `tasks.task_id`.
//   * session_id       text, FK to `sessions.session_id`.
//   * kind             text, one of {progress_report, diagnostic_flag,
//                      task_summary} — matches
//                      `StructuredOutputKind::variant_tag`.
//   * severity         text, one of {info, warning, critical} for
//                      `diagnostic_flag` rows; NULL for
//                      `progress_report` / `task_summary`.
//   * payload_json     text, the validated/normalised
//                      `serde_json::to_string` projection of the
//                      `StructuredOutputKind` enum (tagged
//                      snake_case).
//   * emitted_at       integer unix-seconds.
//
// Indexes:
//   * `(task_id, emitted_at)` — `raxis task outputs <id>` query.
//   * `(initiative_id, emitted_at)` — dashboard initiative view.
//   * `(session_id)` — per-session rate-limit lookup
//     (`STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT`).
//
// Atomicity: a single INSERT is enough — no FSM transition, no
// budget reservation. The §3.2 handler runs its INSERT inside the
// same `BEGIN IMMEDIATE` transaction as the per-session rate-limit
// COUNT(*) so the count cannot race past the cap.
// ---------------------------------------------------------------------------

fn apply_migration_13(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_13_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 13 failed: {e}")))
}

/// The complete migration-13 DDL.
pub fn render_migration_13_ddl() -> String {
    let structured_outputs = Table::StructuredOutputs.as_str();
    let initiatives = Table::Initiatives.as_str();
    let tasks = Table::Tasks.as_str();
    let sessions = Table::Sessions.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- ── structured_outputs: V2 §3.2 typed mid-session outputs ───────────────
CREATE TABLE {structured_outputs} (
    output_id      TEXT NOT NULL PRIMARY KEY,
    initiative_id  TEXT NOT NULL REFERENCES {initiatives}(initiative_id) ON DELETE CASCADE,
    task_id        TEXT NOT NULL REFERENCES {tasks}(task_id)             ON DELETE CASCADE,
    session_id     TEXT NOT NULL REFERENCES {sessions}(session_id)       ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('progress_report', 'diagnostic_flag', 'task_summary')),
    severity       TEXT          CHECK (severity IS NULL OR severity IN ('info', 'warning', 'critical')),
    payload_json   TEXT NOT NULL,
    emitted_at     INTEGER NOT NULL
);

CREATE INDEX idx_{structured_outputs}_task
    ON {structured_outputs}(task_id, emitted_at);

CREATE INDEX idx_{structured_outputs}_initiative
    ON {structured_outputs}(initiative_id, emitted_at);

CREATE INDEX idx_{structured_outputs}_session
    ON {structured_outputs}(session_id);

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (13, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 14 — kernel-owned notifications table.
//
// Every notification the kernel generates is stored here unconditionally,
// regardless of which delivery channels (Shell, File, Email, Sidecar)
// the operator configured. This is the ground truth for `raxis inbox`,
// the dashboard notification view, and read/unread state.
//
// The inbox.jsonl file continues to be appended to as a durable fallback,
// but the SQLite table is the queryable, indexed, authoritative store.
// ---------------------------------------------------------------------------

fn apply_migration_14(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_14_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 14 failed: {e}")))
}

/// The complete migration-14 DDL.
pub fn render_migration_14_ddl() -> String {
    let notifications = Table::Notifications.as_str();
    let initiatives = Table::Initiatives.as_str();
    let tasks = Table::Tasks.as_str();
    let sessions = Table::Sessions.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- ── notifications: kernel-owned notification store ──────────────────────
CREATE TABLE {notifications} (
    notification_id  TEXT    NOT NULL PRIMARY KEY,
    event_kind       TEXT    NOT NULL,
    initiative_id    TEXT             REFERENCES {initiatives}(initiative_id) ON DELETE CASCADE,
    task_id          TEXT             REFERENCES {tasks}(task_id)             ON DELETE CASCADE,
    session_id       TEXT             REFERENCES {sessions}(session_id)       ON DELETE CASCADE,
    summary          TEXT    NOT NULL,
    payload_json     TEXT    NOT NULL,
    read             INTEGER NOT NULL DEFAULT 0 CHECK (read IN (0, 1)),
    source_event_id  TEXT    NOT NULL,
    created_at       INTEGER NOT NULL
);

-- Primary query path: unread notifications, newest first.
CREATE INDEX idx_{notifications}_unread
    ON {notifications}(read, created_at DESC);

-- Per-initiative notification history.
CREATE INDEX idx_{notifications}_initiative
    ON {notifications}(initiative_id, created_at DESC);

-- Per-task notification history.
CREATE INDEX idx_{notifications}_task
    ON {notifications}(task_id, created_at DESC);

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (14, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 15 — provider_circuit_state table.
// provider-failure-handling.md §6.3 / §6.4.
//
// Per-(provider, model) circuit-breaker state. State transitions are
// transactional: every record_failure / record_success / Open → HalfOpen
// promotion executes inside a single BEGIN IMMEDIATE that also inserts
// the CircuitBreakerStateChanged audit event (INV-PROVIDER-08).
// ---------------------------------------------------------------------------

fn apply_migration_15(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_15_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 15 failed: {e}")))
}

/// The complete migration-15 DDL.
pub fn render_migration_15_ddl() -> String {
    let provider_circuit_state = Table::ProviderCircuitState.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    // Derive the CHECK constraint from the canonical enum — single
    // source of truth (raxis-types::fsm::CircuitBreakerState).
    let state_check = raxis_types::CircuitBreakerState::sql_check_in_clause();
    let open_str = raxis_types::CircuitBreakerState::Open.as_sql_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- ── provider_circuit_state: per-(provider, model) circuit breaker ────────
CREATE TABLE {provider_circuit_state} (
    provider                  TEXT    NOT NULL,
    model                     TEXT    NOT NULL,
    state                     TEXT    NOT NULL CHECK (state IN ({state_check})),
    consecutive_failures      INTEGER NOT NULL DEFAULT 0,
    last_failure_at_ms        INTEGER,
    last_failure_kind         TEXT,
    last_failure_http_code    INTEGER,
    opened_at_ms              INTEGER,
    open_expires_at_ms        INTEGER,
    half_open_inflight        INTEGER NOT NULL DEFAULT 0 CHECK (half_open_inflight IN (0, 1)),
    last_success_at_ms        INTEGER,
    last_state_change_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (provider, model)
);

-- Index for lazy Open → HalfOpen promotion: the resolver scans for
-- rows where state = 'Open' AND open_expires_at_ms <= now().
CREATE INDEX idx_{provider_circuit_state}_open_expires
    ON {provider_circuit_state} (open_expires_at_ms)
    WHERE state = '{open_str}';

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (15, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 16 — initiatives.git_apply_pending durable-recovery flag.
// integration-merge.md §11.1 (DDL) + §11.2/§11.3 (recovery semantics).
//
// Three-phase model for IntegrationMerge admission:
//
//   * Phase 1 — SQLite BEGIN IMMEDIATE: UPDATE current_sha,
//               SET git_apply_pending = 1, INSERT
//               IntegrationMergeCompleted audit, UPDATE
//               subtask_activations.merge_included.
//   * Phase 2 — Host-side `git fetch` + `git update-ref` against
//               refs/heads/<target_ref> (idempotent).
//   * Phase 3 — Single SQLite UPDATE: git_apply_pending = 0.
//
// Between Phase 1 and Phase 3 the row carries
// `git_apply_pending = 1`. Startup recovery
// (kernel-lifecycle.md §7 + integration-merge.md §11.3) scans
// the partial index `idx_initiatives_pending_git`, runs cases
// A/B against the worktree referenced by the most-recent
// `IntegrationMergeCompleted` audit event, and either restores
// the (a) consistent state or transitions the initiative to
// `Blocked` with a `SecurityViolation { GitStateInconsistent }`
// audit event (case C — §11.8 INV-MERGE-CONSISTENCY).
//
// The partial index keeps the boot-scan O(in-flight merges)
// rather than O(all initiatives ever) (§11.1, end of section).
// ---------------------------------------------------------------------------

fn apply_migration_16(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_16_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 16 failed: {e}")))
}

/// The complete migration-16 DDL.
pub fn render_migration_16_ddl() -> String {
    let initiatives = Table::Initiatives.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- Add the recovery driver flag. Default 0 ⇒ all preexisting rows
-- are observably in INV-MERGE-CONSISTENCY case (a) the moment
-- the migration completes (no in-flight merges across boots
-- because the process restart implies any prior process exit
-- was clean for the purposes of this column — pre-V2.5 the
-- column did not exist, so there is no pending work to recover).
ALTER TABLE {initiatives} ADD COLUMN git_apply_pending INTEGER NOT NULL DEFAULT 0;

-- Partial index keyed off the recovery driver predicate so the
-- boot-time scan in integration-merge.md §11.3 is O(in-flight
-- merges) rather than O(all initiatives).
CREATE INDEX idx_initiatives_pending_git
    ON {initiatives} (initiative_id)
    WHERE git_apply_pending = 1;

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (16, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 17 — widen `task_credential_proxies.proxy_type` CHECK to
// include every variant declared by `raxis_plan_credentials::ProxyVariant`.
//
// The original migration-10 DDL pinned the CHECK to the eight V2-baseline
// proxy types (postgres, http, k8s, smtp, redis, aws, gcp, azure). Three
// later proxy variants — `mysql`, `mssql`, `mongodb` — were added to
// `crates/plan-credentials/src/lib.rs::ProxyVariant` as part of the V2.x
// integration-merge work but the on-disk CHECK was never widened to
// match. The result: a `[[tasks.credentials]] proxy_type = "mongodb"`
// block decodes cleanly through `ProxyVariant`, then `approve_plan`'s
// transactional INSERT into `task_credential_proxies` fires
// `CHECK constraint failed: proxy_type IN (...)` and the operator
// sees `FAIL_APPROVE_PLAN` with no actionable detail.
//
// SQLite does NOT support `ALTER TABLE ... DROP CONSTRAINT` (or any
// constraint-mutation idiom on a CHECK), so we rebuild the table
// using the canonical `CREATE-NEW → INSERT-FROM-OLD → DROP-OLD →
// RENAME` pattern documented at
// <https://www.sqlite.org/lang_altertable.html#otheralter>. The
// rebuild preserves the PRIMARY KEY, FK to `tasks(task_id)`, and the
// `idx_task_credential_proxies_task_id` index.
// ---------------------------------------------------------------------------

fn apply_migration_17(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_17_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 17 failed: {e}")))
}

/// The complete migration-17 DDL.
pub fn render_migration_17_ddl() -> String {
    let task_credential_proxies = Table::TaskCredentialProxies.as_str();
    let tasks = Table::Tasks.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- 1. Build the rebuilt table under a temporary name with the widened
--    CHECK. Column order, types, and constraints mirror the original
--    DDL (migration 10) modulo the `proxy_type` whitelist.
CREATE TABLE {task_credential_proxies}_new (
    task_id              TEXT    NOT NULL
        REFERENCES {tasks}(task_id),
    credential_name      TEXT    NOT NULL,
    mount_as             TEXT    NOT NULL,
    proxy_type           TEXT    NOT NULL
        CHECK (proxy_type IN (
            'postgres', 'http', 'k8s', 'smtp', 'redis',
            'aws',      'gcp',  'azure',
            'mysql',    'mssql', 'mongodb'
        )),
    proxy_json           TEXT    NOT NULL,
    created_at_unix_secs INTEGER NOT NULL,
    PRIMARY KEY (task_id, credential_name)
);

-- 2. Copy every existing row over. Pre-migration rows by definition
--    pass the original (narrower) CHECK so they pass the widened
--    CHECK trivially.
INSERT INTO {task_credential_proxies}_new
    (task_id, credential_name, mount_as, proxy_type, proxy_json,
     created_at_unix_secs)
SELECT task_id, credential_name, mount_as, proxy_type, proxy_json,
       created_at_unix_secs
  FROM {task_credential_proxies};

-- 3. Drop the old table (also drops the old index).
DROP TABLE {task_credential_proxies};

-- 4. Rename the rebuilt table into place.
ALTER TABLE {task_credential_proxies}_new RENAME TO {task_credential_proxies};

-- 5. Recreate the lookup index. CredentialProxyManager queries by
--    task_id at session-spawn time; the composite PK already covers
--    this prefix but the explicit index makes the query plan
--    self-documenting and survives any future PK refactor.
CREATE INDEX IF NOT EXISTS idx_task_credential_proxies_task_id
    ON {task_credential_proxies} (task_id);

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (17, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 18 — Orchestrator session ↔ initiative linkage + relax
//                `structured_outputs.task_id` to nullable.
//
// Spec references:
//   * `v2_extended_gaps.md §3.2` — `structured_output` is a tool any
//     planner-class agent can call (Executor, Reviewer, **and**
//     Orchestrator). The original migration-13 schema modelled the
//     `structured_outputs` row as `(initiative_id, task_id, session_id)`
//     with `task_id` NOT NULL + a foreign-key reference to
//     `tasks(task_id)`. That model breaks for the Orchestrator: the
//     coordinator session is admitted under an *initiative*, not under
//     a `tasks` row, so an orchestrator-emitted output has no task to
//     point at and the FK refuses the INSERT (`FAIL_UNKNOWN_TASK` as
//     observed by the live-e2e on 2026-05-09).
//   * `v2-deep-spec.md §Step 6` — Orchestrator sessions are minted by
//     `auto_spawn_orchestrator_session_in_tx` immediately after
//     `approve_plan`. The row carries `session_agent_type =
//     "Orchestrator"` but had no direct edge back to the initiative
//     it was minted for. Recovery and per-initiative observability
//     queries had to walk through `subtask_activations` (which only
//     covers Executor / Reviewer descendants) to discover the
//     coordinator — fragile and inconsistent.
//
// What changes:
//
//   1. `sessions` gains a nullable `initiative_id` column with a FK
//      to `initiatives(initiative_id)` and a partial index covering
//      the populated-only subset. Orchestrator sessions populate it
//      at auto-spawn time; pre-Migration-18 rows + future non-V2
//      sessions leave it NULL (the FK is only enforced when the
//      column is non-NULL per SQLite semantics — ditto for the
//      partial index probe). This gives the intent handler a single,
//      typed lookup to recover the coordinator's owning initiative
//      without join-walking through `subtask_activations`.
//
//   2. `structured_outputs` is rebuilt with a NULLABLE `task_id`.
//      The FK to `tasks(task_id)` is preserved (FK still enforced
//      when the value is non-null per SQLite semantics) so executor
//      / reviewer rows continue to refer to a real task, while the
//      Orchestrator's coordinator-level outputs land with
//      `task_id IS NULL`. Indexes and the `(initiative_id, session_id,
//      kind, severity, payload_json, emitted_at)` column shape are
//      otherwise byte-identical to migration 13.
//
// SQLite has no `ALTER TABLE ... ALTER COLUMN`, so the
// `structured_outputs` change uses the canonical
// `CREATE-NEW → INSERT-FROM-OLD → DROP-OLD → RENAME` pattern (see
// migration 17 for the precedent). The `sessions` change is a
// straight `ALTER TABLE ADD COLUMN` because SQLite *does* support
// adding a nullable column without a table rebuild.
//
// Atomicity: the entire migration runs inside one
// `BEGIN EXCLUSIVE … COMMIT`, so a crash mid-migration leaves the
// pre-migration schema fully intact (matches the every-migration
// invariant declared at the top of this module).
// ---------------------------------------------------------------------------

fn apply_migration_18(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_18_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 18 failed: {e}")))
}

/// The complete migration-18 DDL.
pub fn render_migration_18_ddl() -> String {
    let sessions = Table::Sessions.as_str();
    let initiatives = Table::Initiatives.as_str();
    let tasks = Table::Tasks.as_str();
    let structured_outputs = Table::StructuredOutputs.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- ── 1. sessions: add initiative_id (nullable) + partial index ────────────
--
-- v2_extended_gaps.md §3.2 — a planner-class session needs a typed
-- back-reference to the initiative it was minted under so the kernel
-- can route Orchestrator-emitted `structured_output` rows to the
-- correct `initiatives.initiative_id` without a join through
-- `subtask_activations`. NULL for pre-Migration-18 rows and for
-- non-V2 sessions (Gateway / Verifier).
ALTER TABLE {sessions}
    ADD COLUMN initiative_id TEXT
        REFERENCES {initiatives}(initiative_id) ON DELETE CASCADE;

-- Partial index — most rows are NULL; we only ever probe by the
-- populated subset (operator-side initiative dashboards, recovery
-- driver coordinator-rebind).
CREATE INDEX IF NOT EXISTS idx_sessions_initiative
    ON {sessions} (initiative_id)
    WHERE initiative_id IS NOT NULL;

-- ── 2. structured_outputs: rebuild with nullable task_id ─────────────────
--
-- Column shape mirrors migration 13 byte-for-byte modulo the
-- `task_id` nullability. The FK to `tasks(task_id)` is preserved —
-- SQLite enforces FKs only when the column value is non-NULL, so
-- executor / reviewer rows keep their referential guarantee and
-- orchestrator rows (NULL) bypass the FK without a constraint
-- violation.
CREATE TABLE {structured_outputs}_new (
    output_id      TEXT NOT NULL PRIMARY KEY,
    initiative_id  TEXT NOT NULL REFERENCES {initiatives}(initiative_id) ON DELETE CASCADE,
    task_id        TEXT          REFERENCES {tasks}(task_id)             ON DELETE CASCADE,
    session_id     TEXT NOT NULL REFERENCES {sessions}(session_id)       ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('progress_report', 'diagnostic_flag', 'task_summary')),
    severity       TEXT          CHECK (severity IS NULL OR severity IN ('info', 'warning', 'critical')),
    payload_json   TEXT NOT NULL,
    emitted_at     INTEGER NOT NULL
);

INSERT INTO {structured_outputs}_new
    (output_id, initiative_id, task_id, session_id,
     kind, severity, payload_json, emitted_at)
SELECT output_id, initiative_id, task_id, session_id,
       kind, severity, payload_json, emitted_at
  FROM {structured_outputs};

DROP TABLE {structured_outputs};

ALTER TABLE {structured_outputs}_new RENAME TO {structured_outputs};

-- Recreate the migration-13 indexes — DROP TABLE drops the indexes
-- defined on the old table along with it.
CREATE INDEX idx_{structured_outputs}_task
    ON {structured_outputs}(task_id, emitted_at)
    WHERE task_id IS NOT NULL;

CREATE INDEX idx_{structured_outputs}_initiative
    ON {structured_outputs}(initiative_id, emitted_at);

CREATE INDEX idx_{structured_outputs}_session
    ON {structured_outputs}(session_id);

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (18, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 19 — Orchestrator no-progress respawn counter.
//
// `INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01` requires a structural
// backstop against unbounded orchestrator respawn loops on rejected
// intents. The Orchestrator agent is short-lived (per
// `session_spawn_orchestrator.rs::respawn_orchestrator_for_initiative`);
// it boots, reads the KSB, calls one terminal tool, and exits. When
// the kernel rejects the intent (e.g. `RetrySubTaskRejectedNotRetryable`
// per `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`), the session exits
// cleanly (no `Failed` FSM transition) and the post-exit hook
// re-spawns. Without a per-initiative counter, the orchestrator can
// loop on a rejected intent indefinitely (observed on the second
// iter42: 45 `SessionVmSpawned` in 18 min, zero progress, zero
// `Failed` transitions to trigger `crash_count`).
//
// This migration adds `orchestrator_no_progress_respawn_count` to
// `initiatives`. The counter is:
//
//   * incremented in `respawn_orchestrator_for_initiative` BEFORE
//     each new orchestrator session is spawned;
//   * reset to 0 whenever the kernel observes a task-FSM advance or
//     a new `subtask_activations` row insert for that initiative
//     (i.e. real DAG progress, NOT just an intent landing);
//   * compared against
//     `respawn_orchestrator_for_initiative`'s constant
//     `MAX_ORCH_NO_PROGRESS_RESPAWNS` (default 3).
//
// On ceiling exceed: the kernel marks the initiative `Failed` with
// `reason = "orchestrator no-progress respawn ceiling exceeded"`,
// emits `AuditEventKind::OrchestratorRespawnCeilingExceeded`, and
// refuses further respawns for that initiative.
//
// Atomicity: single `BEGIN EXCLUSIVE … COMMIT`. Crash mid-migration
// leaves the pre-migration schema intact (every-migration invariant
// declared at the top of this module).
//
// Pre-Migration-19 rows default to 0 — the moment migration completes
// every initiative observably has no respawns counted, consistent
// with "fresh kernel start treats all initiatives as un-loop-stalled".
// ---------------------------------------------------------------------------

fn apply_migration_19(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_19_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 19 failed: {e}")))
}

/// The complete migration-19 DDL.
pub fn render_migration_19_ddl() -> String {
    let initiatives = Table::Initiatives.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- Add the orchestrator-respawn no-progress counter. Default 0 ⇒
-- pre-Migration-19 rows observably have not accumulated respawns
-- (the counter only ever increments on a fresh respawn). Type is
-- INTEGER (SQLite stores it as i64 native); the kernel narrows
-- to u32 on read.
ALTER TABLE {initiatives}
    ADD COLUMN orchestrator_no_progress_respawn_count INTEGER NOT NULL DEFAULT 0;

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (19, strftime('%s', 'now'));

COMMIT;
"
    )
}

// ---------------------------------------------------------------------------
// Migration 20 — Escalation initiator column.
//
// `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01` introduces the FIRST
// kernel-initiated escalation class
// (`EscalationClass::LogicalDeadlock`). Pre-Migration-20 every row
// in `escalations` was planner-initiated by construction (the only
// admission path was the planner-side `EscalationRequest` IPC); the
// new auto-create path inside
// `kernel/src/orch_respawn_ceiling.rs::insert_logical_deadlock_escalation_in_tx`
// inserts a row whose `initiator` is `'Kernel'` instead of
// `'Planner'`.
//
// This migration adds the column with a default of `'Planner'` so
// pre-Migration-20 rows observably keep their original semantics
// after the upgrade. The kernel approve/deny handlers consult the
// column to decide whether a `LogicalDeadlock` row may carry an
// approval that resets the orch-respawn counter (only kernel-
// initiated rows are eligible — a planner-submitted row of the
// same class would be rejected at admission, but the constraint
// is encoded as a defense-in-depth check on the approve path).
//
// Atomicity: single `BEGIN EXCLUSIVE … COMMIT`. Crash mid-migration
// leaves the pre-migration schema intact (every-migration invariant
// declared at the top of this module).
// ---------------------------------------------------------------------------

fn apply_migration_20(conn: &Connection) -> Result<(), StoreError> {
    let ddl = render_migration_20_ddl();
    conn.execute_batch(&ddl)
        .map_err(|e| StoreError::Migration(format!("migration 20 failed: {e}")))
}

/// The complete migration-20 DDL.
pub fn render_migration_20_ddl() -> String {
    let escalations = Table::Escalations.as_str();
    let schema_version = Table::SchemaVersion.as_str();

    format!(
        "
BEGIN EXCLUSIVE;

-- Add the escalation initiator column. Default 'Planner' ⇒
-- pre-Migration-20 rows observably remain planner-initiated
-- (the only V1/V2 admission path was the planner-side
-- `EscalationRequest` IPC). The kernel-initiated auto-create
-- path inside `kernel/src/orch_respawn_ceiling.rs` writes
-- 'Kernel' explicitly. The text-typed CHECK keeps the column
-- closed-set so a future variant requires both an enum +
-- migration update.
ALTER TABLE {escalations}
    ADD COLUMN initiator TEXT NOT NULL DEFAULT 'Planner'
        CHECK (initiator IN ('Planner', 'Kernel'));

-- Record this migration.
INSERT OR IGNORE INTO {schema_version} (version, applied_at)
    VALUES (20, strftime('%s', 'now'));

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
        assert_eq!(
            v, SCHEMA_VERSION as i64,
            "schema_version should be SCHEMA_VERSION ({SCHEMA_VERSION}) after first apply"
        );

        // Spot-check: a representative table exists post-migration.
        // We use `Table::Tasks.as_str()` here too — keeping the test
        // consistent with the production INV-STORE-03 contract.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
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
        assert_eq!(
            n, SCHEMA_VERSION as i64,
            "expected one row per applied migration"
        );
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
        let tasks_t = Table::Tasks.as_str();
        let draft = InitiativeState::Draft.as_sql_str();
        let admitted = TaskState::Admitted.as_sql_str();
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
            check_in_clause(&DelegationStatus::STORED, |s| DelegationStatus::as_sql_str(
                s
            )
            .expect("STORED variants must serialise"),),
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
            // Migration 5 — v2: hierarchical orchestration
            Table::SubtaskActivations,
            // Migration 8 — v2: plan-bundle-sealing storage layout (§8.2)
            Table::PlanBundles,
            Table::PlanBundleArtifacts,
            Table::PlanBundleNoncesSeen,
            // Migration 10 — v2: per-task credential-proxy declarations
            //                    (METADATA ONLY; credential bytes never
            //                    stored in kernel.db).
            //                    See credential-proxy.md §3.
            Table::TaskCredentialProxies,
            // Migration 11 — v2: pre-merge verifier attempt tracking
            //                    (integration-merge.md §11.10.1 + §11.10.4;
            //                    verifier-processes.md §16). Rows are
            //                    swept at boot per §11.10.4 to fold
            //                    crashed mid-flight verifier runs.
            Table::IntegrationMergeAttempts,
            // Migration 13 — V2 §3.2 typed mid-session structured outputs
            //                emitted by executor / orchestrator agents
            //                via the `structured_output` planner tool.
            //                See `crates/types/src/structured_output.rs`
            //                for the closed-enum payload shape.
            Table::StructuredOutputs,
            // Migration 14 — v2: kernel-owned notification store
            //                (notification-routing.md §3 + §4 +
            //                v2_extended_gaps.md §3.4). Source of truth
            //                for raxis inbox + the dashboard
            //                /notifications page.
            Table::Notifications,
            // Migration 15 — v2: per-(provider, model) circuit-breaker
            //                state (provider-failure-handling.md §6.3
            //                / §6.4). Restored across kernel restarts
            //                so an Open circuit mid-cooldown does not
            //                silently reset to Closed on reboot.
            Table::ProviderCircuitState,
            // Migration 16 — v2: initiatives.git_apply_pending column +
            //                idx_initiatives_pending_git partial index
            //                (integration-merge.md §11.1). The column
            //                is added by ALTER TABLE so the bare
            //                `initiatives` row stays in the migration-1
            //                entry above; the partial index is not a
            //                table and intentionally absent from this
            //                set.
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
        assert_eq!(
            read_current_version(&conn).unwrap(),
            SCHEMA_VERSION as i64,
            "schema_version must be SCHEMA_VERSION after applying all migrations"
        );

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
            "pubkey_fingerprint",
            "epoch_id",
            "kind",
            "display_name",
            "pubkey_hex",
            "not_before",
            "not_after",
            "warn_before_expiry_days",
            "grace_period_days",
            "permitted_ops_json",
            "contact_info",
            "self_sig_hex",
            "force_misconfig_bypass",
            "installed_at",
        ] {
            assert!(
                cols.iter().any(|c| c == required),
                "operator_certificates is missing column {required:?}; \
                 got columns: {cols:?}"
            );
        }

        // Both partial indexes registered.
        let idx_count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type='index' AND tbl_name='{}'",
                    Table::OperatorCertificates.as_str(),
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            idx_count >= 2,
            "expected at least 2 indexes on operator_certificates, got {idx_count}"
        );
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
        )
        .unwrap();

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
        assert!(
            result.is_err(),
            "INSERT with kind='NotARealKind' must violate CHECK constraint"
        );
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
        assert!(
            result.is_err(),
            "INSERT referencing missing epoch_id MUST trip the FK constraint"
        );
    }

    // ── Migration 3 — initiative_quarantines ─────────────────────────

    /// Migration 3 creates the quarantine table AND adds the
    /// `signed_by_fingerprint` column on `signed_plan_artifacts`.
    /// Both are reachable from a fresh DB after `apply_pending`.
    #[test]
    fn migration_3_creates_initiative_quarantines_table_and_signer_column() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(
            read_current_version(&conn).unwrap(),
            SCHEMA_VERSION as i64,
            "schema_version must be SCHEMA_VERSION after applying all migrations"
        );

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
            "initiative_id",
            "quarantined_at",
            "quarantined_by",
            "reason",
            "sweep_target",
        ] {
            assert!(
                cols.iter().any(|c| c == required),
                "initiative_quarantines is missing column {required:?}; got: {cols:?}"
            );
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
        assert!(
            plan_cols.iter().any(|c| c == "signed_by_fingerprint"),
            "migration 3 must add signed_by_fingerprint; got: {plan_cols:?}"
        );
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
        assert_eq!(
            read_current_version(&conn).unwrap(),
            SCHEMA_VERSION as i64,
            "schema_version must be SCHEMA_VERSION after applying all migrations"
        );

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
        assert_eq!(
            row.1,
            Table::InitiativeQuarantines.as_str(),
            "index must be on the initiative_quarantines table"
        );

        // The PRAGMA index_info confirms the index targets the right
        // column — protects against a future "fix" that points the
        // index at quarantined_by by mistake.
        let cols: Vec<String> = conn
            .prepare(
                "SELECT name FROM pragma_index_info('idx_initiative_quarantines_quarantined_at')",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            cols,
            vec!["quarantined_at".to_string()],
            "index must be on the quarantined_at column only"
        );
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
        // there by running migrations 1..=3 directly so that no
        // higher migration's artifacts pollute the test fixture.
        // (The original test ran the full `apply_pending` and then
        // deleted just the v=4 row; that broke when migration 5
        // shipped because the v=5 row remained, leaving
        // `read_current_version` reading as 5.)
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        assert_eq!(
            read_current_version(&conn).unwrap(),
            3,
            "test pre-condition: database must be at version 3"
        );
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
        assert_eq!(
            n_after, 1,
            "migration 4 must add the index when re-running on a v3 database"
        );
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
        assert!(
            result.is_err(),
            "INSERT referencing missing initiative_id MUST trip the FK constraint"
        );
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
        assert_eq!(
            InitiativeState::ALL.len(),
            7,
            "InitiativeState v1 has 7 variants; bumping this requires migration_2"
        );
        assert_eq!(
            TaskState::ALL.len(),
            8,
            "TaskState v1 has 8 variants; bumping this requires migration_2"
        );
        assert_eq!(
            EscalationStatus::ALL.len(),
            6,
            "EscalationStatus v1 has 6 variants; bumping this requires migration_2"
        );
        assert_eq!(
            WitnessResultClass::ALL.len(),
            3,
            "WitnessResultClass v1 has 3 variants; bumping this requires migration_2"
        );
        assert_eq!(
            DelegationStatus::STORED.len(),
            3,
            "DelegationStatus v1 STORED has 3 variants; bumping this requires migration_2"
        );
    }

    /// V2 enum-shape pin. Bumping any of these requires a NEW migration
    /// (after migration 5) that ALTERs the corresponding CHECK
    /// constraint on already-installed databases. The store
    /// `apply_pending` machinery treats migration 5 as historical the
    /// moment a v2-installed database has it applied; subsequent
    /// schema changes must arrive as migration 6+, not as edits to
    /// migration 5's rendered DDL.
    #[test]
    fn v2_enum_variant_counts_are_pinned_to_migration_5() {
        assert_eq!(
            SessionAgentType::ALL.len(),
            3,
            "SessionAgentType v2 has 3 variants (Orchestrator, Executor, \
             Reviewer); bumping this requires a new migration"
        );
        assert_eq!(
            SubtaskActivationState::ALL.len(),
            4,
            "SubtaskActivationState v2 has 4 variants; bumping this \
             requires a new migration"
        );
    }

    // ── Migration 5 — V2 hierarchical orchestration ────────────────────────

    /// Every column added to `sessions` by migration 5 is materialised
    /// in the live schema, with the right type and NULL-ability.
    /// A future refactor that drops a column or changes its type
    /// silently would surface here before any V2 handler hits the row.
    #[test]
    fn migration_5_adds_v2_columns_to_sessions() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        // sqlite `pragma table_info` returns one row per column with
        // (cid, name, type, notnull, dflt_value, pk).
        let mut stmt = conn
            .prepare(&format!(
                "SELECT name, type, [notnull], dflt_value \
                 FROM pragma_table_info('{}')",
                Table::Sessions.as_str()
            ))
            .unwrap();
        let cols: std::collections::HashMap<String, (String, i64, Option<String>)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    (
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ),
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();

        // session_agent_type: TEXT, NULLable (V1 backward compat).
        let (ty, notnull, _dflt) = cols
            .get("session_agent_type")
            .expect("sessions.session_agent_type must exist after migration 5");
        assert_eq!(ty, "TEXT", "session_agent_type must be TEXT");
        assert_eq!(*notnull, 0, "session_agent_type must be NULLable for V1");

        // can_delegate: INTEGER NOT NULL DEFAULT 0.
        let (ty, notnull, dflt) = cols
            .get("can_delegate")
            .expect("sessions.can_delegate must exist after migration 5");
        assert_eq!(ty, "INTEGER");
        assert_eq!(*notnull, 1, "can_delegate must be NOT NULL");
        assert_eq!(
            dflt.as_deref(),
            Some("0"),
            "can_delegate must default to 0 so V1 rows survive ALTER"
        );

        // vsock_cid: INTEGER, NULLable.
        let (ty, notnull, _) = cols
            .get("vsock_cid")
            .expect("sessions.vsock_cid must exist after migration 5");
        assert_eq!(ty, "INTEGER");
        assert_eq!(*notnull, 0, "vsock_cid must be NULLable for V1");
    }

    /// INV-DELEGATE-01 enforced at the SQL layer (defense in depth):
    /// a row with can_delegate=1 AND session_agent_type ≠ 'Orchestrator'
    /// must be rejected by the row-level CHECK.
    ///
    /// The application-layer create_session is the primary gate; this
    /// test pins the secondary database-level guard so that even a
    /// raw SQL writer (e.g. an admin debugging through `sqlite3`) cannot
    /// produce a row that violates the invariant.
    #[test]
    fn inv_delegate_01_check_rejects_non_orchestrator_with_can_delegate() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        // Seed a parent FK target so the test isolates the CHECK fault
        // (otherwise the FK on tasks would also raise).
        let sessions = Table::Sessions.as_str();

        // Reviewer + can_delegate=1 must FAIL the CHECK.
        let bad = conn.execute(
            &format!(
                "INSERT INTO {sessions}\
                  (session_id, role_id, session_token, lineage_id, fetch_quota,\
                   created_at, expires_at,\
                   session_agent_type, can_delegate)\
                 VALUES ('s1','r','t1','l',0,1,2,'Reviewer',1)"
            ),
            [],
        );
        assert!(
            bad.is_err(),
            "INV-DELEGATE-01 row-level CHECK must reject \
             can_delegate=1 with session_agent_type='Reviewer'"
        );

        // Orchestrator + can_delegate=1 must SUCCEED.
        let good = conn.execute(
            &format!(
                "INSERT INTO {sessions}\
                  (session_id, role_id, session_token, lineage_id, fetch_quota,\
                   created_at, expires_at,\
                   session_agent_type, can_delegate)\
                 VALUES ('s2','r','t2','l',0,1,2,'Orchestrator',1)"
            ),
            [],
        );
        assert!(
            good.is_ok(),
            "Orchestrator + can_delegate=1 must satisfy INV-DELEGATE-01"
        );
    }

    /// V1 backward compat: a row with no V2 fields populated must
    /// continue to insert. The default for can_delegate is 0; the
    /// CHECK constraint allows can_delegate=0 with NULL agent type.
    #[test]
    fn v1_session_row_unchanged_after_migration_5() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let sessions = Table::Sessions.as_str();
        let r = conn.execute(
            &format!(
                "INSERT INTO {sessions}\
                  (session_id, role_id, session_token, lineage_id, fetch_quota,\
                   created_at, expires_at)\
                 VALUES ('v1-row','planner','tok','lin',0,1,9999999999)"
            ),
            [],
        );
        assert!(r.is_ok(), "V1-shape session row must still INSERT");

        // Confirm the V2 defaults landed correctly.
        let (sat, cd, vc): (Option<String>, i64, Option<i64>) = conn
            .query_row(
                &format!(
                    "SELECT session_agent_type, can_delegate, vsock_cid \
                     FROM {sessions} WHERE session_id = 'v1-row'"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(sat, None, "V1 row must have NULL session_agent_type");
        assert_eq!(cd, 0, "V1 row must have can_delegate=0 (default)");
        assert_eq!(vc, None, "V1 row must have NULL vsock_cid");
    }

    /// `subtask_activations` exists post-migration and rejects bad
    /// activation_state values via the enum-driven CHECK.
    #[test]
    fn migration_5_creates_subtask_activations_with_check() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        apply_pending(&conn).unwrap();

        // Seed the FK targets.
        let initiatives_t = Table::Initiatives.as_str();
        let tasks_t = Table::Tasks.as_str();
        let activ_t = Table::SubtaskActivations.as_str();
        let draft = InitiativeState::Draft.as_sql_str();
        let admitted = TaskState::Admitted.as_sql_str();
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives_t} (initiative_id, state, terminal_criteria_json, \
                                          plan_artifact_sha256, created_at) \
             VALUES ('init-1', '{draft}', '{{}}', 'deadbeef', 0); \
             INSERT INTO {tasks_t} (task_id, initiative_id, lane_id, state, actor, \
                                     policy_epoch, admitted_at, transitioned_at) \
             VALUES ('task-1', 'init-1', 'default', '{admitted}', 'planner', \
                     1, 0, 0);"
        ))
        .unwrap();

        // Legal: PendingActivation row with no session and no timestamps.
        let pending = SubtaskActivationState::PendingActivation.as_sql_str();
        let r = conn.execute(
            &format!(
                "INSERT INTO {activ_t}\
                  (activation_id, task_id, initiative_id, activation_state, created_at)\
                 VALUES ('a1','task-1','init-1','{pending}', 100)"
            ),
            [],
        );
        assert!(r.is_ok(), "PendingActivation insert must succeed: {r:?}");

        // Illegal: bogus activation_state — CHECK constraint fires.
        let r = conn.execute(
            &format!(
                "INSERT INTO {activ_t}\
                  (activation_id, task_id, initiative_id, activation_state, created_at)\
                 VALUES ('a2','task-1','init-1','BogusState', 100)"
            ),
            [],
        );
        assert!(r.is_err(), "Unknown activation_state must trip the CHECK");

        // Illegal: PendingActivation with a timestamp set — cross-
        // column CHECK fires.
        let r = conn.execute(
            &format!(
                "INSERT INTO {activ_t}\
                  (activation_id, task_id, initiative_id, activation_state, \
                   created_at, activated_at)\
                 VALUES ('a3','task-1','init-1','{pending}', 100, 200)"
            ),
            [],
        );
        assert!(
            r.is_err(),
            "PendingActivation with non-NULL activated_at must trip the cross-CHECK"
        );

        // Illegal: Completed without timestamps.
        let completed = SubtaskActivationState::Completed.as_sql_str();
        let r = conn.execute(
            &format!(
                "INSERT INTO {activ_t}\
                  (activation_id, task_id, initiative_id, activation_state, created_at)\
                 VALUES ('a4','task-1','init-1','{completed}', 100)"
            ),
            [],
        );
        assert!(
            r.is_err(),
            "Completed without activated_at/terminated_at must trip the cross-CHECK"
        );
    }

    /// Migration 5 is idempotent: re-running `apply_pending` after a
    /// successful apply must NOT produce duplicate `subtask_activations`
    /// tables, fail to re-add ALTERed columns, or trigger a duplicate
    /// index error. A typical accidental-call scenario (kernel restart
    /// hot-loop with a transient I/O error) must be a no-op.
    #[test]
    fn migration_5_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();

        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        // Exactly one subtask_activations row in sqlite_master.
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'table' AND name = ?1",
                [Table::SubtaskActivations.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "exactly one subtask_activations table row expected");

        // schema_version has exactly SCHEMA_VERSION rows (one per applied
        // migration) — no duplicates from the second apply_pending.
        let total: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::SchemaVersion.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, SCHEMA_VERSION as i64);
    }

    /// Upgrade scenario: a database that completed migrations 1–4 but
    /// not 5 (i.e. installed under a v1.x build) must pick up
    /// migration 5 when `apply_pending` runs. Pinning this guards
    /// against the class of bug where a future `apply_pending` refactor
    /// short-circuits the `current_version < 5` gate. We get to a
    /// "version 4" state by running migrations 1–4 directly (skipping
    /// migration 5).
    #[test]
    fn migration_5_applies_to_a_v4_database() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        apply_migration_4(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 4);

        // Pre-condition: subtask_activations table is absent at v=4.
        let n_before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'table' AND name = ?1",
                [Table::SubtaskActivations.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_before, 0, "subtask_activations must not yet exist at v=4");

        // Run apply_pending — it must apply ONLY migration 5
        // (the gate `current_version < 5` should skip 1–4).
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        // Subtask_activations is created.
        let n_after: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'table' AND name = ?1",
                [Table::SubtaskActivations.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_after, 1, "migration 5 must add subtask_activations");
    }

    /// Migration 5 wraps all four DDL pieces in a single
    /// `BEGIN EXCLUSIVE; ... COMMIT;` so a crash mid-migration leaves
    /// the DB at v=4. We pin this contract by inspecting the rendered
    /// DDL text — the implementation could otherwise drift to multiple
    /// transactions which would break the partial-failure invariant.
    #[test]
    fn migration_5_is_a_single_transaction() {
        let ddl = render_migration_5_ddl();
        // The DDL must contain exactly one BEGIN and one COMMIT, in
        // that order, and no nested transactions.
        assert_eq!(
            ddl.matches("BEGIN EXCLUSIVE").count(),
            1,
            "migration 5 must open exactly one transaction (BEGIN EXCLUSIVE)"
        );
        assert_eq!(
            ddl.matches("COMMIT").count(),
            1,
            "migration 5 must commit exactly once"
        );
        assert!(
            ddl.find("BEGIN EXCLUSIVE").unwrap() < ddl.find("COMMIT").unwrap(),
            "BEGIN must precede COMMIT"
        );
    }

    // ── Migration 6 — V2 critique routing column on `tasks` ─────────────

    /// Migration 6 adds `tasks.last_critique` as a NULLable TEXT column.
    /// The presence and shape of the column is the entire contract: any
    /// future write to the column happens through application code
    /// (handlers/intent.rs), so the schema test is purely structural.
    #[test]
    fn migration_6_adds_last_critique_column_to_tasks() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let cols: Vec<(String, String, i64, Option<String>)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,         // name
                    r.get::<_, String>(2)?,         // type
                    r.get::<_, i64>(3)?,            // notnull
                    r.get::<_, Option<String>>(4)?, // dflt_value
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();

        let last_critique = cols
            .iter()
            .find(|(name, _, _, _)| name == "last_critique")
            .expect("tasks.last_critique column must exist after migration 6");

        assert_eq!(last_critique.1, "TEXT", "last_critique must be TEXT");
        assert_eq!(last_critique.2, 0, "last_critique must be NULLable");
        assert!(
            last_critique.3.is_none(),
            "last_critique must have no DEFAULT"
        );
    }

    /// Migration 6 leaves V1 task rows untouched: the column is added
    /// with no DEFAULT, so `last_critique` defaults to NULL on every
    /// pre-existing row. We pin this with a synthetic V1 row inserted
    /// before migration 6 runs.
    #[test]
    fn migration_6_preserves_v1_task_rows_with_null_last_critique() {
        let conn = Connection::open_in_memory().unwrap();
        // Apply only migrations 1–5 (the V1+v1.x+v2-substrate state
        // that existed before this column landed).
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        apply_migration_4(&conn).unwrap();
        apply_migration_5(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 5);

        // Insert a V1-shaped row. We only care that the row survives
        // migration 6 with last_critique = NULL; the exact column set
        // matches whatever migration 1 created (kernel-store.md §2.5.1
        // Table 5).
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES ('init-mig6', 'Draft', '{{}}', 'deadbeef', 0); \
                 INSERT INTO {tasks} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at) \
                 VALUES ('task-mig6', 'init-mig6', 'lane.default', \
                         'Admitted', 'Operator', 1, 0, 0);",
            initiatives = Table::Initiatives.as_str(),
            tasks = Table::Tasks.as_str(),
        ))
        .unwrap();

        // Now run migration 6 only — assert the version is exactly 6
        // (this test is scoped to migration 6's contract; migration 7
        // is exercised by the v6→v7 upgrade test below).
        apply_migration_6(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 6);

        let last_critique: Option<String> = conn
            .query_row(
                &format!(
                    "SELECT last_critique FROM {} WHERE task_id = ?1",
                    Table::Tasks.as_str(),
                ),
                ["task-mig6"],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            last_critique.is_none(),
            "last_critique must be NULL on pre-existing V1 rows (got {last_critique:?})"
        );
    }

    /// Migration 6 is idempotent under `apply_pending` — re-running
    /// after a successful boot is a no-op (no duplicate column, no
    /// duplicate schema_version row).
    #[test]
    fn migration_6_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();

        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        // schema_version has exactly SCHEMA_VERSION rows (one per applied
        // migration) — no duplicates from repeated apply_pending.
        let total: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::SchemaVersion.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, SCHEMA_VERSION as i64);

        // last_critique appears exactly once in the column list.
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let n_last_critique = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .filter(|name| name == "last_critique")
            .count();
        assert_eq!(
            n_last_critique, 1,
            "last_critique must appear exactly once in tasks PRAGMA"
        );
    }

    /// Upgrade scenario: a database at v=5 (a build that shipped before
    /// critique routing) must pick up migration 6 cleanly.
    #[test]
    fn migration_6_applies_to_a_v5_database() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        apply_migration_4(&conn).unwrap();
        apply_migration_5(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 5);

        // last_critique not yet present.
        let mut stmt_pre = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let has_pre = stmt_pre
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .any(|name| name == "last_critique");
        assert!(!has_pre, "last_critique must not yet exist at v=5");

        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        // last_critique now present.
        let mut stmt_post = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let has_post = stmt_post
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .any(|name| name == "last_critique");
        assert!(has_post, "migration 6 must add last_critique");
    }

    /// Migration 6 wraps the single ALTER TABLE in a single
    /// `BEGIN EXCLUSIVE; ... COMMIT;`. Pinning the transaction shape
    /// guards against future drift to multi-tx layout.
    #[test]
    fn migration_6_is_a_single_transaction() {
        let ddl = render_migration_6_ddl();
        assert_eq!(
            ddl.matches("BEGIN EXCLUSIVE").count(),
            1,
            "migration 6 must open exactly one transaction (BEGIN EXCLUSIVE)"
        );
        assert_eq!(
            ddl.matches("COMMIT").count(),
            1,
            "migration 6 must commit exactly once"
        );
        assert!(
            ddl.find("BEGIN EXCLUSIVE").unwrap() < ddl.find("COMMIT").unwrap(),
            "BEGIN must precede COMMIT"
        );
    }

    // ── Migration 7 — V2 per-Reviewer verdict column on `tasks` ─────────

    /// Migration 7 adds `tasks.review_verdict` as a NULLable TEXT column
    /// with a CHECK constraint pinning the (NULL | Approved | Rejected)
    /// universe.
    #[test]
    fn migration_7_adds_review_verdict_column_to_tasks() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let cols: Vec<(String, String, i64, Option<String>)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,         // name
                    r.get::<_, String>(2)?,         // type
                    r.get::<_, i64>(3)?,            // notnull
                    r.get::<_, Option<String>>(4)?, // dflt_value
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();

        let review_verdict = cols
            .iter()
            .find(|(name, _, _, _)| name == "review_verdict")
            .expect("tasks.review_verdict column must exist after migration 7");

        assert_eq!(review_verdict.1, "TEXT", "review_verdict must be TEXT");
        assert_eq!(review_verdict.2, 0, "review_verdict must be NULLable");
        assert!(
            review_verdict.3.is_none(),
            "review_verdict must have no DEFAULT"
        );
    }

    /// The CHECK constraint on `review_verdict` must accept the canonical
    /// `ReviewVerdict::ALL` strings AND NULL, and reject anything else.
    #[test]
    fn migration_7_check_constraint_accepts_only_canonical_strings() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        // Seed an initiative + task so the CHECK constraint is exercised
        // by an actual UPDATE.
        let now = raxis_types::unix_now_secs();
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES ('init-mig7', 'Draft', '{{}}', 'deadbeef', {now}); \
                 INSERT INTO {tasks} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at) \
                 VALUES ('task-mig7', 'init-mig7', 'lane.default', \
                         'Admitted', 'Operator', 1, {now}, {now});",
            initiatives = Table::Initiatives.as_str(),
            tasks = Table::Tasks.as_str(),
            now = now,
        ))
        .unwrap();

        let upd_sql = format!(
            "UPDATE {} SET review_verdict = ?1 WHERE task_id = 'task-mig7'",
            Table::Tasks.as_str(),
        );

        // Canonical strings must be accepted.
        for variant in &ReviewVerdict::ALL {
            let r = conn.execute(&upd_sql, rusqlite::params![variant.as_sql_str()]);
            assert!(
                r.is_ok(),
                "CHECK constraint must accept canonical {variant:?} (got {r:?})"
            );
        }
        // NULL must be accepted.
        let r = conn.execute(&upd_sql, rusqlite::params![Option::<&str>::None]);
        assert!(r.is_ok(), "CHECK constraint must accept NULL (got {r:?})");

        // A bogus string must be rejected.
        let r = conn.execute(&upd_sql, rusqlite::params!["ApprovedYes"]);
        assert!(
            r.is_err(),
            "CHECK constraint must reject non-canonical strings"
        );
    }

    /// V2 enum-driven CHECK clauses are pinned at the SQL level so a
    /// future variant addition forces a migration rather than slipping
    /// through silently.
    #[test]
    fn v2_review_verdict_check_clause_is_pinned_to_migration_7() {
        assert_eq!(
            check_in_clause(&ReviewVerdict::ALL, ReviewVerdict::as_sql_str),
            "('Approved', 'Rejected')",
        );
    }

    /// Migration 7 is idempotent under `apply_pending`.
    #[test]
    fn migration_7_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();

        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let total: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::SchemaVersion.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, SCHEMA_VERSION as i64);

        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let n_review_verdict = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .filter(|name| name == "review_verdict")
            .count();
        assert_eq!(
            n_review_verdict, 1,
            "review_verdict must appear exactly once in tasks PRAGMA"
        );
    }

    /// Upgrade scenario: a database at v=6 must pick up migration 7
    /// cleanly when `apply_pending` runs.
    #[test]
    fn migration_7_applies_to_a_v6_database() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        apply_migration_4(&conn).unwrap();
        apply_migration_5(&conn).unwrap();
        apply_migration_6(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 6);

        let mut stmt_pre = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let has_pre = stmt_pre
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .any(|name| name == "review_verdict");
        assert!(!has_pre, "review_verdict must not yet exist at v=6");

        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let mut stmt_post = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let has_post = stmt_post
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .any(|name| name == "review_verdict");
        assert!(has_post, "migration 7 must add review_verdict");
    }

    /// Migration 7 wraps the single ALTER TABLE in a single
    /// `BEGIN EXCLUSIVE; ... COMMIT;`.
    #[test]
    fn migration_7_is_a_single_transaction() {
        let ddl = render_migration_7_ddl();
        assert_eq!(
            ddl.matches("BEGIN EXCLUSIVE").count(),
            1,
            "migration 7 must open exactly one transaction (BEGIN EXCLUSIVE)"
        );
        assert_eq!(
            ddl.matches("COMMIT").count(),
            1,
            "migration 7 must commit exactly once"
        );
        assert!(
            ddl.find("BEGIN EXCLUSIVE").unwrap() < ddl.find("COMMIT").unwrap(),
            "BEGIN must precede COMMIT"
        );
    }

    // ── Migration 8 — V2 plan-bundle-sealing storage layout (§8.2) ─────

    /// `apply_pending` advances the schema all the way to V8 (current
    /// `SCHEMA_VERSION`), creating the three plan-bundle-sealing tables
    /// alongside the V1+V1.x+V2 baseline.
    #[test]
    fn migration_8_creates_plan_bundle_sealing_tables() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        for table in [
            Table::PlanBundles,
            Table::PlanBundleArtifacts,
            Table::PlanBundleNoncesSeen,
        ] {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master \
                     WHERE type='table' AND name=?1",
                    rusqlite::params![table.as_str()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "{} must exist after migration 8", table.as_str());
        }
    }

    /// `plan_bundles` columns match the §8.2 schema exactly (column
    /// names, types, and NULLability). Pinning each column shape
    /// surfaces silent drift between this DDL and the spec.
    #[test]
    fn migration_8_plan_bundles_column_shape_matches_spec() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let mut stmt = conn
            .prepare(&format!(
                "PRAGMA table_info({})",
                Table::PlanBundles.as_str(),
            ))
            .unwrap();
        let cols: Vec<(String, String, i64)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();

        let by_name: std::collections::HashMap<&str, (&str, i64)> = cols
            .iter()
            .map(|(n, ty, nn)| (n.as_str(), (ty.as_str(), *nn)))
            .collect();

        // NOT NULL columns
        for (name, expected_type) in [
            ("bundle_sha256", "BLOB"),
            ("bundle_bytes", "BLOB"),
            ("signature", "BLOB"),
            ("signed_by", "BLOB"),
            ("schema_version", "INTEGER"),
            ("artifact_count", "INTEGER"),
            ("bundle_bytes_len", "INTEGER"),
            ("sealed_at_unix_secs", "INTEGER"),
        ] {
            let (ty, nn) = by_name
                .get(name)
                .copied()
                .unwrap_or_else(|| panic!("missing column: {name}"));
            assert_eq!(ty, expected_type, "column {name}: type mismatch");
            assert_eq!(nn, 1, "column {name} must be NOT NULL");
        }
        // Schema-1-nullable columns
        for (name, expected_type) in [("signed_at_unix_secs", "INTEGER"), ("bundle_nonce", "BLOB")]
        {
            let (ty, nn) = by_name
                .get(name)
                .copied()
                .unwrap_or_else(|| panic!("missing column: {name}"));
            assert_eq!(ty, expected_type, "column {name}: type mismatch");
            assert_eq!(nn, 0, "column {name} must be NULLable for schema-1");
        }
    }

    /// `plan_bundle_artifacts` exposes the §8.2 composite primary key
    /// (`bundle_sha256`, `artifact_seq`).
    #[test]
    fn migration_8_plan_bundle_artifacts_uses_composite_primary_key() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let mut stmt = conn
            .prepare(&format!(
                "PRAGMA table_info({})",
                Table::PlanBundleArtifacts.as_str(),
            ))
            .unwrap();
        let pk_columns: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, i64>(5)?)))
            .unwrap()
            .map(Result::unwrap)
            .filter(|(_, pk)| *pk > 0)
            .collect();

        assert_eq!(
            pk_columns.len(),
            2,
            "plan_bundle_artifacts must have a 2-column primary key"
        );
        // pk index is the position WITHIN the PK; SQLite assigns 1, 2.
        let by_pk: std::collections::HashMap<i64, String> =
            pk_columns.iter().map(|(n, pk)| (*pk, n.clone())).collect();
        assert_eq!(by_pk.get(&1).map(String::as_str), Some("bundle_sha256"));
        assert_eq!(by_pk.get(&2).map(String::as_str), Some("artifact_seq"));
    }

    /// `plan_bundle_nonces_seen.outcome` CHECK constraint accepts only
    /// the two `PlanBundleNonceOutcome::ALL` strings.
    #[test]
    fn migration_8_nonces_outcome_check_constraint_is_canonical() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let now = raxis_types::unix_now_secs();
        let nonce_a = vec![0x01u8; 16];
        let nonce_b = vec![0x02u8; 16];
        let nonce_c = vec![0x03u8; 16];
        let bundle = vec![0xAAu8; 32];

        // Seed an initiative for the Admitted row's FK target.
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES ('init-mig8', 'Draft', '{{}}', 'deadbeef', {now});",
            initiatives = Table::Initiatives.as_str(),
            now = now,
        ))
        .unwrap();

        let ins_sql = format!(
            "INSERT INTO {} \
                (bundle_nonce, bundle_sha256, signed_at_unix_secs, \
                 first_seen_at_unix_secs, outcome, initiative_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            Table::PlanBundleNoncesSeen.as_str(),
        );

        // Admitted requires non-NULL initiative_id.
        let r = conn.execute(
            &ins_sql,
            rusqlite::params![
                nonce_a,
                bundle,
                now,
                now,
                PlanBundleNonceOutcome::Admitted.as_sql_str(),
                "init-mig8",
            ],
        );
        assert!(r.is_ok(), "Admitted with init_id must be accepted: {r:?}");

        // TerminallyRejected requires NULL initiative_id.
        let r = conn.execute(
            &ins_sql,
            rusqlite::params![
                nonce_b,
                bundle,
                now,
                now,
                PlanBundleNonceOutcome::TerminallyRejected.as_sql_str(),
                Option::<&str>::None,
            ],
        );
        assert!(
            r.is_ok(),
            "TerminallyRejected with NULL init_id must be accepted: {r:?}"
        );

        // Bogus outcome must be rejected.
        let r = conn.execute(
            &ins_sql,
            rusqlite::params![nonce_c, bundle, now, now, "Pending", Option::<&str>::None,],
        );
        assert!(
            r.is_err(),
            "non-canonical outcome string must be rejected by CHECK"
        );
    }

    /// Admitted nonce row MUST carry a non-NULL `initiative_id`; a NULL
    /// `initiative_id` violates the §8.1 step 12b contract enforced at
    /// the DDL layer by the §8.2 CHECK clause.
    #[test]
    fn migration_8_admitted_nonce_row_requires_initiative_id() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let now = raxis_types::unix_now_secs();
        let nonce = vec![0x55u8; 16];
        let bundle = vec![0xCCu8; 32];

        let r = conn.execute(
            &format!(
                "INSERT INTO {} \
                    (bundle_nonce, bundle_sha256, signed_at_unix_secs, \
                     first_seen_at_unix_secs, outcome, initiative_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                Table::PlanBundleNoncesSeen.as_str(),
            ),
            rusqlite::params![
                nonce,
                bundle,
                now,
                now,
                PlanBundleNonceOutcome::Admitted.as_sql_str(),
                Option::<&str>::None,
            ],
        );
        assert!(
            r.is_err(),
            "Admitted with NULL initiative_id must be rejected by CHECK \
             (plan-bundle-sealing.md §8.1 step 12b)"
        );
    }

    /// TerminallyRejected nonce row MUST carry a NULL `initiative_id`
    /// (§8.1 step 12b: "for terminal rejections in steps 10–11 …
    /// `initiative_id = NULL`").
    #[test]
    fn migration_8_terminally_rejected_nonce_row_requires_null_initiative_id() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let now = raxis_types::unix_now_secs();
        let nonce = vec![0xAAu8; 16];
        let bundle = vec![0xBBu8; 32];

        // Seed an initiative so the FK *would* otherwise resolve.
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES ('init-mig8b', 'Draft', '{{}}', 'deadbeef', {now});",
            initiatives = Table::Initiatives.as_str(),
            now = now,
        ))
        .unwrap();

        let r = conn.execute(
            &format!(
                "INSERT INTO {} \
                    (bundle_nonce, bundle_sha256, signed_at_unix_secs, \
                     first_seen_at_unix_secs, outcome, initiative_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                Table::PlanBundleNoncesSeen.as_str(),
            ),
            rusqlite::params![
                nonce,
                bundle,
                now,
                now,
                PlanBundleNonceOutcome::TerminallyRejected.as_sql_str(),
                "init-mig8b",
            ],
        );
        assert!(
            r.is_err(),
            "TerminallyRejected with non-NULL initiative_id must be rejected \
             by CHECK (plan-bundle-sealing.md §8.1 step 12b)"
        );
    }

    /// Migration 8 enforces the schema-1/schema-2 envelope contract on
    /// `plan_bundles`: schema-1 rows MUST have NULL signed_at/nonce;
    /// schema-2 rows MUST have non-NULL of both, with a 16-byte nonce.
    #[test]
    fn migration_8_plan_bundles_envelope_check_clause_is_enforced() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let bundle_a = vec![0x01u8; 32];
        let bundle_b = vec![0x02u8; 32];
        let bundle_c = vec![0x03u8; 32];
        let bundle_d = vec![0x04u8; 32];
        let bundle_e = vec![0x05u8; 32];
        let signature = vec![0x77u8; 64];
        let signed_by = vec![0x88u8; 8];
        let nonce_16 = vec![0xAAu8; 16];
        let nonce_short = vec![0xAAu8; 12];
        let now = raxis_types::unix_now_secs();
        let bundle_bytes = vec![0u8; 4];

        let ins = |sha: &Vec<u8>, schema: i64, signed_at: Option<i64>, nonce: Option<&Vec<u8>>| {
            conn.execute(
                &format!(
                    "INSERT INTO {} \
                       (bundle_sha256, bundle_bytes, signature, signed_by, \
                        schema_version, artifact_count, bundle_bytes_len, \
                        sealed_at_unix_secs, signed_at_unix_secs, bundle_nonce) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    Table::PlanBundles.as_str(),
                ),
                rusqlite::params![
                    sha,
                    bundle_bytes,
                    signature,
                    signed_by,
                    schema,
                    1i64,
                    bundle_bytes.len() as i64,
                    now,
                    signed_at,
                    nonce,
                ],
            )
        };

        // Schema-1 with both NULL → OK.
        let r = ins(&bundle_a, 1, None, None);
        assert!(
            r.is_ok(),
            "schema-1 with NULL envelope fields must accept: {r:?}"
        );

        // Schema-2 with full envelope → OK.
        let r = ins(&bundle_b, 2, Some(now), Some(&nonce_16));
        assert!(r.is_ok(), "schema-2 with full envelope must accept: {r:?}");

        // Schema-1 with envelope fields populated → REJECT.
        let r = ins(&bundle_c, 1, Some(now), Some(&nonce_16));
        assert!(
            r.is_err(),
            "schema-1 with non-NULL envelope fields must be rejected by CHECK"
        );

        // Schema-2 missing nonce → REJECT.
        let r = ins(&bundle_d, 2, Some(now), None);
        assert!(
            r.is_err(),
            "schema-2 with NULL bundle_nonce must be rejected by CHECK"
        );

        // Schema-2 with wrong-length nonce → REJECT.
        let r = ins(&bundle_e, 2, Some(now), Some(&nonce_short));
        assert!(
            r.is_err(),
            "schema-2 with non-16-byte bundle_nonce must be rejected by CHECK"
        );
    }

    /// V1 initiatives rows survive migration 8 with `plan_bundle_sha256
    /// = NULL`. The new column is additive; existing data is untouched.
    #[test]
    fn migration_8_preserves_v1_initiatives_rows_with_null_plan_bundle_sha256() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        apply_migration_4(&conn).unwrap();
        apply_migration_5(&conn).unwrap();
        apply_migration_6(&conn).unwrap();
        apply_migration_7(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 7);

        let now = raxis_types::unix_now_secs();
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES ('legacy-init', 'Draft', '{{}}', 'deadbeef', {now});",
            initiatives = Table::Initiatives.as_str(),
            now = now,
        ))
        .unwrap();

        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        // Pre-existing column still readable.
        let plan_artifact: String = conn
            .query_row(
                &format!(
                    "SELECT plan_artifact_sha256 FROM {} WHERE initiative_id='legacy-init'",
                    Table::Initiatives.as_str(),
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(plan_artifact, "deadbeef");

        // New column is NULL for pre-existing row.
        let plan_bundle: Option<Vec<u8>> = conn
            .query_row(
                &format!(
                    "SELECT plan_bundle_sha256 FROM {} WHERE initiative_id='legacy-init'",
                    Table::Initiatives.as_str(),
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            plan_bundle.is_none(),
            "V1 rows must retain plan_bundle_sha256 = NULL after migration 8"
        );
    }

    /// Migration 8 is idempotent under `apply_pending`.
    #[test]
    fn migration_8_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();

        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let total: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::SchemaVersion.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            total, SCHEMA_VERSION as i64,
            "schema_version must hold exactly SCHEMA_VERSION rows after \
             two apply_pending calls"
        );

        // Both new tables exist exactly once each.
        for table in [
            Table::PlanBundles,
            Table::PlanBundleArtifacts,
            Table::PlanBundleNoncesSeen,
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master \
                     WHERE type='table' AND name=?1",
                    rusqlite::params![table.as_str()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "{} must exist exactly once", table.as_str());
        }
    }

    /// Upgrade scenario: a database at v=7 must pick up migration 8
    /// cleanly when `apply_pending` runs.
    #[test]
    fn migration_8_applies_to_a_v7_database() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        apply_migration_4(&conn).unwrap();
        apply_migration_5(&conn).unwrap();
        apply_migration_6(&conn).unwrap();
        apply_migration_7(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 7);

        // Pre: none of the V2 plan-bundle tables exist yet.
        for table in [
            Table::PlanBundles,
            Table::PlanBundleArtifacts,
            Table::PlanBundleNoncesSeen,
        ] {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master \
                     WHERE type='table' AND name=?1",
                    rusqlite::params![table.as_str()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(exists, 0, "{} must NOT yet exist at v=7", table.as_str());
        }

        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        // Post: every V2 table now exists.
        for table in [
            Table::PlanBundles,
            Table::PlanBundleArtifacts,
            Table::PlanBundleNoncesSeen,
        ] {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master \
                     WHERE type='table' AND name=?1",
                    rusqlite::params![table.as_str()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "{} must exist after migration 8", table.as_str());
        }
    }

    /// Migration 8 wraps every DDL statement in a single
    /// `BEGIN EXCLUSIVE; ... COMMIT;`. Spliting the migration across
    /// multiple transactions would let a crash mid-DDL leave the schema
    /// half-applied (`schema_version` updated, indexes missing, …).
    #[test]
    fn migration_8_is_a_single_transaction() {
        let ddl = render_migration_8_ddl();
        assert_eq!(
            ddl.matches("BEGIN EXCLUSIVE").count(),
            1,
            "migration 8 must open exactly one transaction (BEGIN EXCLUSIVE)"
        );
        assert_eq!(
            ddl.matches("COMMIT").count(),
            1,
            "migration 8 must commit exactly once"
        );
        assert!(
            ddl.find("BEGIN EXCLUSIVE").unwrap() < ddl.find("COMMIT").unwrap(),
            "BEGIN must precede COMMIT"
        );
    }

    /// V2 enum-driven CHECK clause for the nonce-outcome column is
    /// pinned at the SQL level so a future variant addition forces a
    /// migration rather than slipping through silently.
    #[test]
    fn v2_plan_bundle_nonce_outcome_check_clause_is_pinned_to_migration_8() {
        assert_eq!(
            check_in_clause(
                &PlanBundleNonceOutcome::ALL,
                PlanBundleNonceOutcome::as_sql_str,
            ),
            "('Admitted', 'TerminallyRejected')",
        );
    }

    /// The supporting index on `plan_bundle_nonces_seen` is what makes
    /// the §8.4 retention sweep tractable. Pinning the index name +
    /// column surfaces silent removal in code review.
    #[test]
    fn migration_8_creates_first_seen_index_for_nonce_sweep() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let mut stmt = conn
            .prepare(
                "SELECT name, sql FROM sqlite_master \
                 WHERE type='index' AND tbl_name=?1 \
                   AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let indexes: Vec<(String, String)> = stmt
            .query_map(
                rusqlite::params![Table::PlanBundleNoncesSeen.as_str()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .unwrap()
            .map(Result::unwrap)
            .collect();

        let sweep_index = indexes
            .iter()
            .find(|(n, _)| n == "idx_plan_bundle_nonces_first_seen")
            .expect("idx_plan_bundle_nonces_first_seen must exist (§8.4 sweep)");
        assert!(
            sweep_index.1.contains("first_seen_at_unix_secs"),
            "sweep index must cover first_seen_at_unix_secs (got: {})",
            sweep_index.1
        );
    }

    // ── Migration 9 — V2 worktree clone-strategy column on `tasks` ─────

    /// Migration 9 adds `tasks.clone_strategy` as a NULLable TEXT
    /// column with a CHECK constraint pinning the (NULL | full |
    /// blobless | sparse) universe.
    #[test]
    fn migration_9_adds_clone_strategy_column_to_tasks() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let cols: Vec<(String, String, i64, Option<String>)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();

        let clone_strategy = cols
            .iter()
            .find(|(name, _, _, _)| name == "clone_strategy")
            .expect("tasks.clone_strategy column must exist after migration 9");

        assert_eq!(clone_strategy.1, "TEXT", "clone_strategy must be TEXT");
        assert_eq!(clone_strategy.2, 0, "clone_strategy must be NULLable");
        assert!(
            clone_strategy.3.is_none(),
            "clone_strategy must have no DEFAULT"
        );
    }

    /// The CHECK constraint on `clone_strategy` must accept the
    /// canonical `CloneStrategy::ALL` strings AND NULL, and reject
    /// anything else.
    #[test]
    fn migration_9_check_constraint_accepts_only_canonical_strings() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let now = raxis_types::unix_now_secs();
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES ('init-mig9', 'Draft', '{{}}', 'deadbeef', {now}); \
                 INSERT INTO {tasks} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at) \
                 VALUES ('task-mig9', 'init-mig9', 'lane.default', \
                         'Admitted', 'Operator', 1, {now}, {now});",
            initiatives = Table::Initiatives.as_str(),
            tasks = Table::Tasks.as_str(),
            now = now,
        ))
        .unwrap();

        let upd_sql = format!(
            "UPDATE {} SET clone_strategy = ?1 WHERE task_id = 'task-mig9'",
            Table::Tasks.as_str(),
        );

        for variant in &CloneStrategy::ALL {
            let r = conn.execute(&upd_sql, rusqlite::params![variant.as_sql_str()]);
            assert!(
                r.is_ok(),
                "CHECK constraint must accept canonical {variant:?} (got {r:?})"
            );
        }
        let r = conn.execute(&upd_sql, rusqlite::params![Option::<&str>::None]);
        assert!(r.is_ok(), "CHECK constraint must accept NULL (got {r:?})");

        for bogus in ["Full", "shallow", "treeless", ""] {
            let r = conn.execute(&upd_sql, rusqlite::params![bogus]);
            assert!(
                r.is_err(),
                "CHECK constraint must reject non-canonical {bogus:?}"
            );
        }
    }

    /// V2 enum-driven CHECK clauses are pinned at the SQL level so a
    /// future variant addition forces a migration rather than slipping
    /// through silently.
    #[test]
    fn migration_9_clone_strategy_check_pins_known_variants() {
        assert_eq!(
            check_in_clause(&CloneStrategy::ALL, CloneStrategy::as_sql_str),
            "('full', 'blobless', 'sparse')",
        );
    }

    /// Migration 9 is idempotent under `apply_pending`.
    #[test]
    fn migration_9_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();

        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let total: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::SchemaVersion.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, SCHEMA_VERSION as i64);

        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let n_clone_strategy = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .filter(|name| name == "clone_strategy")
            .count();
        assert_eq!(
            n_clone_strategy, 1,
            "clone_strategy must appear exactly once in tasks PRAGMA"
        );
    }

    /// Upgrade scenario: a database at v=8 must pick up migration 9
    /// cleanly when `apply_pending` runs.
    #[test]
    fn migration_9_applies_to_a_v8_database() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        apply_migration_4(&conn).unwrap();
        apply_migration_5(&conn).unwrap();
        apply_migration_6(&conn).unwrap();
        apply_migration_7(&conn).unwrap();
        apply_migration_8(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 8);

        let mut stmt_pre = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let has_pre = stmt_pre
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .any(|name| name == "clone_strategy");
        assert!(!has_pre, "clone_strategy must not yet exist at v=8");

        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let mut stmt_post = conn
            .prepare(&format!("PRAGMA table_info({})", Table::Tasks.as_str()))
            .unwrap();
        let has_post = stmt_post
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .any(|name| name == "clone_strategy");
        assert!(has_post, "migration 9 must add clone_strategy");
    }

    /// Migration 9 wraps the single ALTER TABLE in a single
    /// `BEGIN EXCLUSIVE; ... COMMIT;`.
    #[test]
    fn migration_9_is_a_single_transaction() {
        let ddl = render_migration_9_ddl();
        assert_eq!(
            ddl.matches("BEGIN EXCLUSIVE").count(),
            1,
            "migration 9 must open exactly one transaction (BEGIN EXCLUSIVE)"
        );
        assert_eq!(
            ddl.matches("COMMIT").count(),
            1,
            "migration 9 must commit exactly once"
        );
        assert!(
            ddl.find("BEGIN EXCLUSIVE").unwrap() < ddl.find("COMMIT").unwrap(),
            "BEGIN must precede COMMIT"
        );
    }

    // ── Migration 10: task_credential_proxies (per-task credential-proxy
    //                  declarations, METADATA ONLY — no credential
    //                  bytes are stored in kernel.db) ──────────────────────

    /// Migration 10 creates the `task_credential_proxies` table on
    /// a fresh DB after `apply_pending` runs.
    #[test]
    fn migration_10_creates_task_credential_proxies_table() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [Table::TaskCredentialProxies.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "task_credential_proxies table must exist after migration 10",
        );
    }

    /// The table name MUST be `task_credential_proxies`, NOT
    /// `task_credentials`. The shorter name was rejected because it
    /// would falsely imply that credential bytes are persisted in
    /// kernel.db (they are not — bytes live with the
    /// CredentialBackend, never in the DB). Pinning the literal at
    /// migration time surfaces any rename in code review.
    #[test]
    fn migration_10_table_name_disambiguates_from_credential_bytes() {
        assert_eq!(
            Table::TaskCredentialProxies.as_str(),
            "task_credential_proxies",
        );
        assert_ne!(
            Table::TaskCredentialProxies.as_str(),
            "task_credentials",
            "the bare `task_credentials` name is forbidden; it falsely \
             implies credential bytes are stored",
        );
    }

    /// The CHECK clause on `proxy_type` must accept the four MVP
    /// variants and reject everything else.
    #[test]
    fn migration_10_proxy_type_check_pins_known_variants() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let initiative_id = "init-mig10";
        let task_id = "task-mig10";
        let now = 1_700_000_000_i64;

        conn.execute_batch(&format!(
            "INSERT INTO {initiatives}
                 (initiative_id, state, terminal_criteria_json,
                  plan_artifact_sha256, created_at)
             VALUES ('{initiative_id}', 'Draft', '{{}}',
                     'deadbeef', {now});
             INSERT INTO {tasks}
                 (task_id, initiative_id, lane_id, state, actor,
                  policy_epoch, admitted_at, transitioned_at)
             VALUES ('{task_id}', '{initiative_id}', 'lane.default',
                     'Admitted', 'Operator', 1, {now}, {now});",
            initiatives = Table::Initiatives.as_str(),
            tasks = Table::Tasks.as_str(),
            now = now,
        ))
        .unwrap();

        let ins_sql = format!(
            "INSERT INTO {} (task_id, credential_name, mount_as,
                              proxy_type, proxy_json,
                              created_at_unix_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            Table::TaskCredentialProxies.as_str(),
        );

        for (idx, ok) in [
            "postgres", "http", "k8s", "smtp", "redis", "aws", "gcp", "azure",
        ]
        .iter()
        .enumerate()
        {
            let r = conn.execute(
                &ins_sql,
                rusqlite::params![
                    task_id,
                    format!("cred-{idx}"),
                    format!("MOUNT_{idx}"),
                    ok,
                    "{}",
                    now,
                ],
            );
            assert!(
                r.is_ok(),
                "CHECK constraint must accept canonical proxy_type {ok:?} (got {r:?})"
            );
        }

        for bogus in ["Postgres", "HTTP", "ftp", "", "ssh"] {
            let r = conn.execute(
                &ins_sql,
                rusqlite::params![
                    task_id,
                    format!("cred-bogus-{bogus}"),
                    "MOUNT_X",
                    bogus,
                    "{}",
                    now,
                ],
            );
            assert!(
                r.is_err(),
                "CHECK constraint must reject non-canonical proxy_type {bogus:?}"
            );
        }
    }

    /// Migration 10 is idempotent under `apply_pending`.
    #[test]
    fn migration_10_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();

        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let total: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::SchemaVersion.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, SCHEMA_VERSION as i64);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='table' AND name=?1",
                [Table::TaskCredentialProxies.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "task_credential_proxies must appear exactly once after \
             repeated apply_pending"
        );
    }

    /// Upgrade scenario: a database at v=9 must pick up migration 10
    /// cleanly when `apply_pending` runs.
    #[test]
    fn migration_10_applies_to_a_v9_database() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        apply_migration_4(&conn).unwrap();
        apply_migration_5(&conn).unwrap();
        apply_migration_6(&conn).unwrap();
        apply_migration_7(&conn).unwrap();
        apply_migration_8(&conn).unwrap();
        apply_migration_9(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 9);

        let pre_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='table' AND name=?1",
                [Table::TaskCredentialProxies.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            pre_count, 0,
            "task_credential_proxies must not yet exist at v=9",
        );

        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let post_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='table' AND name=?1",
                [Table::TaskCredentialProxies.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            post_count, 1,
            "migration 10 must add task_credential_proxies",
        );
    }

    /// Migration 10 wraps the table+index creation in a single
    /// `BEGIN EXCLUSIVE; ... COMMIT;`.
    #[test]
    fn migration_10_is_a_single_transaction() {
        let ddl = render_migration_10_ddl();
        assert_eq!(
            ddl.matches("BEGIN EXCLUSIVE").count(),
            1,
            "migration 10 must open exactly one transaction (BEGIN EXCLUSIVE)"
        );
        assert_eq!(
            ddl.matches("COMMIT").count(),
            1,
            "migration 10 must commit exactly once"
        );
        assert!(
            ddl.find("BEGIN EXCLUSIVE").unwrap() < ddl.find("COMMIT").unwrap(),
            "BEGIN must precede COMMIT"
        );
    }

    /// The composite PK enforces (task_id, credential_name) uniqueness.
    #[test]
    fn migration_10_pk_enforces_unique_credential_name_per_task() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let now = 1_700_000_000_i64;
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives}
                 (initiative_id, state, terminal_criteria_json,
                  plan_artifact_sha256, created_at)
             VALUES ('init-pk', 'Draft', '{{}}', 'deadbeef', {now});
             INSERT INTO {tasks}
                 (task_id, initiative_id, lane_id, state, actor,
                  policy_epoch, admitted_at, transitioned_at)
             VALUES ('task-pk', 'init-pk', 'lane.default', 'Admitted',
                     'Operator', 1, {now}, {now});",
            initiatives = Table::Initiatives.as_str(),
            tasks = Table::Tasks.as_str(),
            now = now,
        ))
        .unwrap();

        let ins_sql = format!(
            "INSERT INTO {} (task_id, credential_name, mount_as,
                              proxy_type, proxy_json,
                              created_at_unix_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            Table::TaskCredentialProxies.as_str(),
        );

        let r1 = conn.execute(
            &ins_sql,
            rusqlite::params!["task-pk", "db-main", "DB_URL", "postgres", "{}", now],
        );
        assert!(r1.is_ok(), "first insert must succeed (got {r1:?})");

        let r2 = conn.execute(
            &ins_sql,
            rusqlite::params!["task-pk", "db-main", "OTHER", "http", "{}", now],
        );
        assert!(
            r2.is_err(),
            "second insert with same (task_id, credential_name) must violate PK"
        );
    }

    // ── Migration 11: integration_merge_attempts (V2 pre-merge verifier
    //                  attempt tracking — integration-merge.md §11.10.1
    //                  & §11.10.4; verifier-processes.md §16) ─────────────

    /// Migration 11 creates the `integration_merge_attempts` table on
    /// a fresh DB after `apply_pending` runs.
    #[test]
    fn migration_11_creates_integration_merge_attempts_table() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [Table::IntegrationMergeAttempts.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "integration_merge_attempts table must exist after migration 11",
        );
    }

    /// The CHECK clause on `state` accepts every canonical
    /// `IntegrationMergeAttemptState` variant and rejects everything
    /// else. Using `INSERT OR REPLACE` to round-trip the same row id
    /// lets us reuse one parent initiative for each variant probe.
    #[test]
    fn migration_11_state_check_pins_known_variants() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let initiative_id = "init-mig11-state";
        let now = 1_700_000_000_i64;

        conn.execute_batch(&format!(
            "INSERT INTO {initiatives}
                 (initiative_id, state, terminal_criteria_json,
                  plan_artifact_sha256, created_at)
             VALUES ('{initiative_id}', 'Draft', '{{}}',
                     'deadbeef', {now});",
            initiatives = Table::Initiatives.as_str(),
            now = now,
        ))
        .unwrap();

        let imerge = Table::IntegrationMergeAttempts.as_str();

        for variant in &IntegrationMergeAttemptState::ALL {
            let (discard, finalized, candidate_merge_sha): (
                Option<&str>,
                Option<i64>,
                Option<&str>,
            ) = match variant {
                IntegrationMergeAttemptState::AwaitingPreMergeVerifiers => (None, None, None),
                IntegrationMergeAttemptState::PreMergeVerifiersPassed => {
                    (None, None, Some("c0ffee"))
                }
                IntegrationMergeAttemptState::CompletedAdvanceApplied => {
                    (None, Some(now + 100), Some("c0ffee"))
                }
                IntegrationMergeAttemptState::BlockedByPreMergeVerifier => {
                    (Some("verifier_blocked"), Some(now + 100), Some("c0ffee"))
                }
                IntegrationMergeAttemptState::DiscardedCandidateOnly => {
                    (Some("candidate_computation_failed"), Some(now + 100), None)
                }
                IntegrationMergeAttemptState::DiscardedCrashRecovery => {
                    (Some("crash_recovery"), Some(now + 100), Some("c0ffee"))
                }
            };

            let sql = format!(
                "INSERT OR REPLACE INTO {imerge}
                     (id, initiative_id, orchestrator_session_id,
                      requested_commit_sha, candidate_merge_sha,
                      state, discard_reason,
                      created_at, finalized_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            );
            let r = conn.execute(
                &sql,
                rusqlite::params![
                    "imerge-1",
                    initiative_id,
                    "session-orch",
                    "deadbeef",
                    candidate_merge_sha,
                    variant.as_sql_str(),
                    discard,
                    now,
                    finalized,
                ],
            );
            assert!(
                r.is_ok(),
                "CHECK constraint must accept canonical state {variant:?} (got {r:?})"
            );
        }

        let bogus_sql = format!(
            "INSERT INTO {imerge}
                 (id, initiative_id, orchestrator_session_id,
                  requested_commit_sha, candidate_merge_sha,
                  state, discard_reason,
                  created_at, finalized_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        );
        for bogus in ["Awaiting", "awaitingPremergeVerifiers", "Completed", ""] {
            let r = conn.execute(
                &bogus_sql,
                rusqlite::params![
                    format!("imerge-bogus-{bogus}"),
                    initiative_id,
                    "session-orch",
                    "deadbeef",
                    Option::<&str>::None,
                    bogus,
                    Option::<&str>::None,
                    now,
                    Option::<i64>::None,
                ],
            );
            assert!(
                r.is_err(),
                "CHECK constraint must reject non-canonical state {bogus:?}"
            );
        }
    }

    /// The CHECK clause on `discard_reason` accepts NULL plus every
    /// canonical `IntegrationMergeAttemptDiscardReason` variant and
    /// rejects everything else.
    #[test]
    fn migration_11_discard_reason_check_pins_known_variants() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let initiative_id = "init-mig11-discard";
        let now = 1_700_000_000_i64;

        conn.execute_batch(&format!(
            "INSERT INTO {initiatives}
                 (initiative_id, state, terminal_criteria_json,
                  plan_artifact_sha256, created_at)
             VALUES ('{initiative_id}', 'Draft', '{{}}',
                     'deadbeef', {now});",
            initiatives = Table::Initiatives.as_str(),
            now = now,
        ))
        .unwrap();

        let imerge = Table::IntegrationMergeAttempts.as_str();
        let ins_sql = format!(
            "INSERT INTO {imerge}
                 (id, initiative_id, orchestrator_session_id,
                  requested_commit_sha, candidate_merge_sha,
                  state, discard_reason,
                  created_at, finalized_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        );

        for variant in &IntegrationMergeAttemptDiscardReason::ALL {
            let id = format!("imerge-discard-{}", variant.as_sql_str());
            let r = conn.execute(
                &ins_sql,
                rusqlite::params![
                    id,
                    initiative_id,
                    "session-orch",
                    "deadbeef",
                    "c0ffee",
                    variant.terminal_state().as_sql_str(),
                    variant.as_sql_str(),
                    now,
                    now + 100,
                ],
            );
            assert!(
                r.is_ok(),
                "CHECK constraint must accept canonical discard_reason \
                 {variant:?} (got {r:?})"
            );
        }

        for bogus in ["Verifier_Blocked", "VERIFIER_BLOCKED", "rejected", "abort"] {
            let r = conn.execute(
                &ins_sql,
                rusqlite::params![
                    format!("imerge-discard-bogus-{bogus}"),
                    initiative_id,
                    "session-orch",
                    "deadbeef",
                    "c0ffee",
                    "BlockedByPreMergeVerifier",
                    bogus,
                    now,
                    now + 100,
                ],
            );
            assert!(
                r.is_err(),
                "CHECK constraint must reject non-canonical discard_reason {bogus:?}"
            );
        }
    }

    /// V2 enum-driven CHECK clauses are pinned at the SQL level so a
    /// future variant addition forces a migration rather than slipping
    /// through silently.
    #[test]
    fn migration_11_enum_check_clauses_match_spec() {
        assert_eq!(
            check_in_clause(
                &IntegrationMergeAttemptState::ALL,
                IntegrationMergeAttemptState::as_sql_str,
            ),
            "('AwaitingPreMergeVerifiers', 'PreMergeVerifiersPassed', \
              'BlockedByPreMergeVerifier', 'CompletedAdvanceApplied', \
              'DiscardedCandidateOnly', 'DiscardedCrashRecovery')"
                .replace("              ", ""),
        );
        assert_eq!(
            check_in_clause(
                &IntegrationMergeAttemptDiscardReason::ALL,
                IntegrationMergeAttemptDiscardReason::as_sql_str,
            ),
            "('verifier_blocked', 'candidate_computation_failed', \
              'crash_recovery', 'merge_aborted_by_operator')"
                .replace("              ", ""),
        );
    }

    /// The cross-column CHECK clause enforces the four valid (state,
    /// discard_reason, finalized_at, candidate_merge_sha) shapes from
    /// `integration-merge.md §11.10.1`. Pin a representative
    /// failing case for each shape so a future relaxation can't slip
    /// through.
    #[test]
    fn migration_11_cross_column_check_rejects_invalid_shapes() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let initiative_id = "init-mig11-cross";
        let now = 1_700_000_000_i64;

        conn.execute_batch(&format!(
            "INSERT INTO {initiatives}
                 (initiative_id, state, terminal_criteria_json,
                  plan_artifact_sha256, created_at)
             VALUES ('{initiative_id}', 'Draft', '{{}}',
                     'deadbeef', {now});",
            initiatives = Table::Initiatives.as_str(),
            now = now,
        ))
        .unwrap();

        let imerge = Table::IntegrationMergeAttempts.as_str();
        let ins_sql = format!(
            "INSERT INTO {imerge}
                 (id, initiative_id, orchestrator_session_id,
                  requested_commit_sha, candidate_merge_sha,
                  state, discard_reason,
                  created_at, finalized_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        );

        // 1. AwaitingPreMergeVerifiers with finalized_at set → reject.
        let r = conn.execute(
            &ins_sql,
            rusqlite::params![
                "x1",
                initiative_id,
                "sess",
                "deadbeef",
                Option::<&str>::None,
                "AwaitingPreMergeVerifiers",
                Option::<&str>::None,
                now,
                Some(now + 1),
            ],
        );
        assert!(
            r.is_err(),
            "AwaitingPreMergeVerifiers with finalized_at must be rejected"
        );

        // 2. PreMergeVerifiersPassed without candidate_merge_sha → reject.
        let r = conn.execute(
            &ins_sql,
            rusqlite::params![
                "x2",
                initiative_id,
                "sess",
                "deadbeef",
                Option::<&str>::None,
                "PreMergeVerifiersPassed",
                Option::<&str>::None,
                now,
                Option::<i64>::None,
            ],
        );
        assert!(
            r.is_err(),
            "PreMergeVerifiersPassed without candidate_merge_sha must be rejected"
        );

        // 3. CompletedAdvanceApplied with discard_reason set → reject.
        let r = conn.execute(
            &ins_sql,
            rusqlite::params![
                "x3",
                initiative_id,
                "sess",
                "deadbeef",
                "c0ffee",
                "CompletedAdvanceApplied",
                Some("verifier_blocked"),
                now,
                Some(now + 1),
            ],
        );
        assert!(
            r.is_err(),
            "CompletedAdvanceApplied with discard_reason must be rejected"
        );

        // 4. BlockedByPreMergeVerifier without discard_reason → reject.
        let r = conn.execute(
            &ins_sql,
            rusqlite::params![
                "x4",
                initiative_id,
                "sess",
                "deadbeef",
                "c0ffee",
                "BlockedByPreMergeVerifier",
                Option::<&str>::None,
                now,
                Some(now + 1),
            ],
        );
        assert!(
            r.is_err(),
            "BlockedByPreMergeVerifier without discard_reason must be rejected"
        );

        // 5. DiscardedCrashRecovery without finalized_at → reject.
        let r = conn.execute(
            &ins_sql,
            rusqlite::params![
                "x5",
                initiative_id,
                "sess",
                "deadbeef",
                "c0ffee",
                "DiscardedCrashRecovery",
                Some("crash_recovery"),
                now,
                Option::<i64>::None,
            ],
        );
        assert!(
            r.is_err(),
            "DiscardedCrashRecovery without finalized_at must be rejected"
        );
    }

    /// The partial open-attempts index is created and is the one
    /// the recovery sweep at §11.10.4 uses.
    #[test]
    fn migration_11_creates_open_attempts_index() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='index' AND name='idx_imerge_attempts_open'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "idx_imerge_attempts_open partial index must exist after migration 11",
        );
    }

    /// The FK on `initiative_id` rejects rows whose initiative does
    /// not exist. Foreign-key enforcement requires `PRAGMA
    /// foreign_keys = ON` on the *connection* — same way we set it
    /// in production via `Store::open_with_clock`.
    #[test]
    fn migration_11_rejects_orphan_initiative_id() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        apply_pending(&conn).unwrap();

        let imerge = Table::IntegrationMergeAttempts.as_str();
        let ins_sql = format!(
            "INSERT INTO {imerge}
                 (id, initiative_id, orchestrator_session_id,
                  requested_commit_sha, candidate_merge_sha,
                  state, discard_reason,
                  created_at, finalized_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        );
        let r = conn.execute(
            &ins_sql,
            rusqlite::params![
                "imerge-orphan",
                "no-such-initiative",
                "sess",
                "deadbeef",
                Option::<&str>::None,
                "AwaitingPreMergeVerifiers",
                Option::<&str>::None,
                1_i64,
                Option::<i64>::None,
            ],
        );
        assert!(
            r.is_err(),
            "FK on initiative_id must reject orphan rows when foreign_keys=ON"
        );
    }

    /// Migration 11 is idempotent under `apply_pending`.
    #[test]
    fn migration_11_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();

        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let total: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::SchemaVersion.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, SCHEMA_VERSION as i64);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='table' AND name=?1",
                [Table::IntegrationMergeAttempts.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "integration_merge_attempts must appear exactly once after \
             repeated apply_pending"
        );
    }

    /// Upgrade scenario: a database at v=10 must pick up migration 11
    /// cleanly when `apply_pending` runs.
    #[test]
    fn migration_11_applies_to_a_v10_database() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        apply_migration_4(&conn).unwrap();
        apply_migration_5(&conn).unwrap();
        apply_migration_6(&conn).unwrap();
        apply_migration_7(&conn).unwrap();
        apply_migration_8(&conn).unwrap();
        apply_migration_9(&conn).unwrap();
        apply_migration_10(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 10);

        let pre_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='table' AND name=?1",
                [Table::IntegrationMergeAttempts.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            pre_count, 0,
            "integration_merge_attempts must not yet exist at v=10",
        );

        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let post_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='table' AND name=?1",
                [Table::IntegrationMergeAttempts.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            post_count, 1,
            "migration 11 must add integration_merge_attempts",
        );
    }

    /// Migration 11 wraps the table+index creation in a single
    /// `BEGIN EXCLUSIVE; ... COMMIT;`.
    #[test]
    fn migration_11_is_a_single_transaction() {
        let ddl = render_migration_11_ddl();
        assert_eq!(
            ddl.matches("BEGIN EXCLUSIVE").count(),
            1,
            "migration 11 must open exactly one transaction (BEGIN EXCLUSIVE)"
        );
        assert_eq!(
            ddl.matches("COMMIT").count(),
            1,
            "migration 11 must commit exactly once"
        );
        assert!(
            ddl.find("BEGIN EXCLUSIVE").unwrap() < ddl.find("COMMIT").unwrap(),
            "BEGIN must precede COMMIT"
        );
    }

    // ── Migration 18 — sessions.initiative_id + nullable structured_outputs.task_id ──

    /// Migration 18 wraps the column ADD + table rebuild in a single
    /// `BEGIN EXCLUSIVE; ... COMMIT;` per the migration-1 invariant.
    #[test]
    fn migration_18_is_a_single_transaction() {
        let ddl = render_migration_18_ddl();
        assert_eq!(
            ddl.matches("BEGIN EXCLUSIVE").count(),
            1,
            "migration 18 must open exactly one transaction (BEGIN EXCLUSIVE)"
        );
        assert_eq!(
            ddl.matches("COMMIT").count(),
            1,
            "migration 18 must commit exactly once"
        );
        assert!(
            ddl.find("BEGIN EXCLUSIVE").unwrap() < ddl.find("COMMIT").unwrap(),
            "BEGIN must precede COMMIT"
        );
    }

    /// After migration 18, the `sessions` table carries an
    /// `initiative_id` column. PRAGMA reports the column shape; we
    /// assert it is nullable and that the partial index exists.
    #[test]
    fn migration_18_adds_sessions_initiative_id_column_and_partial_index() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();

        // Column metadata via PRAGMA — `initiative_id` must exist
        // and be nullable (notnull = 0).
        let (col_name, notnull): (String, i64) = conn
            .query_row(
                "SELECT name, [notnull] FROM pragma_table_info('sessions') \
                 WHERE name = 'initiative_id'",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .expect("sessions.initiative_id must exist after migration 18");
        assert_eq!(col_name, "initiative_id");
        assert_eq!(
            notnull, 0,
            "sessions.initiative_id must be nullable for backward compatibility \
             with non-V2 sessions (Gateway / Verifier)"
        );

        // Partial index must exist.
        let idx_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='index' AND name='idx_sessions_initiative'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            idx_count, 1,
            "idx_sessions_initiative partial index must exist after migration 18"
        );
    }

    /// After migration 18, the `structured_outputs` table accepts a
    /// row with `task_id IS NULL`. Pre-Migration-18 the FK + NOT NULL
    /// constraint would have rejected this insert.
    #[test]
    fn migration_18_structured_outputs_accepts_null_task_id() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        apply_pending(&conn).unwrap();

        let initiatives_t = Table::Initiatives.as_str();
        let sessions_t = Table::Sessions.as_str();
        let structured_outs_t = Table::StructuredOutputs.as_str();

        // Seed an initiative + an Orchestrator session linked to it.
        // The session has `initiative_id = 'init-1'` (Migration 18
        // back-edge) and no enclosing `tasks` row.
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives_t} \
                (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
             VALUES \
                ('init-1', 'Executing', '{{}}', 'aa', 0); \
             INSERT INTO {sessions_t} \
                (session_id, role_id, session_token, lineage_id, fetch_quota, \
                 created_at, expires_at, revoked, session_agent_type, \
                 can_delegate, initiative_id) \
             VALUES \
                ('sess-orch-1', 'Planner', 'tok-orch-1', 'lin-1', 0, 100, \
                 9999999999, 0, 'Orchestrator', 1, 'init-1');"
        ))
        .unwrap();

        // INSERT with `task_id IS NULL` — the orchestrator path the
        // intent handler exercises at runtime.
        let r = conn.execute(
            &format!(
                "INSERT INTO {structured_outs_t} \
                    (output_id, initiative_id, task_id, session_id, \
                     kind, severity, payload_json, emitted_at) \
                 VALUES \
                    ('out-orch-1', 'init-1', NULL, 'sess-orch-1', \
                     'progress_report', NULL, '{{}}', 100)"
            ),
            [],
        );
        assert!(
            r.is_ok(),
            "structured_outputs.task_id must accept NULL after migration 18: {r:?}"
        );

        // FK is still enforced when task_id IS NOT NULL — an
        // orphan task_id rejects.
        let r = conn.execute(
            &format!(
                "INSERT INTO {structured_outs_t} \
                    (output_id, initiative_id, task_id, session_id, \
                     kind, severity, payload_json, emitted_at) \
                 VALUES \
                    ('out-orphan-1', 'init-1', 'no-such-task', 'sess-orch-1', \
                     'progress_report', NULL, '{{}}', 100)"
            ),
            [],
        );
        assert!(
            r.is_err(),
            "FK on structured_outputs.task_id must still reject orphan non-null values \
             after migration 18"
        );
    }

    /// Migration 18 preserves every pre-existing structured_outputs
    /// row (the table-rebuild copy must be lossless).
    #[test]
    fn migration_18_preserves_existing_structured_outputs_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();

        // Apply migrations 1..=17 to land at the pre-18 schema.
        apply_migration_1(&conn).unwrap();
        apply_migration_2(&conn).unwrap();
        apply_migration_3(&conn).unwrap();
        apply_migration_4(&conn).unwrap();
        apply_migration_5(&conn).unwrap();
        apply_migration_6(&conn).unwrap();
        apply_migration_7(&conn).unwrap();
        apply_migration_8(&conn).unwrap();
        apply_migration_9(&conn).unwrap();
        apply_migration_10(&conn).unwrap();
        apply_migration_11(&conn).unwrap();
        apply_migration_12(&conn).unwrap();
        apply_migration_13(&conn).unwrap();
        apply_migration_14(&conn).unwrap();
        apply_migration_15(&conn).unwrap();
        apply_migration_16(&conn).unwrap();
        apply_migration_17(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), 17);

        let initiatives_t = Table::Initiatives.as_str();
        let sessions_t = Table::Sessions.as_str();
        let tasks_t = Table::Tasks.as_str();
        let so_t = Table::StructuredOutputs.as_str();

        // Seed minimum FK chain (initiative + session + task) and a
        // structured_outputs row pointing at the task. This row
        // MUST survive the Migration-18 table rebuild verbatim.
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives_t} \
                (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
             VALUES \
                ('init-1', 'Executing', '{{}}', 'aa', 0); \
             INSERT INTO {sessions_t} \
                (session_id, role_id, session_token, lineage_id, fetch_quota, \
                 created_at, expires_at, revoked) \
             VALUES \
                ('sess-1', 'Planner', 'tok-1', 'lin-1', 0, 100, 9999999999, 0); \
             INSERT INTO {tasks_t} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, session_id) \
             VALUES \
                ('task-1', 'init-1', 'lane-1', 'Running', 'op', 1, 100, 100, 'sess-1'); \
             INSERT INTO {so_t} \
                (output_id, initiative_id, task_id, session_id, \
                 kind, severity, payload_json, emitted_at) \
             VALUES \
                ('out-1', 'init-1', 'task-1', 'sess-1', \
                 'progress_report', NULL, '{{\"a\":1}}', 100);"
        ))
        .unwrap();

        // Apply migration 18.
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        // The pre-18 row survives unchanged.
        let (output_id, initiative_id, task_id, session_id, kind, payload): (
            String,
            String,
            Option<String>,
            String,
            String,
            String,
        ) = conn
            .query_row(
                &format!(
                    "SELECT output_id, initiative_id, task_id, session_id, kind, payload_json \
                       FROM {so_t} WHERE output_id = 'out-1'"
                ),
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .expect("pre-Migration-18 row must survive the table rebuild");
        assert_eq!(output_id, "out-1");
        assert_eq!(initiative_id, "init-1");
        assert_eq!(task_id, Some("task-1".to_owned()));
        assert_eq!(session_id, "sess-1");
        assert_eq!(kind, "progress_report");
        assert_eq!(payload, "{\"a\":1}");
    }

    /// Migration 18 is idempotent under `apply_pending`.
    #[test]
    fn migration_18_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        apply_pending(&conn).unwrap();
        assert_eq!(read_current_version(&conn).unwrap(), SCHEMA_VERSION as i64);

        let total: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::SchemaVersion.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, SCHEMA_VERSION as i64);

        // structured_outputs table must appear exactly once after
        // repeated apply_pending — the rebuild path is gated on
        // schema_version, so a second call must NOT drop+recreate.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='table' AND name=?1",
                [Table::StructuredOutputs.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "structured_outputs must appear exactly once after repeated apply_pending"
        );
    }
}
