-- ┌──────────────────────────────────────────────────────────────────────┐
-- │ Auto-generated from raxis_store::migration::render_migration_N_ddl. │
-- │ DO NOT EDIT BY HAND.                                                │
-- │                                                                     │
-- │ Source of truth: crates/store/src/migration.rs                      │
-- │ Regenerate:      RAXIS_DUMP_MIGRATION_SQL=1 cargo test               │
-- │                  -p raxis-store --test migration_sql_dumps           │
-- │ Drift detector:  cargo test -p raxis-store --test migration_sql_dumps│
-- └──────────────────────────────────────────────────────────────────────┘

PRAGMA foreign_keys=OFF;
BEGIN EXCLUSIVE;

-- recovery-required initiatives -- split recoverable operator-action
-- pauses from terminal Failed. SQLite cannot ALTER a CHECK
-- constraint, so rebuild the initiatives table with the expanded
-- state set while preserving every v30 column.
CREATE TABLE initiatives_v31 (
    initiative_id          TEXT    NOT NULL PRIMARY KEY,
    state                  TEXT    NOT NULL
        CHECK (state IN ('Draft', 'ApprovedPlan', 'Executing', 'Blocked', 'RecoveryRequired', 'Completed', 'Failed', 'Aborted')),
    terminal_criteria_json TEXT    NOT NULL,
    plan_artifact_sha256   TEXT    NOT NULL,
    created_at             INTEGER NOT NULL,
    approved_at            INTEGER,
    completed_at           INTEGER,
    plan_bundle_sha256     BLOB
        REFERENCES plan_bundles(bundle_sha256),
    git_apply_pending      INTEGER NOT NULL DEFAULT 0,
    orchestrator_no_progress_respawn_count INTEGER NOT NULL DEFAULT 0
);

INSERT INTO initiatives_v31 (
    initiative_id,
    state,
    terminal_criteria_json,
    plan_artifact_sha256,
    created_at,
    approved_at,
    completed_at,
    plan_bundle_sha256,
    git_apply_pending,
    orchestrator_no_progress_respawn_count
)
SELECT
    initiative_id,
    state,
    terminal_criteria_json,
    plan_artifact_sha256,
    created_at,
    approved_at,
    completed_at,
    plan_bundle_sha256,
    git_apply_pending,
    orchestrator_no_progress_respawn_count
FROM initiatives;

DROP TABLE initiatives;
ALTER TABLE initiatives_v31 RENAME TO initiatives;

CREATE INDEX IF NOT EXISTS idx_initiatives_pending_git
    ON initiatives (initiative_id)
    WHERE git_apply_pending = 1;

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (31, strftime('%s', 'now'));

COMMIT;
PRAGMA foreign_keys=ON;
