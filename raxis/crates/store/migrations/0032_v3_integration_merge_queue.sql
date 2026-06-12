-- ┌──────────────────────────────────────────────────────────────────────┐
-- │ Auto-generated from raxis_store::migration::render_migration_N_ddl. │
-- │ DO NOT EDIT BY HAND.                                                │
-- │                                                                     │
-- │ Source of truth: crates/store/src/migration.rs                      │
-- │ Regenerate:      RAXIS_DUMP_MIGRATION_SQL=1 cargo test               │
-- │                  -p raxis-store --test migration_sql_dumps           │
-- │ Drift detector:  cargo test -p raxis-store --test migration_sql_dumps│
-- └──────────────────────────────────────────────────────────────────────┘

BEGIN EXCLUSIVE;

-- repo/ref IntegrationMerge closeout queue -- serializes only the final
-- managed-repository target-ref advancement for one (repository_id,
-- target_ref). Executor/reviewer work remains parallel; this table records
-- the deterministic closeout order and recoverable conflict diagnostics.
CREATE TABLE IF NOT EXISTS integration_merge_queue (
    queue_id                TEXT    NOT NULL PRIMARY KEY,
    initiative_id           TEXT    NOT NULL
        REFERENCES initiatives(initiative_id)
        ON DELETE CASCADE,
    task_id                 TEXT    NOT NULL
        REFERENCES tasks(task_id)
        ON DELETE CASCADE,
    orchestrator_session_id TEXT,
    repository_id           TEXT    NOT NULL,
    target_ref              TEXT    NOT NULL,
    requested_commit_sha    TEXT    NOT NULL,
    base_sha                TEXT,
    worktree_root           TEXT    NOT NULL,
    state                   TEXT    NOT NULL
        CHECK (state IN (
            'Queued',
            'Running',
            'Completed',
            'RecoveryRequired',
            'Failed',
            'Cancelled'
        )),
    enqueued_at             INTEGER NOT NULL,
    started_at              INTEGER,
    finished_at             INTEGER,
    applied_commit_sha      TEXT,
    previous_sha            TEXT,
    failure_category        TEXT,
    failure_reason          TEXT,
    operator_hint           TEXT
);

CREATE INDEX IF NOT EXISTS idx_integration_merge_queue_active
    ON integration_merge_queue (repository_id, target_ref, state, enqueued_at);

CREATE INDEX IF NOT EXISTS idx_integration_merge_queue_initiative
    ON integration_merge_queue (initiative_id, enqueued_at);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (32, strftime('%s', 'now'));

COMMIT;
