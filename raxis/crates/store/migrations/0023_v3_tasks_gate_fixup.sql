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

-- iter65 — gate-fixup columns on tasks.
-- specs/v3/gate-rejection-orchestrator-fixup.md §4.8.
ALTER TABLE tasks
    ADD COLUMN gate_reject_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE tasks
    ADD COLUMN gate_fixup_attempts INTEGER NOT NULL DEFAULT 0;

ALTER TABLE tasks
    ADD COLUMN last_gate_critique TEXT;

ALTER TABLE tasks
    ADD COLUMN last_gate_type TEXT;

ALTER TABLE tasks
    ADD COLUMN is_gate_fixup INTEGER NOT NULL DEFAULT 0;

ALTER TABLE tasks
    ADD COLUMN parent_gate_failure_task_id TEXT;

ALTER TABLE tasks
    ADD COLUMN parent_gate_failure_type TEXT;

-- Partial index: only fixup rows. Fixup-completion hook reads
-- `WHERE parent_gate_failure_task_id = ? AND is_gate_fixup = 1`.
CREATE INDEX IF NOT EXISTS idx_tasks_parent_gate_failure
    ON tasks (parent_gate_failure_task_id)
    WHERE is_gate_fixup = 1;

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (23, strftime('%s', 'now'));

COMMIT;
