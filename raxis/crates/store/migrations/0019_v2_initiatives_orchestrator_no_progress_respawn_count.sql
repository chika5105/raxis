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

-- Add the orchestrator-respawn no-progress counter. Default 0 ⇒
-- pre-Migration-19 rows observably have not accumulated respawns
-- (the counter only ever increments on a fresh respawn). Type is
-- INTEGER (SQLite stores it as i64 native); the kernel narrows
-- to u32 on read.
ALTER TABLE initiatives
    ADD COLUMN orchestrator_no_progress_respawn_count INTEGER NOT NULL DEFAULT 0;

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (19, strftime('%s', 'now'));

COMMIT;
