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

-- iter69 -- surface per-session provider+model on the dashboard.
-- Both columns nullable; populated opportunistically by the
-- kernel intent handler (provider) and by the dashboard
-- session-view enrichment (model, lifted from the latest LLM
-- turn capture). Existing rows remain NULL/NULL and render as
-- a placeholder on the dashboard until the next usage report.
ALTER TABLE sessions ADD COLUMN provider TEXT;
ALTER TABLE sessions ADD COLUMN model TEXT;

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (25, strftime('%s', 'now'));

COMMIT;
