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

-- Lookup: ORDER BY quarantined_at DESC for `list_all` (operator
-- inspect / doctor surfaces). See kernel-store.md §2.5.8.
CREATE INDEX IF NOT EXISTS idx_initiative_quarantines_quarantined_at
    ON initiative_quarantines (quarantined_at);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (4, strftime('%s', 'now'));

COMMIT;
