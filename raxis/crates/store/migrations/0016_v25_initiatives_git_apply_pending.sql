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

-- Add the recovery driver flag. Default 0 ⇒ all preexisting rows
-- are observably in INV-MERGE-CONSISTENCY case (a) the moment
-- the migration completes (no in-flight merges across boots
-- because the process restart implies any prior process exit
-- was clean for the purposes of this column — pre-V2.5 the
-- column did not exist, so there is no pending work to recover).
ALTER TABLE initiatives ADD COLUMN git_apply_pending INTEGER NOT NULL DEFAULT 0;

-- Partial index keyed off the recovery driver predicate so the
-- boot-time scan in integration-merge.md §11.3 is O(in-flight
-- merges) rather than O(all initiatives).
CREATE INDEX idx_initiatives_pending_git
    ON initiatives (initiative_id)
    WHERE git_apply_pending = 1;

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (16, strftime('%s', 'now'));

COMMIT;
