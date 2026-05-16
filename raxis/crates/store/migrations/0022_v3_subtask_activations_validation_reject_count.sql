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

-- iter62 — `INV-INTENT-VALIDATION-REJECTED-CLASSIFIED-01`. The
-- kernel's FailInvalidDiff path bumps `validation_reject_count`
-- on the new activation row instead of `crash_retry_count`;
-- `max_validation_rejections` (per-activation ceiling) gates
-- the retry admission gate alongside `max_crash_retries` and
-- `max_review_rejections`.
ALTER TABLE subtask_activations
    ADD COLUMN validation_reject_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE subtask_activations
    ADD COLUMN max_validation_rejections INTEGER NOT NULL DEFAULT 2;

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (22, strftime('%s', 'now'));

COMMIT;
