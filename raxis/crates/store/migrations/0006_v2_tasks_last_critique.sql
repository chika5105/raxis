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

-- ── tasks: V2 critique routing column ─────────────────────────────────────
-- last_critique: most-recent aggregated reviewer critique for this
-- (sub)task. NULL for V1 tasks and for V2 tasks that have never been
-- rejected. Hard-capped at MAX_CRITIQUE_BYTES at the application layer
-- (v2-deep-spec.md §Step 22) — the database does NOT enforce length so
-- a forensic dump can preserve the full payload that the kernel
-- accepted. Cleared (set NULL) on every fresh activation by the
-- subtask activation handler.
ALTER TABLE tasks
    ADD COLUMN last_critique TEXT;

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (6, strftime('%s', 'now'));

COMMIT;
