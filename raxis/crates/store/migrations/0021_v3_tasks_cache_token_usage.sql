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

-- iter62 — per-task cumulative cache-token ledger
-- (`INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01`). The kernel's
-- `pre_gate_evaluate_for_envelope` UPDATE bumps these columns
-- in lock-step with `cumulative_input_tokens` /
-- `cumulative_output_tokens` whenever the planner reports
-- non-zero cache_creation / cache_read deltas in
-- `IntentRequest.tokens_used`.
ALTER TABLE tasks
    ADD COLUMN cumulative_cache_creation_tokens INTEGER NOT NULL DEFAULT 0;

ALTER TABLE tasks
    ADD COLUMN cumulative_cache_read_tokens INTEGER NOT NULL DEFAULT 0;

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (21, strftime('%s', 'now'));

COMMIT;
