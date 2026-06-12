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

-- ── tasks: V2 §2.5 cumulative LLM token accounting ───────────────────────
ALTER TABLE tasks
    ADD COLUMN cumulative_input_tokens INTEGER NOT NULL DEFAULT 0;

ALTER TABLE tasks
    ADD COLUMN cumulative_output_tokens INTEGER NOT NULL DEFAULT 0;

-- Cumulative micro-dollar cost = sum over every accepted intent of
-- `provider_pricing.cost_micro_dollars(input_tokens, output_tokens, ...)`.
-- The kernel re-computes the increment per intent from the planner-
-- reported `tokens_used` delta and the active token-pricing resolver.
ALTER TABLE tasks
    ADD COLUMN cumulative_token_cost_micros INTEGER NOT NULL DEFAULT 0;

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (12, strftime('%s', 'now'));

COMMIT;
