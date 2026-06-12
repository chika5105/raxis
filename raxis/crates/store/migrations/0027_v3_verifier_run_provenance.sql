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

-- iter verifier-provenance -- classify every verifier run by source and hook.
-- These fields let the dashboard and audit readers distinguish active
-- policy gates, per-task plan verifiers, and future integration verifiers
-- without inferring semantics from gate_type strings.
ALTER TABLE verifier_run_tokens
    ADD COLUMN gate_source TEXT NOT NULL DEFAULT 'policy_gate';

ALTER TABLE verifier_run_tokens
    ADD COLUMN gate_hook TEXT NOT NULL DEFAULT 'intent';

ALTER TABLE verifier_run_tokens
    ADD COLUMN verifier_image_alias TEXT;

ALTER TABLE verifier_run_tokens
    ADD COLUMN verifier_command TEXT;

ALTER TABLE verifier_run_tokens
    ADD COLUMN verifier_on_failure TEXT;

CREATE INDEX IF NOT EXISTS idx_verifier_run_tokens_source_hook
    ON verifier_run_tokens (task_id, gate_source, gate_hook, issued_at DESC);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (27, strftime('%s', 'now'));

COMMIT;
