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

-- verifier-run lifecycle status -- make failed verifier launches and
-- process failures visible in dashboard/API projections even when no
-- witness row can be produced.
ALTER TABLE verifier_run_tokens
    ADD COLUMN status TEXT NOT NULL DEFAULT 'Pending'
        CHECK (status IN (
            'Pending',
            'Pass',
            'Fail',
            'Inconclusive',
            'SpawnFailed',
            'ProcessFailed',
            'Timeout',
            'ConfigInvalid',
            'BudgetExhausted',
            'CapExceeded'
        ));

ALTER TABLE verifier_run_tokens
    ADD COLUMN failure_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_verifier_run_tokens_status
    ON verifier_run_tokens (task_id, status, issued_at DESC);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (28, strftime('%s', 'now'));

COMMIT;
