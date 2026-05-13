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

-- Add the escalation initiator column. Default 'Planner' ⇒
-- pre-Migration-20 rows observably remain planner-initiated
-- (the only V1/V2 admission path was the planner-side
-- `EscalationRequest` IPC). The kernel-initiated auto-create
-- path inside `kernel/src/orch_respawn_ceiling.rs` writes
-- 'Kernel' explicitly. The text-typed CHECK keeps the column
-- closed-set so a future variant requires both an enum +
-- migration update.
ALTER TABLE escalations
    ADD COLUMN initiator TEXT NOT NULL DEFAULT 'Planner'
        CHECK (initiator IN ('Planner', 'Kernel'));

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (20, strftime('%s', 'now'));

COMMIT;
