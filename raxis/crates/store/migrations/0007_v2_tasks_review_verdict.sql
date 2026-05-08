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

-- ── tasks: V2 per-Reviewer verdict column ─────────────────────────────────
-- review_verdict: latest verdict for this (Reviewer) task. NULL for
-- pre-V2 tasks and for Reviewer tasks that have not yet submitted.
-- Written by `handlers/intent::handle_submit_review` on accept of a
-- SubmitReview, alongside the FSM transition Running → Completed (one
-- SQLite tx, INV-STORE-02 Pattern B). Cleared (set NULL) on every fresh
-- activation by the subtask activation handler — same lifecycle as
-- `last_critique`.
ALTER TABLE tasks
    ADD COLUMN review_verdict TEXT
        CHECK (review_verdict IS NULL
               OR review_verdict IN ('Approved', 'Rejected'));

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (7, strftime('%s', 'now'));

COMMIT;
