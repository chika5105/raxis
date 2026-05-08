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

-- ── tasks: V2 worktree clone strategy column ──────────────────────────────
-- clone_strategy: chosen at admission time per v2-deep-spec.md §Step 27.
-- One of `full`, `blobless`, `sparse`. NULL on every V1 row; NOT NULL
-- on every V2 row (enforced at the application layer in admit_in_tx —
-- column-level NULLability is preserved here for V1 backward
-- compatibility). The CHECK clause pins the universe of legal V2
-- values through `CloneStrategy::ALL`, drift-protected by
-- `tests::migration_9_clone_strategy_check_pins_known_variants` below.
ALTER TABLE tasks
    ADD COLUMN clone_strategy TEXT
        CHECK (clone_strategy IS NULL
               OR clone_strategy IN ('full', 'blobless', 'sparse'));

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (9, strftime('%s', 'now'));

COMMIT;
