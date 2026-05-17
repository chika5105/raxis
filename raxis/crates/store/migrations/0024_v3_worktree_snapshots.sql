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

-- iter68 — content-addressed worktree snapshot index.
-- specs/v3/worktree-snapshots.md §3 (schema).
-- INV-WORKTREE-SNAPSHOT-{PRE-GC, CONTENT-ADDR, DURABLE-WRITE, BOUNDED-DIFF}-01.
CREATE TABLE IF NOT EXISTS worktree_snapshots (
    snapshot_id           TEXT    NOT NULL PRIMARY KEY,
    task_id               TEXT    NOT NULL
        REFERENCES tasks(task_id),
    session_id            TEXT,
    initiative_id         TEXT,
    trigger               TEXT    NOT NULL
        CHECK (trigger IN ('ExecutorActivate','ExecutorIdle',
                           'ExecutorCommitCopy','WitnessPass',
                           'WitnessFail','WitnessInconclusive',
                           'IntegrationMerge','PreGc')),
    taken_at              INTEGER NOT NULL,
    base_sha              TEXT    NOT NULL,
    head_sha              TEXT    NOT NULL,
    commit_count          INTEGER NOT NULL DEFAULT 0,
    diff_blob_sha256      TEXT,
    log_blob_sha256       TEXT,
    tree_blob_sha256      TEXT,
    porcelain_blob_sha256 TEXT,
    diff_bytes_total      INTEGER NOT NULL DEFAULT 0,
    diff_truncated        INTEGER NOT NULL DEFAULT 0
        CHECK (diff_truncated IN (0, 1))
);

-- Per-task lookup: the dashboard's TaskDetail page lists every
-- snapshot for the task in reverse-chronological order.
CREATE INDEX IF NOT EXISTS idx_worktree_snapshots_task_time
    ON worktree_snapshots (task_id, taken_at DESC);

-- Per-session lookup: the GitWorktrees page joins snapshots back to
-- the session that produced them (so a GC'd worktree can still
-- surface its last few snapshots).
CREATE INDEX IF NOT EXISTS idx_worktree_snapshots_session_time
    ON worktree_snapshots (session_id, taken_at DESC);

-- Per-initiative lookup: the InitiativeDetail page rolls up
-- snapshots across the initiative's tasks.
CREATE INDEX IF NOT EXISTS idx_worktree_snapshots_initiative_time
    ON worktree_snapshots (initiative_id, taken_at DESC);

-- Content-address dedupe lookup. Reading this index answers
-- 'is the diff_blob_sha256 already referenced by another row?'
-- in O(log N) — used by `snapshot_worktree` to short-circuit blob
-- writes on stable worktree states.
CREATE INDEX IF NOT EXISTS idx_worktree_snapshots_diff_sha
    ON worktree_snapshots (diff_blob_sha256);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (24, strftime('%s', 'now'));

COMMIT;
