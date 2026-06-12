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

-- adopted repository lifecycle -- persistent metadata for repositories
-- explicitly adopted by the operator. Dashboard/CLI/kernel code must
-- prefer this table over directory scanning so a child of a parent Git
-- checkout is never mistaken for a RAXIS-managed repository.
CREATE TABLE IF NOT EXISTS managed_repositories (
    repository_id      TEXT    PRIMARY KEY,
    managed_path       TEXT    NOT NULL,
    source_url         TEXT,
    default_remote     TEXT,
    default_target_ref TEXT    NOT NULL DEFAULT 'refs/heads/main',
    tracking_ref       TEXT,
    lifecycle_state    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (lifecycle_state IN (
            'unknown',
            'clean',
            'dirty',
            'ahead',
            'behind',
            'diverged',
            'local_only',
            'remote_unreachable',
            'missing',
            'not_a_git_root'
        )),
    publish_state      TEXT    NOT NULL DEFAULT 'local_only'
        CHECK (publish_state IN (
            'unknown',
            'local_only',
            'pending',
            'published',
            'failed'
        )),
    head_sha           TEXT,
    remote_sha         TEXT,
    ahead_count        INTEGER,
    behind_count       INTEGER,
    dirty              INTEGER NOT NULL DEFAULT 0 CHECK (dirty IN (0, 1)),
    last_fetch_at      INTEGER,
    last_push_at       INTEGER,
    last_status_at     INTEGER,
    last_error         TEXT,
    adopted_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_managed_repositories_lifecycle
    ON managed_repositories (lifecycle_state, publish_state);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (29, strftime('%s', 'now'));

COMMIT;
