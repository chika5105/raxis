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

-- iter env-debug -- per-session VM env snapshot for dashboard debugging.
-- Values are redacted before insertion when the key/value shape is
-- authority-bearing. The table records key presence even when value
-- redaction is required.
CREATE TABLE IF NOT EXISTS session_vm_env (
    session_id  TEXT    NOT NULL
        REFERENCES sessions(session_id)
        ON DELETE CASCADE,
    env_key     TEXT    NOT NULL,
    env_value   TEXT    NOT NULL,
    redacted    INTEGER NOT NULL DEFAULT 0
        CHECK (redacted IN (0, 1)),
    source      TEXT    NOT NULL DEFAULT 'session-spawn',
    captured_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, env_key)
);

CREATE INDEX IF NOT EXISTS idx_session_vm_env_session
    ON session_vm_env (session_id, env_key);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (26, strftime('%s', 'now'));

COMMIT;
