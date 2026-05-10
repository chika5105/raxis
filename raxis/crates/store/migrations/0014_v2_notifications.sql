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

-- ── notifications: kernel-owned notification store ──────────────────────
CREATE TABLE notifications (
    notification_id  TEXT    NOT NULL PRIMARY KEY,
    event_kind       TEXT    NOT NULL,
    initiative_id    TEXT             REFERENCES initiatives(initiative_id) ON DELETE CASCADE,
    task_id          TEXT             REFERENCES tasks(task_id)             ON DELETE CASCADE,
    session_id       TEXT             REFERENCES sessions(session_id)       ON DELETE CASCADE,
    summary          TEXT    NOT NULL,
    payload_json     TEXT    NOT NULL,
    read             INTEGER NOT NULL DEFAULT 0 CHECK (read IN (0, 1)),
    source_event_id  TEXT    NOT NULL,
    created_at       INTEGER NOT NULL
);

-- Primary query path: unread notifications, newest first.
CREATE INDEX idx_notifications_unread
    ON notifications(read, created_at DESC);

-- Per-initiative notification history.
CREATE INDEX idx_notifications_initiative
    ON notifications(initiative_id, created_at DESC);

-- Per-task notification history.
CREATE INDEX idx_notifications_task
    ON notifications(task_id, created_at DESC);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (14, strftime('%s', 'now'));

COMMIT;
