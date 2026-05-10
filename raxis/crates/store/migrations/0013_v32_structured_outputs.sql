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

-- ── structured_outputs: V2 §3.2 typed mid-session outputs ───────────────
CREATE TABLE structured_outputs (
    output_id      TEXT NOT NULL PRIMARY KEY,
    initiative_id  TEXT NOT NULL REFERENCES initiatives(initiative_id) ON DELETE CASCADE,
    task_id        TEXT NOT NULL REFERENCES tasks(task_id)             ON DELETE CASCADE,
    session_id     TEXT NOT NULL REFERENCES sessions(session_id)       ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('progress_report', 'diagnostic_flag', 'task_summary')),
    severity       TEXT          CHECK (severity IS NULL OR severity IN ('info', 'warning', 'critical')),
    payload_json   TEXT NOT NULL,
    emitted_at     INTEGER NOT NULL
);

CREATE INDEX idx_structured_outputs_task
    ON structured_outputs(task_id, emitted_at);

CREATE INDEX idx_structured_outputs_initiative
    ON structured_outputs(initiative_id, emitted_at);

CREATE INDEX idx_structured_outputs_session
    ON structured_outputs(session_id);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (13, strftime('%s', 'now'));

COMMIT;
