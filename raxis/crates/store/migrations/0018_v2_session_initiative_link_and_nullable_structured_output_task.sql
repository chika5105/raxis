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

-- ── 1. sessions: add initiative_id (nullable) + partial index ────────────
--
-- v2_extended_gaps.md §3.2 — a planner-class session needs a typed
-- back-reference to the initiative it was minted under so the kernel
-- can route Orchestrator-emitted `structured_output` rows to the
-- correct `initiatives.initiative_id` without a join through
-- `subtask_activations`. NULL for pre-Migration-18 rows and for
-- non-V2 sessions (Gateway / Verifier).
ALTER TABLE sessions
    ADD COLUMN initiative_id TEXT
        REFERENCES initiatives(initiative_id) ON DELETE CASCADE;

-- Partial index — most rows are NULL; we only ever probe by the
-- populated subset (operator-side initiative dashboards, recovery
-- driver coordinator-rebind).
CREATE INDEX IF NOT EXISTS idx_sessions_initiative
    ON sessions (initiative_id)
    WHERE initiative_id IS NOT NULL;

-- ── 2. structured_outputs: rebuild with nullable task_id ─────────────────
--
-- Column shape mirrors migration 13 byte-for-byte modulo the
-- `task_id` nullability. The FK to `tasks(task_id)` is preserved —
-- SQLite enforces FKs only when the column value is non-NULL, so
-- executor / reviewer rows keep their referential guarantee and
-- orchestrator rows (NULL) bypass the FK without a constraint
-- violation.
CREATE TABLE structured_outputs_new (
    output_id      TEXT NOT NULL PRIMARY KEY,
    initiative_id  TEXT NOT NULL REFERENCES initiatives(initiative_id) ON DELETE CASCADE,
    task_id        TEXT          REFERENCES tasks(task_id)             ON DELETE CASCADE,
    session_id     TEXT NOT NULL REFERENCES sessions(session_id)       ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('progress_report', 'diagnostic_flag', 'task_summary')),
    severity       TEXT          CHECK (severity IS NULL OR severity IN ('info', 'warning', 'critical')),
    payload_json   TEXT NOT NULL,
    emitted_at     INTEGER NOT NULL
);

INSERT INTO structured_outputs_new
    (output_id, initiative_id, task_id, session_id,
     kind, severity, payload_json, emitted_at)
SELECT output_id, initiative_id, task_id, session_id,
       kind, severity, payload_json, emitted_at
  FROM structured_outputs;

DROP TABLE structured_outputs;

ALTER TABLE structured_outputs_new RENAME TO structured_outputs;

-- Recreate the migration-13 indexes — DROP TABLE drops the indexes
-- defined on the old table along with it.
CREATE INDEX idx_structured_outputs_task
    ON structured_outputs(task_id, emitted_at)
    WHERE task_id IS NOT NULL;

CREATE INDEX idx_structured_outputs_initiative
    ON structured_outputs(initiative_id, emitted_at);

CREATE INDEX idx_structured_outputs_session
    ON structured_outputs(session_id);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (18, strftime('%s', 'now'));

COMMIT;
