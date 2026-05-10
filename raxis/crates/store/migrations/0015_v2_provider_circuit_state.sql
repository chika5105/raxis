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

-- ── provider_circuit_state: per-(provider, model) circuit breaker ────────
CREATE TABLE provider_circuit_state (
    provider                  TEXT    NOT NULL,
    model                     TEXT    NOT NULL,
    state                     TEXT    NOT NULL CHECK (state IN ('Closed', 'Open', 'HalfOpen')),
    consecutive_failures      INTEGER NOT NULL DEFAULT 0,
    last_failure_at_ms        INTEGER,
    last_failure_kind         TEXT,
    last_failure_http_code    INTEGER,
    opened_at_ms              INTEGER,
    open_expires_at_ms        INTEGER,
    half_open_inflight        INTEGER NOT NULL DEFAULT 0 CHECK (half_open_inflight IN (0, 1)),
    last_success_at_ms        INTEGER,
    last_state_change_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (provider, model)
);

-- Index for lazy Open → HalfOpen promotion: the resolver scans for
-- rows where state = 'Open' AND open_expires_at_ms <= now().
CREATE INDEX idx_provider_circuit_state_open_expires
    ON provider_circuit_state (open_expires_at_ms)
    WHERE state = 'Open';

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (15, strftime('%s', 'now'));

COMMIT;
