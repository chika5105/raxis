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

-- ── Table 20: operator_certificates ──────────────────────────────────────────
-- Denormalised view of [[operators.entries.cert]] from the currently-
-- installed policy.toml. Repopulated atomically on every advance_epoch.
--
-- Columns:
--   pubkey_fingerprint    — SHA-256[:16] of the operator's pubkey;
--                           UNIQUE (one cert per operator at any time).
--   epoch_id              — policy_epoch_history.epoch_id this cert was
--                           installed under. FK enforces that the
--                           denormalised view cannot reference an epoch
--                           that no longer exists in the history table.
--   kind                  — 'Standard' | 'EmergencyRecovery' (from
--                           CertKind::as_str). CHECK constraint pins
--                           the universe of accepted values; a
--                           future kind requires a new migration.
--   display_name          — operator label (denormalised from cert).
--   pubkey_hex            — 64-char raw Ed25519 pubkey (denormalised).
--   not_before            — Unix seconds. 0 sentinel for emergency.
--   not_after             — Unix seconds. 0 sentinel for emergency.
--   warn_before_expiry_days — width of the Expiring zone.
--   grace_period_days     — width of the Grace zone.
--   permitted_ops_json    — JSON array of op names. Stored as JSON
--                           rather than a separate child table so the
--                           cert is always queryable as a single row
--                           (no joins for the common path).
--   contact_info          — optional free-form string; NULL when
--                           absent.
--   self_sig_hex          — 128-char self-signature for
--                           re-verification on demand.
--   force_misconfig_bypass — 0 or 1; mirrors the entry-level flag so
--                           audit / doctor queries can `SELECT *
--                           WHERE force_misconfig_bypass = 1` without
--                           re-reading the policy bundle.
--   installed_at          — Unix seconds when this row was rebuilt.
CREATE TABLE IF NOT EXISTS operator_certificates (
    pubkey_fingerprint      TEXT    NOT NULL PRIMARY KEY,
    epoch_id                INTEGER NOT NULL
        REFERENCES policy_epoch_history(epoch_id),
    kind                    TEXT    NOT NULL
        CHECK (kind IN ('Standard', 'EmergencyRecovery')),
    display_name            TEXT    NOT NULL,
    pubkey_hex              TEXT    NOT NULL UNIQUE,
    not_before              INTEGER NOT NULL,
    not_after               INTEGER NOT NULL,
    warn_before_expiry_days INTEGER NOT NULL,
    grace_period_days       INTEGER NOT NULL,
    permitted_ops_json      TEXT    NOT NULL,
    contact_info            TEXT,
    self_sig_hex            TEXT    NOT NULL,
    force_misconfig_bypass  INTEGER NOT NULL DEFAULT 0
        CHECK (force_misconfig_bypass IN (0, 1)),
    installed_at            INTEGER NOT NULL
);

-- Lookup: expiry sweep. Standard certs only — emergency certs have
-- not_after = 0 sentinel and would always sort first; partial index
-- on kind = 'Standard' keeps the index small and the sweep precise.
CREATE INDEX IF NOT EXISTS idx_operator_certificates_expiry_sweep
    ON operator_certificates (not_after, kind)
    WHERE kind = 'Standard';

-- Lookup: enumerate emergency certs without scanning the whole table.
CREATE INDEX IF NOT EXISTS idx_operator_certificates_emergency
    ON operator_certificates (kind)
    WHERE kind = 'EmergencyRecovery';

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (2, strftime('%s', 'now'));

COMMIT;
