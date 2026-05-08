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

-- ── signed_plan_artifacts.signed_by_fingerprint ─────────────────────────────
-- The operator pubkey_fingerprint that approved this plan (the operator
-- whose Ed25519 signature `lifecycle::approve_plan` verified). Needed by
-- `quarantine-plans-by` to sweep every initiative whose plan was approved
-- by a now-compromised operator.
--
-- NULLABLE for backward compatibility with rows inserted under
-- migration 1/2 (pre-step-10). Application code MUST set this column
-- on every new INSERT going forward; the sweep skips NULL rows on the
-- premise that v1 approvals predate this column entirely.
ALTER TABLE signed_plan_artifacts
    ADD COLUMN signed_by_fingerprint TEXT;

-- Lookup: enumerate all initiatives a given operator approved.
CREATE INDEX IF NOT EXISTS idx_signed_plan_artifacts_signed_by
    ON signed_plan_artifacts (signed_by_fingerprint)
    WHERE signed_by_fingerprint IS NOT NULL;

-- ── Table 21: initiative_quarantines ────────────────────────────────────────
-- Quarantine markers. One row per quarantined initiative. The kernel
-- intent path rejects new IntentRequests against any initiative with a
-- row here.
--
-- Columns:
--   initiative_id      — PK; FK into initiatives so a quarantine row
--                        cannot reference an unknown initiative.
--   quarantined_at     — Unix seconds; clock-injected at insert time.
--   quarantined_by     — operator pubkey_fingerprint that issued the
--                        command (peripherals.md §3 'operator socket'
--                        fingerprint format: SHA-256[:16] of the raw
--                        Ed25519 pubkey, 32 hex chars).
--   reason             — free-form operator-supplied label; capped at
--                        the application layer to 512 bytes.
--   sweep_target       — NULL for single-initiative quarantines;
--                        carries the pubkey_fingerprint of the
--                        operator whose plans were swept when this
--                        row originated from the
--                        `quarantine-plans-by` sweep. Lets `raxis
--                        inspect` distinguish individually-quarantined
--                        initiatives from collateral sweep entries
--                        without joining against the audit chain.
CREATE TABLE IF NOT EXISTS initiative_quarantines (
    initiative_id   TEXT    NOT NULL PRIMARY KEY
        REFERENCES initiatives(initiative_id),
    quarantined_at  INTEGER NOT NULL,
    quarantined_by  TEXT    NOT NULL,
    reason          TEXT,
    sweep_target    TEXT
);

-- Lookup: enumerate all initiatives a given operator quarantined.
-- NOTE (spec/migration parity audit, 2026-05): no v1 kernel code
-- path filters by `quarantined_by` yet — the column is populated for
-- forensics, but the only reader (`views::initiative_quarantines::
-- list_all`) does an unfiltered scan ordered by `quarantined_at`. The
-- index is preserved as it supports the obvious future
-- `raxis inspect --quarantined-by <op-fp>` surface and is small (one
-- entry per quarantined initiative). The spec DDL block in
-- kernel-store.md §2.5.8 documents this index with the same future-
-- use note.
CREATE INDEX IF NOT EXISTS idx_initiative_quarantines_by_operator
    ON initiative_quarantines (quarantined_by);

-- Lookup: enumerate sweep-collateral entries for a given operator.
CREATE INDEX IF NOT EXISTS idx_initiative_quarantines_sweep_target
    ON initiative_quarantines (sweep_target)
    WHERE sweep_target IS NOT NULL;

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (3, strftime('%s', 'now'));

COMMIT;
