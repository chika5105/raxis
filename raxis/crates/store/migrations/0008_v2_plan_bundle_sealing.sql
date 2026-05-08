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

-- ── plan_bundles ─────────────────────────────────────────────────────────
-- Content-addressed store of admitted V2 plan bundles. Keyed by the
-- canonical bundle_sha256 (32 bytes, the hash the operator signed); two
-- initiatives that happen to use byte-identical bundles share a single
-- row here.
--
-- Retained indefinitely per plan-bundle-sealing.md §10 (D8): the bundle
-- bytes are foundational cryptographic input to the initiative state
-- machine, and audit-chain replay needs to be able to re-derive the
-- exact plan the kernel executed.
--
-- Schema-1 envelopes (V2.0 cutover bundles) carry NULL for
-- signed_at_unix_secs / bundle_nonce. Schema-2 envelopes (V2.1 default)
-- carry both. The kernel admission path enforces the schema-vs-fields
-- contract at decode time.
CREATE TABLE IF NOT EXISTS plan_bundles (
    bundle_sha256          BLOB    NOT NULL PRIMARY KEY,
    bundle_bytes           BLOB    NOT NULL,
    signature              BLOB    NOT NULL,
    signed_by              BLOB    NOT NULL,
    schema_version         INTEGER NOT NULL,
    artifact_count         INTEGER NOT NULL,
    bundle_bytes_len       INTEGER NOT NULL,
    sealed_at_unix_secs    INTEGER NOT NULL,
    signed_at_unix_secs    INTEGER,
    bundle_nonce           BLOB,
    CHECK (length(bundle_sha256) = 32),
    CHECK (length(signature)     = 64),
    CHECK (length(signed_by)     = 8),
    CHECK (schema_version IN (1, 2)),
    CHECK (artifact_count   >= 1),
    CHECK (bundle_bytes_len >= 0),
    CHECK (
        (schema_version = 1
         AND signed_at_unix_secs IS NULL
         AND bundle_nonce        IS NULL)
        OR
        (schema_version = 2
         AND signed_at_unix_secs IS NOT NULL
         AND bundle_nonce        IS NOT NULL
         AND length(bundle_nonce) = 16)
    )
);

-- ── plan_bundle_artifacts ────────────────────────────────────────────────
-- Per-artifact rows. artifact_seq=0 is always plan.toml; subsequent rows
-- (1..) are operator-declared host-path artifacts. The composite PK
-- gives the kernel an O(1) lookup by (bundle, seq) without a secondary
-- index, and ON DELETE is moot here because `plan_bundles` rows are
-- never deleted (§10).
CREATE TABLE IF NOT EXISTS plan_bundle_artifacts (
    bundle_sha256        BLOB    NOT NULL
        REFERENCES plan_bundles(bundle_sha256),
    artifact_seq         INTEGER NOT NULL,
    artifact_name        TEXT    NOT NULL,
    artifact_sha256      BLOB    NOT NULL,
    artifact_bytes       BLOB    NOT NULL,
    artifact_bytes_len   INTEGER NOT NULL,
    PRIMARY KEY (bundle_sha256, artifact_seq),
    CHECK (length(artifact_sha256) = 32),
    CHECK (artifact_seq        >= 0),
    CHECK (artifact_bytes_len  >= 0)
);

-- ── plan_bundle_nonces_seen ──────────────────────────────────────────────
-- Replay-protection state (plan-bundle-sealing.md §3.5). One row per
-- consumed bundle_nonce. `outcome` distinguishes whether the nonce was
-- consumed by a successful admission (`Admitted`, with a non-NULL
-- initiative_id) or a terminal rejection (`TerminallyRejected`,
-- initiative_id is NULL).
--
-- Sweep schedule: rows older than (max_plan_bundle_age_secs +
-- max_clock_skew_secs + nonce_retention_grace_secs) are reaped by the
-- kernel's maintenance loop (§8.4). The freshness window in §3.5
-- guarantees a reaped row's nonce is no longer admissible (step 10a
-- rejects with FAIL_PLAN_BUNDLE_EXPIRED before step 10b queries this
-- table).
CREATE TABLE IF NOT EXISTS plan_bundle_nonces_seen (
    bundle_nonce             BLOB    NOT NULL PRIMARY KEY,
    bundle_sha256            BLOB    NOT NULL,
    signed_at_unix_secs      INTEGER NOT NULL,
    first_seen_at_unix_secs  INTEGER NOT NULL,
    outcome                  TEXT    NOT NULL
        CHECK (outcome IN ('Admitted', 'TerminallyRejected')),
    initiative_id            TEXT,
    CHECK (length(bundle_nonce)   = 16),
    CHECK (length(bundle_sha256) = 32),
    -- Admitted rows MUST carry an initiative_id; TerminallyRejected
    -- rows MUST carry NULL. Enforces the §8.1 step 12b contract at the
    -- DDL layer so a future code path that forgets the join-key cannot
    -- silently violate it.
    CHECK (
        (outcome = 'Admitted'           AND initiative_id IS NOT NULL)
        OR
        (outcome = 'TerminallyRejected' AND initiative_id IS NULL)
    )
);

-- Sweep-driver index. The §8.4 retention DELETE filters on
-- first_seen_at_unix_secs; without this index it'd be a full scan.
CREATE INDEX IF NOT EXISTS idx_plan_bundle_nonces_first_seen
    ON plan_bundle_nonces_seen(first_seen_at_unix_secs);

-- ── initiatives.plan_bundle_sha256 ───────────────────────────────────────
-- V2 admissions populate this column with the bundle's canonical hash,
-- which joins back to plan_bundles. V1 admissions kept plan_artifact_sha256
-- and leave this NULL.
ALTER TABLE initiatives
    ADD COLUMN plan_bundle_sha256 BLOB
        REFERENCES plan_bundles(bundle_sha256);

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (8, strftime('%s', 'now'));

COMMIT;
