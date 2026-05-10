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

-- ── Table: integration_merge_attempts ────────────────────────────────────
-- One row per IntegrationMerge intent that reaches Check 5d. Tracks
-- the candidate-merge-tree → pre-merge-verifier → main-advance
-- pipeline FSM and is swept at boot per integration-merge.md §11.10.4.
--
-- ⚠ Distinct from initiatives.git_apply_pending. The existing flag
--   gates the SQLite-intent → git-apply boundary for the eventual
--   main advance (§11.1); this table governs the strictly *earlier*
--   candidate-merge-tree → pre-merge-verifier boundary (§11.10).
--
--   * id                       — uuid; matches the IntegrationMerge
--                                  intent's request_id. PK.
--   * initiative_id            — FK to initiatives(initiative_id).
--   * orchestrator_session_id  — the Orchestrator session that
--                                  submitted the IntegrationMerge intent.
--   * requested_commit_sha     — the head sha the orchestrator wants
--                                  fast-forwarded onto main.
--   * candidate_merge_sha      — orphan commit that would become main
--                                  if all block_merge verifiers pass.
--                                  NULL until Check 5d.2 succeeds.
--   * state                    — IntegrationMergeAttemptState
--                                  (CHECK-pinned).
--   * discard_reason           — IntegrationMergeAttemptDiscardReason
--                                  (CHECK-pinned). NULL when state ∈
--                                  { AwaitingPreMergeVerifiers,
--                                     PreMergeVerifiersPassed,
--                                     CompletedAdvanceApplied }.
--   * created_at               — Unix epoch ms; set on insert.
--   * finalized_at             — Unix epoch ms; set on transition to
--                                  any terminal state. NULL ⟺ state
--                                  is non-terminal (the recovery
--                                  sweep at §11.10.4 keys off this).
CREATE TABLE IF NOT EXISTS integration_merge_attempts (
    id                       TEXT    NOT NULL PRIMARY KEY,
    initiative_id            TEXT    NOT NULL
        REFERENCES initiatives(initiative_id),
    orchestrator_session_id  TEXT    NOT NULL,
    requested_commit_sha     TEXT    NOT NULL,
    candidate_merge_sha      TEXT,
    state                    TEXT    NOT NULL
        CHECK (state IN ('AwaitingPreMergeVerifiers', 'PreMergeVerifiersPassed', 'BlockedByPreMergeVerifier', 'CompletedAdvanceApplied', 'DiscardedCandidateOnly', 'DiscardedCrashRecovery')),
    discard_reason           TEXT
        CHECK (discard_reason IS NULL
               OR discard_reason IN ('verifier_blocked', 'candidate_computation_failed', 'crash_recovery', 'merge_aborted_by_operator')),
    created_at               INTEGER NOT NULL,
    finalized_at             INTEGER,
    -- Cross-column invariants:
    --   * Non-terminal rows always have NULL finalized_at and NULL
    --     discard_reason.
    --   * BlockedByPreMergeVerifier / DiscardedCandidateOnly /
    --     DiscardedCrashRecovery rows always have NON-NULL
    --     discard_reason and finalized_at.
    --   * CompletedAdvanceApplied rows always have NULL discard_reason
    --     and NON-NULL finalized_at + candidate_merge_sha.
    --   * PreMergeVerifiersPassed rows have a candidate_merge_sha set
    --     (Check 5d.2 succeeded by definition of the transition).
    CHECK (
        (state = 'AwaitingPreMergeVerifiers'
            AND discard_reason IS NULL
            AND finalized_at IS NULL)
        OR (state = 'PreMergeVerifiersPassed'
            AND discard_reason IS NULL
            AND finalized_at IS NULL
            AND candidate_merge_sha IS NOT NULL)
        OR (state = 'CompletedAdvanceApplied'
            AND discard_reason IS NULL
            AND finalized_at IS NOT NULL
            AND candidate_merge_sha IS NOT NULL)
        OR (state IN ('BlockedByPreMergeVerifier',
                      'DiscardedCandidateOnly',
                      'DiscardedCrashRecovery')
            AND discard_reason IS NOT NULL
            AND finalized_at IS NOT NULL)
    )
);

-- Lookup: "every pre-merge attempt for this initiative" — joins
-- through audit replay and operator forensics. Keeps the per-
-- initiative scan O(rows-for-this-initiative) without a full
-- table scan.
CREATE INDEX IF NOT EXISTS idx_imerge_attempts_initiative
    ON integration_merge_attempts (initiative_id);

-- Lookup: "every non-terminal attempt for this initiative" — the
-- boot-time recovery sweep at integration-merge.md §11.10.4 reads
-- this index to fold mid-flight verifier runs whose VMs were killed
-- with the kernel. Partial index keeps the sweep O(non-terminal
-- rows) rather than O(all rows ever).
CREATE INDEX IF NOT EXISTS idx_imerge_attempts_open
    ON integration_merge_attempts (initiative_id)
    WHERE state IN ('AwaitingPreMergeVerifiers',
                    'PreMergeVerifiersPassed');

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (11, strftime('%s', 'now'));

COMMIT;
