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

-- ── sessions: V2 hierarchical orchestration columns ─────────────────────────
-- session_agent_type: NULL for V1 sessions, NOT NULL on every V2 row
-- (enforced at the application layer in create_session — column level
-- stays NULLable for V1 backward compatibility). The CHECK constraint
-- pins the universe of legal V2 values.
ALTER TABLE sessions
    ADD COLUMN session_agent_type TEXT
        CHECK (session_agent_type IS NULL
               OR session_agent_type IN ('Orchestrator', 'Executor', 'Reviewer'));

-- can_delegate: gate for ActivateSubTask. Defaults to 0 so V1 rows are
-- unaffected. The row-level CHECK enforces INV-DELEGATE-01 directly:
-- can_delegate=1 implies session_agent_type='Orchestrator'. The
-- bidirectional guarantee (Orchestrator ⇒ can_delegate=1) is enforced
-- at the application layer in create_session because a SQL CHECK
-- cannot reference a default-derivation rule.
ALTER TABLE sessions
    ADD COLUMN can_delegate INTEGER NOT NULL DEFAULT 0
        CHECK (can_delegate IN (0, 1)
               AND (can_delegate = 0 OR session_agent_type = 'Orchestrator'));

-- vsock_cid: context id for the planner microVM. NULL for V1 UDS
-- sessions and for V2 sessions before the VM is spawned (the kernel
-- writes it AFTER the hypervisor returns the assigned CID). Read on
-- hot-restart by bootstrap.rs to rebuild the in-memory CID allowlist
-- BEFORE opening the VSock listener.
ALTER TABLE sessions
    ADD COLUMN vsock_cid INTEGER;

-- Lookup: bootstrap.rs hot-restart query — rebuild the CID allowlist
-- in O(active V2 sessions). V1 sessions (vsock_cid IS NULL) are not
-- in this index thanks to the partial-index predicate.
CREATE INDEX IF NOT EXISTS idx_sessions_vsock_cid
    ON sessions (vsock_cid)
    WHERE vsock_cid IS NOT NULL AND revoked = 0;

-- ── Table 22: subtask_activations ───────────────────────────────────────────
-- Per-(initiative, sub-task) activation FSM. One row per activation
-- attempt — a retry inserts a NEW row, never updates the prior one.
-- Inserted by approve_plan → admit_in_tx in the same transaction
-- that inserts the corresponding `tasks` row (INV-STORE-02).
--
-- Columns:
--   activation_id       — UUID; PK. New uuid per (re)activation.
--   task_id             — FK to tasks.task_id. The (V2 Executor or
--                         Reviewer) sub-task this activation is for.
--   initiative_id       — denormalised FK for fast per-initiative
--                         queries on the recovery sweep.
--   activation_state    — PendingActivation | Active | Completed |
--                         Failed (CHECK constraint, drift-pinned in
--                         tests below).
--   session_id          — FK to sessions.session_id once a VM is
--                         spawned and the session row is bound. NULL
--                         while activation_state = 'PendingActivation'.
--   evaluation_sha      — for Reviewer activations: the Executor's
--                         CompleteTask head_sha captured at admission
--                         time. NULL for Executor activations and for
--                         Reviewer rows in PendingActivation (it is
--                         filled by the Kernel when the predecessor
--                         Executor's CompleteTask is admitted).
--   crash_retry_count   — incremented by the Kernel on OS-level VM
--                         death (SIGCHLD / non-zero exit). Ceiling:
--                         `max_crash_retries` from the signed plan.
--                         Per v2-deep-spec.md §Step 12.
--   review_reject_count — incremented by the Kernel when a Reviewer
--                         submits `approved: false` for this sub-task.
--                         Ceiling: `max_review_rejections` from the
--                         signed plan. Per v2-deep-spec.md §Step 12.
--   created_at          — Unix seconds, clock-injected at insert.
--   activated_at        — set when state transitions to Active.
--   terminated_at       — set when state transitions to terminal
--                         (Completed | Failed).
--
-- The dual retry counters are deliberately separate: a VM that
-- OOM-crashes shares NO counter with a sub-task whose code review
-- failed, because the two failure modes have different remediation
-- strategies (crash → just retry, review-fail → planner is
-- consistently producing wrong code → human escalation).
CREATE TABLE IF NOT EXISTS subtask_activations (
    activation_id        TEXT    NOT NULL PRIMARY KEY,
    task_id              TEXT    NOT NULL
        REFERENCES tasks(task_id),
    initiative_id        TEXT    NOT NULL
        REFERENCES initiatives(initiative_id),
    activation_state     TEXT    NOT NULL
        CHECK (activation_state IN ('PendingActivation', 'Active', 'Completed', 'Failed')),
    session_id           TEXT
        REFERENCES sessions(session_id),
    evaluation_sha       TEXT,
    crash_retry_count    INTEGER NOT NULL DEFAULT 0
        CHECK (crash_retry_count >= 0),
    review_reject_count  INTEGER NOT NULL DEFAULT 0
        CHECK (review_reject_count >= 0),
    created_at           INTEGER NOT NULL,
    activated_at         INTEGER,
    terminated_at        INTEGER,
    -- Cross-column invariants:
    --   * Active rows always have a session_id.
    --   * Terminal rows always have a terminated_at.
    --   * activated_at is set ⇔ state has reached Active or beyond.
    CHECK (
        (activation_state = 'PendingActivation' AND session_id IS NULL
         AND activated_at IS NULL AND terminated_at IS NULL)
        OR (activation_state = 'Active' AND session_id IS NOT NULL
            AND activated_at IS NOT NULL AND terminated_at IS NULL)
        OR (activation_state IN ('Completed', 'Failed')
            AND activated_at IS NOT NULL AND terminated_at IS NOT NULL)
    )
);

-- Lookup: "all activations for this task" — used by RetrySubTask to
-- find the most-recent terminal row, and by audit replay tools.
CREATE INDEX IF NOT EXISTS idx_subtask_activations_task_id
    ON subtask_activations (task_id, created_at DESC);

-- Lookup: "all V2 sub-tasks pending activation in this initiative" —
-- the Orchestrator prompt assembler (Layer 2 prompt-hiding) consults
-- this on every InferenceRequest to filter the visible activatable
-- list.
CREATE INDEX IF NOT EXISTS idx_subtask_activations_pending
    ON subtask_activations (initiative_id, activation_state)
    WHERE activation_state = 'PendingActivation';

-- Lookup: "every active V2 session" — used by recovery::reconcile_tasks
-- to find activations whose underlying VM died with the kernel and
-- need crash_retry_count incremented during boot.
CREATE INDEX IF NOT EXISTS idx_subtask_activations_active
    ON subtask_activations (initiative_id, activation_state)
    WHERE activation_state = 'Active';

-- Record this migration.
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (5, strftime('%s', 'now'));

COMMIT;
