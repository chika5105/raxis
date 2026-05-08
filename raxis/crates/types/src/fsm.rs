// raxis-types::fsm — Task and Initiative finite-state machine types.
//
// Normative reference:
//   - kernel-core.md §2.4 "Initiative FSM" and "Task FSM" tables.
//   - kernel-store.md §2.5.1 Table 2 (`initiatives.status`) and
//     Table 5 (`tasks.state`).
//
// The CHECK constraints in the DDL are the canonical allowed values; this
// Rust enum must be kept in bijection with those SQL strings.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// InitiativeState
// DDL: CHECK (status IN ('Draft','ApprovedPlan','Executing','Blocked',
//                        'Completed','Failed','Aborted'))
// kernel-store.md §2.5.1 Table 2
// ---------------------------------------------------------------------------

/// The lifecycle state of an initiative.
///
/// Transitions (kernel-core.md §2.4 initiative FSM):
///   Draft → ApprovedPlan (approve_plan)
///   Draft → Aborted (reject_plan)
///   ApprovedPlan → Executing (first task Running)
///   Executing → Blocked (evaluate_terminal_criteria under partial-failure policies)
///   Executing → Completed (evaluate_terminal_criteria: all success criteria met)
///   Executing → Failed (evaluate_terminal_criteria: failure criterion met)
///   Executing / Blocked → Aborted (abort_initiative)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum InitiativeState {
    Draft,
    ApprovedPlan,
    Executing,
    Blocked,
    Completed,
    Failed,
    Aborted,
}

impl InitiativeState {
    /// All variants in v1 — the canonical set referenced by the
    /// `initiatives.state` SQL CHECK constraint
    /// (kernel-store.md §2.5.1 Table 2).
    ///
    /// **Spec drift contract.** The array length is part of the v1
    /// schema contract; bumping it (i.e. adding a new variant) MUST be
    /// accompanied by a schema migration that ALTERs the CHECK
    /// constraint on already-installed databases. The
    /// `migration::tests::migration_1_ddl_fingerprint_is_pinned` hash
    /// guard catches any silent drift between this array and the
    /// rendered Migration 1 DDL.
    pub const ALL: [Self; 7] = [
        Self::Draft,
        Self::ApprovedPlan,
        Self::Executing,
        Self::Blocked,
        Self::Completed,
        Self::Failed,
        Self::Aborted,
    ];

    /// Returns true for terminal states (no further transitions possible).
    /// kernel-core.md: "terminal state" = Completed | Failed | Aborted.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Aborted)
    }

    /// Canonical SQL string used in CHECK constraints and at-rest storage.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Draft => "Draft",
            Self::ApprovedPlan => "ApprovedPlan",
            Self::Executing => "Executing",
            Self::Blocked => "Blocked",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Aborted => "Aborted",
        }
    }

    /// Parse from the SQL at-rest string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Draft" => Some(Self::Draft),
            "ApprovedPlan" => Some(Self::ApprovedPlan),
            "Executing" => Some(Self::Executing),
            "Blocked" => Some(Self::Blocked),
            "Completed" => Some(Self::Completed),
            "Failed" => Some(Self::Failed),
            "Aborted" => Some(Self::Aborted),
            _ => None,
        }
    }
}

impl fmt::Display for InitiativeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// TaskState
// DDL: CHECK (state IN ('Admitted','Running','GatesPending','Completed',
//                       'Failed','Aborted','Cancelled','BlockedRecoveryPending'))
// kernel-store.md §2.5.1 Table 5
// ---------------------------------------------------------------------------

/// The lifecycle state of a task within an initiative.
///
/// Transitions (kernel-core.md §2.4 task FSM):
///   Admitted → Running (first intent accepted for this task)
///   Running → GatesPending (gate evaluation in progress)
///   GatesPending → Running (all gates cleared, next intent accepted)
///   Running / GatesPending → Failed (ReportFailure intent)
///   Running / GatesPending → Aborted (abort_task / abort_initiative / WitnessTimeout)
///   Running / GatesPending → BlockedRecoveryPending (kernel crash recovery)
///   BlockedRecoveryPending → Running (resume_task operator command)
///   Running → Completed (CompleteTask intent accepted with path+gate closure)
///   Admitted / Running / GatesPending → Cancelled (bulk cancel from abort_initiative)
///   Failed → Admitted (retry_task operator command)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TaskState {
    Admitted,
    Running,
    GatesPending,
    Completed,
    Failed,
    Aborted,
    Cancelled,
    BlockedRecoveryPending,
}

impl TaskState {
    /// All variants in v1 — the canonical set referenced by the
    /// `tasks.state` SQL CHECK constraint
    /// (kernel-store.md §2.5.1 Table 5).
    ///
    /// Order matches `tasks.state` CHECK in v1 DDL so the rendered
    /// Migration 1 SQL is byte-stable across builds (the
    /// `migration::tests::migration_1_ddl_fingerprint_is_pinned` hash
    /// guard relies on this ordering).
    ///
    /// **Spec drift contract.** Adding a new variant requires both a
    /// length bump here AND a new migration that ALTERs the CHECK
    /// constraint on already-installed databases.
    pub const ALL: [Self; 8] = [
        Self::Admitted,
        Self::GatesPending,
        Self::Running,
        Self::Completed,
        Self::Failed,
        Self::Aborted,
        Self::Cancelled,
        Self::BlockedRecoveryPending,
    ];

    /// Terminal task states from which no transition is possible (except
    /// Failed → Admitted via retry_task).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted | Self::Cancelled)
    }

    /// Returns true when the task is in a non-terminal, non-runnable state —
    /// i.e. the planner cannot submit intents right now but the task is not
    /// terminal. Used for FAIL_TASK_NOT_RUNNING discrimination.
    pub fn is_blocked(self) -> bool {
        matches!(self, Self::BlockedRecoveryPending | Self::GatesPending)
    }

    /// Canonical SQL string used in CHECK constraints and at-rest storage.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Admitted => "Admitted",
            Self::Running => "Running",
            Self::GatesPending => "GatesPending",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Aborted => "Aborted",
            Self::Cancelled => "Cancelled",
            Self::BlockedRecoveryPending => "BlockedRecoveryPending",
        }
    }

    /// Parse from the SQL at-rest string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Admitted" => Some(Self::Admitted),
            "Running" => Some(Self::Running),
            "GatesPending" => Some(Self::GatesPending),
            "Completed" => Some(Self::Completed),
            "Failed" => Some(Self::Failed),
            "Aborted" => Some(Self::Aborted),
            "Cancelled" => Some(Self::Cancelled),
            "BlockedRecoveryPending" => Some(Self::BlockedRecoveryPending),
            _ => None,
        }
    }
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// BlockReason — why a task entered Aborted or BlockedRecoveryPending.
// kernel-core.md §2.4 FSM and §4.6 lifecycle handlers.
// ---------------------------------------------------------------------------

/// The reason a task was aborted or blocked for recovery.
/// Stored in `tasks.block_reason TEXT` (nullable; NULL when state is not
/// Aborted/BlockedRecoveryPending).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "PascalCase")]
pub enum BlockReason {
    /// Operator issued `task abort` or `initiative abort`.
    OperatorAbort,
    /// Verifier subprocess did not submit a witness before its token TTL expired.
    WitnessTimeout,
    /// Kernel crashed with this task in-flight; task pending operator `task resume`.
    KernelCrash,
    /// Budget exhausted before task could complete (v1: enforced at admit time,
    /// so this fires if the lane budget drops to zero between admission and
    /// CompleteTask acceptance).
    BudgetExhausted,
}

impl BlockReason {
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            Self::OperatorAbort => "OperatorAbort",
            Self::WitnessTimeout => "WitnessTimeout",
            Self::KernelCrash => "KernelCrash",
            Self::BudgetExhausted => "BudgetExhausted",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "OperatorAbort" => Some(Self::OperatorAbort),
            "WitnessTimeout" => Some(Self::WitnessTimeout),
            "KernelCrash" => Some(Self::KernelCrash),
            "BudgetExhausted" => Some(Self::BudgetExhausted),
            _ => None,
        }
    }
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// SessionAgentType — V2 hierarchical orchestration agent kind.
// v2-deep-spec.md §1.2 (Step 6) and INV-DELEGATE-01 (Step 18).
// DDL: sessions.session_agent_type TEXT NULL (V1 rows: NULL ⇒ V1-flat planner;
//      V2 rows: 'Orchestrator' | 'Executor' | 'Reviewer').
//
// Why this enum is in fsm.rs alongside TaskState/InitiativeState rather than
// in a dedicated module: it is a pure data discriminant whose lifecycle is
// tied to the session row's lifetime (set at create_session, read at every
// intent dispatch, never updated). Co-locating it with the other tightly-
// scoped session/task enums keeps the type module surface small.
// ---------------------------------------------------------------------------

/// V2 agent type for a planner session.
///
/// V2 introduces hierarchical orchestration: a single Orchestrator decomposes
/// the plan into sub-tasks, each executed by an Executor; some sub-tasks are
/// reviewed by a Reviewer. The agent type drives:
///
///   1. The static dispatch matrix (v2-deep-spec.md §Step 20) — which intent
///      kinds this session may submit.
///   2. The Kernel Prompt Assembler — selects the prompt template family.
///   3. Reverse-DAG queries that identify Reviewer successor tasks.
///
/// The companion field is `sessions.can_delegate INTEGER NOT NULL DEFAULT 0`.
/// INV-DELEGATE-01: `can_delegate = 1` if and only if `session_agent_type =
/// Orchestrator`. The kernel enforces this at create_session time, AND at
/// approve_plan check #2 ("exactly one Orchestrator per plan"). Handlers
/// MUST read `can_delegate` from the session row directly; they MUST NOT
/// re-derive it from `session_agent_type` at runtime (so that this enum can
/// gain a new variant in a future spec without silently flipping
/// `can_delegate` for old rows).
///
/// V1 backward compatibility: legacy V1 sessions store NULL in this column.
/// Kernel handlers that did not exist in V1 (e.g. `handlers/activate_subtask.rs`)
/// reject NULL with a typed error; legacy V1 handlers do not consult this
/// field at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SessionAgentType {
    /// Schedules sub-tasks declared in the operator-signed plan.
    /// Submits `ActivateSubTask`, `RetrySubTask`, `CancelSubTask`,
    /// `IntegrationMerge`, `CompleteTask`. Owns `cross_cutting_artifacts`
    /// during integration-merge (v2-deep-spec.md §Step 11).
    Orchestrator,

    /// Executes a single sub-task. Submits `SingleCommit`, `CompleteTask`,
    /// `ReportFailure`. Cannot delegate.
    Executor,

    /// Evaluates an Executor's `evaluation_sha` (post-CompleteTask).
    /// Submits `SubmitReview { approved, critique }`. Cannot delegate.
    /// Pure-static reviewer image — no `git` binary in the VM
    /// (planner-harness.md §4.5; INV-PLANNER-HARNESS-02).
    Reviewer,
}

impl SessionAgentType {
    /// All variants in V2 — referenced by the
    /// `sessions.session_agent_type` SQL CHECK constraint
    /// (v2-deep-spec.md §Step 6, store migration 5).
    ///
    /// **Spec drift contract.** Adding a new variant requires (a) bumping
    /// this array, (b) a new migration that ALTERs the CHECK constraint
    /// on already-installed databases, AND (c) refreshing the static
    /// dispatch matrix in `raxis-kernel` (v2-deep-spec.md §Step 20).
    pub const ALL: [Self; 3] = [
        Self::Orchestrator,
        Self::Executor,
        Self::Reviewer,
    ];

    /// Canonical SQL string used in CHECK constraints and at-rest storage.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Orchestrator => "Orchestrator",
            Self::Executor     => "Executor",
            Self::Reviewer     => "Reviewer",
        }
    }

    /// Parse from the SQL at-rest string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Orchestrator" => Some(Self::Orchestrator),
            "Executor"     => Some(Self::Executor),
            "Reviewer"     => Some(Self::Reviewer),
            _ => None,
        }
    }

    /// INV-DELEGATE-01: `can_delegate` is `true` iff
    /// `session_agent_type = Orchestrator`.
    ///
    /// **Important.** Handlers MUST read the persisted `can_delegate`
    /// column directly rather than calling this helper at the
    /// authorization point — see the v2-deep-spec.md §Step 18 reasoning
    /// (handler robustness across future enum changes). This helper is
    /// the single source of truth used by `create_session` to set the
    /// column, by `approve_plan` to validate plan check #2, and by tests.
    pub fn implies_can_delegate(self) -> bool {
        matches!(self, Self::Orchestrator)
    }
}

// ---------------------------------------------------------------------------
// CloneStrategy — V2 §Step 27 typed clone strategy.
// v2-deep-spec.md §Step 27 ("Sparse Clone Strategy — Typed Strategies with
// Orchestrator Merge Constraint").
// DDL: tasks.clone_strategy TEXT NOT NULL DEFAULT 'blobless' CHECK
//      (clone_strategy IN ('full', 'blobless', 'sparse')).
//
// Why this enum lives in fsm.rs alongside SessionAgentType: it is a pure
// data discriminant carried per-task, set at approve_plan from the plan
// TOML, read at provisioning time. Same lifecycle shape as
// SessionAgentType — one canonical SQL string, one enum, no runtime
// transitions.
// ---------------------------------------------------------------------------

/// V2 typed clone strategy for a planner-session worktree.
///
/// **Decision (v2-deep-spec.md §Step 27).** Three strategies:
///
/// | Strategy   | Mechanism (gix-equivalent)                            | Use case                                        |
/// |------------|--------------------------------------------------------|-------------------------------------------------|
/// | `full`     | Full object DB                                         | Small repos; any agent type                     |
/// | `blobless` | Tree+commit objects, blobs lazy-loaded                 | Large repos with big binaries; any agent type   |
/// | `sparse`   | Full objects + sparse-checkout from `path_allowlist`   | Executors/Reviewers with narrow allowlists      |
///
/// **The Sparse-Orchestrator exclusion (Step 27, approve_plan check #6).**
/// `sparse` is rejected for `SessionAgentType::Orchestrator` at admission
/// time. Git's 3-way merge machinery walks the trees of merge-base, current
/// HEAD, and incoming branch simultaneously; if the Orchestrator's sparse
/// checkout has excluded a path that an incoming Executor branch touches,
/// the traversal either fails or silently corrupts the index. `full` and
/// `blobless` are both safe for merge work because both download complete
/// tree objects (only blob content is lazy in `blobless`). The constraint
/// is checked by `kernel/src/initiatives/lifecycle.rs::
/// validate_sparse_orchestrator_exclusion` at approve_plan time.
///
/// **Why `blobless` is the V2 default.** It is uniformly safer than
/// `sparse` (works for every agent type including Orchestrators) and
/// strictly cheaper than `full` for the common case of repos with binary
/// blobs (build artifacts, vendored deps, fixtures). Operators who know
/// their repo is small enough to clone in full opt in to `full`; operators
/// with a known narrow path scope opt in to `sparse`.
///
/// **Auto-configuration of sparse.** When `sparse` is selected, the kernel
/// auto-derives the sparse-checkout path set from the task's
/// `path_allowlist` (sealed in the signed plan). The operator does not
/// duplicate the allowlist between two TOML keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloneStrategy {
    /// `git clone` with no filters. Safe for every agent type.
    Full,
    /// `git clone --filter=blob:none` equivalent (gix lazy-blob).
    /// Safe for every agent type — tree objects are downloaded in full.
    /// V2 default.
    Blobless,
    /// Sparse checkout: full object DB, but the working tree is filtered
    /// to the union of the task's `path_allowlist`. Forbidden for
    /// `SessionAgentType::Orchestrator` (Step 27 check #6).
    Sparse,
}

impl CloneStrategy {
    /// All variants — referenced by the `tasks.clone_strategy` SQL
    /// CHECK constraint and the parser tests.
    pub const ALL: [Self; 3] = [Self::Full, Self::Blobless, Self::Sparse];

    /// Canonical at-rest string. Lower-case to match the TOML
    /// surface (`clone_strategy = "blobless"`).
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Full     => "full",
            Self::Blobless => "blobless",
            Self::Sparse   => "sparse",
        }
    }

    /// Parse the at-rest / TOML string. Returns `None` for any unknown
    /// spelling — case-sensitive.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "full"     => Some(Self::Full),
            "blobless" => Some(Self::Blobless),
            "sparse"   => Some(Self::Sparse),
            _ => None,
        }
    }
}

impl fmt::Display for CloneStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

impl fmt::Display for SessionAgentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// SubtaskActivationState — V2 sub-task pre-activation lifecycle.
// v2-deep-spec.md §1.2 (Step 5).
// DDL: subtask_activations.activation_state TEXT NOT NULL CHECK (...).
//
// Why a separate FSM from `tasks.state`:
//   - `tasks.state` is the V1 operational FSM (Admitted → Running → ...).
//   - V2 sub-tasks need a pre-activation state ("declared in plan, no VM yet")
//     that does not pollute the V1 FSM. Adding a `PendingActivation` variant
//     to TaskState would force every V1 state-machine handler to be aware of
//     the new state and risk recovery::reconcile_tasks sweeping it into
//     `BlockedRecoveryPending` (no VM has been provisioned yet, so there is
//     nothing to recover).
// ---------------------------------------------------------------------------

/// Sub-task activation lifecycle. Only Executor and Reviewer tasks have a
/// row in `subtask_activations`; the Orchestrator is activated by the Kernel
/// at initiative start, not by another agent (no row).
///
/// Transitions:
///   `PendingActivation` → `Active` (Orchestrator submits `ActivateSubTask`,
///                                    Kernel admits & spawns VM)
///   `Active`            → `Completed` (Executor: CompleteTask accepted with
///                                       valid `head_sha`; Reviewer:
///                                       SubmitReview accepted)
///   `Active`            → `Failed`    (VM crash, Reviewer rejected, or
///                                       budget/retry ceiling hit)
///
/// `Completed | Failed` are terminal w.r.t. this FSM (the Orchestrator may
/// still issue `RetrySubTask` which inserts a NEW `subtask_activations` row,
/// not a transition on the old one — each retry is a fresh activation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SubtaskActivationState {
    /// Declared in the signed plan; no VM provisioned yet. Inserted by
    /// `approve_plan` alongside the `tasks` row in the same transaction
    /// (INV-STORE-02 atomicity).
    PendingActivation,
    /// Orchestrator submitted `ActivateSubTask`, Kernel spawned the VM,
    /// session is bound and the planner is running.
    Active,
    /// Sub-task reached a successful terminal: Executor's CompleteTask
    /// accepted, or Reviewer's SubmitReview accepted (both `approved=true`
    /// and `approved=false` are kernel-acceptances of the review verdict —
    /// the rejection signal lives in `tasks.last_critique`, not here).
    Completed,
    /// Sub-task failed terminally for THIS activation. The Orchestrator
    /// may submit `RetrySubTask` to insert a fresh `PendingActivation` row
    /// subject to the dual retry counters in v2-deep-spec.md §Step 12.
    Failed,
}

impl SubtaskActivationState {
    /// All variants — referenced by the
    /// `subtask_activations.activation_state` SQL CHECK constraint
    /// (v2-deep-spec.md §Step 5, store migration 5).
    pub const ALL: [Self; 4] = [
        Self::PendingActivation,
        Self::Active,
        Self::Completed,
        Self::Failed,
    ];

    /// Canonical SQL string used in CHECK constraints and at-rest storage.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::PendingActivation => "PendingActivation",
            Self::Active            => "Active",
            Self::Completed         => "Completed",
            Self::Failed            => "Failed",
        }
    }

    /// Parse from the SQL at-rest string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "PendingActivation" => Some(Self::PendingActivation),
            "Active"            => Some(Self::Active),
            "Completed"         => Some(Self::Completed),
            "Failed"            => Some(Self::Failed),
            _ => None,
        }
    }

    /// True for terminal activation states. Note: `Failed` is terminal w.r.t.
    /// this FSM — a retry creates a new `subtask_activations` row.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

impl fmt::Display for SubtaskActivationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// IntegrationMergeAttemptState — V2 pre-merge verifier attempt lifecycle.
// integration-merge.md §11.10.1; verifier-processes.md §16.
// DDL: integration_merge_attempts.state TEXT NOT NULL CHECK (...).
//
// Why a separate FSM from `initiatives.git_apply_pending`:
//   - `git_apply_pending` is a single-bit gate at the
//     SQLite-intent → git-apply boundary for the *eventual* main
//     advance (integration-merge.md §11.1).
//   - This enum governs the strictly *earlier* candidate-merge-tree
//     → pre-merge-verifier boundary (integration-merge.md §11.10).
//     It needs richer states (block-merge vs. warn-only verdict,
//     candidate-only failure vs. crash-recovery discard) than a
//     single bit can express.
// ---------------------------------------------------------------------------

/// Pre-merge verifier attempt lifecycle. One row in
/// `integration_merge_attempts` per `IntegrationMerge` intent that
/// reaches Check 5d.
///
/// Transitions (`integration-merge.md §4 Check 5d` and `§11.10`):
///   `AwaitingPreMergeVerifiers` → `PreMergeVerifiersPassed`
///                                  (all `block_merge` verifiers passed)
///   `AwaitingPreMergeVerifiers` → `BlockedByPreMergeVerifier`
///                                  (any `block_merge` verifier failed)
///   `AwaitingPreMergeVerifiers` → `DiscardedCandidateOnly`
///                                  (Check 5d.2 candidate-merge-tree
///                                   computation failed; verifiers
///                                   never spawned)
///   `AwaitingPreMergeVerifiers` → `DiscardedCrashRecovery`
///                                  (kernel restart sweep — VM
///                                   verdicts unrecoverable)
///   `PreMergeVerifiersPassed`   → `CompletedAdvanceApplied`
///                                  (§11.1 phase 3 finalize ran)
///   `PreMergeVerifiersPassed`   → `DiscardedCrashRecovery`
///                                  (kernel restart sweep before
///                                   §11.1 phase 3 ran — the
///                                   recovery flow rebuilds the
///                                   candidate per §11.10.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IntegrationMergeAttemptState {
    /// Inserted at Check 5d.1 in the same `BEGIN IMMEDIATE`
    /// transaction that admits the `IntegrationMerge` intent.
    /// Pre-merge verifier VMs are spawned right after.
    AwaitingPreMergeVerifiers,
    /// All `block_merge` verifiers passed. The candidate is now an
    /// input to the §11.1 phase 1 main-advance pipeline. Warn-only
    /// failures DO NOT gate this transition.
    PreMergeVerifiersPassed,
    /// At least one `block_merge` verifier failed. Terminal — the
    /// candidate is discarded, no main advance happens, the
    /// `IntegrationMerge` intent returns failure to the orchestrator.
    BlockedByPreMergeVerifier,
    /// Phase 3 (`§11.1`) finalize ran: `initiatives.current_sha`
    /// updated and `git_apply_pending = 0`. Terminal success.
    CompletedAdvanceApplied,
    /// Check 5d.2 candidate-merge-tree computation failed (e.g.
    /// merge conflict). Terminal — the candidate was never spawned;
    /// the `IntegrationMerge` intent returns failure.
    DiscardedCandidateOnly,
    /// The kernel was killed mid-flight. The boot-time recovery
    /// sweep (§11.10.4) folded a non-terminal row to this terminal
    /// state because the candidate worktree was missing or the
    /// verifier-VM cgroups had already been killed.
    DiscardedCrashRecovery,
}

impl IntegrationMergeAttemptState {
    /// All variants — referenced by the
    /// `integration_merge_attempts.state` SQL CHECK constraint
    /// (`integration-merge.md §11.10.1`, store migration 11).
    pub const ALL: [Self; 6] = [
        Self::AwaitingPreMergeVerifiers,
        Self::PreMergeVerifiersPassed,
        Self::BlockedByPreMergeVerifier,
        Self::CompletedAdvanceApplied,
        Self::DiscardedCandidateOnly,
        Self::DiscardedCrashRecovery,
    ];

    /// Canonical SQL string used in CHECK constraints and at-rest
    /// storage. The recovery sweep at boot (§11.10.4) compares
    /// `state` against the literal strings emitted here using
    /// `IN ('AwaitingPreMergeVerifiers','PreMergeVerifiersPassed')`,
    /// so any rename here MUST be backed by a migration that
    /// rewrites the CHECK constraint and the recovery query.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::AwaitingPreMergeVerifiers => "AwaitingPreMergeVerifiers",
            Self::PreMergeVerifiersPassed   => "PreMergeVerifiersPassed",
            Self::BlockedByPreMergeVerifier => "BlockedByPreMergeVerifier",
            Self::CompletedAdvanceApplied   => "CompletedAdvanceApplied",
            Self::DiscardedCandidateOnly    => "DiscardedCandidateOnly",
            Self::DiscardedCrashRecovery    => "DiscardedCrashRecovery",
        }
    }

    /// Parse from the SQL at-rest string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "AwaitingPreMergeVerifiers" => Some(Self::AwaitingPreMergeVerifiers),
            "PreMergeVerifiersPassed"   => Some(Self::PreMergeVerifiersPassed),
            "BlockedByPreMergeVerifier" => Some(Self::BlockedByPreMergeVerifier),
            "CompletedAdvanceApplied"   => Some(Self::CompletedAdvanceApplied),
            "DiscardedCandidateOnly"    => Some(Self::DiscardedCandidateOnly),
            "DiscardedCrashRecovery"    => Some(Self::DiscardedCrashRecovery),
            _ => None,
        }
    }

    /// True for states whose `finalized_at` column MUST be set
    /// (i.e. no further FSM transition is legal). Inverse of the
    /// recovery sweep's `IN (...)` predicate at §11.10.4.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::BlockedByPreMergeVerifier
                | Self::CompletedAdvanceApplied
                | Self::DiscardedCandidateOnly
                | Self::DiscardedCrashRecovery
        )
    }
}

impl fmt::Display for IntegrationMergeAttemptState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// IntegrationMergeAttemptDiscardReason — populates `discard_reason`
// on terminal-discard transitions of `IntegrationMergeAttemptState`.
// integration-merge.md §11.10.3.
// DDL: integration_merge_attempts.discard_reason TEXT (NULLABLE);
//      NULL ⟺ state ∈ { AwaitingPreMergeVerifiers,
//                        PreMergeVerifiersPassed,
//                        CompletedAdvanceApplied }.
// ---------------------------------------------------------------------------

/// Why a candidate-merge-tree was discarded. Persisted only on
/// transitions to `BlockedByPreMergeVerifier`, `DiscardedCandidateOnly`,
/// or `DiscardedCrashRecovery`. The fourth value `MergeAbortedByOperator`
/// is reserved for a later operator-driven abort path
/// (`integration-merge.md §11.10.3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationMergeAttemptDiscardReason {
    /// At least one `block_merge` pre-merge verifier failed
    /// (`integration-merge.md §11.10` Check 5d.4).
    VerifierBlocked,
    /// Check 5d.2 candidate-merge-tree computation failed
    /// (e.g. textual merge conflict, three-way ancestor missing).
    CandidateComputationFailed,
    /// Kernel restart sweep folded a non-terminal row to terminal
    /// because the candidate worktree was missing or the verifier
    /// VMs had already been killed (`integration-merge.md §11.10.4`).
    CrashRecovery,
    /// Operator explicitly aborted an in-flight merge attempt
    /// (reserved — not yet wired in V2).
    MergeAbortedByOperator,
}

impl IntegrationMergeAttemptDiscardReason {
    /// All variants — referenced by the
    /// `integration_merge_attempts.discard_reason` SQL CHECK
    /// constraint (store migration 11).
    pub const ALL: [Self; 4] = [
        Self::VerifierBlocked,
        Self::CandidateComputationFailed,
        Self::CrashRecovery,
        Self::MergeAbortedByOperator,
    ];

    /// Canonical SQL string used in CHECK constraints and at-rest
    /// storage. Matches the `DiscardReason` value list at
    /// `integration-merge.md §11.10.3`.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::VerifierBlocked            => "verifier_blocked",
            Self::CandidateComputationFailed => "candidate_computation_failed",
            Self::CrashRecovery              => "crash_recovery",
            Self::MergeAbortedByOperator     => "merge_aborted_by_operator",
        }
    }

    /// Parse from the SQL at-rest string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "verifier_blocked"            => Some(Self::VerifierBlocked),
            "candidate_computation_failed" => Some(Self::CandidateComputationFailed),
            "crash_recovery"              => Some(Self::CrashRecovery),
            "merge_aborted_by_operator"   => Some(Self::MergeAbortedByOperator),
            _ => None,
        }
    }

    /// The terminal `IntegrationMergeAttemptState` this reason
    /// implies. Used by `discard_candidate_merge_tree`
    /// (`integration-merge.md §11.10.3`) to compute the FSM target
    /// from the reason without a separate parameter.
    pub fn terminal_state(self) -> IntegrationMergeAttemptState {
        match self {
            Self::VerifierBlocked => {
                IntegrationMergeAttemptState::BlockedByPreMergeVerifier
            }
            Self::CandidateComputationFailed => {
                IntegrationMergeAttemptState::DiscardedCandidateOnly
            }
            Self::CrashRecovery | Self::MergeAbortedByOperator => {
                IntegrationMergeAttemptState::DiscardedCrashRecovery
            }
        }
    }
}

impl fmt::Display for IntegrationMergeAttemptDiscardReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// TerminalCriteria — the initiative terminal policy in force.
// kernel-core.md §2.4 "evaluate_terminal_criteria" and §4.5.
// DDL: initiatives.terminal_criteria TEXT NOT NULL.
// ---------------------------------------------------------------------------

/// The criterion by which the kernel decides when an initiative becomes terminal.
/// Set at plan-load time from the signed plan TOML `terminal_criteria` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TerminalCriteria {
    /// Initiative succeeds when every task reaches Completed.
    /// Fails when any task reaches Failed (strict).
    AllTasksSucceeded,
    /// Initiative succeeds when every task reaches a terminal state
    /// (Completed, Failed, Aborted, or Cancelled).
    AllTasksTerminal,
    /// Initiative succeeds when at least `n` tasks reach Completed.
    /// The count `n` is stored alongside the enum in the DDL as a separate
    /// column (`min_success_count`) — this variant is the discriminant only.
    MinSuccessCount,
}

impl TerminalCriteria {
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::AllTasksSucceeded => "AllTasksSucceeded",
            Self::AllTasksTerminal => "AllTasksTerminal",
            Self::MinSuccessCount => "MinSuccessCount",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "AllTasksSucceeded" => Some(Self::AllTasksSucceeded),
            "AllTasksTerminal" => Some(Self::AllTasksTerminal),
            "MinSuccessCount" => Some(Self::MinSuccessCount),
            _ => None,
        }
    }
}

impl fmt::Display for TerminalCriteria {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// ReviewVerdict — the per-Reviewer outcome on a SubmitReview.
// v2-deep-spec.md §Step 25 "Parallel Reviewers and the Logical AND Verdict".
// DDL: tasks.review_verdict TEXT (Migration 7).
// ---------------------------------------------------------------------------
//
// **Why on `tasks` rather than `subtask_activations`.** The aggregation
// pass (Step 25) runs at the moment the LAST sibling Reviewer submits;
// it queries the executor's successors in `task_dag_edges` and counts
// per-task verdicts. Putting the column on `tasks` lets the aggregation
// query be a single join — `task_dag_edges → tasks.review_verdict` —
// without traversing the activation history (which may have multiple
// rows per task across retries). The PER-ACTIVATION verdict lives on
// `subtask_activations` as `activation_state` (Completed = the kernel
// accepted the verdict, regardless of approve/reject — see the doc on
// `SubtaskActivationState::Completed`); `tasks.review_verdict` is the
// LATEST verdict, mirroring the LATEST critique on `tasks.last_critique`.
//
// Aggregation contract: a Reviewer task whose `review_verdict` is NULL
// has not yet submitted; one whose verdict is `Approved` passed; one
// whose verdict is `Rejected` failed. The Logical-AND verdict over all
// Reviewer siblings is "all Approved (and none NULL)" → AllPassed,
// "any Rejected (and none NULL)" → AtLeastOneRejected, otherwise →
// Pending.

/// Per-Reviewer outcome on a `IntentKind::SubmitReview` accept.
///
/// Persisted on `tasks.review_verdict` as TEXT so the aggregation
/// query (Step 25) can join `task_dag_edges → tasks` in one shot. NULL
/// means "not yet submitted"; the enum represents the two terminal
/// per-Reviewer outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ReviewVerdict {
    /// Reviewer submitted `SubmitReview { approved: true, .. }`. The
    /// Reviewer's task transitioned to `Completed` and the Executor's
    /// `last_critique` was untouched by this Reviewer.
    Approved,
    /// Reviewer submitted `SubmitReview { approved: false, critique }`.
    /// The Reviewer's task transitioned to `Completed` and the
    /// Executor's `last_critique` was appended with this Reviewer's
    /// formatted critique.
    Rejected,
}

impl ReviewVerdict {
    /// All variants — referenced by the SQL CHECK constraint on
    /// `tasks.review_verdict`.
    pub const ALL: [Self; 2] = [Self::Approved, Self::Rejected];

    /// Canonical SQL string used in CHECK constraints and at-rest
    /// storage.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Approved => "Approved",
            Self::Rejected => "Rejected",
        }
    }

    /// Parse from the SQL at-rest string. NULL is the "not yet
    /// submitted" sentinel; this function does NOT accept NULL — the
    /// caller deals with `Option<ReviewVerdict>` at the row-read layer.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Approved" => Some(Self::Approved),
            "Rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

impl fmt::Display for ReviewVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// PlanBundleNonceOutcome — how the kernel disposed of a `bundle_nonce`.
// DDL: CHECK (outcome IN ('Admitted','TerminallyRejected'))
// plan-bundle-sealing.md §8.2 (`plan_bundle_nonces_seen.outcome` column).
// ---------------------------------------------------------------------------

/// The disposition the kernel reached for a given `bundle_nonce` during
/// the §8.1 admission sequence. Recorded inside the same `BEGIN
/// IMMEDIATE` transaction as the admission decision so a concurrent
/// re-submission cannot race past the §3.5 replay check.
///
/// Only two outcomes are persisted: a third virtual outcome —
/// "transient rejection that consumed nothing" (e.g. the bundle never
/// reached the transaction because of an envelope SHA mismatch in step
/// 2) — is represented by the absence of a row, not by a third variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PlanBundleNonceOutcome {
    /// The nonce was committed by a successful admission. The
    /// `plan_bundle_nonces_seen.initiative_id` column carries the
    /// resulting `initiatives.initiative_id` for forensic join.
    Admitted,
    /// The nonce was committed by a terminal rejection inside steps
    /// 10a–11 of the admission sequence (e.g. key revocation,
    /// freshness expiry, or a policy admission failure). The
    /// `initiative_id` column is NULL. A terminally-rejected nonce
    /// is consumed for replay-protection purposes — the operator
    /// MUST mint a fresh nonce (re-run `raxis-cli submit plan`) to
    /// retry against future policy.
    TerminallyRejected,
}

impl PlanBundleNonceOutcome {
    /// All variants — referenced by the SQL CHECK constraint on
    /// `plan_bundle_nonces_seen.outcome` (Migration 8 / §8.2).
    pub const ALL: [Self; 2] = [Self::Admitted, Self::TerminallyRejected];

    /// Canonical SQL string used in CHECK constraints and at-rest
    /// storage.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Admitted           => "Admitted",
            Self::TerminallyRejected => "TerminallyRejected",
        }
    }

    /// Parse from the SQL at-rest string. NULL is not a valid outcome
    /// — every nonce row carries one of the two variants.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Admitted"           => Some(Self::Admitted),
            "TerminallyRejected" => Some(Self::TerminallyRejected),
            _                    => None,
        }
    }
}

impl fmt::Display for PlanBundleNonceOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── SessionAgentType ─────────────────────────────────────────────────────

    /// SQL round-trip on every variant. The CHECK constraint in migration 5
    /// uses these strings verbatim; a typo here would render the constraint
    /// non-bijective with the enum.
    #[test]
    fn session_agent_type_sql_round_trip_is_total() {
        for &variant in &SessionAgentType::ALL {
            let s = variant.as_sql_str();
            assert!(!s.is_empty(), "SessionAgentType::{variant:?} → empty string");
            assert_eq!(SessionAgentType::from_sql_str(s), Some(variant),
                "round-trip failed for {variant:?}: as_sql_str → {s}");
        }
    }

    #[test]
    fn session_agent_type_unknown_sql_returns_none() {
        assert_eq!(SessionAgentType::from_sql_str(""), None);
        assert_eq!(SessionAgentType::from_sql_str("orchestrator"), None,
            "case-sensitive match: lowercase must NOT round-trip");
        assert_eq!(SessionAgentType::from_sql_str("Planner"), None,
            "V1 'Planner' role MUST NOT decode as a V2 agent type");
    }

    /// INV-DELEGATE-01: only the Orchestrator may delegate.
    /// This is the single source of truth for `can_delegate` derivation
    /// at create_session and approve_plan; runtime handlers MUST consult
    /// the persisted `can_delegate` column instead.
    #[test]
    fn inv_delegate_01_orchestrator_only_implies_can_delegate() {
        assert!(SessionAgentType::Orchestrator.implies_can_delegate());
        assert!(!SessionAgentType::Executor.implies_can_delegate());
        assert!(!SessionAgentType::Reviewer.implies_can_delegate());
    }

    /// V2 has exactly three agent types. Bumping this requires the
    /// dispatch matrix and migration to be updated in lock-step.
    #[test]
    fn session_agent_type_variant_count_is_pinned_to_v2() {
        assert_eq!(SessionAgentType::ALL.len(), 3,
            "V2 has exactly 3 SessionAgentType variants \
             (Orchestrator, Executor, Reviewer); bumping this requires \
             a new migration AND dispatch-matrix refresh.");
    }

    #[test]
    fn session_agent_type_display_equals_as_sql_str() {
        for &variant in &SessionAgentType::ALL {
            assert_eq!(variant.to_string(), variant.as_sql_str());
        }
    }

    /// Bincode/JSON round-trip via serde must use the exact PascalCase
    /// strings — these are the same strings used in the audit-event
    /// JSONL projection (audit-paired-writes.md §3) and the SQL CHECK
    /// constraint. A future serde-rename refactor that changes the
    /// projection silently would break audit-replay tooling.
    // ── CloneStrategy ─────────────────────────────────────────────────────

    #[test]
    fn clone_strategy_sql_round_trip_is_total() {
        for &variant in &CloneStrategy::ALL {
            let s = variant.as_sql_str();
            assert!(!s.is_empty());
            assert_eq!(CloneStrategy::from_sql_str(s), Some(variant));
        }
    }

    #[test]
    fn clone_strategy_canonical_strings_match_spec() {
        // v2-deep-spec.md §Step 27 declares exactly these three lower-case
        // strings on the wire surface (TOML key) and at-rest (SQL CHECK).
        assert_eq!(CloneStrategy::Full.as_sql_str(),     "full");
        assert_eq!(CloneStrategy::Blobless.as_sql_str(), "blobless");
        assert_eq!(CloneStrategy::Sparse.as_sql_str(),   "sparse");
    }

    #[test]
    fn clone_strategy_unknown_sql_returns_none() {
        assert_eq!(CloneStrategy::from_sql_str(""), None);
        assert_eq!(CloneStrategy::from_sql_str("Full"), None,
            "case-sensitive match: PascalCase must NOT round-trip");
        assert_eq!(CloneStrategy::from_sql_str("treeless"), None,
            "git's treeless filter is NOT a V2 strategy");
    }

    #[test]
    fn clone_strategy_variant_count_is_pinned_to_v2() {
        assert_eq!(CloneStrategy::ALL.len(), 3,
            "V2 has exactly 3 CloneStrategy variants (full, blobless, sparse); \
             bumping this requires a v2-deep-spec.md §Step 27 update.");
    }

    #[test]
    fn clone_strategy_display_equals_as_sql_str() {
        for &variant in &CloneStrategy::ALL {
            assert_eq!(variant.to_string(), variant.as_sql_str());
        }
    }

    #[test]
    fn clone_strategy_serde_uses_lowercase() {
        // The serde projection must match the TOML key — operators and
        // tools that read `clone_strategy = "blobless"` from a plan should
        // see the same casing in any audit/JSON dumps.
        let json = serde_json::to_string(&CloneStrategy::Blobless).unwrap();
        assert_eq!(json, r#""blobless""#);
        let parsed: CloneStrategy = serde_json::from_str(r#""sparse""#).unwrap();
        assert_eq!(parsed, CloneStrategy::Sparse);
    }

    #[test]
    fn session_agent_type_serde_uses_pascal_case() {
        let json = serde_json::to_string(&SessionAgentType::Orchestrator).unwrap();
        assert_eq!(json, r#""Orchestrator""#);
        let parsed: SessionAgentType =
            serde_json::from_str(r#""Reviewer""#).unwrap();
        assert_eq!(parsed, SessionAgentType::Reviewer);
    }

    // ── SubtaskActivationState ───────────────────────────────────────────────

    #[test]
    fn subtask_activation_state_sql_round_trip_is_total() {
        for &variant in &SubtaskActivationState::ALL {
            let s = variant.as_sql_str();
            assert!(!s.is_empty(), "SubtaskActivationState::{variant:?} → empty string");
            assert_eq!(SubtaskActivationState::from_sql_str(s), Some(variant),
                "round-trip failed for {variant:?}: as_sql_str → {s}");
        }
    }

    #[test]
    fn subtask_activation_state_unknown_sql_returns_none() {
        assert_eq!(SubtaskActivationState::from_sql_str(""), None);
        // V1 task states must NOT decode as activation states; the two
        // FSMs are deliberately separate (v2-deep-spec.md §Step 5).
        assert_eq!(SubtaskActivationState::from_sql_str("Admitted"), None);
        assert_eq!(SubtaskActivationState::from_sql_str("BlockedRecoveryPending"), None);
    }

    #[test]
    fn subtask_activation_state_terminal_predicate() {
        assert!(!SubtaskActivationState::PendingActivation.is_terminal());
        assert!(!SubtaskActivationState::Active.is_terminal());
        assert!(SubtaskActivationState::Completed.is_terminal());
        assert!(SubtaskActivationState::Failed.is_terminal(),
            "Failed is terminal w.r.t. THIS activation; retries insert a \
             new subtask_activations row, not a transition.");
    }

    #[test]
    fn subtask_activation_state_variant_count_is_pinned_to_v2() {
        assert_eq!(SubtaskActivationState::ALL.len(), 4,
            "V2 has exactly 4 SubtaskActivationState variants; \
             bumping this requires a new migration that ALTERs the \
             CHECK constraint on already-installed databases.");
    }

    #[test]
    fn subtask_activation_state_display_equals_as_sql_str() {
        for &variant in &SubtaskActivationState::ALL {
            assert_eq!(variant.to_string(), variant.as_sql_str());
        }
    }

    // ── ReviewVerdict round-trips ──────────────────────────────────────

    #[test]
    fn review_verdict_round_trips_through_as_sql_str_and_from_sql_str() {
        for &variant in &ReviewVerdict::ALL {
            let s = variant.as_sql_str();
            assert!(!s.is_empty());
            assert_eq!(ReviewVerdict::from_sql_str(s), Some(variant),
                "round-trip failed for {variant:?}: as_sql_str → {s}");
        }
        // Pin the wire-stable strings — these are persisted in
        // `tasks.review_verdict` and embedded in the SQL CHECK
        // constraint emitted by Migration 7.
        assert_eq!(ReviewVerdict::Approved.as_sql_str(), "Approved");
        assert_eq!(ReviewVerdict::Rejected.as_sql_str(), "Rejected");
    }

    #[test]
    fn review_verdict_unknown_sql_returns_none() {
        assert_eq!(ReviewVerdict::from_sql_str(""), None);
        // Defensive: the SubtaskActivationState terminal strings must
        // NOT collide — review_verdict and activation_state are
        // distinct columns.
        assert_eq!(ReviewVerdict::from_sql_str("Completed"), None);
        assert_eq!(ReviewVerdict::from_sql_str("Failed"), None);
        // Defensive: avoid collision with Postgres-style booleans.
        assert_eq!(ReviewVerdict::from_sql_str("true"), None);
        assert_eq!(ReviewVerdict::from_sql_str("false"), None);
    }

    #[test]
    fn review_verdict_variant_count_is_pinned() {
        assert_eq!(ReviewVerdict::ALL.len(), 2,
            "ReviewVerdict has exactly 2 variants (Approved | Rejected); \
             bumping this requires a new migration that ALTERs the CHECK \
             constraint on already-installed databases.");
    }

    #[test]
    fn review_verdict_display_equals_as_sql_str() {
        for &variant in &ReviewVerdict::ALL {
            assert_eq!(variant.to_string(), variant.as_sql_str());
        }
    }

    // ── PlanBundleNonceOutcome round-trips ─────────────────────────────

    #[test]
    fn plan_bundle_nonce_outcome_round_trips_through_as_sql_str_and_from_sql_str() {
        for &variant in &PlanBundleNonceOutcome::ALL {
            let s = variant.as_sql_str();
            assert!(!s.is_empty());
            assert_eq!(PlanBundleNonceOutcome::from_sql_str(s), Some(variant),
                "round-trip failed for {variant:?}: as_sql_str → {s}");
        }
        // Pin the wire-stable strings — these are persisted in
        // `plan_bundle_nonces_seen.outcome` and embedded in the SQL CHECK
        // constraint emitted by Migration 8.
        assert_eq!(PlanBundleNonceOutcome::Admitted.as_sql_str(), "Admitted");
        assert_eq!(PlanBundleNonceOutcome::TerminallyRejected.as_sql_str(),
                   "TerminallyRejected");
    }

    #[test]
    fn plan_bundle_nonce_outcome_unknown_sql_returns_none() {
        assert_eq!(PlanBundleNonceOutcome::from_sql_str(""), None);
        // Defensive: lowercase / kebab-case must NOT round-trip.
        assert_eq!(PlanBundleNonceOutcome::from_sql_str("admitted"), None);
        assert_eq!(PlanBundleNonceOutcome::from_sql_str("terminally-rejected"), None);
        // Defensive: avoid accidental collision with the InitiativeState
        // family — distinct columns, distinct vocab.
        assert_eq!(PlanBundleNonceOutcome::from_sql_str("Aborted"), None);
        assert_eq!(PlanBundleNonceOutcome::from_sql_str("Failed"), None);
    }

    #[test]
    fn plan_bundle_nonce_outcome_variant_count_is_pinned() {
        assert_eq!(PlanBundleNonceOutcome::ALL.len(), 2,
            "PlanBundleNonceOutcome has exactly 2 variants \
             (Admitted | TerminallyRejected); bumping this requires a new \
             migration that ALTERs the CHECK constraint on already-installed \
             databases (plan-bundle-sealing.md §8.2).");
    }

    #[test]
    fn plan_bundle_nonce_outcome_display_equals_as_sql_str() {
        for &variant in &PlanBundleNonceOutcome::ALL {
            assert_eq!(variant.to_string(), variant.as_sql_str());
        }
    }
}
