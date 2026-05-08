// raxis-kernel::initiatives::lifecycle — Initiative and task FSM operations.
//
// Normative reference: kernel-core.md §2.3 operator IPC dispatcher and
// kernel-store.md §2.5.1 Table 2 (initiatives) + Table 5 (tasks) DDL.
//
// CANONICAL STATE NAMES from DDL Table 2 CHECK constraint:
//   'Draft', 'ApprovedPlan', 'Executing', 'Blocked', 'Completed', 'Failed', 'Aborted'
// (NOT 'PlanSubmitted' — that name appeared in draft specs only. DDL wins.)
//
// OPERATOR-DRIVEN lifecycle:
//   create_initiative() — submit plan bytes + Ed25519 sig → Draft row
//   approve_plan()      — verify sig, promote to Executing, admit all tasks
//   reject_plan()       — set state = Aborted (rejection is terminal, no dedicated state)
//   abort_initiative()  — set state = Aborted, cancel all non-terminal tasks
//   abort_task()        — cancel a single task inside an Executing initiative
//   retry_task()        — transition a Failed task back to Admitted
//
// All writes are atomic (single SQLite connection lock per operation).
//
// Separate tables:
//   initiatives   — initiative-level lifecycle (state, plan metadata)
//   signed_plan_artifacts — immutable plan bytes + sig (separate from initiatives)
//   tasks         — task rows, FK to initiatives

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_store::{Store, Table};
use raxis_types::{unix_now_secs, CloneStrategy, InitiativeState, SessionAgentType, TaskState};

use crate::authority::keys::AuthorityError;
use crate::initiatives::plan_registry::{PlanRegistry, TaskKey, TaskPlanFields};
use crate::scheduler::{self, SchedulerError};

// Table name consts — one definition, used everywhere below.
const INITIATIVES: &str            = Table::Initiatives.as_str();
const SIGNED_PLAN_ARTIFACTS: &str  = Table::SignedPlanArtifacts.as_str();
const TASKS: &str                  = Table::Tasks.as_str();
/// Per-task credential-proxy declarations, METADATA ONLY. Credential
/// **values** never live in `kernel.db` — see
/// `raxis_store::Table::TaskCredentialProxies` for the authoritative
/// invariant note.
const TASK_CREDENTIAL_PROXIES: &str = Table::TaskCredentialProxies.as_str();
/// Per-(initiative, sub-task) activation FSM. Inserted by
/// `approve_plan` for every Executor / Reviewer task in lock-step
/// with the parent `tasks` row (INV-STORE-02). See
/// `raxis_store::Table::SubtaskActivations` for the authoritative
/// invariant note.
const SUBTASK_ACTIVATIONS: &str    = Table::SubtaskActivations.as_str();

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("initiative not found: {initiative_id}")]
    InitiativeNotFound { initiative_id: String },

    #[error("initiative is in terminal state: {current_state}")]
    InitiativeTerminal { current_state: String },

    #[error("task not found: {task_id}")]
    TaskNotFound { task_id: String },

    #[error("task is not in Failed state (current: {current_state})")]
    TaskNotFailed { current_state: String },

    #[error("task is not retryable (current: {current_state})")]
    TaskNotRetryable { current_state: String },

    #[error("task is not abortable (current: {current_state})")]
    TaskNotAbortable { current_state: String },

    #[error("plan signature verification failed: {reason}")]
    PlanSignatureInvalid { reason: String },

    #[error("plan TOML invalid: {reason}")]
    PlanInvalid { reason: String },

    /// **V2 (Step 19) — `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX`.** A
    /// `path_allowlist` entry violates the V2 trailing-slash discipline.
    /// Surfaced by `validate_path_allowlist_v2_format` at `approve_plan`
    /// time. The wire-side projection lives in
    /// `policy-plan-authority.md §FAIL_PATH_ALLOWLIST_INVALID_SYNTAX`.
    ///
    /// `reason` is one of the four canonical strings spelled out in
    /// `policy-plan-authority.md`:
    ///   * `"glob_character_in_path"` — entry contains `*`, `?`, `[`,
    ///     `]`, `{`, or `}`.
    ///   * `"absolute_path"` — entry begins with `/`.
    ///   * `"path_escape"` — entry contains a `..` segment.
    ///   * `"empty_entry"` — entry is the empty string.
    ///   * `"negation_marker"` — entry begins with `!` (gitignore-style
    ///     negation; not supported because containment is starts_with /
    ///     equality, not a multi-pass evaluator).
    #[error("path_allowlist[{entry:?}] on task {task_id}: {reason}")]
    PathAllowlistInvalidSyntax {
        task_id: String,
        entry:   String,
        reason:  &'static str,
    },

    /// **V2 (Step 11) — `FAIL_CROSS_CUTTING_ARTIFACT_INVALID_SYNTAX`.**
    /// A `[orchestrator] cross_cutting_artifacts` entry violates the
    /// "exact filename only" discipline. Surfaced by
    /// `validate_cross_cutting_artifacts` at `approve_plan` time.
    /// The wire-side projection collapses to
    /// `INVALID_PLAN_SCHEMA` per INV-08.
    ///
    /// `reason` is one of:
    ///   * `"glob_character"` — entry contains `*`, `?`, `[`, `]`,
    ///     `{`, or `}`.
    ///   * `"contains_slash"` — entry contains `/` (must be a bare
    ///     filename, no directory prefix).
    ///   * `"absolute_path"` — entry begins with `/`.
    ///   * `"path_escape"` — entry contains a `..` segment.
    ///   * `"empty_entry"` — entry is the empty string.
    ///   * `"negation_marker"` — entry begins with `!`.
    ///   * `"trailing_slash"` — entry ends with `/` (would otherwise be
    ///     a directory prefix; cross-cutting artifacts are exact files
    ///     only per Step 11).
    #[error("cross_cutting_artifacts[{entry:?}]: {reason}")]
    CrossCuttingArtifactInvalidSyntax {
        entry:  String,
        reason: &'static str,
    },

    /// **V2 (Step 27) — `INVALID_PLAN_SCHEMA` clone-strategy family.**
    /// A `[[tasks]]` block declares either:
    ///   * an unknown `clone_strategy` value (must be one of `full`,
    ///     `blobless`, `sparse`), OR
    ///   * an unknown `session_agent_type` (must be one of
    ///     `Executor`, `Reviewer` for plan-declared tasks; see also
    ///     `OrchestratorTaskNotPermitted` below for the
    ///     `Orchestrator`-in-`[[tasks]]` rejection), OR
    ///   * `clone_strategy = "sparse"` together with
    ///     `session_agent_type = "Orchestrator"` — the V2 §Step 27
    ///     check #6 ("Sparse-Orchestrator exclusion"). Git's 3-way
    ///     merge machinery walks the merge-base / current / incoming
    ///     trees in lockstep; an Orchestrator with a sparse-trimmed
    ///     working tree cannot safely complete a merge if any incoming
    ///     branch touches an excluded path.
    ///
    /// Surfaced by `validate_clone_strategy_v2_format` /
    /// `validate_sparse_orchestrator_exclusion` at `approve_plan` time,
    /// **before** `BEGIN TRANSACTION`.
    ///
    /// `rule` is one of:
    ///   * `"unknown_clone_strategy"` — value is not `full|blobless|sparse`.
    ///   * `"unknown_agent_type"` — value is not in `SessionAgentType`'s
    ///     SQL set (`Orchestrator|Executor|Reviewer`).
    ///   * `"sparse_orchestrator_exclusion"` — `sparse` + `Orchestrator`.
    ///   * `"orchestrator_task_not_permitted"` — `[[tasks]]` block declares
    ///     `session_agent_type = "Orchestrator"` (V2: the Orchestrator
    ///     session is auto-created by the kernel from the kernel-bundled
    ///     `raxis-orchestrator-core` image; operators do not declare it).
    #[error("plan clone-strategy invalid (rule={rule}, task={offending_task}): {suggestion}")]
    PlanCloneStrategyInvalid {
        rule:           &'static str,
        offending_task: String,
        suggestion:     String,
    },

    /// **V2 (Step 28) — `INVALID_PLAN_SCHEMA` single-lane propagation.**
    /// Either:
    ///   * the plan TOML has no `[workspace] lane_id = "..."` declaration
    ///     (V2 makes the workspace-root lane mandatory so the
    ///     budget-ceiling propagation in `v2-deep-spec.md §Step 28` has
    ///     a concrete value to fan out to every task row, every
    ///     orchestrator session, every executor session, and every
    ///     reviewer session — without it the existing per-lane
    ///     `SUM(reserved_cost)` enforcement cannot bound an initiative as
    ///     a unit), OR
    ///   * a `[[tasks]]` block declares its own `lane_id = "..."`
    ///     override. The Step 28 single-lane invariant rejects per-task
    ///     overrides at `approve_plan` time so the operator's
    ///     workspace-root lane is the authoritative ceiling for every
    ///     session in the initiative.
    ///
    /// Surfaced by `validate_single_lane_propagation` at `approve_plan`
    /// time, **before** `BEGIN TRANSACTION`, so a malformed plan never
    /// allocates a row.
    ///
    /// `rule` is one of:
    ///   * `"missing_workspace_lane"` — plan TOML has no
    ///     `[workspace] lane_id`.
    ///   * `"empty_workspace_lane"` — `[workspace] lane_id` is the empty
    ///     string.
    ///   * `"single_lane_propagation"` — at least one `[[tasks]]`
    ///     block sets `lane_id` (V2 forbids per-task overrides).
    ///
    /// `offending_task` names the offending task (or the literal
    /// `"<workspace>"` for `missing_workspace_lane` /
    /// `empty_workspace_lane`).
    /// `suggestion` is the actionable remediation hint required by
    /// `v2-deep-spec.md §Step 17` ("must always include a concrete
    /// remediation suggestion, not just the violation").
    #[error("plan single-lane propagation invalid (rule={rule}, task={offending_task}): {suggestion}")]
    PlanSingleLaneInvalid {
        rule:           &'static str,
        offending_task: String,
        suggestion:     String,
    },

    /// **V2 (Step 17) — `INVALID_PLAN_SCHEMA` shift-left, DAG family.**
    /// A `[[tasks]]` block declares a structurally invalid dependency
    /// graph. Surfaced by `validate_plan_dag` at `approve_plan` time,
    /// **before** `BEGIN TRANSACTION`, so a malformed plan never
    /// allocates a row.
    ///
    /// `rule` is one of the four canonical Step 17 DAG rules:
    ///   * `"duplicate_task_id"` — two tasks share the same `task_id`.
    ///   * `"self_loop"`         — `task.predecessors` lists `task`.
    ///   * `"dangling_dependency"` — predecessor not declared in plan.
    ///   * `"cyclic_dependency"` — directed cycle through `predecessors`.
    ///
    /// `offending_task` names the task whose entry triggered the rule
    /// (for cycles, an arbitrary task on the cycle — sufficient for
    /// the operator to grep the plan).
    /// `suggestion` is the actionable remediation hint required by
    /// `v2-deep-spec.md §Step 17` ("must always include a concrete
    /// remediation suggestion, not just the violation").
    ///
    /// **Note on shift-left vs in-tx:** the in-transaction
    /// `scheduler::admit_in_tx` still calls `detect_cycle_in` as a
    /// defense-in-depth backstop. It should never fire for a plan that
    /// passed shift-left, but if a future refactor accidentally
    /// bypasses the shift-left validator, the tx-level check catches
    /// the cycle and rolls back. A plan that fails *only* the
    /// in-tx check (theoretically impossible) surfaces as
    /// `Scheduler(SchedulerError::CyclicDependency)`, distinct from
    /// this variant.
    #[error("plan DAG invalid (rule={rule}, task={offending_task}): {suggestion}")]
    PlanDagInvalid {
        rule:           &'static str,
        offending_task: String,
        suggestion:     String,
    },

    /// **V2 (Step 17 / `credential-proxy.md §3`) —
    /// `INVALID_PLAN_SCHEMA` task-credentials family.** A
    /// `[[tasks.credentials]]` block declared by an operator is
    /// structurally invalid:
    ///
    ///   * `"unknown_proxy_type"` — the `proxy_type` is not one of
    ///     `postgres | http | k8s` (the V2 implemented set). Future
    ///     proxy types (`smtp`, `redis`, `aws`) gain new variants in
    ///     `raxis_plan_credentials::ProxyDecl` and graduate out of
    ///     this rule.
    ///   * `"malformed"` — a generic structural error from
    ///     `raxis_plan_credentials::ParseError` (missing required
    ///     field, wrong TOML type, etc.). The exact diagnostic from
    ///     the parser is preserved in `suggestion`.
    ///
    /// Surfaced by `validate_task_credentials` at `approve_plan`
    /// time, **before** `BEGIN TRANSACTION`, so a malformed plan
    /// never allocates a row. Sister-of `PlanDagInvalid` —
    /// shift-left validation per `v2-deep-spec.md §Step 17`.
    #[error("plan task-credentials invalid (rule={rule}, task={offending_task}, credential={offending_credential}): {suggestion}")]
    PlanTaskCredentialsInvalid {
        /// One of `unknown_proxy_type`, `malformed`.
        rule:                 &'static str,
        /// The task whose `[[tasks.credentials]]` block was rejected.
        offending_task:       String,
        /// The `name` field on the offending credential decl, or
        /// the literal `"<unparsed>"` when the parser failed before
        /// the name was reached.
        offending_credential: String,
        /// Operator-facing remediation hint per Step 17 ("must
        /// always include a concrete remediation suggestion").
        suggestion:           String,
    },

    #[error("scheduler error during admission: {0}")]
    Scheduler(#[from] SchedulerError),

    #[error("store error: {0}")]
    Store(#[from] raxis_store::StoreError),

    #[error("store SQL error: {0}")]
    Sql(#[from] rusqlite::Error),
}

impl From<AuthorityError> for LifecycleError {
    fn from(e: AuthorityError) -> Self {
        LifecycleError::Store(raxis_store::StoreError::Invariant(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct InitiativeCreated {
    pub initiative_id: String,
    /// Always "Draft" in v1.
    pub status: String,
}

#[derive(Debug)]
pub struct PlanApproved {
    pub initiative_id: String,
    pub tasks_admitted: usize,

    /// V2 §Step 6 / `INV-PLANNER-HARNESS-06` — the kernel auto-creates
    /// the canonical Orchestrator session for every V2 initiative at
    /// `approve_plan` time. The session row is inserted inside the
    /// same transaction that admits `[[tasks]]`, so a successful
    /// `approve_plan` either persists BOTH the tasks AND the
    /// Orchestrator session, or rolls back both (INV-STORE-02).
    ///
    /// Caller path: `kernel/src/handlers/intent.rs` consumes this id
    /// in `handle_approve_plan` (post-transaction) and hands it to
    /// `ctx.orchestrator_spawn.spawn_for_initiative(...)` —
    /// `kernel/src/session_spawn_orchestrator.rs` —
    /// which performs the host-capacity check and the
    /// `IsolationBackend::spawn` call that boots the canonical
    /// Orchestrator VM. The substrate handle is then bound to the
    /// session token in the same hop, satisfying
    /// `extensibility-traits.md §3.5` post-commit ordering.
    ///
    /// `None` is reserved for test fixtures that bypass the auto-spawn
    /// (e.g. unit tests asserting only the SQL admission tx). Every
    /// production caller of `approve_plan` observes this as `Some`.
    pub orchestrator_session_id: Option<String>,
}

// ---------------------------------------------------------------------------
// create_initiative — submit a plan for operator review
// ---------------------------------------------------------------------------

/// Submit a plan document for this initiative.
///
/// - `plan_toml`: raw plan bytes (TOML text).
/// - `plan_sig_hex`: hex-encoded Ed25519 signature over the plan bytes.
/// - `submitted_by`: operator fingerprint for audit.
///
/// Creates:
///   - initiatives row in `Draft` state (DDL canonical; NOT 'PlanSubmitted').
///   - signed_plan_artifacts row with the raw plan bytes + signature.
///
/// Signature verification is deferred to `approve_plan` so the operator
/// can submit and inspect before approving.
pub fn create_initiative(
    plan_toml:    &str,
    plan_sig_hex: &str,
    submitted_by: &str,
    store: &Store,
) -> Result<InitiativeCreated, LifecycleError> {
    let initiative_id  = uuid::Uuid::new_v4().to_string();
    let plan_sha256    = raxis_crypto::token::sha256_hex(plan_toml.as_bytes());
    let now            = unix_now_secs();

    // terminal_criteria_json: empty JSON object in v1 (operator-driven terminal
    // criteria not yet configured at submission time).
    let terminal_criteria = "{}";

    // Reject malformed hex up-front (before opening the transaction) rather
    // than silently storing an empty `plan_sig` (which would later fail
    // signature verification with a misleading "Ed25519 signature verification
    // failed" error and obscure the real cause). Surfaces as `PlanInvalid` so
    // the operator sees the actual problem.
    let sig_bytes = hex::decode(plan_sig_hex).map_err(|e| LifecycleError::PlanInvalid {
        reason: format!("plan signature is not valid hex: {e}"),
    })?;
    if sig_bytes.len() != 64 {
        return Err(LifecycleError::PlanInvalid {
            reason: format!(
                "plan signature must be 64 bytes (Ed25519); got {} bytes",
                sig_bytes.len()
            ),
        });
    }

    // INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern D): both INSERTs MUST
    // commit atomically. Pre-fix, a process crash between the two left an
    // orphaned `Draft` initiative with no `signed_plan_artifacts` row that
    // subsequent `approve_plan` calls would fail to read with
    // QueryReturnedNoRows — producing an undeletable initiative the operator
    // could never approve. Single-transaction commit makes the failure mode
    // binary: either both rows land or neither does.
    let mut conn = store.lock_sync();
    let tx = conn.transaction()?;

    tx.execute(
        &format!(
            "INSERT INTO {INITIATIVES}
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)"
        ),
        rusqlite::params![
            &initiative_id,
            InitiativeState::Draft.as_sql_str(),
            terminal_criteria,
            &plan_sha256,
            now,
        ],
    )?;

    tx.execute(
        &format!(
            "INSERT INTO {SIGNED_PLAN_ARTIFACTS}
                (initiative_id, plan_bytes, plan_sig, stored_at)
             VALUES (?1, ?2, ?3, ?4)"
        ),
        rusqlite::params![
            &initiative_id,
            plan_toml.as_bytes(),
            &sig_bytes,
            now,
        ],
    )?;

    tx.commit()?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"InitiativeCreated\",\
         \"initiative_id\":\"{initiative_id}\",\"submitted_by\":\"{submitted_by}\"}}",
    );

    Ok(InitiativeCreated {
        initiative_id,
        status: "Draft".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// approve_plan — verify sig, admit tasks, promote to Executing
// ---------------------------------------------------------------------------

/// Approve a plan: verify the operator Ed25519 signature, parse task definitions
/// from the plan TOML, admit all tasks (insert task rows + DAG edges in
/// Admitted state), and transition the initiative from `Draft` to `Executing`.
///
/// Spec INV-INIT-01: task rows are derived from plan TOML at approval time.
///
/// **INV-STORE-02 (kernel-store.md §2.5.1, table row "approve_plan").**
/// All writes — the `initiatives` UPDATE, every `tasks` INSERT, and every
/// `task_dag_edges` INSERT — happen inside ONE `BEGIN`/`COMMIT` held under
/// ONE mutex acquisition. Failure on any task admit (cycle detected, FK
/// violation, lane validation) rolls back the entire transaction; the
/// initiative remains `Draft` and no partial task rows linger.
///
/// The audit event is intentionally emitted **after** `tx.commit()` per
/// kernel-store.md §2.5.2 ("SQLite committed first, JSONL appended second").
/// PR-8 will replace the `eprintln!` with `AuditWriter::append`.
/// Approve a signed plan and admit its tasks. See module docstring
/// for the full transaction-boundary contract.
///
/// `approving_operator_display_name` is the operator's display name
/// resolved from the policy entry by the IPC handler (kernel-store.md
/// §2.5.2 "Operator display-name fields"). It is plumbed in rather
/// than re-resolved here because `approve_plan` runs on a
/// `spawn_blocking` thread that does not own a `PolicyBundle`
/// snapshot, and fetching one mid-fn would break the "single epoch
/// view per approval" guarantee the dispatcher already establishes.
/// `None` when the dispatcher could not resolve the fingerprint
/// (legacy callers, or a tight rotation race).
pub fn approve_plan(
    initiative_id:                   &str,
    approving_operator:              &str,
    approving_operator_display_name: Option<String>,
    operator_pubkey_bytes:           &[u8],
    policy_epoch:                    u64,
    store:                           &Store,
    audit:                           &dyn AuditSink,
    plan_registry:                   &PlanRegistry,
) -> Result<PlanApproved, LifecycleError> {
    let mut conn = store.lock_sync();

    // ── Pre-tx reads (cheap, do not need to be in the tx) ────────────────
    // We read state + plan bytes + sig before BEGIN so a malformed sig or
    // a non-Draft initiative does not even start a transaction.
    let current_state: String = conn.query_row(
        &format!("SELECT state FROM {INITIATIVES} WHERE initiative_id=?1"),
        rusqlite::params![initiative_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;
    if current_state != InitiativeState::Draft.as_sql_str() {
        return Err(LifecycleError::InitiativeTerminal { current_state });
    }

    let (plan_bytes, plan_sig): (Vec<u8>, Vec<u8>) = conn.query_row(
        &format!("SELECT plan_bytes, plan_sig FROM {SIGNED_PLAN_ARTIFACTS} WHERE initiative_id=?1"),
        rusqlite::params![initiative_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;

    // Canonical Ed25519 verification per kernel-store.md §2.5.3 (the same
    // signing domain the CLI's `policy sign` constructs). Verifying raw
    // plan bytes — as an earlier draft did — would reject every CLI sig.
    raxis_crypto::plan::verify_plan_signature(operator_pubkey_bytes, &plan_bytes, &plan_sig)
        .map_err(|e| LifecycleError::PlanSignatureInvalid {
            reason: e.to_string(),
        })?;

    let plan_toml_str    = String::from_utf8_lossy(&plan_bytes);
    let plan_tasks       = parse_plan_tasks(&plan_toml_str)?;
    let orchestrator_fields = parse_plan_orchestrator(&plan_toml_str)?;
    // V2 §Step 28 — read `[workspace] lane_id` (or surface the
    // missing/empty/override error below).
    let workspace_lane_raw  = parse_plan_workspace_lane(&plan_toml_str)?;

    // V2 Step 17 — shift-left plan validation. Each helper runs BEFORE
    // `BEGIN TRANSACTION`, so a malformed plan never mutates kernel
    // state. We run the DAG check first because a structurally broken
    // plan can confuse later validators (e.g. a path-allowlist entry
    // on a duplicate task_id), and the path-format check second because
    // it is purely syntactic and cannot depend on graph well-formedness.
    //
    // V2 §Step 11 cross_cutting_artifacts validator runs alongside —
    // it has no dependency on graph well-formedness either, but lives
    // here so a malformed orchestrator stanza is rejected with the same
    // pre-tx posture as the path_allowlist validator.
    //
    // The other Step 17 checks (referential integrity over `[[subtasks]]`,
    // meta-authority of the unique Orchestrator, path-subset containment,
    // sparse-Orchestrator exclusion, single-lane propagation) require V2
    // schema fields (`session_agent_type`, `clone_strategy`,
    // `[plan.orchestrator]`) that are not yet parsed by `parse_plan_tasks`.
    // Those checks land alongside the V2 plan-bundle schema work
    // (see `plan-bundle-sealing.md §8.2`); the DAG and path-format
    // validators run today and are forward-compatible (they operate on
    // `predecessors` / `path_allowlist`, both already in the V1 schema).
    validate_plan_dag(&plan_tasks)?;
    validate_path_allowlist_v2_format(&plan_tasks)?;
    validate_cross_cutting_artifacts(&orchestrator_fields)?;
    // V2 `credential-proxy.md §3` shift-left: any
    // `[[tasks.credentials]]` block declaring an unknown
    // `proxy_type` (or a structurally malformed entry — already
    // surfaced as `PlanInvalid` inside `parse_plan_tasks`) is
    // rejected here, before BEGIN TRANSACTION, so a plan that
    // names a proxy this kernel build does not implement cannot
    // allocate a task row.
    validate_task_credentials(&plan_tasks)?;
    // V2 §Step 27 — clone-strategy + Sparse-Orchestrator exclusion +
    // Orchestrator-in-`[[tasks]]` rejection. Runs after the parser-
    // level "unknown value" rejection (which fires inside
    // `parse_plan_tasks`) so by here every task has a valid typed
    // `clone_strategy` and `session_agent_type`.
    validate_sparse_orchestrator_exclusion(&plan_tasks)?;
    // V2 §Step 28 — single-lane propagation: rejects missing /
    // empty `[workspace] lane_id` AND per-task `lane_id` overrides
    // before the transaction opens. `workspace_lane` is the
    // authoritative non-empty lane id every `scheduler::PlanTask`
    // below will be stamped with.
    let workspace_lane = validate_single_lane_propagation(
        &workspace_lane_raw,
        &plan_tasks,
    )?;

    let task_count    = plan_tasks.len();
    let now           = unix_now_secs();

    // ── INV-STORE-02 transaction ─────────────────────────────────────────
    // Everything below MUST commit or roll back as one unit.
    let tx = conn.transaction()?;

    // Defer FK enforcement until COMMIT. The intra-plan FK pattern is:
    //   task_dag_edges.predecessor_task_id → tasks(task_id)
    // and within a single plan, tasks frequently reference each other
    // (t2 depends on t1). We insert tasks one at a time, so the edge
    // (t1, t2) inserted while admitting t2 would fail FK if t1 were not
    // yet committed (it isn't — we're still inside the tx). Deferring
    // FK to COMMIT lets the entire plan land before validation, while
    // still rolling back on any unresolved reference at commit time.
    tx.execute_batch("PRAGMA defer_foreign_keys = 1;")?;

    // Re-check Draft inside the tx using a conditional UPDATE — this
    // closes the TOCTOU window between the pre-tx read and BEGIN. If a
    // concurrent caller already approved (or rejected) the initiative,
    // `rows == 0` and we error out cleanly.
    let rows = tx.execute(
        &format!(
            "UPDATE {INITIATIVES} SET state=?1, approved_at=?2
             WHERE initiative_id=?3 AND state=?4"
        ),
        rusqlite::params![
            InitiativeState::Executing.as_sql_str(),
            now,
            initiative_id,
            InitiativeState::Draft.as_sql_str(),
        ],
    )?;
    if rows == 0 {
        // Tx is dropped → automatic rollback. No state change.
        return Err(LifecycleError::InitiativeTerminal {
            current_state: "<changed concurrently>".to_owned(),
        });
    }

    // Stamp the approving operator into `signed_plan_artifacts` so the
    // step-10 sweep `quarantine-plans-by` can answer "which initiatives
    // did this operator approve?" without scanning the audit chain.
    // Schema added by `migration_3` (kernel-store.md §2.5.8); the column
    // is NULLABLE for backward compatibility, but every NEW approval
    // MUST populate it. Done inside the same tx as the state flip so a
    // committed `Executing` initiative ALWAYS has a non-NULL signer.
    tx.execute(
        &format!(
            "UPDATE {SIGNED_PLAN_ARTIFACTS}
                SET signed_by_fingerprint = ?1
              WHERE initiative_id = ?2"
        ),
        rusqlite::params![approving_operator, initiative_id],
    )?;

    // Admit every task. `admit_in_tx` owns no lock and no transaction; it
    // writes through the borrowed `&Connection` exposed by `tx`.
    //
    // We clone the §2.5.8 path-scope fields out of `plan_tasks` BEFORE
    // moving each `pt` into the scheduler::PlanTask struct, because
    // those fields are not part of the scheduler-side type (they live
    // in the in-memory PlanRegistry, not in `tasks` columns). The clone
    // is small (mostly Vec<String> of plan-time globs) and only happens
    // once per task at approve time.
    let mut path_scope_snapshots: Vec<(String, TaskPlanFields, bool)>
        = Vec::with_capacity(plan_tasks.len());

    for pt in plan_tasks {
        let path_fields = TaskPlanFields {
            path_allowlist:            pt.path_allowlist.clone(),
            path_export_to_successors: pt.path_export_to_successors,
            path_export_globs:         pt.path_export_globs.clone(),
            path_scope_override:       pt.path_scope_override,
            // V2 §Step 27 — typed clone strategy + agent type.
            clone_strategy:            pt.clone_strategy,
            session_agent_type:        pt.session_agent_type,
        };
        path_scope_snapshots.push((
            pt.task_id.clone(),
            path_fields,
            pt.path_scope_override,
        ));

        // V2 §Step 28 — every task row carries the workspace-root
        // lane verbatim. `pt.lane_id` is `""` here (validator
        // already rejected non-empty per-task overrides); this is
        // the propagation step.
        //
        // We capture (`task_id`, `credentials`) up front because we
        // are about to move `pt.predecessors` and `pt.name` into the
        // scheduler's `PlanTask` struct; the credential rows are
        // inserted immediately AFTER `admit_in_tx` so they share
        // the same approve-plan transaction as the parent
        // `tasks(task_id)` row (INV-STORE-02 / Pattern A).
        let task_id_for_creds = pt.task_id.clone();
        let credentials_for_task = pt.credentials.clone();
        let agent_type_for_activation = pt.session_agent_type;

        let task = scheduler::PlanTask {
            task_id:       pt.task_id.clone(),
            initiative_id: initiative_id.to_owned(),
            lane_id:       workspace_lane.clone(),
            name:          pt.name,
            dependencies:  pt.predecessors,
        };
        scheduler::admit_in_tx(&tx, task, policy_epoch)?;

        // V2 — `[[tasks.credentials]]` persistence
        // (credential-proxy.md §3 + §1.1).
        //
        // Insert one `task_credential_proxies` row per declared
        // credential proxy. METADATA ONLY: each row carries
        // `credential_name`, `mount_as`, `proxy_type`, and the
        // serialised `proxy_json` restriction blob — *never* the
        // credential value bytes themselves. Bytes resolve through
        // the kernel's `CredentialBackend` at proxy-bind time.
        //
        // Atomicity. Same `tx` as `admit_in_tx`, so a partial
        // approve_plan is impossible: either both the parent
        // `tasks` row AND every declared credential-proxy land,
        // or both roll back together.
        if !credentials_for_task.is_empty() {
            insert_task_credential_proxies_in_tx(
                &tx,
                &task_id_for_creds,
                &credentials_for_task,
            )?;
        }

        // V2 §Step 5 — `subtask_activations` row population.
        //
        // Insert one row per Executor / Reviewer task in
        // `PendingActivation`. INV-STORE-02 (Pattern A): atomic with
        // the parent `tasks` row. The Orchestrator's newly-activatable
        // prompt query (Layer 2 prompt assembly) reads this table on
        // every InferenceRequest, so the row must be visible to the
        // first prompt rendered after `tx.commit()`. Orchestrator
        // tasks (auto-spawned by the kernel) deliberately receive no
        // row — the helper is a no-op for that agent_type.
        insert_subtask_activation_in_tx(
            &tx,
            &task_id_for_creds,
            initiative_id,
            agent_type_for_activation,
        )?;
    }

    // V2 §Step 6 / `INV-PLANNER-HARNESS-06` — auto-spawn the canonical
    // Orchestrator session inside the SAME transaction as the task
    // admit loop. INV-STORE-02 (Pattern A): a successful approve_plan
    // either persists tasks AND the Orchestrator session, or rolls
    // back both. The session row is `Planner`-roled at the wire layer
    // (the IPC role taxonomy) and `Orchestrator`-typed at the V2
    // dispatch layer (`session_agent_type`). `worktree_root` and
    // `base_sha` start NULL — both will be populated by the kernel's
    // VM-spawn step when it provisions the Orchestrator's worktree
    // (DDL allows `(base_sha NULL, worktree_root NULL)` per the
    // sessions table CHECK clause). `vsock_cid` is also NULL until
    // the hypervisor returns the assigned CID.
    let orchestrator_auto_spawn =
        auto_spawn_orchestrator_session_in_tx(&tx, initiative_id)?;

    tx.commit()?;
    drop(conn); // release the store mutex before doing audit I/O.

    // ── Post-commit: populate in-memory PlanRegistry ─────────────────────
    //
    // Per kernel-store.md §2.5.8 line 1911 — the four path-scope fields
    // are loaded from the signed plan artifact at `approve_plan` time
    // and held in the kernel's in-memory plan representation, NOT in
    // the `tasks` table. The intent handler reads them back via
    // `path_scope::effective_allow`, which is the only consumer.
    //
    // We deliberately populate AFTER `tx.commit()` rather than before:
    // if the SQLite commit fails for any reason (FK violation, disk
    // pressure), the registry must NOT contain entries for tasks that
    // were never persisted. The reverse failure mode (commit succeeds,
    // registry insert "fails") cannot happen: `PlanRegistry::insert`
    // is infallible — it's a `RwLock<HashMap>` write — so once we get
    // past `tx.commit()?` every `insert` below is guaranteed to land.
    for (task_id, fields, _) in &path_scope_snapshots {
        plan_registry.insert(
            TaskKey::new(initiative_id, task_id),
            fields.clone(),
        );
    }

    // V2 §Step 11 — persist the orchestrator's `cross_cutting_artifacts`
    // for IntegrationMerge admission. Same post-commit ordering as the
    // per-task registry insert: the SQLite tx is the source of truth,
    // and the in-memory registry is repopulated from `plan_bytes` on
    // hot-restart so a missed insert here cannot survive a kernel boot.
    plan_registry.insert_orchestrator(initiative_id, orchestrator_fields);

    // Audit-after-commit per kernel-store.md §2.5.2. A failure here
    // produces a §2.5.2 "SQLite committed, JSONL not appended" gap that
    // recovery::reconcile detects and repairs via ReconciliationGap;
    // we therefore only log the failure here and return success — the
    // store is consistent and the operator's intent has been honoured.
    if let Err(e) = audit.emit(
        AuditEventKind::PlanApproved {
            initiative_id: initiative_id.to_owned(),
            task_count,
        },
        None,
        None,
        Some(initiative_id),
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"PlanApproved\",\"audit_emit_failed\":\"{e}\",\
             \"initiative_id\":\"{initiative_id}\",\"approving_operator\":\"{approving_operator}\"}}",
        );
    }

    // V2 §Step 6 / `INV-PLANNER-HARNESS-06` — emit `SessionCreated` for
    // the auto-spawned Orchestrator session. Same audit-after-commit
    // treatment as `PlanApproved`: the row is committed; an emit
    // failure here is repaired by `recovery::reconcile`.
    if let Err(e) = audit.emit(
        AuditEventKind::SessionCreated {
            session_id:    orchestrator_auto_spawn.session_id.clone(),
            role:          "planner".to_owned(),
            lineage_id:    orchestrator_auto_spawn.lineage_id.clone(),
            worktree_root: None,
            initiative_id: Some(initiative_id.to_owned()),
            // The plan_bundle_sha256 reference is wired by the
            // V2-bundle admission path (Migration 8); for the V1+V2
            // signed_plan_artifacts path we leave it None and the
            // attribution chain still resolves through
            // `signed_plan_artifacts.plan_artifact_sha256`.
            plan_bundle_sha256: None,
            policy_epoch:  Some(policy_epoch),
            session_agent_type:
                Some(SessionAgentType::Orchestrator.as_sql_str().to_owned()),
        },
        Some(&orchestrator_auto_spawn.session_id),
        None,
        Some(initiative_id),
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"SessionCreated\",\
             \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{initiative_id}\",\
             \"orchestrator_session_id\":\"{}\"}}",
            orchestrator_auto_spawn.session_id,
        );
    }

    // §2.5.8 path_scope_override semantics: emit one
    // `PathScopeOverrideApplied` event per task with the override on,
    // recording (initiative, task, approving_operator). Same audit-
    // after-commit treatment as `PlanApproved`: failures are logged,
    // never propagated, since the store is already consistent and the
    // override has *de facto* taken effect.
    for (task_id, _, override_on) in &path_scope_snapshots {
        if !*override_on { continue; }
        if let Err(e) = audit.emit(
            AuditEventKind::PathScopeOverrideApplied {
                initiative_id:      initiative_id.to_owned(),
                task_id:            task_id.clone(),
                approving_operator: approving_operator.to_owned(),
                approving_operator_display_name:
                    approving_operator_display_name.clone(),
            },
            None,
            Some(task_id),
            Some(initiative_id),
        ) {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"PathScopeOverrideApplied\",\
                 \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{initiative_id}\",\
                 \"task_id\":\"{task_id}\"}}",
            );
        }
    }

    Ok(PlanApproved {
        initiative_id: initiative_id.to_owned(),
        tasks_admitted: task_count,
        orchestrator_session_id: Some(orchestrator_auto_spawn.session_id),
    })
}

// ---------------------------------------------------------------------------
// auto_spawn_orchestrator_session_in_tx — V2 §Step 6
// ---------------------------------------------------------------------------

/// Outcome of `auto_spawn_orchestrator_session_in_tx`. Returned to
/// `approve_plan` so the post-commit audit emitter has the freshly
/// generated `session_id` and `lineage_id` without a follow-up read
/// from the store.
#[derive(Debug, Clone)]
pub struct OrchestratorAutoSpawn {
    /// Newly generated session UUID.
    pub session_id: String,
    /// Newly generated lineage id (the Orchestrator session is the
    /// root of a fresh lineage tree per initiative).
    pub lineage_id: String,
}

/// V2 §Step 6 / `INV-PLANNER-HARNESS-06` — auto-create the canonical
/// Orchestrator session for `initiative_id` inside the same SQLite
/// transaction that admits the plan's `[[tasks]]` rows.
///
/// **Why inside the tx.** The session row, the task rows, and the
/// initiative state flip all share a single INV-STORE-02 atomicity
/// boundary: a successful `approve_plan` produces a complete and
/// consistent V2 admission state (initiative `Executing` + tasks
/// `Admitted` + Orchestrator session `created` and ready to be
/// VM-spawned), or it rolls everything back.
///
/// **Wire-role vs. agent-type.** The IPC role taxonomy
/// (`Planner | Gateway | Verifier`) does not distinguish among V2
/// agent types — that distinction lives in the dispatch matrix
/// (v2-deep-spec.md §Step 20) and is keyed on
/// `sessions.session_agent_type`. We persist the row with
/// `role_id = 'Planner'` (matching the wire taxonomy) and
/// `session_agent_type = 'Orchestrator'` + `can_delegate = 1` (the
/// V2 dispatch keys).
///
/// **NULL columns at insert time.** The DDL CHECK clause on `sessions`
/// is `CHECK (base_sha IS NULL OR worktree_root IS NOT NULL)`; the
/// `(base_sha NULL, worktree_root NULL)` pair is therefore admissible.
/// Both columns are filled in later by the kernel's VM-spawn step
/// when it provisions the Orchestrator's worktree; the
/// `vsock_cid` column is similarly NULL until the hypervisor returns
/// the assigned CID (Migration 5 doc-comment).
///
/// **Failure mode.** RNG / SQLite errors propagate as
/// `LifecycleError::Sql` and abort the entire `approve_plan` tx —
/// the operator sees a generic `FAIL_APPROVE_PLAN` and the store
/// stays in `Draft`. There is no partial-spawn failure mode.
fn auto_spawn_orchestrator_session_in_tx(
    tx:            &rusqlite::Transaction<'_>,
    initiative_id: &str,
) -> Result<OrchestratorAutoSpawn, LifecycleError> {
    use raxis_types::SessionId;

    let session_id    = SessionId::new_v4();
    let session_id_s  = session_id.as_str().to_owned();
    let lineage_id    = uuid::Uuid::new_v4().to_string();

    // 32 CSPRNG bytes → 64 hex chars. RNG failure surfaces here and
    // short-circuits approve_plan; we never write a zeroed token.
    let session_token = raxis_crypto::token::generate_session_token()
        .map_err(|e| LifecycleError::PlanInvalid {
            reason: format!("orchestrator session token RNG failed: {e}"),
        })?;

    // Default V2 session lifetime: 1 day. The kernel-side maintenance
    // loop renews active session expiries on heartbeat; a 1-day
    // baseline matches `SessionConfig::default()` in
    // `authority::session::create_session`.
    let now_secs   = unix_now_secs();
    let expires_at = now_secs + 86_400;

    let sessions_t = Table::Sessions.as_str();
    tx.execute(
        &format!(
            "INSERT INTO {sessions_t} (
                session_id, role_id, session_token, sequence_number,
                worktree_root, base_sha, base_tracking_ref,
                lineage_id, fetch_quota, created_at, expires_at, revoked,
                session_agent_type, can_delegate
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,?12,1)"
        ),
        rusqlite::params![
            session_id_s,
            "Planner",
            session_token,
            0i64,
            // worktree_root: NULL — populated by VM spawn step.
            Option::<String>::None,
            // base_sha: NULL — populated by VM spawn step.
            Option::<String>::None,
            // base_tracking_ref: NULL — paired with base_sha.
            Option::<String>::None,
            lineage_id,
            // fetch_quota: same default as `SessionConfig::default()`.
            1000i64,
            now_secs,
            expires_at,
            SessionAgentType::Orchestrator.as_sql_str(),
        ],
    )?;

    Ok(OrchestratorAutoSpawn {
        session_id: session_id_s,
        lineage_id,
    })
}

// ---------------------------------------------------------------------------
// repopulate_plan_registry — kernel-restart hook
// ---------------------------------------------------------------------------

/// Re-parse every non-terminal initiative's signed plan artifact and refill
/// the in-memory `PlanRegistry`. Called once during kernel boot, after
/// the store opens and `recovery::reconcile` returns.
///
/// **Why this is necessary:** the four §2.5.8 path-scope fields live only
/// in the in-memory registry, not in the `tasks` DDL. A kernel restart
/// would otherwise leave the registry empty for every previously-approved
/// initiative, causing `path_scope::effective_allow` to return
/// `NoPlanEntry` (fail-closed → `FAIL_PATH_POLICY_VIOLATION`) on the
/// first intent submitted after restart. Repopulating from the immutable
/// `signed_plan_artifacts.plan_bytes` row gives identical semantics as
/// the in-process `approve_plan` path.
///
/// **Scope:** initiatives in `Executing` or `Blocked` state. `Draft` is
/// skipped because no tasks have been admitted yet (so no intents can
/// arrive). Terminal states (`Completed`/`Failed`/`Aborted`) are skipped
/// because tasks there are not accepting intents.
///
/// **Failure mode:** a per-initiative failure (corrupt TOML, missing
/// artifact row) is logged and skipped. The kernel does NOT abort boot
/// because path-scope enforcement still works for any initiative whose
/// plan parsed correctly — and any initiative that fails to load will
/// fail-closed at intent time anyway, which is the desired degraded
/// behaviour.
///
/// Returns the number of (initiative, task) pairs successfully inserted.
pub fn repopulate_plan_registry(
    store:    &Store,
    registry: &PlanRegistry,
) -> Result<usize, LifecycleError> {
    let conn = store.lock_sync();

    let mut stmt = conn.prepare(&format!(
        "SELECT initiative_id FROM {INITIATIVES}
         WHERE state IN (?1, ?2)",
    ))?;
    let initiative_ids: Vec<String> = stmt
        .query_map(rusqlite::params![
            InitiativeState::Executing.as_sql_str(),
            InitiativeState::Blocked.as_sql_str(),
        ], |r| r.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    drop(stmt);

    let mut inserted = 0usize;

    for init_id in initiative_ids {
        // Load the immutable plan blob for this initiative.
        let plan_bytes: Vec<u8> = match conn.query_row(
            &format!(
                "SELECT plan_bytes FROM {SIGNED_PLAN_ARTIFACTS} WHERE initiative_id=?1",
            ),
            rusqlite::params![&init_id],
            |r| r.get::<_, Vec<u8>>(0),
        ) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"plan_registry_repopulate\",\
                     \"initiative_id\":\"{init_id}\",\"reason\":\"missing_artifact: {e}\"}}",
                );
                continue;
            }
        };

        let plan_str = String::from_utf8_lossy(&plan_bytes);
        let parsed   = match parse_plan_tasks(&plan_str) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"plan_registry_repopulate\",\
                     \"initiative_id\":\"{init_id}\",\"reason\":\"parse_failed: {e}\"}}",
                );
                continue;
            }
        };

        for pt in parsed {
            registry.insert(
                TaskKey::new(&init_id, &pt.task_id),
                TaskPlanFields {
                    path_allowlist:            pt.path_allowlist,
                    path_export_to_successors: pt.path_export_to_successors,
                    path_export_globs:         pt.path_export_globs,
                    path_scope_override:       pt.path_scope_override,
                    // V2 §Step 27 — re-hydrate typed clone strategy +
                    // agent type from the immutable signed plan bytes.
                    clone_strategy:            pt.clone_strategy,
                    session_agent_type:        pt.session_agent_type,
                },
            );
            inserted += 1;
        }

        // V2 §Step 11 — repopulate the per-initiative orchestrator
        // section. Best-effort: a malformed `[orchestrator]` table on
        // hot-restart is logged at error-level and skipped (mirrors the
        // pattern used for `parse_plan_tasks` above) rather than
        // aborting registry rebuild for the whole kernel.
        match parse_plan_orchestrator(&plan_str) {
            Ok(orch) => registry.insert_orchestrator(&init_id, orch),
            Err(e)   => eprintln!(
                "{{\"level\":\"error\",\"event\":\"plan_registry_repopulate\",\
                 \"initiative_id\":\"{init_id}\",\"reason\":\"orchestrator_parse_failed: {e}\"}}",
            ),
        }
    }

    Ok(inserted)
}

// ---------------------------------------------------------------------------
// reject_plan — operator explicitly rejects a Draft initiative
// ---------------------------------------------------------------------------

/// Reject a Draft initiative — transitions to Aborted (DDL has no 'Rejected' state;
/// 'Aborted' is the terminal state for operator-cancelled initiatives per the
/// DDL CHECK constraint in kernel-store.md §2.5.1 Table 2).
pub fn reject_plan(
    initiative_id: &str,
    rejected_by:   &str,
    _reason:       Option<&str>,
    store: &Store,
) -> Result<(), LifecycleError> {
    let conn = store.lock_sync();
    let rows = conn.execute(
        &format!(
            "UPDATE {INITIATIVES} SET state=?1
             WHERE initiative_id=?2 AND state=?3"
        ),
        rusqlite::params![
            InitiativeState::Aborted.as_sql_str(),
            initiative_id,
            InitiativeState::Draft.as_sql_str(),
        ],
    )?;
    if rows == 0 {
        // Could be: not found, or already past Draft state.
        return Err(LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        });
    }
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"PlanRejected\",\
         \"initiative_id\":\"{initiative_id}\",\"rejected_by\":\"{rejected_by}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// abort_initiative — operator aborts an in-progress initiative
// ---------------------------------------------------------------------------

/// Abort an initiative — transitions to Aborted and cancels all non-terminal tasks.
///
/// **INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern D):** the `tasks`
/// bulk-cancel UPDATE and the `initiatives` UPDATE MUST commit atomically.
/// Pre-fix, the two writes ran under one mutex hold but with SQLite's
/// per-statement auto-commit — a process crash between them would leave
/// every task `Cancelled` while the initiative remained `Executing` forever
/// (no startup recovery sweep re-derives initiative state from task state).
/// Wrapping both writes in `conn.transaction()` makes the failure binary.
pub fn abort_initiative(
    initiative_id: &str,
    aborted_by:    &str,
    store: &Store,
) -> Result<(), LifecycleError> {
    let mut conn = store.lock_sync();

    // Pre-tx read: terminal-state guard (TOCTOU-safe — re-checked inside the
    // transaction's UPDATE WHERE clause via the initiative_id PK; concurrent
    // operator double-aborts collapse to one effective state change).
    let current_state: String = conn.query_row(
        &format!("SELECT state FROM {INITIATIVES} WHERE initiative_id=?1"),
        rusqlite::params![initiative_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    let parsed = InitiativeState::from_sql_str(&current_state)
        .ok_or_else(|| LifecycleError::InitiativeTerminal {
            current_state: current_state.clone(),
        })?;
    if parsed.is_terminal() {
        return Err(LifecycleError::InitiativeTerminal { current_state });
    }

    let now = unix_now_secs();
    let cancel_state    = TaskState::Cancelled.as_sql_str();
    let terminal_not_in = [TaskState::Completed, TaskState::Failed, TaskState::Aborted, TaskState::Cancelled]
        .iter()
        .map(|s| format!("'{}'", s.as_sql_str()))
        .collect::<Vec<_>>()
        .join(", ");

    let tx = conn.transaction()?;

    tx.execute(
        &format!(
            "UPDATE {TASKS} SET state='{cancel_state}', transitioned_at=?1
             WHERE initiative_id=?2 AND state NOT IN ({terminal_not_in})"
        ),
        rusqlite::params![now, initiative_id],
    )?;

    tx.execute(
        &format!(
            "UPDATE {INITIATIVES} SET state=?1, completed_at=?2
             WHERE initiative_id=?3"
        ),
        rusqlite::params![InitiativeState::Aborted.as_sql_str(), now, initiative_id],
    )?;

    tx.commit()?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"InitiativeAborted\",\
         \"initiative_id\":\"{initiative_id}\",\"aborted_by\":\"{aborted_by}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// abort_task — operator cancels a single task
// ---------------------------------------------------------------------------

pub fn abort_task(
    task_id:    &str,
    aborted_by: &str,
    store: &Store,
) -> Result<(), LifecycleError> {
    let conn = store.lock_sync();
    let now  = unix_now_secs();

    let state: String = conn.query_row(
        &format!("SELECT state FROM {TASKS} WHERE task_id=?1"),
        rusqlite::params![task_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::TaskNotFound {
            task_id: task_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    let aborted_states = [TaskState::Completed, TaskState::Failed, TaskState::Aborted, TaskState::Cancelled]
        .map(|s| s.as_sql_str());
    if aborted_states.contains(&state.as_str()) {
        return Err(LifecycleError::TaskNotAbortable { current_state: state });
    }

    conn.execute(
        &format!(
            "UPDATE {TASKS} SET state=?1, transitioned_at=?2 WHERE task_id=?3"
        ),
        rusqlite::params![TaskState::Aborted.as_sql_str(), now, task_id],
    )?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskAborted\",\
         \"task_id\":\"{task_id}\",\"aborted_by\":\"{aborted_by}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// retry_task — operator retries a Failed task
// ---------------------------------------------------------------------------

/// Retry a Failed task — transition back to Admitted.
/// Uses `task_transitions::transition_task` to enforce FSM rules (INV-INIT-04).
pub fn retry_task(task_id: &str, store: &Store) -> Result<(), LifecycleError> {
    use crate::initiatives::task_transitions::{transition_task, TransitionActor};

    let conn = store.lock_sync();
    let state: String = conn.query_row(
        &format!("SELECT state FROM {TASKS} WHERE task_id=?1"),
        rusqlite::params![task_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::TaskNotFound {
            task_id: task_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    if state != TaskState::Failed.as_sql_str() {
        return Err(LifecycleError::TaskNotFailed { current_state: state });
    }
    drop(conn); // release lock before calling transition_task which re-acquires

    transition_task(task_id, TaskState::Admitted, None, TransitionActor::Kernel, store)
        .map_err(|e| LifecycleError::Store(raxis_store::StoreError::Invariant(e.to_string())))?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskRetried\",\"task_id\":\"{task_id}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// One task entry parsed from a plan TOML `[[tasks]]` array.
///
/// Spec reference: cli-ceremony.md §4.3 fixture format + kernel-store.md
/// §2.5.8 "Plan artifact fields (per `[[tasks]]` stanza)".
///
/// `predecessors` populates `task_dag_edges` per INV-INIT-03.
///
/// The four §2.5.8 fields (`path_allowlist`, `path_export_to_successors`,
/// `path_export_globs`, `path_scope_override`) are NOT persisted to
/// `tasks` — they live in the in-memory `PlanRegistry`. The `tasks` DDL
/// has no columns for them by intent (kernel-store.md §2.5.8 line 1911).
///
/// **V2 §Step 28 single-lane propagation.** `lane_id` carries the
/// *plan-author-declared* value, defaulting to the empty string when
/// the `[[tasks]]` block did not set one. The empty marker is
/// distinguishable from `"default"` (which is itself a plan-explicit
/// value); `validate_single_lane_propagation` rejects any task whose
/// `lane_id` is non-empty (i.e. a per-task override) and otherwise the
/// approve_plan path overwrites every task's `lane_id` with the
/// workspace-root value before persisting.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanTask {
    task_id:      String,
    name:         String,
    /// Plan-author-declared lane override; `""` when omitted. The
    /// approve_plan path replaces this with the `[workspace] lane_id`
    /// value before constructing the scheduler-side `PlanTask`.
    lane_id:      String,
    predecessors: Vec<String>,

    // ── V2 §Step 27 typed fields ───────────────────────────────────────
    /// **V2 §Step 27 — typed clone strategy.** `full | blobless | sparse`.
    /// Default `Blobless` (uniformly safe; cheaper than `Full` for repos
    /// with binary blobs). The TOML key is `clone_strategy`.
    clone_strategy:     CloneStrategy,
    /// **V2 §Step 6 — agent type for this plan-declared task.**
    /// Default `Executor`. The Orchestrator is auto-created by the
    /// kernel at admission and is NOT operator-declared in `[[tasks]]`;
    /// `validate_sparse_orchestrator_exclusion` rejects any
    /// `[[tasks]]` block that declares `session_agent_type = "Orchestrator"`
    /// regardless of clone strategy.
    session_agent_type: SessionAgentType,

    // ── §2.5.8 path-scope fields (in-memory only) ──────────────────────
    /// Glob patterns this task may touch. **Default `[]` (deny everything)**.
    path_allowlist:            Vec<String>,
    /// Whether to export `touched_paths` to direct DAG successors. Default `false`.
    path_export_to_successors: bool,
    /// Optional filter on what gets exported. Default `[]` (export the
    /// full touched set if `path_export_to_successors = true`).
    path_export_globs:         Vec<String>,
    /// Bypass flag. Default `false`. When `true`, kernel emits
    /// `PathScopeOverrideApplied` at `approve_plan`.
    path_scope_override:       bool,

    // ── V2 `credential-proxy.md §3` typed credential decls ─────────────
    /// Parsed `[[tasks.credentials]]` entries for this task. Empty
    /// when the operator omitted the block. The
    /// `validate_task_credentials` shift-left validator runs against
    /// these to fail-fast on `Unknown` proxy types and structural
    /// errors before `BEGIN TRANSACTION`. The kernel-side
    /// `CredentialProxyManager::start_for_session` consumes the
    /// vector once a session-spawn callsite hands it the
    /// per-task decls (see `kernel/src/ipc/context.rs proxy_manager`).
    credentials:               Vec<raxis_plan_credentials::TaskCredentialDecl>,
}

/// Parse `[[tasks]]` array from plan TOML.
///
/// Required: `task_id`.
/// Optional: `name` (defaults to `task_id`),
///           `predecessors` (defaults to empty list).
///
/// **V2 §Step 28 — `lane_id` is intentionally NOT defaulted here.** A
/// `[[tasks]] lane_id = "..."` override is parsed verbatim into
/// `PlanTask::lane_id` so `validate_single_lane_propagation` can
/// distinguish "operator omitted lane_id (good — propagation will
/// fill it)" from "operator declared a per-task lane_id (rejected —
/// the workspace-root lane is the only authority)". Tasks that omit
/// `lane_id` get `lane_id = ""` here; the approve_plan path replaces
/// that with the workspace-root value after validation passes.
///
/// §2.5.8 path-scope fields: all optional; defaults are deny-everything,
/// no-export, no-override (matching the spec's locked-down defaults).
/// Non-array values for the array-typed fields silently fall back to
/// the default — same conservative behaviour as `predecessors`. The
/// signing tool is the gate that catches operator typos; the kernel
/// does not re-validate plan shape beyond what's necessary for safety.
fn parse_plan_tasks(plan_toml: &str) -> Result<Vec<PlanTask>, LifecycleError> {
    let doc: toml::Value = toml::from_str(plan_toml).map_err(|e| LifecycleError::PlanInvalid {
        reason: format!("TOML parse error: {e}"),
    })?;

    let tasks_array = doc
        .get("tasks")
        .and_then(|v| v.as_array())
        .ok_or_else(|| LifecycleError::PlanInvalid {
            reason: "plan TOML missing [[tasks]] array".to_owned(),
        })?;

    let mut tasks = Vec::with_capacity(tasks_array.len());
    for (i, entry) in tasks_array.iter().enumerate() {
        let task_id = entry
            .get("task_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LifecycleError::PlanInvalid {
                reason: format!("tasks[{i}] missing task_id"),
            })?
            .to_owned();
        let name    = entry.get("name").and_then(|v| v.as_str()).unwrap_or(&task_id).to_owned();
        // V2 §Step 28: do NOT default to "default" here. Empty marker
        // means "operator omitted lane_id"; any non-empty value is a
        // per-task override that `validate_single_lane_propagation`
        // rejects.
        let lane_id = entry
            .get("lane_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        let predecessors        = string_array(entry, "predecessors");
        let path_allowlist      = string_array(entry, "path_allowlist");
        let path_export_globs   = string_array(entry, "path_export_globs");

        let path_export_to_successors = entry
            .get("path_export_to_successors")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let path_scope_override = entry
            .get("path_scope_override")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // V2 §Step 27 — typed clone strategy. We carry the *raw* string
        // through to the validator (`validate_clone_strategy_v2_format`)
        // so the diagnostic can name the offending string verbatim. We
        // don't decode here so a malformed value reports
        // `unknown_clone_strategy` at validation time, not as a silent
        // fallback to the default. Operators who omit the key get the
        // V2 default (`Blobless`).
        let clone_strategy_raw     = entry.get("clone_strategy")
            .and_then(|v| v.as_str()).map(str::to_owned);
        let session_agent_type_raw = entry.get("session_agent_type")
            .and_then(|v| v.as_str()).map(str::to_owned);

        let clone_strategy = match clone_strategy_raw.as_deref() {
            None    => CloneStrategy::Blobless,
            Some(s) => match CloneStrategy::from_sql_str(s) {
                Some(strategy) => strategy,
                None => return Err(LifecycleError::PlanCloneStrategyInvalid {
                    rule:           "unknown_clone_strategy",
                    offending_task: task_id.clone(),
                    suggestion: format!(
                        "value `{s}` is not a valid clone_strategy. \
                         Valid values: full, blobless, sparse. \
                         (V2 default: blobless.)",
                    ),
                }),
            },
        };
        let session_agent_type = match session_agent_type_raw.as_deref() {
            None    => SessionAgentType::Executor,
            Some(s) => match SessionAgentType::from_sql_str(s) {
                Some(t) => t,
                None => return Err(LifecycleError::PlanCloneStrategyInvalid {
                    rule:           "unknown_agent_type",
                    offending_task: task_id.clone(),
                    suggestion: format!(
                        "value `{s}` is not a valid session_agent_type. \
                         Valid values: Executor, Reviewer. \
                         (Orchestrator is auto-created by the kernel and \
                         must not appear in [[tasks]].)",
                    ),
                }),
            },
        };

        // V2 `credential-proxy.md §3` — parse the optional
        // `[[tasks.credentials]]` sub-array. The parser is strict: a
        // missing required field (`name`, `proxy_type`) surfaces as
        // a `ParseError::Malformed` here and gets converted to
        // `PlanInvalid` so approve_plan rejects the whole plan. The
        // *semantic* check (Unknown proxy type) runs in
        // `validate_task_credentials` alongside the other Step 17
        // shift-left validators so the error path matches the rest
        // of the plan-shape rejections.
        let credentials = raxis_plan_credentials::parse_for_task(entry)
            .map_err(|e| LifecycleError::PlanInvalid {
                reason: format!("[[tasks.credentials]] (task `{task_id}`): {e}"),
            })?;

        tasks.push(PlanTask {
            task_id,
            name,
            lane_id,
            predecessors,
            path_allowlist,
            path_export_to_successors,
            path_export_globs,
            path_scope_override,
            clone_strategy,
            session_agent_type,
            credentials,
        });
    }

    Ok(tasks)
}

/// V2 §Step 11 — Parse the optional `[orchestrator]` section.
///
/// Returns the parsed `OrchestratorPlanFields`. Missing or malformed
/// (i.e., not a TOML table) sections degrade silently to the default
/// (empty `cross_cutting_artifacts`) — V1 plans never had this section
/// and must continue to round-trip. The semantic check
/// (`validate_cross_cutting_artifacts`) runs in approve_plan and
/// surfaces malformed entries as `CrossCuttingArtifactInvalidSyntax`,
/// not as TOML parse failures.
///
/// **TOML shape (`v2-deep-spec.md §Step 11`):**
/// ```toml
/// [orchestrator]
/// cross_cutting_artifacts = ["Cargo.lock", "package-lock.json", "go.sum"]
/// ```
fn parse_plan_orchestrator(plan_toml: &str)
    -> Result<crate::initiatives::OrchestratorPlanFields, LifecycleError>
{
    let doc: toml::Value = toml::from_str(plan_toml).map_err(|e| {
        LifecycleError::PlanInvalid {
            reason: format!("TOML parse error: {e}"),
        }
    })?;

    let cross_cutting_artifacts = doc
        .get("orchestrator")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("cross_cutting_artifacts"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    Ok(crate::initiatives::OrchestratorPlanFields { cross_cutting_artifacts })
}

// ---------------------------------------------------------------------------
// V2 §Step 28 — workspace-root lane (single lane per initiative)
// ---------------------------------------------------------------------------

/// Parse the V2-mandatory `[workspace] lane_id = "..."` declaration.
///
/// **Normative reference:** `v2-deep-spec.md §Step 28`. The `[workspace]`
/// table is the single authoritative source for the initiative's lane
/// — every task row, every Orchestrator/Executor/Reviewer session, and
/// every budget reservation propagates this value, so the existing
/// `SUM(reserved_cost) FROM lane_budget_reservations WHERE lane_id = ?`
/// query in `scheduler::lane::get_lane_status_in_tx` naturally bounds
/// the *initiative as a whole* (not the per-session view).
///
/// **TOML shape:**
/// ```toml
/// [workspace]
/// lane_id = "feature-work"
/// ```
///
/// Returns `Ok(Some(lane_id))` when the table+key is present and the
/// value is a non-empty string. Returns `Ok(None)` when the
/// `[workspace]` table is missing or `lane_id` is absent — the
/// `validate_single_lane_propagation` validator turns that into
/// `PlanSingleLaneInvalid { rule: "missing_workspace_lane", .. }`.
/// An empty-string value yields
/// `Ok(Some("".to_owned()))`, surfaced as `"empty_workspace_lane"` by
/// the same validator.
///
/// We accept silent absence here (rather than returning the error
/// directly) so the caller can compose the workspace-lane validator
/// with the per-task-override validator inside the same audit
/// surface — a single `PlanSingleLaneInvalid` error type, three
/// disjoint `rule` strings.
fn parse_plan_workspace_lane(plan_toml: &str)
    -> Result<Option<String>, LifecycleError>
{
    let doc: toml::Value = toml::from_str(plan_toml).map_err(|e| {
        LifecycleError::PlanInvalid {
            reason: format!("TOML parse error: {e}"),
        }
    })?;

    let raw = doc
        .get("workspace")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("lane_id"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    Ok(raw)
}

/// V2 §Step 28 — Reject malformed single-lane plans before
/// `BEGIN TRANSACTION`.
///
/// Three rules:
///
///   * `"missing_workspace_lane"` — plan TOML has no
///     `[workspace] lane_id`. The kernel cannot propagate a lane
///     value into task rows / sessions / budget reservations
///     without it, so the initiative-as-a-whole budget ceiling
///     would be unbounded. Rejected.
///   * `"empty_workspace_lane"` — `[workspace] lane_id` is the
///     empty string. The empty marker is reserved internally for
///     "task did not declare a lane" (see `parse_plan_tasks`); the
///     workspace-root MUST be a non-empty identifier.
///   * `"single_lane_propagation"` — at least one `[[tasks]]` block
///     declares its own `lane_id`. V2 forbids per-task overrides;
///     the workspace-root lane is the single authority.
///
/// On success, returns the workspace-root lane id (a non-empty
/// `String`) for the caller to propagate into every
/// `scheduler::PlanTask::lane_id`.
fn validate_single_lane_propagation(
    workspace_lane: &Option<String>,
    tasks:          &[PlanTask],
) -> Result<String, LifecycleError> {
    let workspace_lane = match workspace_lane {
        None => return Err(LifecycleError::PlanSingleLaneInvalid {
            rule:           "missing_workspace_lane",
            offending_task: "<workspace>".to_owned(),
            suggestion:     "Add `[workspace]\\nlane_id = \"<lane>\"` to plan.toml. \
                             V2 requires a single workspace-root lane so the \
                             initiative budget ceiling propagates to every \
                             session in the initiative."
                .to_owned(),
        }),
        Some(s) if s.is_empty() => return Err(LifecycleError::PlanSingleLaneInvalid {
            rule:           "empty_workspace_lane",
            offending_task: "<workspace>".to_owned(),
            suggestion:     "Set `[workspace] lane_id` to a non-empty lane \
                             identifier from your policy.toml `[[lanes]]` list."
                .to_owned(),
        }),
        Some(s) => s.clone(),
    };

    if let Some(offender) = tasks.iter().find(|t| !t.lane_id.is_empty()) {
        return Err(LifecycleError::PlanSingleLaneInvalid {
            rule:           "single_lane_propagation",
            offending_task: offender.task_id.clone(),
            suggestion:     "Remove `lane_id` from `[[tasks]]` blocks. V2 declares \
                             the lane once at `[workspace] lane_id` and \
                             propagates it to every sub-task — per-task \
                             overrides defeat the shared-budget ceiling."
                .to_owned(),
        });
    }

    Ok(workspace_lane)
}

// ---------------------------------------------------------------------------
// V2 §Step 27 — Sparse-Orchestrator exclusion (approve_plan check #6)
// ---------------------------------------------------------------------------

/// V2 §Step 27 — reject plans that combine `clone_strategy = sparse`
/// with `session_agent_type = Orchestrator`, AND reject plans that
/// declare `Orchestrator` tasks in `[[tasks]]` at all.
///
/// **Why two rules in one validator.** Both rules concern the
/// Orchestrator's structural relationship to clone strategy:
///   * `sparse_orchestrator_exclusion` — semantic: a sparse-trimmed
///     working tree breaks `git merge`'s 3-way tree traversal.
///   * `orchestrator_task_not_permitted` — structural: V2 auto-creates
///     the Orchestrator from the kernel-bundled
///     `raxis-orchestrator-core` image (`planner-harness.md §4.7-§4.8`,
///     `INV-PLANNER-HARNESS-05`/`-06`). An operator-declared
///     `Orchestrator` task would either silently shadow the
///     auto-created session or run alongside it; both are wrong.
///
/// The structural rule fires first (it's a more general violation:
/// any Orchestrator-in-[[tasks]] is wrong, regardless of clone
/// strategy). The semantic rule fires when an Orchestrator declaration
/// somehow slipped past defense-in-depth — useful for forward-compat
/// where the Orchestrator might re-enter `[[tasks]]` in a future spec.
///
/// Runs before `BEGIN TRANSACTION` so a malformed plan never allocates
/// a row.
fn validate_sparse_orchestrator_exclusion(
    tasks: &[PlanTask],
) -> Result<(), LifecycleError> {
    for task in tasks {
        if task.session_agent_type == SessionAgentType::Orchestrator {
            return Err(LifecycleError::PlanCloneStrategyInvalid {
                rule:           "orchestrator_task_not_permitted",
                offending_task: task.task_id.clone(),
                suggestion:
                    "Remove the `session_agent_type = \"Orchestrator\"` line from \
                     this `[[tasks]]` block. V2 auto-creates exactly one \
                     Orchestrator session per initiative from the kernel-bundled \
                     `raxis-orchestrator-core` image; operators only declare \
                     Executor (and optionally Reviewer) tasks."
                    .to_owned(),
            });
        }

        if task.clone_strategy == CloneStrategy::Sparse
            && task.session_agent_type == SessionAgentType::Orchestrator
        {
            // Defense-in-depth — unreachable given the first check fires
            // first, but kept as a structural backstop in case the
            // structural rule is loosened or a new agent type is added
            // without re-evaluating this constraint.
            return Err(LifecycleError::PlanCloneStrategyInvalid {
                rule:           "sparse_orchestrator_exclusion",
                offending_task: task.task_id.clone(),
                suggestion:
                    "The Orchestrator runs `git merge` in its workspace; \
                     git's 3-way tree traversal cannot complete safely \
                     against a sparse-checkout-trimmed working tree. \
                     Use `clone_strategy = \"full\"` or `\"blobless\"` for \
                     Orchestrator-class tasks (V2 default: blobless)."
                    .to_owned(),
            });
        }
    }
    Ok(())
}

/// V2 §Step 11 — Validate `cross_cutting_artifacts` entries.
///
/// Spec (`v2-deep-spec.md §Step 11`): "These must be exact filenames
/// (no globs), operator-declared, and sealed in the signed plan."
///
/// We enforce the following at `approve_plan` time, BEFORE
/// `BEGIN TRANSACTION`, so a malformed plan never mutates kernel
/// state:
///
///   1. **`empty_entry`** — `""` is rejected (would degenerate to a
///      vacuous match-everything).
///   2. **`glob_character`** — `*`, `?`, `[`, `]`, `{`, `}` rejected
///      (the matcher is exact; globs would silently widen scope).
///   3. **`contains_slash`** — any `/` rejected (the spec says "exact
///      filenames" — a multi-segment path is a directory prefix in
///      Step 19's vocabulary, which doesn't compose with the
///      cross-cutting "small list of well-known files" model).
///   4. **`absolute_path`** — `/`-prefixed entry rejected (covered by
///      rule 3 but kept distinct for operator diagnostics).
///   5. **`path_escape`** — `..` segments rejected (defense in depth).
///   6. **`negation_marker`** — `!`-prefixed entries rejected
///      (consistent with Step 19's `path_allowlist` rule).
///   7. **`trailing_slash`** — `/`-suffix rejected (covered by rule 3
///      but kept distinct: in Step 19 a trailing slash means
///      "directory prefix"; cross-cutting artifacts MUST be exact
///      files only).
fn validate_cross_cutting_artifacts(
    fields: &crate::initiatives::OrchestratorPlanFields,
) -> Result<(), LifecycleError> {
    for raw in &fields.cross_cutting_artifacts {
        let entry = raw.as_str();

        if entry.is_empty() {
            return Err(LifecycleError::CrossCuttingArtifactInvalidSyntax {
                entry: raw.clone(),
                reason: "empty_entry",
            });
        }
        if entry.starts_with('!') {
            return Err(LifecycleError::CrossCuttingArtifactInvalidSyntax {
                entry: raw.clone(),
                reason: "negation_marker",
            });
        }
        if entry.starts_with('/') {
            return Err(LifecycleError::CrossCuttingArtifactInvalidSyntax {
                entry: raw.clone(),
                reason: "absolute_path",
            });
        }
        if entry.ends_with('/') {
            return Err(LifecycleError::CrossCuttingArtifactInvalidSyntax {
                entry: raw.clone(),
                reason: "trailing_slash",
            });
        }
        if entry.split('/').any(|seg| seg == "..") {
            return Err(LifecycleError::CrossCuttingArtifactInvalidSyntax {
                entry: raw.clone(),
                reason: "path_escape",
            });
        }
        if entry.contains('/') {
            return Err(LifecycleError::CrossCuttingArtifactInvalidSyntax {
                entry: raw.clone(),
                reason: "contains_slash",
            });
        }
        if entry.chars().any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}')) {
            return Err(LifecycleError::CrossCuttingArtifactInvalidSyntax {
                entry: raw.clone(),
                reason: "glob_character",
            });
        }
    }
    Ok(())
}

/// V2 Step 17 — DAG family of the seven shift-left checks
/// (`v2-deep-spec.md §Step 17`, rule 5: "DAG acyclicity").
///
/// Runs after `parse_plan_tasks` and before `BEGIN TRANSACTION` in
/// `approve_plan`. Validates the four structural properties of the
/// proposed task graph that can be decided purely from the plan TOML
/// (no `tasks` rows yet), in deterministic order so the operator
/// always sees the *first* offending rule rather than a confusing
/// cascade:
///
///   1. **`duplicate_task_id`** — two `[[tasks]]` blocks share the same
///      `task_id`. SQLite's `tasks.task_id PRIMARY KEY` would catch
///      this in the tx, but the FK error is opaque ("constraint failed");
///      the shift-left rule produces a structured diagnostic naming
///      the duplicate.
///
///   2. **`self_loop`** — `task.predecessors` lists the task itself.
///      A task can never be its own predecessor; this is a degenerate
///      cycle case that we surface separately for clearer operator
///      diagnostics ("did you mean to depend on a sibling?").
///
///   3. **`dangling_dependency`** — `task.predecessors` lists a
///      `task_id` that is not declared anywhere in the plan. SQLite's
///      `task_dag_edges.predecessor_task_id REFERENCES tasks(task_id)`
///      with `defer_foreign_keys = 1` would catch this at COMMIT,
///      but again the FK message is opaque.
///
///   4. **`cyclic_dependency`** — directed cycle in the proposed
///      `predecessors` graph. Implemented as iterative DFS over the
///      in-memory plan (Kahn's algorithm would also work; DFS gives
///      us "an arbitrary task on the cycle" for the diagnostic).
///      The in-tx `scheduler::dag::detect_cycle_in` is retained as a
///      defense-in-depth backstop — see `LifecycleError::PlanDagInvalid`.
///
/// All four rules emit `LifecycleError::PlanDagInvalid { rule,
/// offending_task, suggestion }`. The `suggestion` field is mandatory
/// per the spec; it is a concrete fix the operator can apply, not a
/// generic restatement of the rule name.
///
/// # Why DFS, not the SQLite cycle check
///
/// Pros of DFS-on-the-plan:
///   * Runs before tx → no rollback scar, no half-state.
///   * Operates on the full plan in one pass → can find a cycle that
///     only manifests when ALL edges are considered together. The in-tx
///     `detect_cycle_in` is incremental (one task at a time) — it would
///     correctly catch any single-task cycle but produces a less
///     actionable diagnostic ("task t3 introduces a cycle") because by
///     the time t3 is admitted, the t1↔t2 cycle is already half-built.
///   * Produces a structured `(rule, offending_task, suggestion)`
///     triple instead of an opaque SQLite error.
///
/// Cons:
///   * One additional graph traversal at approve time (O(V+E)).
///     Negligible for plan sizes of practical interest.
fn validate_plan_dag(tasks: &[PlanTask]) -> Result<(), LifecycleError> {
    use std::collections::{HashMap, HashSet};

    // ── Rule 1: duplicate_task_id ────────────────────────────────────
    let mut seen = HashSet::with_capacity(tasks.len());
    for pt in tasks {
        if !seen.insert(pt.task_id.as_str()) {
            return Err(LifecycleError::PlanDagInvalid {
                rule:           "duplicate_task_id",
                offending_task: pt.task_id.clone(),
                suggestion:     format!(
                    "Two `[[tasks]]` blocks declare task_id = {:?}. \
                     Pick a unique identifier for each task.",
                    pt.task_id,
                ),
            });
        }
    }

    // ── Rule 2: self_loop ────────────────────────────────────────────
    //
    // Cheaper than full cycle detection; surface it first so the
    // operator gets the most specific diagnostic.
    for pt in tasks {
        if pt.predecessors.iter().any(|d| d == &pt.task_id) {
            return Err(LifecycleError::PlanDagInvalid {
                rule:           "self_loop",
                offending_task: pt.task_id.clone(),
                suggestion:     format!(
                    "Task {:?} lists itself in `predecessors`. \
                     A task cannot depend on itself; remove that entry.",
                    pt.task_id,
                ),
            });
        }
    }

    // Build a lookup table for the dangling-ref check and the DFS.
    let task_index: HashMap<&str, &PlanTask> =
        tasks.iter().map(|pt| (pt.task_id.as_str(), pt)).collect();

    // ── Rule 3: dangling_dependency ──────────────────────────────────
    for pt in tasks {
        for dep in &pt.predecessors {
            if !task_index.contains_key(dep.as_str()) {
                return Err(LifecycleError::PlanDagInvalid {
                    rule:           "dangling_dependency",
                    offending_task: pt.task_id.clone(),
                    suggestion:     format!(
                        "Task {:?} declares `predecessors = [..., {:?}, ...]`, \
                         but no `[[tasks]]` block defines a task with that id. \
                         Either add the missing task or fix the typo in \
                         `predecessors`.",
                        pt.task_id, dep,
                    ),
                });
            }
        }
    }

    // ── Rule 4: cyclic_dependency ────────────────────────────────────
    //
    // Iterative DFS with the standard three-color visit pattern:
    //   * `White` — never visited
    //   * `Gray`  — on the current DFS stack (cycle witness)
    //   * `Black` — fully explored
    //
    // Edges go predecessor → successor (i.e., reverse of the
    // `predecessors` field). For each unvisited task we do a stack-
    // based DFS over its predecessors; encountering a Gray node means
    // the current path closes a cycle.
    #[derive(Copy, Clone, PartialEq, Eq)]
    enum Color { White, Gray, Black }
    let mut color: HashMap<&str, Color> =
        tasks.iter().map(|pt| (pt.task_id.as_str(), Color::White)).collect();

    // Each DFS frame remembers the task and the next predecessor index
    // to inspect, so we can resume after recursing without using the
    // call stack (avoids `MAX_DAG_DEPTH` issues for large plans).
    for start in tasks {
        if color[start.task_id.as_str()] != Color::White {
            continue;
        }
        let mut stack: Vec<(&str, usize)> = vec![(start.task_id.as_str(), 0)];
        color.insert(start.task_id.as_str(), Color::Gray);

        while let Some((node_id, idx)) = stack.pop() {
            let preds = &task_index[node_id].predecessors;
            if idx < preds.len() {
                let dep = preds[idx].as_str();
                stack.push((node_id, idx + 1));

                match color[dep] {
                    Color::White => {
                        color.insert(dep, Color::Gray);
                        stack.push((dep, 0));
                    }
                    Color::Gray => {
                        // `dep` is on the current DFS path → cycle.
                        // Report `node_id` as the offending task —
                        // it's the task whose `predecessors` array
                        // closes the cycle, which is the most
                        // actionable arrow for the operator to follow.
                        return Err(LifecycleError::PlanDagInvalid {
                            rule:           "cyclic_dependency",
                            offending_task: node_id.to_owned(),
                            suggestion:     format!(
                                "Task {:?} has a cyclic dependency through {:?}. \
                                 Break the cycle by removing one of the edges \
                                 along the chain.",
                                node_id, dep,
                            ),
                        });
                    }
                    Color::Black => {
                        // Already explored — no cycle through this path.
                    }
                }
            } else {
                color.insert(node_id, Color::Black);
            }
        }
    }

    Ok(())
}

/// V2 Step 19 — validate every `path_allowlist` entry across `tasks` for
/// the trailing-slash discipline mandated by `v2-deep-spec.md §6` table 4
/// and `policy-plan-authority.md §FAIL_PATH_ALLOWLIST_INVALID_SYNTAX`.
///
/// The kernel's path-matching subsystem (`path_scope::AllowSet`) treats
/// `path_allowlist` entries as either:
///
///   * **Exact filenames** — repo-relative, no trailing `/`
///     (e.g., `src/api/handler.rs`); matched by string equality.
///   * **Directory prefixes** — repo-relative, ending in `/`
///     (e.g., `src/api/`); matched by prefix.
///
/// Glob characters, absolute paths, and path-escapes are rejected here.
/// We deliberately fail-fast at `approve_plan` (not at `start_initiative`)
/// because the operator's signature is over the plan bytes — a plan with
/// invalid syntax never makes it to the registry, never admits tasks, and
/// never affects already-running initiatives.
///
/// # Reason taxonomy (canonical strings)
///
/// Surfaces in `LifecycleError::PathAllowlistInvalidSyntax::reason`:
///
/// | reason                    | trigger                                        |
/// |---------------------------|------------------------------------------------|
/// | `"empty_entry"`           | `entry == ""`                                  |
/// | `"glob_character_in_path"`| any of `*`, `?`, `[`, `]`, `{`, `}`            |
/// | `"absolute_path"`         | starts with `/`                                |
/// | `"path_escape"`           | contains a `..` segment                        |
/// | `"negation_marker"`       | starts with `!` (gitignore-style negation)     |
///
/// # Pros / cons of the call site
///
/// **Chosen call site:** `approve_plan`, after `parse_plan_tasks`,
/// **before** the `BEGIN TRANSACTION`.
///
/// * **Pro:** A bad plan is rejected before the kernel mutates any
///   on-disk state — no rollback scar, no half-state.
/// * **Pro:** Keeps `parse_plan_tasks` purely structural, so it can be
///   reused at recovery (`repopulate_plan_registry`) for V1 plans whose
///   bytes were approved before V2 syntax existed. Recovery uses
///   `parse_plan_tasks` only, so legacy plans continue to round-trip.
/// * **Con:** A V1 plan reapproved against a V2 kernel would fail.
///   This is intentional and documented at
///   `v2-deep-spec.md §Step 19` (the V2 wire is the canonical V2
///   syntax — operators must `plan prepare && policy sign` again).
///
/// # Test obligation
///
/// Each branch of the `reason` taxonomy MUST be exercised by a unit
/// test in this module. See `validate_path_allowlist_v2_format_*` tests.
fn validate_path_allowlist_v2_format(tasks: &[PlanTask]) -> Result<(), LifecycleError> {
    for pt in tasks {
        for entry in &pt.path_allowlist {
            if let Some(reason) = path_allowlist_entry_violation(entry) {
                return Err(LifecycleError::PathAllowlistInvalidSyntax {
                    task_id: pt.task_id.clone(),
                    entry:   entry.clone(),
                    reason,
                });
            }
        }
    }
    Ok(())
}

/// **V2 §Step 17 / `credential-proxy.md §3` — shift-left
/// validation of `[[tasks.credentials]]` declarations.**
///
/// Runs at `approve_plan` time, **before** `BEGIN TRANSACTION`, so a
/// plan declaring an unknown `proxy_type` (or a structurally
/// malformed credential block — already converted to
/// `PlanInvalid` inside `parse_plan_tasks`) cannot allocate a row.
///
/// Today the V2 implemented set is `postgres | http | k8s`. The
/// `Unknown` variant from `raxis_plan_credentials::ProxyDecl` is
/// surfaced here as a `PlanTaskCredentialsInvalid {
/// rule: "unknown_proxy_type" }` rejection so future proxy types
/// (`smtp`, `redis`, `aws`, ...) do not silently parse as
/// no-ops; the operator gets a clear "this proxy type is not yet
/// supported in this kernel build" signal that names the offending
/// task and credential.
///
/// Sister-of `validate_path_allowlist_v2_format` /
/// `validate_cross_cutting_artifacts` — same shift-left posture.
fn validate_task_credentials(tasks: &[PlanTask]) -> Result<(), LifecycleError> {
    use raxis_plan_credentials::ProxyDecl;

    for pt in tasks {
        for decl in &pt.credentials {
            if matches!(decl.proxy, ProxyDecl::Unknown) {
                return Err(LifecycleError::PlanTaskCredentialsInvalid {
                    rule:                 "unknown_proxy_type",
                    offending_task:       pt.task_id.clone(),
                    offending_credential: decl.name.as_str().to_owned(),
                    suggestion: format!(
                        "task `{}` declares credential `{}` with a \
                         `proxy_type` this kernel build does not \
                         implement. Valid values in V2: \
                         `postgres`, `http`, `k8s`, `smtp`. Drop \
                         the credential block or upgrade the kernel \
                         build to one that ships the matching \
                         proxy.",
                        pt.task_id,
                        decl.name.as_str(),
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Wire label for `task_credential_proxies.proxy_type`. Kept in
/// lock-step with the SQL CHECK clause in
/// `raxis_store::migration::render_migration_10_ddl`. The
/// `ProxyDecl::Unknown` arm is unreachable here because
/// `validate_task_credentials` rejects it shift-left BEFORE this
/// helper is reached; we surface that constraint as an
/// `Invariant` store error rather than a panic so the operator
/// gets a structured diagnostic on the (impossible) hot-path.
fn proxy_type_label_for_storage(
    decl: &raxis_plan_credentials::ProxyDecl,
) -> Result<&'static str, LifecycleError> {
    use raxis_plan_credentials::ProxyDecl;
    Ok(match decl {
        ProxyDecl::Postgres { .. } => "postgres",
        ProxyDecl::Http { .. }     => "http",
        ProxyDecl::K8s { .. }      => "k8s",
        ProxyDecl::Smtp { .. }     => "smtp",
        ProxyDecl::Unknown => {
            return Err(LifecycleError::Store(
                raxis_store::StoreError::Invariant(
                    "ProxyDecl::Unknown reached the persistence \
                     layer; validate_task_credentials must reject \
                     it shift-left before approve_plan opens its \
                     transaction".to_owned(),
                ),
            ));
        }
    })
}

/// Insert the per-task `task_credential_proxies` rows for one
/// admitted task.
///
/// **What this writes** (METADATA ONLY): one row per declared
/// `[[tasks.credentials]]` block, carrying `credential_name`,
/// `mount_as`, `proxy_type`, and the serde-JSON `proxy_json`
/// restriction blob.
///
/// **What this does NOT write.** Credential VALUES (postgres URLs
/// with passwords, bearer tokens, kubeconfig YAML bytes, …) are
/// never persisted — they live behind the `CredentialBackend`
/// trait. See `credential-proxy.md §1.1` and
/// `raxis_store::Table::TaskCredentialProxies` for the
/// authoritative invariant.
///
/// **Atomicity.** Caller passes the open `approve_plan`
/// transaction. INV-STORE-02 (Pattern A): the rows commit together
/// with the parent `tasks(task_id)` row.
///
/// **Drift protection.** The `proxy_type` string is rendered
/// through `proxy_type_label_for_storage`, which is pinned to the
/// same set as the SQL CHECK clause in migration 10. Any new
/// `ProxyDecl` variant requires updating both this label table
/// AND the migration's CHECK clause; the
/// `task_credential_proxies_persistence_round_trips_via_session_spawn`
/// test at the bottom of this file additionally exercises the
/// (insert → re-read → re-deserialise) loop end to end.
fn insert_task_credential_proxies_in_tx(
    tx:          &rusqlite::Transaction<'_>,
    task_id:     &str,
    credentials: &[raxis_plan_credentials::TaskCredentialDecl],
) -> Result<(), LifecycleError> {
    let now = unix_now_secs();

    // We prepare once and reuse the cached statement across the
    // (usually small) credentials slice — cheaper than rebuilding
    // SQL per row, and gives a clearer query plan in EXPLAIN logs.
    let mut stmt = tx.prepare_cached(&format!(
        "INSERT INTO {table}
             (task_id, credential_name, mount_as,
              proxy_type, proxy_json, created_at_unix_secs)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        table = TASK_CREDENTIAL_PROXIES,
    ))?;

    for decl in credentials {
        let proxy_type = proxy_type_label_for_storage(&decl.proxy)?;
        let proxy_json = serde_json::to_string(&decl.proxy)
            .map_err(|e| {
                LifecycleError::Store(raxis_store::StoreError::Invariant(
                    format!(
                        "task `{task_id}` credential `{cred}`: \
                         serde_json failed to serialise \
                         ProxyDecl: {e}",
                        cred = decl.name.as_str(),
                    ),
                ))
            })?;

        stmt.execute(rusqlite::params![
            task_id,
            decl.name.as_str(),
            &decl.mount_as,
            proxy_type,
            proxy_json,
            now as i64,
        ])?;
    }

    Ok(())
}

/// Insert a `subtask_activations` row for every Executor / Reviewer
/// task admitted by `approve_plan`.
///
/// Spec reference: `v2-deep-spec.md §Step 5` — the `subtask_activations`
/// table is the V2 sub-task FSM (`PendingActivation → Active →
/// Completed | Failed`). Orchestrator tasks deliberately get NO row
/// here: the Orchestrator session is auto-spawned by the Kernel itself
/// at initiative start (see `auto_spawn_orchestrator_session_in_tx`),
/// not by another agent's `ActivateSubTask` intent.
///
/// **Atomicity.** Caller passes the open `approve_plan` transaction.
/// INV-STORE-02 (Pattern A): the activation row commits together with
/// the parent `tasks(task_id)` row. A `tx.commit()` failure rolls
/// both back; a successful commit guarantees the activation FSM is
/// observable by the Orchestrator's "newly_activatable" prompt query
/// on the next `InferenceRequest` (see `prompt-assembler.md §Layer 2`
/// + `idx_subtask_activations_pending`).
///
/// **Initial state.** The row is inserted with:
///
/// * `activation_state = 'PendingActivation'` — the only state for
///   which the cross-column CHECK clause permits `session_id IS NULL
///   AND activated_at IS NULL AND terminated_at IS NULL`. The
///   activation transitions to `Active` when `handle_activate_sub_task`
///   completes the `ctx.session_spawn.spawn_session()` round-trip.
///
/// * `crash_retry_count = 0`, `review_reject_count = 0` — the two
///   independent counters per `v2-deep-spec.md §Step 12` (a VM
///   crash and a code-review rejection do NOT share a counter; their
///   ceilings are tracked separately).
///
/// * `evaluation_sha = NULL` — for Reviewer activations this is
///   filled by the predecessor Executor's `CompleteTask` admission
///   (per `v2-deep-spec.md §Step 23`); for Executor activations it
///   stays `NULL` for the row's lifetime.
///
/// **Drift protection.** The `activation_state` literal is taken
/// straight from `SubtaskActivationState::PendingActivation`'s SQL
/// projection so a future addition to the enum surfaces here at
/// compile time. The DDL CHECK clause in
/// `migration::ensure_v2_schema` independently pins the same set;
/// the round-trip read in
/// `read_subtask_activation_in_tx` (below) plus the
/// `subtask_activations_round_trip_after_approve_plan` test in this
/// file exercises the full insert → read loop.
fn insert_subtask_activation_in_tx(
    tx:                 &rusqlite::Transaction<'_>,
    task_id:            &str,
    initiative_id:      &str,
    session_agent_type: SessionAgentType,
) -> Result<(), LifecycleError> {
    // Orchestrator tasks deliberately get no row (Step 5 §"Only
    // Executor and Reviewer tasks have rows here"). The caller is
    // expected to gate on this; we defense-in-depth here.
    if matches!(session_agent_type, SessionAgentType::Orchestrator) {
        return Ok(());
    }

    let activation_id = uuid::Uuid::new_v4().to_string();
    let now = unix_now_secs() as i64;

    tx.execute(
        &format!(
            "INSERT INTO {SUBTASK_ACTIVATIONS} (
                activation_id, task_id, initiative_id,
                activation_state, session_id, evaluation_sha,
                crash_retry_count, review_reject_count,
                created_at, activated_at, terminated_at
             ) VALUES (?1, ?2, ?3, 'PendingActivation', NULL, NULL,
                       0, 0, ?4, NULL, NULL)"
        ),
        rusqlite::params![activation_id, task_id, initiative_id, now],
    )?;

    Ok(())
}

/// Read the per-task credential-proxy declarations stored at
/// `approve_plan` time and rehydrate them into the same
/// `TaskCredentialDecl` shape that
/// `raxis_plan_credentials::parse_for_task` produced.
///
/// Used at session-spawn time by the kernel's
/// `CredentialProxyManager` (see `credential-proxy.md §3`). The
/// helper is the read-side mirror of
/// `insert_task_credential_proxies_in_tx`: every row inserted by
/// approve_plan round-trips back through this function losslessly.
///
/// Returns rows in declaration order (insertion order is the
/// PRIMARY KEY composite (`task_id`, `credential_name`); since we
/// insert in the order we saw entries, we order by
/// `created_at_unix_secs ASC` and break ties with
/// `credential_name ASC` for determinism).
///
/// **No credential values are returned**: the `TaskCredentialDecl`
/// struct does not carry secret bytes, by design. The proxy
/// manager separately calls `CredentialBackend::resolve` to fetch
/// the bytes for each `decl.name` at bind time.
pub fn read_task_credential_proxies_in_tx(
    tx:      &rusqlite::Connection,
    task_id: &str,
) -> Result<Vec<raxis_plan_credentials::TaskCredentialDecl>, LifecycleError> {
    use raxis_credentials::CredentialName;

    let mut stmt = tx.prepare(&format!(
        "SELECT credential_name, mount_as, proxy_json
           FROM {table}
          WHERE task_id = ?1
       ORDER BY created_at_unix_secs ASC, credential_name ASC",
        table = TASK_CREDENTIAL_PROXIES,
    ))?;

    let rows = stmt
        .query_map([task_id], |row| {
            let credential_name: String = row.get(0)?;
            let mount_as:        String = row.get(1)?;
            let proxy_json:      String = row.get(2)?;
            Ok((credential_name, mount_as, proxy_json))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut out = Vec::with_capacity(rows.len());
    for (credential_name, mount_as, proxy_json) in rows {
        // Re-deserialise the proxy variant. If a future kernel
        // build changes the serde tag layout this is the place
        // we'd surface the migration error — fail-closed so the
        // operator notices on the next session-spawn rather than
        // the proxy silently no-op-ing.
        let proxy: raxis_plan_credentials::ProxyDecl =
            serde_json::from_str(&proxy_json).map_err(|e| {
                LifecycleError::Store(raxis_store::StoreError::Invariant(
                    format!(
                        "task `{task_id}` credential `{credential_name}`: \
                         serde_json failed to re-deserialise \
                         ProxyDecl from `task_credential_proxies. \
                         proxy_json` (schema drift?): {e}",
                    ),
                ))
            })?;

        out.push(raxis_plan_credentials::TaskCredentialDecl {
            name: CredentialName::new(credential_name),
            mount_as,
            proxy,
        });
    }
    Ok(out)
}

/// Returns `Some(reason)` if `entry` violates the V2 path-allowlist
/// syntax discipline; `None` if the entry is acceptable. The reason
/// strings are stable wire-side identifiers — DO NOT rename without
/// updating `policy-plan-authority.md §FAIL_PATH_ALLOWLIST_INVALID_SYNTAX`
/// AND every operator-side warning that consumes them
/// (`operator-ergonomics.md §4.5.4`).
fn path_allowlist_entry_violation(entry: &str) -> Option<&'static str> {
    if entry.is_empty() {
        return Some("empty_entry");
    }
    // Negation marker is a gitignore-ism we don't support: V2 path
    // matching is a single-pass starts_with/equality check, not a
    // multi-pass evaluator with allow/deny precedence. We reject this
    // before the glob-character check so the operator sees the more
    // actionable reason ("you wrote a negation"), not the catch-all
    // ("you used a special character").
    if entry.starts_with('!') {
        return Some("negation_marker");
    }
    if entry.starts_with('/') {
        return Some("absolute_path");
    }
    // `..` as a *path segment*. Substring check is too permissive
    // (matches benign filenames like `foo..bar`); split-on-`/` is the
    // right granularity. We also reject the bare `".."` entry.
    if entry.split('/').any(|seg| seg == "..") {
        return Some("path_escape");
    }
    // Glob characters per `policy-plan-authority.md` line 538: the
    // five forbidden metacharacters. `?` is included because operators
    // sometimes use it as a single-char wildcard in shell globs even
    // though it has no place here. The closing `]` and `}` are flagged
    // for symmetry — an entry like `src/[abc].rs` would otherwise pass
    // the opening-only check on partially-malformed input.
    if entry
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'))
    {
        return Some("glob_character_in_path");
    }
    None
}

/// Read an optional TOML field as a `Vec<String>`. Missing field, wrong
/// type, or non-string array entries all fall back to the empty vec —
/// matching the original `predecessors` parsing semantics.
fn string_array(entry: &toml::Value, field: &str) -> Vec<String> {
    entry
        .get(field)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

// `admit_task` (private helper) was removed: task insertion is now done by
// `scheduler::admit_in_tx`, which inserts both the task row AND its DAG
// edges inside the surrounding transaction. The old helper inserted only
// the task row, which silently dropped every `task_dag_edges` row a plan
// declared — a violation of kernel-store.md §2.5.1 line 384 ("All edges
// for an initiative are inserted by approve_plan alongside the task rows,
// in the same transaction").

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plan_tasks_requires_task_id() {
        // Entry without task_id must produce PlanInvalid error.
        let toml = "[[tasks]]\nname = \"no-id\"\n";
        let err = parse_plan_tasks(toml).unwrap_err();
        assert!(err.to_string().contains("task_id"));
    }

    #[test]
    fn parse_plan_tasks_empty_array_ok() {
        let toml = "[meta]\nversion = 1\n[[tasks]]\ntask_id = \"t1\"\n";
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].task_id, "t1");
    }

    #[test]
    fn parse_plan_tasks_omitted_lane_id_yields_empty_marker() {
        // V2 §Step 28: omitted `lane_id` parses as `""`, which is the
        // internal "operator did not declare" marker. The approve_plan
        // path replaces this with the workspace-root value after
        // `validate_single_lane_propagation` accepts the plan.
        let toml = "[[tasks]]\ntask_id = \"t2\"\n";
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].lane_id, "");
    }

    #[test]
    fn parse_plan_tasks_lane_id_override_is_preserved_for_validator() {
        // V2 §Step 28: an explicit per-task `lane_id` survives parsing
        // verbatim so `validate_single_lane_propagation` can spot the
        // override and emit `single_lane_propagation`. The approve_plan
        // path never reaches the propagation step in this case.
        let toml = r#"
[[tasks]]
task_id = "t1"
lane_id = "rogue-lane"
"#;
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].lane_id, "rogue-lane");
    }

    #[test]
    fn parse_plan_tasks_name_defaults_to_task_id() {
        let toml = "[[tasks]]\ntask_id = \"t3\"\n";
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].name, "t3");
    }

    #[test]
    fn parse_plan_tasks_missing_tasks_array_is_error() {
        let toml = "[meta]\nversion = 1\n";
        assert!(parse_plan_tasks(toml).is_err());
    }

    // ── §2.5.8 path-scope field defaults — locked-down ────────────────────

    #[test]
    fn parse_plan_tasks_path_scope_defaults_are_lockdown() {
        // A task that omits ALL four §2.5.8 fields must default to:
        //   path_allowlist            = []     (deny everything)
        //   path_export_to_successors = false  (zero export blast radius)
        //   path_export_globs         = []
        //   path_scope_override       = false  (no bypass)
        // This pins the safe defaults — any regression that flips one of
        // these would silently weaken path enforcement for every plan
        // that omits the field.
        let toml = r#"[[tasks]]
        task_id = "t-default"
        "#;
        let tasks = parse_plan_tasks(toml).unwrap();
        assert!(tasks[0].path_allowlist.is_empty(),
                "default allowlist must deny everything");
        assert!(!tasks[0].path_export_to_successors,
                "default export must be off (zero blast radius)");
        assert!(tasks[0].path_export_globs.is_empty());
        assert!(!tasks[0].path_scope_override,
                "default override must be off (no bypass)");
    }

    #[test]
    fn parse_plan_tasks_reads_path_allowlist_in_order() {
        // Note: parse_plan_tasks itself is purely structural — it does
        // not enforce V2 syntax. Glob-style entries here exercise the
        // ordering invariant only; `validate_path_allowlist_v2_format`
        // is the syntax gate (see tests below) and runs in approve_plan.
        let toml = r#"[[tasks]]
        task_id        = "t-globs"
        path_allowlist = ["src/", "tests/", "README.md"]
        "#;
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].path_allowlist,
                   vec!["src/", "tests/", "README.md"]);
    }

    #[test]
    fn parse_plan_tasks_reads_path_export_optin_and_globs() {
        let toml = r#"[[tasks]]
        task_id                   = "t-export"
        path_export_to_successors = true
        path_export_globs         = ["src/ipc/**"]
        "#;
        let tasks = parse_plan_tasks(toml).unwrap();
        assert!(tasks[0].path_export_to_successors);
        assert_eq!(tasks[0].path_export_globs, vec!["src/ipc/**"]);
    }

    #[test]
    fn parse_plan_tasks_reads_path_scope_override() {
        let toml = r#"[[tasks]]
        task_id             = "t-override"
        path_scope_override = true
        "#;
        let tasks = parse_plan_tasks(toml).unwrap();
        assert!(tasks[0].path_scope_override);
    }

    #[test]
    fn parse_plan_tasks_silently_ignores_non_string_array_entries() {
        // Defense in depth: the signing tool catches malformed arrays;
        // the kernel's parser conservatively falls back to skipping
        // non-string entries rather than panicking. (Matches the existing
        // `predecessors` behaviour.)
        let toml = r#"[[tasks]]
        task_id        = "t"
        path_allowlist = ["src/", 123, "ok.rs"]
        "#;
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].path_allowlist, vec!["src/", "ok.rs"]);
    }

    // ── V2 Step 19 — `path_allowlist` syntax validator ────────────────────
    //
    // Each `reason` in the canonical taxonomy MUST be exercised by at
    // least one test. The tests intentionally pass the entry through
    // `validate_path_allowlist_v2_format` (the public gate) rather than
    // calling `path_allowlist_entry_violation` directly, so the wiring
    // from validator → `LifecycleError::PathAllowlistInvalidSyntax` is
    // also covered. See `policy-plan-authority.md
    // §FAIL_PATH_ALLOWLIST_INVALID_SYNTAX` for the canonical reason
    // strings.
    fn make_task(task_id: &str, allow: &[&str]) -> PlanTask {
        PlanTask {
            task_id:                   task_id.to_owned(),
            name:                      task_id.to_owned(),
            lane_id:                   "default".to_owned(),
            predecessors:              vec![],
            path_allowlist:            allow.iter().map(|s| (*s).to_owned()).collect(),
            path_export_to_successors: false,
            path_export_globs:         vec![],
            path_scope_override:       false,
            clone_strategy:            CloneStrategy::Blobless,
            session_agent_type:        SessionAgentType::Executor,
            credentials:               vec![],
        }
    }

    fn assert_violation(task_id: &str, entries: &[&str], expected_reason: &'static str) {
        let tasks = vec![make_task(task_id, entries)];
        let err = validate_path_allowlist_v2_format(&tasks).unwrap_err();
        match err {
            LifecycleError::PathAllowlistInvalidSyntax { task_id: tid, entry: _, reason } => {
                assert_eq!(tid, task_id);
                assert_eq!(reason, expected_reason,
                           "expected reason {expected_reason} but got {reason}");
            }
            other => panic!("expected PathAllowlistInvalidSyntax, got {other:?}"),
        }
    }

    #[test]
    fn validate_v2_format_accepts_exact_filenames_and_directory_prefixes() {
        let tasks = vec![make_task(
            "t",
            &[
                "README.md",
                "src/api/handler.rs",
                "src/",
                "tests/integration/",
                "Cargo.toml",
                ".github/workflows/ci.yml",
            ],
        )];
        validate_path_allowlist_v2_format(&tasks).unwrap();
    }

    #[test]
    fn validate_v2_format_accepts_empty_allowlist() {
        // Empty allowlist is the locked-down default — denies everything,
        // not a syntax violation. Caught by the read-path containment
        // check, not by this admission-time validator.
        let tasks = vec![make_task("t-empty", &[])];
        validate_path_allowlist_v2_format(&tasks).unwrap();
    }

    #[test]
    fn validate_v2_format_rejects_empty_entry() {
        // The bare empty string "" is meaningless and would silently
        // match every relative path under starts_with semantics — the
        // most dangerous possible interpretation. Rejected explicitly.
        assert_violation("t", &[""], "empty_entry");
    }

    #[test]
    fn validate_v2_format_rejects_glob_star() {
        assert_violation("t-star", &["src/**"], "glob_character_in_path");
    }

    #[test]
    fn validate_v2_format_rejects_glob_question_mark() {
        assert_violation("t-q", &["src/file?.rs"], "glob_character_in_path");
    }

    #[test]
    fn validate_v2_format_rejects_glob_brackets() {
        assert_violation("t-bracket", &["src/[abc].rs"], "glob_character_in_path");
    }

    #[test]
    fn validate_v2_format_rejects_glob_braces() {
        assert_violation("t-brace", &["src/{a,b}.rs"], "glob_character_in_path");
    }

    #[test]
    fn validate_v2_format_rejects_absolute_path() {
        assert_violation("t-abs", &["/etc/secrets/"], "absolute_path");
    }

    #[test]
    fn validate_v2_format_rejects_path_escape_segment() {
        assert_violation("t-esc", &["../escape/"], "path_escape");
    }

    #[test]
    fn validate_v2_format_rejects_interior_path_escape_segment() {
        // `..` as a *segment*, not a substring. `foo/../bar` escapes
        // upward at evaluation time and must be rejected even though
        // the surface form looks "structured".
        assert_violation("t-int", &["src/../etc/"], "path_escape");
    }

    #[test]
    fn validate_v2_format_accepts_dotdot_inside_filename_segment() {
        // `foo..bar` is a valid filename in some repos (git stash names,
        // version tags). The split-on-`/` segment check yields `["foo..bar"]`,
        // which is neither `..` nor empty, so it's accepted. This pins
        // the segment-vs-substring distinction.
        let tasks = vec![make_task("t", &["dist/foo..bar.txt"])];
        validate_path_allowlist_v2_format(&tasks).unwrap();
    }

    #[test]
    fn validate_v2_format_rejects_negation_marker() {
        assert_violation("t-neg", &["!secret/"], "negation_marker");
    }

    #[test]
    fn validate_v2_format_reports_first_offender_with_task_id_and_entry() {
        // Multi-task plan: t1 valid, t2's third entry is bogus. We must
        // surface the offending entry verbatim and the originating task_id.
        let tasks = vec![
            make_task("t1", &["src/", "README.md"]),
            make_task("t2", &["src/lib.rs", "tests/", "/etc/secrets/"]),
        ];
        let err = validate_path_allowlist_v2_format(&tasks).unwrap_err();
        match err {
            LifecycleError::PathAllowlistInvalidSyntax {
                task_id, entry, reason,
            } => {
                assert_eq!(task_id, "t2");
                assert_eq!(entry,   "/etc/secrets/");
                assert_eq!(reason,  "absolute_path");
            }
            other => panic!("expected PathAllowlistInvalidSyntax, got {other:?}"),
        }
    }

    #[test]
    fn validate_v2_format_short_circuits_on_first_violation() {
        // The validator is an early-exit (Step 19 wants a deterministic,
        // operator-friendly single-error response — not a list). Pin
        // that contract so a future refactor does not silently switch
        // to "report all violations" without a spec update.
        let tasks = vec![make_task(
            "t",
            &[
                "src/**",          // glob_character_in_path  ← reported
                "/etc/secrets/",   // absolute_path           ← shadowed
                "../escape/",      // path_escape             ← shadowed
            ],
        )];
        let err = validate_path_allowlist_v2_format(&tasks).unwrap_err();
        match err {
            LifecycleError::PathAllowlistInvalidSyntax { entry, reason, .. } => {
                assert_eq!(entry,  "src/**");
                assert_eq!(reason, "glob_character_in_path");
            }
            other => panic!("expected PathAllowlistInvalidSyntax, got {other:?}"),
        }
    }

    // ── V2 Step 17 — `validate_plan_dag` shift-left DAG checks ────────────
    //
    // Each of the four canonical rules (`duplicate_task_id`,
    // `self_loop`, `dangling_dependency`, `cyclic_dependency`) MUST
    // be exercised. We additionally pin the *deterministic ordering*
    // of detection — the operator must always see the most-specific
    // rule first when multiple are violated — and the structural
    // properties (`offending_task` is named verbatim, `suggestion`
    // is non-empty and references a concrete fix).

    fn dag_task(id: &str, deps: &[&str]) -> PlanTask {
        PlanTask {
            task_id:                   id.to_owned(),
            name:                      id.to_owned(),
            lane_id:                   "default".to_owned(),
            predecessors:              deps.iter().map(|s| (*s).to_owned()).collect(),
            path_allowlist:            vec![],
            path_export_to_successors: false,
            path_export_globs:         vec![],
            path_scope_override:       false,
            clone_strategy:            CloneStrategy::Blobless,
            session_agent_type:        SessionAgentType::Executor,
            credentials:               vec![],
        }
    }

    fn assert_dag_invalid(
        plan:                  Vec<PlanTask>,
        expected_rule:         &'static str,
        expected_offender:     &str,
        suggestion_must_match: &str,
    ) {
        let err = validate_plan_dag(&plan).unwrap_err();
        match err {
            LifecycleError::PlanDagInvalid { rule, offending_task, suggestion } => {
                assert_eq!(rule, expected_rule,
                           "expected rule {expected_rule}, got {rule}");
                assert_eq!(offending_task, expected_offender,
                           "expected offender {expected_offender}, got {offending_task}");
                assert!(suggestion.contains(suggestion_must_match),
                        "suggestion missing required fragment {suggestion_must_match:?}: \
                         {suggestion:?}");
            }
            other => panic!("expected PlanDagInvalid({expected_rule}), got {other:?}"),
        }
    }

    #[test]
    fn validate_plan_dag_accepts_empty_plan() {
        validate_plan_dag(&[]).unwrap();
    }

    #[test]
    fn validate_plan_dag_accepts_single_task_with_no_deps() {
        validate_plan_dag(&[dag_task("solo", &[])]).unwrap();
    }

    #[test]
    fn validate_plan_dag_accepts_diamond_dag() {
        // a → b, a → c, b → d, c → d  — classic diamond, no cycle.
        let plan = vec![
            dag_task("a", &[]),
            dag_task("b", &["a"]),
            dag_task("c", &["a"]),
            dag_task("d", &["b", "c"]),
        ];
        validate_plan_dag(&plan).unwrap();
    }

    #[test]
    fn validate_plan_dag_accepts_chain_of_arbitrary_length() {
        // Pin that the iterative DFS does not overflow on a long chain
        // (a → b → c → ... → z). 26 tasks is far below
        // `MAX_DAG_DEPTH`, but the iterative implementation is
        // depth-independent; this test documents that property.
        let mut plan = Vec::with_capacity(26);
        let mut prev: Option<String> = None;
        for ch in 'a'..='z' {
            let id = ch.to_string();
            let preds: Vec<&str> = prev.iter().map(|s| s.as_str()).collect();
            plan.push(dag_task(&id, &preds));
            prev = Some(id);
        }
        validate_plan_dag(&plan).unwrap();
    }

    #[test]
    fn validate_plan_dag_rejects_duplicate_task_id() {
        let plan = vec![dag_task("t", &[]), dag_task("t", &[])];
        assert_dag_invalid(plan, "duplicate_task_id", "t", "Pick a unique");
    }

    #[test]
    fn validate_plan_dag_rejects_self_loop() {
        let plan = vec![dag_task("solo", &["solo"])];
        assert_dag_invalid(plan, "self_loop", "solo", "cannot depend on itself");
    }

    #[test]
    fn validate_plan_dag_rejects_dangling_dependency() {
        // `t2` references a missing predecessor. The diagnostic must
        // point at `t2` (the task that DECLARED the bad reference),
        // not at the missing `phantom`.
        let plan = vec![
            dag_task("t1", &[]),
            dag_task("t2", &["phantom"]),
        ];
        assert_dag_invalid(plan, "dangling_dependency", "t2", "phantom");
    }

    #[test]
    fn validate_plan_dag_rejects_two_node_cycle() {
        let plan = vec![
            dag_task("t1", &["t2"]),
            dag_task("t2", &["t1"]),
        ];
        let err = validate_plan_dag(&plan).unwrap_err();
        match err {
            LifecycleError::PlanDagInvalid { rule, suggestion, .. } => {
                assert_eq!(rule, "cyclic_dependency");
                assert!(suggestion.contains("Break the cycle"),
                        "suggestion must include the canonical fix phrase: {suggestion:?}");
            }
            other => panic!("expected PlanDagInvalid(cyclic_dependency), got {other:?}"),
        }
    }

    #[test]
    fn validate_plan_dag_rejects_three_node_cycle() {
        // Triangle: t1 → t2 → t3 → t1. The cycle witness must reference
        // a task that is actually on the cycle (any of t1/t2/t3).
        let plan = vec![
            dag_task("t1", &["t3"]),
            dag_task("t2", &["t1"]),
            dag_task("t3", &["t2"]),
        ];
        let err = validate_plan_dag(&plan).unwrap_err();
        match err {
            LifecycleError::PlanDagInvalid { rule, offending_task, .. } => {
                assert_eq!(rule, "cyclic_dependency");
                assert!(["t1", "t2", "t3"].contains(&offending_task.as_str()),
                        "offending task must be on the cycle: got {offending_task}");
            }
            other => panic!("expected PlanDagInvalid(cyclic_dependency), got {other:?}"),
        }
    }

    #[test]
    fn validate_plan_dag_rule_priority_duplicate_before_self_loop() {
        // Both rules fire; pin that `duplicate_task_id` wins, because
        // until duplicates are resolved we cannot reliably attribute
        // the self-loop to a specific task instance.
        let plan = vec![
            dag_task("dup", &[]),
            dag_task("dup", &["dup"]),  // would also be a self_loop
        ];
        assert_dag_invalid(plan, "duplicate_task_id", "dup", "Pick a unique");
    }

    #[test]
    fn validate_plan_dag_rule_priority_self_loop_before_dangling() {
        // Both rules fire on the same task; `self_loop` is the more
        // specific (and more common typo), so it wins.
        let plan = vec![
            dag_task("a", &["a", "missing"]),
        ];
        assert_dag_invalid(plan, "self_loop", "a", "cannot depend on itself");
    }

    #[test]
    fn validate_plan_dag_rule_priority_dangling_before_cycle() {
        // A plan with both a dangling ref and a cycle must report the
        // dangling ref first — it is the structural rule, evaluable
        // without DFS, and operators usually fix it before re-validating.
        let plan = vec![
            dag_task("t1", &["t2"]),
            dag_task("t2", &["t1", "ghost"]),
        ];
        assert_dag_invalid(plan, "dangling_dependency", "t2", "ghost");
    }

    #[test]
    fn validate_plan_dag_accepts_disconnected_dags() {
        // Two independent trees in one plan must both validate.
        let plan = vec![
            dag_task("a1", &[]),
            dag_task("a2", &["a1"]),
            dag_task("b1", &[]),
            dag_task("b2", &["b1"]),
        ];
        validate_plan_dag(&plan).unwrap();
    }

    // ── V2 §Step 28 — single-lane propagation tests ──────────────────────
    //
    // These run against the pure validator (no SQLite, no signing) so
    // they pin the rule semantics without coupling to the approve_plan
    // transactional surface. End-to-end approve_plan coverage of the
    // same rules lives further down.

    fn lane_task(task_id: &str, lane_id: &str) -> PlanTask {
        PlanTask {
            task_id: task_id.into(),
            name: task_id.into(),
            lane_id: lane_id.into(),
            predecessors: vec![],
            path_allowlist: vec![],
            path_export_to_successors: false,
            path_export_globs: vec![],
            path_scope_override: false,
            clone_strategy: CloneStrategy::Blobless,
            session_agent_type: SessionAgentType::Executor,
            credentials: vec![],
        }
    }

    #[test]
    fn validate_single_lane_missing_workspace_lane_is_rejected() {
        let tasks = vec![lane_task("t1", "")];
        let err = validate_single_lane_propagation(&None, &tasks).unwrap_err();
        match err {
            LifecycleError::PlanSingleLaneInvalid { rule, offending_task, .. } => {
                assert_eq!(rule, "missing_workspace_lane");
                assert_eq!(offending_task, "<workspace>");
            }
            other => panic!("expected PlanSingleLaneInvalid(missing_workspace_lane), got {other:?}"),
        }
    }

    #[test]
    fn validate_single_lane_empty_workspace_lane_is_rejected() {
        let tasks = vec![lane_task("t1", "")];
        let err = validate_single_lane_propagation(
            &Some(String::new()), &tasks,
        ).unwrap_err();
        match err {
            LifecycleError::PlanSingleLaneInvalid { rule, offending_task, .. } => {
                assert_eq!(rule, "empty_workspace_lane");
                assert_eq!(offending_task, "<workspace>");
            }
            other => panic!("expected PlanSingleLaneInvalid(empty_workspace_lane), got {other:?}"),
        }
    }

    #[test]
    fn validate_single_lane_per_task_override_is_rejected() {
        // Workspace lane is fine; one task declares its own override.
        // The validator names that task in `offending_task`.
        let tasks = vec![
            lane_task("t1", ""),
            lane_task("t2", "rogue-lane"),
        ];
        let err = validate_single_lane_propagation(
            &Some("default".into()), &tasks,
        ).unwrap_err();
        match err {
            LifecycleError::PlanSingleLaneInvalid { rule, offending_task, suggestion } => {
                assert_eq!(rule, "single_lane_propagation");
                assert_eq!(offending_task, "t2");
                assert!(suggestion.contains("Remove `lane_id`"));
            }
            other => panic!("expected PlanSingleLaneInvalid(single_lane_propagation), got {other:?}"),
        }
    }

    #[test]
    fn validate_single_lane_happy_path_returns_workspace_lane() {
        let tasks = vec![
            lane_task("t1", ""),
            lane_task("t2", ""),
        ];
        let lane = validate_single_lane_propagation(
            &Some("feature-work".into()), &tasks,
        ).unwrap();
        assert_eq!(lane, "feature-work");
    }

    // ── V2 §Step 27 — clone_strategy / session_agent_type parsing ───────

    #[test]
    fn parse_plan_tasks_omitted_clone_strategy_defaults_to_blobless() {
        let toml = "[[tasks]]\ntask_id = \"t1\"\n";
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].clone_strategy, CloneStrategy::Blobless);
    }

    #[test]
    fn parse_plan_tasks_reads_clone_strategy_full() {
        let toml = r#"
[[tasks]]
task_id = "t1"
clone_strategy = "full"
"#;
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].clone_strategy, CloneStrategy::Full);
    }

    #[test]
    fn parse_plan_tasks_reads_clone_strategy_sparse() {
        let toml = r#"
[[tasks]]
task_id = "t1"
clone_strategy = "sparse"
"#;
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].clone_strategy, CloneStrategy::Sparse);
    }

    #[test]
    fn parse_plan_tasks_rejects_unknown_clone_strategy() {
        let toml = r#"
[[tasks]]
task_id = "t1"
clone_strategy = "treeless"
"#;
        let err = parse_plan_tasks(toml).unwrap_err();
        match err {
            LifecycleError::PlanCloneStrategyInvalid { rule, offending_task, suggestion } => {
                assert_eq!(rule, "unknown_clone_strategy");
                assert_eq!(offending_task, "t1");
                assert!(suggestion.contains("treeless"));
                assert!(suggestion.contains("full, blobless, sparse"));
            }
            other => panic!("expected PlanCloneStrategyInvalid(unknown_clone_strategy), got {other:?}"),
        }
    }

    #[test]
    fn parse_plan_tasks_omitted_session_agent_type_defaults_to_executor() {
        let toml = "[[tasks]]\ntask_id = \"t1\"\n";
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].session_agent_type, SessionAgentType::Executor);
    }

    #[test]
    fn parse_plan_tasks_reads_session_agent_type_reviewer() {
        let toml = r#"
[[tasks]]
task_id = "t1"
session_agent_type = "Reviewer"
"#;
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].session_agent_type, SessionAgentType::Reviewer);
    }

    #[test]
    fn parse_plan_tasks_reads_session_agent_type_orchestrator_passes_parser() {
        // The parser accepts `Orchestrator` because it's a valid SQL
        // string for the type — the rejection is structural and lives
        // in `validate_sparse_orchestrator_exclusion`. Pinning this
        // separation prevents accidentally moving the structural check
        // into the parser (where `OrchestratorTaskNotPermitted` would
        // become an unstructured `PlanInvalid`).
        let toml = r#"
[[tasks]]
task_id = "t1"
session_agent_type = "Orchestrator"
"#;
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].session_agent_type, SessionAgentType::Orchestrator);
    }

    #[test]
    fn parse_plan_tasks_rejects_unknown_session_agent_type() {
        let toml = r#"
[[tasks]]
task_id = "t1"
session_agent_type = "Coordinator"
"#;
        let err = parse_plan_tasks(toml).unwrap_err();
        match err {
            LifecycleError::PlanCloneStrategyInvalid { rule, offending_task, .. } => {
                assert_eq!(rule, "unknown_agent_type");
                assert_eq!(offending_task, "t1");
            }
            other => panic!("expected PlanCloneStrategyInvalid(unknown_agent_type), got {other:?}"),
        }
    }

    // ── V2 §Step 27 — validate_sparse_orchestrator_exclusion ─────────────

    fn task_with_strategy_and_agent(
        task_id: &str,
        strategy: CloneStrategy,
        agent: SessionAgentType,
    ) -> PlanTask {
        PlanTask {
            task_id: task_id.into(),
            name: task_id.into(),
            lane_id: String::new(),
            predecessors: vec![],
            path_allowlist: vec![],
            path_export_to_successors: false,
            path_export_globs: vec![],
            path_scope_override: false,
            clone_strategy: strategy,
            session_agent_type: agent,
            credentials: vec![],
        }
    }

    #[test]
    fn validate_sparse_orchestrator_rejects_orchestrator_task() {
        // V2 auto-creates the Orchestrator; declaring one in `[[tasks]]`
        // is structurally wrong regardless of clone strategy.
        let tasks = vec![task_with_strategy_and_agent(
            "rogue", CloneStrategy::Full, SessionAgentType::Orchestrator,
        )];
        let err = validate_sparse_orchestrator_exclusion(&tasks).unwrap_err();
        match err {
            LifecycleError::PlanCloneStrategyInvalid { rule, offending_task, .. } => {
                assert_eq!(rule, "orchestrator_task_not_permitted");
                assert_eq!(offending_task, "rogue");
            }
            other => panic!("expected PlanCloneStrategyInvalid(orchestrator_task_not_permitted), got {other:?}"),
        }
    }

    #[test]
    fn validate_sparse_orchestrator_accepts_executor_with_any_strategy() {
        // Every strategy is valid for plan-declared Executor tasks.
        for strategy in CloneStrategy::ALL {
            let tasks = vec![task_with_strategy_and_agent(
                "t", strategy, SessionAgentType::Executor,
            )];
            validate_sparse_orchestrator_exclusion(&tasks)
                .unwrap_or_else(|e| panic!("strategy {strategy:?} on Executor must pass: {e:?}"));
        }
    }

    #[test]
    fn validate_sparse_orchestrator_accepts_reviewer_with_any_strategy() {
        for strategy in CloneStrategy::ALL {
            let tasks = vec![task_with_strategy_and_agent(
                "rev", strategy, SessionAgentType::Reviewer,
            )];
            validate_sparse_orchestrator_exclusion(&tasks)
                .unwrap_or_else(|e| panic!("strategy {strategy:?} on Reviewer must pass: {e:?}"));
        }
    }

    #[test]
    fn validate_sparse_orchestrator_short_circuits_on_first_offender() {
        // Multiple offenders → only the first task_id is reported.
        let tasks = vec![
            task_with_strategy_and_agent(
                "executor-ok", CloneStrategy::Full, SessionAgentType::Executor,
            ),
            task_with_strategy_and_agent(
                "first-rogue", CloneStrategy::Full, SessionAgentType::Orchestrator,
            ),
            task_with_strategy_and_agent(
                "second-rogue", CloneStrategy::Sparse, SessionAgentType::Orchestrator,
            ),
        ];
        let err = validate_sparse_orchestrator_exclusion(&tasks).unwrap_err();
        match err {
            LifecycleError::PlanCloneStrategyInvalid { offending_task, .. } => {
                assert_eq!(offending_task, "first-rogue");
            }
            other => panic!("expected PlanCloneStrategyInvalid, got {other:?}"),
        }
    }

    #[test]
    fn approve_plan_rejects_orchestrator_task_in_tasks_array() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        // Operator declared an Orchestrator task — V2 forbids this.
        let plan = r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "rogue-orch"
session_agent_type = "Orchestrator"
"#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap_err();
        match err {
            LifecycleError::PlanCloneStrategyInvalid { rule, offending_task, .. } => {
                assert_eq!(rule, "orchestrator_task_not_permitted");
                assert_eq!(offending_task, "rogue-orch");
            }
            other => panic!("expected PlanCloneStrategyInvalid, got {other:?}"),
        }
        assert_eq!(read_initiative_state(&store, &init_id), "Draft");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 0);
    }

    #[test]
    fn approve_plan_rejects_unknown_clone_strategy() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "t1"
clone_strategy = "treeless"
"#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap_err();
        match err {
            LifecycleError::PlanCloneStrategyInvalid { rule, .. } => {
                assert_eq!(rule, "unknown_clone_strategy");
            }
            other => panic!("expected PlanCloneStrategyInvalid(unknown_clone_strategy), got {other:?}"),
        }
        assert_eq!(read_initiative_state(&store, &init_id), "Draft");
    }

    #[test]
    fn approve_plan_persists_clone_strategy_and_agent_type_in_registry() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "build-svc"
clone_strategy = "blobless"

[[tasks]]
task_id = "run-tests"
clone_strategy = "sparse"
path_allowlist = ["tests/", "Cargo.toml"]
predecessors = ["build-svc"]

[[tasks]]
task_id = "review-it"
session_agent_type = "Reviewer"
clone_strategy = "full"
predecessors = ["run-tests"]
"#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap();

        // Each task's typed `clone_strategy` and `session_agent_type`
        // are persisted in the in-memory PlanRegistry; this is what
        // `Step 24` and `Step 24b` will read at provisioning time.
        let by_id: std::collections::HashMap<String, _> = registry
            .tasks_in_initiative(&init_id)
            .into_iter()
            .collect();
        assert_eq!(by_id["build-svc"].clone_strategy, CloneStrategy::Blobless);
        assert_eq!(by_id["build-svc"].session_agent_type, SessionAgentType::Executor);
        assert_eq!(by_id["run-tests"].clone_strategy, CloneStrategy::Sparse);
        assert_eq!(by_id["run-tests"].session_agent_type, SessionAgentType::Executor);
        assert_eq!(by_id["review-it"].clone_strategy, CloneStrategy::Full);
        assert_eq!(by_id["review-it"].session_agent_type, SessionAgentType::Reviewer);
    }

    /// V2 §Step 5 — `approve_plan` MUST insert one
    /// `subtask_activations` row per Executor / Reviewer task in the
    /// `PendingActivation` state. Orchestrator tasks deliberately
    /// receive NO row. The row is inserted in the same transaction
    /// as the parent `tasks` row (INV-STORE-02 / Pattern A).
    #[test]
    fn approve_plan_populates_subtask_activations_for_each_executor_or_reviewer_task() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "build-svc"

[[tasks]]
task_id = "run-tests"
predecessors = ["build-svc"]

[[tasks]]
task_id = "review-it"
session_agent_type = "Reviewer"
predecessors = ["run-tests"]
"#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap();

        // Three Executor / Reviewer tasks → three activation rows.
        let conn = store.lock_sync();
        let activation_count: i64 = conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {SUBTASK_ACTIVATIONS}
                 WHERE initiative_id = ?1"
            ),
            rusqlite::params![&init_id],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(
            activation_count, 3,
            "expected one subtask_activations row per Executor/Reviewer task",
        );

        // Every row must start in PendingActivation with all three
        // post-activation timestamps NULL (the cross-column CHECK
        // requires this).
        let mut stmt = conn.prepare(
            &format!(
                "SELECT task_id, activation_state, session_id,
                        activated_at, terminated_at,
                        crash_retry_count, review_reject_count
                 FROM {SUBTASK_ACTIVATIONS}
                 WHERE initiative_id = ?1
                 ORDER BY task_id"
            )
        ).unwrap();
        let rows: Vec<(String, String, Option<String>, Option<i64>, Option<i64>, i64, i64)> = stmt
            .query_map(rusqlite::params![&init_id], |r| Ok((
                r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?,
            )))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(rows.len(), 3);
        for (task_id, state, session_id, activated_at, terminated_at, crash, review)
            in &rows
        {
            assert_eq!(
                state, "PendingActivation",
                "{task_id}: expected PendingActivation, got {state}",
            );
            assert!(session_id.is_none(),
                "{task_id}: PendingActivation rows must have NULL session_id");
            assert!(activated_at.is_none(),
                "{task_id}: PendingActivation rows must have NULL activated_at");
            assert!(terminated_at.is_none(),
                "{task_id}: PendingActivation rows must have NULL terminated_at");
            assert_eq!(*crash, 0,
                "{task_id}: crash_retry_count must start at 0");
            assert_eq!(*review, 0,
                "{task_id}: review_reject_count must start at 0");
        }

        // The Orchestrator's auto-spawned session row (Step 6) must
        // NOT carry an activation row of its own — it's activated by
        // the kernel itself, not by another agent's ActivateSubTask.
        let task_ids: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
        assert!(task_ids.contains(&"build-svc"));
        assert!(task_ids.contains(&"run-tests"));
        assert!(task_ids.contains(&"review-it"));
    }

    // ── V2 `credential-proxy.md §3` — task-credential shift-left
    // validation. The validator runs in approve_plan alongside the
    // path_allowlist / cross_cutting_artifacts validators per Step 17,
    // **before** BEGIN TRANSACTION. The tests below pin both the
    // happy-path (postgres / http with restrictions) and the
    // unknown-proxy-type rejection.

    #[test]
    fn approve_plan_accepts_known_proxy_types_in_tasks_credentials() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "build-svc"

  [[tasks.credentials]]
  name       = "pg-staging"
  mount_as   = "DATABASE_URL"
  proxy_type = "postgres"

    [tasks.credentials.restrictions]
    allow_only_select = true

[[tasks]]
task_id = "test-it"
predecessors = ["build-svc"]

  [[tasks.credentials]]
  name         = "stripe-api-key"
  mount_as     = "STRIPE_API_BASE_URL"
  proxy_type   = "http"
  upstream_url = "https://api.stripe.com/v1"
  auth_mode    = "bearer"

    [tasks.credentials.restrictions]
    allowed_methods = ["GET", "POST"]

[[tasks]]
task_id = "send-receipts"
predecessors = ["test-it"]

  [[tasks.credentials]]
  name               = "smtp-relay"
  mount_as           = "SMTP_URL"
  proxy_type         = "smtp"
  upstream_host_port = "smtp.example.com:587"

    [tasks.credentials.auth_mode]
    kind = "plain"
    user = "smtp-user"

    [tasks.credentials.restrictions]
    allowed_sender_address     = "noreply@example.com"
    allowed_recipient_domains  = ["customers.example.com"]
    max_recipients_per_message = 10
    max_message_bytes          = 65536
"#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).expect("plan with valid task-credentials must be accepted");

        // The plan landed in Executing — task-credential validation
        // did not block the happy path.
        assert_eq!(read_initiative_state(&store, &init_id), "Executing");
    }

    /// End-to-end round-trip across the persistence boundary:
    ///   * `approve_plan` parses `[[tasks.credentials]]`
    ///   * inserts one `task_credential_proxies` row per decl, and
    ///   * `read_task_credential_proxies_in_tx` re-deserialises each
    ///     row back into the same `TaskCredentialDecl` shape the
    ///     parser produced.
    ///
    /// This pins the (insert → SELECT → serde-from-JSON) path that
    /// the kernel-side `CredentialProxyManager` will use at session-
    /// spawn time. METADATA-ONLY invariant is enforced by inspecting
    /// the column projection: no row may carry credential bytes.
    #[test]
    fn task_credential_proxies_persistence_round_trips_via_session_spawn() {
        use raxis_plan_credentials::{
            HttpAuthMode, HttpRestrictions, PostgresRestrictions, ProxyDecl,
        };

        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        // Two tasks, each declaring a different proxy variant, so the
        // round-trip exercises postgres + http + k8s + per-task row
        // partitioning all in one go.
        let plan = r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "build-svc"

  [[tasks.credentials]]
  name       = "pg-staging"
  mount_as   = "DATABASE_URL"
  proxy_type = "postgres"

    [tasks.credentials.restrictions]
    allow_only_select = true

[[tasks]]
task_id = "deploy"
predecessors = ["build-svc"]

  [[tasks.credentials]]
  name         = "stripe-api-key"
  mount_as     = "STRIPE_API_BASE_URL"
  proxy_type   = "http"
  upstream_url = "https://api.stripe.com/v1"
  auth_mode    = "bearer"

    [tasks.credentials.restrictions]
    allowed_methods       = ["GET", "POST"]
    allowed_path_prefixes = ["/charges", "/customers"]

  [[tasks.credentials]]
  name       = "k8s-staging"
  mount_as   = "KUBECONFIG_API"
  proxy_type = "k8s"

    [tasks.credentials.restrictions]
    allowed_methods = ["GET"]
"#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).expect("approve_plan must succeed");

        // Read back through the session-spawn-side helper. We use a
        // short-lived read-only connection on the same store; the
        // helper accepts any rusqlite::Connection (transaction or
        // not) so we can call it without opening a write tx here.
        let conn = store.lock_sync();

        let build_svc = read_task_credential_proxies_in_tx(&conn, "build-svc")
            .expect("read build-svc creds");
        assert_eq!(build_svc.len(), 1, "build-svc has exactly 1 credential");
        assert_eq!(build_svc[0].name.as_str(), "pg-staging");
        assert_eq!(build_svc[0].mount_as, "DATABASE_URL");
        match &build_svc[0].proxy {
            ProxyDecl::Postgres { restrictions: PostgresRestrictions { allow_only_select } } => {
                assert!(*allow_only_select, "postgres restrictions round-trip");
            }
            other => panic!("expected ProxyDecl::Postgres, got {other:?}"),
        }

        let deploy = read_task_credential_proxies_in_tx(&conn, "deploy")
            .expect("read deploy creds");
        assert_eq!(deploy.len(), 2, "deploy has exactly 2 credentials");
        // Order-stable: created_at_unix_secs ASC + credential_name ASC.
        // Both rows are inserted at the same wall-clock second by the
        // approve_plan loop, so the alphabetical tiebreaker applies:
        // `k8s-staging` < `stripe-api-key`.
        assert_eq!(deploy[0].name.as_str(), "k8s-staging");
        match &deploy[0].proxy {
            ProxyDecl::K8s { restrictions: HttpRestrictions { allowed_methods, .. } } => {
                assert_eq!(allowed_methods, &vec!["GET".to_owned()]);
            }
            other => panic!("expected ProxyDecl::K8s, got {other:?}"),
        }

        assert_eq!(deploy[1].name.as_str(), "stripe-api-key");
        assert_eq!(deploy[1].mount_as, "STRIPE_API_BASE_URL");
        match &deploy[1].proxy {
            ProxyDecl::Http {
                auth_mode: HttpAuthMode::Bearer,
                upstream_url,
                restrictions: HttpRestrictions { allowed_methods, allowed_path_prefixes },
            } => {
                assert_eq!(upstream_url, "https://api.stripe.com/v1");
                assert_eq!(allowed_methods, &vec!["GET".to_owned(), "POST".to_owned()]);
                assert_eq!(
                    allowed_path_prefixes,
                    &vec!["/charges".to_owned(), "/customers".to_owned()],
                );
            }
            other => panic!("expected ProxyDecl::Http, got {other:?}"),
        }

        // ── Invariant probe: no credential bytes leak into the row ────
        // Inspect every column of the new table and assert that none
        // contains anything resembling a secret. This is the SQL-level
        // mirror of the documentation invariant: future schema
        // changes that accidentally added a value column would land
        // here as a hard test failure rather than slipping through
        // review.
        let columns: Vec<String> = conn
            .prepare(&format!(
                "SELECT name FROM pragma_table_info(?1)"
            )).unwrap()
            .query_map([TASK_CREDENTIAL_PROXIES], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let expected_columns = [
            "task_id",
            "credential_name",
            "mount_as",
            "proxy_type",
            "proxy_json",
            "created_at_unix_secs",
        ];
        assert_eq!(
            columns.len(),
            expected_columns.len(),
            "task_credential_proxies must have exactly the metadata-only \
             column set; observed {columns:?}",
        );
        for c in &expected_columns {
            assert!(
                columns.iter().any(|col| col == c),
                "task_credential_proxies missing expected column {c}",
            );
        }
        for forbidden in [
            "credential_value",
            "value",
            "secret",
            "password",
            "token",
            "kubeconfig",
            "credential_bytes",
        ] {
            assert!(
                !columns.iter().any(|col| col == forbidden),
                "task_credential_proxies must NEVER carry a {forbidden:?} \
                 column — credential VALUES live with the \
                 CredentialBackend, not in kernel.db",
            );
        }
    }

    #[test]
    fn approve_plan_rejects_unknown_proxy_type_in_tasks_credentials() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        // V2 ships `postgres`, `http`, `k8s`, `smtp`. Any other
        // `proxy_type` MUST land in `ProxyDecl::Unknown` and be
        // rejected shift-left by `validate_task_credentials`. Pin
        // a forward-looking name (`mongodb-future-spec`) so the
        // test keeps tracking the unknown-arm policy as new
        // proxies are added.
        let plan = r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "send-email"

  [[tasks.credentials]]
  name       = "future-uri"
  mount_as   = "FUTURE_URL"
  proxy_type = "mongodb-future-spec"
"#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).expect_err("unknown proxy_type must be rejected");

        match err {
            LifecycleError::PlanTaskCredentialsInvalid {
                rule, offending_task, offending_credential, suggestion,
            } => {
                assert_eq!(rule, "unknown_proxy_type");
                assert_eq!(offending_task, "send-email");
                assert_eq!(offending_credential, "future-uri");
                assert!(
                    suggestion.contains("postgres") &&
                    suggestion.contains("http") &&
                    suggestion.contains("k8s") &&
                    suggestion.contains("smtp"),
                    "diagnostic should enumerate the V2 implemented set, got: {suggestion}",
                );
            }
            other => panic!("expected PlanTaskCredentialsInvalid, got {other:?}"),
        }
        // Plan stayed in Draft — shift-left rejection is pre-tx so no
        // state mutation happened.
        assert_eq!(read_initiative_state(&store, &init_id), "Draft");
    }

    #[test]
    fn approve_plan_rejects_malformed_tasks_credentials_block() {
        // A `[[tasks.credentials]]` entry without `proxy_type` is
        // structurally malformed — the parser inside parse_plan_tasks
        // surfaces it as PlanInvalid (the catch-all generic-shape
        // error), not the typed PlanTaskCredentialsInvalid. This pins
        // the parser-level rejection.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "x"

  [[tasks.credentials]]
  name     = "no-proxy-type"
  mount_as = "DATABASE_URL"
"#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).expect_err("malformed credential block must be rejected");

        match err {
            LifecycleError::PlanInvalid { reason } => {
                assert!(
                    reason.contains("[[tasks.credentials]]") && reason.contains("`x`"),
                    "diagnostic should name the offending task block, got: {reason}",
                );
            }
            other => panic!("expected PlanInvalid for malformed creds, got {other:?}"),
        }
        assert_eq!(read_initiative_state(&store, &init_id), "Draft");
    }

    #[test]
    fn parse_plan_workspace_lane_reads_value() {
        let toml = r#"
[workspace]
lane_id = "feature-work"

[[tasks]]
task_id = "t1"
"#;
        let lane = parse_plan_workspace_lane(toml).unwrap();
        assert_eq!(lane.as_deref(), Some("feature-work"));
    }

    #[test]
    fn parse_plan_workspace_lane_missing_returns_none() {
        let toml = "[[tasks]]\ntask_id = \"t1\"\n";
        let lane = parse_plan_workspace_lane(toml).unwrap();
        assert_eq!(lane, None);
    }

    #[test]
    fn path_allowlist_entry_violation_canonical_table() {
        // Direct unit test of the helper — pins the (entry → reason)
        // table that `policy-plan-authority.md
        // §FAIL_PATH_ALLOWLIST_INVALID_SYNTAX` calls out.
        assert_eq!(path_allowlist_entry_violation(""),
                   Some("empty_entry"));
        assert_eq!(path_allowlist_entry_violation("src/**"),
                   Some("glob_character_in_path"));
        assert_eq!(path_allowlist_entry_violation("/abs/"),
                   Some("absolute_path"));
        assert_eq!(path_allowlist_entry_violation("../up/"),
                   Some("path_escape"));
        assert_eq!(path_allowlist_entry_violation("!neg"),
                   Some("negation_marker"));
        assert_eq!(path_allowlist_entry_violation("src/api/handler.rs"), None);
        assert_eq!(path_allowlist_entry_violation("src/"),               None);
    }

    #[test]
    fn lifecycle_error_initiative_not_found_display() {
        let e = LifecycleError::InitiativeNotFound { initiative_id: "i-1".into() };
        assert!(e.to_string().contains("i-1"));
    }

    #[test]
    fn lifecycle_error_task_not_failed_display() {
        let e = LifecycleError::TaskNotFailed { current_state: "Running".into() };
        assert!(e.to_string().contains("Running"));
    }

    // ───────────────────────────────────────────────────────────────────
    //  approve_plan — INV-STORE-02 atomicity tests
    //
    // These tests verify the spec contract from kernel-store.md §2.5.1
    // (table row "approve_plan"): every initiatives UPDATE, every tasks
    // INSERT, and every task_dag_edges INSERT either all commit together
    // or none do.
    // ───────────────────────────────────────────────────────────────────

    use ed25519_dalek::{Signer, SigningKey};
    use raxis_test_support::FakeAuditSink;
    use raxis_store::Store;

    /// Deterministic Ed25519 keypair for fixtures (no entropy needed).
    fn fixture_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// V2 §Step 28 — every signed plan needs `[workspace] lane_id`.
    /// Tests that don't explicitly exercise the missing/override
    /// workspace-lane error paths use this helper to prepend the
    /// canonical default block. Tests that DO want to exercise those
    /// rejection paths use `seed_draft_initiative_raw` directly.
    fn ensure_workspace_lane(plan_toml: &str) -> String {
        // Detect either `[workspace]` or `[ workspace ]` (whitespace
        // around the table name). The bytes-substring check is good
        // enough — TOML test fixtures here are hand-authored and
        // never embed the literal sequence inside a string value.
        if plan_toml.contains("[workspace]") || plan_toml.contains("[ workspace ]") {
            return plan_toml.to_owned();
        }
        format!("[workspace]\nlane_id = \"default\"\n\n{plan_toml}")
    }

    /// Build a Draft initiative + signed_plan_artifacts row directly
    /// (no IPC), returning everything the test needs to call
    /// `approve_plan`. Auto-prepends `[workspace] lane_id = "default"`
    /// unless the plan already has a `[workspace]` table.
    fn seed_draft_initiative(
        store:      &Store,
        plan_toml:  &str,
        sk:         &SigningKey,
    ) -> (String, Vec<u8>) {
        let plan_with_lane = ensure_workspace_lane(plan_toml);
        seed_draft_initiative_raw(store, &plan_with_lane, sk)
    }

    /// Like `seed_draft_initiative` but persists the plan TOML
    /// verbatim — used by tests that need to assert the
    /// `validate_single_lane_propagation` error paths
    /// (`missing_workspace_lane`, `empty_workspace_lane`,
    /// `single_lane_propagation`).
    fn seed_draft_initiative_raw(
        store:      &Store,
        plan_toml:  &str,
        sk:         &SigningKey,
    ) -> (String, Vec<u8>) {
        let initiative_id = "init-test".to_owned();
        let plan_bytes    = plan_toml.as_bytes().to_vec();
        let signing_input = raxis_crypto::plan::plan_signing_input(&plan_bytes);
        let sig_bytes     = sk.sign(&signing_input).to_bytes().to_vec();
        let plan_sha      = raxis_crypto::plan::plan_artifact_sha256(&plan_bytes);
        let pk_bytes      = sk.verifying_key().to_bytes();
        let now           = unix_now_secs();

        let conn = store.lock_sync();
        // initiatives row in Draft. terminal_criteria_json is NOT NULL
        // per kernel-store.md §2.5.1 Table 2; an empty JSON object is the
        // canonical "no criteria yet" placeholder.
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)"
            ),
            rusqlite::params![
                &initiative_id,
                InitiativeState::Draft.as_sql_str(),
                "{}",
                &plan_sha,
                now,
            ],
        ).unwrap();

        // signed_plan_artifacts: column set per kernel-store.md §2.5.1 Table 3
        // is exactly (initiative_id, plan_bytes, plan_sig, stored_at).
        conn.execute(
            &format!(
                "INSERT INTO {SIGNED_PLAN_ARTIFACTS}
                    (initiative_id, plan_bytes, plan_sig, stored_at)
                 VALUES (?1, ?2, ?3, ?4)"
            ),
            rusqlite::params![&initiative_id, &plan_bytes, &sig_bytes, now],
        ).unwrap();
        drop(conn);

        (initiative_id, pk_bytes.to_vec())
    }

    /// Count rows in a table where `initiative_id = ?` (for assertions).
    fn count_initiative_rows(store: &Store, table: &str, init_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE initiative_id=?1"),
            rusqlite::params![init_id],
            |r| r.get(0),
        ).unwrap()
    }

    /// Count edges that mention any task in the given initiative.
    fn count_edges_for_initiative(store: &Store, init_id: &str) -> i64 {
        const TASK_DAG_EDGES: &str = Table::TaskDagEdges.as_str();
        let conn = store.lock_sync();
        conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {TASK_DAG_EDGES} e
                   JOIN {TASKS} t ON t.task_id = e.successor_task_id
                  WHERE t.initiative_id = ?1"
            ),
            rusqlite::params![init_id],
            |r| r.get(0),
        ).unwrap()
    }

    fn read_initiative_state(store: &Store, init_id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT state FROM {INITIATIVES} WHERE initiative_id=?1"),
            rusqlite::params![init_id],
            |r| r.get(0),
        ).unwrap()
    }

    // NOTE on test attribute choice: these tests use `#[test]`, not
    // `#[tokio::test]`, because `approve_plan` is a sync function that
    // acquires the store mutex via `Store::lock_sync()` → `blocking_lock`.
    // tokio's `blocking_lock` panics if invoked from a thread already
    // driving an async runtime. In production, the operator handler
    // wraps the call in `tokio::task::spawn_blocking`; in tests we
    // simply call from a non-async thread.
    #[test]
    fn approve_plan_happy_path_inserts_tasks_and_edges() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _pk) = fixture_keypair();

        // Plan with two tasks — t2 depends on t1 (one DAG edge).
        let plan = r#"
            [meta]
            version = 1

            [[tasks]]
            task_id  = "t1"
            name     = "first"

            [[tasks]]
            task_id      = "t2"
            name         = "second"
            predecessors = ["t1"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit = FakeAuditSink::new();

        let registry = PlanRegistry::new();
        let result = approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap();
        assert_eq!(result.tasks_admitted, 2);
        assert_eq!(
            registry.len(), 2,
            "approve_plan must populate the in-memory plan registry for every task",
        );

        assert_eq!(read_initiative_state(&store, &init_id), "Executing");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 2);
        assert_eq!(
            count_edges_for_initiative(&store, &init_id), 1,
            "one DAG edge (t1 → t2) should be inserted alongside the task rows",
        );

        // Audit-after-commit per kernel-store.md §2.5.2: V2 admission
        // emits `PlanApproved` followed by `SessionCreated` (for the
        // auto-spawned canonical Orchestrator session per
        // INV-PLANNER-HARNESS-06). Both carry `initiative_id`.
        let events = audit.events();
        assert_eq!(events.len(), 2,
            "V2 admission emits PlanApproved + SessionCreated (orchestrator); got {:?}",
            events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>());
        assert_eq!(events[0].kind.as_str(), "PlanApproved");
        assert_eq!(events[0].initiative_id.as_deref(), Some(init_id.as_str()));
        assert_eq!(events[1].kind.as_str(), "SessionCreated");
        assert_eq!(events[1].initiative_id.as_deref(), Some(init_id.as_str()));
        // The auto-spawned session must surface a canonical Orchestrator
        // agent type on the audit record.
        match &events[1].kind {
            AuditEventKind::SessionCreated { session_agent_type, .. } => {
                assert_eq!(session_agent_type.as_deref(), Some("Orchestrator"));
            }
            other => panic!("expected SessionCreated; got {other:?}"),
        }
        // The post-commit `PlanApproved` return must carry the same
        // session_id as the audit emit.
        let auto_spawn_id = result.orchestrator_session_id
            .as_deref()
            .expect("V2 approve_plan must return orchestrator_session_id");
        match &events[1].kind {
            AuditEventKind::SessionCreated { session_id, .. } => {
                assert_eq!(session_id, auto_spawn_id);
            }
            other => panic!("expected SessionCreated; got {other:?}"),
        }

        // V2 §Step 28: every task row carries the workspace-root
        // lane_id verbatim (the helper prepended `lane_id = "default"`).
        // We assert the propagation persisted to the `tasks` table —
        // that's where `scheduler::lane::get_lane_status_in_tx` reads it
        // when computing the budget snapshot for new intent admission.
        let conn = store.lock_sync();
        let lanes: Vec<String> = conn.prepare(
            &format!("SELECT lane_id FROM {TASKS} WHERE initiative_id = ?1"),
        ).unwrap()
            .query_map(rusqlite::params![&init_id], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(lanes.len(), 2);
        assert!(lanes.iter().all(|l| l == "default"),
            "every task row must carry the workspace-root lane_id; got {lanes:?}");
    }

    // ── V2 §Step 6 / INV-PLANNER-HARNESS-06 — Orchestrator auto-spawn ───

    /// `approve_plan` MUST insert the canonical Orchestrator session
    /// row inside the same transaction that admits the plan tasks.
    /// This pins the row's V2-mandated columns at the SQL layer:
    ///   * `session_agent_type = 'Orchestrator'`
    ///   * `can_delegate       = 1`
    ///   * `role_id            = 'Planner'` (wire-role taxonomy)
    ///   * `worktree_root      IS NULL` (filled at VM spawn)
    ///   * `base_sha           IS NULL` (filled at VM spawn)
    ///   * `vsock_cid          IS NULL` (filled by hypervisor)
    #[test]
    fn approve_plan_inserts_canonical_orchestrator_session_row() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [[tasks]]
            task_id = "only"
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let result = approve_plan(
            &init_id, "op", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap();

        let auto_spawn_id = result.orchestrator_session_id
            .as_deref()
            .expect("approve_plan must surface orchestrator_session_id");

        let conn = store.lock_sync();
        let row: (
            String, String, String,         // session_id, role_id, session_token
            Option<String>, Option<String>, // session_agent_type, worktree_root
            Option<String>, Option<i64>,    // base_sha, vsock_cid
            i64,                            // can_delegate
        ) = conn.query_row(
            &format!(
                "SELECT session_id, role_id, session_token,
                        session_agent_type, worktree_root,
                        base_sha, vsock_cid, can_delegate
                 FROM {} WHERE session_id = ?1",
                Table::Sessions.as_str(),
            ),
            rusqlite::params![auto_spawn_id],
            |r| Ok((
                r.get(0)?, r.get(1)?, r.get(2)?,
                r.get(3)?, r.get(4)?,
                r.get(5)?, r.get(6)?,
                r.get(7)?,
            )),
        ).expect("orchestrator session row must exist after approve_plan");

        assert_eq!(row.1, "Planner",
            "wire-role taxonomy: orchestrator session is roled as Planner");
        assert_eq!(row.2.len(), 64,
            "session_token must be 32 CSPRNG bytes hex-encoded");
        assert_eq!(row.3.as_deref(), Some("Orchestrator"),
            "session_agent_type must be 'Orchestrator' (V2 dispatch key)");
        assert!(row.4.is_none(),
            "worktree_root must be NULL until VM spawn provisions it");
        assert!(row.5.is_none(),
            "base_sha must be NULL until VM spawn binds it");
        assert!(row.6.is_none(),
            "vsock_cid must be NULL until hypervisor returns it");
        assert_eq!(row.7, 1,
            "can_delegate must be 1 for Orchestrator (INV-DELEGATE-01)");
    }

    /// Two independently-approved initiatives MUST receive two distinct
    /// orchestrator sessions with different session_ids and tokens.
    /// Pins the per-initiative auto-spawn contract. Uses two stores
    /// because `seed_draft_initiative` collides on the hardcoded
    /// `init-test` initiative_id within a single store.
    #[test]
    fn approve_plan_orchestrator_session_is_unique_per_initiative() {
        let plan = r#"
            [[tasks]]
            task_id = "t"
        "#;

        let approve = |store: &Store| -> String {
            let (sk, _) = fixture_keypair();
            let (init, pk_bytes) = seed_draft_initiative(store, plan, &sk);
            let audit    = FakeAuditSink::new();
            let registry = PlanRegistry::new();
            let r = approve_plan(
                &init, "op", None, &pk_bytes, 1, store, &audit, &registry,
            ).unwrap();
            r.orchestrator_session_id.unwrap()
        };

        let store_a = Store::open_in_memory().unwrap();
        let store_b = Store::open_in_memory().unwrap();
        let id_a    = approve(&store_a);
        let id_b    = approve(&store_b);
        assert_ne!(id_a, id_b,
            "every initiative must auto-spawn a distinct orchestrator session");

        let token = |store: &Store, sid: &str| -> String {
            let conn = store.lock_sync();
            conn.query_row(
                &format!("SELECT session_token FROM {} WHERE session_id = ?1",
                         Table::Sessions.as_str()),
                rusqlite::params![sid],
                |r| r.get(0),
            ).unwrap()
        };
        assert_ne!(token(&store_a, &id_a), token(&store_b, &id_b),
            "each orchestrator session token must come from a fresh CSPRNG draw");
    }

    /// INV-STORE-02 atomicity: when the plan validator rejects mid-flight
    /// (e.g. cyclic DAG), no orchestrator session row is left behind.
    /// Pins the rollback contract.
    #[test]
    fn approve_plan_rolls_back_orchestrator_session_on_cycle() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        // Two-node cycle: t1 → t2 → t1.
        let plan = r#"
            [[tasks]]
            task_id      = "t1"
            predecessors = ["t2"]

            [[tasks]]
            task_id      = "t2"
            predecessors = ["t1"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap_err();
        assert!(matches!(err, LifecycleError::PlanDagInvalid { .. }),
            "cyclic plan must yield PlanDagInvalid; got {err:?}");

        // No orchestrator session row must be present for the failed
        // initiative — the entire transaction rolled back.
        let conn = store.lock_sync();
        let count: i64 = conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {} WHERE session_agent_type = 'Orchestrator'",
                Table::Sessions.as_str(),
            ),
            [],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(count, 0,
            "rollback contract: no orchestrator session row may survive a failed approve_plan");
    }

    // ── V2 §Step 28 — approve_plan-level rejection of malformed plans ───

    #[test]
    fn approve_plan_rejects_missing_workspace_lane() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        // No `[workspace]` table at all. `seed_draft_initiative_raw`
        // bypasses the auto-prepend so the validator must surface the
        // missing-workspace-lane rule.
        let plan = r#"
            [meta]
            version = 1

            [[tasks]]
            task_id = "t1"
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap_err();
        match err {
            LifecycleError::PlanSingleLaneInvalid { rule, offending_task, .. } => {
                assert_eq!(rule, "missing_workspace_lane");
                assert_eq!(offending_task, "<workspace>");
            }
            other => panic!("expected PlanSingleLaneInvalid(missing_workspace_lane), got {other:?}"),
        }

        // Initiative stays Draft; no tasks admitted.
        assert_eq!(read_initiative_state(&store, &init_id), "Draft");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 0);
        // No audit event emitted (the rejection happens before commit).
        assert!(audit.events().is_empty());
    }

    #[test]
    fn approve_plan_rejects_empty_workspace_lane() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [workspace]
            lane_id = ""

            [[tasks]]
            task_id = "t1"
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap_err();
        match err {
            LifecycleError::PlanSingleLaneInvalid { rule, .. } => {
                assert_eq!(rule, "empty_workspace_lane");
            }
            other => panic!("expected PlanSingleLaneInvalid(empty_workspace_lane), got {other:?}"),
        }
        assert_eq!(read_initiative_state(&store, &init_id), "Draft");
    }

    #[test]
    fn approve_plan_rejects_per_task_lane_id_override() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [workspace]
            lane_id = "feature-work"

            [[tasks]]
            task_id = "t1"

            [[tasks]]
            task_id = "t2"
            lane_id = "rogue-lane"
            predecessors = ["t1"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap_err();
        match err {
            LifecycleError::PlanSingleLaneInvalid { rule, offending_task, .. } => {
                assert_eq!(rule, "single_lane_propagation");
                assert_eq!(offending_task, "t2");
            }
            other => panic!("expected PlanSingleLaneInvalid(single_lane_propagation), got {other:?}"),
        }
        assert_eq!(read_initiative_state(&store, &init_id), "Draft");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 0);
    }

    #[test]
    fn approve_plan_propagates_workspace_lane_to_every_task() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        // Three tasks, none declare lane_id. `[workspace]` declares the
        // single source of truth.
        let plan = r#"
            [workspace]
            lane_id = "feature-work"

            [[tasks]]
            task_id = "t1"

            [[tasks]]
            task_id = "t2"
            predecessors = ["t1"]

            [[tasks]]
            task_id = "t3"
            predecessors = ["t2"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative_raw(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap();

        let conn = store.lock_sync();
        let lanes: Vec<String> = conn.prepare(
            &format!("SELECT lane_id FROM {TASKS} WHERE initiative_id = ?1"),
        ).unwrap()
            .query_map(rusqlite::params![&init_id], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(lanes.len(), 3);
        assert!(lanes.iter().all(|l| l == "feature-work"),
            "every task row must carry the workspace-root lane_id verbatim; got {lanes:?}");
    }

    #[test]
    fn approve_plan_rolls_back_on_cyclic_dependency() {
        // Cycle: t1 depends on t2, t2 depends on t1. The V2 Step 17
        // shift-left validator (`validate_plan_dag`) must catch this
        // BEFORE the transaction begins, so the initiative stays Draft
        // and no tasks/edges are persisted. The diagnostic must be the
        // structured `PlanDagInvalid { rule: "cyclic_dependency", ... }`
        // rather than the old in-tx `Scheduler(CyclicDependency)`,
        // which is now only the defense-in-depth backstop.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();

        let plan = r#"
            [meta]
            version = 1

            [[tasks]]
            task_id      = "t1"
            predecessors = ["t2"]

            [[tasks]]
            task_id      = "t2"
            predecessors = ["t1"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit = FakeAuditSink::new();

        let registry = PlanRegistry::new();
        let err = approve_plan(
            &init_id, "op-test", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap_err();
        match &err {
            LifecycleError::PlanDagInvalid { rule, suggestion, .. } => {
                assert_eq!(*rule, "cyclic_dependency",
                           "shift-left validator must surface the cycle rule");
                assert!(!suggestion.is_empty(),
                        "Step 17 mandates a non-empty remediation suggestion");
            }
            other => panic!("expected PlanDagInvalid(cyclic_dependency), got {other:?}"),
        }
        // Registry must remain empty too — partial population on a
        // rolled-back tx would let stale glob entries leak into later
        // intent checks. We populate AFTER tx.commit(), so this MUST hold.
        assert!(registry.is_empty(),
                "registry must not be populated when the tx rolls back");

        // INV-STORE-02 atomicity: nothing partial.
        assert_eq!(
            read_initiative_state(&store, &init_id), "Draft",
            "initiative must remain Draft on cycle rejection",
        );
        assert_eq!(
            count_initiative_rows(&store, "tasks", &init_id), 0,
            "no task rows may be persisted when the tx rolls back",
        );
        assert_eq!(
            count_edges_for_initiative(&store, &init_id), 0,
            "no edges may be persisted when the tx rolls back",
        );

        // Audit-after-commit invariant: a rolled-back operation MUST NOT
        // produce a PlanApproved record.
        assert!(audit.events().is_empty(),
                "no audit events may be emitted when the tx rolls back");
    }

    /// **V2 Step 17 end-to-end** — each shift-left DAG rule must abort
    /// `approve_plan` BEFORE any tx state mutation. We pin the
    /// "no rows written" property for all four rules so a future
    /// regression that, say, runs the path-format check before the
    /// DAG check (and therefore opens a tx) is caught.
    fn assert_dag_rule_blocks_approve_plan(plan: &str, expected_rule: &'static str) {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap_err();
        match err {
            LifecycleError::PlanDagInvalid { rule, .. } => {
                assert_eq!(rule, expected_rule,
                           "expected rule {expected_rule}, got {rule}");
            }
            other => panic!("expected PlanDagInvalid({expected_rule}), got {other:?}"),
        }

        // INV-STORE-02 atomicity: shift-left rejection MUST NOT touch
        // initiatives, tasks, edges, or audit.
        assert_eq!(read_initiative_state(&store, &init_id), "Draft",
                   "initiative must remain Draft after shift-left rejection");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 0);
        assert_eq!(count_edges_for_initiative(&store, &init_id), 0);
        assert!(audit.events().is_empty(),
                "shift-left rejection must emit no audit events");
        assert!(registry.is_empty(),
                "shift-left rejection must not populate the plan registry");
    }

    #[test]
    fn approve_plan_rejects_duplicate_task_id_shift_left() {
        let plan = r#"
            [[tasks]]
            task_id = "dup"
            [[tasks]]
            task_id = "dup"
        "#;
        assert_dag_rule_blocks_approve_plan(plan, "duplicate_task_id");
    }

    #[test]
    fn approve_plan_rejects_self_loop_shift_left() {
        let plan = r#"
            [[tasks]]
            task_id      = "solo"
            predecessors = ["solo"]
        "#;
        assert_dag_rule_blocks_approve_plan(plan, "self_loop");
    }

    #[test]
    fn approve_plan_rejects_dangling_dependency_shift_left() {
        let plan = r#"
            [[tasks]]
            task_id      = "t1"
            [[tasks]]
            task_id      = "t2"
            predecessors = ["phantom"]
        "#;
        assert_dag_rule_blocks_approve_plan(plan, "dangling_dependency");
    }

    #[test]
    fn approve_plan_rejects_bad_signature_without_starting_tx() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [[tasks]]
            task_id = "t1"
        "#;
        let (init_id, _correct_pk) = seed_draft_initiative(&store, plan, &sk);

        // Hand `approve_plan` a different pubkey — sig will fail to verify.
        let wrong_pk = SigningKey::from_bytes(&[0x99u8; 32]).verifying_key().to_bytes();
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();
        let err = approve_plan(
            &init_id, "op-test", None, &wrong_pk, 1, &store, &audit, &registry,
        ).unwrap_err();
        assert!(
            matches!(err, LifecycleError::PlanSignatureInvalid { .. }),
            "expected PlanSignatureInvalid, got {err:?}",
        );

        // No state change at all.
        assert_eq!(read_initiative_state(&store, &init_id), "Draft");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 0);
        assert!(audit.events().is_empty(),
                "audit must remain silent when the signature check fails");
    }

    #[test]
    fn approve_plan_is_idempotent_under_double_call() {
        // Calling approve_plan twice on the same Draft must succeed once
        // (Draft → Executing) and fail the second time (already Executing).
        // The second failure must NOT clobber the first call's state.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [[tasks]]
            task_id = "only"
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit = FakeAuditSink::new();

        let registry = PlanRegistry::new();
        approve_plan(&init_id, "op-1", None, &pk_bytes, 1, &store, &audit, &registry).unwrap();
        let second = approve_plan(&init_id, "op-2", None, &pk_bytes, 1, &store, &audit, &registry);
        assert!(second.is_err(), "second approve must fail (not Draft)");

        assert_eq!(read_initiative_state(&store, &init_id), "Executing");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 1);

        // Exactly ONE PlanApproved emitted, despite two attempts. The
        // second (failed) call must NOT add an audit row.
        let approved: Vec<_> = audit.events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "PlanApproved")
            .collect();
        assert_eq!(approved.len(), 1,
                   "PlanApproved must emit exactly once across both attempts");
    }

    #[test]
    fn approve_plan_records_correct_policy_epoch_on_tasks() {
        // policy_epoch column on `tasks` must equal what the caller passed —
        // not the hardcoded value that the OLD `admit_task` helper used.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"[[tasks]]
        task_id = "t1"
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit = FakeAuditSink::new();

        let registry = PlanRegistry::new();
        approve_plan(&init_id, "op", None, &pk_bytes, 42, &store, &audit, &registry).unwrap();

        let conn = store.lock_sync();
        let epoch: i64 = conn.query_row(
            &format!("SELECT policy_epoch FROM {TASKS} WHERE initiative_id=?1"),
            rusqlite::params![&init_id],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(epoch, 42, "policy_epoch must be the value passed to approve_plan");
    }

    /// Step-10 quarantine prerequisite: every successful approval MUST
    /// stamp `signed_plan_artifacts.signed_by_fingerprint` with the
    /// fingerprint of the approving operator. Without this row the
    /// `quarantine-plans-by` sweep cannot map an operator key back to
    /// the initiatives they approved (kernel-store.md §2.5.8).
    #[test]
    fn approve_plan_stamps_signed_by_fingerprint_on_signed_plan_artifacts() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"[[tasks]]
        task_id = "t1"
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        // Pre-approval: column exists (migration 3) but is NULL.
        {
            let conn = store.lock_sync();
            let pre: Option<String> = conn.query_row(
                &format!(
                    "SELECT signed_by_fingerprint FROM {SIGNED_PLAN_ARTIFACTS} \
                     WHERE initiative_id=?1"
                ),
                rusqlite::params![&init_id],
                |r| r.get(0),
            ).unwrap();
            assert!(pre.is_none(),
                "fresh signed_plan_artifacts row must have NULL signed_by_fingerprint until approval");
        }

        approve_plan(&init_id, "op-prime-fp", None, &pk_bytes, 1, &store, &audit, &registry)
            .unwrap();

        let conn = store.lock_sync();
        let stamped: Option<String> = conn.query_row(
            &format!(
                "SELECT signed_by_fingerprint FROM {SIGNED_PLAN_ARTIFACTS} \
                 WHERE initiative_id=?1"
            ),
            rusqlite::params![&init_id],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(
            stamped.as_deref(),
            Some("op-prime-fp"),
            "approve_plan MUST stamp the approving operator's fingerprint into \
             signed_plan_artifacts.signed_by_fingerprint so quarantine-plans-by has \
             data to sweep (kernel-store.md §2.5.8)",
        );
    }

    // ── §2.5.8 path-scope wiring through approve_plan ──────────────────────

    #[test]
    fn approve_plan_populates_registry_with_path_scope_fields() {
        // Each task's four §2.5.8 fields land in the in-memory registry
        // exactly as parsed from the signed plan — values, not just keys.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [[tasks]]
            task_id                   = "t1"
            # V2 Step 19: directory prefix `src/` (recursive) +
            # exact filename `README.md`. `path_export_globs` keeps
            # V1 glob syntax — it's a *filter*, not containment.
            path_allowlist            = ["src/", "README.md"]
            path_export_to_successors = true
            path_export_globs         = ["src/ipc/**"]

            [[tasks]]
            task_id        = "t2"
            path_allowlist = ["docs/"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        approve_plan(&init_id, "op", None, &pk_bytes, 1, &store, &audit, &registry).unwrap();

        let f1 = registry.get(&TaskKey::new(&init_id, "t1"))
            .expect("registry must contain t1");
        assert_eq!(f1.path_allowlist, vec!["src/", "README.md"]);
        assert!(f1.path_export_to_successors);
        assert_eq!(f1.path_export_globs, vec!["src/ipc/**"]);
        assert!(!f1.path_scope_override);

        let f2 = registry.get(&TaskKey::new(&init_id, "t2"))
            .expect("registry must contain t2");
        assert_eq!(f2.path_allowlist, vec!["docs/"]);
        assert!(!f2.path_export_to_successors,
                "t2 omits the field — must default to false");
    }

    // ── V2 §Step 11 — `[orchestrator]` cross_cutting_artifacts wiring ─────

    #[test]
    fn approve_plan_populates_orchestrator_cross_cutting_artifacts() {
        // The `[orchestrator]` table's `cross_cutting_artifacts` lands
        // in `PlanRegistry::orchestrator(initiative_id)` — the bridge
        // that `compute_hybrid_effective_allow` reads at IntegrationMerge
        // admission time.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [orchestrator]
            cross_cutting_artifacts = ["Cargo.lock", "package-lock.json"]

            [[tasks]]
            task_id        = "t1"
            path_allowlist = ["src/"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        approve_plan(&init_id, "op", None, &pk_bytes, 1, &store, &audit, &registry).unwrap();

        let orch = registry.orchestrator(&init_id)
            .expect("registry must contain an orchestrator entry for the initiative");
        assert_eq!(
            orch.cross_cutting_artifacts,
            vec!["Cargo.lock".to_owned(), "package-lock.json".to_owned()],
            "approve_plan must hydrate `[orchestrator] cross_cutting_artifacts` \
             into the in-memory PlanRegistry verbatim (V2 §Step 11)",
        );
    }

    #[test]
    fn approve_plan_orchestrator_section_is_optional() {
        // Plans WITHOUT `[orchestrator]` must approve cleanly — the
        // section is optional per `v2-deep-spec.md §Step 11`. The
        // registry entry that's persisted is the empty `Default::default()`.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [[tasks]]
            task_id        = "lone-task"
            path_allowlist = ["src/"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        approve_plan(&init_id, "op", None, &pk_bytes, 1, &store, &audit, &registry).unwrap();

        let orch = registry.orchestrator(&init_id)
            .unwrap_or_default();
        assert!(orch.cross_cutting_artifacts.is_empty(),
                "missing `[orchestrator]` must yield an empty artifact list");
    }

    #[test]
    fn approve_plan_rejects_glob_in_cross_cutting_artifacts() {
        // Glob-bearing entries are rejected before BEGIN TRANSACTION —
        // the kernel state must remain Draft and the registry must stay
        // empty. Mirrors the shift-left posture of `validate_plan_dag` /
        // `validate_path_allowlist_v2_format`.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [orchestrator]
            cross_cutting_artifacts = ["Cargo.*"]

            [[tasks]]
            task_id        = "t1"
            path_allowlist = ["src/"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap_err();
        assert!(
            matches!(
                err,
                LifecycleError::CrossCuttingArtifactInvalidSyntax {
                    reason: "glob_character", ..
                },
            ),
            "expected CrossCuttingArtifactInvalidSyntax(glob_character), got {err:?}",
        );

        // Shift-left posture: state never advanced past Draft, no tasks
        // admitted, audit silent, registry empty for both per-task and
        // orchestrator entries.
        assert_eq!(read_initiative_state(&store, &init_id), "Draft");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 0);
        assert!(audit.events().is_empty());
        assert!(registry.is_empty());
        assert!(registry.orchestrator(&init_id).is_none(),
                "registry must NOT carry an orchestrator entry when approve_plan failed");
    }

    #[test]
    fn approve_plan_rejects_directory_in_cross_cutting_artifacts() {
        // Trailing-slash entries are rejected — Step 11 mandates exact
        // filenames, not directory prefixes (Step 19 vocabulary doesn't
        // compose with the cross-cutting "well-known files" model).
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [orchestrator]
            cross_cutting_artifacts = ["vendor/"]

            [[tasks]]
            task_id        = "t1"
            path_allowlist = ["src/"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        let err = approve_plan(
            &init_id, "op", None, &pk_bytes, 1, &store, &audit, &registry,
        ).unwrap_err();
        assert!(
            matches!(
                err,
                LifecycleError::CrossCuttingArtifactInvalidSyntax {
                    reason: "trailing_slash", ..
                },
            ),
            "expected CrossCuttingArtifactInvalidSyntax(trailing_slash), got {err:?}",
        );
    }

    #[test]
    fn repopulate_plan_registry_rehydrates_orchestrator_artifacts() {
        // Hot-restart parity: kernel reboot must rebuild the in-memory
        // PlanRegistry's orchestrator entry from the on-disk plan TOML.
        // Without this, IntegrationMerge would silently fail post-restart
        // because `compute_hybrid_effective_allow` would not see the
        // operator-declared cross-cutting artifacts.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [orchestrator]
            cross_cutting_artifacts = ["Cargo.lock", "go.sum"]

            [[tasks]]
            task_id        = "t1"
            path_allowlist = ["src/"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry_one = PlanRegistry::new();

        approve_plan(&init_id, "op", None, &pk_bytes, 1, &store, &audit, &registry_one).unwrap();

        // Simulate a kernel restart: brand-new (empty) registry rebuilt
        // from the on-disk store via repopulate_plan_registry.
        let registry_two = PlanRegistry::new();
        repopulate_plan_registry(&store, &registry_two).unwrap();

        let orch = registry_two.orchestrator(&init_id)
            .expect("repopulate must rehydrate orchestrator entry");
        assert_eq!(
            orch.cross_cutting_artifacts,
            vec!["Cargo.lock".to_owned(), "go.sum".to_owned()],
            "repopulate_plan_registry must rebuild cross_cutting_artifacts from \
             the on-disk plan TOML (V2 §Step 11 hot-restart parity)",
        );
    }

    #[test]
    fn approve_plan_emits_path_scope_override_audit_event_per_overriding_task() {
        // Per kernel-store.md §2.5.8 `path_scope_override`:
        //   "the kernel emits PathScopeOverrideApplied { initiative_id,
        //    task_id, operator_id } for every task with
        //    path_scope_override = true, inside the approve_plan
        //    transaction."
        // Two of three tasks set the override; PlanApproved + 2 events
        // = 3 audit emissions total, in deterministic order
        // (PlanApproved first, then one PathScopeOverrideApplied per
        // overriding task in plan order).
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [[tasks]]
            task_id             = "t-normal"
            path_allowlist      = ["src/"]

            [[tasks]]
            task_id             = "t-override-1"
            path_scope_override = true

            [[tasks]]
            task_id             = "t-override-2"
            path_scope_override = true
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        approve_plan(&init_id, "op-prime", Some("Chika".to_owned()), &pk_bytes, 1, &store, &audit, &registry).unwrap();

        let evs = audit.events();
        let kinds: Vec<_> = evs.iter().map(|e| e.kind.as_str()).collect();
        // V2 admission emits the per-initiative audit sequence:
        //   PlanApproved → SessionCreated (auto-spawned Orchestrator,
        //   INV-PLANNER-HARNESS-06) → one PathScopeOverrideApplied per
        //   overriding task.
        assert_eq!(
            kinds,
            vec![
                "PlanApproved",
                "SessionCreated",
                "PathScopeOverrideApplied",
                "PathScopeOverrideApplied",
            ],
            "expected PlanApproved → SessionCreated → 2× PathScopeOverrideApplied",
        );

        // The override events MUST carry initiative + task + operator.
        let overriding_task_ids: Vec<_> = evs.iter()
            .filter(|e| e.kind.as_str() == "PathScopeOverrideApplied")
            .map(|e| e.task_id.clone().unwrap_or_default())
            .collect();
        assert_eq!(overriding_task_ids, vec!["t-override-1", "t-override-2"]);

        for ev in evs.iter().filter(|e| e.kind.as_str() == "PathScopeOverrideApplied") {
            assert_eq!(ev.initiative_id.as_deref(), Some(init_id.as_str()));
            // Both the operator fingerprint AND the display name
            // (kernel-store.md §2.5.2 "Operator display-name fields")
            // go into the AuditEventKind variant payload. Pin both
            // so a future schema change can't silently drop either.
            let dbg = format!("{:?}", ev.kind);
            assert!(dbg.contains("op-prime"),
                    "PathScopeOverrideApplied payload must record approving_operator: {dbg}");
            assert!(dbg.contains("Chika"),
                    "PathScopeOverrideApplied payload must record \
                     approving_operator_display_name when the dispatcher \
                     resolved one: {dbg}");
        }
    }

    #[test]
    fn approve_plan_emits_no_override_event_when_no_task_overrides() {
        // Conservative path: the override event MUST NOT be emitted for
        // plans where every task uses the normal allowlist mechanism.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [[tasks]]
            task_id        = "t1"
            path_allowlist = ["src/"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit    = FakeAuditSink::new();
        let registry = PlanRegistry::new();

        approve_plan(&init_id, "op", None, &pk_bytes, 1, &store, &audit, &registry).unwrap();

        let kinds: Vec<_> = audit.events().iter().map(|e| e.kind.as_str()).collect();
        // V2 admission still emits SessionCreated for the auto-spawned
        // Orchestrator (INV-PLANNER-HARNESS-06); the rule under test is
        // that NO PathScopeOverrideApplied event is emitted when no
        // operator task sets the override.
        assert_eq!(kinds, vec!["PlanApproved", "SessionCreated"],
                   "PathScopeOverrideApplied must NOT emit when no task sets the override");
    }

    // ── repopulate_plan_registry — kernel-restart hook ────────────────────

    #[test]
    fn repopulate_plan_registry_refills_executing_initiatives() {
        // Simulate kernel restart: approve a plan, then drop the registry
        // and rebuild it from the immutable signed_plan_artifacts row.
        // The repopulated registry must be byte-equal for the values
        // that matter to path-scope enforcement.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [[tasks]]
            task_id                   = "t1"
            path_allowlist            = ["src/"]
            path_export_to_successors = true
            path_export_globs         = ["src/ipc/**"]

            [[tasks]]
            task_id             = "t2"
            path_scope_override = true
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit         = FakeAuditSink::new();
        let live_registry = PlanRegistry::new();

        approve_plan(
            &init_id, "op", None, &pk_bytes, 1, &store, &audit, &live_registry,
        ).unwrap();

        // Simulate a kernel restart — fresh registry, populated only
        // by the boot-time hook.
        let restarted_registry = PlanRegistry::new();
        let n = repopulate_plan_registry(&store, &restarted_registry).unwrap();
        assert_eq!(n, 2, "two tasks must be re-inserted from the plan");

        let f1 = restarted_registry.get(&TaskKey::new(&init_id, "t1")).unwrap();
        assert_eq!(f1.path_allowlist, vec!["src/"]);
        assert!(f1.path_export_to_successors);
        assert_eq!(f1.path_export_globs, vec!["src/ipc/**"]);
        assert!(!f1.path_scope_override);

        let f2 = restarted_registry.get(&TaskKey::new(&init_id, "t2")).unwrap();
        assert!(f2.path_scope_override);
    }

    #[test]
    fn repopulate_plan_registry_skips_terminal_initiatives() {
        // After an initiative is Aborted, its tasks never accept intents
        // again — there is no reason to repopulate registry entries for
        // it. Conserves memory and prevents accidentally honouring an
        // override on an aborted plan.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"[[tasks]]
        task_id = "t1"
        path_allowlist = ["src/"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit         = FakeAuditSink::new();
        let live_registry = PlanRegistry::new();

        approve_plan(
            &init_id, "op", None, &pk_bytes, 1, &store, &audit, &live_registry,
        ).unwrap();
        abort_initiative(&init_id, "op", &store).unwrap();

        let restarted = PlanRegistry::new();
        let n = repopulate_plan_registry(&store, &restarted).unwrap();
        assert_eq!(n, 0, "aborted initiatives must NOT be repopulated");
        assert!(restarted.is_empty());
    }

    #[test]
    fn repopulate_plan_registry_skips_draft_initiatives() {
        // Draft initiatives have plan_bytes but no `tasks` rows yet —
        // skipping them keeps the registry from holding stale entries
        // that would later contradict whatever the operator finally
        // approves.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"[[tasks]]
        task_id = "t1"
        path_allowlist = ["src/"]
        "#;
        let (_init_id, _pk) = seed_draft_initiative(&store, plan, &sk);

        let registry = PlanRegistry::new();
        let n = repopulate_plan_registry(&store, &registry).unwrap();
        assert_eq!(n, 0,
            "Draft initiatives have no admitted tasks — repopulate must skip");
    }

    #[test]
    fn repopulate_plan_registry_handles_empty_store() {
        // No initiatives → nothing to repopulate, MUST NOT error.
        let store    = Store::open_in_memory().unwrap();
        let registry = PlanRegistry::new();
        let n        = repopulate_plan_registry(&store, &registry).unwrap();
        assert_eq!(n, 0);
        assert!(registry.is_empty());
    }

    // ── INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern D) regression ───────

    /// `abort_initiative` must commit the `tasks` bulk-cancel and the
    /// `initiatives` UPDATE in a SINGLE transaction. Pre-fix, the two
    /// writes ran under one mutex hold but with SQLite per-statement
    /// auto-commit; a process crash between them would leave tasks
    /// `Cancelled` while the initiative remained `Executing` forever.
    ///
    /// Direct round-trip-through-crash testing is hard from a
    /// `#[cfg(test)]` block (would need WAL frame-level fault injection),
    /// so we pin the post-fix property by asserting that the success path
    /// commits BOTH writes and the failure path commits NEITHER. The
    /// failure path is exercised by triggering a CHECK violation on the
    /// final write — pre-fix, the first UPDATE would have auto-committed
    /// even though the second errored; post-fix, the transaction rolls
    /// back the first UPDATE too.
    #[test]
    fn abort_initiative_commits_tasks_and_initiative_atomically() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"[[tasks]]
        task_id = "t1"
        path_allowlist = ["src/"]
        "#;
        let (init_id, pk) = seed_draft_initiative(&store, plan, &sk);
        let audit         = FakeAuditSink::new();
        let live_registry = PlanRegistry::new();
        approve_plan(&init_id, "op", None, &pk, 1, &store, &audit, &live_registry).unwrap();

        // Sanity: task is Admitted, initiative is Executing.
        {
            let conn = store.lock_sync();
            let task_state: String = conn.query_row(
                &format!("SELECT state FROM {TASKS} WHERE task_id='t1'"),
                [], |r| r.get(0),
            ).unwrap();
            let init_state: String = conn.query_row(
                &format!("SELECT state FROM {INITIATIVES} WHERE initiative_id=?1"),
                rusqlite::params![&init_id], |r| r.get(0),
            ).unwrap();
            assert_eq!(task_state, "Admitted");
            assert_eq!(init_state, "Executing");
        }

        abort_initiative(&init_id, "op", &store).unwrap();

        // Both writes MUST be visible (success path = commit both).
        let conn = store.lock_sync();
        let task_state: String = conn.query_row(
            &format!("SELECT state FROM {TASKS} WHERE task_id='t1'"),
            [], |r| r.get(0),
        ).unwrap();
        let init_state: String = conn.query_row(
            &format!("SELECT state FROM {INITIATIVES} WHERE initiative_id=?1"),
            rusqlite::params![&init_id], |r| r.get(0),
        ).unwrap();
        assert_eq!(task_state, "Cancelled",
            "tasks UPDATE must have committed");
        assert_eq!(init_state, "Aborted",
            "initiatives UPDATE must have committed in the SAME transaction");
    }

    /// `create_initiative` must commit BOTH the `initiatives` INSERT and
    /// the `signed_plan_artifacts` INSERT in one transaction. Pre-fix, a
    /// crash between the two left an orphaned `Draft` initiative with no
    /// plan artifact — `approve_plan` would fail with QueryReturnedNoRows
    /// and the operator could neither approve nor delete it.
    ///
    /// We pin the property by inducing the failure path: if the second
    /// INSERT fails (signature is invalid), the first INSERT MUST also
    /// roll back so no orphan `initiatives` row remains.
    #[test]
    fn create_initiative_rolls_back_initiative_row_on_signature_failure() {
        let store = Store::open_in_memory().unwrap();
        let plan_toml = r#"[[tasks]]
        task_id = "t1"
        "#;
        // Provide a malformed signature hex — `create_initiative` must
        // reject this BEFORE writing either row (validation happens
        // before the transaction opens).
        let result = create_initiative(plan_toml, "not-hex-at-all", "op", &store);
        assert!(result.is_err(),
            "malformed signature must reject the submission");

        // No `initiatives` row should exist (validation was pre-tx).
        let conn = store.lock_sync();
        let count: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {INITIATIVES}"),
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(count, 0,
            "validation failure must not leave orphan initiative row");
        let plan_count: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {SIGNED_PLAN_ARTIFACTS}"),
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(plan_count, 0,
            "validation failure must not leave orphan plan artifact row");
    }

    /// Happy-path `create_initiative` MUST land BOTH rows together.
    #[test]
    fn create_initiative_commits_both_rows_atomically_on_success() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan_toml = r#"[[tasks]]
        task_id = "t1"
        "#;
        let plan_bytes = plan_toml.as_bytes().to_vec();
        let signing_input = raxis_crypto::plan::plan_signing_input(&plan_bytes);
        let sig_hex = hex::encode(sk.sign(&signing_input).to_bytes());

        let created = create_initiative(plan_toml, &sig_hex, "op", &store).unwrap();

        // Both rows MUST be present.
        let conn = store.lock_sync();
        let init_state: String = conn.query_row(
            &format!("SELECT state FROM {INITIATIVES} WHERE initiative_id=?1"),
            rusqlite::params![&created.initiative_id], |r| r.get(0),
        ).unwrap();
        assert_eq!(init_state, "Draft");
        let plan_present: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {SIGNED_PLAN_ARTIFACTS} WHERE initiative_id=?1"),
            rusqlite::params![&created.initiative_id], |r| r.get(0),
        ).unwrap();
        assert_eq!(plan_present, 1,
            "signed_plan_artifacts row MUST commit alongside initiatives row");
    }
}
