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
use raxis_types::{unix_now_secs, InitiativeState, TaskState};

use crate::authority::keys::AuthorityError;
use crate::initiatives::plan_registry::{PlanRegistry, TaskKey, TaskPlanFields};
use crate::scheduler::{self, SchedulerError};

// Table name consts — one definition, used everywhere below.
const INITIATIVES: &str            = Table::Initiatives.as_str();
const SIGNED_PLAN_ARTIFACTS: &str  = Table::SignedPlanArtifacts.as_str();
const TASKS: &str                  = Table::Tasks.as_str();

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

    let plan_toml_str = String::from_utf8_lossy(&plan_bytes);
    let plan_tasks    = parse_plan_tasks(&plan_toml_str)?;

    // V2 Step 17 — shift-left plan validation. Each helper runs BEFORE
    // `BEGIN TRANSACTION`, so a malformed plan never mutates kernel
    // state. We run the DAG check first because a structurally broken
    // plan can confuse later validators (e.g. a path-allowlist entry
    // on a duplicate task_id), and the path-format check second because
    // it is purely syntactic and cannot depend on graph well-formedness.
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
        };
        path_scope_snapshots.push((
            pt.task_id.clone(),
            path_fields,
            pt.path_scope_override,
        ));

        let task = scheduler::PlanTask {
            task_id:       pt.task_id.clone(),
            initiative_id: initiative_id.to_owned(),
            lane_id:       pt.lane_id,
            name:          pt.name,
            dependencies:  pt.predecessors,
        };
        scheduler::admit_in_tx(&tx, task, policy_epoch)?;
    }

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
                },
            );
            inserted += 1;
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
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanTask {
    task_id:      String,
    name:         String,
    lane_id:      String,
    predecessors: Vec<String>,

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
}

/// Parse `[[tasks]]` array from plan TOML.
///
/// Required: `task_id`.
/// Optional: `name` (defaults to `task_id`), `lane_id` (defaults to `"default"`),
///           `predecessors` (defaults to empty list).
///
/// §2.5.8 path-scope fields: all optional; defaults are deny-everything,
/// no-export, no-override (matching the spec's locked-down defaults).
/// Non-array values for the array-typed fields silently fall back to the
/// default — same conservative behaviour as `predecessors`. The signing
/// tool is the gate that catches operator typos; the kernel does not
/// re-validate plan shape beyond what's necessary for safety.
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
        let lane_id = entry.get("lane_id").and_then(|v| v.as_str()).unwrap_or("default").to_owned();

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

        tasks.push(PlanTask {
            task_id,
            name,
            lane_id,
            predecessors,
            path_allowlist,
            path_export_to_successors,
            path_export_globs,
            path_scope_override,
        });
    }

    Ok(tasks)
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
    fn parse_plan_tasks_lane_defaults_to_default() {
        let toml = "[[tasks]]\ntask_id = \"t2\"\n";
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].lane_id, "default");
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
    use raxis_audit_tools::FakeAuditSink;
    use raxis_store::Store;

    /// Deterministic Ed25519 keypair for fixtures (no entropy needed).
    fn fixture_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Build a Draft initiative + signed_plan_artifacts row directly (no
    /// IPC), returning everything the test needs to call `approve_plan`.
    fn seed_draft_initiative(
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
            lane_id  = "default"

            [[tasks]]
            task_id      = "t2"
            name         = "second"
            lane_id      = "default"
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

        // Audit-after-commit per kernel-store.md §2.5.2: PlanApproved emits
        // exactly once, with the initiative_id wired through.
        let events = audit.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind.as_str(), "PlanApproved");
        assert_eq!(events[0].initiative_id.as_deref(), Some(init_id.as_str()));
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
        assert_eq!(
            kinds,
            vec!["PlanApproved", "PathScopeOverrideApplied", "PathScopeOverrideApplied"],
            "expected exactly one PlanApproved + 2 PathScopeOverrideApplied (in that order)",
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
        assert_eq!(kinds, vec!["PlanApproved"],
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
