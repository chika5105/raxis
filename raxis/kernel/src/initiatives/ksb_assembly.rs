//! Kernel-side KSB (Kernel-State-Block) assembler.
//! Closes V2 by reading the live kernel
//! state for an initiative + task at session-spawn time and projecting
//! it into a [`raxis_ksb::KsbSnapshot`]. The result is JSON-serialized
//! and stamped into the spawned planner binary's env at
//! `RAXIS_PLANNER_KSB` (constant [`raxis_ksb::PLANNER_KSB_ENV`]).
//! ## Why this lives in `initiatives/`
//! The KSB is a per-initiative-and-per-task projection. Every input
//! field comes from rows the lifecycle subsystem already owns
//! (`plan_registry`, `tasks`, `escalations`, `task_credential_proxies`),
//! so co-locating the assembler keeps the read paths in one module
//! and avoids forcing every IPC handler to learn the schema.
//! ## Trust + redaction boundary
//! This is the **only** place where operator-supplied free-form text
//! (task descriptions, reviewer critiques, escalation summaries) is
//! projected into the LLM's system prompt. The
//! [`TASK_DESCRIPTION_MAX_BYTES`] cap is the kernel-side defence; the
//! `raxis-ksb` renderer additionally rejects any text containing the
//! `KSB_DELIMITER_CLOSE` byte sequence (defense-in-depth INV-KSB-01).
//! ## Failure model
//! The assembler is fail-soft: it returns `Result<KsbSnapshot, …>`.
//! A read failure on an optional field (e.g. `escalations` table
//! query times out) returns the error to the caller; the caller (the
//! spawn path) MAY decide to spawn without a KSB rather than refuse
//! the spawn. The current spawn-side wiring `unwrap_or_default()`s a
//! minimum-bootable snapshot on read failure so a transient SQLite
//! lock contention does not block the operator's plan from
//! activating.

use rusqlite::{Connection, OptionalExtension};
use thiserror::Error;

use raxis_ksb::{
    Capabilities, ConcurrencyCapabilityView, CredentialPort, DagRow, ExecutorCapabilities,
    GateStatusView, InitiativeCapabilityView, IntegrationMergeCapabilityView,
    IntegrationMergeExecutorSha, KsbSnapshot, OrchestratorCapabilities, PendingEscalation,
    ReviewerCapabilities, ReviewerVerdict, SessionCapabilityView, TaskCapabilityView,
    KSB_SCHEMA_VERSION,
};
use raxis_store::Table;
use raxis_types::SessionAgentType;
use raxis_types::TaskState;

use crate::orch_respawn_ceiling::MAX_ORCH_NO_PROGRESS_RESPAWNS;
use raxis_types::intent_admit::{admit_retry_subtask_check, AdmitOutcome, RetryAdmitInputs};

use crate::initiatives::plan_registry::{PlanRegistry, TaskKey};
use crate::initiatives::review_aggregation::{
    compute_aggregate_review_outcome_with_conn, AgentTypeFilter,
};

/// `task_description` cap. The kernel
/// truncates `[[tasks]] description` (already capped at admission
/// against an upstream limit; this is the projection-time backstop)
/// to this size before stamping it into the rendered KSB. The model
/// will see at most this many bytes of operator-authored prompt
/// material per turn.
pub const TASK_DESCRIPTION_MAX_BYTES: usize = 4096;

/// Failure modes for the assembler.
#[derive(Debug, Error)]
pub enum KsbAssemblyError {
    /// SQLite read failed. Surfaces the underlying `rusqlite::Error`
    /// verbatim so dashboards can pivot on the `code()` projection.
    #[error("sqlite read failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// JSON serialization failed. Practically unreachable — every
    /// field of [`KsbSnapshot`] is `Serialize`-derived — but kept
    /// in the error enum so the spawn path's `?` operator stays
    /// honest.
    #[error("serde_json failed to serialise KsbSnapshot: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Role the spawn is targeting. Mirrors the lower-case ASCII values
/// the [`raxis_ksb::KsbSnapshot::role`] field carries.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KsbRole {
    Executor,
    Reviewer,
    Orchestrator,
}

impl KsbRole {
    /// Wire-stable role string. The renderer + every downstream
    /// LLM prompt template pivots on this verbatim — DO NOT
    /// rename without bumping [`KSB_SCHEMA_VERSION`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executor => "executor",
            Self::Reviewer => "reviewer",
            Self::Orchestrator => "orchestrator",
        }
    }
}

/// Assembled inputs the kernel passes to [`assemble_ksb_snapshot`].
/// Bundled into a struct so future fields (token-cost estimator,
/// witness DAG snapshot, …) can be appended without breaking every
/// call-site.
pub struct KsbInputs<'a> {
    pub initiative_id: &'a str,
    pub task_id: Option<&'a str>,
    pub role: KsbRole,
    /// Per-task token budget remaining, in LLM tokens. The kernel's
    /// budget subsystem feeds this; `0` is a valid value (the
    /// model is expected to terminate via `report_failure`).
    pub token_budget_remaining: u64,
    /// Per-task wall-clock budget remaining, seconds. `0` means the
    /// caller did not have a wall-clock budget to declare (the
    /// model treats `0` as "no enforced ceiling").
    pub wallclock_budget_remaining_s: u64,
    /// Credential proxy port assignments resolved at spawn time
    /// (one row per `[[tasks.credentials]]` decl). Empty for the
    /// reviewer (which cannot consume credentials —
    /// `INV-PLANNER-HARNESS-02`) and for tasks with no decls.
    pub credential_ports: Vec<CredentialPort>,
    /// Session id the spawn path is provisioning the planner role
    /// against. Stamped into the `capabilities.session.session_id`
    /// projection so the LLM has wire-stable identity for the
    /// envelope. Empty (`""`) ⇒ the spawn path did not yet have a
    /// session id (boot race / fixture); the assembler still
    /// populates the rest of the capabilities envelope but emits
    /// the literal empty string for `session_id`.
    pub session_id: &'a str,

    /// **V2.7 — `INV-KSB-MAX-TURNS-VISIBILITY-01`.** Resolved
    /// per-session planner turn ceiling. The spawn callsites
    /// (`session_spawn_orchestrator::spawn_orchestrator_for_initiative`
    /// and `…spawn_executor_for_task`) MUST populate this with
    /// the SAME `ResolvedPlannerMaxTurns::effective` value
    /// `resolve_planner_max_turns_for(task_fields, gateway,
    /// attempt)` returns for the env stamp — single source of
    /// truth for the resolution. Tests that do not care can
    /// pass
    /// [`crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS`].
    pub planner_max_turns: u32,

    /// **V3 — `INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01`.**
    /// Per-session breakdown of the progressive-scaling resolver's
    /// decision: `attempt`, `base`, `step`, `hard_ceiling`. The spawn
    /// callsites convert the `ResolvedPlannerMaxTurns` struct
    /// returned by `resolve_planner_max_turns_for` into this view via
    /// the `From<ResolvedPlannerMaxTurns>` impl. Surfaces onto the
    /// orchestrator + executor envelopes; the assembler discards it
    /// for the reviewer (role-scoping rule).
    pub max_turns_scaling: raxis_ksb::MaxTurnsScalingView,
}

/// Assemble the KSB snapshot the kernel will stamp into
/// `RAXIS_PLANNER_KSB`.
/// **Reads.**
///   * `tasks` — for the per-task `evaluation_sha` + per-initiative
///     DAG snapshot (every row of the initiative).
///   * `plan_registry` — for the `target_ref`, the per-task path
///     allowlist + description, and the per-initiative orchestrator
///     description.
///   * `escalations` — for the `pending_escalations` block (status
///     filter `Pending`, scoped to this initiative).
///   * `subtask_activations` (currently unused — reviewer verdicts
///     would be sourced here; placeholder for V3).
///     **Pure projection.** No mutations; safe to call from a
///     `spawn_blocking` context with the sync `Connection` lock.
pub fn assemble_ksb_snapshot(
    conn: &Connection,
    registry: &PlanRegistry,
    inputs: &KsbInputs<'_>,
) -> Result<KsbSnapshot, KsbAssemblyError> {
    let task_id = inputs.task_id.unwrap_or("");

    // ── Plan-registry projections ────────────────────────────────
    let task_fields = inputs
        .task_id
        .map(|tid| TaskKey::new(inputs.initiative_id.to_owned(), tid.to_owned()))
        .and_then(|key| registry.get(&key));
    let orch_fields = registry.orchestrator(inputs.initiative_id);

    let target_ref = orch_fields
        .as_ref()
        .map(|o| o.target_ref.clone())
        .unwrap_or_default();

    let path_allowlist = task_fields
        .as_ref()
        .map(|t| t.path_allowlist.clone())
        .unwrap_or_default();

    let task_description = match inputs.role {
        KsbRole::Orchestrator => {
            // Orchestrator: source from `[plan.initiative]
            // description` (held on `OrchestratorPlanFields`).
            orch_fields
                .as_ref()
                .map(|o| truncate_to_bytes(&o.description, TASK_DESCRIPTION_MAX_BYTES))
                .unwrap_or_default()
        }
        KsbRole::Executor | KsbRole::Reviewer => {
            // Executor / reviewer: source from per-task
            // `[[tasks]].description`.
            task_fields
                .as_ref()
                .map(|t| truncate_to_bytes(&t.description, TASK_DESCRIPTION_MAX_BYTES))
                .unwrap_or_default()
        }
    };

    // ── Per-task evaluation_sha ──────────────────────────────────
    let evaluation_sha = if !task_id.is_empty() {
        read_evaluation_sha(conn, task_id)?.unwrap_or_default()
    } else {
        String::new()
    };

    // ── DAG snapshot (executor sees nothing; reviewer + orchestrator
    //    see the full per-initiative DAG) ───────────────────────
    let dag_rows = match inputs.role {
        KsbRole::Executor => Vec::new(),
        KsbRole::Reviewer | KsbRole::Orchestrator => {
            read_dag_rows_for_initiative(conn, inputs.initiative_id, registry)?
        }
    };

    // ── Pending escalations scoped to this initiative ────────────
    let pending_escalations = read_pending_escalations(conn, inputs.initiative_id)?;

    // ── Gate / witness lifecycle posture ─────────────────────────
    // Keep gate visibility role-scoped: the orchestrator sees the
    // initiative-wide gate feed so it can distinguish "reviewer work
    // remains" from "verifier/integration gate is running"; executor /
    // reviewer sessions only see their own task id, avoiding sibling
    // leakage. The dashboard has a richer UI projection; this KSB view
    // is intentionally compact and action-shaped for the model.
    let gate_statuses = match inputs.role {
        KsbRole::Orchestrator => {
            read_gate_statuses_for_initiative(conn, inputs.initiative_id, None)?
        }
        KsbRole::Executor | KsbRole::Reviewer => match inputs.task_id {
            Some(tid) => read_gate_statuses_for_initiative(conn, inputs.initiative_id, Some(tid))?,
            None => Vec::new(),
        },
    };

    // ── Reviewer verdicts scoped to this initiative ──────────────
    // Closes `INV-PLANNER-ORCH-RETRY-ON-REJECT-01`
    // (`specs/invariants.md §10`): the orchestrator NNSP directs
    // the model to call `retry_subtask` whenever any
    // `reviewer_verdicts=` row reads `approved=false`. That rule
    // is dead-letter unless this projection actually populates
    // the rows from the live store. The reviewer's own
    // `tasks.review_verdict` (written by
    // `review_aggregation::increment_executor_review_reject_count`
    // post-`SubmitReview`) carries the per-Reviewer verdict; the
    // executor's `tasks.last_critique` carries the concatenated
    // formatted critiques (one per Reviewer per round). Executor
    // sessions get an empty list — the executor's KSB has no DAG
    // visibility per `KsbRole::Executor` matching above, and
    // surfacing siblings' verdicts to a peer Executor would
    // expose review state across DAG nodes the executor was not
    // permitted to read.
    let reviewer_verdicts = match inputs.role {
        KsbRole::Executor => Vec::new(),
        KsbRole::Reviewer | KsbRole::Orchestrator => {
            read_reviewer_verdicts_for_initiative(conn, inputs.initiative_id)?
        }
    };

    // ── Initiative anchor `base_sha` ─────────────────────────────
    // V2.5: every per-initiative session (orchestrator, executor,
    // reviewer) is anchored at the same base SHA — the SHA the
    // orchestrator's worktree was provisioned at by
    // `worktree_provisioning::provision_orchestrator_worktree`.
    // The orchestrator's `integration_merge` tool call cites this
    // verbatim as `base_sha`. We source it from the live
    // orchestrator session row so a respawn re-attached to the
    // existing anchor surfaces the same SHA without reading the
    // on-disk worktree (which would race the spawn).
    // A miss surfaces as an empty string; the renderer emits the
    // literal `<unset>` and the agent fails-loud per
    // `kernel-mechanics-prompt.md` ("never invent a SHA").
    let base_sha = read_initiative_anchor_base_sha(conn, inputs.initiative_id)?.unwrap_or_default();

    // Slice C — `INV-KSB-CAPABILITIES-TURN-COHERENT-01`: the
    // capabilities envelope is read from the SAME `&Connection` as
    // every other field above (no separate `BEGIN`/`COMMIT` —
    // SQLite serialises reads on a single connection so all reads
    // in this function see the same store snapshot).
    let capabilities = Some(assemble_capabilities(conn, registry, inputs, &base_sha)?);

    // ── iter62 — `INV-RETRY-LAST-CRITIQUE-IN-KSB-01` ─────────────
    // Surface the most-recent reviewer critique into the KSB so a
    // retried executor / reviewer can re-orient on the prior
    // round's feedback. Previously the persisted column was
    // correct but never projected — the round-N+1 LLM produced
    // the same flawed diff because it never saw the round-N
    // reviewer feedback.
    // Project on retry rounds only: a task whose most-recent
    // activation row carries `crash_retry_count > 0`,
    // `review_reject_count > 0`, OR `validation_reject_count > 0`
    // is "past attempt 1". Round-1 sessions surface `None` so
    // the KSB byte prefix stays stable for first-attempt tasks.
    // The orchestrator's KSB always omits this field (it has
    // initiative-wide visibility via the DAG / reviewer_verdicts
    // already; the per-task critique would be ambiguous without
    // a task scope).
    let last_critique = match inputs.role {
        KsbRole::Orchestrator => None,
        KsbRole::Executor | KsbRole::Reviewer => match inputs.task_id {
            None => None,
            Some(tid) => read_last_critique_for_retry(conn, tid)?,
        },
    };

    // ── iter65 — `INV-KSB-GATE-FIXUP-CONTEXT-01` ────────────────
    // Surface the gate-fixup context iff this is the KSB for a
    // gate-fixup executor task (`tasks.is_gate_fixup = 1`).
    // Non-fixup tasks (every steady-state executor / reviewer /
    // orchestrator) leave the field `None` so the wire stays
    // compact and the steady-state KSB shape is unchanged. The
    // orchestrator's KSB is never a gate-fixup view (the
    // orchestrator coordinates fixup spawns; it does not BECOME
    // one), so we short-circuit that role.
    let gate_fixup = match inputs.role {
        KsbRole::Orchestrator => None,
        KsbRole::Executor | KsbRole::Reviewer => match inputs.task_id {
            None => None,
            Some(tid) => read_gate_fixup_context(conn, tid)?,
        },
    };

    Ok(KsbSnapshot {
        version: KSB_SCHEMA_VERSION,
        initiative_id: inputs.initiative_id.to_owned(),
        task_id: inputs.task_id.map(str::to_owned),
        role: inputs.role.as_str().to_owned(),
        evaluation_sha,
        path_allowlist,
        token_budget_remaining: inputs.token_budget_remaining,
        wallclock_budget_remaining_s: inputs.wallclock_budget_remaining_s,
        dag_rows,
        task_description,
        target_ref,
        base_sha,
        reviewer_verdicts,
        pending_escalations,
        gate_statuses,
        credential_ports: inputs.credential_ports.clone(),
        capabilities,
        last_critique,
        gate_fixup,
    })
}

/// iter65 — `INV-KSB-GATE-FIXUP-CONTEXT-01`. Load the focused
/// gate-fixup context for a fixup executor's KSB. Returns
/// `Ok(None)` when the task is not a fixup (the common path),
/// or `Ok(Some(...))` when the task carries `is_gate_fixup = 1`
/// and all required parent linkage columns are present.
///
/// Errors out only on SQL-level failures; missing parent rows
/// (which would be a structural regression — every fixup task
/// has a parent by construction) downgrade to a defensive
/// `Ok(None)` with a kernel-bug stderr line so the spawn path
/// stays boot-safe rather than refusing to bring up the
/// session.
fn read_gate_fixup_context(
    conn: &rusqlite::Connection,
    task_id: &str,
) -> Result<Option<raxis_ksb::GateFixupContext>, rusqlite::Error> {
    let tasks = raxis_store::Table::Tasks.as_str();
    // Pull the fixup row.
    // (is_gate_fixup, parent_gate_failure_task_id, parent_gate_failure_type,
    //  last_gate_critique, last_gate_type, gate_fixup_attempts)
    type FixupChildRow = (
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    );
    let row: Result<FixupChildRow, rusqlite::Error> = conn.query_row(
        &format!(
            "SELECT is_gate_fixup, \
                    parent_gate_failure_task_id, \
                    parent_gate_failure_type, \
                    last_gate_critique, \
                    last_gate_type, \
                    COALESCE(gate_fixup_attempts, 0) \
               FROM {tasks} WHERE task_id = ?1"
        ),
        rusqlite::params![task_id],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        },
    );
    let (
        is_gate_fixup,
        parent_id_opt,
        parent_gate_type_opt,
        _last_critique,
        last_gate_type,
        _attempts,
    ) = match row {
        Ok(t) => t,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e),
    };
    if is_gate_fixup == 0 {
        return Ok(None);
    }
    let parent_id = match parent_id_opt {
        Some(p) if !p.is_empty() => p,
        _ => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"KsbAssemblyGateFixupMissingParent\",\
                 \"fixup_task_id\":\"{task_id}\"}}",
            );
            return Ok(None);
        }
    };
    // Gate-type / critique provenance:
    //   * The fixup's `parent_gate_failure_type` is the
    //     authoritative wire value the admit pipeline copied
    //     across at fixup-spawn time. Prefer it over the
    //     parent's `last_gate_type` (which could drift if the
    //     parent fails a different gate after the fixup was
    //     spawned).
    //   * The hint, however, lives on the PARENT's
    //     `last_gate_critique` because the witness handler
    //     persists the resolved hint on the parent at rejection
    //     time. The admit pipeline does NOT copy the hint onto
    //     the fixup row (the parent is the single source of
    //     truth — keeping the hint in one place avoids drift
    //     when the operator updates `agent_hint_default`).
    let gate_type = parent_gate_type_opt
        .or(last_gate_type)
        .unwrap_or_else(|| "<unknown>".to_owned());

    // Pull the parent's repair-relevant state.
    // (last_gate_critique, evaluation_sha, session_id)
    type FixupParentRow = (Option<String>, Option<String>, Option<String>);
    let parent_row: Result<FixupParentRow, rusqlite::Error> = conn.query_row(
        &format!(
            "SELECT last_gate_critique, evaluation_sha, session_id \
               FROM {tasks} WHERE task_id = ?1"
        ),
        rusqlite::params![&parent_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    );
    let (parent_critique, parent_eval_sha, parent_session_id) = match parent_row {
        Ok(t) => t,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"KsbAssemblyGateFixupParentMissing\",\
                 \"fixup_task_id\":\"{task_id}\",\"parent_task_id\":\"{parent_id}\"}}",
            );
            return Ok(None);
        }
        Err(e) => return Err(e),
    };

    // Resolve the parent's worktree_root from its session row.
    let parent_worktree_pointer: String = match parent_session_id.as_deref() {
        None => String::new(),
        Some(sid) => {
            let sessions = raxis_store::Table::Sessions.as_str();
            conn.query_row(
                &format!("SELECT worktree_root FROM {sessions} WHERE session_id = ?1"),
                rusqlite::params![sid],
                |r| r.get::<_, Option<String>>(0),
            )
            .unwrap_or(None)
            .unwrap_or_default()
        }
    };

    // Bound the hint to `WITNESS_AGENT_HINT_MAX_BYTES` defensively.
    // The witness handler already enforces the cap, but if the
    // operator hand-edits the column in an emergency the prompt
    // should still render safely.
    let hint = parent_critique.unwrap_or_default();
    let bounded_hint = if hint.len() > raxis_ksb::AGENT_HINT_MAX_BYTES {
        hint[..raxis_ksb::AGENT_HINT_MAX_BYTES].to_owned()
    } else {
        hint
    };

    // `attempt_index` for the prompt is 1-based: the
    // first fixup is attempt 1 even though the parent's
    // `gate_fixup_attempts` counter holds the post-admit value.
    // We use the parent's counter directly here because it has
    // been incremented at admit time per
    // `INV-GATE-FIXUP-BUDGET-KERNEL-ENFORCED-01`.
    let parent_attempts: i64 = conn
        .query_row(
            &format!("SELECT COALESCE(gate_fixup_attempts, 0) FROM {tasks} WHERE task_id = ?1"),
            rusqlite::params![&parent_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let attempt_index = u32::try_from(parent_attempts).unwrap_or(1).max(1);

    Ok(Some(raxis_ksb::GateFixupContext {
        gate_type,
        agent_hint: bounded_hint,
        parent_task_id: parent_id,
        parent_evaluation_sha: parent_eval_sha.unwrap_or_default(),
        parent_worktree_pointer,
        attempt_index,
        // `max_attempts` is policy-derived; the assembler doesn't
        // hold a `PolicyBundle` reference here, so we surface the
        // attempt count without a max ceiling. The renderer prints
        // `attempt=N/0` if the policy is unset, which the LLM
        // treats as "no declared ceiling — defer to the kernel's
        // budget check." Iter72: the gate-fixup admit pipeline is
        // kernel-authoritative (the kernel enforces the ceiling
        // at admit time); the executor's view here is the
        // attempt counter only.
        max_attempts: 0,
    }))
}

/// iter62 — `INV-RETRY-LAST-CRITIQUE-IN-KSB-01`. Read
/// `tasks.last_critique` for `task_id` IFF the most-recent
/// `subtask_activations` row indicates the task is past attempt
/// 1 (any of `crash_retry_count`, `review_reject_count`,
/// `validation_reject_count` is non-zero). Returns `None` on the
/// round-1 path so the KSB byte prefix stays stable.
fn read_last_critique_for_retry(
    conn: &Connection,
    task_id: &str,
) -> Result<Option<String>, KsbAssemblyError> {
    let row: Option<(i64, i64, i64, Option<String>)> = conn
        .query_row(
            &format!(
                "SELECT a.crash_retry_count, \
                        a.review_reject_count, \
                        COALESCE(a.validation_reject_count, 0), \
                        t.last_critique \
                   FROM {acts} a \
                   JOIN {tasks} t ON t.task_id = a.task_id \
                  WHERE a.task_id = ?1 \
                  ORDER BY a.created_at DESC \
                  LIMIT 1",
                acts = Table::SubtaskActivations.as_str(),
                tasks = Table::Tasks.as_str(),
            ),
            rusqlite::params![task_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(KsbAssemblyError::Sqlite)?;

    match row {
        Some((crash, review, validation, Some(critique)))
            if (crash > 0 || review > 0 || validation > 0) && !critique.is_empty() =>
        {
            Ok(Some(critique))
        }
        _ => Ok(None),
    }
}

/// Read the per-initiative anchor `base_sha` from the live
/// orchestrator session row. The orchestrator session is the
/// canonical source — every executor / reviewer session for the
/// initiative was cloned from that anchor.
/// Returns `Ok(None)` when no orchestrator row exists yet (boot
/// race) or the row's `base_sha` is `NULL` (the spawn path's
/// post-provisioning UPDATE has not landed yet). The caller falls
/// back to the literal `<unset>` rendering.
fn read_initiative_anchor_base_sha(
    conn: &Connection,
    initiative_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    use raxis_types::SessionAgentType;
    let sql = format!(
        "SELECT base_sha FROM {sessions} \
          WHERE initiative_id      = ?1 \
            AND session_agent_type = ?2 \
            AND base_sha IS NOT NULL \
          ORDER BY created_at DESC \
          LIMIT 1",
        sessions = Table::Sessions.as_str(),
    );
    conn.query_row(
        &sql,
        rusqlite::params![initiative_id, SessionAgentType::Orchestrator.as_sql_str()],
        |r| r.get::<_, Option<String>>(0),
    )
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        other => Err(other),
    })
}

/// Truncate `s` to at most `max_bytes` bytes, falling on a UTF-8
/// codepoint boundary. Empty when `s` is empty.
fn truncate_to_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

fn read_evaluation_sha(
    conn: &Connection,
    task_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    let sql = format!(
        "SELECT evaluation_sha FROM {tasks} WHERE task_id = ?1",
        tasks = Table::Tasks.as_str(),
    );
    conn.query_row(&sql, rusqlite::params![task_id], |r| {
        r.get::<_, Option<String>>(0)
    })
    .optional()
    .map(|o| o.flatten())
}

fn read_dag_rows_for_initiative(
    conn: &Connection,
    initiative_id: &str,
    registry: &PlanRegistry,
) -> Result<Vec<DagRow>, rusqlite::Error> {
    // V2.5 §11.4-adjacent — the DAG-row projection now includes
    // `evaluation_sha` so the Orchestrator's KSB-rendered `dag=`
    // block carries the per-task commit SHA the
    // `integration_merge` tool needs to cite as `head_sha`.
    // Without this projection the Orchestrator agent has no
    // wire-visible source for the SHA — it would have to invent
    // one or call `read_file` against `.git/refs/heads/...`,
    // both of which would round-trip incorrect (or empty)
    // values into the kernel.
    // Filter the synthetic coordinator row (`task_id == initiative_id`,
    // inserted at orchestrator-spawn time per `lifecycle.rs §spawn_
    // orchestrator_session_for_initiative` and used to receive the
    // initiative-level `block_reason` on `IntegrationMerge` failure).
    // The coordinator row is load-bearing for kernel bookkeeping and
    // for the dashboard's failure-surface, but it MUST NOT appear in
    // the orchestrator LLM's `dag=` block: the LLM has no admission
    // primitive that targets it, and leaking it caused the iter70
    // primary-initiative NNSP failure where the model spent its
    // turn budget puzzling "why is there a row whose id matches my
    // own initiative_id, in state=admitted, with no title or
    // reviewers?" instead of dispatching ready successor tasks.
    // (`INV-KSB-COORDINATOR-ROW-HIDDEN-FROM-DAG-01`.)
    let sql = format!(
        "SELECT task_id, state, evaluation_sha FROM {tasks} \
         WHERE initiative_id = ?1 \
           AND task_id != ?1 \
         ORDER BY admitted_at ASC, task_id ASC",
        tasks = Table::Tasks.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params![initiative_id], |r| {
            let task_id: String = r.get(0)?;
            let state: String = r.get(1)?;
            let evaluation_sha: Option<String> = r.get(2)?;
            Ok((task_id, state, evaluation_sha))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Per-executor reviewer count comes from `task_dag_edges` joined
    // against `plan_registry` for the successor's session_agent_type
    // (a successor MAY be a downstream executor rather than a
    // reviewer — we only count the latter, matching how the
    // orchestrator-NNSP rule pivots on `reviewer_verdicts=`).
    let reviewer_counts = read_reviewer_counts_per_executor(conn, initiative_id, registry)?;

    // iter50 — `preds_ready` is the wire-stable boolean that gates
    // the Orchestrator NNSP rule 2 `activate_subtask` decision. A
    // task is `preds_ready=true` iff every plan-declared
    // predecessor in `task_dag_edges` is in the
    // `tasks.state = 'Completed'` terminal state. Tasks with no
    // predecessor edges are vacuously ready. The same predicate
    // (joined to `task_dag_edges` + `tasks.state`) is what the
    // kernel-side `ActivateSubTask` reviewer-evaluation_sha
    // gate observes; surfacing it directly in the KSB closes
    // `INV-KSB-PREDS-READY-PROJECTION-01` (added alongside the
    // iter50 fix for the `lint-defect → lint-runner →
    // review-lint-defect-A` chain — the orchestrator activated
    // the reviewer before its IMMEDIATE Executor predecessor
    // `lint-runner` had even started, and the kernel rejected
    // every attempt with `ActivateSubTaskReviewerNoEvalSha`
    // until the orchestrator-respawn-no-progress ceiling fired).
    let preds_ready_map = read_preds_ready_per_task(conn, initiative_id)?;

    rows.into_iter()
        .map(|(task_id, state, evaluation_sha)| {
            let task_fields =
                registry.get(&TaskKey::new(initiative_id.to_owned(), task_id.clone()));
            let title = task_fields
                .as_ref()
                .map(|t| t.description.lines().next().unwrap_or("").to_owned())
                .unwrap_or_default();
            let reviewers: u32 = reviewer_counts.get(task_id.as_str()).copied().unwrap_or(0);
            // V2.5 — populate `aggregate_verdict` ONLY for completed
            // Executor rows. A failed Executor has no reviewable
            // artifact for its current activation; any pending
            // reviewer rows left over from a prior rejected-review
            // retry must not make the orchestrator think it is
            // `AwaitingReviewerVerdicts`. Retry admissibility for
            // failures is projected through `capabilities.tasks[*]`.
            // Completed executors still fold ONLY plan-declared
            // Reviewer successors, so downstream executor edges do not
            // masquerade as unsubmitted reviewer votes. Reviewer /
            // Orchestrator rows leave this empty so the renderer omits
            // `aggregate=` where it carries no signal.
            let aggregate_verdict = match (
                task_fields.as_ref().map(|t| t.session_agent_type),
                state.as_str(),
            ) {
                (Some(SessionAgentType::Executor), state)
                    if state == TaskState::Completed.as_sql_str() =>
                {
                    compute_aggregate_review_outcome_with_conn(
                        &task_id,
                        conn,
                        Some(AgentTypeFilter {
                            plan_registry: registry,
                            initiative_id,
                            reviewer_task_id: "<ksb_assembly>",
                        }),
                    )?
                    .verdict
                    .wire_str()
                    .to_owned()
                }
                _ => String::new(),
            };
            let preds_ready = preds_ready_map
                .get(task_id.as_str())
                .copied()
                .unwrap_or(true);
            Ok::<DagRow, rusqlite::Error>(DagRow {
                task_id,
                state: state.to_lowercase(),
                title,
                reviewers,
                evaluation_sha: evaluation_sha.unwrap_or_default(),
                aggregate_verdict,
                preds_ready,
            })
        })
        .collect()
}

/// For every task in the initiative, compute whether all of its
/// `task_dag_edges` predecessors are in `tasks.state = 'Completed'`.
/// Returned map only carries entries for tasks with at least one
/// predecessor edge — the caller treats missing keys as
/// `preds_ready=true` (the no-predecessor / root case).
/// The check intentionally pivots on `tasks.state = 'Completed'`
/// rather than the unmaintained `task_dag_edges.predecessor_satisfied`
/// column (the kernel never UPDATEs that column in v1, despite the
/// schema comment — see iter50 audit). `Completed` is the only
/// state where an Executor has stamped `evaluation_sha` (per
/// `commit_task_completion` step 1) and is therefore the only
/// state at which a downstream Reviewer activation will pass the
/// kernel-side `ActivateSubTaskReviewerNoEvalSha` gate.
fn read_preds_ready_per_task(
    conn: &Connection,
    initiative_id: &str,
) -> Result<std::collections::BTreeMap<String, bool>, rusqlite::Error> {
    let sql = format!(
        "SELECT e.successor_task_id, p.state \
           FROM {edges} AS e \
           JOIN {tasks} AS p ON p.task_id = e.predecessor_task_id \
          WHERE e.initiative_id = ?1",
        edges = Table::TaskDagEdges.as_str(),
        tasks = Table::Tasks.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params![initiative_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Each successor starts as ready=true; a single non-Completed
    // predecessor flips it to false (monotone; we never flip back).
    let mut map: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
    let completed = TaskState::Completed.as_sql_str();
    for (successor, pred_state) in rows {
        let entry = map.entry(successor).or_insert(true);
        if pred_state != completed {
            *entry = false;
        }
    }
    Ok(map)
}

/// Count the number of `Reviewer`-typed successors per executor task
/// in the initiative. Used to populate `DagRow::reviewers` so the
/// orchestrator can ground the `reviewer_verdicts=` block scan
/// against the per-executor reviewer multiplicity.
/// The reviewer-vs-other classification is sourced from the plan
/// registry (`session_agent_type` per `[[tasks]]`) — `task_dag_edges`
/// alone does not encode role since executors can also depend on
/// other executors.
fn read_reviewer_counts_per_executor(
    conn: &Connection,
    initiative_id: &str,
    registry: &PlanRegistry,
) -> Result<std::collections::BTreeMap<String, u32>, rusqlite::Error> {
    use raxis_types::SessionAgentType;
    let sql = format!(
        "SELECT predecessor_task_id, successor_task_id \
           FROM {edges} \
          WHERE initiative_id = ?1",
        edges = Table::TaskDagEdges.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let edges = stmt
        .query_map(rusqlite::params![initiative_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut counts: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for (pred, succ) in edges {
        let succ_role = registry
            .get(&TaskKey::new(initiative_id.to_owned(), succ.clone()))
            .map(|t| t.session_agent_type);
        if matches!(succ_role, Some(SessionAgentType::Reviewer)) {
            *counts.entry(pred).or_insert(0) += 1;
        }
    }
    Ok(counts)
}

/// Project the per-Reviewer verdict feed for the initiative.
/// Closes `INV-PLANNER-ORCH-RETRY-ON-REJECT-01` (the orchestrator
/// NNSP scans `reviewer_verdicts=` for `approved=false`; that scan
/// is meaningful only when the kernel populates the block from
/// live `tasks.review_verdict` data).
/// **Source of truth.** `handle_submit_review`'s post-commit
/// branch writes to two columns:
///   * `tasks.review_verdict` on the **reviewer**'s row — the
///     per-Reviewer verdict (`Approved` / `Rejected`); written by
///     the `SubmitReview` handler. NULL until the reviewer votes.
///   * `tasks.last_critique` on the **executor predecessor**'s
///     row — the concatenated formatted critiques
///     (`[Reviewer <id>]: <text>\n\n` per submission, per Step 22
///     of the v2-deep-spec). Empty until at least one rejection.
///     The renderer joins these via `task_dag_edges` (reviewer →
///     executor predecessor) so each rendered `reviewer_verdicts=`
///     row carries the executor's `evaluation_sha` (the SHA the
///     reviewer voted against). Reviewer rows whose `review_verdict`
///     is still NULL are omitted (no signal yet) so the orchestrator
///     does not over-trigger retry on stale state.
///     Critique extraction parses the executor's
///     `last_critique` looking for the `[Reviewer <reviewer_task_id>]: `
///     prefix — fail-soft (empty critique on parse miss) so a malformed
///     critique payload never breaks the projection. The KSB renderer
///     (`crates/ksb/src/lib.rs`) tolerates an empty critique field by
///     rendering `""` verbatim.
fn read_reviewer_verdicts_for_initiative(
    conn: &Connection,
    initiative_id: &str,
) -> Result<Vec<ReviewerVerdict>, rusqlite::Error> {
    // Single SQL query: every Reviewer task with a non-NULL
    // `review_verdict` joined against its executor predecessor's
    // evaluation_sha + last_critique. We rely on `task_dag_edges`
    // to map reviewer → executor; a reviewer with multiple
    // executor predecessors is exotic enough (the realistic plan
    // is the 1:1 case) that we include one row per (reviewer,
    // predecessor) pair — the renderer handles duplicates
    // verbatim and the orchestrator's `approved=false` scan is
    // monotone.
    let sql = format!(
        "SELECT
             rev.task_id           AS reviewer_task_id,
             rev.review_verdict    AS verdict,
             COALESCE(exe.evaluation_sha, '')  AS exec_sha,
             COALESCE(exe.last_critique, '')   AS exec_last_critique
           FROM {tasks} rev
           JOIN {edges} edge ON edge.successor_task_id = rev.task_id
                            AND edge.initiative_id   = rev.initiative_id
           JOIN {tasks} exe  ON exe.task_id        = edge.predecessor_task_id
                            AND exe.initiative_id  = rev.initiative_id
          WHERE rev.initiative_id  = ?1
            AND rev.review_verdict IS NOT NULL
          ORDER BY rev.task_id ASC, exe.task_id ASC",
        tasks = Table::Tasks.as_str(),
        edges = Table::TaskDagEdges.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params![initiative_id], |r| {
            let reviewer_task_id: String = r.get(0)?;
            let verdict: String = r.get(1)?;
            let evaluation_sha: String = r.get(2)?;
            let last_critique: String = r.get(3)?;
            Ok(ReviewerVerdict {
                approved: verdict.eq_ignore_ascii_case("Approved"),
                critique: extract_critique_for_reviewer(&last_critique, &reviewer_task_id),
                reviewer_task_id,
                evaluation_sha,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Extract one Reviewer's critique from the executor's
/// concatenated `last_critique` field. The format is per
/// `handle_submit_review` Step 22 — each submission appends
/// `"[Reviewer <reviewer_task_id>]: <critique>\n\n"`. Returns the
/// most recent matching critique (i.e. the last segment with the
/// matching prefix), or empty string when no segment matches —
/// fail-soft so a parse miss does not break the KSB projection.
fn extract_critique_for_reviewer(last_critique: &str, reviewer_task_id: &str) -> String {
    let prefix = format!("[Reviewer {reviewer_task_id}]: ");
    let mut latest: Option<&str> = None;
    for segment in last_critique.split("\n\n") {
        if let Some(rest) = segment.strip_prefix(&prefix) {
            latest = Some(rest);
        }
    }
    latest.unwrap_or("").to_owned()
}

/// Compact verifier / witness lifecycle feed for the KSB.
///
/// The dashboard has richer projections, but the planner needs one
/// low-token block that answers "what gate is pending or failed right now?"
/// without reverse-engineering from task FSM state. We start from
/// `verifier_run_tokens` (not `witness_records`) so pending/spawn-failed
/// runs are visible before a witness row can exist. Latest row wins per
/// `(task_id, gate_source, gate_hook, gate_type)` so old retry attempts do
/// not distract the model from the current gate posture.
fn read_gate_statuses_for_initiative(
    conn: &Connection,
    initiative_id: &str,
    task_scope: Option<&str>,
) -> Result<Vec<GateStatusView>, rusqlite::Error> {
    use std::collections::BTreeMap;

    let task_filter = if task_scope.is_some() {
        " AND v.task_id = ?2"
    } else {
        ""
    };
    let sql = format!(
        "SELECT v.task_id, v.gate_type, \
                COALESCE(v.gate_source, 'policy_gate') AS gate_source, \
                COALESCE(v.gate_hook, 'intent') AS gate_hook, \
                v.evaluation_sha, \
                COALESCE(w.result_class, v.status, 'Pending') AS latest_verdict, \
                COALESCE(v.failure_reason, '') AS failure_reason, \
                COALESCE(w.recorded_at, v.consumed_at, v.issued_at) AS observed_at \
           FROM {vrt} AS v \
           JOIN {tasks} AS t ON t.task_id = v.task_id \
           LEFT JOIN {witnesses} AS w ON w.verifier_run_id = v.verifier_run_id \
          WHERE t.initiative_id = ?1{task_filter} \
          ORDER BY v.task_id ASC, v.gate_source ASC, v.gate_hook ASC, \
                   v.gate_type ASC, observed_at ASC, v.verifier_run_id ASC",
        vrt = Table::VerifierRunTokens.as_str(),
        tasks = Table::Tasks.as_str(),
        witnesses = Table::WitnessRecords.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut latest: BTreeMap<String, GateStatusView> = BTreeMap::new();

    if let Some(task_id) = task_scope {
        let rows = stmt.query_map(
            rusqlite::params![initiative_id, task_id],
            gate_status_from_row,
        )?;
        for row in rows {
            upsert_gate_status(&mut latest, row?);
        }
    } else {
        let rows = stmt.query_map(rusqlite::params![initiative_id], gate_status_from_row)?;
        for row in rows {
            upsert_gate_status(&mut latest, row?);
        }
    }

    Ok(latest.into_values().collect())
}

fn gate_status_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GateStatusView> {
    let failure_reason: String = row.get(6)?;
    Ok(GateStatusView {
        task_id: row.get(0)?,
        gate_type: row.get(1)?,
        gate_source: row.get(2)?,
        gate_hook: row.get(3)?,
        evaluation_sha: row.get(4)?,
        verdict: row.get(5)?,
        failure_reason: if failure_reason.is_empty() {
            None
        } else {
            Some(failure_reason)
        },
        observed_at: row.get::<_, i64>(7)?.max(0),
    })
}

fn upsert_gate_status(
    latest: &mut std::collections::BTreeMap<String, GateStatusView>,
    status: GateStatusView,
) {
    let key = format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        status.task_id, status.gate_source, status.gate_hook, status.gate_type
    );
    latest.insert(key, status);
}

fn read_pending_escalations(
    conn: &Connection,
    initiative_id: &str,
) -> Result<Vec<PendingEscalation>, rusqlite::Error> {
    let sql = format!(
        "SELECT escalation_id, class, justification \
           FROM {esc} \
          WHERE initiative_id = ?1 AND status = 'Pending' \
          ORDER BY created_at ASC, escalation_id ASC",
        esc = Table::Escalations.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params![initiative_id], |r| {
            Ok(PendingEscalation {
                escalation_id: r.get(0)?,
                class: r.get(1)?,
                summary: r
                    .get::<_, String>(2)?
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_owned(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Slice C — capabilities envelope assembly
// ---------------------------------------------------------------------------
// `INV-KSB-CAPABILITIES-PARITY-01`  — the per-task `retry_admissible`
//   boolean is computed via `intent_admit::admit_retry_subtask_check`,
//   the SAME pub fn the `RetrySubTask` IPC handler routes its
//   eligibility cascade through. Parity is mechanical: same inputs ⇒
//   same answer.
// `INV-KSB-CAPABILITIES-ROLE-SCOPED-01` — enforced by the type system
//   (orchestrator / executor / reviewer are distinct enum variants
//   with disjoint field sets); the assembler picks the variant per
//   `KsbRole` and cannot accidentally cross-pollinate.
// `INV-KSB-CAPABILITIES-TURN-COHERENT-01` — every read here uses the
//   SAME `&Connection` the rest of `assemble_ksb_snapshot` uses; the
//   single-connection serialisation guarantees a stable snapshot for
//   the duration of the assembly.

/// Assemble the per-role capabilities envelope. Called from
/// `assemble_ksb_snapshot` while it holds the same `&Connection`
/// used for every other field.
fn assemble_capabilities(
    conn: &Connection,
    registry: &PlanRegistry,
    inputs: &KsbInputs<'_>,
    base_sha: &str,
) -> Result<Capabilities, KsbAssemblyError> {
    let session = SessionCapabilityView {
        session_id: inputs.session_id.to_owned(),
        role: inputs.role.as_str().to_owned(),
        // V2.7 `INV-KSB-MAX-TURNS-VISIBILITY-01` — projected verbatim
        // from the resolver-provided value the spawn callsite already
        // used for the `RAXIS_PLANNER_MAX_TURNS` env stamp. Single
        // source of truth: env stamp and KSB projection are bit-equal
        // by construction.
        planner_max_turns: inputs.planner_max_turns,
    };

    match inputs.role {
        KsbRole::Orchestrator => {
            let orch_count =
                read_orchestrator_no_progress_respawn_count(conn, inputs.initiative_id)?;
            let initiative = build_initiative_view(inputs.initiative_id, orch_count);
            let tasks = read_executor_task_capability_views(conn, registry, inputs.initiative_id)?;
            // V3 iter70+ — surface the kernel-authoritative ready
            // set and per-initiative concurrency posture directly
            // to the orchestrator LLM. The previous design forced
            // the model to re-derive admissibility from `dag=`
            // rows + `preds_ready` flags, which it consistently
            // got wrong on plans larger than ~5 tasks and which
            // ate respawn-budget on `IdleNoTerminalIntent` exits.
            // Both projections share the SAME SQL connection used
            // for the rest of the assembly, so the view is
            // point-in-time consistent with the rendered `dag=`
            // block.
            let ready_now = read_ready_now_task_ids(conn, registry, inputs.initiative_id)?;
            let cap = registry
                .orchestrator(inputs.initiative_id)
                .map(|o| o.max_concurrent_admissions)
                // Defensive default — matches
                // `OrchestratorPlanFields::default().max_concurrent_admissions`
                // (= 3). A missing entry would mean a corrupt
                // initialisation; surfacing `cap=3` here keeps
                // the KSB renderable while the bigger problem
                // (missing plan registry entry) surfaces elsewhere.
                .unwrap_or(3);
            let active_count = read_active_subtask_activations_count(conn, inputs.initiative_id)?;
            let headroom = cap.saturating_sub(active_count);
            let concurrency = ConcurrencyCapabilityView {
                cap,
                active_count,
                headroom,
            };
            let integration_merge = build_integration_merge_view(
                conn,
                registry,
                inputs.initiative_id,
                &base_sha,
                &ready_now,
            )?;
            Ok(Capabilities::Orchestrator(OrchestratorCapabilities {
                session,
                initiative,
                tasks,
                ready_now,
                concurrency,
                integration_merge,
                // V3 `INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01`
                // orchestrator carries the scaling view so its
                // NNSP can reason about retry economics (e.g. surface
                // "this child task is on attempt 3/3 with a 3× scaled
                // budget; further retries hit the ceiling" before
                // the LLM blind-issues another `retry_subtask`).
                max_turns_scaling: inputs.max_turns_scaling,
            }))
        }
        KsbRole::Executor => {
            let task_id = inputs.task_id.unwrap_or("");
            let task = build_task_capability_view_for_single(
                conn,
                registry,
                inputs.initiative_id,
                task_id,
            )?;
            Ok(Capabilities::Executor(ExecutorCapabilities {
                session,
                task,
                // V3 — executor sees its OWN budget breakdown so the
                // role NNSP can self-regulate (`remaining = effective
                // - turn_index`; the agent now knows the effective
                // value differs from base because attempt > 1, not
                // because of operator misconfiguration).
                max_turns_scaling: inputs.max_turns_scaling,
            }))
        }
        KsbRole::Reviewer => {
            // Reviewer's `artifact_task_id` is the executor task
            // whose commit the reviewer is verdicting against. We
            // resolve it via `task_dag_edges`: the reviewer's
            // *predecessor* with a matching evaluation_sha is the
            // executor under review. When the lookup fails (boot
            // race / fixture without the join row), we fall back
            // to the reviewer's own task_id so the envelope still
            // carries a wire-stable identity.
            let reviewer_task_id = inputs.task_id.unwrap_or("");
            let artifact_task_id =
                read_reviewer_artifact_task_id(conn, inputs.initiative_id, reviewer_task_id)?
                    .unwrap_or_else(|| reviewer_task_id.to_owned());
            Ok(Capabilities::Reviewer(ReviewerCapabilities {
                session,
                artifact_task_id,
            }))
        }
    }
}

fn build_initiative_view(initiative_id: &str, orch_count: u32) -> InitiativeCapabilityView {
    let max = MAX_ORCH_NO_PROGRESS_RESPAWNS;
    InitiativeCapabilityView {
        initiative_id: initiative_id.to_owned(),
        orchestrator_no_progress_respawn_count: orch_count,
        max_orchestrator_no_progress_respawns: max,
        orchestrator_respawns_remaining: max.saturating_sub(orch_count),
    }
}

fn build_integration_merge_view(
    conn: &Connection,
    registry: &PlanRegistry,
    initiative_id: &str,
    base_sha: &str,
    ready_now: &[String],
) -> Result<IntegrationMergeCapabilityView, KsbAssemblyError> {
    let mut blockers = Vec::new();
    if base_sha.is_empty() {
        blockers.push("base_sha=<unset>".to_owned());
    }
    if !ready_now.is_empty() {
        blockers.push(format!(
            "ready_now has {} activatable task(s)",
            ready_now.len()
        ));
    }

    let mut task_entries = registry.tasks_in_initiative(initiative_id);
    task_entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut required_executor_shas = Vec::new();
    for (task_id, fields) in task_entries {
        if fields.session_agent_type != SessionAgentType::Executor {
            continue;
        }
        let (state, evaluation_sha) = read_task_state_and_eval_sha(conn, &task_id)?;
        match (state.as_deref(), evaluation_sha.as_deref()) {
            (Some(s), Some(sha)) if s == TaskState::Completed.as_sql_str() => {
                let aggregate = compute_aggregate_review_outcome_with_conn(
                    &task_id,
                    conn,
                    Some(AgentTypeFilter {
                        plan_registry: registry,
                        initiative_id,
                        reviewer_task_id: "<ksb_integration_merge>",
                    }),
                )?
                .verdict
                .wire_str()
                .to_owned();
                if aggregate == "AllPassed" || aggregate == "NoSuccessors" {
                    required_executor_shas.push(IntegrationMergeExecutorSha {
                        task_id,
                        sha: sha.to_owned(),
                    });
                } else {
                    blockers.push(format!("{task_id} aggregate={aggregate}"));
                }
            }
            (Some(s), Some(_)) => blockers.push(format!("{task_id} state={s}")),
            (Some(s), None) => blockers.push(format!("{task_id} state={s} sha=<none>")),
            (None, _) => blockers.push(format!("{task_id} missing_task_row")),
        }
    }

    let ready = blockers.is_empty() && !required_executor_shas.is_empty();
    Ok(IntegrationMergeCapabilityView {
        ready,
        base_sha: base_sha.to_owned(),
        required_executor_shas,
        blockers,
    })
}

fn read_task_state_and_eval_sha(
    conn: &Connection,
    task_id: &str,
) -> Result<(Option<String>, Option<String>), rusqlite::Error> {
    let sql = format!(
        "SELECT state, evaluation_sha FROM {} WHERE task_id = ?1",
        Table::Tasks.as_str()
    );
    conn.query_row(&sql, rusqlite::params![task_id], |r| {
        Ok((Some(r.get::<_, String>(0)?), r.get::<_, Option<String>>(1)?))
    })
    .optional()
    .map(|o| o.unwrap_or((None, None)))
}

/// Read the per-initiative orchestrator no-progress respawn counter
/// (slice B's column added by migration 0019). Returns 0 if the
/// initiative row does not exist (defensive — the caller still
/// surfaces a coherent envelope for boot-race / fixture cases).
fn read_orchestrator_no_progress_respawn_count(
    conn: &Connection,
    initiative_id: &str,
) -> Result<u32, rusqlite::Error> {
    let sql = format!(
        "SELECT orchestrator_no_progress_respawn_count \
           FROM {} WHERE initiative_id = ?1",
        Table::Initiatives.as_str()
    );
    let v: Option<i64> = conn
        .query_row(&sql, rusqlite::params![initiative_id], |r| {
            r.get::<_, i64>(0)
        })
        .optional()?;
    Ok(v.map(|n| u32::try_from(n).unwrap_or(0)).unwrap_or(0))
}

/// For the orchestrator: build one [`TaskCapabilityView`] per
/// **executor** task in the initiative (reviewer tasks are
/// reactivate-only — the orchestrator does not `retry_subtask` on
/// a reviewer, so surfacing reviewer rows would be noise).
fn read_executor_task_capability_views(
    conn: &Connection,
    registry: &PlanRegistry,
    initiative_id: &str,
) -> Result<Vec<TaskCapabilityView>, KsbAssemblyError> {
    let sql = format!(
        "SELECT task_id FROM {tasks} \
         WHERE initiative_id = ?1 \
         ORDER BY admitted_at ASC, task_id ASC",
        tasks = Table::Tasks.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let task_ids: Vec<String> = stmt
        .query_map(rusqlite::params![initiative_id], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;

    let mut out = Vec::with_capacity(task_ids.len());
    for task_id in task_ids {
        let key = TaskKey::new(initiative_id.to_owned(), task_id.clone());
        let fields = match registry.get(&key) {
            Some(f) => f,
            None => continue,
        };
        // Only project executor rows — reviewers are not retry-eligible.
        if fields.session_agent_type != SessionAgentType::Executor {
            continue;
        }
        out.push(build_task_capability_view(
            conn,
            &task_id,
            fields.effective_max_crash_retries(),
            fields.effective_max_review_rejections(),
        )?);
    }
    Ok(out)
}

/// V3 iter70+ — compute the kernel-authoritative `ready_now` list:
/// every executor task in this initiative that
/// `handle_activate_sub_task` / `classify_batch_candidates` would
/// admit RIGHT NOW. The predicate mirrors
/// `handle_batch_activate_sub_tasks` exactly (see
/// `kernel/src/handlers/intent.rs::classify_batch_candidates`):
///
/// * `tasks.state = 'Admitted'` (post-admission, pre-activation)
/// * `plan_registry` entry present for an Executor or Reviewer
///   task (defense-in-depth)
/// * every `task_dag_edges` predecessor in `tasks.state = 'Completed'`
/// * latest `subtask_activations.activation_state = 'PendingActivation'`
///   (the FSM is parked waiting for an `ActivateSubTask` intent)
///
/// The synthetic coordinator row (`task_id == initiative_id`) is
/// excluded by the outer `task_id != ?1` predicate so the
/// orchestrator never sees its own bookkeeping row in
/// `ready_now=[…]`. Reviewer rows MUST be included once their
/// predecessor executor has stamped `evaluation_sha`; the same
/// `ActivateSubTask` path provisions reviewer worktrees read-only
/// at that SHA.
///
/// Order: `(admitted_at ASC, task_id ASC)` — byte-identical to the
/// kernel's batch-handler sort, so the LLM picking from this list
/// in order gets the same admission ordering the kernel would
/// produce regardless.
///
/// Performance: O(N · E_avg) SQL probes per turn, where N is the
/// task count and E_avg is the average inbound-edge count. On a
/// 15-task plan that is < 100 SQLite point lookups, well inside
/// the KSB-assembly budget.
///
/// `INV-KSB-READY-NOW-MATCHES-KERNEL-ADMISSION-01`.
fn read_ready_now_task_ids(
    conn: &Connection,
    registry: &PlanRegistry,
    initiative_id: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let sql = format!(
        "SELECT task_id FROM {tasks} \
         WHERE initiative_id = ?1 \
           AND task_id != ?1 \
           AND state = ?2 \
         ORDER BY admitted_at ASC, task_id ASC",
        tasks = Table::Tasks.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let admitted_ids: Vec<String> = stmt
        .query_map(
            rusqlite::params![initiative_id, TaskState::Admitted.as_sql_str()],
            |r| r.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;

    let mut out: Vec<String> = Vec::with_capacity(admitted_ids.len());
    for task_id in admitted_ids {
        let key = TaskKey::new(initiative_id.to_owned(), task_id.clone());
        let fields = match registry.get(&key) {
            Some(f) => f,
            None => continue,
        };
        // Executor and Reviewer rows are activatable via
        // `activate_subtask` / `batch_activate_subtasks`. The
        // activation handler has reviewer-specific provisioning that
        // clones the predecessor executor's `evaluation_sha`, so the
        // predecessor-Completed predicate below is the readiness gate.
        if !matches!(
            fields.session_agent_type,
            SessionAgentType::Executor | SessionAgentType::Reviewer
        ) {
            continue;
        }
        // Predecessor closure — mirrors
        // `missing_predecessors_for_activation` in
        // `kernel/src/handlers/intent.rs`. A non-Completed
        // predecessor disqualifies the task, except for the
        // parent→fixup lineage edge of a gate-fixup task. That edge
        // records which `GatesPending` parent is being repaired; it
        // is not a wait-for-parent-completion dependency.
        let any_unfinished_pred: bool = {
            let pred_sql = format!(
                "SELECT 1 \
                   FROM {edges} AS e \
                   JOIN {tasks} AS pred \
                     ON pred.task_id = e.predecessor_task_id \
                   JOIN {tasks} AS succ \
                     ON succ.task_id = e.successor_task_id \
                  WHERE e.successor_task_id = ?1 \
                    AND pred.state != ?2 \
                    AND NOT (COALESCE(succ.is_gate_fixup, 0) = 1 \
                             AND succ.parent_gate_failure_task_id = e.predecessor_task_id) \
                  LIMIT 1",
                edges = Table::TaskDagEdges.as_str(),
                tasks = Table::Tasks.as_str(),
            );
            conn.query_row(
                &pred_sql,
                rusqlite::params![&task_id, TaskState::Completed.as_sql_str()],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        };
        if any_unfinished_pred {
            continue;
        }
        // Latest activation row — must be `PendingActivation`. A
        // missing row (very-early state) or any other state means
        // the FSM is not parked at the admission boundary.
        let activation_state: Option<String> = conn
            .query_row(
                &format!(
                    "SELECT activation_state FROM {acts} \
                     WHERE task_id = ?1 \
                     ORDER BY created_at DESC LIMIT 1",
                    acts = Table::SubtaskActivations.as_str(),
                ),
                rusqlite::params![&task_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        if activation_state.as_deref() != Some("PendingActivation") {
            continue;
        }
        out.push(task_id);
    }
    Ok(out)
}

/// V3 iter70+ — count live subtask activations for the
/// initiative. Mirrors the per-initiative bounded-concurrency
/// gate enforced by the orchestrator-post-exit respawn hook
/// (`session_spawn_orchestrator.rs` Mode A), which gates on
/// `subtask_activations.activation_state = 'Active' AND
/// initiative_id = ?1`. `Active` is the post-spawn pre-terminate
/// state — the row carries a non-null `session_id` and an
/// `activated_at` timestamp, the VM has booted. The result feeds
/// the LLM's `concurrency: cap=N active=M headroom=K` line so it
/// can pre-size its `batch_activate_subtasks` request to the
/// actual headroom and avoid per-id `DroppedAtCap` outcomes from
/// the kernel's batch handler.
///
/// `INV-KSB-CONCURRENCY-VIEW-MIRRORS-KERNEL-CAP-01`.
fn read_active_subtask_activations_count(
    conn: &Connection,
    initiative_id: &str,
) -> Result<u32, rusqlite::Error> {
    let sql = format!(
        "SELECT COUNT(1) FROM {acts} \
          WHERE initiative_id = ?1 \
            AND activation_state = 'Active'",
        acts = Table::SubtaskActivations.as_str(),
    );
    let count: i64 = conn.query_row(&sql, rusqlite::params![initiative_id], |r| r.get(0))?;
    Ok(u32::try_from(count.max(0)).unwrap_or(u32::MAX))
}

/// For the executor: build the [`TaskCapabilityView`] for the single
/// task this executor session was spawned for. When the task lookup
/// fails the assembler returns a defensive view with zero counters
/// and the inadmissible-NoPriorActivation reason — the LLM sees
/// `retry_admissible=false reason="no prior activation"` and the
/// NNSP teaches it not to call `retry_subtask` from an executor
/// session anyway (only the orchestrator can).
fn build_task_capability_view_for_single(
    conn: &Connection,
    registry: &PlanRegistry,
    initiative_id: &str,
    task_id: &str,
) -> Result<TaskCapabilityView, KsbAssemblyError> {
    let key = TaskKey::new(initiative_id.to_owned(), task_id.to_owned());
    let (max_crash, max_review) = registry
        .get(&key)
        .map(|f| {
            (
                f.effective_max_crash_retries(),
                f.effective_max_review_rejections(),
            )
        })
        // Defensive defaults — match the kernel-side defaults applied
        // when a plan omits the field. See
        // `plan_registry::TaskPlanFields::effective_*`.
        .unwrap_or((3, 2));
    build_task_capability_view(conn, task_id, max_crash, max_review)
}

/// Build a [`TaskCapabilityView`] for `task_id`, sourcing the
/// counters from the most-recent `subtask_activations` row. Calls
/// [`raxis_types::intent_admit::admit_retry_subtask_check`] to populate
/// `retry_admissible` (parity with the IPC handler).
fn build_task_capability_view(
    conn: &Connection,
    task_id: &str,
    max_crash: u32,
    max_review: u32,
) -> Result<TaskCapabilityView, KsbAssemblyError> {
    let sql = format!(
        "SELECT activation_state, crash_retry_count, review_reject_count \
           FROM {acts} WHERE task_id = ?1 ORDER BY created_at DESC LIMIT 1",
        acts = Table::SubtaskActivations.as_str(),
    );
    let row: Option<(String, i64, i64)> = conn
        .query_row(&sql, rusqlite::params![task_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?;
    let (prior_state, crash, review) = row.unwrap_or_default();
    let crash_u = u32::try_from(crash).unwrap_or(0);
    let review_u = u32::try_from(review).unwrap_or(0);
    let admit_inputs = RetryAdmitInputs {
        prior_activation_state: if prior_state.is_empty() {
            None
        } else {
            Some(prior_state.as_str())
        },
        crash_retry_count: crash_u,
        review_reject_count: review_u,
        max_crash_retries: max_crash,
        max_review_rejections: max_review,
    };
    let (retry_admissible, retry_inadmissible_reason) =
        match admit_retry_subtask_check(&admit_inputs) {
            AdmitOutcome::Admissible => (true, None),
            AdmitOutcome::Inadmissible(r) => (false, Some(r.human())),
        };
    Ok(TaskCapabilityView {
        task_id: task_id.to_owned(),
        crash_retry_count: crash_u,
        review_reject_count: review_u,
        max_crash_retries: max_crash,
        max_review_rejections: max_review,
        crash_retries_remaining: max_crash.saturating_sub(crash_u),
        review_retries_remaining: max_review.saturating_sub(review_u),
        retry_admissible,
        retry_inadmissible_reason,
    })
}

/// For the reviewer: walk `task_dag_edges` to find the predecessor
/// executor task whose commit this reviewer is verdicting against.
fn read_reviewer_artifact_task_id(
    conn: &Connection,
    initiative_id: &str,
    reviewer_task_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    let sql = format!(
        "SELECT predecessor_task_id FROM {} \
         WHERE initiative_id = ?1 AND successor_task_id = ?2 \
         LIMIT 1",
        Table::TaskDagEdges.as_str()
    );
    conn.query_row(
        &sql,
        rusqlite::params![initiative_id, reviewer_task_id],
        |r| r.get::<_, String>(0),
    )
    .optional()
}

/// Placeholder used by the spawn
/// paths when the assembler returns an error: a minimum-bootable
/// snapshot whose required fields are populated and whose optional
/// fields default to empty. The driver still gets a non-empty
/// `RAXIS_PLANNER_KSB` env var so the dispatch loop produces a
/// meaningful prompt; the model sees no DAG / verdict context, but
/// the kernel-state-block delimiters are still present so the LLM
/// trusts the rest of the prompt.
pub fn fallback_snapshot(initiative_id: &str, task_id: Option<&str>, role: KsbRole) -> KsbSnapshot {
    KsbSnapshot {
        version: KSB_SCHEMA_VERSION,
        initiative_id: initiative_id.to_owned(),
        task_id: task_id.map(str::to_owned),
        role: role.as_str().to_owned(),
        evaluation_sha: String::new(),
        path_allowlist: Vec::new(),
        token_budget_remaining: 0,
        wallclock_budget_remaining_s: 0,
        dag_rows: Vec::new(),
        task_description: String::new(),
        target_ref: crate::initiatives::OrchestratorPlanFields::DEFAULT_TARGET_REF.to_owned(),
        base_sha: String::new(),
        reviewer_verdicts: Vec::new(),
        pending_escalations: Vec::new(),
        gate_statuses: Vec::new(),
        credential_ports: Vec::new(),
        // Slice C — fallback snapshot omits the capabilities
        // envelope; the LLM falls through to its NNSP defaults.
        // The spawn path's primary code path (real
        // `assemble_ksb_snapshot` call) populates the envelope
        // when the SQL read succeeds.
        capabilities: None,
        // iter62 — fallback snapshot has no SQL context to read
        // the per-task `last_critique` from; the LLM does not
        // surface prior round feedback in the fail-soft path.
        last_critique: None,
        // iter65 — fallback snapshot has no SQL context to read
        // gate-fixup linkage. A fixup-executor session that hits
        // this path is degraded but boot-safe: the LLM sees the
        // standard non-fixup KSB and its NNSP fallback applies.
        gate_fixup: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initiatives::plan_registry::{OrchestratorPlanFields, TaskPlanFields};
    use raxis_store::Store;
    use std::sync::Arc;
    use tempfile::TempDir;

    const INITIATIVES: &str = Table::Initiatives.as_str();
    const TASKS: &str = Table::Tasks.as_str();
    const TASK_DAG_EDGES: &str = Table::TaskDagEdges.as_str();
    const SESSIONS: &str = Table::Sessions.as_str();
    const SUBTASK_ACTIVATIONS: &str = Table::SubtaskActivations.as_str();

    fn fresh_store() -> (Arc<Store>, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(&dir.path().join("kernel.db")).expect("open kernel.db");
        (Arc::new(store), dir)
    }

    /// V3 — fixture default for the
    /// `KsbInputs::max_turns_scaling` field. Carries the inert
    /// "attempt 1 / step = 10 / hard_ceiling = 240" view so tests
    /// that don't care about progressive scaling can spread
    /// `..Default::default()` semantics inline.
    fn default_max_turns_scaling() -> raxis_ksb::MaxTurnsScalingView {
        raxis_ksb::MaxTurnsScalingView {
            max_turns_attempt: 1,
            max_turns_base: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
            max_turns_step: 10,
            max_turns_hard_ceiling: 240,
        }
    }

    fn populate_registry(registry: &PlanRegistry, initiative_id: &str, task_id: &str) {
        let key = TaskKey::new(initiative_id.to_owned(), task_id.to_owned());
        registry.insert(
            key,
            TaskPlanFields {
                path_allowlist: vec!["src/lib.rs".to_owned(), "src/main.rs".to_owned()],
                description: "Land the typed enum on top of the executor lane.".to_owned(),
                ..Default::default()
            },
        );
        registry.insert_orchestrator(
            initiative_id.to_owned(),
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec![],
                description: "Drive the typed-enum refactor across the executor lane.".to_owned(),
                target_ref: "refs/heads/feature/typed-enum".to_owned(),
                elastic: None,
                ..Default::default()
            },
        );
    }

    #[test]
    fn assemble_executor_snapshot_carries_task_description_and_paths() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        populate_registry(&registry, "init-1", "task-a");

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: "init-1",
                task_id: Some("task-a"),
                role: KsbRole::Executor,
                token_budget_remaining: 12_345,
                wallclock_budget_remaining_s: 600,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("assemble snapshot");

        assert_eq!(snap.initiative_id, "init-1");
        assert_eq!(snap.task_id.as_deref(), Some("task-a"));
        assert_eq!(snap.role, "executor");
        assert_eq!(snap.target_ref, "refs/heads/feature/typed-enum");
        assert_eq!(snap.path_allowlist, vec!["src/lib.rs", "src/main.rs"]);
        assert!(
            snap.task_description.starts_with("Land the typed enum"),
            "executor MUST source description from per-task plan field, got: {}",
            snap.task_description
        );
        assert_eq!(snap.token_budget_remaining, 12_345);
        assert_eq!(snap.wallclock_budget_remaining_s, 600);
        // Executor's DAG view is intentionally empty (it sees only
        // its own task), so a missing `tasks` row in the store does
        // not surface a populated DAG row by mistake.
        assert!(
            snap.dag_rows.is_empty(),
            "executor's KSB MUST NOT carry a DAG view"
        );
    }

    #[test]
    fn assemble_orchestrator_snapshot_sources_description_from_initiative_field() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        populate_registry(&registry, "init-1", "task-a");

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: "init-1",
                task_id: None,
                role: KsbRole::Orchestrator,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("assemble orchestrator snapshot");

        assert_eq!(snap.role, "orchestrator");
        assert!(
            snap.task_id.is_none(),
            "orchestrator KSB MUST omit task_id (the orchestrator is per-initiative, not per-task)"
        );
        assert_eq!(snap.target_ref, "refs/heads/feature/typed-enum");
        assert!(
            snap.task_description
                .starts_with("Drive the typed-enum refactor"),
            "orchestrator MUST source description from `[plan.initiative] description`, got: {}",
            snap.task_description
        );
    }

    #[test]
    fn assembler_renders_through_raxis_ksb_round_trip() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        populate_registry(&registry, "init-1", "task-a");

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: "init-1",
                task_id: Some("task-a"),
                role: KsbRole::Executor,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("assemble snapshot");
        drop(conn);

        // JSON wire shape MUST
        // round-trip cleanly so the kernel-side serialise + the
        // driver-side deserialise pair produce a byte-identical
        // render. This is the load-bearing pin against schema
        // drift between the two sides of the env-var contract.
        let json = serde_json::to_string(&snap).expect("serialise");
        let decoded: KsbSnapshot = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(snap, decoded);

        let rendered = raxis_ksb::render_ksb(&decoded).expect("render");
        assert!(rendered.contains("initiative_id=init-1"));
        assert!(rendered.contains("task_id=task-a"));
        assert!(rendered.contains("role=executor"));
        assert!(rendered.contains("target_ref=refs/heads/feature/typed-enum"));
        assert!(rendered.contains("- src/lib.rs"));
        assert!(rendered.contains("Land the typed enum"));
    }

    #[test]
    fn gate_status_projection_latest_run_wins_and_carries_failure_reason() {
        let (store, _dir) = fresh_store();
        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at)
                 VALUES ('init-gates', 'Executing', '{{}}', 'sha', 1)"
            ),
            [],
        )
        .unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor, policy_epoch,
                     admitted_at, transitioned_at, evaluation_sha)
                 VALUES ('task-a', 'init-gates', 'lane-0', 'GatesPending',
                         'kernel', 1, 1, 1,
                         'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')"
            ),
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO verifier_run_tokens
                (verifier_run_id, task_id, gate_type, evaluation_sha, token_hash,
                 issued_at, expires_at, consumed, consumed_at, gate_source,
                 gate_hook, status, failure_reason)
             VALUES
                ('run-old', 'task-a', 'NoSecretStrings',
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hash-old',
                 10, 100, 1, 20, 'task_verifier', 'complete_task',
                 'Fail', 'old failure'),
                ('run-new', 'task-a', 'NoSecretStrings',
                 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'hash-new',
                 30, 130, 0, NULL, 'task_verifier', 'complete_task',
                 'Pending', NULL),
                ('run-bad', 'task-a', 'TypeCheck',
                 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'hash-bad',
                 40, 140, 1, 40, 'plan_integration_verifier', 'integration_merge',
                 'ConfigInvalid', 'missing verifier binary')",
            [],
        )
        .unwrap();

        let rows = read_gate_statuses_for_initiative(&conn, "init-gates", Some("task-a")).unwrap();
        assert_eq!(
            rows.len(),
            2,
            "latest status should collapse duplicate gate runs"
        );
        let no_secret = rows
            .iter()
            .find(|r| r.gate_type == "NoSecretStrings")
            .expect("NoSecretStrings row");
        assert_eq!(no_secret.verdict, "Pending");
        assert_eq!(
            no_secret.evaluation_sha,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert!(
            no_secret.failure_reason.is_none(),
            "newer pending run must not inherit old failure reason"
        );
        let type_check = rows
            .iter()
            .find(|r| r.gate_type == "TypeCheck")
            .expect("TypeCheck row");
        assert_eq!(type_check.gate_source, "plan_integration_verifier");
        assert_eq!(type_check.gate_hook, "integration_merge");
        assert_eq!(type_check.verdict, "ConfigInvalid");
        assert_eq!(
            type_check.failure_reason.as_deref(),
            Some("missing verifier binary")
        );
    }

    #[test]
    fn truncates_oversized_task_description_at_byte_boundary() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        let huge = "a".repeat(TASK_DESCRIPTION_MAX_BYTES + 1024);
        let key = TaskKey::new("init-1".to_owned(), "task-a".to_owned());
        registry.insert(
            key,
            TaskPlanFields {
                description: huge,
                ..Default::default()
            },
        );
        registry.insert_orchestrator("init-1".to_owned(), OrchestratorPlanFields::default());

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: "init-1",
                task_id: Some("task-a"),
                role: KsbRole::Executor,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("assemble snapshot");

        assert!(
            snap.task_description.len() <= TASK_DESCRIPTION_MAX_BYTES,
            "oversized description MUST be truncated to TASK_DESCRIPTION_MAX_BYTES, \
             got len={}",
            snap.task_description.len()
        );
    }

    /// Closes `INV-PLANNER-ORCH-RETRY-ON-REJECT-01`: the orchestrator
    /// KSB MUST surface per-Reviewer verdicts so the orchestrator NNSP
    /// can scan `reviewer_verdicts=` for `approved=false` and trigger
    /// `retry_subtask`. Iter42 reproduced the kernel-side gap (the
    /// projection was hard-coded to `Vec::new()`) directly: the
    /// orchestrator never saw the rejection signal because the kernel
    /// never populated the block, even though the data was present
    /// on `tasks.review_verdict`.
    #[test]
    fn assemble_orchestrator_snapshot_populates_reviewer_verdicts_from_store() {
        use raxis_types::SessionAgentType;
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        let init = "init-realistic";
        let exec = "lint-defect";
        let rev_a = "review-lint-defect-A";
        let rev_b = "review-lint-defect-B";

        registry.insert_orchestrator(
            init.to_owned(),
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec![],
                description: "drive lint-defect to merge".to_owned(),
                target_ref: "refs/heads/main".to_owned(),
                elastic: None,
                ..Default::default()
            },
        );
        registry.insert(
            TaskKey::new(init.to_owned(), exec.to_owned()),
            TaskPlanFields {
                description: "introduce one lint defect".to_owned(),
                session_agent_type: SessionAgentType::Executor,
                ..Default::default()
            },
        );
        registry.insert(
            TaskKey::new(init.to_owned(), rev_a.to_owned()),
            TaskPlanFields {
                description: "Reviewer A".to_owned(),
                session_agent_type: SessionAgentType::Reviewer,
                ..Default::default()
            },
        );
        registry.insert(
            TaskKey::new(init.to_owned(), rev_b.to_owned()),
            TaskPlanFields {
                description: "Reviewer B".to_owned(),
                session_agent_type: SessionAgentType::Reviewer,
                ..Default::default()
            },
        );

        // Seed the store directly with the rows the verdict-feed
        // projection joins against. We bypass the full intent
        // pipeline (lifecycle / submit_review handlers) — the
        // assertion is on the projection's read path, not the
        // upstream writers.
        let conn = store.lock_sync();
        // SQLite's `PRAGMA foreign_keys=ON` (set by `Store::open`)
        // requires the parent initiative row to exist before we can
        // insert the task / edge rows below. Mirrors the seeder in
        // `dag_aggregate_in_realistic_two_executor_plan_is_pending_until_runner_completes`.
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES} (
                 initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at
             ) VALUES (?1, 'Executing', '{{}}', 'sha-test', 0)"
            ),
            rusqlite::params![init],
        )
        .expect("insert initiative");
        let exec_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        for (tid, role, verdict) in &[
            (exec, "Executor", None::<&str>),
            (rev_a, "Reviewer", Some("Approved")),
            (rev_b, "Reviewer", Some("Rejected")),
        ] {
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS} (
                     task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at,
                     evaluation_sha, last_critique, review_verdict
                 ) VALUES (?1, ?2, 'default', 'Completed', 'op',
                           0, 0, 0, ?3, ?4, ?5)"
                ),
                rusqlite::params![
                    tid, init,
                    if *role == "Executor" { Some(exec_sha) } else { None },
                    if *role == "Executor" {
                        Some("[Reviewer review-lint-defect-A]: ok\n\n[Reviewer review-lint-defect-B]: REJECTION: greeting.rs introduces clippy::useless_conversion\n\n")
                    } else { None },
                    *verdict,
                ],
            ).expect("insert task");
        }
        for rev in &[rev_a, rev_b] {
            conn.execute(
                &format!(
                    "INSERT INTO {TASK_DAG_EDGES} (
                    initiative_id, predecessor_task_id, successor_task_id,
                    predecessor_satisfied
                 ) VALUES (?1, ?2, ?3, 1)"
                ),
                rusqlite::params![init, exec, rev],
            )
            .expect("insert dag edge");
        }
        drop(conn);

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: init,
                task_id: None,
                role: KsbRole::Orchestrator,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("assemble orchestrator snapshot");
        drop(conn);

        // Reviewer-verdict projection MUST surface both Reviewers'
        // verdicts against the executor's evaluation_sha.
        assert_eq!(
            snap.reviewer_verdicts.len(),
            2,
            "orchestrator KSB MUST carry one row per voted Reviewer; got: {:?}",
            snap.reviewer_verdicts
        );
        let rev_a_row = snap
            .reviewer_verdicts
            .iter()
            .find(|v| v.reviewer_task_id == rev_a)
            .expect("reviewer A row present");
        let rev_b_row = snap
            .reviewer_verdicts
            .iter()
            .find(|v| v.reviewer_task_id == rev_b)
            .expect("reviewer B row present");
        assert!(rev_a_row.approved, "Reviewer A must read approved=true");
        assert!(!rev_b_row.approved, "Reviewer B must read approved=false");
        assert_eq!(
            rev_a_row.evaluation_sha, exec_sha,
            "reviewer evaluation_sha MUST mirror the executor predecessor's"
        );
        assert_eq!(rev_b_row.evaluation_sha, exec_sha);
        assert!(
            rev_b_row.critique.contains("greeting.rs"),
            "Reviewer B's critique MUST be parsed from the executor's last_critique"
        );

        // dag_rows MUST report 2 reviewers attached to lint-defect
        // (neither sibling executor nor non-reviewer downstream
        // would otherwise inflate the count).
        let lint_row = snap
            .dag_rows
            .iter()
            .find(|r| r.task_id == exec)
            .expect("lint-defect dag row present");
        assert_eq!(
            lint_row.reviewers, 2,
            "lint-defect MUST surface its reviewer multiplicity in dag_rows"
        );
        // Closes `INV-KSB-AGGREGATE-VERDICT-PROJECTION-01`: both
        // siblings have voted, one Rejected, so the executor's
        // dag row MUST carry `aggregate=AtLeastOneRejected` — the
        // wire-stable trigger the orchestrator NNSP rule 3a
        // pivots on.
        assert_eq!(
            lint_row.aggregate_verdict, "AtLeastOneRejected",
            "lint-defect MUST surface terminal aggregator verdict; got: {:?}",
            lint_row.aggregate_verdict
        );
        // Reviewer rows MUST NOT carry an aggregator verdict —
        // they are not the predecessor of any reviewer; leaving
        // the field empty keeps the wire compact and matches the
        // renderer's omit-when-empty contract.
        for rev in &[rev_a, rev_b] {
            let row = snap
                .dag_rows
                .iter()
                .find(|r| r.task_id == *rev)
                .unwrap_or_else(|| panic!("reviewer {} dag row present", rev));
            assert_eq!(
                row.aggregate_verdict, "",
                "reviewer rows MUST NOT carry `aggregate_verdict`; got: {:?}",
                row.aggregate_verdict
            );
        }
    }

    /// Iter42 regression: when ONE of two sibling Reviewers has
    /// voted and the other has not, the executor's KSB dag-row
    /// MUST surface `aggregate=AwaitingReviewerVerdicts` — NOT
    /// `aggregate=AtLeastOneRejected`. The earlier orchestrator
    /// NNSP rule 3a pivoted on per-Reviewer rows
    /// (`reviewer_verdicts[*].approved=false`) and therefore fired
    /// `retry_subtask` as soon as the FIRST sibling voted Reject,
    /// before the kernel's aggregator had bumped
    /// `review_reject_count`. The kernel correctly rejected every
    /// retry per `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`,
    /// producing a respawn loop. This test pins the projection's
    /// part of the fix: as long as ANY sibling is still
    /// pending (NULL `review_verdict`), the dag row reads
    /// `AwaitingReviewerVerdicts` and the NNSP rule MUST NOT fire
    /// `retry_subtask`.
    /// Closes `INV-KSB-AGGREGATE-VERDICT-PROJECTION-01` and the
    /// iter42 regression on the projection side.
    #[test]
    fn dag_row_aggregate_is_pending_when_only_one_of_two_reviewers_voted() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        let init = "init-iter42";
        let exec = "lint-defect";
        let rev_a = "review-lint-defect-A";
        let rev_b = "review-lint-defect-B";

        registry.insert_orchestrator(
            init.to_owned(),
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec![],
                description: "drive lint-defect to merge".to_owned(),
                target_ref: "refs/heads/main".to_owned(),
                elastic: None,
                ..Default::default()
            },
        );
        registry.insert(
            TaskKey::new(init.to_owned(), exec.to_owned()),
            TaskPlanFields {
                description: "introduce one lint defect".to_owned(),
                session_agent_type: SessionAgentType::Executor,
                ..Default::default()
            },
        );
        registry.insert(
            TaskKey::new(init.to_owned(), rev_a.to_owned()),
            TaskPlanFields {
                description: "Reviewer A".to_owned(),
                session_agent_type: SessionAgentType::Reviewer,
                ..Default::default()
            },
        );
        registry.insert(
            TaskKey::new(init.to_owned(), rev_b.to_owned()),
            TaskPlanFields {
                description: "Reviewer B".to_owned(),
                session_agent_type: SessionAgentType::Reviewer,
                ..Default::default()
            },
        );

        let conn = store.lock_sync();
        // SQLite's `PRAGMA foreign_keys=ON` (set by `Store::open`)
        // requires the parent initiative row to exist before we can
        // insert task / edge rows below.
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES} (
                 initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at
             ) VALUES (?1, 'Executing', '{{}}', 'sha-test', 0)"
            ),
            rusqlite::params![init],
        )
        .expect("insert initiative");
        let exec_sha = "cafebabecafebabecafebabecafebabecafebabe";
        // Reviewer A has voted Rejected; Reviewer B has NOT voted
        // (review_verdict is NULL). This is the exact wire shape
        // iter42 produced between the first SubmitReview and the
        // second.
        for (tid, role, verdict) in &[
            (exec, "Executor", None::<&str>),
            (rev_a, "Reviewer", Some("Rejected")),
            (rev_b, "Reviewer", None::<&str>),
        ] {
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS} (
                     task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at,
                     evaluation_sha, last_critique, review_verdict
                 ) VALUES (?1, ?2, 'default', 'Completed', 'op',
                           0, 0, 0, ?3, ?4, ?5)"
                ),
                rusqlite::params![
                    tid,
                    init,
                    if *role == "Executor" {
                        Some(exec_sha)
                    } else {
                        None
                    },
                    if *role == "Executor" {
                        Some("[Reviewer review-lint-defect-A]: REJECTION\n\n")
                    } else {
                        None
                    },
                    *verdict,
                ],
            )
            .expect("insert task");
        }
        for rev in &[rev_a, rev_b] {
            conn.execute(
                &format!(
                    "INSERT INTO {TASK_DAG_EDGES} (
                    initiative_id, predecessor_task_id, successor_task_id,
                    predecessor_satisfied
                 ) VALUES (?1, ?2, ?3, 1)"
                ),
                rusqlite::params![init, exec, rev],
            )
            .expect("insert dag edge");
        }
        drop(conn);

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: init,
                task_id: None,
                role: KsbRole::Orchestrator,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("assemble orchestrator snapshot");
        drop(conn);

        let lint_row = snap
            .dag_rows
            .iter()
            .find(|r| r.task_id == exec)
            .expect("lint-defect dag row present");
        assert_eq!(
            lint_row.aggregate_verdict, "AwaitingReviewerVerdicts",
            "lint-defect MUST read `AwaitingReviewerVerdicts` while one Reviewer \
             still owes a verdict — iter42 regression; got: {:?}",
            lint_row.aggregate_verdict
        );

        // Render and confirm the wire payload omits the
        // misleading "aggregate=AtLeastOneRejected" the
        // pre-fix code would have emitted.
        let rendered = raxis_ksb::render_ksb(&snap).expect("render");
        assert!(
            rendered.contains("aggregate=AwaitingReviewerVerdicts"),
            "rendered KSB MUST carry `aggregate=AwaitingReviewerVerdicts` while \
             one Reviewer is still pending; got: {rendered}"
        );
        assert!(
            !rendered.contains("aggregate=AtLeastOneRejected"),
            "rendered KSB MUST NOT carry `AtLeastOneRejected` \
             while any sibling Reviewer is pending — that is the \
             iter42 race; got: {rendered}"
        );
    }

    /// Live-e2e regression: once an Executor has failed, its row must
    /// not look like it is awaiting reviewer votes. Reviewers cannot
    /// complete a failed predecessor's artifact; retry admissibility is
    /// carried through `capabilities.tasks[*]`, while
    /// `DagRow::aggregate_verdict` stays empty until the Executor
    /// reaches `Completed`.
    #[test]
    fn failed_executor_dag_row_does_not_surface_pending_reviewer_aggregate() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        let init = "init-failed-executor";
        let exec = "lint-runner-rust";
        let rev = "review-lint-runner-rust";

        registry.insert_orchestrator(
            init.to_owned(),
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec![],
                description: "drive lint runners to merge".to_owned(),
                target_ref: "refs/heads/main".to_owned(),
                elastic: None,
                ..Default::default()
            },
        );
        registry.insert(
            TaskKey::new(init.to_owned(), exec.to_owned()),
            TaskPlanFields {
                description: "run cargo fmt and cargo clippy".to_owned(),
                session_agent_type: SessionAgentType::Executor,
                ..Default::default()
            },
        );
        registry.insert(
            TaskKey::new(init.to_owned(), rev.to_owned()),
            TaskPlanFields {
                description: "review rust lint output".to_owned(),
                session_agent_type: SessionAgentType::Reviewer,
                ..Default::default()
            },
        );

        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES} (
                 initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at
             ) VALUES (?1, 'Executing', '{{}}', 'sha-test', 0)"
            ),
            rusqlite::params![init],
        )
        .expect("insert initiative");
        conn.execute(
            &format!(
                "INSERT INTO {TASKS} (
                 task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at,
                 evaluation_sha, last_critique, review_verdict
             ) VALUES (?1, ?2, 'default', 'Failed', 'op',
                       0, 0, 0, ?3, ?4, NULL)"
            ),
            rusqlite::params![
                exec,
                init,
                "2222222222222222222222222222222222222222",
                "CompleteTask rejected: touched workspace/rust-crate/src/greeting.rs"
            ],
        )
        .expect("insert failed executor");
        conn.execute(
            &format!(
                "INSERT INTO {TASKS} (
                 task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at,
                 evaluation_sha, last_critique, review_verdict
             ) VALUES (?1, ?2, 'default', 'Admitted', 'op',
                       0, 0, 0, NULL, NULL, NULL)"
            ),
            rusqlite::params![rev, init],
        )
        .expect("insert pending reviewer");
        conn.execute(
            &format!(
                "INSERT INTO {TASK_DAG_EDGES} (
                 initiative_id, predecessor_task_id, successor_task_id,
                 predecessor_satisfied
             ) VALUES (?1, ?2, ?3, 1)"
            ),
            rusqlite::params![init, exec, rev],
        )
        .expect("insert dag edge");
        drop(conn);

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: init,
                task_id: None,
                role: KsbRole::Orchestrator,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("assemble orchestrator snapshot");
        drop(conn);

        let row = snap
            .dag_rows
            .iter()
            .find(|r| r.task_id == exec)
            .expect("failed executor dag row present");
        assert_eq!(
            row.aggregate_verdict, "",
            "failed executors must not be rendered as awaiting reviewer votes"
        );

        let rendered = raxis_ksb::render_ksb(&snap).expect("render");
        assert!(
            !rendered.contains("aggregate=AwaitingReviewerVerdicts"),
            "rendered KSB must not make failed executor retries look like \
             pending reviewer work; got: {rendered}"
        );
    }

    /// Live-e2e regression: the KSB aggregate projection MUST fold
    /// only plan-declared Reviewer successors. A normal downstream
    /// Executor edge (`producer -> consumer`) has no review verdict
    /// and therefore looked like `aggregate=AwaitingReviewerVerdicts` when the KSB
    /// called the aggregator without the sealed-plan agent-type
    /// filter. That stranded the orchestrator at the merge boundary:
    /// it waited for nonexistent reviewer votes instead of calling
    /// `integration_merge`.
    #[test]
    fn dag_row_aggregate_ignores_downstream_executor_successors() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        let init = "init-downstream-executor";
        let producer = "materialize-records";
        let consumer = "service-round-trip";

        registry.insert_orchestrator(
            init.to_owned(),
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec![],
                description: "drive pipeline to merge".to_owned(),
                target_ref: "refs/heads/main".to_owned(),
                elastic: None,
                ..Default::default()
            },
        );
        for (task_id, description) in [(producer, "produce records"), (consumer, "consume records")]
        {
            registry.insert(
                TaskKey::new(init.to_owned(), task_id.to_owned()),
                TaskPlanFields {
                    description: description.to_owned(),
                    session_agent_type: SessionAgentType::Executor,
                    ..Default::default()
                },
            );
        }

        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES} (
                 initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at
             ) VALUES (?1, 'Executing', '{{}}', 'sha-test', 0)"
            ),
            rusqlite::params![init],
        )
        .expect("insert initiative");
        let producer_sha = "1111111111111111111111111111111111111111";
        for (task_id, sha) in [(producer, Some(producer_sha)), (consumer, None)] {
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS} (
                     task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at,
                     evaluation_sha, last_critique, review_verdict
                 ) VALUES (?1, ?2, 'default', 'Completed', 'op',
                           0, 0, 0, ?3, NULL, NULL)"
                ),
                rusqlite::params![task_id, init, sha],
            )
            .expect("insert task");
        }
        conn.execute(
            &format!(
                "INSERT INTO {TASK_DAG_EDGES} (
                 initiative_id, predecessor_task_id, successor_task_id,
                 predecessor_satisfied
             ) VALUES (?1, ?2, ?3, 1)"
            ),
            rusqlite::params![init, producer, consumer],
        )
        .expect("insert dag edge");
        drop(conn);

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: init,
                task_id: None,
                role: KsbRole::Orchestrator,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("assemble orchestrator snapshot");
        drop(conn);

        let row = snap
            .dag_rows
            .iter()
            .find(|r| r.task_id == producer)
            .expect("producer dag row present");
        assert_eq!(row.reviewers, 0, "downstream Executor is not a Reviewer");
        assert_eq!(
            row.aggregate_verdict, "NoSuccessors",
            "non-Reviewer successors must not be folded as missing reviewer votes"
        );
        let rendered = raxis_ksb::render_ksb(&snap).expect("render");
        assert!(
            !rendered.contains("aggregate=AwaitingReviewerVerdicts"),
            "KSB must not tell the orchestrator to wait for nonexistent reviewer votes; got: {rendered}"
        );
    }

    /// Iter50 regression — pin `DagRow::preds_ready` against the
    /// `lint-defect → lint-runner → review-lint-defect-A` shape
    /// the realistic-plan iter49 reproduction surfaced. The
    /// orchestrator activated `review-lint-defect-A` while its
    /// IMMEDIATE plan-declared Executor predecessor `lint-runner`
    /// was still in `Admitted` (not `Completed`); the kernel
    /// rejected every attempt with `ActivateSubTaskReviewerNoEvalSha`
    /// until the orchestrator-respawn-no-progress ceiling fired.
    /// With the projection in place the LLM sees
    /// `review-lint-defect-A … preds_ready=false` directly on
    /// the `dag=` block and the NNSP rule 2 gates the activation.
    /// Closes `INV-KSB-PREDS-READY-PROJECTION-01`.
    #[test]
    fn dag_row_preds_ready_blocks_reviewer_when_immediate_executor_predecessor_not_completed() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        let init = "init-iter50";
        let lint_def = "lint-defect";
        let lint_run = "lint-runner";
        let rev_a = "review-lint-defect-A";

        registry.insert_orchestrator(
            init.to_owned(),
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec![],
                description: "drive lint-defect → lint-runner → review chain".to_owned(),
                target_ref: "refs/heads/main".to_owned(),
                elastic: None,
                ..Default::default()
            },
        );
        for (tid, role) in &[
            (lint_def, SessionAgentType::Executor),
            (lint_run, SessionAgentType::Executor),
            (rev_a, SessionAgentType::Reviewer),
        ] {
            registry.insert(
                TaskKey::new(init.to_owned(), (*tid).to_owned()),
                TaskPlanFields {
                    description: format!("{tid} description"),
                    session_agent_type: *role,
                    ..Default::default()
                },
            );
        }

        let conn = store.lock_sync();
        // Initiatives row is the FK target for `tasks.initiative_id`
        // and `task_dag_edges.initiative_id`; insert it first so
        // SQLite's deferred-FK enforcement (PRAGMA foreign_keys=ON
        // is set by `Store::open`) does not reject the task inserts.
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES} (
                 initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at
             ) VALUES (?1, 'ApprovedPlan', '{{}}', 'sha-test', 0)"
            ),
            rusqlite::params![init],
        )
        .expect("insert initiative");
        // lint-defect has Completed (with evaluation_sha so the
        // `aggregate=NoSuccessors` calculation does not panic on
        // a missing column). lint-runner is still Admitted —
        // never activated. review-lint-defect-A is Admitted.
        for (tid, state, sha) in &[
            (lint_def, "Completed", Some("a".repeat(40))),
            (lint_run, "Admitted", None),
            (rev_a, "Admitted", None),
        ] {
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS} (
                     task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at,
                     evaluation_sha
                 ) VALUES (?1, ?2, 'default', ?3, 'op', 0, 0, 0, ?4)"
                ),
                rusqlite::params![tid, init, state, sha.as_deref()],
            )
            .expect("insert task");
        }
        // Realistic-plan DAG edges:
        //   lint-runner ⟵ lint-defect    (executor depends on executor)
        //   review-lint-defect-A ⟵ lint-runner  (reviewer depends on its runner)
        for (pred, succ) in &[(lint_def, lint_run), (lint_run, rev_a)] {
            conn.execute(
                &format!(
                    "INSERT INTO {TASK_DAG_EDGES} (
                    initiative_id, predecessor_task_id, successor_task_id,
                    predecessor_satisfied
                 ) VALUES (?1, ?2, ?3, 0)"
                ),
                rusqlite::params![init, pred, succ],
            )
            .expect("insert dag edge");
        }
        drop(conn);

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: init,
                task_id: None,
                role: KsbRole::Orchestrator,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("assemble orchestrator snapshot");
        drop(conn);

        let by_id: std::collections::HashMap<&str, &DagRow> = snap
            .dag_rows
            .iter()
            .map(|r| (r.task_id.as_str(), r))
            .collect();

        // lint-defect has no upstream edges in this projection —
        // vacuously preds_ready.
        assert!(
            by_id[lint_def].preds_ready,
            "lint-defect (no predecessors in this fixture) MUST read preds_ready=true"
        );
        // lint-runner's predecessor lint-defect is Completed —
        // ready to activate.
        assert!(
            by_id[lint_run].preds_ready,
            "lint-runner MUST read preds_ready=true once lint-defect is Completed"
        );
        // review-lint-defect-A's IMMEDIATE predecessor lint-runner
        // is still Admitted — NOT ready. This is the iter49
        // reproduction.
        assert!(
            !by_id[rev_a].preds_ready,
            "review-lint-defect-A MUST read preds_ready=false while \
             its immediate Executor predecessor lint-runner is still Admitted \
             — iter49 reproduction; got row: {:?}",
            by_id[rev_a]
        );

        // The rendered KSB MUST carry the wire-stable token the
        // NNSP rule 2 parses on.
        let rendered = raxis_ksb::render_ksb(&snap).expect("render");
        assert!(
            rendered
                .contains("review-lint-defect-A admitted reviewers=0 preds_ready=false sha=<none>"),
            "rendered KSB MUST surface preds_ready=false on the \
             reviewer row; got: {rendered}",
        );
    }

    /// `INV-KSB-COORDINATOR-ROW-HIDDEN-FROM-DAG-01` — the synthetic
    /// coordinator task row (`task_id == initiative_id`, inserted at
    /// orchestrator-spawn time per `lifecycle.rs §spawn_orchestrator_
    /// session_for_initiative`) MUST NOT appear in
    /// `OrchestratorCapabilities::tasks` nor in `KsbSnapshot::dag_rows`.
    /// Leaking it (iter70 regression) caused the orchestrator LLM to
    /// spend its turn-budget puzzling "why is there a row whose id
    /// matches my own initiative_id, in state=admitted, with no
    /// title or reviewers?" instead of dispatching ready successor
    /// tasks.
    #[test]
    fn dag_rows_and_tasks_exclude_synthetic_coordinator_row() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        let init = "init-iter70-coord";
        let exec = "real-executor-task";
        registry.insert_orchestrator(
            init.to_owned(),
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec![],
                description: "coordinator-row exclusion witness".to_owned(),
                target_ref: "refs/heads/main".to_owned(),
                elastic: None,
                ..Default::default()
            },
        );
        registry.insert(
            TaskKey::new(init.to_owned(), exec.to_owned()),
            TaskPlanFields {
                description: format!("{exec} description"),
                session_agent_type: SessionAgentType::Executor,
                ..Default::default()
            },
        );

        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES} (
                 initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at
             ) VALUES (?1, 'ApprovedPlan', '{{}}', 'sha-test', 0)"
            ),
            rusqlite::params![init],
        )
        .expect("insert initiative");
        // Synthetic coordinator row (`task_id == initiative_id`).
        // Mirrors what `lifecycle.rs §spawn_orchestrator_session_
        // for_initiative` would insert.
        conn.execute(
            &format!(
                "INSERT INTO {TASKS} (
                 task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at
             ) VALUES (?1, ?1, 'default', 'Admitted', 'kernel', 0, 0, 0)"
            ),
            rusqlite::params![init],
        )
        .expect("insert coordinator row");
        // Real executor task.
        conn.execute(
            &format!(
                "INSERT INTO {TASKS} (
                 task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at
             ) VALUES (?1, ?2, 'default', 'Admitted', 'kernel', 0, 100, 100)"
            ),
            rusqlite::params![exec, init],
        )
        .expect("insert executor row");
        drop(conn);

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: init,
                task_id: None,
                role: KsbRole::Orchestrator,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("assemble orchestrator snapshot");
        drop(conn);

        // The DAG block MUST carry the real executor row and MUST
        // NOT carry the synthetic coordinator row.
        let dag_ids: Vec<&str> = snap.dag_rows.iter().map(|r| r.task_id.as_str()).collect();
        assert!(
            dag_ids.contains(&exec),
            "dag_rows MUST include the real executor row; got: {dag_ids:?}",
        );
        assert!(
            !dag_ids.contains(&init),
            "dag_rows MUST NOT include the synthetic coordinator row \
             (task_id == initiative_id); got: {dag_ids:?}",
        );

        // The capabilities.tasks block (already filters by
        // `session_agent_type == Executor`) MUST also exclude the
        // coordinator. Pin the contract explicitly.
        let caps = snap
            .capabilities
            .as_ref()
            .expect("orchestrator capabilities present");
        let raxis_ksb::Capabilities::Orchestrator(o) = caps else {
            panic!("expected Orchestrator capabilities; got {caps:?}");
        };
        let task_ids: Vec<&str> = o.tasks.iter().map(|t| t.task_id.as_str()).collect();
        assert!(
            !task_ids.contains(&init),
            "capabilities.tasks MUST NOT include the synthetic \
             coordinator row; got: {task_ids:?}",
        );

        // The rendered KSB MUST NOT mention the coordinator's id on
        // any DAG line.
        let rendered = raxis_ksb::render_ksb(&snap).expect("render");
        for line in rendered.lines() {
            assert!(
                !(line.trim_start().starts_with(&format!("- {init} "))
                    && line.contains(" preds_ready=")),
                "rendered DAG block MUST NOT contain a row for the \
                 synthetic coordinator (`task_id == initiative_id`); \
                 offending line: {line:?}; full render:\n{rendered}",
            );
        }
    }

    /// `INV-KSB-READY-NOW-MATCHES-KERNEL-ADMISSION-01` — the
    /// `OrchestratorCapabilities::ready_now` projection MUST equal
    /// the set of task ids the kernel's
    /// `classify_batch_candidates` would mark `Admissible` right
    /// now. The predicate is: task state == Admitted AND every
    /// `task_dag_edges` predecessor in `tasks.state = 'Completed'`
    /// AND the latest `subtask_activations.activation_state ==
    /// 'PendingActivation'` AND `plan_registry.session_agent_type
    /// is Executor or Reviewer.
    #[test]
    fn ready_now_matches_kernel_admission_predicate() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        let init = "init-iter70-ready";
        let ready_a = "ready-a";
        let ready_b = "ready-b";
        let blocked_pred = "blocked-pred";
        let no_activation_row = "no-activation-row";
        let reviewer = "reviewer-of-ready-a";
        let ready_reviewer = "reviewer-of-pred-done";
        let pred_done = "predecessor-completed";
        let gate_parent = "gate-parent";
        let gate_fixup = "gate-fixup";

        registry.insert_orchestrator(
            init.to_owned(),
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec![],
                description: "ready_now witness".to_owned(),
                target_ref: "refs/heads/main".to_owned(),
                repository_id: OrchestratorPlanFields::DEFAULT_REPOSITORY_ID.to_owned(),
                elastic: None,
                max_concurrent_admissions: 5,
                integration_merge_verifiers: Vec::new(),
            },
        );
        for (tid, kind) in &[
            (pred_done, SessionAgentType::Executor),
            (ready_a, SessionAgentType::Executor),
            (ready_b, SessionAgentType::Executor),
            (blocked_pred, SessionAgentType::Executor),
            (no_activation_row, SessionAgentType::Executor),
            (reviewer, SessionAgentType::Reviewer),
            (ready_reviewer, SessionAgentType::Reviewer),
            (gate_parent, SessionAgentType::Executor),
            (gate_fixup, SessionAgentType::Executor),
        ] {
            registry.insert(
                TaskKey::new(init.to_owned(), (*tid).to_owned()),
                TaskPlanFields {
                    description: format!("{tid} description"),
                    session_agent_type: *kind,
                    ..Default::default()
                },
            );
        }

        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES} (
                 initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at
             ) VALUES (?1, 'Executing', '{{}}', 'sha', 0)"
            ),
            rusqlite::params![init],
        )
        .expect("init");
        // Coordinator row (must be filtered out everywhere).
        conn.execute(
            &format!(
                "INSERT INTO {TASKS} (task_id, initiative_id, lane_id, state, actor, \
                                policy_epoch, admitted_at, transitioned_at) \
             VALUES (?1, ?1, 'default', 'Admitted', 'kernel', 0, 0, 0)"
            ),
            rusqlite::params![init],
        )
        .expect("coord");
        // pred_done = Completed (so any successor whose predecessor
        // closure depends on it gets `preds_ready=true`).
        conn.execute(
            &format!(
                "INSERT INTO {TASKS} (task_id, initiative_id, lane_id, state, actor, \
                                policy_epoch, admitted_at, transitioned_at, \
                                evaluation_sha) \
             VALUES (?1, ?2, 'default', 'Completed', 'kernel', 0, 10, 10, ?3)"
            ),
            rusqlite::params![pred_done, init, "a".repeat(40)],
        )
        .expect("pred_done");
        // The candidate fixtures, all Admitted.
        for (tid, ts) in &[
            (ready_a, 20i64),
            (ready_b, 30i64),
            (ready_reviewer, 35i64),
            (blocked_pred, 40i64),
            (no_activation_row, 50i64),
            (reviewer, 60i64),
        ] {
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS} (task_id, initiative_id, lane_id, state, actor, \
                                    policy_epoch, admitted_at, transitioned_at) \
                 VALUES (?1, ?2, 'default', 'Admitted', 'kernel', 0, ?3, ?3)"
                ),
                rusqlite::params![tid, init, ts],
            )
            .expect("task");
        }
        conn.execute(
            &format!(
                "INSERT INTO {TASKS} (task_id, initiative_id, lane_id, state, actor, \
                                policy_epoch, admitted_at, transitioned_at) \
             VALUES (?1, ?2, 'default', 'GatesPending', 'kernel', 0, 24, 24)"
            ),
            rusqlite::params![gate_parent, init],
        )
        .expect("gate parent");
        conn.execute(
            &format!(
                "INSERT INTO {TASKS} (task_id, initiative_id, lane_id, state, actor, \
                                policy_epoch, admitted_at, transitioned_at, \
                                is_gate_fixup, parent_gate_failure_task_id, \
                                parent_gate_failure_type) \
             VALUES (?1, ?2, 'default', 'Admitted', 'kernel', 0, 25, 25, \
                     1, ?3, 'coverage')"
            ),
            rusqlite::params![gate_fixup, init, gate_parent],
        )
        .expect("gate fixup task");
        // Edges:
        //   ready_a   ⟵ pred_done       (pred Completed → ready)
        //   blocked_pred ⟵ ready_a      (pred is Admitted not Completed → NOT ready)
        //   ready_reviewer ⟵ pred_done  (Reviewer with pred Completed → ready)
        //   reviewer  ⟵ ready_a         (pred Admitted → reviewer NOT ready)
        //   gate_fixup ⟵ gate_parent    (parent is GatesPending but this is a
        //                                fixup-lineage edge → ready)
        for (pred, succ) in &[
            (pred_done, ready_a),
            (pred_done, ready_reviewer),
            (ready_a, blocked_pred),
            (ready_a, reviewer),
            (gate_parent, gate_fixup),
        ] {
            conn.execute(
                &format!(
                    "INSERT INTO {TASK_DAG_EDGES} (initiative_id, predecessor_task_id, \
                                              successor_task_id, predecessor_satisfied) \
                 VALUES (?1, ?2, ?3, 0)"
                ),
                rusqlite::params![init, pred, succ],
            )
            .expect("edge");
        }
        // Activation rows:
        //   ready_a       latest = PendingActivation (ADMISSIBLE)
        //   ready_b       latest = PendingActivation (ADMISSIBLE)
        //   blocked_pred  latest = PendingActivation (would be admissible, but pred not Completed)
        //   no_activation_row  NO row (NOT admissible)
        //   ready_reviewer latest = PendingActivation (ADMISSIBLE reviewer)
        //   reviewer      latest = PendingActivation (blocked by predecessor)
        //   gate_fixup    latest = PendingActivation (ADMISSIBLE despite parent GatesPending)
        for (tid, state, created_at) in &[
            (ready_a, "PendingActivation", 21i64),
            (ready_b, "PendingActivation", 31i64),
            (ready_reviewer, "PendingActivation", 36i64),
            (blocked_pred, "PendingActivation", 41i64),
            (reviewer, "PendingActivation", 61i64),
            (gate_fixup, "PendingActivation", 26i64),
        ] {
            conn.execute(
                &format!(
                    "INSERT INTO {SUBTASK_ACTIVATIONS} \
                    (activation_id, task_id, initiative_id, activation_state, \
                     session_id, crash_retry_count, review_reject_count, \
                     validation_reject_count, created_at) \
                 VALUES (?1, ?2, ?3, ?4, NULL, 0, 0, 0, ?5)"
                ),
                rusqlite::params![format!("act-{tid}"), tid, init, state, created_at],
            )
            .expect("activation");
        }
        drop(conn);

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: init,
                task_id: None,
                role: KsbRole::Orchestrator,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("snapshot");
        drop(conn);

        let raxis_ksb::Capabilities::Orchestrator(o) =
            snap.capabilities.as_ref().expect("capabilities present")
        else {
            panic!("expected orchestrator capabilities");
        };

        assert_eq!(
            o.ready_now,
            vec![
                ready_a.to_owned(),
                gate_fixup.to_owned(),
                ready_b.to_owned(),
                ready_reviewer.to_owned()
            ],
            "ready_now MUST list only Executor/Reviewer tasks whose latest \
             activation is PendingActivation AND whose predecessors \
             are all Completed except for the parent lineage edge of \
             a gate-fixup task; got: {:?}",
            o.ready_now,
        );

        // Concurrency cap reflects the plan registry value (5);
        // active_count is 0 (no Active activation rows seeded).
        assert_eq!(o.concurrency.cap, 5);
        assert_eq!(o.concurrency.active_count, 0);
        assert_eq!(o.concurrency.headroom, 5);

        // Renderer must surface both lines in the orchestrator block.
        let rendered = raxis_ksb::render_ksb(&snap).expect("render");
        assert!(
            rendered.contains(&format!(
                "ready_now=[{ready_a}, {gate_fixup}, {ready_b}, {ready_reviewer}]"
            )),
            "rendered KSB MUST surface `ready_now=[…]` in order; got:\n{rendered}",
        );
        assert!(
            rendered.contains("concurrency: cap=5 active=0 headroom=5"),
            "rendered KSB MUST surface `concurrency:` line; got:\n{rendered}",
        );
    }

    /// `INV-KSB-CONCURRENCY-VIEW-MIRRORS-KERNEL-CAP-01` — the
    /// `active_count` field MUST equal `COUNT(*) FROM
    /// subtask_activations WHERE initiative_id = ? AND
    /// activation_state = 'Active'` — the exact predicate the
    /// orchestrator-post-exit respawn hook uses to gate bounded
    /// concurrency (`session_spawn_orchestrator.rs` Mode A).
    #[test]
    fn concurrency_view_active_count_mirrors_post_exit_hook_predicate() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        let init = "init-iter70-conc";

        registry.insert_orchestrator(
            init.to_owned(),
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec![],
                description: "concurrency view witness".to_owned(),
                target_ref: "refs/heads/main".to_owned(),
                repository_id: OrchestratorPlanFields::DEFAULT_REPOSITORY_ID.to_owned(),
                elastic: None,
                max_concurrent_admissions: 4,
                integration_merge_verifiers: Vec::new(),
            },
        );
        // Two executor tasks so the projection has something to
        // count; agent type kept consistent for the activation row
        // FK.
        for tid in &["e-active", "e-pending"] {
            registry.insert(
                TaskKey::new(init.to_owned(), (*tid).to_owned()),
                TaskPlanFields {
                    description: (*tid).to_owned(),
                    session_agent_type: SessionAgentType::Executor,
                    ..Default::default()
                },
            );
        }

        let conn = store.lock_sync();
        // Seed the session row FIRST so the subtask_activations FK
        // (session_id) resolves at INSERT time. PRAGMA foreign_keys
        // is ON in `Store::open`.
        conn.execute(
            &format!(
                "INSERT INTO {SESSIONS} \
                (session_id, role_id, session_token, lineage_id, \
                 fetch_quota, created_at, expires_at, revoked) \
             VALUES ('11111111-1111-1111-1111-111111111111', 'Executor', \
                     'tok-iter70-conc', 'lin-iter70-conc', 1000, 1, 9999999999, 0)"
            ),
            [],
        )
        .expect("session");
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES} (initiative_id, state, terminal_criteria_json, \
                                       plan_artifact_sha256, created_at) \
             VALUES (?1, 'Executing', '{{}}', 'sha', 0)"
            ),
            rusqlite::params![init],
        )
        .expect("init");
        conn.execute(
            &format!(
                "INSERT INTO {TASKS} (task_id, initiative_id, lane_id, state, actor, \
                                policy_epoch, admitted_at, transitioned_at) \
             VALUES (?1, ?1, 'default', 'Admitted', 'kernel', 0, 0, 0)"
            ),
            rusqlite::params![init],
        )
        .expect("coord");
        for (tid, ts) in &[("e-active", 10i64), ("e-pending", 20i64)] {
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS} (task_id, initiative_id, lane_id, state, actor, \
                                    policy_epoch, admitted_at, transitioned_at) \
                 VALUES (?1, ?2, 'default', 'Running', 'kernel', 0, ?3, ?3)"
                ),
                rusqlite::params![tid, init, ts],
            )
            .expect("task");
        }
        // One Active activation row + one PendingActivation row.
        // The active_count helper counts ONLY Active rows.
        conn.execute(
            &format!(
                "INSERT INTO {SUBTASK_ACTIVATIONS} \
                (activation_id, task_id, initiative_id, activation_state, \
                 session_id, crash_retry_count, review_reject_count, \
                 validation_reject_count, created_at, activated_at) \
             VALUES ('act-active', 'e-active', ?1, 'Active', \
                     '11111111-1111-1111-1111-111111111111', \
                     0, 0, 0, 11, 12)"
            ),
            rusqlite::params![init],
        )
        .expect("active");
        conn.execute(
            &format!(
                "INSERT INTO {SUBTASK_ACTIVATIONS} \
                (activation_id, task_id, initiative_id, activation_state, \
                 session_id, crash_retry_count, review_reject_count, \
                 validation_reject_count, created_at) \
             VALUES ('act-pending', 'e-pending', ?1, 'PendingActivation', \
                     NULL, 0, 0, 0, 21)"
            ),
            rusqlite::params![init],
        )
        .expect("pending");
        drop(conn);

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &conn,
            &registry,
            &KsbInputs {
                initiative_id: init,
                task_id: None,
                role: KsbRole::Orchestrator,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
                session_id: "",
                planner_max_turns: crate::initiatives::plan_registry::DEFAULT_PLANNER_MAX_TURNS,
                max_turns_scaling: default_max_turns_scaling(),
            },
        )
        .expect("snapshot");
        drop(conn);

        let raxis_ksb::Capabilities::Orchestrator(o) = snap.capabilities.as_ref().unwrap() else {
            panic!("orchestrator caps expected");
        };
        assert_eq!(o.concurrency.cap, 4);
        assert_eq!(o.concurrency.active_count, 1);
        assert_eq!(o.concurrency.headroom, 3);
    }

    #[test]
    fn fallback_snapshot_carries_required_fields_for_renderer() {
        let snap = fallback_snapshot("init-x", Some("task-y"), KsbRole::Executor);
        assert_eq!(snap.initiative_id, "init-x");
        assert_eq!(snap.role, "executor");
        // The fallback MUST satisfy `render_ksb`'s required-field
        // checks (initiative_id + role non-empty, no delimiter
        // injection) so the spawn path can stamp it without a
        // second-order failure on the driver side.
        let r = raxis_ksb::render_ksb(&snap).expect("render fallback");
        assert!(r.contains("initiative_id=init-x"));
        assert!(r.contains("role=executor"));
    }

    /// V2.7 `INV-KSB-MAX-TURNS-VISIBILITY-01` — the
    /// `SessionCapabilityView::planner_max_turns` projection MUST
    /// equal `KsbInputs::planner_max_turns` byte-for-byte for ALL
    /// three role envelopes. The spawn callsite passes the
    /// already-resolved value (computed by
    /// `crate::session_spawn_orchestrator::resolve_planner_max_turns_for`)
    /// here so the env stamp and the KSB are bit-equal by
    /// construction; this test pins that the assembler does not
    /// transform / clamp / floor the input.
    #[test]
    fn inv_ksb_max_turns_visibility_01_session_view_carries_resolved_value() {
        use raxis_ksb::Capabilities;

        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        populate_registry(&registry, "init-mt", "task-mt");

        // A non-default value to pin that the assembler is NOT
        // ignoring its input and substituting a compiled default.
        const RESOLVED: u32 = 137;

        for role in [KsbRole::Orchestrator, KsbRole::Executor] {
            let conn = store.lock_sync();
            let snap = assemble_ksb_snapshot(
                &conn,
                &registry,
                &KsbInputs {
                    initiative_id: "init-mt",
                    task_id: Some("task-mt"),
                    role,
                    token_budget_remaining: 0,
                    wallclock_budget_remaining_s: 0,
                    credential_ports: Vec::new(),
                    session_id: "sess-mt",
                    planner_max_turns: RESOLVED,
                    max_turns_scaling: default_max_turns_scaling(),
                },
            )
            .expect("assemble snapshot");
            drop(conn);

            let caps = snap.capabilities.expect("capabilities populated");
            let session = match &caps {
                Capabilities::Orchestrator(o) => &o.session,
                Capabilities::Executor(e) => &e.session,
                Capabilities::Reviewer(r) => &r.session,
            };
            assert_eq!(
                session.planner_max_turns, RESOLVED,
                "role {role:?}: SessionCapabilityView::planner_max_turns MUST \
                 equal KsbInputs::planner_max_turns; assembler MUST NOT \
                 clamp / transform the resolver-provided value",
            );
        }
    }

    // ─── iter62 — INV-RETRY-LAST-CRITIQUE-IN-KSB-01 ────────────────

    /// `read_last_critique_for_retry` projects `tasks.last_critique`
    /// IFF the most-recent activation row is past attempt 1 (any of
    /// `crash_retry_count`, `review_reject_count`, or
    /// `validation_reject_count` is non-zero). The round-1 path
    /// surfaces `None` so the KSB byte prefix stays stable.
    #[test]
    fn last_critique_projection_returns_none_on_round_1() {
        let (store, _td) = fresh_store();
        let conn = store.lock_sync();
        // Seed the session row FIRST so the subtask_activations FK
        // (session_id) resolves at INSERT time. PRAGMA foreign_keys
        // is ON in `Store::open`, and `execute_batch` auto-commits
        // each statement so deferred-FK semantics do not apply.
        conn.execute(
            &format!(
                "INSERT INTO {SESSIONS} \
                (session_id, role_id, session_token, lineage_id, \
                 fetch_quota, created_at, expires_at, revoked) \
             VALUES ('11111111-1111-1111-1111-111111111111', 'Executor', \
                     'tok-c7r1', 'lin-c7r1', 1000, 1, 9999999999, 0)"
            ),
            [],
        )
        .unwrap();
        // Seed a task with last_critique populated but ZERO retry
        // counters on the most-recent activation row.
        conn.execute_batch(&format!(
            "INSERT INTO {INITIATIVES} \
                (initiative_id, state, terminal_criteria_json, \
                 plan_artifact_sha256, created_at) \
             VALUES ('init-c7r1', 'Executing', '{{}}', 'deadbeef', 1); \
             INSERT INTO {TASKS} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, \
                 actual_cost, last_critique) \
             VALUES ('task-c7r1', 'init-c7r1', 'default', \
                     'Running', 'kernel', 1, 1, 1, 0, \
                     'round-0 critique that should not surface'); \
             INSERT INTO {SUBTASK_ACTIVATIONS} \
                (activation_id, task_id, initiative_id, \
                 activation_state, session_id, \
                 crash_retry_count, review_reject_count, \
                 validation_reject_count, created_at, \
                 activated_at) \
             VALUES ('act-c7r1', 'task-c7r1', 'init-c7r1', \
                     'Active', \
                     '11111111-1111-1111-1111-111111111111', \
                     0, 0, 0, 1, 2);"
        ))
        .unwrap();

        let critique = read_last_critique_for_retry(&conn, "task-c7r1").unwrap();
        assert!(
            critique.is_none(),
            "round-1 task MUST surface last_critique=None so the KSB byte prefix is stable"
        );
    }

    /// Retry rounds (any non-zero counter) MUST surface the
    /// persisted `tasks.last_critique`.
    #[test]
    fn last_critique_projection_returns_critique_when_review_rejected() {
        let (store, _td) = fresh_store();
        let conn = store.lock_sync();
        conn.execute_batch(&format!(
            "INSERT INTO {INITIATIVES} \
                (initiative_id, state, terminal_criteria_json, \
                 plan_artifact_sha256, created_at) \
             VALUES ('init-c7r2', 'Executing', '{{}}', 'deadbeef', 1); \
             INSERT INTO {TASKS} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, \
                 actual_cost, last_critique) \
             VALUES ('task-c7r2', 'init-c7r2', 'default', \
                     'Admitted', 'kernel', 1, 1, 1, 0, \
                     'round-0 reviewer feedback'); \
             INSERT INTO {SUBTASK_ACTIVATIONS} \
                (activation_id, task_id, initiative_id, \
                 activation_state, session_id, \
                 crash_retry_count, review_reject_count, \
                 validation_reject_count, created_at) \
             VALUES ('act-c7r2', 'task-c7r2', 'init-c7r2', \
                     'PendingActivation', NULL, \
                     0, 1, 0, 1);"
        ))
        .unwrap();

        let critique = read_last_critique_for_retry(&conn, "task-c7r2").unwrap();
        assert_eq!(
            critique.as_deref(),
            Some("round-0 reviewer feedback"),
            "review-rejection retry MUST surface tasks.last_critique"
        );
    }

    /// Validation-rejection retries (`validation_reject_count > 0`)
    /// MUST also surface `last_critique` — the spec requires it
    /// alongside review rejections.
    #[test]
    fn last_critique_projection_returns_critique_when_validation_rejected() {
        let (store, _td) = fresh_store();
        let conn = store.lock_sync();
        conn.execute_batch(&format!(
            "INSERT INTO {INITIATIVES} \
                (initiative_id, state, terminal_criteria_json, \
                 plan_artifact_sha256, created_at) \
             VALUES ('init-c7r3', 'Executing', '{{}}', 'deadbeef', 1); \
             INSERT INTO {TASKS} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, \
                 actual_cost, last_critique) \
             VALUES ('task-c7r3', 'init-c7r3', 'default', \
                     'Admitted', 'kernel', 1, 1, 1, 0, \
                     'kernel: empty diff at head ABCD'); \
             INSERT INTO {SUBTASK_ACTIVATIONS} \
                (activation_id, task_id, initiative_id, \
                 activation_state, session_id, \
                 crash_retry_count, review_reject_count, \
                 validation_reject_count, created_at) \
             VALUES ('act-c7r3', 'task-c7r3', 'init-c7r3', \
                     'PendingActivation', NULL, \
                     0, 0, 1, 1);"
        ))
        .unwrap();

        let critique = read_last_critique_for_retry(&conn, "task-c7r3").unwrap();
        assert_eq!(
            critique.as_deref(),
            Some("kernel: empty diff at head ABCD"),
            "validation-rejection retry MUST surface tasks.last_critique"
        );
    }

    // ── iter65 — INV-KSB-GATE-FIXUP-CONTEXT-01 projection ────────────────

    /// Non-fixup task (`is_gate_fixup = 0`) MUST surface `None`.
    /// This is the steady-state path — every executor / reviewer
    /// activation that is not a fixup goes through this branch
    /// and the projection MUST leave the KSB compact.
    #[test]
    fn gate_fixup_projection_returns_none_for_non_fixup_task() {
        let (store, _td) = fresh_store();
        let conn = store.lock_sync();
        conn.execute_batch(&format!(
            "INSERT INTO {INITIATIVES} \
                (initiative_id, state, terminal_criteria_json, \
                 plan_artifact_sha256, created_at) \
             VALUES ('init-gf1', 'Executing', '{{}}', 'deadbeef', 1); \
             INSERT INTO {TASKS} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, \
                 actual_cost) \
             VALUES ('task-plain', 'init-gf1', 'default', \
                     'Admitted', 'kernel', 1, 1, 1, 0);"
        ))
        .unwrap();
        let ctx = read_gate_fixup_context(&conn, "task-plain").unwrap();
        assert!(ctx.is_none(), "non-fixup task MUST surface gate_fixup=None");
    }

    /// Happy path: a fixup task whose parent carries the witness
    /// handler's `last_gate_critique` + `last_gate_type` MUST
    /// project a fully-populated `GateFixupContext` with the
    /// parent linkage, the bounded hint, and the
    /// worktree pointer resolved through the parent's session
    /// row.
    #[test]
    fn gate_fixup_projection_returns_populated_context_for_fixup_task() {
        let (store, _td) = fresh_store();
        let conn = store.lock_sync();
        conn.execute_batch(&format!(
            "INSERT INTO {INITIATIVES} \
                (initiative_id, state, terminal_criteria_json, \
                 plan_artifact_sha256, created_at) \
             VALUES ('init-gf2', 'Executing', '{{}}', 'deadbeef', 1); \
             INSERT INTO {SESSIONS} \
                (session_id, role_id, session_token, sequence_number, \
                 worktree_root, base_sha, base_tracking_ref, \
                 lineage_id, fetch_quota, created_at, expires_at, \
                 revoked, session_agent_type, can_delegate) \
             VALUES ('sess-parent', 'Planner', 'tok-1', 0, \
                     '/srv/raxis/wt/parent', NULL, NULL, \
                     'lin-1', 1000, 1, 3600, 0, 'Executor', 0); \
             INSERT INTO {TASKS} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, \
                 actual_cost, evaluation_sha, last_gate_critique, \
                 last_gate_type, session_id, gate_fixup_attempts) \
             VALUES ('parent-1', 'init-gf2', 'default', \
                     'GatesPending', 'kernel', 1, 1, 1, 0, \
                     'deadbeefcafebabe', \
                     'Remove the AWS access key shape.', \
                     'NoSecretStrings', 'sess-parent', 1); \
             INSERT INTO {TASKS} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, \
                 actual_cost, is_gate_fixup, \
                 parent_gate_failure_task_id, \
                 parent_gate_failure_type) \
             VALUES ('fixup-1', 'init-gf2', 'default', \
                     'Running', 'kernel', 1, 1, 1, 0, 1, \
                     'parent-1', 'NoSecretStrings');"
        ))
        .unwrap();

        let ctx = read_gate_fixup_context(&conn, "fixup-1")
            .unwrap()
            .expect("fixup task MUST surface a Some(GateFixupContext)");
        assert_eq!(ctx.gate_type, "NoSecretStrings");
        assert_eq!(ctx.agent_hint, "Remove the AWS access key shape.");
        assert_eq!(ctx.parent_task_id, "parent-1");
        assert_eq!(ctx.parent_evaluation_sha, "deadbeefcafebabe");
        assert_eq!(ctx.parent_worktree_pointer, "/srv/raxis/wt/parent");
        assert_eq!(
            ctx.attempt_index, 1,
            "attempt index must reflect the parent's gate_fixup_attempts counter"
        );
    }

    /// Defense-in-depth: a fixup task with NO parent linkage
    /// (structurally invalid, but the projection must not crash)
    /// MUST surface `None` so the spawn path can fall back to the
    /// degraded KSB instead of crashing the substrate boot.
    #[test]
    fn gate_fixup_projection_returns_none_when_parent_link_missing() {
        let (store, _td) = fresh_store();
        let conn = store.lock_sync();
        conn.execute_batch(&format!(
            "INSERT INTO {INITIATIVES} \
                (initiative_id, state, terminal_criteria_json, \
                 plan_artifact_sha256, created_at) \
             VALUES ('init-gf3', 'Executing', '{{}}', 'deadbeef', 1); \
             INSERT INTO {TASKS} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, \
                 actual_cost, is_gate_fixup) \
             VALUES ('fixup-orphan', 'init-gf3', 'default', \
                     'Running', 'kernel', 1, 1, 1, 0, 1);"
        ))
        .unwrap();
        let ctx = read_gate_fixup_context(&conn, "fixup-orphan").unwrap();
        assert!(
            ctx.is_none(),
            "fixup with NULL parent linkage MUST surface None (defensive boot-safe path)"
        );
    }
}
