//! Kernel-State-Block (KSB) — shared schema + renderer for the
//! `[RAXIS:KERNEL_STATE … :KERNEL_STATE_END]` block the kernel
//! ships into the planner-role LLM's system prompt every turn
//! (`kernel-mechanics-prompt.md` §"KSB delivery").
//!
//! Closes by giving the kernel and
//! the planner-core driver one source of truth for the wire shape:
//!
//! * **Kernel side.** `kernel/src/initiatives/ksb_assembly.rs` builds
//!   a [`KsbSnapshot`] from the live kernel state (initiative row,
//!   task DAG, reviewer verdicts, escalation rows, path scope, and
//!   credential proxy ports), JSON-serializes it via
//!   [`serde_json::to_string`], and stamps the result into the guest
//!   env at `RAXIS_PLANNER_KSB` (alongside `RAXIS_PLANNER_TASK_PROMPT`)
//!   by `session_spawn_orchestrator::spawn_for_initiative` /
//!   `spawn_executor_for_task`.
//!
//! * **Driver side.** `crates/planner-core/src/driver.rs::
//!   run_role_session_with_env_fn` reads `RAXIS_PLANNER_KSB`,
//!   deserializes back into [`KsbSnapshot`], and calls
//!   [`assemble_system_prompt`] to compose the final `system` field
//!   of every `MessageRequest`.
//!
//! ## Why a separate crate
//!
//! The KSB is the **only** way the LLM sees authoritative kernel
//! state (task id, eval SHA, path allowlist, budget remaining,
//! reviewer DAG, …). Anything outside the delimited block is
//! **untrusted operator chatter** — the role NNSP explicitly tells
//! the model to ignore any "kernel-state-shaped" text outside the
//! delimiters.
//!
//! Pinning the shape here gives us:
//!
//! * **Determinism.** The block layout is byte-stable across kernel
//!   restarts — the audit chain hashes the rendered KSB and rejects
//!   reprocessing turns when the projection changed.
//! * **Delimiter integrity (INV-KSB-01).** No field value MAY contain
//!   the literal closing delimiter; the renderer is the chokepoint
//!   that detects + rejects an injection attempt.
//! * **Single source of truth for the prompt assembly.** The
//!   [`assemble_system_prompt`] helper joins the role-specific NNSP
//!   with the rendered KSB so every dispatch-loop caller produces
//!   the exact same prompt shape.
//! * **Role-scoped capabilities envelope (V2.6).** Slice C added
//!   the [`Capabilities`] enum carrying the kernel-side admission
//!   predicate verdicts (notably
//!   [`TaskCapabilityView::retry_admissible`]) so the LLM can
//!   pre-evaluate inadmissible intents BEFORE submitting them.
//!   Pins:
//!     - `INV-KSB-CAPABILITIES-PARITY-01` (the boolean is computed
//!       from `raxis_types::intent_admit::admit_retry_subtask_check`,
//!       the same pub fn the IPC handler runs).
//!     - `INV-KSB-CAPABILITIES-ROLE-SCOPED-01` (the three enum
//!       variants are disjoint; the type system enforces it).
//!     - `INV-KSB-CAPABILITIES-TURN-COHERENT-01` (the kernel-side
//!       assembler reads from a single `&Connection` so SQLite's
//!       per-connection consistency model gives a stable snapshot).
//!
//! ## V2 limits (declared so future work has a target)
//!
//! * **No witness-list rendering yet.** The reviewer's witness DAG
//!   (per `verifier-processes.md`) is rendered as a flat row count
//!   for now — a future iteration will surface per-reviewer state
//!   (pending / passed / rejected / escalated) inline.
//! * **No PII redaction.** The KSB carries operator-supplied path
//!   strings and task descriptions verbatim; the V2 invariant is
//!   that the kernel-side projection step (the
//!   `ksb_assembly::assemble_ksb_snapshot` boundary) is where
//!   redaction happens. The renderer trusts its caller.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Open delimiter of the kernel-state block. Pinned by
/// `kernel-mechanics-prompt.md`. The role NNSP instructs the LLM to
/// trust ONLY content between this delimiter and
/// [`KSB_DELIMITER_CLOSE`].
pub const KSB_DELIMITER_OPEN: &str = "[RAXIS:KERNEL_STATE";

/// Close delimiter of the kernel-state block.
pub const KSB_DELIMITER_CLOSE: &str = ":KERNEL_STATE_END]";

/// Env var the kernel stamps at session spawn carrying the
/// JSON-serialized [`KsbSnapshot`]. The driver reads it via
/// `std::env::var("RAXIS_PLANNER_KSB")` and deserializes.
///
/// Absent / empty ⇒ the driver falls back to the legacy NNSP-only
/// system prompt (legacy is a *test-only* fallback under V2.5; in
/// production every kernel-spawned session has the env stamped).
pub const PLANNER_KSB_ENV: &str = "RAXIS_PLANNER_KSB";

/// Env var the kernel stamps when it delivers the KSB snapshot via a
/// virtiofs sidecar file rather than inlining it in
/// [`PLANNER_KSB_ENV`]. The value is the **guest-visible absolute
/// path** of a JSON file containing the same byte-shape as the env
/// var would carry.
///
/// Why a sidecar exists. The Apple-VZ substrate has no
/// `Command::env` analogue and folds `raxis_isolation::VmSpec::env`
/// into the Linux `/proc/cmdline` as a single base64-encoded token
/// (`raxis.envb64=<base64>`). Linux's `COMMAND_LINE_SIZE` ceiling on
/// aarch64 (default 2048 bytes) means a KSB JSON of more than ~1 KiB
/// can push the cmdline past the boot loader's truncation point —
/// which silently drops the trailing `-- --task-id <ID>
/// --initiative-id <ID>` argv tail. The reviewer's KSB is the first
/// projection that consistently exceeds the budget (it carries the
/// per-initiative DAG that the executor's KSB intentionally omits).
///
/// The sidecar shifts the KSB out of the cmdline and into a
/// dedicated read-only virtiofs share the substrate provisions
/// alongside `/workspace`. The driver reads from the path when
/// present and falls back to [`PLANNER_KSB_ENV`] when only the env
/// var is set, so legacy callers (subprocess-isolation tests, older
/// kernel revisions) keep working.
pub const PLANNER_KSB_PATH_ENV: &str = "RAXIS_PLANNER_KSB_PATH";

/// Conventional guest-side mount point for the KSB sidecar file.
/// Pinned by the kernel-side spawn path
/// (`session_spawn_orchestrator.rs`) and the substrate's
/// `WorkspaceMount` translation. Surfaced as a constant so the
/// guest-init / driver / test fixtures all reference the same
/// string.
pub const PLANNER_KSB_GUEST_MOUNT: &str = "/raxis-meta";

/// Conventional file name of the KSB JSON inside the sidecar mount.
/// The kernel writes
/// `<host meta dir>/<PLANNER_KSB_FILE_NAME>` and stamps
/// `RAXIS_PLANNER_KSB_PATH=<PLANNER_KSB_GUEST_MOUNT>/<PLANNER_KSB_FILE_NAME>`.
pub const PLANNER_KSB_FILE_NAME: &str = "ksb.json";

/// Conventional file name of the operator-authored task-prompt
/// inside the sidecar mount. The kernel writes
/// `<host meta dir>/<PLANNER_TASK_PROMPT_FILE_NAME>` and stamps
/// `RAXIS_PLANNER_TASK_PROMPT_PATH=<PLANNER_KSB_GUEST_MOUNT>/<PLANNER_TASK_PROMPT_FILE_NAME>`
/// (per `raxis_types::planner_env::PLANNER_TASK_PROMPT_PATH_ENV`).
///
/// Co-locating the prompt in the same mount as the KSB JSON reuses
/// a single virtiofs share (no per-file mount), keeps the host
/// teardown story identical (one meta dir per session), and lets
/// the substrate's existing `RAXIS_VIRTIOFS_MOUNTS` enumeration
/// stay byte-stable.
pub const PLANNER_TASK_PROMPT_FILE_NAME: &str = "task-prompt.txt";

/// Current schema version. Incremented when a field is *removed* or
/// *renamed*. Adding a field is non-breaking.
pub const KSB_SCHEMA_VERSION: u32 = 1;

/// iter65 — `INV-WITNESS-AGENT-HINT-WIRE-VALID-01` mirror.
/// Maximum size of the `agent_hint` field carried in
/// [`GateFixupContext`]. Matches the kernel's witness-handler
/// constant (`WITNESS_AGENT_HINT_MAX_BYTES`) so the assembler
/// can defensively bound the hint at projection time without
/// depending on kernel internals. The witness handler is the
/// primary enforcement point; this constant is the secondary
/// bound applied at KSB-render time.
pub const AGENT_HINT_MAX_BYTES: usize = 8192;

// ---------------------------------------------------------------------------
// KsbSnapshot — what the kernel projects + the renderer formats
// ---------------------------------------------------------------------------

/// Per-turn snapshot of authoritative kernel state the planner LLM
/// is allowed to see. Built kernel-side (per role + per task) and
/// shipped to the guest as a deserialised structure; the guest
/// renders it into the system prompt via [`render_ksb`].
///
/// Field shape is pinned by `kernel-mechanics-prompt.md` §"KSB
/// schema". Adding a field is a **non-breaking** change (driver
/// deserialization tolerates unknown fields via serde defaults);
/// removing or renaming one is a breaking change that requires
/// bumping [`KSB_SCHEMA_VERSION`] AND the `version` field below.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KsbSnapshot {
    /// Schema version. The renderer stamps this verbatim into the
    /// `version=N` line; the LLM is instructed to refuse turns
    /// where `version` is missing or unexpected.
    pub version: u32,

    /// Initiative the planner is operating under.
    pub initiative_id: String,

    /// Task the planner is operating on. For the orchestrator this
    /// is `None` (the orchestrator's task id is implicit per its
    /// per-initiative session).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,

    /// Role the planner is operating in (lowercase ASCII;
    /// `"executor"`, `"reviewer"`, `"orchestrator"`).
    pub role: String,

    /// Evaluation SHA the executor is required to commit on top of.
    /// Empty for the orchestrator and the early-bootstrapping
    /// reviewer turns (the reviewer sees `evaluation_sha` only after
    /// the executor lands a commit).
    #[serde(default)]
    pub evaluation_sha: String,

    /// Workspace-relative path allowlist. Each entry is a normalised
    /// relative path (no leading `/`, no `..`). The model is
    /// instructed to refuse to edit files outside this list.
    #[serde(default)]
    pub path_allowlist: Vec<String>,

    /// Remaining per-task token budget (LLM tokens). The model is
    /// expected to terminate (via `report_failure`) before running
    /// out.
    #[serde(default)]
    pub token_budget_remaining: u64,

    /// Per-task wall-clock budget remaining, seconds.
    #[serde(default)]
    pub wallclock_budget_remaining_s: u64,

    /// DAG view: rows the reviewer / orchestrator is allowed to see.
    /// Empty for the executor's KSB (the executor sees only its own
    /// task).
    #[serde(default)]
    pub dag_rows: Vec<DagRow>,

    /// Free-form operator-declared task description / acceptance
    /// criteria. Length-capped at 4 KiB by the kernel-side
    /// projection step (`ksb_assembly::TASK_DESCRIPTION_MAX_BYTES`);
    /// the renderer assumes this cap and does NOT re-validate.
    #[serde(default)]
    pub task_description: String,

    /// Initiative target ref the orchestrator's
    /// `IntegrationMerge` will fast-forward (resolved at admission
    /// time per ``). Empty for non-orchestrator
    /// roles.
    #[serde(default)]
    pub target_ref: String,

    /// Initiative-wide base SHA — the 40-char hex SHA the
    /// orchestrator's worktree (and every per-task executor /
    /// reviewer worktree cloned from it) is anchored at. The
    /// orchestrator's `integration_merge { base_sha, head_sha }`
    /// tool call cites this verbatim as `base_sha`; the kernel
    /// admission gate enforces `is_ancestor(base_sha, head_sha)`
    /// against the orchestrator's worktree, which holds because
    /// the executor's commit is parented on this exact SHA.
    ///
    /// Empty when the kernel cannot resolve the anchor (boot
    /// race / corrupted session row); the renderer emits the
    /// literal `<unset>` so the agent fails-loud rather than
    /// guessing.
    #[serde(default)]
    pub base_sha: String,

    /// Reviewer verdicts on prior attempts of this task, oldest
    /// first. Empty if no review has been recorded yet.
    #[serde(default)]
    pub reviewer_verdicts: Vec<ReviewerVerdict>,

    /// Pending escalations attached to this initiative the operator
    /// must resolve before the planner can proceed. Empty in the
    /// happy path.
    #[serde(default)]
    pub pending_escalations: Vec<PendingEscalation>,

    /// Credential-proxy port assignments: which loopback ports map
    /// to which logical upstream services for this task. Empty for
    /// reviewer / orchestrator and for executor tasks without
    /// credential decls.
    #[serde(default)]
    pub credential_ports: Vec<CredentialPort>,

    /// Role-scoped capabilities envelope (slice C —
    /// `INV-KSB-CAPABILITIES-PARITY-01`,
    /// `INV-KSB-CAPABILITIES-ROLE-SCOPED-01`,
    /// `INV-KSB-CAPABILITIES-TURN-COHERENT-01`). Carries the
    /// kernel-side admit-predicate verdicts the LLM needs to
    /// stop blind-asking for inadmissible intents. `None` ⇒ the
    /// kernel did not project a capabilities envelope (legacy
    /// path / boot race / fixture); the renderer omits the
    /// `capabilities=` block and the LLM's NNSP fallback applies.
    /// See [`Capabilities`].
    ///
    /// Non-breaking addition (per the field-shape contract above).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,

    /// iter62 — `INV-RETRY-LAST-CRITIQUE-IN-KSB-01`. The most-
    /// recent reviewer critique attached to this task (mirror of
    /// `tasks.last_critique`), surfaced into the executor / reviewer
    /// KSB on retry rounds (`attempt > 1` OR
    /// `review_reject_count > 0` OR `validation_reject_count > 0`).
    /// Previously the persisted column was correct but never
    /// projected into the KSB, so a retried executor produced the
    /// same flawed diff round after round — the round-N+1 turn
    /// could not reference the round-N reviewer feedback because
    /// it never reached the prompt.
    ///
    /// `None` on the round-1 path (no prior critique to surface)
    /// and on roles for which it has no semantic (orchestrator).
    /// Non-breaking addition (per the field-shape contract above).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_critique: Option<String>,

    /// iter65 — `INV-KSB-GATE-FIXUP-CONTEXT-01`. Populated for
    /// gate-fixup executor tasks only (`tasks.is_gate_fixup = 1`).
    /// Carries the focused repair-context the fixup executor
    /// needs: the gate that failed, the verifier-/operator-supplied
    /// `agent_hint`, the parent task id, the parent's failing
    /// `evaluation_sha`, and the worktree pointer the fixup
    /// inherits from the parent's session. Tasks that are not
    /// gate-fixup MUST leave this field `None` so the KSB shape
    /// for the steady-state executor / reviewer / orchestrator
    /// path is unchanged.
    ///
    /// **Why a focused block instead of dumping the full DAG.**
    /// The fixup executor's job is ONE thing — repair the cited
    /// gate failure. The standard KSB's `dag_rows`, `reviewer_verdicts`,
    /// `pending_escalations` columns dilute the prompt with state
    /// the fixup doesn't act on. The focused block keeps the
    /// signal-to-noise ratio high and pins the role boundary —
    /// a gate-fixup executor that starts reasoning about
    /// initiative-level lifecycle decisions is out of contract.
    ///
    /// Non-breaking addition (per the field-shape contract above).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_fixup: Option<GateFixupContext>,
}

// ---------------------------------------------------------------------------
// GateFixupContext — iter65 fixup-executor KSB block
// ---------------------------------------------------------------------------

/// Per-session view of the gate failure the fixup executor is
/// meant to repair. Populated only when `tasks.is_gate_fixup = 1`.
///
/// Wire shape under JSON:
/// ```json
/// {
///   "gate_type": "NoSecretStrings",
///   "agent_hint": "Remove AWS access key from src/auth.rs:42 and reference env var.",
///   "parent_task_id": "task-7",
///   "parent_evaluation_sha": "abcdef0123...",
///   "parent_worktree_pointer": "/var/lib/raxis/worktrees/init-3/task-7",
///   "attempt_index": 1,
///   "max_attempts": 3
/// }
/// ```
///
/// The kernel-side assembler reads these fields from
/// `tasks.last_gate_type`, `tasks.last_gate_critique`,
/// `tasks.parent_gate_failure_task_id`, plus a join into the
/// parent's `tasks` + `sessions` rows. The renderer is
/// chokepoint-validated against `KSB_DELIMITER_CLOSE` injection
/// the same way every other text field is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateFixupContext {
    /// `GateType` the parent task failed against. Stable
    /// canonical name from `raxis_types::GateType::as_str()`.
    pub gate_type: String,
    /// Resolved repair hint — the verifier-emitted hint, the
    /// operator-default hint, or the defensive gate-name template
    /// per `INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01`. Bounded
    /// by `WITNESS_AGENT_HINT_MAX_BYTES` (8 KiB).
    pub agent_hint: String,
    /// Parent (`is_gate_fixup = 0`) task whose gate failed. The
    /// fixup executor is allowed to read this task's state via
    /// the standard kernel facilities; the agent treats it as
    /// the artifact under repair.
    pub parent_task_id: String,
    /// 40-char hex SHA of the parent's `evaluation_sha` at fixup
    /// spawn time. The fixup commits on top of this SHA so the
    /// parent's range stays intact.
    pub parent_evaluation_sha: String,
    /// Absolute or pointer path the kernel substrate provisions
    /// the fixup's `/workspace` mount against. Same shape carried
    /// in `KernelPush::GateRejected.parent_worktree_pointer`.
    pub parent_worktree_pointer: String,
    /// 1-based fixup attempt index. First fixup has
    /// `attempt_index = 1`; subsequent attempts increment.
    pub attempt_index: u32,
    /// `[gate_fixup].max_attempts` configured at the time. The
    /// fixup executor sees `attempt_index` and `max_attempts`
    /// together so it can budget its repair effort against the
    /// remaining retry quota.
    pub max_attempts: u32,
}

// ---------------------------------------------------------------------------
// Capabilities envelope — slice C role-scoped capability projection
// ---------------------------------------------------------------------------
//
// V2.6 capabilities envelope. Three role-scoped variants enforce the
// `INV-KSB-CAPABILITIES-ROLE-SCOPED-01` contract by construction —
// the type system literally cannot let an Executor's KSB carry the
// orchestrator's per-initiative respawn counter or peer-task review
// trajectory because the variant doesn't have a field for it.
//
// `INV-KSB-CAPABILITIES-PARITY-01`: `retry_admissible` is computed
// kernel-side from the same `admit_retry_subtask_check` pub fn the
// `RetrySubTask` IPC handler calls (see `kernel/src/intent_admit.rs`).
// Both call sites MUST get the same answer for the same `(prior_state,
// crash_retry_count, review_reject_count, max_crash_retries,
// max_review_rejections)` tuple — the parity witness test pins this.
//
// `INV-KSB-CAPABILITIES-TURN-COHERENT-01`: the assembler MUST source
// every capability field from the SAME `&Connection` it uses for the
// rest of the KSB projection — there's no separate `BEGIN`/`COMMIT`
// because SQLite's read consistency model already gives us a stable
// snapshot for the duration of a single connection's read sequence
// (the assembler holds the lock for the whole projection). The
// witness test asserts this by checking that a concurrent writer's
// committed change CANNOT race into a partially-projected snapshot.

/// Role-scoped capabilities envelope. Each variant carries ONLY the
/// fields the role's decision surface needs, enforced by the type
/// system per `INV-KSB-CAPABILITIES-ROLE-SCOPED-01`.
///
/// JSON wire shape uses an internally-tagged representation
/// (`{"role": "orchestrator", "session": …, "initiative": …, "tasks": …}`)
/// so the driver-side deserializer can dispatch on `role` without
/// ambiguity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Capabilities {
    /// Orchestrator's view: per-session + per-initiative budget +
    /// per-task admit-predicate verdicts for every task in the DAG.
    /// The orchestrator is the only role that sees the per-task
    /// retry-admissibility envelope because it is the only role
    /// authorised to issue `RetrySubTask`.
    Orchestrator(OrchestratorCapabilities),

    /// Executor's view: per-session + the SINGLE assigned task. Does
    /// NOT carry orchestrator's respawn counter or peer-task review
    /// trajectories — the executor's decision surface is its own
    /// task; cross-DAG visibility would leak review state across
    /// sibling executors.
    Executor(ExecutorCapabilities),

    /// Reviewer's view: per-session + the artifact under review
    /// (identity only, no counters). The reviewer's verdict MUST be
    /// on the artifact, not on the executor's prior trajectory —
    /// surfacing `crash_retry_count` / `review_reject_count` would
    /// bias the reviewer toward "approve, the executor is already
    /// burning retries" or "reject, the executor has been failing"
    /// reasoning that the contract explicitly forbids.
    Reviewer(ReviewerCapabilities),
}

/// Per-session view fields shared across all three role envelopes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCapabilityView {
    /// Session id this capability projection was built against.
    pub session_id: String,
    /// Role string (`"orchestrator"` / `"executor"` / `"reviewer"`).
    /// Mirrors [`KsbSnapshot::role`].
    pub role: String,

    /// **V2.7 — `INV-KSB-MAX-TURNS-VISIBILITY-01`.** Resolved
    /// per-session planner turn ceiling, populated from the SAME
    /// `crate::session_spawn_orchestrator::resolve_planner_max_turns_for`
    /// call that produces the `RAXIS_PLANNER_MAX_TURNS` env stamp at
    /// session spawn (single source of truth — the env stamp and the
    /// KSB projection are guaranteed bit-equal).
    ///
    /// **Why this is in the KSB, not just the env.** The agent (LLM)
    /// inside the planner VM does not have direct visibility into its
    /// own process env — it only sees the rendered system prompt the
    /// driver assembles via [`assemble_system_prompt`]. Surfacing
    /// `planner_max_turns` in the per-session capabilities lets the
    /// renderer expose the budget verbatim. The agent then
    /// self-tracks its own turn index by counting prior assistant
    /// turns in its conversation transcript and computes
    /// `remaining = planner_max_turns - turn_index`. The role NNSPs
    /// instruct the agent on how to spend the remaining budget
    /// (e.g. the Executor NNSP at >75% spent biases toward
    /// `task_complete` over speculative investigation).
    pub planner_max_turns: u32,
}

/// Orchestrator's per-initiative view. Carries the orchestrator
/// no-progress respawn counter (slice B,
/// `INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`) plus the ceiling /
/// remaining-quota derivation so the LLM can pre-emptively
/// `request_escalation` rather than blind-respawning into the
/// kernel's auto-escalation backstop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitiativeCapabilityView {
    /// Initiative id.
    pub initiative_id: String,
    /// Current value of
    /// `initiatives.orchestrator_no_progress_respawn_count`.
    pub orchestrator_no_progress_respawn_count: u32,
    /// Kernel-side ceiling default
    /// (`MAX_ORCH_NO_PROGRESS_RESPAWNS`).
    pub max_orchestrator_no_progress_respawns: u32,
    /// `max - count` saturated at zero. When `0`, the next
    /// orchestrator post-exit respawn trigger will exceed the
    /// ceiling and auto-escalate.
    pub orchestrator_respawns_remaining: u32,
}

/// Per-task admit-predicate view. The orchestrator carries one row
/// per executor task in the DAG; the executor carries exactly one
/// row (its own task). The `retry_admissible` boolean is computed
/// from the SAME `admit_retry_subtask_check` predicate the
/// `RetrySubTask` IPC handler runs (parity contract).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskCapabilityView {
    /// Task id this view describes.
    pub task_id: String,
    /// Most-recent activation's `crash_retry_count` (the executor's
    /// crash / `ReportFailure` count for THIS task).
    pub crash_retry_count: u32,
    /// Most-recent activation's `review_reject_count` (cross-Reviewer
    /// terminal `AtLeastOneRejected` count for THIS task).
    pub review_reject_count: u32,
    /// Plan-declared crash-retry ceiling (effective: plan override OR
    /// kernel default).
    pub max_crash_retries: u32,
    /// Plan-declared review-rejection ceiling.
    pub max_review_rejections: u32,
    /// `max_crash_retries - crash_retry_count` saturated at zero.
    pub crash_retries_remaining: u32,
    /// `max_review_rejections - review_reject_count` saturated at
    /// zero.
    pub review_retries_remaining: u32,
    /// `true` iff `RetrySubTask` for this task would be ADMITTED by
    /// the kernel RIGHT NOW per `admit_retry_subtask_check`. This
    /// is the load-bearing field for slice C — the orchestrator's
    /// NNSP teaches the LLM to consult this BEFORE issuing a
    /// `retry_subtask` intent so the kernel doesn't have to keep
    /// rejecting blind-asks (which is what the iter44 leading-
    /// indicator metric `IntentAdmitPredicateEvaluatedTotal{
    /// admissible="false"}` was tracking).
    pub retry_admissible: bool,
    /// Human-readable reason when `retry_admissible == false`. Empty
    /// (`None`) when the retry would be admissible. Stable lexemes:
    /// `"prior state {state}; need Failed or Completed-with-rejection"`,
    /// `"crash_retry_count {n} >= max_crash_retries {m}"`,
    /// `"review_reject_count {n} >= max_review_rejections {m}"`,
    /// `"no prior activation"`. The strings are lexeme-stable across
    /// kernel revisions because the planner-core driver is allowed
    /// to substring-match against them in the system prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_inadmissible_reason: Option<String>,
}

/// V3 `INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01` — per-session
/// view of the progressive-scaling resolver's decision. Surfaced on
/// the orchestrator + executor envelopes (so both roles can reason
/// about retry economics) and intentionally absent from the reviewer
/// envelope: the reviewer's verdict MUST be on the artifact, not on
/// the executor's budget pressure (same role-scoping rule as the
/// existing `crash_retry_count` exclusion on `ReviewerCapabilities`).
///
/// Companion to `SessionCapabilityView::planner_max_turns` (which
/// stays the **effective** value for this attempt). The fields here
/// let the agent see *why* the effective value differs from the base
/// — a Round-2 retry surfaces `attempt = 2, base = 30, step = 30,
/// effective = 60, hard_ceiling = 240` so the agent knows the budget
/// is larger because the kernel scaled it up on retry, and can
/// budget its turn-spend accordingly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaxTurnsScalingView {
    /// 1-based attempt index (`subtask_activations.crash_retry_count
    /// + 1`). `1` on first spawn; `>= 2` on every retry.
    pub max_turns_attempt: u32,
    /// Per-task / per-policy / compiled base ceiling
    /// (`INV-PLANNER-MAX-TURNS-PRECEDENCE-01`). Constant across
    /// attempts for the same task.
    pub max_turns_base: u32,
    /// Per-task / per-policy / derived scaling step.
    pub max_turns_step: u32,
    /// Runtime hard ceiling clamp (`240` by default, overridable via
    /// `RAXIS_PLANNER_MAX_TURNS_HARD_CEILING`).
    pub max_turns_hard_ceiling: u32,
}

/// Orchestrator's full envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrchestratorCapabilities {
    pub session: SessionCapabilityView,
    pub initiative: InitiativeCapabilityView,
    /// One row per executor task in the initiative's DAG. Reviewer
    /// rows are intentionally omitted — the orchestrator does not
    /// `retry_subtask` on a reviewer (reviewers are
    /// reactivate-only).
    pub tasks: Vec<TaskCapabilityView>,
    /// V3 iter70+ — kernel-authoritative list of task ids that are
    /// admissible **right now** for `activate_subtask` /
    /// `batch_activate_subtasks`. Computed via the SAME predicate
    /// `handle_activate_sub_task` and `classify_batch_candidates`
    /// use (`tasks.state IN ('Admitted','GatesPending') AND every
    /// `task_dag_edges` predecessor is in `tasks.state =
    /// 'Completed'` AND no live `subtask_activations` row in
    /// `PendingActivation` / `Running`). Sorted
    /// `(admitted_at ASC, task_id ASC)` — exactly the order the
    /// kernel's batch handler applies after candidate
    /// classification. The orchestrator LLM picks dispatch
    /// candidates from this list directly; it does NOT re-derive
    /// admissibility from `preds_ready` / `state` in the rendered
    /// DAG (which it was getting wrong on the iter70 primary
    /// plan, falling into NNSP idle-no-terminal-intent). Empty
    /// vector ⇒ no subtask is dispatchable this turn (consider
    /// `integration_merge` or yield).
    /// `INV-KSB-READY-NOW-MATCHES-KERNEL-ADMISSION-01`.
    #[serde(default)]
    pub ready_now: Vec<String>,
    /// V3 iter70+ — concurrency posture the orchestrator sees on
    /// every turn. Mirrors the kernel's per-initiative concurrency
    /// gate (`[workspace] max_concurrent_admissions` from the
    /// signed plan registry).
    /// `INV-KSB-CONCURRENCY-VIEW-MIRRORS-KERNEL-CAP-01`.
    #[serde(default)]
    pub concurrency: ConcurrencyCapabilityView,
    /// V3 — progressive scaling view (this session's
    /// per-attempt budget breakdown).
    pub max_turns_scaling: MaxTurnsScalingView,
}

/// Per-initiative concurrency posture surfaced to the orchestrator
/// LLM. Stable on the wire — every field is a u32 so `headroom`
/// rendering is allocation-free.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConcurrencyCapabilityView {
    /// `max_concurrent_admissions` from the initiative's plan
    /// registry entry (`[workspace] max_concurrent_admissions`,
    /// default 3).
    pub cap: u32,
    /// Number of currently-non-terminal subtask activations for
    /// the initiative (`subtask_activations.activation_state IN
    /// ('PendingActivation','Running')`). Read at KSB assembly time
    /// from the same connection that builds the rest of the
    /// snapshot, so the view is point-in-time consistent with the
    /// rendered DAG block.
    pub active_count: u32,
    /// `cap - active_count`, saturating-clamped at 0 in case the
    /// kernel admits over-cap during a TOCTOU race (the gate is
    /// best-effort; a per-id `DroppedAtCap` outcome from the
    /// batch handler is the kernel's authoritative answer).
    pub headroom: u32,
}

/// Executor's envelope. Single task — the one this executor session
/// was spawned for. Does NOT carry orchestrator's respawn counter
/// or peer-task views.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutorCapabilities {
    pub session: SessionCapabilityView,
    pub task: TaskCapabilityView,
    /// V3 — progressive scaling view (this session's
    /// per-attempt budget breakdown).
    pub max_turns_scaling: MaxTurnsScalingView,
}

/// Reviewer's envelope. Identity-only artifact view — no counters
/// (the reviewer must verdict on the artifact, not the executor's
/// trajectory). The progressive-scaling view is intentionally absent
/// per the same role-scoping rule that excludes `crash_retry_count` /
/// `review_reject_count` — the reviewer's verdict must be on the
/// artifact, not on the executor's budget pressure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewerCapabilities {
    pub session: SessionCapabilityView,
    /// Task id of the executor artifact under review.
    pub artifact_task_id: String,
}

/// One DAG row visible in the KSB.
///
/// A row's `state` is the lowercased name of the
/// `raxis_types::TaskState` variant (`"pending"`, `"in_progress"`,
/// `"complete"`, `"failed"`, `"in_review"`, …) — pinned by
/// `kernel-mechanics-states.md`. The renderer trusts the caller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DagRow {
    /// Task id of this row.
    pub task_id: String,
    /// Lowercase state name.
    pub state: String,
    /// Optional one-line title. Empty if the operator did not
    /// supply one.
    #[serde(default)]
    pub title: String,
    /// Number of reviewers attached to this task.
    #[serde(default)]
    pub reviewers: u32,
    /// 40-char hex SHA the predecessor (Executor) stamped into
    /// `tasks.evaluation_sha` at `CompleteTask`. Empty until the
    /// task completes; populated for every Executor row in the
    /// initiative DAG so the Orchestrator's `integration_merge`
    /// tool call can cite the right `head_sha`. Reviewer rows
    /// inherit their predecessor's `evaluation_sha` here too —
    /// the kernel does not stamp Reviewer tasks with SHAs (they
    /// are read-only); a Reviewer row whose predecessor
    /// completed shows the same SHA the Executor produced so
    /// downstream agents can correlate the verdict with the
    /// commit being reviewed.
    ///
    /// `serde(default)` for forward/backward wire compat with
    /// any pre-V2.5 dashboard / replay tool that decodes a KSB
    /// snapshot from disk.
    #[serde(default)]
    pub evaluation_sha: String,
    /// Aggregator's terminal cross-Reviewer verdict for this
    /// Executor's reviewer set, per `v2-deep-spec.md §Step 25`.
    /// Wire-stable values (sourced from
    /// `raxis_kernel::initiatives::review_aggregation::
    /// AggregateReviewVerdict::wire_str`):
    ///
    /// * `"Pending"` — at least one sibling Reviewer still owes a
    ///   verdict.
    /// * `"AllPassed"` — every Reviewer Approved.
    /// * `"AtLeastOneRejected"` — every Reviewer voted; at least one
    ///   Rejected (the kernel already bumped
    ///   `subtask_activations.review_reject_count` and a
    ///   `retry_subtask` from this executor's Completed activation is
    ///   now admission-eligible).
    /// * `"NoSuccessors"` — plan declares zero Reviewers for this
    ///   Executor (malformed in V2; surface so the operator sees the
    ///   misconfiguration).
    /// * `""` — non-Executor row (Reviewer / Orchestrator) OR an
    ///   Executor row whose aggregate is not yet relevant (kept empty
    ///   to keep the wire compact).
    ///
    /// Orchestrator NNSP rule 3a (see
    /// `crates/planner-core/src/driver.rs::render_system_prompt_for_role`)
    /// pivots on this field — NOT on the per-Reviewer
    /// `reviewer_verdicts=` block — to decide
    /// `retry_subtask` vs `activate_subtask` vs
    /// `integration_merge`. The per-Reviewer block fires
    /// `approved=false` as soon as the FIRST sibling Reviewer
    /// votes Reject, but the kernel's cross-Reviewer aggregator
    /// only emits
    /// `ReviewAggregationCompleted{verdict=AtLeastOneRejected}`
    /// AND bumps `review_reject_count` when the LAST sibling has
    /// voted. Reading the per-Reviewer block to drive
    /// `retry_subtask` therefore races the aggregator and
    /// produces a respawn loop where the kernel rejects every
    /// retry with `FAIL_INVALID_REQUEST` per
    /// `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01` (see
    /// `iter42` regression). Closes
    /// `INV-KSB-AGGREGATE-VERDICT-PROJECTION-01`.
    #[serde(default)]
    pub aggregate_verdict: String,

    /// Wire-stable boolean: `true` iff every plan-declared
    /// predecessor of this task in `task_dag_edges` is in the
    /// `tasks.state = 'Completed'` terminal state. Tasks with no
    /// declared predecessors are vacuously `preds_ready=true`.
    ///
    /// This field is the **only** signal the Orchestrator LLM is
    /// permitted to use to decide whether `activate_subtask` is
    /// admission-eligible for a row whose `state=pending`. Without
    /// it the LLM has to reconstruct predecessor satisfaction from
    /// the plan TOML it was never handed (it sees only the
    /// per-task description blob), and the iter49 reproduction on
    /// the realistic plan showed this is exactly the
    /// blind-asking pattern that gets rejected by the kernel
    /// (`ActivateSubTaskReviewerNoEvalSha` in the lint-defect →
    /// lint-runner → review-lint-defect-A chain — the LLM
    /// activated the reviewer expecting `lint-defect`'s SHA to
    /// satisfy it, but the reviewer's IMMEDIATE plan-declared
    /// predecessor was the in-image lint-runner Executor whose
    /// activation had not even started). The kernel-side gate
    /// (`kernel/src/handlers/intent.rs::handle_activate_sub_task`
    /// reviewer branch — `ActivateSubTaskReviewerNoEvalSha`)
    /// remains the authoritative invariant; this field merely
    /// projects the same predecessor-satisfaction predicate
    /// directly into the LLM-visible KSB so the rejection class
    /// becomes self-preventing rather than respawn-loop-discoverable.
    ///
    /// `serde(default)` for forward / backward wire compat with
    /// any earlier dashboard / replay tool that decodes a KSB
    /// snapshot from disk: the renderer always emits the field on
    /// the wire so a fresh KSB carries it, but a stale
    /// JSON-decoded snapshot without the field defaults to
    /// `false`, which is the safe (over-blocking) behaviour for
    /// any retroactive consumer.
    #[serde(default)]
    pub preds_ready: bool,
}

/// One reviewer verdict against a prior executor attempt.
///
/// `approved = true` ⇒ the reviewer accepted the commit; the
/// optional `critique` carries supplementary notes the executor
/// MAY consider on a follow-up attempt. `approved = false` ⇒ the
/// reviewer rejected; `critique` carries the rejection rationale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewerVerdict {
    /// Reviewer task id that submitted the verdict.
    pub reviewer_task_id: String,
    /// Evaluation SHA the verdict was rendered against.
    pub evaluation_sha: String,
    /// Whether the reviewer approved the executor's commit.
    pub approved: bool,
    /// Operator-readable critique. Empty if the reviewer did not
    /// supply one.
    #[serde(default)]
    pub critique: String,
}

/// One pending escalation row visible in the KSB.
///
/// Rendered so the planner can self-park rather than re-attempt the
/// step that triggered the escalation; the operator resolves the
/// escalation out-of-band, the resolution lands as an audit event,
/// and the next KSB projection drops the row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEscalation {
    /// Escalation row id.
    pub escalation_id: String,
    /// Escalation class (`"MergeConflict"`, `"PolicyOverride"`, …).
    pub class: String,
    /// One-line operator-readable summary. Empty if not supplied.
    #[serde(default)]
    pub summary: String,
}

/// One credential-proxy port assignment visible in the KSB.
///
/// Carries the logical upstream id (matches `[[tasks.credentials]]`
/// `id`) and the loopback port the in-VM tproxy redirects to. The
/// model uses the port to construct the connection URL; it never
/// sees the credential bytes (those flow through the host-side
/// proxy at the redirected port).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialPort {
    /// Logical upstream id (`"primary_pg"`, `"redis_cache"`, …).
    pub upstream_id: String,
    /// Proxy kind (`"postgres"`, `"redis"`, `"http"`, …).
    pub kind: String,
    /// Loopback port the in-VM tproxy listens on.
    pub port: u16,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Renderer-side error. Both variants surface a planner-harness bug
/// (the kernel-side projection let through an invalid value) and
/// fail the dispatch loop closed.
#[derive(Debug, Error)]
pub enum KsbError {
    /// One of the snapshot's text fields contains the literal
    /// `KSB_DELIMITER_CLOSE` byte sequence. INV-KSB-01: refusing to
    /// render is the planner-side defence-in-depth backstop against
    /// a kernel-projection bug that lets a model-supplied string
    /// through into a kernel-stamped field.
    #[error("ksb field {field} contains the close delimiter sequence (INV-KSB-01 violation)")]
    DelimiterInjection {
        /// Name of the offending field (one of `initiative_id`,
        /// `task_id`, `role`, `evaluation_sha`, `task_description`,
        /// `target_ref`, `path_allowlist`, `dag_rows`,
        /// `reviewer_verdicts`, `pending_escalations`,
        /// `credential_ports`).
        field: &'static str,
    },

    /// A required text field was empty. Most fields are allowed to
    /// be empty (e.g. `evaluation_sha` for the orchestrator), but a
    /// few — `initiative_id`, `role` — are not.
    #[error("ksb required field {field} is empty")]
    EmptyRequired {
        /// Name of the empty required field.
        field: &'static str,
    },
}

// ---------------------------------------------------------------------------
// render_ksb — the load-bearing rendering function
// ---------------------------------------------------------------------------

/// Render `snapshot` into a UTF-8 string ready for embedding into a
/// system prompt. The rendered block has the shape:
///
/// ```text
///   [RAXIS:KERNEL_STATE version=1
///   initiative_id=init-7
///   task_id=task-42
///   role=executor
///   evaluation_sha=abcdef0123456789...
///   target_ref=refs/heads/main
///   path_allowlist=
///     - src/lib.rs
///     - src/tools.rs
///   token_budget_remaining=12345
///   wallclock_budget_remaining_s=600
///   credential_ports=
///     - primary_pg postgres :5432
///   reviewer_verdicts=
///     - reviewer=task-99 sha=abc12 approved=false "needs typed enum"
///   pending_escalations=
///     - esc-7 MergeConflict "operator must rebase main"
///   task_description=
///     <free-form text>
///   dag=
///     - task-42 in_progress reviewers=2 aggregate=AtLeastOneRejected sha=abc12 "First sub-task"
///     - task-43 pending     reviewers=1 sha=<none> ""
///   :KERNEL_STATE_END]
/// ```
///
/// The output is line-oriented + indentation-fixed so the LLM can
/// learn to parse it positionally even if a future iteration adds
/// new fields. Field order is **stable** — adding new fields APPENDS
/// to the end so the prefix remains byte-stable.
pub fn render_ksb(snapshot: &KsbSnapshot) -> Result<String, KsbError> {
    if snapshot.initiative_id.is_empty() {
        return Err(KsbError::EmptyRequired {
            field: "initiative_id",
        });
    }
    if snapshot.role.is_empty() {
        return Err(KsbError::EmptyRequired { field: "role" });
    }
    for (field_name, value) in [
        ("initiative_id", snapshot.initiative_id.as_str()),
        ("task_id", snapshot.task_id.as_deref().unwrap_or("")),
        ("role", snapshot.role.as_str()),
        ("evaluation_sha", snapshot.evaluation_sha.as_str()),
        ("task_description", snapshot.task_description.as_str()),
        ("target_ref", snapshot.target_ref.as_str()),
        ("base_sha", snapshot.base_sha.as_str()),
    ] {
        if value.contains(KSB_DELIMITER_CLOSE) {
            return Err(KsbError::DelimiterInjection { field: field_name });
        }
    }
    for p in &snapshot.path_allowlist {
        if p.contains(KSB_DELIMITER_CLOSE) {
            return Err(KsbError::DelimiterInjection {
                field: "path_allowlist",
            });
        }
    }
    for row in &snapshot.dag_rows {
        for s in [&row.task_id, &row.state, &row.title, &row.aggregate_verdict] {
            if s.contains(KSB_DELIMITER_CLOSE) {
                return Err(KsbError::DelimiterInjection { field: "dag_rows" });
            }
        }
    }
    for v in &snapshot.reviewer_verdicts {
        for s in [&v.reviewer_task_id, &v.evaluation_sha, &v.critique] {
            if s.contains(KSB_DELIMITER_CLOSE) {
                return Err(KsbError::DelimiterInjection {
                    field: "reviewer_verdicts",
                });
            }
        }
    }
    for e in &snapshot.pending_escalations {
        for s in [&e.escalation_id, &e.class, &e.summary] {
            if s.contains(KSB_DELIMITER_CLOSE) {
                return Err(KsbError::DelimiterInjection {
                    field: "pending_escalations",
                });
            }
        }
    }
    for c in &snapshot.credential_ports {
        for s in [&c.upstream_id, &c.kind] {
            if s.contains(KSB_DELIMITER_CLOSE) {
                return Err(KsbError::DelimiterInjection {
                    field: "credential_ports",
                });
            }
        }
    }
    if let Some(caps) = &snapshot.capabilities {
        check_capabilities_delimiter(caps)?;
    }
    // iter62 — defend the `last_critique` block against
    // delimiter injection (the critique is operator/LLM-supplied
    // text and could embed `]] ksb` literally).
    if let Some(critique) = &snapshot.last_critique {
        if critique.contains(KSB_DELIMITER_CLOSE) {
            return Err(KsbError::DelimiterInjection {
                field: "last_critique",
            });
        }
    }
    // iter65 — defend the `gate_fixup` block. Every text field
    // (notably `agent_hint`, which is verifier-script-authored)
    // is scanned for the close delimiter the same way every
    // other text field in this projection is.
    if let Some(gf) = &snapshot.gate_fixup {
        for s in [
            &gf.gate_type,
            &gf.agent_hint,
            &gf.parent_task_id,
            &gf.parent_evaluation_sha,
            &gf.parent_worktree_pointer,
        ] {
            if s.contains(KSB_DELIMITER_CLOSE) {
                return Err(KsbError::DelimiterInjection {
                    field: "gate_fixup",
                });
            }
        }
    }

    let mut buf = String::with_capacity(512 + snapshot.task_description.len());
    buf.push_str(KSB_DELIMITER_OPEN);
    buf.push_str(" version=");
    buf.push_str(&snapshot.version.to_string());
    buf.push('\n');

    push_kv(&mut buf, "initiative_id", &snapshot.initiative_id);
    push_kv(
        &mut buf,
        "task_id",
        snapshot.task_id.as_deref().unwrap_or(""),
    );
    push_kv(&mut buf, "role", &snapshot.role);
    push_kv(&mut buf, "evaluation_sha", &snapshot.evaluation_sha);
    push_kv(&mut buf, "target_ref", &snapshot.target_ref);
    // V2.5 — `base_sha` is the orchestrator's
    // `integration_merge { base_sha, head_sha }` source. We emit
    // the literal `<unset>` (rather than an empty value) when
    // the anchor is missing so the agent does not silently
    // submit an empty-string SHA and round-trip it as
    // `INVALID_REQUEST` from the kernel.
    push_kv(
        &mut buf,
        "base_sha",
        if snapshot.base_sha.is_empty() {
            "<unset>"
        } else {
            snapshot.base_sha.as_str()
        },
    );

    buf.push_str("path_allowlist=\n");
    if snapshot.path_allowlist.is_empty() {
        buf.push_str("  <empty>\n");
    } else {
        for p in &snapshot.path_allowlist {
            buf.push_str("  - ");
            buf.push_str(p);
            buf.push('\n');
        }
    }

    push_kv(
        &mut buf,
        "token_budget_remaining",
        &snapshot.token_budget_remaining.to_string(),
    );
    push_kv(
        &mut buf,
        "wallclock_budget_remaining_s",
        &snapshot.wallclock_budget_remaining_s.to_string(),
    );

    buf.push_str("credential_ports=\n");
    if snapshot.credential_ports.is_empty() {
        buf.push_str("  <empty>\n");
    } else {
        for c in &snapshot.credential_ports {
            buf.push_str("  - ");
            buf.push_str(&c.upstream_id);
            buf.push(' ');
            buf.push_str(&c.kind);
            buf.push_str(" :");
            buf.push_str(&c.port.to_string());
            buf.push('\n');
        }
    }

    buf.push_str("reviewer_verdicts=\n");
    if snapshot.reviewer_verdicts.is_empty() {
        buf.push_str("  <empty>\n");
    } else {
        for v in &snapshot.reviewer_verdicts {
            buf.push_str("  - reviewer=");
            buf.push_str(&v.reviewer_task_id);
            buf.push_str(" sha=");
            buf.push_str(&v.evaluation_sha);
            buf.push_str(" approved=");
            buf.push_str(if v.approved { "true" } else { "false" });
            buf.push_str(" \"");
            buf.push_str(&v.critique);
            buf.push_str("\"\n");
        }
    }

    buf.push_str("pending_escalations=\n");
    if snapshot.pending_escalations.is_empty() {
        buf.push_str("  <empty>\n");
    } else {
        for e in &snapshot.pending_escalations {
            buf.push_str("  - ");
            buf.push_str(&e.escalation_id);
            buf.push(' ');
            buf.push_str(&e.class);
            buf.push_str(" \"");
            buf.push_str(&e.summary);
            buf.push_str("\"\n");
        }
    }

    buf.push_str("task_description=\n");
    if snapshot.task_description.is_empty() {
        buf.push_str("  <empty>\n");
    } else {
        for line in snapshot.task_description.lines() {
            buf.push_str("  ");
            buf.push_str(line);
            buf.push('\n');
        }
    }

    buf.push_str("dag=\n");
    if snapshot.dag_rows.is_empty() {
        buf.push_str("  <empty>\n");
    } else {
        for row in &snapshot.dag_rows {
            buf.push_str("  - ");
            buf.push_str(&row.task_id);
            buf.push(' ');
            buf.push_str(&row.state);
            buf.push_str(" reviewers=");
            buf.push_str(&row.reviewers.to_string());
            // iter50 — `preds_ready=<true|false>` is the
            // wire-stable projection of "every plan-declared
            // predecessor of this task is in `tasks.state =
            // 'Completed'`". The Orchestrator NNSP rule 2 gates
            // `activate_subtask` on this boolean: the LLM is
            // forbidden from activating a row whose
            // `preds_ready=false`. Always emitted (no compactness
            // optimisation): the LLM relies on the field's
            // presence to tell apart "predecessors actually all
            // complete" from "row is from an older renderer that
            // never emitted the field". Closes
            // `INV-KSB-PREDS-READY-PROJECTION-01` (added
            // alongside the iter50 fix).
            buf.push_str(" preds_ready=");
            buf.push_str(if row.preds_ready { "true" } else { "false" });
            // V2.5 — `aggregate=` carries the cross-Reviewer
            // aggregator's terminal verdict for this Executor row
            // when the kernel has projected one. Omitted for
            // Reviewer / Orchestrator rows and for Executor rows
            // with no projected verdict (the projection leaves
            // `aggregate_verdict` empty in both cases) so the
            // wire stays compact and the LLM only sees the field
            // where it carries signal. Closes
            // `INV-KSB-AGGREGATE-VERDICT-PROJECTION-01`.
            if !row.aggregate_verdict.is_empty() {
                buf.push_str(" aggregate=");
                buf.push_str(&row.aggregate_verdict);
            }
            buf.push_str(" sha=");
            // Empty string when the task has not yet stamped an
            // evaluation_sha — the orchestrator's prompt teaches
            // it that an empty `sha=` field means the task has
            // not produced a commit (still pending / in-progress
            // / failed-before-commit).
            buf.push_str(if row.evaluation_sha.is_empty() {
                "<none>"
            } else {
                row.evaluation_sha.as_str()
            });
            buf.push_str(" \"");
            buf.push_str(&row.title);
            buf.push_str("\"\n");
        }
    }

    if let Some(caps) = &snapshot.capabilities {
        push_capabilities(&mut buf, caps);
    }

    // iter62 — `INV-RETRY-LAST-CRITIQUE-IN-KSB-01`. The most-
    // recent reviewer critique attached to this task is rendered
    // as a multi-line block keyed `last_critique=` so the LLM
    // can reliably re-orient on retry rounds. Omitted on the
    // round-1 path so the byte prefix stays stable for tasks
    // that have not yet been reviewed.
    if let Some(critique) = &snapshot.last_critique {
        buf.push_str("last_critique=\n");
        if critique.is_empty() {
            buf.push_str("  <empty>\n");
        } else {
            for line in critique.lines() {
                buf.push_str("  ");
                buf.push_str(line);
                buf.push('\n');
            }
        }
    }

    // iter65 — `INV-KSB-GATE-FIXUP-CONTEXT-01`. The focused
    // gate-fixup block. Only rendered for the gate-fixup
    // executor's KSB; non-fixup tasks leave the field `None`
    // so the wire stays compact for the steady-state path. The
    // `agent_hint` is rendered as a multi-line indented block
    // (matching `task_description=` / `last_critique=`) because
    // the hint is operator-readable text that may exceed one
    // line; every other field is a single-line key=value
    // primitive.
    if let Some(gf) = &snapshot.gate_fixup {
        buf.push_str("gate_fixup=\n");
        buf.push_str("  gate_type=");
        buf.push_str(&gf.gate_type);
        buf.push('\n');
        buf.push_str("  parent_task_id=");
        buf.push_str(&gf.parent_task_id);
        buf.push('\n');
        buf.push_str("  parent_evaluation_sha=");
        buf.push_str(&gf.parent_evaluation_sha);
        buf.push('\n');
        buf.push_str("  parent_worktree_pointer=");
        buf.push_str(&gf.parent_worktree_pointer);
        buf.push('\n');
        buf.push_str("  attempt=");
        buf.push_str(&gf.attempt_index.to_string());
        buf.push('/');
        buf.push_str(&gf.max_attempts.to_string());
        buf.push('\n');
        buf.push_str("  agent_hint=\n");
        if gf.agent_hint.is_empty() {
            buf.push_str("    <empty>\n");
        } else {
            for line in gf.agent_hint.lines() {
                buf.push_str("    ");
                buf.push_str(line);
                buf.push('\n');
            }
        }
    }

    buf.push_str(KSB_DELIMITER_CLOSE);
    buf.push('\n');
    Ok(buf)
}

/// Validate every text field of a [`Capabilities`] envelope against
/// the `KSB_DELIMITER_CLOSE` injection guard. Centralised here so
/// the `render_ksb` chokepoint inherits the same defence-in-depth
/// the existing field-by-field scan applies to the rest of the
/// snapshot (INV-KSB-01).
fn check_capabilities_delimiter(caps: &Capabilities) -> Result<(), KsbError> {
    let session = match caps {
        Capabilities::Orchestrator(o) => &o.session,
        Capabilities::Executor(e) => &e.session,
        Capabilities::Reviewer(r) => &r.session,
    };
    for s in [&session.session_id, &session.role] {
        if s.contains(KSB_DELIMITER_CLOSE) {
            return Err(KsbError::DelimiterInjection {
                field: "capabilities",
            });
        }
    }
    let task_iter: Box<dyn Iterator<Item = &TaskCapabilityView>> = match caps {
        Capabilities::Orchestrator(o) => Box::new(o.tasks.iter()),
        Capabilities::Executor(e) => Box::new(std::iter::once(&e.task)),
        Capabilities::Reviewer(_) => Box::new(std::iter::empty()),
    };
    for t in task_iter {
        if t.task_id.contains(KSB_DELIMITER_CLOSE) {
            return Err(KsbError::DelimiterInjection {
                field: "capabilities",
            });
        }
        if let Some(reason) = &t.retry_inadmissible_reason {
            if reason.contains(KSB_DELIMITER_CLOSE) {
                return Err(KsbError::DelimiterInjection {
                    field: "capabilities",
                });
            }
        }
    }
    if let Capabilities::Orchestrator(o) = caps {
        if o.initiative.initiative_id.contains(KSB_DELIMITER_CLOSE) {
            return Err(KsbError::DelimiterInjection {
                field: "capabilities",
            });
        }
        // V3 iter70+ — defence-in-depth on `ready_now`. The task
        // ids come from the kernel's own `tasks` table so the
        // injection surface is structurally absent (admission-side
        // INSERT validates the id), but the chokepoint scan stays
        // honest so a future schema laxity surfaces here rather
        // than as a prompt-injection escape.
        for tid in &o.ready_now {
            if tid.contains(KSB_DELIMITER_CLOSE) {
                return Err(KsbError::DelimiterInjection {
                    field: "capabilities",
                });
            }
        }
    }
    if let Capabilities::Reviewer(r) = caps {
        if r.artifact_task_id.contains(KSB_DELIMITER_CLOSE) {
            return Err(KsbError::DelimiterInjection {
                field: "capabilities",
            });
        }
    }
    Ok(())
}

/// Append the `capabilities=` block to the rendered KSB. The block
/// is role-keyed so the LLM's NNSP can dispatch on the visible
/// `role=` field above. Layout is line-oriented + indentation-fixed
/// per the rest of the renderer.
///
/// Wire shape (orchestrator example):
///
/// ```text
/// capabilities=
///   role=orchestrator session=ses-7
///   initiative=init-3 orch_no_progress_respawns=1/3 remaining=2
///   tasks=
///     - task=task-a crash=0/3 review=1/2 retry_admissible=true
///     - task=task-b crash=2/3 review=0/2 retry_admissible=false reason="crash_retry_count 2 >= max_crash_retries 3"
/// ```
fn push_capabilities(buf: &mut String, caps: &Capabilities) {
    buf.push_str("capabilities=\n");
    match caps {
        Capabilities::Orchestrator(o) => {
            push_session_capability_line(buf, "orchestrator", &o.session);
            push_max_turns_scaling_line(buf, &o.max_turns_scaling);
            buf.push_str("  initiative=");
            buf.push_str(&o.initiative.initiative_id);
            buf.push_str(" orch_no_progress_respawns=");
            buf.push_str(
                &o.initiative
                    .orchestrator_no_progress_respawn_count
                    .to_string(),
            );
            buf.push('/');
            buf.push_str(
                &o.initiative
                    .max_orchestrator_no_progress_respawns
                    .to_string(),
            );
            buf.push_str(" remaining=");
            buf.push_str(&o.initiative.orchestrator_respawns_remaining.to_string());
            buf.push('\n');
            // V3 iter70+ — emit the kernel-authoritative dispatch
            // hint lines BEFORE the `tasks=` block so the LLM reads
            // its admission menu first. The orchestrator system
            // prompt instructs the model to pick exclusively from
            // `ready_now=[…]` for `activate_subtask` /
            // `batch_activate_subtasks` and to consult `concurrency=
            // cap=N active=M headroom=K` to decide singular vs
            // batch. The model is forbidden from re-deriving
            // admissibility from the `dag=` block's per-row
            // `preds_ready` field.
            // `INV-KSB-READY-NOW-MATCHES-KERNEL-ADMISSION-01`
            // `INV-KSB-CONCURRENCY-VIEW-MIRRORS-KERNEL-CAP-01`.
            buf.push_str("  ready_now=[");
            for (idx, tid) in o.ready_now.iter().enumerate() {
                if idx > 0 {
                    buf.push_str(", ");
                }
                buf.push_str(tid);
            }
            buf.push_str("]\n");
            buf.push_str("  concurrency: cap=");
            buf.push_str(&o.concurrency.cap.to_string());
            buf.push_str(" active=");
            buf.push_str(&o.concurrency.active_count.to_string());
            buf.push_str(" headroom=");
            buf.push_str(&o.concurrency.headroom.to_string());
            buf.push('\n');
            buf.push_str("  tasks=\n");
            if o.tasks.is_empty() {
                buf.push_str("    <empty>\n");
            } else {
                for t in &o.tasks {
                    push_task_capability_row(buf, t);
                }
            }
        }
        Capabilities::Executor(e) => {
            push_session_capability_line(buf, "executor", &e.session);
            push_max_turns_scaling_line(buf, &e.max_turns_scaling);
            buf.push_str("  task=\n");
            push_task_capability_row(buf, &e.task);
        }
        Capabilities::Reviewer(r) => {
            push_session_capability_line(buf, "reviewer", &r.session);
            // V3 — reviewer is intentionally NOT given the scaling
            // view (role-scoping rule per
            // `INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01`).
            buf.push_str("  artifact_task_id=");
            buf.push_str(&r.artifact_task_id);
            buf.push('\n');
        }
    }
}

/// V3 `INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01` — render the
/// per-session progressive-scaling line:
///
/// ```text
///   max_turns_attempt=N base=B step=S hard_ceiling=H
/// ```
///
/// Emitted only on orchestrator + executor envelopes (the reviewer
/// envelope omits this line by contract). The agent uses these fields
/// to reason about retry economics — a Round-2 executor sees
/// `max_turns_attempt=2`, knows the budget rose `base + step` since
/// last attempt, and can budget its turns accordingly.
fn push_max_turns_scaling_line(buf: &mut String, v: &MaxTurnsScalingView) {
    buf.push_str("  max_turns_attempt=");
    buf.push_str(&v.max_turns_attempt.to_string());
    buf.push_str(" base=");
    buf.push_str(&v.max_turns_base.to_string());
    buf.push_str(" step=");
    buf.push_str(&v.max_turns_step.to_string());
    buf.push_str(" hard_ceiling=");
    buf.push_str(&v.max_turns_hard_ceiling.to_string());
    buf.push('\n');
}

/// V2.7 `INV-KSB-MAX-TURNS-VISIBILITY-01` — render the per-session
/// capability line uniformly across all three role envelopes:
///
/// ```text
///   role={orchestrator|executor|reviewer} session={id} planner_max_turns={N}
/// ```
///
/// `planner_max_turns` is the resolved per-session hard turn ceiling
/// (`crate::session_spawn_orchestrator::resolve_planner_max_turns_for`).
/// The agent self-tracks its turn index inside the dispatch loop and
/// computes `remaining = planner_max_turns - turn_index`; the
/// dispatch loop's per-turn `[KERNEL: TURN BUDGET turn=K of N,
/// remaining=M]` preamble (see
/// `crates/planner-core/src/dispatch.rs::Dispatcher::run`) renders
/// the live count every turn.
fn push_session_capability_line(buf: &mut String, role: &str, sess: &SessionCapabilityView) {
    buf.push_str("  role=");
    buf.push_str(role);
    buf.push_str(" session=");
    buf.push_str(&sess.session_id);
    buf.push_str(" planner_max_turns=");
    buf.push_str(&sess.planner_max_turns.to_string());
    buf.push('\n');
}

fn push_task_capability_row(buf: &mut String, t: &TaskCapabilityView) {
    buf.push_str("    - task=");
    buf.push_str(&t.task_id);
    buf.push_str(" crash=");
    buf.push_str(&t.crash_retry_count.to_string());
    buf.push('/');
    buf.push_str(&t.max_crash_retries.to_string());
    buf.push_str(" review=");
    buf.push_str(&t.review_reject_count.to_string());
    buf.push('/');
    buf.push_str(&t.max_review_rejections.to_string());
    buf.push_str(" retry_admissible=");
    buf.push_str(if t.retry_admissible { "true" } else { "false" });
    if let Some(reason) = &t.retry_inadmissible_reason {
        buf.push_str(" reason=\"");
        buf.push_str(reason);
        buf.push('"');
    }
    buf.push('\n');
}

fn push_kv(buf: &mut String, key: &str, value: &str) {
    buf.push_str(key);
    buf.push('=');
    buf.push_str(value);
    buf.push('\n');
}

// ---------------------------------------------------------------------------
// assemble_system_prompt — the role NNSP + KSB join
// ---------------------------------------------------------------------------

/// Join the role-specific Non-Negotiable System Prompt (NNSP) with
/// the rendered KSB into the final `system` field of a planner
/// `MessageRequest`.
///
/// The NNSP is the **operator-supplied** prompt shipped with the
/// kernel binary (per role); the KSB is the **kernel-projected**
/// per-turn state block. The two are joined with a blank line in
/// between so a future debugger can split them cleanly.
///
/// Returns an error if `nnsp` is empty (a role binary that boots
/// without an NNSP is a build bug — fail-closed).
pub fn assemble_system_prompt(nnsp: &str, snapshot: &KsbSnapshot) -> Result<String, KsbError> {
    if nnsp.is_empty() {
        return Err(KsbError::EmptyRequired { field: "nnsp" });
    }
    let ksb = render_ksb(snapshot)?;
    let mut out = String::with_capacity(nnsp.len() + ksb.len() + 2);
    out.push_str(nnsp);
    if !nnsp.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&ksb);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests — moved verbatim from the legacy `planner-core::ksb` module
// + extended with the new fields.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_snapshot() -> KsbSnapshot {
        KsbSnapshot {
            version: 1,
            initiative_id: "init-7".to_owned(),
            task_id: Some("task-42".to_owned()),
            role: "executor".to_owned(),
            evaluation_sha: "abcdef0123456789abcdef0123456789abcdef01".to_owned(),
            path_allowlist: vec!["src/lib.rs".to_owned(), "src/tools.rs".to_owned()],
            token_budget_remaining: 12345,
            wallclock_budget_remaining_s: 600,
            dag_rows: vec![
                DagRow {
                    task_id: "task-42".to_owned(),
                    state: "in_progress".to_owned(),
                    title: "First sub-task".to_owned(),
                    reviewers: 2,
                    evaluation_sha: String::new(),
                    aggregate_verdict: String::new(),
                    preds_ready: true,
                },
                DagRow {
                    task_id: "task-43".to_owned(),
                    state: "pending".to_owned(),
                    title: String::new(),
                    reviewers: 1,
                    evaluation_sha: String::new(),
                    aggregate_verdict: String::new(),
                    preds_ready: false,
                },
            ],
            task_description: "Make the executor land a commit.".to_owned(),
            target_ref: "refs/heads/main".to_owned(),
            base_sha: "f3d21a09f3d21a09f3d21a09f3d21a09f3d21a09".to_owned(),
            reviewer_verdicts: vec![],
            pending_escalations: vec![],
            credential_ports: vec![],
            capabilities: None,
            last_critique: None,
            gate_fixup: None,
        }
    }

    fn gate_fixup_fixture() -> GateFixupContext {
        GateFixupContext {
            gate_type: "NoSecretStrings".to_owned(),
            agent_hint: "Remove the AWS access key shape from src/auth.rs:42 \
                         and reference an env var instead."
                .to_owned(),
            parent_task_id: "task-7".to_owned(),
            parent_evaluation_sha: "deadbeefcafebabedeadbeefcafebabedeadbeef".to_owned(),
            parent_worktree_pointer: "/var/lib/raxis/worktrees/init-3/task-7".to_owned(),
            attempt_index: 1,
            max_attempts: 3,
        }
    }

    #[test]
    fn render_emits_open_and_close_delimiters() {
        let s = render_ksb(&fixture_snapshot()).unwrap();
        assert!(
            s.starts_with(KSB_DELIMITER_OPEN),
            "rendered block must start with the open delimiter, got: {s}"
        );
        assert!(
            s.contains(KSB_DELIMITER_CLOSE),
            "rendered block must end with the close delimiter, got: {s}"
        );
    }

    #[test]
    fn render_is_deterministic_for_identical_inputs() {
        let a = render_ksb(&fixture_snapshot()).unwrap();
        let b = render_ksb(&fixture_snapshot()).unwrap();
        assert_eq!(
            a, b,
            "two renders of the same snapshot MUST be byte-identical \
             (the audit chain hashes the rendered KSB)"
        );
    }

    #[test]
    fn render_includes_required_fields() {
        let s = render_ksb(&fixture_snapshot()).unwrap();
        assert!(s.contains("version=1"));
        assert!(s.contains("initiative_id=init-7"));
        assert!(s.contains("task_id=task-42"));
        assert!(s.contains("role=executor"));
        assert!(s.contains("evaluation_sha=abcdef0123456789abcdef0123456789abcdef01"));
        assert!(s.contains("target_ref=refs/heads/main"));
        assert!(s.contains("- src/lib.rs"));
        assert!(s.contains("- src/tools.rs"));
        assert!(s.contains("token_budget_remaining=12345"));
        assert!(s.contains("wallclock_budget_remaining_s=600"));
        assert!(s.contains("Make the executor land a commit."));
        assert!(s.contains(
            "- task-42 in_progress reviewers=2 preds_ready=true sha=<none> \"First sub-task\""
        ));
        assert!(s.contains("- task-43 pending reviewers=1 preds_ready=false sha=<none> \"\""));
    }

    #[test]
    fn render_with_empty_path_allowlist_emits_placeholder() {
        let mut snap = fixture_snapshot();
        snap.path_allowlist.clear();
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains("path_allowlist=\n  <empty>"),
            "empty path_allowlist must render as <empty> placeholder, got: {s}"
        );
    }

    #[test]
    fn render_with_empty_dag_emits_placeholder() {
        let mut snap = fixture_snapshot();
        snap.dag_rows.clear();
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains("dag=\n  <empty>"),
            "empty dag must render as <empty> placeholder, got: {s}"
        );
    }

    #[test]
    fn render_with_orchestrator_task_id_none() {
        let mut snap = fixture_snapshot();
        snap.task_id = None;
        snap.role = "orchestrator".to_owned();
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains("task_id=\n"),
            "orchestrator's KSB must render task_id with empty value, got: {s}"
        );
    }

    #[test]
    fn render_includes_credential_ports_block() {
        let mut snap = fixture_snapshot();
        snap.credential_ports.push(CredentialPort {
            upstream_id: "primary_pg".to_owned(),
            kind: "postgres".to_owned(),
            port: 5432,
        });
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains("credential_ports=\n  - primary_pg postgres :5432"),
            "credential port row missing or malformed: {s}"
        );
    }

    #[test]
    fn render_includes_reviewer_verdict_block() {
        let mut snap = fixture_snapshot();
        snap.reviewer_verdicts.push(ReviewerVerdict {
            reviewer_task_id: "task-99".to_owned(),
            evaluation_sha: "abc12".to_owned(),
            approved: false,
            critique: "needs typed enum".to_owned(),
        });
        let s = render_ksb(&snap).unwrap();
        assert!(s.contains("reviewer_verdicts=\n  - reviewer=task-99 sha=abc12 approved=false \"needs typed enum\""),
            "reviewer verdict row missing or malformed: {s}");
    }

    /// The renderer MUST omit the `aggregate=` field when
    /// `DagRow::aggregate_verdict` is the empty string. Reviewer /
    /// Orchestrator rows (and Executor rows the projection has not
    /// stamped a verdict on yet) leave the field empty, and the
    /// wire stays compact. Pins
    /// `INV-KSB-AGGREGATE-VERDICT-PROJECTION-01` against an
    /// accidental flip that would emit a spurious `aggregate=` for
    /// every row.
    #[test]
    fn render_omits_aggregate_when_unset() {
        let s = render_ksb(&fixture_snapshot()).unwrap();
        assert!(
            !s.contains("aggregate="),
            "renderer must not emit `aggregate=` when no DagRow \
             carries a value; got: {s}"
        );
    }

    /// The renderer MUST emit `aggregate=<value>` between
    /// `reviewers=N` and `sha=` when `DagRow::aggregate_verdict`
    /// is non-empty. The exact placement is pinned so the
    /// orchestrator NNSP rule 3a can parse it positionally even
    /// if a future iteration adds new fields elsewhere on the
    /// row.
    #[test]
    fn render_emits_aggregate_when_set() {
        let mut snap = fixture_snapshot();
        // Hydrate the first row with `AtLeastOneRejected` to
        // simulate the post-aggregator state the NNSP rule 3a
        // pivots on.
        snap.dag_rows[0].aggregate_verdict = "AtLeastOneRejected".to_owned();
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains("reviewers=2 preds_ready=true aggregate=AtLeastOneRejected sha="),
            "renderer must place `aggregate=` between `preds_ready=` \
             and `sha=`; got: {s}",
        );
    }

    /// Renderer MUST reject a `KSB_DELIMITER_CLOSE` byte sequence
    /// in `DagRow::aggregate_verdict`. Defense-in-depth — the
    /// projection only ever stamps wire-stable variant names from
    /// `AggregateReviewVerdict::wire_str`, but if a future
    /// refactor allows operator-supplied text into the field the
    /// renderer must fail-closed.
    #[test]
    fn render_rejects_close_delimiter_in_aggregate_verdict() {
        let mut snap = fixture_snapshot();
        snap.dag_rows[0].aggregate_verdict = format!("evil{}", KSB_DELIMITER_CLOSE);
        match render_ksb(&snap).unwrap_err() {
            KsbError::DelimiterInjection { field } => {
                assert_eq!(field, "dag_rows");
            }
            other => panic!("expected DelimiterInjection, got {other:?}"),
        }
    }

    #[test]
    fn render_includes_pending_escalations_block() {
        let mut snap = fixture_snapshot();
        snap.pending_escalations.push(PendingEscalation {
            escalation_id: "esc-7".to_owned(),
            class: "MergeConflict".to_owned(),
            summary: "operator must rebase main".to_owned(),
        });
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains(
                "pending_escalations=\n  - esc-7 MergeConflict \"operator must rebase main\""
            ),
            "pending escalation row missing or malformed: {s}"
        );
    }

    #[test]
    fn render_rejects_empty_initiative_id() {
        let mut snap = fixture_snapshot();
        snap.initiative_id.clear();
        match render_ksb(&snap).unwrap_err() {
            KsbError::EmptyRequired { field } => {
                assert_eq!(field, "initiative_id");
            }
            other => panic!("expected EmptyRequired, got {other:?}"),
        }
    }

    #[test]
    fn render_rejects_empty_role() {
        let mut snap = fixture_snapshot();
        snap.role.clear();
        match render_ksb(&snap).unwrap_err() {
            KsbError::EmptyRequired { field } => {
                assert_eq!(field, "role");
            }
            other => panic!("expected EmptyRequired, got {other:?}"),
        }
    }

    #[test]
    fn render_rejects_close_delimiter_in_task_description() {
        let mut snap = fixture_snapshot();
        snap.task_description = format!("fake close: {} extra text", KSB_DELIMITER_CLOSE,);
        match render_ksb(&snap).unwrap_err() {
            KsbError::DelimiterInjection { field } => {
                assert_eq!(field, "task_description");
            }
            other => panic!("expected DelimiterInjection, got {other:?}"),
        }
    }

    #[test]
    fn render_rejects_close_delimiter_in_path_allowlist() {
        let mut snap = fixture_snapshot();
        snap.path_allowlist
            .push(format!("evil/path{}", KSB_DELIMITER_CLOSE));
        match render_ksb(&snap).unwrap_err() {
            KsbError::DelimiterInjection { field } => {
                assert_eq!(field, "path_allowlist");
            }
            other => panic!("expected DelimiterInjection, got {other:?}"),
        }
    }

    #[test]
    fn render_rejects_close_delimiter_in_dag_row_title() {
        let mut snap = fixture_snapshot();
        snap.dag_rows[0].title = format!("title-{}", KSB_DELIMITER_CLOSE);
        match render_ksb(&snap).unwrap_err() {
            KsbError::DelimiterInjection { field } => {
                assert_eq!(field, "dag_rows");
            }
            other => panic!("expected DelimiterInjection, got {other:?}"),
        }
    }

    #[test]
    fn render_rejects_close_delimiter_in_credential_port() {
        let mut snap = fixture_snapshot();
        snap.credential_ports.push(CredentialPort {
            upstream_id: format!("evil{}", KSB_DELIMITER_CLOSE),
            kind: "postgres".to_owned(),
            port: 5432,
        });
        match render_ksb(&snap).unwrap_err() {
            KsbError::DelimiterInjection { field } => {
                assert_eq!(field, "credential_ports");
            }
            other => panic!("expected DelimiterInjection, got {other:?}"),
        }
    }

    #[test]
    fn assemble_system_prompt_joins_nnsp_and_ksb() {
        let snap = fixture_snapshot();
        let nnsp = "You are an executor. Stay in your lane.";
        let s = assemble_system_prompt(nnsp, &snap).unwrap();
        assert!(
            s.starts_with(nnsp),
            "system prompt must begin with the NNSP verbatim"
        );
        assert!(s.contains(KSB_DELIMITER_OPEN));
        assert!(s.contains(KSB_DELIMITER_CLOSE));
        assert!(
            s.contains(&format!("\n\n{}", KSB_DELIMITER_OPEN)),
            "NNSP and KSB must be separated by a blank line, got: {s}"
        );
    }

    #[test]
    fn assemble_system_prompt_rejects_empty_nnsp() {
        let snap = fixture_snapshot();
        match assemble_system_prompt("", &snap).unwrap_err() {
            KsbError::EmptyRequired { field } => {
                assert_eq!(field, "nnsp");
            }
            other => panic!("expected EmptyRequired, got {other:?}"),
        }
    }

    #[test]
    fn assemble_system_prompt_handles_nnsp_with_trailing_newline() {
        let snap = fixture_snapshot();
        let nnsp = "You are an executor.\n";
        let s = assemble_system_prompt(nnsp, &snap).unwrap();
        assert!(
            !s.contains("\n\n\n"),
            "assemble must not emit triple newlines, got: {s:?}"
        );
    }

    #[test]
    fn render_ksb_field_order_is_stable_prefix() {
        let s = render_ksb(&fixture_snapshot()).unwrap();
        let prefix_order = [
            "version=",
            "initiative_id=",
            "task_id=",
            "role=",
            "evaluation_sha=",
            "target_ref=",
            "path_allowlist=",
        ];
        let mut last_idx = 0;
        for key in &prefix_order {
            let idx = s
                .find(key)
                .unwrap_or_else(|| panic!("missing key {key:?} in rendered KSB: {s}"));
            assert!(
                idx >= last_idx,
                "field order regression: {key:?} appears before earlier field, \
                 idx={idx} last_idx={last_idx}, full output:\n{s}"
            );
            last_idx = idx;
        }
    }

    /// the JSON wire shape MUST
    /// round-trip cleanly so the kernel-side serialise + driver-side
    /// deserialise pair produces a byte-identical render.
    #[test]
    fn json_round_trip_produces_identical_render() {
        let original = fixture_snapshot();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: KsbSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(
            original, decoded,
            "JSON round-trip MUST preserve every field — drift here \
             corrupts the system prompt seen by the model"
        );
        let render_a = render_ksb(&original).unwrap();
        let render_b = render_ksb(&decoded).unwrap();
        assert_eq!(
            render_a, render_b,
            "render MUST be byte-stable across JSON round-trip"
        );
    }

    /// adding a field is a
    /// non-breaking change. A driver running an older
    /// `KsbSnapshot` schema MUST tolerate a kernel that emits
    /// extra keys (forward compat). serde's `#[serde(default)]`
    /// across every appended field is the load-bearing contract.
    #[test]
    fn driver_tolerates_legacy_kernel_with_missing_optional_keys() {
        let legacy = serde_json::json!({
            "version":       1,
            "initiative_id": "init-x",
            "role":          "executor",
        });
        let snap: KsbSnapshot = serde_json::from_value(legacy).unwrap();
        assert_eq!(snap.initiative_id, "init-x");
        assert_eq!(snap.role, "executor");
        assert!(snap.task_id.is_none());
        assert!(snap.path_allowlist.is_empty());
        assert!(snap.dag_rows.is_empty());
        assert_eq!(snap.token_budget_remaining, 0);
        assert_eq!(snap.wallclock_budget_remaining_s, 0);
        assert!(snap.evaluation_sha.is_empty());
        assert!(snap.target_ref.is_empty());
        assert!(snap.reviewer_verdicts.is_empty());
        assert!(snap.pending_escalations.is_empty());
        assert!(snap.credential_ports.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────
    // V2.7 `INV-KSB-MAX-TURNS-VISIBILITY-01` — renderer pin: every
    // role's `role=` line MUST carry a `planner_max_turns=N` token.
    // The presence of the token is a positive structural signal the
    // agent's NNSP relies on; absence is taken as a renderer
    // regression and the agent is permitted to refuse.
    // ─────────────────────────────────────────────────────────────────

    fn caps_session_view(role: &str, max_turns: u32) -> SessionCapabilityView {
        SessionCapabilityView {
            session_id: format!("sess-{role}-test"),
            role: role.to_owned(),
            planner_max_turns: max_turns,
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // iter65 — INV-KSB-GATE-FIXUP-CONTEXT-01
    //
    // The fixup-executor's KSB MUST carry a focused `gate_fixup=`
    // block with the gate_type, repair hint, parent linkage, and
    // attempt counter. Non-fixup tasks MUST NOT emit the block so
    // the steady-state KSB shape (executor / reviewer / orchestrator)
    // is unaffected.
    // ─────────────────────────────────────────────────────────────────

    /// Pinned positive case — the focused block appears when
    /// `gate_fixup` is `Some`. All five primitive lines are
    /// rendered in the specified order and the `agent_hint`
    /// block is rendered as a multi-line indented sub-block.
    #[test]
    fn render_emits_gate_fixup_block_when_set() {
        let mut snap = fixture_snapshot();
        snap.gate_fixup = Some(gate_fixup_fixture());
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains("gate_fixup=\n"),
            "rendered KSB must open a `gate_fixup=` block; got: {s}"
        );
        assert!(
            s.contains("  gate_type=NoSecretStrings\n"),
            "rendered KSB must carry the gate_type primitive; got: {s}"
        );
        assert!(
            s.contains("  parent_task_id=task-7\n"),
            "rendered KSB must carry the parent_task_id primitive; got: {s}"
        );
        assert!(
            s.contains("  parent_evaluation_sha=deadbeefcafebabedeadbeefcafebabedeadbeef\n"),
            "rendered KSB must carry the parent_evaluation_sha primitive; got: {s}"
        );
        assert!(
            s.contains("  parent_worktree_pointer=/var/lib/raxis/worktrees/init-3/task-7\n"),
            "rendered KSB must carry the parent_worktree_pointer primitive; got: {s}"
        );
        assert!(
            s.contains("  attempt=1/3\n"),
            "rendered KSB must carry the attempt counter; got: {s}"
        );
        assert!(
            s.contains("  agent_hint=\n"),
            "rendered KSB must open an indented agent_hint sub-block; got: {s}"
        );
        assert!(
            s.contains("    Remove the AWS access key shape from src/auth.rs:42"),
            "rendered KSB must indent the agent_hint body; got: {s}"
        );
    }

    /// Pinned negative case — non-fixup tasks (`gate_fixup =
    /// None`) MUST omit the entire block so the wire stays
    /// compact and the steady-state KSB shape is unchanged.
    #[test]
    fn render_omits_gate_fixup_block_for_non_fixup_tasks() {
        let snap = fixture_snapshot();
        assert!(snap.gate_fixup.is_none());
        let s = render_ksb(&snap).unwrap();
        assert!(
            !s.contains("gate_fixup="),
            "non-fixup KSB must NOT emit the `gate_fixup=` block; got: {s}"
        );
    }

    /// Empty `agent_hint` strings render as the `<empty>`
    /// placeholder so the LLM sees a structurally complete
    /// block even when (defensively) the kernel projection
    /// produced an empty hint. The renderer never panics on
    /// empty strings.
    #[test]
    fn render_gate_fixup_empty_agent_hint_renders_placeholder() {
        let mut snap = fixture_snapshot();
        let mut gf = gate_fixup_fixture();
        gf.agent_hint = String::new();
        snap.gate_fixup = Some(gf);
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains("agent_hint=\n    <empty>\n"),
            "empty agent_hint must render as <empty> placeholder; got: {s}"
        );
    }

    /// Renderer MUST reject `KSB_DELIMITER_CLOSE` injected via any
    /// gate-fixup text field. Defense-in-depth: the
    /// verifier-supplied `agent_hint` is the highest-risk surface
    /// because it transits operator-controlled verifier scripts.
    /// The pre-render scan fails the whole render closed.
    #[test]
    fn render_rejects_close_delimiter_in_gate_fixup_fields() {
        for (field_name, mutator) in [
            (
                "gate_type",
                Box::new(|gf: &mut GateFixupContext| {
                    gf.gate_type = format!("evil{KSB_DELIMITER_CLOSE}")
                }) as Box<dyn Fn(&mut GateFixupContext)>,
            ),
            (
                "agent_hint",
                Box::new(|gf: &mut GateFixupContext| {
                    gf.agent_hint = format!("hint with embedded {KSB_DELIMITER_CLOSE}")
                }),
            ),
            (
                "parent_task_id",
                Box::new(|gf: &mut GateFixupContext| {
                    gf.parent_task_id = format!("p{KSB_DELIMITER_CLOSE}")
                }),
            ),
            (
                "parent_evaluation_sha",
                Box::new(|gf: &mut GateFixupContext| {
                    gf.parent_evaluation_sha = format!("sha{KSB_DELIMITER_CLOSE}")
                }),
            ),
            (
                "parent_worktree_pointer",
                Box::new(|gf: &mut GateFixupContext| {
                    gf.parent_worktree_pointer = format!("/path{KSB_DELIMITER_CLOSE}")
                }),
            ),
        ] {
            let mut snap = fixture_snapshot();
            let mut gf = gate_fixup_fixture();
            mutator(&mut gf);
            snap.gate_fixup = Some(gf);
            match render_ksb(&snap).unwrap_err() {
                KsbError::DelimiterInjection { field } => {
                    assert_eq!(
                        field, "gate_fixup",
                        "delimiter injection in gate_fixup.{field_name} must \
                         classify as `gate_fixup`, not `{field}`"
                    );
                }
                other => panic!(
                    "expected DelimiterInjection on gate_fixup.{field_name}, got {other:?}"
                ),
            }
        }
    }

    /// The JSON wire shape MUST round-trip when `gate_fixup` is
    /// populated. The kernel-side assembler serializes the
    /// snapshot to JSON before the substrate hands it to the
    /// driver; the driver-side deserialization must observe
    /// every field unchanged. Pinned alongside the existing
    /// `json_round_trip_produces_identical_render` test for the
    /// steady-state shape.
    #[test]
    fn render_gate_fixup_block_json_round_trips() {
        let mut snap = fixture_snapshot();
        snap.gate_fixup = Some(gate_fixup_fixture());
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: KsbSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
        let a = render_ksb(&snap).unwrap();
        let b = render_ksb(&decoded).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn inv_ksb_max_turns_visibility_01_renderer_emits_planner_max_turns_for_all_roles() {
        // Orchestrator envelope.
        let mut snap = fixture_snapshot();
        snap.role = "orchestrator".to_owned();
        snap.task_id = None;
        snap.capabilities = Some(Capabilities::Orchestrator(OrchestratorCapabilities {
            session: caps_session_view("orchestrator", 77),
            initiative: InitiativeCapabilityView {
                initiative_id: snap.initiative_id.clone(),
                orchestrator_no_progress_respawn_count: 0,
                max_orchestrator_no_progress_respawns: 3,
                orchestrator_respawns_remaining: 3,
            },
            tasks: Vec::new(),
            ready_now: Vec::new(),
            concurrency: ConcurrencyCapabilityView::default(),
            max_turns_scaling: MaxTurnsScalingView {
                max_turns_attempt: 1,
                max_turns_base: 77,
                max_turns_step: 40,
                max_turns_hard_ceiling: 240,
            },
        }));
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains("role=orchestrator"),
            "orchestrator capabilities line MUST emit `role=orchestrator`; got: {s}"
        );
        assert!(
            s.contains("planner_max_turns=77"),
            "orchestrator capabilities line MUST carry `planner_max_turns=77`; got: {s}"
        );

        // Executor envelope.
        let mut snap = fixture_snapshot();
        snap.role = "executor".to_owned();
        snap.capabilities = Some(Capabilities::Executor(ExecutorCapabilities {
            session: caps_session_view("executor", 25),
            task: TaskCapabilityView {
                task_id: "task-42".to_owned(),
                crash_retry_count: 0,
                review_reject_count: 0,
                max_crash_retries: 3,
                max_review_rejections: 3,
                crash_retries_remaining: 3,
                review_retries_remaining: 3,
                retry_admissible: false,
                retry_inadmissible_reason: Some("no prior activation".to_owned()),
            },
            max_turns_scaling: MaxTurnsScalingView {
                max_turns_attempt: 1,
                max_turns_base: 25,
                max_turns_step: 15,
                max_turns_hard_ceiling: 240,
            },
        }));
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains("role=executor"),
            "executor capabilities line MUST emit `role=executor`; got: {s}"
        );
        assert!(
            s.contains("planner_max_turns=25"),
            "executor capabilities line MUST carry `planner_max_turns=25`; got: {s}"
        );

        // Reviewer envelope.
        let mut snap = fixture_snapshot();
        snap.role = "reviewer".to_owned();
        snap.task_id = Some("rev-A".to_owned());
        snap.capabilities = Some(Capabilities::Reviewer(ReviewerCapabilities {
            session: caps_session_view("reviewer", 5),
            artifact_task_id: "task-42".to_owned(),
        }));
        let s = render_ksb(&snap).unwrap();
        assert!(
            s.contains("role=reviewer"),
            "reviewer capabilities line MUST emit `role=reviewer`; got: {s}"
        );
        assert!(
            s.contains("planner_max_turns=5"),
            "reviewer capabilities line MUST carry `planner_max_turns=5`; got: {s}"
        );
    }
}
