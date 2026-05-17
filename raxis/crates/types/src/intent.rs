// raxis-types::intent — IntentRequest, IntentResponse, IntentKind, BudgetSnapshot.
// Normative reference: peripherals.md §3.1 "IntentRequest wire shape" and
// "IntentResponse wire shape". The JSON shown in the spec is a human-readable
// projection; the canonical types are defined here.
// Wire encoding: bincode 2.0.1 with `config::standard()` wrapped in a 4-byte
// LE length prefix by `raxis-ipc::frame`. The serde names here are used only
// for JSON projections (operator UIs, test harnesses); they are NOT transmitted
// on the wire (bincode standard() encodes positionally).

use crate::{CommitSha, EscalationId, TaskId, TaskState};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// IntentKind
// peripherals.md §3.1 "intent_kind valid values (v1)"
// ---------------------------------------------------------------------------

/// The kind of action the planner is asserting with an IntentRequest.
/// v1 values — the kernel rejects any other string with FAIL_POLICY_VIOLATION.
/// V2 values — gated by the static dispatch matrix (v2-deep-spec.md §Step 20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentKind {
    /// Exactly one committed change on top of `base_sha`.
    /// Kernel enforces `parent(head_sha) == base_sha` for non-empty ranges.
    /// Empty diff (`base_sha == head_sha`) is permitted (vacuous path check).
    SingleCommit,

    /// A merge commit integrating agent branches.
    /// Subject to the 5-predicate topology check (kernel-store.md §2.5.8).
    IntegrationMerge,

    /// Assert the task is complete. Triggers path closure + gate closure check.
    CompleteTask,

    /// Planner self-reports inability to complete the task.
    /// Transitions Running → Failed. Requires `justification`.
    ReportFailure,

    // ── V2 hierarchical orchestration (v2-deep-spec.md §1.2) ──────────────
    /// **V2.** Orchestrator-only. Requests that the Kernel admit and spawn
    /// the sub-task identified by `task_id` (an Executor or Reviewer
    /// sub-task declared in the operator-signed plan).
    /// Authorization: gated by the static dispatch matrix
    /// (v2-deep-spec.md §Step 20) AND the `can_delegate` boolean on the
    /// session row (INV-DELEGATE-01). `can_delegate = 1` ⇔
    /// `session_agent_type = Orchestrator`.
    /// Wire fields used: `task_id` only (every other field is unused).
    /// Rejection codes:
    ///   * `FAIL_POLICY_VIOLATION` if dispatch matrix says the session
    ///     is not authorized.
    ///   * `DEPENDENCY_NOT_MET` if the requested sub-task's
    ///     `task_dag_edges` predecessors are not all `Completed`. This
    ///     is a TIMING error, not an authority error
    ///     (v2-deep-spec.md §Step 21) — the Orchestrator may retry
    ///     after the next `KernelPush::SubTaskCompleted`.
    ActivateSubTask,

    /// **V2.** Orchestrator-only. Requests that a previously-failed
    /// sub-task be re-activated, subject to the dual retry counters
    /// (v2-deep-spec.md §Step 12). The Kernel inserts a NEW
    /// `subtask_activations` row (PendingActivation), increments the
    /// appropriate counter (`crash_retry_count` for VM-crash failures,
    /// `review_reject_count` for Reviewer rejections), and returns
    /// `FAIL_INVALID_REQUEST` if either ceiling is exceeded.
    /// Wire fields used: `task_id` only.
    RetrySubTask,

    /// **V2.** Reviewer-only. Reports the Reviewer's verdict on the
    /// Executor's `evaluation_sha` set into the Reviewer's session by
    /// the Kernel at activation time.
    /// Wire fields used:
    ///   * `task_id` — the Reviewer's own task_id (NOT the Executor's;
    ///     the Kernel reverse-joins via `task_dag_edges` to the
    ///     predecessor Executor).
    ///   * `approved` — required, NOT NULL (`Some(true)` or
    ///     `Some(false)`). NULL ⇒ `FAIL_INVALID_REQUEST`.
    ///   * `critique` — required when `approved = false`; max 32 KiB.
    ///     Empty when `approved = true` (the Kernel ignores any text;
    ///     `Some("...")` with `approved = true` is silently
    ///     dropped — the critique field has no meaning in the success
    ///     path). Oversized critique ⇒ `FAIL_INVALID_ARGUMENT`.
    SubmitReview,

    /// **V2 .** Executor / Orchestrator —
    /// emit a typed mid-session output (progress report, diagnostic
    /// flag, task summary). NON-TERMINAL: the session continues
    /// after the kernel records the output. Reviewer is NEVER
    /// authorized to submit this kind (INV-PLANNER-HARNESS-02).
    /// Wire fields used: `structured_output` (must be `Some(_)`;
    /// `None` ⇒ `FAIL_STRUCTURED_OUTPUT_INVALID`). `task_id` is
    /// required so the kernel can scope the row to the correct
    /// `(initiative_id, task_id)` per R-1. `base_sha` / `head_sha`
    /// are unused.
    /// Rate-limit: per-session N outputs (kernel-side counter,
    /// reset on session expiry). Exceeding ⇒
    /// `FAIL_STRUCTURED_OUTPUT_RATE_LIMITED`.
    StructuredOutput,

    /// **V3 (`specs/v3/gate-rejection-orchestrator-fixup.md`).**
    /// Orchestrator-only. Requests that the Kernel admit a new
    /// sub-task row that was NOT declared in the operator-signed
    /// plan. The only authorised use-case in V3 is gate-rejection
    /// fixup (`sub_task_kind = SubTaskKind::GateFixup`) — a
    /// kernel-budgeted retry loop driven by the
    /// `KernelPush::GateRejected` push. Every other
    /// `sub_task_kind` value is reserved for future work and
    /// rejects with `FAIL_POLICY_VIOLATION`.
    /// Wire fields used:
    ///   * `task_id` — the NEW sub-task's identifier. MUST NOT
    ///     collide with an existing `tasks.task_id` (returns
    ///     `INVALID_REQUEST`).
    ///   * `sub_task_kind` — `Some(SubTaskKind::GateFixup)`; any
    ///     other value (or `None`) returns `INVALID_REQUEST`.
    ///   * `parent_gate_failure_task_id` — required, the parent
    ///     task whose gate produced the witness rejection.
    ///   * `parent_gate_failure_type` — required, the gate-type
    ///     string this fixup targets (MUST equal a known
    ///     `policy.gates[].gate_type`).
    ///   * `base_sha` / `head_sha` are unused at this lifecycle
    ///     layer (no SHA range; the parent's worktree pointer is
    ///     reused when the fixup activates).
    ///     Admission contract (`INV-GATE-FIXUP-BUDGET-KERNEL-ENFORCED-01`):
    ///   * `parent.gate_fixup_attempts < [gate_fixup].max_attempts`
    ///     OR rejection with the dedicated retryable-but-
    ///     terminal-for-this-parent code
    ///     `FAIL_GATE_FIXUP_BUDGET_EXHAUSTED`.
    ///     On success the kernel inserts a `tasks` row with
    ///     `is_gate_fixup = 1`, increments the parent's
    ///     `gate_fixup_attempts`, and emits a `GateFixupSpawned` audit
    ///     event. A follow-up `ActivateSubTask` from the Orchestrator
    ///     then spawns the VM (existing path).
    AddSubTask,
}

/// V3 (`specs/v3/gate-rejection-orchestrator-fixup.md` §4.3).
/// Optional discriminator on the new `AddSubTask` intent: which
/// admission code-path the kernel should follow. `Executor` is
/// the implicit default for the wire (`None` decodes as `Executor`)
/// and is **reserved** — no current handler accepts it; the only
/// authorised variant at v3 is `GateFixup`.
/// **Wire stability.** Encoded as a tagged enum through bincode
/// standard(); the JSON projection uses
/// `#[serde(rename_all = "PascalCase")]` to match other wire
/// enums in this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum SubTaskKind {
    /// Default. **Reserved** — a future iteration may allow
    /// orchestrators to declare additional executor sub-tasks at
    /// runtime, but until then admitting an `AddSubTask` with
    /// `kind = Executor` rejects with `FAIL_POLICY_VIOLATION`.
    #[default]
    Executor,

    /// **V3.** Kernel-budgeted fixup task spawned in response to a
    /// non-`Pass` gate verdict. Subject to the
    /// `policy.gate_fixup.max_attempts` ceiling enforced at admit
    /// (`INV-GATE-FIXUP-BUDGET-KERNEL-ENFORCED-01`). The
    /// orchestrator emits this kind in response to a
    /// `KernelPush::GateRejected` push (`§4.2`).
    GateFixup,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleCommit => "SingleCommit",
            Self::IntegrationMerge => "IntegrationMerge",
            Self::CompleteTask => "CompleteTask",
            Self::ReportFailure => "ReportFailure",
            Self::ActivateSubTask => "ActivateSubTask",
            Self::RetrySubTask => "RetrySubTask",
            Self::SubmitReview => "SubmitReview",
            Self::StructuredOutput => "StructuredOutput",
            Self::AddSubTask => "AddSubTask",
        }
    }

    /// Whether this intent kind requires `base_sha` and `head_sha`.
    /// V1: required for all kinds except `ReportFailure` (peripherals.md
    /// §3.1).
    /// V2: `ActivateSubTask`, `RetrySubTask`, and `SubmitReview` operate
    /// at the sub-task lifecycle layer, NOT the commit layer; they
    /// carry no SHA range. The Kernel ignores `base_sha` / `head_sha`
    /// entirely on these kinds (it does not even read them, so a
    /// truncated planner that passes garbage Some-values is harmless).
    /// V3 `AddSubTask` is also lifecycle-layer (the parent's worktree
    /// pointer is reused on the fixup task's activation; the kernel
    /// does NOT touch `base_sha` / `head_sha` at admit time).
    pub fn requires_sha_range(self) -> bool {
        matches!(
            self,
            Self::SingleCommit | Self::IntegrationMerge | Self::CompleteTask
        )
    }

    /// Whether this intent kind requires a non-empty `justification` field.
    pub fn requires_justification(self) -> bool {
        matches!(self, Self::ReportFailure)
    }

    /// V2: whether this intent kind is one of the V2-only sub-task
    /// lifecycle kinds. Useful at the dispatch matrix boundary as a
    /// fast guard before consulting the per-(kind, agent_type) matrix.
    /// V3 `AddSubTask` is also a sub-task lifecycle kind.
    pub fn is_v2_subtask_kind(self) -> bool {
        matches!(
            self,
            Self::ActivateSubTask
                | Self::RetrySubTask
                | Self::SubmitReview
                | Self::AddSubTask
        )
    }

    /// V2: whether this intent kind requires the `approved` field
    /// to be `Some(_)`. Currently only `SubmitReview` does.
    pub fn requires_approved(self) -> bool {
        matches!(self, Self::SubmitReview)
    }

    /// All variants. Used by the static-dispatch-matrix exhaustiveness
    /// guard (v2-deep-spec.md §Step 20) so a future added variant
    /// automatically fails the matrix-build test until a row is added.
    pub const ALL: [Self; 9] = [
        Self::SingleCommit,
        Self::IntegrationMerge,
        Self::CompleteTask,
        Self::ReportFailure,
        Self::ActivateSubTask,
        Self::RetrySubTask,
        Self::SubmitReview,
        Self::StructuredOutput,
        Self::AddSubTask,
    ];
}

// ---------------------------------------------------------------------------
// SubmittedClaim — one entry in IntentRequest.submitted_claims.
// peripherals.md §3.1 wire field `submitted_claims`.
// ---------------------------------------------------------------------------

/// A claim the planner asserts alongside an intent.
/// The kernel evaluates claims against the witness records for the task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmittedClaim {
    /// Must match a ClaimType recognised by the policy for the touched paths.
    pub claim_type: String,
    /// Hash of the witness blob this claim references (optional in v1 —
    /// if absent the kernel derives it from the task's witness_records).
    pub evidence_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// ApprovalToken — presented on IntentRequest after an escalation is approved.
// planner-api.md §"After the operator approves".
// ---------------------------------------------------------------------------

/// An operator-issued approval token presented by the planner on its next
/// intent after an escalation is approved. The kernel validates all three
/// fields together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalToken {
    /// UUID of the approval record in `approval_tokens`.
    pub approval_id: Uuid,
    /// Must match the `escalation_id` from the EscalationResponse::Submitted.
    pub escalation_id: crate::EscalationId,
    /// Ed25519 signature from the operator (64 bytes, hex-encoded on the wire).
    pub operator_sig: String,
}

// ---------------------------------------------------------------------------
// IntentRequest
// peripherals.md §3.1 "IntentRequest wire shape"
// ---------------------------------------------------------------------------

/// The planner's intent submission message. Sent on the planner UDS socket.
/// Wire shape: bincode 2.0.1 standard() inside a 4-byte LE length prefix
/// frame produced by `raxis-ipc::frame`. The JSON in the spec is illustrative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentRequest {
    /// Kernel-issued session credential. Validated by ipc/auth.rs on every frame.
    pub session_token: String,

    /// Must be exactly `prev_accepted_sequence + 1`.
    /// Gaps or reuse → UNAUTHORIZED.
    /// peripherals.md §3.1: "sequence_number — must be exactly prev_accepted_sequence + 1"
    pub sequence_number: u64,

    /// 16 random bytes as lowercase hex (32 chars). Globally unique per
    /// (session_id, nonce) within the nonce cache TTL. Reuse → UNAUTHORIZED.
    pub envelope_nonce: String,

    /// The kind of action being asserted.
    pub intent_kind: IntentKind,

    /// The task_id from the signed plan this intent targets.
    pub task_id: TaskId,

    /// Base commit OID. Required for all intent kinds except ReportFailure.
    /// For SingleCommit non-empty: must be the immediate parent of head_sha.
    pub base_sha: Option<CommitSha>,

    /// Tip commit OID. Required for all intent kinds except ReportFailure.
    pub head_sha: Option<CommitSha>,

    /// Claims the planner submits. May be empty if the gate set has no active
    /// requirements; extra claims when none are required are silently ignored.
    #[serde(default)]
    pub submitted_claims: Vec<SubmittedClaim>,

    /// Required non-empty for ReportFailure. Ignored for all other kinds.
    /// Max 2048 chars. planner-api.md §"Reporting failure".
    pub justification: Option<String>,

    /// If provided, the kernel returns the same IntentResponse on duplicate
    /// submission with the same key within the session. Does not replace
    /// sequence_number / nonce rules.
    pub idempotency_key: Option<Uuid>,

    /// Optional: approval token from an approved escalation.
    /// planner-api.md §"After the operator approves".
    pub approval_token: Option<ApprovalToken>,

    // ── V2 SubmitReview payload (v2-deep-spec.md §Step 22) ────────────────
    /// **V2 SubmitReview only.** The Reviewer's verdict on the
    /// Executor's `evaluation_sha`. Required when `intent_kind =
    /// SubmitReview`; ignored for every other kind.
    /// `Some(true)` — Reviewer approves the Executor's commits. The
    /// Kernel marks this Reviewer's `subtask_activations` row
    /// `Completed` and runs the reverse-DAG query to check whether
    /// every Reviewer of the predecessor Executor has now approved
    /// (Logical AND verdict; v2-deep-spec.md §Step 25). On the last
    /// Reviewer approving, the Kernel sends
    /// `KernelPush::AllReviewersPassed` to the Orchestrator.
    /// `Some(false)` — Reviewer rejects the Executor's commits.
    /// `critique` MUST be non-empty (kernel returns
    /// `FAIL_INVALID_ARGUMENT` if absent). The kernel writes the
    /// critique to the Executor's `tasks.last_critique`, increments
    /// `subtask_activations.review_reject_count`, and pushes
    /// `KernelPush::ReviewFailed` to the Orchestrator.
    /// `None` for any non-`SubmitReview` kind. `None` on `SubmitReview`
    /// returns `FAIL_INVALID_REQUEST`.
    /// **Wire encoding note:** this field is NOT marked
    /// `#[serde(skip_serializing_if = "Option::is_none")]` because the
    /// canonical wire format is bincode 2.0.1 in `bincode::serde` mode,
    /// which honours `skip_serializing_if` on the encode side but ALWAYS
    /// reads all fields on the decode side. A skipped Option would
    /// deserialise as `UnexpectedEnd { additional: 1 }` and the kernel
    /// would drop the connection on every V2-aware planner frame
    /// (regression caught by `kernel_full_lifecycle_e2e` against a
    /// previous draft). The JSON projection still elides `null`s
    /// because `serde_json` does not pre-allocate field counts; any
    /// future operator UI consuming JSON keeps the same shape.
    #[serde(default)]
    pub approved: Option<bool>,

    /// **V2 SubmitReview only.** The Reviewer's critique text on
    /// rejection. Capped at 32,768 bytes (`MAX_CRITIQUE_BYTES`); larger
    /// payloads are rejected with `FAIL_INVALID_ARGUMENT` and NOT
    /// stored. Why 32 KiB: long critiques (including full file diffs)
    /// would exhaust the retry Executor's context window before it
    /// processes a single turn (v2-deep-spec.md §Step 22). 32 KiB is
    /// generous for actionable feedback while preventing context-
    /// flooding DoS.
    /// Required to be `Some(non-empty)` when `approved = false`;
    /// ignored when `approved = true` (kernel does not store the text);
    /// must be `None` for every non-`SubmitReview` intent kind.
    /// **Wire encoding note:** see the analogous comment on `approved`
    /// `skip_serializing_if` is intentionally absent here for bincode
    /// round-trip compatibility.
    #[serde(default)]
    pub critique: Option<String>,

    // ── V2 IntegrationMerge attribution payload (v2-deep-spec.md §Step 30) ──
    /// **V2 IntegrationMerge only.** When `Some(id)`, this merge was
    /// produced via operator escalation: either Path 1 (operator
    /// hint guided the LLM's re-attempt) or Path 2 (operator
    /// committed the resolution by hand against the Orchestrator's
    /// worktree). The kernel verifies the linked escalation is in
    /// `Consumed` state under `class = MergeConflict` and belongs
    /// to the submitting Orchestrator's session before admitting
    /// the merge (Check 6b in `integration-merge.md §4`).
    /// `None` for every standard (LLM-resolved or conflict-free)
    /// merge AND for every non-`IntegrationMerge` intent kind.
    /// **Why optional, not a separate intent variant:** the
    /// admission pipeline (Checks 1–5, 7, 8) is identical for both
    /// merge paths; the only difference is the additional
    /// escalation-attribution gate at Check 6b. Modelling
    /// operator-assisted merges as a separate variant would
    /// duplicate every other check and tempt the kernel into
    /// path-specific divergence. INV-05 (audit chain attribution)
    /// is achievable from the optional field alone.
    /// **Wire encoding note:** see the analogous comment on
    /// `approved` — `skip_serializing_if` is intentionally absent
    /// for bincode round-trip compatibility (a skipped Option would
    /// surface as `UnexpectedEnd { additional: 1 }` on every
    /// V2-aware planner frame).
    #[serde(default)]
    pub resolved_via_escalation: Option<EscalationId>,

    // ── V2 §2.5 token-limit enforcement (per-intent token reporting) ──
    /// **V2 per-intent token report.**
    /// The cumulative token usage the planner has consumed in its
    /// dispatch loop *up to and including* the LLM turn that
    /// produced this intent. Stamped by
    /// `crate::IntentSubmitter` from the dispatch loop's
    /// `(cum_in, cum_out)` counters.
    /// **Required by every planner-submitted intent.** Forward-only,
    /// no V1/V2.4 fallback path: every planner binary that runs
    /// against the V2.5+ kernel populates this field unconditionally.
    /// `Some(zero)` is a legitimate value (the dispatch loop
    /// short-circuited on a deterministic terminal tool before any
    /// LLM turn fired); `None` is reserved for synthetic
    /// kernel-injected intents where no dispatch loop ran (e.g.
    /// the recovery sweep's posthumous `ReportFailure`).
    /// **Why on the request and not the response.** Both directions
    /// were considered. Carrying the report on the request makes
    /// every individual intent self-describing: kernel-side audit
    /// and budget gates need the token total *at admission time*
    /// (not after a successful response), so attaching to the
    /// request keeps the admission pipeline's single-pass shape.
    /// The response carries the *post-admission* lane budget snapshot
    /// (see `IntentResponse.budget`), which is a different quantity.
    /// **Wire encoding note:** see the analogous comment on
    /// `approved` — `skip_serializing_if` is intentionally absent
    /// for bincode round-trip compatibility.
    #[serde(default)]
    pub tokens_used: Option<TokensReport>,

    // ── V2 §3.2 StructuredOutput payload ───────────────────────────────
    /// **V2 typed mid-session output.**
    /// Required to be `Some(_)` when `intent_kind = StructuredOutput`
    /// (kernel rejects with `FAIL_STRUCTURED_OUTPUT_INVALID`); MUST
    /// be `None` for every other intent kind. The kernel runs
    /// [`crate::structured_output::StructuredOutputKind::validate_and_normalise`]
    /// on the payload before storing it in `structured_outputs` —
    /// see the type doc for the closed enum's invariant matrix.
    /// **Wire encoding note:** see the analogous comment on
    /// `approved` — `skip_serializing_if` is intentionally absent
    /// for bincode round-trip compatibility.
    #[serde(default)]
    pub structured_output: Option<crate::StructuredOutputKind>,

    // ── V3 AddSubTask payload (specs/v3/gate-rejection-orchestrator-fixup.md) ──
    /// **V3 AddSubTask only.** Discriminator on which admission
    /// code-path the kernel should follow. At v3, the only
    /// authorised value is `Some(SubTaskKind::GateFixup)`. Any
    /// other value (or `None`) on an `AddSubTask` intent returns
    /// `INVALID_REQUEST`. MUST be `None` for every other intent
    /// kind. **Wire encoding note:** see the analogous comment on
    /// `approved` — `skip_serializing_if` is intentionally absent.
    #[serde(default)]
    pub sub_task_kind: Option<SubTaskKind>,

    /// **V3 AddSubTask only.** The parent task whose gate
    /// produced the witness rejection that this fixup is
    /// responding to. The kernel validates the parent exists,
    /// belongs to the same initiative, and has
    /// `gate_fixup_attempts < [gate_fixup].max_attempts`.
    /// MUST be `None` for every other intent kind.
    #[serde(default)]
    pub parent_gate_failure_task_id: Option<TaskId>,

    /// **V3 AddSubTask only.** The gate-type string this fixup
    /// targets. MUST match a known `policy.gates[].gate_type`
    /// (otherwise `FAIL_POLICY_VIOLATION` at admit). Stored on
    /// the new fixup task row's `parent_gate_failure_type`
    /// column for KSB assembly and dashboard rendering. MUST
    /// be `None` for every other intent kind.
    #[serde(default)]
    pub parent_gate_failure_type: Option<String>,
}

/// Cumulative LLM token usage the
/// planner has consumed across its dispatch loop up to (and
/// including) the turn that produced the carrying intent.
/// All counts are non-negative and saturate at `u64::MAX` in the
/// driver before being stamped on the wire (so the wire shape never
/// has to reason about overflow). Cache-read / cache-creation
/// counters are zero unless the model client surfaces them
/// explicitly via the streaming `usage` events; the
/// `raxis_policy::ProviderPricing::cost_micro_dollars` arithmetic
/// handles all four channels uniformly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokensReport {
    /// Cumulative input tokens (prompt + tool output) the planner
    /// has consumed in this session.
    pub input_tokens: u64,
    /// Cumulative output tokens (model-generated text + tool calls)
    /// the planner has emitted in this session.
    pub output_tokens: u64,
    /// Cumulative cache-read tokens (Anthropic prompt-caching). 0
    /// when the provider does not surface this counter.
    #[serde(default)]
    pub cache_read_tokens: u64,
    /// Cumulative cache-creation tokens (Anthropic prompt-caching).
    /// 0 when the provider does not surface this counter.
    #[serde(default)]
    pub cache_creation_tokens: u64,
    /// **Provider id** the planner billed these tokens against —
    /// matches an entry in `policy.providers[].provider_id`. The
    /// kernel uses this to pick the right
    /// `ProviderPricing` table at admission time. Empty string
    /// when the planner did not route through the gateway (e.g.
    /// reviewer that short-circuited on a deterministic check).
    #[serde(default)]
    pub provider_id: String,
}

/// V2 hard cap on `IntentRequest.critique` byte length
/// (v2-deep-spec.md §Step 22). Kernel-side size check returns
/// `FAIL_INVALID_ARGUMENT` if exceeded; the critique is NOT stored
/// (so an attacker cannot use oversized critique submissions to
/// flood `tasks.last_critique`).
pub const MAX_CRITIQUE_BYTES: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// BudgetSnapshot
// peripherals.md §3.1 "remaining_budget" field.
// ---------------------------------------------------------------------------

/// The lane budget snapshot returned on every Accepted IntentResponse.
/// Treat as opaque — it is NOT a token count, USD amount, or wall-clock estimate.
/// planner-api.md §"Budget awareness".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    /// Admission units remaining on this task's lane after charging for this intent.
    pub admission_units: u64,
}

// ---------------------------------------------------------------------------
// PlannerErrorTemplate — fixed generic-template set for error_detail.
// peripherals.md §3.1 INV-08 rule for FAIL_POLICY_VIOLATION.
// raxis-types/src/error.rs (cross-reference).
// ---------------------------------------------------------------------------

/// Fixed, version-controlled template strings returned in `error_detail` for
/// FAIL_POLICY_VIOLATION only. No runtime interpolation; no file paths; no
/// policy rule names. INV-08 (peripherals.md §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlannerErrorTemplate {
    /// The intent kind is not permitted under the current policy epoch.
    IntentKindNotPermitted,
    /// A submitted claim is malformed (wrong type, invalid evidence ref format).
    MalformedClaim,
    /// The task has a constraint in the signed plan that this intent violates.
    PlanConstraintViolation,
    /// The session's lineage is quarantined; no further intents accepted.
    LineageQuarantined,
}

// ---------------------------------------------------------------------------
// IntentResponse
// peripherals.md §3.1 "IntentResponse wire shape"
// ---------------------------------------------------------------------------

/// The kernel's response to an IntentRequest. Two variants: Accepted / Rejected.
/// The `outcome` field is the discriminant; field exclusivity rules are enforced
/// by the type system via the nested enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentResponse {
    /// Matches the `sequence_number` of the IntentRequest this responds to.
    pub sequence_number: u64,

    /// The current task state at response time.
    /// Post-transition on Accepted; last-committed-state on Rejected.
    pub task_state: TaskState,

    /// The outcome variant with its exclusive payload.
    pub outcome: IntentOutcome,
}

/// The exclusive payload variants for IntentResponse.
/// **Wire format note (INV-IPC-BINCODE):** this enum is serialised through
/// `raxis-ipc::frame` with `bincode::config::standard()`, which encodes
/// enums positionally with a single varint discriminator. Earlier
/// revisions had `#[serde(tag = "outcome", rename_all = "PascalCase")]`
/// here to mirror the JSON projection in `peripherals.md` §3.1; that
/// internal-tag representation requires `serde::deserialize_any` which
/// `bincode::config::standard()` does NOT support, and produces
/// `Decode(Serde(AnyNotSupported))` at the first wire round-trip. The
/// attribute had survived only because no test exercised the actual
/// bincode round-trip — `kernel/tests/mock_planner_end_to_end.rs` is
/// the regression guard.
/// The default external-tag representation works with bincode and stays
/// compatible with JSON consumers that read the discriminant from the
/// outer key (`{"Accepted": {...}}` / `{"Rejected": {...}}`). The flat
/// JSON projection sketched in the spec is documentation-only in v1; if
/// a JSON wire shape is added later it should be a separate type, not a
/// serde mode that breaks the bincode wire path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentOutcome {
    Accepted {
        /// Lane budget snapshot after budget consumption for this intent.
        remaining_budget: BudgetSnapshot,
        /// true iff evaluate_claims took the SufficientStale grace use.
        /// The planner must renew the delegation before the next gated action.
        warn_delegation_stale: bool,
    },
    Rejected {
        /// Coarse rejection reason. Full enum in error.rs.
        error_code: crate::PlannerErrorCode,
        /// Non-null only for FAIL_POLICY_VIOLATION. Fixed template set; INV-08.
        error_detail: Option<PlannerErrorTemplate>,
    },
}

impl IntentResponse {
    /// Convenience: was this intent accepted?
    pub fn is_accepted(&self) -> bool {
        matches!(self.outcome, IntentOutcome::Accepted { .. })
    }
}

// ---------------------------------------------------------------------------
// SessionId re-export for use in this module's session_token field
// ---------------------------------------------------------------------------
// Note: session_token on the wire is a hex string, not a SessionId (UUIDs are
// separate from the token bytes). The SessionId is the UUID that identifies the
// row; the token is 32 CSPRNG bytes as 64-char hex. Both are strings on the
// wire; we keep them as String here to match the wire shape exactly.
// See kernel-store.md §2.5.1 Table 4 for the column distinction.

#[cfg(test)]
mod tests {
    use super::*;

    /// V3 has 9 IntentKind variants total:
    ///   * 4 V1 — SingleCommit, IntegrationMerge, CompleteTask,
    ///     ReportFailure.
    ///   * 3 V2 — ActivateSubTask, RetrySubTask, SubmitReview.
    ///   * 1 V2.5 — `StructuredOutput`.
    ///   * 1 V3 — `AddSubTask` (gate-fixup spawn entry, see
    ///     `specs/v3/gate-rejection-orchestrator-fixup.md`).
    ///     The pinned-count test surfaces accidental adds at the test
    ///     layer before any dispatch matrix or store mapping regresses.
    #[test]
    fn intent_kind_variant_count_is_pinned_to_v3() {
        assert_eq!(
            IntentKind::ALL.len(),
            9,
            "V3 has exactly 9 IntentKind variants \
             (4 V1: SingleCommit, IntegrationMerge, CompleteTask, \
             ReportFailure; 3 V2: ActivateSubTask, RetrySubTask, \
             SubmitReview; 1 V2.5: StructuredOutput; \
             1 V3: AddSubTask). Bumping this requires the static \
             dispatch matrix (v2-deep-spec.md §Step 20) to gain a \
             matching row."
        );
    }

    /// `as_str` round-trip: every variant maps to a non-empty
    /// PascalCase string and the strings are pairwise distinct.
    /// Pinning prevents an accidental rename from silently breaking
    /// audit-replay tooling that matches on the discriminator.
    #[test]
    fn intent_kind_as_str_is_pairwise_distinct() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for &k in &IntentKind::ALL {
            let s = k.as_str();
            assert!(!s.is_empty());
            assert!(
                seen.insert(s),
                "IntentKind::as_str collision detected at {k:?}: {s}"
            );
        }
        // Pin the exact strings — these are wire-stable.
        assert_eq!(IntentKind::SingleCommit.as_str(), "SingleCommit");
        assert_eq!(IntentKind::IntegrationMerge.as_str(), "IntegrationMerge");
        assert_eq!(IntentKind::CompleteTask.as_str(), "CompleteTask");
        assert_eq!(IntentKind::ReportFailure.as_str(), "ReportFailure");
        assert_eq!(IntentKind::ActivateSubTask.as_str(), "ActivateSubTask");
        assert_eq!(IntentKind::RetrySubTask.as_str(), "RetrySubTask");
        assert_eq!(IntentKind::SubmitReview.as_str(), "SubmitReview");
        assert_eq!(IntentKind::StructuredOutput.as_str(), "StructuredOutput");
        assert_eq!(IntentKind::AddSubTask.as_str(), "AddSubTask");
    }

    /// V2 sub-task kinds do NOT carry a SHA range. The kernel
    /// admission pipeline must short-circuit ancestry / topology
    /// checks for them.
    #[test]
    fn requires_sha_range_only_for_commit_kinds() {
        // V1 kinds (except ReportFailure).
        assert!(IntentKind::SingleCommit.requires_sha_range());
        assert!(IntentKind::IntegrationMerge.requires_sha_range());
        assert!(IntentKind::CompleteTask.requires_sha_range());
        // V1 ReportFailure.
        assert!(!IntentKind::ReportFailure.requires_sha_range());
        // V2 sub-task kinds — no SHA range.
        assert!(!IntentKind::ActivateSubTask.requires_sha_range());
        assert!(!IntentKind::RetrySubTask.requires_sha_range());
        assert!(!IntentKind::SubmitReview.requires_sha_range());
    }

    /// `is_v2_subtask_kind` is the fast-path guard for the static
    /// dispatch matrix entry point. Pin the predicate so it cannot
    /// silently widen.
    #[test]
    fn is_v2_subtask_kind_excludes_v1_kinds() {
        // V2 kinds.
        assert!(IntentKind::ActivateSubTask.is_v2_subtask_kind());
        assert!(IntentKind::RetrySubTask.is_v2_subtask_kind());
        assert!(IntentKind::SubmitReview.is_v2_subtask_kind());
        // V1 kinds — must NOT be misclassified as V2.
        for k in [
            IntentKind::SingleCommit,
            IntentKind::IntegrationMerge,
            IntentKind::CompleteTask,
            IntentKind::ReportFailure,
        ] {
            assert!(
                !k.is_v2_subtask_kind(),
                "V1 kind {k:?} must NOT be a V2 sub-task kind"
            );
        }
    }

    /// Only `SubmitReview` requires the `approved` field. Other V2
    /// kinds do not consult it; V1 kinds never do.
    #[test]
    fn requires_approved_only_for_submit_review() {
        assert!(IntentKind::SubmitReview.requires_approved());
        for k in [
            IntentKind::SingleCommit,
            IntentKind::IntegrationMerge,
            IntentKind::CompleteTask,
            IntentKind::ReportFailure,
            IntentKind::ActivateSubTask,
            IntentKind::RetrySubTask,
        ] {
            assert!(
                !k.requires_approved(),
                "{k:?} must NOT require the `approved` field"
            );
        }
    }

    /// V1 backward compat at the bincode wire layer. The canonical wire
    /// format for `IntentRequest` is `bincode::serde` (peripherals.md
    /// §3.1, raxis-ipc::frame); the JSON projection is documentation
    /// only. We pin behaviour at THAT layer:
    ///   1. A V2 codebase serialising an "old shape" intent (V2 fields
    ///      `None`) round-trips byte-for-byte through bincode.
    ///   2. The JSON projection includes the new fields explicitly as
    ///      `null` — this is intentional. We did NOT use
    ///      `skip_serializing_if = "Option::is_none"` because
    ///      `bincode::serde` honours skip on encode but reads all
    ///      fields on decode, which would surface as
    ///      `UnexpectedEnd { additional: 1 }` and drop the planner
    ///      connection on every frame
    ///      (regression caught by the kernel full-lifecycle E2E suite).
    #[test]
    fn v1_intent_request_under_v2_codebase_round_trips_through_bincode() {
        use crate::TaskId;
        use uuid::Uuid;

        let req = IntentRequest {
            session_token: "tok".into(),
            sequence_number: 1,
            envelope_nonce: "0".repeat(32),
            intent_kind: IntentKind::SingleCommit,
            task_id: TaskId::parse("t-1").unwrap(),
            base_sha: None,
            head_sha: None,
            submitted_claims: vec![],
            justification: None,
            idempotency_key: Some(Uuid::nil()),
            approval_token: None,
            approved: None,
            critique: None,
            resolved_via_escalation: None,
            tokens_used: None,
            structured_output: None,
            sub_task_kind: None,
            parent_gate_failure_task_id: None,
            parent_gate_failure_type: None,
        };

        // 1. bincode round-trip on the canonical wire shape.
        let bytes = bincode::serde::encode_to_vec(&req, bincode::config::standard())
            .expect("bincode encode");
        let (back, _): (IntentRequest, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("bincode decode");
        assert_eq!(back.intent_kind, IntentKind::SingleCommit);
        assert!(back.approved.is_none());
        assert!(back.critique.is_none());

        // 2. JSON projection: V2 fields appear as `null`. Operator UIs
        //    that read JSON should match on `obj["approved"] == null`,
        //    not on absence-of-key.
        let v = serde_json::to_value(&req).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            obj.contains_key("approved"),
            "approved present (as null) in JSON projection"
        );
        assert!(obj.get("approved").unwrap().is_null());
        assert!(obj.contains_key("critique"));
        assert!(obj.get("critique").unwrap().is_null());
    }

    /// V2 SubmitReview wire shape includes `approved` and (on
    /// rejection) `critique`. Round-trip through JSON must preserve
    /// every field.
    #[test]
    fn v2_submit_review_round_trips_with_approved_and_critique() {
        use crate::TaskId;

        let req = IntentRequest {
            session_token: "tok".into(),
            sequence_number: 1,
            envelope_nonce: "1".repeat(32),
            intent_kind: IntentKind::SubmitReview,
            task_id: TaskId::parse("rev-task-1").unwrap(),
            base_sha: None,
            head_sha: None,
            submitted_claims: vec![],
            justification: None,
            idempotency_key: None,
            approval_token: None,
            approved: Some(false),
            critique: Some("the auth check is missing".to_owned()),
            resolved_via_escalation: None,
            tokens_used: None,
            structured_output: None,
            sub_task_kind: None,
            parent_gate_failure_task_id: None,
            parent_gate_failure_type: None,
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: IntentRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.approved, Some(false));
        assert_eq!(back.critique.as_deref(), Some("the auth check is missing"));
        assert_eq!(back.intent_kind, IntentKind::SubmitReview);
    }

    /// MAX_CRITIQUE_BYTES pinned at 32 KiB per v2-deep-spec.md §Step 22.
    /// Bumping this requires a spec amendment AND a dispatch-matrix
    /// review to reconfirm the context-flooding-DoS analysis.
    #[test]
    fn max_critique_bytes_is_pinned_at_32_kib() {
        assert_eq!(
            MAX_CRITIQUE_BYTES,
            32 * 1024,
            "MAX_CRITIQUE_BYTES is wire-load-bearing per \
             v2-deep-spec.md §Step 22; bumping requires a spec amend."
        );
    }

    /// V2 Step 30: `IntegrationMerge` carries an optional
    /// `resolved_via_escalation` link. The wire shape MUST round-trip
    /// through both bincode (canonical IPC) and serde JSON (operator
    /// projections / audit replay tooling) when the field is `Some`.
    /// Regression guard: a future serde change that defaults the
    /// field on encode would silently drop attribution evidence and
    /// the kernel's Check 6b verification would never see the link.
    #[test]
    fn v2_integration_merge_round_trips_resolved_via_escalation() {
        use crate::id::EscalationId;
        use crate::TaskId;
        // Fixed UUID — round-trip identity check below depends on
        // observing exactly this id on the decoded side.
        let escalation_id = EscalationId::parse("4f3a4f3a-4f3a-4f3a-4f3a-4f3a4f3a4f3a")
            .expect("fixed UUID v4 fixture parses");
        let req = IntentRequest {
            session_token: "tok".into(),
            sequence_number: 1,
            envelope_nonce: "2".repeat(32),
            intent_kind: IntentKind::IntegrationMerge,
            task_id: TaskId::parse("merge-1").unwrap(),
            base_sha: None,
            head_sha: None,
            submitted_claims: vec![],
            justification: None,
            idempotency_key: None,
            approval_token: None,
            approved: None,
            critique: None,
            resolved_via_escalation: Some(escalation_id.clone()),
            tokens_used: None,
            structured_output: None,
            sub_task_kind: None,
            parent_gate_failure_task_id: None,
            parent_gate_failure_type: None,
        };

        // Canonical IPC wire — bincode standard().
        let bytes = bincode::serde::encode_to_vec(&req, bincode::config::standard())
            .expect("bincode encode");
        let (back, _): (IntentRequest, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("bincode decode");
        assert_eq!(
            back.resolved_via_escalation.as_ref(),
            Some(&escalation_id),
            "bincode wire MUST preserve resolved_via_escalation: \
             without it, Step 30 attribution fails silently"
        );

        // Operator JSON projection — round-trip through serde JSON.
        let s = serde_json::to_string(&req).unwrap();
        let back = serde_json::from_str::<IntentRequest>(&s).unwrap();
        assert_eq!(back.resolved_via_escalation.as_ref(), Some(&escalation_id));

        // The field appears literally (not as a magic-numeric variant)
        // in the JSON projection so audit-replay UIs can match on key
        // name without depending on serde's representation rules.
        let v = serde_json::to_value(&req).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            obj.contains_key("resolved_via_escalation"),
            "JSON projection MUST surface `resolved_via_escalation` for \
             operator UIs that scan the wire frame"
        );
    }

    /// V2 Step 30: when the field is `None` (the standard merge path),
    /// bincode round-trip MUST still succeed and the JSON projection
    /// MUST carry a literal `null` (not absence-of-key) so JSON-mode
    /// consumers can match on the same key in both branches.
    #[test]
    fn v2_integration_merge_round_trips_with_no_escalation() {
        use crate::TaskId;
        use uuid::Uuid;

        let req = IntentRequest {
            session_token: "tok".into(),
            sequence_number: 1,
            envelope_nonce: "3".repeat(32),
            intent_kind: IntentKind::IntegrationMerge,
            task_id: TaskId::parse("merge-1").unwrap(),
            base_sha: None,
            head_sha: None,
            submitted_claims: vec![],
            justification: None,
            idempotency_key: Some(Uuid::nil()),
            approval_token: None,
            approved: None,
            critique: None,
            resolved_via_escalation: None,
            tokens_used: None,
            structured_output: None,
            sub_task_kind: None,
            parent_gate_failure_task_id: None,
            parent_gate_failure_type: None,
        };
        let bytes = bincode::serde::encode_to_vec(&req, bincode::config::standard())
            .expect("bincode encode");
        let (back, _): (IntentRequest, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("bincode decode");
        assert!(back.resolved_via_escalation.is_none());

        let v = serde_json::to_value(&req).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            obj.contains_key("resolved_via_escalation"),
            "JSON projection MUST surface `resolved_via_escalation` even \
             when None — operator UIs key off the field name, not serde \
             elision"
        );
        assert!(obj.get("resolved_via_escalation").unwrap().is_null());
    }

    /// V3 — `AddSubTask` is wire-stable through bincode + JSON.
    /// The three new optional fields (`sub_task_kind`,
    /// `parent_gate_failure_task_id`, `parent_gate_failure_type`)
    /// MUST round-trip through both canonical paths so audit replay
    /// and operator JSON projection agree on the value, including
    /// the `null` projection when the fields are absent (mirrors
    /// the analogous `approved` / `resolved_via_escalation` rules).
    /// See `specs/v3/gate-rejection-orchestrator-fixup.md` §4.3.
    #[test]
    fn v3_add_sub_task_round_trips_with_gate_fixup_payload() {
        use crate::TaskId;
        use uuid::Uuid;

        let parent = TaskId::parse("parent-merge-1").unwrap();
        let fixup = TaskId::parse("fixup-merge-1").unwrap();
        let req = IntentRequest {
            session_token: "tok".into(),
            sequence_number: 7,
            envelope_nonce: "a".repeat(32),
            intent_kind: IntentKind::AddSubTask,
            task_id: fixup.clone(),
            base_sha: None,
            head_sha: None,
            submitted_claims: vec![],
            justification: None,
            idempotency_key: Some(Uuid::nil()),
            approval_token: None,
            approved: None,
            critique: None,
            resolved_via_escalation: None,
            tokens_used: None,
            structured_output: None,
            sub_task_kind: Some(SubTaskKind::GateFixup),
            parent_gate_failure_task_id: Some(parent.clone()),
            parent_gate_failure_type: Some("NoSecretStrings".to_owned()),
        };

        // Canonical IPC wire — bincode.
        let bytes = bincode::serde::encode_to_vec(&req, bincode::config::standard())
            .expect("bincode encode");
        let (back, _): (IntentRequest, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("bincode decode");
        assert_eq!(back.intent_kind, IntentKind::AddSubTask);
        assert_eq!(back.sub_task_kind, Some(SubTaskKind::GateFixup));
        assert_eq!(back.parent_gate_failure_task_id.as_ref(), Some(&parent));
        assert_eq!(
            back.parent_gate_failure_type.as_deref(),
            Some("NoSecretStrings"),
        );

        // JSON projection — the new fields surface literally so
        // audit-replay UIs can match on key name without depending
        // on serde representation rules.
        let v = serde_json::to_value(&req).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "sub_task_kind",
            "parent_gate_failure_task_id",
            "parent_gate_failure_type",
        ] {
            assert!(
                obj.contains_key(key),
                "JSON projection MUST surface `{key}` for v3 AddSubTask"
            );
        }
        assert_eq!(
            obj.get("sub_task_kind").unwrap().as_str(),
            Some("GateFixup"),
            "SubTaskKind JSON form must be `GateFixup` (PascalCase \
             rename matches the rest of the V2 wire enums)",
        );
        assert_eq!(
            obj.get("parent_gate_failure_type").unwrap().as_str(),
            Some("NoSecretStrings"),
        );
    }

    /// `SubTaskKind` default is `Executor`. This is the reserved
    /// wire-default; an orchestrator that omits the field on an
    /// `AddSubTask` intent gets routed to the
    /// `kind = Executor` admit branch, which v3 rejects with
    /// `FAIL_POLICY_VIOLATION`. Pinned here so a future default
    /// flip is caught at unit-test layer.
    #[test]
    fn sub_task_kind_default_is_executor() {
        let k: SubTaskKind = SubTaskKind::default();
        assert_eq!(k, SubTaskKind::Executor);
    }

    /// `AddSubTask` is a V2 sub-task lifecycle kind (does not
    /// carry a SHA range, does not require justification, does
    /// not require approved). Pinned so the predicate set stays
    /// honest after the v3 addition.
    #[test]
    fn add_sub_task_predicates_match_lifecycle_layer() {
        let k = IntentKind::AddSubTask;
        assert!(!k.requires_sha_range());
        assert!(!k.requires_justification());
        assert!(!k.requires_approved());
        assert!(k.is_v2_subtask_kind());
    }
}
