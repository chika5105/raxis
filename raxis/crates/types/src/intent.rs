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

    /// **V3 batch-admit primitive (iter70).** Orchestrator-only.
    /// Requests that the Kernel admit a SET of candidate sub-tasks
    /// in a single IPC round-trip. The Orchestrator passes a *set*
    /// of `task_id`s via [`IntentRequest::batch_task_ids`]; the Kernel:
    ///   1. evaluates each id independently against the same
    ///      admission gates the singular `ActivateSubTask` enforces
    ///      (plan-membership, FSM state, predecessor-completion,
    ///      `vm_image` alias, `can_delegate`),
    ///   2. filters down to the admissible subset,
    ///   3. sorts that subset by the **kernel-side** deterministic
    ///      policy `(admitted_at ASC, task_id ASC)` — the input
    ///      order is informational at best; the kernel decides
    ///      which candidates win the available headroom,
    ///   4. admits `min(admissible_count, concurrency_headroom)`
    ///      of them by re-using the SAME per-task admission
    ///      machinery the singular `ActivateSubTask` runs (no
    ///      duplicate FSM transition or SQL; INV-IPC-BATCH-REUSE-
    ///      SINGULAR-MACHINERY-01), and
    ///   5. returns a per-id [`BatchTaskResult`] for EVERY
    ///      submitted id so the LLM learns exactly what happened
    ///      to each candidate (Accepted / DroppedAtCap /
    ///      NotAdmissible / UnknownTask / DuplicateInBatch).
    /// Wire fields used:
    ///   * `batch_task_ids` — required `Some(non-empty)`; capped
    ///     at [`MAX_BATCH_ACTIVATE_TASK_IDS`] (defense-in-depth
    ///     bound). `task_id` on the envelope MUST equal the
    ///     Orchestrator's own task id (same convention as
    ///     singular `ActivateSubTask`: envelope identifies the
    ///     SUBMITTER; the payload field carries the targets).
    /// Outcome variant: [`IntentOutcome::AcceptedBatch`]. The
    /// kernel returns `Rejected{FailInvalidArgument}` ONLY for
    /// envelope-malformed cases (`batch_task_ids = None | Some([])`,
    /// oversize, role mismatch); per-id classification failures
    /// (typo → `UnknownTask`, wrong-state → `NotAdmissible`,
    /// repeated id → `DuplicateInBatch`) surface inside
    /// `BatchTaskResult::outcome` so a single bad id never
    /// poisons a batch with otherwise-valid ids.
    BatchActivateSubTasks,
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
            Self::BatchActivateSubTasks => "BatchActivateSubTasks",
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
    pub fn is_v2_subtask_kind(self) -> bool {
        matches!(
            self,
            Self::ActivateSubTask
                | Self::RetrySubTask
                | Self::SubmitReview
                | Self::BatchActivateSubTasks
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
        Self::BatchActivateSubTasks,
    ];
}

/// Defense-in-depth ceiling on the number of candidate task ids a
/// single [`IntentKind::BatchActivateSubTasks`] envelope may carry.
/// The bound exists so a malicious or hallucinating orchestrator
/// cannot DoS the kernel by emitting a single batch envelope listing
/// every task in a 10 000-task plan; the per-task admission machinery
/// is `O(N)` SQL + `O(N)` substrate spawns, and the kernel's
/// concurrency cap is small (default 3, max 20). 64 is generous for
/// any realistic plan while keeping the per-batch work bounded.
/// Exceeding this returns `FAIL_INVALID_ARGUMENT` at the
/// envelope-validation gate — the Orchestrator must resubmit a
/// trimmed set.
pub const MAX_BATCH_ACTIVATE_TASK_IDS: usize = 64;

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
    /// Kernel-issued session credential. Session-bound VM planners
    /// send this empty; the host dispatcher stamps the canonical
    /// DB token before the request reaches admission.
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

    // ── V3 iter70 BatchActivateSubTasks payload ────────────────────────
    /// **V3 BatchActivateSubTasks only (iter70).** The candidate
    /// SET of sub-task ids the orchestrator proposes for admission
    /// in this turn. The kernel evaluates each id independently
    /// against the same admission gates as singular
    /// `ActivateSubTask`, sorts the admissible subset by its own
    /// deterministic policy `(admitted_at ASC, task_id ASC)`, and
    /// admits up to the live concurrency headroom. Per-id outcomes
    /// (Accepted / DroppedAtCap / NotAdmissible / UnknownTask /
    /// DuplicateInBatch) surface on
    /// [`IntentOutcome::AcceptedBatch::results`].
    /// Required `Some(non-empty)` on `BatchActivateSubTasks`;
    /// `None | Some([])` ⇒ `FAIL_INVALID_ARGUMENT`. MUST be `None`
    /// for every other intent kind (kernel ignores otherwise). The
    /// list is capped at [`MAX_BATCH_ACTIVATE_TASK_IDS`].
    /// **Order semantics:** the input ordering is informational
    /// only; the kernel ignores it. See [`IntentKind::BatchActivateSubTasks`].
    /// **Wire encoding note:** see the analogous comment on
    /// `approved` — `skip_serializing_if` is intentionally absent
    /// for bincode round-trip compatibility.
    #[serde(default)]
    pub batch_task_ids: Option<Vec<TaskId>>,
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
    /// **V3 iter70.** Successful envelope for
    /// [`IntentKind::BatchActivateSubTasks`]: the envelope itself was
    /// well-formed (non-empty, under [`MAX_BATCH_ACTIVATE_TASK_IDS`],
    /// authorised submitter); per-id outcomes are reported inside
    /// `results`. NOTE: an envelope where every id ended up as
    /// `UnknownTask` / `NotAdmissible` / `DroppedAtCap` is STILL
    /// `AcceptedBatch` — the wire-level success means "kernel evaluated
    /// the batch"; per-id `Accepted` vs. non-`Accepted` is the
    /// task-level decision. The planner-core driver MAY treat a
    /// zero-`Accepted` batch as a no-progress turn for its own
    /// retry book-keeping.
    AcceptedBatch {
        /// Lane budget snapshot AFTER all admitted-this-batch
        /// budget consumption. Same accounting as the singular
        /// `Accepted::remaining_budget`; each per-id `Accepted`
        /// charged its lane independently and this snapshot is
        /// the orchestrator-lane post-state.
        remaining_budget: BudgetSnapshot,
        /// One entry per id in the submitted `batch_task_ids`,
        /// in the SAME order the orchestrator submitted them
        /// (so a downstream tool wrapper can 1:1 zip the
        /// outcomes back to its own input vector).
        results: Vec<BatchTaskResult>,
    },
}

impl IntentResponse {
    /// Convenience: was this intent accepted?
    /// `AcceptedBatch` counts as accepted at the envelope level
    /// (per-id outcomes are inspected on
    /// [`IntentOutcome::AcceptedBatch::results`]).
    pub fn is_accepted(&self) -> bool {
        matches!(
            self.outcome,
            IntentOutcome::Accepted { .. } | IntentOutcome::AcceptedBatch { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// BatchTaskResult / BatchTaskOutcome / NotAdmissibleReason
// V3 iter70 — per-id outcome carried on
// `IntentOutcome::AcceptedBatch::results`.
// ---------------------------------------------------------------------------

/// Per-id outcome the kernel reports on the BatchActivateSubTasks
/// response. Returned in input order so the tool-call wrapper can
/// reconcile each candidate with its outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTaskResult {
    /// The candidate task id the orchestrator submitted at this
    /// position in `batch_task_ids`. Echoed verbatim — including
    /// for `UnknownTask` outcomes — so the tool-call layer can
    /// emit a structured per-id log entry without needing to
    /// re-derive the id from its own input.
    pub task_id: TaskId,
    /// Classification of what the kernel did for this id.
    pub outcome: BatchTaskOutcome,
}

/// Per-id classification on a BatchActivateSubTasks response.
///
/// **Status taxonomy:**
///   * `Accepted` — kernel ran the SAME per-task admission
///     machinery as singular `ActivateSubTask` and the task was
///     admitted-and-spawned this turn. `admission_order` is the
///     0-based slot within this batch's admitted list (so the
///     orchestrator can see which of its candidates won the
///     scarce headroom).
///   * `DroppedAtCap` — the task was admissible under every
///     gate, but the concurrency headroom was already filled
///     by higher-priority (kernel-sorted) candidates from the
///     same batch. The orchestrator may resubmit this id on a
///     future turn after a worker completes.
///   * `NotAdmissible` — the task is in the plan and belongs
///     to this initiative, but is not currently eligible
///     (wrong FSM state, predecessor not complete, etc.).
///     The reason is sub-classified in `NotAdmissibleReason`.
///   * `UnknownTask` — typo / hallucination: the id does not
///     map to any task in this initiative's plan registry. NOT
///     an envelope-level reject (so a batch of `[bad, good]`
///     still admits `good`).
///   * `DuplicateInBatch` — the orchestrator listed the same
///     id twice (or more) in the same `batch_task_ids`. The
///     FIRST occurrence is evaluated normally; subsequent
///     occurrences emit `DuplicateInBatch` so the orchestrator
///     can tell its own deduplication is broken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BatchTaskOutcome {
    Accepted {
        /// 0-based admission slot within this batch. `0` is the
        /// first admitted in kernel-sorted order; equals
        /// `results.iter().filter(|r| matches!(r.outcome,
        /// Accepted { .. })).count() - 1` for the LAST admitted
        /// id, etc.
        admission_order: u32,
    },
    DroppedAtCap,
    NotAdmissible {
        reason: NotAdmissibleReason,
    },
    UnknownTask,
    DuplicateInBatch,
}

/// Detail enum for `BatchTaskOutcome::NotAdmissible`. The
/// orchestrator's NNSP teaches the LLM to inspect this so it can
/// pick a different candidate on its next turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotAdmissibleReason {
    /// The task's FSM state is not `Admitted` (it is
    /// already running, completed, failed, or in some other
    /// non-admittable state). The string captures the observed
    /// state for forensic clarity (e.g. `"Running"`,
    /// `"Completed"`, `"PendingActivation"`).
    WrongState { observed: String },
    /// One or more DAG predecessors are not `Completed`. The
    /// list carries `(predecessor_task_id, observed_state)` for
    /// each blocker so the orchestrator can decide which
    /// predecessor to drive next.
    PredecessorsNotComplete { predecessors: Vec<(String, String)> },
    /// The task row is missing the in-memory plan registry entry
    /// the activation path needs (typed agent kind, vm_image
    /// alias, task prompt). Should be impossible in practice
    /// — surfaced as defense-in-depth so a corrupt registry
    /// row does not silently propagate as `UnknownTask`.
    PlanRegistryMissing,
    /// The task has a prior `subtask_activations` row that is
    /// neither `PendingActivation` nor terminal — i.e. it is
    /// already running through the singular path. The
    /// orchestrator should wait for that activation to settle
    /// rather than retry through batch.
    AlreadyActive,
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

    /// V3 (iter72) has 9 IntentKind variants total:
    ///   * 4 V1 — SingleCommit, IntegrationMerge, CompleteTask,
    ///     ReportFailure.
    ///   * 3 V2 — ActivateSubTask, RetrySubTask, SubmitReview.
    ///   * 1 V2.5 — `StructuredOutput`.
    ///   * 1 V3 iter70 — `BatchActivateSubTasks` (batch-admit
    ///     primitive; the kernel selects which candidates win
    ///     the scarce concurrency headroom and reports per-id
    ///     outcomes back to the orchestrator).
    ///
    /// iter72 removed `AddSubTask` (V3 `kind:GateFixup` carrier).
    /// The kernel now admits gate-fixup tasks directly from the
    /// witness handler via `crate::gate_fixup::auto_admit_gate_fixup_task`
    /// — no orchestrator-mediated wire intent needed.
    ///
    /// The pinned-count test surfaces accidental adds at the test
    /// layer before any dispatch matrix or store mapping regresses.
    #[test]
    fn intent_kind_variant_count_is_pinned_to_v3() {
        assert_eq!(
            IntentKind::ALL.len(),
            9,
            "V3 (iter72) has exactly 9 IntentKind variants \
             (4 V1: SingleCommit, IntegrationMerge, CompleteTask, \
             ReportFailure; 3 V2: ActivateSubTask, RetrySubTask, \
             SubmitReview; 1 V2.5: StructuredOutput; \
             1 V3 iter70: BatchActivateSubTasks). Bumping this \
             requires the static dispatch matrix (v2-deep-spec.md \
             §Step 20) to gain a matching row. AddSubTask was \
             removed in iter72 — gate-fixup spawn is now kernel-\
             authoritative (`gate_fixup::auto_admit_gate_fixup_task`)."
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
        assert_eq!(
            IntentKind::BatchActivateSubTasks.as_str(),
            "BatchActivateSubTasks"
        );
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
            batch_task_ids: None,
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
            batch_task_ids: None,
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
            batch_task_ids: None,
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
            batch_task_ids: None,
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

    /// **V3 iter70.** `BatchActivateSubTasks` is a sub-task
    /// lifecycle kind that wraps a SET of singular activations.
    /// Carries no SHA range, no justification, no approved
    /// — same predicate shape as singular `ActivateSubTask`.
    /// Pinned here so a future widening of the wire shape does
    /// not silently change the predicate matrix the kernel
    /// dispatch layer reads.
    #[test]
    fn batch_activate_sub_tasks_predicates_match_lifecycle_layer() {
        let k = IntentKind::BatchActivateSubTasks;
        assert!(!k.requires_sha_range());
        assert!(!k.requires_justification());
        assert!(!k.requires_approved());
        assert!(k.is_v2_subtask_kind());
    }

    /// **V3 iter70.** Wire round-trip for a
    /// `BatchActivateSubTasks` envelope: bincode encode +
    /// decode preserves `batch_task_ids` exactly, and the JSON
    /// projection exposes the field for audit-replay UIs.
    #[test]
    fn v3_batch_activate_sub_tasks_round_trips_with_candidate_set() {
        use crate::TaskId;
        use uuid::Uuid;

        let id_a = TaskId::parse("dep-fetch-evidence").unwrap();
        let id_b = TaskId::parse("materialize-records").unwrap();
        let id_c = TaskId::parse("lint-defect").unwrap();
        let owner = TaskId::parse("orchestrator-root").unwrap();
        let req = IntentRequest {
            session_token: "tok".into(),
            sequence_number: 11,
            envelope_nonce: "b".repeat(32),
            intent_kind: IntentKind::BatchActivateSubTasks,
            task_id: owner.clone(),
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
            batch_task_ids: Some(vec![id_a.clone(), id_b.clone(), id_c.clone()]),
        };

        // Canonical IPC wire — bincode.
        let bytes = bincode::serde::encode_to_vec(&req, bincode::config::standard())
            .expect("bincode encode");
        let (back, _): (IntentRequest, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("bincode decode");
        assert_eq!(back.intent_kind, IntentKind::BatchActivateSubTasks);
        let back_ids = back
            .batch_task_ids
            .as_ref()
            .expect("batch_task_ids preserved");
        assert_eq!(back_ids.len(), 3);
        assert_eq!(back_ids[0], id_a);
        assert_eq!(back_ids[1], id_b);
        assert_eq!(back_ids[2], id_c);

        // JSON projection — `batch_task_ids` surfaces literally.
        let v = serde_json::to_value(&req).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            obj.contains_key("batch_task_ids"),
            "JSON projection MUST surface `batch_task_ids` for v3 iter70"
        );
    }

    /// **V3 iter70.** `IntentOutcome::AcceptedBatch` carries a
    /// per-id result vector — pin the round-trip so a future
    /// variant change is caught at unit-test layer.
    #[test]
    fn v3_intent_outcome_accepted_batch_round_trips() {
        use crate::TaskId;

        let outcome = IntentOutcome::AcceptedBatch {
            remaining_budget: BudgetSnapshot {
                admission_units: 42,
            },
            results: vec![
                BatchTaskResult {
                    task_id: TaskId::parse("good-task").unwrap(),
                    outcome: BatchTaskOutcome::Accepted { admission_order: 0 },
                },
                BatchTaskResult {
                    task_id: TaskId::parse("typo-task").unwrap(),
                    outcome: BatchTaskOutcome::UnknownTask,
                },
                BatchTaskResult {
                    task_id: TaskId::parse("at-cap-task").unwrap(),
                    outcome: BatchTaskOutcome::DroppedAtCap,
                },
                BatchTaskResult {
                    task_id: TaskId::parse("dup-task").unwrap(),
                    outcome: BatchTaskOutcome::DuplicateInBatch,
                },
                BatchTaskResult {
                    task_id: TaskId::parse("pred-pending-task").unwrap(),
                    outcome: BatchTaskOutcome::NotAdmissible {
                        reason: NotAdmissibleReason::PredecessorsNotComplete {
                            predecessors: vec![("upstream".to_owned(), "Admitted".to_owned())],
                        },
                    },
                },
            ],
        };
        let bytes = bincode::serde::encode_to_vec(&outcome, bincode::config::standard()).unwrap();
        let (back, _): (IntentOutcome, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        let results = match back {
            IntentOutcome::AcceptedBatch { results, .. } => results,
            other => panic!("expected AcceptedBatch, got {other:?}"),
        };
        assert_eq!(results.len(), 5);
        assert!(matches!(
            results[0].outcome,
            BatchTaskOutcome::Accepted { admission_order: 0 }
        ));
        assert!(matches!(results[1].outcome, BatchTaskOutcome::UnknownTask));
        assert!(matches!(results[2].outcome, BatchTaskOutcome::DroppedAtCap));
        assert!(matches!(
            results[3].outcome,
            BatchTaskOutcome::DuplicateInBatch
        ));
        match &results[4].outcome {
            BatchTaskOutcome::NotAdmissible {
                reason: NotAdmissibleReason::PredecessorsNotComplete { predecessors },
            } => {
                assert_eq!(predecessors.len(), 1);
                assert_eq!(predecessors[0].0, "upstream");
                assert_eq!(predecessors[0].1, "Admitted");
            }
            other => panic!("expected PredecessorsNotComplete, got {other:?}"),
        }
    }

    /// **V3 iter70.** The defense-in-depth ceiling on batch
    /// size is `MAX_BATCH_ACTIVATE_TASK_IDS = 64`. Pinned so a
    /// future widening of the wire shape is a deliberate
    /// matrix-update, not an accidental drift.
    #[test]
    fn max_batch_activate_task_ids_pin() {
        assert_eq!(MAX_BATCH_ACTIVATE_TASK_IDS, 64);
    }
}
