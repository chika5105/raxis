//! Per-session planner-activity tracker — kernel-side observation
//! of the last `IntentRequest` each substrate-spawned planner
//! submitted before its IPC channel went to EOF.
//!
//! ## Why this module exists
//!
//! `INV-FAILURE-REASON-MANDATORY-01` mandates that every kernel-
//! synthesised terminal-failure transition carry an operator-
//! actionable, non-generic `block_reason` text. The Mode-B post-
//! exit synthesis hook in
//! [`crate::session_spawn_orchestrator::spawn_planner_dispatcher`]
//! already does the right thing when the planner-side dispatch
//! loop *errored* (`drive_planner_stream` returned `Err(_)`):
//! the dispatch error string is inlined verbatim into the
//! synthesised `tasks.block_reason`, so the dashboard's
//! `<FailureReasonPanel>` surfaces the actual planner-boot-error
//! / transport EOF / codec failure verbatim.
//!
//! The remaining gap closed by this module is the case where
//! `drive_planner_stream` returns `Ok(())` — i.e. the planner
//! submitted N intents and then dialed its IPC socket cleanly to
//! EOF — but never landed a *terminal* intent (`CompleteTask`,
//! `ReportFailure`, or `SubmitReview`). Pre-fix the synthesised
//! reason was the generic
//! `"executor VM exited without submitting a terminal intent
//! (MaxTurnsExceeded / TokensExceeded / DispatchIdle / process
//! death). Kernel synthesised Running → Failed so the orchestrator
//! can decide retry_subtask vs. settle Blocked."` placeholder
//! umbrella — which violates the spirit of
//! `INV-FAILURE-REASON-MANDATORY-01` (the dashboard's empty-
//! reason regression alarm fires identically for "kernel didn't
//! supply a reason" and "kernel supplied a reason that is
//! semantically equivalent to having none"; see the anti-pattern
//! catalogue in `specs/invariants.md
//! §INV-FAILURE-REASON-MANDATORY-01`).
//!
//! ## What this tracker records
//!
//! Per session_id (string from the `sessions.session_id`
//! column), the kernel keeps an in-memory `SessionActivity`:
//!
//!   * Last [`raxis_types::IntentKind`] the planner submitted.
//!   * The wire `sequence_number`.
//!   * Whether the kernel `Accepted` or `Rejected` the intent;
//!     when rejected, the stable [`raxis_types::PlannerErrorCode`]
//!     short string.
//!   * The unix-second timestamp at which the kernel finished
//!     handling the intent.
//!
//! The tracker is updated by
//! [`crate::ipc::server::drive_planner_stream`] on every
//! `IntentRequest` arm AFTER the kernel has produced a response —
//! so the recorded outcome reflects what the planner saw, not
//! merely what it asked for.
//!
//! When the post-exit hook needs to synthesise a failure reason
//! for a clean-EOF-without-terminal-intent session, it calls
//! [`SessionActivityTracker::take`] to consume the entry: the
//! description it weaves into `tasks.block_reason` quotes the
//! last activity (e.g. *"executor VM exited cleanly after last
//! intent StructuredOutput #7 (Accepted) at 1715694342 ; no
//! terminal intent submitted before exit (likely
//! MaxTurnsExceeded / TokensExceeded / DispatchIdle)"*) and the
//! entry is dropped because the session row was just revoked
//! and will not be reused. Sessions that exit cleanly *after*
//! a terminal intent never enter the post-exit synthesis arm
//! (the EarlyResponse dispatch on the terminal intent already
//! drove the FSM through its terminal transition); their
//! activity rows are unbounded but bounded by total active-
//! session count, which the kernel already gates at admission
//! time.
//!
//! ## Why a per-process in-memory map and not the SQL store
//!
//! 1. Activity is forensic, not authoritative — it never gates
//!    admission and a kernel restart that loses the map only
//!    means a post-restart synthesis path falls back to the
//!    pre-fix umbrella (which is still better than the panic
//!    case the SQL approach would risk on a write-during-
//!    teardown race).
//! 2. The post-exit hook reads the entry inside the same
//!    `tokio::task::spawn_blocking` closure that holds the
//!    SQLite write transaction; folding the tracker read into
//!    that closure is one extra `Mutex::lock()` rather than
//!    a SQL roundtrip.
//! 3. The map size is bounded by the number of active
//!    substrate-spawned VM sessions (single digits to low
//!    hundreds in production), so the `HashMap<String, _>`
//!    footprint is negligible.
//!
//! ## Cross-references
//!
//! * `specs/invariants.md §INV-FAILURE-REASON-MANDATORY-01` —
//!   the invariant this tracker exists to honour, including the
//!   clean-exit-no-terminal-intent sub-case description and the
//!   expected `block_reason` template.
//! * `specs/v2/audit-paired-writes.md §14.8` — non-nullability
//!   declaration for `TaskFailedOnWorkerPrematureExit::failure_reason`.
//! * `specs/v2/dashboard-hardening.md §5.5.1` — dashboard-side
//!   counterpart contract.

use std::collections::HashMap;
use std::sync::Mutex;

use raxis_types::{IntentKind, IntentOutcome};

/// Coarse outcome the kernel surfaced back to the planner for the
/// last observed `IntentRequest`. Stored as a small enum (rather
/// than the full [`raxis_types::IntentOutcome`]) because the
/// tracker only needs the operator-rendered short-form text and
/// the rejection error code; the budget snapshot and other
/// outcome fields are irrelevant to post-exit failure-reason
/// synthesis.
#[derive(Debug, Clone)]
pub enum LastIntentOutcome {
    Accepted,
    Rejected {
        /// The stable [`raxis_types::PlannerErrorCode`] wire
        /// string (e.g. `"FAIL_POLICY_VIOLATION"`,
        /// `"DEPENDENCY_NOT_MET"`) as projected by the type's
        /// `Display` impl. Inlined verbatim into the synthesised
        /// reason so the operator can correlate against the
        /// dispatch matrix.
        error_code: String,
    },
}

impl LastIntentOutcome {
    /// Project a fresh kernel response onto the tracker's coarse
    /// shape. The kernel's response variant carries the rich
    /// budget snapshot / approval-staleness flag / template
    /// detail; the tracker drops everything except the
    /// operator-rendered short form.
    pub fn from_response(outcome: &IntentOutcome) -> Self {
        match outcome {
            IntentOutcome::Accepted { .. } => Self::Accepted,
            IntentOutcome::Rejected { error_code, .. } => Self::Rejected {
                error_code: error_code.to_string(),
            },
            // V3 iter70 — envelope-level success for the batch
            // primitive. The operator-facing tracker only cares
            // about the envelope verdict (per-id outcomes are
            // surfaced via the dashboard's structured-log feed);
            // a partial-admission turn still counts as `Accepted`
            // at this layer so the operator's "last activity"
            // muscle memory remains stable.
            IntentOutcome::AcceptedBatch { .. } => Self::Accepted,
        }
    }

    /// Operator-facing short-form rendering used when weaving the
    /// last activity into a synthesised `block_reason`. Pinned
    /// so the dashboard surfaces a stable taxonomy and so a
    /// future tracker rename does not silently break operator
    /// muscle memory.
    pub fn as_short_str(&self) -> String {
        match self {
            Self::Accepted => "Accepted".to_owned(),
            Self::Rejected { error_code } => {
                format!("Rejected/{error_code}")
            }
        }
    }
}

/// One per-session activity record. Single-writer (the
/// `drive_planner_stream` task driving this session is exclusive
/// — substrates surrender exactly one per-VM kernel-side fd) so
/// the `HashMap`-internal `Mutex` is contended only between the
/// IPC arm writer and the post-exit-hook reader, which never
/// interleave (the reader runs after the writer's `loop` returned
/// and the session was revoked).
#[derive(Debug, Clone)]
pub struct SessionActivity {
    /// The kind of the last `IntentRequest` the planner dispatched.
    pub last_intent_kind: IntentKind,
    /// The wire `sequence_number` of that request — useful to the
    /// operator as a turn-counter proxy ("planner submitted 7
    /// intents before going quiet").
    pub last_intent_seq: u64,
    /// The kernel's response classification.
    pub last_intent_outcome: LastIntentOutcome,
    /// `unix_now_secs()` at the moment the kernel finished
    /// handling the intent (post-response-write). Inlined into
    /// the synthesised reason so the operator can correlate
    /// against the audit chain timeline. Type matches
    /// [`raxis_types::clock::unix_now_secs`] verbatim (`i64`,
    /// signed-epoch convention) so no cast is required at the
    /// emit site.
    pub recorded_at_unix: i64,
}

/// Kernel-wide per-session activity tracker.
///
/// Held inside [`crate::ipc::context::HandlerContext`] so every
/// IPC handler and the session-spawn orchestrator share one map.
/// Lookup keys are session_id strings (matching
/// `sessions.session_id`).
#[derive(Debug, Default)]
pub struct SessionActivityTracker {
    /// Single `Mutex<HashMap>` keeps the implementation minimal;
    /// production traffic on this path is one write per planner
    /// intent (typically a few dozen per session lifetime), so
    /// finer-grained sharding is not warranted. The `Mutex` is a
    /// `std::sync::Mutex` rather than `tokio::sync::Mutex`
    /// because every caller already runs on a blocking-friendly
    /// surface (the IPC arm holds it briefly between intent
    /// handling and the next frame read; the post-exit reader
    /// runs inside `spawn_blocking`).
    inner: Mutex<HashMap<String, SessionActivity>>,
}

impl SessionActivityTracker {
    /// Construct an empty tracker. Production wiring in
    /// [`crate::ipc::context::HandlerContext::new`] does this
    /// once at kernel boot; tests get a fresh tracker per
    /// fixture.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or replace) the last-activity entry for
    /// `session_id`. Called by `drive_planner_stream` after each
    /// `IntentRequest` round-trip completes. A poisoned mutex is
    /// silently ignored — this tracker is forensic and a stale
    /// entry on a poisoned lock is preferable to the kernel
    /// panicking on the planner-IPC hot path.
    pub fn record(&self, session_id: &str, activity: SessionActivity) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(session_id.to_owned(), activity);
        }
    }

    /// Consume the last-activity entry for `session_id`. Called by
    /// the Mode-B post-exit synthesis hook in
    /// [`crate::session_spawn_orchestrator`]. Returns `None` if
    /// the session never submitted an intent (e.g. a planner
    /// that died during model-init before its first
    /// `IntentRequest`); the synthesis hook surfaces that case
    /// with a distinct "no IntentRequest observed before EOF"
    /// reason so the operator can disambiguate
    /// MaxTurnsExceeded-class exits from boot-failure-class
    /// exits.
    pub fn take(&self, session_id: &str) -> Option<SessionActivity> {
        self.inner
            .lock()
            .ok()
            .and_then(|mut g| g.remove(session_id))
    }

    /// Test-only: peek the entry without consuming it. Production
    /// code MUST call `take` so a re-spawned session under the
    /// same id never inherits a predecessor's activity.
    #[cfg(test)]
    pub fn peek(&self, session_id: &str) -> Option<SessionActivity> {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.get(session_id).cloned())
    }

    /// **`INV-PLANNER-CLEAN-COMPLETION-MUST-NOT-WRAP-REJECTED-INTENT-01`
    /// (iter65)** — read the entry without consuming it. Used by
    /// the orchestrator post-exit hook
    /// (`session_spawn_orchestrator::spawn_planner_dispatcher`
    /// Mode A) which needs to inspect the most-recent intent
    /// outcome BEFORE the `SessionRevoked` audit emit so the
    /// `revoked_by` URN can distinguish a true clean disconnect
    /// from a "DirtyCompletion" — a planner that submitted a
    /// terminal tool, observed the kernel reject the intent
    /// (e.g. with `FailVmConcurrencyAtCap`), and called PowerOff
    /// anyway. The planner-side `PlannerExitOutcome` is
    /// `CleanCompletion { tool_name }` regardless of the kernel's
    /// response — the only authoritative reclassification source
    /// is the kernel-observed last intent status.
    ///
    /// Distinct from [`Self::take`] because Mode A still wants
    /// Mode B's downstream consumer (the worker premature-exit
    /// synthesiser) to see a non-empty entry on the same
    /// session_id; Mode A reads + Mode B takes is the canonical
    /// consumer order.
    pub fn get(&self, session_id: &str) -> Option<SessionActivity> {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.get(session_id).cloned())
    }
}

/// **`INV-PLANNER-CLEAN-COMPLETION-MUST-NOT-WRAP-REJECTED-INTENT-01`
/// (iter65)** — the kernel-side effective classification of a
/// planner exit, accounting for both the planner-shipped
/// `PlannerExitOutcome` (P3 signal) AND the kernel-observed last
/// IntentRequest outcome (P2 breadcrumb).
///
/// The planner driver in `crates/planner-core/src/driver.rs`
/// builds a `DriverOutcome::Completed` whenever the dispatch loop
/// fires a terminal tool, **regardless** of whether the kernel
/// accepted the matching `IntentRequest`. The audit chain pre-
/// iter65 carried this misclassification verbatim: a session that
/// observed `intent_response.status = "rejected"` (e.g.
/// `FailVmConcurrencyAtCap`) still surfaced as a `SessionRevoked`
/// with `revoked_by_display_name = "Planner self-exit (clean
/// disconnect, terminal_tool = activate_subtask)"`. Downstream
/// consumers (orchestrator NNSP counter, respawn classification,
/// operator-facing failure-reason synthesis) treated the
/// "CleanCompletion" claim as gospel and burned the no-progress
/// counter against capacity-pressure intents that the operator
/// never told the planner to retry.
///
/// This classifier folds the two signals together: the planner's
/// notice is "clean" only when the most-recent kernel-observed
/// IntentRequest was `Accepted`. A `Rejected` last intent
/// downgrades the exit to [`ExitCleanliness::Dirty`] regardless of
/// what the planner shipped.
#[derive(Debug, Clone)]
pub enum ExitCleanliness {
    /// Either:
    ///   * the planner shipped `CleanCompletion { tool_name }` AND
    ///     the kernel-observed last intent was `Accepted`, OR
    ///   * the planner did not ship a `CleanCompletion` notice
    ///     (the Mode-B premature-exit synthesiser handles that
    ///     case via the structured `PlannerExitOutcome` already).
    ///
    /// In both cases the orchestrator post-exit hook treats the
    /// exit as a normal clean disconnect.
    Clean,
    /// The planner shipped `CleanCompletion { tool_name }` but the
    /// kernel-observed last IntentRequest was `Rejected`. The
    /// planner exited "cleanly" only by walking off the cliff:
    /// the kernel told it the terminal tool's intent failed, and
    /// it called PowerOff anyway without the operator ever telling
    /// it to retry. Downstream signalling (the
    /// `SessionRevoked.revoked_by` URN, the orchestrator NNSP
    /// counter — `INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01`,
    /// respawn-decision logging) MUST treat this as Dirty so a
    /// forensic chain replay can distinguish "planner shipped a
    /// terminal intent that landed" from "planner shipped a
    /// terminal intent that the kernel refused".
    Dirty {
        /// The terminal tool name from the
        /// `PlannerExitOutcome::CleanCompletion`. Stamped into the
        /// `SessionRevoked.revoked_by_display_name` for forensic
        /// readers.
        tool_name: String,
        /// The stable [`raxis_types::PlannerErrorCode`] short
        /// string (e.g. `"FAIL_VM_CONCURRENCY_AT_CAP"`,
        /// `"FAIL_POLICY_VIOLATION"`) the kernel returned for
        /// the rejected last intent. Surfaces in the
        /// `revoked_by_display_name` and (per
        /// `INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01`)
        /// gates whether the orchestrator NNSP counter
        /// increments.
        last_rejection_code: String,
    },
}

impl ExitCleanliness {
    /// Whether the rejection error_code on a `Dirty` exit names a
    /// capacity-pressure surface (the orchestrator NNSP counter
    /// SHOULD NOT increment for these per
    /// `INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01`).
    /// Returns `false` for `Clean` exits.
    ///
    /// The closed lexicon below tracks
    /// `crates/types/src/error.rs::PlannerErrorCode` Display impl;
    /// every variant whose semantics are "the kernel's resource
    /// gate pushed back; retry after the gate clears" rather than
    /// "the planner's intent was structurally invalid" lands here.
    /// Adding a new capacity-class error code requires updating
    /// this list.
    pub fn is_capacity_pressure(&self) -> bool {
        match self {
            ExitCleanliness::Clean => false,
            ExitCleanliness::Dirty {
                last_rejection_code,
                ..
            } => is_capacity_pressure_code(last_rejection_code.as_str()),
        }
    }
}

/// `INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01`
/// — closed lexicon of [`raxis_types::PlannerErrorCode`] Display
/// strings that name capacity-pressure rejections. The orchestrator
/// no-progress respawn counter MUST NOT increment when the
/// just-exited session's last rejection lands in this set; a peer
/// initiative consuming the cap is back-pressure, not orchestrator
/// no-progress, and burning the NNSP ceiling against capacity
/// contention causes the kernel to mark a healthy initiative
/// `Failed` for a transient host-resource shortfall (the iter64
/// failure mode).
///
/// Adding a new capacity-class code requires updating the lexicon
/// here AND the matching test in
/// `kernel/src/session_spawn_orchestrator.rs::tests::nnsp_capacity_pressure*`.
pub fn is_capacity_pressure_code(code: &str) -> bool {
    matches!(
        code,
        "FAIL_VM_CONCURRENCY_AT_CAP"
            | "FailVmConcurrencyAtCap"
            | "FAIL_ADMISSION_QUEUE_FULL"
            | "FailAdmissionQueueFull"
    )
}

/// **`INV-PLANNER-CLEAN-COMPLETION-MUST-NOT-WRAP-REJECTED-INTENT-01`
/// (iter65)** — fold the planner-side
/// [`raxis_types::PlannerExitOutcome`] and the kernel-side
/// last-intent breadcrumb [`SessionActivity`] into the effective
/// [`ExitCleanliness`] classification.
///
/// The classifier returns [`ExitCleanliness::Clean`] when:
///   * the planner did not ship a `CleanCompletion` notice (Mode-B
///     handles non-clean exits via the structured notice itself),
///     OR
///   * the planner shipped `CleanCompletion` AND the most-recent
///     kernel-observed IntentRequest was `Accepted` (or the
///     activity tracker has no entry, which is itself a clean-
///     disconnect signal: the planner exited before submitting
///     any intent at all — see
///     `session_activity::render_clean_exit_without_activity`).
///
/// Returns [`ExitCleanliness::Dirty`] when the planner shipped
/// `CleanCompletion` but the most-recent kernel-observed
/// IntentRequest was `Rejected`. The dirty form carries the
/// terminal-tool name (for forensic display) and the rejection
/// error_code (which gates `INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01`).
pub fn classify_planner_exit(
    exit_notice: Option<&raxis_types::PlannerExitOutcome>,
    last_activity: Option<&SessionActivity>,
) -> ExitCleanliness {
    let Some(notice) = exit_notice else {
        return ExitCleanliness::Clean;
    };
    let raxis_types::PlannerExitOutcome::CleanCompletion { tool_name } = notice else {
        return ExitCleanliness::Clean;
    };
    match last_activity.map(|a| &a.last_intent_outcome) {
        Some(LastIntentOutcome::Rejected { error_code }) => ExitCleanliness::Dirty {
            tool_name: tool_name.clone(),
            last_rejection_code: error_code.clone(),
        },
        _ => ExitCleanliness::Clean,
    }
}

/// Operator-facing rendering of a captured activity, woven into
/// the Mode-B synthesised `block_reason` for the
/// clean-exit-no-terminal-intent sub-case of
/// `INV-FAILURE-REASON-MANDATORY-01` AND
/// `INV-FAILURE-REASON-CONCRETE-01`. Returns the dashboard-
/// stable text the spec pins.
///
/// Post-`INV-FAILURE-REASON-CONCRETE-01` template (canonical):
///
// SWEEP-IGNORE-BEGIN
/// ```text
/// session_spawn_orchestrator: <role> VM exited via clean EOF
/// after last intent <Kind> #<seq> (<outcome>) at unix=<ts>; no
/// terminal intent submitted and no PlannerExitNotice was
/// received before the socket closed. …
/// ```
// SWEEP-IGNORE-END
///
/// The pre-`INV-FAILURE-REASON-CONCRETE-01` form of this
/// template hedged with `(likely MaxTurnsExceeded /
/// TokensExceeded / DispatchIdle)` — that multi-option umbrella
/// is now forbidden (it is the iter56 regression baseline). The
/// helper names the missing exit-notice gap explicitly instead.
pub fn render_clean_exit_with_activity(role: &str, activity: &SessionActivity) -> String {
    // INV-FAILURE-REASON-CONCRETE-01 — this is the P2 activity-
    // tracker fallback used only when the planner did NOT ship an
    // `IpcMessage::PlannerExitNotice` (the P3 signal). The pre-
    // INV-FAILURE-REASON-CONCRETE-01 template hedged with
    // "(likely MaxTurnsExceeded / TokensExceeded / DispatchIdle)";
    // that umbrella is now forbidden. We instead NAME the gap
    // (no exit notice was received before EOF) and let the
    // operator correlate against the inlined last-intent
    // breadcrumb (`kind #seq (outcome) at unix=ts`) plus the
    // substrate's `SessionVmExited` event for the host-side exit
    // code — both of which carry concrete forensic detail.
    format!(
        "session_spawn_orchestrator: {role} VM exited via clean \
         EOF after last intent {kind} #{seq} ({outcome}) at \
         unix={ts}; no terminal intent submitted and no \
         PlannerExitNotice was received before the socket \
         closed. The planner driver emits an exit notice for \
         every documented exit shape (max_turns / max_tokens / \
         idle / explicit give-up / clean completion); the \
         absence of one here means the process was killed \
         BEFORE the driver's exit-notice emit could fire — \
         cross-correlate with the substrate's SessionVmExited \
         event for the host-side exit code.",
        role = role,
        kind = activity.last_intent_kind.as_str(),
        seq = activity.last_intent_seq,
        outcome = activity.last_intent_outcome.as_short_str(),
        ts = activity.recorded_at_unix,
    )
}

/// Operator-facing rendering for the no-activity case (the
/// kernel observed EOF on the IPC channel without ever
/// receiving an `IntentRequest`). Distinct from
/// `render_clean_exit_with_activity` so the operator can
/// disambiguate boot-failure exits (this branch) from
/// runaway-loop exits (the activity branch).
///
/// Post-`INV-FAILURE-REASON-CONCRETE-01` template (canonical):
///
/// ```text
/// session_spawn_orchestrator: <role> VM exited via clean EOF
/// without ever submitting an IntentRequest AND without
/// shipping a PlannerExitNotice — i.e. the planner process died
/// before its first model turn. …
/// ```
pub fn render_clean_exit_without_activity(role: &str) -> String {
    // INV-FAILURE-REASON-CONCRETE-01 — the boot-failure branch.
    // The kernel saw a clean EOF on the planner socket without
    // ever receiving an `IntentRequest` AND without a
    // `PlannerExitNotice`. Operationally this is a planner-boot
    // / model-init failure: the planner process died before its
    // first model turn (cold-start panic, model-init OOM,
    // missing `RAXIS_MODEL_ID`, etc.). We NAME this distinct
    // failure surface explicitly rather than hedging across
    // unrelated causes (e.g. the old "/ dispatch loop returned
    // Idle on the very first turn" tail was a stretch — that
    // case is handled by tier 1 via the planner's own
    // `IdleNoTerminalIntent` exit notice).
    format!(
        "session_spawn_orchestrator: {role} VM exited via clean \
         EOF without ever submitting an IntentRequest AND \
         without shipping a PlannerExitNotice — i.e. the planner \
         process died before its first model turn. This is the \
         planner-boot / model-init failure surface: cold-start \
         panic, model-init OOM (check the host cgroup \
         memory.peak), missing RAXIS_MODEL_ID / model-asset \
         lookup failure, or a substrate-level VM teardown during \
         boot. Cross-correlate with the substrate's \
         SessionVmExited audit event for the host-side exit \
         code and the planner stderr for a panic backtrace.",
        role = role,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn act(kind: IntentKind, seq: u64, accepted: bool) -> SessionActivity {
        SessionActivity {
            last_intent_kind: kind,
            last_intent_seq: seq,
            last_intent_outcome: if accepted {
                LastIntentOutcome::Accepted
            } else {
                LastIntentOutcome::Rejected {
                    error_code: "FAIL_POLICY_VIOLATION".to_owned(),
                }
            },
            recorded_at_unix: 1_715_694_342_i64,
        }
    }

    #[test]
    fn record_then_take_returns_last_value() {
        let t = SessionActivityTracker::new();
        t.record("s-1", act(IntentKind::StructuredOutput, 1, true));
        t.record("s-1", act(IntentKind::StructuredOutput, 2, true));
        let a = t.take("s-1").expect("entry should exist");
        assert_eq!(a.last_intent_seq, 2);
        assert!(t.peek("s-1").is_none(), "take must consume the entry");
    }

    #[test]
    fn take_missing_session_returns_none() {
        let t = SessionActivityTracker::new();
        assert!(t.take("s-never-recorded").is_none());
    }

    #[test]
    fn render_clean_exit_with_activity_inlines_kind_seq_outcome() {
        let a = act(IntentKind::StructuredOutput, 7, true);
        let s = render_clean_exit_with_activity("executor", &a);
        assert!(s.contains("executor"), "role inlined: {s}");
        assert!(s.contains("StructuredOutput"), "kind inlined: {s}");
        assert!(s.contains("#7"), "seq inlined:  {s}");
        assert!(s.contains("Accepted"), "outcome inlined: {s}");
        assert!(s.contains("unix=1715694342"), "timestamp inlined: {s}");
        // `INV-FAILURE-REASON-CONCRETE-01` — the multi-option
        // umbrella the iter56 P2 patch left behind must be
        // absent from this fallback as well.
        let lower = s.to_lowercase();
        assert!(
            !lower.contains("maxturnsexceeded / tokensexceeded / dispatchidle"),
            "must NOT echo any pre-fix umbrella — that string \
             is the regression alarm for INV-FAILURE-REASON-\
             CONCRETE-01: {s}"
        );
        assert!(
            !lower.contains("maxturnsexceeded"),
            "must NOT hedge with MaxTurnsExceeded — tier 1 \
             (PlannerExitNotice MaxTurnsReached) is the \
             concreteness source for that surface: {s}"
        );
        assert!(
            s.contains("PlannerExitNotice"),
            "must NAME the missing-notice gap concretely: {s}"
        );
    }

    #[test]
    fn render_clean_exit_with_rejected_outcome_inlines_error_code() {
        let a = act(IntentKind::SingleCommit, 3, false);
        let s = render_clean_exit_with_activity("executor", &a);
        assert!(
            s.contains("Rejected/FAIL_POLICY_VIOLATION"),
            "rejection error code MUST be inlined: {s}"
        );
    }

    /// `INV-PLANNER-CLEAN-COMPLETION-MUST-NOT-WRAP-REJECTED-INTENT-01`
    /// — `CleanCompletion` over an `Accepted` last intent reads
    /// as `Clean`. The orchestrator post-exit hook treats this
    /// as a normal clean disconnect.
    #[test]
    fn classify_clean_completion_with_accepted_last_intent_is_clean() {
        let activity = act(IntentKind::CompleteTask, 7, true);
        let notice = raxis_types::PlannerExitOutcome::CleanCompletion {
            tool_name: "task_complete".to_owned(),
        };
        match classify_planner_exit(Some(&notice), Some(&activity)) {
            ExitCleanliness::Clean => {}
            other => panic!(
                "CleanCompletion + Accepted last intent must classify as Clean; got {other:?}"
            ),
        }
    }

    /// `INV-PLANNER-CLEAN-COMPLETION-MUST-NOT-WRAP-REJECTED-INTENT-01`
    /// — the regression witness. `CleanCompletion` over a
    /// `Rejected` last intent reads as `Dirty`, carrying the
    /// terminal-tool name AND the rejection error_code so the
    /// kernel-side `SessionRevoked` emit + the orchestrator NNSP
    /// counter logic can disambiguate from a genuine clean
    /// disconnect.
    #[test]
    fn classify_clean_completion_with_rejected_last_intent_is_dirty() {
        let activity = SessionActivity {
            last_intent_kind: IntentKind::ActivateSubTask,
            last_intent_seq: 3,
            last_intent_outcome: LastIntentOutcome::Rejected {
                error_code: "FAIL_VM_CONCURRENCY_AT_CAP".to_owned(),
            },
            recorded_at_unix: 1_715_694_342_i64,
        };
        let notice = raxis_types::PlannerExitOutcome::CleanCompletion {
            tool_name: "activate_subtask".to_owned(),
        };
        let classification = classify_planner_exit(Some(&notice), Some(&activity));
        match &classification {
            ExitCleanliness::Dirty {
                tool_name,
                last_rejection_code,
            } => {
                assert_eq!(tool_name, "activate_subtask");
                assert_eq!(last_rejection_code, "FAIL_VM_CONCURRENCY_AT_CAP");
            }
            other => panic!(
                "CleanCompletion + Rejected last intent must classify as Dirty; got {other:?}",
            ),
        }
        assert!(
            classification.is_capacity_pressure(),
            "FAIL_VM_CONCURRENCY_AT_CAP must be classified as capacity-pressure \
             so INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01 \
             can short-circuit the NNSP increment",
        );
    }

    /// `INV-PLANNER-CLEAN-COMPLETION-MUST-NOT-WRAP-REJECTED-INTENT-01`
    /// — non-clean exit notices route through the Mode-B path
    /// regardless of last_activity; the classifier surfaces
    /// `Clean` so the orchestrator post-exit hook does not
    /// double-up the dirty signalling on top of the structured
    /// `MaxTurnsReached` / `MaxTokensReached` / etc. handling.
    #[test]
    fn classify_non_clean_completion_is_clean_regardless_of_activity() {
        let activity = SessionActivity {
            last_intent_kind: IntentKind::ActivateSubTask,
            last_intent_seq: 3,
            last_intent_outcome: LastIntentOutcome::Rejected {
                error_code: "FAIL_POLICY_VIOLATION".to_owned(),
            },
            recorded_at_unix: 1_715_694_342_i64,
        };
        let notice = raxis_types::PlannerExitOutcome::MaxTurnsReached {
            used: 60,
            limit: 60,
        };
        match classify_planner_exit(Some(&notice), Some(&activity)) {
            ExitCleanliness::Clean => {}
            other => {
                panic!("MaxTurnsReached must classify as Clean (Mode-B handles it); got {other:?}",)
            }
        }
    }

    /// Non-capacity rejection codes do NOT short-circuit the NNSP
    /// counter — only the closed-lexicon capacity codes per
    /// `INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01`.
    #[test]
    fn dirty_classification_with_policy_violation_is_not_capacity_pressure() {
        let activity = SessionActivity {
            last_intent_kind: IntentKind::ActivateSubTask,
            last_intent_seq: 3,
            last_intent_outcome: LastIntentOutcome::Rejected {
                error_code: "FAIL_POLICY_VIOLATION".to_owned(),
            },
            recorded_at_unix: 1_715_694_342_i64,
        };
        let notice = raxis_types::PlannerExitOutcome::CleanCompletion {
            tool_name: "activate_subtask".to_owned(),
        };
        let classification = classify_planner_exit(Some(&notice), Some(&activity));
        assert!(
            !classification.is_capacity_pressure(),
            "FAIL_POLICY_VIOLATION is structural — NNSP counter MUST \
             increment to surface it via the LogicalDeadlock auto-escalation",
        );
    }

    /// The closed lexicon — pinned per
    /// `INV-ORCHESTRATOR-NNSP-COUNTER-EXCLUDES-CAPACITY-PRESSURE-01`.
    /// Adding a new code requires updating both this test and the
    /// `is_capacity_pressure_code` body in lockstep.
    #[test]
    fn capacity_pressure_lexicon_pinned() {
        for c in [
            "FAIL_VM_CONCURRENCY_AT_CAP",
            "FailVmConcurrencyAtCap",
            "FAIL_ADMISSION_QUEUE_FULL",
            "FailAdmissionQueueFull",
        ] {
            assert!(
                is_capacity_pressure_code(c),
                "{c} must be capacity-pressure",
            );
        }
        for c in [
            "FAIL_POLICY_VIOLATION",
            "FAIL_DELEGATION_REQUIRED",
            "DEPENDENCY_NOT_MET",
            "",
        ] {
            assert!(
                !is_capacity_pressure_code(c),
                "{c} must NOT be capacity-pressure",
            );
        }
    }

    #[test]
    fn render_clean_exit_without_activity_distinguishes_boot_failure() {
        let s = render_clean_exit_without_activity("reviewer");
        assert!(s.contains("reviewer"), "role inlined: {s}");
        assert!(
            s.contains("without ever submitting an IntentRequest"),
            "no-activity case MUST be distinguished from the \
             with-activity case so operators can tell boot-failure \
             from runaway-loop exits: {s}"
        );
        assert!(
            s.contains("planner-boot"),
            "operator hint about likely cause MUST appear: {s}"
        );
        // `INV-FAILURE-REASON-CONCRETE-01` — the boot-failure
        // template MUST NOT hedge with multi-option umbrellas
        // (the pre-fix "/ dispatch loop returned Idle on the
        // very first turn" tail is gone — that case has its own
        // exit-notice variant).
        let lower = s.to_lowercase();
        assert!(
            !lower.contains("dispatch loop returned idle"),
            "must NOT hedge into the Idle-on-first-turn surface \
             — that case is handled by tier 1 via the planner's \
             IdleNoTerminalIntent exit notice: {s}"
        );
    }
}
