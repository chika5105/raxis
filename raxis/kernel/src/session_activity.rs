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
        }
    }

    /// Operator-facing short-form rendering used when weaving the
    /// last activity into a synthesised `block_reason`. Pinned
    /// so the dashboard surfaces a stable taxonomy and so a
    /// future tracker rename does not silently break operator
    /// muscle memory.
    pub fn as_short_str(&self) -> String {
        match self {
            Self::Accepted        => "Accepted".to_owned(),
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
    pub last_intent_kind:    IntentKind,
    /// The wire `sequence_number` of that request — useful to the
    /// operator as a turn-counter proxy ("planner submitted 7
    /// intents before going quiet").
    pub last_intent_seq:     u64,
    /// The kernel's response classification.
    pub last_intent_outcome: LastIntentOutcome,
    /// `unix_now_secs()` at the moment the kernel finished
    /// handling the intent (post-response-write). Inlined into
    /// the synthesised reason so the operator can correlate
    /// against the audit chain timeline. Type matches
    /// [`raxis_types::clock::unix_now_secs`] verbatim (`i64`,
    /// signed-epoch convention) so no cast is required at the
    /// emit site.
    pub recorded_at_unix:    i64,
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
        self.inner.lock().ok().and_then(|mut g| g.remove(session_id))
    }

    /// Test-only: peek the entry without consuming it. Production
    /// code MUST call `take` so a re-spawned session under the
    /// same id never inherits a predecessor's activity.
    #[cfg(test)]
    pub fn peek(&self, session_id: &str) -> Option<SessionActivity> {
        self.inner.lock().ok().and_then(|g| g.get(session_id).cloned())
    }
}

/// Operator-facing rendering of a captured activity, woven into
/// the Mode-B synthesised `block_reason` for the
/// clean-exit-no-terminal-intent sub-case of
/// `INV-FAILURE-REASON-MANDATORY-01`. Returns the dashboard-
/// stable text the spec pins.
///
/// Template (canonical):
///
/// ```text
/// session_spawn_orchestrator: <role> VM exited cleanly after
/// last intent <Kind> #<seq> (<outcome>) at unix=<ts>; no
/// terminal intent submitted before EOF (likely MaxTurnsExceeded
/// / TokensExceeded / DispatchIdle).
/// ```
///
/// Example:
///
/// ```text
/// session_spawn_orchestrator: executor VM exited cleanly after
/// last intent StructuredOutput #7 (Accepted) at unix=1715694342;
/// no terminal intent submitted before EOF (likely
/// MaxTurnsExceeded / TokensExceeded / DispatchIdle).
/// ```
pub fn render_clean_exit_with_activity(role: &str, activity: &SessionActivity) -> String {
    format!(
        "session_spawn_orchestrator: {role} VM exited cleanly \
         after last intent {kind} #{seq} ({outcome}) at unix={ts}; \
         no terminal intent submitted before EOF (likely \
         MaxTurnsExceeded / TokensExceeded / DispatchIdle).",
        role     = role,
        kind     = activity.last_intent_kind.as_str(),
        seq      = activity.last_intent_seq,
        outcome  = activity.last_intent_outcome.as_short_str(),
        ts       = activity.recorded_at_unix,
    )
}

/// Operator-facing rendering for the no-activity case (the
/// kernel observed EOF on the IPC channel without ever
/// receiving an `IntentRequest`). Distinct from
/// `render_clean_exit_with_activity` so the operator can
/// disambiguate boot-failure exits (this branch) from
/// MaxTurnsExceeded-class exits (the activity branch).
///
/// Template (canonical):
///
/// ```text
/// session_spawn_orchestrator: <role> VM exited cleanly without
/// ever submitting an IntentRequest before EOF; likely planner-
/// boot-error / model-init failure / dispatch loop returned Idle
/// on the very first turn (no terminal intent observed).
/// ```
pub fn render_clean_exit_without_activity(role: &str) -> String {
    format!(
        "session_spawn_orchestrator: {role} VM exited cleanly \
         without ever submitting an IntentRequest before EOF; \
         likely planner-boot-error / model-init failure / \
         dispatch loop returned Idle on the very first turn \
         (no terminal intent observed).",
        role = role,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn act(kind: IntentKind, seq: u64, accepted: bool) -> SessionActivity {
        SessionActivity {
            last_intent_kind: kind,
            last_intent_seq:  seq,
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
        assert!(s.contains("executor"),         "role inlined: {s}");
        assert!(s.contains("StructuredOutput"), "kind inlined: {s}");
        assert!(s.contains("#7"),               "seq inlined:  {s}");
        assert!(s.contains("Accepted"),         "outcome inlined: {s}");
        assert!(s.contains("unix=1715694342"),  "timestamp inlined: {s}");
        assert!(
            !s.contains("MaxTurnsExceeded / TokensExceeded / \
                         DispatchIdle / process death"),
            "must NOT echo the pre-fix umbrella verbatim — \
             that string is the regression alarm: {s}"
        );
        assert!(
            s.contains("MaxTurnsExceeded"),
            "operator hint about likely cause MUST appear: {s}"
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
            s.contains("planner-boot-error"),
            "operator hint about likely cause MUST appear: {s}"
        );
    }
}
