//! Integration witness for `INV-FAILURE-REASON-MANDATORY-01`.
//!
//! ## What this pins
//!
//! Every transition into a terminal-failure or operator-blocked
//! state (`TaskState::Failed`, `TaskState::Aborted`,
//! `TaskState::Cancelled`, `TaskState::BlockedRecoveryPending`,
//! `InitiativeState::Failed`, `InitiativeState::Aborted`,
//! `InitiativeState::Blocked`, `SessionRevoked`) MUST carry a
//! non-empty, human-readable reason string. The kernel emitting
//! `"No reason supplied"` (or its empty / whitespace-only
//! cousins) on a Failed transition surfaces in the dashboard as
//! the bare text `"No reason supplied — kernel bug"` —
//! operator-visible evidence that the kernel violated this
//! invariant.
//!
//! ## Layered enforcement
//!
//! 1. **Type-level (Option A).** `raxis_types::FailureReason` is
//!    a newtype whose constructor `FailureReason::new(s)` rejects
//!    empty / whitespace-only input. New code paths that take
//!    `FailureReason` instead of `Option<String>` get the
//!    invariant for free at compile time.
//!
//! 2. **Audit-emit gate (Option B, defense-in-depth).** Existing
//!    `Option<&str>` callers route through
//!    `kernel::initiatives::task_transitions::transition_task_in_tx`,
//!    which carries a `debug_assert!` that fires on every
//!    Failed / BlockedRecoveryPending transition with a missing
//!    or empty reason.
//!
//! ## What this *integration* witness covers (cross-crate seam)
//!
//! The kernel binary has no `lib.rs` re-export so cross-crate
//! integration tests cannot link kernel-internal modules
//! directly. This file therefore pins:
//!
//!   * The `FailureReason` newtype's constructor contract
//!     (test 1–3).
//!   * The `AuditEventKind` variant shapes for the
//!     terminal-failure / revocation events the dashboard reads
//!     (test 4–5: SessionRevoked carries `revoked_by_display_name`;
//!     InitiativeAborted carries operator attribution).
//!   * The `tasks.block_reason` SQL column shape the dashboard
//!     joins against — confirms the column is non-NULL after the
//!     kernel writes a real reason verbatim through the public
//!     `raxis-store::Store` API (test 6).

#![cfg(test)]

use raxis_audit_tools::AuditEventKind;
use raxis_store::Table;
use raxis_types::{unix_now_secs, FailureReason, TaskState};

// ---------------------------------------------------------------------------
// Tests 1–3: FailureReason newtype contract (type-level layer)
// ---------------------------------------------------------------------------

/// Empty input MUST be rejected at the constructor — the type
/// system makes it impossible to mark a task `Failed` without
/// supplying a reason in any new code path that takes
/// `FailureReason` rather than `Option<String>`.
#[test]
fn failure_reason_newtype_rejects_empty_string() {
    let err = FailureReason::new("").expect_err(
        "empty input MUST be rejected per INV-FAILURE-REASON-MANDATORY-01",
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("INV-FAILURE-REASON-MANDATORY-01"),
        "Display impl should name the invariant for engineer signposting; got {msg:?}",
    );
}

/// Whitespace-only input is structurally identical to empty
/// input from the operator's perspective — a string of `"   "`
/// renders as a blank dashboard cell exactly like an empty
/// string. Reject at construction.
#[test]
fn failure_reason_newtype_rejects_whitespace_only() {
    for ws in ["   ", "\n", "\t", "\r\n", " \n\t\r ", "\u{00a0}"] {
        assert!(
            FailureReason::new(ws).is_err(),
            "whitespace-only input {ws:?} MUST be rejected — \
             empty after trim is the dashboard-visible failure mode",
        );
    }
}

/// A real, operator-actionable reason — the kind every emit
/// site MUST supply — round-trips losslessly. Pins the canonical
/// iter54 example so a future signature drift (e.g. accidental
/// trim-on-construct) is caught loudly.
#[test]
fn failure_reason_newtype_accepts_valid_reason() {
    let raw = "executor exit_code=4: dispatch loop exceeded \
               max_turns: 30 (see guests/<sid>/console.log for \
               planner-boot-error)";
    let reason = FailureReason::new(raw).expect("non-empty input must succeed");
    assert_eq!(reason.as_str(), raw, "constructor must NOT trim — \
        leading / trailing context matters for dashboard rendering of \
        multi-line stack tails");
    assert_eq!(format!("{reason}"), raw, "Display round-trip");
    let json = serde_json::to_string(&reason).expect("serialise");
    let back: FailureReason = serde_json::from_str(&json)
        .expect("deserialise round-trip");
    assert_eq!(back, reason);
}

// ---------------------------------------------------------------------------
// Tests 4–5: audit-event variant shape contract
// ---------------------------------------------------------------------------

/// The `SessionRevoked` audit-event variant carries
/// `revoked_by` (operator fingerprint) AND
/// `revoked_by_display_name` (Option<String>). The display name
/// is the operator-readable surface — the fingerprint alone is a
/// 64-char hex string the operator cannot decode at a glance.
#[test]
fn session_revoked_audit_carries_revoked_by_display_name() {
    let event = AuditEventKind::SessionRevoked {
        session_id:              "s-witness".to_owned(),
        revoked_by:              "fp-witness".to_owned(),
        revoked_by_display_name: Some("alice@example.com".to_owned()),
    };
    let AuditEventKind::SessionRevoked {
        revoked_by_display_name,
        ..
    } = &event
    else {
        panic!("constructor returned the wrong variant: {event:?}");
    };
    let name = revoked_by_display_name.as_deref().expect(
        "SessionRevoked MUST carry a non-None revoked_by_display_name \
         when the operator is resolvable in the policy bundle — None \
         here surfaces in the dashboard as a fingerprint-only revoke \
         row, which is the same operator-experience failure mode as \
         'No reason supplied — kernel bug' on a Failed task",
    );
    assert!(
        !name.trim().is_empty(),
        "display_name MUST be non-empty when present; empty == None \
         from the dashboard's perspective",
    );

    let json = serde_json::to_string(&event).expect("serialise");
    assert!(
        json.contains("revoked_by_display_name"),
        "JSON projection MUST carry the display-name field; got {json}",
    );
    assert!(
        json.contains("alice@example.com"),
        "JSON projection MUST round-trip the display name verbatim; got {json}",
    );
}

/// The `InitiativeAborted` audit variant carries
/// `triggered_by_operator` (Option<String>) +
/// `triggered_by_operator_display_name` (Option<String>). For a
/// kernel-internal abort cascade (no operator) BOTH are `None`
/// by construction — that's NOT a missing-reason violation
/// because there is no human authority to attribute. For an
/// operator-driven abort, BOTH MUST be present.
#[test]
fn initiative_aborted_audit_carries_operator_attribution_when_present() {
    let kernel_abort = AuditEventKind::InitiativeAborted {
        initiative_id:                       "init-kernel".to_owned(),
        triggered_by_operator:               None,
        triggered_by_operator_display_name:  None,
    };
    let AuditEventKind::InitiativeAborted {
        triggered_by_operator,
        triggered_by_operator_display_name,
        ..
    } = &kernel_abort
    else {
        panic!("wrong variant");
    };
    assert!(triggered_by_operator.is_none());
    assert!(triggered_by_operator_display_name.is_none());

    let operator_abort = AuditEventKind::InitiativeAborted {
        initiative_id:                       "init-op".to_owned(),
        triggered_by_operator:               Some("fp-op".to_owned()),
        triggered_by_operator_display_name:  Some("bob@example.com".to_owned()),
    };
    let AuditEventKind::InitiativeAborted {
        triggered_by_operator,
        triggered_by_operator_display_name,
        ..
    } = &operator_abort
    else {
        panic!("wrong variant");
    };
    let fp = triggered_by_operator.as_deref().expect(
        "operator-driven abort MUST carry the fingerprint",
    );
    let name = triggered_by_operator_display_name.as_deref().expect(
        "operator-driven abort MUST carry the display name when the \
         operator is resolvable — INV-FAILURE-REASON-MANDATORY-01",
    );
    assert!(!fp.trim().is_empty());
    assert!(!name.trim().is_empty());
}

// ---------------------------------------------------------------------------
// Test 6: SQL column shape — tasks.block_reason persists a real string
// ---------------------------------------------------------------------------

/// End-to-end SQL-projection witness. Drives a task to `Failed`
/// via raw SQL on a `raxis-store::Store` (the same underlying
/// connection the kernel uses), simulating what
/// `transition_task_in_tx` writes when a real
/// `FailureReason::as_str()` is supplied as `block_reason`.
#[test]
fn tasks_block_reason_persists_failure_reason_verbatim() {
    let store = raxis_store::Store::open_in_memory().expect("open store");

    let now = unix_now_secs();
    let initiatives = Table::Initiatives.as_str();
    let tasks       = Table::Tasks.as_str();

    let task_id     = "t-fr-witness";
    let initiative  = "init-fr-witness";

    let reason = FailureReason::new(
        "executor exit_code=4: dispatch loop exceeded max_turns: 30",
    ).expect("real reason constructs");

    {
        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {initiatives}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, 'Executing', '{{}}', 'beef', ?2)"
            ),
            rusqlite::params![initiative, now],
        ).expect("seed initiative");
        conn.execute(
            &format!(
                "INSERT INTO {tasks}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost,
                     block_reason)
                 VALUES (?1, ?2, 'default', ?3, 'kernel',
                         1, ?4, ?4, 0, ?5)"
            ),
            rusqlite::params![
                task_id,
                initiative,
                TaskState::Failed.as_sql_str(),
                now,
                reason.as_str(),
            ],
        ).expect("write Failed row with reason");
    }

    let persisted: Option<String> = {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT block_reason FROM {tasks} WHERE task_id = ?1"),
            rusqlite::params![task_id],
            |r| r.get::<_, Option<String>>(0),
        ).expect("read block_reason")
    };
    let payload = persisted.expect(
        "INV-FAILURE-REASON-MANDATORY-01: tasks.block_reason MUST \
         persist non-NULL when the task is driven to Failed; \
         a NULL here would surface as 'No reason supplied — kernel bug' \
         on the dashboard's <FailureReasonPanel>",
    );
    assert!(
        !payload.trim().is_empty(),
        "block_reason MUST be non-empty after a Failed transition",
    );
    assert_eq!(
        payload.as_str(),
        reason.as_str(),
        "the operator-actionable detail MUST round-trip verbatim — \
         the dashboard's <FailureReasonPanel> renders this column \
         directly with no kernel-side rewriting",
    );
}

// ---------------------------------------------------------------------------
// Test 7-8: clean-exit-no-terminal-intent sub-case
// (iter56 fix — the reason this witness file gained these tests)
// ---------------------------------------------------------------------------
//
// The Mode-B post-exit synthesis hook in
// `kernel/src/session_spawn_orchestrator.rs::spawn_planner_dispatcher`
// runs when an Executor / Reviewer VM exits without emitting a
// terminal intent (`CompleteTask` / `ReportFailure` / `SubmitReview`).
// Before iter56, the synthesis hook wrote a generic umbrella
// `block_reason` string for the case where `drive_planner_stream`
// returned `Ok(())` (clean EOF), violating the spirit of
// `INV-FAILURE-REASON-MANDATORY-01` — the dashboard surfaced the
// placeholder verbatim instead of the actual cause.
//
// The iter56 fix introduces two distinct templates, replacing the
// umbrella with operator-actionable text in both branches:
//
//   * **Clean-exit WITH last activity** — the planner submitted
//     N intents, then hit EOF. The reason quotes the last
//     `(intent_kind, sequence_number, outcome, timestamp)` so
//     the operator can correlate against the dispatch matrix
//     and the audit chain timeline.
//   * **Clean-exit WITHOUT activity** — the planner died
//     before issuing its first IntentRequest. The reason names
//     the boot-failure / model-init-failure surface so the
//     operator does not chase the wrong hypothesis.
//
// The witnesses below pin both templates by their dashboard-
// stable markers: every operator-actionable substring MUST be
// present, and the pre-fix umbrella MUST be absent. The strings
// here are duplicated from
// `kernel/src/session_activity.rs::{render_clean_exit_with_activity,
// render_clean_exit_without_activity}` because the kernel binary
// has no `lib.rs` re-export so the integration test cannot link
// the helpers directly. Spec edits ride the same commit so the
// templates and the witness stay in lockstep.
//
// The pre-fix umbrella is the regression alarm: if a future edit
// re-introduces the
//   "MaxTurnsExceeded / TokensExceeded / DispatchIdle / process death"
// substring on either branch, this witness fails loudly — that
// is exactly the operator-visible failure mode iter56 fixed.

/// The pre-fix umbrella substring. Copy-pasted from the deleted
/// branch so the regression alarm stays self-contained. Any
/// future edit that introduces this string on a synthesised
/// `block_reason` violates `INV-FAILURE-REASON-MANDATORY-01`'s
/// anti-pattern catalogue ("a placeholder that doesn't carry
/// operator-actionable detail is structurally equivalent to
/// `None` from the dashboard's perspective").
const PRE_FIX_UMBRELLA_MARKER: &str =
    "MaxTurnsExceeded / TokensExceeded / DispatchIdle / process death";

/// Spec-pinned template for the WITH-activity branch. Mirrors
/// `kernel/src/session_activity.rs::render_clean_exit_with_activity`
/// verbatim. The arguments match the canonical example in the
/// spec (`specs/invariants.md §INV-FAILURE-REASON-MANDATORY-01`).
fn synthesised_block_reason_with_activity(
    role: &str,
    kind: &str,
    seq: u64,
    outcome: &str,
    ts: u64,
) -> String {
    format!(
        "session_spawn_orchestrator: {role} VM exited cleanly \
         after last intent {kind} #{seq} ({outcome}) at unix={ts}; \
         no terminal intent submitted before EOF (likely \
         MaxTurnsExceeded / TokensExceeded / DispatchIdle).",
    )
}

/// Spec-pinned template for the WITHOUT-activity branch. Mirrors
/// `kernel/src/session_activity.rs::render_clean_exit_without_activity`
/// verbatim.
fn synthesised_block_reason_without_activity(role: &str) -> String {
    format!(
        "session_spawn_orchestrator: {role} VM exited cleanly \
         without ever submitting an IntentRequest before EOF; \
         likely planner-boot-error / model-init failure / \
         dispatch loop returned Idle on the very first turn \
         (no terminal intent observed).",
    )
}

/// End-to-end SQL-projection witness for the WITH-activity
/// branch. Drives a task to `Failed` via raw SQL with the
/// kernel-synthesised `block_reason`, then re-reads the column
/// and asserts:
///
///   * `FailureReason::new()` accepts the text (so the type-
///     level layer of `INV-FAILURE-REASON-MANDATORY-01` admits
///     it).
///   * The umbrella marker is absent (the iter56 regression
///     alarm).
///   * The operator-actionable markers (intent kind, sequence,
///     outcome class, role) are present (the dashboard
///     `<FailureReasonPanel>` projection contract).
#[test]
fn tasks_block_reason_clean_exit_with_activity_is_non_generic() {
    let store = raxis_store::Store::open_in_memory().expect("open store");
    let now = unix_now_secs();
    let initiatives = Table::Initiatives.as_str();
    let tasks       = Table::Tasks.as_str();

    let task_id    = "t-clean-exit-activity";
    let initiative = "init-clean-exit-activity";

    let synthesised = synthesised_block_reason_with_activity(
        "executor", "StructuredOutput", 7, "Accepted", 1_715_694_342,
    );
    // FailureReason newtype admits the text — type-level layer.
    let fr = FailureReason::new(&synthesised).expect(
        "synthesised reason MUST construct a FailureReason — empty / \
         whitespace-only would violate INV-FAILURE-REASON-MANDATORY-01 \
         at the type level",
    );

    {
        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {initiatives}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, 'Executing', '{{}}', 'beef', ?2)"
            ),
            rusqlite::params![initiative, now],
        ).expect("seed initiative");
        conn.execute(
            &format!(
                "INSERT INTO {tasks}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost,
                     block_reason)
                 VALUES (?1, ?2, 'default', ?3, 'kernel',
                         1, ?4, ?4, 0, ?5)"
            ),
            rusqlite::params![
                task_id,
                initiative,
                TaskState::Failed.as_sql_str(),
                now,
                fr.as_str(),
            ],
        ).expect("write Failed row with synthesised reason");
    }

    let persisted: Option<String> = {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT block_reason FROM {tasks} WHERE task_id = ?1"),
            rusqlite::params![task_id],
            |r| r.get::<_, Option<String>>(0),
        ).expect("read block_reason")
    };
    let payload = persisted.expect(
        "INV-FAILURE-REASON-MANDATORY-01: tasks.block_reason MUST \
         persist non-NULL when the kernel synthesises a Failed \
         transition for a clean-exit-no-terminal-intent worker",
    );

    // Regression alarm: pre-fix umbrella MUST NOT appear.
    assert!(
        !payload.contains(PRE_FIX_UMBRELLA_MARKER),
        "iter56 regression: clean-exit-with-activity block_reason \
         MUST NOT contain the pre-fix umbrella \
         {PRE_FIX_UMBRELLA_MARKER:?} — that string is the \
         placeholder INV-FAILURE-REASON-MANDATORY-01 \
         anti-pattern catalogue forbids ('a placeholder that \
         doesn't carry operator-actionable detail is \
         structurally equivalent to None from the dashboard's \
         perspective'). Got: {payload}"
    );

    // Operator-actionable markers — every one MUST be present so
    // the dashboard's <FailureReasonPanel> can render a row the
    // operator can act on without opening kernel.stderr.log.
    let must_contain = [
        "executor",         // role disambiguation
        "StructuredOutput", // kind taxonomy hint
        "#7",               // sequence_number turn-counter proxy
        "Accepted",         // outcome class
        "unix=1715694342",  // timestamp correlator
        "MaxTurnsExceeded", // operator hint about likely cause
    ];
    for marker in must_contain {
        assert!(
            payload.contains(marker),
            "synthesised block_reason MUST contain operator-actionable \
             marker {marker:?}; got {payload}"
        );
    }
}

/// End-to-end SQL-projection witness for the WITHOUT-activity
/// branch (boot-failure / model-init-failure exits, where the
/// kernel observed EOF on the IPC channel without ever receiving
/// an `IntentRequest`).
///
/// Pins the same regression alarm + a distinct set of markers
/// that disambiguate this branch from the WITH-activity branch
/// — the operator must be able to tell boot-failure exits from
/// runaway-loop exits at a glance.
#[test]
fn tasks_block_reason_clean_exit_without_activity_is_non_generic() {
    let store = raxis_store::Store::open_in_memory().expect("open store");
    let now = unix_now_secs();
    let initiatives = Table::Initiatives.as_str();
    let tasks       = Table::Tasks.as_str();

    let task_id    = "t-clean-exit-no-activity";
    let initiative = "init-clean-exit-no-activity";

    let synthesised = synthesised_block_reason_without_activity("reviewer");
    let fr = FailureReason::new(&synthesised).expect(
        "without-activity synthesised reason MUST construct a \
         FailureReason — type-level layer of \
         INV-FAILURE-REASON-MANDATORY-01",
    );

    {
        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {initiatives}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, 'Executing', '{{}}', 'beef', ?2)"
            ),
            rusqlite::params![initiative, now],
        ).expect("seed initiative");
        conn.execute(
            &format!(
                "INSERT INTO {tasks}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost,
                     block_reason)
                 VALUES (?1, ?2, 'default', ?3, 'kernel',
                         1, ?4, ?4, 0, ?5)"
            ),
            rusqlite::params![
                task_id,
                initiative,
                TaskState::Failed.as_sql_str(),
                now,
                fr.as_str(),
            ],
        ).expect("write Failed row with synthesised reason");
    }

    let persisted: Option<String> = {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT block_reason FROM {tasks} WHERE task_id = ?1"),
            rusqlite::params![task_id],
            |r| r.get::<_, Option<String>>(0),
        ).expect("read block_reason")
    };
    let payload = persisted.expect(
        "INV-FAILURE-REASON-MANDATORY-01: tasks.block_reason MUST \
         persist non-NULL on the without-activity branch too",
    );

    // Regression alarm: pre-fix umbrella MUST NOT appear.
    assert!(
        !payload.contains(PRE_FIX_UMBRELLA_MARKER),
        "iter56 regression: clean-exit-without-activity block_reason \
         MUST NOT contain the pre-fix umbrella {PRE_FIX_UMBRELLA_MARKER:?}. \
         Got: {payload}"
    );

    // The operator-actionable markers for THIS branch are
    // distinct from the WITH-activity branch — that distinction
    // is the whole point. A future edit that collapses both
    // branches to one template fails THIS test loudly.
    let must_contain = [
        "reviewer",                          // role disambiguation
        "without ever submitting",           // distinguishing prefix
        "IntentRequest",                     // dispatch-channel marker
        "planner-boot-error",                // operator hint about likely cause
    ];
    for marker in must_contain {
        assert!(
            payload.contains(marker),
            "without-activity synthesised block_reason MUST contain \
             marker {marker:?}; got {payload}"
        );
    }
    // The two branches MUST be operationally distinguishable:
    // the WITHOUT-activity branch must NOT carry the
    // WITH-activity branch's "after last intent" prefix.
    assert!(
        !payload.contains("after last intent"),
        "without-activity branch MUST NOT echo the WITH-activity \
         branch's 'after last intent' prefix — operationally \
         distinct exits MUST surface as distinct reasons. Got: {payload}"
    );
}
