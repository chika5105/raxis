//! Cross-crate contract witness — `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`.
//!
//! `kernel/` is a binary-only crate, so the FSM-level witness for the
//! auto-resume sweep itself lives as a `#[cfg(test)] mod
//! supervisor_auto_resume_witness` block inside `kernel/src/recovery.rs`
//! (the only place that has access to `recovery::reconcile_tasks` and
//! `reconcile_after_supervisor_restart`). This integration test pins
//! the *cross-crate* contract surface — the parts of the auto-resume
//! invariant that downstream tools (`raxis verify-chain`, the dashboard
//! kernel-glue layer, the policy notification router) match against.
//!
//! Specifically, this test asserts:
//!
//!   1. **Wire shape pinned.** `TaskAutoResumedAfterSupervisorRestart`
//!      serialises to a stable JSON envelope with the exact field set
//!      named in `self-healing-supervisor.md §3.5` —
//!      `task_id`, `initiative_id`, `prior_state`,
//!      `witness_count_preserved`, `supervisor_restart_id` — under
//!      the canonical `kind = "TaskAutoResumedAfterSupervisorRestart"`
//!      discriminant.
//!   2. **Notification routing pinned.** The audit-event-kind discriminant
//!      maps to `NotificationPriority::Medium` through both the
//!      enum-aware (`notification_priority`) and string-aware
//!      (`notification_priority_for_kind_str`) routing surfaces, so
//!      the dashboard inbox + the policy-router agree on a single
//!      classification regardless of which entry point the caller
//!      uses.
//!   3. **Policy lockstep.** The discriminant string appears in
//!      `raxis-policy::KNOWN_AUDIT_EVENT_KINDS`, so a `[notifications.routes]`
//!      block referring to `event_kind = "TaskAutoResumedAfterSupervisorRestart"`
//!      is accepted at policy-load time (vs. silently dropped as
//!      a typo per `cli-readonly.md §5.6.2`).
//!
//! The witness runs without spawning the kernel binary or seeding
//! any storage — it pins the wire-shape contracts that drift would
//! break downstream of `kernel/src/recovery.rs`.

#![cfg(test)]

use raxis_audit_tools::AuditEventKind;
use raxis_dashboard_kernel::notification_filter::{
    notification_priority, notification_priority_for_kind_str, NotificationPriority,
};

const KIND_STR: &str = "TaskAutoResumedAfterSupervisorRestart";

fn sample() -> AuditEventKind {
    AuditEventKind::TaskAutoResumedAfterSupervisorRestart {
        task_id: "task-abc".to_owned(),
        initiative_id: "init-xyz".to_owned(),
        prior_state: "Running".to_owned(),
        witness_count_preserved: 3,
        supervisor_restart_id: "supervisor-restart-1700000000-1".to_owned(),
    }
}

#[test]
fn wire_shape_pins_task_auto_resumed_envelope() {
    let kind = sample();

    assert_eq!(
        kind.as_str(),
        KIND_STR,
        "as_str() discriminant must be stable for verify-chain + dashboard parsers"
    );

    let v = serde_json::to_value(&kind).expect("audit kind must serialise");
    assert_eq!(v["kind"], serde_json::json!(KIND_STR));
    assert_eq!(v["task_id"], serde_json::json!("task-abc"));
    assert_eq!(v["initiative_id"], serde_json::json!("init-xyz"));
    assert_eq!(v["prior_state"], serde_json::json!("Running"));
    assert_eq!(v["witness_count_preserved"], serde_json::json!(3));
    assert_eq!(
        v["supervisor_restart_id"],
        serde_json::json!("supervisor-restart-1700000000-1")
    );
}

#[test]
fn auto_resume_notifies_at_medium_priority_via_both_routing_surfaces() {
    let kind = sample();
    assert_eq!(
        notification_priority(&kind),
        Some(NotificationPriority::Medium),
        "the typed path must classify auto-resume at Medium per \
         self-healing-supervisor.md §3.5"
    );
    assert_eq!(
        notification_priority_for_kind_str(KIND_STR),
        Some(NotificationPriority::Medium),
        "the string-aware path (used by the policy notification router) \
         MUST agree with the typed path so the dashboard inbox + the \
         policy router cannot disagree on classification"
    );
}

#[test]
fn auto_resume_kind_is_in_policy_known_audit_event_kinds() {
    assert!(
        raxis_policy::KNOWN_AUDIT_EVENT_KINDS.contains(&KIND_STR),
        "TaskAutoResumedAfterSupervisorRestart must be in \
         KNOWN_AUDIT_EVENT_KINDS so [notifications.routes] referring \
         to it parse cleanly (cli-readonly.md §5.6.2). Without this \
         entry, an operator's per-kind route would be silently \
         dropped as a typo."
    );
}
