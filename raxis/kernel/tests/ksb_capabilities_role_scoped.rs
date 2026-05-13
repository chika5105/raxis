//! Integration witness for `INV-KSB-CAPABILITIES-ROLE-SCOPED-01`.
//!
//! ## What this pins
//!
//! Each role's KSB MUST carry ONLY capabilities relevant to its
//! decision surface:
//!
//!   * **Orchestrator**: per-session + per-initiative respawn
//!     budget + per-task admit-predicate verdicts (the only role
//!     authorised to issue `RetrySubTask`).
//!   * **Executor**: per-session + the SINGLE assigned task. Does
//!     NOT carry orchestrator's respawn counter or peer-task review
//!     trajectories.
//!   * **Reviewer**: per-session + the artifact under review
//!     (identity only, no counters). The reviewer's verdict MUST
//!     be on the artifact, not on the executor's prior trajectory.
//!
//! Slice C enforces this at the type level — the [`raxis_ksb::
//! Capabilities`] enum has three disjoint variants whose field
//! sets cannot accidentally cross-pollinate. This witness pins the
//! contract on the **wire shape**: when a role's capabilities
//! envelope is JSON-serialised (the form the driver-side code
//! deserialises), forbidden fields MUST NOT appear and required
//! fields MUST appear. A regression where an enum variant grows
//! a field cross-cutting the role boundary surfaces here as a
//! serialised key the witness explicitly forbids.

#![cfg(test)]

use raxis_ksb::{
    Capabilities, ExecutorCapabilities, InitiativeCapabilityView,
    OrchestratorCapabilities, ReviewerCapabilities, SessionCapabilityView,
    TaskCapabilityView,
};

fn sample_session(role: &str) -> SessionCapabilityView {
    SessionCapabilityView {
        session_id: format!("ses-{role}"),
        role:       role.to_owned(),
    }
}

fn sample_task_view(task_id: &str) -> TaskCapabilityView {
    TaskCapabilityView {
        task_id:                  task_id.to_owned(),
        crash_retry_count:        1,
        review_reject_count:      1,
        max_crash_retries:        3,
        max_review_rejections:    2,
        crash_retries_remaining:  2,
        review_retries_remaining: 1,
        retry_admissible:         true,
        retry_inadmissible_reason: None,
    }
}

/// Orchestrator envelope MUST carry initiative + tasks; serialised
/// `role` discriminant MUST be `"orchestrator"`.
#[test]
fn orchestrator_envelope_carries_initiative_and_tasks() {
    let env = Capabilities::Orchestrator(OrchestratorCapabilities {
        session:    sample_session("orchestrator"),
        initiative: InitiativeCapabilityView {
            initiative_id:                          "init-1".to_owned(),
            orchestrator_no_progress_respawn_count: 1,
            max_orchestrator_no_progress_respawns:  3,
            orchestrator_respawns_remaining:        2,
        },
        tasks:      vec![sample_task_view("task-a"), sample_task_view("task-b")],
    });
    let json = serde_json::to_value(&env).expect("orchestrator serialise");
    assert_eq!(json["role"], "orchestrator",
        "orchestrator envelope MUST tag role=orchestrator on the wire");
    assert!(json.get("initiative").is_some(),
        "orchestrator envelope MUST include initiative view");
    assert!(json.get("tasks").is_some(),
        "orchestrator envelope MUST include tasks array");
    assert!(json.get("session").is_some(),
        "orchestrator envelope MUST include session view");

    // The executor's single `task` field and the reviewer's
    // `artifact_task_id` field MUST NOT appear in the orchestrator
    // shape (those are role-bound to the other variants).
    assert!(json.get("task").is_none(),
        "orchestrator envelope MUST NOT carry executor's `task` field");
    assert!(json.get("artifact_task_id").is_none(),
        "orchestrator envelope MUST NOT carry reviewer's `artifact_task_id` field");
}

/// Executor envelope MUST carry exactly ONE task and MUST NOT
/// surface the orchestrator's per-initiative respawn counter or
/// peer-task views (cross-DAG visibility leak protection).
#[test]
fn executor_envelope_omits_orchestrator_and_peer_state() {
    let env = Capabilities::Executor(ExecutorCapabilities {
        session: sample_session("executor"),
        task:    sample_task_view("task-self"),
    });
    let json = serde_json::to_value(&env).expect("executor serialise");
    assert_eq!(json["role"], "executor");
    assert!(json.get("task").is_some(),
        "executor envelope MUST carry the single assigned task");
    assert!(json.get("session").is_some());

    assert!(json.get("initiative").is_none(),
        "executor envelope MUST NOT surface orchestrator's per-initiative \
         respawn counter (slice C role-scope contract)");
    assert!(json.get("tasks").is_none(),
        "executor envelope MUST NOT carry the per-initiative tasks list \
         (cross-DAG visibility leak)");
    assert!(json.get("artifact_task_id").is_none(),
        "executor envelope MUST NOT carry reviewer's artifact pointer");
}

/// Reviewer envelope MUST carry session + artifact identity ONLY.
/// Counters (crash_retry_count, review_reject_count) MUST NOT appear
/// — the reviewer's verdict is on the artifact, not the executor's
/// trajectory.
#[test]
fn reviewer_envelope_carries_artifact_identity_only() {
    let env = Capabilities::Reviewer(ReviewerCapabilities {
        session:          sample_session("reviewer"),
        artifact_task_id: "task-under-review".to_owned(),
    });
    let json = serde_json::to_value(&env).expect("reviewer serialise");
    assert_eq!(json["role"], "reviewer");
    assert!(json.get("session").is_some());
    assert_eq!(json["artifact_task_id"], "task-under-review",
        "reviewer envelope MUST carry artifact_task_id verbatim");

    // Counter / budget fields MUST NOT appear in the wire shape —
    // they would bias the reviewer's verdict toward the executor's
    // prior trajectory rather than the artifact under review.
    assert!(json.get("initiative").is_none(),
        "reviewer envelope MUST NOT carry orchestrator's per-initiative \
         respawn budget");
    assert!(json.get("tasks").is_none(),
        "reviewer envelope MUST NOT carry the per-initiative tasks list");
    assert!(json.get("task").is_none(),
        "reviewer envelope MUST NOT carry executor-style task counters \
         (would surface crash/review counts the reviewer must verdict \
         independently of)");
    assert!(!json.to_string().contains("crash_retry_count"),
        "reviewer envelope MUST NOT mention crash_retry_count anywhere — \
         the reviewer's verdict is on the artifact, not the executor's \
         trajectory: got {json}");
    assert!(!json.to_string().contains("review_reject_count"),
        "reviewer envelope MUST NOT mention review_reject_count anywhere: got {json}");
}

/// Cross-role round-trip witness: every variant MUST round-trip
/// through serde JSON byte-stably so the kernel-side projection
/// and the driver-side deserialiser produce identical structures.
/// A drift in serde tagging would surface here as a deserialise
/// failure.
#[test]
fn capabilities_round_trip_through_json_for_every_variant() {
    let envelopes = vec![
        Capabilities::Orchestrator(OrchestratorCapabilities {
            session:    sample_session("orchestrator"),
            initiative: InitiativeCapabilityView {
                initiative_id:                          "init-rt".to_owned(),
                orchestrator_no_progress_respawn_count: 0,
                max_orchestrator_no_progress_respawns:  3,
                orchestrator_respawns_remaining:        3,
            },
            tasks:      vec![sample_task_view("task-rt")],
        }),
        Capabilities::Executor(ExecutorCapabilities {
            session: sample_session("executor"),
            task:    sample_task_view("task-rt"),
        }),
        Capabilities::Reviewer(ReviewerCapabilities {
            session:          sample_session("reviewer"),
            artifact_task_id: "task-art".to_owned(),
        }),
    ];
    for env in envelopes {
        let json = serde_json::to_string(&env).expect("serialise");
        let back: Capabilities = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(env, back,
            "capabilities envelope MUST round-trip byte-stably; \
             original={env:?}, round-tripped={back:?}");
    }
}

/// The role-scoped contract is enforced ALSO at the rendered-text
/// level: the `capabilities=` block in the rendered KSB MUST surface
/// the role-keyed prefix and the per-role payload, and MUST NOT
/// surface forbidden field names from sibling roles.
#[test]
fn rendered_capabilities_block_respects_role_scope() {
    use raxis_ksb::{render_ksb, KsbSnapshot, KSB_SCHEMA_VERSION};

    fn fixture(caps: Capabilities) -> KsbSnapshot {
        KsbSnapshot {
            version:                       KSB_SCHEMA_VERSION,
            initiative_id:                 "init-rs".to_owned(),
            task_id:                       Some("task-rs".to_owned()),
            role:                          match &caps {
                Capabilities::Orchestrator(_) => "orchestrator",
                Capabilities::Executor(_)     => "executor",
                Capabilities::Reviewer(_)     => "reviewer",
            }.to_owned(),
            evaluation_sha:                String::new(),
            path_allowlist:                vec![],
            token_budget_remaining:        0,
            wallclock_budget_remaining_s:  0,
            dag_rows:                      vec![],
            task_description:              String::new(),
            target_ref:                    "refs/heads/main".to_owned(),
            base_sha:                      String::new(),
            reviewer_verdicts:             vec![],
            pending_escalations:           vec![],
            credential_ports:              vec![],
            capabilities:                  Some(caps),
        }
    }

    let orch = render_ksb(&fixture(Capabilities::Orchestrator(OrchestratorCapabilities {
        session:    sample_session("orchestrator"),
        initiative: InitiativeCapabilityView {
            initiative_id:                          "init-rs".to_owned(),
            orchestrator_no_progress_respawn_count: 1,
            max_orchestrator_no_progress_respawns:  3,
            orchestrator_respawns_remaining:        2,
        },
        tasks:      vec![sample_task_view("task-x")],
    }))).expect("render orchestrator");
    assert!(orch.contains("role=orchestrator"),
        "orchestrator render must carry role=orchestrator key in capabilities block: {orch}");
    assert!(orch.contains("orch_no_progress_respawns=1/3"),
        "orchestrator render must surface initiative respawn budget: {orch}");
    assert!(orch.contains("tasks=") && orch.contains("- task=task-x"),
        "orchestrator render must list per-task views: {orch}");

    let exec = render_ksb(&fixture(Capabilities::Executor(ExecutorCapabilities {
        session: sample_session("executor"),
        task:    sample_task_view("task-x"),
    }))).expect("render executor");
    assert!(exec.contains("role=executor"),
        "executor render must carry role=executor: {exec}");
    assert!(exec.contains("task=\n    - task=task-x"),
        "executor render must surface single task block: {exec}");
    assert!(!exec.contains("orch_no_progress_respawns"),
        "executor render MUST NOT leak orchestrator's respawn budget: {exec}");

    let rev = render_ksb(&fixture(Capabilities::Reviewer(ReviewerCapabilities {
        session:          sample_session("reviewer"),
        artifact_task_id: "task-art".to_owned(),
    }))).expect("render reviewer");
    assert!(rev.contains("role=reviewer"),
        "reviewer render must carry role=reviewer: {rev}");
    assert!(rev.contains("artifact_task_id=task-art"),
        "reviewer render must surface artifact id: {rev}");
    assert!(!rev.contains("crash_retry_count"),
        "reviewer render MUST NOT leak executor crash counters: {rev}");
    assert!(!rev.contains("review_reject_count"),
        "reviewer render MUST NOT leak executor review counters: {rev}");
}
