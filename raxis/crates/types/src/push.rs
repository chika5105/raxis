// raxis-types::push — KernelPush and KernelPushFrame V2 wire types.
//
// Normative reference: `kernel-push-protocol.md §9` ("KernelPush
// Variants" — authoritative enumeration for V2.0) and
// `v2-deep-spec.md §14` (the `SubTaskSecurityViolation` variant, which
// was missing from §9 before V2 implementation; see the spec amendment
// at the bottom of `kernel-push-protocol.md §9` for the rationale).
//
// Wire encoding contract (mirror of `IntentRequest`):
//   * Bincode 2.0.1 with `bincode::config::standard()`, wrapped in a
//     4-byte LE length prefix by `raxis-ipc::frame`.
//   * Bincode `serde` mode encodes positionally — every variant's
//     fields land on the wire in declaration order, regardless of
//     whether they are `Option`-typed or have `serde` rename
//     attributes.
//   * Adding a NEW variant is forward-compatible (bincode tags
//     variants by index); REORDERING existing variants is a
//     wire-incompatible break.
//   * Adding fields to an EXISTING variant is also a break unless the
//     receiver is updated first. This module currently exposes only
//     the **V2 sub-task lifecycle subset** of the §9 enumeration.
//     Other variants (escalation, resource pressure, provider routing,
//     initiative cancel, session terminal) land alongside their
//     respective V2 implementation tasks; each addition appends to the
//     enum and bumps no other variant's index.
//
// Crate rules (philosophy.md §1.5, INV-CRATE-01):
//   * No I/O, no async, no database access. Pure data definitions
//     plus serde derives only.

use crate::{SessionId, TaskId};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// KernelPush — V2 sub-task lifecycle subset
// ---------------------------------------------------------------------------

/// Outbound message from the Kernel to a planner session, delivered
/// over the same VSock connection that ferries `IntentRequest` /
/// `IntentResponse` frames in the opposite direction. This subset
/// covers exactly the sub-task lifecycle events documented in
/// `kernel-push-protocol.md §9` and the
/// `SubTaskSecurityViolation` amendment.
///
/// **What "the Orchestrator" / "the Executor" mean here.** Pushes are
/// session-scoped — every variant is enqueued onto a specific session's
/// `pending_pushes` queue, and the recipient is determined by where
/// the Kernel inserts the row, not by an explicit `recipient_session_id`
/// field. The doc comments below name the canonical recipient role for
/// each variant.
///
/// **Why no `enum` discriminants are spelled out.** Bincode encodes
/// variants by their declaration order (0, 1, 2, ...). Reordering the
/// variants below is a wire-incompatible break; adding new variants at
/// the END is forward-compatible. The integration tests in
/// `kernel/tests/` pin the bincode encoding so a reorder shows up as
/// a test failure rather than as a silent on-the-wire ABI break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelPush {
    /// **V2.** Sent to the Orchestrator when the Kernel has admitted
    /// and spawned a sub-task in response to an `ActivateSubTask`
    /// intent. The `base_sha` is the commit the sub-task's worktree
    /// was checked out at (the Orchestrator's `head_sha` at activation
    /// time, modulo path-export merges per §11). The Orchestrator uses
    /// this in its KSB to track which sub-tasks are currently running.
    ///
    /// Cross-ref: `kernel-push-protocol.md §9` line 437.
    SubTaskActivated {
        task_id:  TaskId,
        base_sha: String,
    },

    /// **V2.** Sent to the Orchestrator when a sub-task transitions
    /// `Running → Completed` (i.e., the Executor's `CompleteTask`
    /// intent succeeded AND every Reviewer attached to the sub-task
    /// has returned `approved = true`). `newly_activatable` lists the
    /// sub-tasks whose dependency-completion sets are now empty —
    /// the Orchestrator MAY immediately submit `ActivateSubTask` for
    /// any of them (the Kernel re-checks predecessors at admission and
    /// returns `DEPENDENCY_NOT_MET` if the Orchestrator races ahead).
    ///
    /// Empty `newly_activatable` is meaningful: it means this sub-task
    /// was a leaf in the DAG (or all its successors were already
    /// activated by a prior push). The Orchestrator treats the empty
    /// list as "no new work — wait for further completions".
    ///
    /// Cross-ref: `kernel-push-protocol.md §9` line 438.
    SubTaskCompleted {
        task_id:           TaskId,
        completed_sha:     String,
        newly_activatable: Vec<TaskId>,
    },

    /// **V2.** Sent to the Orchestrator when EVERY Reviewer attached
    /// to the named sub-task has returned `approved = true`. Per
    /// `v2-deep-spec.md §Step 25` the Reviewer verdict aggregator is
    /// a logical AND, so this push fires only when the last `Reviewer`
    /// session resolves to `approved`. The Orchestrator treats this
    /// as the "green light" for the Executor's diff to flow into a
    /// later `IntegrationMerge`.
    ///
    /// Distinct from `SubTaskCompleted` because:
    ///   * `AllReviewersPassed` fires *before* the Executor's
    ///     `CompleteTask` is admitted (or after — order depends on
    ///     timing); the Orchestrator does not couple them.
    ///   * `SubTaskCompleted` carries `newly_activatable`, which only
    ///     makes sense at the FSM transition; review verdicts are
    ///     orthogonal to DAG progression.
    ///
    /// Cross-ref: `kernel-push-protocol.md §9` line 439.
    AllReviewersPassed {
        task_id: TaskId,
    },

    /// **V2.** Sent to the Orchestrator when ANY Reviewer attached to
    /// the named sub-task has returned `approved = false`. The Kernel
    /// short-circuits the Logical-AND aggregator on the first
    /// rejection — there is no "all reviewers rejected" push.
    ///
    /// `critique` is the Reviewer's verbatim critique payload, capped
    /// at `MAX_CRITIQUE_BYTES` (32 KiB) by `IntentRequest` admission;
    /// the Kernel re-includes it here so the Orchestrator can route
    /// it into the failed sub-task's retry `system_prompt` per
    /// `v2-deep-spec.md §Step 22`. The `reviewer_session_id` lets the
    /// Orchestrator (and the operator's audit reconstruction) trace
    /// which Reviewer originated the rejection.
    ///
    /// **Naming amendment.** The earlier task list referred to this
    /// variant as `ReviewFailed`; the spec at
    /// `kernel-push-protocol.md §9` line 440 names it
    /// `ReviewRejected`. We keep the spec name on the wire so spec
    /// and code do not drift; the canonical wire name is
    /// `ReviewRejected`.
    ///
    /// Cross-ref: `kernel-push-protocol.md §9` line 440.
    ReviewRejected {
        task_id:             TaskId,
        critique:            String,
        reviewer_session_id: SessionId,
    },

    /// **V2.** Sent to the Orchestrator when a sub-planner session is
    /// revoked due to a `SecurityViolation` event
    /// (`v2-deep-spec.md §14`, step 4). The revocation is treated as
    /// a class-1 infrastructure failure: the Kernel transitions the
    /// sub-task's `subtask_activations.activation_state` to `Failed`,
    /// increments `crash_retry_count`, and emits this push so the
    /// Orchestrator can decide whether to `RetrySubTask` (subject to
    /// the dual retry-counter ceiling at §Step 12).
    ///
    /// **Spec amendment.** This variant is required by
    /// `v2-deep-spec.md §14` line 588 but was omitted from the §9
    /// authoritative enumeration in earlier drafts. We added it here
    /// AND updated `kernel-push-protocol.md §9` so the two specs are
    /// consistent. The parameter set (`task_id` only) matches the
    /// wire shape stipulated by §14 line 588 verbatim.
    SubTaskSecurityViolation {
        task_id: TaskId,
    },
}

// ---------------------------------------------------------------------------
// KernelPushFrame — wire envelope (push_id + session_id + enqueued_at + push)
// ---------------------------------------------------------------------------

/// Wire envelope wrapping a `KernelPush`. Mirror of
/// `kernel-push-protocol.md §9` line 537–542.
///
/// `push_id` is the per-session monotonic push counter, used by the
/// planner-side ACK protocol to confirm receipt and by the Kernel-side
/// at-least-once delivery loop to retransmit unacked pushes after a
/// reconnect (INV-PUSH-02). `enqueued_at` is the Unix timestamp at
/// the moment the Kernel committed the push row to `pending_pushes`,
/// **not** the moment the planner read it off the socket — the
/// planner uses the lag to contextualize stale notifications after
/// a reconnect ("escalation was resolved 30 minutes ago").
///
/// `session_id` is redundant with the VSock-level session binding but
/// included explicitly for forensic reconstruction (per
/// `kernel-push-protocol.md §9` line 539).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelPushFrame {
    pub push_id:     u64,
    pub session_id:  SessionId,
    pub enqueued_at: i64,
    pub push:        KernelPush,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SessionId, TaskId};
    use uuid::Uuid;

    fn task_id(s: &str) -> TaskId {
        TaskId::parse(s).expect("test task id")
    }

    fn session_id(seed: u8) -> SessionId {
        // Deterministic UUID v4-shaped string for the test fixture;
        // the actual bytes don't matter — we just need stable
        // round-trips. We construct the UUID explicitly (instead of
        // `new_v4()`) so the test is reproducible and the `seed`
        // parameter lets us distinguish reviewer sessions.
        let u = Uuid::from_bytes([seed; 16]);
        SessionId::parse(&u.hyphenated().to_string()).expect("test session id")
    }

    // ── Bincode round-trips — pin the wire encoding ──────────────────────
    //
    // These tests deliberately exercise `bincode::serde::encode_to_vec` /
    // `decode_from_slice`, which is what `raxis-ipc::frame` uses on the
    // socket. A change to `bincode::config::standard()` semantics or to
    // any variant's field order would surface here as a decode failure.
    fn bincode_round_trip(push: KernelPush) -> KernelPush {
        let cfg = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&push, cfg)
            .expect("encode KernelPush");
        let (decoded, _len) = bincode::serde::decode_from_slice::<KernelPush, _>(&bytes, cfg)
            .expect("decode KernelPush");
        decoded
    }

    #[test]
    fn sub_task_activated_round_trips_through_bincode() {
        let p = KernelPush::SubTaskActivated {
            task_id:  task_id("sub-1"),
            base_sha: "deadbeefcafebabedeadbeefcafebabedeadbeef".to_owned(),
        };
        assert_eq!(bincode_round_trip(p.clone()), p);
    }

    #[test]
    fn sub_task_completed_preserves_newly_activatable_order() {
        // `newly_activatable` is a Vec — ordering matters because the
        // Orchestrator's KSB displays the list in the order it received
        // it (no implicit sort), and bincode is order-preserving.
        let p = KernelPush::SubTaskCompleted {
            task_id:           task_id("sub-A"),
            completed_sha:     "0000000000000000000000000000000000000000".to_owned(),
            newly_activatable: vec![task_id("sub-B"), task_id("sub-C"), task_id("sub-D")],
        };
        let decoded = bincode_round_trip(p.clone());
        match (p, decoded) {
            (
                KernelPush::SubTaskCompleted { newly_activatable: orig, .. },
                KernelPush::SubTaskCompleted { newly_activatable: got,  .. },
            ) => assert_eq!(orig, got, "newly_activatable must round-trip in order"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn sub_task_completed_empty_newly_activatable_is_meaningful() {
        // Pin: an empty list is preserved (NOT collapsed to an Option).
        // The recipient distinguishes "no new work" from "absent field".
        let p = KernelPush::SubTaskCompleted {
            task_id:           task_id("leaf"),
            completed_sha:     "1111111111111111111111111111111111111111".to_owned(),
            newly_activatable: vec![],
        };
        match bincode_round_trip(p) {
            KernelPush::SubTaskCompleted { newly_activatable, .. } => {
                assert!(newly_activatable.is_empty(),
                        "empty newly_activatable must remain empty after round-trip");
            }
            other => panic!("wrong variant after round-trip: {other:?}"),
        }
    }

    #[test]
    fn all_reviewers_passed_round_trips_through_bincode() {
        let p = KernelPush::AllReviewersPassed { task_id: task_id("sub-rev") };
        assert_eq!(bincode_round_trip(p.clone()), p);
    }

    #[test]
    fn review_rejected_round_trips_with_critique_and_session_id() {
        let p = KernelPush::ReviewRejected {
            task_id:             task_id("sub-fail"),
            critique:            "Insufficient test coverage on src/auth.rs".to_owned(),
            reviewer_session_id: session_id(0xab),
        };
        assert_eq!(bincode_round_trip(p.clone()), p);
    }

    #[test]
    fn review_rejected_carries_max_critique_size_payload() {
        // Pin that a critique up to MAX_CRITIQUE_BYTES (32 KiB) round-trips.
        // The Kernel-side admission gate caps incoming critiques on
        // `IntentRequest::SubmitReview`; we re-emit them verbatim here.
        let critique = "x".repeat(crate::MAX_CRITIQUE_BYTES);
        let p = KernelPush::ReviewRejected {
            task_id:             task_id("sub-large"),
            critique:            critique.clone(),
            reviewer_session_id: session_id(0x01),
        };
        match bincode_round_trip(p) {
            KernelPush::ReviewRejected { critique: got, .. } => {
                assert_eq!(got.len(), critique.len());
                assert_eq!(got, critique);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn sub_task_security_violation_round_trips_through_bincode() {
        let p = KernelPush::SubTaskSecurityViolation { task_id: task_id("sub-evil") };
        assert_eq!(bincode_round_trip(p.clone()), p);
    }

    #[test]
    fn kernel_push_frame_round_trips_through_bincode() {
        // The envelope must round-trip independently of the inner
        // variant, because `raxis-ipc::frame` wraps the whole frame in
        // a length-prefixed bincode payload.
        let frame = KernelPushFrame {
            push_id:     17,
            session_id:  session_id(0x42),
            enqueued_at: 1_700_000_000,
            push:        KernelPush::AllReviewersPassed { task_id: task_id("sub-z") },
        };
        let cfg = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&frame, cfg).unwrap();
        let (decoded, _) = bincode::serde::decode_from_slice::<KernelPushFrame, _>(&bytes, cfg)
            .unwrap();
        assert_eq!(decoded, frame);
    }

    // ── Variant ordering — pin the on-wire discriminant indices ──────────
    //
    // bincode encodes enum variants by declaration order; reordering
    // the `KernelPush` enum is a wire-incompatible break. Pin the
    // discriminant index of each V2 sub-task variant so a future
    // refactor that accidentally reorders shows up here.
    fn discriminant_byte(push: &KernelPush) -> u8 {
        let cfg = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(push, cfg).unwrap();
        // bincode `standard()` encodes the variant index as a varint,
        // and small indices (< 64) fit in one byte. The first byte is
        // the discriminant for every sub-task variant we ship today.
        bytes[0]
    }

    #[test]
    fn variant_discriminants_are_pinned_in_declaration_order() {
        // SubTaskActivated         — index 0
        // SubTaskCompleted         — index 1
        // AllReviewersPassed       — index 2
        // ReviewRejected           — index 3
        // SubTaskSecurityViolation — index 4
        //
        // A reorder breaks every existing planner connection on a
        // running kernel (mismatched tags decode as the wrong variant
        // or fail outright). This test is the single point of
        // detection.
        assert_eq!(discriminant_byte(
            &KernelPush::SubTaskActivated {
                task_id: task_id("a"), base_sha: String::new(),
            }), 0);
        assert_eq!(discriminant_byte(
            &KernelPush::SubTaskCompleted {
                task_id: task_id("a"), completed_sha: String::new(),
                newly_activatable: vec![],
            }), 1);
        assert_eq!(discriminant_byte(
            &KernelPush::AllReviewersPassed { task_id: task_id("a") }), 2);
        assert_eq!(discriminant_byte(
            &KernelPush::ReviewRejected {
                task_id: task_id("a"), critique: String::new(),
                reviewer_session_id: session_id(0),
            }), 3);
        assert_eq!(discriminant_byte(
            &KernelPush::SubTaskSecurityViolation { task_id: task_id("a") }), 4);
    }

    // ── JSON projection sanity (operator UI / test harnesses) ────────────

    #[test]
    fn kernel_push_serializes_to_human_readable_json() {
        // The serde derive provides the JSON projection used by
        // operator UIs and audit reconstruction tooling. Verify
        // variant names land verbatim (PascalCase) and the field
        // structure is what the spec spells out.
        let p = KernelPush::SubTaskCompleted {
            task_id:           task_id("sub-2"),
            completed_sha:     "abc123".to_owned(),
            newly_activatable: vec![task_id("sub-3")],
        };
        let v = serde_json::to_value(&p).unwrap();
        let obj = v.get("SubTaskCompleted")
            .expect("variant tag must be present in JSON projection");
        assert_eq!(obj["task_id"], serde_json::json!("sub-2"));
        assert_eq!(obj["completed_sha"], serde_json::json!("abc123"));
        assert_eq!(obj["newly_activatable"], serde_json::json!(["sub-3"]));
    }

    #[test]
    fn kernel_push_json_round_trips_through_serde() {
        let original = KernelPush::SubTaskSecurityViolation {
            task_id: task_id("sub-violator"),
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: KernelPush = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }
}
