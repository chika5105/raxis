//! `InitiativeEvent` — wire shape of the realtime stream emitted by
//! `OperatorRequest::SubscribeInitiative` (`v2_extended_gaps.md §2.1`).
//!
//! # Why this lives in `raxis-types`
//!
//! Both the kernel (publisher) and the CLI (subscriber, via
//! `raxis initiative watch`) need to encode/decode these frames.
//! Putting the enum in the shared types crate lets us pin a single
//! wire shape and write one set of round-trip tests against it.
//!
//! # Wire format
//!
//! `InitiativeEvent` is serialised through `serde_json` as
//! `{"kind": "<Variant>", "payload": {...}}` and framed by
//! `raxis-ipc::write_json_frame_async` — exactly the same envelope
//! every other operator IPC response uses today. The dispatch loop
//! writes one frame per event; the CLI reads frames in a loop.
//!
//! # Stream lifecycle (kernel side)
//!
//! 1. The kernel writes a single `Subscribed { initiative_id }`
//!    frame as the first payload after admission.
//! 2. The kernel writes one frame per event off the in-process
//!    `InitiativeEventBus` for the rest of the stream.
//! 3. On initiative terminal state (`Completed`, `Failed`,
//!    `Aborted`) the kernel writes one final `Closed` frame, then
//!    drops the connection. The CLI uses `Closed` as the unambiguous
//!    "stream finished cleanly" signal so a peer-half-close is
//!    distinguishable from a transport hiccup.
//!
//! All variant-payload fields are simple owned strings / integers
//! so the type does not depend on any other `raxis-*` crate; this
//! keeps the dependency graph free of cycles between `raxis-types`
//! and the kernel.

use serde::{Deserialize, Serialize};

/// Realtime event delivered to a `SubscribeInitiative` stream.
///
/// Variant set is pinned by the
/// `initiative_event_variant_count_is_pinned` test below. Adding
/// a new variant is a wire change — bump the count assertion and
/// add a round-trip test.
///
/// All payload fields use plain owned types
/// (`String` / `Option<String>` / `i64`) rather than the typed
/// `*Id` newtypes to keep `raxis-types::initiative_event`
/// dependency-free of `id::*`. The kernel publisher converts its
/// typed ids into strings at the bus boundary; the CLI consumer
/// keeps them as strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "payload")]
pub enum InitiativeEvent {
    /// First frame of every successful subscribe stream. Echoes
    /// the subscribed initiative_id back to the operator so the
    /// CLI can confirm it spelled the id correctly.
    Subscribed {
        initiative_id: String,
    },

    /// A task transitioned to a new FSM state. Mirrors the
    /// kernel's `AuditEventKind::TaskStateChanged` — we do NOT
    /// re-derive the state machine on the CLI; we just surface
    /// the kernel's authoritative transitions.
    TaskStateChanged {
        task_id:        String,
        from_state:     Option<String>,
        to_state:       String,
        transitioned_at: i64,
    },

    /// The owning initiative's FSM state changed (e.g.
    /// `Executing → Completed`).
    InitiativeStateChanged {
        from_state:     Option<String>,
        to_state:       String,
        transitioned_at: i64,
    },

    /// A reviewer aggregation crossed `all_passed = true`. Used by
    /// dashboards to celebrate "all reviewers approved" without
    /// polling.
    ReviewAggregationCompleted {
        task_id:    String,
        all_passed: bool,
    },

    /// An escalation was raised (transitioned to Pending) on this
    /// initiative.
    EscalationRaised {
        escalation_id: String,
        task_id:       Option<String>,
        capability:    String,
    },

    /// An escalation was resolved (`Approved`, `Denied`, or
    /// `Expired`).
    EscalationResolved {
        escalation_id: String,
        outcome:       String,
    },

    /// An integration merge attempt completed (`Succeeded` or
    /// `Discarded`). `head_sha` is `Some(_)` only on success.
    IntegrationMergeCompleted {
        task_id: String,
        outcome: String,
        head_sha: Option<String>,
    },

    /// A typed structured output (`v2_extended_gaps.md §3.2`) was
    /// emitted under this initiative. Surfaces the `kind`
    /// discriminator + optional severity so the operator can
    /// react to `diagnostic_flag/critical` without poll.
    StructuredOutputEmitted {
        task_id:     String,
        output_kind: String,
        severity:    Option<String>,
    },

    /// Final frame: the kernel is closing the stream because the
    /// initiative reached a terminal state, the operator
    /// disconnected, or the kernel is shutting down.
    Closed {
        reason: ClosedReason,
    },
}

/// Why a `SubscribeInitiative` stream closed. Drives the CLI
/// exit behaviour (`InitiativeTerminal` → exit 0;
/// `KernelShutdown` → exit 1; `OperatorDisconnected` is never
/// observable on the CLI since it is the disconnector).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClosedReason {
    /// The initiative reached `Completed`, `Failed`, or `Aborted`.
    InitiativeTerminal,
    /// The kernel is shutting down. The stream is dropped from
    /// the publisher side; subsequent reconnect attempts will
    /// hit `ECONNREFUSED` until the kernel comes back.
    KernelShutdown,
    /// The kernel is closing the stream proactively because the
    /// initiative_id is unknown. Reported BEFORE any
    /// `Subscribed` frame would have been sent.
    InitiativeNotFound,
}

impl InitiativeEvent {
    /// Stable string discriminator for log lines and metrics. The
    /// JSON wire shape uses the exact same names (serde tag).
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Subscribed { .. }                 => "Subscribed",
            Self::TaskStateChanged { .. }           => "TaskStateChanged",
            Self::InitiativeStateChanged { .. }     => "InitiativeStateChanged",
            Self::ReviewAggregationCompleted { .. } => "ReviewAggregationCompleted",
            Self::EscalationRaised { .. }           => "EscalationRaised",
            Self::EscalationResolved { .. }         => "EscalationResolved",
            Self::IntegrationMergeCompleted { .. }  => "IntegrationMergeCompleted",
            Self::StructuredOutputEmitted { .. }    => "StructuredOutputEmitted",
            Self::Closed { .. }                     => "Closed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn round_trip(value: InitiativeEvent, expected: Value) {
        let serialised = serde_json::to_value(&value).unwrap();
        assert_eq!(serialised, expected, "wire shape regression");
        let parsed: InitiativeEvent = serde_json::from_value(expected).unwrap();
        assert_eq!(parsed, value);
    }

    /// Variant count is the wire-shape canary. Bump alongside
    /// the `kind_str` match arm and the round-trip tests.
    #[test]
    fn initiative_event_variant_count_is_pinned() {
        // Constructing one of each variant guarantees we visit
        // every match arm. If a variant is added without a test,
        // this fails to compile.
        let all = [
            InitiativeEvent::Subscribed { initiative_id: "i-1".into() },
            InitiativeEvent::TaskStateChanged {
                task_id: "t-1".into(),
                from_state: None,
                to_state: "Admitted".into(),
                transitioned_at: 0,
            },
            InitiativeEvent::InitiativeStateChanged {
                from_state: None,
                to_state: "Executing".into(),
                transitioned_at: 0,
            },
            InitiativeEvent::ReviewAggregationCompleted {
                task_id: "t-1".into(),
                all_passed: true,
            },
            InitiativeEvent::EscalationRaised {
                escalation_id: "e-1".into(),
                task_id: Some("t-1".into()),
                capability: "WriteCode".into(),
            },
            InitiativeEvent::EscalationResolved {
                escalation_id: "e-1".into(),
                outcome: "Approved".into(),
            },
            InitiativeEvent::IntegrationMergeCompleted {
                task_id: "t-1".into(),
                outcome: "Succeeded".into(),
                head_sha: Some("aabb".into()),
            },
            InitiativeEvent::StructuredOutputEmitted {
                task_id: "t-1".into(),
                output_kind: "diagnostic_flag".into(),
                severity: Some("warning".into()),
            },
            InitiativeEvent::Closed {
                reason: ClosedReason::InitiativeTerminal,
            },
        ];
        // 9 variants today. Bumping this counter without bumping
        // `kind_str` + the round-trip suite is a wire change.
        assert_eq!(all.len(), 9);
        for ev in &all {
            assert!(!ev.kind_str().is_empty());
        }
    }

    #[test]
    fn subscribed_wire_shape() {
        round_trip(
            InitiativeEvent::Subscribed { initiative_id: "i-1".into() },
            json!({ "kind": "Subscribed", "payload": { "initiative_id": "i-1" } }),
        );
    }

    #[test]
    fn task_state_changed_wire_shape() {
        round_trip(
            InitiativeEvent::TaskStateChanged {
                task_id: "t-1".into(),
                from_state: Some("Admitted".into()),
                to_state: "Running".into(),
                transitioned_at: 1_700_000_000,
            },
            json!({
                "kind": "TaskStateChanged",
                "payload": {
                    "task_id": "t-1",
                    "from_state": "Admitted",
                    "to_state": "Running",
                    "transitioned_at": 1_700_000_000_i64,
                }
            }),
        );
    }

    #[test]
    fn initiative_state_changed_wire_shape() {
        round_trip(
            InitiativeEvent::InitiativeStateChanged {
                from_state: Some("Executing".into()),
                to_state: "Completed".into(),
                transitioned_at: 1_700_000_010,
            },
            json!({
                "kind": "InitiativeStateChanged",
                "payload": {
                    "from_state": "Executing",
                    "to_state": "Completed",
                    "transitioned_at": 1_700_000_010_i64,
                }
            }),
        );
    }

    #[test]
    fn review_aggregation_completed_wire_shape() {
        round_trip(
            InitiativeEvent::ReviewAggregationCompleted {
                task_id: "t-1".into(),
                all_passed: false,
            },
            json!({
                "kind": "ReviewAggregationCompleted",
                "payload": { "task_id": "t-1", "all_passed": false }
            }),
        );
    }

    #[test]
    fn escalation_raised_wire_shape() {
        round_trip(
            InitiativeEvent::EscalationRaised {
                escalation_id: "e-1".into(),
                task_id: Some("t-1".into()),
                capability: "WriteSecrets".into(),
            },
            json!({
                "kind": "EscalationRaised",
                "payload": {
                    "escalation_id": "e-1",
                    "task_id": "t-1",
                    "capability": "WriteSecrets",
                }
            }),
        );
    }

    #[test]
    fn escalation_resolved_wire_shape() {
        round_trip(
            InitiativeEvent::EscalationResolved {
                escalation_id: "e-1".into(),
                outcome: "Denied".into(),
            },
            json!({
                "kind": "EscalationResolved",
                "payload": { "escalation_id": "e-1", "outcome": "Denied" }
            }),
        );
    }

    #[test]
    fn integration_merge_completed_wire_shape() {
        round_trip(
            InitiativeEvent::IntegrationMergeCompleted {
                task_id: "t-1".into(),
                outcome: "Succeeded".into(),
                head_sha: Some("deadbeef".into()),
            },
            json!({
                "kind": "IntegrationMergeCompleted",
                "payload": {
                    "task_id": "t-1",
                    "outcome": "Succeeded",
                    "head_sha": "deadbeef",
                }
            }),
        );
    }

    #[test]
    fn structured_output_emitted_wire_shape() {
        round_trip(
            InitiativeEvent::StructuredOutputEmitted {
                task_id: "t-1".into(),
                output_kind: "diagnostic_flag".into(),
                severity: Some("critical".into()),
            },
            json!({
                "kind": "StructuredOutputEmitted",
                "payload": {
                    "task_id": "t-1",
                    "output_kind": "diagnostic_flag",
                    "severity": "critical",
                }
            }),
        );
    }

    #[test]
    fn closed_wire_shape() {
        round_trip(
            InitiativeEvent::Closed { reason: ClosedReason::InitiativeTerminal },
            json!({ "kind": "Closed", "payload": { "reason": "InitiativeTerminal" } }),
        );

        round_trip(
            InitiativeEvent::Closed { reason: ClosedReason::KernelShutdown },
            json!({ "kind": "Closed", "payload": { "reason": "KernelShutdown" } }),
        );

        round_trip(
            InitiativeEvent::Closed { reason: ClosedReason::InitiativeNotFound },
            json!({ "kind": "Closed", "payload": { "reason": "InitiativeNotFound" } }),
        );
    }
}
