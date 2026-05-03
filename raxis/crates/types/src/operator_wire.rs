// raxis-types::operator_wire — JSON-shape operator IPC types.
//
// Why a second module alongside `operator.rs`?
// --------------------------------------------
// `raxis_types::operator::OperatorRequest` is the **bincode + typed-IDs**
// canonical design — it uses newtype wrappers (`InitiativeId`, `SessionId`,
// `Role`), references plan/sig blobs by `PathBuf`, and assumes the kernel
// reads them locally.
//
// The actual operator UDS protocol shipped in v1 is **JSON + plain
// strings**, defined here. The CLI hand-builds JSON frames (or, after
// PR-2c, constructs typed values from this module and serialises them);
// the kernel deserialises into the same types. The two protocols are
// genuinely different — `operator.rs` is the v2 destination, this module
// is the v1 contract.
//
// Single source of truth: this file is the ONLY place either the kernel
// or the CLI may define wire-shape variants for the operator socket.
// Adding a new operator op MUST start here. Wire-shape contract tests in
// `raxis_types::operator_wire::tests` pin the exact JSON byte layout for
// every variant — any drift breaks compilation or tests.
//
// Framing
// -------
// Every frame is a 4-byte little-endian length prefix followed by a
// JSON document. Helpers live in `raxis-ipc::json_frame`. This module
// only defines the document body.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// OperatorRequest — every operator IPC variant the kernel accepts on the
// JSON-shape operator socket.
// ---------------------------------------------------------------------------

/// JSON-shape operator request. Tagged on the wire as
/// `{"op": "<Variant>", "payload": {...}}`. The empty-payload variants
/// emit `{"op":"<Variant>","payload":{}}` for byte-shape consistency.
///
/// `Clone` is intentional — both the dispatcher and the audit emit may
/// hold references; cloning costs are dominated by the embedded plan
/// blob (`CreateInitiative.plan_toml`), which the dispatcher already
/// owns by the time the cost matters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", content = "payload")]
pub enum OperatorRequest {
    // ── session management ────────────────────────────────────────────
    CreateSession {
        role:              String,
        worktree_root:     Option<String>,
        base_sha:          Option<String>,
        base_tracking_ref: Option<String>,
        lineage_id:        String,
        task_id:           Option<String>,
    },
    RevokeSession {
        session_id: String,
    },

    // ── delegation ────────────────────────────────────────────────────
    GrantDelegation {
        session_id:       String,
        delegation_id:    String,
        capability_class: String,
        scope_json:       Option<String>,
        ttl_secs:         u64,
        max_uses:         Option<i64>,
        signature_hex:    String,
    },

    // ── initiative lifecycle ──────────────────────────────────────────
    CreateInitiative {
        plan_toml:    String,
        plan_sig_hex: String,
        submitted_by: String,
    },
    ApprovePlan {
        initiative_id:       String,
        approving_operator:  String,
        /// Hex-encoded Ed25519 pubkey of the approving operator.
        ///
        /// **Wire field, IGNORED by the kernel.** Per kernel-store.md
        /// §2.5.3 `approve_plan call path`, the canonical pubkey is
        /// looked up from `policy.operators` keyed by
        /// `authenticated.fingerprint`. The wire field is preserved
        /// for backward compatibility with older CLIs but its value is
        /// discarded; sending an attacker-controlled value here gives
        /// the attacker no advantage. See spec §2.5.3 for the full
        /// trust model.
        operator_pubkey_hex: String,
    },
    RejectPlan {
        initiative_id: String,
        rejected_by:   String,
        reason:        Option<String>,
    },
    AbortInitiative {
        initiative_id: String,
        aborted_by:    String,
    },

    // ── task state ops ────────────────────────────────────────────────
    AbortTask {
        task_id:    String,
        aborted_by: String,
    },
    ResumeTask {
        task_id:    String,
        resumed_by: String,
    },
    RetryTask {
        task_id: String,
    },

    // ── escalation review ─────────────────────────────────────────────
    //
    // Operator approves or denies a planner-submitted escalation.
    // Spec: kernel-store.md §2.5.5 "Escalation approval on the
    // operator socket" + cli-ceremony.md §"Approve / deny escalation"
    // + planner-api.md §"Escalating for higher authority".
    //
    // The signing input for ApproveEscalation is canonical:
    //   "approval|<escalation_id>|<capability_class>|<max_uses>|<valid_for_seconds>"
    // (see authority::escalation::approval_signing_input — the kernel
    // and CLI MUST agree on this exact byte layout).
    ApproveEscalation {
        escalation_id:    String,
        approval_scope:   ApprovalScopeWire,
        operator_sig_hex: String,
    },
    DenyEscalation {
        escalation_id: String,
        /// Optional; max 512 chars. Recorded in the audit log only;
        /// the operator may pass `None` when no public reason is
        /// appropriate (e.g. confidential security concerns).
        reason: Option<String>,
    },

    // ── policy epoch advance ──────────────────────────────────────────
    //
    // Operator rotates the active policy artifact in-process. The
    // kernel verifies the new artifact (signature, monotonic epoch,
    // path containment under <data_dir>/policy/), runs the four-phase
    // advance from `policy_manager::advance_epoch`, and replies with
    // `EpochAdvanced`. Spec: kernel-core.md §`policy_manager.rs`,
    // cli-ceremony.md §"epoch advance".
    RotateEpoch {
        /// Filesystem path to the new signed policy.toml. Resolved by
        /// the CLI from the operator-supplied `--policy` argument.
        /// MUST canonicalise to a location under `<data_dir>/policy/`
        /// or the kernel rejects with `FAIL_POLICY_PATH_OUTSIDE_DATA_DIR`.
        policy_path: String,
        /// Filesystem path to the corresponding 64-byte raw Ed25519
        /// signature file. Same containment rule as `policy_path`.
        sig_path:    String,
    },
}

/// Scope of an approval token issued for a `Pending` escalation.
///
/// Kernel-store.md §2.5.5 wire format:
///   `approval_scope: { capability_class, max_uses, valid_for_seconds }`
///
/// `capability_class` is the string discriminant of `CapabilityClass`
/// (e.g. `"WriteSecrets"`, `"WriteCode"`). The kernel parses it back
/// into the typed enum at validation time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalScopeWire {
    pub capability_class: String,
    /// Maximum number of times the issued token may be presented.
    /// `0` is rejected by the kernel — issue at least one use.
    pub max_uses:         i64,
    /// Lifetime of the issued token, in seconds from `issued_at`.
    /// `0` is rejected by the kernel.
    pub valid_for_seconds: u64,
}

// ---------------------------------------------------------------------------
// OperatorResponse — every operator IPC response the kernel emits.
// ---------------------------------------------------------------------------

/// JSON-shape operator response. Tagged on the wire as
/// `{"status": "<Variant>", "payload": {...}}`.
///
/// The `Error` variant is the SOLE error envelope — every per-handler
/// failure path collapses to `{ code, detail }` here (peripherals.md §3
/// "Operator socket"). The CLI's pattern-matching layer keys off `code`
/// and shows `detail` to the operator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", content = "payload")]
pub enum OperatorResponse {
    SessionCreated {
        session_id:    String,
        session_token: String,
        role:          String,
        worktree_root: Option<String>,
        base_sha:      Option<String>,
        lineage_id:    String,
    },
    SessionRevoked {
        session_id: String,
        revoked_at: i64,
    },
    DelegationGranted {
        delegation_id: String,
    },
    InitiativeCreated {
        initiative_id: String,
        status:        String,
    },
    PlanApproved {
        initiative_id:  String,
        tasks_admitted: usize,
    },
    /// Issued by the kernel after a successful `ApproveEscalation`.
    ///
    /// `approval_token_raw` is the high-entropy secret the operator
    /// must hand to the planner out-of-band; the kernel only stores
    /// `sha256(approval_token_raw)` in the `approval_tokens` table
    /// (kernel-store.md Table 9 — `token_hash` column). After the
    /// planner presents the token on its next intent, the kernel
    /// re-derives the hash and looks it up to authorise the action.
    EscalationApproved {
        escalation_id:      String,
        approval_token_id:  String,
        /// Hex-encoded high-entropy token (32 bytes → 64 hex chars).
        /// Operators MUST treat this value as a secret.
        approval_token_raw: String,
        expires_at:         i64,
    },
    /// Issued by the kernel after a successful `DenyEscalation`.
    /// No durable approval artifact is written — the audit event is
    /// the only record (kernel-store.md §2.5.5 — `DenyEscalation`).
    EscalationDenied {
        escalation_id: String,
        denied_at:     i64,
    },
    /// Issued by the kernel after a successful `RotateEpoch`.
    ///
    /// Carries forensic-grade detail: the new epoch id, the SHA-256
    /// of the artifact bytes (so the operator can confirm the kernel
    /// loaded the file they intended), the authority fingerprint that
    /// signed it, and the sweep counts from Phase 1. The CLI prints
    /// every field so a deployment audit trail can be reconstructed
    /// from operator shell history alone.
    ///
    /// Note: `new_epoch_id` is explicitly typed as a monotonic `u64` rather than
    /// a UUID to strictly enforce linear time (preventing replay attacks with old
    /// policies) and to provide human-readable sequence numbers for operators.
    EpochAdvanced {
        new_epoch_id:                u64,
        policy_sha256:               String,
        signed_by_authority:         String,
        n_delegations_marked_stale:  u64,
        n_sessions_invalidated:      u64,
        advanced_at:                 i64,
    },
    /// Generic acknowledgement for handlers that have no structured
    /// success payload (today: stubs, abort/retry/resume responses).
    Ack { message: String },
    /// Single canonical error envelope. `code` is an opaque short string
    /// the CLI keys off (e.g. `"FAIL_APPROVE_PLAN"`); `detail` is a
    /// human-readable explanation.
    Error {
        code:   String,
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// Tests — wire-shape contract pins.
//
// These tests are the contract between the kernel-side dispatcher and
// every CLI command's JSON construction site. A change to a serialised
// shape breaks one of these tests, forcing the implementer to look at
// the cross-process protocol.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn round_trip<T>(value: &T, expected: Value)
    where
        T: Serialize + for<'de> Deserialize<'de> + std::fmt::Debug + PartialEq,
    {
        // 1. Serialise the typed value and check it produces the
        //    expected JSON document — pins the on-the-wire shape.
        let serialised: Value = serde_json::to_value(value)
            .expect("serialisation must succeed");
        assert_eq!(serialised, expected,
            "wire shape regression — value:\n{value:?}\nproduced JSON:\n{}\nexpected:\n{}",
            serde_json::to_string_pretty(&serialised).unwrap(),
            serde_json::to_string_pretty(&expected).unwrap(),
        );

        // 2. Deserialise the expected JSON into the type and check it
        //    round-trips back to the original value — pins the parser
        //    side.
        let parsed: T = serde_json::from_value(expected.clone())
            .expect("expected JSON must parse back into the type");
        assert_eq!(&parsed, value,
            "round-trip mismatch — expected:\n{value:?}\ngot:\n{parsed:?}",
        );
    }

    // ── OperatorRequest variants ──────────────────────────────────────────

    #[test]
    fn create_session_wire_shape() {
        round_trip(
            &OperatorRequest::CreateSession {
                role:              "planner".into(),
                worktree_root:     Some("/srv/work".into()),
                base_sha:          Some("abcdef".into()),
                base_tracking_ref: Some("refs/heads/main".into()),
                lineage_id:        "lin-1".into(),
                task_id:           None,
            },
            json!({
                "op": "CreateSession",
                "payload": {
                    "role": "planner",
                    "worktree_root": "/srv/work",
                    "base_sha": "abcdef",
                    "base_tracking_ref": "refs/heads/main",
                    "lineage_id": "lin-1",
                    "task_id": null,
                }
            }),
        );
    }

    #[test]
    fn revoke_session_wire_shape() {
        round_trip(
            &OperatorRequest::RevokeSession { session_id: "sess-1".into() },
            json!({
                "op": "RevokeSession",
                "payload": { "session_id": "sess-1" }
            }),
        );
    }

    #[test]
    fn grant_delegation_wire_shape() {
        round_trip(
            &OperatorRequest::GrantDelegation {
                session_id:       "sess-1".into(),
                delegation_id:    "del-1".into(),
                capability_class: "FsRead".into(),
                scope_json:       Some(r#"{"paths":["src/"]}"#.into()),
                ttl_secs:         3600,
                max_uses:         Some(10),
                signature_hex:    "deadbeef".into(),
            },
            json!({
                "op": "GrantDelegation",
                "payload": {
                    "session_id": "sess-1",
                    "delegation_id": "del-1",
                    "capability_class": "FsRead",
                    "scope_json": r#"{"paths":["src/"]}"#,
                    "ttl_secs": 3600,
                    "max_uses": 10,
                    "signature_hex": "deadbeef"
                }
            }),
        );
    }

    #[test]
    fn create_initiative_wire_shape() {
        round_trip(
            &OperatorRequest::CreateInitiative {
                plan_toml:    "[[tasks]]\ntask_id = \"t1\"".into(),
                plan_sig_hex: "00ff".into(),
                submitted_by: "op-prime".into(),
            },
            json!({
                "op": "CreateInitiative",
                "payload": {
                    "plan_toml": "[[tasks]]\ntask_id = \"t1\"",
                    "plan_sig_hex": "00ff",
                    "submitted_by": "op-prime"
                }
            }),
        );
    }

    #[test]
    fn approve_plan_wire_shape() {
        round_trip(
            &OperatorRequest::ApprovePlan {
                initiative_id:       "init-1".into(),
                approving_operator:  "op-prime".into(),
                operator_pubkey_hex: "abcd".into(),
            },
            json!({
                "op": "ApprovePlan",
                "payload": {
                    "initiative_id": "init-1",
                    "approving_operator": "op-prime",
                    "operator_pubkey_hex": "abcd"
                }
            }),
        );
    }

    #[test]
    fn reject_plan_wire_shape() {
        round_trip(
            &OperatorRequest::RejectPlan {
                initiative_id: "init-1".into(),
                rejected_by:   "op-prime".into(),
                reason:        Some("spec violation".into()),
            },
            json!({
                "op": "RejectPlan",
                "payload": {
                    "initiative_id": "init-1",
                    "rejected_by": "op-prime",
                    "reason": "spec violation"
                }
            }),
        );
    }

    #[test]
    fn abort_initiative_wire_shape() {
        round_trip(
            &OperatorRequest::AbortInitiative {
                initiative_id: "init-1".into(),
                aborted_by:    "op-prime".into(),
            },
            json!({
                "op": "AbortInitiative",
                "payload": {
                    "initiative_id": "init-1",
                    "aborted_by": "op-prime"
                }
            }),
        );
    }

    #[test]
    fn abort_task_wire_shape() {
        round_trip(
            &OperatorRequest::AbortTask {
                task_id:    "t1".into(),
                aborted_by: "op-prime".into(),
            },
            json!({
                "op": "AbortTask",
                "payload": { "task_id": "t1", "aborted_by": "op-prime" }
            }),
        );
    }

    #[test]
    fn resume_task_wire_shape() {
        round_trip(
            &OperatorRequest::ResumeTask {
                task_id:    "t1".into(),
                resumed_by: "op-prime".into(),
            },
            json!({
                "op": "ResumeTask",
                "payload": { "task_id": "t1", "resumed_by": "op-prime" }
            }),
        );
    }

    #[test]
    fn retry_task_wire_shape() {
        round_trip(
            &OperatorRequest::RetryTask { task_id: "t1".into() },
            json!({
                "op": "RetryTask",
                "payload": { "task_id": "t1" }
            }),
        );
    }

    #[test]
    fn approve_escalation_wire_shape() {
        round_trip(
            &OperatorRequest::ApproveEscalation {
                escalation_id:    "esc-1".into(),
                approval_scope:   ApprovalScopeWire {
                    capability_class:  "WriteSecrets".into(),
                    max_uses:          1,
                    valid_for_seconds: 3600,
                },
                operator_sig_hex: "deadbeef".into(),
            },
            json!({
                "op": "ApproveEscalation",
                "payload": {
                    "escalation_id": "esc-1",
                    "approval_scope": {
                        "capability_class": "WriteSecrets",
                        "max_uses": 1,
                        "valid_for_seconds": 3600
                    },
                    "operator_sig_hex": "deadbeef"
                }
            }),
        );
    }

    #[test]
    fn deny_escalation_with_reason_wire_shape() {
        round_trip(
            &OperatorRequest::DenyEscalation {
                escalation_id: "esc-1".into(),
                reason:        Some("scope too broad".into()),
            },
            json!({
                "op": "DenyEscalation",
                "payload": {
                    "escalation_id": "esc-1",
                    "reason": "scope too broad"
                }
            }),
        );
    }

    #[test]
    fn deny_escalation_without_reason_wire_shape() {
        // Confirms `reason: None` serialises as explicit `null`, matching
        // the optional-field convention pinned by
        // `create_session_omits_optional_keys_as_null`.
        round_trip(
            &OperatorRequest::DenyEscalation {
                escalation_id: "esc-1".into(),
                reason:        None,
            },
            json!({
                "op": "DenyEscalation",
                "payload": {
                    "escalation_id": "esc-1",
                    "reason": null
                }
            }),
        );
    }

    #[test]
    fn escalation_approved_response_wire_shape() {
        round_trip(
            &OperatorResponse::EscalationApproved {
                escalation_id:      "esc-1".into(),
                approval_token_id:  "atk-1".into(),
                approval_token_raw: "ff".repeat(32),
                expires_at:         1_700_000_000,
            },
            json!({
                "status": "EscalationApproved",
                "payload": {
                    "escalation_id":      "esc-1",
                    "approval_token_id":  "atk-1",
                    "approval_token_raw": "ff".repeat(32),
                    "expires_at":         1_700_000_000_i64
                }
            }),
        );
    }

    #[test]
    fn rotate_epoch_request_wire_shape() {
        round_trip(
            &OperatorRequest::RotateEpoch {
                policy_path: "/var/lib/raxis/policy/policy.epoch-2.toml".into(),
                sig_path:    "/var/lib/raxis/policy/policy.epoch-2.sig".into(),
            },
            json!({
                "op": "RotateEpoch",
                "payload": {
                    "policy_path": "/var/lib/raxis/policy/policy.epoch-2.toml",
                    "sig_path":    "/var/lib/raxis/policy/policy.epoch-2.sig"
                }
            }),
        );
    }

    #[test]
    fn epoch_advanced_response_wire_shape() {
        round_trip(
            &OperatorResponse::EpochAdvanced {
                new_epoch_id:               2,
                policy_sha256:              "ab".repeat(32),
                signed_by_authority:        "ff".repeat(16),
                n_delegations_marked_stale: 7,
                n_sessions_invalidated:     3,
                advanced_at:                1_700_000_000,
            },
            json!({
                "status": "EpochAdvanced",
                "payload": {
                    "new_epoch_id":               2,
                    "policy_sha256":              "ab".repeat(32),
                    "signed_by_authority":        "ff".repeat(16),
                    "n_delegations_marked_stale": 7,
                    "n_sessions_invalidated":     3,
                    "advanced_at":                1_700_000_000_i64
                }
            }),
        );
    }

    #[test]
    fn escalation_denied_response_wire_shape() {
        round_trip(
            &OperatorResponse::EscalationDenied {
                escalation_id: "esc-1".into(),
                denied_at:     1_700_000_000,
            },
            json!({
                "status": "EscalationDenied",
                "payload": {
                    "escalation_id": "esc-1",
                    "denied_at":     1_700_000_000_i64
                }
            }),
        );
    }

    // ── OperatorResponse variants ─────────────────────────────────────────

    #[test]
    fn session_created_wire_shape() {
        round_trip(
            &OperatorResponse::SessionCreated {
                session_id:    "sess-1".into(),
                session_token: "deadbeef".into(),
                role:          "planner".into(),
                worktree_root: Some("/srv/work".into()),
                base_sha:      Some("abcdef".into()),
                lineage_id:    "lin-1".into(),
            },
            json!({
                "status": "SessionCreated",
                "payload": {
                    "session_id": "sess-1",
                    "session_token": "deadbeef",
                    "role": "planner",
                    "worktree_root": "/srv/work",
                    "base_sha": "abcdef",
                    "lineage_id": "lin-1"
                }
            }),
        );
    }

    #[test]
    fn plan_approved_wire_shape() {
        round_trip(
            &OperatorResponse::PlanApproved {
                initiative_id:  "init-1".into(),
                tasks_admitted: 3,
            },
            json!({
                "status": "PlanApproved",
                "payload": { "initiative_id": "init-1", "tasks_admitted": 3 }
            }),
        );
    }

    #[test]
    fn ack_wire_shape() {
        round_trip(
            &OperatorResponse::Ack { message: "ok".into() },
            json!({
                "status": "Ack",
                "payload": { "message": "ok" }
            }),
        );
    }

    #[test]
    fn error_wire_shape() {
        round_trip(
            &OperatorResponse::Error {
                code:   "FAIL_APPROVE_PLAN".into(),
                detail: "bad signature".into(),
            },
            json!({
                "status": "Error",
                "payload": { "code": "FAIL_APPROVE_PLAN", "detail": "bad signature" }
            }),
        );
    }

    // ── Optional-field semantics: missing => None ─────────────────────────

    #[test]
    fn create_session_omits_optional_keys_as_null() {
        // Confirm the canonical Serialize representation emits `null` for
        // a `None` Option field, not omits the key. The CLI's hand-built
        // JSON used to OMIT optional keys, which broke parsers expecting
        // explicit null. By pinning the typed serialization we lock the
        // contract.
        let val = OperatorRequest::CreateSession {
            role:              "planner".into(),
            worktree_root:     None,
            base_sha:          None,
            base_tracking_ref: None,
            lineage_id:        "lin-1".into(),
            task_id:           None,
        };
        let serialised: Value = serde_json::to_value(&val).unwrap();
        let payload = serialised.get("payload").unwrap();
        for key in ["worktree_root", "base_sha", "base_tracking_ref", "task_id"] {
            assert!(payload.get(key).is_some(),
                "optional key `{key}` MUST be present (as null), not omitted");
            assert!(payload[key].is_null(),
                "optional key `{key}` must serialise to null when None");
        }
    }

    #[test]
    fn parser_accepts_omitted_optional_keys() {
        // Backward-compat with older CLI builds that omitted optional
        // keys instead of emitting null. The kernel-side parser MUST
        // still accept those frames.
        let frame = json!({
            "op": "CreateSession",
            "payload": {
                "role": "planner",
                "lineage_id": "lin-1"
                // worktree_root, base_sha, base_tracking_ref, task_id all OMITTED
            }
        });
        let parsed: OperatorRequest = serde_json::from_value(frame).unwrap();
        match parsed {
            OperatorRequest::CreateSession {
                worktree_root, base_sha, base_tracking_ref, task_id, ..
            } => {
                assert!(worktree_root.is_none());
                assert!(base_sha.is_none());
                assert!(base_tracking_ref.is_none());
                assert!(task_id.is_none());
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
