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
    /// V2.1 plan-bundle-sealed initiative creation.
    ///
    /// Normative reference: `specs/v2/plan-bundle-sealing.md` §3.4 (IPC
    /// envelope) and §4.2 step 10 (CLI submit phase).
    ///
    /// The wire fields differ structurally from V1:
    ///
    /// * `initiative_id` is **CLI-chosen** (UUIDv7). V1 had the kernel
    ///   assign one server-side; V2 hands authority for the id to the
    ///   operator so the audit chain can correlate the operator's
    ///   `raxis submit plan` invocation with the kernel-side
    ///   `InitiativeCreated` event using a single id known to both
    ///   sides at IPC time. The kernel rejects the request with
    ///   `FAIL_INITIATIVE_ID_COLLISION` if the id is already in use.
    /// * `plan_bundle` carries the **canonical_input bytes** per
    ///   §3.2 — every artifact's name, length, and bytes are
    ///   length-prefix-encoded. This is the byte-stream the
    ///   operator signed, byte-identical to what the kernel will
    ///   re-decode and seal into `plan_bundles`.
    /// * `bundle_sha256` is the SHA-256 over `plan_bundle`. Sent
    ///   redundantly so the kernel can reject obviously-corrupt
    ///   wire bytes before allocating Ed25519 verification cycles
    ///   (admission step 2 per §8.1).
    /// * `signature` is the 64-byte raw Ed25519 signature over
    ///   `signing_input` per §3.2 (= `RAXIS-V2-PLAN-BUNDLE-SIG\0` ||
    ///   `bundle_sha256`).
    /// * `signed_by` is the 8-byte operator key fingerprint
    ///   (SHA-256[:16] of the operator's Ed25519 public key) used
    ///   to look up the operator entry in `policy.operators` at
    ///   admission step 8.
    ///
    /// **Hex-encoding choice (best-judgment, documented in spec):**
    /// the V2 spec lists raw Rust types (`Vec<u8>`, `[u8; 32]`,
    /// `[u8; 64]`, `OperatorFingerprint`). The actual JSON wire format
    /// uses lowercase hex strings for byte-array fields because the
    /// V1 envelope (`plan_sig_hex`, fingerprints in `policy.operators`)
    /// is also hex-on-the-wire — keeping the encoding consistent across
    /// V1 and V2 wire variants means the operator socket has a single
    /// "what does a bytes field look like" answer and the JSON-frame
    /// contract test in `tests::create_initiative_v2_pinned` can pin
    /// the byte shape with a regular string literal. The hex values
    /// are decoded back into the typed bundle structures
    /// (`BundleSha256` / `BundleNonce` / `OperatorFingerprint`) by
    /// the kernel admission decoder.
    CreateInitiativeV2 {
        /// CLI-chosen UUIDv7. Rejected with
        /// `FAIL_INITIATIVE_ID_COLLISION` on collision.
        initiative_id:    String,
        /// canonical_input bytes per §3.2. Hex-encoded on the wire so
        /// the JSON frame stays string-only; the kernel decodes back
        /// to bytes before calling `canonical_decode`.
        plan_bundle_hex:  String,
        /// SHA-256 of `plan_bundle` (the decoded canonical_input
        /// bytes). 64-char lowercase hex.
        bundle_sha256_hex: String,
        /// Ed25519 signature over `signing_input` per §3.2.
        /// 128-char lowercase hex.
        signature_hex:    String,
        /// Operator's pubkey fingerprint — 16-char lowercase hex of
        /// the 8-byte SHA-256[:16] fingerprint.
        signed_by_hex:    String,
    },
    ApprovePlan {
        initiative_id:      String,
        approving_operator: String,
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

    // ── initiative quarantine (kernel-store.md §2.5.8) ────────────────
    //
    // Operator marks an initiative (or every initiative whose plan
    // was approved by a named operator) as frozen. The kernel inserts
    // the quarantine row(s) atomically with the
    // `InitiativeQuarantined` audit event(s); subsequent
    // `IntentRequest`s against the targeted initiative(s) are
    // rejected with `FAIL_INITIATIVE_QUARANTINED` by the planner
    // intent gate. v1 has no "unquarantine" wire op — the operator
    // recovers from a false positive by aborting the initiative.

    /// Quarantine a single initiative.
    QuarantineInitiative {
        /// UUID-shaped initiative_id to freeze.
        initiative_id:  String,
        /// Free-form reason (e.g. "compromised plan signer"). Capped
        /// to 512 bytes by the CLI before submission.
        reason:         Option<String>,
    },

    /// Sweep every initiative whose plan was approved by
    /// `target_fingerprint` and quarantine each one in a single
    /// transaction. Used after key compromise to freeze blast
    /// radius without aborting initiatives one-by-one.
    QuarantinePlansBy {
        /// Operator pubkey_fingerprint (32 hex chars) whose
        /// approved plans should be swept.
        target_fingerprint: String,
        /// Same shape as the single-initiative `reason` field.
        reason:             Option<String>,
    },

    // -----------------------------------------------------------------
    // V2_GAPS §12.4 — Operator-ergonomics IPC. The wire shape is
    // pinned in V2.3 so the CLI can be written against the final
    // contract; the kernel-side handlers fail closed with
    // `FAIL_NOT_YET_IMPLEMENTED` until V3 lands the concrete logic.
    // Defined in `operator-ergonomics.md` §5.3, §11.3, §12.3, §13.4,
    // §14.3 (linked from `V2_GAPS.md §12.4`).
    // -----------------------------------------------------------------
    /// `operator-ergonomics.md §5.3` (`raxis plan prepare`).
    /// Returns the kernel-recommended defaults (token budget,
    /// max-turns, model selection, timeouts) derived from the
    /// active policy. V2 stub responds with
    /// `FAIL_NOT_YET_IMPLEMENTED`; CLI consumers can still
    /// build against the wire shape.
    ProposeDefaults {
        /// Optional initiative scope so the kernel can specialise
        /// the defaults to an in-flight policy epoch (e.g. when the
        /// caller is amending an existing plan).
        initiative_id: Option<String>,
    },

    /// `operator-ergonomics.md §11.3` (`raxis plan cost-estimate`).
    /// Heuristic upper-bound dollar cost. V2 stub.
    EstimateCost {
        plan_toml:        String,
        plan_sig_hex:     String,
    },

    /// `operator-ergonomics.md §12.3`
    /// (`raxis submit plan --dry-run`). Runs admission validation
    /// pipeline without persisting state. V2 stub.
    DryRunAdmit {
        plan_toml:        String,
        plan_sig_hex:     String,
        submitted_by:     String,
    },

    /// `operator-ergonomics.md §13.4` (`raxis initiative watch`).
    /// Subscribes to `KernelPush` events for one initiative.
    /// V2 stub — depends on the V3 KernelPush transport
    /// (`V2_GAPS.md §12.1`).
    SubscribeInitiative {
        initiative_id: String,
    },

    /// `operator-ergonomics.md §14.3`
    /// (`raxis initiative resume`). Reports pause status and
    /// outstanding escalations. V2 stub.
    DescribeInitiativePause {
        initiative_id: String,
    },

    /// `v2_extended_gaps.md §3.2 StructuredOutput tool`
    /// (`raxis task outputs <task_id>`).
    ///
    /// Lists every typed structured output emitted under
    /// `task_id`, ordered by `emitted_at` ascending. Read-only;
    /// upholds `INV-OPERATOR-ERG-01`.
    ListTaskOutputs {
        task_id: String,
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

/// Wire-shape of a single row of the `structured_outputs`
/// table, surfaced through `OperatorResponse::TaskOutputsListed`.
///
/// `kind` is one of `progress_report` / `diagnostic_flag` /
/// `task_summary` (the same string used by the executor's
/// `structured_output` tool). `severity` is `Some(...)` only
/// for `diagnostic_flag` rows. `payload_json` is the verbatim
/// JSON the kernel persisted (already validated /
/// normalised at admission time).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskOutputWire {
    pub output_id:     String,
    pub initiative_id: String,
    pub task_id:       String,
    pub session_id:    String,
    pub kind:          String,
    pub severity:      Option<String>,
    pub payload_json:  String,
    pub emitted_at:    i64,
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

    /// Issued after a successful `QuarantineInitiative`. Carries the
    /// initiative_id back so the CLI can echo it verbatim, plus
    /// `was_already_quarantined` so the operator can tell the
    /// difference between "this command moved the system" and "no-op
    /// because someone else already quarantined it" without parsing
    /// the audit chain.
    InitiativeQuarantined {
        initiative_id:           String,
        quarantined_at:          i64,
        was_already_quarantined: bool,
    },

    /// Issued after a successful `QuarantinePlansBy`. Returns the
    /// list of newly-quarantined initiative_ids and the
    /// `target_fingerprint` for echo. Empty list ⇒ no plans by that
    /// operator OR all of them were already quarantined.
    QuarantineSwept {
        target_fingerprint:     String,
        newly_quarantined_ids:  Vec<String>,
        quarantined_at:         i64,
    },
    // -----------------------------------------------------------------
    // V2_GAPS §12.4 — Operator-ergonomics IPC success envelopes. Wire
    // shape pinned for V3 forward compatibility; V2 dispatchers always
    // emit `Error { code: "FAIL_NOT_YET_IMPLEMENTED", ... }` so these
    // variants are never produced today. CLI consumers may still
    // pattern-match against them when targeting V3.
    // -----------------------------------------------------------------
    /// Response to `ProposeDefaults`. `defaults_json` carries the
    /// recommended values as a free-form JSON document so the
    /// schema can evolve without breaking the wire shape; the CLI
    /// pretty-prints it for the operator.
    ProposedDefaults {
        defaults_json: String,
    },
    /// Response to `EstimateCost`. `breakdown_json` is a free-form
    /// JSON document detailing per-task cost contributions.
    /// `upper_bound_usd_cents` is integer cents to preserve `Eq`
    /// on the wire envelope; the CLI divides by 100 for display.
    CostEstimated {
        upper_bound_usd_cents: i64,
        breakdown_json:        String,
    },
    /// Response to `DryRunAdmit`. `target_ref` is the resolved
    /// initial integration ref; `warnings` are non-fatal admission
    /// warnings the operator should review before the real submit.
    DryRunAdmitted {
        target_ref: String,
        warnings:   Vec<String>,
    },
    /// Response to `SubscribeInitiative`. The kernel ack'd the
    /// subscription; subsequent `KernelPush` frames flow over the
    /// same socket per `V2_GAPS.md §12.1`.
    InitiativeSubscribed {
        initiative_id: String,
    },
    /// Response to `DescribeInitiativePause`.
    InitiativePauseDescribed {
        initiative_id:           String,
        is_paused:               bool,
        paused_at:               Option<i64>,
        outstanding_escalations: Vec<String>,
    },

    /// Response to `ListTaskOutputs`. Each entry is the
    /// canonical wire shape for a single row of the
    /// `structured_outputs` table.
    ///
    /// `payload_json` is the verbatim JSON string the kernel
    /// stored in `structured_outputs.payload_json`; the CLI is
    /// responsible for pretty-printing or filtering it. The
    /// kernel has already validated and normalised the payload
    /// at admission time (`StructuredOutputKind::validate_and_normalise`).
    TaskOutputsListed {
        task_id: String,
        outputs: Vec<TaskOutputWire>,
    },

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
    fn create_initiative_v2_wire_shape() {
        // Pin the V2.1 envelope hex-encoded byte shape exactly. If
        // this test fails, every released CLI/kernel pair stops
        // talking — treat the field set/order/encoding as a
        // forever-stable wire contract. Spec: plan-bundle-sealing.md
        // §3.4 + §11.1 "CLI workflow" landing.
        let sig_hex = "02".repeat(64);
        let bundle_sha_hex = "01".repeat(32);
        round_trip(
            &OperatorRequest::CreateInitiativeV2 {
                initiative_id:     "0192a8f0-1234-7abc-9000-000000000001".into(),
                plan_bundle_hex:   "deadbeef".into(),
                bundle_sha256_hex: bundle_sha_hex.clone(),
                signature_hex:     sig_hex.clone(),
                signed_by_hex:     "0303030303030303".into(),
            },
            json!({
                "op": "CreateInitiativeV2",
                "payload": {
                    "initiative_id":     "0192a8f0-1234-7abc-9000-000000000001",
                    "plan_bundle_hex":   "deadbeef",
                    "bundle_sha256_hex": bundle_sha_hex,
                    "signature_hex":     sig_hex,
                    "signed_by_hex":     "0303030303030303"
                }
            }),
        );
    }

    #[test]
    fn approve_plan_wire_shape() {
        round_trip(
            &OperatorRequest::ApprovePlan {
                initiative_id:      "init-1".into(),
                approving_operator: "op-prime".into(),
            },
            json!({
                "op": "ApprovePlan",
                "payload": {
                    "initiative_id":      "init-1",
                    "approving_operator": "op-prime",
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

    // ── Quarantine wire shapes (step-10) ──────────────────────────────────
    //
    // These pin the wire shape exactly as the CLI emits and the kernel
    // dispatcher decodes, mirroring the rest of this test module.

    #[test]
    fn quarantine_initiative_request_wire_shape_with_reason() {
        round_trip(
            &OperatorRequest::QuarantineInitiative {
                initiative_id: "init-abc".into(),
                reason:        Some("leaked key".into()),
            },
            json!({
                "op": "QuarantineInitiative",
                "payload": {
                    "initiative_id": "init-abc",
                    "reason":        "leaked key"
                }
            }),
        );
    }

    #[test]
    fn quarantine_initiative_request_wire_shape_without_reason() {
        // INV-WIRE-OPT: optional `reason` MUST be present-and-null on the
        // wire when None, matching the rest of `OperatorRequest`.
        let val = OperatorRequest::QuarantineInitiative {
            initiative_id: "init-abc".into(),
            reason:        None,
        };
        let serialised = serde_json::to_value(&val).unwrap();
        let payload    = serialised.get("payload").unwrap();
        assert!(payload.get("reason").is_some(),
            "optional `reason` MUST be present (as null), not omitted");
        assert!(payload["reason"].is_null());
    }

    #[test]
    fn quarantine_plans_by_request_wire_shape_with_reason() {
        round_trip(
            &OperatorRequest::QuarantinePlansBy {
                target_fingerprint: "abcdef0123456789".into(),
                reason:             Some("operator suspended".into()),
            },
            json!({
                "op": "QuarantinePlansBy",
                "payload": {
                    "target_fingerprint": "abcdef0123456789",
                    "reason":             "operator suspended"
                }
            }),
        );
    }

    #[test]
    fn initiative_quarantined_response_wire_shape() {
        round_trip(
            &OperatorResponse::InitiativeQuarantined {
                initiative_id:           "init-abc".into(),
                quarantined_at:          1_700_000_000,
                was_already_quarantined: false,
            },
            json!({
                "status": "InitiativeQuarantined",
                "payload": {
                    "initiative_id":           "init-abc",
                    "quarantined_at":          1_700_000_000_i64,
                    "was_already_quarantined": false
                }
            }),
        );
    }

    // ── V2_GAPS §12.4 — Operator-ergonomics IPC stubs ─────────────────
    //
    // Wire-shape pinning for the five V2.3 stubs. Locking the byte
    // layout in V2 means the V3 patch that lands real handlers cannot
    // accidentally re-shape the JSON envelope and break operator CLIs
    // shipped against V2.

    #[test]
    fn propose_defaults_request_wire_shape() {
        round_trip(
            &OperatorRequest::ProposeDefaults {
                initiative_id: Some("init-1".into()),
            },
            json!({
                "op": "ProposeDefaults",
                "payload": { "initiative_id": "init-1" }
            }),
        );
    }

    #[test]
    fn estimate_cost_request_wire_shape() {
        round_trip(
            &OperatorRequest::EstimateCost {
                plan_toml: "[[tasks]]".into(),
                plan_sig_hex: "ab".into(),
            },
            json!({
                "op": "EstimateCost",
                "payload": { "plan_toml": "[[tasks]]", "plan_sig_hex": "ab" }
            }),
        );
    }

    #[test]
    fn dry_run_admit_request_wire_shape() {
        round_trip(
            &OperatorRequest::DryRunAdmit {
                plan_toml: "[[tasks]]".into(),
                plan_sig_hex: "ab".into(),
                submitted_by: "op-prime".into(),
            },
            json!({
                "op": "DryRunAdmit",
                "payload": {
                    "plan_toml": "[[tasks]]",
                    "plan_sig_hex": "ab",
                    "submitted_by": "op-prime"
                }
            }),
        );
    }

    #[test]
    fn subscribe_initiative_request_wire_shape() {
        round_trip(
            &OperatorRequest::SubscribeInitiative {
                initiative_id: "init-1".into(),
            },
            json!({
                "op": "SubscribeInitiative",
                "payload": { "initiative_id": "init-1" }
            }),
        );
    }

    #[test]
    fn describe_initiative_pause_request_wire_shape() {
        round_trip(
            &OperatorRequest::DescribeInitiativePause {
                initiative_id: "init-1".into(),
            },
            json!({
                "op": "DescribeInitiativePause",
                "payload": { "initiative_id": "init-1" }
            }),
        );
    }

    #[test]
    fn proposed_defaults_response_wire_shape() {
        round_trip(
            &OperatorResponse::ProposedDefaults {
                defaults_json: r#"{"max_turns":12}"#.into(),
            },
            json!({
                "status": "ProposedDefaults",
                "payload": { "defaults_json": r#"{"max_turns":12}"# }
            }),
        );
    }

    #[test]
    fn cost_estimated_response_wire_shape() {
        round_trip(
            &OperatorResponse::CostEstimated {
                upper_bound_usd_cents: 12_345,
                breakdown_json: r#"{"by_task":[]}"#.into(),
            },
            json!({
                "status": "CostEstimated",
                "payload": {
                    "upper_bound_usd_cents": 12_345_i64,
                    "breakdown_json": r#"{"by_task":[]}"#
                }
            }),
        );
    }

    #[test]
    fn dry_run_admitted_response_wire_shape() {
        round_trip(
            &OperatorResponse::DryRunAdmitted {
                target_ref: "refs/heads/main".into(),
                warnings: vec!["TODO_IMAGE_DIGEST_PLACEHOLDER".into()],
            },
            json!({
                "status": "DryRunAdmitted",
                "payload": {
                    "target_ref": "refs/heads/main",
                    "warnings": ["TODO_IMAGE_DIGEST_PLACEHOLDER"]
                }
            }),
        );
    }

    #[test]
    fn initiative_subscribed_response_wire_shape() {
        round_trip(
            &OperatorResponse::InitiativeSubscribed {
                initiative_id: "init-1".into(),
            },
            json!({
                "status": "InitiativeSubscribed",
                "payload": { "initiative_id": "init-1" }
            }),
        );
    }

    #[test]
    fn initiative_pause_described_response_wire_shape() {
        round_trip(
            &OperatorResponse::InitiativePauseDescribed {
                initiative_id: "init-1".into(),
                is_paused: true,
                paused_at: Some(1_700_000_000),
                outstanding_escalations: vec!["esc-1".into(), "esc-2".into()],
            },
            json!({
                "status": "InitiativePauseDescribed",
                "payload": {
                    "initiative_id": "init-1",
                    "is_paused": true,
                    "paused_at": 1_700_000_000_i64,
                    "outstanding_escalations": ["esc-1", "esc-2"]
                }
            }),
        );
    }

    #[test]
    fn list_task_outputs_request_wire_shape() {
        round_trip(
            &OperatorRequest::ListTaskOutputs { task_id: "task-1".into() },
            json!({
                "op": "ListTaskOutputs",
                "payload": { "task_id": "task-1" }
            }),
        );
    }

    #[test]
    fn task_outputs_listed_response_wire_shape_empty() {
        round_trip(
            &OperatorResponse::TaskOutputsListed {
                task_id: "task-1".into(),
                outputs: vec![],
            },
            json!({
                "status": "TaskOutputsListed",
                "payload": {
                    "task_id": "task-1",
                    "outputs": [],
                }
            }),
        );
    }

    #[test]
    fn task_outputs_listed_response_wire_shape_full() {
        round_trip(
            &OperatorResponse::TaskOutputsListed {
                task_id: "task-1".into(),
                outputs: vec![
                    TaskOutputWire {
                        output_id:     "out-1".into(),
                        initiative_id: "init-1".into(),
                        task_id:       "task-1".into(),
                        session_id:    "sess-1".into(),
                        kind:          "diagnostic_flag".into(),
                        severity:      Some("warning".into()),
                        payload_json:  r#"{"DiagnosticFlag":{"severity":"warning","message":"x"}}"#.into(),
                        emitted_at:    1_700_000_000,
                    },
                    TaskOutputWire {
                        output_id:     "out-2".into(),
                        initiative_id: "init-1".into(),
                        task_id:       "task-1".into(),
                        session_id:    "sess-1".into(),
                        kind:          "progress_report".into(),
                        severity:      None,
                        payload_json:  r#"{"ProgressReport":{}}"#.into(),
                        emitted_at:    1_700_000_010,
                    },
                ],
            },
            json!({
                "status": "TaskOutputsListed",
                "payload": {
                    "task_id": "task-1",
                    "outputs": [
                        {
                            "output_id": "out-1",
                            "initiative_id": "init-1",
                            "task_id": "task-1",
                            "session_id": "sess-1",
                            "kind": "diagnostic_flag",
                            "severity": "warning",
                            "payload_json": r#"{"DiagnosticFlag":{"severity":"warning","message":"x"}}"#,
                            "emitted_at": 1_700_000_000_i64,
                        },
                        {
                            "output_id": "out-2",
                            "initiative_id": "init-1",
                            "task_id": "task-1",
                            "session_id": "sess-1",
                            "kind": "progress_report",
                            "severity": null,
                            "payload_json": r#"{"ProgressReport":{}}"#,
                            "emitted_at": 1_700_000_010_i64,
                        }
                    ],
                }
            }),
        );
    }

    #[test]
    fn quarantine_swept_response_wire_shape() {
        round_trip(
            &OperatorResponse::QuarantineSwept {
                target_fingerprint:    "abcdef0123456789".into(),
                newly_quarantined_ids: vec!["init-1".into(), "init-2".into()],
                quarantined_at:        1_700_000_000,
            },
            json!({
                "status": "QuarantineSwept",
                "payload": {
                    "target_fingerprint":    "abcdef0123456789",
                    "newly_quarantined_ids": ["init-1", "init-2"],
                    "quarantined_at":        1_700_000_000_i64
                }
            }),
        );
    }
}
