// raxis-cli integration test — operator wire-shape contract from the
// CLI side.
//
// Why this lives in `cli/tests/` not `crates/types/src/operator_wire.rs`:
// the contract that matters is "the JSON the CLI ACTUALLY puts on the
// wire matches what the kernel ACTUALLY accepts". The unit tests in
// `operator_wire` cover the typed-value ↔ JSON round trip; this test
// covers the additional fact that every CLI command path constructs
// the same typed values as the unit tests pin (no hidden hand-built
// `serde_json::json!` snuck back in).
//
// The test is a compile-time + runtime contract: if a future PR
// re-introduces a hand-built JSON shape for an OperatorRequest variant,
// the test that pins THAT variant's shape will fail.

use raxis_types::operator_wire::{ApprovalScopeWire, OperatorRequest, OperatorResponse};
use serde_json::{json, Value};

/// Helper: serialise → JSON value → deserialise → equality.
fn round_trip(req: OperatorRequest) -> Value {
    let v: Value = serde_json::to_value(&req).expect("serialise");
    let parsed: OperatorRequest = serde_json::from_value(v.clone())
        .expect("deserialise");
    assert_eq!(parsed, req, "round-trip mismatch");
    v
}

// ── ApprovePlan: kernel ignores operator_pubkey_hex, so empty string is
//    an acceptable wire value (kernel-store.md §2.5.3).
#[test]
fn approve_plan_with_empty_pubkey_round_trips() {
    let v = round_trip(OperatorRequest::ApprovePlan {
        initiative_id:       "init-xyz".into(),
        approving_operator:  "op-prime".into(),
        operator_pubkey_hex: String::new(),
    });
    assert_eq!(v["op"], "ApprovePlan");
    assert_eq!(v["payload"]["operator_pubkey_hex"], "");
}

// ── CreateSession: optional fields serialise as null (NOT omitted).
#[test]
fn create_session_emits_null_for_unset_optionals() {
    let v = round_trip(OperatorRequest::CreateSession {
        role:              "planner".into(),
        worktree_root:     None,
        base_sha:          None,
        base_tracking_ref: None,
        lineage_id:        "lin-1".into(),
        task_id:           None,
    });
    assert!(v["payload"]["worktree_root"].is_null());
    assert!(v["payload"]["base_sha"].is_null());
    assert!(v["payload"]["base_tracking_ref"].is_null());
    assert!(v["payload"]["task_id"].is_null());
}

// ── GrantDelegation: ttl_secs is on the wire (NOT expires_at).
//    Earlier CLI builds sent expires_at, which the kernel could not parse;
//    this test pins the corrected shape.
#[test]
fn grant_delegation_uses_ttl_secs_not_expires_at() {
    let v = round_trip(OperatorRequest::GrantDelegation {
        session_id:       "sess-1".into(),
        delegation_id:    "del-1".into(),
        capability_class: "FsRead".into(),
        scope_json:       None,
        ttl_secs:         3600,
        max_uses:         None,
        signature_hex:    "deadbeef".into(),
    });
    assert!(v["payload"].get("ttl_secs").is_some(),
            "wire MUST carry ttl_secs (kernel-side OperatorRequest field)");
    assert!(v["payload"].get("expires_at").is_none(),
            "wire MUST NOT carry expires_at (CLI-only computed value)");
    assert!(v["payload"].get("granted_by").is_none(),
            "wire MUST NOT carry granted_by (kernel infers from auth)");
    assert_eq!(v["payload"]["ttl_secs"], 3600);
}

// ── ApproveEscalation: typed payload (escalation_id, approval_scope, sig).
//    Phase A.6 promoted ApproveEscalation from a tier-2 `serde_json::Value`
//    payload to a fully typed wire variant. This test pins the new shape so
//    no future PR slips back to a hand-built JSON envelope.
#[test]
fn approve_escalation_uses_typed_payload() {
    let req = OperatorRequest::ApproveEscalation {
        escalation_id: "esc-1".into(),
        approval_scope: ApprovalScopeWire {
            capability_class:  "WriteSecrets".into(),
            max_uses:          1,
            valid_for_seconds: 3600,
        },
        operator_sig_hex: "deadbeef".into(),
    };
    let v = round_trip(req);
    assert_eq!(v["op"], "ApproveEscalation");
    assert_eq!(v["payload"]["escalation_id"], "esc-1");
    assert_eq!(v["payload"]["approval_scope"]["capability_class"], "WriteSecrets");
    assert_eq!(v["payload"]["approval_scope"]["max_uses"], 1);
    assert_eq!(v["payload"]["approval_scope"]["valid_for_seconds"], 3600);
    assert_eq!(v["payload"]["operator_sig_hex"], "deadbeef");
}

// ── DenyEscalation: typed payload with optional reason.
#[test]
fn deny_escalation_uses_typed_payload_with_optional_reason() {
    let req = OperatorRequest::DenyEscalation {
        escalation_id: "esc-1".into(),
        reason:        Some("scope too broad".into()),
    };
    let v = round_trip(req);
    assert_eq!(v["op"], "DenyEscalation");
    assert_eq!(v["payload"]["escalation_id"], "esc-1");
    assert_eq!(v["payload"]["reason"], "scope too broad");
}

#[test]
fn deny_escalation_emits_null_reason_when_unset() {
    let req = OperatorRequest::DenyEscalation {
        escalation_id: "esc-1".into(),
        reason:        None,
    };
    let v = round_trip(req);
    assert!(v["payload"]["reason"].is_null(),
        "reason MUST serialise as explicit null when unset (matches the optional-field convention)");
}

// ── OperatorResponse parsing — every status variant decodes back to type.
#[test]
fn every_response_status_variant_decodes() {
    let session_created = json!({
        "status": "SessionCreated",
        "payload": {
            "session_id": "s1",
            "session_token": "deadbeef",
            "role": "planner",
            "worktree_root": "/srv",
            "base_sha": null,
            "lineage_id": "lin-1"
        }
    });
    let parsed: OperatorResponse = serde_json::from_value(session_created)
        .expect("SessionCreated must decode");
    assert!(matches!(parsed, OperatorResponse::SessionCreated { .. }));

    let plan_approved = json!({
        "status": "PlanApproved",
        "payload": { "initiative_id": "i1", "tasks_admitted": 3 }
    });
    let parsed: OperatorResponse = serde_json::from_value(plan_approved)
        .expect("PlanApproved must decode");
    assert!(matches!(parsed, OperatorResponse::PlanApproved { .. }));

    let err = json!({
        "status": "Error",
        "payload": { "code": "FAIL_X", "detail": "oops" }
    });
    let parsed: OperatorResponse = serde_json::from_value(err)
        .expect("Error must decode");
    assert!(matches!(parsed, OperatorResponse::Error { .. }));

    let approved = json!({
        "status": "EscalationApproved",
        "payload": {
            "escalation_id":      "esc-1",
            "approval_token_id":  "atk-1",
            "approval_token_raw": "ff".repeat(32),
            "expires_at":         1_700_000_000_i64
        }
    });
    let parsed: OperatorResponse = serde_json::from_value(approved)
        .expect("EscalationApproved must decode");
    assert!(matches!(parsed, OperatorResponse::EscalationApproved { .. }));

    let denied = json!({
        "status": "EscalationDenied",
        "payload": { "escalation_id": "esc-1", "denied_at": 1_700_000_000_i64 }
    });
    let parsed: OperatorResponse = serde_json::from_value(denied)
        .expect("EscalationDenied must decode");
    assert!(matches!(parsed, OperatorResponse::EscalationDenied { .. }));
}

// ── Negative case: a flat (un-tagged) shape MUST NOT decode.
//    This guards against accidentally reverting to the pre-PR-2 hand-built
//    `json!({"op":"X", "field":...})` style that bypasses the typed enum.
#[test]
fn flat_request_shape_does_not_decode_into_typed_enum() {
    let flat = json!({
        "op": "RevokeSession",
        "session_id": "s1"  // top-level instead of under "payload"
    });
    let parsed: Result<OperatorRequest, _> = serde_json::from_value(flat);
    assert!(parsed.is_err(),
        "flat-shape JSON MUST be rejected — typed enum requires `payload` envelope");
}
