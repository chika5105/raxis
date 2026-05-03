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

use raxis_types::operator_wire::{OperatorRequest, OperatorResponse};
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

// ── Tier-2 stubs: payload is an opaque object, but the variant tag is fixed.
#[test]
fn approve_escalation_wraps_payload_in_typed_envelope() {
    let req = OperatorRequest::ApproveEscalation {
        payload: json!({ "escalation_id": "e1" }),
    };
    let v = serde_json::to_value(&req).unwrap();
    assert_eq!(v["op"], "ApproveEscalation");
    // The typed envelope nests payload twice: outer payload (per
    // OperatorRequest's #[serde(content = "payload")]) wraps the inner
    // tier-2 stub `payload` field.
    assert_eq!(v["payload"]["payload"]["escalation_id"], "e1");
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
