// raxis-kernel::handlers::agent_hint — agent_hint wire validity +
// three-tier resolution for non-Pass `WitnessSubmission` bodies.
//
// Normative reference:
//   - specs/v3/gate-rejection-orchestrator-fixup.md §2
//     ("`agent_hint` Reserved Key")
//   - specs/invariants.md
//     INV-WITNESS-AGENT-HINT-WIRE-VALID-01
//     INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01
//
// This module is intentionally pure: every function takes inputs by
// reference, returns a typed result, and has no `&HandlerContext` or
// SQLite dependency. The caller (`handlers::witness`) wires the
// resolved string into the `tasks` row update + audit emission.
// Keeping the logic in a sibling module makes it trivial to unit-test
// the tier transitions in isolation.

use serde_json::Value;

use super::witness::{
    WitnessRejectionReason, WITNESS_AGENT_HINT_MAX_BYTES, WITNESS_BODY_AGENT_HINT_KEY,
};

// ---------------------------------------------------------------------------
// Wire validity
// ---------------------------------------------------------------------------

/// The outcome of inspecting `body.agent_hint` on a non-`Pass`
/// `WitnessSubmission`. Drives both rejection (wire-invalid) and the
/// tier-fallback chain (absent / empty drops to operator default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentHintWire<'a> {
    /// Verifier emitted a non-empty UTF-8 string ≤ 8 KiB. Tier 1.
    Present(&'a str),
    /// Field absent entirely OR present but empty string. The kernel
    /// commits the witness and falls back through tier 2 / defensive.
    AbsentOrEmpty,
    /// Field is present but violates the wire contract. The witness
    /// is REJECTED; token is NOT consumed; the kernel emits a
    /// `WitnessMissingAgentHint` audit row keyed by the rejection
    /// reason.
    Invalid(WitnessRejectionReason),
}

/// Inspect `body.agent_hint` against the wire contract from
/// `INV-WITNESS-AGENT-HINT-WIRE-VALID-01`.
///
/// **`Pass` submissions are exempt** from this check; callers MUST
/// skip the inspection entirely when `result_class == Pass`.
///
/// Rules:
/// - body must be a JSON object (otherwise no place to carry the key).
/// - if the key is absent → `AbsentOrEmpty`.
/// - if the value is `Null` or `String("")` → `AbsentOrEmpty`.
/// - if the value is `String(s)` with `s.len() > WITNESS_AGENT_HINT_MAX_BYTES` → `Invalid("oversized")`.
/// - if the value is `String(s)` with valid length → `Present(s)`.
/// - any other JSON type (number, bool, array, object) → `Invalid("non_string")`.
pub fn inspect_wire(body: &Value) -> AgentHintWire<'_> {
    let obj = match body {
        Value::Object(map) => map,
        // Non-object bodies cannot carry the reserved key by
        // structure. Treat as "absent" so the tier-fallback chain
        // resolves rather than rejecting wire-valid Fail witnesses
        // that simply have a non-object body shape.
        _ => return AgentHintWire::AbsentOrEmpty,
    };
    let raw = match obj.get(WITNESS_BODY_AGENT_HINT_KEY) {
        Some(v) => v,
        None => return AgentHintWire::AbsentOrEmpty,
    };
    match raw {
        Value::Null => AgentHintWire::AbsentOrEmpty,
        Value::String(s) if s.is_empty() => AgentHintWire::AbsentOrEmpty,
        Value::String(s) if s.len() > WITNESS_AGENT_HINT_MAX_BYTES => {
            AgentHintWire::Invalid(WitnessRejectionReason::InvalidAgentHint {
                reason: "oversized",
            })
        }
        Value::String(s) => AgentHintWire::Present(s.as_str()),
        // Numbers, arrays, booleans, objects, etc. — wire-invalid.
        _ => AgentHintWire::Invalid(WitnessRejectionReason::InvalidAgentHint {
            reason: "non_string",
        }),
    }
}

// ---------------------------------------------------------------------------
// Tier resolution
// ---------------------------------------------------------------------------

/// Which tier produced the resolved hint. Drives the
/// `WitnessMissingAgentHint{source}` audit on tier-2 and the
/// defensive fallback. Tier 1 (verifier-emitted) commits the witness
/// without a missing-hint audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedTier {
    /// `body.agent_hint` was present + wire-valid. No audit emission.
    Verifier,
    /// Operator-supplied `[[gates]].agent_hint_default`. Emits
    /// `WitnessMissingAgentHint{source:"operator_default", reason}`.
    OperatorDefault,
    /// Defensive gate-name-only template. Reachable only after a
    /// regression bypassed policy-load validation. Emits
    /// `WitnessMissingAgentHint{source:"gate_name_only", reason}`
    /// AND a loud kernel-bug stderr warning at the call site.
    GateNameOnly,
}

/// The fully-resolved hint a non-`Pass` witness commits as
/// `tasks.last_gate_critique`, plus the tier discriminator the
/// caller uses to drive audit emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHint {
    pub critique: String,
    pub tier: ResolvedTier,
    /// `"absent"` | `"empty"` for tier 2 / defensive fallback.
    /// `None` for tier 1. Mirrors the
    /// `WitnessMissingAgentHint.reason` audit field.
    pub fallback_reason: Option<&'static str>,
}

/// Render the defensive fallback hint when both tier-1 (verifier)
/// and tier-2 (operator default) are unavailable. Public so the
/// witness handler can re-use this exact string in stderr warnings.
pub fn render_defensive_template(gate_type: &str) -> String {
    format!(
        "Gate '{gate_type}' rejected this change. Review your work against the '{gate_type}' \
         policy and adjust your commit before resubmitting."
    )
}

/// Resolve the effective hint for a non-`Pass` witness through the
/// three-tier chain pinned by
/// `INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01`:
///
/// 1. Verifier-emitted (`body.agent_hint`).
/// 2. Operator-supplied (`[[gates]].agent_hint_default`).
/// 3. Defensive gate-name-only template.
///
/// `wire` is the output of [`inspect_wire`] on the same body
/// (callers must NOT call this with `AgentHintWire::Invalid` — that
/// case is REJECT, not resolve; see the handler's pre-commit
/// branching).
pub fn resolve(
    wire: AgentHintWire<'_>,
    operator_default: Option<&str>,
    gate_type: &str,
) -> ResolvedHint {
    match wire {
        AgentHintWire::Present(s) => ResolvedHint {
            critique: s.to_owned(),
            tier: ResolvedTier::Verifier,
            fallback_reason: None,
        },
        AgentHintWire::AbsentOrEmpty => match operator_default {
            Some(default) if !default.trim().is_empty() => ResolvedHint {
                critique: default.to_owned(),
                tier: ResolvedTier::OperatorDefault,
                // We treat both "absent" and "empty string" as
                // "absent" for audit purposes — the verifier delivered
                // nothing actionable, regardless of whether the key
                // was missing or present-but-empty.
                fallback_reason: Some("absent"),
            },
            _ => ResolvedHint {
                critique: render_defensive_template(gate_type),
                tier: ResolvedTier::GateNameOnly,
                fallback_reason: Some("absent"),
            },
        },
        AgentHintWire::Invalid(_) => {
            // Callers must NOT reach this branch — wire-invalid hints
            // reject the submission. Returning a defensive fallback
            // here keeps the function total without panicking, and
            // any production reach would surface as both a noisy
            // stderr warning at the call site AND the rejection path
            // (which the witness handler emits BEFORE calling
            // `resolve`).
            ResolvedHint {
                critique: render_defensive_template(gate_type),
                tier: ResolvedTier::GateNameOnly,
                fallback_reason: Some("wire_invalid"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── inspect_wire ────────────────────────────────────────────────────

    #[test]
    fn inspect_wire_absent_when_key_missing() {
        let body = json!({ "findings": [] });
        assert_eq!(inspect_wire(&body), AgentHintWire::AbsentOrEmpty);
    }

    #[test]
    fn inspect_wire_absent_when_empty_string() {
        let body = json!({ "agent_hint": "" });
        assert_eq!(inspect_wire(&body), AgentHintWire::AbsentOrEmpty);
    }

    #[test]
    fn inspect_wire_absent_when_null() {
        let body = json!({ "agent_hint": serde_json::Value::Null });
        assert_eq!(inspect_wire(&body), AgentHintWire::AbsentOrEmpty);
    }

    #[test]
    fn inspect_wire_present_when_valid_string() {
        let body = json!({ "agent_hint": "Remove the AWS access key from src/auth.rs:42." });
        match inspect_wire(&body) {
            AgentHintWire::Present(s) => {
                assert!(s.starts_with("Remove the AWS"));
            }
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn inspect_wire_invalid_non_string() {
        let cases = vec![
            json!({ "agent_hint": 42 }),
            json!({ "agent_hint": ["a", "b"] }),
            json!({ "agent_hint": { "k": "v" } }),
            json!({ "agent_hint": true }),
        ];
        for case in cases {
            match inspect_wire(&case) {
                AgentHintWire::Invalid(WitnessRejectionReason::InvalidAgentHint {
                    reason: "non_string",
                }) => {}
                other => panic!("expected non_string Invalid, got {other:?} for {case}"),
            }
        }
    }

    #[test]
    fn inspect_wire_invalid_oversized() {
        // One byte over the cap. Keep this assertion sharp so a future
        // off-by-one in the comparison surfaces clearly.
        let oversized = "x".repeat(WITNESS_AGENT_HINT_MAX_BYTES + 1);
        let body = json!({ "agent_hint": oversized });
        assert_eq!(
            inspect_wire(&body),
            AgentHintWire::Invalid(WitnessRejectionReason::InvalidAgentHint {
                reason: "oversized"
            })
        );
        // Boundary: exactly at the cap must pass.
        let at_cap = "y".repeat(WITNESS_AGENT_HINT_MAX_BYTES);
        let body = json!({ "agent_hint": at_cap });
        match inspect_wire(&body) {
            AgentHintWire::Present(_) => {}
            other => panic!("expected Present at-cap, got {other:?}"),
        }
    }

    #[test]
    fn inspect_wire_treats_non_object_body_as_absent() {
        // Non-object bodies cannot carry the reserved key by
        // structure. The fallback chain handles them; the wire path
        // does NOT reject (otherwise we'd break every legacy
        // null-body verifier that intends Fail/Inconclusive).
        for body in [
            json!(null),
            json!("just a string body"),
            json!(42),
            json!(["a", "b"]),
        ] {
            assert_eq!(inspect_wire(&body), AgentHintWire::AbsentOrEmpty);
        }
    }

    // ── resolve / tier fallback ─────────────────────────────────────────

    #[test]
    fn resolve_tier_1_uses_verifier_hint_verbatim() {
        let hint = "AWS access key shape detected at src/auth.rs:42.";
        let r = resolve(
            AgentHintWire::Present(hint),
            Some("operator default unused"),
            "NoSecretStrings",
        );
        assert_eq!(r.critique, hint);
        assert_eq!(r.tier, ResolvedTier::Verifier);
        assert!(r.fallback_reason.is_none());
    }

    #[test]
    fn resolve_tier_2_uses_operator_default_when_verifier_absent() {
        let r = resolve(
            AgentHintWire::AbsentOrEmpty,
            Some("Operator-supplied repair instructions go here."),
            "NoSecretStrings",
        );
        assert_eq!(
            r.critique,
            "Operator-supplied repair instructions go here."
        );
        assert_eq!(r.tier, ResolvedTier::OperatorDefault);
        assert_eq!(r.fallback_reason, Some("absent"));
    }

    #[test]
    fn resolve_defensive_fallback_renders_gate_name_template() {
        let r = resolve(AgentHintWire::AbsentOrEmpty, None, "NoSecretStrings");
        assert_eq!(r.tier, ResolvedTier::GateNameOnly);
        assert!(
            r.critique.contains("'NoSecretStrings'"),
            "defensive template must surface gate_type in single quotes (got: {})",
            r.critique
        );
        assert_eq!(r.fallback_reason, Some("absent"));
    }

    #[test]
    fn resolve_empty_operator_default_falls_through_to_defensive() {
        // An operator default that's just whitespace must NOT be
        // accepted at runtime — it provides no actionable signal.
        // The policy validator catches this at load, but the
        // resolver is defensively coded for the post-validation
        // regression case.
        for blank in ["", "   ", "\t\n"] {
            let r = resolve(AgentHintWire::AbsentOrEmpty, Some(blank), "TestCoverage");
            assert_eq!(r.tier, ResolvedTier::GateNameOnly);
            assert!(r.critique.contains("'TestCoverage'"));
        }
    }

    #[test]
    fn resolve_invariant_defensive_template_includes_gate_type_twice() {
        // The defensive template references the gate_type twice
        // (subject + object of the sentence) so the message is
        // self-contained when surfaced to an agent that has no other
        // gate context. Pin the shape against drift.
        let s = render_defensive_template("MyCustomGate");
        let count = s.matches("'MyCustomGate'").count();
        assert_eq!(
            count, 2,
            "defensive template must reference gate_type twice (got: {s})"
        );
    }
}
