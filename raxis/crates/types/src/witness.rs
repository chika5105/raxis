// raxis-types::witness — WitnessSubmission and WitnessResultClass.
//
// Normative reference:
//   - peripherals.md §3.3 "Output: WitnessSubmission"
//   - peripherals.md §3.3 "`result_class` — canonical enum"
//   - kernel-store.md §2.5.1 Table 13 `witness_records`
//     CHECK (result_class IN ('Pass', 'Fail', 'Inconclusive'))
//
// IMPORTANT: The canonical third variant is "Inconclusive" (DDL wins per the
// authority rule in kernel-store.md intro). The name "Error" that appeared in
// an earlier draft of peripherals.md §3.3 is non-canonical. The DDL CHECK
// constraint is the authoritative source.

use crate::{CommitSha, GateType, TaskId};
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// WitnessResultClass
// DDL: CHECK (result_class IN ('Pass', 'Fail', 'Inconclusive'))
// peripherals.md §3.3 (canonical enum, DDL wins for the name)
// ---------------------------------------------------------------------------

/// The outcome of a single verifier run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WitnessResultClass {
    /// Gate evaluation ran and evidence meets the policy threshold.
    Pass,
    /// Gate evaluation ran but evidence does not meet threshold
    /// (e.g. coverage below minimum). Gate outcome is Fail.
    Fail,
    /// Verifier could not complete evaluation due to an environmental error
    /// (build failure, test runner crash). Not a gate outcome — kernel
    /// re-queues for retry up to `max_verifier_retries` (default 2).
    /// DDL canonical name: "Inconclusive". peripherals.md §3.3 note.
    Inconclusive,
}

impl WitnessResultClass {
    /// All variants in v1 — the canonical set referenced by the
    /// `witness_records.result_class` SQL CHECK constraint
    /// (kernel-store.md §2.5.1 Table 13). Order matches the v1 DDL
    /// CHECK list so the rendered Migration 1 SQL is byte-stable
    /// across builds (the
    /// `migration::tests::migration_1_ddl_fingerprint_is_pinned`
    /// hash guard relies on this ordering).
    ///
    /// **Spec drift contract.** Adding a new variant requires both a
    /// length bump here AND a new migration that ALTERs the CHECK
    /// constraint on already-installed databases.
    pub const ALL: [Self; 3] = [Self::Pass, Self::Fail, Self::Inconclusive];

    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Pass => "Pass",
            Self::Fail => "Fail",
            Self::Inconclusive => "Inconclusive",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Pass" => Some(Self::Pass),
            "Fail" => Some(Self::Fail),
            "Inconclusive" => Some(Self::Inconclusive),
            _ => None,
        }
    }

    /// Returns true for a terminal success (gate cleared).
    pub fn is_pass(self) -> bool {
        self == Self::Pass
    }

    /// Returns true when the verifier should be re-spawned (up to retry limit).
    pub fn should_retry(self) -> bool {
        self == Self::Inconclusive
    }
}

impl fmt::Display for WitnessResultClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// WitnessSubmission
// peripherals.md §3.3 "Output: WitnessSubmission"
//
// Wire: bincode 2.0.1 standard() + 4-byte LE length prefix via raxis-ipc::frame.
// The verifier connects to RAXIS_KERNEL_SOCKET and sends exactly one of these.
// ---------------------------------------------------------------------------

/// The single message a verifier subprocess submits to the kernel on the
/// witness intake UDS. The kernel deduplicates on
/// (task_id, gate_type, verifier_run_token) — peripherals.md §3.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSubmission {
    /// The RAXIS_VERIFIER_TOKEN value from the verifier's spawn envelope.
    /// Single-use; kernel consumes it on first valid presentation.
    pub verifier_token: String,

    /// Must match RAXIS_TASK_ID from the spawn envelope.
    pub task_id: TaskId,

    /// Must match RAXIS_GATE_TYPE from the spawn envelope.
    pub gate_type: GateType,

    /// Must match RAXIS_EVALUATION_SHA from the spawn envelope.
    /// Mismatch → EvaluationShaMismatch rejection (token not consumed).
    pub evaluation_sha: CommitSha,

    /// The outcome of this verifier run.
    pub result_class: WitnessResultClass,

    /// Gate-type-specific structured evidence. Schema is per GateType.
    /// The kernel validates the body schema; malformed bodies → witness rejected.
    /// Stored as raw JSON bytes in `witness_records.witness_body_json`.
    ///
    /// **Wire encoding:** `serde_json::Value` cannot round-trip through
    /// bincode 2 because `Value::deserialize` dispatches via
    /// `deserialize_any` — bincode's strict (non-self-describing) codec
    /// surfaces this as `Decode(Serde(AnyNotSupported))`. We work
    /// around that by encoding the body as a JSON STRING on the wire
    /// (which bincode trivially supports) and re-parsing it on the
    /// receiving side. The in-memory shape stays `serde_json::Value`,
    /// so handlers and producers see the same API as before. This is
    /// pinned by `witness::tests::witness_submission_round_trips_through_bincode`.
    #[serde(with = "json_value_as_string")]
    pub body: serde_json::Value,
}

/// Serde helper: round-trip a `serde_json::Value` through any
/// non-self-describing format (bincode in our case) by encoding it as
/// a JSON string. See the doc on `WitnessSubmission.body` for the
/// rationale; `cargo test -p raxis-types` enforces the round-trip.
mod json_value_as_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_json::Value;

    pub fn serialize<S>(v: &Value, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // We use `to_string` (not `to_vec`) because the wire side reads
        // it back via `String::deserialize`. Errors are extremely rare
        // here — `serde_json::to_string` only fails on a `Value` with
        // non-string map keys, which `Value` itself cannot represent.
        let json = serde_json::to_string(v).map_err(serde::ser::Error::custom)?;
        s.serialize_str(&json)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        // We deserialize the wire bytes as a `String` (bincode handles
        // strings natively as length-prefixed UTF-8) and then re-parse
        // the JSON with `serde_json::from_str`. This sidesteps
        // `deserialize_any` on the `bincode` side; the JSON parser
        // does its own self-describing read of the string body.
        let s = String::deserialize(d)?;
        serde_json::from_str(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `WitnessSubmission` literal for round-trip tests. The
    /// `body` is intentionally non-empty and mixes scalar / array /
    /// nested-object shapes so any future regression in the JSON-as-string
    /// helper surfaces immediately rather than only in production.
    fn fixture_submission() -> WitnessSubmission {
        WitnessSubmission {
            verifier_token: "tok-abc".to_owned(),
            task_id: TaskId::parse("task-1").expect("valid task_id"),
            gate_type: GateType::parse("TestCoverage").expect("valid gate_type"),
            evaluation_sha: CommitSha::parse("abcd1234abcd1234abcd1234abcd1234abcd1234")
                .expect("valid 40-char SHA"),
            result_class: WitnessResultClass::Pass,
            body: serde_json::json!({
                "coverage_pct": 92.5,
                "lines_uncovered": 14,
                "evidence": ["src/foo.rs:42", "src/bar.rs:108"],
                "nested": { "k": [1, 2, 3] },
                "null_field": null,
            }),
        }
    }

    /// REGRESSION GUARD (P0): pre-fix, `serde_json::Value::deserialize`
    /// dispatched via `deserialize_any`, and bincode 2's strict
    /// non-self-describing decode rejected the result with
    /// `Decode(Serde(AnyNotSupported))`. This means a real verifier
    /// could submit a `WitnessSubmission` and the kernel's `read_frame`
    /// would fail to decode it — i.e. the witness intake path would
    /// be broken in production for ANY non-trivial body.
    ///
    /// The fix is a custom serde helper (`json_value_as_string`) that
    /// encodes the body as a JSON string on the wire. Removing or
    /// breaking that helper MUST fail this test loudly.
    #[test]
    fn witness_submission_round_trips_through_bincode() {
        let original = fixture_submission();

        // Round-trip via the EXACT codec the kernel uses on the wire
        // (bincode::config::standard() — see peripherals.md §3.3 and
        // raxis-ipc::frame). If the kernel and verifier ever disagree
        // about the wire codec, this test will not catch it — but
        // `raxis-ipc::frame::round_trip_*` tests pin THAT contract.
        let encoded = bincode::serde::encode_to_vec(&original, bincode::config::standard())
            .expect("encode WitnessSubmission via bincode standard()");
        let (decoded, _consumed): (WitnessSubmission, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
                .expect("decode WitnessSubmission via bincode standard()");

        // Field-by-field equality. We do NOT derive PartialEq on
        // `WitnessSubmission` (the body is `serde_json::Value` which
        // does have PartialEq), but we have to compare each field
        // explicitly because the struct itself does not.
        assert_eq!(decoded.verifier_token, original.verifier_token);
        assert_eq!(decoded.task_id.as_str(), original.task_id.as_str());
        assert_eq!(decoded.gate_type.as_str(), original.gate_type.as_str());
        assert_eq!(
            decoded.evaluation_sha.as_str(),
            original.evaluation_sha.as_str()
        );
        assert_eq!(decoded.result_class, original.result_class);
        // Most important assertion: the body round-trips with full
        // structural equality, including the nested object and the
        // `null` value (which is its own discriminant in
        // `serde_json::Value`).
        assert_eq!(
            decoded.body, original.body,
            "WitnessSubmission.body must round-trip through bincode without drift"
        );
    }

    #[test]
    fn witness_submission_round_trips_with_empty_object_body() {
        // The default body the verifier-stub emits is `{}`. Pin it
        // separately because an empty `Map` is a different
        // `serde_json::Value` discriminant than the populated one
        // exercised above and our helper must support both.
        let mut sub = fixture_submission();
        sub.body = serde_json::json!({});

        let encoded = bincode::serde::encode_to_vec(&sub, bincode::config::standard())
            .expect("encode empty-body submission");
        let (decoded, _): (WitnessSubmission, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
                .expect("decode empty-body submission");
        assert_eq!(decoded.body, serde_json::json!({}));
    }

    #[test]
    fn witness_submission_round_trips_with_null_body() {
        // `Value::Null` is a yet-different discriminant. Cover it
        // explicitly so a future helper that special-cases "object"
        // does not silently break the null path.
        let mut sub = fixture_submission();
        sub.body = serde_json::Value::Null;

        let encoded = bincode::serde::encode_to_vec(&sub, bincode::config::standard())
            .expect("encode null-body submission");
        let (decoded, _): (WitnessSubmission, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
                .expect("decode null-body submission");
        assert_eq!(decoded.body, serde_json::Value::Null);
    }
}
