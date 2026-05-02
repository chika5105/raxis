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
    pub body: serde_json::Value,
}
