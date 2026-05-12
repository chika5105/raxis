// raxis-kernel::gates::witness — Read-side witness existence check.
//
// Normative reference: kernel-core.md §2.3 `src/gates/witness.rs`.
//
// Does not write witness records. Writes go through
// `ipc/handlers/witness.rs` →
// `witness_index::{write_blob_to_disk, insert_witness_index_in_tx}`
// (Pattern C: blob FS write + SQL index INSERT + verifier-token
// consume composed inside one transaction). This module is
// intentionally kept dumb: it returns the record as stored and
// never makes a pass/fail judgment. The sole interpreter of
// result_class is gates/mod.rs step 4.

use raxis_store::Store;

use crate::witness_index::{self, WitnessRecord};
use super::GateError;

/// Look up a witness record for (evaluation_sha, task_id, gate_type).
///
/// If `verifier_run_id` is Some, returns that specific run.
/// If None, returns the most recently recorded matching row.
/// Returns None if no matching record exists.
///
/// Does NOT interpret result_class. The sole interpreter is gates/mod.rs.
pub fn lookup(
    evaluation_sha:  &str,
    task_id:         &str,
    gate_type:       &str,
    verifier_run_id: Option<&str>,
    store:           &Store,
) -> Result<Option<WitnessRecord>, GateError> {
    witness_index::lookup(evaluation_sha, task_id, gate_type, verifier_run_id, store)
        .map_err(|e| GateError::WitnessError(e.to_string()))
}
