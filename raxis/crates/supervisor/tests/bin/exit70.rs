// Fake kernel binary that exits with code 70 (deadlock).
// Used by `tests/supervisor_classifier_witness.rs` to exercise
// the supervisor's `Outcome::DeadlockDetected` decision path.

fn main() {
    std::process::exit(70);
}
