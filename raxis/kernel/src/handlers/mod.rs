// raxis-kernel::handlers — Planner-facing and verifier-facing IPC handlers.
//
// Normative reference: kernel-core.md §2.3 `src/ipc/handlers/`.
//
// Handler modules:
//   intent  — handles IntentRequest from planners (planner.sock)
//   witness — handles WitnessSubmission from verifier subprocesses (planner.sock,
//             routed by message variant per spec §2.2 startup step 7)
pub mod intent;
pub mod witness;
