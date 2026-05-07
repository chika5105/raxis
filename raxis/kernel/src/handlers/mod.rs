// raxis-kernel::handlers — Planner-facing and verifier-facing IPC handlers.
//
// Normative reference: kernel-core.md §2.3 `src/ipc/handlers/`.
//
// Handler modules:
//   intent     — handles IntentRequest from planners (planner.sock)
//   witness    — handles WitnessSubmission from verifier subprocesses
//                (planner.sock, routed by message variant per spec §2.2
//                startup step 7)
//   escalation — handles EscalationRequest from planners (planner.sock,
//                same socket as IntentRequest, different IpcMessage
//                variant per kernel-core.md §2.3 dispatcher table).
pub mod escalation;
pub mod intent;
pub mod integration_merge_attribution;
pub mod witness;
