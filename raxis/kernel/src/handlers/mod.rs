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
pub mod planner_fetch;
pub mod witness;

// Path A3 universal-airgap admission + DNS resolution handlers.
// Compiled in only when the `runtime-airgap-a3` feature is enabled
// (specs/v2/airgap-architecture.md §6). Default-off builds drop
// these modules entirely so the legacy NIC-based egress path is
// bit-identical to the V2 baseline.
#[cfg(feature = "runtime-airgap-a3")]
pub mod dns_resolve;
#[cfg(feature = "runtime-airgap-a3")]
pub mod tproxy_admit;
