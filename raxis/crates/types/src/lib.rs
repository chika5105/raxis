// raxis-types — shared domain types for the RAXIS kernel and its peripherals.
//
// Normative reference: specs/v1/philosophy.md §1.5 (crate layout) and the type
// definitions scattered across kernel-core.md, kernel-store.md, and
// peripherals.md. Every public type in this crate must match the spec exactly.
//
// Crate rules (philosophy.md §1.5, INV-CRATE-01):
//  - No I/O, no async, no database access, no process spawning.
//  - Pure data definitions + serde derives + Display/Error impls only.
//  - Every other crate depends on this one; it depends on nothing in the workspace.

pub mod capability;
pub mod error;
pub mod escalation;
pub mod fsm;
pub mod id;
pub mod intent;
pub mod operator;
pub mod policy;
pub mod witness;

// Convenient flat re-exports for the most-used types.
pub use capability::{CapabilityClass, DelegationStatus};
pub use error::{OperatorErrorCode, PlannerErrorCode};
pub use escalation::{EscalationClass, EscalationRequest, EscalationResponse, RequestedEscalationScope};
pub use fsm::{InitiativeState, TaskState, BlockReason, TerminalCriteria};
pub use id::{
    CommitSha, DelegationId, EscalationId, GateType, InitiativeId, LineageId, SessionId,
    TaskId, VerifierRunId,
};
pub use intent::{
    BudgetSnapshot, IntentKind, IntentOutcome, IntentRequest, IntentResponse,
    PlannerErrorTemplate, SubmittedClaim,
};
pub use operator::{ApprovalScope, OperatorErrorDetail, OperatorRequest, OperatorResponse};
pub use policy::Role;
pub use witness::{WitnessResultClass, WitnessSubmission};
