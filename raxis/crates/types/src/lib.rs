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
pub mod clock;
pub mod error;
pub mod escalation;
pub mod fsm;
pub mod host_preflight;
pub mod id;
pub mod initiative_event;
pub mod intent;
pub mod intent_admit;
pub mod operator;
pub mod operator_cert;
pub mod operator_wire;
pub mod plan_bundle;
pub mod planner_env;
pub mod planner_exit;
pub mod planner_fetch;
pub mod policy;
pub mod push;
pub mod structured_output;
pub mod tproxy;
pub mod witness;

// Convenient flat re-exports for the most-used types.
pub use capability::{CapabilityClass, DelegationStatus};
pub use clock::{unix_now_secs, Clock, RealClock};
pub use error::{
    EmptyReasonError, FailureReason, OperatorErrorCode, PlannerErrorCode, MAX_FAILURE_REASON_LEN,
};
pub use escalation::{
    EscalationClass, EscalationRejectionReason, EscalationRequest, EscalationResponse,
    EscalationStatus, RequestedEscalationScope, MAX_LOGICAL_DEADLOCK_REASON_LEN,
    MAX_MERGE_CONFLICT_PATHS, MAX_MERGE_CONFLICT_PATH_LEN,
};
pub use fsm::{
    BlockReason, CircuitBreakerState, CloneStrategy, InitiativeState,
    IntegrationMergeAttemptDiscardReason, IntegrationMergeAttemptState, PlanBundleNonceOutcome,
    ReviewVerdict, SessionAgentType, SubtaskActivationState, TaskState, TerminalCriteria,
};
pub use host_preflight::{DiskVolumeReport, HostPreflightError};
pub use id::{
    CommitSha, CommitShaError, DelegationId, EscalationId, GateType, GateTypeError, InitiativeId,
    LineageId, SessionId, TaskId, TaskIdError, VerifierRunId,
};
pub use initiative_event::{ClosedReason, InitiativeEvent};
pub use intent::{
    BatchTaskOutcome, BatchTaskResult, BudgetSnapshot, IntentKind, IntentOutcome, IntentRequest,
    IntentResponse, NotAdmissibleReason, PlannerErrorTemplate, SubmittedClaim, TokensReport,
    MAX_BATCH_ACTIVATE_TASK_IDS, MAX_CRITIQUE_BYTES,
};
pub use operator::{ApprovalScope, OperatorErrorDetail, OperatorRequest, OperatorResponse};
pub use operator_cert::{CertKind, OperatorCert};
pub use plan_bundle::{
    BundleArtifact, BundleNonce, BundleSha256, OperatorFingerprint, PlanBundle, SchemaVersion,
};
pub use planner_exit::PlannerExitOutcome;
pub use planner_fetch::{PlannerFetchKind, PlannerFetchRequest, PlannerFetchResponse};
pub use policy::Role;
pub use push::{KernelPush, KernelPushFrame};
pub use structured_output::{
    DiagnosticSeverity, StructuredOutputKind, STRUCTURED_OUTPUT_MAX_APPROACH_BYTES,
    STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES, STRUCTURED_OUTPUT_MAX_PATH_BYTES,
    STRUCTURED_OUTPUT_MAX_PATH_LIST_LEN, STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT,
};
pub use tproxy::{
    DnsQueryType, DnsResolveRequest, DnsResolveResponse, TproxyAdmissionRequest,
    TproxyAdmissionResponse, TproxyProtocol,
};
pub use witness::{WitnessResultClass, WitnessSubmission};
