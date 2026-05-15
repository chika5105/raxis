// raxis-ipc::message — Top-level IpcMessage and GatewayMessage enums.
//
// Normative reference:
//   - peripherals.md §3.1 (planner socket messages)
//   - peripherals.md §3.2 (gateway socket messages)
//   - peripherals.md §3.3 (verifier / witness intake)
//   - kernel-core.md §`handlers/operator.rs` (operator socket)
//
// There are THREE distinct UDS sockets; each carries a separate top-level
// message type. Mixing them is a protocol violation caught by auth.rs.
//
//   planner.sock  → IpcMessage (planner variants + witness intake)
//   operator.sock → IpcMessage (operator variants)
//   gateway.sock  → GatewayMessage
//
// In v1 the planner, witness, and operator messages share one enum to
// keep the framing layer uniform. The socket-level `permitted_message_kinds`
// check in ipc/auth.rs enforces that a planner session cannot send operator
// messages and vice versa.

use raxis_types::{
    DnsResolveRequest, DnsResolveResponse, EscalationRequest, EscalationResponse, IntentRequest,
    IntentResponse, OperatorRequest, OperatorResponse, PlannerExitOutcome, PlannerFetchRequest,
    PlannerFetchResponse, TproxyAdmissionRequest, TproxyAdmissionResponse, WitnessSubmission,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// IpcMessage — planner socket, operator socket, witness intake
// ---------------------------------------------------------------------------

/// The top-level discriminant enum for all messages on the planner and
/// operator UDS sockets. Wire: positional bincode 2.0.1 standard() u32 tag.
//
// `clippy::large_enum_variant` is intentionally allowed: the variant
// payloads are wire-stable (per `peripherals.md §3.1`) and bincode
// serializes them positionally, so boxing the larger variants
// (`IntentRequest` ~440 B vs `EscalationRequest` ~184 B) would
// either change the wire shape or force a per-variant Box wrapper
// purely to satisfy a heap-vs-stack tradeoff that doesn't apply
// here. IpcMessage values live for the duration of a single
// dispatch frame; they are not stored in collections or moved
// around in hot loops.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcMessage {
    // -----------------------------------------------------------------------
    // Planner socket — inbound (planner → kernel)
    // peripherals.md §3.1
    // -----------------------------------------------------------------------
    /// A planner intent submission.
    IntentRequest(IntentRequest),

    /// A planner escalation submission.
    /// Sent on the same socket as IntentRequest (same session context).
    EscalationRequest(EscalationRequest),

    /// **Kernel-mediated egress request.** The planner asks the kernel
    /// to perform an HTTP fetch against an external service on its
    /// behalf (typically an LLM provider call). The kernel forwards
    /// the request to the gateway subprocess and routes the response
    /// back as a [`Self::KernelPlannerFetchResponse`].
    ///
    /// Normative reference: `provider-failure-handling.md §2.1` and
    /// `peripherals.md §3.1`. This is the sole egress path for
    /// planners running in `EgressTier::None` substrates (the
    /// canonical Orchestrator and Reviewer guests).
    PlannerFetchRequest(PlannerFetchRequest),

    // -----------------------------------------------------------------------
    // Planner socket — outbound (kernel → planner)
    // peripherals.md §3.1
    // -----------------------------------------------------------------------
    /// Kernel response to an IntentRequest.
    KernelIntentResponse(IntentResponse),

    /// Kernel response to an EscalationRequest.
    KernelEscalationResponse(EscalationResponse),

    /// Kernel response to a [`Self::PlannerFetchRequest`]. Carries the
    /// upstream provider's response (status / headers / body) or a
    /// stable short failure code in the `error` field. The
    /// `request_id` echoes the planner's correlation id from the
    /// request.
    KernelPlannerFetchResponse(PlannerFetchResponse),

    /// **Planner → kernel — `INV-FAILURE-REASON-CONCRETE-01`.** The
    /// planner-core driver emits this notice immediately before
    /// the role binary returns from `main`. It carries the
    /// structured reason the dispatch loop terminated
    /// ([`PlannerExitOutcome`]) so the kernel's `drive_planner_stream`
    /// can capture a concrete cause for the Mode-B premature-exit
    /// synthesis in `session_spawn_orchestrator`.
    ///
    /// **Wire contract.**
    ///   * Sent at most once per session, immediately before EOF.
    ///   * Kernel responds with [`Self::KernelPlannerExitNoticeAck`]
    ///     so the request/reply shape of the planner socket is
    ///     preserved. The planner ignores ack errors — the notice
    ///     is best-effort forensic context, NOT a structural
    ///     unstall mechanism (the kernel's EOF-driven Mode-B
    ///     synthesis still fires even if the notice never
    ///     arrives, e.g. SIGKILL / panic mid-loop).
    ///
    /// Anchors `INV-FAILURE-REASON-CONCRETE-01` (specs/invariants.md)
    /// and `audit-paired-writes.md §14.8`. See `planner-harness.md`
    /// for the role-binary contract.
    PlannerExitNotice {
        /// Structured reason the dispatch loop terminated.
        outcome: PlannerExitOutcome,
    },

    /// Kernel acknowledgement of a [`Self::PlannerExitNotice`].
    /// Carries no payload — the planner only needs to know its
    /// frame round-tripped before issuing `LINUX_REBOOT_CMD_POWER_OFF`.
    KernelPlannerExitNoticeAck,

    // -----------------------------------------------------------------------
    // Path A3 — in-guest tproxy admission + DNS resolution.
    // airgap-architecture.md §3
    // -----------------------------------------------------------------------
    /// **Guest → kernel.** Admission request from the in-VM
    /// `raxis-tproxy` for one outbound TCP connection it has
    /// intercepted via iptables REDIRECT. The kernel matches the
    /// `(sni, host_header, destination)` tuple against the session's
    /// `policy.tproxy_allowlist`, emits the paired
    /// `TproxyAdmissionGranted` / `TproxyAdmissionDenied` audit
    /// event, and responds with `KernelTproxyAdmissionResponse`. See
    /// `airgap-architecture.md §3.1` for the wire-protocol contract.
    ///
    /// Only present on the per-session A3 admission vsock channel;
    /// the kernel's planner socket dispatch loop also routes this
    /// variant when running in A3 mode so the admission frames share
    /// the planner socket's session-token authentication contract.
    TproxyAdmissionRequest(TproxyAdmissionRequest),

    /// **Kernel → guest.** Verdict for a [`Self::TproxyAdmissionRequest`].
    /// On Admit the guest re-dials the kernel's tunnel port with the
    /// returned `(tunnel_id, tunnel_token)`; on Deny it closes the
    /// agent-side TCP with RST.
    KernelTproxyAdmissionResponse(TproxyAdmissionResponse),

    /// **Guest → kernel.** DNS resolution request from the in-VM
    /// stub forwarder. The kernel resolves via the host-side
    /// resolver and audits the hostname before returning the
    /// resolved addresses. DNS resolution does not itself grant
    /// egress (see `INV-NETISO-A3-DNS-MEDIATED-01`).
    DnsResolveRequest(DnsResolveRequest),

    /// **Kernel → guest.** Resolved addresses for a
    /// [`Self::DnsResolveRequest`]. Empty `addresses` ⇒ NXDOMAIN /
    /// resolver failure.
    KernelDnsResolveResponse(DnsResolveResponse),

    // -----------------------------------------------------------------------
    // Verifier / witness intake (verifier → kernel)
    // peripherals.md §3.3
    // -----------------------------------------------------------------------
    /// A verifier subprocess submitting its gate evaluation result.
    WitnessSubmission(WitnessSubmission),

    /// Kernel acknowledgement of a witness submission.
    WitnessAck {
        /// The verifier_run_id from the submission; echoed for correlation.
        verifier_run_id: Uuid,
        /// true if the witness was accepted; false if rejected (see reason).
        accepted: bool,
        /// On rejection: a short reason string for the verifier's stderr.
        /// INV-08 does not apply to verifier↔kernel messages.
        reason: Option<String>,
    },

    // -----------------------------------------------------------------------
    // Operator socket — inbound (operator CLI → kernel)
    // cli-ceremony.md §4.1, peripherals.md §3
    // -----------------------------------------------------------------------
    /// An operator command.
    OperatorRequest(OperatorRequest),

    // -----------------------------------------------------------------------
    // Operator socket — outbound (kernel → operator CLI)
    // peripherals.md §3 "Operator socket"
    // -----------------------------------------------------------------------
    /// Kernel response to an OperatorRequest.
    OperatorResponse(OperatorResponse),
}

// ---------------------------------------------------------------------------
// GatewayMessage — gateway socket only
// peripherals.md §3.2
// ---------------------------------------------------------------------------

/// Messages exchanged on the gateway UDS socket (kernel ↔ gateway subprocess).
///
/// The gateway socket uses its own message type (not IpcMessage) because the
/// gateway has no planner context and the message set is entirely different.
#[derive(Debug, Serialize, Deserialize)]
pub enum GatewayMessage {
    // -----------------------------------------------------------------------
    // kernel → gateway
    // peripherals.md §3.2 "FetchRequest wire shape"
    // -----------------------------------------------------------------------
    FetchRequest {
        /// The gateway_process_token issued at spawn time. Validated by gateway.
        gateway_token: String,
        /// UUID v4 for correlating this request to its FetchResponse.
        fetch_id: Uuid,
        /// "Inference" or "DataFetch" — different timeout/size limits apply.
        fetch_kind: FetchKind,
        url: String,
        method: String,
        /// HTTP headers as key-value pairs.
        headers: Vec<(String, String)>,
        /// Raw request body bytes. The gateway injects credentials then forwards.
        body_bytes: Vec<u8>,
        /// Maximum milliseconds to wait for a response. Hard cap: 120_000 ms.
        timeout_ms: u32,
        /// Session context for audit logging (not used for auth by the gateway).
        session_id: Option<Uuid>,
        /// Task context for audit logging.
        task_id: Option<String>,
    },

    /// Signal from the kernel that the policy epoch has advanced.
    /// Gateway must re-read `policy.toml` before processing the next
    /// `FetchRequest`. peripherals.md §3.2 "Domain allowlist re-validation"
    /// and kernel-core.md §`policy_manager.rs` Phase 3 ("Gateway signal").
    ///
    /// `new_epoch_id` is the monotonic `u64` epoch counter (matches
    /// `policy_epoch_history.epoch_id` and `meta.epoch` in `policy.toml`).
    /// Typed as `u64` (rather than UUID) to explicitly enforce monotonicity
    /// (preventing replay attacks of older policies) and to provide human-readable
    /// sequence numbers for operator ergonomics (e.g. `policy_epoch: 4`).
    EpochAdvanced { new_epoch_id: u64 },

    // -----------------------------------------------------------------------
    // gateway → kernel
    // peripherals.md §3.2 "FetchResponse wire shape"
    // -----------------------------------------------------------------------
    FetchResponse {
        /// Correlates to the FetchRequest.fetch_id.
        fetch_id: Uuid,
        /// HTTP status code, or None if the request failed before a response.
        status_code: Option<u16>,
        /// Response headers.
        headers: Vec<(String, String)>,
        /// Raw response body bytes. Max 16 MiB (configurable per provider).
        /// None on error.
        body_bytes: Option<Vec<u8>>,
        /// Observed latency in milliseconds.
        latency_ms: u32,
        /// On error: a short reason string.
        /// Possible values: "TimeoutExceeded", "DomainNotAllowed",
        /// "ResponseTooLarge", "PolicyReloadFailed", "NetworkError".
        error: Option<String>,
    },

    /// Gateway → kernel: gateway is ready to accept requests (sent once at startup
    /// after the gateway has loaded credentials and policy).
    GatewayReady { gateway_token: String },
}

/// The kind of external fetch, determining timeout and size limits.
/// peripherals.md §3.2: "Inference" vs "DataFetch".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FetchKind {
    /// LLM API call. Higher timeout; response body validated by the provider adapter.
    Inference,
    /// URL data fetch for context. Lower timeout; 16 MiB body limit.
    DataFetch,
}
