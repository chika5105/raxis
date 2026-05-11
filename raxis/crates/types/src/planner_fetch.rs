// raxis-types::planner_fetch — kernel-mediated HTTP fetch wire types.
//
// Normative references:
//   * `provider-failure-handling.md §2.1` — the planner ↔ kernel ↔
//     gateway flow: the planner submits an InferenceRequest over its
//     vsock channel; the kernel resolves alias / breaker / budget,
//     dispatches to the gateway, and returns the response.
//   * `peripherals.md §3.1` — planner socket; this is the new
//     IpcMessage variant pair `PlannerFetchRequest` /
//     `KernelPlannerFetchResponse`.
//   * `peripherals.md §3.2` — gateway socket; the kernel forwards
//     the planner's request to the gateway as a
//     `GatewayMessage::FetchRequest` (the kernel substitutes its
//     `gateway_token` for the planner's `session_token` since the
//     planner has no gateway authority).
//
// # Why this lives in raxis-types and not raxis-ipc
//
// The wire envelope is in raxis-ipc::message::IpcMessage; the
// per-variant payload structs live here because every other planner
// IPC payload (`IntentRequest`, `EscalationRequest`,
// `WitnessSubmission`, …) does. Keeps the layering one-way:
// `raxis-ipc → raxis-types`, never the reverse.
//
// # Why the planner specifies the URL (not just provider + model)
//
// V2 GA: the planner's model client constructs the upstream URL
// (e.g. `https://api.anthropic.com/v1/messages`) because it owns
// the per-provider SDK (chat-completions vs messages vs Bedrock
// runtime invoke). The kernel re-validates the URL against the
// gateway's `policy.toml` allowlist before forwarding, so a
// compromised planner cannot reach a domain the operator has not
// signed off on. This keeps the planner SDK pluggable
// (`ModelClient` impls don't have to teach the kernel a new
// URL-templating convention) while preserving the audit chain:
// the gateway sees the same `(url, body)` tuple it would have
// seen on the legacy direct-egress path, and the kernel records
// it under the planner's session id.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What kind of upstream this fetch is. The kernel uses this to
/// pick the gateway-side timeout / response-size envelope.
///
/// Mirrors `raxis_ipc::message::FetchKind` but lives in raxis-types
/// so the planner-side wire shape does not pull a dep on the
/// gateway-internal `FetchKind`. The kernel handler maps between
/// the two enums 1:1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlannerFetchKind {
    /// LLM API call (Anthropic Messages, OpenAI Chat Completions,
    /// Bedrock InvokeModel, …). Higher per-attempt timeout, larger
    /// response body cap.
    Inference,
    /// Generic URL data fetch (WebFetch / WebSearch tool, …). Tighter
    /// timeout, hard 16 MiB body cap.
    DataFetch,
}

/// **Planner → kernel.** Asks the kernel to perform an HTTP fetch
/// against an external service on the planner's behalf.
///
/// This is the kernel-mediated egress path; it is the **only** way
/// a planner running in an air-gapped substrate (`EgressTier::None`,
/// e.g. the canonical Orchestrator and Reviewer VMs) can reach an
/// upstream provider. Substrates with in-VM tproxy
/// (`EgressTier::Tier1Tproxy`) MAY still use the direct path but
/// SHOULD use this path uniformly so audit, breaker, and credential
/// invariants live entirely on the kernel side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerFetchRequest {
    /// Per-fetch UUIDv4 the planner mints. The kernel echoes it on
    /// the response so the planner's transport can correlate
    /// in-flight requests when concurrent fetches are added (V2.5+).
    pub request_id:    Uuid,

    /// The session token the kernel stamped at spawn time. The
    /// kernel re-validates against `sessions.session_token` for the
    /// authenticated connection — a mismatch is
    /// `FAIL_SESSION_TOKEN_MISMATCH`.
    pub session_token: String,

    /// Inference vs DataFetch — gates timeout + size caps.
    pub fetch_kind:    PlannerFetchKind,

    /// Full upstream URL including scheme, host, path, query.
    /// Re-validated by the gateway against the policy allowlist
    /// (`peripherals.md §3.2 "Domain allowlist re-validation"`).
    pub url:           String,

    /// HTTP method (`"POST"` for inference, `"GET"` for data
    /// fetch). Validated against the gateway's per-host
    /// `allowed_methods`.
    pub method:        String,

    /// HTTP headers the planner wants forwarded. The gateway:
    ///
    /// 1. Strips any `Authorization` header (planner-side credentials
    ///    are an INV-CRED-01 violation).
    /// 2. Injects the credentials the operator declared for this
    ///    provider in `policy.toml`.
    /// 3. Forwards the rest verbatim.
    pub headers:       Vec<(String, String)>,

    /// Raw request body bytes. The planner's model SDK serialises
    /// the JSON body locally; the kernel does not inspect the body
    /// content.
    pub body_bytes:    Vec<u8>,

    /// Per-attempt timeout in milliseconds. Hard ceiling pinned by
    /// `peripherals.md §3.2` (120_000 ms). The kernel clamps to
    /// `min(planner_supplied, host_max)` before forwarding.
    pub timeout_ms:    u32,
}

/// **Kernel → planner.** The kernel's response to a
/// [`PlannerFetchRequest`].
///
/// Mirror of the gateway's `FetchResponse` shape; the kernel
/// translates between the two without restructuring fields so the
/// audit log can compare them byte-for-byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerFetchResponse {
    /// Echoes [`PlannerFetchRequest::request_id`].
    pub request_id:    Uuid,

    /// HTTP status code returned by the upstream. `None` on failures
    /// before the upstream produced a status line (DNS, TLS, etc.).
    pub status_code:   Option<u16>,

    /// Response headers (after gateway-side filtering of
    /// `Set-Cookie` / `Authorization` / `WWW-Authenticate`).
    pub headers:       Vec<(String, String)>,

    /// Response body bytes. `None` on transport failure.
    pub body_bytes:    Option<Vec<u8>>,

    /// Observed end-to-end latency in milliseconds. Populated even
    /// on failure (so retry policies can budget against it).
    pub latency_ms:    u32,

    /// On error: a stable short reason string. Same vocabulary as
    /// `peripherals.md §3.2`:
    /// `"TimeoutExceeded"`, `"DomainNotAllowed"`,
    /// `"ResponseTooLarge"`, `"PolicyReloadFailed"`,
    /// `"NetworkError"`, plus the kernel-side additions
    /// `"GatewayUnavailable"` (no gateway connected) and
    /// `"FAIL_SESSION_TOKEN_MISMATCH"` (session-auth failure).
    pub error:         Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire round-trip pin: bincode-encode and decode the request
    /// + response shapes so any future field reorder surfaces
    /// before it can be deployed mid-cluster.
    #[test]
    fn planner_fetch_request_round_trips_through_serde_json() {
        let req = PlannerFetchRequest {
            request_id:    Uuid::nil(),
            session_token: "session-token-fixture".to_owned(),
            fetch_kind:    PlannerFetchKind::Inference,
            url:           "https://api.anthropic.com/v1/messages".to_owned(),
            method:        "POST".to_owned(),
            headers:       vec![("anthropic-version".to_owned(), "2023-06-01".to_owned())],
            body_bytes:    b"{\"model\":\"x\"}".to_vec(),
            timeout_ms:    60_000,
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: PlannerFetchRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.url, req.url);
        assert_eq!(back.body_bytes, req.body_bytes);
        assert_eq!(back.fetch_kind, req.fetch_kind);
    }

    #[test]
    fn planner_fetch_response_round_trips_through_serde_json() {
        let resp = PlannerFetchResponse {
            request_id:    Uuid::nil(),
            status_code:   Some(200),
            headers:       vec![("content-type".to_owned(), "application/json".to_owned())],
            body_bytes:    Some(b"{\"id\":\"msg_x\"}".to_vec()),
            latency_ms:    1234,
            error:         None,
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: PlannerFetchResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.status_code, resp.status_code);
        assert_eq!(back.body_bytes, resp.body_bytes);
        assert_eq!(back.error, resp.error);
    }
}
