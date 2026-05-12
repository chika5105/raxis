//! `handlers::planner_fetch` — kernel-mediated egress for planners.
//!
//! Normative references:
//!   * `provider-failure-handling.md §2.1` — the planner ↔ kernel ↔
//!     gateway flow.
//!   * `peripherals.md §3.1` — planner socket dispatch table; the new
//!     `IpcMessage::PlannerFetchRequest` variant lands here.
//!   * `peripherals.md §3.2` — the gateway socket; the kernel
//!     translates the planner's request into a
//!     `GatewayMessage::FetchRequest` (substituting its own gateway
//!     token) and routes the response back.
//!
//! ## Why the kernel forwards instead of the planner dialing the
//! gateway directly
//!
//! The gateway socket is a kernel-private UDS at
//! `<data_dir>/sockets/gateway.sock`, mode `0600`, owned by the kernel
//! UID. Even if a compromised planner could escape its VM and reach
//! the host filesystem, the gateway socket is not group-readable and
//! the gateway re-validates the per-spawn `gateway_token` on every
//! frame. Routing through the kernel preserves a single audit-chain
//! anchor for every outbound call — the kernel records
//! `(session_id, request_id, url, status_code)` and chains it.
//!
//! ## Authorisation gating (V2 GA scope)
//!
//! - Reviewer sessions are split by `fetch_kind`:
//!     * `PlannerFetchKind::Inference` — ALLOWED. Reviewers MUST be
//!       able to call the LLM provider to generate the critique
//!       (`agent-disagreement.md §19` describes the per-round
//!       Reviewer InferenceRequest cost; `planner-harness.md §2535`
//!       references "Reviewer + InferenceRequest" as a valid shape
//!       gated only by the per-provider tool surface). The kernel
//!       still routes through the gateway's `policy.toml` provider
//!       allowlist, so the only reachable hosts are the
//!       operator-signed Inference providers.
//!     * `PlannerFetchKind::DataFetch` — DENIED. The spec invariant
//!       "no egress in review sessions" (`kernel-mediated-egress.md
//!       §178`, `planner-harness.md §1482`) targets exactly this
//!       arbitrary-URL surface. Returns
//!       `"FAIL_PLANNER_FETCH_DENIED_REVIEWER"`.
//! - Orchestrator and Executor sessions are admitted for both
//!   `Inference` and `DataFetch`; the gateway's own `policy.toml`
//!   allowlist is the second line of defence (rejects unknown
//!   hostnames with `"DomainNotAllowed"`).
//!
//! Per-task `[[tasks.allowed_egress]]` enforcement is **not** performed
//! at this layer in V2 GA; that gate lives in the in-VM tproxy stack
//! per `vm-network-isolation.md`. Every fetch the kernel forwards is
//! still bounded by the gateway's domain allowlist, so a malicious
//! planner cannot reach a host outside the operator-signed set even
//! when this handler admits the request. V3 will add per-session URL
//! prefix enforcement here once the unified `[[tasks.allowed_egress]]`
//! schema is wired through to the kernel.

use std::sync::Arc;

use raxis_ipc::message::FetchKind;
use raxis_types::{
    PlannerFetchKind, PlannerFetchRequest, PlannerFetchResponse, SessionAgentType,
};
use uuid::Uuid;

use crate::authority::session::get_session_by_token;
use crate::gateway::client::GatewayCallError;
use crate::ipc::context::HandlerContext;

/// Hard ceiling on per-attempt timeout — matches the gateway's
/// `peripherals.md §3.2` cap. Planners that submit a higher value
/// are silently clamped (no error) so a buggy planner cannot park
/// the gateway pump for longer than the spec admits.
const HARD_TIMEOUT_CEILING_MS: u32 = 120_000;

/// Floor — protects against a planner that submits `0` and
/// permanently fails its own request.
const HARD_TIMEOUT_FLOOR_MS: u32 = 1_000;

/// Stable short error strings used in [`PlannerFetchResponse::error`].
///
/// Mirrors `peripherals.md §3.2` vocabulary plus the kernel-side
/// additions documented on [`PlannerFetchResponse::error`]. Pinned by
/// this module's tests so the wire never drifts.
mod errors {
    pub const SESSION_TOKEN_MISMATCH: &str = "FAIL_SESSION_TOKEN_MISMATCH";
    pub const PLANNER_FETCH_DENIED:   &str = "FAIL_PLANNER_FETCH_DENIED";
    pub const REVIEWER_DENIED:        &str = "FAIL_PLANNER_FETCH_DENIED_REVIEWER";
    pub const GATEWAY_UNAVAILABLE:    &str = "GatewayUnavailable";
    pub const NETWORK_ERROR:          &str = "NetworkError";
}

/// Top-level dispatch entry point; called by `accept_planner_loop`
/// after it has read a `IpcMessage::PlannerFetchRequest` frame.
///
/// Returns a [`PlannerFetchResponse`] for **every** input (no panics,
/// no early-returns into the dispatch loop) — failures are surfaced
/// in the `error` field so the connection stays healthy and the
/// planner gets a typed reply it can match on.
pub async fn handle(req: PlannerFetchRequest, ctx: &Arc<HandlerContext>) -> PlannerFetchResponse {
    let request_id = req.request_id;
    let started    = std::time::Instant::now();

    // ── Step 1: resolve session token → SessionRow ────────────────
    //
    // Mirrors the IntentRequest admission contract (handlers::intent
    // §1). A kernel that admits a fetch from an expired or
    // unrecognised session would defeat the per-session audit
    // anchor.
    let session = match resolve_session(&req.session_token, ctx).await {
        Some(row) => row,
        None      => return failure_response(
            request_id,
            started.elapsed().as_millis() as u32,
            errors::SESSION_TOKEN_MISMATCH,
        ),
    };

    // ── Step 2: dispatch matrix ──────────────────────────────────
    //
    // The gating is two-dimensional in (`session_agent_type`,
    // `fetch_kind`):
    //
    //   Reviewer + Inference  → ALLOW (LLM critique requires it;
    //                           `agent-disagreement.md §19`,
    //                           `planner-harness.md §2535`)
    //   Reviewer + DataFetch  → DENY  (`kernel-mediated-egress.md
    //                           §178`: "Reviewer ❌ always — no
    //                           egress in review sessions")
    //   Orch / Exec + any     → ALLOW (gateway-side allowlist is
    //                           the second line of defence)
    //   None + any            → DENY  (V2 GA wires every spawn path
    //                           through `SessionAgentType`; a
    //                           missing tag means a synthetic /
    //                           legacy row that should not gain
    //                           egress authority)
    match (session.session_agent_type, req.fetch_kind) {
        (Some(SessionAgentType::Reviewer), PlannerFetchKind::DataFetch) => {
            return failure_response(
                request_id,
                started.elapsed().as_millis() as u32,
                errors::REVIEWER_DENIED,
            );
        }
        (Some(SessionAgentType::Reviewer), PlannerFetchKind::Inference)
        | (Some(SessionAgentType::Orchestrator), _)
        | (Some(SessionAgentType::Executor), _) => {}
        (None, _) => {
            return failure_response(
                request_id,
                started.elapsed().as_millis() as u32,
                errors::PLANNER_FETCH_DENIED,
            );
        }
    }

    // ── Step 3: shape adaptation ─────────────────────────────────
    let fetch_kind = map_fetch_kind(req.fetch_kind);
    let timeout_ms = req
        .timeout_ms
        .clamp(HARD_TIMEOUT_FLOOR_MS, HARD_TIMEOUT_CEILING_MS);

    // ── Step 4: gateway dispatch ─────────────────────────────────
    //
    // The gateway client validates `gateway_token` on its side so
    // we always pass the kernel's currently-expected token. When no
    // gateway is connected, fetch() returns Unavailable; we surface
    // it as `GatewayUnavailable` so the planner can decide whether
    // to retry or fall through to a single-attempt failure.
    let gateway_token = ctx.gateway.expected_token().await.unwrap_or_default();
    let session_uuid  = Uuid::parse_str(&session.session_id).ok();

    let result = ctx
        .gateway
        .fetch(
            gateway_token,
            fetch_kind,
            req.url,
            req.method,
            req.headers,
            req.body_bytes,
            timeout_ms,
            session_uuid,
            // V2 GA: SessionRow does not carry `task_id` (the planner
            // socket auth is per-session, not per-task). The gateway
            // logs only session id for kernel-mediated fetches; the
            // per-task scoping lives on the gateway's own audit row
            // when the operator's [[tasks.allowed_egress]] schema
            // ships in V3.
            None,
        )
        .await;

    let latency_ms = started.elapsed().as_millis() as u32;

    match result {
        Ok(fr) => PlannerFetchResponse {
            request_id,
            status_code: fr.status_code,
            headers:     fr.headers,
            body_bytes:  fr.body_bytes,
            latency_ms:  fr.latency_ms.max(latency_ms),
            error:       None,
        },
        Err(GatewayCallError::Unavailable) => failure_response(
            request_id,
            latency_ms,
            errors::GATEWAY_UNAVAILABLE,
        ),
        Err(GatewayCallError::Dropped) => failure_response(
            request_id,
            latency_ms,
            errors::NETWORK_ERROR,
        ),
        Err(GatewayCallError::GatewayError(msg)) => failure_response(
            request_id,
            latency_ms,
            &msg,
        ),
        Err(GatewayCallError::UnexpectedReply) => failure_response(
            request_id,
            latency_ms,
            errors::NETWORK_ERROR,
        ),
    }
}

fn map_fetch_kind(k: PlannerFetchKind) -> FetchKind {
    match k {
        PlannerFetchKind::Inference => FetchKind::Inference,
        PlannerFetchKind::DataFetch => FetchKind::DataFetch,
    }
}

fn failure_response(request_id: Uuid, latency_ms: u32, error: &str) -> PlannerFetchResponse {
    PlannerFetchResponse {
        request_id,
        status_code: None,
        headers:     Vec::new(),
        body_bytes:  None,
        latency_ms,
        error:       Some(error.to_owned()),
    }
}

async fn resolve_session(
    token: &str,
    ctx: &Arc<HandlerContext>,
) -> Option<crate::authority::session::SessionRow> {
    let store = Arc::clone(&ctx.store);
    let token_owned = token.to_owned();
    tokio::task::spawn_blocking(move || get_session_by_token(&token_owned, &store).ok())
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error vocabulary is a wire surface; pin it so future
    /// refactors cannot accidentally rename a code that planner
    /// retry classifiers match on.
    #[test]
    fn error_codes_pinned() {
        assert_eq!(errors::SESSION_TOKEN_MISMATCH, "FAIL_SESSION_TOKEN_MISMATCH");
        assert_eq!(errors::PLANNER_FETCH_DENIED, "FAIL_PLANNER_FETCH_DENIED");
        assert_eq!(errors::REVIEWER_DENIED, "FAIL_PLANNER_FETCH_DENIED_REVIEWER");
        assert_eq!(errors::GATEWAY_UNAVAILABLE, "GatewayUnavailable");
        assert_eq!(errors::NETWORK_ERROR, "NetworkError");
    }

    #[test]
    fn timeout_clamp_bounds() {
        assert_eq!(0u32.clamp(HARD_TIMEOUT_FLOOR_MS, HARD_TIMEOUT_CEILING_MS), 1_000);
        assert_eq!(
            999_999u32.clamp(HARD_TIMEOUT_FLOOR_MS, HARD_TIMEOUT_CEILING_MS),
            120_000,
        );
        assert_eq!(60_000u32.clamp(HARD_TIMEOUT_FLOOR_MS, HARD_TIMEOUT_CEILING_MS), 60_000);
    }

    #[test]
    fn fetch_kind_mapping_is_one_to_one() {
        assert_eq!(map_fetch_kind(PlannerFetchKind::Inference), FetchKind::Inference);
        assert_eq!(map_fetch_kind(PlannerFetchKind::DataFetch), FetchKind::DataFetch);
    }
}
