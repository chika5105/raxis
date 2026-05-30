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

use raxis_audit_tools::AuditEventKind;
use raxis_egress_admission::StallSignal;
use raxis_ipc::message::FetchKind;
use raxis_store::Table;
use raxis_types::{PlannerFetchKind, PlannerFetchRequest, PlannerFetchResponse, SessionAgentType};
use uuid::Uuid;

use crate::authority::session::get_active_session_by_token;
use crate::gateway::client::{FetchResult, GatewayCallError};
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
    pub const PLANNER_FETCH_DENIED: &str = "FAIL_PLANNER_FETCH_DENIED";
    pub const REVIEWER_DENIED: &str = "FAIL_PLANNER_FETCH_DENIED_REVIEWER";
    pub const GATEWAY_UNAVAILABLE: &str = "GatewayUnavailable";
    pub const NETWORK_ERROR: &str = "NetworkError";
    pub const TIMEOUT_EXCEEDED: &str = "TimeoutExceeded";
}

/// Closed-cardinality failure taxonomy for gateway-backed provider
/// telemetry. The planner still receives the stable wire error
/// strings above; this label is for operator dashboards so a host-
/// provider outage is visible without asking the planner to spend
/// another turn explaining a generic `NetworkError`.
fn gateway_failure_class(result: &Result<FetchResult, GatewayCallError>) -> &'static str {
    match result {
        Ok(fr) => match fr.status_code {
            Some(code) if (200..400).contains(&code) => "none",
            Some(408 | 429) => "provider_retryable_http",
            Some(code) if code >= 500 => "provider_retryable_http",
            Some(code) if (400..500).contains(&code) => "provider_client_http",
            Some(_) => "provider_http_other",
            None => "gateway_protocol",
        },
        Err(GatewayCallError::GatewayError(msg)) => match msg.as_str() {
            "NetworkError" => "host_provider_network",
            "TimeoutExceeded" => "host_provider_timeout",
            "DomainNotAllowed" => "policy_denied",
            "ResponseTooLarge" => "response_too_large",
            "PolicyReloadFailed" => "policy_reload_failed",
            _ => "gateway_error_other",
        },
        Err(GatewayCallError::Unavailable) => "gateway_unavailable",
        Err(GatewayCallError::Dropped) => "gateway_dropped",
        Err(GatewayCallError::Timeout { .. }) => "gateway_response_timeout",
        Err(GatewayCallError::UnexpectedReply) => "gateway_protocol",
    }
}

fn gateway_outcome_label(result: &Result<FetchResult, GatewayCallError>) -> &'static str {
    match result {
        Ok(fr) => match fr.status_code {
            Some(code) if (200..400).contains(&code) => "ok",
            _ => "error",
        },
        Err(_) => "error",
    }
}

/// Saturating conversion of `Instant::elapsed()` to the wire-level
/// `latency_ms: u32` field on [`PlannerFetchResponse`].
///
/// `Duration::as_millis()` returns `u128`; `as u32` would silently
/// wrap to a small value once the elapsed time exceeds
/// `u32::MAX` ≈ 49.7 days. In normal operation the per-fetch hard
/// ceiling is `HARD_TIMEOUT_CEILING_MS = 120_000`, so a real call
/// can never reach the wrap boundary — but the previous `as u32`
/// cast also wrapped silently on any pathological input (a stuck
/// gateway pump, a paused VM where `Instant::now()` keeps moving
/// while the response is in flight, or a future change that lifts
/// the cap). Saturate to `u32::MAX` instead of wrapping so the
/// reported latency is monotonically truthful: a wrapped "21 ms"
/// after a real 50-day stall would be far more dangerous in an
/// audit log than a clamped sentinel.
///
/// `u32::MAX` ms ≈ 1193 hours, which is well outside any legitimate
/// fetch and a clear "saturated" sentinel for operators reading
/// `PlannerFetchResponse`/`AuditEvent` rows.
#[inline]
fn elapsed_ms_clamped(started: std::time::Instant) -> u32 {
    u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)
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
    let started = std::time::Instant::now();

    // ── Step 1: resolve session token → SessionRow ────────────────
    //
    // Mirrors the IntentRequest admission contract (handlers::intent
    // §1). A kernel that admits a fetch from an expired or
    // unrecognised session would defeat the per-session audit
    // anchor.
    let session = match resolve_session(&req.session_token, ctx).await {
        Some(row) => row,
        None => {
            return failure_response(
                request_id,
                elapsed_ms_clamped(started),
                errors::SESSION_TOKEN_MISMATCH,
            )
        }
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
                elapsed_ms_clamped(started),
                errors::REVIEWER_DENIED,
            );
        }
        (Some(SessionAgentType::Reviewer), PlannerFetchKind::Inference)
        | (Some(SessionAgentType::Orchestrator), _)
        | (Some(SessionAgentType::Executor), _) => {}
        (None, _) => {
            return failure_response(
                request_id,
                elapsed_ms_clamped(started),
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
    let session_uuid = Uuid::parse_str(&session.session_id).ok();

    // V2 reviewer-egress-defaults-decision.md §7 — capture the
    // URL pre-call so we can extract the host/port for stall
    // detection on a `DomainNotAllowed` failure path. Cloning the
    // string keeps the gateway call's signature unchanged (it
    // takes ownership of `req.url`).
    let url_for_stall_detection = req.url.clone();

    // iter62 — `INV-DASHBOARD-LLM-TURN-CAPTURED-01`. Resolve the
    // executor / reviewer task_id bound to this session before
    // the gateway fetch so the dispatch pump's `LlmTurnObserver`
    // guard `(Some(obs), Some(tid))` (gateway/client.rs:508)
    // can fire and the substrate's
    // `dashboard-kernel/src/task_llm_capture.rs` ring receives
    // one record per round-trip.
    //
    // Previously this was hardcoded to `None`, defeating the
    // observer entirely — the iter62 forensics work-dir's
    // `llm-turns/` directory was empty across 22+ planner
    // sessions because every kernel-mediated fetch dropped
    // task_id on the floor.
    //
    // iter65 — `orchestrator-llm-turns`. Orchestrator sessions
    // have NO `subtask_activations` row (those are scoped to
    // executor / reviewer subtasks), so the iter62 lookup
    // returned `None` for every orchestrator planner_fetch and
    // the dashboard's LLM-turns panel stayed empty for the
    // most operator-visible session. Fall back to the
    // session's owning `initiative_id` as the synthetic
    // coordinator `task_id` (== `initiative_id`, per
    // `INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01`)
    // so orchestrator turns land in `<initiative_id>.jsonl`
    // and the dashboard's TaskDetail page for the coordinator
    // row renders them through the existing TaskLlmTurns
    // panel. The `agent_role` stamp (see below) lets the
    // operator distinguish orchestrator turns from any
    // executor / reviewer turns that may also have landed in
    // the same file.
    //
    // The lookup remains best-effort: a missing Active row
    // (transient gap during session activation, or a session
    // with no `initiative_id` at all) downgrades to `None` so
    // the fetch still succeeds — capture is best-effort by
    // contract, never a load-bearing gate on the planner's
    // egress.
    let active_task_id = lookup_active_task_id_for_session(ctx, &session.session_id).await;
    let task_id_for_observer = resolve_observer_task_id(
        active_task_id,
        session.session_agent_type,
        session.initiative_id.as_deref(),
    );

    let agent_role_for_observer = agent_role_label(session.session_agent_type);

    // Dashboard/provider visibility must not wait for a terminal
    // IntentReport. A stalled planner_fetch is exactly when the
    // operator needs the session header to say which provider/model
    // was in play, so persist the first observation as soon as the
    // fetch is admitted. The write is best-effort and NULL-coalescing:
    // it cannot block or rewrite the planner's real egress path.
    let provider_id_for_observer =
        provider_id_for_fetch_url(ctx.policy.load().as_ref(), &url_for_stall_detection);
    let model_id_for_observer =
        model_id_for_fetch_request(&url_for_stall_detection, &req.body_bytes);
    persist_session_provider_model_observation(
        ctx,
        session.session_id.as_str(),
        provider_id_for_observer.clone(),
        model_id_for_observer.clone(),
    );

    let provider_label = extract_host_port(&url_for_stall_detection)
        .map(|(host, _)| host)
        .unwrap_or_else(|| "unknown".to_owned());
    let mut fetch_span = ctx.observability.start_span(
        raxis_observability::SpanName::GatewayFetch,
        raxis_observability::SpanKind::Client,
        None,
    );
    fetch_span.set_attr("provider", provider_label.as_str());
    fetch_span.set_attr("cached", false);

    let result = ctx
        .gateway
        .fetch_with_observer_metadata(
            gateway_token,
            fetch_kind,
            req.url,
            req.method,
            req.headers,
            req.body_bytes,
            timeout_ms,
            session_uuid,
            task_id_for_observer,
            agent_role_for_observer,
            provider_id_for_observer,
            model_id_for_observer,
        )
        .await;

    let latency_ms = elapsed_ms_clamped(started);

    // V3 §3 perf-telemetry — record one `raxis.gateway.fetch.{total,duration}`
    // observation per kernel-mediated call. `provider` is the request host
    // (the only stable identifier visible at this layer; model / token usage
    // / gateway-cache state live one process boundary further into the
    // gateway subprocess and are not observable here). `status_code` is the
    // upstream HTTP status on success, 0 on every gateway-side failure.
    let fetch_status_i64: i64 = match &result {
        Ok(fr) => fr.status_code.map(|c| c as i64).unwrap_or(0),
        Err(_) => 0,
    };
    let outcome_label = gateway_outcome_label(&result);
    let failure_class = gateway_failure_class(&result);
    fetch_span.set_attr("status_code", fetch_status_i64);
    fetch_span.set_attr("latency_ms", latency_ms as i64);
    if outcome_label == "ok" {
        fetch_span.set_status(raxis_observability::SpanStatus::Ok, None);
    } else {
        fetch_span.set_status(
            raxis_observability::SpanStatus::Error,
            Some(
                result
                    .as_ref()
                    .err()
                    .map(GatewayCallError::category)
                    .unwrap_or("http_error")
                    .to_owned(),
            ),
        );
    }
    fetch_span.end();
    crate::observability::record_gateway_fetch(
        &ctx.observability,
        &provider_label,
        None,
        fetch_status_i64,
        outcome_label,
        failure_class,
        latency_ms as i64,
        false,
        None,
        None,
    );

    // INV-OBSERVABILITY-LATENCY-METRICS-WIRED-01 — every kernel-
    // mediated planner Inference round-trip emits one
    // `raxis.planner.inference.{duration,tokens}` observation,
    // success AND error. The kernel layer cannot resolve the
    // upstream `model` field (the planner-side SDK opaque-serialises
    // the body bytes; the kernel never parses them — see this
    // module's header comment), so we tag with `model = "unknown"`
    // and emit zero token counters. The richer per-model / per-tier
    // observation point lives planner-side; iter61+ will route those
    // observations back through a future `PlannerObservationReport`
    // IPC frame and the histogram pivots will gain real `model`
    // labels at that point. Until then the kernel-side
    // `provider+outcome` pivot is the operator's primary
    // bottleneck-localisation signal.
    if matches!(req.fetch_kind, PlannerFetchKind::Inference) {
        crate::observability::record_planner_inference(
            &ctx.observability,
            &provider_label,
            "unknown",
            outcome_label,
            false,
            latency_ms as i64,
            0,
            0,
        );
    }

    // INV-OBSERVABILITY-LATENCY-METRICS-WIRED-02 — record the
    // gateway's reported upstream RTT (distinct from the kernel-
    // measured end-to-end `record_gateway_fetch`). Uses
    // `fr.latency_ms` on the success arm and the kernel-measured
    // value on every failure arm where the gateway never produced a
    // structured response. Both arms emit so success and error
    // observations stay paired and a regression in one is visible
    // against the other.
    let gateway_upstream_ms = match &result {
        Ok(fr) => fr.latency_ms as i64,
        Err(_) => latency_ms as i64,
    };
    crate::observability::record_gateway_upstream(
        &ctx.observability,
        &provider_label,
        outcome_label,
        failure_class,
        gateway_upstream_ms,
    );
    crate::observability::record_gateway_stage(
        &ctx.observability,
        &provider_label,
        crate::observability::GATEWAY_STAGE_UPSTREAM_ROUNDTRIP,
        outcome_label,
        gateway_upstream_ms,
    );

    match result {
        Ok(fr) => PlannerFetchResponse {
            request_id,
            status_code: fr.status_code,
            headers: fr.headers,
            body_bytes: fr.body_bytes,
            latency_ms: fr.latency_ms.max(latency_ms),
            error: None,
        },
        Err(GatewayCallError::Unavailable) => {
            failure_response(request_id, latency_ms, errors::GATEWAY_UNAVAILABLE)
        }
        Err(GatewayCallError::Dropped) => {
            failure_response(request_id, latency_ms, errors::NETWORK_ERROR)
        }
        Err(GatewayCallError::Timeout { .. }) => {
            failure_response(request_id, latency_ms, errors::TIMEOUT_EXCEEDED)
        }
        Err(GatewayCallError::GatewayError(msg)) => {
            // V2 reviewer-egress-defaults-decision.md §7: feed
            // `DomainNotAllowed` denials into the kernel-wide
            // `EgressStallTracker`. Surfaces the silent-spin
            // failure mode where a kernel-mediated inference
            // call is repeatedly rejected by the gateway URL
            // allowlist without the operator noticing.
            //
            // Match on the EXACT wire string the gateway emits
            // (`DispatchError::DomainNotAllowed.as_wire_string()
            // = "DomainNotAllowed"`). Other gateway errors
            // (`InvalidToken`, `TimeoutExceeded`, `NetworkError`,
            // `PolicyReloadFailed`) are real failures but not
            // egress-policy stalls; they get their own
            // diagnostics and would noise up the stall signal.
            if msg == "DomainNotAllowed" {
                feed_stall_tracker_for_domain_not_allowed(
                    ctx,
                    &session.session_id,
                    &url_for_stall_detection,
                );
            }
            failure_response(request_id, latency_ms, &msg)
        }
        Err(GatewayCallError::UnexpectedReply) => {
            failure_response(request_id, latency_ms, errors::NETWORK_ERROR)
        }
    }
}

/// V2 reviewer-egress-defaults-decision.md §7: feed one
/// `DomainNotAllowed` rejection from the kernel-mediated path
/// into the kernel-wide `EgressStallTracker`. When the bucket
/// trips the threshold, emits one
/// `SessionEgressStallDetected { source: "kernel_mediated_fetch" }`
/// audit event.
///
/// Best-effort: a malformed URL skips stall detection (the
/// gateway's own error response is the authoritative signal in
/// that case), and an audit-emit failure is logged but never
/// propagated up — the underlying gateway error is what the
/// planner sees.
fn feed_stall_tracker_for_domain_not_allowed(
    ctx: &Arc<HandlerContext>,
    session_id: &str,
    url: &str,
) {
    let (host, port) = match extract_host_port(url) {
        Some(pair) => pair,
        None => return,
    };
    let signal = ctx.egress_stall_tracker.record_denial(
        session_id,
        Some(&host),
        port,
        "host_not_in_allowlist",
    );
    if let StallSignal::Detected(emit) = signal {
        if let Err(e) = ctx.audit.emit(
            AuditEventKind::SessionEgressStallDetected {
                session_id: emit.session_id,
                host_or_sni: emit.host_or_sni,
                original_dst_port: emit.original_dst_port,
                reason: emit.reason,
                block_count_in_window: emit.block_count_in_window,
                window_seconds: emit.window_seconds,
                source: "kernel_mediated_fetch".to_owned(),
            },
            Some(session_id),
            None,
            None,
        ) {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"SessionEgressStallDetected\",\
                 \"audit_emit_failed\":\"{e}\",\"session_id\":\"{}\",\
                 \"source\":\"kernel_mediated_fetch\"}}",
                session_id,
            );
        }
    }
}

/// Extract `(host, port)` from a URL string. Defaults to `443`
/// for `https`, `80` for `http`, otherwise drops to `0`. Returns
/// `None` if the URL is unparseable as a `url::Url`. Lifted
/// inline rather than pulling a heavy URL parser dependency —
/// the function only powers stall-bucket keying so a coarse
/// extraction is sufficient.
fn extract_host_port(url: &str) -> Option<(String, u16)> {
    let after_scheme = url.split_once("://")?;
    let scheme = after_scheme.0;
    let rest = after_scheme.1;
    let host_with_path = rest.split('/').next()?;
    let (host, port_str) = match host_with_path.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_with_path, None),
    };
    if host.is_empty() {
        return None;
    }
    let port = match port_str.and_then(|p| p.parse::<u16>().ok()) {
        Some(p) => p,
        None => match scheme {
            "https" => 443,
            "http" => 80,
            _ => 0,
        },
    };
    Some((host.to_owned(), port))
}

fn provider_id_for_fetch_url(policy: &raxis_policy::PolicyBundle, url: &str) -> Option<String> {
    let (host, _) = extract_host_port(url)?;
    let host_lower = host.to_ascii_lowercase();
    policy
        .providers()
        .iter()
        .find(|p| provider_entry_matches_host(p, &host_lower))
        .map(|p| p.provider_id.clone())
}

fn provider_entry_matches_host(p: &raxis_policy::ProviderEntry, host_lower: &str) -> bool {
    match p.kind.as_str() {
        "Anthropic" => host_lower == "anthropic.com" || host_lower.ends_with(".anthropic.com"),
        "OpenAI" => host_lower == "openai.com" || host_lower.ends_with(".openai.com"),
        "Gemini" => host_lower == "generativelanguage.googleapis.com",
        "Bedrock" => {
            host_lower.starts_with("bedrock-runtime.") && host_lower.ends_with(".amazonaws.com")
        }
        "http_sidecar" => p
            .sidecar_endpoint
            .as_deref()
            .and_then(endpoint_host)
            .map(|h| h.eq_ignore_ascii_case(host_lower))
            .unwrap_or(false),
        _ => false,
    }
}

fn endpoint_host(endpoint: &str) -> Option<String> {
    let after_scheme = endpoint.split_once("://")?.1;
    let host_with_path = after_scheme.split('/').next()?;
    let host = host_with_path.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

fn model_id_for_fetch_request(url: &str, body_bytes: &[u8]) -> Option<String> {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
        if let Some(model) = v
            .get("model")
            .or_else(|| v.get("model_id"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(model.to_owned());
        }
    }
    model_id_from_url(url)
}

fn model_id_from_url(url: &str) -> Option<String> {
    let path = url.split_once("://")?.1.split_once('/')?.1;
    if let Some(rest) = path.split_once("models/").map(|(_, r)| r) {
        let model = rest
            .split([':', '?', '/'])
            .next()
            .unwrap_or_default()
            .trim();
        if !model.is_empty() {
            return Some(model.to_owned());
        }
    }
    if let Some(rest) = path.split_once("model/").map(|(_, r)| r) {
        let model = rest.split(['/', '?']).next().unwrap_or_default().trim();
        if !model.is_empty() {
            return Some(model.to_owned());
        }
    }
    None
}

fn persist_session_provider_model_observation(
    ctx: &Arc<HandlerContext>,
    session_id: &str,
    provider: Option<String>,
    model: Option<String>,
) {
    if provider.as_deref().unwrap_or("").is_empty() && model.as_deref().unwrap_or("").is_empty() {
        return;
    }
    let store = Arc::clone(&ctx.store);
    let session_id = session_id.to_owned();
    let _ = tokio::task::spawn_blocking(move || {
        let conn = store.lock_sync();
        if let Err(e) = raxis_store::views::sessions::set_session_provider_model_if_unset(
            &conn,
            session_id.as_str(),
            provider.as_deref(),
            model.as_deref(),
        ) {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"session_provider_model_observation_failed\",\
                 \"session_id\":\"{}\",\"reason\":\"{}\"}}",
                session_id, e,
            );
        }
    });
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
        headers: Vec::new(),
        body_bytes: None,
        latency_ms,
        error: Some(error.to_owned()),
    }
}

async fn resolve_session(
    token: &str,
    ctx: &Arc<HandlerContext>,
) -> Option<crate::authority::session::SessionRow> {
    let store = Arc::clone(&ctx.store);
    let token_owned = token.to_owned();
    tokio::task::spawn_blocking(move || get_active_session_by_token(&token_owned, &store).ok())
        .await
        .ok()
        .flatten()
}

/// Resolve the executor / reviewer task_id bound to this session's
/// **Active** subtask activation row.
///
/// `subtask_activations` carries a CHECK constraint
/// (kernel-store.md §2.5.1 Table 6) that pins exactly one row per
/// `session_id` in `activation_state = 'Active'`, so the lookup
/// is a single-row primary-key-indexed read. Returns `None`
/// when:
///   * the session has no Active activation row yet (transient
///     gap during session activation, or an orchestrator-only
///     session that the orchestrator has not yet routed to a
///     specific subtask),
///   * the SQL fails (best-effort capture must NEVER block egress).
///
/// Powering invariant: `INV-DASHBOARD-LLM-TURN-CAPTURED-01`. The
/// gateway pump's observer guard (`gateway/client.rs:508`) only
/// fans `LlmTurnObserver::observe(...)` when the inflight slot
/// carries a `Some(task_id)`; threading the resolved task_id here
/// is the load-bearing wiring that closes the iter62 silent-drop.
/// Pure helper extracted so the orchestrator-fallback for the
/// `task_id_for_observer` stamp can be unit-tested without the
/// full `HandlerContext` / tokio scaffold.
///
/// Contract:
///   - if `active_task_id` is `Some`, use it as-is (executor /
///     reviewer happy path — the planner_fetch caller is bound
///     to an `Active` `subtask_activations` row).
///   - otherwise, if the session is an orchestrator AND has an
///     `initiative_id`, stamp with that `initiative_id` (the
///     synthetic coordinator task_id == initiative_id — the
///     turns land on the coordinator's TaskDetail page).
///   - otherwise, `None` → silent capture-side drop (legacy
///     contract; the gateway fetch itself still succeeds).
fn resolve_observer_task_id(
    active_task_id: Option<String>,
    agent_type: Option<SessionAgentType>,
    initiative_id: Option<&str>,
) -> Option<String> {
    if let Some(t) = active_task_id {
        return Some(t);
    }
    if matches!(agent_type, Some(SessionAgentType::Orchestrator)) {
        return initiative_id.map(str::to_owned);
    }
    None
}

/// Pure helper that maps `SessionAgentType` → the role label
/// stamped onto `LlmTurnRecord.agent_role` so the dashboard can
/// render a per-turn role badge. Extracted from the handler
/// body so the projection is unit-testable in isolation and
/// the wire labels (`"Orchestrator"`, `"Executor"`, `"Reviewer"`)
/// are pinned by `agent_role_label_*` tests below — the
/// `TaskLlmTurns` frontend matches on these exact strings.
fn agent_role_label(agent_type: Option<SessionAgentType>) -> Option<String> {
    agent_type.map(|t| match t {
        SessionAgentType::Orchestrator => "Orchestrator".to_owned(),
        SessionAgentType::Executor => "Executor".to_owned(),
        SessionAgentType::Reviewer => "Reviewer".to_owned(),
    })
}

async fn lookup_active_task_id_for_session(
    ctx: &Arc<HandlerContext>,
    session_id: &str,
) -> Option<String> {
    let store = Arc::clone(&ctx.store);
    let session_owned = session_id.to_owned();
    tokio::task::spawn_blocking(move || {
        lookup_active_task_id_for_session_sync(&store, &session_owned)
    })
    .await
    .ok()
    .flatten()
}

/// Sync core of [`lookup_active_task_id_for_session`] — extracted so
/// the C5 witness test can drive it without the full
/// `HandlerContext` / tokio-runtime scaffold.
fn lookup_active_task_id_for_session_sync(
    store: &raxis_store::Store,
    session_id: &str,
) -> Option<String> {
    let conn = store.lock_sync();
    conn.query_row(
        &format!(
            "SELECT task_id FROM {} \
                  WHERE session_id = ?1 \
                    AND activation_state = 'Active' \
                  LIMIT 1",
            Table::SubtaskActivations.as_str()
        ),
        rusqlite::params![session_id],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error vocabulary is a wire surface; pin it so future
    /// refactors cannot accidentally rename a code that planner
    /// retry classifiers match on.
    #[test]
    fn error_codes_pinned() {
        assert_eq!(
            errors::SESSION_TOKEN_MISMATCH,
            "FAIL_SESSION_TOKEN_MISMATCH"
        );
        assert_eq!(errors::PLANNER_FETCH_DENIED, "FAIL_PLANNER_FETCH_DENIED");
        assert_eq!(
            errors::REVIEWER_DENIED,
            "FAIL_PLANNER_FETCH_DENIED_REVIEWER"
        );
        assert_eq!(errors::GATEWAY_UNAVAILABLE, "GatewayUnavailable");
        assert_eq!(errors::NETWORK_ERROR, "NetworkError");
        assert_eq!(errors::TIMEOUT_EXCEEDED, "TimeoutExceeded");
    }

    fn fetch_result(status_code: Option<u16>) -> FetchResult {
        FetchResult {
            fetch_id: Uuid::nil(),
            status_code,
            headers: Vec::new(),
            body_bytes: None,
            latency_ms: 1,
        }
    }

    #[test]
    fn gateway_failure_class_distinguishes_host_provider_transients() {
        assert_eq!(
            gateway_failure_class(&Err(GatewayCallError::GatewayError(
                "NetworkError".to_owned()
            ))),
            "host_provider_network"
        );
        assert_eq!(
            gateway_failure_class(&Err(GatewayCallError::GatewayError(
                "TimeoutExceeded".to_owned()
            ))),
            "host_provider_timeout"
        );
        assert_eq!(
            gateway_failure_class(&Ok(fetch_result(Some(429)))),
            "provider_retryable_http"
        );
        assert_eq!(
            gateway_failure_class(&Err(GatewayCallError::GatewayError(
                "DomainNotAllowed".to_owned()
            ))),
            "policy_denied"
        );
    }

    #[test]
    fn gateway_outcome_label_is_success_only_for_2xx_3xx() {
        assert_eq!(gateway_outcome_label(&Ok(fetch_result(Some(200)))), "ok");
        assert_eq!(gateway_outcome_label(&Ok(fetch_result(Some(302)))), "ok");
        assert_eq!(gateway_outcome_label(&Ok(fetch_result(Some(500)))), "error");
        assert_eq!(
            gateway_outcome_label(&Err(GatewayCallError::Unavailable)),
            "error"
        );
    }

    #[test]
    fn timeout_clamp_bounds() {
        assert_eq!(
            0u32.clamp(HARD_TIMEOUT_FLOOR_MS, HARD_TIMEOUT_CEILING_MS),
            1_000
        );
        assert_eq!(
            999_999u32.clamp(HARD_TIMEOUT_FLOOR_MS, HARD_TIMEOUT_CEILING_MS),
            120_000,
        );
        assert_eq!(
            60_000u32.clamp(HARD_TIMEOUT_FLOOR_MS, HARD_TIMEOUT_CEILING_MS),
            60_000
        );
    }

    #[test]
    fn fetch_kind_mapping_is_one_to_one() {
        assert_eq!(
            map_fetch_kind(PlannerFetchKind::Inference),
            FetchKind::Inference
        );
        assert_eq!(
            map_fetch_kind(PlannerFetchKind::DataFetch),
            FetchKind::DataFetch
        );
    }

    // ─── V2 reviewer-egress-defaults-decision.md §7 ─────────────

    #[test]
    fn extract_host_port_https_default_443() {
        assert_eq!(
            extract_host_port("https://api.anthropic.com/v1/messages"),
            Some(("api.anthropic.com".to_owned(), 443)),
        );
    }

    #[test]
    fn extract_host_port_http_default_80() {
        assert_eq!(
            extract_host_port("http://internal.example/path"),
            Some(("internal.example".to_owned(), 80)),
        );
    }

    #[test]
    fn extract_host_port_explicit_port_overrides_scheme_default() {
        assert_eq!(
            extract_host_port("https://api.example:8443/x"),
            Some(("api.example".to_owned(), 8443)),
        );
    }

    #[test]
    fn extract_host_port_unknown_scheme_falls_back_to_zero() {
        assert_eq!(
            extract_host_port("ws://wss.example/realtime"),
            Some(("wss.example".to_owned(), 0)),
        );
    }

    #[test]
    fn extract_host_port_returns_none_for_malformed_url() {
        // No scheme separator → bucket-less; we drop the request.
        assert_eq!(extract_host_port("not-a-url"), None);
        // Empty host segment after `://` → drop too.
        assert_eq!(extract_host_port("https:///path"), None);
    }

    #[test]
    fn model_id_for_fetch_request_lifts_json_and_provider_url_shapes() {
        assert_eq!(
            model_id_for_fetch_request(
                "https://api.anthropic.com/v1/messages",
                br#"{"model":"claude-sonnet-4-5-20250929"}"#,
            )
            .as_deref(),
            Some("claude-sonnet-4-5-20250929"),
        );
        assert_eq!(
            model_id_for_fetch_request(
                "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
                br#"{"contents":[]}"#,
            )
            .as_deref(),
            Some("gemini-1.5-pro"),
        );
        assert_eq!(
            model_id_for_fetch_request(
                "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-haiku/invoke",
                br#"{}"#,
            )
            .as_deref(),
            Some("anthropic.claude-3-haiku"),
        );
    }

    fn provider(kind: &str, sidecar_endpoint: Option<&str>) -> raxis_policy::ProviderEntry {
        raxis_policy::ProviderEntry {
            provider_id: format!("{kind}-prod"),
            kind: kind.to_owned(),
            credentials_file: format!("{kind}.toml"),
            inference_timeout_ms: 30_000,
            data_fetch_timeout_ms: 10_000,
            max_response_bytes: 16 * 1024 * 1024,
            stream_idle_timeout_ms: None,
            sidecar_endpoint: sidecar_endpoint.map(str::to_owned),
            sidecar_hmac_secret: None,
            sidecar_health_check_path: None,
            pricing: None,
        }
    }

    #[test]
    fn provider_entry_matches_host_covers_all_model_provider_kinds() {
        assert!(provider_entry_matches_host(
            &provider("Anthropic", None),
            "api.anthropic.com",
        ));
        assert!(!provider_entry_matches_host(
            &provider("Anthropic", None),
            "evil-anthropic.com",
        ));
        assert!(provider_entry_matches_host(
            &provider("OpenAI", None),
            "api.openai.com",
        ));
        assert!(!provider_entry_matches_host(
            &provider("OpenAI", None),
            "fakeopenai.com",
        ));
        assert!(provider_entry_matches_host(
            &provider("Gemini", None),
            "generativelanguage.googleapis.com",
        ));
        assert!(provider_entry_matches_host(
            &provider("Bedrock", None),
            "bedrock-runtime.us-east-1.amazonaws.com",
        ));
        assert!(provider_entry_matches_host(
            &provider("http_sidecar", Some("http://127.0.0.1:9100")),
            "127.0.0.1",
        ));
    }

    /// Regression guard: `Duration::as_millis() -> u128 as u32` wraps
    /// silently at ~49.7 days. The helper must saturate to `u32::MAX`
    /// instead so a stuck call surfaces as an obvious sentinel rather
    /// than a small wrapped value in the audit log.
    ///
    /// We can't easily construct a stuck `Instant` in a unit test, but
    /// we can pin the conversion behaviour via the same
    /// `u32::try_from(u128)` shape the helper uses.
    #[test]
    fn elapsed_ms_saturates_instead_of_wrapping() {
        assert_eq!(
            u32::try_from(u128::from(u32::MAX)).unwrap_or(u32::MAX),
            u32::MAX
        );
        assert_eq!(
            u32::try_from(u128::from(u32::MAX) + 1).unwrap_or(u32::MAX),
            u32::MAX
        );
        assert_eq!(u32::try_from(u128::MAX).unwrap_or(u32::MAX), u32::MAX);
        assert_eq!(u32::try_from(0u128).unwrap_or(u32::MAX), 0);
        assert_eq!(u32::try_from(120_000u128).unwrap_or(u32::MAX), 120_000);
    }

    // ─── iter62 — INV-DASHBOARD-LLM-TURN-CAPTURED-01 ───────────────

    /// Helper: build an in-memory `Store`, seed an
    /// initiative + task + session + an Active subtask_activation
    /// row, and return the store. Mirrors the schema invariants in
    /// `crates/store/src/migration.rs` §1070 (`subtask_activations`
    /// CHECK pins `session_id NOT NULL` for Active rows).
    fn seed_active_activation(task_id: &str, session_id: &str) -> raxis_store::Store {
        let store = raxis_store::Store::open_in_memory().unwrap();
        let conn = store.lock_sync();
        let initiatives = Table::Initiatives.as_str();
        let tasks = Table::Tasks.as_str();
        let sessions = Table::Sessions.as_str();
        let activations = Table::SubtaskActivations.as_str();
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives} \
                (initiative_id, state, terminal_criteria_json, \
                 plan_artifact_sha256, created_at) \
             VALUES ('init-c5', 'Executing', '{{}}', 'deadbeef', 1); \
             INSERT INTO {tasks} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, actual_cost) \
             VALUES ('{task_id}', 'init-c5', 'default', 'Running', \
                     'kernel', 1, 1, 1, 0); \
             INSERT INTO {sessions} \
                (session_id, role_id, session_token, lineage_id, \
                 fetch_quota, created_at, expires_at, revoked) \
             VALUES ('{session_id}', 'Executor', 'tok-c5-{session_id}', \
                     'lin-c5', 1000, 1, 9999999999, 0); \
             INSERT INTO {activations} \
                (activation_id, task_id, initiative_id, \
                 activation_state, session_id, created_at, activated_at) \
             VALUES ('act-c5', '{task_id}', 'init-c5', 'Active', \
                     '{session_id}', 1, 2);"
        ))
        .unwrap();
        drop(conn);
        store
    }

    /// Happy path: a session with one Active subtask_activation
    /// row resolves to that row's `task_id`. This is the load-
    /// bearing wiring for `INV-DASHBOARD-LLM-TURN-CAPTURED-01`
    /// — the gateway pump's observer guard
    /// (`gateway/client.rs:508`) requires a Some(task_id) on
    /// the inflight slot to fire.
    #[test]
    fn lookup_active_task_id_for_session_returns_active_row() {
        let store = seed_active_activation("task-c5-happy", "sess-c5-happy");
        let resolved = lookup_active_task_id_for_session_sync(&store, "sess-c5-happy");
        assert_eq!(resolved.as_deref(), Some("task-c5-happy"));
    }

    /// Negative path: a session with no matching Active row falls
    /// back to None. The handler MUST NOT block on this — capture
    /// is best-effort.
    #[test]
    fn lookup_active_task_id_for_session_returns_none_when_no_active_row() {
        let store = seed_active_activation("task-c5-none", "sess-c5-none");
        // Different session_id → no row → None.
        let resolved = lookup_active_task_id_for_session_sync(&store, "sess-c5-other");
        assert!(resolved.is_none());
    }

    /// PendingActivation rows must NOT match — the observer is
    /// scoped to live executor / reviewer rounds; a row that has
    /// not yet been bound to a session has `session_id = NULL`
    /// per the table CHECK (kernel-store.md §2.5.1 Table 6) and
    /// therefore cannot be matched anyway. This test pins the
    /// `activation_state = 'Active'` filter in the SQL so a future
    /// refactor cannot accidentally widen it.
    #[test]
    fn lookup_active_task_id_for_session_ignores_completed_rows() {
        let store = raxis_store::Store::open_in_memory().unwrap();
        let conn = store.lock_sync();
        let initiatives = Table::Initiatives.as_str();
        let tasks = Table::Tasks.as_str();
        let sessions = Table::Sessions.as_str();
        let activations = Table::SubtaskActivations.as_str();
        conn.execute_batch(&format!(
            "INSERT INTO {initiatives} \
                (initiative_id, state, terminal_criteria_json, \
                 plan_artifact_sha256, created_at) \
             VALUES ('init-c5b', 'Executing', '{{}}', 'deadbeef', 1); \
             INSERT INTO {tasks} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, actual_cost) \
             VALUES ('task-completed', 'init-c5b', 'default', \
                     'Completed', 'kernel', 1, 1, 2, 0); \
             INSERT INTO {sessions} \
                (session_id, role_id, session_token, lineage_id, \
                 fetch_quota, created_at, expires_at, revoked) \
             VALUES ('sess-c5b', 'Executor', 'tok-c5b', 'lin-c5b', \
                     1000, 1, 9999999999, 0); \
             INSERT INTO {activations} \
                (activation_id, task_id, initiative_id, \
                 activation_state, session_id, created_at, \
                 activated_at, terminated_at) \
             VALUES ('act-c5b', 'task-completed', 'init-c5b', \
                     'Completed', 'sess-c5b', 1, 2, 3);"
        ))
        .unwrap();
        drop(conn);

        let resolved = lookup_active_task_id_for_session_sync(&store, "sess-c5b");
        assert!(
            resolved.is_none(),
            "Completed activation rows must not match the Active filter"
        );
    }

    // ─── iter65: orchestrator-llm-turns fallback ────────────────
    //
    // `resolve_observer_task_id` is the load-bearing helper that
    // closes the silent-drop on orchestrator planner_fetch calls:
    // orchestrator sessions never carry an `Active` row in
    // `subtask_activations`, so without a fallback the captured
    // `LlmTurnRecord` would be discarded by the
    // `task_id is None` guard in `gateway/client.rs::pump`.

    /// Executor / reviewer happy path: an Active activation row
    /// has been resolved upstream, so the helper passes it
    /// through unchanged regardless of agent type. The
    /// orchestrator-fallback branch must NEVER overwrite a
    /// real executor / reviewer task_id with an initiative_id.
    #[test]
    fn resolve_observer_task_id_passes_through_active_task_for_executor() {
        let out = resolve_observer_task_id(
            Some("task-executor-7".to_owned()),
            Some(SessionAgentType::Executor),
            Some("init-ignored"),
        );
        assert_eq!(out.as_deref(), Some("task-executor-7"));
    }

    /// Orchestrator fallback (the iter65 unblock): when the
    /// lookup returns `None` (orchestrator sessions have no
    /// Active activation row by design), the helper substitutes
    /// the session's `initiative_id` so the captured turns land
    /// on the coordinator task's TaskDetail page
    /// (task_id == initiative_id for the synthetic coordinator).
    #[test]
    fn resolve_observer_task_id_falls_back_to_initiative_id_for_orchestrator() {
        let out = resolve_observer_task_id(
            None,
            Some(SessionAgentType::Orchestrator),
            Some("init-feeg-2"),
        );
        assert_eq!(out.as_deref(), Some("init-feeg-2"));
    }

    /// Orchestrator with no initiative_id (defensive — should
    /// never happen in production since the session row's
    /// `initiative_id` FK is NOT NULL once the orchestrator has
    /// been bound) returns None rather than panicking.
    #[test]
    fn resolve_observer_task_id_orchestrator_without_initiative_id_is_none() {
        let out = resolve_observer_task_id(None, Some(SessionAgentType::Orchestrator), None);
        assert!(out.is_none());
    }

    /// Executor / reviewer without an Active row legitimately
    /// have no task scope (e.g. during early session activation).
    /// The helper MUST NOT fall back to the initiative_id for
    /// these — that would attribute the executor's mid-init
    /// gateway probe to the coordinator task and confuse the
    /// dashboard role attribution.
    #[test]
    fn resolve_observer_task_id_executor_without_active_row_is_none() {
        let out =
            resolve_observer_task_id(None, Some(SessionAgentType::Executor), Some("init-ignored"));
        assert!(out.is_none());

        let out_reviewer =
            resolve_observer_task_id(None, Some(SessionAgentType::Reviewer), Some("init-ignored"));
        assert!(out_reviewer.is_none());
    }

    /// Untagged session (no `session_agent_type` — legacy V1
    /// rows) falls back to None even if an initiative_id is
    /// present. The dashboard role-badge column expects one of
    /// the three pinned labels; emitting an empty role would
    /// render an ugly empty pill.
    #[test]
    fn resolve_observer_task_id_untagged_session_is_none() {
        let out = resolve_observer_task_id(None, None, Some("init-ignored"));
        assert!(out.is_none());
    }

    /// Pin the exact wire labels emitted by `agent_role_label`.
    /// The `TaskLlmTurns` FE (dashboard-fe/src/components/
    /// TaskLlmTurns.tsx) matches case-sensitively on these
    /// strings to pick the badge color; a typo here would
    /// silently fall through to the neutral default styling.
    #[test]
    fn agent_role_label_pins_wire_strings() {
        assert_eq!(
            agent_role_label(Some(SessionAgentType::Orchestrator)).as_deref(),
            Some("Orchestrator"),
        );
        assert_eq!(
            agent_role_label(Some(SessionAgentType::Executor)).as_deref(),
            Some("Executor"),
        );
        assert_eq!(
            agent_role_label(Some(SessionAgentType::Reviewer)).as_deref(),
            Some("Reviewer"),
        );
        assert_eq!(agent_role_label(None), None);
    }

    /// A real call to `elapsed_ms_clamped` on a freshly-minted
    /// `Instant` must return a small value — this just confirms the
    /// helper compiles and the type plumbing is correct end-to-end.
    #[test]
    fn elapsed_ms_clamped_returns_small_value_for_fresh_instant() {
        let started = std::time::Instant::now();
        let ms = elapsed_ms_clamped(started);
        assert!(ms < 60_000, "expected a small value, got {ms}");
    }
}
