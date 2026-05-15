//! Per-FetchRequest dispatch: validate → call backend → assemble response.
//!
//! Normative reference: `peripherals.md` §3.2.
//!
//! Why a free function rather than a method: every input the dispatcher
//! needs is already a borrow on `PolicyView`, the `Backend`, and the
//! request itself. Holding a "Dispatcher" struct would just bundle
//! borrows we already have — and would force a `Mutex` around the
//! `PolicyView` swap (epoch advance) which would block dispatch.
//! Instead, the runtime loop holds the policy view in `ArcSwap` and
//! hands a fresh `Arc<PolicyView>` clone into each invocation.

use std::time::Duration;

use raxis_ipc::message::{FetchKind, GatewayMessage};
use thiserror::Error;
use uuid::Uuid;

use crate::backend::{Backend, BackendError, BackendRequest};
use crate::policy_view::{PolicyView, ProviderEntryView};

/// V2_GAPS §C9 / `provider-failure-handling.md §7.3` — default
/// per-chunk idle deadline for streaming inference responses.
///
/// Used as the fallback when a provider's
/// `stream_idle_timeout_ms` is `None` in policy.toml (the standard
/// case for generation-tier providers like Claude / GPT-4). A
/// provider that opens the connection but stalls mid-body fails
/// fast at this boundary rather than dragging out the per-provider
/// `inference_timeout_ms` (often 5 min). The kernel surfaces the
/// boundary as `BackendError::Timeout` → `error: "Timeout"` on the
/// wire `FetchResponse`.
///
/// **Reasoning-tier override.** OpenAI o1/o3 emit no SSE chunks for
/// the full chain-of-thought duration; the operator MUST widen
/// `[providers.<id>].stream_idle_timeout_ms` to 60_000–120_000 in
/// policy.toml to avoid spurious aborts. The 30-second default
/// stays correct for everything else (Claude including extended
/// thinking, where thinking-token deltas flow with sub-5s gaps).
const STREAM_IDLE_TIMEOUT_DEFAULT: Duration = Duration::from_secs(30);

/// Why a single `FetchRequest` could not be answered. These map 1:1 to
/// `peripherals.md` §3.2 "FetchResponse error strings". Anything that
/// should land in the response's `error` field comes through this enum
/// rather than as a `panic!` — the gateway must NEVER bring down the
/// process over a single bad request.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DispatchError {
    /// `gateway_token` on the FetchRequest didn't match the expected one.
    /// This indicates either kernel/gateway desync or a hostile sender on
    /// the gateway socket. The gateway closes the connection after
    /// emitting one `FetchResponse { error: "InvalidToken" }`.
    #[error("gateway_token mismatch: expected={expected_prefix}, got={got_prefix}")]
    InvalidToken {
        /// We log only the first 8 chars of either token so the rest of
        /// the secret never lands in stderr or in audit logs.
        expected_prefix: String,
        got_prefix: String,
    },
    /// URL hostname not in `egress_domains` ∪ `egress_patterns`.
    #[error("domain not allowed: {host}")]
    DomainNotAllowed { host: String },
    /// We could not derive a provider for the URL (no `[[providers]]`
    /// matches the URL's host).
    #[error("no provider matches host {host}")]
    UnknownProviderForHost { host: String },
    /// The configured timeout exceeds the per-provider hard cap.
    #[error("timeout {requested_ms} ms exceeds provider cap {cap_ms} ms")]
    TimeoutAboveCap { requested_ms: u32, cap_ms: u32 },
    /// Backend returned an error.
    #[error(transparent)]
    Backend(#[from] BackendError),
    /// `PolicyView` is missing (e.g. last reload failed). Dispatcher
    /// short-circuits to `error: "PolicyReloadFailed"` per spec.
    #[error("policy view unavailable")]
    PolicyReloadFailed,
}

impl DispatchError {
    /// Project the dispatch error onto the spec-mandated short string
    /// that lands in `FetchResponse.error`. Keeps the wire vocabulary
    /// stable across minor refactors.
    pub fn as_wire_string(&self) -> &'static str {
        match self {
            Self::InvalidToken { .. } => "InvalidToken",
            Self::DomainNotAllowed { .. } => "DomainNotAllowed",
            Self::UnknownProviderForHost { .. } => "UnknownProviderForHost",
            Self::TimeoutAboveCap { .. } => "TimeoutExceeded",
            Self::Backend(BackendError::Timeout { .. }) => "TimeoutExceeded",
            Self::Backend(BackendError::TooLarge { .. }) => "ResponseTooLarge",
            Self::Backend(BackendError::Upstream { .. }) => "NetworkError",
            Self::PolicyReloadFailed => "PolicyReloadFailed",
        }
    }
}

/// Handle one `FetchRequest`. Always returns a `FetchResponse` — never
/// a `Result` — because the spec requires every request to receive
/// exactly one response (success OR error). If the request was
/// unparseable upstream of this function, the runtime loop is
/// responsible for assembling its own error response.
pub async fn handle_fetch_request(
    request: GatewayMessage,
    expected_token: &str,
    policy_view: Option<&PolicyView>,
    backend: &dyn Backend,
) -> GatewayMessage {
    let (fetch_id, gateway_token, fetch_kind, url, method, headers, body_bytes, timeout_ms) =
        match request {
            GatewayMessage::FetchRequest {
                gateway_token,
                fetch_id,
                fetch_kind,
                url,
                method,
                headers,
                body_bytes,
                timeout_ms,
                ..
            } => (
                fetch_id,
                gateway_token,
                fetch_kind,
                url,
                method,
                headers,
                body_bytes,
                timeout_ms,
            ),
            // Caller invariant: only `FetchRequest` ever lands here. If
            // it does not, that is a runtime-loop bug — surface it as
            // `Upstream` (which projects to "NetworkError" on the wire)
            // so an operator sees a clear envelope while the kernel-side
            // log carries the variant name for diagnosis.
            other => {
                return error_response(
                    Uuid::nil(),
                    DispatchError::Backend(BackendError::Upstream {
                        reason: format!(
                            "handle_fetch_request received non-FetchRequest variant: \
                         {}",
                            std::any::type_name_of_val(&other),
                        ),
                    }),
                );
            }
        };

    match dispatch(
        fetch_id,
        &gateway_token,
        expected_token,
        fetch_kind,
        &url,
        &method,
        &headers,
        &body_bytes,
        timeout_ms,
        policy_view,
        backend,
    )
    .await
    {
        Ok(resp) => resp,
        Err(err) => error_response(fetch_id, err),
    }
}

/// Inner pipeline: fail-closed at every step. Returns the success
/// `FetchResponse` or the first dispatch error encountered.
#[allow(clippy::too_many_arguments)]
async fn dispatch(
    fetch_id: Uuid,
    got_token: &str,
    expected_token: &str,
    fetch_kind: FetchKind,
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body_bytes: &[u8],
    timeout_ms: u32,
    policy_view: Option<&PolicyView>,
    backend: &dyn Backend,
) -> Result<GatewayMessage, DispatchError> {
    // 1. Token check FIRST — refuses to do any further work for a
    //    sender we cannot authenticate.
    if got_token != expected_token {
        return Err(DispatchError::InvalidToken {
            expected_prefix: token_prefix(expected_token),
            got_prefix: token_prefix(got_token),
        });
    }

    // 2. Policy view must be loaded. If the last reload failed, every
    //    request short-circuits with PolicyReloadFailed per
    //    peripherals.md §3.2 "Domain allowlist re-validation".
    let view = policy_view.ok_or(DispatchError::PolicyReloadFailed)?;

    // 3. URL allowlist re-validation. The gateway does NOT trust the
    //    kernel's pre-validation — we re-check independently.
    if !view.is_url_allowed(url) {
        let host = host_of_url(url).unwrap_or_else(|| "<unparsed>".to_owned());
        return Err(DispatchError::DomainNotAllowed { host });
    }

    // 4. Provider lookup by URL hostname. v1 derivation rules:
    //      kind == "Anthropic" → host ends with "anthropic.com"
    //      kind == "OpenAI"    → host ends with "openai.com"
    //    Unknown `kind` strings never auto-match; v2 will add a
    //    `url_match` field to make this explicit per provider.
    let host = host_of_url(url).ok_or_else(|| {
        // We already passed `is_url_allowed`, so `extract_host` succeeding
        // there means it must succeed here — but we keep a defensive
        // branch so a future change to `is_url_allowed` can't silently
        // remove the host check.
        DispatchError::DomainNotAllowed {
            host: "<unparsed>".to_owned(),
        }
    })?;
    let provider = provider_for_host(view, &host)
        .ok_or_else(|| DispatchError::UnknownProviderForHost { host: host.clone() })?;

    // 5. Timeout cap by fetch kind.
    let provider_cap_ms = match fetch_kind {
        FetchKind::Inference => provider.inference_timeout_ms,
        FetchKind::DataFetch => provider.data_fetch_timeout_ms,
    };
    if timeout_ms > provider_cap_ms {
        return Err(DispatchError::TimeoutAboveCap {
            requested_ms: timeout_ms,
            cap_ms: provider_cap_ms,
        });
    }

    // 6. Backend call. Backend is responsible for credential injection
    //    and per-call enforcement of `provider.max_response_bytes`.
    //
    //    V2_GAPS §C9 — for `FetchKind::Inference`, attach a per-chunk
    //    idle timeout so a provider that accepts the request but
    //    stalls mid-body fails fast at the configured boundary
    //    rather than dragging the request out to the
    //    `inference_timeout_ms` ceiling. The per-provider override
    //    (`provider.stream_idle_timeout_ms`) takes precedence when
    //    set; otherwise the hard-coded `STREAM_IDLE_TIMEOUT_DEFAULT`
    //    (30 s) applies. Reasoning-tier providers (OpenAI o1/o3)
    //    must widen this to 60–120 s in policy.toml — see
    //    `V2_GAPS.md §C9 "Per-provider stream_idle_timeout"`.
    //
    //    `FetchKind::DataFetch` (tools' bounded HTTP fetches) keeps
    //    the buffered shape because legitimate REST calls can pause
    //    briefly between a big `Content-Length` body's chunks and
    //    we don't want spurious timeouts there.
    let stream_idle_timeout = match fetch_kind {
        FetchKind::Inference => Some(
            provider
                .stream_idle_timeout_ms
                .map(|ms| Duration::from_millis(u64::from(ms)))
                .unwrap_or(STREAM_IDLE_TIMEOUT_DEFAULT),
        ),
        FetchKind::DataFetch => None,
    };
    let backend_resp = backend
        .call(BackendRequest {
            provider,
            url,
            method,
            headers,
            body: body_bytes,
            timeout: Duration::from_millis(timeout_ms as u64),
            stream_idle_timeout,
        })
        .await?;

    // 7. Wrap in the spec FetchResponse shape.
    Ok(GatewayMessage::FetchResponse {
        fetch_id,
        status_code: Some(backend_resp.status_code),
        headers: backend_resp.headers,
        body_bytes: Some(backend_resp.body),
        latency_ms: backend_resp.latency_ms.min(u32::MAX as u64) as u32,
        error: None,
    })
}

/// Build the spec-shaped error variant of `FetchResponse`. The success-
/// shape fields are all None / 0 / empty so a careless consumer that
/// inspects them gets defensive defaults rather than stale data.
fn error_response(fetch_id: Uuid, err: DispatchError) -> GatewayMessage {
    eprintln!(
        "{{\"level\":\"warn\",\"fetch_id\":\"{fetch_id}\",\
         \"dispatch_error\":\"{}\",\"detail\":\"{}\"}}",
        err.as_wire_string(),
        err,
    );
    GatewayMessage::FetchResponse {
        fetch_id,
        status_code: None,
        headers: Vec::new(),
        body_bytes: None,
        latency_ms: 0,
        error: Some(err.as_wire_string().to_owned()),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

/// Trim a token to its first 8 chars for logging. NEVER log the full
/// 64-char value — operators tail stderr in shared environments.
fn token_prefix(token: &str) -> String {
    let n = token.len().min(8);
    format!("{}...", &token[..n])
}

/// Extract the URL's host. Mirrors `policy_view::extract_host` (kept
/// private there) — duplicated here rather than re-exported because the
/// gateway is the only caller and the function is six lines.
fn host_of_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let host_with_path = after_scheme.split('/').next()?;
    let host = host_with_path.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

/// Map a URL host to the matching `ProviderEntryView`, if any.
///
/// v1 mapping table:
///
/// - `kind = "Anthropic"` matches any host ending in `anthropic.com`.
/// - `kind = "OpenAI"`    matches any host ending in `openai.com`.
/// - All other kinds: no auto-match.
///
/// v2 will replace this with an explicit `url_match` field per
/// `[[providers]]` entry. Until then, the auto-mapping covers the two
/// providers the spec calls out by name; operators wanting other
/// providers MUST set `provider_id` on the FetchRequest (a planned
/// IPC field — currently unused).
fn provider_for_host<'a>(view: &'a PolicyView, host: &str) -> Option<&'a ProviderEntryView> {
    let host_lower = host.to_lowercase();
    for entry in view.providers.values() {
        let matches = match entry.kind.as_str() {
            "Anthropic" => host_lower.ends_with("anthropic.com"),
            "OpenAI" => host_lower.ends_with("openai.com"),
            _ => false,
        };
        if matches {
            return Some(entry);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    // The in-memory `MockBackend` lives in `raxis-test-support` (the
    // dev-dep-only crate) so it can never reach a release binary.
    // See `gateway/src/backend.rs` module header for the discipline
    // rationale (philosophy.md §1.6 / `RealClock` ↔ `FakeClock`).
    use crate::policy_view::{PolicyView, ProviderCredentials};
    use raxis_test_support::MockBackend;
    use std::collections::HashMap;

    const EXPECTED_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn anthropic_provider() -> ProviderEntryView {
        ProviderEntryView {
            provider_id: "anthropic-prod".to_owned(),
            kind: "Anthropic".to_owned(),
            inference_timeout_ms: 30_000,
            data_fetch_timeout_ms: 10_000,
            max_response_bytes: 16 * 1024 * 1024,
            stream_idle_timeout_ms: None,
            credentials: ProviderCredentials {
                api_key: "sk-ant-x".to_owned(),
                auth_header: "x-api-key".to_owned(),
                auth_prefix: "".to_owned(),
            },
        }
    }

    fn view_with_anthropic() -> PolicyView {
        let mut providers = HashMap::new();
        providers.insert("anthropic-prod".to_owned(), anthropic_provider());
        PolicyView {
            epoch: 1,
            egress_domains: vec![],
            egress_patterns: vec!["*.anthropic.com".to_owned()],
            providers,
        }
    }

    fn ok_request(url: &str, timeout_ms: u32, kind: FetchKind) -> GatewayMessage {
        GatewayMessage::FetchRequest {
            gateway_token: EXPECTED_TOKEN.to_owned(),
            fetch_id: Uuid::new_v4(),
            fetch_kind: kind,
            url: url.to_owned(),
            method: "POST".to_owned(),
            headers: vec![],
            body_bytes: b"{}".to_vec(),
            timeout_ms,
            session_id: None,
            task_id: None,
        }
    }

    /// V2_GAPS §C9 — pin the per-provider `stream_idle_timeout_ms`
    /// override path. A `Backend` that captures the inbound
    /// `BackendRequest::stream_idle_timeout` lets us prove that
    /// dispatch reads `provider.stream_idle_timeout_ms` and converts
    /// it to the right `Duration` for the `Inference` path,
    /// AND that the `DataFetch` path is unconditionally `None`
    /// (so a tool's bounded HTTP fetch doesn't get spuriously aborted
    /// on legitimate inter-chunk pauses).
    #[derive(Default, Clone)]
    struct CapturingBackend {
        // Outer Option = "was the backend called at all"; inner
        // Option<Duration> mirrors `BackendRequest::stream_idle_timeout`
        // so we can distinguish "called with None" from "not called".
        seen_stream_idle: std::sync::Arc<std::sync::Mutex<Option<Option<Duration>>>>,
    }

    impl Backend for CapturingBackend {
        fn call<'a>(
            &'a self,
            req: BackendRequest<'a>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<raxis_gateway_substrate::BackendResponse, BackendError>,
                    > + Send
                    + 'a,
            >,
        > {
            *self.seen_stream_idle.lock().unwrap() = Some(req.stream_idle_timeout);
            Box::pin(async move {
                Ok(raxis_gateway_substrate::BackendResponse {
                    status_code: 200,
                    headers: vec![],
                    body: b"{}".to_vec(),
                    latency_ms: 1,
                })
            })
        }
    }

    /// Default provider (no `stream_idle_timeout_ms`) MUST surface a
    /// 30-second per-chunk deadline on `Inference` so generation-tier
    /// providers (Claude / GPT-4) detect a stalled provider quickly.
    #[tokio::test]
    async fn inference_uses_30s_default_when_provider_has_no_override() {
        let view = view_with_anthropic();
        let backend = CapturingBackend::default();
        let req = ok_request(
            "https://api.anthropic.com/v1/messages",
            30_000,
            FetchKind::Inference,
        );
        let _ = handle_fetch_request(req, EXPECTED_TOKEN, Some(&view), &backend).await;
        let observed =
            (*backend.seen_stream_idle.lock().unwrap()).expect("backend must have been called");
        assert_eq!(
            observed,
            Some(Duration::from_secs(30)),
            "default per-chunk idle MUST be 30s (V2_GAPS §C9 fallback)",
        );
    }

    /// A provider with `stream_idle_timeout_ms = 120_000` (typical
    /// OpenAI o1/o3 setting) MUST surface a 120-second per-chunk
    /// deadline. This is the central use case for the per-provider
    /// override.
    #[tokio::test]
    async fn inference_honours_per_provider_stream_idle_override() {
        let mut view = view_with_anthropic();
        let p = view.providers.get_mut("anthropic-prod").unwrap();
        p.stream_idle_timeout_ms = Some(120_000);

        let backend = CapturingBackend::default();
        let req = ok_request(
            "https://api.anthropic.com/v1/messages",
            30_000,
            FetchKind::Inference,
        );
        let _ = handle_fetch_request(req, EXPECTED_TOKEN, Some(&view), &backend).await;
        let observed =
            (*backend.seen_stream_idle.lock().unwrap()).expect("backend must have been called");
        assert_eq!(
            observed,
            Some(Duration::from_millis(120_000)),
            "per-provider override MUST flow through to BackendRequest",
        );
    }

    /// `FetchKind::DataFetch` MUST NOT carry a per-chunk deadline
    /// even if the provider's policy declares one — a tool's
    /// bounded REST call can legitimately pause between chunks of
    /// a `Content-Length`-framed body and we don't want spurious
    /// idle-timeout aborts there.
    #[tokio::test]
    async fn data_fetch_never_attaches_stream_idle_timeout() {
        let mut view = view_with_anthropic();
        let p = view.providers.get_mut("anthropic-prod").unwrap();
        p.stream_idle_timeout_ms = Some(60_000);

        let backend = CapturingBackend::default();
        let req = ok_request(
            "https://api.anthropic.com/v1/messages",
            5_000,
            FetchKind::DataFetch,
        );
        let _ = handle_fetch_request(req, EXPECTED_TOKEN, Some(&view), &backend).await;
        let observed =
            (*backend.seen_stream_idle.lock().unwrap()).expect("backend must have been called");
        // After the outer `expect` the value type is `Option<Duration>`;
        // `None` means "no per-chunk idle deadline attached".
        assert_eq!(
            observed, None,
            "DataFetch MUST NOT carry a per-chunk idle timeout (V2_GAPS §C9)",
        );
    }

    #[tokio::test]
    async fn happy_path_returns_fetch_response_with_mock_body() {
        let view = view_with_anthropic();
        let backend = MockBackend::default();
        let req = ok_request(
            "https://api.anthropic.com/v1/messages",
            30_000,
            FetchKind::Inference,
        );
        let resp = handle_fetch_request(req, EXPECTED_TOKEN, Some(&view), &backend).await;
        match resp {
            GatewayMessage::FetchResponse {
                status_code,
                body_bytes,
                error,
                ..
            } => {
                assert_eq!(status_code, Some(200));
                assert!(body_bytes.is_some());
                assert!(error.is_none());
            }
            other => panic!("expected FetchResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn token_mismatch_returns_invalid_token_error_string() {
        let view = view_with_anthropic();
        let backend = MockBackend::default();
        let mut req = ok_request(
            "https://api.anthropic.com/v1/messages",
            30_000,
            FetchKind::Inference,
        );
        if let GatewayMessage::FetchRequest { gateway_token, .. } = &mut req {
            *gateway_token =
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_owned();
        }
        let resp = handle_fetch_request(req, EXPECTED_TOKEN, Some(&view), &backend).await;
        assert_error_string(&resp, "InvalidToken");
    }

    #[tokio::test]
    async fn unallowed_domain_returns_domain_not_allowed_error() {
        let view = view_with_anthropic();
        let backend = MockBackend::default();
        let req = ok_request(
            "https://evil.example.com/exfiltrate",
            1000,
            FetchKind::DataFetch,
        );
        let resp = handle_fetch_request(req, EXPECTED_TOKEN, Some(&view), &backend).await;
        assert_error_string(&resp, "DomainNotAllowed");
    }

    #[tokio::test]
    async fn host_with_no_matching_provider_returns_unknown_provider() {
        // Allowlist allows the host (we add a fake "*.unknown-vendor.io"
        // pattern) but no [[providers]] entry maps to it.
        let mut view = view_with_anthropic();
        view.egress_patterns.push("*.unknown-vendor.io".to_owned());
        let backend = MockBackend::default();
        let req = ok_request(
            "https://api.unknown-vendor.io/v1/x",
            1000,
            FetchKind::DataFetch,
        );
        let resp = handle_fetch_request(req, EXPECTED_TOKEN, Some(&view), &backend).await;
        assert_error_string(&resp, "UnknownProviderForHost");
    }

    #[tokio::test]
    async fn timeout_above_provider_cap_returns_timeout_exceeded() {
        let view = view_with_anthropic();
        let backend = MockBackend::default();
        // Inference cap is 30000 ms — request 30001 ms.
        let req = ok_request(
            "https://api.anthropic.com/v1/messages",
            30_001,
            FetchKind::Inference,
        );
        let resp = handle_fetch_request(req, EXPECTED_TOKEN, Some(&view), &backend).await;
        assert_error_string(&resp, "TimeoutExceeded");
    }

    #[tokio::test]
    async fn backend_too_large_maps_to_response_too_large_string() {
        let view = view_with_anthropic();
        let backend = MockBackend {
            canned_body: vec![0; 100],
            ..MockBackend::default()
        };
        // Override provider via building the view by hand with a tiny cap.
        let mut tiny = anthropic_provider();
        tiny.max_response_bytes = 16;
        let mut providers = HashMap::new();
        providers.insert("anthropic-prod".to_owned(), tiny);
        let view = PolicyView { providers, ..view };
        let req = ok_request(
            "https://api.anthropic.com/v1/messages",
            1000,
            FetchKind::Inference,
        );
        let resp = handle_fetch_request(req, EXPECTED_TOKEN, Some(&view), &backend).await;
        assert_error_string(&resp, "ResponseTooLarge");
    }

    #[tokio::test]
    async fn backend_timeout_maps_to_timeout_exceeded_string() {
        let view = view_with_anthropic();
        let backend = MockBackend::always_timeout(Duration::from_millis(100));
        let req = ok_request(
            "https://api.anthropic.com/v1/messages",
            100,
            FetchKind::DataFetch,
        );
        let resp = handle_fetch_request(req, EXPECTED_TOKEN, Some(&view), &backend).await;
        assert_error_string(&resp, "TimeoutExceeded");
    }

    #[tokio::test]
    async fn missing_policy_view_returns_policy_reload_failed() {
        let backend = MockBackend::default();
        let req = ok_request(
            "https://api.anthropic.com/v1/messages",
            1000,
            FetchKind::Inference,
        );
        let resp = handle_fetch_request(req, EXPECTED_TOKEN, None, &backend).await;
        assert_error_string(&resp, "PolicyReloadFailed");
    }

    fn assert_error_string(resp: &GatewayMessage, expected: &str) {
        match resp {
            GatewayMessage::FetchResponse {
                error,
                status_code,
                body_bytes,
                ..
            } => {
                assert_eq!(
                    error.as_deref(),
                    Some(expected),
                    "error should be {expected}; full response: {resp:?}"
                );
                assert!(
                    status_code.is_none(),
                    "error responses must have status_code = None"
                );
                assert!(
                    body_bytes.is_none(),
                    "error responses must have body_bytes = None"
                );
            }
            other => panic!("expected FetchResponse, got {other:?}"),
        }
    }
}
