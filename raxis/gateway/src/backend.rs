//! `Backend` trait + a `MockBackend` implementation.
//!
//! Why a trait: the gateway's network call IS its single side effect. To
//! keep `dispatch::handle_fetch_request` testable end-to-end without
//! going through the network, every outbound HTTP is routed through
//! `Backend::call`. Tests inject `MockBackend`; production wires in a
//! real `reqwest`-based impl (planned for Phase B). The trait uses
//! stable async-fn-in-trait (Rust 1.75+).
//!
//! `Backend::call` returns owned bytes — no streaming in v1 per
//! `peripherals.md` §3.2 ("Full-response buffering only").

use std::time::Duration;
use thiserror::Error;

use crate::policy_view::ProviderEntryView;

/// Why a backend call could not produce a `BackendResponse`. Maps 1:1 to
/// the `error` strings in `peripherals.md` §3.2 `FetchResponse` table so
/// the dispatch layer's error→string projection is a one-liner.
///
/// `PartialEq + Eq` are derived so `dispatch::DispatchError` (which has
/// a `Backend` variant) can derive them too — the dispatch tests assert
/// against specific error variants.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BackendError {
    /// Network reachability / TLS / DNS / connection refused.
    #[error("upstream unreachable: {reason}")]
    Upstream { reason: String },
    /// The configured per-request timeout fired.
    #[error("upstream timeout after {timeout_ms} ms")]
    Timeout { timeout_ms: u32 },
    /// The response body exceeded the per-provider `max_response_bytes`.
    #[error("response body too large: {got} bytes > {limit} bytes")]
    TooLarge { got: u64, limit: u64 },
    /// The mock backend was given a directive it could not satisfy
    /// (test-only).
    #[error("mock misconfiguration: {reason}")]
    MockMisconfigured { reason: String },
}

/// One outbound call through the backend.
pub struct BackendRequest<'a> {
    pub provider:  &'a ProviderEntryView,
    pub url:       &'a str,
    pub method:    &'a str,
    pub headers:   &'a [(String, String)],
    pub body:      &'a [u8],
    pub timeout:   Duration,
}

/// Raw upstream response, ready for the gateway to wrap in a
/// `FetchResponse`.
#[derive(Debug, Clone)]
pub struct BackendResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub latency_ms: u64,
}

/// One outbound HTTP call. v1 ships exactly one impl (`MockBackend`);
/// real-network impls (e.g. `HttpBackend` based on `reqwest`) land in
/// follow-up PRs without touching the call sites.
///
/// **Why a hand-boxed Future return rather than `async fn` in the
/// trait:** stable async-fn-in-trait (Rust 1.75+) makes traits
/// non-dyn-compatible by default, but the dispatcher holds the backend
/// behind `Arc<dyn Backend>` (so it can swap mock ↔ real-HTTP without
/// re-monomorphising every call site). Returning an explicit
/// `Pin<Box<dyn Future + Send>>` recovers dyn-compatibility at the
/// cost of one heap allocation per call — negligible relative to the
/// ms-scale network round-trip we're wrapping.
pub trait Backend: Send + Sync {
    fn call<'a>(
        &'a self,
        req: BackendRequest<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<BackendResponse, BackendError>> + Send + 'a>>;
}

// ─────────────────────────────────────────────────────────────────────────
// MockBackend — canned responses keyed by URL prefix.
// ─────────────────────────────────────────────────────────────────────────

/// In-process backend that returns a single canned `BackendResponse` for
/// every request. Used by integration tests AND by operators running the
/// gateway in offline / development mode (`RAXIS_GATEWAY_BACKEND=mock`).
#[derive(Debug, Clone)]
pub struct MockBackend {
    pub canned_status:  u16,
    pub canned_body:    Vec<u8>,
    pub canned_headers: Vec<(String, String)>,
    pub canned_latency: Duration,
    /// If true, `call` returns `Err(BackendError::Timeout)` regardless
    /// of the canned response — used to exercise timeout-mapping paths.
    pub force_timeout:  bool,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            canned_status:  200,
            canned_body:    b"{\"mock\":true,\"completion\":\"hello world\"}".to_vec(),
            canned_headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            canned_latency: Duration::from_millis(1),
            force_timeout:  false,
        }
    }
}

impl MockBackend {
    /// Construct a backend that always errors with the given timeout
    /// duration. Convenience for tests asserting the timeout-mapping
    /// path in `dispatch::handle_fetch_request`.
    pub fn always_timeout(timeout: Duration) -> Self {
        Self {
            force_timeout: true,
            canned_latency: timeout,
            ..Default::default()
        }
    }
}

impl Backend for MockBackend {
    fn call<'a>(
        &'a self,
        req: BackendRequest<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<BackendResponse, BackendError>> + Send + 'a>>
    {
        // We capture the relevant inputs by-move (cheap clones / Copy)
        // and then return the boxed future. This pattern is what
        // `async-trait` would expand to under the hood — keeping it
        // explicit avoids the macro dependency.
        let force_timeout = self.force_timeout;
        let timeout = req.timeout;
        let canned_body_len = self.canned_body.len() as u64;
        let provider_max = req.provider.max_response_bytes;
        let canned_status = self.canned_status;
        let canned_headers = self.canned_headers.clone();
        let canned_body = self.canned_body.clone();
        let canned_latency = self.canned_latency;

        Box::pin(async move {
            // Honour the timeout switch first so timeout tests don't depend
            // on the body-size check below.
            if force_timeout {
                return Err(BackendError::Timeout {
                    timeout_ms: timeout.as_millis().min(u32::MAX as u128) as u32,
                });
            }

            // Enforce the per-provider body cap on the canned bytes — this
            // is what the real backend does; we honour it here so tests can
            // exercise the TooLarge path without standing up an HTTP server.
            if canned_body_len > provider_max {
                return Err(BackendError::TooLarge {
                    got:   canned_body_len,
                    limit: provider_max,
                });
            }

            Ok(BackendResponse {
                status_code: canned_status,
                headers:     canned_headers,
                body:        canned_body,
                latency_ms:  canned_latency.as_millis().min(u64::MAX as u128) as u64,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_view::ProviderCredentials;

    fn provider_view(max_bytes: u64) -> ProviderEntryView {
        ProviderEntryView {
            provider_id: "p1".to_owned(),
            kind: "Anthropic".to_owned(),
            inference_timeout_ms: 30_000,
            data_fetch_timeout_ms: 10_000,
            max_response_bytes: max_bytes,
            credentials: ProviderCredentials {
                api_key:     "sk-test".to_owned(),
                auth_header: "Authorization".to_owned(),
                auth_prefix: "Bearer ".to_owned(),
            },
        }
    }

    #[tokio::test]
    async fn default_mock_returns_canned_200() {
        let backend = MockBackend::default();
        let provider = provider_view(64 * 1024);
        let req = BackendRequest {
            provider: &provider,
            url: "https://api.anthropic.com/v1/messages",
            method: "POST",
            headers: &[],
            body: b"{}",
            timeout: Duration::from_secs(30),
        };
        let resp = backend.call(req).await.unwrap();
        assert_eq!(resp.status_code, 200);
        assert!(!resp.body.is_empty());
    }

    #[tokio::test]
    async fn mock_always_timeout_returns_timeout_error_with_timeout_ms() {
        let backend = MockBackend::always_timeout(Duration::from_millis(250));
        let provider = provider_view(64 * 1024);
        let req = BackendRequest {
            provider: &provider,
            url: "https://api.anthropic.com/v1/messages",
            method: "POST",
            headers: &[],
            body: b"{}",
            timeout: Duration::from_millis(250),
        };
        let err = backend.call(req).await.unwrap_err();
        match err {
            BackendError::Timeout { timeout_ms } => assert_eq!(timeout_ms, 250),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_enforces_per_provider_body_cap_with_too_large_error() {
        // Set the canned body to 1 KiB but the provider cap to 16 bytes.
        let mut backend = MockBackend::default();
        backend.canned_body = vec![0xAA; 1024];
        let provider = provider_view(16);
        let req = BackendRequest {
            provider: &provider,
            url: "https://api.anthropic.com/v1/messages",
            method: "POST",
            headers: &[],
            body: b"{}",
            timeout: Duration::from_secs(30),
        };
        let err = backend.call(req).await.unwrap_err();
        match err {
            BackendError::TooLarge { got, limit } => {
                assert_eq!(got, 1024);
                assert_eq!(limit, 16);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
