// raxis-test-support::gateway_backend — `MockBackend` for unit & integration tests.
//
// Why this lives here, not in `raxis-gateway`:
//   The same discipline that keeps `FakeClock` out of `raxis-types`
//   (philosophy.md §1.6 / `raxis-test-support` Layer 1+2 enforcement)
//   applies to gateway substrates. A `MockBackend` shipped in the
//   production gateway crate would be reachable from any binary that
//   links `raxis-gateway` — including the gateway binary itself. The
//   FakeClock / RealClock split is the canonical pattern: the trait
//   and the sole production implementation (`HttpBackend`) live in
//   `raxis-gateway`; the in-memory test fake (`MockBackend`) lives
//   here, where the dev-dep-only gates prevent it from leaking into
//   release binaries.
//
// What this module provides:
//   - `MockBackend` — canned-response `Backend` implementation. Tests
//     either use the `Default` (200 OK + a small JSON body) or the
//     `always_timeout` constructor for the timeout-mapping path.
//   - `MockBackend::with_response` — construct with explicit status,
//     headers, and body; used by tests that pin the gateway's
//     dispatch projection (status-code, error mapping).
//
// What this module does NOT provide:
//   - A "fake HTTP server" — for tests that need genuine HTTP-on-loopback
//     coverage (TLS handshake, connection reuse, gzip decode), spin up
//     a real `tokio::net::TcpListener` or `wiremock` instance and point
//     `HttpBackend` at it. `MockBackend` short-circuits the `reqwest`
//     stack entirely; it tests the dispatch contract, not the network.

use std::time::Duration;

use raxis_gateway_substrate::{
    Backend, BackendError, BackendRequest, BackendResponse,
};

/// In-process `Backend` that returns a single canned `BackendResponse`
/// for every request. Used by integration tests AND by the gateway
/// in-process test harness.
///
/// Cheap to clone — every field is `Vec`/`Duration`/`bool` and there
/// is no shared mutable state. Several tests construct one per case
/// rather than sharing a global instance.
#[derive(Debug, Clone)]
pub struct MockBackend {
    pub canned_status:  u16,
    pub canned_body:    Vec<u8>,
    pub canned_headers: Vec<(String, String)>,
    pub canned_latency: Duration,
    /// If true, `call` returns `Err(BackendError::Timeout)` regardless
    /// of the canned response — used to exercise the gateway's
    /// timeout-mapping path.
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

    /// Construct a backend with explicit status + body + headers. Used
    /// by dispatch tests that pin specific status-code passthrough.
    pub fn with_response(status: u16, body: Vec<u8>, headers: Vec<(String, String)>) -> Self {
        Self {
            canned_status:  status,
            canned_body:    body,
            canned_headers: headers,
            canned_latency: Duration::from_millis(1),
            force_timeout:  false,
        }
    }
}

impl Backend for MockBackend {
    fn call<'a>(
        &'a self,
        req: BackendRequest<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<BackendResponse, BackendError>> + Send + 'a>>
    {
        // Capture the relevant inputs by-move (cheap clones / Copy)
        // and then return the boxed future. This pattern is what
        // `async-trait` would expand to under the hood — keeping it
        // explicit avoids the macro dependency and matches the
        // `Backend` trait's hand-boxed-future signature.
        let force_timeout = self.force_timeout;
        let timeout = req.timeout;
        let canned_body_len = self.canned_body.len() as u64;
        let provider_max = req.provider.max_response_bytes;
        let canned_status = self.canned_status;
        let canned_headers = self.canned_headers.clone();
        let canned_body = self.canned_body.clone();
        let canned_latency = self.canned_latency;

        Box::pin(async move {
            // Honour the timeout switch first so timeout tests don't
            // depend on the body-size check below.
            if force_timeout {
                return Err(BackendError::Timeout {
                    timeout_ms: timeout.as_millis().min(u32::MAX as u128) as u32,
                });
            }

            // Enforce the per-provider body cap on the canned bytes —
            // this is what the real backend does; we honour it here so
            // tests can exercise the TooLarge path without standing up
            // an HTTP server.
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

// ---------------------------------------------------------------------------
// Tests — pin the canned-response contract.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_gateway_substrate::{ProviderCredentials, ProviderEntryView};

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
        let backend = MockBackend {
            canned_body: vec![0xAA; 1024],
            ..MockBackend::default()
        };
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

    #[tokio::test]
    async fn with_response_sets_canned_fields() {
        let backend = MockBackend::with_response(
            429,
            b"{\"err\":\"rate_limited\"}".to_vec(),
            vec![("retry-after".to_owned(), "5".to_owned())],
        );
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
        assert_eq!(resp.status_code, 429);
        assert!(resp.body.starts_with(b"{\"err\""));
        assert_eq!(resp.headers[0].0, "retry-after");
    }
}
