//! `HttpBackend` — real outbound HTTP for the gateway.
//!
//! Normative reference: `peripherals.md` §3.2 ("Gateway Wire Format" and
//! "Outbound provider call"). This is the production backend that
//! replaces `MockBackend` for real provider traffic.
//!
//! # Why this is feature-gated
//!
//! `cargo test` (no flag) must NOT link `reqwest` / `rustls`: the
//! gateway test surface is built around `MockBackend`, and pulling
//! TLS into every CI run inflates link times by ~3 s and pulls in
//! `ring` / `rustls-pemfile` / a transitive web-pki bundle that
//! every workspace crate then has to either depend-on or ignore.
//! `cargo test --features http-backend` opts in for real-network
//! work (e2e harness, `raxis-gateway` binary) without changing the
//! default test discipline.
//!
//! # Discipline
//!
//! - One reusable `reqwest::Client` per gateway process. Connection
//!   pool keeps the TLS handshake out of the per-request hot path
//!   for repeat calls to the same provider host (Anthropic, OpenAI,
//!   etc.).
//! - Per-request hard timeout from `BackendRequest::timeout` (NOT a
//!   builder-side default — the kernel's policy decides timeouts
//!   per provider per `peripherals.md` §3.2 inference_timeout_ms /
//!   data_fetch_timeout_ms).
//! - Body cap: `provider.max_response_bytes` is enforced at *read*
//!   time — we stream the body with `response.bytes_stream()` and
//!   bail with `BackendError::TooLarge` the moment the running
//!   total exceeds the cap. This protects the kernel from a
//!   pathological provider returning a 1 GiB body and OOMing the
//!   gateway.
//! - The auth header is injected from `provider.credentials.api_key`
//!   on the gateway side; the kernel never sees the raw key, the
//!   planner never sees the raw key, and the audit chain only
//!   records the provider_id (per `credential-proxy.md` §4.3).
//!
//! # What this backend does NOT do
//!
//! - No retry. The kernel is the retry authority (`provider-failure-
//!   handling.md` §4); the gateway is a request-reply shim.
//! - No JSON parsing (per spec).
//! - No streaming SSE: every Anthropic / OpenAI completion is
//!   fetched in full-body buffering mode, mirroring `peripherals.md`
//!   §3.2 "Full-response buffering only".

use std::sync::Arc;
use std::time::Duration;

use crate::backend::{Backend, BackendError, BackendRequest, BackendResponse};

/// Production HTTP backend backed by a single `reqwest::Client`. Cheap
/// to clone (`Arc` underneath); keep one per gateway process and reuse
/// across every call.
#[derive(Clone)]
pub struct HttpBackend {
    client: Arc<reqwest::Client>,
}

impl Default for HttpBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpBackend {
    /// Construct a backend with sensible production defaults:
    /// - HTTP/1.1 + HTTP/2 negotiated via TLS ALPN
    /// - Connection-keep-alive + a small connection pool
    /// - No request-level timeout (set per-call; see `Backend::call`)
    /// - rustls-only (no system OpenSSL)
    /// - User-Agent: `raxis-gateway/<version>`
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("raxis-gateway/", env!("CARGO_PKG_VERSION")))
            // Tight connect timeout: the per-provider inference
            // timeout covers the full call, but a 60-second connect
            // wait would mask outages.
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(4)
            .build()
            // The TLS stack initialiser is fail-open in our call
            // sites — if it ever returns Err here we panic, because
            // a gateway that cannot mint a TLS client cannot fulfil
            // its single side effect.
            .expect("reqwest::Client init failed (TLS stack misconfigured?)");
        Self { client: Arc::new(client) }
    }

    /// Construct a backend backed by an externally-built client.
    /// Used by tests and by operators that want to install custom
    /// root CAs or middleware.
    pub fn from_client(client: reqwest::Client) -> Self {
        Self { client: Arc::new(client) }
    }
}

impl Backend for HttpBackend {
    fn call<'a>(
        &'a self,
        req: BackendRequest<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<BackendResponse, BackendError>> + Send + 'a>>
    {
        let client = self.client.clone();
        Box::pin(async move {
            let started = std::time::Instant::now();
            let url = req.url.to_owned();
            let method = parse_method(req.method)?;

            let mut builder = client
                .request(method, &url)
                .timeout(req.timeout)
                .body(req.body.to_vec());

            // Operator-supplied headers come first.
            for (k, v) in req.headers {
                builder = builder.header(k, v);
            }

            // Inject the provider's auth credential. We do this AFTER
            // the operator-supplied headers so a malicious / buggy
            // planner cannot override `Authorization` with their own
            // value and bypass the gateway-side credential proxy.
            //
            // The header name + prefix come from policy
            // (`provider.credentials`), not the planner — see
            // `credential-proxy.md` §4.
            let auth_value = format!(
                "{}{}",
                req.provider.credentials.auth_prefix,
                req.provider.credentials.api_key,
            );
            builder = builder.header(&req.provider.credentials.auth_header, auth_value);

            // Anthropic-flavoured extras when applicable. The header
            // names are stable across the public Messages API; if
            // the provider isn't Anthropic these headers are
            // harmless padding.
            if req.provider.kind.eq_ignore_ascii_case("Anthropic") {
                // anthropic-version pins the API contract. The kernel
                // does not embed the version in the policy today, so
                // we hard-code a known-good baseline; future revisions
                // will move this to `[providers.headers]`.
                builder = builder.header("anthropic-version", "2023-06-01");
            }

            let resp = match builder.send().await {
                Ok(r) => r,
                Err(e) => {
                    if e.is_timeout() {
                        return Err(BackendError::Timeout {
                            timeout_ms: req.timeout.as_millis().min(u32::MAX as u128) as u32,
                        });
                    }
                    return Err(BackendError::Upstream {
                        reason: format!("send failed: {e}"),
                    });
                }
            };

            let status_code = resp.status().as_u16();
            // Materialise headers up-front: they're cheap and we need
            // them in the response regardless of the body outcome.
            let mut headers: Vec<(String, String)> = Vec::with_capacity(resp.headers().len());
            for (k, v) in resp.headers() {
                let v_str = match v.to_str() {
                    Ok(s) => s.to_owned(),
                    // Non-ASCII headers come through as `Err`; we
                    // keep them in lossy form (URL-encoded bytes)
                    // because a strict reject would surprise
                    // operators when a CDN inserts a `via:` header
                    // with a Latin-1 character.
                    Err(_) => v.as_bytes().iter()
                        .map(|b| format!("\\x{:02x}", b))
                        .collect::<String>(),
                };
                headers.push((k.as_str().to_owned(), v_str));
            }

            // Bounded body read. `resp.bytes()` would allocate the
            // full body before letting us check the cap; instead we
            // pull chunks via `Response::chunk()` (a built-in async
            // iterator on `reqwest::Response` that doesn't drag in
            // `futures_util`) and bail the moment our running total
            // exceeds `max_response_bytes`.
            let limit = req.provider.max_response_bytes;
            let mut body = Vec::with_capacity(((limit).min(64 * 1024)) as usize);
            let mut resp = resp;
            loop {
                let next = resp.chunk().await.map_err(|e| BackendError::Upstream {
                    reason: format!("body stream error: {e}"),
                })?;
                let Some(chunk) = next else { break; };
                let next_total = body.len() as u64 + chunk.len() as u64;
                if next_total > limit {
                    return Err(BackendError::TooLarge {
                        got:   next_total,
                        limit,
                    });
                }
                body.extend_from_slice(&chunk);
            }

            Ok(BackendResponse {
                status_code,
                headers,
                body,
                latency_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            })
        })
    }
}

fn parse_method(m: &str) -> Result<reqwest::Method, BackendError> {
    match m.to_ascii_uppercase().as_str() {
        "GET"     => Ok(reqwest::Method::GET),
        "POST"    => Ok(reqwest::Method::POST),
        "PUT"     => Ok(reqwest::Method::PUT),
        "PATCH"   => Ok(reqwest::Method::PATCH),
        "DELETE"  => Ok(reqwest::Method::DELETE),
        "HEAD"    => Ok(reqwest::Method::HEAD),
        "OPTIONS" => Ok(reqwest::Method::OPTIONS),
        other => Err(BackendError::Upstream {
            reason: format!("unsupported HTTP method {other:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_backend_constructs_with_defaults() {
        // Sanity: the static initialiser must never panic; a
        // gateway that cannot stand up its TLS client is unusable.
        let _ = HttpBackend::new();
    }

    #[test]
    fn parse_method_accepts_canonical_set() {
        assert!(parse_method("GET").is_ok());
        assert!(parse_method("post").is_ok());
        assert!(parse_method("PaTcH").is_ok());
    }

    #[test]
    fn parse_method_rejects_unknown() {
        match parse_method("CONNECT").unwrap_err() {
            BackendError::Upstream { reason } => assert!(reason.contains("CONNECT")),
            other => panic!("expected Upstream, got {other:?}"),
        }
    }
}
