//! V3 cloud-forwarding HTTPS client.
//!
//! Normative reference: `specs/v3/cloud-proxy-forwarding.md §3`.
//!
//! [`CloudHttpClient`] is the only thing the per-provider proxy
//! uses to dispatch upstream requests. The client is bound to a
//! single [`CloudUpstreamHost`] at construction time and refuses
//! to dispatch any request whose URL falls off the allowlist.
//!
//! Construction-time enforcement is the primary guarantee; the
//! dispatch-time check is defence-in-depth.

use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::allowlist::{validate_upstream_url, CloudUpstreamHost};
use crate::error::{classify_reqwest_error, UpstreamError};

/// Outbound HTTPS client pinned to a single cloud-control-plane
/// host. Refuses any dispatch off the allowlist.
#[derive(Debug, Clone)]
pub struct CloudHttpClient {
    upstream: CloudUpstreamHost,
    inner: reqwest::Client,
    timeout: Duration,
}

impl CloudHttpClient {
    /// Construct a client locked to `upstream`. Internal `reqwest`
    /// client is built with TLS, no proxies (so an operator-side
    /// MITM proxy can never intercept), connect + read timeouts.
    pub fn new(upstream: CloudUpstreamHost) -> Result<Self, UpstreamError> {
        Self::with_timeout(upstream, Duration::from_secs(30))
    }

    /// Construct with a custom timeout. The minimum enforced
    /// timeout is 5 seconds — any shorter would render the
    /// retries-pinned cloud control planes unreachable on
    /// transient latency.
    pub fn with_timeout(
        upstream: CloudUpstreamHost,
        timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        if timeout < Duration::from_secs(5) {
            return Err(UpstreamError::Misconfigured(
                "cloud-forwarding HTTP timeout must be >= 5s".to_owned(),
            ));
        }
        let inner = reqwest::Client::builder()
            .user_agent("raxis-credential-proxy-cloud-shared/0.1")
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))
            .no_proxy()
            .build()
            .map_err(|e| {
                UpstreamError::Misconfigured(format!("reqwest client build failed: {e}",))
            })?;
        Ok(Self {
            upstream,
            inner,
            timeout,
        })
    }

    /// Upstream host this client is bound to.
    pub fn upstream(&self) -> &CloudUpstreamHost {
        &self.upstream
    }

    /// Configured request timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Dispatch a POST with `application/x-www-form-urlencoded`
    /// body. `url` MUST resolve to the constructor-configured
    /// upstream host (defence-in-depth check).
    ///
    /// Returns the upstream status code + body bytes on any
    /// response (including 4xx / 5xx — those are not errors
    /// here; the caller classifies them via `UpstreamError::Upstream4xx`
    /// `Upstream5xx`).
    pub async fn post_form_urlencoded(
        &self,
        url: &str,
        body: Bytes,
        extra_hdrs: &[(&str, &str)],
    ) -> Result<(u16, Bytes), UpstreamError> {
        validate_upstream_url(&self.upstream, url)?;

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert(
            reqwest::header::HOST,
            HeaderValue::from_str(self.upstream.host())
                .map_err(|e| UpstreamError::Misconfigured(format!("host header invalid: {e}",)))?,
        );
        for (k, v) in extra_hdrs {
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| UpstreamError::Misconfigured(format!("header name invalid: {e}",)))?;
            let value = HeaderValue::from_str(v)
                .map_err(|e| UpstreamError::Misconfigured(format!("header value invalid: {e}",)))?;
            headers.insert(name, value);
        }

        let response = self
            .inner
            .post(url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(classify_reqwest_error)?;

        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(classify_reqwest_error)?;
        Ok((status, bytes))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_constructs_with_default_timeout() {
        let c = CloudHttpClient::new(CloudUpstreamHost::aws_global()).unwrap();
        assert_eq!(c.upstream().host(), "sts.amazonaws.com");
        assert_eq!(c.timeout(), Duration::from_secs(30));
    }

    #[test]
    fn client_refuses_too_short_timeout() {
        let err =
            CloudHttpClient::with_timeout(CloudUpstreamHost::aws_global(), Duration::from_secs(1))
                .unwrap_err();
        assert!(matches!(err, UpstreamError::Misconfigured(_)));
    }

    #[tokio::test]
    async fn post_form_urlencoded_rejects_off_allowlist_url() {
        let c = CloudHttpClient::new(CloudUpstreamHost::aws_global()).unwrap();
        let err = c
            .post_form_urlencoded("https://attacker.example/foo", Bytes::from_static(b""), &[])
            .await
            .unwrap_err();
        assert!(matches!(err, UpstreamError::EgressAllowlist(_)));
    }

    #[tokio::test]
    async fn post_form_urlencoded_rejects_http_scheme() {
        let c = CloudHttpClient::new(CloudUpstreamHost::aws_global()).unwrap();
        let err = c
            .post_form_urlencoded("http://sts.amazonaws.com/", Bytes::from_static(b""), &[])
            .await
            .unwrap_err();
        assert!(matches!(err, UpstreamError::EgressAllowlist(_)));
    }
}
