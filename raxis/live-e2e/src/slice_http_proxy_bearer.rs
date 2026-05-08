//! Slice 3 — real `HttpProxy` + a real public HTTPS endpoint.
//!
//! Goal: prove that the HTTP credential proxy injects the
//! `Authorization: Bearer <value>` header into a request that
//! reaches a REAL upstream over the open Internet.
//!
//! We target `https://httpbin.org/anything` (a stable public
//! request-introspection endpoint that echoes back the headers it
//! received). The slice asserts:
//!
//!   * `status_code == 200`
//!   * The echoed `headers.Authorization` carries the test bearer
//!     (the proxy MUST have injected it; the agent never sent one).
//!   * The echoed `headers.Host` is `httpbin.org` (the proxy MUST
//!     have rewritten the agent's `Host` header to the upstream
//!     authority).
//!
//! The bearer here is a synthetic test value, NOT a real secret.
//! The point is the *injection*: a real production deployment would
//! resolve a real credential through `CredentialBackend`; the
//! injection plumbing is what this slice exercises end-to-end.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{anyhow, Result};
use raxis_credential_proxy_http::{
    AuthMode, HttpProxy, NoopAuditChannel, OwnedConsumer, ProxyConfig,
    restriction::Restrictions,
};
use raxis_credentials::{
    CredentialBackend, CredentialError, CredentialName, CredentialValue,
    ConsumerIdentity, Lease, OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::env_file::EnvMap;

const TEST_BEARER: &str = "raxis-live-e2e-bearer-NOT-A-REAL-SECRET";

struct LiveBackend {
    value:    Vec<u8>,
    resolves: AtomicU32,
}

impl CredentialBackend for LiveBackend {
    fn resolve(
        &self,
        name: &CredentialName,
        _consumer: ConsumerIdentity<'_>,
    ) -> Result<CredentialValue, CredentialError> {
        if name.as_str() != "live-e2e" {
            return Err(CredentialError::NotFound(name.clone()));
        }
        self.resolves.fetch_add(1, Ordering::Relaxed);
        Ok(CredentialValue::from_bytes(self.value.clone()))
    }
    fn rotate(
        &self, name: &CredentialName, _v: CredentialValue, _a: OperatorId,
    ) -> Result<(), CredentialError> {
        Err(CredentialError::Malformed {
            name: name.clone(),
            reason: "live-e2e backend does not rotate".to_owned(),
        })
    }
    fn exists(&self, name: &CredentialName) -> bool { name.as_str() == "live-e2e" }
    fn lease(&self, _name: &CredentialName) -> Lease { Lease::Forever }
    fn backend_kind(&self) -> &'static str { "live-e2e" }
}

pub(crate) async fn run(_env: &EnvMap) -> Result<()> {
    tracing::info!("slice http-proxy-bearer: starting");
    let backend = Arc::new(LiveBackend {
        value:    TEST_BEARER.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        upstream_url:    "https://httpbin.org/".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        auth_mode:       AuthMode::Bearer,
        consumer:        OwnedConsumer::new("credential_proxy", "live-e2e:http:0"),
        restrictions:    Restrictions::default(),
    };
    let proxy = HttpProxy::bind(backend.clone(), cfg, Arc::new(NoopAuditChannel)).await
        .map_err(|e| anyhow!("HttpProxy::bind: {e}"))?;
    let addr = proxy.local_addr()?;
    tokio::spawn(proxy.serve());

    // Drive a real GET against the proxy.
    let mut s = tokio::net::TcpStream::connect(addr).await?;
    let req = b"GET /anything HTTP/1.1\r\n\
                Host: agent-injected\r\n\
                User-Agent: raxis-live-e2e/1.0\r\n\
                Accept: application/json\r\n\
                Connection: close\r\n\
                \r\n";
    s.write_all(req).await?;
    let mut buf = Vec::with_capacity(8192);
    s.read_to_end(&mut buf).await?;

    // Find the header/body boundary.
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("no end-of-headers in response"))?;
    let head = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
    let body = &buf[header_end + 4..];

    // Status.
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.starts_with("HTTP/1.1 200") {
        return Err(anyhow!(
            "expected 200 from httpbin via proxy; got {status_line:?}; \
             body={:?}", String::from_utf8_lossy(body),
        ));
    }

    // httpbin returns JSON with the request headers it observed in
    // `headers`. Validate the proxy's behaviour from there.
    let json: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| anyhow!("body is not JSON: {e}; body={:?}",
            String::from_utf8_lossy(body)))?;
    let headers = json.get("headers")
        .and_then(|h| h.as_object())
        .ok_or_else(|| anyhow!("no .headers in {json}"))?;
    let auth = headers.get("Authorization")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("upstream did not see Authorization; saw {:?}", headers))?;
    if auth != format!("Bearer {TEST_BEARER}") {
        return Err(anyhow!(
            "Authorization header was not injected/correct; got {auth:?}",
        ));
    }
    let host = headers.get("Host")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("upstream saw no Host header"))?;
    if host != "httpbin.org" {
        return Err(anyhow!(
            "Host header was not rewritten to upstream authority; got {host:?}",
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) < 1 {
        return Err(anyhow!("CredentialBackend was never asked for the bearer"));
    }
    tracing::info!(
        "slice http-proxy-bearer: PASS — bearer injected, host rewritten, real upstream replied 200",
    );
    Ok(())
}
