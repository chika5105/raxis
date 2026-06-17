//! Slice — `HttpProxy` enforces method + path-prefix denials against
//! a real public HTTPS upstream.
//!
//! Goal: prove that the HTTP credential proxy correctly REJECTS
//! requests that violate the per-task `[tasks.credentials.restrictions]`
//! clause **before** the bearer token is injected and **before** the
//! upstream is contacted, while still allowing the matching shape
//! through. This is the deny-path twin of `http-proxy-bearer`.
//!
//! Why this matters: a positive-only test (one allow path) cannot
//! distinguish "the proxy works" from "the proxy is wide open and
//! always forwards." This slice exercises both halves of the policy.
//!
//! Wire shape:
//!
//!   1. Bind the real `HttpProxy` against `https://httpbin.org/`
//!      with `Restrictions { allowed_methods: ["GET"],
//!      allowed_path_prefixes: ["/anything"] }`.
//!   2. Sub-test A — `GET /anything/widget` → MUST reach upstream
//!      with the bearer injected (httpbin replies 200 + echo).
//!   3. Sub-test B — `POST /anything/widget` → MUST be rejected at
//!      the proxy with a 4xx and the bearer MUST NOT be observable
//!      anywhere on the wire (the local LiveBackend's resolve
//!      counter MUST NOT increment for this attempt).
//!   4. Sub-test C — `GET /forbidden` → MUST be rejected at the
//!      proxy with a 4xx (path-prefix denial); same bearer-leak
//!      assertion.
//!
//! No real secret is involved — `TEST_BEARER` is a synthetic
//! constant. The deny test still asserts that the proxy did NOT
//! resolve the credential when the request was structurally
//! rejected; if a future refactor accidentally moved the resolve
//! call ahead of the restriction check, this slice catches it.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use raxis_credential_proxy_http::{
    restriction::Restrictions, AuthMode, HttpProxy, NoopAuditChannel, OwnedConsumer, ProxyConfig,
};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::env_file::EnvMap;

const TEST_BEARER: &str = "raxis-live-e2e-restricted-bearer-NOT-A-SECRET";

struct LiveBackend {
    value: Vec<u8>,
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
        &self,
        name: &CredentialName,
        _v: CredentialValue,
        _a: OperatorId,
    ) -> Result<(), CredentialError> {
        Err(CredentialError::Malformed {
            name: name.clone(),
            reason: "live-e2e backend does not rotate".to_owned(),
        })
    }
    fn exists(&self, name: &CredentialName) -> bool {
        name.as_str() == "live-e2e"
    }
    fn backend_kind(&self) -> &'static str {
        "live-e2e"
    }
}

pub(crate) async fn run(_env: &EnvMap) -> Result<()> {
    tracing::info!("slice http-proxy-restrictions: starting");
    let backend = Arc::new(LiveBackend {
        value: TEST_BEARER.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        upstream_url: "https://httpbin.org/".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        auth_mode: AuthMode::Bearer,
        consumer: OwnedConsumer::new("credential_proxy", "live-e2e:http:r"),
        restrictions: Restrictions {
            allowed_methods: vec!["GET".to_owned()],
            allowed_path_prefixes: vec!["/anything".to_owned()],
        },
    };
    let proxy = HttpProxy::bind(backend.clone(), cfg, Arc::new(NoopAuditChannel))
        .await
        .map_err(|e| anyhow!("HttpProxy::bind: {e}"))?;
    let addr = proxy.local_addr()?;
    tokio::spawn(proxy.serve());

    // ── Sub-test A: allowed shape (GET /anything/widget) ────────────────
    let resolves_before_a = backend.resolves.load(Ordering::Relaxed);
    let (status_a, body_a) = http_round_trip(
        addr,
        b"GET /anything/widget HTTP/1.1\r\n\
          Host: agent-injected\r\n\
          User-Agent: raxis-live-e2e/1.0\r\n\
          Accept: application/json\r\n\
          Connection: close\r\n\
          \r\n",
    )
    .await?;
    if !status_a.starts_with("HTTP/1.1 200") {
        return Err(anyhow!(
            "sub-test A: expected 200 from httpbin via proxy; got {status_a:?}"
        ));
    }
    let json: serde_json::Value = serde_json::from_slice(&body_a)
        .map_err(|e| anyhow!("sub-test A: body is not JSON: {e}"))?;
    let auth = json
        .get("headers")
        .and_then(|h| h.as_object())
        .and_then(|h| h.get("Authorization"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("sub-test A: upstream did not see Authorization"))?;
    if auth != format!("Bearer {TEST_BEARER}") {
        return Err(anyhow!(
            "sub-test A: Authorization injection wrong: {auth:?}"
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) <= resolves_before_a {
        return Err(anyhow!(
            "sub-test A: backend was not asked for the bearer despite reaching upstream",
        ));
    }
    tracing::info!("sub-test A: allowed GET /anything/widget reached upstream OK");

    // ── Sub-test B: method-denied shape (POST /anything/widget) ─────────
    let resolves_before_b = backend.resolves.load(Ordering::Relaxed);
    let (status_b, body_b) = http_round_trip(
        addr,
        b"POST /anything/widget HTTP/1.1\r\n\
          Host: agent-injected\r\n\
          Content-Type: application/json\r\n\
          Content-Length: 2\r\n\
          Connection: close\r\n\
          \r\n\
          {}",
    )
    .await?;
    if status_b.starts_with("HTTP/1.1 200") {
        return Err(anyhow!(
            "sub-test B: method-denied request reached upstream (got 200); \
             status={status_b:?}, body={:?}",
            String::from_utf8_lossy(&body_b),
        ));
    }
    if !(status_b.starts_with("HTTP/1.1 4")) {
        return Err(anyhow!(
            "sub-test B: expected a 4xx rejection; got {status_b:?}"
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) > resolves_before_b {
        return Err(anyhow!(
            "sub-test B: backend was asked for the bearer despite the request being method-denied",
        ));
    }
    tracing::info!(
        "sub-test B: POST /anything/widget rejected at proxy ({status_b}) — bearer never resolved"
    );

    // ── Sub-test C: path-denied shape (GET /forbidden) ──────────────────
    let resolves_before_c = backend.resolves.load(Ordering::Relaxed);
    let (status_c, _body_c) = http_round_trip(
        addr,
        b"GET /forbidden HTTP/1.1\r\n\
          Host: agent-injected\r\n\
          User-Agent: raxis-live-e2e/1.0\r\n\
          Connection: close\r\n\
          \r\n",
    )
    .await?;
    if status_c.starts_with("HTTP/1.1 200") {
        return Err(anyhow!(
            "sub-test C: path-denied request reached upstream (got 200); status={status_c:?}"
        ));
    }
    if !(status_c.starts_with("HTTP/1.1 4")) {
        return Err(anyhow!(
            "sub-test C: expected a 4xx rejection; got {status_c:?}"
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) > resolves_before_c {
        return Err(anyhow!(
            "sub-test C: backend was asked for the bearer despite the request being path-denied",
        ));
    }
    tracing::info!(
        "sub-test C: GET /forbidden rejected at proxy ({status_c}) — bearer never resolved"
    );

    tracing::info!(
        "slice http-proxy-restrictions: PASS — allow path forwards, deny paths reject pre-upstream and pre-resolve",
    );
    Ok(())
}

/// Send `req` to the proxy on `addr` and read the full response.
/// Returns `(status_line, body_bytes)` where `body_bytes` excludes
/// the headers.
async fn http_round_trip(addr: std::net::SocketAddr, req: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut s = tokio::net::TcpStream::connect(addr).await?;
    s.write_all(req).await?;
    let mut buf = Vec::with_capacity(8192);
    s.read_to_end(&mut buf).await?;

    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("no end-of-headers in response"))?;
    let head_str = std::str::from_utf8(&buf[..header_end])
        .unwrap_or("")
        .to_owned();
    let body = buf[header_end + 4..].to_vec();
    let status = head_str.lines().next().unwrap_or("").to_owned();
    Ok((status, body))
}
