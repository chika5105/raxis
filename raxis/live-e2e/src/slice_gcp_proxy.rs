//! Slice — real `GcpProxy` against a real raw HTTP/1.1 client.
//!
//! Shape:
//!
//!   1. Bind a real `GcpProxy` against an in-memory
//!      `CredentialBackend` we control (returns env-style GCP
//!      access-token bytes).
//!   2. Open raw `TcpStream`s to the proxy and drive HTTP/1.1
//!      requests:
//!        * `GET /computeMetadata/v1/instance/service-accounts/default/token`
//!          with `Metadata-Flavor: Google` → 200 JSON with
//!          `access_token` + `expires_in` + `token_type=Bearer`.
//!        * Same path **without** the `Metadata-Flavor` header → 403.
//!        * `GET /computeMetadata/v1/project/project-id` with the
//!          header → 200 plain-text `my-live-e2e-proj`.
//!        * `GET /computeMetadata/v1/instance/network-interfaces`
//!          with the header → 404 (not in allowlist).
//!   3. Verify counters match.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    Lease, OperatorId,
};
use serde_json::Value as JsonValue;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use raxis_credential_proxy_gcp::{
    GcpProxy, NoopAuditChannel, OwnedConsumer, ProxyConfig, Restrictions,
};

const ENV_BODY: &str = "\
GCP_ACCESS_TOKEN=ya29.live-e2e-token\n\
GCP_SERVICE_ACCOUNT_EMAIL=svc@my-live-e2e-proj.iam.gserviceaccount.com\n";

struct LiveBackend {
    body:     Vec<u8>,
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
        Ok(CredentialValue::from_bytes(self.body.clone()))
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
    fn lease(&self, _: &CredentialName) -> Lease { Lease::Forever }
    fn backend_kind(&self) -> &'static str { "live-e2e" }
}

pub async fn run() -> Result<()> {
    tracing::info!("gcp-proxy slice starting");

    let backend = Arc::new(LiveBackend {
        body:     ENV_BODY.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:        "127.0.0.1:0".to_owned(),
        credential_name:    CredentialName::new("live-e2e"),
        consumer:           OwnedConsumer::new("live-e2e-gcp-slice", "session-1"),
        lease_seconds:      3600,
        project_id:         "my-live-e2e-proj".to_owned(),
        numeric_project_id: Some(123456789),
        restrictions:       Restrictions::default(),
    };
    let proxy = GcpProxy::bind(
        Arc::clone(&backend) as Arc<dyn CredentialBackend>,
        cfg,
        Arc::new(NoopAuditChannel::default()),
    ).await.context("bind GcpProxy")?;
    let addr  = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(async move { proxy.serve().await; });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1) Token endpoint — happy path.
    let resp = http_get(
        addr,
        "/computeMetadata/v1/instance/service-accounts/default/token",
        &[("Metadata-Flavor", "Google")],
    ).await?;
    if !resp.starts_with("HTTP/1.1 200") {
        return Err(anyhow!("expected 200 OK on /token, got: {resp:.200?}"));
    }
    let body = body_of(&resp).ok_or_else(|| anyhow!("no body"))?;
    let parsed: JsonValue = serde_json::from_str(body)
        .with_context(|| format!("parse JSON body: {body:.200}"))?;
    if parsed.get("access_token").and_then(|v| v.as_str()) != Some("ya29.live-e2e-token") {
        return Err(anyhow!("access_token mismatch in body: {body}"));
    }
    if parsed.get("token_type").and_then(|v| v.as_str()) != Some("Bearer") {
        return Err(anyhow!("token_type mismatch in body: {body}"));
    }
    if parsed.get("expires_in").and_then(|v| v.as_u64()) != Some(3600) {
        return Err(anyhow!("expires_in mismatch in body: {body}"));
    }

    // 2) Token endpoint without Metadata-Flavor — must 403.
    let resp = http_get(
        addr,
        "/computeMetadata/v1/instance/service-accounts/default/token",
        &[],
    ).await?;
    if !resp.starts_with("HTTP/1.1 403") {
        return Err(anyhow!(
            "expected 403 without Metadata-Flavor: Google, got: {resp:.200?}"
        ));
    }

    // 3) project-id endpoint — happy path.
    let resp = http_get(
        addr,
        "/computeMetadata/v1/project/project-id",
        &[("Metadata-Flavor", "Google")],
    ).await?;
    if !resp.starts_with("HTTP/1.1 200") {
        return Err(anyhow!("expected 200 on /project/project-id, got: {resp:.200?}"));
    }
    let body = body_of(&resp).ok_or_else(|| anyhow!("no body"))?;
    if body.trim() != "my-live-e2e-proj" {
        return Err(anyhow!("project-id body mismatch: {body:?}"));
    }

    // 4) Path outside allowlist — must 404.
    let resp = http_get(
        addr,
        "/computeMetadata/v1/instance/network-interfaces",
        &[("Metadata-Flavor", "Google")],
    ).await?;
    if !resp.starts_with("HTTP/1.1 404") {
        return Err(anyhow!(
            "expected 404 for non-allowlisted path, got: {resp:.200?}"
        ));
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let snap = stats.snapshot();
    if snap.credentials_served < 2 {
        return Err(anyhow!(
            "credentials_served must be ≥ 2 (token + project-id), got {}",
            snap.credentials_served,
        ));
    }
    if snap.requests_blocked < 2 {
        return Err(anyhow!(
            "requests_blocked must be ≥ 2 (no-header + bad-path), got {}",
            snap.requests_blocked,
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) == 0 {
        return Err(anyhow!("CredentialBackend was never asked to resolve"));
    }

    tracing::info!("gcp-proxy slice OK");
    Ok(())
}

async fn http_get(
    addr: std::net::SocketAddr,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<String> {
    let mut s = TcpStream::connect(addr).await
        .with_context(|| format!("connect to GcpProxy listener at {addr}"))?;
    let mut req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: metadata.google.internal\r\n\
         User-Agent: raxis-live-e2e\r\n\
         Connection: close\r\n",
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(4096);
    let timeout = Duration::from_secs(5);
    tokio::time::timeout(timeout, s.read_to_end(&mut buf)).await
        .map_err(|_| anyhow!("read timed out after {timeout:?}"))??;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn body_of(resp: &str) -> Option<&str> {
    resp.split_once("\r\n\r\n").map(|(_, b)| b)
}
