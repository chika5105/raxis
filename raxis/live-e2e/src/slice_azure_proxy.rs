//! Slice — real `AzureProxy` against a real raw HTTP/1.1 client.
//!
//! Shape:
//!
//!   1. Bind a real `AzureProxy` against an in-memory
//!      `CredentialBackend` we control (returns env-style Azure
//!      access-token bytes).
//!   2. Open raw `TcpStream`s to the proxy and drive HTTP/1.1
//!      requests:
//!        * `GET /metadata/identity/oauth2/token?api-version=2018-02-01&resource=...`
//!          for an allowed resource with `Metadata: true` → 200 JSON
//!          with stringified numeric fields.
//!        * Same path **without** the `Metadata` header → 400.
//!        * Allowed path with a resource **not** in the allowlist →
//!          400 with the IMDS error envelope.
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

use raxis_credential_proxy_azure::{
    AzureProxy, NoopAuditChannel, OwnedConsumer, ProxyConfig, Restrictions,
};

const ENV_BODY: &str = "AZURE_ACCESS_TOKEN=eyJ0eXAi.live-e2e-token\n";

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
    tracing::info!("azure-proxy slice starting");

    let backend = Arc::new(LiveBackend {
        body:     ENV_BODY.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer:        OwnedConsumer::new("live-e2e-azure-slice", "session-1"),
        lease_seconds:   3600,
        tenant_id:       "live-e2e-tenant".to_owned(),
        client_id:       Some("live-e2e-client".to_owned()),
        restrictions: Restrictions {
            allowed_resources: vec!["https://management.azure.com/".to_owned()],
            allowed_actions:   Vec::new(),
        },
    };
    let proxy = AzureProxy::bind(
        Arc::clone(&backend) as Arc<dyn CredentialBackend>,
        cfg,
        Arc::new(NoopAuditChannel::default()),
    ).await.context("bind AzureProxy")?;
    let addr  = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(async move { proxy.serve().await; });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1) Allowed resource with Metadata: true — happy path.
    let resp = http_get(
        addr,
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F",
        &[("Metadata", "true")],
    ).await?;
    if !resp.starts_with("HTTP/1.1 200") {
        return Err(anyhow!("expected 200 OK on token endpoint, got: {resp:.300?}"));
    }
    let body = body_of(&resp).ok_or_else(|| anyhow!("no body"))?;
    let parsed: JsonValue = serde_json::from_str(body)
        .with_context(|| format!("parse JSON body: {body:.300}"))?;
    let obj = parsed.as_object().ok_or_else(|| anyhow!("body is not a JSON object"))?;
    if obj.get("access_token").and_then(|v| v.as_str())
        != Some("eyJ0eXAi.live-e2e-token")
    {
        return Err(anyhow!("access_token mismatch in body: {body}"));
    }
    if obj.get("token_type").and_then(|v| v.as_str()) != Some("Bearer") {
        return Err(anyhow!("token_type mismatch: {body}"));
    }
    if obj.get("client_id").and_then(|v| v.as_str()) != Some("live-e2e-client") {
        return Err(anyhow!("client_id mismatch: {body}"));
    }
    // Numeric fields must be stringified — match real IMDS wire shape.
    if obj.get("expires_in").and_then(|v| v.as_str()) != Some("3600") {
        return Err(anyhow!("expires_in must be stringified \"3600\": {body}"));
    }
    if obj.get("resource").and_then(|v| v.as_str())
        != Some("https://management.azure.com/")
    {
        return Err(anyhow!("resource mismatch: {body}"));
    }

    // 2) Allowed resource WITHOUT Metadata: true — must 400.
    let resp = http_get(
        addr,
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F",
        &[],
    ).await?;
    if !resp.starts_with("HTTP/1.1 400") {
        return Err(anyhow!(
            "expected 400 without `Metadata: true` header, got: {resp:.300?}"
        ));
    }

    // 3) Disallowed resource (not in allowlist) — must 400.
    let resp = http_get(
        addr,
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fdatabase.windows.net%2F",
        &[("Metadata", "true")],
    ).await?;
    if !resp.starts_with("HTTP/1.1 400") {
        return Err(anyhow!(
            "expected 400 for resource not in allowed_resources, got: {resp:.300?}"
        ));
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let snap = stats.snapshot();
    if snap.tokens_served < 1 {
        return Err(anyhow!(
            "tokens_served must be ≥ 1, got {}", snap.tokens_served,
        ));
    }
    if snap.requests_blocked < 2 {
        return Err(anyhow!(
            "requests_blocked must be ≥ 2 (no-header + bad-resource), got {}",
            snap.requests_blocked,
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) == 0 {
        return Err(anyhow!("CredentialBackend was never asked to resolve"));
    }

    tracing::info!("azure-proxy slice OK");
    Ok(())
}

async fn http_get(
    addr: std::net::SocketAddr,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<String> {
    let mut s = TcpStream::connect(addr).await
        .with_context(|| format!("connect to AzureProxy listener at {addr}"))?;
    let mut req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: 169.254.169.254\r\n\
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
