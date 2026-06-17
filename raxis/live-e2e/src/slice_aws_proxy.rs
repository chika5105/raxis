//! Slice — real `AwsProxy` against a real raw HTTP/1.1 client.
//!
//! There is no in-process upstream because `AwsProxy` does not
//! forward to any upstream — it is the credential issuer itself
//! (the AWS IMDS container-credential-provider shape returns the
//! credential bytes directly to the SDK). The slice's "service
//! under test" is the proxy's HTTP wire conformance:
//!
//!   1. Bind a real `AwsProxy` against an in-memory
//!      `CredentialBackend` we control (returns env-style AWS
//!      key bytes).
//!   2. Open raw `TcpStream`s to the proxy and drive HTTP/1.1
//!      requests:
//!        * `GET /creds` → must return 200 with the canonical
//!          JSON envelope (`AccessKeyId`, `SecretAccessKey`,
//!          `Expiration`, `RoleArn`).
//!        * `GET /latest/meta-data/iam/security-credentials/foo`
//!          → must return 403 (path allowlist denial).
//!        * `GET /creds?refresh=1` → querystring is stripped
//!          before allowlist match, so still 200.
//!   3. Verify counters: `credentials_served ≥ 1`,
//!      `requests_blocked ≥ 1`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    OperatorId,
};
use serde_json::Value as JsonValue;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use raxis_credential_proxy_aws::{
    AwsProxy, NoopAuditChannel, OwnedConsumer, ProxyConfig, Restrictions,
};

const ENV_BODY: &str = "\
AWS_ACCESS_KEY_ID=AKIA-LIVE-E2E\n\
AWS_SECRET_ACCESS_KEY=secret-live-e2e\n\
AWS_SESSION_TOKEN=tok-live-e2e\n";

struct LiveBackend {
    body: Vec<u8>,
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

pub async fn run() -> Result<()> {
    tracing::info!("aws-proxy slice starting");

    let backend = Arc::new(LiveBackend {
        body: ENV_BODY.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer: OwnedConsumer::new("live-e2e-aws-slice", "session-1"),
        lease_seconds: 900,
        role_arn: Some("arn:aws:iam::123456789:role/raxis-live-e2e".to_owned()),
        forwarding: None,
        restrictions: Restrictions::default(),
    };
    let proxy = AwsProxy::bind(
        Arc::clone(&backend) as Arc<dyn CredentialBackend>,
        cfg,
        Arc::new(NoopAuditChannel),
    )
    .await
    .context("bind AwsProxy")?;
    let addr = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(async move {
        proxy.serve().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1) GET /creds — canonical happy path.
    let resp = http_get(addr, "/creds", &[]).await?;
    if !resp.starts_with("HTTP/1.1 200") {
        return Err(anyhow!("expected 200 OK on /creds, got: {resp:.200?}"));
    }
    let body = body_of(&resp).ok_or_else(|| anyhow!("no body on 200 response"))?;
    let parsed: JsonValue =
        serde_json::from_str(body).with_context(|| format!("parse JSON body: {body:.200}"))?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| anyhow!("body is not a JSON object"))?;
    if obj.get("AccessKeyId").and_then(|v| v.as_str()) != Some("AKIA-LIVE-E2E") {
        return Err(anyhow!("AccessKeyId mismatch in body: {body}"));
    }
    if obj.get("SecretAccessKey").and_then(|v| v.as_str()) != Some("secret-live-e2e") {
        return Err(anyhow!("SecretAccessKey mismatch in body: {body}"));
    }
    if obj.get("Token").and_then(|v| v.as_str()) != Some("tok-live-e2e") {
        return Err(anyhow!("Token mismatch in body: {body}"));
    }
    let expiration = obj
        .get("Expiration")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing Expiration in body: {body}"))?;
    if !expiration.ends_with('Z') || expiration.len() < 20 {
        return Err(anyhow!("Expiration not in ISO-8601 Z form: {expiration}"));
    }
    if obj.get("RoleArn").and_then(|v| v.as_str())
        != Some("arn:aws:iam::123456789:role/raxis-live-e2e")
    {
        return Err(anyhow!("RoleArn mismatch in body: {body}"));
    }

    // 2) Path outside allowlist — must 403.
    let resp = http_get(addr, "/latest/meta-data/iam/security-credentials/foo", &[]).await?;
    if !resp.starts_with("HTTP/1.1 403") {
        return Err(anyhow!(
            "expected 403 Forbidden for non-allowlisted path, got: {resp:.200?}"
        ));
    }

    // 3) Querystring must be stripped before allowlist match.
    let resp = http_get(addr, "/creds?refresh=1", &[]).await?;
    if !resp.starts_with("HTTP/1.1 200") {
        return Err(anyhow!(
            "expected 200 with stripped querystring on /creds?refresh=1, got: {resp:.200?}"
        ));
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let snap = stats.snapshot();
    if snap.credentials_served < 2 {
        return Err(anyhow!(
            "credentials_served must be ≥ 2 (two /creds), got {}",
            snap.credentials_served,
        ));
    }
    if snap.requests_blocked < 1 {
        return Err(anyhow!(
            "requests_blocked must be ≥ 1 (one /latest/...), got {}",
            snap.requests_blocked,
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) == 0 {
        return Err(anyhow!("CredentialBackend was never asked to resolve"));
    }

    tracing::info!("aws-proxy slice OK");
    Ok(())
}

async fn http_get(
    addr: std::net::SocketAddr,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<String> {
    let mut s = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect to AwsProxy listener at {addr}"))?;
    let mut req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
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
    tokio::time::timeout(timeout, s.read_to_end(&mut buf))
        .await
        .map_err(|_| anyhow!("read timed out after {timeout:?}"))??;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn body_of(resp: &str) -> Option<&str> {
    resp.split_once("\r\n\r\n").map(|(_, b)| b)
}
