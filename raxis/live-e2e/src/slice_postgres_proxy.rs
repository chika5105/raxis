//! Slice 2 — real `PostgresProxy` + a real Postgres-protocol client.
//!
//! Goal: prove the proxy's frontend-protocol surface (startup,
//! authentication, parameter status, simple-query path) handshakes
//! cleanly with a real Postgres client AND that the V2.1
//! real-upstream-forwarding path is wired end-to-end.
//!
//! ## Two modes
//!
//! 1. **Hermetic (default)** — no real Postgres required. The slice
//!    asserts the proxy reaches `ReadyForQuery`, then drives a
//!    `SELECT` that the proxy attempts to forward upstream. Because
//!    the configured upstream URL points at an unreachable address
//!    (`127.0.0.1:1` — IANA-reserved), the proxy emits an
//!    `ErrorResponse` with `08006 (upstream unreachable)` and stays
//!    alive for `ReadyForQuery`. This proves the upstream-forwarding
//!    path is wired without requiring an external service.
//!
//! 2. **Real upstream (`RAXIS_LIVE_POSTGRES_URL=postgresql://...`)** —
//!    when the env var is present, the slice points the proxy at the
//!    real Postgres URL. The `SELECT 1` round-trips real `RowDescription`
//!    + `DataRow` + `CommandComplete` frames and the slice asserts
//!    the wire shape. Use this with a docker-compose Postgres or a
//!    locally-running pg server to validate the full relay path.
//!
//! Either mode exercises the proxy's restriction enforcement
//! (default `Restrictions::default()` — unrestricted), credential
//! resolution (the backend MUST be hit at least once), and audit
//! emission. The hermetic mode covers what
//! `cargo run -p raxis-live-e2e -- all` runs in CI.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{anyhow, Result};
use raxis_credential_proxy_postgres::{
    NoopAuditChannel, OwnedConsumer, PostgresProxy, ProxyConfig, restriction::Restrictions,
};
use raxis_credentials::{
    CredentialBackend, CredentialError, CredentialName, CredentialValue,
    ConsumerIdentity, Lease, OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
        &self, name: &CredentialName, _new_value: CredentialValue, _actor: OperatorId,
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

pub(crate) async fn run() -> Result<()> {
    let real_upstream = std::env::var("RAXIS_LIVE_POSTGRES_URL").ok();
    let upstream_url: Vec<u8> = match real_upstream.as_deref() {
        Some(url) if !url.is_empty() => {
            tracing::info!(
                "slice postgres-proxy: starting (real upstream from RAXIS_LIVE_POSTGRES_URL)"
            );
            url.as_bytes().to_vec()
        }
        _ => {
            tracing::info!(
                "slice postgres-proxy: starting (hermetic — unreachable upstream\n\
                 set RAXIS_LIVE_POSTGRES_URL=postgresql://user:pass@host:port/db to test\n\
                 the full relay path against a real Postgres server)"
            );
            // 127.0.0.1:1 is IANA-reserved (TCPMUX) and effectively
            // never bound on a developer machine — perfect for a
            // hermetic "upstream unreachable" assertion.
            b"postgresql://demo:demo@127.0.0.1:1/demo".to_vec()
        }
    };
    let hermetic = real_upstream.as_deref().is_none_or(str::is_empty);

    let backend = Arc::new(LiveBackend {
        value:    upstream_url,
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer:        OwnedConsumer::new("credential_proxy", "live-e2e:postgres:0"),
        restrictions:    Restrictions::default(),
    };
    let proxy = PostgresProxy::bind(backend.clone(), cfg, Arc::new(NoopAuditChannel)).await
        .map_err(|e| anyhow!("PostgresProxy::bind: {e}"))?;
    let addr = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(proxy.serve());

    let mut s = TcpStream::connect(addr).await?;

    write_startup(&mut s).await?;
    let msgs = drain_until_ready(&mut s).await?;
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    if !tags.contains(&b'R') { return Err(anyhow!("no AuthenticationOk; tags={tags:?}")); }
    if !tags.contains(&b'S') { return Err(anyhow!("no ParameterStatus; tags={tags:?}")); }
    if !tags.contains(&b'K') { return Err(anyhow!("no BackendKeyData; tags={tags:?}")); }
    if tags.last() != Some(&b'Z') { return Err(anyhow!("last frame must be 'Z'; tags={tags:?}")); }
    tracing::info!("slice postgres-proxy: handshake reached ReadyForQuery");

    // SELECT 1 — exercises the upstream-forwarding path.
    write_query(&mut s, "SELECT 1").await?;
    let msgs = drain_until_ready(&mut s).await?;
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    if hermetic {
        // Expect ErrorResponse ('E') + ReadyForQuery ('Z') because
        // the upstream is unreachable. The proxy must NOT crash and
        // MUST emit the audit envelope. We assert the envelope by
        // checking the upstream-failed counter below.
        if !tags.contains(&b'E') {
            return Err(anyhow!(
                "hermetic mode: expected ErrorResponse for unreachable upstream, got tags={tags:?}"
            ));
        }
        if tags.last() != Some(&b'Z') {
            return Err(anyhow!(
                "hermetic mode: expected ReadyForQuery after upstream failure, got tags={tags:?}"
            ));
        }
        tracing::info!(
            "slice postgres-proxy: hermetic SELECT got ErrorResponse + ReadyForQuery (expected)"
        );
    } else {
        // Real upstream: expect at least CommandComplete ('C').
        // RowDescription ('T') + DataRow ('D') are also present for
        // a SELECT but we don't strictly require them here so a
        // backend without a `t` table still passes when the SELECT
        // is `SELECT 1` (which any pg server can answer).
        if !tags.contains(&b'C') {
            return Err(anyhow!("no CommandComplete for SELECT; tags={tags:?}"));
        }
        if !tags.contains(&b'D') && !tags.contains(&b'T') {
            tracing::warn!(
                "slice postgres-proxy: SELECT returned neither RowDescription ('T') nor DataRow ('D'); \
                 unusual but not fatal (server may have answered with empty result-set)"
            );
        }
    }

    // Terminate.
    write_terminate(&mut s).await?;

    let snap = stats.snapshot();
    if snap.queries_audited < 1 {
        return Err(anyhow!(
            "expected ≥1 query audited, got {}", snap.queries_audited
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) < 1 {
        return Err(anyhow!("backend was never asked for the credential"));
    }
    if hermetic {
        // The upstream-failed counter must increment in hermetic
        // mode — it's the V2.1 audit envelope's hard signal that
        // the upstream-forwarding path is wired.
        if snap.upstream_connects_failed < 1 {
            return Err(anyhow!(
                "hermetic mode: expected upstream_connects_failed≥1, got {}",
                snap.upstream_connects_failed,
            ));
        }
    } else {
        // Real-upstream mode: at least one connect must succeed.
        if snap.upstream_connects_succeeded < 1 {
            return Err(anyhow!(
                "real-upstream mode: expected upstream_connects_succeeded≥1, got {}",
                snap.upstream_connects_succeeded,
            ));
        }
    }
    tracing::info!(
        mode               = if hermetic { "hermetic" } else { "real-upstream" },
        queries_audited    = snap.queries_audited,
        queries_blocked    = snap.queries_blocked,
        upstream_succeeded = snap.upstream_connects_succeeded,
        upstream_failed    = snap.upstream_connects_failed,
        backend_resolves   = backend.resolves.load(Ordering::Relaxed),
        "slice postgres-proxy: PASS",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Frontend protocol helpers (subset of the postgres-proxy integration tests)
// ---------------------------------------------------------------------------

async fn write_startup(s: &mut TcpStream) -> Result<()> {
    let mut body = Vec::new();
    body.extend_from_slice(&196608i32.to_be_bytes());
    body.extend_from_slice(b"user\0raxis\0\0");
    let len = (body.len() as i32) + 4;
    s.write_all(&len.to_be_bytes()).await?;
    s.write_all(&body).await?;
    Ok(())
}

async fn read_tagged_message(s: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut tag = [0u8; 1];
    s.read_exact(&mut tag).await?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let len = i32::from_be_bytes(len);
    let body_len = (len as usize)
        .checked_sub(4)
        .ok_or_else(|| anyhow!("frame length {len} < 4"))?;
    let mut body = vec![0u8; body_len];
    s.read_exact(&mut body).await?;
    Ok((tag[0], body))
}

async fn drain_until_ready(s: &mut TcpStream) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut acc = Vec::new();
    loop {
        let (t, b) = read_tagged_message(s).await?;
        let is_z = t == b'Z';
        acc.push((t, b));
        if is_z { return Ok(acc); }
    }
}

async fn write_query(s: &mut TcpStream, sql: &str) -> Result<()> {
    s.write_all(b"Q").await?;
    let mut body = Vec::new();
    body.extend_from_slice(sql.as_bytes());
    body.push(0);
    let len = (body.len() as i32) + 4;
    s.write_all(&len.to_be_bytes()).await?;
    s.write_all(&body).await?;
    Ok(())
}

async fn write_terminate(s: &mut TcpStream) -> Result<()> {
    s.write_all(b"X").await?;
    let len = 4i32;
    s.write_all(&len.to_be_bytes()).await?;
    Ok(())
}
