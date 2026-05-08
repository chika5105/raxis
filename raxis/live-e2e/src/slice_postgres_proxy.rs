//! Slice 2 — real `PostgresProxy` + a real Postgres-protocol client.
//!
//! Goal: prove that the proxy's frontend-protocol surface (startup,
//! authentication, parameter status, simple-query path) handshakes
//! cleanly with a real `tokio-postgres`-style client. Upstream
//! forwarding is deferred per spec; this slice exercises everything
//! the MVP guarantees.
//!
//! Wire shape:
//!
//!   1. Start the real `PostgresProxy::bind` against an in-memory
//!      `CredentialBackend` that returns a postgres URL when asked.
//!   2. Open a raw `TcpStream` and drive the Postgres frontend
//!      protocol (StartupMessage → AuthenticationOk → ... →
//!      ReadyForQuery → simple `SELECT 1` → CommandComplete).
//!   3. Assert the wire shape matches the spec and the proxy stats
//!      counter increments correctly.
//!
//! We use a hand-rolled client (reusing the test harness from the
//! crate's integration tests) rather than `tokio-postgres` so the
//! slice has no DB-driver dependency. The MVP synthesises
//! `CommandComplete` for the simple-query path; a real
//! `tokio-postgres` driver would require RowDescription which is
//! the next slice when upstream forwarding lands.

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
    tracing::info!("slice postgres-proxy: starting");
    let backend = Arc::new(LiveBackend {
        value:    b"postgresql://demo:demo@127.0.0.1:5432/demo".to_vec(),
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

    // Drive a real frontend handshake.
    write_startup(&mut s).await?;
    let msgs = drain_until_ready(&mut s).await?;
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    if !tags.contains(&b'R') { return Err(anyhow!("no AuthenticationOk; tags={tags:?}")); }
    if !tags.contains(&b'S') { return Err(anyhow!("no ParameterStatus; tags={tags:?}")); }
    if !tags.contains(&b'K') { return Err(anyhow!("no BackendKeyData; tags={tags:?}")); }
    if tags.last() != Some(&b'Z') { return Err(anyhow!("last frame must be 'Z'; tags={tags:?}")); }
    tracing::info!("slice postgres-proxy: handshake reached ReadyForQuery");

    // Drive a SELECT.
    write_query(&mut s, "SELECT 1").await?;
    let msgs = drain_until_ready(&mut s).await?;
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    if !tags.contains(&b'C') { return Err(anyhow!("no CommandComplete for SELECT; tags={tags:?}")); }

    // Drive an INSERT under default restrictions (unrestricted, so it
    // should NOT be blocked under default policy).
    write_query(&mut s, "INSERT INTO t VALUES (1)").await?;
    let msgs = drain_until_ready(&mut s).await?;
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    if !tags.contains(&b'C') { return Err(anyhow!("no CommandComplete for unrestricted INSERT; tags={tags:?}")); }

    // Terminate.
    write_terminate(&mut s).await?;

    // Verify counters.
    let snap = stats.snapshot();
    if snap.queries_audited < 2 {
        return Err(anyhow!("expected ≥2 queries audited, got {}", snap.queries_audited));
    }
    if backend.resolves.load(Ordering::Relaxed) < 1 {
        return Err(anyhow!("backend was never asked for the credential"));
    }
    tracing::info!(
        "slice postgres-proxy: PASS — queries_audited={}, queries_blocked={}, backend resolves={}",
        snap.queries_audited, snap.queries_blocked,
        backend.resolves.load(Ordering::Relaxed),
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
