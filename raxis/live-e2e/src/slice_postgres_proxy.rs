//! Slice 2 — real `PostgresProxy` + a real Postgres-protocol client.
//!
//! Goal: prove the proxy's frontend-protocol surface (startup,
//! authentication, parameter status, simple-query path) handshakes
//! cleanly with a real Postgres client AND that the V2.1
//! real-upstream-forwarding path is wired end-to-end.
//!
//! ## Active by default
//!
//! Mirrors the post-fix MySQL / MSSQL slices: the upstream is the
//! `postgres:16-alpine` container published by
//! `live-e2e/docker-compose.e2e.yml` on `127.0.0.1:54399`. The
//! slice TCP-preflights that endpoint and fails fast with an
//! actionable error message if the container is not running. Set
//! `RAXIS_LIVE_POSTGRES_URL=postgresql://user:pass@host:port/db` to
//! point at a different real upstream (non-CI debugging, custom
//! schema, etc.).
//!
//! Exercises the proxy's restriction enforcement (default
//! `Restrictions::default()` — unrestricted), credential
//! resolution (the backend MUST be hit at least once), and audit
//! emission. Real-upstream mode is what
//! `cargo run -p raxis-live-e2e -- all` runs in CI.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use raxis_credential_proxy_postgres::{
    restriction::Restrictions, NoopAuditChannel, OwnedConsumer, PostgresProxy, ProxyConfig,
};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue, Lease,
    OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Loopback host:port the docker-compose Postgres publishes.
/// Pinned to match `live-e2e/docker-compose.e2e.yml`.
const POSTGRES_HOST_PORT: &str = "127.0.0.1:54399";

/// Default upstream URL for the docker-compose Postgres 16 container.
/// Operators can override via `RAXIS_LIVE_POSTGRES_URL`.
const DEFAULT_UPSTREAM_URL: &str =
    "postgresql://raxis_test:raxis_test_pass@127.0.0.1:54399/raxis_e2e";

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
        _new_value: CredentialValue,
        _actor: OperatorId,
    ) -> Result<(), CredentialError> {
        Err(CredentialError::Malformed {
            name: name.clone(),
            reason: "live-e2e backend does not rotate".to_owned(),
        })
    }
    fn exists(&self, name: &CredentialName) -> bool {
        name.as_str() == "live-e2e"
    }
    fn lease(&self, _name: &CredentialName) -> Lease {
        Lease::Forever
    }
    fn backend_kind(&self) -> &'static str {
        "live-e2e"
    }
}

pub(crate) async fn run() -> Result<()> {
    require_postgres_container().await?;
    let env_override = std::env::var("RAXIS_LIVE_POSTGRES_URL").ok();
    let upstream_url: Vec<u8> = match env_override.as_deref() {
        Some(url) if !url.is_empty() => {
            tracing::info!(
                "slice postgres-proxy: starting (real upstream from \
                 RAXIS_LIVE_POSTGRES_URL override)",
            );
            url.as_bytes().to_vec()
        }
        _ => {
            tracing::info!(
                host_port = POSTGRES_HOST_PORT,
                "slice postgres-proxy: starting (real upstream — \
                 docker-compose postgres:16-alpine)",
            );
            DEFAULT_UPSTREAM_URL.as_bytes().to_vec()
        }
    };

    let backend = Arc::new(LiveBackend {
        value: upstream_url,
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer: OwnedConsumer::new("credential_proxy", "live-e2e:postgres:0"),
        restrictions: Restrictions::default(),
    };
    let proxy = PostgresProxy::bind(backend.clone(), cfg, Arc::new(NoopAuditChannel))
        .await
        .map_err(|e| anyhow!("PostgresProxy::bind: {e}"))?;
    let addr = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(proxy.serve());

    let mut s = TcpStream::connect(addr).await?;

    write_startup(&mut s).await?;
    let msgs = drain_until_ready(&mut s).await?;
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    if !tags.contains(&b'R') {
        return Err(anyhow!("no AuthenticationOk; tags={tags:?}"));
    }
    if !tags.contains(&b'S') {
        return Err(anyhow!("no ParameterStatus; tags={tags:?}"));
    }
    if !tags.contains(&b'K') {
        return Err(anyhow!("no BackendKeyData; tags={tags:?}"));
    }
    if tags.last() != Some(&b'Z') {
        return Err(anyhow!("last frame must be 'Z'; tags={tags:?}"));
    }
    tracing::info!("slice postgres-proxy: handshake reached ReadyForQuery");

    // SELECT 1 — exercises the upstream-forwarding path against the
    // real Postgres 16 container. We expect at least
    // `CommandComplete` ('C'); `RowDescription` + `DataRow` are also
    // present but not strictly required (a server quirk that ever
    // emits an empty result-set would still satisfy the assertion).
    write_query(&mut s, "SELECT 1").await?;
    let msgs = drain_until_ready(&mut s).await?;
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    if !tags.contains(&b'C') {
        return Err(anyhow!("no CommandComplete for SELECT; tags={tags:?}"));
    }
    if !tags.contains(&b'D') && !tags.contains(&b'T') {
        tracing::warn!(
            "slice postgres-proxy: SELECT returned neither RowDescription ('T') nor DataRow ('D'); \
             unusual but not fatal (server may have answered with empty result-set)"
        );
    }

    write_terminate(&mut s).await?;

    let snap = stats.snapshot();
    if snap.queries_audited < 1 {
        return Err(anyhow!(
            "expected ≥1 query audited, got {}",
            snap.queries_audited
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) < 1 {
        return Err(anyhow!("backend was never asked for the credential"));
    }
    // Real-upstream mode: at least one connect must succeed.
    if snap.upstream_connects_succeeded < 1 {
        return Err(anyhow!(
            "expected upstream_connects_succeeded≥1, got {}",
            snap.upstream_connects_succeeded,
        ));
    }
    tracing::info!(
        queries_audited = snap.queries_audited,
        queries_blocked = snap.queries_blocked,
        upstream_succeeded = snap.upstream_connects_succeeded,
        upstream_failed = snap.upstream_connects_failed,
        backend_resolves = backend.resolves.load(Ordering::Relaxed),
        "slice postgres-proxy: PASS",
    );
    Ok(())
}

async fn require_postgres_container() -> Result<()> {
    match tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(POSTGRES_HOST_PORT),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!(
            "postgres container not reachable at {POSTGRES_HOST_PORT}: {e}\n\
             hint: docker compose -f live-e2e/docker-compose.e2e.yml up -d postgres --wait",
        )),
        Err(_) => Err(anyhow!(
            "postgres container not reachable at {POSTGRES_HOST_PORT}: timed out after 2s\n\
             hint: docker compose -f live-e2e/docker-compose.e2e.yml up -d postgres --wait",
        )),
    }
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
        if is_z {
            return Ok(acc);
        }
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
