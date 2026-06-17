//! Slice — real `RedisProxy` against a real `redis-server` container.
//!
//! ## Why a real container, not an in-process RESP fixture
//!
//! An earlier revision of this slice used a tokio `TcpListener` that
//! re-implemented the RESP wire (AUTH/PING/SET/GET/QUIT) and asserted
//! on what the listener observed. That fixture passed even when the
//! proxy made decisions that a real Redis would reject — RESP3
//! `HELLO` downgrade quirks, `requirepass`-mismatch error shape,
//! actual TTL semantics, and the `-NOAUTH` reply prefix all differ
//! between hand-rolled fixtures and an upstream `redis-server`. Real
//! services catch real bugs (TTL semantics, command-table changes
//! across minor versions, AUTH error wording) that a fixture papers
//! over by construction.
//!
//! The slice now runs against the `redis:7-alpine` container declared
//! in `live-e2e/docker-compose.e2e.yml` (and its
//! `docker-compose.extended.e2e.yml` superset). The container is
//! pinned to `7-alpine` so a Redis 8.x major-bump cannot silently
//! flip behaviour — bumping the tag is a deliberate, reviewable
//! action.
//!
//! ## Lifecycle
//!
//! 1. Preflight — TCP-probe the loopback host:port the compose file
//!    publishes (`127.0.0.1:63799`). On failure the slice prints the
//!    exact `docker compose up` invocation and bails with an
//!    actionable error so an operator running `cargo run -p
//!    raxis-live-e2e -- redis-proxy` against a missing container
//!    does not see a confusing handshake error.
//! 2. Bind the real `RedisProxy` against an in-memory
//!    `CredentialBackend` whose value IS the upstream's
//!    `requirepass`. The proxy's `upstream_host_port` points at the
//!    container.
//! 3. Drive a real RESP2 conversation through the proxy with a junk
//!    agent `AUTH`, then `PING / SET / GET` (allow path) and
//!    `FLUSHDB` (deny path).
//! 4. Verify against the **real upstream**:
//!    The proxy was able to authenticate to upstream — a wrong
//!    `requirepass` would surface as `-NOAUTH` and the slice
//!    would fail at the first forwarded `PING`. The fact that
//!    `PING / SET / GET` round-trip proves the proxy stripped
//!    the agent's junk AUTH and injected the real credential.
//!    `GET deploy:latest` returns the bytes `SET` wrote — the
//!    value lives in real Redis memory, not a fixture's match
//!    arm. `FLUSHDB` is rejected by the proxy with `-ERR
//!    command FLUSHDB not allowed by RAXIS policy`; the slice
//!    then opens an out-of-band connection straight to the
//!    container and verifies the key is still there — proving
//!    FLUSHDB never reached upstream. The proxy's
//!    `commands_forwarded` counter ≥ 3 (PING + SET + GET) and
//!    `commands_blocked` ≥ 1 (FLUSHDB), and
//!    `CredentialBackend::resolve` was called at least once per
//!    connection (rotation semantics).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use raxis_credential_proxy_redis::{
    NoopAuditChannel, OwnedConsumer, ProxyConfig, RedisProxy, Restrictions,
};

/// Loopback host:port the docker-compose Redis publishes. Pinned
/// to match `live-e2e/docker-compose.e2e.yml`.
const REDIS_HOST_PORT: &str = "127.0.0.1:63799";

/// Real `requirepass` baked into the compose file. The slice
/// resolves this through `CredentialBackend` so the proxy
/// authenticates upstream with the EXACT bytes we configured.
const REDIS_REQUIREPASS: &str = "raxis_test_pass";

/// Distinct key namespace so the slice never collides with another
/// run still in progress against the same long-running container.
fn unique_key() -> String {
    format!("raxis-live-e2e:deploy:{}", uuid_v7())
}

fn uuid_v7() -> String {
    uuid::Uuid::now_v7().to_string()
}

// ---------------------------------------------------------------------------
// Local CredentialBackend: returns the upstream password verbatim.
// ---------------------------------------------------------------------------

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
    fn backend_kind(&self) -> &'static str {
        "live-e2e"
    }
}

// ---------------------------------------------------------------------------
// Slice driver
// ---------------------------------------------------------------------------

pub async fn run() -> Result<()> {
    tracing::info!(host_port = REDIS_HOST_PORT, "redis-proxy slice starting");

    // Step 1 — preflight: the container must be reachable.
    require_redis_container().await?;

    // Step 2 — bind the real RedisProxy.
    let backend = Arc::new(LiveBackend {
        value: REDIS_REQUIREPASS.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        upstream_host_port: REDIS_HOST_PORT.to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer: OwnedConsumer::new("live-e2e-redis-slice", "session-1"),
        restrictions: Restrictions {
            allowed_commands: vec![
                "PING".into(),
                "SET".into(),
                "GET".into(),
                "DEL".into(),
                "EXISTS".into(),
            ],
        },
        upstream_tls: false,
    };
    let proxy = RedisProxy::bind(
        Arc::clone(&backend) as Arc<dyn CredentialBackend>,
        cfg,
        Arc::new(NoopAuditChannel),
    )
    .await
    .context("bind RedisProxy")?;
    let proxy_addr = proxy.local_addr()?;
    let stats_handle = proxy.stats_handle();
    tokio::spawn(async move {
        proxy.serve().await;
    });

    // Give the proxy a tick to be ready.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let key = unique_key();
    let value = "v1.2.3-real-redis";

    // Step 3 — drive a real RESP conversation through the proxy.
    let mut client = TcpStream::connect(proxy_addr)
        .await
        .context("connect to RedisProxy listener")?;

    // Junk AUTH (must be discarded by the proxy and replied +OK by
    // the proxy itself; never forwarded).
    client
        .write_all(b"*2\r\n$4\r\nAUTH\r\n$25\r\nagent-supplied-junk-bytes\r\n")
        .await?;
    expect_simple_string(&mut client, "+OK\r\n")
        .await
        .context("proxy must reply +OK to agent AUTH (discarded)")?;

    // PING — allowed, forwarded. Real Redis answers +PONG.
    client.write_all(b"*1\r\n$4\r\nPING\r\n").await?;
    expect_simple_string(&mut client, "+PONG\r\n")
        .await
        .context("PING must round-trip to real Redis and return +PONG")?;

    // SET — allowed, forwarded. Real Redis stores the key.
    let set_frame = build_set_frame(&key, value);
    client.write_all(&set_frame).await?;
    expect_simple_string(&mut client, "+OK\r\n")
        .await
        .context("SET must be forwarded to real Redis and return +OK")?;

    // GET — allowed, forwarded. Real Redis returns the value we
    // just SET — proving the SET landed in real memory.
    let get_frame = build_get_frame(&key);
    client.write_all(&get_frame).await?;
    expect_bulk_string(&mut client, value.as_bytes())
        .await
        .context("GET must round-trip from real Redis with the value SET wrote")?;

    // FLUSHDB — denied by allowlist; must never reach upstream.
    client.write_all(b"*1\r\n$7\r\nFLUSHDB\r\n").await?;
    let denied = read_simple_response(&mut client).await?;
    if !starts_with(&denied, b"-ERR command FLUSHDB not allowed by RAXIS policy") {
        return Err(anyhow!(
            "FLUSHDB must be denied with `-ERR command FLUSHDB not allowed by RAXIS policy`, \
             observed: {:?}",
            String::from_utf8_lossy(&denied),
        ));
    }

    // Cleanly close the proxy session.
    client.write_all(b"*1\r\n$4\r\nQUIT\r\n").await?;
    let _ = tokio::time::timeout(Duration::from_millis(200), async {
        let mut buf = [0u8; 64];
        let _ = client.read(&mut buf).await;
    })
    .await;

    // Step 4 — assertions against the real upstream.
    //
    // 4a. The key SET wrote MUST still be present in upstream Redis
    // (FLUSHDB was denied at the proxy boundary; the database must
    // be intact). We open an out-of-band TCP connection straight to
    // the container and authenticate with the real credential.
    let upstream_value = direct_get(REDIS_HOST_PORT, REDIS_REQUIREPASS, &key)
        .await
        .context("direct upstream GET to verify FLUSHDB never landed")?;
    if upstream_value.as_deref() != Some(value.as_bytes()) {
        return Err(anyhow!(
            "post-conversation upstream GET mismatch — expected {:?}, got {:?}.\n\
             Either SET never reached real Redis (proxy-forwarding regression) or\n\
             FLUSHDB sneaked through (allowlist regression).",
            value,
            upstream_value
                .as_ref()
                .map(|v| String::from_utf8_lossy(v).into_owned()),
        ));
    }

    // 4b. Cleanup: DEL the key so the container's keyspace doesn't
    // accumulate residue across slice invocations against a
    // long-running compose stack. Best-effort — failure here is a
    // warning, not a slice failure (the key is unique per run).
    if let Err(e) = direct_del(REDIS_HOST_PORT, REDIS_REQUIREPASS, &key).await {
        tracing::warn!(error = %e, "best-effort upstream DEL failed (non-fatal)");
    }

    // Give the proxy a tick to flush counters.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let snap = stats_handle.snapshot();
    if snap.commands_forwarded < 3 {
        return Err(anyhow!(
            "commands_forwarded counter must be ≥ 3 (PING+SET+GET), got {}",
            snap.commands_forwarded,
        ));
    }
    if snap.commands_blocked < 1 {
        return Err(anyhow!(
            "commands_blocked counter must be ≥ 1 (FLUSHDB), got {}",
            snap.commands_blocked,
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) == 0 {
        return Err(anyhow!(
            "CredentialBackend::resolve must be called at least once per connection",
        ));
    }

    tracing::info!(
        commands_forwarded = snap.commands_forwarded,
        commands_blocked = snap.commands_blocked,
        bytes_out_to_upstream = snap.bytes_out_to_upstream,
        backend_resolves = backend.resolves.load(Ordering::Relaxed),
        "redis-proxy slice OK (real upstream)",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

async fn require_redis_container() -> Result<()> {
    match tokio::time::timeout(
        Duration::from_millis(800),
        TcpStream::connect(REDIS_HOST_PORT),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!(
            "Redis container not reachable at {REDIS_HOST_PORT} ({e}).\n\
             Run:\n  \
             docker compose -f live-e2e/docker-compose.e2e.yml up -d redis --wait\n\
             (or use docker-compose.extended.e2e.yml for the extended scenario)",
        )),
        Err(_) => Err(anyhow!(
            "Redis container TCP connect to {REDIS_HOST_PORT} timed out after 800 ms.\n\
             Run:\n  \
             docker compose -f live-e2e/docker-compose.e2e.yml up -d redis --wait",
        )),
    }
}

// ---------------------------------------------------------------------------
// Out-of-band direct-to-upstream RESP helpers (used to verify state
// in real Redis after the proxy session ends).
// ---------------------------------------------------------------------------

async fn direct_auth(stream: &mut TcpStream, password: &str) -> Result<()> {
    let frame = build_auth_frame(password);
    stream.write_all(&frame).await?;
    let resp = read_simple_response(stream).await?;
    if !resp.starts_with(b"+OK") {
        return Err(anyhow!(
            "direct upstream AUTH failed — got {:?}",
            String::from_utf8_lossy(&resp),
        ));
    }
    Ok(())
}

async fn direct_get(host_port: &str, password: &str, key: &str) -> Result<Option<Vec<u8>>> {
    let mut s = TcpStream::connect(host_port).await?;
    direct_auth(&mut s, password).await?;
    let frame = build_get_frame(key);
    s.write_all(&frame).await?;
    read_bulk_or_nil(&mut s).await
}

async fn direct_del(host_port: &str, password: &str, key: &str) -> Result<()> {
    let mut s = TcpStream::connect(host_port).await?;
    direct_auth(&mut s, password).await?;
    let mut frame = Vec::with_capacity(32 + key.len());
    frame.extend_from_slice(b"*2\r\n$3\r\nDEL\r\n$");
    frame.extend_from_slice(key.len().to_string().as_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(key.as_bytes());
    frame.extend_from_slice(b"\r\n");
    s.write_all(&frame).await?;
    let _ = read_until_crlf_stream(&mut s).await?; // discard reply
    Ok(())
}

fn build_auth_frame(password: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(32 + password.len());
    frame.extend_from_slice(b"*2\r\n$4\r\nAUTH\r\n$");
    frame.extend_from_slice(password.len().to_string().as_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(password.as_bytes());
    frame.extend_from_slice(b"\r\n");
    frame
}

fn build_get_frame(key: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(32 + key.len());
    frame.extend_from_slice(b"*2\r\n$3\r\nGET\r\n$");
    frame.extend_from_slice(key.len().to_string().as_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(key.as_bytes());
    frame.extend_from_slice(b"\r\n");
    frame
}

fn build_set_frame(key: &str, value: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(64 + key.len() + value.len());
    frame.extend_from_slice(b"*3\r\n$3\r\nSET\r\n$");
    frame.extend_from_slice(key.len().to_string().as_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(key.as_bytes());
    frame.extend_from_slice(b"\r\n$");
    frame.extend_from_slice(value.len().to_string().as_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(value.as_bytes());
    frame.extend_from_slice(b"\r\n");
    frame
}

// ---------------------------------------------------------------------------
// Tiny client-side RESP helpers
// ---------------------------------------------------------------------------

async fn expect_simple_string(client: &mut TcpStream, expected: &str) -> Result<()> {
    let resp = read_simple_response(client).await?;
    if resp != expected.as_bytes() {
        return Err(anyhow!(
            "expected {:?}, got {:?}",
            expected,
            String::from_utf8_lossy(&resp),
        ));
    }
    Ok(())
}

async fn expect_bulk_string(client: &mut TcpStream, expected_body: &[u8]) -> Result<()> {
    let body = read_bulk_or_nil(client)
        .await?
        .ok_or_else(|| anyhow!("expected non-null bulk, got null"))?;
    if body != expected_body {
        return Err(anyhow!(
            "expected bulk body {:?}, got {:?}",
            String::from_utf8_lossy(expected_body),
            String::from_utf8_lossy(&body),
        ));
    }
    Ok(())
}

async fn read_bulk_or_nil(client: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    let header = read_until_crlf_stream(client).await?;
    if !header.starts_with(b"$") {
        return Err(anyhow!(
            "expected bulk-string header, got {:?}",
            String::from_utf8_lossy(&header),
        ));
    }
    let n: i64 = std::str::from_utf8(&header[1..header.len() - 2])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad bulk header"))?;
    if n < 0 {
        return Ok(None);
    }
    let mut body = vec![0u8; (n as usize) + 2];
    client.read_exact(&mut body).await?;
    body.truncate(n as usize);
    Ok(Some(body))
}

async fn read_simple_response(client: &mut TcpStream) -> Result<Vec<u8>> {
    read_until_crlf_stream(client).await
}

async fn read_until_crlf_stream(client: &mut TcpStream) -> Result<Vec<u8>> {
    let mut acc = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = client.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        acc.push(byte[0]);
        if acc.ends_with(b"\r\n") {
            break;
        }
    }
    if !acc.ends_with(b"\r\n") {
        return Err(anyhow!("short read mid-frame"));
    }
    Ok(acc)
}

fn starts_with(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack.len() >= prefix.len() && &haystack[..prefix.len()] == prefix
}
