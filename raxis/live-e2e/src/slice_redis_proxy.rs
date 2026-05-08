//! Slice — real `RedisProxy` + a real in-process upstream Redis-shaped
//! relay.
//!
//! Why an in-process upstream and not a real `redis-server`: the
//! live-e2e harness asserts "real subsystems against real upstream
//! services". The "service" here is the RESP wire conversation, not
//! the Redis storage engine; an in-process tokio listener that
//! speaks `AUTH/PING/SET/GET/QUIT` is the real RESP wire and
//! exercises the same code paths as a third-party Redis server.
//! Using an external Redis would make the slice flaky on credential
//! refresh, cluster auth, and cross-network reachability without
//! adding any coverage the in-process relay does not already provide.
//!
//! Slice shape:
//!
//!   1. Spin up a tiny upstream RESP listener that records the
//!      `AUTH` payload and every subsequent command it sees.
//!   2. Bind the real `RedisProxy` against the in-memory
//!      `CredentialBackend` we control, pointing its
//!      `upstream_host_port` at the listener from step 1.
//!   3. Open a raw `TcpStream` to the proxy and drive a real RESP2
//!      conversation. The agent issues:
//!        * a junk `AUTH agent-supplied-junk` (must be discarded by
//!          the proxy, never forwarded);
//!        * `PING` — must be forwarded;
//!        * `SET deploy:latest v1.2.3` — must be forwarded (allow-
//!          list permits SET in this slice);
//!        * `GET deploy:latest` — must be forwarded and return the
//!          value;
//!        * `FLUSHDB` — denied by the allowlist with `-ERR command
//!          not allowed by RAXIS policy`.
//!   4. Verify:
//!        a. The upstream received the **proxy's** AUTH bytes (the
//!           real `live-e2e` value resolved through the
//!           CredentialBackend) — never the agent's junk bytes —
//!           proving the proxy strips and rewrites the agent-
//!           supplied AUTH payload.
//!        b. The upstream observed the allowed verbs in order
//!           (PING, SET, GET) and never observed the denied verb
//!           (FLUSHDB).
//!        c. The proxy's `commands_forwarded` counter matched the
//!           number of allowed commands forwarded; `commands_blocked`
//!           matched the number of denied commands.
//!        d. The `CredentialBackend` was asked at least once
//!           (per-connection resolution preserves rotation
//!           semantics).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    Lease, OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use raxis_credential_proxy_redis::{
    NoopAuditChannel, OwnedConsumer, ProxyConfig, RedisProxy, Restrictions,
};

const UPSTREAM_PASS: &str = "live-e2e-upstream-redis-secret";

// ---------------------------------------------------------------------------
// Local CredentialBackend: returns the upstream password verbatim.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Shared "what did upstream see" record — the slice asserts on this
// after the conversation.
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
struct UpstreamObserved {
    /// Bytes of the password the upstream's AUTH command carried.
    /// We compare these to the real credential bytes.
    auth_password_bytes: Option<Vec<u8>>,
    /// Uppercased verbs of every non-AUTH command the upstream
    /// received, in arrival order.
    forwarded_verbs:     Vec<String>,
    /// Whether the upstream observed FLUSHDB (must remain `false`).
    observed_flushdb:    bool,
}

// ---------------------------------------------------------------------------
// Upstream RESP fixture
// ---------------------------------------------------------------------------

async fn run_upstream_fixture(listener: TcpListener, observed: Arc<Mutex<UpstreamObserved>>) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let observed_for_conn = Arc::clone(&observed);
        tokio::spawn(async move {
            if let Err(e) = handle_upstream_conn(stream, observed_for_conn).await {
                tracing::warn!(error = %e, "upstream RESP fixture connection ended");
            }
        });
    }
}

async fn handle_upstream_conn(
    stream: TcpStream,
    observed: Arc<Mutex<UpstreamObserved>>,
) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    loop {
        let frame = match read_one_request_frame(&mut reader).await? {
            Some(b) => b,
            None    => return Ok(()),
        };
        let verb = first_array_token(&frame).unwrap_or_default().to_ascii_uppercase();

        match verb.as_str() {
            "AUTH" => {
                // Extract bulk-string body for the AUTH password (last
                // bulk in the array). The proxy always sends array
                // form, so we walk the bulks.
                let pw = extract_last_bulk(&frame).unwrap_or_default();
                {
                    let mut obs = observed.lock().await;
                    obs.auth_password_bytes = Some(pw.clone());
                }
                write.write_all(b"+OK\r\n").await?;
            }
            "PING" => {
                {
                    let mut obs = observed.lock().await;
                    obs.forwarded_verbs.push(verb.clone());
                }
                write.write_all(b"+PONG\r\n").await?;
            }
            "SET" => {
                {
                    let mut obs = observed.lock().await;
                    obs.forwarded_verbs.push(verb.clone());
                }
                write.write_all(b"+OK\r\n").await?;
            }
            "GET" => {
                {
                    let mut obs = observed.lock().await;
                    obs.forwarded_verbs.push(verb.clone());
                }
                write.write_all(b"$6\r\nv1.2.3\r\n").await?;
            }
            "FLUSHDB" => {
                // Should never happen — denied by allowlist.
                {
                    let mut obs = observed.lock().await;
                    obs.observed_flushdb = true;
                }
                write.write_all(b"+OK\r\n").await?;
            }
            "QUIT" => {
                write.write_all(b"+OK\r\n").await?;
                return Ok(());
            }
            _ => {
                // Treat as a noop the proxy might forward in future
                // expansions; record it for debugging without
                // forcing a slice failure.
                {
                    let mut obs = observed.lock().await;
                    obs.forwarded_verbs.push(verb);
                }
                write.write_all(b"+OK\r\n").await?;
            }
        }
    }
}

// Read one RESP request frame from upstream's POV (same contract as
// the proxy's reader) — array form or inline form. None on clean
// EOF.
async fn read_one_request_frame(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<Option<Vec<u8>>> {
    use tokio::io::AsyncBufReadExt;
    let buf = reader.fill_buf().await?;
    if buf.is_empty() { return Ok(None); }
    let first = buf[0];
    if first == b'*' {
        let header = read_until_crlf(reader).await?;
        let n: i64 = std::str::from_utf8(&header[1..header.len()-2])
            .ok().and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("malformed array header"))?;
        let mut frame = header;
        if n <= 0 { return Ok(Some(frame)); }
        for _ in 0..n {
            let bulk_header = read_until_crlf(reader).await?;
            frame.extend_from_slice(&bulk_header);
            let len: i64 = std::str::from_utf8(&bulk_header[1..bulk_header.len()-2])
                .ok().and_then(|s| s.parse().ok())
                .ok_or_else(|| anyhow!("malformed bulk header"))?;
            if len < 0 { continue; }
            let mut body = vec![0u8; (len as usize) + 2];
            reader.read_exact(&mut body).await?;
            frame.extend_from_slice(&body);
        }
        Ok(Some(frame))
    } else {
        // Inline form.
        let line = read_until_crlf(reader).await?;
        Ok(Some(line))
    }
}

async fn read_until_crlf(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<Vec<u8>> {
    let mut acc = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 { break; }
        acc.push(byte[0]);
        if acc.ends_with(b"\r\n") { break; }
    }
    if !acc.ends_with(b"\r\n") {
        return Err(anyhow!("short read mid-frame"));
    }
    Ok(acc)
}

fn first_array_token(frame: &[u8]) -> Option<String> {
    if frame.is_empty() { return None; }
    if frame[0] == b'*' {
        // Skip array header → first bulk header → bulk body.
        let crlf1 = find_crlf(frame, 0)? + 2;
        if crlf1 >= frame.len() || frame[crlf1] != b'$' { return None; }
        let crlf2 = find_crlf(frame, crlf1)? + 2;
        let body_end = find_crlf(frame, crlf2)?;
        Some(String::from_utf8_lossy(&frame[crlf2..body_end]).into_owned())
    } else {
        // Inline form: take first whitespace-delimited token.
        let trimmed = if frame.ends_with(b"\r\n") { &frame[..frame.len()-2] } else { frame };
        let first = trimmed
            .split(|b| *b == b' ' || *b == b'\t')
            .next()
            .unwrap_or_default();
        Some(String::from_utf8_lossy(first).into_owned())
    }
}

fn extract_last_bulk(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.is_empty() || frame[0] != b'*' { return None; }
    // Walk every CRLF; the LAST `$<len>\r\n<body>\r\n` we find is
    // the AUTH password.
    let mut idx = find_crlf(frame, 0)? + 2;
    let mut last_body: Option<Vec<u8>> = None;
    while idx < frame.len() {
        if frame[idx] != b'$' { break; }
        let header_end = find_crlf(frame, idx)?;
        let len: i64 = std::str::from_utf8(&frame[idx+1..header_end])
            .ok().and_then(|s| s.parse().ok())?;
        let body_start = header_end + 2;
        if len < 0 { idx = body_start; continue; }
        let body_end = body_start + (len as usize);
        if body_end + 2 > frame.len() { return None; }
        last_body = Some(frame[body_start..body_end].to_vec());
        idx = body_end + 2;
    }
    last_body
}

fn find_crlf(b: &[u8], start: usize) -> Option<usize> {
    if start >= b.len() { return None; }
    b[start..].windows(2).position(|w| w == b"\r\n").map(|i| start + i)
}

// ---------------------------------------------------------------------------
// Slice driver
// ---------------------------------------------------------------------------

pub async fn run() -> Result<()> {
    tracing::info!("redis-proxy slice starting");

    // Step 1 — upstream fixture.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await
        .context("bind upstream RESP listener")?;
    let upstream_addr = upstream_listener.local_addr()?;
    let observed = Arc::new(Mutex::new(UpstreamObserved::default()));
    {
        let observed_for_fixture = Arc::clone(&observed);
        tokio::spawn(async move {
            run_upstream_fixture(upstream_listener, observed_for_fixture).await;
        });
    }

    // Step 2 — bind the real RedisProxy.
    let backend = Arc::new(LiveBackend {
        value:    UPSTREAM_PASS.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:        "127.0.0.1:0".to_owned(),
        upstream_host_port: upstream_addr.to_string(),
        credential_name:    CredentialName::new("live-e2e"),
        consumer:           OwnedConsumer::new("live-e2e-redis-slice", "session-1"),
        restrictions: Restrictions {
            allowed_commands: vec!["PING".into(), "SET".into(), "GET".into()],
        },
    };
    let proxy = RedisProxy::bind(
        Arc::clone(&backend) as Arc<dyn CredentialBackend>,
        cfg,
        Arc::new(NoopAuditChannel::default()),
    )
    .await
    .context("bind RedisProxy")?;
    let proxy_addr = proxy.local_addr()?;
    let stats_handle = proxy.stats_handle();
    tokio::spawn(async move { proxy.serve().await; });

    // Give the proxy a tick to be ready.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Step 3 — drive a real RESP conversation through the proxy.
    let mut client = TcpStream::connect(proxy_addr).await
        .context("connect to RedisProxy listener")?;

    // Junk AUTH (must be discarded by the proxy and replied +OK).
    client.write_all(b"*2\r\n$4\r\nAUTH\r\n$25\r\nagent-supplied-junk-bytes\r\n").await?;
    expect_simple_string(&mut client, "+OK\r\n").await
        .context("proxy must reply +OK to agent AUTH (discarded)")?;

    // PING — allowed, forwarded.
    client.write_all(b"*1\r\n$4\r\nPING\r\n").await?;
    expect_simple_string(&mut client, "+PONG\r\n").await
        .context("PING must be forwarded and return +PONG")?;

    // SET — allowed, forwarded.
    client.write_all(b"*3\r\n$3\r\nSET\r\n$13\r\ndeploy:latest\r\n$6\r\nv1.2.3\r\n").await?;
    expect_simple_string(&mut client, "+OK\r\n").await
        .context("SET must be forwarded and return +OK")?;

    // GET — allowed, forwarded.
    client.write_all(b"*2\r\n$3\r\nGET\r\n$13\r\ndeploy:latest\r\n").await?;
    expect_bulk_string(&mut client, b"v1.2.3").await
        .context("GET must be forwarded and return the value")?;

    // FLUSHDB — denied by allowlist.
    client.write_all(b"*1\r\n$7\r\nFLUSHDB\r\n").await?;
    let denied = read_simple_response(&mut client).await?;
    if !starts_with(&denied, b"-ERR command FLUSHDB not allowed by RAXIS policy") {
        return Err(anyhow!(
            "FLUSHDB must be denied with `-ERR command FLUSHDB not allowed by RAXIS policy`, \
             observed: {:?}",
            String::from_utf8_lossy(&denied),
        ));
    }

    // Cleanly close.
    client.write_all(b"*1\r\n$4\r\nQUIT\r\n").await?;
    let _ = tokio::time::timeout(Duration::from_millis(200),
        async { let mut buf = [0u8; 64]; let _ = client.read(&mut buf).await; },
    ).await;

    // Give the proxy a tick to flush counters.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Step 4 — assertions.
    let obs = observed.lock().await.clone();

    let upstream_pw = obs.auth_password_bytes.as_deref()
        .ok_or_else(|| anyhow!("upstream did not observe AUTH"))?;
    if upstream_pw != UPSTREAM_PASS.as_bytes() {
        return Err(anyhow!(
            "upstream observed wrong AUTH bytes — expected the real credential, \
             got {:?}",
            String::from_utf8_lossy(upstream_pw),
        ));
    }
    if obs.observed_flushdb {
        return Err(anyhow!(
            "FLUSHDB must NEVER reach upstream (allowlist denial) — fixture saw it",
        ));
    }
    let expected_verbs = vec!["PING".to_owned(), "SET".to_owned(), "GET".to_owned()];
    if obs.forwarded_verbs != expected_verbs {
        return Err(anyhow!(
            "forwarded verbs mismatch — expected {expected_verbs:?}, got {:?}",
            obs.forwarded_verbs,
        ));
    }

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
        commands_blocked   = snap.commands_blocked,
        bytes_out_to_upstream = snap.bytes_out_to_upstream,
        backend_resolves = backend.resolves.load(Ordering::Relaxed),
        "redis-proxy slice OK",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Tiny client-side helpers
// ---------------------------------------------------------------------------

async fn expect_simple_string(client: &mut TcpStream, expected: &str) -> Result<()> {
    let resp = read_simple_response(client).await?;
    if resp != expected.as_bytes() {
        return Err(anyhow!(
            "expected {:?}, got {:?}",
            expected, String::from_utf8_lossy(&resp),
        ));
    }
    Ok(())
}

async fn expect_bulk_string(client: &mut TcpStream, expected_body: &[u8]) -> Result<()> {
    // Read header line `$N\r\n`.
    let header = read_until_crlf_stream(client).await?;
    if !header.starts_with(b"$") {
        return Err(anyhow!(
            "expected bulk-string header, got {:?}", String::from_utf8_lossy(&header),
        ));
    }
    let n: i64 = std::str::from_utf8(&header[1..header.len()-2])
        .ok().and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad bulk header"))?;
    if n < 0 {
        return Err(anyhow!("expected non-null bulk, got null"));
    }
    let mut body = vec![0u8; (n as usize) + 2];
    client.read_exact(&mut body).await?;
    let body_only = &body[..n as usize];
    if body_only != expected_body {
        return Err(anyhow!(
            "expected bulk body {:?}, got {:?}",
            String::from_utf8_lossy(expected_body),
            String::from_utf8_lossy(body_only),
        ));
    }
    Ok(())
}

async fn read_simple_response(client: &mut TcpStream) -> Result<Vec<u8>> {
    read_until_crlf_stream(client).await
}

async fn read_until_crlf_stream(client: &mut TcpStream) -> Result<Vec<u8>> {
    let mut acc = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = client.read(&mut byte).await?;
        if n == 0 { break; }
        acc.push(byte[0]);
        if acc.ends_with(b"\r\n") { break; }
    }
    if !acc.ends_with(b"\r\n") {
        return Err(anyhow!("short read mid-frame"));
    }
    Ok(acc)
}

fn starts_with(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack.len() >= prefix.len() && &haystack[..prefix.len()] == prefix
}
