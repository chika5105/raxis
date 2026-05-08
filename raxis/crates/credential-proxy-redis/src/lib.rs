//! `raxis-credential-proxy-redis` — Redis credential proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §1` (core
//! principle: the agent never sees the secret) and `§3` (concrete
//! proxy types — Redis is the simplest TCP proxy because RESP is
//! human-readable and AUTH is one command).
//!
//! # What this MVP supports
//!
//!   * **Inbound RESP-shaped accept.** The agent VM connects to a
//!     localhost listener that speaks Redis Serialization Protocol
//!     v2 (RESP2; the same wire format every Redis client speaks
//!     when targeting Redis ≤ 6 with AUTH). RESP3 / HELLO are
//!     accepted but the response is degraded to RESP2 (`-NOPROTO`)
//!     because the proxy only re-serialises RESP2 frames.
//!   * **Per-connection upstream dial.** One agent connection
//!     opens one upstream `TcpStream` to `upstream_host_port`.
//!     The proxy authenticates upstream with the credential
//!     resolved through `CredentialBackend` *before* it forwards
//!     any agent-issued command. Rotations land mid-session
//!     because the resolve happens at the *connection* boundary,
//!     not at proxy bind.
//!   * **AUTH command interception.** Whatever the agent issues
//!     as `AUTH password` (or the array form `*2\r\n$4\r\nAUTH\r\n$N\r\npassword\r\n`)
//!     is **discarded** and the proxy responds `+OK\r\n`. The
//!     real `AUTH` against the upstream is whatever the
//!     `CredentialBackend` returned.
//!   * **Command allowlist.** `Restrictions::allowed_commands`
//!     gates the first array element of every inbound command
//!     frame (case-insensitive). Disallowed commands are
//!     rejected with `-ERR command not allowed by RAXIS policy`
//!     and never reach upstream; the upstream connection stays
//!     open for the next command.
//!   * **Audit emission.** Every forwarded (and every blocked)
//!     command emits a `RedisCommandExecuted` event with the
//!     consumer identity, command name, allowlist verdict, and a
//!     SHA-256 of the rendered RESP frame the upstream would
//!     have seen. The kernel translates these into
//!     `AuditEventKind::RedisCommandExecuted`.
//!
//! # What is deferred
//!
//!   * **TLS to upstream.** V3 lands `RESP-over-TLS` for managed
//!     Redis (Elasticache, Memorystore). Rationale: the upstream
//!     hop is loopback in the typical operator deployment (Redis
//!     in the same VPC as the kernel), and TLS adds CA bundle +
//:    SNI plumbing without security gain in that posture.
//!   * **`MULTI/EXEC` transactional grouping for the audit
//!     trail.** Each command in the transaction is audited as a
//!     standalone row; the audit chain is byte-stable but
//!     transactional intent is not surfaced.
//!   * **Cluster proxy** (multiple upstream nodes by hash slot).
//!     The proxy pins a single `host:port` upstream; a
//!     `CLUSTER SLOTS` response is returned verbatim to the
//!     agent so the agent's client library does not request
//!     slot-aware routing through the proxy.
//!   * **Pub/sub fan-out.** `SUBSCRIBE` / `PSUBSCRIBE` work
//!     end-to-end (the proxy is a transparent byte forwarder
//!     once the AUTH handshake has completed) but multi-client
//!     fan-out across multiple agent sessions is not supported.
//!   * **`AUTH SCAN` / username+password ACL form** — the proxy
//!     currently emits `AUTH <password>`; ACL form (`AUTH user
//!     pass`) lands when the ConsumerIdentity carries a user
//!     name. The credential resolver returns just the password
//!     in V2.
//!
//! # Threat model
//!
//! Identical to the postgres / smtp / http proxies: a fully-
//! compromised agent process cannot exfiltrate the upstream
//! credential because the proxy is the only entity with access
//! to the resolved bytes. The agent's `AUTH ...` is recorded but
//! never forwarded; the proxy refuses to dial any upstream other
//! than the one pinned at bind time.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use raxis_credentials::{CredentialBackend, CredentialName, ConsumerIdentity};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

pub mod resp;
pub mod restriction;

pub use restriction::Restrictions;

// ---------------------------------------------------------------------------
// OwnedConsumer — local mirror of the postgres / http / smtp proxies'
// type. The proxies are deliberate siblings, never share types.
// ---------------------------------------------------------------------------

/// Owned form of `ConsumerIdentity` used in the proxy's audit events.
#[derive(Debug, Clone)]
pub struct OwnedConsumer {
    /// Subsystem identifier.
    pub kind: String,
    /// Free-form disambiguator within `kind`.
    pub id:   String,
}

impl OwnedConsumer {
    /// Convenience constructor.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self { kind: kind.into(), id: id.into() }
    }
    /// Borrow as the trait-facing form.
    pub fn as_ref(&self) -> ConsumerIdentity<'_> {
        ConsumerIdentity::new(&self.kind, &self.id)
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for one Redis proxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the inbound listener binds to. Production wires
    /// `127.0.0.1:0` so the kernel can pass the chosen port to
    /// the VM via env-var injection.
    pub listen_addr:        String,
    /// `host:port` of the upstream Redis. The proxy refuses to
    /// dial any other address per the threat-model section.
    pub upstream_host_port: String,
    /// Credential to inject. Resolved via `CredentialBackend` per
    /// **connection** so rotations land mid-session.
    pub credential_name:    CredentialName,
    /// Identity of the agent session this proxy serves.
    pub consumer:           OwnedConsumer,
    /// Effective restriction set parsed out of
    /// `[tasks.credentials.restrictions]`.
    pub restrictions:       Restrictions,
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Counters surfaced for `CredentialProxyStopped`.
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Number of accepted connections served.
    pub connections_served:  AtomicU32,
    /// Number of commands forwarded to upstream after restriction
    /// check.
    pub commands_forwarded:  AtomicU32,
    /// Number of commands rejected by `Restrictions`.
    pub commands_blocked:    AtomicU32,
    /// Total bytes forwarded to upstream (request side only).
    pub bytes_out_to_upstream: AtomicU64,
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served:    self.connections_served   .load(Ordering::Relaxed),
            commands_forwarded:    self.commands_forwarded   .load(Ordering::Relaxed),
            commands_blocked:      self.commands_blocked     .load(Ordering::Relaxed),
            bytes_out_to_upstream: self.bytes_out_to_upstream.load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot of the counters at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted connections served.
    pub connections_served:    u32,
    /// Number of commands forwarded to upstream.
    pub commands_forwarded:    u32,
    /// Number of commands rejected by `Restrictions`.
    pub commands_blocked:      u32,
    /// Total bytes forwarded to upstream.
    pub bytes_out_to_upstream: u64,
}

// ---------------------------------------------------------------------------
// Audit channel
// ---------------------------------------------------------------------------

/// Sink the kernel-side `CredentialProxyManager` plugs into; per
/// the postgres / http / smtp parity contract the proxy crate
/// stays dependency-free of `raxis-audit-tools`.
pub trait AuditChannel: Send + Sync {
    /// Record one decision (forwarded or rejected).
    fn emit(&self, event: AuditEvent);
}

/// Convenience no-op channel for tests / out-of-band callers.
#[derive(Default)]
pub struct NoopAuditChannel;

impl AuditChannel for NoopAuditChannel {
    fn emit(&self, _event: AuditEvent) {}
}

/// Audit-event surface emitted by this crate. Names match
/// `credential-proxy.md §5` and `§14.5`.
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// One forwarded (or rejected) command.
    RedisCommandExecuted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
        /// Uppercased command verb (e.g. `"GET"`, `"AUTH"`,
        /// `"FLUSHDB"`). For pipelined frames this is the verb of
        /// the leading frame.
        command:     String,
        /// SHA-256 of the rendered RESP request frame the
        /// upstream would have seen. For blocked commands this
        /// is computed from the inbound bytes.
        frame_sha256: String,
        /// True if a restriction blocked this command.
        blocked:     bool,
    },

    /// Emitted once per agent connection on the first successful
    /// upstream TCP+AUTH handshake. Per `credential-proxy.md §14.5.2`.
    CredentialProxyUpstreamConnected {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session that triggered upstream contact.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
        /// Upstream **hostname from the credential URL** so
        /// dashboards can group events without leaking DNS noise.
        upstream_host: String,
        /// Upstream port from the credential URL.
        upstream_port: u16,
        /// True if the upstream connection negotiated TLS. V2.1
        /// MVP supports plaintext only; this is always `false`.
        tls: bool,
        /// Wall-clock from `TcpStream::connect()` start to first
        /// usable session, in milliseconds.
        handshake_ms: u32,
    },

    /// Emitted on every upstream-connect attempt that did NOT reach
    /// a usable session. Per `credential-proxy.md §14.5.3`.
    CredentialProxyUpstreamFailed {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session that triggered upstream contact.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
        /// Upstream hostname from the credential URL.
        upstream_host: String,
        /// Upstream port from the credential URL.
        upstream_port: u16,
        /// Failure category. One of `"DnsResolveFailed" |
        /// "TcpConnectFailed" | "TlsHandshakeFailed" |
        /// "ProtocolHandshakeFailed" | "AuthRejected" | "Timeout"`.
        reason: String,
        /// Short redacted message; never carries credential bytes.
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors the proxy lifecycle can surface.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Listener bind failed.
    #[error("listener bind failed at {addr}: {source}")]
    Bind {
        /// Address the bind was attempted on.
        addr:   String,
        /// Underlying I/O error from `tokio::net::TcpListener::bind`.
        source: std::io::Error,
    },
    /// Upstream `host:port` was malformed.
    #[error("upstream host:port `{0}` is not a valid Redis address")]
    BadUpstream(String),
}

// ---------------------------------------------------------------------------
// Library entry point
// ---------------------------------------------------------------------------

/// Redis credential proxy.
pub struct RedisProxy {
    listener: TcpListener,
    backend:  Arc<dyn CredentialBackend>,
    config:   ProxyConfig,
    stats:    Arc<ProxyStats>,
    audit:    Arc<dyn AuditChannel>,
}

impl RedisProxy {
    /// Bind a listener and return an owned proxy.
    pub async fn bind(
        backend: Arc<dyn CredentialBackend>,
        config:  ProxyConfig,
        audit:   Arc<dyn AuditChannel>,
    ) -> Result<Self, ProxyError> {
        if !config.upstream_host_port.contains(':') {
            return Err(ProxyError::BadUpstream(config.upstream_host_port.clone()));
        }
        let listener = TcpListener::bind(&config.listen_addr).await
            .map_err(|source| ProxyError::Bind {
                addr:   config.listen_addr.clone(),
                source,
            })?;
        Ok(Self {
            listener,
            backend,
            config,
            stats: Arc::new(ProxyStats::default()),
            audit,
        })
    }

    /// The address the listener is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Counters snapshot.
    pub fn stats(&self) -> ProxyStatsSnapshot {
        self.stats.snapshot()
    }

    /// Borrow the underlying counters Arc so callers can keep
    /// reading after `serve()` consumes the proxy.
    pub fn stats_handle(&self) -> Arc<ProxyStats> {
        Arc::clone(&self.stats)
    }

    /// Run the accept loop until the future is dropped.
    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _peer)) => {
                    self.stats.connections_served.fetch_add(1, Ordering::Relaxed);
                    let backend = Arc::clone(&self.backend);
                    let config  = self.config.clone();
                    let stats   = Arc::clone(&self.stats);
                    let audit   = Arc::clone(&self.audit);
                    tokio::spawn(async move {
                        if let Err(e) = serve_one(stream, backend, config, stats, audit).await {
                            tracing::warn!(error = %e, "redis proxy connection ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "redis proxy accept failed");
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-connection driver.
// ---------------------------------------------------------------------------

async fn serve_one(
    client_stream: TcpStream,
    backend:       Arc<dyn CredentialBackend>,
    config:        ProxyConfig,
    stats:         Arc<ProxyStats>,
    audit:         Arc<dyn AuditChannel>,
) -> std::io::Result<()> {
    // Resolve the upstream credential ONCE per connection so a
    // rotation lands mid-session.
    let cred = backend.resolve(&config.credential_name, config.consumer.as_ref())
        .map_err(|e| std::io::Error::other(format!("credential resolve: {e}")))?;
    let cred_str = match cred.as_utf8() {
        Some(s) => s.to_owned(),
        None    => {
            // Treat non-UTF-8 credentials as a hard error — Redis
            // AUTH wire takes a UTF-8 string. We surface as IO.
            return Err(std::io::Error::other("credential is not valid UTF-8"));
        }
    };

    // Dial upstream. Per `credential-proxy.md §14.3` the proxy
    // emits CredentialProxyUpstreamConnected on a successful TCP+
    // AUTH handshake and CredentialProxyUpstreamFailed on every
    // failure category (TCP, AUTH, timeout). The host/port pair
    // we report is the one parsed from `upstream_host_port` BEFORE
    // DNS resolution so dashboards group by upstream cluster
    // without DNS noise.
    let (upstream_host, upstream_port) = parse_host_port(&config.upstream_host_port);
    let connect_started = std::time::Instant::now();
    let upstream = match TcpStream::connect(&config.upstream_host_port).await {
        Ok(s) => s,
        Err(e) => {
            audit.emit(AuditEvent::CredentialProxyUpstreamFailed {
                timestamp_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0),
                consumer:      config.consumer.clone(),
                credential:    config.credential_name.clone(),
                upstream_host: upstream_host.clone(),
                upstream_port,
                reason:        if e.kind() == std::io::ErrorKind::TimedOut {
                    "Timeout".into()
                } else {
                    "TcpConnectFailed".into()
                },
                detail:        e.to_string(),
            });
            return Err(std::io::Error::other(format!("upstream dial: {e}")));
        }
    };
    // Authenticate upstream.
    let mut upstream_reader = BufReader::new(upstream);
    write_auth(&mut upstream_reader, &cred_str).await?;
    let auth_resp = read_simple_response(&mut upstream_reader).await?;
    if !is_ok_or_unauth_already(&auth_resp) {
        // Upstream rejected our credential. Surface a generic
        // upstream auth error to the agent and close.
        audit.emit(AuditEvent::CredentialProxyUpstreamFailed {
            timestamp_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0),
            consumer:      config.consumer.clone(),
            credential:    config.credential_name.clone(),
            upstream_host: upstream_host.clone(),
            upstream_port,
            reason:        "AuthRejected".into(),
            detail:        format!(
                "upstream rejected AUTH (response prefix: {:.32?})",
                String::from_utf8_lossy(&auth_resp[..auth_resp.len().min(64)]),
            ),
        });
        let mut client = client_stream;
        client.write_all(b"-ERR upstream auth rejected by RAXIS proxy\r\n").await?;
        return Ok(());
    }
    let handshake_ms = connect_started.elapsed().as_millis().min(u32::MAX as u128) as u32;
    audit.emit(AuditEvent::CredentialProxyUpstreamConnected {
        timestamp_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0),
        consumer:      config.consumer.clone(),
        credential:    config.credential_name.clone(),
        upstream_host,
        upstream_port,
        tls:           false,
        handshake_ms,
    });

    let (client_read, client_write) = client_stream.into_split();
    let mut client_reader = BufReader::new(client_read);
    let client_write = Arc::new(tokio::sync::Mutex::new(client_write));

    let upstream_inner = upstream_reader.into_inner();
    let (upstream_read, mut upstream_write) = upstream_inner.into_split();

    // Upstream-to-client forwarder. Holds the client-write
    // mutex for one chunk at a time so the inbound parser can
    // interleave synthetic replies (AUTH +OK, blocked-command
    // -ERR, HELLO -NOPROTO) without contending with upstream
    // bytes.
    let client_write_for_forwarder = Arc::clone(&client_write);
    let downstream_forwarder = tokio::spawn(async move {
        let mut upstream_read = upstream_read;
        let mut buf = [0u8; 8 * 1024];
        loop {
            match upstream_read.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => {
                    let mut w = client_write_for_forwarder.lock().await;
                    if w.write_all(&buf[..n]).await.is_err() { return; }
                }
                Err(_) => return,
            }
        }
    });

    // Inbound: parse frames, gate against allowlist, forward
    // approved frames to upstream OR synthesise replies to client.
    loop {
        let frame_bytes = match read_one_request_frame(&mut client_reader).await {
            Ok(Some(b)) => b,
            Ok(None)    => break,
            Err(e)      => {
                tracing::warn!(error = %e, "redis proxy: malformed inbound frame");
                break;
            }
        };
        let verb = resp::frame_verb_uppercased(&frame_bytes).unwrap_or_default();

        // AUTH from the agent: discard, always reply +OK to keep
        // client SDKs happy. We DO NOT forward to upstream.
        if verb == "AUTH" {
            audit.emit(audit_event(&config, &verb, &frame_bytes, false));
            let mut w = client_write.lock().await;
            let _ = w.write_all(b"+OK\r\n").await;
            continue;
        }
        // HELLO: refuse RESP3 to keep the proxy on RESP2 wire.
        if verb == "HELLO" {
            audit.emit(audit_event(&config, &verb, &frame_bytes, false));
            let mut w = client_write.lock().await;
            let _ = w.write_all(b"-NOPROTO sorry, this proxy speaks RESP2\r\n").await;
            continue;
        }

        if !config.restrictions.allows_command(&verb) {
            stats.commands_blocked.fetch_add(1, Ordering::Relaxed);
            audit.emit(audit_event(&config, &verb, &frame_bytes, true));
            let mut w = client_write.lock().await;
            let _ = w.write_all(
                format!("-ERR command {verb} not allowed by RAXIS policy\r\n").as_bytes(),
            ).await;
            continue;
        }

        // Forward.
        upstream_write.write_all(&frame_bytes).await?;
        stats.commands_forwarded.fetch_add(1, Ordering::Relaxed);
        stats.bytes_out_to_upstream.fetch_add(
            frame_bytes.len() as u64, Ordering::Relaxed,
        );
        audit.emit(audit_event(&config, &verb, &frame_bytes, false));
    }

    // Drop our half of upstream so the downstream forwarder
    // returns. Both halves end up dropped on connection close.
    drop(upstream_write);
    let _ = downstream_forwarder.await;
    Ok(())
}

// Helper writers / readers for the AUTH dance with the upstream.

async fn write_auth(
    upstream: &mut BufReader<TcpStream>,
    password: &str,
) -> std::io::Result<()> {
    let inner = upstream.get_mut();
    let frame = build_auth_frame(password);
    inner.write_all(&frame).await
}

fn build_auth_frame(password: &str) -> Vec<u8> {
    // `*2\r\n$4\r\nAUTH\r\n$<n>\r\n<password>\r\n` — RESP array
    // form, version-stable across Redis 5.x → 7.x.
    let pw = password.as_bytes();
    let mut out = Vec::with_capacity(20 + pw.len());
    out.extend_from_slice(b"*2\r\n$4\r\nAUTH\r\n$");
    out.extend_from_slice(pw.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(pw);
    out.extend_from_slice(b"\r\n");
    out
}

/// Read one simple response frame from upstream (`+OK\r\n` or
/// `-ERR ...\r\n` or `:NUMBER\r\n`).
async fn read_simple_response(
    upstream: &mut BufReader<TcpStream>,
) -> std::io::Result<Vec<u8>> {
    let mut acc = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = upstream.read(&mut byte).await?;
        if n == 0 { break; }
        acc.push(byte[0]);
        if acc.ends_with(b"\r\n") { break; }
    }
    Ok(acc)
}

fn is_ok_or_unauth_already(resp: &[u8]) -> bool {
    // `+OK\r\n` is the canonical accept; `-ERR Client sent AUTH,
    // but no password is set` is what the upstream returns when
    // it has no `requirepass` configured (test fixtures!) — we
    // treat that as success because it means the wire is open.
    resp.starts_with(b"+OK\r\n")
        || resp.starts_with(b"-ERR Client sent AUTH, but no password is set")
        || resp.starts_with(b"-ERR Client sent AUTH, but no password is configured")
}

/// Read one inbound RESP request frame. Handles inline form
/// (`PING\r\n`) and array form
/// (`*N\r\n$M\r\nVERB\r\n...`).
///
/// Returns `Ok(None)` on clean EOF; `Err(...)` on malformed
/// bytes or short read mid-frame.
async fn read_one_request_frame(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> std::io::Result<Option<Vec<u8>>> {
    let first = match peek_byte(reader).await? {
        Some(b) => b,
        None    => return Ok(None),
    };
    if first == b'*' {
        // Array form. Read count, then N bulk strings.
        let header = read_until_crlf(reader).await?;
        let n: i64 = std::str::from_utf8(&header[1..header.len()-2])
            .ok().and_then(|s| s.parse().ok())
            .ok_or_else(|| std::io::Error::other("malformed array header"))?;
        let mut frame = header.clone();
        if n <= 0 { return Ok(Some(frame)); }
        for _ in 0..n {
            let bulk_header = read_until_crlf(reader).await?;
            frame.extend_from_slice(&bulk_header);
            let len: i64 = std::str::from_utf8(&bulk_header[1..bulk_header.len()-2])
                .ok().and_then(|s| s.parse().ok())
                .ok_or_else(|| std::io::Error::other("malformed bulk header"))?;
            if len < 0 {
                // null bulk
                continue;
            }
            let mut body = vec![0u8; (len as usize) + 2];
            reader.read_exact(&mut body).await?;
            frame.extend_from_slice(&body);
        }
        Ok(Some(frame))
    } else {
        // Inline form. Read until CRLF.
        let line = read_until_crlf(reader).await?;
        Ok(Some(line))
    }
}

async fn peek_byte(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> std::io::Result<Option<u8>> {
    use tokio::io::AsyncBufReadExt;
    let buf = reader.fill_buf().await?;
    if buf.is_empty() { Ok(None) } else { Ok(Some(buf[0])) }
}

async fn read_until_crlf(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> std::io::Result<Vec<u8>> {
    let mut acc = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 { break; }
        acc.push(byte[0]);
        if acc.ends_with(b"\r\n") { break; }
    }
    if !acc.ends_with(b"\r\n") {
        return Err(std::io::Error::other("short read mid-frame"));
    }
    Ok(acc)
}

/// Split an `upstream_host_port` string into `(host, port)` pieces
/// for the V2.1 audit envelopes. Falls back to `("unknown", 0)` for
/// malformed inputs — `bind()` already rejects those at proxy
/// startup, so this path is only reached if a future caller manages
/// to construct a `ProxyConfig` with a malformed `upstream_host_port`.
fn parse_host_port(host_port: &str) -> (String, u16) {
    match host_port.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse::<u16>().unwrap_or(0);
            (host.trim_start_matches('[').trim_end_matches(']').to_owned(), port)
        }
        None => (host_port.to_owned(), 0),
    }
}

fn audit_event(
    config:    &ProxyConfig,
    verb:      &str,
    frame_bytes: &[u8],
    blocked:   bool,
) -> AuditEvent {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(frame_bytes);
    let sha = hex::encode(h.finalize());
    AuditEvent::RedisCommandExecuted {
        timestamp_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        consumer:    config.consumer.clone(),
        credential:  config.credential_name.clone(),
        command:     verb.to_owned(),
        frame_sha256: sha,
        blocked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_frame_uses_canonical_resp_array_form() {
        let f = build_auth_frame("hunter2");
        assert_eq!(
            std::str::from_utf8(&f).unwrap(),
            "*2\r\n$4\r\nAUTH\r\n$7\r\nhunter2\r\n",
        );
    }

    #[test]
    fn auth_frame_handles_empty_password_canonically() {
        let f = build_auth_frame("");
        // Empty password is `$0\r\n\r\n` — well-formed even if
        // useless. Operators with no password set should not be
        // declaring a Redis credential proxy in the first place.
        assert_eq!(
            std::str::from_utf8(&f).unwrap(),
            "*2\r\n$4\r\nAUTH\r\n$0\r\n\r\n",
        );
    }

    #[test]
    fn is_ok_or_unauth_already_accepts_canonical_ok() {
        assert!(is_ok_or_unauth_already(b"+OK\r\n"));
    }

    #[test]
    fn is_ok_or_unauth_already_accepts_no_requirepass() {
        assert!(is_ok_or_unauth_already(
            b"-ERR Client sent AUTH, but no password is set as the default user has no password\r\n"
        ));
    }

    #[test]
    fn is_ok_or_unauth_already_rejects_bad_password() {
        assert!(!is_ok_or_unauth_already(b"-WRONGPASS invalid username-password pair\r\n"));
    }
}
