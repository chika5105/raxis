//! `raxis-credential-proxy-http` — generic HTTP-shaped credential
//! proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §1b` ("HTTP
//! Proxy vs. TCP Proxy") and §3 (concrete HTTP proxy types — k8s,
//! AWS, GCP, Azure, generic Bearer).
//!
//! # What this MVP supports
//!
//!   * **Generic Bearer token injection** — the credential value is
//!     taken from `CredentialBackend::resolve` and injected as
//!     `Authorization: Bearer <value>`. Other auth schemes (Basic,
//!     AWS SigV4, IMDS) extend the same `AuthMode` enum.
//!   * **Host header rewriting** — every incoming request is
//!     forwarded to a single, policy-pinned upstream URL; the
//!     inbound `Host` header is overwritten with the upstream
//!     authority before transmission.
//!   * **Method allowlist** — `Restrictions::allowed_methods` rejects
//!     `POST`/`PUT`/`DELETE`/etc. with `405 Method Not Allowed` when
//!     the policy is read-only.
//!   * **Path prefix allowlist** — `Restrictions::allowed_path_prefix`
//!     scopes which URI paths the proxy will forward.
//!   * **Audit emission** — every request emits an `AuditEvent` with
//!     the URI sha256, method, status code, and bytes_out.
//!
//! # What is deferred
//!
//!   * HTTP/2 — the inbound parser is HTTP/1.1 only. Most agent
//!     SDKs (kubectl, boto3, gcloud, azure-cli) negotiate HTTP/1.1
//!     against an explicit proxy, so the MVP is sufficient; HTTP/2
//!     lands when the upstream client also speaks h2c.
//!   * IMDS-shaped `/creds` endpoint for AWS/GCP/Azure managed
//!     identity — the agent-facing wire shape is documented in
//!     `credential-proxy.md §3.2 — §3.4`. The MVP focuses on the
//!     generic Bearer surface; the IMDS variants share the same
//!     plumbing and land as additional `AuthMode` variants.
//!   * Streaming uploads (chunked-encoded request bodies). Inbound
//!     requests are buffered to a configurable cap.
//!   * WebSockets / `Upgrade: websocket` — the proxy returns
//!     `400 Bad Request` for upgrade attempts.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use raxis_credentials::{ConsumerIdentity, CredentialBackend, CredentialName};

pub mod restriction;

pub use restriction::Restrictions;

// ---------------------------------------------------------------------------
// Owned consumer identity (mirror of the postgres-proxy variant; the
// two crates intentionally don't depend on each other).
// ---------------------------------------------------------------------------

/// Owned form of `ConsumerIdentity` used in the proxy's audit events.
#[derive(Debug, Clone)]
pub struct OwnedConsumer {
    /// Subsystem identifier.
    pub kind: String,
    /// Free-form disambiguator within `kind`.
    pub id: String,
}

impl OwnedConsumer {
    /// Convenience constructor.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }
    /// Borrow as the trait-facing form.
    pub fn as_ref(&self) -> ConsumerIdentity<'_> {
        ConsumerIdentity::new(&self.kind, &self.id)
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// How the credential is injected into outbound requests.
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// `Authorization: Bearer <credential-value>`.
    Bearer,
    /// `Authorization: Basic <base64(user:credential-value)>`.
    Basic {
        /// Username placed before the colon.
        user: String,
    },
}

/// Configuration for one HTTP proxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to listen on (e.g. `127.0.0.1:0`).
    pub listen_addr: String,
    /// Upstream URL the proxy forwards to. The path of an inbound
    /// request is appended to this URL's path; query strings pass
    /// through.
    pub upstream_url: String,
    /// Credential to inject. Resolved via `CredentialBackend` per
    /// connection (so rotations land mid-session).
    pub credential_name: CredentialName,
    /// How to shape the auth header.
    pub auth_mode: AuthMode,
    /// Identity of the agent session this proxy serves.
    pub consumer: OwnedConsumer,
    /// Effective restriction set.
    pub restrictions: Restrictions,
}

// ---------------------------------------------------------------------------
// Audit channel — kernel-injected sink for per-request audit events.
// ---------------------------------------------------------------------------

/// Sink the kernel-side `CredentialProxyManager` plugs into so each
/// `AuditEvent::HttpProxyRequestExecuted` produced by the proxy is
/// translated into the kernel's
/// `AuditEventKind::HttpProxyRequestExecuted` and written through
/// the same `AuditSink` as every other audit event.
///
/// Per the postgres / http parity contract documented in
/// `credential-proxy.md §5`, this proxy crate stays
/// dependency-free of `raxis-audit-tools`. The kernel wraps the
/// real `AuditSink` adapter around this trait at bind time
/// (`raxis-credential-proxy-manager::bind_http`).
///
/// Emission is deliberately fire-and-forget (`fn emit` returns
/// `()`) — the request has already been forwarded by the time we
/// audit it, and the kernel-side adapter logs (rather than panics)
/// on a transient audit-pipe failure to keep the agent's session
/// alive when the chain is momentarily wedged.
pub trait AuditChannel: Send + Sync {
    /// Record one `AuditEvent::HttpProxyRequestExecuted`.
    fn emit(&self, event: AuditEvent);
}

/// Convenience no-op channel for tests / out-of-band callers that
/// don't care about per-request audit translation.
#[derive(Default)]
pub struct NoopAuditChannel;

impl AuditChannel for NoopAuditChannel {
    fn emit(&self, _event: AuditEvent) {}
}

/// Errors the proxy lifecycle can surface.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Listener bind failed.
    #[error("listener bind failed at {addr}: {source}")]
    Bind {
        /// Address the bind was attempted on.
        addr: String,
        /// Underlying I/O error from `tokio::net::TcpListener::bind`.
        source: std::io::Error,
    },
    /// Upstream URL didn't parse at construction time.
    #[error("upstream URL `{0}` is not a valid http(s) URL")]
    BadUpstream(String),
}

/// Counters surfaced for `CredentialProxyStopped`.
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Number of accepted connections served (regardless of success).
    pub connections_served: AtomicU32,
    /// Number of requests forwarded to upstream.
    pub requests_forwarded: AtomicU32,
    /// Number of requests rejected by `Restrictions`.
    pub requests_blocked: AtomicU32,
    /// Total bytes returned to clients (response bodies only).
    pub bytes_out: AtomicU64,
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served: self.connections_served.load(Ordering::Relaxed),
            requests_forwarded: self.requests_forwarded.load(Ordering::Relaxed),
            requests_blocked: self.requests_blocked.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot of proxy counters at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted connections served.
    pub connections_served: u32,
    /// Number of requests forwarded to upstream.
    pub requests_forwarded: u32,
    /// Number of requests rejected by `Restrictions`.
    pub requests_blocked: u32,
    /// Total bytes returned to clients (response bodies only).
    pub bytes_out: u64,
}

// ---------------------------------------------------------------------------
// Library entry point
// ---------------------------------------------------------------------------

/// Generic HTTP credential proxy.
pub struct HttpProxy {
    listener: tokio::net::TcpListener,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    upstream: url::Url,
    stats: Arc<ProxyStats>,
    http: reqwest::Client,
    audit: Arc<dyn AuditChannel>,
}

impl HttpProxy {
    /// Bind a listener and return an owned proxy.
    ///
    /// The `audit` channel is invoked with one
    /// `AuditEvent::HttpProxyRequestExecuted` per request the proxy
    /// processes (forwarded or rejected). The kernel-side
    /// `CredentialProxyManager::bind_http` plugs in an adapter that
    /// translates each event into the kernel's
    /// `AuditEventKind::HttpProxyRequestExecuted` and writes it
    /// through the same `AuditSink` as every other audit event.
    /// Out-of-band callers (subprocess integration tests, ad-hoc
    /// tooling) that don't want translation can pass
    /// [`NoopAuditChannel`].
    pub async fn bind(
        backend: Arc<dyn CredentialBackend>,
        config: ProxyConfig,
        audit: Arc<dyn AuditChannel>,
    ) -> Result<Self, ProxyError> {
        let upstream = url::Url::parse(&config.upstream_url)
            .map_err(|_| ProxyError::BadUpstream(config.upstream_url.clone()))?;
        if upstream.scheme() != "http" && upstream.scheme() != "https" {
            return Err(ProxyError::BadUpstream(config.upstream_url.clone()));
        }
        let listener = tokio::net::TcpListener::bind(&config.listen_addr)
            .await
            .map_err(|source| ProxyError::Bind {
                addr: config.listen_addr.clone(),
                source,
            })?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client build");
        Ok(Self {
            listener,
            backend,
            config,
            upstream,
            stats: Arc::new(ProxyStats::default()),
            http,
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

    /// Borrow the underlying `Arc<ProxyStats>` so a caller (e.g. the
    /// kernel-side `CredentialProxyManager`) can keep reading counters
    /// AFTER `serve` has consumed the proxy. Call this BEFORE
    /// `tokio::spawn(proxy.serve())`.
    pub fn stats_handle(&self) -> Arc<ProxyStats> {
        Arc::clone(&self.stats)
    }

    /// Run the accept loop until the future is dropped.
    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _peer)) => {
                    self.stats
                        .connections_served
                        .fetch_add(1, Ordering::Relaxed);
                    let backend = self.backend.clone();
                    let config = self.config.clone();
                    let stats = self.stats.clone();
                    let upstream = self.upstream.clone();
                    let http = self.http.clone();
                    let audit = Arc::clone(&self.audit);
                    tokio::spawn(async move {
                        if let Err(e) =
                            serve_one(stream, backend, config, upstream, http, stats, audit).await
                        {
                            tracing::warn!(error = %e, "http proxy connection ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "http proxy accept failed");
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-connection driver
// ---------------------------------------------------------------------------

const MAX_REQUEST_BYTES: usize = 1024 * 1024; // 1 MiB cap on inbound bodies.

async fn serve_one(
    mut client_stream: tokio::net::TcpStream,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    upstream: url::Url,
    http: reqwest::Client,
    stats: Arc<ProxyStats>,
    audit: Arc<dyn AuditChannel>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = Vec::with_capacity(8 * 1024);
    let mut tmp = [0u8; 4096];

    // Step 1: read until end-of-headers.
    let header_end = loop {
        let n = client_stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_REQUEST_BYTES {
            return write_error(&mut client_stream, 431, "Request Header Fields Too Large").await;
        }
        if let Some(end) = find_header_end(&buf) {
            break end;
        }
    };

    // Step 2: parse the request line + headers.
    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers_buf);
    let parse_status = req
        .parse(&buf[..header_end])
        .unwrap_or(httparse::Status::Partial);
    let _ = parse_status;

    let method = req.method.unwrap_or("GET").to_ascii_uppercase();
    let raw_path = req.path.unwrap_or("/").to_owned();

    // Step 3: restriction checks.
    if !config.restrictions.allows_method(&method) {
        stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        audit.emit(audit_request_executed(
            &config, &method, &raw_path, 405, true,
        ));
        return write_error(&mut client_stream, 405, "Method Not Allowed").await;
    }
    if !config.restrictions.allows_path(&raw_path) {
        stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        audit.emit(audit_request_executed(
            &config, &method, &raw_path, 403, true,
        ));
        return write_error(&mut client_stream, 403, "Forbidden by RAXIS policy").await;
    }
    if request_attempts_websocket_upgrade(&req) {
        stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        audit.emit(audit_request_executed(
            &config, &method, &raw_path, 400, true,
        ));
        return write_error(&mut client_stream, 400, "Upgrade not supported").await;
    }

    // Step 4: capture content-length so we know how much body to read.
    let content_length: usize = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    if content_length > MAX_REQUEST_BYTES {
        return write_error(&mut client_stream, 413, "Payload Too Large").await;
    }

    // Step 5: read remaining body, if any.
    let mut body = Vec::with_capacity(content_length);
    let body_already = buf.len().saturating_sub(header_end);
    body.extend_from_slice(&buf[header_end..header_end + body_already]);
    while body.len() < content_length {
        let n = client_stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    // Step 6: resolve credential + forward.
    let cred = match backend.resolve(&config.credential_name, config.consumer.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, name = %config.credential_name,
                "http proxy credential resolution failed");
            return write_error(&mut client_stream, 502, "credential resolution failed").await;
        }
    };
    let cred_str = match cred.as_utf8() {
        Some(s) => s,
        None => return write_error(&mut client_stream, 502, "credential is not valid UTF-8").await,
    };

    let target = compose_target(&upstream, &raw_path);
    let mut request_builder = match method.as_str() {
        "GET" => http.get(&target),
        "HEAD" => http.head(&target),
        "POST" => http.post(&target),
        "PUT" => http.put(&target),
        "PATCH" => http.patch(&target),
        "DELETE" => http.delete(&target),
        other => http.request(
            reqwest::Method::from_bytes(other.as_bytes()).unwrap_or(reqwest::Method::GET),
            &target,
        ),
    };

    // Forward agent-supplied headers EXCEPT those we replace.
    for h in req.headers.iter().filter(|h| !h.name.is_empty()) {
        let n = h.name;
        if n.eq_ignore_ascii_case("host")
            || n.eq_ignore_ascii_case("authorization")
            || n.eq_ignore_ascii_case("connection")
            || n.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if let Ok(v) = std::str::from_utf8(h.value) {
            request_builder = request_builder.header(n, v);
        }
    }
    // Inject auth.
    let auth_value = match &config.auth_mode {
        AuthMode::Bearer => format!("Bearer {cred_str}"),
        AuthMode::Basic { user } => {
            let raw = format!("{user}:{cred_str}");
            format!("Basic {}", base64_encode(raw.as_bytes()))
        }
    };
    request_builder = request_builder.header("Authorization", auth_value);
    if !body.is_empty() {
        request_builder = request_builder.body(body);
    }

    let resp = match request_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, target = %target,
                "http proxy upstream request failed");
            return write_error(&mut client_stream, 502, "upstream request failed").await;
        }
    };

    // Step 7: write response back. INV-CREDPROXY-HTTP-BOUNDED-RESPONSE-01 —
    // stream the upstream body in chunks and bound the total at
    // `MAX_REQUEST_BYTES`. The previous shape called `resp.bytes()` which
    // buffers the full body in memory regardless of size, so a hostile or
    // buggy upstream returning a multi-GiB body could OOM the proxy on
    // behalf of a single in-VM caller.
    let status = resp.status();
    let headers = resp.headers().clone();
    let body_bytes: Vec<u8> = {
        let mut buf: Vec<u8> = Vec::new();
        let mut response_stream = resp;
        let mut oversize = false;
        loop {
            match response_stream.chunk().await {
                Ok(Some(chunk)) => {
                    if buf.len().saturating_add(chunk.len()) > MAX_REQUEST_BYTES {
                        oversize = true;
                        break;
                    }
                    buf.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(error = %e, target = %target,
                        "http proxy upstream chunked read failed");
                    return write_error(&mut client_stream, 502, "upstream read failed").await;
                }
            }
        }
        if oversize {
            tracing::warn!(
                target = %target,
                cap = MAX_REQUEST_BYTES,
                "http proxy upstream response exceeded cap"
            );
            return write_error(&mut client_stream, 502, "upstream response too large").await;
        }
        buf
    };
    stats.requests_forwarded.fetch_add(1, Ordering::Relaxed);
    stats
        .bytes_out
        .fetch_add(body_bytes.len() as u64, Ordering::Relaxed);
    audit.emit(audit_request_executed(
        &config,
        &method,
        &raw_path,
        status.as_u16(),
        false,
    ));

    let mut out = Vec::with_capacity(64 + body_bytes.len());
    out.extend_from_slice(
        format!(
            "HTTP/1.1 {} {}\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("OK")
        )
        .as_bytes(),
    );
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("transfer-encoding")
            || n.eq_ignore_ascii_case("connection")
            || n.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
        }
    }
    out.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body_bytes.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&body_bytes);

    client_stream.write_all(&out).await?;
    client_stream.shutdown().await?;
    Ok(())
}

fn request_attempts_websocket_upgrade(req: &httparse::Request) -> bool {
    req.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("upgrade")
            && std::str::from_utf8(h.value)
                .map(|s| s.to_ascii_lowercase().contains("websocket"))
                .unwrap_or(false)
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn compose_target(upstream: &url::Url, agent_path: &str) -> String {
    // The kernel pins the upstream URL; the agent's path is appended
    // after the upstream's path. Query strings on the agent's path
    // pass through verbatim.
    let mut target = upstream.clone();
    let upstream_path = upstream.path().trim_end_matches('/');
    let agent_trimmed = agent_path.trim_start_matches('/');
    let combined = if agent_trimmed.is_empty() {
        upstream_path.to_owned()
    } else {
        format!("{upstream_path}/{agent_trimmed}")
    };
    // Split path?query.
    if let Some((path, query)) = combined.split_once('?') {
        target.set_path(path);
        target.set_query(Some(query));
    } else {
        target.set_path(&combined);
        target.set_query(None);
    }
    target.to_string()
}

async fn write_error(
    s: &mut tokio::net::TcpStream,
    code: u16,
    reason: &str,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let body = format!("{{\"error\":\"{reason}\"}}");
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len(),
    );
    s.write_all(resp.as_bytes()).await?;
    s.shutdown().await?;
    Ok(())
}

fn audit_request_executed(
    config: &ProxyConfig,
    method: &str,
    path: &str,
    status: u16,
    blocked: bool,
) -> AuditEvent {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(method.as_bytes());
    h.update(b" ");
    h.update(path.as_bytes());
    let sha = hex::encode(h.finalize());
    AuditEvent::HttpProxyRequestExecuted {
        timestamp_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        consumer: config.consumer.clone(),
        credential: config.credential_name.clone(),
        method: method.to_owned(),
        path: path.to_owned(),
        path_sha256: sha,
        status_code: status,
        blocked,
    }
}

/// Audit event surface emitted by this crate. Names match
/// `credential-proxy.md §3` for the HTTP family. The kernel is
/// responsible for translating these into `AuditEventKind`.
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// One forwarded (or rejected) request.
    HttpProxyRequestExecuted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer: OwnedConsumer,
        /// Credential name (never the value).
        credential: CredentialName,
        /// Request method.
        method: String,
        /// Request path.
        path: String,
        /// SHA-256 of `"<method> <path>"`.
        path_sha256: String,
        /// Status returned to the agent.
        status_code: u16,
        /// True if a restriction blocked this request.
        blocked: bool,
    },
}

// ---------------------------------------------------------------------------
// Tiny base64 — avoids pulling in the `base64` crate for one function.
// ---------------------------------------------------------------------------

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let chunks = input.chunks(3);
    for c in chunks {
        let (a, b, d) = match c.len() {
            3 => (c[0], c[1], c[2]),
            2 => (c[0], c[1], 0),
            1 => (c[0], 0, 0),
            _ => unreachable!(),
        };
        let n = ((a as u32) << 16) | ((b as u32) << 8) | (d as u32);
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        if c.len() >= 2 {
            out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if c.len() == 3 {
            out.push(CHARS[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn compose_target_appends_agent_path() {
        let up = url::Url::parse("https://api.example.com/v1").unwrap();
        assert_eq!(
            compose_target(&up, "/widgets"),
            "https://api.example.com/v1/widgets"
        );
        assert_eq!(
            compose_target(&up, "/widgets?count=10"),
            "https://api.example.com/v1/widgets?count=10"
        );
    }

    #[test]
    fn compose_target_handles_root() {
        let up = url::Url::parse("https://api.example.com/").unwrap();
        assert_eq!(compose_target(&up, "/"), "https://api.example.com/");
        assert_eq!(compose_target(&up, "/foo"), "https://api.example.com/foo");
    }

    #[test]
    fn find_header_end_locates_terminator() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(find_header_end(buf), Some(buf.len() - 4));
    }
}
