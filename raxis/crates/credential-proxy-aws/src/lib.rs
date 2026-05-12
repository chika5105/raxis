//! `raxis-credential-proxy-aws` — AWS IMDS-compatible credential
//! proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §3.2` (AWS).
//! The agent's AWS SDK reads the
//! `AWS_CONTAINER_CREDENTIALS_FULL_URI` env var, dials the URL it
//! contains, and expects an HTTP `200 OK` body shaped like:
//!
//! ```json
//! {
//!   "AccessKeyId":     "AKIA...",
//!   "SecretAccessKey": "...",
//!   "Token":           "...",
//!   "Expiration":      "2026-05-08T12:00:00Z",
//!   "RoleArn":         "arn:aws:iam::123456789:role/raxis-staging-agent"
//! }
//! ```
//!
//! AWS SDKs cache the response and re-fetch shortly before the
//! `Expiration` timestamp. The proxy issues a fresh response every
//! request — `Expiration` is set to `now + lease_seconds` (default
//! 900 s) so any cached value is discarded after one slot.
//!
//! # What this MVP supports
//!
//!   * **`GET /creds`** (path can be tightened by `Restrictions::allowed_paths`).
//!     Returns the IAM container-credential-provider JSON shape the
//!     SDK expects.
//!   * **Per-request credential resolution.** Each `GET` resolves
//!     the credential through `CredentialBackend::resolve` so a
//!     rotation lands at the *next* SDK refresh — no daemon-level
//!     caching, no in-process leases beyond the lifetime of one
//!     request.
//!   * **Static-credential payload.** The credential value is a
//!     UTF-8 envelope (env-style or JSON) declaring the IAM access
//!     key id, secret access key, and an optional session token.
//!     The proxy parses both shapes:
//!     ```env
//!     AWS_ACCESS_KEY_ID=AKIA...
//!     AWS_SECRET_ACCESS_KEY=...
//!     AWS_SESSION_TOKEN=...
//!     ```
//!     ```json
//!     { "AccessKeyId": "AKIA...", "SecretAccessKey": "...", "Token": "..." }
//!     ```
//!   * **`role_arn` echo.** The decl carries an optional `role_arn`
//!     the proxy mirrors back into the response. Useful for SDKs
//!     and audit chains that record the assumed role; the proxy
//!     does NOT call `sts:AssumeRole` itself in V2 (see deferrals).
//!   * **Path allowlist.** `Restrictions::allowed_paths` defaults
//!     to `["/creds"]`. Requests outside the allowlist get
//!     `403 Forbidden` and are audited as `blocked = true`.
//!   * **Audit emission.** Every served (and every blocked)
//!     request emits an `AwsCredentialServed` event with the
//!     consumer identity, role ARN, decision, and request-path
//!     SHA-256.
//!
//! # V3 upstream forwarding (landed)
//!
//! When `ProxyConfig::forwarding = Some(...)` is wired
//! through the plan TOML's `[tasks.credentials.forwarding]`
//! block, the proxy drives a real `sts:AssumeRole` against
//! the closed-allowlist STS endpoint and serves the
//! upstream-issued short-lived credential to the in-VM
//! SDK. The hand-rolled SigV4 signer lives in
//! `raxis-credential-proxy-cloud-shared`; the AssumeRole XML
//! response parser + cache + audit emission lives in
//! `forwarding.rs`. See
//! `specs/v3/cloud-proxy-forwarding.md §2.1, §5, §6.1`.
//!
//! When `forwarding` is `None` (the default), the V2 emulator
//! path below runs unchanged.
//!
//! # What is deferred
//!
//!   * **Real `sts:AssumeRole` round-trip** — landed in V3 via
//!     [`ForwardingConfig`] / [`AwsProxy::bind_v3`]. V2 mints
//!     synthetic responses from the long-lived IAM key the
//!     operator stores in the credential backend.
//!     Defence-in-depth still works — the IAM key itself never
//!     reaches the VM.
//!   * **IMDSv2 token dance** (`PUT /latest/api/token` →
//!     `GET /latest/meta-data/iam/security-credentials/...`). The
//!     V2 wire is the `AWS_CONTAINER_CREDENTIALS_FULL_URI` shape,
//!     which is strictly simpler and is what every modern SDK
//!     prefers anyway.
//!   * **Region / regional STS endpoint awareness.** The proxy
//!     always returns whatever `region` the decl declared; AWS
//!     SDKs that derive region from EC2 metadata are NOT
//!     supported in V2 — the operator must set
//!     `AWS_DEFAULT_REGION` (or `AWS_REGION`) explicitly in the
//!     plan's environment block.
//!
//! # Threat model
//!
//! Identical to the postgres / smtp / http / redis proxies: a
//! fully-compromised agent process cannot exfiltrate the IAM key
//! material because the proxy is the only entity with access to
//! the resolved bytes. The agent only ever sees the
//! short-lived synthetic response — the real IAM key never crosses
//! the VM boundary.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use raxis_audit_tools::AuditSink;
use raxis_credential_proxy_cloud_shared::{CloudHttpClient, TokenCache};
use raxis_credentials::{CredentialBackend, CredentialName, ConsumerIdentity};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod forwarding;
pub mod restriction;

pub use forwarding::{AWS_XML_CONTENT_TYPE, ForwardOutcome, ForwardingConfig, StsCacheValue};
pub use restriction::Restrictions;

// ---------------------------------------------------------------------------
// OwnedConsumer — local mirror.
// ---------------------------------------------------------------------------

/// Owned form of `ConsumerIdentity`.
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

/// Configuration for one AWS-IMDS proxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the inbound listener binds to. Production wires
    /// `127.0.0.1:0`.
    pub listen_addr:     String,
    /// Credential to resolve per request. Bytes must parse as
    /// either `KEY=VALUE` env-style or as a JSON object with
    /// `AccessKeyId` + `SecretAccessKey` (and optional `Token`).
    pub credential_name: CredentialName,
    /// Identity of the agent session this proxy serves.
    pub consumer:        OwnedConsumer,
    /// Lease length the proxy advertises in `Expiration`. SDKs
    /// will refresh shortly before this window closes.
    pub lease_seconds:   u64,
    /// Optional IAM role ARN the proxy mirrors back into the
    /// response body. Operator-declared in `[[tasks.credentials]]`.
    pub role_arn:        Option<String>,
    /// Effective restriction set parsed out of
    /// `[tasks.credentials.restrictions]`.
    pub restrictions:    Restrictions,
    /// V3 forwarding configuration. When `Some`, the proxy
    /// drives a real `sts:AssumeRole` exchange against the
    /// closed-allowlist STS endpoint instead of mirroring the
    /// long-lived IAM key. See `specs/v3/cloud-proxy-forwarding.md`.
    pub forwarding:      Option<ForwardingConfig>,
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Counters surfaced for `CredentialProxyStopped`.
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Number of accepted connections served.
    pub connections_served: AtomicU32,
    /// Number of requests that returned a credential.
    pub credentials_served: AtomicU32,
    /// Number of requests rejected by `Restrictions`.
    pub requests_blocked:   AtomicU32,
    /// Bytes in the served credential bodies.
    pub bytes_served:       AtomicU64,
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served: self.connections_served.load(Ordering::Relaxed),
            credentials_served: self.credentials_served.load(Ordering::Relaxed),
            requests_blocked:   self.requests_blocked  .load(Ordering::Relaxed),
            bytes_served:       self.bytes_served      .load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot of the counters at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted connections served.
    pub connections_served: u32,
    /// Number of requests that returned a credential.
    pub credentials_served: u32,
    /// Number of requests rejected by `Restrictions`.
    pub requests_blocked:   u32,
    /// Bytes in the served credential bodies.
    pub bytes_served:       u64,
}

// ---------------------------------------------------------------------------
// Audit channel
// ---------------------------------------------------------------------------

/// Sink the kernel-side `CredentialProxyManager` plugs into.
pub trait AuditChannel: Send + Sync {
    /// Record one decision.
    fn emit(&self, event: AuditEvent);
}

/// No-op channel for tests / out-of-band callers.
#[derive(Default)]
pub struct NoopAuditChannel;

impl AuditChannel for NoopAuditChannel {
    fn emit(&self, _event: AuditEvent) {}
}

/// Audit-event surface emitted by this crate.
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// One served (or rejected) credential request.
    AwsCredentialServed {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
        /// Path the agent requested (`/creds`, etc.) — never the
        /// SDK request body.
        path:        String,
        /// SHA-256 of `"<METHOD> <path>"` so reviewers can
        /// fingerprint the call shape.
        path_sha256: String,
        /// IAM role ARN mirrored to the SDK response (or empty
        /// if not declared).
        role_arn:    String,
        /// Operator-declared service scope. Echoed verbatim from
        /// `Restrictions::allowed_services`. Empty when no
        /// service-level intent was declared. Used by reviewers
        /// and `raxis doctor` to cross-check the egress allowlist.
        /// V2.3 enforcement is declarative + TProxy; V3 lands the
        /// SigV4 inspector.
        allowed_services: Vec<String>,
        /// Operator-declared region scope. Echoed verbatim from
        /// `Restrictions::allowed_regions`. Same enforcement
        /// model as `allowed_services`.
        allowed_regions:  Vec<String>,
        /// True if a restriction blocked this request.
        blocked:     bool,
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
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

// ---------------------------------------------------------------------------
// SDK response shape
// ---------------------------------------------------------------------------

/// IAM container-credential-provider response body. Field names
/// MUST match exactly — the AWS SDK looks them up by name.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerCredentialResponse {
    access_key_id:     String,
    secret_access_key: String,
    /// Optional session token (only present when the upstream
    /// envelope carries one).
    #[serde(skip_serializing_if = "Option::is_none")]
    token:             Option<String>,
    /// ISO-8601 / RFC 3339 expiration timestamp.
    expiration:        String,
    /// IAM role ARN. When the decl does not declare one we still
    /// emit an empty string so SDKs that read the field do not
    /// trip on `null`.
    role_arn:          String,
}

/// Internal envelope the proxy resolves the credential into. The
/// upstream credential body either parses as env-style
/// (`KEY=VALUE\nKEY=VALUE`) or as a JSON object with the same
/// `AccessKeyId` / `SecretAccessKey` / `Token` fields.
#[derive(Debug, Clone)]
struct ResolvedKey {
    access_key_id:     String,
    secret_access_key: String,
    token:             Option<String>,
}

fn parse_credential_body(body: &str) -> Result<ResolvedKey, &'static str> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        // JSON form.
        let v: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|_| "credential body is not valid JSON despite leading `{`")?;
        let obj = v.as_object().ok_or("JSON credential body is not an object")?;
        let access_key_id = pick_str(obj, &["AccessKeyId", "aws_access_key_id"])
            .ok_or("missing AccessKeyId / aws_access_key_id")?
            .to_owned();
        let secret_access_key = pick_str(obj, &["SecretAccessKey", "aws_secret_access_key"])
            .ok_or("missing SecretAccessKey / aws_secret_access_key")?
            .to_owned();
        let token = pick_str(obj, &["Token", "SessionToken", "aws_session_token"])
            .map(str::to_owned);
        Ok(ResolvedKey { access_key_id, secret_access_key, token })
    } else {
        // Env-style form.
        let mut access_key_id     = None;
        let mut secret_access_key = None;
        let mut token             = None;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches(['"', '\''].as_ref());
                match k {
                    "AWS_ACCESS_KEY_ID"     => access_key_id     = Some(v.to_owned()),
                    "AWS_SECRET_ACCESS_KEY" => secret_access_key = Some(v.to_owned()),
                    "AWS_SESSION_TOKEN"     => token             = Some(v.to_owned()),
                    _ => {}
                }
            }
        }
        let access_key_id     = access_key_id.ok_or("missing AWS_ACCESS_KEY_ID")?;
        let secret_access_key = secret_access_key.ok_or("missing AWS_SECRET_ACCESS_KEY")?;
        Ok(ResolvedKey { access_key_id, secret_access_key, token })
    }
}

fn pick_str<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<&'a str> {
    for k in keys {
        if let Some(v) = obj.get(*k).and_then(|v| v.as_str()) {
            return Some(v);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Library entry point
// ---------------------------------------------------------------------------

/// AWS-IMDS-compatible credential proxy.
pub struct AwsProxy {
    listener:    TcpListener,
    backend:     Arc<dyn CredentialBackend>,
    config:      ProxyConfig,
    stats:       Arc<ProxyStats>,
    audit:       Arc<dyn AuditChannel>,
    /// V3 forwarding glue — only used when
    /// [`ProxyConfig::forwarding`] is `Some`.
    audit_sink:  Option<Arc<dyn AuditSink>>,
    http_client: Option<Arc<CloudHttpClient>>,
    token_cache: Option<Arc<TokenCache<StsCacheValue>>>,
}

impl AwsProxy {
    /// Bind a listener and return an owned proxy. V2-only
    /// constructor — see [`Self::bind_v3`] for the
    /// V3-cloud-forwarding-aware constructor that wires the
    /// HTTP client, token cache, and audit sink.
    pub async fn bind(
        backend: Arc<dyn CredentialBackend>,
        config:  ProxyConfig,
        audit:   Arc<dyn AuditChannel>,
    ) -> Result<Self, ProxyError> {
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
            audit_sink:  None,
            http_client: None,
            token_cache: None,
        })
    }

    /// Bind a listener with V3 forwarding plumbing. When
    /// [`ProxyConfig::forwarding`] is `Some`, the per-request
    /// path drives a real `sts:AssumeRole` exchange and emits
    /// the four V3 audit events through `audit_sink` (in
    /// addition to the existing V2 `AwsCredentialServed`).
    pub async fn bind_v3(
        backend:     Arc<dyn CredentialBackend>,
        config:      ProxyConfig,
        audit:       Arc<dyn AuditChannel>,
        audit_sink:  Arc<dyn AuditSink>,
        http_client: Arc<CloudHttpClient>,
        token_cache: Arc<TokenCache<StsCacheValue>>,
    ) -> Result<Self, ProxyError> {
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
            audit_sink:  Some(audit_sink),
            http_client: Some(http_client),
            token_cache: Some(token_cache),
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

    /// Borrow the underlying counters Arc.
    pub fn stats_handle(&self) -> Arc<ProxyStats> {
        Arc::clone(&self.stats)
    }

    /// Run the accept loop until the future is dropped.
    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _peer)) => {
                    self.stats.connections_served.fetch_add(1, Ordering::Relaxed);
                    let backend     = Arc::clone(&self.backend);
                    let config      = self.config.clone();
                    let stats       = Arc::clone(&self.stats);
                    let audit       = Arc::clone(&self.audit);
                    let audit_sink  = self.audit_sink.clone();
                    let http_client = self.http_client.clone();
                    let token_cache = self.token_cache.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_one(
                            stream, backend, config, stats, audit,
                            audit_sink, http_client, token_cache,
                        ).await {
                            tracing::warn!(error = %e, "aws proxy connection ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "aws proxy accept failed");
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-connection driver. One inbound HTTP/1.1 request per connection;
// we never pipeline.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn serve_one(
    mut stream:  TcpStream,
    backend:     Arc<dyn CredentialBackend>,
    config:      ProxyConfig,
    stats:       Arc<ProxyStats>,
    audit:       Arc<dyn AuditChannel>,
    audit_sink:  Option<Arc<dyn AuditSink>>,
    http_client: Option<Arc<CloudHttpClient>>,
    token_cache: Option<Arc<TokenCache<StsCacheValue>>>,
) -> std::io::Result<()> {
    // Read request line + headers.
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if buf.len() > 8192 {
            // Defence: refuse oversized headers. The IMDS surface
            // does not need bodies; keep the bound tight.
            write_status(&mut stream, 431, "Request Header Fields Too Large").await?;
            return Ok(());
        }
    }
    if buf.is_empty() { return Ok(()); }

    // Parse with httparse.
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req     = httparse::Request::new(&mut headers);
    let (method, path) = match req.parse(&buf) {
        Ok(httparse::Status::Complete(_)) => {
            (
                req.method.unwrap_or("GET").to_owned(),
                req.path.unwrap_or("/").to_owned(),
            )
        }
        _ => {
            write_status(&mut stream, 400, "Bad Request").await?;
            return Ok(());
        }
    };

    // Path allowlist.
    if !config.restrictions.allows_path(&path) {
        stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        audit.emit(audit_event(&config, &method, &path, true));
        write_status(&mut stream, 403, "Forbidden").await?;
        return Ok(());
    }

    // Resolve the credential.
    let resolved = match backend.resolve(&config.credential_name, config.consumer.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "aws proxy credential resolve failed");
            write_status(&mut stream, 502, "Bad Gateway").await?;
            return Ok(());
        }
    };
    let body_str = match resolved.as_utf8() {
        Some(s) => s.to_owned(),
        None    => {
            tracing::warn!("aws proxy credential body is not UTF-8");
            write_status(&mut stream, 502, "Bad Gateway").await?;
            return Ok(());
        }
    };
    let key = match parse_credential_body(&body_str) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(reason = %e, "aws proxy credential body is malformed");
            write_status(&mut stream, 502, "Bad Gateway").await?;
            return Ok(());
        }
    };

    // V3 branch — when forwarding is wired, drive a real
    // sts:AssumeRole exchange through the closed-allowlist
    // HTTPS client and serve the upstream-issued short-lived
    // credentials (or pass through the canonical AWS XML error
    // envelope on failure). Cache-hit / aging-window
    // semantics live inside the helper.
    if let (Some(fwd), Some(sink), Some(http), Some(cache)) = (
        config.forwarding.as_ref(),
        audit_sink.as_ref(),
        http_client.as_ref(),
        token_cache.as_ref(),
    ) {
        let session_id = format!("{}:{}", config.consumer.kind, config.consumer.id);
        let outcome = forwarding::forward_or_serve_from_cache(
            fwd, http, cache, sink,
            &session_id,
            config.credential_name.as_str(),
            &key.access_key_id,
            &key.secret_access_key,
        ).await;
        match outcome {
            ForwardOutcome::Ok(body) => {
                write_full_response(
                    &mut stream,
                    200, "OK",
                    "application/json",
                    &body,
                ).await?;
                stats.credentials_served.fetch_add(1, Ordering::Relaxed);
                stats.bytes_served.fetch_add(body.len() as u64, Ordering::Relaxed);
                audit.emit(audit_event(&config, &method, &path, false));
            }
            ForwardOutcome::UpstreamEnvelope { status, body } => {
                let reason = upstream_status_reason_phrase(status);
                write_full_response(
                    &mut stream,
                    status, reason,
                    AWS_XML_CONTENT_TYPE,
                    &body,
                ).await?;
                stats.bytes_served.fetch_add(body.len() as u64, Ordering::Relaxed);
                // V3 envelope passthrough is NOT a V2 "blocked"
                // — the V2 audit event is omitted on the
                // forwarding-error path so the V2 wire shape is
                // not muddied with statuses that V2 never
                // produced. The V3 events from
                // `forward_or_serve_from_cache` provide the
                // structured audit record.
            }
        }
        return Ok(());
    }

    // V2 emulator path (forwarding disabled).
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let expiration = format_iso8601_z(now + config.lease_seconds);
    let resp_body = ContainerCredentialResponse {
        access_key_id:     key.access_key_id,
        secret_access_key: key.secret_access_key,
        token:             key.token,
        expiration,
        role_arn:          config.role_arn.clone().unwrap_or_default(),
    };
    let body = serde_json::to_vec(&resp_body)
        .map_err(|e| std::io::Error::other(format!("json serialise: {e}")))?;
    let body_len = body.len();

    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         \r\n",
        len = body_len,
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    stats.credentials_served.fetch_add(1, Ordering::Relaxed);
    stats.bytes_served.fetch_add(body_len as u64, Ordering::Relaxed);
    audit.emit(audit_event(&config, &method, &path, false));
    Ok(())
}

/// Map an HTTP status code to its conventional reason phrase
/// for the lines the V3 path emits. The status-and-phrase pair
/// matches what AWS' real STS endpoint emits so SDKs parse the
/// envelope as-is.
fn upstream_status_reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ if (200..300).contains(&status) => "OK",
        _ if (400..500).contains(&status) => "Client Error",
        _ if (500..600).contains(&status) => "Server Error",
        _ => "Status",
    }
}

/// Common helper for writing a full HTTP/1.1 response (line +
/// headers + body) in one shot. Used by both the V2 and V3
/// success / error paths.
async fn write_full_response(
    stream:       &mut TcpStream,
    status:       u16,
    reason:       &str,
    content_type: &str,
    body:         &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len(),
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

async fn write_status(
    stream: &mut TcpStream,
    code:   u16,
    reason: &str,
) -> std::io::Result<()> {
    let line = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    stream.write_all(line.as_bytes()).await?;
    stream.flush().await
}

fn audit_event(
    config: &ProxyConfig,
    method: &str,
    path:   &str,
    blocked: bool,
) -> AuditEvent {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(method.as_bytes());
    h.update(b" ");
    h.update(path.as_bytes());
    let path_sha256 = hex::encode(h.finalize());
    AuditEvent::AwsCredentialServed {
        timestamp_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        consumer:    config.consumer.clone(),
        credential:  config.credential_name.clone(),
        path:        path.to_owned(),
        path_sha256,
        role_arn:    config.role_arn.clone().unwrap_or_default(),
        allowed_services: config.restrictions.allowed_services.clone(),
        allowed_regions:  config.restrictions.allowed_regions.clone(),
        blocked,
    }
}

/// Format `secs_since_epoch` as an RFC 3339 / ISO 8601 timestamp
/// with a `Z` suffix. AWS SDKs accept this exact shape.
fn format_iso8601_z(secs_since_epoch: u64) -> String {
    // Compute civil date directly so we don't need `chrono`.
    let (year, month, day, hour, min, sec) = unix_to_civil(secs_since_epoch);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert unix seconds to (year, month, day, hour, minute, second)
/// in UTC. Handles the leap-year rules through Howard Hinnant's
/// "civil_from_days" algorithm — the canonical const-foldable
/// translation used by every modern date lib. Domain: 1970-01-01
/// onward through year 9999.
fn unix_to_civil(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days  = (secs / 86_400) as i64;
    let secs_of_day = (secs % 86_400) as u32;
    let hour = secs_of_day / 3600;
    let min  = (secs_of_day / 60) % 60;
    let sec  = secs_of_day % 60;

    // Howard Hinnant — civil_from_days, days from 1970-01-01.
    let z = days + 719_468;
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_style_credential_body() {
        let body = "\
            AWS_ACCESS_KEY_ID=AKIAEXAMPLE\n\
            AWS_SECRET_ACCESS_KEY=secret\n";
        let k = parse_credential_body(body).unwrap();
        assert_eq!(k.access_key_id,     "AKIAEXAMPLE");
        assert_eq!(k.secret_access_key, "secret");
        assert_eq!(k.token, None);
    }

    #[test]
    fn parses_env_style_with_session_token() {
        let body = "\
            AWS_ACCESS_KEY_ID=AKIAEXAMPLE\n\
            AWS_SECRET_ACCESS_KEY=secret\n\
            AWS_SESSION_TOKEN=tok\n";
        let k = parse_credential_body(body).unwrap();
        assert_eq!(k.token.as_deref(), Some("tok"));
    }

    #[test]
    fn parses_json_credential_body_pascal_case() {
        let body = r#"{
            "AccessKeyId":     "AKIAEXAMPLE",
            "SecretAccessKey": "secret",
            "Token":           "tok"
        }"#;
        let k = parse_credential_body(body).unwrap();
        assert_eq!(k.access_key_id,     "AKIAEXAMPLE");
        assert_eq!(k.secret_access_key, "secret");
        assert_eq!(k.token.as_deref(),  Some("tok"));
    }

    #[test]
    fn parses_json_credential_body_snake_case() {
        let body = r#"{
            "aws_access_key_id":     "AKIAEXAMPLE",
            "aws_secret_access_key": "secret",
            "aws_session_token":     "tok"
        }"#;
        let k = parse_credential_body(body).unwrap();
        assert_eq!(k.access_key_id,     "AKIAEXAMPLE");
        assert_eq!(k.token.as_deref(),  Some("tok"));
    }

    #[test]
    fn malformed_json_is_rejected_with_clear_error() {
        let body = "{ not really json";
        let err = parse_credential_body(body).unwrap_err();
        assert!(err.contains("JSON"));
    }

    #[test]
    fn missing_required_env_field_is_rejected() {
        let body = "AWS_ACCESS_KEY_ID=AKIAEXAMPLE\n";
        let err = parse_credential_body(body).unwrap_err();
        assert!(err.contains("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn iso8601_z_format_pins_to_canonical_shape() {
        // 2026-01-01T00:00:00Z = 1_767_225_600
        assert_eq!(format_iso8601_z(1_767_225_600), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_z_round_trips_a_known_unix_timestamp() {
        // 2026-05-06T12:50:45Z = 1_778_071_845. Verified by:
        //   python3 -c "import datetime as d;
        //               print(d.datetime.utcfromtimestamp(1778071845)
        //                       .strftime('%Y-%m-%dT%H:%M:%SZ'))"
        let s = format_iso8601_z(1_778_071_845);
        assert_eq!(s, "2026-05-06T12:50:45Z");
    }

    #[test]
    fn iso8601_z_handles_a_leap_year_boundary() {
        // 2024-02-29T12:00:00Z = 1_709_208_000 (leap day).
        let s = format_iso8601_z(1_709_208_000);
        assert_eq!(s, "2024-02-29T12:00:00Z");
    }
}
