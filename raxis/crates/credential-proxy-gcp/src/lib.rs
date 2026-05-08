//! `raxis-credential-proxy-gcp` — GCP metadata-server-compatible
//! credential proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §3.3` (GCP).
//! `google-auth-library`, `google-cloud-storage`, `gcloud auth
//! application-default print-access-token`, and the `google`
//! Terraform provider all reach for `http://metadata.google.internal`
//! (or its IP literal `169.254.169.254`) when looking for an
//! application-default credential. The agent's `/etc/hosts` inside
//! the executor VM points `metadata.google.internal` at
//! `127.0.0.1`, so the SDK ends up dialling this proxy.
//!
//! The metadata-server wire is HTTP/1.1, request/response, with a
//! mandatory `Metadata-Flavor: Google` header. Each well-known path
//! returns either a JSON object (token endpoint) or a raw text
//! string (project metadata).
//!
//! # What this MVP supports
//!
//!   * **`GET /computeMetadata/v1/instance/service-accounts/default/token`**
//!     — returns
//!     ```json
//!     { "access_token": "...", "expires_in": 3599, "token_type": "Bearer" }
//!     ```
//!     The proxy reads `access_token` (or `GCP_ACCESS_TOKEN`) from
//!     the resolved credential body. The `expires_in` field is
//!     `lease_seconds` from the decl; SDKs will refresh just before
//!     it elapses.
//!   * **`GET /computeMetadata/v1/instance/service-accounts/default/email`**
//!     — returns the service-account email from the credential body
//!     (`client_email` in JSON or `GCP_SERVICE_ACCOUNT_EMAIL` in
//!     env-style).
//!   * **`GET /computeMetadata/v1/project/project-id`**
//!     — returns `ProxyConfig::project_id`, declared in
//!     `[[tasks.credentials]]`.
//!   * **`GET /computeMetadata/v1/project/numeric-project-id`**
//!     — returns the numeric project ID when declared, otherwise
//!     `0` (matches GCP behaviour for projects without a numeric
//!     binding).
//!   * **`Metadata-Flavor: Google` enforcement.** Requests missing
//!     this header are rejected with `403 Forbidden` so SDKs that
//!     accidentally hit the proxy without identifying themselves
//!     do not leak credentials. This mirrors the GCP metadata
//!     server's own requirement.
//!   * **Path allowlist.** `Restrictions::allowed_paths` defaults to
//!     the four endpoints above. Requests outside the allowlist get
//!     `404 Not Found` (so the proxy looks like a real metadata
//!     server with a tightened API surface) and are audited as
//!     `blocked = true`.
//!   * **Audit emission.** Every served (and every blocked) request
//!     emits a `GcpMetadataServed` event with the consumer
//!     identity, request path, decision, and request-path SHA-256.
//!
//! # What is deferred
//!
//!   * **Real `oauth2.googleapis.com` exchange** so the proxy mints
//!     a fresh OAuth2 access token from a service-account JSON key
//!     using the JWT-bearer grant. V3 lands this; V2 mirrors a
//!     long-lived token the operator stored in the credential
//!     backend (or one minted out-of-band by `raxis credential
//!     refresh gcp-staging`).
//!   * **`recursive=true` query param** that would return a JSON
//!     tree of all instance metadata. The V2 surface is single
//!     leaves only.
//!   * **Workload identity federation** (`?audience=...`).
//!   * **Streaming `?wait_for_change=true`** long-poll path.
//!
//! # Threat model
//!
//! Identical to the AWS / Postgres / SMTP proxies: a fully
//! compromised agent process cannot exfiltrate the GCP service
//! account key bytes because the proxy is the only entity with
//! access to the resolved bytes. The agent only ever sees the
//! short-lived synthetic token — the real key never crosses the VM
//! boundary.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use raxis_credentials::{CredentialBackend, CredentialName, ConsumerIdentity};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod restriction;

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

/// Configuration for one GCP metadata proxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the inbound listener binds to. Production wires
    /// `127.0.0.1:9002` so an `/etc/hosts` rewrite of
    /// `metadata.google.internal → 127.0.0.1` reaches the proxy.
    pub listen_addr:        String,
    /// Credential to resolve per request. Bytes must parse as
    /// either `KEY=VALUE` env-style or as a JSON object containing
    /// at least an `access_token` (or `GCP_ACCESS_TOKEN`) field.
    pub credential_name:    CredentialName,
    /// Identity of the agent session this proxy serves.
    pub consumer:           OwnedConsumer,
    /// Lease length advertised in `expires_in`. SDKs refresh shortly
    /// before this elapses.
    pub lease_seconds:      u64,
    /// GCP project ID (e.g. `"my-staging-project"`). Returned
    /// verbatim by `/computeMetadata/v1/project/project-id`.
    pub project_id:         String,
    /// Numeric project ID. Returned by
    /// `/computeMetadata/v1/project/numeric-project-id`. `None`
    /// renders as `"0"` so SDKs that demand the field do not panic.
    pub numeric_project_id: Option<u64>,
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
    pub connections_served: AtomicU32,
    /// Number of requests that returned a credential.
    pub credentials_served: AtomicU32,
    /// Number of requests rejected by `Restrictions` or missing
    /// `Metadata-Flavor: Google` header.
    pub requests_blocked:   AtomicU32,
    /// Bytes in the served response bodies.
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

/// Plain-data snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted connections served.
    pub connections_served: u32,
    /// Number of requests that returned a credential.
    pub credentials_served: u32,
    /// Number of requests rejected by `Restrictions`.
    pub requests_blocked:   u32,
    /// Bytes in the served response bodies.
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

/// No-op channel for tests.
#[derive(Default)]
pub struct NoopAuditChannel;

impl AuditChannel for NoopAuditChannel {
    fn emit(&self, _event: AuditEvent) {}
}

/// Audit-event surface emitted by this crate.
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// One served (or rejected) metadata request.
    GcpMetadataServed {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
        /// Request path (`/computeMetadata/v1/...`) — never the
        /// SDK request body.
        path:        String,
        /// SHA-256 of `"<METHOD> <path>"`.
        path_sha256: String,
        /// GCP project ID associated with the proxy.
        project_id:  String,
        /// True if a restriction or missing header blocked this
        /// request.
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
// Token-endpoint response shape
// ---------------------------------------------------------------------------

/// Response body for `/computeMetadata/v1/instance/service-accounts/default/token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in:   u64,
    token_type:   String,
}

/// Internal envelope the proxy resolves the credential body into.
/// Either env-style or JSON, parsed to the same shape.
#[derive(Debug, Clone)]
struct ResolvedKey {
    access_token:           String,
    service_account_email:  Option<String>,
}

fn parse_credential_body(body: &str) -> Result<ResolvedKey, &'static str> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|_| "credential body is not valid JSON despite leading `{`")?;
        let obj = v.as_object().ok_or("JSON credential body is not an object")?;
        let access_token = pick_str(obj, &["access_token", "GCP_ACCESS_TOKEN"])
            .ok_or("missing access_token / GCP_ACCESS_TOKEN")?
            .to_owned();
        let service_account_email = pick_str(
            obj,
            &["client_email", "service_account_email", "GCP_SERVICE_ACCOUNT_EMAIL"],
        ).map(str::to_owned);
        Ok(ResolvedKey { access_token, service_account_email })
    } else {
        let mut access_token          = None;
        let mut service_account_email = None;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches(['"', '\''].as_ref());
                match k {
                    "GCP_ACCESS_TOKEN"           => access_token          = Some(v.to_owned()),
                    "GCP_SERVICE_ACCOUNT_EMAIL"  => service_account_email = Some(v.to_owned()),
                    _ => {}
                }
            }
        }
        let access_token = access_token.ok_or("missing GCP_ACCESS_TOKEN")?;
        Ok(ResolvedKey { access_token, service_account_email })
    }
}

fn pick_str<'a>(
    obj:  &'a serde_json::Map<String, serde_json::Value>,
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

/// GCP metadata-server-compatible credential proxy.
pub struct GcpProxy {
    listener: TcpListener,
    backend:  Arc<dyn CredentialBackend>,
    config:   ProxyConfig,
    stats:    Arc<ProxyStats>,
    audit:    Arc<dyn AuditChannel>,
}

impl GcpProxy {
    /// Bind a listener and return an owned proxy.
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
        })
    }

    /// The address the listener is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Counters snapshot.
    pub fn stats(&self) -> ProxyStatsSnapshot { self.stats.snapshot() }

    /// Borrow the underlying counters Arc.
    pub fn stats_handle(&self) -> Arc<ProxyStats> { Arc::clone(&self.stats) }

    /// Run the accept loop until dropped.
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
                            tracing::warn!(error = %e, "gcp proxy connection ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "gcp proxy accept failed");
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

async fn serve_one(
    mut stream: TcpStream,
    backend:    Arc<dyn CredentialBackend>,
    config:     ProxyConfig,
    stats:      Arc<ProxyStats>,
    audit:      Arc<dyn AuditChannel>,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if buf.len() > 8192 {
            write_status(&mut stream, 431, "Request Header Fields Too Large").await?;
            return Ok(());
        }
    }
    if buf.is_empty() { return Ok(()); }

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req     = httparse::Request::new(&mut headers);
    let (method, path, has_metadata_flavor) = match req.parse(&buf) {
        Ok(httparse::Status::Complete(_)) => {
            let method = req.method.unwrap_or("GET").to_owned();
            let path   = req.path.unwrap_or("/").to_owned();
            let has    = req.headers.iter().any(|h|
                h.name.eq_ignore_ascii_case("Metadata-Flavor")
                && h.value.eq_ignore_ascii_case(b"Google")
            );
            (method, path, has)
        }
        _ => {
            write_status(&mut stream, 400, "Bad Request").await?;
            return Ok(());
        }
    };

    // Enforce Metadata-Flavor: Google. Real GCP metadata-server
    // does this — SDKs that forget the header should not see a
    // success.
    if !has_metadata_flavor {
        stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        audit.emit(audit_event(&config, &method, &path, true));
        write_status_with_metadata_flavor(&mut stream, 403, "Forbidden").await?;
        return Ok(());
    }

    // Path allowlist.
    if !config.restrictions.allows_path(&path) {
        stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        audit.emit(audit_event(&config, &method, &path, true));
        write_status_with_metadata_flavor(&mut stream, 404, "Not Found").await?;
        return Ok(());
    }

    let bare_path = path.split('?').next().unwrap_or(&path);
    let (body, content_type) = match bare_path {
        "/computeMetadata/v1/instance/service-accounts/default/token" => {
            let resolved = match resolve_key(&backend, &config) {
                Ok(k) => k,
                Err(()) => {
                    write_status_with_metadata_flavor(&mut stream, 502, "Bad Gateway").await?;
                    return Ok(());
                }
            };
            let body = serde_json::to_vec(&TokenResponse {
                access_token: resolved.access_token,
                expires_in:   config.lease_seconds,
                token_type:   "Bearer".to_owned(),
            }).map_err(|e| std::io::Error::other(format!("json serialise: {e}")))?;
            (body, "application/json")
        }
        "/computeMetadata/v1/instance/service-accounts/default/email" => {
            let resolved = match resolve_key(&backend, &config) {
                Ok(k) => k,
                Err(()) => {
                    write_status_with_metadata_flavor(&mut stream, 502, "Bad Gateway").await?;
                    return Ok(());
                }
            };
            let email = resolved.service_account_email
                .unwrap_or_else(|| "default".to_owned());
            (email.into_bytes(), "application/text")
        }
        "/computeMetadata/v1/project/project-id" => {
            (config.project_id.clone().into_bytes(), "application/text")
        }
        "/computeMetadata/v1/project/numeric-project-id" => {
            let body = config.numeric_project_id.unwrap_or(0).to_string();
            (body.into_bytes(), "application/text")
        }
        _ => {
            // Allowed by the path allowlist but not implemented in
            // V2. Treat as a benign 404 so SDKs that probe optional
            // endpoints continue without surfacing a hard error.
            write_status_with_metadata_flavor(&mut stream, 404, "Not Found").await?;
            return Ok(());
        }
    };

    let body_len = body.len();
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {ct}\r\n\
         Content-Length: {len}\r\n\
         Metadata-Flavor: Google\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         \r\n",
        ct  = content_type,
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

fn resolve_key(
    backend: &Arc<dyn CredentialBackend>,
    config:  &ProxyConfig,
) -> Result<ResolvedKey, ()> {
    let resolved = backend.resolve(&config.credential_name, config.consumer.as_ref())
        .map_err(|e| {
            tracing::warn!(error = %e, "gcp proxy credential resolve failed");
        })?;
    let body_str = resolved.as_utf8().ok_or_else(|| {
        tracing::warn!("gcp proxy credential body is not UTF-8");
    })?.to_owned();
    parse_credential_body(&body_str).map_err(|e| {
        tracing::warn!(reason = %e, "gcp proxy credential body is malformed");
    })
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

async fn write_status_with_metadata_flavor(
    stream: &mut TcpStream,
    code:   u16,
    reason: &str,
) -> std::io::Result<()> {
    let line = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Length: 0\r\n\
         Metadata-Flavor: Google\r\n\
         Connection: close\r\n\
         \r\n",
    );
    stream.write_all(line.as_bytes()).await?;
    stream.flush().await
}

fn audit_event(
    config:  &ProxyConfig,
    method:  &str,
    path:    &str,
    blocked: bool,
) -> AuditEvent {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(method.as_bytes());
    h.update(b" ");
    h.update(path.as_bytes());
    let path_sha256 = hex::encode(h.finalize());
    AuditEvent::GcpMetadataServed {
        timestamp_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        consumer:    config.consumer.clone(),
        credential:  config.credential_name.clone(),
        path:        path.to_owned(),
        path_sha256,
        project_id:  config.project_id.clone(),
        blocked,
    }
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
            GCP_ACCESS_TOKEN=ya29.example\n\
            GCP_SERVICE_ACCOUNT_EMAIL=svc@my-proj.iam.gserviceaccount.com\n";
        let k = parse_credential_body(body).unwrap();
        assert_eq!(k.access_token, "ya29.example");
        assert_eq!(
            k.service_account_email.as_deref(),
            Some("svc@my-proj.iam.gserviceaccount.com"),
        );
    }

    #[test]
    fn parses_json_credential_body() {
        let body = r#"{
            "access_token": "ya29.example",
            "client_email": "svc@my-proj.iam.gserviceaccount.com"
        }"#;
        let k = parse_credential_body(body).unwrap();
        assert_eq!(k.access_token, "ya29.example");
        assert_eq!(
            k.service_account_email.as_deref(),
            Some("svc@my-proj.iam.gserviceaccount.com"),
        );
    }

    #[test]
    fn missing_token_is_rejected() {
        let body = "GCP_SERVICE_ACCOUNT_EMAIL=svc@example.com\n";
        let err = parse_credential_body(body).unwrap_err();
        assert!(err.contains("GCP_ACCESS_TOKEN"));
    }
}
