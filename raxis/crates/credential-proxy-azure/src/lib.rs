//! `raxis-credential-proxy-azure` — Azure IMDS-compatible
//! credential proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §3.4`
//! (Azure). The Azure SDK (`azure-identity` Python, `Azure.Identity`
//! .NET, `@azure/identity` Node, the `az` CLI's `ManagedIdentityCredential`
//! flow) reaches for `http://169.254.169.254/metadata/identity/oauth2/token`
//! when running on a VM with managed identity. The agent's
//! `/etc/hosts` (or its iptables NAT rule) inside the executor VM
//! redirects that IP literal to `127.0.0.1`, so the SDK ends up
//! dialling this proxy.
//!
//! The IMDS wire is HTTP/1.1 GET with a mandatory `Metadata: true`
//! header. The response body is JSON shaped like:
//!
//! ```json
//! {
//!   "access_token":   "eyJ0eXAi...",
//!   "client_id":      "11111111-2222-3333-4444-555555555555",
//!   "expires_in":     "3599",
//!   "expires_on":     "1577919900",
//!   "ext_expires_in": "3599",
//!   "not_before":     "1577916300",
//!   "resource":       "https://management.azure.com/",
//!   "token_type":     "Bearer"
//! }
//! ```
//!
//! Numeric fields are stringified (`"3599"` not `3599`) — Azure SDKs
//! parse them as strings, so we mirror the wire shape exactly.
//!
//! # What this MVP supports
//!
//!   * **`GET /metadata/identity/oauth2/token`** with required
//!     `?resource=<uri>` query parameter. Returns the JSON body
//!     above. The `access_token` is read from the resolved
//!     credential body — see `parse_credential_body`.
//!   * **`Metadata: true` enforcement.** Requests missing this
//!     header get `400 Bad Request` (matches real IMDS behaviour)
//!     and are audited as `blocked = true`.
//!   * **Per-resource allowlist.** `Restrictions::allowed_resources`
//!     declares which Azure resource URIs the proxy will mint
//!     tokens for. Requests for resources outside the allowlist get
//!     `400 Bad Request` with the IMDS-shaped error body. This is
//!     stricter than path allowlists in other proxies because Azure
//!     IMDS uses a single path for all resources — scoping happens
//!     through the `resource` query parameter.
//!   * **Audit emission.** Every served (and every blocked) request
//!     emits an `AzureTokenServed` event with the consumer
//!     identity, requested resource, and decision.
//!
//! # V3 upstream forwarding (landed)
//!
//! When `ProxyConfig::forwarding = Some(...)` is wired
//! through the plan TOML's `[tasks.credentials.forwarding]`
//! block, the IMDS `/metadata/identity/oauth2/token` endpoint
//! drives a real `client_credentials`-grant exchange against
//! the closed-allowlist `login.microsoftonline.com` endpoint
//! and serves the upstream-issued short-lived access token
//! to the in-VM SDK. The form encoder, AAD response parser,
//! IMDS-shape adapter, token cache, and audit emission all
//! live in `forwarding.rs`. See
//! `specs/v3/cloud-proxy-forwarding.md §2.3, §5, §6.3`.
//!
//! The `tenant_id` / `client_id` / `client_secret` come from
//! the service-principal credential body resolved through
//! `CredentialBackend`. Plan TOML never carries the secret.
//!
//! # What is deferred
//!
//!   * **Real `oauth2/v2.0/token` exchange** — landed in V3 via
//!     [`ForwardingConfig`] / [`AzureProxy::bind_v3`]. V2
//!     mirrors a token the operator stored in the credential
//!     backend.
//!   * **Per-resource credential resolution.** V2 resolves the same
//!     credential for every allowed resource — the assumption is
//!     that the operator stored a token already scoped to (or
//!     refreshable for) the union of `allowed_resources`. V3 will
//!     resolve a different credential per resource so e.g. a
//!     PostgreSQL token comes from one secret and an ARM token
//!     from another.
//!   * **`?api-version=` validation.** The proxy accepts any
//!     `api-version` value the SDK sends. Real IMDS rejects
//!     unknown versions — V3 will pin
//!     `2018-02-01` / `2019-08-01` etc.
//!   * **`?client_id=` selection** for VMs with multiple managed
//!     identities. V2 uses a single identity per credential.
//!
//! # Threat model
//!
//! Identical to the AWS / GCP proxies: the agent only ever sees the
//! short-lived synthetic token; the long-lived service-principal
//! secret never crosses the VM boundary.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use raxis_audit_tools::AuditSink;
use raxis_credential_proxy_cloud_shared::{CloudHttpClient, TokenCache};
use raxis_credentials::{ConsumerIdentity, CredentialBackend, CredentialName};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod forwarding;
pub mod restriction;

pub use forwarding::{AzureCacheValue, ForwardOutcome, ForwardingConfig, AZURE_JSON_CONTENT_TYPE};
pub use restriction::Restrictions;

// ---------------------------------------------------------------------------
// OwnedConsumer.
// ---------------------------------------------------------------------------

/// Owned form of `ConsumerIdentity`.
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

/// Configuration for one Azure IMDS proxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the inbound listener binds to. Production wires
    /// `127.0.0.1:9003` so an `/etc/hosts` rewrite of
    /// `169.254.169.254 → 127.0.0.1` reaches the proxy.
    pub listen_addr: String,
    /// Credential to resolve per request. Bytes must parse as
    /// either `KEY=VALUE` env-style or as a JSON object containing
    /// at least an `access_token` (or `AZURE_ACCESS_TOKEN`) field.
    pub credential_name: CredentialName,
    /// Identity of the agent session this proxy serves.
    pub consumer: OwnedConsumer,
    /// Lease length advertised in `expires_in`. SDKs refresh shortly
    /// before this elapses.
    pub lease_seconds: u64,
    /// Azure tenant ID. Returned in audit events. Operator-declared
    /// in `[[tasks.credentials]]`.
    pub tenant_id: String,
    /// Optional managed-identity client ID mirrored back in the
    /// response body. Useful for SDKs that record the identity that
    /// minted the token.
    pub client_id: Option<String>,
    /// Effective restriction set parsed out of
    /// `[tasks.credentials.restrictions]`.
    pub restrictions: Restrictions,
    /// V3 forwarding configuration. When `Some`, the IMDS
    /// `/metadata/identity/oauth2/token` endpoint drives a
    /// real `client_credentials`-grant OAuth2 exchange
    /// against the closed-allowlist `login.microsoftonline.com`
    /// endpoint. See `specs/v3/cloud-proxy-forwarding.md`.
    pub forwarding: Option<ForwardingConfig>,
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Counters surfaced for `CredentialProxyStopped`.
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Number of accepted connections served.
    pub connections_served: AtomicU32,
    /// Number of requests that returned a token.
    pub tokens_served: AtomicU32,
    /// Number of requests rejected by `Restrictions` or missing
    /// `Metadata: true` header.
    pub requests_blocked: AtomicU32,
    /// Bytes in the served response bodies.
    pub bytes_served: AtomicU64,
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served: self.connections_served.load(Ordering::Relaxed),
            tokens_served: self.tokens_served.load(Ordering::Relaxed),
            requests_blocked: self.requests_blocked.load(Ordering::Relaxed),
            bytes_served: self.bytes_served.load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted connections served.
    pub connections_served: u32,
    /// Number of requests that returned a token.
    pub tokens_served: u32,
    /// Number of requests rejected by `Restrictions`.
    pub requests_blocked: u32,
    /// Bytes in the served response bodies.
    pub bytes_served: u64,
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
    /// One served (or rejected) IMDS token request.
    AzureTokenServed {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer: OwnedConsumer,
        /// Credential name (never the value).
        credential: CredentialName,
        /// Request path.
        path: String,
        /// Resource URI the SDK requested (or empty if missing).
        resource: String,
        /// SHA-256 of `"<METHOD> <path>?resource=<resource>"`.
        request_sha256: String,
        /// Tenant ID associated with the proxy.
        tenant_id: String,
        /// operator-declared ARM action
        /// vocabulary for the requested resource (e.g.
        /// `["Microsoft.Storage/storageAccounts/read"]`). Empty
        /// when no per-resource action filter was declared. V2.3
        /// is declarative + audit echo; runtime ARM-URL gating
        /// lands in V3.
        allowed_actions: Vec<String>,
        /// True if a restriction or missing header blocked this
        /// request.
        blocked: bool,
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
        addr: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

// ---------------------------------------------------------------------------
// IMDS response shape. Numeric fields are stringified to match wire.
// ---------------------------------------------------------------------------

/// Response body for `/metadata/identity/oauth2/token`. Field
/// types match the wire (numeric fields are strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImdsTokenResponse {
    access_token: String,
    /// Empty string when not declared by the proxy decl.
    client_id: String,
    expires_in: String,
    expires_on: String,
    ext_expires_in: String,
    not_before: String,
    resource: String,
    token_type: String,
}

/// Internal envelope the proxy resolves the credential into.
#[derive(Debug, Clone)]
struct ResolvedKey {
    access_token: String,
}

fn parse_credential_body(body: &str) -> Result<ResolvedKey, &'static str> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|_| "credential body is not valid JSON despite leading `{`")?;
        let obj = v
            .as_object()
            .ok_or("JSON credential body is not an object")?;
        let access_token = pick_str(obj, &["access_token", "AZURE_ACCESS_TOKEN"])
            .ok_or("missing access_token / AZURE_ACCESS_TOKEN")?
            .to_owned();
        Ok(ResolvedKey { access_token })
    } else {
        let mut access_token = None;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches(['"', '\''].as_ref());
                if k == "AZURE_ACCESS_TOKEN" {
                    access_token = Some(v.to_owned());
                }
            }
        }
        let access_token = access_token.ok_or("missing AZURE_ACCESS_TOKEN")?;
        Ok(ResolvedKey { access_token })
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

/// Azure IMDS-compatible credential proxy.
pub struct AzureProxy {
    listener: TcpListener,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    stats: Arc<ProxyStats>,
    audit: Arc<dyn AuditChannel>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    http_client: Option<Arc<CloudHttpClient>>,
    token_cache: Option<Arc<TokenCache<AzureCacheValue>>>,
}

impl AzureProxy {
    /// Bind a listener and return an owned proxy. V2-only
    /// constructor — see [`Self::bind_v3`] for the
    /// V3-cloud-forwarding-aware constructor.
    pub async fn bind(
        backend: Arc<dyn CredentialBackend>,
        config: ProxyConfig,
        audit: Arc<dyn AuditChannel>,
    ) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(&config.listen_addr)
            .await
            .map_err(|source| ProxyError::Bind {
                addr: config.listen_addr.clone(),
                source,
            })?;
        Ok(Self {
            listener,
            backend,
            config,
            stats: Arc::new(ProxyStats::default()),
            audit,
            audit_sink: None,
            http_client: None,
            token_cache: None,
        })
    }

    /// Bind a listener with V3 forwarding plumbing.
    pub async fn bind_v3(
        backend: Arc<dyn CredentialBackend>,
        config: ProxyConfig,
        audit: Arc<dyn AuditChannel>,
        audit_sink: Arc<dyn AuditSink>,
        http_client: Arc<CloudHttpClient>,
        token_cache: Arc<TokenCache<AzureCacheValue>>,
    ) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(&config.listen_addr)
            .await
            .map_err(|source| ProxyError::Bind {
                addr: config.listen_addr.clone(),
                source,
            })?;
        Ok(Self {
            listener,
            backend,
            config,
            stats: Arc::new(ProxyStats::default()),
            audit,
            audit_sink: Some(audit_sink),
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

    /// Run the accept loop until dropped.
    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _peer)) => {
                    self.stats
                        .connections_served
                        .fetch_add(1, Ordering::Relaxed);
                    let backend = Arc::clone(&self.backend);
                    let config = self.config.clone();
                    let stats = Arc::clone(&self.stats);
                    let audit = Arc::clone(&self.audit);
                    let audit_sink = self.audit_sink.clone();
                    let http_client = self.http_client.clone();
                    let token_cache = self.token_cache.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_one(
                            stream,
                            backend,
                            config,
                            stats,
                            audit,
                            audit_sink,
                            http_client,
                            token_cache,
                        )
                        .await
                        {
                            tracing::warn!(error = %e, "azure proxy connection ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "azure proxy accept failed");
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-connection driver. One inbound HTTP/1.1 request per connection.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn serve_one(
    mut stream: TcpStream,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    stats: Arc<ProxyStats>,
    audit: Arc<dyn AuditChannel>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    http_client: Option<Arc<CloudHttpClient>>,
    token_cache: Option<Arc<TokenCache<AzureCacheValue>>>,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            write_status(&mut stream, 431, "Request Header Fields Too Large").await?;
            return Ok(());
        }
    }
    if buf.is_empty() {
        return Ok(());
    }

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    let (method, path, has_metadata_header) = match req.parse(&buf) {
        Ok(httparse::Status::Complete(_)) => {
            let method = req.method.unwrap_or("GET").to_owned();
            let path = req.path.unwrap_or("/").to_owned();
            let has = req.headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("Metadata") && h.value.eq_ignore_ascii_case(b"true")
            });
            (method, path, has)
        }
        _ => {
            write_status(&mut stream, 400, "Bad Request").await?;
            return Ok(());
        }
    };

    let resource = extract_query_value(&path, "resource").unwrap_or_default();

    // Enforce Metadata: true header. Real Azure IMDS requires it.
    if !has_metadata_header {
        stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        audit.emit(audit_event(&config, &method, &path, &resource, true));
        write_imds_error(&mut stream, 400, "missing 'Metadata: true' header").await?;
        return Ok(());
    }

    // Path is fixed.
    let bare_path = path.split('?').next().unwrap_or(&path);
    if bare_path != "/metadata/identity/oauth2/token" {
        stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        audit.emit(audit_event(&config, &method, &path, &resource, true));
        write_imds_error(&mut stream, 404, "unknown IMDS endpoint").await?;
        return Ok(());
    }

    // Resource allowlist.
    if resource.is_empty() {
        stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        audit.emit(audit_event(&config, &method, &path, &resource, true));
        write_imds_error(&mut stream, 400, "missing 'resource' query parameter").await?;
        return Ok(());
    }
    if !config.restrictions.allows_resource(&resource) {
        stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        audit.emit(audit_event(&config, &method, &path, &resource, true));
        write_imds_error(&mut stream, 400, "resource not in allowed_resources").await?;
        return Ok(());
    }

    // V3 branch — drive a real client_credentials-grant exchange.
    if let (Some(fwd), Some(sink), Some(http), Some(cache)) = (
        config.forwarding.as_ref(),
        audit_sink.as_ref(),
        http_client.as_ref(),
        token_cache.as_ref(),
    ) {
        let resolved_bytes =
            match backend.resolve(&config.credential_name, config.consumer.as_ref()) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "azure proxy credential resolve failed");
                    write_imds_error(&mut stream, 502, "credential resolve failed").await?;
                    return Ok(());
                }
            };
        let body_str = match resolved_bytes.as_utf8() {
            Some(s) => s.to_owned(),
            None => {
                tracing::warn!("azure proxy credential body is not UTF-8");
                write_imds_error(&mut stream, 502, "credential body is not UTF-8").await?;
                return Ok(());
            }
        };
        let sp = match forwarding::parse_service_principal(&body_str) {
            Ok(s) => s,
            Err(_) => {
                write_imds_error(&mut stream, 502, "service-principal credential malformed")
                    .await?;
                return Ok(());
            }
        };
        let session_id = format!("{}:{}", config.consumer.kind, config.consumer.id);
        let outcome = forwarding::forward_or_serve_from_cache(
            fwd,
            http,
            cache,
            sink,
            &session_id,
            config.credential_name.as_str(),
            &sp,
            &resource,
        )
        .await;
        let allowed_actions_header = match config.restrictions.actions_for(&resource) {
            Some(actions) if !actions.is_empty() => {
                let json = serde_json::to_string(actions)
                    .map_err(|e| std::io::Error::other(format!("json serialise actions: {e}")))?;
                format!("x-ms-allowed-actions: {json}\r\n")
            }
            _ => String::new(),
        };
        match outcome {
            ForwardOutcome::Ok(body) => {
                let body_len = body.len();
                let header = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: {ct}\r\n\
                     Content-Length: {len}\r\n\
                     Cache-Control: no-store\r\n\
                     {allowed_actions_header}\
                     Connection: close\r\n\
                     \r\n",
                    ct = AZURE_JSON_CONTENT_TYPE,
                    len = body_len,
                );
                stream.write_all(header.as_bytes()).await?;
                stream.write_all(&body).await?;
                stream.flush().await?;
                stats.tokens_served.fetch_add(1, Ordering::Relaxed);
                stats
                    .bytes_served
                    .fetch_add(body_len as u64, Ordering::Relaxed);
                audit.emit(audit_event(&config, &method, &path, &resource, false));
            }
            ForwardOutcome::UpstreamEnvelope { status, body } => {
                let body_len = body.len();
                let header = format!(
                    "HTTP/1.1 {status} {reason}\r\n\
                     Content-Type: {ct}\r\n\
                     Content-Length: {len}\r\n\
                     Cache-Control: no-store\r\n\
                     Connection: close\r\n\
                     \r\n",
                    reason = code_to_reason(status),
                    ct = AZURE_JSON_CONTENT_TYPE,
                    len = body_len,
                );
                stream.write_all(header.as_bytes()).await?;
                stream.write_all(&body).await?;
                stream.flush().await?;
                stats
                    .bytes_served
                    .fetch_add(body_len as u64, Ordering::Relaxed);
            }
        }
        return Ok(());
    }

    // V2 emulator path (forwarding disabled).
    let resolved = match backend.resolve(&config.credential_name, config.consumer.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "azure proxy credential resolve failed");
            write_imds_error(&mut stream, 502, "credential resolve failed").await?;
            return Ok(());
        }
    };
    let body_str = match resolved.as_utf8() {
        Some(s) => s.to_owned(),
        None => {
            tracing::warn!("azure proxy credential body is not UTF-8");
            write_imds_error(&mut stream, 502, "credential body is not UTF-8").await?;
            return Ok(());
        }
    };
    let key = match parse_credential_body(&body_str) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(reason = %e, "azure proxy credential body is malformed");
            write_imds_error(&mut stream, 502, "credential body is malformed").await?;
            return Ok(());
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_on = now + config.lease_seconds;
    let body = ImdsTokenResponse {
        access_token: key.access_token,
        client_id: config.client_id.clone().unwrap_or_default(),
        expires_in: config.lease_seconds.to_string(),
        expires_on: expires_on.to_string(),
        ext_expires_in: config.lease_seconds.to_string(),
        not_before: now.to_string(),
        resource: resource.clone(),
        token_type: "Bearer".to_owned(),
    };
    let body = serde_json::to_vec(&body)
        .map_err(|e| std::io::Error::other(format!("json serialise: {e}")))?;
    let body_len = body.len();
    // surface the operator-declared per-resource
    // ARM action vocabulary as an `x-ms-allowed-actions` response
    // header so the V3 ARM-aware egress proxy (and any in-VM
    // tooling that wants to introspect the declared scope) can read
    // it without parsing the audit chain. Empty list ⇒ header
    // omitted so SDKs see byte-identical responses to V2.2.
    let allowed_actions_header = match config.restrictions.actions_for(&resource) {
        Some(actions) if !actions.is_empty() => {
            // JSON-encoded array, e.g.
            // `["Microsoft.Storage/storageAccounts/read"]`. We
            // serialise via `serde_json::to_string` so the header
            // value is well-formed JSON regardless of the verbs.
            let json = serde_json::to_string(actions)
                .map_err(|e| std::io::Error::other(format!("json serialise actions: {e}")))?;
            format!("x-ms-allowed-actions: {json}\r\n")
        }
        _ => String::new(),
    };
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Cache-Control: no-store\r\n\
         {allowed_actions_header}\
         Connection: close\r\n\
         \r\n",
        len = body_len,
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    stats.tokens_served.fetch_add(1, Ordering::Relaxed);
    stats
        .bytes_served
        .fetch_add(body_len as u64, Ordering::Relaxed);
    audit.emit(audit_event(&config, &method, &path, &resource, false));
    Ok(())
}

/// Extract a query parameter value out of a request path. Returns
/// `None` when the path has no querystring, when the parameter is
/// absent, or when its value would be empty after percent-decoding.
fn extract_query_value(path: &str, key: &str) -> Option<String> {
    let qs = path.split_once('?')?.1;
    for pair in qs.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

/// Minimal `application/x-www-form-urlencoded` percent decoder. Big
/// enough for resource URIs (we only need to handle `%3A`, `%2F`,
/// `%3F` etc. — no percent-encoded multi-byte UTF-8 in practice).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_owned())
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

async fn write_status(stream: &mut TcpStream, code: u16, reason: &str) -> std::io::Result<()> {
    let line =
        format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",);
    stream.write_all(line.as_bytes()).await?;
    stream.flush().await
}

async fn write_imds_error(stream: &mut TcpStream, code: u16, message: &str) -> std::io::Result<()> {
    // Match real IMDS error shape so SDKs that pattern-match the
    // body field continue to behave.
    let body = serde_json::json!({
        "error":             code_to_short(code),
        "error_description": message,
    });
    let body = serde_json::to_vec(&body)
        .map_err(|e| std::io::Error::other(format!("json serialise: {e}")))?;
    let body_len = body.len();
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         \r\n",
        reason = code_to_reason(code),
        len = body_len,
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await
}

fn code_to_reason(code: u16) -> &'static str {
    match code {
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
        _ if (200..300).contains(&code) => "OK",
        _ if (400..500).contains(&code) => "Client Error",
        _ if (500..600).contains(&code) => "Server Error",
        _ => "Error",
    }
}

fn code_to_short(code: u16) -> &'static str {
    match code {
        400 => "invalid_request",
        404 => "unsupported_endpoint",
        502 => "credential_resolve_failed",
        _ => "error",
    }
}

fn audit_event(
    config: &ProxyConfig,
    method: &str,
    path: &str,
    resource: &str,
    blocked: bool,
) -> AuditEvent {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(method.as_bytes());
    h.update(b" ");
    h.update(path.as_bytes());
    h.update(b"?resource=");
    h.update(resource.as_bytes());
    let request_sha256 = hex::encode(h.finalize());
    let allowed_actions = config
        .restrictions
        .actions_for(resource)
        .map(|a| a.to_vec())
        .unwrap_or_default();
    AuditEvent::AzureTokenServed {
        timestamp_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        consumer: config.consumer.clone(),
        credential: config.credential_name.clone(),
        path: path.to_owned(),
        resource: resource.to_owned(),
        request_sha256,
        tenant_id: config.tenant_id.clone(),
        allowed_actions,
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
        let body = "AZURE_ACCESS_TOKEN=eyJ0eXAi.example\n";
        let k = parse_credential_body(body).unwrap();
        assert_eq!(k.access_token, "eyJ0eXAi.example");
    }

    #[test]
    fn parses_json_credential_body() {
        let body = r#"{ "access_token": "eyJ0eXAi.example" }"#;
        let k = parse_credential_body(body).unwrap();
        assert_eq!(k.access_token, "eyJ0eXAi.example");
    }

    #[test]
    fn missing_token_is_rejected() {
        let body = "AZURE_TENANT_ID=aaaa\n";
        let err = parse_credential_body(body).unwrap_err();
        assert!(err.contains("AZURE_ACCESS_TOKEN"));
    }

    #[test]
    fn extracts_resource_query_param() {
        let path = "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F";
        let r = extract_query_value(path, "resource").unwrap();
        assert_eq!(r, "https://management.azure.com/");
    }

    #[test]
    fn missing_resource_query_returns_none() {
        let path = "/metadata/identity/oauth2/token?api-version=2018-02-01";
        assert!(extract_query_value(path, "resource").is_none());
    }
}
