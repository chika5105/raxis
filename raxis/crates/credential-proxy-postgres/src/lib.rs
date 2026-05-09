//! `raxis-credential-proxy-postgres` — Postgres wire-protocol credential
//! proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §4.1`.
//!
//! # Architecture
//!
//! The kernel spawns one proxy instance per VM session that declares a
//! `kind = "postgres"` credential. The proxy listens on a localhost
//! TCP port that the agent's VM can reach (via vsock-bridged or
//! kernel-injected DNAT — that wiring lives in the isolation backend,
//! not here). When the agent connects, the proxy:
//!
//!   1. Reads the `StartupMessage` and accepts the dummy connection
//!      with an `AuthenticationOk` regardless of the agent's claimed
//!      password (the agent never has a real password — see the spec
//!      §1 "Core principle").
//!   2. Opens an upstream connection to the real Postgres using the
//!      credential resolved through `Arc<dyn CredentialBackend>`.
//!   3. Forwards `Query` and `Parse` messages bidirectionally,
//!      auditing the SQL text via `AuditSink` on the way.
//!   4. Optionally enforces simple restrictions
//!      (`allow_only_select`).
//!
//! # What this MVP supports
//!
//!   * **Startup** — version-3 handshake with `AuthenticationOk`,
//!     a fixed set of `ParameterStatus` rows, `BackendKeyData`,
//!     and `ReadyForQuery`.
//!   * **Simple Query** — `'Q'` messages forwarded to the real DB
//!     via `tokio-postgres`. Each statement is audited.
//!   * **Termination** — `'X'` cleanly closes both halves.
//!   * **Restrictions** — `allow_only_select` rejects DML/DDL with
//!     a Postgres `ErrorResponse`.
//!
//! # What is deferred (documented in the spec as gaps)
//!
//!   * SSL request preface — the proxy answers `'N'` (no SSL) and
//!     the agent uses cleartext on the loopback interface; loopback
//!     is jail-internal so this is safe per spec §1.
//!   * Cancel-request preface — out of scope for the MVP.
//!   * Connection multiplexing per the spec §4.7 "connection pooling"
//!     — the MVP is 1-connection-in to 1-connection-out per accept.
//!
//! # Extended-query protocol (V2.4)
//!
//! The proxy supports the Postgres Extended Query path
//! (`Parse`/`Bind`/`Describe`/`Execute`/`Sync`/`Close`/`Flush`) used
//! by every modern ORM (SQLAlchemy, Django, asyncpg, Diesel, sqlx,
//! Prisma, ActiveRecord, GORM). Implementation strategy:
//!
//!   1. **`Parse`**: classify the SQL via `classify_first_operation`,
//!      apply `Restrictions::is_blocked`, audit-emit
//!      `DatabaseQueryExecuted`. On allow, lazily call upstream
//!      `prepare(sql)` and cache the resulting
//!      [`upstream::UpstreamPreparedMeta`]; replies `ParseComplete`
//!      (or `ErrorResponse` on prepare failure / restriction block).
//!   2. **`Bind`**: store the bound portal (statement name + raw
//!      parameter bytes + format codes); replies `BindComplete`.
//!   3. **`Describe('S')`**: replies `ParameterDescription` (OIDs
//!      from upstream prepare) + `RowDescription` (or `NoData`).
//!   4. **`Describe('P')`**: replies `RowDescription` (or `NoData`).
//!   5. **`Execute`**: substitutes parameter values into the SQL
//!      using dollar-quoted text literals (binary-format values for
//!      common OIDs are decoded inline), then forwards via the
//!      simple-query path. Re-frames the upstream's response as
//!      DataRow + CommandComplete in extended-query order. Audits
//!      `DatabaseQueryCompleted`.
//!   6. **`Sync`**: replies `ReadyForQuery`.
//!   7. **`Close('S' | 'P')`**: drops the cached entry; replies
//!      `CloseComplete`.
//!   8. **`Flush`**: no-op (the proxy does not buffer).
//!
//! Binary-format parameters are decoded for the canonical OID set
//! (int2, int4, int8, float4, float8, bool, text/varchar/bpchar,
//! bytea, uuid). Unknown binary OIDs surface as a structured
//! `ErrorResponse` with `FAIL_PROXY_EXT_QUERY_BINARY_PARAM_UNSUPPORTED`
//! so the operator can choose to reconfigure the driver to use
//! text-format parameters until V3 widens the type support.
//!
//! All deferred items are noted in the spec under §22 Implementation
//! Checklist.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use raxis_credentials::{CredentialBackend, CredentialName, ConsumerIdentity};

// `AuditSink` is intentionally NOT imported here — see Cargo.toml.

// ---------------------------------------------------------------------------
// Owned consumer identity
// ---------------------------------------------------------------------------

/// Owned form of `raxis_credentials::ConsumerIdentity`.
///
/// `ConsumerIdentity<'a>` carries borrowed `&'a str` fields, so we
/// can't clone or store it across an async boundary directly. The
/// proxy keeps an owned mirror and constructs a borrowed
/// `ConsumerIdentity` for each backend call.
#[derive(Debug, Clone)]
pub struct OwnedConsumer {
    /// Subsystem identifier. See `ConsumerIdentity::kind`.
    pub kind: String,
    /// Free-form disambiguator. See `ConsumerIdentity::id`.
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

pub mod extended;
pub mod restriction;
pub mod upstream;
pub mod wire;

pub use restriction::{Restrictions, OperationKind, classify_first_operation};
pub use upstream::{
    ForwardOutcome, ParsedUpstreamUrl, UpstreamError, UpstreamPreparedMeta, UpstreamSession,
    redact_for_audit, resolve_upstream_url,
};

// ---------------------------------------------------------------------------
// Public configuration
// ---------------------------------------------------------------------------

/// Configuration for one PostgresProxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to listen on (e.g. `127.0.0.1:0` to let the OS pick).
    pub listen_addr: String,
    /// Credential name to look up in the backend. The credential body
    /// must be a Postgres connection URL like
    /// `postgresql://user:pass@host:5432/db`.
    pub credential_name: CredentialName,
    /// Identity of the agent session this proxy serves; used in audit
    /// events so reviewers can attribute every query.
    pub consumer: OwnedConsumer,
    /// Effective restriction set.
    pub restrictions: Restrictions,
}

// ---------------------------------------------------------------------------
// Audit channel (kernel-injected sink for per-query audit events)
// ---------------------------------------------------------------------------

/// Sink the kernel-side `CredentialProxyManager` plugs into so each
/// `AuditEvent::DatabaseQueryExecuted` produced by the proxy is
/// translated into the kernel's `AuditEventKind::DatabaseQueryExecuted`
/// and written through the same `AuditSink` as every other audit
/// event (one chained line per query, hashed into the audit chain).
///
/// Per the postgres / http parity contract documented in
/// `credential-proxy.md §5`, this proxy crate stays
/// dependency-free of `raxis-audit-tools`. The kernel wraps the
/// real `AuditSink` adapter around this trait at bind time
/// (`raxis-credential-proxy-manager::bind_postgres`).
///
/// The trait is `Send + Sync` because the proxy spawns one
/// per-connection task per accepted client and threads the channel
/// through to the simple-query loop. Emission is deliberately
/// fire-and-forget (`fn emit` returns `()`) — the SQL has already
/// been forwarded by the time we audit it, and the kernel-side
/// adapter logs (rather than panics) on a transient audit-pipe
/// failure to keep the agent's session alive when the chain is
/// momentarily wedged.
pub trait AuditChannel: Send + Sync {
    /// Record one `AuditEvent::DatabaseQueryExecuted`.
    fn emit(&self, event: AuditEvent);
}

/// Convenience no-op channel for tests / out-of-band callers that
/// don't care about per-query audit translation.
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
        /// The address the bind was attempted on.
        addr:   String,
        /// Underlying I/O error from `tokio::net::TcpListener::bind`.
        source: std::io::Error,
    },
    /// Credential resolution failed.
    #[error("credential lookup failed for `{name}`: {detail}")]
    CredentialLookup {
        /// Name of the credential whose resolution failed.
        name:   String,
        /// Human-readable detail (never includes the credential value).
        detail: String,
    },
    /// Audit sink emission failed.
    #[error("audit emission failed: {0}")]
    AuditSink(String),
}

/// Counters surfaced in `CredentialProxyStopped`.
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Number of accepted connections served (regardless of success).
    pub connections_served: AtomicU32,
    /// Number of queries audited (auditing precedes restriction).
    pub queries_audited:    AtomicU32,
    /// Number of queries blocked by restrictions.
    pub queries_blocked:    AtomicU32,
    /// Number of upstream TCP+auth handshakes started (V2.1+).
    pub upstream_connects_attempted: AtomicU32,
    /// Subset that reached a usable session (V2.1+).
    pub upstream_connects_succeeded: AtomicU32,
    /// Subset that failed (DNS / TCP / TLS / auth / timeout, V2.1+).
    pub upstream_connects_failed:    AtomicU32,
    /// Sum of upstream→agent payload bytes relayed (V2.1+).
    pub upstream_bytes_forwarded:    AtomicU32,
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served:          self.connections_served       .load(Ordering::Relaxed),
            queries_audited:             self.queries_audited          .load(Ordering::Relaxed),
            queries_blocked:             self.queries_blocked          .load(Ordering::Relaxed),
            upstream_connects_attempted: self.upstream_connects_attempted.load(Ordering::Relaxed),
            upstream_connects_succeeded: self.upstream_connects_succeeded.load(Ordering::Relaxed),
            upstream_connects_failed:    self.upstream_connects_failed   .load(Ordering::Relaxed),
            upstream_bytes_forwarded:    self.upstream_bytes_forwarded   .load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot of proxy counters at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted connections served.
    pub connections_served: u32,
    /// Number of queries audited.
    pub queries_audited:    u32,
    /// Number of queries blocked by restrictions.
    pub queries_blocked:    u32,
    /// Number of upstream TCP+auth handshakes started.
    pub upstream_connects_attempted: u32,
    /// Subset that reached a usable session.
    pub upstream_connects_succeeded: u32,
    /// Subset that failed.
    pub upstream_connects_failed:    u32,
    /// Sum of upstream→agent payload bytes relayed.
    pub upstream_bytes_forwarded:    u32,
}

// ---------------------------------------------------------------------------
// Library entry point
// ---------------------------------------------------------------------------

/// The proxy itself. Holds:
///   * a TCP listener (already bound, so `local_addr()` is reachable);
///   * the credential backend handle;
///   * config;
///   * counters.
///
/// Spawn the per-connection task with [`PostgresProxy::serve`].
pub struct PostgresProxy {
    listener: tokio::net::TcpListener,
    backend:  Arc<dyn CredentialBackend>,
    config:   ProxyConfig,
    stats:    Arc<ProxyStats>,
    audit:    Arc<dyn AuditChannel>,
}

impl PostgresProxy {
    /// Bind a listener and return an owned proxy.
    ///
    /// The `audit` channel is invoked with one
    /// `AuditEvent::DatabaseQueryExecuted` per simple-query message
    /// the proxy processes. The kernel-side
    /// `CredentialProxyManager::bind_postgres` plugs in an adapter
    /// that translates each event into the kernel's
    /// `AuditEventKind::DatabaseQueryExecuted` and writes it through
    /// the same `AuditSink` as every other audit event. Out-of-band
    /// callers (subprocess integration tests, ad-hoc tooling) that
    /// don't want translation can pass [`NoopAuditChannel`].
    pub async fn bind(
        backend: Arc<dyn CredentialBackend>,
        config: ProxyConfig,
        audit:   Arc<dyn AuditChannel>,
    ) -> Result<Self, ProxyError> {
        let listener = tokio::net::TcpListener::bind(&config.listen_addr)
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
        })
    }

    /// The address the listener is bound to (post-bind, so `0` ports
    /// have been resolved by the kernel).
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Counters snapshot.
    pub fn stats(&self) -> ProxyStatsSnapshot {
        self.stats.snapshot()
    }

    /// Borrow the underlying `Arc<ProxyStats>` so a caller can keep
    /// reading counters AFTER `serve` has consumed the proxy. Call
    /// this BEFORE `tokio::spawn(proxy.serve())`.
    pub fn stats_handle(&self) -> Arc<ProxyStats> {
        Arc::clone(&self.stats)
    }

    /// Run the accept loop until the future is dropped.
    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    self.stats.connections_served.fetch_add(1, Ordering::Relaxed);
                    let backend  = self.backend.clone();
                    let config   = self.config.clone();
                    let stats    = self.stats.clone();
                    let audit    = Arc::clone(&self.audit);
                    tokio::spawn(async move {
                        if let Err(e) = serve_one(stream, backend, config, stats, audit).await {
                            tracing::warn!(peer = %peer, error = %e, "postgres proxy connection ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "postgres proxy accept failed");
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-connection driver
// ---------------------------------------------------------------------------

async fn serve_one(
    mut client_stream: tokio::net::TcpStream,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    stats: Arc<ProxyStats>,
    audit: Arc<dyn AuditChannel>,
) -> Result<(), ProxyError> {
    use crate::wire::*;

    // Step 1: read either an SSLRequest or a StartupMessage.
    let startup = read_startup(&mut client_stream).await
        .map_err(|e| ProxyError::AuditSink(format!("startup read: {e}")))?;
    match startup {
        StartupKind::SslRequest => {
            // Reject SSL on loopback per the MVP doc above.
            use tokio::io::AsyncWriteExt;
            client_stream.write_all(b"N").await
                .map_err(|e| ProxyError::AuditSink(format!("ssl reject: {e}")))?;
            // Now read the actual StartupMessage.
            let StartupKind::Startup(_) = read_startup(&mut client_stream).await
                .map_err(|e| ProxyError::AuditSink(format!("post-ssl startup: {e}")))?
            else {
                return Err(ProxyError::AuditSink("expected StartupMessage post-SSL".into()));
            };
        }
        StartupKind::Startup(_) => {}
        StartupKind::CancelRequest => {
            tracing::debug!("CancelRequest dropped (unsupported in MVP)");
            return Ok(());
        }
    }

    // Step 2: AuthenticationOk + minimal startup completion.
    use tokio::io::AsyncWriteExt;
    client_stream.write_all(&authentication_ok()).await
        .map_err(|e| ProxyError::AuditSink(format!("auth_ok: {e}")))?;
    client_stream.write_all(&parameter_status("server_version", "raxis-proxy-0.1")).await
        .map_err(|e| ProxyError::AuditSink(format!("param_status: {e}")))?;
    client_stream.write_all(&parameter_status("client_encoding", "UTF8")).await
        .map_err(|e| ProxyError::AuditSink(format!("param_status: {e}")))?;
    client_stream.write_all(&backend_key_data(0, 0)).await
        .map_err(|e| ProxyError::AuditSink(format!("backend_key_data: {e}")))?;
    client_stream.write_all(&ready_for_query(b'I')).await
        .map_err(|e| ProxyError::AuditSink(format!("ready_for_query: {e}")))?;

    // Step 3: resolve the upstream URL through the credential
    // backend. Fails closed if the backend can't resolve, or if the
    // credential value isn't a parseable libpq URL — the proxy
    // surfaces those as one connection-scoped Postgres
    // ErrorResponse on the FIRST allowed query (lazy connect, per
    // `credential-proxy.md §14.3`). The handshake itself is
    // already complete by this point; a session that issues no
    // queries cleanly disconnects regardless of credential health.
    let upstream_url = match upstream::resolve_upstream_url(
        &backend,
        &config.credential_name,
        &config.consumer,
    ) {
        Ok(u) => Some(u),
        Err(e) => {
            tracing::warn!(
                error = %e,
                credential = %config.credential_name.as_str(),
                "upstream URL resolution failed; agent connection will fail on first allowed query",
            );
            None
        }
    };

    // Step 4: the simple-query loop.
    //
    // V2.1 contract (`credential-proxy.md §14.3`):
    //   * Audit emission and restriction enforcement happen on EVERY
    //     `Q` message, before any upstream contact (preserves the
    //     V2.0 governance pipeline shape).
    //   * Allowed queries: lazy upstream connect on first allowed Q;
    //     subsequent allowed Qs reuse the same upstream session.
    //   * Blocked queries: synthetic `ErrorResponse` short-circuits
    //     before upstream contact; a session that issues only
    //     blocked queries never opens an upstream connection.

    let mut upstream_session: Option<UpstreamSession> = None;
    let mut upstream_connected_emitted: bool = false;
    let mut ext_state = crate::extended::ExtendedState::default();

    loop {
        use tokio::io::AsyncReadExt;
        let mut tag = [0u8; 1];
        let n = client_stream.read(&mut tag).await
            .map_err(|e| ProxyError::AuditSink(format!("read tag: {e}")))?;
        if n == 0 { break; }
        match tag[0] {
            b'Q' => {
                let body = read_message_body(&mut client_stream).await
                    .map_err(|e| ProxyError::AuditSink(format!("read body: {e}")))?;
                let sql = parse_query_message(&body)
                    .map_err(|e| ProxyError::AuditSink(format!("parse query: {e}")))?;
                let op = classify_first_operation(&sql);
                stats.queries_audited.fetch_add(1, Ordering::Relaxed);
                let blocked = config.restrictions.is_blocked(&op);
                audit.emit(audit_query_executed(&config, &sql, &op, blocked));

                if blocked {
                    stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
                    client_stream.write_all(&error_response(
                        b"ERROR",
                        b"42501",
                        "operation blocked by RAXIS policy",
                    )).await.map_err(|e| ProxyError::AuditSink(format!("err response: {e}")))?;
                    client_stream.write_all(&ready_for_query(b'I')).await
                        .map_err(|e| ProxyError::AuditSink(format!("rfq: {e}")))?;
                    continue;
                }

                // Allowed query: ensure we have an upstream session.
                if upstream_session.is_none() {
                    let url = match upstream_url.as_ref() {
                        Some(u) => u,
                        None => {
                            client_stream.write_all(&error_response(
                                b"ERROR",
                                b"08000",
                                "RAXIS proxy: upstream credential could not be resolved (FAIL_PROXY_UPSTREAM_URL_INVALID)",
                            )).await.map_err(|e| ProxyError::AuditSink(format!("err response: {e}")))?;
                            client_stream.write_all(&ready_for_query(b'I')).await
                                .map_err(|e| ProxyError::AuditSink(format!("rfq: {e}")))?;
                            continue;
                        }
                    };
                    let host = url.host.clone();
                    let port = url.port;
                    let _tls = url.require_tls;
                    stats.upstream_connects_attempted.fetch_add(1, Ordering::Relaxed);
                    match UpstreamSession::connect(url, std::time::Duration::from_secs(8)).await {
                        Ok(sess) => {
                            stats.upstream_connects_succeeded.fetch_add(1, Ordering::Relaxed);
                            audit.emit(AuditEvent::CredentialProxyUpstreamConnected {
                                timestamp_unix_seconds: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map(|d| d.as_secs()).unwrap_or(0),
                                consumer:      config.consumer.clone(),
                                credential:    config.credential_name.clone(),
                                upstream_host: sess.host.clone(),
                                upstream_port: sess.port,
                                tls:           sess.tls,
                                handshake_ms:  sess.handshake_ms,
                            });
                            upstream_connected_emitted = true;
                            upstream_session = Some(sess);
                        }
                        Err(e) => {
                            stats.upstream_connects_failed.fetch_add(1, Ordering::Relaxed);
                            audit.emit(AuditEvent::CredentialProxyUpstreamFailed {
                                timestamp_unix_seconds: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map(|d| d.as_secs()).unwrap_or(0),
                                consumer:      config.consumer.clone(),
                                credential:    config.credential_name.clone(),
                                upstream_host: host,
                                upstream_port: port,
                                reason:        e.audit_reason().to_owned(),
                                detail:        e.audit_detail(),
                            });
                            // The agent sees a single ErrorResponse
                            // mapped from the failure category. The
                            // connection stays open — `psql` retries
                            // a reconnect against the same session.
                            let (sqlstate, msg) = match &e {
                                UpstreamError::AuthRejected(_) => ("28P01", "RAXIS proxy: upstream authentication rejected (FAIL_PROXY_UPSTREAM_AUTH_REJECTED)"),
                                UpstreamError::TcpConnect(_) | UpstreamError::Timeout { .. } => {
                                    ("08006", "RAXIS proxy: upstream unreachable (FAIL_PROXY_UPSTREAM_UNREACHABLE)")
                                }
                                UpstreamError::InvalidUrl(_) => {
                                    ("08000", "RAXIS proxy: upstream URL invalid (FAIL_PROXY_UPSTREAM_URL_INVALID)")
                                }
                                _ => ("08000", "RAXIS proxy: upstream connection failed"),
                            };
                            client_stream.write_all(&error_response(
                                b"ERROR",
                                sqlstate.as_bytes(),
                                msg,
                            )).await.map_err(|e| ProxyError::AuditSink(format!("err response: {e}")))?;
                            client_stream.write_all(&ready_for_query(b'I')).await
                                .map_err(|e| ProxyError::AuditSink(format!("rfq: {e}")))?;
                            continue;
                        }
                    }
                }

                // Forward the query. By now `upstream_session` is `Some`.
                let session = upstream_session.as_mut().expect("upstream connected above");
                let sql_sha = {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(sql.as_bytes());
                    hex::encode(h.finalize())
                };
                match session.forward_simple_query(&sql).await {
                    Ok(outcome) => {
                        for frame in &outcome.frames {
                            client_stream.write_all(frame).await
                                .map_err(|e| ProxyError::AuditSink(format!("relay frame: {e}")))?;
                        }
                        client_stream.write_all(&ready_for_query(b'I')).await
                            .map_err(|e| ProxyError::AuditSink(format!("rfq: {e}")))?;
                        stats.upstream_bytes_forwarded.fetch_add(
                            outcome.bytes_returned.min(u32::MAX as u64) as u32,
                            Ordering::Relaxed,
                        );
                        audit.emit(AuditEvent::DatabaseQueryCompleted {
                            timestamp_unix_seconds: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                            consumer:       config.consumer.clone(),
                            credential:     config.credential_name.clone(),
                            sql_sha256:     sql_sha,
                            rows_returned:  outcome.rows_returned,
                            bytes_returned: outcome.bytes_returned,
                            duration_ms:    outcome.duration_ms,
                            upstream_error: None,
                        });
                    }
                    Err(e) => {
                        let (sqlstate, message) = match &e {
                            UpstreamError::QueryFailed { sqlstate, message } => {
                                (sqlstate.clone(), message.clone())
                            }
                            other => ("XX000".to_owned(), other.audit_detail()),
                        };
                        client_stream.write_all(&error_response(
                            b"ERROR",
                            sqlstate.as_bytes(),
                            &message,
                        )).await.map_err(|e| ProxyError::AuditSink(format!("err response: {e}")))?;
                        client_stream.write_all(&ready_for_query(b'I')).await
                            .map_err(|e| ProxyError::AuditSink(format!("rfq: {e}")))?;
                        audit.emit(AuditEvent::DatabaseQueryCompleted {
                            timestamp_unix_seconds: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                            consumer:       config.consumer.clone(),
                            credential:     config.credential_name.clone(),
                            sql_sha256:     sql_sha,
                            rows_returned:  0,
                            bytes_returned: 0,
                            duration_ms:    0,
                            upstream_error: Some(sqlstate),
                        });
                    }
                }
            }
            b'X' => break,
            b'P' => {
                // Parse: capture SQL + classify, restriction-check.
                let body = read_message_body(&mut client_stream).await
                    .map_err(|e| ProxyError::AuditSink(format!("read body (Parse): {e}")))?;
                let parsed = match parse_parse_message(&body) {
                    Ok(p) => p,
                    Err(e) => {
                        send_extended_error(&mut client_stream, "08P01", &format!("malformed Parse message: {e}")).await?;
                        continue;
                    }
                };
                let op = classify_first_operation(&parsed.sql);
                stats.queries_audited.fetch_add(1, Ordering::Relaxed);
                let blocked = config.restrictions.is_blocked(&op);
                audit.emit(audit_query_executed(&config, &parsed.sql, &op, blocked));
                if blocked {
                    stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
                    send_extended_error(
                        &mut client_stream,
                        "42501",
                        "operation blocked by RAXIS policy",
                    ).await?;
                    continue;
                }
                ext_state.prepared.insert(
                    parsed.statement_name.clone(),
                    crate::extended::ParsedStatement {
                        sql:              parsed.sql.clone(),
                        agent_param_oids: parsed.param_oids.clone(),
                        upstream_meta:    None,
                    },
                );
                client_stream.write_all(&parse_complete()).await
                    .map_err(|e| ProxyError::AuditSink(format!("ParseComplete: {e}")))?;
            }
            b'B' => {
                // Bind: store portal.
                let body = read_message_body(&mut client_stream).await
                    .map_err(|e| ProxyError::AuditSink(format!("read body (Bind): {e}")))?;
                let bind = match parse_bind_message(&body) {
                    Ok(b) => b,
                    Err(e) => {
                        send_extended_error(&mut client_stream, "08P01", &format!("malformed Bind message: {e}")).await?;
                        continue;
                    }
                };
                if !ext_state.prepared.contains_key(&bind.statement_name) {
                    send_extended_error(
                        &mut client_stream,
                        "26000",
                        &format!("RAXIS proxy: prepared statement '{}' does not exist", bind.statement_name),
                    ).await?;
                    continue;
                }
                ext_state.portals.insert(
                    bind.portal_name.clone(),
                    crate::extended::BoundPortal {
                        statement_name: bind.statement_name.clone(),
                        bind,
                    },
                );
                client_stream.write_all(&bind_complete()).await
                    .map_err(|e| ProxyError::AuditSink(format!("BindComplete: {e}")))?;
            }
            b'D' => {
                // Describe (statement or portal).
                let body = read_message_body(&mut client_stream).await
                    .map_err(|e| ProxyError::AuditSink(format!("read body (Describe): {e}")))?;
                let desc = match parse_describe_message(&body) {
                    Ok(d) => d,
                    Err(e) => {
                        send_extended_error(&mut client_stream, "08P01", &format!("malformed Describe message: {e}")).await?;
                        continue;
                    }
                };
                let stmt_name = match desc.kind {
                    b'S' => desc.name.clone(),
                    b'P' => match ext_state.portals.get(&desc.name) {
                        Some(p) => p.statement_name.clone(),
                        None => {
                            send_extended_error(
                                &mut client_stream,
                                "26000",
                                &format!("RAXIS proxy: portal '{}' does not exist", desc.name),
                            ).await?;
                            continue;
                        }
                    },
                    _ => unreachable!("parse_describe_message validated kind"),
                };
                if !ensure_upstream_meta(
                    &mut client_stream,
                    &mut upstream_session,
                    upstream_url.as_ref(),
                    &mut ext_state,
                    &stmt_name,
                    &config,
                    &stats,
                    &audit,
                    &mut upstream_connected_emitted,
                ).await? {
                    // ensure_upstream_meta wrote an ErrorResponse;
                    // continue to the Sync.
                    continue;
                }
                let stmt = ext_state.prepared.get(&stmt_name).expect("ensured above");
                let meta = stmt.upstream_meta.as_ref().expect("ensured above");
                if desc.kind == b'S' {
                    client_stream.write_all(&parameter_description(&meta.param_oids)).await
                        .map_err(|e| ProxyError::AuditSink(format!("ParameterDescription: {e}")))?;
                }
                match crate::extended::row_description_for(meta) {
                    Some(frame) => {
                        client_stream.write_all(&frame).await
                            .map_err(|e| ProxyError::AuditSink(format!("RowDescription: {e}")))?;
                    }
                    None => {
                        client_stream.write_all(&no_data()).await
                            .map_err(|e| ProxyError::AuditSink(format!("NoData: {e}")))?;
                    }
                }
            }
            b'E' => {
                // Execute portal.
                let body = read_message_body(&mut client_stream).await
                    .map_err(|e| ProxyError::AuditSink(format!("read body (Execute): {e}")))?;
                let exec = match parse_execute_message(&body) {
                    Ok(e) => e,
                    Err(e) => {
                        send_extended_error(&mut client_stream, "08P01", &format!("malformed Execute message: {e}")).await?;
                        continue;
                    }
                };
                let portal = match ext_state.portals.get(&exec.portal_name) {
                    Some(p) => p.clone(),
                    None => {
                        send_extended_error(
                            &mut client_stream,
                            "26000",
                            &format!("RAXIS proxy: portal '{}' does not exist", exec.portal_name),
                        ).await?;
                        continue;
                    }
                };
                if !ensure_upstream_meta(
                    &mut client_stream,
                    &mut upstream_session,
                    upstream_url.as_ref(),
                    &mut ext_state,
                    &portal.statement_name,
                    &config,
                    &stats,
                    &audit,
                    &mut upstream_connected_emitted,
                ).await? {
                    continue;
                }
                let stmt = ext_state.prepared.get(&portal.statement_name).expect("ensured above").clone();
                let meta = stmt.upstream_meta.as_ref().expect("ensured above");
                let substituted = match crate::extended::substitute(&stmt.sql, &portal.bind, &meta.param_oids) {
                    Ok(s) => s,
                    Err(e) => {
                        let (sqlstate, msg) = e.to_wire();
                        send_extended_error(&mut client_stream, sqlstate, &msg).await?;
                        continue;
                    }
                };
                let session = upstream_session.as_mut().expect("upstream connected above");
                let sql_sha = {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(stmt.sql.as_bytes());
                    hex::encode(h.finalize())
                };
                match session.forward_simple_query(&substituted).await {
                    Ok(outcome) => {
                        // The simple-query outcome carries
                        // RowDescription + DataRow + CommandComplete.
                        // Per the extended-query protocol, the
                        // RowDescription was already emitted by
                        // Describe — drop it from the relay so the
                        // agent doesn't see it twice.
                        for frame in &outcome.frames {
                            if frame.first().copied() == Some(b'T') {
                                continue;
                            }
                            client_stream.write_all(frame).await
                                .map_err(|e| ProxyError::AuditSink(format!("relay frame: {e}")))?;
                        }
                        // No ReadyForQuery here — Sync sends it.
                        stats.upstream_bytes_forwarded.fetch_add(
                            outcome.bytes_returned.min(u32::MAX as u64) as u32,
                            Ordering::Relaxed,
                        );
                        audit.emit(AuditEvent::DatabaseQueryCompleted {
                            timestamp_unix_seconds: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                            consumer:       config.consumer.clone(),
                            credential:     config.credential_name.clone(),
                            sql_sha256:     sql_sha,
                            rows_returned:  outcome.rows_returned,
                            bytes_returned: outcome.bytes_returned,
                            duration_ms:    outcome.duration_ms,
                            upstream_error: None,
                        });
                    }
                    Err(e) => {
                        let (sqlstate, message) = match &e {
                            UpstreamError::QueryFailed { sqlstate, message } => {
                                (sqlstate.clone(), message.clone())
                            }
                            other => ("XX000".to_owned(), other.audit_detail()),
                        };
                        client_stream.write_all(&error_response(
                            b"ERROR",
                            sqlstate.as_bytes(),
                            &message,
                        )).await.map_err(|e| ProxyError::AuditSink(format!("err response: {e}")))?;
                        audit.emit(AuditEvent::DatabaseQueryCompleted {
                            timestamp_unix_seconds: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                            consumer:       config.consumer.clone(),
                            credential:     config.credential_name.clone(),
                            sql_sha256:     sql_sha,
                            rows_returned:  0,
                            bytes_returned: 0,
                            duration_ms:    0,
                            upstream_error: Some(sqlstate),
                        });
                    }
                }
            }
            b'C' => {
                // Close ('C' frontend) — extended-query close, not to
                // be confused with CommandComplete (which is also
                // tagged 'C' but on the BACKEND wire).
                let body = read_message_body(&mut client_stream).await
                    .map_err(|e| ProxyError::AuditSink(format!("read body (Close): {e}")))?;
                let close = match parse_close_message(&body) {
                    Ok(c) => c,
                    Err(e) => {
                        send_extended_error(&mut client_stream, "08P01", &format!("malformed Close message: {e}")).await?;
                        continue;
                    }
                };
                match close.kind {
                    b'S' => { ext_state.prepared.remove(&close.name); }
                    b'P' => { ext_state.portals.remove(&close.name); }
                    _ => unreachable!("parse_close_message validated kind"),
                }
                client_stream.write_all(&close_complete()).await
                    .map_err(|e| ProxyError::AuditSink(format!("CloseComplete: {e}")))?;
            }
            b'S' => {
                // Sync: empty body. Reply ReadyForQuery.
                let _ = read_message_body(&mut client_stream).await
                    .map_err(|e| ProxyError::AuditSink(format!("read body (Sync): {e}")))?;
                client_stream.write_all(&ready_for_query(b'I')).await
                    .map_err(|e| ProxyError::AuditSink(format!("rfq: {e}")))?;
            }
            b'H' => {
                // Flush: empty body. Proxy does not buffer; no-op.
                let _ = read_message_body(&mut client_stream).await
                    .map_err(|e| ProxyError::AuditSink(format!("read body (Flush): {e}")))?;
            }
            other => {
                let _ = read_message_body(&mut client_stream).await;
                client_stream.write_all(&error_response(
                    b"ERROR",
                    b"0A000",
                    &format!("RAXIS proxy does not yet support frontend message tag {other:?}"),
                )).await.map_err(|e| ProxyError::AuditSink(format!("err response: {e}")))?;
                client_stream.write_all(&ready_for_query(b'I')).await
                    .map_err(|e| ProxyError::AuditSink(format!("rfq: {e}")))?;
            }
        }
    }

    let _ = upstream_connected_emitted; // captured for future Stopped event richening
    Ok(())
}

// ---------------------------------------------------------------------------
// Extended-query helper: send an ErrorResponse without RFQ
// ---------------------------------------------------------------------------
//
// In the extended-query path the proxy MUST NOT emit ReadyForQuery
// after an error — the agent will issue Sync, at which point the
// proxy responds with ReadyForQuery. Sending RFQ here would put the
// agent's driver into a state machine error.
async fn send_extended_error(
    client_stream: &mut tokio::net::TcpStream,
    sqlstate: &str,
    message: &str,
) -> Result<(), ProxyError> {
    use crate::wire::error_response;
    use tokio::io::AsyncWriteExt;
    client_stream
        .write_all(&error_response(b"ERROR", sqlstate.as_bytes(), message))
        .await
        .map_err(|e| ProxyError::AuditSink(format!("err response: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Extended-query helper: lazy upstream connect + prepare metadata
// ---------------------------------------------------------------------------
//
// Returns `Ok(true)` when the prepared metadata is now cached on the
// statement, `Ok(false)` when an `ErrorResponse` was written instead
// (caller should fall through to wait for Sync).
#[allow(clippy::too_many_arguments)]
async fn ensure_upstream_meta(
    client_stream: &mut tokio::net::TcpStream,
    upstream_session: &mut Option<UpstreamSession>,
    upstream_url:    Option<&ParsedUpstreamUrl>,
    ext_state: &mut crate::extended::ExtendedState,
    statement_name: &str,
    config: &ProxyConfig,
    stats:  &Arc<ProxyStats>,
    audit:  &Arc<dyn AuditChannel>,
    upstream_connected_emitted: &mut bool,
) -> Result<bool, ProxyError> {
    let stmt = match ext_state.prepared.get(statement_name) {
        Some(s) => s,
        None => {
            send_extended_error(
                client_stream,
                "26000",
                &format!("RAXIS proxy: prepared statement '{statement_name}' does not exist"),
            ).await?;
            return Ok(false);
        }
    };
    if stmt.upstream_meta.is_some() {
        return Ok(true);
    }
    // Need an upstream session; lazily open one.
    if upstream_session.is_none() {
        let url = match upstream_url {
            Some(u) => u,
            None => {
                send_extended_error(
                    client_stream,
                    "08000",
                    "RAXIS proxy: upstream credential could not be resolved (FAIL_PROXY_UPSTREAM_URL_INVALID)",
                ).await?;
                return Ok(false);
            }
        };
        let host = url.host.clone();
        let port = url.port;
        stats.upstream_connects_attempted.fetch_add(1, Ordering::Relaxed);
        match UpstreamSession::connect(url, std::time::Duration::from_secs(8)).await {
            Ok(sess) => {
                stats.upstream_connects_succeeded.fetch_add(1, Ordering::Relaxed);
                audit.emit(AuditEvent::CredentialProxyUpstreamConnected {
                    timestamp_unix_seconds: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs()).unwrap_or(0),
                    consumer:      config.consumer.clone(),
                    credential:    config.credential_name.clone(),
                    upstream_host: sess.host.clone(),
                    upstream_port: sess.port,
                    tls:           sess.tls,
                    handshake_ms:  sess.handshake_ms,
                });
                *upstream_connected_emitted = true;
                *upstream_session = Some(sess);
            }
            Err(e) => {
                stats.upstream_connects_failed.fetch_add(1, Ordering::Relaxed);
                audit.emit(AuditEvent::CredentialProxyUpstreamFailed {
                    timestamp_unix_seconds: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs()).unwrap_or(0),
                    consumer:      config.consumer.clone(),
                    credential:    config.credential_name.clone(),
                    upstream_host: host,
                    upstream_port: port,
                    reason:        e.audit_reason().to_owned(),
                    detail:        e.audit_detail(),
                });
                let (sqlstate, msg) = crate::extended::prepare_error_to_wire(&e);
                send_extended_error(client_stream, &sqlstate, &msg).await?;
                return Ok(false);
            }
        }
    }
    let session = upstream_session.as_mut().expect("connected above");
    let sql = stmt.sql.clone();
    match session.prepare_statement(&sql).await {
        Ok(meta) => {
            if let Some(s) = ext_state.prepared.get_mut(statement_name) {
                s.upstream_meta = Some(meta);
            }
            Ok(true)
        }
        Err(e) => {
            let (sqlstate, msg) = crate::extended::prepare_error_to_wire(&e);
            send_extended_error(client_stream, &sqlstate, &msg).await?;
            Ok(false)
        }
    }
}

fn audit_query_executed(
    config: &ProxyConfig,
    sql: &str,
    op: &OperationKind,
    blocked: bool,
) -> AuditEvent {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(sql.as_bytes());
    let sha = hex::encode(h.finalize());
    AuditEvent::DatabaseQueryExecuted {
        timestamp_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        consumer:    config.consumer.clone(),
        credential:  config.credential_name.clone(),
        sql_sha256:  sha,
        sql_text:    None,
        operation:   match op {
            OperationKind::Select   => "SELECT".to_owned(),
            OperationKind::Insert   => "INSERT".to_owned(),
            OperationKind::Update   => "UPDATE".to_owned(),
            OperationKind::Delete   => "DELETE".to_owned(),
            OperationKind::Other(_) => "OTHER".to_owned(),
        },
        blocked,
    }
}

/// Audit event surface emitted by this crate. Names match
/// `credential-proxy.md §5` and `§14.5`. The kernel chooses how to
/// flatten these into the global `AuditEventKind` taxonomy when
/// consuming the proxy's events through an `AuditSink`.
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// Emitted on each query forwarded through the proxy.
    /// Pre-upstream-contact event — fires on the agent's `Q`
    /// message regardless of whether upstream is reachable.
    DatabaseQueryExecuted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session that issued the query.
        consumer: OwnedConsumer,
        /// Credential name (never the value).
        credential: CredentialName,
        /// SHA-256 of the SQL text, hex-encoded.
        sql_sha256: String,
        /// Optional plaintext SQL (only set when the operator's
        /// `[inference_audit] log_content = true` policy applies).
        sql_text: Option<String>,
        /// First operation token from the SQL.
        operation: String,
        /// True if a restriction blocked the query.
        blocked: bool,
    },

    /// Emitted on the upstream's terminal frame (`ReadyForQuery`)
    /// for a forwarded query. Pairs with `DatabaseQueryExecuted` via
    /// matching `sql_sha256` so an audit reader can compute round-
    /// trip duration and the agent's observed result against the
    /// proxy-captured row count. Per `credential-proxy.md §14.5.1`.
    DatabaseQueryCompleted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session that issued the query.
        consumer: OwnedConsumer,
        /// Credential name (never the value).
        credential: CredentialName,
        /// SHA-256 of the SQL text — matches the prior
        /// `DatabaseQueryExecuted.sql_sha256`.
        sql_sha256: String,
        /// Number of rows returned by the upstream.
        rows_returned: u64,
        /// Number of payload bytes the proxy relayed
        /// upstream→agent for this query.
        bytes_returned: u64,
        /// Wall-clock duration agent's-Q-arrival → upstream's-RFQ
        /// in milliseconds.
        duration_ms: u32,
        /// `Some(<sqlstate>)` if the upstream returned an error;
        /// `None` on success.
        upstream_error: Option<String>,
    },

    /// Emitted once per agent connection on the first successful
    /// upstream TCP+auth handshake. Per `credential-proxy.md §14.5.2`.
    CredentialProxyUpstreamConnected {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session that triggered upstream contact.
        consumer: OwnedConsumer,
        /// Credential name (never the value).
        credential: CredentialName,
        /// Upstream **hostname from the credential URL** (NOT a
        /// resolved IP) so dashboards can group events by upstream
        /// cluster without leaking DNS-resolution noise.
        upstream_host: String,
        /// Upstream port from the credential URL after
        /// default-port substitution.
        upstream_port: u16,
        /// True if the URL requested TLS.
        tls: bool,
        /// Wall-clock from `TcpStream::connect()` start to first
        /// usable session, in milliseconds.
        handshake_ms: u32,
    },

    /// Emitted on every upstream-connect attempt that did NOT reach
    /// a usable session. The `reason` discriminant is one of
    /// `"DnsResolveFailed" | "TcpConnectFailed" |
    /// "TlsHandshakeFailed" | "ProtocolHandshakeFailed" |
    /// "AuthRejected" | "Timeout"`. Per `credential-proxy.md §14.5.3`.
    /// The `detail` field is redacted via `upstream::redact_for_audit`
    /// before reaching this envelope (no credential bytes in
    /// detail).
    CredentialProxyUpstreamFailed {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session that triggered upstream contact.
        consumer: OwnedConsumer,
        /// Credential name (never the value).
        credential: CredentialName,
        /// Upstream hostname from the credential URL.
        upstream_host: String,
        /// Upstream port from the credential URL.
        upstream_port: u16,
        /// Failure category — see variant doc.
        reason: String,
        /// Short redacted message; never carries credential bytes.
        detail: String,
    },
}
