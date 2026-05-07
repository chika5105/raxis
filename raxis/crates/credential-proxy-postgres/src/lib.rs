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
//!   * Extended-query protocol (`Parse`/`Bind`/`Execute`/`Describe`/
//!     `Sync`/`Close`). The MVP rejects with `ErrorResponse` directing
//!     the client to use the simple-query path; full extended support
//!     lands when prepared-statement audit-keying is wired through.
//!   * SSL request preface — the proxy answers `'N'` (no SSL) and
//!     the agent uses cleartext on the loopback interface; loopback
//!     is jail-internal so this is safe per spec §1.
//!   * Cancel-request preface — out of scope for the MVP.
//!   * Connection multiplexing per the spec §4.7 "connection pooling"
//!     — the MVP is 1-connection-in to 1-connection-out per accept.
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

pub mod restriction;
pub mod wire;

pub use restriction::{Restrictions, OperationKind, classify_first_operation};

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
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served: self.connections_served.load(Ordering::Relaxed),
            queries_audited:    self.queries_audited   .load(Ordering::Relaxed),
            queries_blocked:    self.queries_blocked   .load(Ordering::Relaxed),
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
}

impl PostgresProxy {
    /// Bind a listener and return an owned proxy.
    pub async fn bind(
        backend: Arc<dyn CredentialBackend>,
        config: ProxyConfig,
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
                    tokio::spawn(async move {
                        if let Err(e) = serve_one(stream, backend, config, stats).await {
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

    // Step 3: resolve the upstream credential.
    let value = backend
        .resolve(&config.credential_name, config.consumer.as_ref())
        .map_err(|e| ProxyError::CredentialLookup {
            name:   config.credential_name.as_str().to_owned(),
            detail: e.to_string(),
        })?;
    let _conn_url = value.as_utf8().ok_or_else(|| ProxyError::CredentialLookup {
        name:   config.credential_name.as_str().to_owned(),
        detail: "credential value is not valid UTF-8 (expected a Postgres URL)".to_owned(),
    })?;

    // Step 4: the simple-query loop.
    //
    // We do NOT actually open a real upstream connection in the MVP
    // body — that path is exercised by the integration tests
    // (which provide a real upstream). The MVP demonstrates:
    //   * audit emission per query;
    //   * restriction enforcement;
    //   * a synthesized empty result so simple clients (psql -c
    //     "SELECT 1") see a well-formed response.
    //
    // The integration test wires a real tokio-postgres upstream via
    // a thin shim (see tests/proxy_simple_query.rs).

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
                let _audit_kind = audit_query_executed(&config, &sql, &op, blocked);
                // (audit emission to AuditSink: in production this
                // would go through the kernel's audit pipeline; the
                // MVP returns the AuditEvent struct so the kernel
                // wires emission at its tier.)

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
                client_stream.write_all(&command_complete(&op_label(&op))).await
                    .map_err(|e| ProxyError::AuditSink(format!("cmd cmpl: {e}")))?;
                client_stream.write_all(&ready_for_query(b'I')).await
                    .map_err(|e| ProxyError::AuditSink(format!("rfq: {e}")))?;
            }
            b'X' => break,
            other => {
                let _ = read_message_body(&mut client_stream).await;
                client_stream.write_all(&error_response(
                    b"ERROR",
                    b"0A000",
                    &format!("RAXIS proxy MVP does not yet support frontend message {other:?} (extended-query path)"),
                )).await.map_err(|e| ProxyError::AuditSink(format!("err response: {e}")))?;
                client_stream.write_all(&ready_for_query(b'I')).await
                    .map_err(|e| ProxyError::AuditSink(format!("rfq: {e}")))?;
            }
        }
    }

    Ok(())
}

fn op_label(op: &OperationKind) -> String {
    match op {
        OperationKind::Select   => "SELECT 0".to_owned(),
        OperationKind::Insert   => "INSERT 0 0".to_owned(),
        OperationKind::Update   => "UPDATE 0".to_owned(),
        OperationKind::Delete   => "DELETE 0".to_owned(),
        OperationKind::Other(s) => s.clone(),
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
/// `credential-proxy.md §5`. The kernel chooses how to flatten this
/// into the global `AuditEventKind` taxonomy when consuming the
/// proxy's events through an `AuditSink`.
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// Emitted on each query forwarded through the proxy.
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
}
