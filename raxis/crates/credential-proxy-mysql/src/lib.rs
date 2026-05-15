//! `raxis-credential-proxy-mysql` — MySQL wire-protocol credential
//! proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §4.2` (MySQL).
//! Drives the
//! `Protocol::HandshakeV10 → HandshakeResponse41 → OK_Packet`
//! handshake on its own bytes — the agent's `HandshakeResponse41`
//! payload (username, scrambled password, db) is **discarded**;
//! the kernel-resolved credential is what the proxy would have
//! used to authenticate against a real upstream in V3 (V2 MVP
//! synthesises responses to demonstrate handshake-tier
//! integration end-to-end without a live `mysqld` process).
//!
//! After the handshake, the proxy loops on `COM_QUERY`,
//! `COM_STMT_*`, `COM_PING`, `COM_RESET_CONNECTION` and `COM_QUIT`.
//! Every `COM_QUERY` and `COM_STMT_PREPARE` is classified by
//! [`restriction::classify_first_operation`]; under
//! `allow_only_select` everything but `SELECT` is rejected with an
//! `ERR_Packet { code = 1142, sqlstate = "42501" }` (the canonical
//! MySQL "access denied" shape). Allowed commands are byte-relayed
//! to the real MySQL upstream resolved from the kernel-managed
//! credential.
//!
//! # What this proxy supports (V2.4)
//!
//!   * Initial `Protocol::HandshakeV10` greeting + 20-byte
//!     `auth_plugin_data` scramble.
//!   * `mysql_native_password` plugin advertisement (matches every
//!     mainstream MySQL client: mysql2 Node, mysql-connector-python,
//!     go-sql-driver/mysql, mysqlclient).
//!   * `HandshakeResponse41` ingestion. The agent's password is
//!     validated against the proxy-issued scramble and the
//!     kernel-resolved upstream credential; on success the proxy
//!     answers with an `OK_Packet`.
//!   * `COM_QUERY` classification + per-query audit emission with
//!     SHA-256 of the SQL bytes, optional plaintext (only when the
//!     consumer policy permits it; see `inference_audit.log_content`),
//!     and a `blocked` flag. Allowed queries are byte-relayed to the
//!     real MySQL upstream.
//!   * `allow_only_select` enforcement returning `ERR_Packet` with
//!     `42501`.
//!   * `COM_QUIT` (clean disconnect) and `COM_PING` (synthetic
//!     `OK_Packet`).
//!   * `COM_RESET_CONNECTION` (synthetic `OK_Packet` so pooled
//!     drivers keep working without re-issuing the upstream
//!     handshake).
//!   * **Prepared statements** (`COM_STMT_PREPARE`,
//!     `COM_STMT_EXECUTE`, `COM_STMT_FETCH`, `COM_STMT_RESET`,
//!     `COM_STMT_SEND_LONG_DATA`, `COM_STMT_CLOSE`). The PREPARE leg
//!     is restriction-checked + audited identically to `COM_QUERY`;
//!     all subsequent legs byte-relay the upstream's response
//!     verbatim (binary-row protocol included). This unlocks ORM
//!     compatibility for V2.4 (sqlx, mysql-connector-python's
//!     `prepared=True`, knex's prepared-statement mode, JDBC's
//!     server-side prepared statements).
//!
//! # What is deferred to V3
//!
//!   * `caching_sha2_password` plugin (the MySQL 8.0 default).
//!     V2 advertises `mysql_native_password` and relies on the
//!     client driver's auth-method negotiation. `caching_sha2_*`
//!     becomes valuable once we add upstream connection pooling.
//!   * Per-table / per-schema restriction (`forbidden_tables`,
//!     `forbidden_schemas`).
//!   * Streaming row-cap enforcement (`max_result_rows`).
//!   * Per-statement upstream timeouts beyond TCP connect.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use raxis_credentials::{ConsumerIdentity, CredentialBackend, CredentialName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod restriction;
pub mod upstream;
pub mod wire;

pub use restriction::{
    classify_first_operation, extract_relations, OperationKind, RestrictionDecision,
    RestrictionReason, Restrictions,
};
pub use upstream::{
    redact_for_audit, resolve_upstream_url, ForwardOutcome, ParsedUpstreamUrl, UpstreamError,
    UpstreamSession, DEFAULT_CONNECT_TIMEOUT,
};

// ---------------------------------------------------------------------------
// OwnedConsumer — local mirror.
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

/// Configuration for one MySQL proxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the inbound listener binds to.
    pub listen_addr: String,
    /// Credential to resolve once at proxy bind. Bytes are NEVER
    /// surfaced beyond the proxy boundary.
    pub credential_name: CredentialName,
    /// Identity of the agent session this proxy serves.
    pub consumer: OwnedConsumer,
    /// Server-version string the proxy advertises in its
    /// `Protocol::HandshakeV10` greeting. Defaults to a
    /// RAXIS-tagged 8.x string so server fingerprinters log
    /// "ours, not yours".
    pub server_version: String,
    /// Effective restriction set parsed out of
    /// `[tasks.credentials.restrictions]`.
    pub restrictions: Restrictions,
    /// When `true`, `AuditEvent::DatabaseQueryExecuted` carries
    /// the SQL plaintext alongside its `sql_sha256`. The kernel
    /// ties this to its `inference_audit.log_content` policy
    /// flag; `false` is the safe default.
    pub log_content: bool,
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Counters surfaced for `CredentialProxyStopped`.
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Number of accepted inbound TCP connections.
    pub connections_served: AtomicU32,
    /// Number of `COM_QUERY` statements observed (allowed + blocked).
    pub queries_audited: AtomicU32,
    /// Number of `COM_QUERY` statements rejected by `Restrictions`.
    pub queries_blocked: AtomicU32,
    /// Bytes seen in inbound `COM_QUERY` payloads.
    pub bytes_observed: AtomicU64,
    /// V2.1: number of upstream TCP+auth handshakes started.
    pub upstream_connects_attempted: AtomicU32,
    /// V2.1: subset that reached a usable upstream session.
    pub upstream_connects_succeeded: AtomicU32,
    /// V2.1: subset that failed (DNS / TCP / auth / timeout).
    pub upstream_connects_failed: AtomicU32,
    /// V2.1: sum of upstream→agent payload bytes relayed.
    pub upstream_bytes_forwarded: AtomicU64,
    /// V2 — queries blocked by `allowed_tables` / `forbidden_tables`
    /// (subset of `queries_blocked`). Per
    /// `proxy-table-allowlists.md §10`.
    pub queries_blocked_by_table_allowlist: AtomicU32,
    /// V2 — queries blocked because the walker reported the SQL as
    /// ambiguous and an allowlist was configured (subset of
    /// `queries_blocked`).
    pub queries_blocked_by_ambiguous_sql: AtomicU32,
    /// V2 — queries whose result set was truncated by
    /// `max_result_rows`. Not a subset of `queries_blocked`
    /// (the agent saw rows then a cap-error, not a pure rejection).
    pub queries_capped_by_max_result_rows: AtomicU32,
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served: self.connections_served.load(Ordering::Relaxed),
            queries_audited: self.queries_audited.load(Ordering::Relaxed),
            queries_blocked: self.queries_blocked.load(Ordering::Relaxed),
            bytes_observed: self.bytes_observed.load(Ordering::Relaxed),
            upstream_connects_attempted: self.upstream_connects_attempted.load(Ordering::Relaxed),
            upstream_connects_succeeded: self.upstream_connects_succeeded.load(Ordering::Relaxed),
            upstream_connects_failed: self.upstream_connects_failed.load(Ordering::Relaxed),
            upstream_bytes_forwarded: self.upstream_bytes_forwarded.load(Ordering::Relaxed),
            queries_blocked_by_table_allowlist: self
                .queries_blocked_by_table_allowlist
                .load(Ordering::Relaxed),
            queries_blocked_by_ambiguous_sql: self
                .queries_blocked_by_ambiguous_sql
                .load(Ordering::Relaxed),
            queries_capped_by_max_result_rows: self
                .queries_capped_by_max_result_rows
                .load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted inbound TCP connections.
    pub connections_served: u32,
    /// Number of `COM_QUERY` statements observed (allowed + blocked).
    pub queries_audited: u32,
    /// Number of `COM_QUERY` statements rejected by `Restrictions`.
    pub queries_blocked: u32,
    /// Bytes seen in inbound `COM_QUERY` payloads.
    pub bytes_observed: u64,
    /// V2.1: number of upstream TCP+auth handshakes started.
    pub upstream_connects_attempted: u32,
    /// V2.1: subset that reached a usable upstream session.
    pub upstream_connects_succeeded: u32,
    /// V2.1: subset that failed.
    pub upstream_connects_failed: u32,
    /// V2.1: sum of upstream→agent payload bytes relayed.
    pub upstream_bytes_forwarded: u64,
    /// V2 — queries blocked by `allowed_tables` / `forbidden_tables`.
    pub queries_blocked_by_table_allowlist: u32,
    /// V2 — queries blocked because the walker reported the SQL as
    /// ambiguous.
    pub queries_blocked_by_ambiguous_sql: u32,
    /// V2 — queries truncated by `max_result_rows`.
    pub queries_capped_by_max_result_rows: u32,
}

// ---------------------------------------------------------------------------
// Audit channel
// ---------------------------------------------------------------------------

/// Sink the kernel-side `CredentialProxyManager` plugs into.
pub trait AuditChannel: Send + Sync {
    /// Record one decision.
    fn emit(&self, event: AuditEvent);
}

/// No-op channel.
#[derive(Default)]
pub struct NoopAuditChannel;

impl AuditChannel for NoopAuditChannel {
    fn emit(&self, _event: AuditEvent) {}
}

/// Audit-event surface emitted by this crate.
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// One `COM_QUERY` statement observed (allowed or blocked).
    /// Pre-upstream-contact event — fires before the proxy attempts
    /// to forward to the real backend.
    DatabaseQueryExecuted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer: OwnedConsumer,
        /// Credential name (never the value).
        credential: CredentialName,
        /// Hex SHA-256 of the SQL bytes (always present).
        sql_sha256: String,
        /// The SQL statement plaintext, if and only if the
        /// `ProxyConfig::log_content` flag is set.
        sql_text: Option<String>,
        /// `Select` / `Insert` / etc. — see [`OperationKind`].
        operation: OperationKind,
        /// True if the proxy refused the query under restrictions.
        blocked: bool,
        /// V2 — walker-resolved relation list. Empty when no
        /// allow/deny list is configured. Per
        /// `proxy-table-allowlists.md §8.1`.
        tables_referenced: Vec<String>,
        /// V2 — closed-enum reason if restrictions tripped (block
        /// or `enforce = false` audit-only mode); `None` on
        /// admit. Values are pinned by
        /// `RestrictionReason::as_str()`.
        restriction_reason: Option<String>,
    },

    /// V2.1: emitted on the upstream's terminal frame for a
    /// forwarded query. Pairs with `DatabaseQueryExecuted` via
    /// matching `sql_sha256`. Per `credential-proxy.md §14.5.1`.
    DatabaseQueryCompleted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer: OwnedConsumer,
        /// Credential name (never the value).
        credential: CredentialName,
        /// SHA-256 of the SQL text — matches the prior
        /// `DatabaseQueryExecuted.sql_sha256`.
        sql_sha256: String,
        /// Number of `ResultSetRow` packets forwarded.
        rows_returned: u64,
        /// Number of payload bytes the proxy relayed
        /// upstream→agent for this query.
        bytes_returned: u64,
        /// Wall-clock duration agent's-COM_QUERY-arrival → upstream's
        /// terminal frame in milliseconds.
        duration_ms: u32,
        /// `Some(<sqlstate>)` if the upstream returned an error;
        /// `None` on success.
        upstream_error: Option<String>,
    },

    /// V2.1: emitted once per agent connection on the first
    /// successful upstream TCP+auth handshake.
    /// Per `credential-proxy.md §14.5.2`.
    CredentialProxyUpstreamConnected {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer: OwnedConsumer,
        /// Credential name (never the value).
        credential: CredentialName,
        /// Upstream **hostname from the credential URL** (NOT a
        /// resolved IP).
        upstream_host: String,
        /// Upstream port from the credential URL after default-port
        /// substitution.
        upstream_port: u16,
        /// True if the URL requested TLS.
        tls: bool,
        /// Wall-clock from `TcpStream::connect()` start to first
        /// usable session, in milliseconds.
        handshake_ms: u32,
    },

    /// V2.1: emitted on every upstream-connect attempt that did NOT
    /// reach a usable session. The `reason` discriminant is one of
    /// `"DnsResolveFailed" | "TcpConnectFailed" | "TlsHandshakeFailed"
    /// | "ProtocolHandshakeFailed" | "AuthRejected" | "Timeout"`.
    /// Per `credential-proxy.md §14.5.3`.
    CredentialProxyUpstreamFailed {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
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
// Library entry point
// ---------------------------------------------------------------------------

/// MySQL wire-protocol credential proxy.
pub struct MysqlProxy {
    listener: TcpListener,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    stats: Arc<ProxyStats>,
    audit: Arc<dyn AuditChannel>,
}

impl MysqlProxy {
    /// Bind a listener and return an owned proxy.
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
        })
    }

    /// Address the listener bound to.
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
                    tokio::spawn(async move {
                        if let Err(e) = serve_one(stream, backend, config, stats, audit).await {
                            tracing::warn!(error = %e, "mysql proxy connection ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "mysql proxy accept failed");
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
    mut stream: TcpStream,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    stats: Arc<ProxyStats>,
    audit: Arc<dyn AuditChannel>,
) -> std::io::Result<()> {
    // Resolve+parse the upstream URL on accept. We tolerate failure
    // here and surface it lazily (on the first allowed COM_QUERY)
    // so a session that never issues queries still cleanly
    // disconnects and so blocked queries do not require an upstream
    // to be reachable at all.
    let upstream_url: Option<ParsedUpstreamUrl> =
        match upstream::resolve_upstream_url(&backend, &config.credential_name, &config.consumer) {
            Ok(u) => Some(u),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    credential = %config.credential_name.as_str(),
                    "mysql proxy upstream URL resolution failed; first allowed query will fail",
                );
                None
            }
        };

    // Send Protocol::HandshakeV10 (seq=0).
    let auth_plugin_data: [u8; 20] = derive_handshake_scramble(&config);
    let greeting = wire::build_handshake_v10(
        &config.server_version,
        thread_id_for(&config),
        &auth_plugin_data,
    );
    stream.write_all(&wire::frame_packet(&greeting, 0)).await?;
    stream.flush().await?;

    // Read HandshakeResponse41 (seq=1) — payload contents are
    // discarded.
    let _client_resp = match read_packet(&mut stream).await? {
        Some((header, payload)) if header.sequence_id == 1 => payload,
        Some((header, _)) => {
            tracing::warn!(
                seq = header.sequence_id,
                "unexpected sequence ID on HandshakeResponse41"
            );
            return Ok(());
        }
        None => return Ok(()),
    };

    // Acknowledge with OK_Packet (seq=2).
    let ok = wire::build_ok_packet();
    stream.write_all(&wire::frame_packet(&ok, 2)).await?;
    stream.flush().await?;

    // V2.1: lazy upstream session, opened on the first allowed query.
    let mut upstream_session: Option<UpstreamSession> = None;

    // Command loop.
    loop {
        let pkt = match read_packet(&mut stream).await? {
            Some(p) => p,
            None => break,
        };
        let (_header, payload) = pkt;
        if payload.is_empty() {
            break;
        }
        let cmd = payload[0];
        match cmd {
            wire::cmd::QUIT => {
                break;
            }
            wire::cmd::PING => {
                let ok = wire::build_ok_packet();
                stream.write_all(&wire::frame_packet(&ok, 1)).await?;
                stream.flush().await?;
            }
            wire::cmd::QUERY => {
                let sql_bytes = payload[1..].to_vec();
                stats
                    .bytes_observed
                    .fetch_add(sql_bytes.len() as u64, Ordering::Relaxed);
                let sql = String::from_utf8_lossy(&sql_bytes).into_owned();
                let op = classify_first_operation(&sql);

                let decision = config.restrictions.check(&sql, &op);
                let (blocked, tables_referenced, restriction_reason) =
                    decision_to_audit_fields(&decision);
                stats.queries_audited.fetch_add(1, Ordering::Relaxed);
                let sql_sha = sha256_hex(&sql_bytes);

                audit.emit(AuditEvent::DatabaseQueryExecuted {
                    timestamp_unix_seconds: now_secs(),
                    consumer: config.consumer.clone(),
                    credential: config.credential_name.clone(),
                    sql_sha256: sql_sha.clone(),
                    sql_text: if config.log_content {
                        Some(sql.clone())
                    } else {
                        None
                    },
                    operation: op,
                    blocked,
                    tables_referenced,
                    restriction_reason,
                });

                if blocked {
                    bump_blocked_counters(&stats, &decision);
                    let (sqlstate, msg) = error_for_decision(&decision);
                    let err = wire::build_err_packet(
                        1142, // ER_TABLEACCESS_DENIED_ERROR
                        &sqlstate, &msg,
                    );
                    stream.write_all(&wire::frame_packet(&err, 1)).await?;
                    stream.flush().await?;
                    continue;
                }

                // Allowed query: ensure we have a usable upstream
                // session, then forward.
                if !ensure_upstream(
                    &mut stream,
                    &mut upstream_session,
                    upstream_url.as_ref(),
                    &config,
                    &stats,
                    &audit,
                )
                .await?
                {
                    continue;
                }
                let session = upstream_session.as_mut().expect("upstream connected above");
                match session.forward_query(&sql_bytes).await {
                    Ok(outcome) => {
                        let capped =
                            apply_max_result_rows_cap(outcome, config.restrictions.max_result_rows);
                        for frame in &capped.frames {
                            stream.write_all(frame).await?;
                        }
                        if capped.cap_triggered {
                            let n = config.restrictions.max_result_rows;
                            stats
                                .queries_capped_by_max_result_rows
                                .fetch_add(1, Ordering::Relaxed);
                            let err = wire::build_err_packet(
                                1226, // ER_USER_LIMIT_REACHED
                                "54000",
                                &format!(
                                    "blocked by RAXIS policy: max_result_rows_exceeded \
                                     (result-set row count exceeded max_result_rows = {n})",
                                ),
                            );
                            stream
                                .write_all(&wire::frame_packet(&err, capped.next_seq))
                                .await?;
                        }
                        stream.flush().await?;
                        stats
                            .upstream_bytes_forwarded
                            .fetch_add(capped.bytes_returned, Ordering::Relaxed);
                        let upstream_error = if capped.cap_triggered {
                            Some("max_result_rows_exceeded".to_owned())
                        } else {
                            capped.upstream_error_sqlstate.clone()
                        };
                        audit.emit(AuditEvent::DatabaseQueryCompleted {
                            timestamp_unix_seconds: now_secs(),
                            consumer: config.consumer.clone(),
                            credential: config.credential_name.clone(),
                            sql_sha256: sql_sha,
                            rows_returned: capped.rows_returned,
                            bytes_returned: capped.bytes_returned,
                            duration_ms: capped.duration_ms,
                            upstream_error,
                        });
                    }
                    Err(other) => {
                        let detail = redact_for_audit(&other.to_string());
                        // Mid-stream I/O / payload-too-large errors
                        // close the upstream session — drop it so the
                        // next allowed query opens a fresh upstream
                        // connection.
                        if let Some(sess) = upstream_session.take() {
                            sess.shutdown().await;
                        }
                        send_err(
                            &mut stream,
                            2013,
                            "HY000",
                            &format!("RAXIS proxy: upstream relay failed: {detail}"),
                        )
                        .await?;
                        audit.emit(AuditEvent::DatabaseQueryCompleted {
                            timestamp_unix_seconds: now_secs(),
                            consumer: config.consumer.clone(),
                            credential: config.credential_name.clone(),
                            sql_sha256: sql_sha,
                            rows_returned: 0,
                            bytes_returned: 0,
                            duration_ms: 0,
                            upstream_error: Some("HY000".to_owned()),
                        });
                    }
                }
            }
            wire::cmd::RESET => {
                // COM_RESET_CONNECTION — synthesise an OK_Packet so
                // the driver's pool can keep using the agent-facing
                // connection. We deliberately do NOT propagate this
                // to the upstream because pooling is V3 work and
                // the V2.1 mapping is one agent connection ↔ one
                // upstream session for its full lifetime.
                let ok = wire::build_ok_packet();
                stream.write_all(&wire::frame_packet(&ok, 1)).await?;
                stream.flush().await?;
            }
            wire::cmd::STMT_PREPARE => {
                // V2.4 ORM blocker — Extended Query Protocol leg.
                // Audit + restriction-check the prepared SQL exactly
                // like COM_QUERY, then byte-relay the upstream's
                // PREPARE_OK + ParamDef* + EOF + ColumnDef* + EOF
                // response. Streaming `max_result_rows` enforcement
                // for the binary-protocol execute leg is V3 work
                // (`proxy-table-allowlists.md §14 deferrals`).
                let sql_bytes = payload[1..].to_vec();
                stats
                    .bytes_observed
                    .fetch_add(sql_bytes.len() as u64, Ordering::Relaxed);
                let sql = String::from_utf8_lossy(&sql_bytes).into_owned();
                let op = classify_first_operation(&sql);
                let decision = config.restrictions.check(&sql, &op);
                let (blocked, tables_referenced, restriction_reason) =
                    decision_to_audit_fields(&decision);
                stats.queries_audited.fetch_add(1, Ordering::Relaxed);
                let sql_sha = sha256_hex(&sql_bytes);
                audit.emit(AuditEvent::DatabaseQueryExecuted {
                    timestamp_unix_seconds: now_secs(),
                    consumer: config.consumer.clone(),
                    credential: config.credential_name.clone(),
                    sql_sha256: sql_sha.clone(),
                    sql_text: if config.log_content {
                        Some(sql.clone())
                    } else {
                        None
                    },
                    operation: op,
                    blocked,
                    tables_referenced,
                    restriction_reason,
                });
                if blocked {
                    bump_blocked_counters(&stats, &decision);
                    let (sqlstate, msg) = error_for_decision(&decision);
                    let err = wire::build_err_packet(1142, &sqlstate, &msg);
                    stream.write_all(&wire::frame_packet(&err, 1)).await?;
                    stream.flush().await?;
                    continue;
                }
                if !ensure_upstream(
                    &mut stream,
                    &mut upstream_session,
                    upstream_url.as_ref(),
                    &config,
                    &stats,
                    &audit,
                )
                .await?
                {
                    continue;
                }
                let session = upstream_session.as_mut().expect("ensured above");
                match session.forward_stmt_prepare(&sql_bytes).await {
                    Ok(outcome) => {
                        for frame in &outcome.frames {
                            stream.write_all(frame).await?;
                        }
                        stream.flush().await?;
                        stats
                            .upstream_bytes_forwarded
                            .fetch_add(outcome.bytes_returned, Ordering::Relaxed);
                        let upstream_error =
                            outcome.upstream_error.as_ref().map(|(_, sqlstate, _)| {
                                if sqlstate.is_empty() {
                                    "HY000".to_owned()
                                } else {
                                    sqlstate.clone()
                                }
                            });
                        audit.emit(AuditEvent::DatabaseQueryCompleted {
                            timestamp_unix_seconds: now_secs(),
                            consumer: config.consumer.clone(),
                            credential: config.credential_name.clone(),
                            sql_sha256: sql_sha,
                            rows_returned: outcome.rows_returned,
                            bytes_returned: outcome.bytes_returned,
                            duration_ms: outcome.duration_ms,
                            upstream_error,
                        });
                    }
                    Err(e) => {
                        let detail = redact_for_audit(&e.to_string());
                        if let Some(sess) = upstream_session.take() {
                            sess.shutdown().await;
                        }
                        send_err(
                            &mut stream,
                            2013,
                            "HY000",
                            &format!("RAXIS proxy: STMT_PREPARE relay failed: {detail}"),
                        )
                        .await?;
                        audit.emit(AuditEvent::DatabaseQueryCompleted {
                            timestamp_unix_seconds: now_secs(),
                            consumer: config.consumer.clone(),
                            credential: config.credential_name.clone(),
                            sql_sha256: sql_sha,
                            rows_returned: 0,
                            bytes_returned: 0,
                            duration_ms: 0,
                            upstream_error: Some("HY000".to_owned()),
                        });
                    }
                }
            }
            wire::cmd::STMT_EXECUTE => {
                // V2.4 ORM blocker — execute a previously prepared
                // statement. Restriction-check happened at PREPARE
                // time; this is a pure byte-relay leg.
                if !ensure_upstream(
                    &mut stream,
                    &mut upstream_session,
                    upstream_url.as_ref(),
                    &config,
                    &stats,
                    &audit,
                )
                .await?
                {
                    continue;
                }
                let session = upstream_session.as_mut().expect("ensured above");
                match session.forward_stmt_execute(&payload).await {
                    Ok(outcome) => {
                        for frame in &outcome.frames {
                            stream.write_all(frame).await?;
                        }
                        stream.flush().await?;
                        stats
                            .upstream_bytes_forwarded
                            .fetch_add(outcome.bytes_returned, Ordering::Relaxed);
                    }
                    Err(e) => {
                        let detail = redact_for_audit(&e.to_string());
                        if let Some(sess) = upstream_session.take() {
                            sess.shutdown().await;
                        }
                        send_err(
                            &mut stream,
                            2013,
                            "HY000",
                            &format!("RAXIS proxy: STMT_EXECUTE relay failed: {detail}"),
                        )
                        .await?;
                    }
                }
            }
            wire::cmd::STMT_FETCH => {
                if !ensure_upstream(
                    &mut stream,
                    &mut upstream_session,
                    upstream_url.as_ref(),
                    &config,
                    &stats,
                    &audit,
                )
                .await?
                {
                    continue;
                }
                let session = upstream_session.as_mut().expect("ensured above");
                match session.forward_stmt_fetch(&payload).await {
                    Ok(outcome) => {
                        for frame in &outcome.frames {
                            stream.write_all(frame).await?;
                        }
                        stream.flush().await?;
                        stats
                            .upstream_bytes_forwarded
                            .fetch_add(outcome.bytes_returned, Ordering::Relaxed);
                    }
                    Err(e) => {
                        let detail = redact_for_audit(&e.to_string());
                        if let Some(sess) = upstream_session.take() {
                            sess.shutdown().await;
                        }
                        send_err(
                            &mut stream,
                            2013,
                            "HY000",
                            &format!("RAXIS proxy: STMT_FETCH relay failed: {detail}"),
                        )
                        .await?;
                    }
                }
            }
            wire::cmd::STMT_RESET => {
                if !ensure_upstream(
                    &mut stream,
                    &mut upstream_session,
                    upstream_url.as_ref(),
                    &config,
                    &stats,
                    &audit,
                )
                .await?
                {
                    continue;
                }
                let session = upstream_session.as_mut().expect("ensured above");
                match session.forward_stmt_reset(&payload).await {
                    Ok(outcome) => {
                        for frame in &outcome.frames {
                            stream.write_all(frame).await?;
                        }
                        stream.flush().await?;
                    }
                    Err(e) => {
                        let detail = redact_for_audit(&e.to_string());
                        if let Some(sess) = upstream_session.take() {
                            sess.shutdown().await;
                        }
                        send_err(
                            &mut stream,
                            2013,
                            "HY000",
                            &format!("RAXIS proxy: STMT_RESET relay failed: {detail}"),
                        )
                        .await?;
                    }
                }
            }
            wire::cmd::STMT_CLOSE | wire::cmd::STMT_SEND_LONG_DATA => {
                // Both commands have NO reply per the MySQL protocol.
                // Forward to the upstream best-effort and continue.
                if upstream_session.is_none() {
                    // Nothing to forward — continue silently to
                    // mirror MySQL's no-reply behaviour. The agent's
                    // driver does not expect a reply, so this is
                    // safe.
                    continue;
                }
                let session = upstream_session.as_mut().expect("checked above");
                if let Err(e) = session.forward_stmt_no_reply(&payload).await {
                    tracing::debug!(error = %e, "STMT_CLOSE/SEND_LONG_DATA relay failed");
                    // Drop the upstream session so the next command
                    // re-establishes a clean connection. The agent
                    // still does not get an error frame (the
                    // protocol forbids one).
                    if let Some(sess) = upstream_session.take() {
                        sess.shutdown().await;
                    }
                }
            }
            other => {
                // Unsupported command — return ER_NOT_SUPPORTED_YET.
                tracing::warn!(
                    cmd = format!("0x{other:02x}"),
                    "mysql proxy received unsupported command"
                );
                let err = wire::build_err_packet(
                    1235, // ER_NOT_SUPPORTED_YET
                    "0A000",
                    "command not supported by RAXIS proxy in V2",
                );
                stream.write_all(&wire::frame_packet(&err, 1)).await?;
                stream.flush().await?;
            }
        }
    }

    // Best-effort upstream shutdown so the real backend logs a
    // `Quit` rather than a connection-reset.
    if let Some(sess) = upstream_session {
        sess.shutdown().await;
    }
    Ok(())
}

/// Send an ERR_Packet with the canonical V2.1 sequence ID (1) and
/// flush it to the agent.
async fn send_err(
    stream: &mut TcpStream,
    code: u16,
    sqlstate: &str,
    msg: &str,
) -> std::io::Result<()> {
    let err = wire::build_err_packet(code, sqlstate, msg);
    stream.write_all(&wire::frame_packet(&err, 1)).await?;
    stream.flush().await
}

/// Ensure a usable upstream session is open before forwarding a
/// command. Returns `true` when the caller may proceed and `false`
/// when an `ERR_Packet` has already been sent and the caller should
/// continue to the next command.
async fn ensure_upstream(
    stream: &mut TcpStream,
    upstream_session: &mut Option<UpstreamSession>,
    upstream_url: Option<&ParsedUpstreamUrl>,
    config: &ProxyConfig,
    stats: &Arc<ProxyStats>,
    audit: &Arc<dyn AuditChannel>,
) -> std::io::Result<bool> {
    if upstream_session.is_some() {
        return Ok(true);
    }
    let url = match upstream_url {
        Some(u) => u,
        None => {
            send_err(stream, 2003, "HY000",
                "RAXIS proxy: upstream credential could not be resolved (FAIL_PROXY_UPSTREAM_URL_INVALID)").await?;
            return Ok(false);
        }
    };
    let host = url.host.clone();
    let port = url.port;
    stats
        .upstream_connects_attempted
        .fetch_add(1, Ordering::Relaxed);
    match UpstreamSession::connect(url, upstream::DEFAULT_CONNECT_TIMEOUT).await {
        Ok(sess) => {
            stats
                .upstream_connects_succeeded
                .fetch_add(1, Ordering::Relaxed);
            audit.emit(AuditEvent::CredentialProxyUpstreamConnected {
                timestamp_unix_seconds: now_secs(),
                consumer: config.consumer.clone(),
                credential: config.credential_name.clone(),
                upstream_host: sess.host.clone(),
                upstream_port: sess.port,
                tls: sess.tls,
                handshake_ms: sess.handshake_ms,
            });
            *upstream_session = Some(sess);
            Ok(true)
        }
        Err(e) => {
            stats
                .upstream_connects_failed
                .fetch_add(1, Ordering::Relaxed);
            audit.emit(AuditEvent::CredentialProxyUpstreamFailed {
                timestamp_unix_seconds: now_secs(),
                consumer: config.consumer.clone(),
                credential: config.credential_name.clone(),
                upstream_host: host,
                upstream_port: port,
                reason: e.audit_reason().to_owned(),
                detail: e.audit_detail(),
            });
            let (code, sqlstate, msg) = match &e {
                UpstreamError::AuthRejected(_) => (
                    1045u16, "28000",
                    "RAXIS proxy: upstream authentication rejected (FAIL_PROXY_UPSTREAM_AUTH_REJECTED)",
                ),
                UpstreamError::TcpConnect(_) | UpstreamError::Timeout { .. } => (
                    2003u16, "HY000",
                    "RAXIS proxy: upstream unreachable (FAIL_PROXY_UPSTREAM_UNREACHABLE)",
                ),
                UpstreamError::InvalidUrl(_) => (
                    2003u16, "HY000",
                    "RAXIS proxy: upstream URL invalid (FAIL_PROXY_UPSTREAM_URL_INVALID)",
                ),
                _ => (
                    2003u16, "HY000",
                    "RAXIS proxy: upstream connection failed",
                ),
            };
            send_err(stream, code, sqlstate, msg).await?;
            Ok(false)
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn read_packet(
    stream: &mut TcpStream,
) -> std::io::Result<Option<(wire::PacketHeader, Vec<u8>)>> {
    let mut header = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut header).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e);
    }
    let h = wire::PacketHeader::parse(header);
    if h.payload_len > wire::MAX_PACKET_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("MySQL packet payload {} exceeds 16MiB cap", h.payload_len),
        ));
    }
    let mut payload = vec![0u8; h.payload_len];
    stream.read_exact(&mut payload).await?;
    Ok(Some((h, payload)))
}

/// Derive 20 bytes of scramble. We seed a SHA-256 of (server_version
/// + consumer.id + connection-counter) so distinct connections
/// observe distinct scrambles even though we never use them
/// upstream. Deterministic-by-input but unpredictable across
/// distinct sessions.
fn derive_handshake_scramble(config: &ProxyConfig) -> [u8; 20] {
    use sha2::{Digest, Sha256};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut h = Sha256::new();
    h.update(config.server_version.as_bytes());
    h.update(b"|");
    h.update(config.consumer.id.as_bytes());
    h.update(b"|");
    h.update(&n.to_le_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

fn thread_id_for(config: &ProxyConfig) -> u32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(config.consumer.id.as_bytes());
    let d = h.finalize();
    u32::from_le_bytes([d[0], d[1], d[2], d[3]])
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// V2 — restriction decision plumbing
//   (`proxy-table-allowlists.md §8`)
// ---------------------------------------------------------------------------

/// Translate a `RestrictionDecision` into the audit-event fields
/// `(blocked, tables_referenced, restriction_reason)`. Per
/// `proxy-table-allowlists.md §8.3`: `AuditOnly` decisions surface
/// as `blocked = false` BUT carry the would-have-blocked reason in
/// `restriction_reason`.
fn decision_to_audit_fields(decision: &RestrictionDecision) -> (bool, Vec<String>, Option<String>) {
    match decision {
        RestrictionDecision::Admit { tables_referenced } => {
            (false, tables_referenced.clone(), None)
        }
        RestrictionDecision::Block {
            reason,
            tables_referenced,
        } => (
            true,
            tables_referenced.clone(),
            Some(reason.as_str().to_owned()),
        ),
        RestrictionDecision::AuditOnly {
            reason,
            tables_referenced,
        } => (
            false,
            tables_referenced.clone(),
            Some(reason.as_str().to_owned()),
        ),
    }
}

/// Bump the per-restriction-class counter for a blocked decision.
/// Always bumps the V2.1 `queries_blocked` aggregate too.
fn bump_blocked_counters(stats: &Arc<ProxyStats>, decision: &RestrictionDecision) {
    stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
    if let RestrictionDecision::Block { reason, .. } = decision {
        match reason {
            RestrictionReason::TableNotInAllowedList | RestrictionReason::TableInForbiddenList => {
                stats
                    .queries_blocked_by_table_allowlist
                    .fetch_add(1, Ordering::Relaxed);
            }
            RestrictionReason::AmbiguousSqlMultiStatement
            | RestrictionReason::AmbiguousSqlDynamic
            | RestrictionReason::AmbiguousSqlMalformed => {
                stats
                    .queries_blocked_by_ambiguous_sql
                    .fetch_add(1, Ordering::Relaxed);
            }
            RestrictionReason::AllowOnlySelect => {}
        }
    }
}

/// `(sqlstate, message)` for a `RestrictionDecision::Block`. Per
/// `proxy-table-allowlists.md §9.1`: sqlstate `42501` for
/// allow/deny decisions; `54000` is reserved for `max_result_rows`.
/// Message embeds the closed-enum reason verbatim per the
/// `R-10 Opaque Rejection` discussion in §1.3 of that spec.
fn error_for_decision(decision: &RestrictionDecision) -> (String, String) {
    let reason = match decision {
        RestrictionDecision::Block { reason, .. } => reason,
        _ => return ("42501".to_owned(), "blocked by RAXIS policy".to_owned()),
    };
    (
        "42501".to_owned(),
        format!("blocked by RAXIS policy: {}", reason.as_str()),
    )
}

// ---------------------------------------------------------------------------
// V2 — streaming `max_result_rows` cap
//   (`proxy-table-allowlists.md §7.1`)
// ---------------------------------------------------------------------------

/// Result of applying the `max_result_rows` streaming cap to a
/// completed MySQL `ForwardOutcome`. Mirrors the Postgres helper of
/// the same name.
///
/// MySQL's result-set wire shape per the protocol reference:
///   * ResultSetHeader (length-encoded column count) — frame 0
///   * N ColumnDef packets
///   * EOF packet (unless `CLIENT_DEPRECATE_EOF` negotiated, which
///     V2.4 does NOT do upstream — see `upstream.rs`)
///   * M Row packets — these are what we cap
///   * Terminating EOF or OK packet
///
/// When the cap fires we truncate the row packets to N and replace
/// the trailing EOF/OK with an `ERR_Packet { code = 1226, sqlstate
/// = "54000", reason = "max_result_rows_exceeded" }` so the agent's
/// driver sees a visible cap rather than a silent truncation. The
/// caller writes the synthetic ERR packet with sequence ID
/// `next_seq` (which we compute by counting frames kept).
#[derive(Debug)]
struct CappedOutcome {
    frames: Vec<Vec<u8>>,
    rows_returned: u64,
    bytes_returned: u64,
    duration_ms: u32,
    cap_triggered: bool,
    /// Sequence ID the caller must use for the synthetic terminator
    /// ERR_Packet. Honoured ONLY when `cap_triggered = true`.
    next_seq: u8,
    /// Forwarded upstream-error sqlstate when the upstream produced
    /// an ERR mid-stream and the cap did NOT fire.
    upstream_error_sqlstate: Option<String>,
}

fn apply_max_result_rows_cap(
    outcome: crate::upstream::ForwardOutcome,
    max_result_rows: u64,
) -> CappedOutcome {
    let duration_ms = outcome.duration_ms;
    let upstream_error_sqlstate = outcome.upstream_error.as_ref().map(|(_, sqlstate, _)| {
        if sqlstate.is_empty() {
            "HY000".to_owned()
        } else {
            sqlstate.clone()
        }
    });
    if max_result_rows == 0 || outcome.rows_returned <= max_result_rows {
        return CappedOutcome {
            frames: outcome.frames,
            rows_returned: outcome.rows_returned,
            bytes_returned: outcome.bytes_returned,
            duration_ms,
            cap_triggered: false,
            next_seq: 0,
            upstream_error_sqlstate,
        };
    }
    // Cap fires. We need to walk the response packets and keep:
    //   1. ResultSetHeader (frame 0)
    //   2. The N column-definition packets
    //   3. The EOF marking end of column metadata
    //   4. The first `max_result_rows` row packets
    // ...then drop everything else (further rows + terminating EOF).
    // The caller emits an ERR_Packet with sequence ID `next_seq`.
    //
    // Detecting "row vs EOF vs OK vs ERR" from a raw frame: the
    // 4-byte packet header is `bytes[0..3] = payload_len (LE)`,
    // `bytes[3] = seq_id`. The first payload byte is `bytes[4]`.
    //   * 0xff           → ERR (relay verbatim, do NOT cap)
    //   * 0xfe + payload_len < 9 → EOF (without CLIENT_DEPRECATE_EOF;
    //                          this is the V2.4 upstream shape).
    //   * else                   → row or column metadata.
    //
    // We're past column metadata once we've seen the first EOF.
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(outcome.frames.len());
    let mut bytes: u64 = 0;
    let mut rows_kept: u64 = 0;
    let mut seen_metadata_eof = false;
    let mut last_seq: u8 = 0;
    for frame in outcome.frames.into_iter() {
        let kind = mysql_frame_kind(&frame);
        if let Some(seq) = frame.get(3).copied() {
            last_seq = seq;
        }
        match kind {
            MysqlFrameKind::Err => {
                // Upstream ERR — relay verbatim; do not cap.
                bytes += frame.len() as u64;
                out.push(frame);
                break;
            }
            MysqlFrameKind::Eof if !seen_metadata_eof => {
                // First EOF: end of column-definition section.
                seen_metadata_eof = true;
                bytes += frame.len() as u64;
                out.push(frame);
            }
            MysqlFrameKind::Eof => {
                // Second EOF (or OK_Packet acting as terminator):
                // drop — the caller substitutes an ERR_Packet so
                // the cap is visible to the client.
            }
            MysqlFrameKind::OtherOrRow if !seen_metadata_eof => {
                // Column-metadata frame (ResultSetHeader or
                // ColumnDef). Keep as-is.
                bytes += frame.len() as u64;
                out.push(frame);
            }
            MysqlFrameKind::OtherOrRow => {
                // Row packet (we're past the metadata EOF).
                if rows_kept < max_result_rows {
                    bytes += frame.len() as u64;
                    out.push(frame);
                    rows_kept += 1;
                }
                // Drop further rows.
            }
        }
    }
    CappedOutcome {
        frames: out,
        rows_returned: rows_kept,
        bytes_returned: bytes,
        duration_ms,
        cap_triggered: true,
        next_seq: last_seq.wrapping_add(1),
        upstream_error_sqlstate: None,
    }
}

#[derive(Debug)]
enum MysqlFrameKind {
    /// `ERR_Packet` — payload[0] = 0xff.
    Err,
    /// `EOF_Packet` (or short `OK_Packet` acting as a terminator
    /// when `CLIENT_DEPRECATE_EOF` is negotiated upstream): payload
    /// starts with 0xfe and is < 9 bytes.
    Eof,
    /// Either a row, the `ResultSetHeader`, or a `ColumnDef` packet.
    /// Disambiguated by the caller using `seen_metadata_eof`.
    OtherOrRow,
}

fn mysql_frame_kind(frame: &[u8]) -> MysqlFrameKind {
    if frame.len() < 5 {
        return MysqlFrameKind::OtherOrRow;
    }
    let first = frame[4];
    let payload_len =
        (frame[0] as usize) | ((frame[1] as usize) << 8) | ((frame[2] as usize) << 16);
    if first == 0xff {
        return MysqlFrameKind::Err;
    }
    if first == 0xfe && payload_len < 9 {
        return MysqlFrameKind::Eof;
    }
    MysqlFrameKind::OtherOrRow
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_module_re_export_works() {
        // Re-exports: just make sure the surface is reachable from
        // the public API (downstream callers go through the lib).
        assert_eq!(classify_first_operation("SELECT 1"), OperationKind::Select);
        assert_eq!(
            classify_first_operation("DROP TABLE t"),
            OperationKind::Other("DROP".into())
        );
    }

    #[test]
    fn restrictions_select_only_round_trip() {
        let r = Restrictions::select_only();
        assert!(r.allow_only_select);
        assert!(r.is_blocked(&OperationKind::Insert));
        assert!(!r.is_blocked(&OperationKind::Select));
    }
}
