//! `raxis-credential-proxy-mssql` — MSSQL TDS credential proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §4.3`
//! (MSSQL). The proxy speaks the TDS wire (Microsoft SQL Server's
//! Tabular Data Stream protocol) and drives the
//! `PRELOGIN → LOGIN7 → LOGINACK + DONE` handshake on its own
//! bytes. The agent's `LOGIN7` payload (username, password,
//! database, app name, etc.) is **discarded** — the kernel-resolved
//! credential is what the proxy would have used to authenticate
//! against a real upstream in V3 (V2 MVP synthesises responses
//! to demonstrate handshake-tier integration end-to-end without
//! a live `sqlservr.exe`).
//!
//! After the handshake, the proxy loops on `SQLBatch` (packet
//! type 0x01). Every batch's UTF-16 LE SQL text is classified by
//! [`restriction::classify_first_operation`]; under
//! `allow_only_select` everything but `SELECT` is rejected with an
//! `ERROR` token (number `-1`, severity 14) followed by a
//! `DONE_ERROR` (status bit 0x0002). Allowed batches get
//! `DONE` with `done_count = 0`.
//!
//! # What this MVP supports
//!
//!   * PRELOGIN inbound + outbound (advertises VERSION + ENCRYPTION
//!     "not supported" — the kernel terminates TLS at the VM
//!     boundary, not at the proxy).
//!   * LOGIN7 inbound — drained.
//!   * LOGINACK + DONE outbound (TDS 7.3 interface=TSQL,
//!     SQL Server 2019 version stamp).
//!   * SQLBatch inbound + Tabular Result outbound (DONE for OK,
//!     ERROR + DONE_ERROR for blocked).
//!   * `allow_only_select` enforcement.
//!
//! # What is deferred
//!
//!   * Real upstream forwarding via `tiberius` / `tds-rs`.
//!   * TLS — the V2 wire is plaintext TDS only; clients that
//!     require encryption (`Encrypt=true` in the JDBC URL) will
//!     fail PRELOGIN with `ENCRYPTION = NOT_SUP`. V3 lands TLS via
//!     `tokio-rustls` once `tds-rs` is wired up.
//!   * RPC requests (packet type 0x03) — V2 returns ERROR + DONE
//!     for any non-SQLBatch packet after login.
//!   * **Streaming** `max_result_rows` cap — the field is plumbed
//!     and surfaced in audit, but ROW-token counting in the TDS
//!     token stream is V2-followup work (see
//!     `proxy-table-allowlists.md §11`). `allowed_tables`,
//!     `forbidden_tables`, and ambiguity fail-closure are
//!     enforced as of this commit.
//!   * `statement_timeout_ms`.
//!   * Multi-packet messages — V2 reads exactly one packet per
//!     message (so SQL > 4060 bytes is rejected; production
//!     queries fit comfortably).

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
    classify_first_operation, extract_relations, AmbiguityReason, OperationKind, RelationList,
    RestrictionDecision, RestrictionReason, Restrictions,
};
pub use upstream::{
    redact_for_audit, resolve_upstream_url, ForwardOutcome, ParsedUpstreamUrl, UpstreamError,
    UpstreamSession, DEFAULT_CONNECT_TIMEOUT,
};

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

/// Configuration for one MSSQL proxy listener.
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
    /// LOGINACK token. Defaults to a RAXIS-tagged string so
    /// server fingerprinters log "ours, not yours".
    pub server_version: String,
    /// Effective restriction set parsed out of
    /// `[tasks.credentials.restrictions]`.
    pub restrictions: Restrictions,
    /// When `true`, `AuditEvent::DatabaseQueryExecuted` carries
    /// the SQL plaintext alongside its `sql_sha256`.
    pub log_content: bool,
}

/// Counters surfaced for `CredentialProxyStopped`.
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Number of accepted inbound TCP connections.
    pub connections_served: AtomicU32,
    /// Number of `SQLBatch` statements observed (allowed + blocked).
    pub queries_audited: AtomicU32,
    /// Number of `SQLBatch` statements rejected by `Restrictions`.
    pub queries_blocked: AtomicU32,
    /// V2: subset of `queries_blocked` blocked by the
    /// `allowed_tables` / `forbidden_tables` walker.
    pub queries_blocked_by_table_allowlist: AtomicU32,
    /// V2: subset of `queries_blocked` blocked because the walker
    /// could not prove the relation list (fail-closed under the
    /// V2 ambiguity policy).
    pub queries_blocked_by_ambiguous_sql: AtomicU32,
    /// Bytes seen in inbound `SQLBatch` payloads.
    pub bytes_observed: AtomicU64,
    /// V2.1: number of upstream TCP+auth handshakes started.
    pub upstream_connects_attempted: AtomicU32,
    /// V2.1: subset that reached a usable upstream session.
    pub upstream_connects_succeeded: AtomicU32,
    /// V2.1: subset that failed.
    pub upstream_connects_failed: AtomicU32,
    /// V2.1: sum of upstream→agent payload bytes relayed.
    pub upstream_bytes_forwarded: AtomicU64,
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served: self.connections_served.load(Ordering::Relaxed),
            queries_audited: self.queries_audited.load(Ordering::Relaxed),
            queries_blocked: self.queries_blocked.load(Ordering::Relaxed),
            queries_blocked_by_table_allowlist: self
                .queries_blocked_by_table_allowlist
                .load(Ordering::Relaxed),
            queries_blocked_by_ambiguous_sql: self
                .queries_blocked_by_ambiguous_sql
                .load(Ordering::Relaxed),
            bytes_observed: self.bytes_observed.load(Ordering::Relaxed),
            upstream_connects_attempted: self.upstream_connects_attempted.load(Ordering::Relaxed),
            upstream_connects_succeeded: self.upstream_connects_succeeded.load(Ordering::Relaxed),
            upstream_connects_failed: self.upstream_connects_failed.load(Ordering::Relaxed),
            upstream_bytes_forwarded: self.upstream_bytes_forwarded.load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted inbound TCP connections.
    pub connections_served: u32,
    /// Number of `SQLBatch` statements observed.
    pub queries_audited: u32,
    /// Number of `SQLBatch` statements rejected by `Restrictions`.
    pub queries_blocked: u32,
    /// V2: subset of `queries_blocked` blocked by the
    /// `allowed_tables` / `forbidden_tables` walker.
    pub queries_blocked_by_table_allowlist: u32,
    /// V2: subset of `queries_blocked` blocked because the walker
    /// could not prove the relation list.
    pub queries_blocked_by_ambiguous_sql: u32,
    /// Bytes seen in inbound `SQLBatch` payloads.
    pub bytes_observed: u64,
    /// V2.1: number of upstream TCP+auth handshakes started.
    pub upstream_connects_attempted: u32,
    /// V2.1: subset that reached a usable upstream session.
    pub upstream_connects_succeeded: u32,
    /// V2.1: subset that failed.
    pub upstream_connects_failed: u32,
    /// V2.1: sum of upstream→agent payload bytes relayed.
    pub upstream_bytes_forwarded: u64,
}

/// Audit channel.
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
    /// One `SQLBatch` statement observed (allowed or blocked).
    /// Pre-upstream-contact event.
    DatabaseQueryExecuted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer: OwnedConsumer,
        /// Credential name (never the value).
        credential: CredentialName,
        /// Hex SHA-256 of the SQL text bytes.
        sql_sha256: String,
        /// SQL plaintext, when `ProxyConfig::log_content` is set.
        sql_text: Option<String>,
        /// `Select` / `Insert` / etc.
        operation: OperationKind,
        /// True if the proxy refused the batch under restrictions.
        blocked: bool,
        /// V2: walker-resolved relation list, canonicalised to
        /// `<schema>.<table>` or bare `<table>` (per
        /// `proxy-table-allowlists.md §8.1`).
        tables_referenced: Vec<String>,
        /// V2: closed-enum reason key, present iff the batch was
        /// blocked OR audited-only by V2 restrictions.
        restriction_reason: Option<&'static str>,
    },

    /// V2.1: emitted on the upstream's terminal frame for a
    /// forwarded SQLBatch. Pairs with `DatabaseQueryExecuted` via
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
        /// V2.1 MVP doesn't parse upstream ROW tokens; we emit `1`
        /// per allowed batch. V3 lands token-stream parsing for an
        /// accurate count.
        rows_returned: u64,
        /// Bytes the upstream returned (header + body of every
        /// TABULAR_RESULT packet for this batch).
        bytes_returned: u64,
        /// Wall-clock duration in milliseconds.
        duration_ms: u32,
        /// `Some(reason)` if the upstream's reply contained an
        /// `ERROR` token (0xAA); `None` on success.
        upstream_error: Option<String>,
    },

    /// V2.1: emitted once per agent connection on the first
    /// successful upstream PRELOGIN+LOGIN7 handshake.
    /// Per `credential-proxy.md §14.5.2`.
    CredentialProxyUpstreamConnected {
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
        /// True if the URL requested TLS.
        tls: bool,
        /// Wall-clock from `TcpStream::connect()` start to first
        /// usable session, in milliseconds.
        handshake_ms: u32,
    },

    /// V2.1: emitted on every upstream-connect attempt that did NOT
    /// reach a usable session.
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

/// MSSQL TDS credential proxy.
pub struct MssqlProxy {
    listener: TcpListener,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    stats: Arc<ProxyStats>,
    audit: Arc<dyn AuditChannel>,
}

impl MssqlProxy {
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
                            tracing::warn!(error = %e, "mssql proxy connection ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "mssql proxy accept failed");
                    break;
                }
            }
        }
    }
}

async fn serve_one(
    mut stream: TcpStream,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    stats: Arc<ProxyStats>,
    audit: Arc<dyn AuditChannel>,
) -> std::io::Result<()> {
    // Resolve+parse the upstream URL on accept. Failures are
    // tolerated and surfaced lazily on the first allowed batch
    // (mirrors the postgres + mysql + mongodb proxies).
    let upstream_url: Option<ParsedUpstreamUrl> =
        match upstream::resolve_upstream_url(&backend, &config.credential_name, &config.consumer) {
            Ok(u) => Some(u),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    credential = %config.credential_name.as_str(),
                    "mssql proxy upstream URL resolution failed; first allowed batch will fail",
                );
                None
            }
        };

    // Step 1 — read PRELOGIN (drained).
    let pkt = match read_packet(&mut stream).await? {
        Some(p) => p,
        None => return Ok(()),
    };
    if pkt.0.packet_type != wire::pkt::PRELOGIN {
        return Ok(());
    }
    // Step 2 — send PRELOGIN response (proxy synthesises this so
    // the agent's SDK negotiates against our wire shape; the
    // upstream's PRELOGIN happens later, lazily, when the first
    // allowed batch demands a real upstream session).
    let body = wire::build_prelogin_response_body();
    stream
        .write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &body))
        .await?;
    stream.flush().await?;

    // Step 3 — read LOGIN7 (drained — agent's credentials are
    // discarded; the kernel-resolved URL is what authenticates
    // upstream).
    let pkt = match read_packet(&mut stream).await? {
        Some(p) => p,
        None => return Ok(()),
    };
    if pkt.0.packet_type != wire::pkt::LOGIN7 {
        return Ok(());
    }
    // Step 4 — send LOGINACK + DONE.
    let body = wire::build_loginack_done_body(&config.server_version);
    stream
        .write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &body))
        .await?;
    stream.flush().await?;

    let mut upstream_session: Option<UpstreamSession> = None;

    // Step 5 — command loop.
    loop {
        let pkt = match read_packet(&mut stream).await? {
            Some(p) => p,
            None => break,
        };
        let (header, body) = pkt;
        if header.packet_type != wire::pkt::SQL_BATCH {
            // Anything else (RPC, TRANSMGR, ATTENTION) is V3.
            let err = wire::build_error_done_body(
                -1,
                "non-SQLBatch packet types not supported by RAXIS proxy in V2",
            );
            stream
                .write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &err))
                .await?;
            stream.flush().await?;
            continue;
        }

        stats
            .bytes_observed
            .fetch_add(body.len() as u64, Ordering::Relaxed);
        let sql = wire::decode_sql_batch_body(&body).unwrap_or_default();
        let op = classify_first_operation(&sql);

        let decision = config.restrictions.check(&sql, &op);
        stats.queries_audited.fetch_add(1, Ordering::Relaxed);
        let sql_sha = sha256_hex(sql.as_bytes());

        let (tables_referenced, restriction_reason, is_block) = decision_to_audit_fields(&decision);
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
            blocked: is_block,
            tables_referenced,
            restriction_reason,
        });

        if is_block {
            bump_blocked_counters(&stats, &decision);
            let resp = wire::build_error_done_body(-1, error_message_for_decision(&decision));
            stream
                .write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &resp))
                .await?;
            stream.flush().await?;
            continue;
        }

        // Allowed batch: ensure a usable upstream session, then
        // forward the agent's SQLBatch packet verbatim.
        if upstream_session.is_none() {
            let url = match upstream_url.as_ref() {
                Some(u) => u,
                None => {
                    let err = wire::build_error_done_body(
                        -3,
                        "RAXIS proxy: upstream credential could not be resolved (FAIL_PROXY_UPSTREAM_URL_INVALID)",
                    );
                    stream
                        .write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &err))
                        .await?;
                    stream.flush().await?;
                    continue;
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
                    upstream_session = Some(sess);
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
                    let err = wire::build_error_done_body(
                        -3,
                        &format!(
                            "RAXIS proxy: upstream connect failed ({}): {}",
                            e.audit_reason(),
                            e.audit_detail(),
                        ),
                    );
                    stream
                        .write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &err))
                        .await?;
                    stream.flush().await?;
                    continue;
                }
            }
        }

        let session = upstream_session.as_mut().expect("upstream connected above");
        // Re-encode the agent's SQLBatch packet (header + body) as
        // a single buffer to forward to the upstream verbatim.
        let agent_pkt = {
            let mut p = Vec::with_capacity(wire::HEADER_LEN + body.len());
            p.extend_from_slice(&header.encode());
            p.extend_from_slice(&body);
            p
        };
        match session.forward_sql_batch(&agent_pkt).await {
            Ok(outcome) => {
                stream.write_all(&outcome.frames).await?;
                stream.flush().await?;
                stats
                    .upstream_bytes_forwarded
                    .fetch_add(outcome.bytes_returned, Ordering::Relaxed);
                let upstream_error = if outcome.upstream_error {
                    Some("upstream_error".to_owned())
                } else {
                    None
                };
                audit.emit(AuditEvent::DatabaseQueryCompleted {
                    timestamp_unix_seconds: now_secs(),
                    consumer: config.consumer.clone(),
                    credential: config.credential_name.clone(),
                    sql_sha256: sql_sha,
                    rows_returned: 1,
                    bytes_returned: outcome.bytes_returned,
                    duration_ms: outcome.duration_ms,
                    upstream_error,
                });
            }
            Err(e) => {
                let detail = redact_for_audit(&e.to_string());
                upstream_session = None;
                let err = wire::build_error_done_body(
                    -3,
                    &format!("RAXIS proxy: upstream relay failed: {detail}"),
                );
                stream
                    .write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &err))
                    .await?;
                stream.flush().await?;
                audit.emit(AuditEvent::DatabaseQueryCompleted {
                    timestamp_unix_seconds: now_secs(),
                    consumer: config.consumer.clone(),
                    credential: config.credential_name.clone(),
                    sql_sha256: sql_sha,
                    rows_returned: 0,
                    bytes_returned: 0,
                    duration_ms: 0,
                    upstream_error: Some("relay_failed".to_owned()),
                });
            }
        }
    }

    Ok(())
}

/// Translate a `RestrictionDecision` into the audit-envelope
/// fields (`tables_referenced`, `restriction_reason`, `blocked`).
fn decision_to_audit_fields(
    decision: &RestrictionDecision,
) -> (Vec<String>, Option<&'static str>, bool) {
    match decision {
        RestrictionDecision::Admit { tables_referenced } => {
            (tables_referenced.clone(), None, false)
        }
        RestrictionDecision::Block {
            reason,
            tables_referenced,
        } => (tables_referenced.clone(), Some(reason.as_str()), true),
        RestrictionDecision::AuditOnly {
            reason,
            tables_referenced,
        } => (tables_referenced.clone(), Some(reason.as_str()), false),
    }
}

/// Increment the right `queries_blocked_*` sub-counter.
fn bump_blocked_counters(stats: &ProxyStats, decision: &RestrictionDecision) {
    let reason = match decision {
        RestrictionDecision::Block { reason, .. } => *reason,
        _ => return,
    };
    stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
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

fn error_message_for_decision(decision: &RestrictionDecision) -> &'static str {
    match decision {
        RestrictionDecision::Block { reason, .. } => match reason {
            RestrictionReason::AllowOnlySelect => {
                "operation blocked by RAXIS allow_only_select policy"
            }
            RestrictionReason::TableNotInAllowedList => {
                "operation blocked: relation not in RAXIS allowed_tables"
            }
            RestrictionReason::TableInForbiddenList => {
                "operation blocked: relation in RAXIS forbidden_tables"
            }
            RestrictionReason::AmbiguousSqlMultiStatement => {
                "operation blocked: multi-statement batch is ambiguous under RAXIS allowlist"
            }
            RestrictionReason::AmbiguousSqlDynamic => {
                "operation blocked: dynamic SQL is ambiguous under RAXIS allowlist"
            }
            RestrictionReason::AmbiguousSqlMalformed => {
                "operation blocked: malformed SQL could not be parsed by RAXIS allowlist walker"
            }
        },
        _ => "operation blocked by RAXIS policy",
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
    let mut header_bytes = [0u8; wire::HEADER_LEN];
    if let Err(e) = stream.read_exact(&mut header_bytes).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e);
    }
    let h = wire::PacketHeader::parse(header_bytes);
    let total = h.length as usize;
    if total < wire::HEADER_LEN {
        return Ok(None); // malformed; close.
    }
    if total > wire::MAX_PACKET_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("TDS packet length {total} exceeds 64 MiB cap"),
        ));
    }
    let body_len = total - wire::HEADER_LEN;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    Ok(Some((h, body)))
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_module_re_export_works() {
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
