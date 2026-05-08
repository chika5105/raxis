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
//!   * `forbidden_tables`, `forbidden_schemas`, `max_result_rows`,
//!     `statement_timeout_ms`.
//!   * Multi-packet messages — V2 reads exactly one packet per
//!     message (so SQL > 4060 bytes is rejected; production
//!     queries fit comfortably).

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use raxis_credentials::{CredentialBackend, CredentialName, ConsumerIdentity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod restriction;
pub mod wire;

pub use restriction::{OperationKind, Restrictions, classify_first_operation};

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

/// Configuration for one MSSQL proxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the inbound listener binds to.
    pub listen_addr:     String,
    /// Credential to resolve once at proxy bind. Bytes are NEVER
    /// surfaced beyond the proxy boundary.
    pub credential_name: CredentialName,
    /// Identity of the agent session this proxy serves.
    pub consumer:        OwnedConsumer,
    /// Server-version string the proxy advertises in its
    /// LOGINACK token. Defaults to a RAXIS-tagged string so
    /// server fingerprinters log "ours, not yours".
    pub server_version:  String,
    /// Effective restriction set parsed out of
    /// `[tasks.credentials.restrictions]`.
    pub restrictions:    Restrictions,
    /// When `true`, `AuditEvent::DatabaseQueryExecuted` carries
    /// the SQL plaintext alongside its `sql_sha256`.
    pub log_content:     bool,
}

/// Counters surfaced for `CredentialProxyStopped`.
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Number of accepted inbound TCP connections.
    pub connections_served: AtomicU32,
    /// Number of `SQLBatch` statements observed (allowed + blocked).
    pub queries_audited:    AtomicU32,
    /// Number of `SQLBatch` statements rejected by `Restrictions`.
    pub queries_blocked:    AtomicU32,
    /// Bytes seen in inbound `SQLBatch` payloads.
    pub bytes_observed:     AtomicU64,
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served: self.connections_served.load(Ordering::Relaxed),
            queries_audited:    self.queries_audited   .load(Ordering::Relaxed),
            queries_blocked:    self.queries_blocked   .load(Ordering::Relaxed),
            bytes_observed:     self.bytes_observed    .load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted inbound TCP connections.
    pub connections_served: u32,
    /// Number of `SQLBatch` statements observed.
    pub queries_audited:    u32,
    /// Number of `SQLBatch` statements rejected by `Restrictions`.
    pub queries_blocked:    u32,
    /// Bytes seen in inbound `SQLBatch` payloads.
    pub bytes_observed:     u64,
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
    DatabaseQueryExecuted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
        /// Hex SHA-256 of the SQL text bytes.
        sql_sha256:  String,
        /// SQL plaintext, when `ProxyConfig::log_content` is set.
        sql_text:    Option<String>,
        /// `Select` / `Insert` / etc.
        operation:   OperationKind,
        /// True if the proxy refused the batch under restrictions.
        blocked:     bool,
    },
}

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

/// MSSQL TDS credential proxy.
pub struct MssqlProxy {
    listener: TcpListener,
    backend:  Arc<dyn CredentialBackend>,
    config:   ProxyConfig,
    stats:    Arc<ProxyStats>,
    audit:    Arc<dyn AuditChannel>,
}

impl MssqlProxy {
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

    /// Address the listener bound to.
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
    backend:    Arc<dyn CredentialBackend>,
    config:     ProxyConfig,
    stats:      Arc<ProxyStats>,
    audit:      Arc<dyn AuditChannel>,
) -> std::io::Result<()> {
    if let Err(e) = backend.resolve(&config.credential_name, config.consumer.as_ref()) {
        tracing::warn!(error = %e, "mssql proxy credential resolve failed");
        return Ok(());
    }

    // Step 1 — read PRELOGIN (drained).
    let pkt = match read_packet(&mut stream).await? {
        Some(p) => p,
        None    => return Ok(()),
    };
    if pkt.0.packet_type != wire::pkt::PRELOGIN {
        return Ok(());
    }
    // Step 2 — send PRELOGIN response.
    let body = wire::build_prelogin_response_body();
    stream.write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &body)).await?;
    stream.flush().await?;

    // Step 3 — read LOGIN7 (drained).
    let pkt = match read_packet(&mut stream).await? {
        Some(p) => p,
        None    => return Ok(()),
    };
    if pkt.0.packet_type != wire::pkt::LOGIN7 {
        return Ok(());
    }
    // Step 4 — send LOGINACK + DONE.
    let body = wire::build_loginack_done_body(&config.server_version);
    stream.write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &body)).await?;
    stream.flush().await?;

    // Step 5 — command loop.
    loop {
        let pkt = match read_packet(&mut stream).await? {
            Some(p) => p,
            None    => return Ok(()),
        };
        let (header, body) = pkt;
        if header.packet_type != wire::pkt::SQL_BATCH {
            // Anything else (RPC, TRANSMGR, ATTENTION) is V3.
            let err = wire::build_error_done_body(
                -1,
                "non-SQLBatch packet types not supported by RAXIS proxy in V2",
            );
            stream.write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &err)).await?;
            stream.flush().await?;
            continue;
        }

        stats.bytes_observed.fetch_add(body.len() as u64, Ordering::Relaxed);
        let sql = wire::decode_sql_batch_body(&body)
            .unwrap_or_default();
        let op  = classify_first_operation(&sql);

        let blocked = config.restrictions.is_blocked(&op);
        stats.queries_audited.fetch_add(1, Ordering::Relaxed);

        let resp = if blocked {
            stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
            wire::build_error_done_body(
                -1,
                "operation blocked by RAXIS allow_only_select policy",
            )
        } else {
            wire::build_done_token(0x0000, 0x0000, 0)
        };
        stream.write_all(&wire::frame_packet(wire::pkt::TABULAR_RESULT, &resp)).await?;
        stream.flush().await?;

        audit.emit(AuditEvent::DatabaseQueryExecuted {
            timestamp_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            consumer:    config.consumer.clone(),
            credential:  config.credential_name.clone(),
            sql_sha256:  sha256_hex(sql.as_bytes()),
            sql_text:    if config.log_content { Some(sql) } else { None },
            operation:   op,
            blocked,
        });
    }
}

async fn read_packet(stream: &mut TcpStream) -> std::io::Result<Option<(wire::PacketHeader, Vec<u8>)>> {
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
        assert_eq!(classify_first_operation("DROP TABLE t"), OperationKind::Other("DROP".into()));
    }

    #[test]
    fn restrictions_select_only_round_trip() {
        let r = Restrictions::select_only();
        assert!(r.allow_only_select);
        assert!( r.is_blocked(&OperationKind::Insert));
        assert!(!r.is_blocked(&OperationKind::Select));
    }
}
