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
//! After the handshake, the proxy loops on `COM_QUERY` /
//! `COM_QUIT` / `COM_PING`. Every `COM_QUERY` is classified by
//! [`restriction::classify_first_operation`]; under
//! `allow_only_select` everything but `SELECT` is rejected with an
//! `ERR_Packet { code = 1142, sqlstate = "42501" }` (the canonical
//! MySQL "access denied" shape). Allowed queries get a synthetic
//! `OK_Packet` reply (zero affected rows, zero last-insert-id).
//!
//! # What this MVP supports
//!
//!   * Initial `Protocol::HandshakeV10` greeting + 20-byte
//!     `auth_plugin_data` scramble.
//!   * `mysql_native_password` plugin advertisement (matches every
//!     mainstream MySQL client: mysql2 Node, mysql-connector-python,
//!     go-sql-driver/mysql, mysqlclient).
//!   * `HandshakeResponse41` ingestion + immediate `OK_Packet`
//!     reply (we do not validate the agent's password).
//!   * `COM_QUERY` classification + per-query audit emission with
//!     SHA-256 of the SQL bytes, optional plaintext (only when the
//!     consumer policy permits it; see `inference_audit.log_content`),
//!     and a `blocked` flag.
//!   * `allow_only_select` enforcement returning `ERR_Packet` with
//!     `42501`.
//!   * `COM_QUIT` (clean disconnect) and `COM_PING` (synthetic
//!     `OK_Packet`).
//!
//! # What is deferred
//!
//!   * Real upstream forwarding via `mysql_async` / `mysql-rs`.
//!     V3 lands this; V2 synthesises `OK_Packet` so the
//!     handshake-tier integration is observable without a live
//!     `mysqld`.
//!   * `caching_sha2_password` plugin (the MySQL 8.0 default).
//!     V2 advertises `mysql_native_password` and relies on the
//!     client driver's auth-method negotiation. `caching_sha2_*`
//!     comes online once we have real upstream forwarding.
//!   * Prepared statements (`COM_STMT_PREPARE` / `COM_STMT_EXECUTE`).
//!   * Result-set framing for `SELECT` — V2 returns `OK_Packet` for
//!     every allowed statement, including `SELECT`. Drivers that
//!     consume an empty result set tolerate this; drivers that
//!     hard-require column metadata will need V3's real-upstream
//!     path.
//!   * `forbidden_tables`, `forbidden_schemas`, `max_result_rows`,
//!     `statement_timeout_ms`.

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

/// Configuration for one MySQL proxy listener.
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
    /// `Protocol::HandshakeV10` greeting. Defaults to a
    /// RAXIS-tagged 8.x string so server fingerprinters log
    /// "ours, not yours".
    pub server_version:  String,
    /// Effective restriction set parsed out of
    /// `[tasks.credentials.restrictions]`.
    pub restrictions:    Restrictions,
    /// When `true`, `AuditEvent::DatabaseQueryExecuted` carries
    /// the SQL plaintext alongside its `sql_sha256`. The kernel
    /// ties this to its `inference_audit.log_content` policy
    /// flag; `false` is the safe default.
    pub log_content:     bool,
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
    pub queries_audited:    AtomicU32,
    /// Number of `COM_QUERY` statements rejected by `Restrictions`.
    pub queries_blocked:    AtomicU32,
    /// Bytes seen in inbound `COM_QUERY` payloads.
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
    /// Number of `COM_QUERY` statements observed (allowed + blocked).
    pub queries_audited:    u32,
    /// Number of `COM_QUERY` statements rejected by `Restrictions`.
    pub queries_blocked:    u32,
    /// Bytes seen in inbound `COM_QUERY` payloads.
    pub bytes_observed:     u64,
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
    DatabaseQueryExecuted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
        /// Hex SHA-256 of the SQL bytes (always present).
        sql_sha256:  String,
        /// The SQL statement plaintext, if and only if the
        /// `ProxyConfig::log_content` flag is set.
        sql_text:    Option<String>,
        /// `Select` / `Insert` / etc. — see [`OperationKind`].
        operation:   OperationKind,
        /// True if the proxy refused the query under restrictions.
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
// Library entry point
// ---------------------------------------------------------------------------

/// MySQL wire-protocol credential proxy.
pub struct MysqlProxy {
    listener: TcpListener,
    backend:  Arc<dyn CredentialBackend>,
    config:   ProxyConfig,
    stats:    Arc<ProxyStats>,
    audit:    Arc<dyn AuditChannel>,
}

impl MysqlProxy {
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
    backend:    Arc<dyn CredentialBackend>,
    config:     ProxyConfig,
    stats:      Arc<ProxyStats>,
    audit:      Arc<dyn AuditChannel>,
) -> std::io::Result<()> {
    // Resolve the credential once at connect time so a missing /
    // malformed credential aborts the handshake rather than mid-
    // query.
    if let Err(e) = backend.resolve(&config.credential_name, config.consumer.as_ref()) {
        tracing::warn!(error = %e, "mysql proxy credential resolve failed");
        // Send an ERR_Packet with a clear "access denied" shape.
        let payload = wire::build_err_packet(
            1045, // ER_ACCESS_DENIED_ERROR
            "28000",
            "credential resolve failed at RAXIS proxy",
        );
        let _ = stream.write_all(&wire::frame_packet(&payload, 0)).await;
        let _ = stream.flush().await;
        return Ok(());
    }

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
            tracing::warn!(seq = header.sequence_id, "unexpected sequence ID on HandshakeResponse41");
            return Ok(());
        }
        None => return Ok(()),
    };

    // Acknowledge with OK_Packet (seq=2).
    let ok = wire::build_ok_packet();
    stream.write_all(&wire::frame_packet(&ok, 2)).await?;
    stream.flush().await?;

    // Command loop.
    loop {
        let pkt = match read_packet(&mut stream).await? {
            Some(p) => p,
            None    => return Ok(()),
        };
        let (_header, payload) = pkt;
        if payload.is_empty() { return Ok(()); }
        let cmd = payload[0];
        // Sequence resets to 0 on every command. Our reply is seq=1.
        match cmd {
            wire::cmd::QUIT => {
                return Ok(());
            }
            wire::cmd::PING => {
                let ok = wire::build_ok_packet();
                stream.write_all(&wire::frame_packet(&ok, 1)).await?;
                stream.flush().await?;
            }
            wire::cmd::QUERY => {
                let sql_bytes = &payload[1..];
                stats.bytes_observed.fetch_add(sql_bytes.len() as u64, Ordering::Relaxed);
                let sql = String::from_utf8_lossy(sql_bytes).into_owned();
                let op  = classify_first_operation(&sql);

                let blocked = config.restrictions.is_blocked(&op);
                stats.queries_audited.fetch_add(1, Ordering::Relaxed);
                if blocked {
                    stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
                    let err = wire::build_err_packet(
                        1142, // ER_TABLEACCESS_DENIED_ERROR
                        "42501",
                        "operation blocked by RAXIS allow_only_select policy",
                    );
                    stream.write_all(&wire::frame_packet(&err, 1)).await?;
                    stream.flush().await?;
                } else {
                    let ok = wire::build_ok_packet();
                    stream.write_all(&wire::frame_packet(&ok, 1)).await?;
                    stream.flush().await?;
                }

                audit.emit(AuditEvent::DatabaseQueryExecuted {
                    timestamp_unix_seconds: SystemTime::now()
                        .duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
                    consumer:   config.consumer.clone(),
                    credential: config.credential_name.clone(),
                    sql_sha256: sha256_hex(sql_bytes),
                    sql_text:   if config.log_content { Some(sql) } else { None },
                    operation:  op,
                    blocked,
                });
            }
            wire::cmd::RESET => {
                // COM_RESET_CONNECTION — synthesise an OK_Packet so
                // the driver's pool can keep using the connection.
                let ok = wire::build_ok_packet();
                stream.write_all(&wire::frame_packet(&ok, 1)).await?;
                stream.flush().await?;
            }
            other => {
                // Unsupported command — return ER_NOT_SUPPORTED_YET.
                tracing::warn!(cmd = format!("0x{other:02x}"),
                    "mysql proxy received unsupported command");
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
}

async fn read_packet(stream: &mut TcpStream) -> std::io::Result<Option<(wire::PacketHeader, Vec<u8>)>> {
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
