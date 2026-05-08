//! `raxis-credential-proxy-mongodb` — MongoDB OP_MSG credential
//! proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §4.4`
//! (MongoDB). The proxy speaks the modern wire protocol
//! (`OP_MSG`, op code 2013), recognises the `hello` / `isMaster`
//! greeting, and routes every other command document through
//! [`restriction::Restrictions::is_blocked`]. Blocked commands get
//! `{ ok: 0, code: 13, codeName: "Unauthorized", errmsg: "..." }`
//! — the canonical MongoDB authorization-error shape so drivers
//! surface a clean `MongoServerError` with code 13 instead of
//! a generic protocol error.
//!
//! # Why no SCRAM in V2 MVP
//!
//! Mongo's modern auth path (SCRAM-SHA-256) requires the proxy to
//! either (a) hold the upstream password and replay the SASL
//! conversation byte-for-byte against the agent, or (b) terminate
//! SCRAM locally with a known agent-side password and forward
//! commands upstream with a separately-resolved upstream
//! credential. Both options expand the proxy surface considerably
//! and tie its correctness to a third-party crypto library
//! (`pbkdf2`). For V2 the simpler shape is "no auth at all": the
//! `mount_as` URI the agent gets is `mongodb://127.0.0.1:PORT/db`
//! with no credentials. The hello response advertises an empty
//! `saslSupportedMechs` list so well-behaved drivers never attempt
//! authentication. V3 lands the SCRAM path (per the
//! `specs/v2/credential-proxy.md` deferral list) once the BSON
//! doc-walker is mature enough to enforce
//! `forbidden_collections` and `max_documents` too.
//!
//! # What this MVP supports
//!
//!   * `OP_MSG` framing on inbound messages, with the 64 MiB hard
//!     cap enforced before any allocation.
//!   * `hello` / `isMaster` / `ismaster` / `ping` / `buildInfo`:
//!     synthesised replies sufficient for `mongo`, `pymongo`,
//!     `mongoose`, `mongo-rust-driver`, and the official Java /
//!     Go / Node drivers to consider the connection ready.
//!   * Every other command: classified through
//!     [`restriction::Restrictions::is_blocked`].
//!     Allowed commands get `{ ok: 1.0 }`. Blocked commands get
//!     `{ ok: 0.0, code: 13, codeName: "Unauthorized", errmsg }`.
//!   * Per-command audit emission with the command name and a
//!     SHA-256 of the *full* OP_MSG body bytes for fingerprinting.
//!
//! # What is deferred
//!
//!   * Real upstream forwarding via `mongodb`/`mongo-rust-driver`.
//!   * SASL SCRAM-SHA-256 / SCRAM-SHA-1 auth proxying.
//!   * `forbidden_collections`, `max_documents`, `op_timeout_ms`.
//!   * Multi-section `OP_MSG` parsing for batched
//!     insert/update/delete document arrays — V2 classifies on
//!     the kind-0 section command name only.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use raxis_credentials::{CredentialBackend, CredentialName, ConsumerIdentity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod restriction;
pub mod upstream;
pub mod wire;

pub use restriction::Restrictions;
pub use upstream::{
    ForwardOutcome, ParsedUpstreamUrl, UpstreamError, UpstreamSession,
    redact_for_audit, resolve_upstream_url, DEFAULT_CONNECT_TIMEOUT,
};

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

/// Configuration for one MongoDB proxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the inbound listener binds to.
    pub listen_addr:     String,
    /// Credential to resolve once at proxy bind. Bytes are NEVER
    /// surfaced beyond the proxy boundary.
    pub credential_name: CredentialName,
    /// Identity of the agent session this proxy serves.
    pub consumer:        OwnedConsumer,
    /// Effective restriction set parsed out of
    /// `[tasks.credentials.restrictions]`.
    pub restrictions:    Restrictions,
}

/// Counters surfaced for `CredentialProxyStopped`.
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Number of accepted inbound TCP connections.
    pub connections_served: AtomicU32,
    /// Number of commands observed (allowed + blocked).
    pub commands_audited:   AtomicU32,
    /// Number of commands rejected by `Restrictions`.
    pub commands_blocked:   AtomicU32,
    /// Bytes seen in inbound OP_MSG bodies.
    pub bytes_observed:     AtomicU64,
    /// V2.1: number of upstream TCP+auth handshakes started.
    pub upstream_connects_attempted: AtomicU32,
    /// V2.1: subset that reached a usable upstream session.
    pub upstream_connects_succeeded: AtomicU32,
    /// V2.1: subset that failed.
    pub upstream_connects_failed:    AtomicU32,
    /// V2.1: sum of upstream→agent payload bytes relayed.
    pub upstream_bytes_forwarded:    AtomicU64,
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served: self.connections_served.load(Ordering::Relaxed),
            commands_audited:   self.commands_audited  .load(Ordering::Relaxed),
            commands_blocked:   self.commands_blocked  .load(Ordering::Relaxed),
            bytes_observed:     self.bytes_observed    .load(Ordering::Relaxed),
            upstream_connects_attempted: self.upstream_connects_attempted.load(Ordering::Relaxed),
            upstream_connects_succeeded: self.upstream_connects_succeeded.load(Ordering::Relaxed),
            upstream_connects_failed:    self.upstream_connects_failed   .load(Ordering::Relaxed),
            upstream_bytes_forwarded:    self.upstream_bytes_forwarded   .load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted inbound TCP connections.
    pub connections_served: u32,
    /// Number of commands observed.
    pub commands_audited:   u32,
    /// Number of commands rejected by `Restrictions`.
    pub commands_blocked:   u32,
    /// Bytes seen in inbound OP_MSG bodies.
    pub bytes_observed:     u64,
    /// V2.1: number of upstream TCP+auth handshakes started.
    pub upstream_connects_attempted: u32,
    /// V2.1: subset that reached a usable upstream session.
    pub upstream_connects_succeeded: u32,
    /// V2.1: subset that failed.
    pub upstream_connects_failed:    u32,
    /// V2.1: sum of upstream→agent payload bytes relayed.
    pub upstream_bytes_forwarded:    u64,
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
    /// One MongoDB command observed (allowed or blocked).
    /// Pre-upstream-contact event — fires before the proxy attempts
    /// to forward to the real backend.
    MongoCommandExecuted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
        /// Command name (e.g. `"find"`, `"insert"`).
        command:     String,
        /// SHA-256 of the OP_MSG body bytes.
        body_sha256: String,
        /// True if the proxy refused the command under
        /// restrictions.
        blocked:     bool,
    },

    /// V2.1: emitted on the upstream's terminal frame for a
    /// forwarded command. Pairs with `MongoCommandExecuted` via
    /// matching `body_sha256`. Per `credential-proxy.md §14.5.1`.
    DatabaseQueryCompleted {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
        /// SHA-256 of the OP_MSG body bytes — matches the prior
        /// `MongoCommandExecuted.body_sha256`.
        body_sha256: String,
        /// Always `1` for OP_MSG (the proxy doesn't try to count
        /// nested cursor batches in V2.1; that's V3 work).
        rows_returned: u64,
        /// Bytes the upstream returned (header + body of the OP_MSG
        /// reply).
        bytes_returned: u64,
        /// Wall-clock duration of the upstream round trip.
        duration_ms: u32,
        /// `Some("ok=0".to_owned())` if the upstream's reply doc had
        /// `{ ok: 0 }`; `None` on success.
        upstream_error: Option<String>,
    },

    /// V2.1: emitted once per agent connection on the first
    /// successful upstream TCP connect. (No SCRAM in V2.1 MVP, so
    /// this fires after just the TCP connect succeeds.)
    /// Per `credential-proxy.md §14.5.2`.
    CredentialProxyUpstreamConnected {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
        /// Upstream hostname from the credential URL.
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
    /// reach a usable session.
    /// Per `credential-proxy.md §14.5.3`.
    CredentialProxyUpstreamFailed {
        /// Wall-clock time of emission.
        timestamp_unix_seconds: u64,
        /// Identity of the session.
        consumer:    OwnedConsumer,
        /// Credential name (never the value).
        credential:  CredentialName,
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
        addr:   String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// MongoDB OP_MSG credential proxy.
pub struct MongodbProxy {
    listener: TcpListener,
    backend:  Arc<dyn CredentialBackend>,
    config:   ProxyConfig,
    stats:    Arc<ProxyStats>,
    audit:    Arc<dyn AuditChannel>,
}

impl MongodbProxy {
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
                            tracing::warn!(error = %e, "mongodb proxy connection ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "mongodb proxy accept failed");
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
    // Resolve+parse the upstream URL on accept. Failures are
    // tolerated and surfaced lazily on the first allowed agent
    // command (mirrors the postgres + mysql proxies).
    let upstream_url: Option<ParsedUpstreamUrl> = match upstream::resolve_upstream_url(
        &backend,
        &config.credential_name,
        &config.consumer,
    ) {
        Ok(u) => Some(u),
        Err(e) => {
            tracing::warn!(
                error = %e,
                credential = %config.credential_name.as_str(),
                "mongodb proxy upstream URL resolution failed; first allowed command will fail",
            );
            None
        }
    };

    let mut upstream_session: Option<UpstreamSession> = None;

    loop {
        // Read 16-byte header.
        let mut header_bytes = [0u8; wire::HEADER_LEN];
        if let Err(e) = stream.read_exact(&mut header_bytes).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(e);
        }
        let header = wire::MsgHeader::parse(header_bytes);
        if header.message_length < wire::HEADER_LEN as i32 {
            break; // malformed; close.
        }
        let total = header.message_length as usize;
        if total > wire::MAX_MESSAGE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("MongoDB message length {total} exceeds 64 MiB cap"),
            ));
        }
        let body_len = total - wire::HEADER_LEN;
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).await?;
        stats.bytes_observed.fetch_add(body_len as u64, Ordering::Relaxed);

        // Only OP_MSG is supported. Everything else gets a clean
        // close so a confused client backs off rather than hanging.
        if header.op_code != wire::OP_MSG {
            tracing::debug!(op_code = header.op_code, "mongodb proxy received non-OP_MSG, closing");
            break;
        }

        let command = wire::first_command_name(&body)
            .unwrap_or_else(|| "<unknown>".to_owned());
        stats.commands_audited.fetch_add(1, Ordering::Relaxed);

        let body_sha256 = sha256_hex(&body);
        let blocked     = config.restrictions.is_blocked(&command);

        audit.emit(AuditEvent::MongoCommandExecuted {
            timestamp_unix_seconds: now_secs(),
            consumer:    config.consumer.clone(),
            credential:  config.credential_name.clone(),
            command:     command.clone(),
            body_sha256: body_sha256.clone(),
            blocked,
        });

        if blocked {
            stats.commands_blocked.fetch_add(1, Ordering::Relaxed);
            let reply_doc = build_unauthorized_doc(&command);
            let reply_msg = wire::build_op_msg_reply(
                header.request_id.wrapping_add(0x4000_0000),
                header.request_id,
                &reply_doc,
            );
            stream.write_all(&reply_msg).await?;
            stream.flush().await?;
            continue;
        }

        // Hello / isMaster / ismaster / ping / buildInfo — the
        // proxy answers these locally so an agent's driver can
        // negotiate the connection topology without ever touching
        // the upstream. This matches the V2.0 MVP behaviour and
        // also lets the V2.1 relay path stay focused on data
        // commands.
        if matches!(command.as_str(), "hello" | "isMaster" | "ismaster" | "ping" | "buildInfo" | "buildinfo") {
            let reply_doc = build_reply_for(&command);
            let reply_msg = wire::build_op_msg_reply(
                header.request_id.wrapping_add(0x4000_0000),
                header.request_id,
                &reply_doc,
            );
            stream.write_all(&reply_msg).await?;
            stream.flush().await?;
            continue;
        }

        // Allowed data command: ensure a usable upstream session,
        // then forward the agent's full OP_MSG frame verbatim.
        if upstream_session.is_none() {
            let url = match upstream_url.as_ref() {
                Some(u) => u,
                None => {
                    let reply_doc = build_proxy_error_doc(
                        "RAXIS proxy: upstream credential could not be resolved (FAIL_PROXY_UPSTREAM_URL_INVALID)",
                    );
                    let reply_msg = wire::build_op_msg_reply(
                        header.request_id.wrapping_add(0x4000_0000),
                        header.request_id,
                        &reply_doc,
                    );
                    stream.write_all(&reply_msg).await?;
                    stream.flush().await?;
                    continue;
                }
            };
            let host = url.host.clone();
            let port = url.port;
            stats.upstream_connects_attempted.fetch_add(1, Ordering::Relaxed);
            match UpstreamSession::connect(url, upstream::DEFAULT_CONNECT_TIMEOUT).await {
                Ok(sess) => {
                    stats.upstream_connects_succeeded.fetch_add(1, Ordering::Relaxed);
                    audit.emit(AuditEvent::CredentialProxyUpstreamConnected {
                        timestamp_unix_seconds: now_secs(),
                        consumer:      config.consumer.clone(),
                        credential:    config.credential_name.clone(),
                        upstream_host: sess.host.clone(),
                        upstream_port: sess.port,
                        tls:           sess.tls,
                        handshake_ms:  sess.handshake_ms,
                    });
                    upstream_session = Some(sess);
                }
                Err(e) => {
                    stats.upstream_connects_failed.fetch_add(1, Ordering::Relaxed);
                    audit.emit(AuditEvent::CredentialProxyUpstreamFailed {
                        timestamp_unix_seconds: now_secs(),
                        consumer:      config.consumer.clone(),
                        credential:    config.credential_name.clone(),
                        upstream_host: host,
                        upstream_port: port,
                        reason:        e.audit_reason().to_owned(),
                        detail:        e.audit_detail(),
                    });
                    let reply_doc = build_proxy_error_doc(&format!(
                        "RAXIS proxy: upstream connect failed ({}): {}",
                        e.audit_reason(),
                        e.audit_detail(),
                    ));
                    let reply_msg = wire::build_op_msg_reply(
                        header.request_id.wrapping_add(0x4000_0000),
                        header.request_id,
                        &reply_doc,
                    );
                    stream.write_all(&reply_msg).await?;
                    stream.flush().await?;
                    continue;
                }
            }
        }

        // Re-encode the agent's frame (header + body) and forward it
        // to the upstream. Reading the frame back from the parsed
        // pieces avoids the cost of buffering the on-wire bytes
        // separately.
        let agent_frame = {
            let mut f = Vec::with_capacity(total);
            f.extend_from_slice(&header.encode());
            f.extend_from_slice(&body);
            f
        };
        let session = upstream_session.as_mut().expect("upstream connected above");
        match session.forward_op_msg(&agent_frame).await {
            Ok(outcome) => {
                stream.write_all(&outcome.frame).await?;
                stream.flush().await?;
                stats.upstream_bytes_forwarded.fetch_add(
                    outcome.frame.len() as u64, Ordering::Relaxed,
                );
                let upstream_error = if outcome.upstream_error_marker {
                    Some("ok=0".to_owned())
                } else {
                    None
                };
                audit.emit(AuditEvent::DatabaseQueryCompleted {
                    timestamp_unix_seconds: now_secs(),
                    consumer:       config.consumer.clone(),
                    credential:     config.credential_name.clone(),
                    body_sha256,
                    rows_returned:  1,
                    bytes_returned: outcome.frame.len() as u64,
                    duration_ms:    outcome.duration_ms,
                    upstream_error,
                });
            }
            Err(e) => {
                let detail = redact_for_audit(&e.to_string());
                upstream_session = None;
                let reply_doc = build_proxy_error_doc(&format!(
                    "RAXIS proxy: upstream relay failed: {detail}"
                ));
                let reply_msg = wire::build_op_msg_reply(
                    header.request_id.wrapping_add(0x4000_0000),
                    header.request_id,
                    &reply_doc,
                );
                stream.write_all(&reply_msg).await?;
                stream.flush().await?;
                audit.emit(AuditEvent::DatabaseQueryCompleted {
                    timestamp_unix_seconds: now_secs(),
                    consumer:       config.consumer.clone(),
                    credential:     config.credential_name.clone(),
                    body_sha256,
                    rows_returned:  0,
                    bytes_returned: 0,
                    duration_ms:    0,
                    upstream_error: Some("relay_failed".to_owned()),
                });
            }
        }
    }

    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a synthetic Mongo command failure doc the proxy can return
/// when the upstream relay path fails (URL resolve, connect, mid-
/// query I/O). The shape mirrors the upstream's own error-reply
/// envelope so drivers surface a clean `MongoServerError`.
fn build_proxy_error_doc(message: &str) -> Vec<u8> {
    use wire::BsonBuilder as B;
    B::new()
        .double("ok",       0.0)
        .int32 ("code",     8000)
        .string("codeName", "RaxisProxyError")
        .string("errmsg",   message)
        .finish()
}

/// Build a synthesised reply document for the given command.
fn build_reply_for(command: &str) -> Vec<u8> {
    use wire::BsonBuilder as B;
    match command {
        "hello" | "isMaster" | "ismaster" => {
            B::new()
                .double("ok",                  1.0)
                .bool  ("isWritablePrimary",   true)
                .bool  ("ismaster",            true)
                .int32 ("maxBsonObjectSize",   16_777_216)
                .int32 ("maxMessageSizeBytes", 48_000_000)
                .int32 ("maxWriteBatchSize",   100_000)
                .int32 ("maxWireVersion",      17)
                .int32 ("minWireVersion",      0)
                .bool  ("readOnly",            false)
                .string("topologyVersion",     "raxis-mongo-proxy-v2")
                .finish()
        }
        "ping" => {
            B::new().double("ok", 1.0).finish()
        }
        "buildInfo" | "buildinfo" => {
            B::new()
                .double("ok", 1.0)
                .string("version", "raxis-mongo-proxy-v2")
                .int32 ("maxBsonObjectSize", 16_777_216)
                .finish()
        }
        // Generic OK for everything else the restriction set allows.
        _ => B::new().double("ok", 1.0).finish(),
    }
}

/// `{ ok: 0.0, code: 13, codeName: "Unauthorized", errmsg: "..." }`.
fn build_unauthorized_doc(command: &str) -> Vec<u8> {
    use wire::BsonBuilder as B;
    let errmsg = format!(
        "command `{command}` blocked by RAXIS allow_read_only policy",
    );
    B::new()
        .double("ok",       0.0)
        .int32 ("code",     13)
        .string("codeName", "Unauthorized")
        .string("errmsg",   &errmsg)
        .finish()
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
    fn unauthorized_doc_pins_code_13() {
        let doc = build_unauthorized_doc("insert");
        // The doc carries `code: 13` somewhere; we don't decode
        // BSON in tests, but the bytes for `0x10 c o d e 0x00 13_le` must appear.
        let needle = [
            0x10, b'c', b'o', b'd', b'e', 0x00,
            13, 0, 0, 0,
        ];
        assert!(
            doc.windows(needle.len()).any(|w| w == needle),
            "code:13 not found in bson body: {doc:?}",
        );
    }

    #[test]
    fn reply_for_hello_advertises_max_wire_version_17() {
        let doc = build_reply_for("hello");
        let needle = [
            0x10, b'm', b'a', b'x', b'W', b'i', b'r', b'e',
            b'V', b'e', b'r', b's', b'i', b'o', b'n', 0x00,
            17, 0, 0, 0,
        ];
        assert!(
            doc.windows(needle.len()).any(|w| w == needle),
            "maxWireVersion:17 not found in hello reply",
        );
    }
}
