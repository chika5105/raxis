//! `raxis-credential-proxy-mongodb` — MongoDB OP_MSG credential
//! proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §4.4`
//! (MongoDB) and `specs/v2/v2_extended_gaps.md §2.2`
//! (SCRAM-SHA-256 upstream auth, V2.5).
//!
//! The proxy speaks the modern wire protocol (`OP_MSG`, op code
//! 2013), terminates the agent-side `hello` / `isMaster` greeting
//! locally, and routes every other command document through
//! [`restriction::Restrictions::is_blocked`]. Blocked commands get
//! `{ ok: 0, code: 13, codeName: "Unauthorized", errmsg: "..." }`
//! — the canonical MongoDB authorization-error shape so drivers
//! surface a clean `MongoServerError` with code 13 instead of
//! a generic protocol error.
//!
//! # Auth shapes
//!
//! Both upstream auth shapes are supported:
//!
//! * `mongodb://host:port/db` (no userinfo) — pure plaintext +
//!   `--noauth`. Useful for ephemeral CI containers.
//! * `mongodb://user:pass@host:port/db?authSource=admin`
//!   — drives SCRAM-SHA-256 SASL against `authSource` (default
//!   `admin`) before any data command. The proxy's SCRAM client
//!   is RFC 5802 + 7677 compliant: nonce-prefix verified,
//!   server-signature verified in constant time, iteration count
//!   bounded ≥ 4096.
//!
//! In both cases the agent-side connection is no-auth from the
//! agent's point of view (`mount_as` URI =
//! `mongodb://127.0.0.1:PORT/db` with no credentials, hello
//! response advertises an empty `saslSupportedMechs`). The proxy
//! authenticates upstream with the kernel-resolved credential.
//!
//! # What this crate supports
//!
//!   * `OP_MSG` framing on inbound messages, with the 64 MiB hard
//!     cap enforced before any allocation.
//!   * `hello` / `isMaster` / `ismaster` / `ping` / `buildInfo`:
//!     synthesised replies sufficient for `mongo`, `pymongo`,
//!     `mongoose`, `mongo-rust-driver`, and the official Java /
//!     Go / Node drivers to consider the connection ready.
//!   * SCRAM-SHA-256 upstream SASL via the [`upstream`] module.
//!   * Every other agent command: classified through
//!     [`restriction::Restrictions::is_blocked`]. Blocked commands
//!     get `{ ok: 0.0, code: 13, codeName: "Unauthorized", errmsg }`
//!     and never touch the upstream.
//!   * Per-command audit emission with the command name and a
//!     SHA-256 of the *full* OP_MSG body bytes for fingerprinting.
//!
//! # V2 restriction surface (`proxy-table-allowlists.md`)
//!
//! The BSON command walker resolves the primary collection +
//! `$db` from `OP_MSG` bodies, runs `allowed_collections` /
//! `forbidden_collections` allow/deny enforcement, and applies
//! the secondary-collection ($lookup / $unionWith / $out / $merge)
//! reject-on-detection heuristic when an allowlist is configured.
//! Reply cursors get streaming `max_documents` enforcement —
//! `firstBatch` / `nextBatch` is truncated and the cursor id is
//! rewritten to 0 on overshoot (so the agent's driver sees a
//! clean cursor-exhausted result instead of a wire error). The
//! per-cursor counter accumulates across `find` + N `getMore`s.
//!
//! # What is still deferred (tracked under V3)
//!
//!   * Compressed `OP_COMPRESSED` envelopes.
//!   * Per-pipeline allowlist coverage for `$lookup` /
//!     `$graphLookup` — V2 rejects them when ANY allowlist is
//!     configured (the safer fail-closed contract).
//!   * `op_timeout_ms`.
//!   * TLS on the upstream socket (the SCRAM SASL conversation
//!     itself is independent of TLS).

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use raxis_credentials::{CredentialBackend, CredentialName, ConsumerIdentity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod cursor;
pub mod restriction;
pub mod upstream;
pub mod wire;

pub use restriction::{
    CommandTarget, RestrictionDecision, RestrictionReason, Restrictions,
    walk_command,
};
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
    /// V2: subset of `commands_blocked` rejected by the
    /// `allowed_collections` / `forbidden_collections` walker.
    pub commands_blocked_by_collection_allowlist: AtomicU32,
    /// V2: subset of `commands_blocked` rejected because the
    /// walker could not prove the collection list (fail-closed
    /// under the V2 ambiguity policy).
    pub commands_blocked_by_ambiguous_bson:       AtomicU32,
    /// V2: number of reply cursors truncated by `max_documents`.
    pub commands_capped_by_max_documents:         AtomicU32,
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
            commands_blocked_by_collection_allowlist:
                self.commands_blocked_by_collection_allowlist.load(Ordering::Relaxed),
            commands_blocked_by_ambiguous_bson:
                self.commands_blocked_by_ambiguous_bson      .load(Ordering::Relaxed),
            commands_capped_by_max_documents:
                self.commands_capped_by_max_documents        .load(Ordering::Relaxed),
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
    /// V2: subset of `commands_blocked` rejected by the
    /// `allowed_collections` / `forbidden_collections` walker.
    pub commands_blocked_by_collection_allowlist: u32,
    /// V2: subset of `commands_blocked` rejected because the
    /// walker could not prove the collection list.
    pub commands_blocked_by_ambiguous_bson:       u32,
    /// V2: number of reply cursors truncated by `max_documents`.
    pub commands_capped_by_max_documents:         u32,
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
        /// V2: walker-resolved `<db>.<coll>`; `None` for server-
        /// introspection commands like `hello` / `ping`.
        collection:         Option<String>,
        /// V2: closed-enum reason key, present iff the command
        /// was blocked OR audited-only by V2 restrictions.
        restriction_reason: Option<&'static str>,
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
    // V2 cursor-cap tracking. Per `proxy-table-allowlists.md §7.5`
    // the cap is per-cursor: a `find` opens a cursor (id != 0),
    // subsequent `getMore`s on the same id accumulate against the
    // budget. When a cursor id is 0 (single-batch query) or the
    // proxy truncates the batch, the id is removed.
    let mut emitted_by_cursor: std::collections::HashMap<i64, u64> =
        std::collections::HashMap::new();

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

        // ─── Legacy `OP_QUERY` initial-handshake handler ───
        //
        // Pymongo 4.x, the Java driver, Node, Go, Rust, etc. all
        // send the **first** message of a session as `OP_QUERY`
        // (`op_code 2004`) targeting collection `admin.$cmd`
        // with a query document like
        // `{ ismaster: 1, helloOk: true, client: {…} }`. The
        // server reply must be an `OP_REPLY` (`op_code 1`)
        // carrying the synthesised hello document. Without this
        // path the driver's SDAM monitor reports
        // `ServerSelectionTimeoutError: connection closed`
        // (live-e2e iter33 root cause).
        //
        // Subsequent messages from the same driver always switch
        // to `OP_MSG` once the negotiated `maxWireVersion` is
        // ≥ 6, so this branch is **only** the handshake hop —
        // restriction enforcement still runs against `OP_MSG`
        // bodies on the same connection. Per `OP_QUERY` legacy
        // spec, write-bearing collection names look like
        // `db.coll` (not `db.$cmd`); the proxy enforces the V2
        // contract by **rejecting** every non-`$cmd` OP_QUERY
        // with a clean close, so an agent cannot smuggle data
        // commands through the legacy path to bypass the V2
        // walker.
        if header.op_code == wire::OP_QUERY {
            let (collection, command) = match wire::parse_op_query_command(&body) {
                Some(pair) => pair,
                None => {
                    tracing::debug!("mongodb proxy received malformed OP_QUERY, closing");
                    break;
                }
            };
            // Only the legacy command channel (`<db>.$cmd`) is
            // honoured. A normal data collection arriving on
            // OP_QUERY would be a pre-3.6 read; V2 fail-closes.
            if !collection.ends_with(".$cmd") {
                tracing::debug!(
                    collection = %collection,
                    "mongodb proxy received OP_QUERY against non-$cmd collection, closing",
                );
                break;
            }
            stats.commands_audited.fetch_add(1, Ordering::Relaxed);
            // Only `hello` / `isMaster` / `ismaster` / `ping`
            // / `buildInfo` are accepted on the legacy channel —
            // every other command must come over `OP_MSG`.
            let is_handshake = matches!(
                command.as_str(),
                "hello" | "isMaster" | "ismaster" | "ping" | "buildInfo" | "buildinfo",
            );
            if !is_handshake {
                tracing::debug!(
                    command = %command,
                    "mongodb proxy received OP_QUERY for non-handshake command, closing",
                );
                break;
            }
            let reply_doc = build_reply_for(&command);
            let reply_msg = wire::build_op_reply(
                header.request_id.wrapping_add(0x4000_0000),
                header.request_id,
                &reply_doc,
            );
            stream.write_all(&reply_msg).await?;
            stream.flush().await?;
            continue;
        }

        // Only OP_MSG is supported beyond the handshake. Everything
        // else gets a clean close so a confused client backs off
        // rather than hanging.
        if header.op_code != wire::OP_MSG {
            tracing::debug!(op_code = header.op_code, "mongodb proxy received non-OP_MSG, closing");
            break;
        }

        // V2 walker — only inspect the pipeline (for $lookup
        // detection) when an allowlist is configured. Per
        // `proxy-table-allowlists.md §6.1 step 4 (D6)`.
        let inspect_pipeline = config.restrictions.has_collection_lists();
        let target = restriction::walk_command(&body, inspect_pipeline);
        let command = match &target {
            CommandTarget::Resolved { command, .. } => command.clone(),
            CommandTarget::SecondaryCollectionDetected { command, .. } => command.clone(),
            CommandTarget::Ambiguous => wire::first_command_name(&body)
                .unwrap_or_else(|| "<unknown>".to_owned()),
        };
        let cursor_id_for_getmore = if command == "getMore" {
            extract_getmore_cursor_id(&body)
        } else { None };
        stats.commands_audited.fetch_add(1, Ordering::Relaxed);

        let body_sha256 = sha256_hex(&body);
        let decision    = config.restrictions.check(&target);

        let (collection, restriction_reason, is_block) =
            decision_to_audit_fields(&decision);
        audit.emit(AuditEvent::MongoCommandExecuted {
            timestamp_unix_seconds: now_secs(),
            consumer:    config.consumer.clone(),
            credential:  config.credential_name.clone(),
            command:     command.clone(),
            body_sha256: body_sha256.clone(),
            blocked:     is_block,
            collection,
            restriction_reason,
        });

        if is_block {
            bump_blocked_counters(&stats, &decision);
            let reply_doc = build_blocked_doc(&command, &decision);
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
                // V2 cursor cap. Per `§7.4`: when the reply
                // contains a `cursor.firstBatch` / `nextBatch`
                // array and `max_documents` is finite, count the
                // batch against the per-cursor budget and rewrite
                // the reply on overshoot.
                let max_docs = config.restrictions.max_documents;
                let (frame_to_send, rows_returned, capped_reason) =
                    if max_docs > 0 {
                        apply_cursor_cap_to_outcome(
                            &outcome.frame,
                            max_docs,
                            &command,
                            cursor_id_for_getmore,
                            &mut emitted_by_cursor,
                        )
                    } else {
                        (outcome.frame.clone(), 1u64, None)
                    };
                let was_capped = capped_reason.is_some();
                if was_capped {
                    stats.commands_capped_by_max_documents.fetch_add(1, Ordering::Relaxed);
                }
                stream.write_all(&frame_to_send).await?;
                stream.flush().await?;
                stats.upstream_bytes_forwarded.fetch_add(
                    frame_to_send.len() as u64, Ordering::Relaxed,
                );
                let upstream_error = if was_capped {
                    capped_reason.map(|s| s.to_owned())
                } else if outcome.upstream_error_marker {
                    Some("ok=0".to_owned())
                } else {
                    None
                };
                audit.emit(AuditEvent::DatabaseQueryCompleted {
                    timestamp_unix_seconds: now_secs(),
                    consumer:       config.consumer.clone(),
                    credential:     config.credential_name.clone(),
                    body_sha256,
                    rows_returned,
                    bytes_returned: frame_to_send.len() as u64,
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

/// Translate a [`RestrictionDecision`] into audit-envelope fields
/// (`collection`, `restriction_reason`, `blocked`).
fn decision_to_audit_fields(
    decision: &RestrictionDecision,
) -> (Option<String>, Option<&'static str>, bool) {
    match decision {
        RestrictionDecision::Admit { collection } =>
            (collection.clone(), None, false),
        RestrictionDecision::Block { reason, collection } =>
            (collection.clone(), Some(reason.as_str()), true),
        RestrictionDecision::AuditOnly { reason, collection } =>
            (collection.clone(), Some(reason.as_str()), false),
    }
}

/// Increment the right `commands_blocked_*` sub-counter.
fn bump_blocked_counters(stats: &ProxyStats, decision: &RestrictionDecision) {
    let reason = match decision {
        RestrictionDecision::Block { reason, .. } => *reason,
        _ => return,
    };
    stats.commands_blocked.fetch_add(1, Ordering::Relaxed);
    match reason {
        RestrictionReason::CollectionNotInAllowedList
        | RestrictionReason::CollectionInForbiddenList
        | RestrictionReason::SecondaryCollectionInPipeline => {
            stats.commands_blocked_by_collection_allowlist.fetch_add(1, Ordering::Relaxed);
        }
        RestrictionReason::AmbiguousBson => {
            stats.commands_blocked_by_ambiguous_bson.fetch_add(1, Ordering::Relaxed);
        }
        RestrictionReason::AllowReadOnly
        | RestrictionReason::MaxDocumentsExceeded => {}
    }
}

/// Build the reply doc for a blocked command. The closed-enum
/// reason name is embedded verbatim per §9.4.
fn build_blocked_doc(command: &str, decision: &RestrictionDecision) -> Vec<u8> {
    use wire::BsonBuilder as B;
    let reason = match decision {
        RestrictionDecision::Block { reason, .. } => reason.as_str(),
        _ => "policy_block",
    };
    let errmsg = format!(
        "command `{command}` blocked by RAXIS policy: {reason}",
    );
    B::new()
        .double("ok",       0.0)
        .int32 ("code",     13)
        .string("codeName", "Unauthorized")
        .string("errmsg",   &errmsg)
        .finish()
}

/// Pull the `getMore` command's cursor id (i64 first-field value)
/// out of the OP_MSG body. The walker doesn't carry the numeric
/// value, only the command name and (string-valued) collection;
/// we re-parse the first element here.
fn extract_getmore_cursor_id(body: &[u8]) -> Option<i64> {
    if body.len() < 5 { return None; }
    let mut i = 4; // flag_bits
    while i < body.len() {
        let kind = body[i];
        i += 1;
        if kind == 0 {
            let doc = &body[i..];
            if doc.len() < 5 { return None; }
            let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
            if total < 5 || total > doc.len() { return None; }
            let elems = &doc[4..total - 1];
            if elems.is_empty() { return None; }
            // First element: type byte + cstring(name) + value.
            let type_byte = elems[0];
            let nul = elems[1..].iter().position(|&b| b == 0)?;
            let value_off = 1 + nul + 1;
            if elems.len() < value_off + 8 { return None; }
            match type_byte {
                0x12 => {
                    let v = i64::from_le_bytes(
                        elems[value_off..value_off + 8].try_into().ok()?,
                    );
                    return Some(v);
                }
                0x10 => {
                    if elems.len() < value_off + 4 { return None; }
                    let v = i32::from_le_bytes(
                        elems[value_off..value_off + 4].try_into().ok()?,
                    );
                    return Some(v as i64);
                }
                _ => return None,
            }
        } else if kind == 1 {
            if i + 4 > body.len() { return None; }
            let section_size = i32::from_le_bytes(
                body[i..i + 4].try_into().ok()?,
            ) as usize;
            if section_size < 4 || i + section_size > body.len() { return None; }
            i += section_size;
        } else {
            return None;
        }
    }
    None
}

/// Apply the `max_documents` cap to an upstream reply frame.
/// Returns `(frame_to_emit, rows_returned, cap_reason)`. When the
/// reply has no cursor structure or the cap is not exceeded, the
/// frame is returned unchanged and `cap_reason` is `None`.
fn apply_cursor_cap_to_outcome(
    upstream_frame: &[u8],
    max_documents:  u64,
    command:        &str,
    getmore_cursor: Option<i64>,
    emitted_by_cursor: &mut std::collections::HashMap<i64, u64>,
) -> (Vec<u8>, u64, Option<&'static str>) {
    let reply_doc = match cursor::extract_reply_doc(upstream_frame) {
        Some(d) => d,
        None    => return (upstream_frame.to_vec(), 1, None),
    };
    let cursor_id = reply_cursor_id(reply_doc).unwrap_or(0);
    // Cursor key — for the FIRST batch of a query, use the
    // upstream-issued cursor id; for getMore the agent already
    // told us which cursor; for single-batch responses (cursor
    // id 0) there's no continuation to track.
    let cursor_key = match command {
        "getMore" => getmore_cursor,
        "find" | "aggregate" | "listCollections" | "listIndexes" =>
            if cursor_id != 0 { Some(cursor_id) } else { None },
        _ => None,
    };
    let prior = cursor_key.and_then(|k| emitted_by_cursor.get(&k).copied())
        .unwrap_or(0);
    let outcome = cursor::apply_cap(reply_doc, max_documents, prior);
    let frame = if outcome.was_capped || !outcome.bson_doc.is_empty() {
        match cursor::rebuild_op_msg_frame(upstream_frame, &outcome.bson_doc) {
            Some(f) => f,
            None    => upstream_frame.to_vec(),
        }
    } else {
        upstream_frame.to_vec()
    };

    // Update the per-cursor counter.
    if let Some(key) = cursor_key {
        let entry = emitted_by_cursor.entry(key).or_insert(0);
        *entry = entry.saturating_add(outcome.emitted_docs as u64);
        if outcome.was_capped || cursor_id == 0 {
            emitted_by_cursor.remove(&key);
        }
    }

    let rows_returned = outcome.emitted_docs as u64;
    let cap_reason = if outcome.was_capped {
        Some("max_documents_exceeded")
    } else { None };
    (frame, rows_returned, cap_reason)
}

/// Read `cursor.id` from a reply BSON doc.
fn reply_cursor_id(doc: &[u8]) -> Option<i64> {
    if doc.len() < 5 { return None; }
    let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
    if total < 5 || total > doc.len() { return None; }
    let body = &doc[4..total - 1];
    let mut p = 0;
    while p < body.len() {
        let t = body[p];
        p += 1;
        let nul = body[p..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&body[p..p + nul]).ok()?;
        p += nul + 1;
        if name == "cursor" && t == 0x03 {
            let inner_total = i32::from_le_bytes(body[p..p + 4].try_into().ok()?) as usize;
            if p + inner_total > body.len() { return None; }
            let inner = &body[p + 4..p + inner_total - 1];
            let mut q = 0;
            while q < inner.len() {
                let t2 = inner[q];
                q += 1;
                let nul2 = inner[q..].iter().position(|&b| b == 0)?;
                let nm = std::str::from_utf8(&inner[q..q + nul2]).ok()?;
                q += nul2 + 1;
                if nm == "id" && t2 == 0x12 {
                    let v = i64::from_le_bytes(inner[q..q + 8].try_into().ok()?);
                    return Some(v);
                }
                let len = bson_value_len(t2, &inner[q..])?;
                q += len;
            }
            return Some(0);
        }
        let len = bson_value_len(t, &body[p..])?;
        p += len;
    }
    None
}

fn bson_value_len(t: u8, data: &[u8]) -> Option<usize> {
    Some(match t {
        0x01 => 8,
        0x02 => {
            if data.len() < 4 { return None; }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            4 + len
        }
        0x03 | 0x04 => {
            if data.len() < 4 { return None; }
            i32::from_le_bytes(data[..4].try_into().ok()?) as usize
        }
        0x05 => {
            if data.len() < 5 { return None; }
            5 + i32::from_le_bytes(data[..4].try_into().ok()?) as usize
        }
        0x06 => 0,
        0x07 => 12,
        0x08 => 1,
        0x09 => 8,
        0x0A => 0,
        0x0B => {
            let n1 = data.iter().position(|&b| b == 0)?;
            let after1 = &data[n1 + 1..];
            let n2 = after1.iter().position(|&b| b == 0)?;
            n1 + 1 + n2 + 1
        }
        0x0C => {
            if data.len() < 4 { return None; }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            4 + len + 12
        }
        0x0D | 0x0E => {
            if data.len() < 4 { return None; }
            4 + i32::from_le_bytes(data[..4].try_into().ok()?) as usize
        }
        0x0F => {
            if data.len() < 4 { return None; }
            i32::from_le_bytes(data[..4].try_into().ok()?) as usize
        }
        0x10 => 4,
        0x11 | 0x12 => 8,
        0x13 => 16,
        0xFF | 0x7F => 0,
        _ => return None,
    })
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
            // V2 wire-protocol hello reply.
            //
            // **`topologyVersion` is intentionally omitted.** The
            // MongoDB driver spec
            // (`drivers/server-discovery-and-monitoring.rst`)
            // declares `topologyVersion` as
            // `{ processId: ObjectId, counter: Int64 }` — a BSON
            // *sub-document*, not a BSON string. Live-e2e iter32
            // reproduced
            // `pymongo.errors.AutoReconnect: connection closed`
            // when the proxy emitted `topologyVersion` as a BSON
            // string (`type 0x02`): `pymongo` deserialises the
            // hello, runs the SDAM topology-change handler, and
            // calls `_is_stale_error_topology_version` over the
            // mismatched-type value; the resulting attribute
            // lookup raises and pymongo treats it as a stale
            // socket and tears the connection down before the
            // first user command can be issued, surfacing in the
            // executor VM as `ServerSelectionTimeoutError`. The
            // spec also permits servers to omit `topologyVersion`
            // entirely; clients then track topology state with a
            // null version, which is the safer contract for a
            // synthesised proxy that never legitimately rotates
            // its `processId`. The proxy-version banner is still
            // exposed via `buildInfo.version` for operator
            // inspection.
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
    fn blocked_doc_pins_code_13() {
        let decision = RestrictionDecision::Block {
            reason:     RestrictionReason::AllowReadOnly,
            collection: None,
        };
        let doc = build_blocked_doc("insert", &decision);
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

    /// Regression test for Live-e2e iter32: `topologyVersion`
    /// MUST NOT appear as a BSON *string* (`type 0x02`) in the
    /// hello reply.
    ///
    /// The MongoDB driver SDAM spec
    /// (`drivers/server-discovery-and-monitoring.rst §"Hello
    /// response"`) declares `topologyVersion` as
    /// `{ processId: ObjectId, counter: Int64 }`. `pymongo` 4.x,
    /// the Node native driver, and the official Java driver all
    /// store the field verbatim into a per-server descriptor and
    /// invoke `_is_stale_error_topology_version` on subsequent
    /// hello responses; if the stored value is a string the
    /// attribute lookup raises `KeyError` / `TypeError` deep in
    /// the SDAM monitor thread, the driver flags the socket as
    /// stale, and the next user command surfaces as
    /// `ServerSelectionTimeoutError: connection closed`.
    ///
    /// The contract this regression test pins is the simpler
    /// "omit `topologyVersion` entirely"; if a future revision
    /// emits it as a sub-document, expand this test to assert
    /// the BSON type byte is `0x03` (document) and that
    /// `processId` / `counter` sub-fields are present.
    #[test]
    fn reply_for_hello_does_not_emit_topology_version_as_string() {
        let doc = build_reply_for("hello");
        // `02` = BSON string type, followed by C-string key
        // `topologyVersion\0`.
        let string_typed_topology_key = [
            0x02, b't', b'o', b'p', b'o', b'l', b'o', b'g', b'y',
                  b'V', b'e', b'r', b's', b'i', b'o', b'n', 0x00,
        ];
        assert!(
            !doc.windows(string_typed_topology_key.len())
                .any(|w| w == string_typed_topology_key),
            "topologyVersion present as BSON string in hello \
             reply — this trips pymongo/Node/Java SDAM and \
             surfaces as `connection closed` (Live-e2e iter32)"
        );
    }
}
