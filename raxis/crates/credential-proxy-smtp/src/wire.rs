//! SMTP wire driver (RFC 5321 minimal subset).
//!
//! The proxy speaks an inbound SMTP-over-TCP dialect against the
//! agent VM and, per submitted envelope, dials the upstream relay
//! configured in [`crate::ProxyConfig::upstream_host_port`] using
//! the credential resolved through `Arc<dyn CredentialBackend>`.
//!
//! ## Inbound protocol
//!
//! ```text
//!   220 raxis-credential-proxy ready
//!   < EHLO client.example
//!   250-raxis-credential-proxy
//!   250 AUTH PLAIN LOGIN
//!   < AUTH PLAIN <base64>            (accepted; payload discarded)
//!   235 2.7.0 authentication successful
//!   < MAIL FROM:<from>
//!   250 OK
//!   < RCPT TO:<rcpt>                 (one or more)
//!   250 OK                           (or 550 if envelope-blocked)
//!   < DATA
//!   354 end data with <CRLF>.<CRLF>
//!   < <message body terminated by \r\n.\r\n>
//!   250 2.0.0 OK <message-id>        (or 552 if oversize)
//!   < QUIT
//!   221 2.0.0 Bye
//! ```
//!
//! The proxy advertises only `AUTH` so SDKs that auto-authenticate
//! still work; the credentials they send are discarded (the agent
//! never knows the upstream credential — see crate-level threat
//! model). Pipelining, STARTTLS, and ENHANCEDSTATUSCODES are
//! intentionally not advertised.
//!
//! ## Outbound dial
//!
//! Per submitted envelope the proxy dials
//! `upstream_host_port`, runs `EHLO`, optionally `STARTTLS` (when
//! [`crate::ProxyConfig::require_upstream_tls`] is set and the
//! upstream advertises it), authenticates via the configured
//! [`crate::AuthMode`], and submits `MAIL FROM` / `RCPT TO` /
//! `DATA`. If the upstream fails any step the inbound envelope is
//! recorded as `Rejected` with the upstream's response code as the
//! reason.
//!
//! The outbound dial is implemented with raw `TcpStream` for cleartext
//! relays plus a real `STARTTLS` upgrade path through `tokio-rustls`
//! (sharing the same `ring`-backed `rustls` already pulled into the
//! workspace by `reqwest`). [`Outbound::IS_TLS_WIRED`] is now `true`,
//! and `submit` consults [`crate::ProxyConfig::require_upstream_tls`]:
//! when set, the proxy issues `STARTTLS`, performs the TLS handshake
//! against [`crate::ProxyConfig::upstream_host_port`]'s host name with
//! Mozilla's CA bundle (via `webpki-roots`), re-issues `EHLO` over
//! TLS, and refuses to fall back to cleartext on any handshake or
//! status failure. The end-to-end TLS path is exercised in the
//! integration tests with a real `tokio-rustls` server fixture.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use raxis_credentials::CredentialBackend;

use crate::restriction::{EnvelopeRejection, RecipientCheck};
use crate::{
    compute_envelope_sha256, AuthMode, EnvelopeAudit, EnvelopeAuditSink, EnvelopeOutcome,
    ProxyConfig, ProxyStats,
};

/// Errors the proxy lifecycle can surface.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Listener bind failed.
    #[error("listener bind failed at {addr}: {source}")]
    Bind {
        /// Address the bind was attempted on.
        addr: String,
        /// Underlying I/O error from `tokio::net::TcpListener::bind`.
        source: std::io::Error,
    },
    /// Upstream `host:port` was malformed.
    #[error("upstream host:port `{0}` is not a valid SMTP address")]
    BadUpstream(String),
}

/// SMTP credential proxy.
pub struct SmtpProxy {
    listener: TcpListener,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    audit: Arc<dyn EnvelopeAuditSink>,
    stats: Arc<ProxyStats>,
    rate: Arc<Mutex<RateBucket>>,
}

impl SmtpProxy {
    /// Bind a listener and return an owned proxy.
    pub async fn bind(
        backend: Arc<dyn CredentialBackend>,
        config: ProxyConfig,
        audit: Arc<dyn EnvelopeAuditSink>,
    ) -> Result<Self, ProxyError> {
        validate_upstream(&config.upstream_host_port)
            .ok_or_else(|| ProxyError::BadUpstream(config.upstream_host_port.clone()))?;

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
            audit,
            stats: Arc::new(ProxyStats::default()),
            rate: Arc::new(Mutex::new(RateBucket::new())),
        })
    }

    /// The address the listener is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Counters snapshot.
    pub fn stats(&self) -> crate::ProxyStatsSnapshot {
        self.stats.snapshot()
    }

    /// Borrow the underlying `Arc<ProxyStats>` so a caller (e.g. the
    /// kernel-side `CredentialProxyManager`) can keep reading
    /// counters AFTER `serve` has consumed the proxy. Call this
    /// BEFORE `tokio::spawn(proxy.serve())`.
    pub fn stats_handle(&self) -> Arc<ProxyStats> {
        Arc::clone(&self.stats)
    }

    /// Run the accept loop until the future is dropped.
    pub async fn serve(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _peer)) => {
                    self.stats
                        .connections_served
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let backend = Arc::clone(&self.backend);
                    let config = self.config.clone();
                    let audit = Arc::clone(&self.audit);
                    let stats = Arc::clone(&self.stats);
                    let rate = Arc::clone(&self.rate);
                    tokio::spawn(async move {
                        if let Err(e) = serve_one(stream, backend, config, audit, stats, rate).await
                        {
                            tracing::warn!(error = ?e, "smtp proxy connection ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "smtp proxy accept failed");
                    break;
                }
            }
        }
    }

    /// Process one inbound connection synchronously (used by the
    /// integration tests; production calls `serve`).
    pub async fn serve_one_for_tests(&self, stream: TcpStream) -> std::io::Result<()> {
        serve_one(
            stream,
            Arc::clone(&self.backend),
            self.config.clone(),
            Arc::clone(&self.audit),
            Arc::clone(&self.stats),
            Arc::clone(&self.rate),
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Per-connection driver
// ---------------------------------------------------------------------------

/// MAX bytes we will buffer for one inbound DATA payload before
/// forcing a `552`. Independent of `Restrictions::max_message_bytes`
/// — the latter is the policy ceiling; this is the
/// proxy-internal hard cap so we never grow the buffer unbounded.
const HARD_DATA_CAP: u64 = 64 * 1024 * 1024;

/// State machine for one inbound SMTP session. Encoded as an
/// explicit enum so a malformed sequence (e.g. `DATA` before any
/// `RCPT TO`) is a single match arm with a clear `503` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionState {
    /// Pre-EHLO. Only `EHLO`/`HELO`/`QUIT` accepted.
    Greeted,
    /// Post-EHLO; envelope is empty.
    Ready,
    /// Post-`MAIL FROM`. Recipients accumulating.
    Mail { from: String, rcpts: Vec<String> },
    /// Post-DATA opener. Body is being read.
    Body { from: String, rcpts: Vec<String> },
}

async fn serve_one(
    stream: TcpStream,
    backend: Arc<dyn CredentialBackend>,
    config: ProxyConfig,
    audit: Arc<dyn EnvelopeAuditSink>,
    stats: Arc<ProxyStats>,
    rate: Arc<Mutex<RateBucket>>,
) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    write
        .write_all(b"220 raxis-credential-proxy ready\r\n")
        .await?;

    let mut state = SessionState::Greeted;
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // Client closed.
            return Ok(());
        }
        let cmd = line.trim_end_matches(['\r', '\n']);

        if cmd.eq_ignore_ascii_case("QUIT") {
            write.write_all(b"221 2.0.0 Bye\r\n").await?;
            return Ok(());
        }

        match &mut state {
            SessionState::Greeted => {
                if let Some(rest) = strip_prefix_ci(cmd, "EHLO ") {
                    let _ = rest;
                    write.write_all(b"250-raxis-credential-proxy\r\n").await?;
                    write.write_all(b"250 AUTH PLAIN LOGIN\r\n").await?;
                    state = SessionState::Ready;
                } else if strip_prefix_ci(cmd, "HELO ").is_some() {
                    write.write_all(b"250 raxis-credential-proxy\r\n").await?;
                    state = SessionState::Ready;
                } else {
                    write.write_all(b"503 5.5.1 send EHLO first\r\n").await?;
                }
            }
            SessionState::Ready => {
                if strip_prefix_ci(cmd, "AUTH PLAIN").is_some()
                    || strip_prefix_ci(cmd, "AUTH LOGIN").is_some()
                {
                    // Accept any auth attempt and discard the payload —
                    // the agent's credentials are not used. We may
                    // still need to consume the multi-line LOGIN
                    // exchange.
                    if cmd.eq_ignore_ascii_case("AUTH LOGIN") {
                        write.write_all(b"334 VXNlcm5hbWU6\r\n").await?;
                        // Consume username line.
                        line.clear();
                        let n = reader.read_line(&mut line).await?;
                        if n == 0 {
                            return Ok(());
                        }
                        write.write_all(b"334 UGFzc3dvcmQ6\r\n").await?;
                        // Consume password line.
                        line.clear();
                        let n = reader.read_line(&mut line).await?;
                        if n == 0 {
                            return Ok(());
                        }
                    }
                    write
                        .write_all(b"235 2.7.0 authentication successful\r\n")
                        .await?;
                } else if let Some(addr) = strip_prefix_ci(cmd, "MAIL FROM:") {
                    let from = addr.trim().to_owned();

                    // Rate-limit BEFORE we accept the sender so the
                    // agent's SMTP client backs off naturally on
                    // `421`.
                    if let Some(limit) = config.restrictions.max_messages_per_minute {
                        let mut bucket = rate.lock().await;
                        if !bucket.try_consume_now(limit) {
                            audit.emit(rejection_audit(
                                &config,
                                &from,
                                &[],
                                0,
                                EnvelopeRejection::RateLimitExceeded { limit },
                            ));
                            stats
                                .messages_rejected
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            write
                                .write_all(b"421 4.7.0 rate limit exceeded\r\n")
                                .await?;
                            continue;
                        }
                    }

                    if let Err(rej) = config.restrictions.check_sender(&from) {
                        audit.emit(rejection_audit(&config, &from, &[], 0, rej));
                        stats
                            .messages_rejected
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        write.write_all(b"550 5.7.1 sender not allowed\r\n").await?;
                        continue;
                    }

                    state = SessionState::Mail {
                        from,
                        rcpts: Vec::new(),
                    };
                    write.write_all(b"250 2.1.0 OK\r\n").await?;
                } else {
                    write
                        .write_all(b"503 5.5.1 bad sequence of commands\r\n")
                        .await?;
                }
            }
            SessionState::Mail { from, rcpts } => {
                if let Some(addr) = strip_prefix_ci(cmd, "RCPT TO:") {
                    let r = addr.trim().to_owned();
                    match config.restrictions.check_recipient(&r) {
                        RecipientCheck::Allowed => {
                            rcpts.push(r);
                            write.write_all(b"250 2.1.5 OK\r\n").await?;
                        }
                        RecipientCheck::Blocked { reason } => {
                            audit.emit(rejection_audit(
                                &config,
                                from,
                                rcpts,
                                0,
                                EnvelopeRejection::RecipientNotAllowed { reason },
                            ));
                            stats
                                .messages_rejected
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            write
                                .write_all(b"550 5.7.1 recipient not allowed\r\n")
                                .await?;
                        }
                    }
                } else if cmd.eq_ignore_ascii_case("DATA") {
                    if rcpts.is_empty() {
                        write.write_all(b"503 5.5.1 RCPT TO required\r\n").await?;
                        continue;
                    }
                    if let Err(rej) = config
                        .restrictions
                        .check_recipient_count(rcpts.len() as u32)
                    {
                        audit.emit(rejection_audit(&config, from, rcpts, 0, rej));
                        stats
                            .messages_rejected
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        write
                            .write_all(b"452 4.5.3 too many recipients\r\n")
                            .await?;
                        // Reset to Ready so the agent can MAIL FROM again.
                        state = SessionState::Ready;
                        continue;
                    }
                    write
                        .write_all(b"354 end data with <CRLF>.<CRLF>\r\n")
                        .await?;

                    // Read the message body.
                    let body = match read_dot_terminated_body(
                        &mut reader,
                        &mut write,
                        config.restrictions.max_message_bytes,
                    )
                    .await?
                    {
                        Some(b) => b,
                        None => {
                            // Oversize-rejected; client got 552.
                            audit.emit(rejection_audit(
                                &config,
                                from,
                                rcpts,
                                0,
                                EnvelopeRejection::MessageTooLarge {
                                    limit: config.restrictions.max_message_bytes.unwrap_or(0),
                                    got: config.restrictions.max_message_bytes.unwrap_or(0) + 1,
                                },
                            ));
                            stats
                                .messages_rejected
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            state = SessionState::Ready;
                            continue;
                        }
                    };

                    let bytes = body.len() as u64;

                    let from_owned = from.clone();
                    let rcpts_owned = std::mem::take(rcpts);

                    state = SessionState::Body {
                        from: from_owned.clone(),
                        rcpts: rcpts_owned.clone(),
                    };
                    let _ = state;

                    // Forward to upstream.
                    let envelope_sha = compute_envelope_sha256(&from_owned, &rcpts_owned);
                    match Outbound::submit(&backend, &config, &from_owned, &rcpts_owned, &body)
                        .await
                    {
                        Ok(()) => {
                            audit.emit(EnvelopeAudit {
                                outcome: EnvelopeOutcome::Relayed,
                                consumer: config.consumer.clone(),
                                envelope_sha256: envelope_sha,
                                recipient_count: rcpts_owned.len() as u32,
                                bytes_submitted: bytes,
                                rejection_reason: None,
                            });
                            stats
                                .messages_relayed
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            stats.recipients_accepted.fetch_add(
                                rcpts_owned.len() as u32,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            stats
                                .bytes_relayed
                                .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
                            write.write_all(b"250 2.0.0 OK\r\n").await?;
                        }
                        Err(reason) => {
                            audit.emit(EnvelopeAudit {
                                outcome: EnvelopeOutcome::Rejected,
                                consumer: config.consumer.clone(),
                                envelope_sha256: envelope_sha,
                                recipient_count: rcpts_owned.len() as u32,
                                bytes_submitted: bytes,
                                rejection_reason: Some(format!("upstream_failed reason={reason}")),
                            });
                            stats
                                .messages_rejected
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            write
                                .write_all(b"451 4.4.0 upstream relay failed\r\n")
                                .await?;
                        }
                    }
                    state = SessionState::Ready;
                } else {
                    write
                        .write_all(b"503 5.5.1 bad sequence of commands\r\n")
                        .await?;
                }
            }
            SessionState::Body { .. } => {
                // Should never be visible at the outer match — the
                // body branch transitions back to Ready before
                // looping. Defensive only.
                write.write_all(b"503 5.5.1 unexpected state\r\n").await?;
                state = SessionState::Ready;
            }
        }
    }
}

/// Read a `\r\n.\r\n`-terminated SMTP DATA body. Returns
/// `Ok(Some(body))` on success, `Ok(None)` if the policy
/// `max_message_bytes` cap was exceeded (the caller MUST emit the
/// rejection audit + send 552), or an `io::Error` on socket failure.
///
/// Implements the "dot stuffing" protocol per RFC 5321 §4.5.2: a
/// line consisting of `..` is replaced by `.` in the body buffer
/// and is NOT a body terminator.
async fn read_dot_terminated_body<R, W>(
    reader: &mut BufReader<R>,
    write: &mut W,
    soft_cap: Option<u64>,
) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut body = Vec::new();
    let mut line = String::new();
    let mut total: u64 = 0;
    let cap_for_this_envelope = soft_cap
        .map(|c| c.min(HARD_DATA_CAP))
        .unwrap_or(HARD_DATA_CAP);

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // Client closed mid-DATA — treat as oversize-equivalent;
            // the audit caller will record the truncation.
            return Ok(None);
        }
        // Body terminator: a line containing exactly ".\r\n".
        if line == ".\r\n" || line == ".\n" {
            return Ok(Some(body));
        }
        // Dot-stuffing unescape.
        let stripped = if line.starts_with("..") {
            &line[1..]
        } else {
            line.as_str()
        };
        total += stripped.len() as u64;
        if total > cap_for_this_envelope {
            // Drain any remaining bytes from the agent's pipe so the
            // next QUIT lands cleanly, but cap the drain at twice
            // the body cap so we don't get stuck on a malicious
            // agent that never sends ".\r\n".
            let drain_cap = cap_for_this_envelope * 2;
            let mut drained: u64 = total;
            while drained < drain_cap {
                line.clear();
                let m = reader.read_line(&mut line).await?;
                if m == 0 || line == ".\r\n" || line == ".\n" {
                    break;
                }
                drained += m as u64;
            }
            write
                .write_all(b"552 5.3.4 message size exceeds fixed limit\r\n")
                .await?;
            return Ok(None);
        }
        body.extend_from_slice(stripped.as_bytes());
    }
}

fn rejection_audit(
    config: &ProxyConfig,
    from: &str,
    rcpts: &[String],
    bytes: u64,
    rej: EnvelopeRejection,
) -> EnvelopeAudit {
    EnvelopeAudit {
        outcome: EnvelopeOutcome::Rejected,
        consumer: config.consumer.clone(),
        envelope_sha256: compute_envelope_sha256(from, rcpts),
        recipient_count: rcpts.len() as u32,
        bytes_submitted: bytes,
        rejection_reason: Some(rej.audit_summary()),
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() {
        return None;
    }
    let (head, tail) = s.split_at(prefix.len());
    if head.eq_ignore_ascii_case(prefix) {
        Some(tail)
    } else {
        None
    }
}

/// Lightweight `host:port` validator. Returns `Some(())` when the
/// string parses as `<host>:<u16>`; we don't insist on a full
/// `SocketAddr::parse` because operators may name the upstream by
/// hostname (e.g. `email-smtp.us-east-1.amazonaws.com:587`).
fn validate_upstream(host_port: &str) -> Option<()> {
    let (host, port) = host_port.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    port.parse::<u16>().ok()?;
    Some(())
}

// ---------------------------------------------------------------------------
// Outbound dial — TCP greet/EHLO, optional STARTTLS upgrade via
// `tokio-rustls`, AUTH/MAIL FROM/RCPT TO/DATA over the upgraded stream.
// ---------------------------------------------------------------------------

/// Outbound SMTP dial. Performs `EHLO`/(`STARTTLS`)?/`AUTH`/`MAIL
/// FROM`/`RCPT TO`/`DATA` against the configured upstream. The TLS
/// upgrade is wired through `tokio-rustls`; see [`Outbound::IS_TLS_WIRED`].
pub struct Outbound;

impl Outbound {
    /// Whether the outbound dial performs the `STARTTLS` handshake
    /// when `require_upstream_tls = true`. The kernel-side wiring
    /// can consult this constant in tests / preflight to confirm the
    /// proxy build supports TLS.
    pub const IS_TLS_WIRED: bool = true;

    /// Dial the upstream, run the SMTP submission, and return on
    /// success. Errors are flattened to a single `String` for
    /// audit-surface stability — the upstream's response codes are
    /// the operator's diagnostic surface, not the inbound agent's.
    ///
    /// Flow:
    ///   1. TCP-connect to `config.upstream_host_port`.
    ///   2. Read 220 greeting, send `EHLO`, read multi-line 250.
    ///   3. If `config.require_upstream_tls`: send `STARTTLS`, expect
    ///      220, perform TLS handshake using `tokio-rustls` + Mozilla
    ///      CA bundle (`webpki-roots`), re-issue `EHLO` over TLS.
    ///   4. AUTH (PLAIN or LOGIN) using the resolved credential bytes.
    ///   5. `MAIL FROM`, `RCPT TO` (per recipient), `DATA` + body
    ///      (RFC 5321 §4.5.2 dot-stuffing applied).
    ///   6. `QUIT` (best-effort).
    pub async fn submit(
        backend: &Arc<dyn CredentialBackend>,
        config: &ProxyConfig,
        from: &str,
        rcpts: &[String],
        body: &[u8],
    ) -> Result<(), String> {
        // Resolve the credential bytes per submission. The backend's
        // resolve API is synchronous and takes `ConsumerIdentity` by
        // value; we run it on the current task (no thread-blocking
        // I/O for File / Vault backends — the impls bound their
        // sync work to memory + small sockets).
        let cred = backend
            .resolve(&config.credential_name, config.consumer.as_ref())
            .map_err(|e| format!("credential_resolve_failed: {e}"))?;

        let stream = TcpStream::connect(&config.upstream_host_port)
            .await
            .map_err(|e| format!("upstream_dial_failed: {e}"))?;

        if config.require_upstream_tls {
            // STARTTLS path: greet/EHLO/STARTTLS over TCP, then upgrade.
            let stream = starttls_upgrade(stream, &config.upstream_host_port).await?;
            drive_post_handshake(stream, config, &cred, from, rcpts, body).await
        } else {
            // Cleartext path: greet/EHLO inline, then AUTH/...
            drive_cleartext(stream, config, &cred, from, rcpts, body).await
        }
    }
}

/// Cleartext flow: greet → EHLO → AUTH → MAIL FROM → RCPT TO → DATA
/// → QUIT, all on plain TCP.
async fn drive_cleartext(
    stream: TcpStream,
    config: &ProxyConfig,
    cred: &raxis_credentials::CredentialValue,
    from: &str,
    rcpts: &[String],
    body: &[u8],
) -> Result<(), String> {
    let (read, write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut write = write;

    // 220 greeting.
    let _greeting = read_smtp_status(&mut reader, "greeting").await?;

    // EHLO.
    write
        .write_all(b"EHLO raxis-credential-proxy\r\n")
        .await
        .map_err(|e| format!("ehlo_write_failed: {e}"))?;
    let _ehlo_resp = read_smtp_multi_status(&mut reader, "ehlo").await?;

    drive_auth_through_quit(&mut reader, &mut write, config, cred, from, rcpts, body).await
}

/// STARTTLS upgrade: greet → EHLO → STARTTLS → tokio-rustls handshake →
/// re-EHLO over TLS → continue with AUTH/.../QUIT over the upgraded
/// stream.
async fn starttls_upgrade(
    stream: TcpStream,
    upstream_host_port: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let host = upstream_host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .ok_or_else(|| "upstream_host_port_missing_colon".to_owned())?;
    let server_name: ServerName<'static> = ServerName::try_from(host.to_owned())
        .map_err(|e| format!("invalid_upstream_servername: {e}"))?;

    let connector = TlsConnector::from(default_client_config());

    // Step 1: greet/EHLO/STARTTLS over plain TCP. We need to keep the
    // stream alive across the upgrade, so we operate on a mutable
    // reference and drop the buf reader before handing the stream to
    // the TLS connector.
    let mut stream = stream;
    {
        let (read, write) = tokio::io::split(&mut stream);
        let mut reader = BufReader::new(read);
        let mut write = write;

        let _greeting = read_smtp_status(&mut reader, "greeting").await?;

        write
            .write_all(b"EHLO raxis-credential-proxy\r\n")
            .await
            .map_err(|e| format!("ehlo_write_failed: {e}"))?;
        let _ehlo_resp = read_smtp_multi_status(&mut reader, "ehlo").await?;

        write
            .write_all(b"STARTTLS\r\n")
            .await
            .map_err(|e| format!("starttls_write_failed: {e}"))?;
        let s = read_smtp_status(&mut reader, "starttls").await?;
        if s != 220 {
            return Err(format!("starttls_rejected status={s}"));
        }
    }

    // Step 2: TLS handshake.
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("tls_handshake_failed: {e}"))?;

    // Step 3: re-issue EHLO over TLS so the upstream advertises its
    // post-TLS capability set (some relays only advertise AUTH inside
    // the TLS-protected EHLO).
    {
        let (read, write) = tokio::io::split(&mut tls_stream);
        let mut reader = BufReader::new(read);
        let mut write = write;
        write
            .write_all(b"EHLO raxis-credential-proxy\r\n")
            .await
            .map_err(|e| format!("ehlo_tls_write_failed: {e}"))?;
        let _ehlo_resp = read_smtp_multi_status(&mut reader, "ehlo_tls").await?;
        // Drop the split halves; ownership returns to the outer
        // tls_stream via the borrow lifetime.
    }

    Ok(tls_stream)
}

/// Continue the SMTP submission on a (post-handshake) TLS stream.
async fn drive_post_handshake<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    config: &ProxyConfig,
    cred: &raxis_credentials::CredentialValue,
    from: &str,
    rcpts: &[String],
    body: &[u8],
) -> Result<(), String> {
    let (read, write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut write = write;

    drive_auth_through_quit(&mut reader, &mut write, config, cred, from, rcpts, body).await
}

/// Shared AUTH/MAIL FROM/RCPT TO/DATA/QUIT body — generic over the
/// stream halves so the cleartext path and the TLS path share the
/// same code.
async fn drive_auth_through_quit<R, W>(
    reader: &mut BufReader<R>,
    write: &mut W,
    config: &ProxyConfig,
    cred: &raxis_credentials::CredentialValue,
    from: &str,
    rcpts: &[String],
    body: &[u8],
) -> Result<(), String>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // AUTH (the credential bytes never leave this future's stack —
    // we render the wire-format payload inside `with_bytes` so the
    // borrow scope ends before the stream write returns).
    let auth_line = match &config.auth_mode {
        AuthMode::Plain { user } => cred.with_bytes(|cred_bytes| {
            let mut payload = Vec::with_capacity(2 + user.len() + cred_bytes.len());
            payload.push(0u8);
            payload.extend_from_slice(user.as_bytes());
            payload.push(0u8);
            payload.extend_from_slice(cred_bytes);
            let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
            format!("AUTH PLAIN {b64}\r\n")
        }),
        AuthMode::Login { user } => {
            // RFC 4954 §4 allows the user-line to be supplied in the
            // same command for IMF clients that prefer it; many
            // production relays accept it.
            let user_b64 = base64::engine::general_purpose::STANDARD.encode(user.as_bytes());
            format!("AUTH LOGIN {user_b64}\r\n")
        }
    };
    write
        .write_all(auth_line.as_bytes())
        .await
        .map_err(|e| format!("auth_write_failed: {e}"))?;
    let auth_status = read_smtp_status(reader, "auth").await?;
    if auth_status >= 400 {
        return Err(format!("auth_rejected status={auth_status}"));
    }
    // Login may need a second password line if status was 334.
    if matches!(&config.auth_mode, AuthMode::Login { .. }) && auth_status == 334 {
        let pw_b64 = cred
            .with_bytes(|cred_bytes| base64::engine::general_purpose::STANDARD.encode(cred_bytes));
        write
            .write_all(pw_b64.as_bytes())
            .await
            .map_err(|e| format!("auth_login_pw_write_failed: {e}"))?;
        write.write_all(b"\r\n").await.ok();
        let s = read_smtp_status(reader, "auth-login-pw").await?;
        if s >= 400 {
            return Err(format!("auth_rejected status={s}"));
        }
    }

    // MAIL FROM.
    write
        .write_all(format!("MAIL FROM:{from}\r\n").as_bytes())
        .await
        .map_err(|e| format!("mail_from_write_failed: {e}"))?;
    let s = read_smtp_status(reader, "mail_from").await?;
    if s >= 400 {
        return Err(format!("mail_from_rejected status={s}"));
    }

    // RCPT TO (one at a time).
    for r in rcpts {
        write
            .write_all(format!("RCPT TO:{r}\r\n").as_bytes())
            .await
            .map_err(|e| format!("rcpt_to_write_failed: {e}"))?;
        let s = read_smtp_status(reader, "rcpt_to").await?;
        if s >= 400 {
            return Err(format!("rcpt_to_rejected status={s}"));
        }
    }

    // DATA.
    write
        .write_all(b"DATA\r\n")
        .await
        .map_err(|e| format!("data_write_failed: {e}"))?;
    let s = read_smtp_status(reader, "data").await?;
    if s != 354 {
        return Err(format!("data_rejected status={s}"));
    }
    // Apply RFC 5321 §4.5.2 dot-stuffing on the way out.
    for line in body.split_inclusive(|&b| b == b'\n') {
        if line.starts_with(b".") {
            write
                .write_all(b".")
                .await
                .map_err(|e| format!("data_body_dot_stuff_write_failed: {e}"))?;
        }
        write
            .write_all(line)
            .await
            .map_err(|e| format!("data_body_write_failed: {e}"))?;
    }
    // Ensure the body ends with CRLF before the terminator, then
    // send `.\r\n`.
    if !body.ends_with(b"\r\n") {
        write.write_all(b"\r\n").await.ok();
    }
    write
        .write_all(b".\r\n")
        .await
        .map_err(|e| format!("data_terminator_write_failed: {e}"))?;
    let s = read_smtp_status(reader, "data_done").await?;
    if s >= 400 {
        return Err(format!("data_done_rejected status={s}"));
    }

    // QUIT (best-effort; we don't fail the relay if the upstream
    // hangs up before responding).
    write.write_all(b"QUIT\r\n").await.ok();
    let _ = tokio::time::timeout(Duration::from_secs(2), read_smtp_status(reader, "quit")).await;

    Ok(())
}

/// Construct (or reuse) a `rustls::ClientConfig` backed by Mozilla's
/// CA bundle (via `webpki-roots`). The config is built once per
/// process and cached behind a `OnceLock` so per-envelope dials
/// don't re-parse the trust anchors.
fn default_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let cfg = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone()
}

/// Read a single SMTP status response line, return its 3-digit code.
/// Multi-line responses (the leading line carries `<code>-`) are
/// drained with [`read_smtp_multi_status`] when the caller knows
/// they expect one.
async fn read_smtp_status<R: AsyncReadExt + Unpin>(
    reader: &mut BufReader<R>,
    where_: &str,
) -> Result<u16, String> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("{where_}_read_failed: {e}"))?;
    if n == 0 {
        return Err(format!("{where_}_eof_before_status"));
    }
    parse_smtp_status_line(&line, where_)
}

async fn read_smtp_multi_status<R: AsyncReadExt + Unpin>(
    reader: &mut BufReader<R>,
    where_: &str,
) -> Result<u16, String> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("{where_}_read_failed: {e}"))?;
        if n == 0 {
            return Err(format!("{where_}_eof_before_status"));
        }
        let code = parse_smtp_status_line(&line, where_)?;
        if line.len() > 3 && line.as_bytes()[3] == b'-' {
            // Continuation.
            continue;
        }
        return Ok(code);
    }
}

fn parse_smtp_status_line(line: &str, where_: &str) -> Result<u16, String> {
    if line.len() < 3 {
        return Err(format!("{where_}_short_status: {line:?}"));
    }
    line[..3]
        .parse::<u16>()
        .map_err(|e| format!("{where_}_bad_status: {e} (line={line:?})"))
}

// ---------------------------------------------------------------------------
// Rate bucket
// ---------------------------------------------------------------------------

/// Rolling 60-second token bucket. Tracks the timestamps of recent
/// `try_consume_now` successes; the next `try_consume_now` allows a
/// new token IF (count of timestamps within the last 60s) < limit.
#[derive(Debug)]
struct RateBucket {
    timestamps: Vec<Instant>,
}

impl RateBucket {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    fn try_consume_now(&mut self, limit_per_minute: u32) -> bool {
        self.try_consume_at(Instant::now(), limit_per_minute)
    }

    fn try_consume_at(&mut self, now: Instant, limit_per_minute: u32) -> bool {
        let cutoff = now - Duration::from_secs(60);
        self.timestamps.retain(|t| *t >= cutoff);
        if (self.timestamps.len() as u32) < limit_per_minute {
            self.timestamps.push(now);
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_upstream_accepts_host_port_pairs() {
        assert!(validate_upstream("smtp.example.com:587").is_some());
        assert!(validate_upstream("127.0.0.1:25").is_some());
        assert!(validate_upstream("[::1]:587").is_some());
    }

    #[test]
    fn validate_upstream_rejects_malformed_host_or_port() {
        assert!(validate_upstream("").is_none());
        assert!(validate_upstream("smtp.example.com").is_none());
        assert!(validate_upstream(":25").is_none());
        assert!(validate_upstream("smtp.example.com:not-a-port").is_none());
        assert!(
            validate_upstream("smtp.example.com:99999").is_none(),
            "port out of u16 range"
        );
    }

    #[test]
    fn rate_bucket_admits_until_limit_in_one_minute() {
        let mut b = RateBucket::new();
        let now = Instant::now();
        for _ in 0..5 {
            assert!(b.try_consume_at(now, 5));
        }
        assert!(
            !b.try_consume_at(now, 5),
            "6th attempt within 60s must be rejected"
        );
    }

    #[test]
    fn rate_bucket_rolls_off_after_60s() {
        let mut b = RateBucket::new();
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(b.try_consume_at(t0, 5));
        }
        // 61s later the previous bucket has emptied.
        let t1 = t0 + Duration::from_secs(61);
        assert!(b.try_consume_at(t1, 5));
        // and the bucket internally only retains the new timestamp.
        assert_eq!(b.timestamps.len(), 1);
    }

    #[test]
    fn parse_smtp_status_line_extracts_code() {
        assert_eq!(parse_smtp_status_line("220 hello\r\n", "x").unwrap(), 220);
        assert_eq!(parse_smtp_status_line("250-multi\r\n", "x").unwrap(), 250);
        assert_eq!(
            parse_smtp_status_line("550 5.7.1 nope\r\n", "x").unwrap(),
            550
        );
    }

    #[test]
    fn parse_smtp_status_line_rejects_short_or_non_numeric() {
        assert!(parse_smtp_status_line("hi", "x").is_err());
        assert!(parse_smtp_status_line("XYZ ok", "x").is_err());
    }

    #[test]
    fn strip_prefix_ci_handles_mixed_case() {
        assert_eq!(strip_prefix_ci("EHLO foo", "EHLO "), Some("foo"));
        assert_eq!(strip_prefix_ci("ehlo foo", "EHLO "), Some("foo"));
        assert_eq!(strip_prefix_ci("EhLo foo", "EHLO "), Some("foo"));
        assert_eq!(strip_prefix_ci("HELO bar", "EHLO "), None);
        assert_eq!(strip_prefix_ci("EH", "EHLO "), None);
    }

    /// Bind a proxy on `127.0.0.1:0`, exchange a minimal
    /// EHLO/QUIT — confirms the listener is wired and the greeting
    /// banner shape is stable.
    /// Drain a complete SMTP reply (one or more `<code>-...\r\n`
    /// continuation lines followed by a single `<code> ...\r\n`
    /// terminator) using a `BufReader<&mut TcpStream>`. Returns the
    /// concatenated text.
    ///
    /// We intentionally read line-by-line rather than letting the
    /// test code call `read(&mut buf)` once: SMTP replies are
    /// framed by CRLF, not by TCP packet boundaries, so a single
    /// `read` call may return only a prefix (the proxy emits each
    /// EHLO continuation line with an independent `write_all`). The
    /// helper mirrors what a real SMTP client does and what
    /// `read_smtp_multi_status` does in this same file.
    async fn drain_reply<'a>(reader: &mut tokio::io::BufReader<&'a mut TcpStream>) -> String {
        use tokio::io::AsyncBufReadExt;
        let mut out = String::new();
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await.expect("read_line");
            if n == 0 {
                break;
            }
            out.push_str(&line);
            // Continuation marker is `<code>-` (4th byte). Any other
            // 4th byte (typically a space, RFC 5321 §4.2.1) marks
            // the terminator line.
            if line.len() >= 4 && line.as_bytes()[3] != b'-' {
                break;
            }
        }
        out
    }

    #[tokio::test]
    async fn ehlo_quit_round_trip_reads_220_and_221() {
        use raxis_credentials::{
            ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
            Lease, OperatorId,
        };
        struct NoopBackend;
        impl CredentialBackend for NoopBackend {
            fn resolve(
                &self,
                _name: &CredentialName,
                _by: ConsumerIdentity<'_>,
            ) -> Result<CredentialValue, CredentialError> {
                Ok(CredentialValue::from_bytes(b"".to_vec()))
            }
            fn rotate(
                &self,
                _name: &CredentialName,
                _new: CredentialValue,
                _actor: OperatorId,
            ) -> Result<(), CredentialError> {
                unreachable!("rotate not exercised in this test")
            }
            fn exists(&self, _name: &CredentialName) -> bool {
                true
            }
            fn lease(&self, _name: &CredentialName) -> Lease {
                Lease::Forever
            }
            fn backend_kind(&self) -> &'static str {
                "test_noop"
            }
        }

        let cfg = ProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            upstream_host_port: "127.0.0.1:1".to_owned(),
            require_upstream_tls: false,
            credential_name: CredentialName::new("smtp-test"),
            auth_mode: AuthMode::Plain {
                user: "u".to_owned(),
            },
            consumer: crate::OwnedConsumer::new("test", "smtp"),
            restrictions: crate::Restrictions::default(),
        };
        let proxy = SmtpProxy::bind(
            Arc::new(NoopBackend),
            cfg,
            Arc::new(crate::NoopEnvelopeAuditSink),
        )
        .await
        .expect("bind smtp proxy");

        let addr = proxy.local_addr().expect("local_addr");
        let _stats = proxy.stats_handle();
        let server = tokio::spawn(async move { proxy.serve().await });

        let mut client = TcpStream::connect(addr).await.expect("connect to proxy");
        let mut reader = tokio::io::BufReader::new(&mut client);

        let banner = drain_reply(&mut reader).await;
        assert!(
            banner.starts_with("220 "),
            "expected 220 banner, got {banner:?}"
        );

        // Drop the borrow so we can write back through the same
        // socket without splitting it.
        drop(reader);

        client.write_all(b"EHLO smoke\r\n").await.unwrap();
        let mut reader = tokio::io::BufReader::new(&mut client);
        let ehlo = drain_reply(&mut reader).await;
        assert!(ehlo.contains("250"), "expected 250 EHLO line, got {ehlo:?}");
        assert!(
            ehlo.contains("AUTH"),
            "EHLO must advertise AUTH, got {ehlo:?}"
        );
        drop(reader);

        client.write_all(b"QUIT\r\n").await.unwrap();
        let mut reader = tokio::io::BufReader::new(&mut client);
        let quit = drain_reply(&mut reader).await;
        assert!(quit.starts_with("221 "), "expected 221 Bye, got {quit:?}");

        server.abort();
    }

    /// Sender outside `allowed_sender_address` is rejected with
    /// `550` and produces an `EnvelopeOutcome::Rejected` audit event
    /// before any RCPT TO is issued. Pin the audit shape so
    /// downstream dashboards don't drift.
    #[tokio::test]
    async fn sender_not_allowed_rejects_with_550_and_audits_envelope() {
        use raxis_credentials::{
            ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
            Lease, OperatorId,
        };
        use std::sync::Mutex as StdMutex;

        struct NoopBackend;
        impl CredentialBackend for NoopBackend {
            fn resolve(
                &self,
                _name: &CredentialName,
                _by: ConsumerIdentity<'_>,
            ) -> Result<CredentialValue, CredentialError> {
                Ok(CredentialValue::from_bytes(b"".to_vec()))
            }
            fn rotate(
                &self,
                _name: &CredentialName,
                _new: CredentialValue,
                _actor: OperatorId,
            ) -> Result<(), CredentialError> {
                unreachable!("rotate not exercised in this test")
            }
            fn exists(&self, _name: &CredentialName) -> bool {
                true
            }
            fn lease(&self, _name: &CredentialName) -> Lease {
                Lease::Forever
            }
            fn backend_kind(&self) -> &'static str {
                "test_noop"
            }
        }
        struct CapturingSink(StdMutex<Vec<EnvelopeAudit>>);
        impl EnvelopeAuditSink for CapturingSink {
            fn emit(&self, e: EnvelopeAudit) {
                self.0.lock().unwrap().push(e);
            }
        }

        let sink = Arc::new(CapturingSink(StdMutex::new(Vec::new())));
        let cfg = ProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            upstream_host_port: "127.0.0.1:1".to_owned(),
            require_upstream_tls: false,
            credential_name: CredentialName::new("smtp-test"),
            auth_mode: AuthMode::Plain {
                user: "u".to_owned(),
            },
            consumer: crate::OwnedConsumer::new("test", "smtp"),
            restrictions: crate::Restrictions {
                allowed_sender_address: Some("noreply@example.com".to_owned()),
                ..crate::Restrictions::default()
            },
        };
        let proxy = SmtpProxy::bind(Arc::new(NoopBackend), cfg, sink.clone())
            .await
            .unwrap();
        let addr = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move { proxy.serve().await });

        let mut client = TcpStream::connect(addr).await.unwrap();

        // Banner.
        let mut reader = tokio::io::BufReader::new(&mut client);
        let _banner = drain_reply(&mut reader).await;
        drop(reader);

        client.write_all(b"EHLO smoke\r\n").await.unwrap();
        let mut reader = tokio::io::BufReader::new(&mut client);
        let _ehlo = drain_reply(&mut reader).await;
        drop(reader);

        client
            .write_all(b"MAIL FROM:<attacker@elsewhere.example>\r\n")
            .await
            .unwrap();
        let mut reader = tokio::io::BufReader::new(&mut client);
        let resp = drain_reply(&mut reader).await;
        assert!(
            resp.starts_with("550 "),
            "expected 550 sender_not_allowed, got {resp:?}"
        );
        drop(reader);

        client.write_all(b"QUIT\r\n").await.unwrap();
        let mut reader = tokio::io::BufReader::new(&mut client);
        let _ = drain_reply(&mut reader).await;
        drop(reader);

        server.abort();

        let events = sink.0.lock().unwrap();
        assert_eq!(
            events.len(),
            1,
            "expected 1 audit event, got {:?}",
            events.len()
        );
        let ev = &events[0];
        assert_eq!(ev.outcome, EnvelopeOutcome::Rejected);
        assert!(
            ev.rejection_reason
                .as_deref()
                .unwrap()
                .starts_with("sender_not_allowed"),
            "rejection_reason was {:?}",
            ev.rejection_reason
        );
        assert_eq!(ev.recipient_count, 0);
    }
}
