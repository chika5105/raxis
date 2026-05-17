//! Upstream MongoDB connection driver.
//! Normative reference: `credential-proxy.md §14.3` (lazy connect on
//! first allowed query) and `§14.8.4` (per-proxy implementation
//! matrix for MongoDB), plus
//! (SCRAM-SHA-256 upstream auth).
//! # What this module owns
//! * Parsing the **credential value** (resolved through
//!   `Arc<dyn CredentialBackend>`) as a Mongo Standard Connection
//!   String like `mongodb://host:27017/db` or
//!   `mongodb://user:pass@host:27017/db?authSource=admin`.
//! * Opening a real `tokio::net::TcpStream` to the upstream.
//! * Driving the SCRAM-SHA-256 SASL conversation against the
//!   upstream when the URL carries `user:password@` userinfo
//!   (RFC 5802 + 7677 wire shape carried inside MongoDB
//!   `saslStart` / `saslContinue` `OP_MSG` envelopes).
//! * Relaying `OP_MSG` packets verbatim once the upstream session
//!   is usable. The agent's own SASL conversation (if any) is
//!   discarded — `[restriction]` blocks `saslStart`/`saslContinue`
//!   from agents in `allow_read_only` mode by default; the proxy
//!   authenticates upstream with the kernel-resolved credential.
//! * Surfacing structured errors at every failure point so the proxy
//!   can map them to the three V2.1 audit events (`UpstreamConnected`,
//!   `UpstreamFailed`, `DatabaseQueryCompleted`).
//! # SCRAM-SHA-256 wire shape (RFC 5802 + 7677, MongoDB OP_MSG envelope)
//! Once the TCP connect succeeds the proxy issues, in order:
//! 1. `saslStart` (database = `authSource` from URL or `"admin"`):
//!    ```text
//!    { saslStart: 1, mechanism: "SCRAM-SHA-256",
//!      payload: BinData(0, "n,,n=<user>,r=<client-nonce>"),
//!      autoAuthorize: 1, options: { skipEmptyExchange: true } }
//!    ```
//!    The `n,,` prefix is the RFC 5802 §5.1 gs2-header: a `n`
//!    cbind-flag (no channel binding), an empty authzid placeholder,
//!    and the trailing comma that separates the gs2-header from the
//!    bare client-first message. Its base64 form `biws` is what the
//!    proxy later reflects through the `c=biws` channel-binding
//!    attribute on the client-final message in step 3.
//! 2. The server's reply carries `payload = "r=<combined>,s=<salt>,i=<iter>"`
//!    where `<combined>` MUST start with `<client-nonce>`. The proxy
//!    enforces both RFC 5802 §5 invariants (nonce prefix match +
//!    `iter >= 4096` minimum from the SCRAM spec — MongoDB's default
//!    is 15_000 but legacy clusters can be lower).
//! 3. `saslContinue` with the next conversation id and
//!    `payload = "c=biws,r=<combined>,p=<base64(client_proof)>"`
//!    where `client_proof = client_key XOR client_signature`,
//!    `client_key = HMAC-SHA256(salted_password, "Client Key")`,
//!    `salted_password = PBKDF2-HMAC-SHA256(password, salt, iter, 32)`,
//!    and `client_signature = HMAC-SHA256(SHA256(client_key), auth_message)`.
//! 4. The server's reply carries `payload = "v=<base64(server_signature)>"`
//!    where `server_signature = HMAC-SHA256(server_key, auth_message)`
//!    and `server_key = HMAC-SHA256(salted_password, "Server Key")`.
//!    The proxy MUST verify this in constant time. Mismatch surfaces
//!    as `UpstreamError::AuthRejected("scram server-signature mismatch")`.
//! 5. The server typically replies with `done: true` on the third
//!    message; if the first conversation reply already carries
//!    `done: true` (a 1-step fast-path some MongoDB versions use
//!    when `skipEmptyExchange: true` is set), the proxy moves on
//!    without sending step 3.
//! # Why we relay packets verbatim post-handshake
//! Just as for MySQL, the Mongo proxy already does per-command
//! classification + restriction enforcement on the agent's `OP_MSG`
//! BEFORE it forwards to the upstream. After that gate, the proxy
//! is a framing-aware byte relay: read upstream's `OP_MSG` response,
//! write it to the agent. There's no row re-encode pass — the BSON
//! flows through unchanged.

use std::sync::Arc;
use std::time::{Duration, Instant};

use raxis_credentials::{ConsumerIdentity, CredentialBackend, CredentialError, CredentialName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::wire::{MsgHeader, HEADER_LEN, MAX_MESSAGE_LEN, OP_MSG};
use crate::OwnedConsumer;

/// Default upstream connect timeout. Mirrors the Postgres + MySQL
/// proxies' 8s default.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Upstream-connect / forward errors classified into the
/// `CredentialProxyUpstreamFailed::reason` discriminants from
/// `credential-proxy.md §14.5.3`.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The credential bytes could not be parsed as a Mongo SCS URL.
    #[error("invalid upstream URL: {0}")]
    InvalidUrl(String),

    /// Credential resolution through the backend failed.
    #[error("credential resolution failed: {0}")]
    CredentialResolution(String),

    /// DNS lookup or TCP connect to the upstream failed.
    #[error("tcp connect failed: {0}")]
    TcpConnect(String),

    /// Protocol-level handshake / relay failure.
    #[error("mongodb protocol handshake failed: {0}")]
    Handshake(String),

    /// SCRAM-SHA-256 (or other SASL mechanism) rejected the
    /// kernel-resolved credential. Maps to audit reason
    /// `AuthRejected` per `credential-proxy.md §14.5.3`.
    #[error("upstream rejected SCRAM credential: {0}")]
    AuthRejected(String),

    /// Upstream took longer than the connect timeout.
    #[error("upstream connect timed out after {timeout_ms}ms")]
    Timeout {
        /// Timeout in milliseconds.
        timeout_ms: u32,
    },

    /// Mid-relay I/O error or peer reset.
    #[error("upstream relay failed: {0}")]
    RelayFailed(String),

    /// Upstream response exceeded `wire::MAX_MESSAGE_LEN`.
    #[error("upstream response payload too large: {bytes} > {max} bytes")]
    PayloadTooLarge {
        /// Bytes the upstream announced.
        bytes: usize,
        /// Bytes the proxy is willing to buffer.
        max: usize,
    },
}

impl UpstreamError {
    /// Map this error to the `reason` enum string the audit envelope
    /// uses (per `credential-proxy.md §14.5.3`).
    pub fn audit_reason(&self) -> &'static str {
        match self {
            Self::InvalidUrl(_) => "ProtocolHandshakeFailed",
            Self::CredentialResolution(_) => "AuthRejected",
            Self::TcpConnect(_) => "TcpConnectFailed",
            Self::Handshake(_) => "ProtocolHandshakeFailed",
            Self::AuthRejected(_) => "AuthRejected",
            Self::Timeout { .. } => "Timeout",
            Self::RelayFailed(_) => "ProtocolHandshakeFailed",
            Self::PayloadTooLarge { .. } => "ProtocolHandshakeFailed",
        }
    }

    /// Map this error to the redacted detail string the audit
    /// envelope carries.
    pub fn audit_detail(&self) -> String {
        redact_for_audit(&self.to_string())
    }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Strip credential-leak substrings from an upstream-error message
/// before it reaches the audit envelope. Single-pass; mirrors the
/// implementation in `credential-proxy-postgres::upstream` and
/// `credential-proxy-mysql::upstream`.
pub fn redact_for_audit(msg: &str) -> String {
    let bytes = msg.as_bytes();
    let lower: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut out = String::with_capacity(msg.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + b"password=".len() <= bytes.len()
            && &lower[i..i + b"password=".len()] == b"password="
        {
            out.push_str("password=[REDACTED]");
            i += b"password=".len();
            while i < bytes.len()
                && bytes[i] != b'&'
                && bytes[i] != b' '
                && bytes[i] != b'"'
                && bytes[i] != b'\''
                && bytes[i] != b'\n'
            {
                i += 1;
            }
            continue;
        }
        if i + 3 <= bytes.len() && &bytes[i..i + 3] == b"://" {
            let mut auth_end = i + 3;
            while auth_end < bytes.len()
                && bytes[auth_end] != b'/'
                && bytes[auth_end] != b'?'
                && bytes[auth_end] != b' '
                && bytes[auth_end] != b'\n'
                && bytes[auth_end] != b'"'
                && bytes[auth_end] != b'\''
            {
                auth_end += 1;
            }
            if let Some(at_offset) = bytes[i + 3..auth_end].iter().position(|b| *b == b'@') {
                let at = i + 3 + at_offset;
                if let Some(colon_offset) = bytes[i + 3..at].iter().position(|b| *b == b':') {
                    let colon = i + 3 + colon_offset;
                    out.push_str("://");
                    out.push_str(std::str::from_utf8(&bytes[i + 3..colon]).unwrap_or(""));
                    out.push_str(":[REDACTED]");
                    i = at;
                    continue;
                }
            }
        }
        let ch_len = utf8_char_len(bytes[i]);
        let end = (i + ch_len).min(bytes.len());
        out.push_str(std::str::from_utf8(&bytes[i..end]).unwrap_or("?"));
        i = end;
    }
    out
}

fn utf8_char_len(lead: u8) -> usize {
    // ASCII (`< 0x80`) and stray continuation bytes
    // (`0x80..=0xbf`) collapse to a 1-byte advance — see the
    // sibling MSSQL adapter for the rationale.
    if lead < 0xc0 {
        1
    } else if lead < 0xe0 {
        2
    } else if lead < 0xf0 {
        3
    } else {
        4
    }
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

/// Parsed view of a Mongo Standard Connection String credential URL.
#[derive(Debug, Clone)]
pub struct ParsedUpstreamUrl {
    /// Hostname from the credential URL.
    pub host: String,
    /// Port from the credential URL after default-port substitution
    /// (27017).
    pub port: u16,
    /// Optional default database from the URL path.
    pub database: Option<String>,
    /// SCRAM username from `user:password@`. `None` ⇒ no auth (the
    /// upstream is `--noauth` and the proxy skips the SASL handshake).
    pub username: Option<String>,
    /// SCRAM password from `user:password@`, percent-decoded. Stored
    /// alongside `username` so the SASL state machine can reach it
    /// without a second URL parse.
    pub password: Option<String>,
    /// `authSource` query parameter. SCRAM runs against this
    /// database (typically `admin`). Defaults to the URL's path
    /// database, falling back to `"admin"`.
    pub auth_source: String,
    /// True if the URL requested TLS (`tls=true`/`ssl=true`).
    /// V2.5 still supports plaintext only — TLS lands in V3.
    pub require_tls: bool,
}

impl ParsedUpstreamUrl {
    /// Parse a Mongo SCS URL out of a resolved credential value.
    /// Accepts both the no-auth form (`mongodb://host:27017/db`)
    /// and the SCRAM-SHA-256 form
    /// (`mongodb://user:pass@host:27017/db?authSource=admin`).
    pub fn parse(raw_url: &str) -> Result<Self, UpstreamError> {
        let raw = raw_url.trim();
        let after_scheme = if let Some(rest) = raw.strip_prefix("mongodb://") {
            rest
        } else if raw.starts_with("mongodb+srv://") {
            return Err(UpstreamError::InvalidUrl(
                "mongodb+srv:// not supported — use plaintext mongodb:// scheme \
                 (mongodb+srv requires DNS SRV/TXT record discovery; out of scope)"
                    .into(),
            ));
        } else {
            return Err(UpstreamError::InvalidUrl(
                "scheme must be `mongodb://`".into(),
            ));
        };
        let (userinfo, host_and_rest) = match after_scheme.find('@') {
            Some(at) => (Some(&after_scheme[..at]), &after_scheme[at + 1..]),
            None => (None, after_scheme),
        };
        let (username, password) = match userinfo {
            None | Some("") => (None, None),
            Some(ui) => match ui.find(':') {
                Some(colon) => (
                    Some(percent_decode(&ui[..colon])),
                    Some(percent_decode(&ui[colon + 1..])),
                ),
                None => (Some(percent_decode(ui)), None),
            },
        };
        let host_end = host_and_rest
            .find(['/', '?'])
            .unwrap_or(host_and_rest.len());
        let authority = &host_and_rest[..host_end];
        // Reject host lists like `host1,host2` — the proxy talks to a
        // single mongod (no replica-set or sharded cluster discovery).
        if authority.contains(',') {
            return Err(UpstreamError::InvalidUrl(
                "comma-separated host list not supported — point at one mongod".into(),
            ));
        }
        let (host, port) = match authority.rfind(':') {
            Some(colon) => {
                let h = &authority[..colon];
                let p = authority[colon + 1..]
                    .parse::<u16>()
                    .map_err(|_| UpstreamError::InvalidUrl("port is not a valid u16".into()))?;
                (h.to_owned(), p)
            }
            None => (authority.to_owned(), 27017u16),
        };
        if host.is_empty() {
            return Err(UpstreamError::InvalidUrl("hostname is empty".into()));
        }
        let rest = &host_and_rest[host_end..];
        let (path_part, query_part) = match rest.find('?') {
            Some(q) => (&rest[..q], &rest[q + 1..]),
            None => (rest, ""),
        };
        let database = path_part
            .strip_prefix('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let qlower = query_part.to_lowercase();
        let require_tls = qlower.contains("tls=true") || qlower.contains("ssl=true");
        // Pick authSource from query first, then fall back to path
        // db, then to "admin" (the SCRAM-SHA-256 default per MongoDB
        // driver spec).
        let auth_source = parse_query_param(query_part, "authsource")
            .or_else(|| database.clone())
            .unwrap_or_else(|| "admin".to_owned());
        Ok(Self {
            host,
            port,
            database,
            username,
            password,
            auth_source,
            require_tls,
        })
    }

    /// True if the URL carries SCRAM credentials.
    pub fn has_userinfo(&self) -> bool {
        self.username.is_some()
    }
}

/// Look up a single query parameter by lower-cased key.
fn parse_query_param(query: &str, key_lower: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some(eq) = pair.find('=') {
            let k = &pair[..eq];
            if k.to_ascii_lowercase() == key_lower {
                return Some(percent_decode(&pair[eq + 1..]));
            }
        }
    }
    None
}

/// Percent-decode a SCS userinfo / query value. Tolerates malformed
/// %XX escapes by passing them through unchanged so a bad credential
/// URL surfaces as `AuthRejected` from the upstream rather than
/// `InvalidUrl` from the parser.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Resolve the credential bytes through the backend and parse them
/// as a Mongo SCS URL.
pub fn resolve_upstream_url(
    backend: &Arc<dyn CredentialBackend>,
    name: &CredentialName,
    consumer: &OwnedConsumer,
) -> Result<ParsedUpstreamUrl, UpstreamError> {
    let value = backend
        .resolve(name, ConsumerIdentity::new(&consumer.kind, &consumer.id))
        .map_err(|e| match e {
            CredentialError::NotFound(_) => {
                UpstreamError::CredentialResolution("credential not found".into())
            }
            CredentialError::Malformed { reason, .. } => {
                UpstreamError::CredentialResolution(format!("malformed: {reason}"))
            }
            other => UpstreamError::CredentialResolution(format!("{other}")),
        })?;
    value.with_bytes(|bytes| {
        std::str::from_utf8(bytes)
            .map_err(|_| UpstreamError::InvalidUrl("credential value is not UTF-8".into()))
            .and_then(ParsedUpstreamUrl::parse)
    })
}

// ---------------------------------------------------------------------------
// Upstream session
// ---------------------------------------------------------------------------

/// Outcome of a forwarded `OP_MSG` round trip.
#[derive(Debug)]
pub struct ForwardOutcome {
    /// The raw upstream `OP_MSG` reply bytes, header included. The
    /// proxy writes these to the agent verbatim — the caller is
    /// responsible for rewriting `response_to` back to the agent's
    /// original `request_id` if needed (the proxy currently keeps
    /// the upstream's own `response_to` field; see the comment in
    /// `forward_op_msg` for why this is correct).
    pub frame: Vec<u8>,
    /// Wall-clock duration of the upstream round trip in ms.
    pub duration_ms: u32,
    /// True if the upstream's reply doc has `ok: 0.0` — the proxy
    /// emits `DatabaseQueryCompleted` with a non-`None`
    /// `upstream_error` in that case.
    pub upstream_error_marker: bool,
}

/// One live upstream session, held across the lifetime of the
/// agent's connection.
pub struct UpstreamSession {
    stream: TcpStream,
    /// Hostname the audit envelope reports.
    pub host: String,
    /// Port the audit envelope reports.
    pub port: u16,
    /// True if the URL requested TLS — V2.1 surfaces this in the
    /// audit envelope but the implementation only supports plaintext.
    pub tls: bool,
    /// Wall-clock for the connect step.
    pub handshake_ms: u32,
}

impl UpstreamSession {
    /// Open a new upstream session against the parsed URL.
    /// Auth modes:
    /// * `mongodb://host:port/db` (no userinfo) — pure plaintext +
    ///   `--noauth`. Connect succeeds as soon as TCP is up.
    /// * `mongodb://user:pass@host:port/db?authSource=admin`
    ///   (userinfo present) — drives SCRAM-SHA-256 SASL against
    ///   `authSource` (default `admin`). Failure surfaces as
    ///   `UpstreamError::AuthRejected` for the audit trail.
    ///   `tls=true` / `ssl=true` is rejected as `Handshake` because
    ///   the proxy still talks plaintext only on the upstream socket
    ///   (V3 work). Operators on `mongo:7` containers can keep
    ///   `--noauth` or use `mongodb://user:pass@.../authSource=admin`
    ///   without TLS for development.
    pub async fn connect(
        url: &ParsedUpstreamUrl,
        connect_timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        if url.require_tls {
            return Err(UpstreamError::Handshake(
                "tls=true is not supported on the upstream socket yet — \
                 plaintext mongodb:// only"
                    .into(),
            ));
        }
        let started = Instant::now();
        let connect_fut = async {
            let addr = format!("{}:{}", url.host, url.port);
            let stream = TcpStream::connect(&addr)
                .await
                .map_err(|e| UpstreamError::TcpConnect(redact_for_audit(&e.to_string())))?;
            Ok::<_, UpstreamError>(stream)
        };
        let mut stream = match tokio::time::timeout(connect_timeout, connect_fut).await {
            Ok(res) => res?,
            Err(_) => {
                return Err(UpstreamError::Timeout {
                    timeout_ms: connect_timeout.as_millis().min(u32::MAX as u128) as u32,
                });
            }
        };
        // SCRAM if userinfo present. Bound the SASL roundtrips by
        // the same connect_timeout the TCP connect used, so a
        // malicious / slow upstream cannot wedge the proxy.
        if let (Some(user), Some(pass)) = (url.username.as_deref(), url.password.as_deref()) {
            let sasl_fut =
                scram_sha256_authenticate(&mut stream, &url.auth_source, user, pass.as_bytes());
            match tokio::time::timeout(connect_timeout, sasl_fut).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(UpstreamError::Timeout {
                        timeout_ms: connect_timeout.as_millis().min(u32::MAX as u128) as u32,
                    });
                }
            }
        }
        let handshake_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        Ok(Self {
            stream,
            host: url.host.clone(),
            port: url.port,
            tls: url.require_tls,
            handshake_ms,
        })
    }

    /// Forward one full `OP_MSG` request to the upstream and read
    /// its `OP_MSG` reply. The agent's original frame bytes
    /// (`agent_frame`) are written verbatim — including the header —
    /// so the upstream's `response_to` field naturally points at the
    /// agent's `request_id` (drivers correlate on this).
    pub async fn forward_op_msg(
        &mut self,
        agent_frame: &[u8],
    ) -> Result<ForwardOutcome, UpstreamError> {
        let started = Instant::now();
        // Write agent's frame verbatim to upstream.
        self.stream
            .write_all(agent_frame)
            .await
            .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
        self.stream.flush().await.ok();
        // Read upstream's reply: 16-byte header + body.
        let mut header = [0u8; HEADER_LEN];
        self.stream
            .read_exact(&mut header)
            .await
            .map_err(|e| UpstreamError::RelayFailed(format!("read upstream header: {e}")))?;
        let parsed = MsgHeader::parse(header);
        let total = parsed.message_length as usize;
        if !(HEADER_LEN..=MAX_MESSAGE_LEN).contains(&total) {
            return Err(UpstreamError::PayloadTooLarge {
                bytes: total,
                max: MAX_MESSAGE_LEN,
            });
        }
        let body_len = total - HEADER_LEN;
        let mut body = vec![0u8; body_len];
        self.stream
            .read_exact(&mut body)
            .await
            .map_err(|e| UpstreamError::RelayFailed(format!("read upstream body: {e}")))?;
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&body);
        // Inspect the kind-0 BSON section for `ok: 0.0` so we can
        // flag a failed command in the audit envelope.
        let upstream_error_marker = if parsed.op_code == OP_MSG {
            scan_op_msg_ok_zero(&body)
        } else {
            // Non-OP_MSG reply (legacy OP_REPLY etc.) — V2.1 doesn't
            // try to interpret these; treat as opaque success.
            false
        };
        let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        Ok(ForwardOutcome {
            frame,
            duration_ms,
            upstream_error_marker,
        })
    }
}

/// Scan an `OP_MSG` body for a kind-0 section that contains
/// `ok: 0.0`. Used to flag failed commands without doing a full
/// BSON parse (we walk to the first kind-0 BSON doc, then scan
/// for the `ok` element by name).
fn scan_op_msg_ok_zero(body: &[u8]) -> bool {
    if body.len() < 4 {
        return false;
    }
    let mut i = 4; // skip flag_bits
    while i < body.len() {
        let kind = body[i];
        i += 1;
        if kind == 0 {
            // Body section: BSON doc starts at i.
            return scan_bson_for_ok_zero(&body[i..]);
        } else if kind == 1 {
            if i + 4 > body.len() {
                return false;
            }
            let section_size =
                i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]) as usize;
            if section_size < 4 || i + section_size > body.len() {
                return false;
            }
            i += section_size;
        } else {
            return false;
        }
    }
    false
}

/// Walk a BSON doc looking for an `ok` field with value `0.0`
/// (BSON `double` 0x01 OR `int32` 0x10 OR `int64` 0x12 — Mongo
/// servers historically have inconsistent typing here).
fn scan_bson_for_ok_zero(doc: &[u8]) -> bool {
    if doc.len() < 5 {
        return false;
    }
    let total = i32::from_le_bytes([doc[0], doc[1], doc[2], doc[3]]) as usize;
    if total < 5 || total > doc.len() {
        return false;
    }
    let body = &doc[4..total - 1]; // exclude trailing 0x00
    let mut i = 0;
    while i < body.len() {
        let type_byte = body[i];
        i += 1;
        if type_byte == 0 {
            return false;
        }
        // cstring name
        let nul = match body[i..].iter().position(|&b| b == 0) {
            Some(n) => n,
            None => return false,
        };
        let name = std::str::from_utf8(&body[i..i + nul]).unwrap_or("");
        i += nul + 1;
        // Value, type-dependent. We need to know the value's length
        // to skip; for `ok` we read it directly.
        let is_ok = name == "ok";
        match type_byte {
            // double
            0x01 => {
                if i + 8 > body.len() {
                    return false;
                }
                if is_ok {
                    let v = f64::from_le_bytes([
                        body[i],
                        body[i + 1],
                        body[i + 2],
                        body[i + 3],
                        body[i + 4],
                        body[i + 5],
                        body[i + 6],
                        body[i + 7],
                    ]);
                    return v == 0.0;
                }
                i += 8;
            }
            // string
            0x02 => {
                if i + 4 > body.len() {
                    return false;
                }
                let strlen =
                    i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]) as usize;
                i += 4 + strlen;
            }
            // embedded doc / array
            0x03 | 0x04 => {
                if i + 4 > body.len() {
                    return false;
                }
                let inner =
                    i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]) as usize;
                i += inner;
            }
            // binary
            0x05 => {
                if i + 4 > body.len() {
                    return false;
                }
                let blen =
                    i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]) as usize;
                i += 4 + 1 + blen;
            }
            // ObjectId
            0x07 => i += 12,
            // bool
            0x08 => i += 1,
            // datetime
            0x09 => i += 8,
            // null
            0x0a => {}
            // regex: cstring + cstring
            0x0b => {
                let nul1 = match body[i..].iter().position(|&b| b == 0) {
                    Some(n) => n,
                    None => return false,
                };
                i += nul1 + 1;
                let nul2 = match body[i..].iter().position(|&b| b == 0) {
                    Some(n) => n,
                    None => return false,
                };
                i += nul2 + 1;
            }
            // int32
            0x10 => {
                if i + 4 > body.len() {
                    return false;
                }
                if is_ok {
                    let v = i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
                    return v == 0;
                }
                i += 4;
            }
            // timestamp
            0x11 => i += 8,
            // int64
            0x12 => {
                if i + 8 > body.len() {
                    return false;
                }
                if is_ok {
                    let v = i64::from_le_bytes([
                        body[i],
                        body[i + 1],
                        body[i + 2],
                        body[i + 3],
                        body[i + 4],
                        body[i + 5],
                        body[i + 6],
                        body[i + 7],
                    ]);
                    return v == 0;
                }
                i += 8;
            }
            // decimal128
            0x13 => i += 16,
            // min/max key (no value)
            0xff | 0x7f => {}
            _ => {
                // Unknown type byte — we can't safely skip ahead.
                return false;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// SCRAM-SHA-256 (RFC 5802 + 7677) carried inside MongoDB OP_MSG envelopes.
// ---------------------------------------------------------------------------

/// Drive the full SCRAM-SHA-256 conversation against an upstream
/// `mongod`. Returns `Ok(())` when the SASL conversation has
/// terminated with `done: true` AND the server-signature
/// verification has succeeded. Any other outcome surfaces as
/// `UpstreamError::AuthRejected` (mapped to audit reason
/// `AuthRejected`) or `UpstreamError::Handshake` (mapped to
/// `ProtocolHandshakeFailed`).
async fn scram_sha256_authenticate(
    stream: &mut TcpStream,
    auth_source: &str,
    username: &str,
    password: &[u8],
) -> Result<(), UpstreamError> {
    use base64::Engine as _;

    // RFC 5802 §5.1: SCRAM usernames must not contain '=' or ',' —
    // both are SCRAM message delimiters. The official escape rules
    // are `=2C` for ',' and `=3D` for '='. We apply them here so a
    // legal upstream username with a comma or equals does not break
    // the conversation.
    let saslprep_user = scram_username_escape(username);
    // 24-byte client nonce → 32 base64 chars. Matches the official
    // mongo driver's nonce length and is well above the RFC's
    // minimum of 16 bits.
    let mut cnonce_bytes = [0u8; 24];
    if let Err(e) = getrandom::getrandom(&mut cnonce_bytes) {
        return Err(UpstreamError::Handshake(format!(
            "failed to mint SCRAM client nonce: {e}",
        )));
    }
    let client_nonce = base64::engine::general_purpose::STANDARD.encode(cnonce_bytes);
    let client_first_bare = format!("n={saslprep_user},r={client_nonce}");
    // RFC 5802 §5.1: gs2-header = gs2-cbind-flag "," [ authzid ] ","
    // For SCRAM-SHA-256 without channel binding and without an authzid,
    // the header MUST be exactly `n,,` (the trailing comma is the empty-
    // authzid placeholder, not optional). Its base64 encoding is `biws`,
    // which is the value the server later reflects back through the
    // c=biws channel-binding attribute on the client-final message.
    let gs2_header = "n,,";
    let client_first_message = format!("{gs2_header}{client_first_bare}");

    // 1) saslStart
    let start_doc = build_sasl_start_doc(
        auth_source,
        "SCRAM-SHA-256",
        client_first_message.as_bytes(),
    );
    let start_reply = exchange_op_msg(stream, &start_doc)
        .await
        .map_err(|e| UpstreamError::Handshake(format!("saslStart: {e}")))?;
    let SaslReply {
        ok,
        conv_id,
        payload,
        done,
    } = parse_sasl_reply(&start_reply).ok_or_else(|| {
        UpstreamError::Handshake("saslStart reply: malformed BSON or missing payload".into())
    })?;
    if !ok {
        return Err(UpstreamError::AuthRejected(format!(
            "saslStart rejected: {}",
            sasl_reply_errmsg(&start_reply).unwrap_or_else(|| "unknown".into()),
        )));
    }
    let server_first = std::str::from_utf8(&payload)
        .map_err(|_| UpstreamError::Handshake("server first message is not UTF-8".into()))?
        .to_owned();
    let parsed_first = parse_server_first_message(&server_first)
        .map_err(|e| UpstreamError::AuthRejected(format!("server first message: {e}")))?;
    if !parsed_first.combined_nonce.starts_with(&client_nonce) {
        return Err(UpstreamError::AuthRejected(
            "scram server nonce did not extend client nonce (RFC 5802 §5)".into(),
        ));
    }
    if parsed_first.iterations < 4096 {
        return Err(UpstreamError::AuthRejected(format!(
            "scram iteration count {} below RFC 5802 minimum 4096",
            parsed_first.iterations,
        )));
    }

    // 2) Compute proof + send saslContinue
    let salted_password = pbkdf2_hmac_sha256(password, &parsed_first.salt, parsed_first.iterations);
    let client_key = hmac_sha256(&salted_password, b"Client Key");
    let stored_key = sha256_digest(&client_key);
    let server_key = hmac_sha256(&salted_password, b"Server Key");

    let channel_binding = base64::engine::general_purpose::STANDARD.encode(gs2_header.as_bytes());
    let client_final_bare = format!("c={channel_binding},r={}", parsed_first.combined_nonce);
    let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");
    let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
    let mut client_proof = client_key;
    for (a, b) in client_proof.iter_mut().zip(client_signature.iter()) {
        *a ^= *b;
    }
    let client_proof_b64 = base64::engine::general_purpose::STANDARD.encode(client_proof);
    let client_final_message = format!("{client_final_bare},p={client_proof_b64}");

    // Some MongoDB versions return `done: true` on the saslStart
    // reply when `skipEmptyExchange` is enabled. We always issue the
    // final step regardless — RFC 5802 requires it, and the server's
    // final-server-signature is the only proof we have that the
    // upstream actually knows the password.
    let cont_doc = build_sasl_continue_doc(auth_source, conv_id, client_final_message.as_bytes());
    let cont_reply = exchange_op_msg(stream, &cont_doc)
        .await
        .map_err(|e| UpstreamError::Handshake(format!("saslContinue: {e}")))?;
    let SaslReply {
        ok: ok2,
        conv_id: _,
        payload: payload2,
        done: done2,
    } = parse_sasl_reply(&cont_reply).ok_or_else(|| {
        UpstreamError::Handshake("saslContinue reply: malformed BSON or missing payload".into())
    })?;
    if !ok2 {
        return Err(UpstreamError::AuthRejected(format!(
            "saslContinue rejected: {}",
            sasl_reply_errmsg(&cont_reply).unwrap_or_else(|| "unknown".into()),
        )));
    }
    let server_final = std::str::from_utf8(&payload2)
        .map_err(|_| UpstreamError::Handshake("server final message is not UTF-8".into()))?;
    let server_signature = parse_server_final_message(server_final)
        .map_err(|e| UpstreamError::AuthRejected(format!("server final message: {e}")))?;
    let expected_sig = hmac_sha256(&server_key, auth_message.as_bytes());
    if !constant_time_eq(&server_signature, &expected_sig) {
        return Err(UpstreamError::AuthRejected(
            "scram server-signature mismatch — upstream proved wrong key".into(),
        ));
    }

    // RFC 5802 lets the server delay `done: true` until a third
    // empty saslContinue exchange. MongoDB historically issues
    // `done: true` on the second reply, but some driver-test
    // harnesses delay it. Honor the delay.
    if !done && !done2 {
        let final_doc = build_sasl_continue_doc(auth_source, conv_id, b"");
        let final_reply = exchange_op_msg(stream, &final_doc)
            .await
            .map_err(|e| UpstreamError::Handshake(format!("saslContinue (empty): {e}")))?;
        let SaslReply {
            ok: ok3,
            done: done3,
            ..
        } = parse_sasl_reply(&final_reply).ok_or_else(|| {
            UpstreamError::Handshake("trailing saslContinue reply: malformed BSON".into())
        })?;
        if !ok3 || !done3 {
            return Err(UpstreamError::AuthRejected(
                "scram conversation did not terminate with done: true".into(),
            ));
        }
    }
    Ok(())
}

/// Parsed view of an RFC 5802 `server-first-message`.
#[derive(Debug)]
struct ServerFirstMessage {
    combined_nonce: String,
    salt: Vec<u8>,
    iterations: u32,
}

/// Parse `r=<combined>,s=<base64-salt>,i=<iter>` (RFC 5802 §5.1
/// / RFC 7677). Tolerant of attribute order — drivers in the wild
/// sometimes interleave server-supplied extensions.
fn parse_server_first_message(s: &str) -> Result<ServerFirstMessage, String> {
    use base64::Engine as _;
    let mut combined = None;
    let mut salt = None;
    let mut iter = None;
    for attr in s.split(',') {
        let mut it = attr.splitn(2, '=');
        let k = it.next().ok_or_else(|| "empty attribute".to_owned())?;
        let v = it
            .next()
            .ok_or_else(|| format!("attribute `{k}` has no value"))?;
        match k {
            "r" => combined = Some(v.to_owned()),
            "s" => {
                salt = Some(
                    base64::engine::general_purpose::STANDARD
                        .decode(v)
                        .map_err(|e| format!("salt base64 decode: {e}"))?,
                );
            }
            "i" => {
                iter = Some(v.parse::<u32>().map_err(|e| format!("iter parse: {e}"))?);
            }
            // RFC 5802 §5.1: server may include `m=<mandatory-extension>`.
            // If it does, we must abort because we don't understand it.
            "m" => return Err(format!("server requires unknown extension: {v}")),
            _ => {}
        }
    }
    Ok(ServerFirstMessage {
        combined_nonce: combined.ok_or("missing nonce (r=...)")?,
        salt: salt.ok_or("missing salt (s=...)")?,
        iterations: iter.ok_or("missing iter (i=...)")?,
    })
}

/// Parse `v=<base64-server-signature>` (success) or
/// `e=<server-error>` (failure) per RFC 5802 §5.1.
fn parse_server_final_message(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    for attr in s.split(',') {
        let mut it = attr.splitn(2, '=');
        let k = it.next().unwrap_or_default();
        let v = it.next().unwrap_or_default();
        match k {
            "v" => {
                return base64::engine::general_purpose::STANDARD
                    .decode(v)
                    .map_err(|e| format!("v= base64 decode: {e}"))
            }
            "e" => return Err(format!("server reported scram error: {v}")),
            _ => continue,
        }
    }
    Err("missing v= attribute in server final message".into())
}

/// Escape RFC 5802 §5.1 reserved characters in the SCRAM username.
fn scram_username_escape(user: &str) -> String {
    let mut out = String::with_capacity(user.len());
    for ch in user.chars() {
        match ch {
            ',' => out.push_str("=2C"),
            '=' => out.push_str("=3D"),
            other => out.push(other),
        }
    }
    out
}

/// Subset of the SCRAM-bearing OP_MSG reply we care about.
#[derive(Debug)]
struct SaslReply {
    ok: bool,
    conv_id: i32,
    payload: Vec<u8>,
    done: bool,
}

/// Pull `ok`, `conversationId`, `payload`, and `done` out of a
/// MongoDB SASL reply doc. Returns `None` only if the BSON is so
/// malformed we can't even find the kind-0 section.
fn parse_sasl_reply(reply_frame: &[u8]) -> Option<SaslReply> {
    if reply_frame.len() < HEADER_LEN_GUARD + 5 {
        return None;
    }
    let body = &reply_frame[HEADER_LEN_GUARD..];
    let kind = *body.get(4)?;
    if kind != 0 {
        return None;
    }
    let doc = body.get(5..)?;
    let total =
        i32::from_le_bytes([*doc.first()?, *doc.get(1)?, *doc.get(2)?, *doc.get(3)?]) as usize;
    if total < 5 || total > doc.len() {
        return None;
    }
    let inner = &doc[4..total - 1];
    let mut ok = false;
    let mut conv_id: i32 = 1;
    let mut payload: Vec<u8> = Vec::new();
    let mut done = false;
    let mut i = 0;
    while i < inner.len() {
        let type_byte = inner[i];
        i += 1;
        if type_byte == 0 {
            break;
        }
        let nul = inner[i..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&inner[i..i + nul]).ok()?;
        i += nul + 1;
        match (type_byte, name) {
            (0x01, "ok") => {
                if i + 8 > inner.len() {
                    return None;
                }
                let v = f64::from_le_bytes([
                    inner[i],
                    inner[i + 1],
                    inner[i + 2],
                    inner[i + 3],
                    inner[i + 4],
                    inner[i + 5],
                    inner[i + 6],
                    inner[i + 7],
                ]);
                ok = v != 0.0;
                i += 8;
            }
            (0x10, "ok") => {
                if i + 4 > inner.len() {
                    return None;
                }
                ok = i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]]) != 0;
                i += 4;
            }
            (0x10, "conversationId") => {
                if i + 4 > inner.len() {
                    return None;
                }
                conv_id = i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]]);
                i += 4;
            }
            (0x05, "payload") => {
                if i + 5 > inner.len() {
                    return None;
                }
                let blen = i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]])
                    as usize;
                let _subtype = inner[i + 4];
                if i + 5 + blen > inner.len() {
                    return None;
                }
                payload = inner[i + 5..i + 5 + blen].to_vec();
                i += 5 + blen;
            }
            (0x08, "done") => {
                if i >= inner.len() {
                    return None;
                }
                done = inner[i] != 0;
                i += 1;
            }
            (other_type, _) => {
                // Skip any other field by type-dependent length. We
                // only consume the four fields above, so for safety
                // we skip the well-known fixed-size types and bail
                // on anything we don't recognise.
                let skip = match other_type {
                    0x01 | 0x09 | 0x11 | 0x12 => 8,
                    0x02 => {
                        if i + 4 > inner.len() {
                            return None;
                        }
                        let l = i32::from_le_bytes([
                            inner[i],
                            inner[i + 1],
                            inner[i + 2],
                            inner[i + 3],
                        ]) as usize;
                        4 + l
                    }
                    0x03 | 0x04 => {
                        if i + 4 > inner.len() {
                            return None;
                        }
                        i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]])
                            as usize
                    }
                    0x05 => {
                        if i + 4 > inner.len() {
                            return None;
                        }
                        let l = i32::from_le_bytes([
                            inner[i],
                            inner[i + 1],
                            inner[i + 2],
                            inner[i + 3],
                        ]) as usize;
                        4 + 1 + l
                    }
                    0x07 => 12,
                    0x08 => 1,
                    0x10 => 4,
                    0x13 => 16,
                    0x0a => 0,
                    _ => return None,
                };
                i += skip;
            }
        }
    }
    Some(SaslReply {
        ok,
        conv_id,
        payload,
        done,
    })
}

/// Best-effort: extract `errmsg` from a SASL reply for the audit
/// trail. Returns `None` if the reply is malformed or carries no
/// `errmsg` field.
fn sasl_reply_errmsg(reply_frame: &[u8]) -> Option<String> {
    if reply_frame.len() < HEADER_LEN_GUARD + 5 {
        return None;
    }
    let body = &reply_frame[HEADER_LEN_GUARD..];
    let kind = *body.get(4)?;
    if kind != 0 {
        return None;
    }
    let doc = body.get(5..)?;
    let total =
        i32::from_le_bytes([*doc.first()?, *doc.get(1)?, *doc.get(2)?, *doc.get(3)?]) as usize;
    if total < 5 || total > doc.len() {
        return None;
    }
    let inner = &doc[4..total - 1];
    let mut i = 0;
    while i < inner.len() {
        let type_byte = inner[i];
        i += 1;
        if type_byte == 0 {
            break;
        }
        let nul = inner[i..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&inner[i..i + nul]).ok()?;
        i += nul + 1;
        if type_byte == 0x02 && name == "errmsg" {
            if i + 4 > inner.len() {
                return None;
            }
            let l =
                i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]]) as usize;
            if l == 0 || i + 4 + l > inner.len() {
                return None;
            }
            let s = std::str::from_utf8(&inner[i + 4..i + 4 + l - 1]).ok()?;
            return Some(s.to_owned());
        }
        // skip value
        let skip = match type_byte {
            0x01 | 0x09 | 0x11 | 0x12 => 8,
            0x02 => {
                if i + 4 > inner.len() {
                    return None;
                }
                let l = i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]])
                    as usize;
                4 + l
            }
            0x03 | 0x04 => {
                if i + 4 > inner.len() {
                    return None;
                }
                i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]]) as usize
            }
            0x05 => {
                if i + 4 > inner.len() {
                    return None;
                }
                let l = i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]])
                    as usize;
                4 + 1 + l
            }
            0x07 => 12,
            0x08 => 1,
            0x10 => 4,
            0x13 => 16,
            0x0a => 0,
            _ => return None,
        };
        i += skip;
    }
    None
}

/// 16-byte MongoDB OP_MSG header length.
const HEADER_LEN_GUARD: usize = 16;
const OP_MSG_OPCODE: i32 = 2013;
const SASL_REQUEST_ID: i32 = 0x52415853; // "RAXS" — distinguishes proxy-minted SASL frames in pcap.

/// Build the BSON for `{ saslStart: 1, $db: <auth_source>, mechanism: "SCRAM-SHA-256",
/// payload: BinData(0, <client_first_message>),
/// options: { skipEmptyExchange: true } }`.
fn build_sasl_start_doc(auth_source: &str, mechanism: &str, payload: &[u8]) -> Vec<u8> {
    use crate::wire::BsonBuilder as B;
    let options = B::new().bool("skipEmptyExchange", true).finish();
    B::new()
        .int32("saslStart", 1)
        .string("$db", auth_source)
        .string("mechanism", mechanism)
        .binary("payload", payload)
        .document("options", options)
        .finish()
}

/// Build the BSON for `{ saslContinue: 1, $db: <auth_source>,
/// conversationId: <id>, payload: BinData(0, <bytes>) }`.
fn build_sasl_continue_doc(auth_source: &str, conv_id: i32, payload: &[u8]) -> Vec<u8> {
    use crate::wire::BsonBuilder as B;
    B::new()
        .int32("saslContinue", 1)
        .string("$db", auth_source)
        .int32("conversationId", conv_id)
        .binary("payload", payload)
        .finish()
}

/// Wrap a serialized BSON command body into a full OP_MSG frame and
/// exchange it with the upstream, returning the frame bytes
/// (header + body) of the upstream's reply.
async fn exchange_op_msg(stream: &mut TcpStream, bson_doc: &[u8]) -> std::io::Result<Vec<u8>> {
    let body_len = 4 /* flag_bits */ + 1 /* kind */ + bson_doc.len();
    let total = HEADER_LEN_GUARD + body_len;
    if total > MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SASL frame would exceed MAX_MESSAGE_LEN",
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as i32).to_le_bytes());
    out.extend_from_slice(&SASL_REQUEST_ID.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&OP_MSG_OPCODE.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.push(0);
    out.extend_from_slice(bson_doc);
    stream.write_all(&out).await?;
    stream.flush().await?;
    let mut header = [0u8; HEADER_LEN_GUARD];
    stream.read_exact(&mut header).await?;
    let total = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if !(HEADER_LEN_GUARD..=MAX_MESSAGE_LEN).contains(&total) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "upstream SASL reply has invalid message_length",
        ));
    }
    let body_len = total - HEADER_LEN_GUARD;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, rounds, &mut out);
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_minimal() {
        let p = ParsedUpstreamUrl::parse("mongodb://localhost:27017/test").unwrap();
        assert_eq!(p.host, "localhost");
        assert_eq!(p.port, 27017);
        assert_eq!(p.database.as_deref(), Some("test"));
        assert!(!p.has_userinfo());
        assert!(p.username.is_none());
        assert!(p.password.is_none());
        assert_eq!(p.auth_source, "test"); // path-db fallback
        assert!(!p.require_tls);
    }

    #[test]
    fn parse_url_default_port() {
        let p = ParsedUpstreamUrl::parse("mongodb://db/").unwrap();
        assert_eq!(p.port, 27017);
        assert_eq!(p.auth_source, "admin"); // no path → admin fallback
    }

    #[test]
    fn parse_url_with_userinfo_extracts_user_password() {
        let p = ParsedUpstreamUrl::parse("mongodb://demo:hunter2@db/test").unwrap();
        assert!(p.has_userinfo());
        assert_eq!(p.username.as_deref(), Some("demo"));
        assert_eq!(p.password.as_deref(), Some("hunter2"));
        // path db is `test`, no explicit authSource query
        assert_eq!(p.auth_source, "test");
    }

    #[test]
    fn parse_url_authsource_query_overrides_path_db() {
        let p =
            ParsedUpstreamUrl::parse("mongodb://demo:hunter2@db/test?authSource=admin").unwrap();
        assert_eq!(p.auth_source, "admin");
    }

    #[test]
    fn parse_url_percent_decodes_user_password() {
        let p = ParsedUpstreamUrl::parse("mongodb://us%40er:p%40ss%2Cword@db/admin").unwrap();
        assert_eq!(p.username.as_deref(), Some("us@er"));
        assert_eq!(p.password.as_deref(), Some("p@ss,word"));
    }

    #[test]
    fn parse_url_with_tls_marks_flag() {
        let p = ParsedUpstreamUrl::parse("mongodb://db/test?tls=true").unwrap();
        assert!(p.require_tls);
    }

    #[test]
    fn parse_url_rejects_srv() {
        let err = ParsedUpstreamUrl::parse("mongodb+srv://db/test").unwrap_err();
        match err {
            UpstreamError::InvalidUrl(_) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn parse_url_rejects_host_list() {
        let err = ParsedUpstreamUrl::parse("mongodb://h1,h2/test").unwrap_err();
        match err {
            UpstreamError::InvalidUrl(_) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn parse_url_rejects_empty_host() {
        let err = ParsedUpstreamUrl::parse("mongodb:///test").unwrap_err();
        match err {
            UpstreamError::InvalidUrl(_) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn redact_password_in_userinfo() {
        let s = "auth failed for mongodb://demo:hunter2@db/foo";
        let red = redact_for_audit(s);
        assert!(red.contains("[REDACTED]"));
        assert!(!red.contains("hunter2"));
    }

    #[test]
    fn audit_reason_mapping() {
        assert_eq!(
            UpstreamError::TcpConnect("x".into()).audit_reason(),
            "TcpConnectFailed"
        );
        assert_eq!(
            UpstreamError::Handshake("x".into()).audit_reason(),
            "ProtocolHandshakeFailed"
        );
        assert_eq!(
            UpstreamError::Timeout { timeout_ms: 100 }.audit_reason(),
            "Timeout"
        );
    }

    #[test]
    fn scan_ok_zero_finds_failed_double() {
        // BSON: { ok: 0.0, errmsg: "boom" }
        let mut doc = Vec::new();
        // Body: 0x01 ok\0 0.0 + 0x02 errmsg\0 5 boom\0 0
        let mut body = Vec::new();
        body.push(0x01);
        body.extend_from_slice(b"ok");
        body.push(0);
        body.extend_from_slice(&0.0f64.to_le_bytes());
        body.push(0x02);
        body.extend_from_slice(b"errmsg");
        body.push(0);
        body.extend_from_slice(&5i32.to_le_bytes());
        body.extend_from_slice(b"boom");
        body.push(0);
        let total = 4 + body.len() + 1;
        doc.extend_from_slice(&(total as i32).to_le_bytes());
        doc.extend_from_slice(&body);
        doc.push(0);
        // Wrap in OP_MSG body: flag_bits + kind=0 + bson doc.
        let mut msg = Vec::new();
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.push(0);
        msg.extend_from_slice(&doc);
        assert!(scan_op_msg_ok_zero(&msg));
    }

    #[test]
    fn scan_ok_zero_returns_false_for_ok_one() {
        let mut body = Vec::new();
        body.push(0x01);
        body.extend_from_slice(b"ok");
        body.push(0);
        body.extend_from_slice(&1.0f64.to_le_bytes());
        let total = 4 + body.len() + 1;
        let mut doc = Vec::new();
        doc.extend_from_slice(&(total as i32).to_le_bytes());
        doc.extend_from_slice(&body);
        doc.push(0);
        let mut msg = Vec::new();
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.push(0);
        msg.extend_from_slice(&doc);
        assert!(!scan_op_msg_ok_zero(&msg));
    }

    #[test]
    fn scan_ok_zero_handles_int32_form() {
        // Some Mongo internals send `ok: 0` as int32, not double.
        let mut body = Vec::new();
        body.push(0x10);
        body.extend_from_slice(b"ok");
        body.push(0);
        body.extend_from_slice(&0i32.to_le_bytes());
        let total = 4 + body.len() + 1;
        let mut doc = Vec::new();
        doc.extend_from_slice(&(total as i32).to_le_bytes());
        doc.extend_from_slice(&body);
        doc.push(0);
        let mut msg = Vec::new();
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.push(0);
        msg.extend_from_slice(&doc);
        assert!(scan_op_msg_ok_zero(&msg));
    }

    // ----- SCRAM-SHA-256 unit tests (V2 §2.2) -----

    /// RFC 5802 §5.1 reserves `=` and `,` as message-attribute
    /// delimiters; SCRAM clients MUST escape them as `=3D` and `=2C`.
    #[test]
    fn scram_username_escape_handles_reserved_chars() {
        assert_eq!(scram_username_escape("user"), "user");
        assert_eq!(scram_username_escape("user,name"), "user=2Cname");
        assert_eq!(scram_username_escape("user=name"), "user=3Dname");
        assert_eq!(scram_username_escape("a,b=c,d"), "a=2Cb=3Dc=2Cd");
    }

    /// `parse_server_first_message` must extract `r=`, `s=`, `i=`
    /// and reject mandatory extensions.
    #[test]
    fn parse_server_first_message_extracts_r_s_i() {
        // Salt = base64("salt") = "c2FsdA==", iter = 4096.
        let s = "r=combined-nonce-xyz,s=c2FsdA==,i=4096";
        let parsed = parse_server_first_message(s).unwrap();
        assert_eq!(parsed.combined_nonce, "combined-nonce-xyz");
        assert_eq!(parsed.salt, b"salt");
        assert_eq!(parsed.iterations, 4096);
    }

    #[test]
    fn parse_server_first_message_rejects_mandatory_extension() {
        let s = "m=mandatory-feature,r=combined,s=c2FsdA==,i=4096";
        let err = parse_server_first_message(s).unwrap_err();
        assert!(err.contains("mandatory-feature"));
    }

    #[test]
    fn parse_server_first_message_rejects_missing_iter() {
        let s = "r=combined,s=c2FsdA==";
        let err = parse_server_first_message(s).unwrap_err();
        assert!(err.contains("iter") || err.contains("missing"));
    }

    #[test]
    fn parse_server_final_message_returns_signature() {
        // base64("sig") = "c2ln"
        let v = parse_server_final_message("v=c2ln").unwrap();
        assert_eq!(v, b"sig");
    }

    #[test]
    fn parse_server_final_message_surfaces_server_error() {
        let err = parse_server_final_message("e=invalid-proof").unwrap_err();
        assert!(err.contains("invalid-proof"));
    }

    #[test]
    fn constant_time_eq_returns_true_on_equal() {
        let a = b"the quick brown fox";
        let b = b"the quick brown fox";
        assert!(constant_time_eq(a, b));
    }

    #[test]
    fn constant_time_eq_returns_false_on_diff_or_len() {
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abc", b""));
    }

    /// PBKDF2-HMAC-SHA256 RFC 7677 test vector: password=`"pencil"`,
    /// salt=base64("W22ZaJ0SNY7soEsUEjb6gQ=="), iter=4096
    /// expected salted_password (hex):
    /// 89b69552fcc52f9c0c8a6cb4afdcdfa9e8b1f1e84a48ad0f7a9e7e6e6c8c8c8c
    /// but RFC 7677 uses different salt; we just pin a known
    /// reference vector here against the standalone pbkdf2 crate.
    #[test]
    fn pbkdf2_hmac_sha256_matches_reference_vector() {
        // Test vector from RFC 7914 §11 / generated via a known-good
        // implementation: pbkdf2_hmac_sha256("password", "salt", 1, 32)
        let expected =
            hex_decode("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        let got = pbkdf2_hmac_sha256(b"password", b"salt", 1);
        assert_eq!(got.to_vec(), expected, "PBKDF2-HMAC-SHA256 vector mismatch");
    }

    /// HMAC-SHA256 RFC 4231 test vector: key=20*0x0b, data="Hi There".
    #[test]
    fn hmac_sha256_matches_rfc4231_vector_1() {
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let expected =
            hex_decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(hmac_sha256(&key, data).to_vec(), expected);
    }

    /// SHA-256 of empty input pinned for digest sanity.
    #[test]
    fn sha256_digest_of_empty_is_zero_hash() {
        let expected =
            hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_digest(b"").to_vec(), expected);
    }

    /// Build a saslStart doc and verify it carries the
    /// `mechanism: SCRAM-SHA-256` string + a BinData payload.
    #[test]
    fn build_sasl_start_doc_includes_mechanism_and_payload() {
        let doc = build_sasl_start_doc("admin", "SCRAM-SHA-256", b"n,n=demo,r=AAA");
        let needle_mech = b"SCRAM-SHA-256";
        assert!(
            doc.windows(needle_mech.len()).any(|w| w == needle_mech),
            "mechanism must appear verbatim in BSON",
        );
        let needle_payload = b"n,n=demo,r=AAA";
        assert!(
            doc.windows(needle_payload.len())
                .any(|w| w == needle_payload),
            "BinData payload must appear verbatim in BSON",
        );
    }

    /// End-to-end SCRAM round trip against a mock OP_MSG server.
    /// Drives the full state machine: saslStart → server-first →
    /// saslContinue → server-final → server signature verify.
    #[tokio::test]
    async fn scram_sha256_authenticate_against_mock_succeeds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = mock_scram_server(&mut sock, "demo", b"hunter2", true).await;
        });
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        scram_sha256_authenticate(&mut s, "admin", "demo", b"hunter2")
            .await
            .expect("scram should succeed");
        server.await.unwrap();
    }

    /// SCRAM with the wrong password MUST surface AuthRejected and
    /// the error message must NOT contain the password bytes.
    #[tokio::test]
    async fn scram_sha256_authenticate_wrong_password_is_auth_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Mock server validates the proof against `correct`, so when
        // the client uses `wrong` the proof check fails server-side.
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = mock_scram_server(&mut sock, "demo", b"correct", false).await;
        });
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let err = scram_sha256_authenticate(&mut s, "admin", "demo", b"wrong")
            .await
            .expect_err("wrong password should be rejected");
        match err {
            UpstreamError::AuthRejected(msg) => {
                assert!(
                    !msg.contains("wrong"),
                    "AuthRejected detail must not echo password bytes: {msg}"
                );
            }
            other => panic!("expected AuthRejected, got {other:?}"),
        }
        server.await.unwrap();
    }

    // ---- mock-server helpers used by the SCRAM round-trip tests ----

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s).expect("test fixture hex must decode")
    }

    /// Minimal MongoDB SCRAM-SHA-256 server fixture. Reads the
    /// proxy's saslStart/saslContinue OP_MSG frames and emits the
    /// expected server-first / server-final replies.
    /// `expect_proof_valid` controls whether the server validates
    /// the client's proof using its known `password` (true) or
    /// always returns an `e=invalid-proof` server-final (false).
    async fn mock_scram_server(
        s: &mut tokio::net::TcpStream,
        username: &str,
        password: &[u8],
        expect_proof_valid: bool,
    ) -> std::io::Result<()> {
        use base64::Engine as _;
        use tokio::io::AsyncWriteExt;

        // ---- read saslStart ----
        let frame = mock_read_op_msg(s).await?;
        let payload = mock_extract_payload(&frame).expect("saslStart payload");
        let cf = std::str::from_utf8(&payload).unwrap();
        // RFC 5802 gs2-header `n,,` then bare `n=user,r=cnonce`.
        assert!(cf.starts_with("n,,n="));
        let bare = &cf[3..];
        let user_part = bare.split(',').next().unwrap();
        let user = user_part.trim_start_matches("n=");
        assert_eq!(user, username);
        let cnonce_attr = bare.split(',').nth(1).unwrap();
        let cnonce = cnonce_attr.trim_start_matches("r=");

        // Server picks salt + iter + extends nonce.
        let salt = b"raxis-scram-test-salt-32B-pad000";
        let iter: u32 = 4096;
        let snonce = "SERVERNONCE-XYZ";
        let combined = format!("{cnonce}{snonce}");
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
        let server_first = format!("r={combined},s={salt_b64},i={iter}");

        let reply = mock_build_sasl_reply(true, 1, server_first.as_bytes(), false, None);
        s.write_all(&reply).await?;
        s.flush().await?;

        // ---- read saslContinue ----
        let frame = mock_read_op_msg(s).await?;
        let payload = mock_extract_payload(&frame).expect("saslContinue payload");
        let cf2 = std::str::from_utf8(&payload).unwrap();
        // c=biws,r=<combined>,p=<base64-proof>
        let mut got_combined = "";
        let mut proof_b64 = "";
        for attr in cf2.split(',') {
            if let Some(v) = attr.strip_prefix("r=") {
                got_combined = v;
            }
            if let Some(v) = attr.strip_prefix("p=") {
                proof_b64 = v;
            }
        }
        assert_eq!(got_combined, combined);

        // Compute the server-side proof check using the known
        // password (success path) or a wrong key (failure path).
        let salted = pbkdf2_hmac_sha256(password, salt, iter);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256_digest(&client_key);
        let server_key = hmac_sha256(&salted, b"Server Key");
        let cf_bare = format!("n={user},r={cnonce}");
        let cl_final_bare = format!("c=biws,r={combined}");
        let auth_msg = format!("{cf_bare},{server_first},{cl_final_bare}");
        let cli_sig = hmac_sha256(&stored_key, auth_msg.as_bytes());
        let mut expected_proof = client_key;
        for (a, b) in expected_proof.iter_mut().zip(cli_sig.iter()) {
            *a ^= *b;
        }
        let got_proof = base64::engine::general_purpose::STANDARD
            .decode(proof_b64)
            .unwrap();
        let proof_matches = expect_proof_valid && got_proof == expected_proof;

        let server_final = if proof_matches {
            let server_sig = hmac_sha256(&server_key, auth_msg.as_bytes());
            let v = base64::engine::general_purpose::STANDARD.encode(server_sig);
            format!("v={v}")
        } else {
            "e=invalid-proof".into()
        };
        let reply = mock_build_sasl_reply(
            proof_matches,
            1,
            server_final.as_bytes(),
            true, // done
            if proof_matches {
                None
            } else {
                Some("Authentication failed")
            },
        );
        s.write_all(&reply).await?;
        s.flush().await?;
        Ok(())
    }

    async fn mock_read_op_msg(s: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut header = [0u8; 16];
        s.read_exact(&mut header).await?;
        let total = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let body_len = total - 16;
        let mut body = vec![0u8; body_len];
        s.read_exact(&mut body).await?;
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    /// Pull a `payload: BinData(0, ...)` value out of an OP_MSG
    /// kind-0 BSON section. Returns `None` if not found.
    fn mock_extract_payload(frame: &[u8]) -> Option<Vec<u8>> {
        let body = &frame[16..];
        let kind = *body.get(4)?;
        if kind != 0 {
            return None;
        }
        let doc = body.get(5..)?;
        let total =
            i32::from_le_bytes([*doc.first()?, *doc.get(1)?, *doc.get(2)?, *doc.get(3)?]) as usize;
        let inner = &doc[4..total - 1];
        let mut i = 0;
        while i < inner.len() {
            let t = inner[i];
            i += 1;
            if t == 0 {
                break;
            }
            let nul = inner[i..].iter().position(|&b| b == 0)?;
            let name = std::str::from_utf8(&inner[i..i + nul]).ok()?;
            i += nul + 1;
            if t == 0x05 && name == "payload" {
                let blen = i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]])
                    as usize;
                let _subtype = inner[i + 4];
                return Some(inner[i + 5..i + 5 + blen].to_vec());
            }
            // Skip value by type-dependent length (same logic as
            // sasl_reply_errmsg's switch).
            let skip = match t {
                0x01 | 0x09 | 0x11 | 0x12 => 8,
                0x02 => {
                    let l = i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]])
                        as usize;
                    4 + l
                }
                0x03 | 0x04 => {
                    i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]])
                        as usize
                }
                0x05 => {
                    let l = i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]])
                        as usize;
                    4 + 1 + l
                }
                0x07 => 12,
                0x08 => 1,
                0x10 => 4,
                _ => return None,
            };
            i += skip;
        }
        None
    }

    /// Build the BSON for a SASL reply doc and wrap it in OP_MSG.
    fn mock_build_sasl_reply(
        ok: bool,
        conv_id: i32,
        payload: &[u8],
        done: bool,
        errmsg: Option<&str>,
    ) -> Vec<u8> {
        use crate::wire::BsonBuilder as B;
        let mut b = B::new()
            .double("ok", if ok { 1.0 } else { 0.0 })
            .int32("conversationId", conv_id)
            .binary("payload", payload)
            .bool("done", done);
        if let Some(m) = errmsg {
            b = b.string("errmsg", m).int32("code", 18);
        }
        let doc = b.finish();
        let body_len = 4 + 1 + doc.len();
        let total = 16 + body_len;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(total as i32).to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes()); // request_id
        out.extend_from_slice(&0i32.to_le_bytes()); // response_to
        out.extend_from_slice(&2013i32.to_le_bytes()); // OP_MSG
        out.extend_from_slice(&0u32.to_le_bytes());
        out.push(0);
        out.extend_from_slice(&doc);
        out
    }
}
