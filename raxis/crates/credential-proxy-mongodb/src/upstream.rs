//! Upstream MongoDB connection driver.
//!
//! Normative reference: `credential-proxy.md §14.3` (lazy connect on
//! first allowed query) and `§14.8.4` (per-proxy implementation
//! matrix for MongoDB).
//!
//! # What this module owns
//!
//! * Parsing the **credential value** (resolved through
//!   `Arc<dyn CredentialBackend>`) as a Mongo Standard Connection
//!   String like `mongodb://host:27017/db` or
//!   `mongodb://user:pass@host:27017/db?authMechanism=SCRAM-SHA-256`.
//! * Opening a real `tokio::net::TcpStream` to the upstream and
//!   relaying `OP_MSG` packets verbatim once the upstream session
//!   is usable.
//! * Surfacing structured errors at every failure point so the proxy
//!   can map them to the three V2.1 audit events (`UpstreamConnected`,
//!   `UpstreamFailed`, `DatabaseQueryCompleted`).
//!
//! # V2.1 MVP scope: no-auth upstreams only
//!
//! Mongo's modern auth path is SCRAM-SHA-256 over `saslStart` /
//! `saslContinue` `OP_MSG` envelopes. Implementing it correctly is
//! ~150 lines of `HMAC` + `PBKDF2` plumbing whose correctness depends
//! on the SCRAM-SHA-256 RFC 7677. The V2.1 MVP intentionally ships
//! the **relay path** without SCRAM and rejects URLs with userinfo
//! (a `username:password@` segment) so operators get a clear signal
//! to either:
//!
//!   * Run the upstream with `--noauth` (typical for development
//!     containers + ephemeral CI fixtures, including the
//!     `mongo:7` Docker image's default), OR
//!   * Wait for the V2.2 SCRAM-SHA-256 follow-up.
//!
//! The relay path itself is exercised end-to-end in V2.1, which is
//! what unblocks agents from reading real Mongo collections in
//! development environments while we land the SCRAM crypto in a
//! reviewable follow-up commit.
//!
//! # Why we relay packets verbatim
//!
//! Just as for MySQL, the Mongo proxy already does per-command
//! classification + restriction enforcement on the agent's `OP_MSG`
//! BEFORE it forwards to the upstream. After that gate, the proxy
//! is a framing-aware byte relay: read upstream's `OP_MSG` response,
//! write it to the agent. There's no row re-encode pass — the BSON
//! flows through unchanged.

use std::sync::Arc;
use std::time::{Duration, Instant};

use raxis_credentials::{
    CredentialBackend, CredentialError, CredentialName, ConsumerIdentity,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::OwnedConsumer;
use crate::wire::{HEADER_LEN, MAX_MESSAGE_LEN, MsgHeader, OP_MSG};

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
    if lead < 0x80 { 1 }
    else if lead < 0xc0 { 1 }
    else if lead < 0xe0 { 2 }
    else if lead < 0xf0 { 3 }
    else { 4 }
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
    /// True if the URL had `username:password@` userinfo. The V2.1
    /// MVP rejects URLs with userinfo at `connect()` time because
    /// SCRAM-SHA-256 is V2.2 work — see the module-level doc.
    pub has_userinfo: bool,
    /// True if the URL requested TLS (`mongodb+srv` or `tls=true`).
    /// V2.1 supports plaintext only.
    pub require_tls: bool,
}

impl ParsedUpstreamUrl {
    /// Parse a Mongo SCS URL out of a resolved credential value.
    pub fn parse(raw_url: &str) -> Result<Self, UpstreamError> {
        let raw = raw_url.trim();
        let after_scheme = if let Some(rest) = raw.strip_prefix("mongodb://") {
            rest
        } else if raw.starts_with("mongodb+srv://") {
            return Err(UpstreamError::InvalidUrl(
                "mongodb+srv:// not supported by V2.1 MVP — use plaintext mongodb:// scheme".into(),
            ));
        } else {
            return Err(UpstreamError::InvalidUrl(
                "scheme must be `mongodb://`".into(),
            ));
        };
        let (userinfo_present, host_and_rest) = match after_scheme.find('@') {
            Some(at) => (!after_scheme[..at].is_empty(), &after_scheme[at + 1..]),
            None => (false, after_scheme),
        };
        let host_end = host_and_rest
            .find(|c: char| c == '/' || c == '?')
            .unwrap_or(host_and_rest.len());
        let authority = &host_and_rest[..host_end];
        // Reject host lists like `host1,host2` — the V2.1 MVP only
        // talks to a single mongod.
        if authority.contains(',') {
            return Err(UpstreamError::InvalidUrl(
                "comma-separated host list not supported by V2.1 MVP — point at one mongod".into(),
            ));
        }
        let (host, port) = match authority.rfind(':') {
            Some(colon) => {
                let h = &authority[..colon];
                let p = authority[colon + 1..].parse::<u16>().map_err(|_| {
                    UpstreamError::InvalidUrl("port is not a valid u16".into())
                })?;
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
        Ok(Self {
            host,
            port,
            database,
            has_userinfo: userinfo_present,
            require_tls,
        })
    }
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
    stream:        TcpStream,
    /// Hostname the audit envelope reports.
    pub host:      String,
    /// Port the audit envelope reports.
    pub port:      u16,
    /// True if the URL requested TLS — V2.1 surfaces this in the
    /// audit envelope but the implementation only supports plaintext.
    pub tls:       bool,
    /// Wall-clock for the connect step.
    pub handshake_ms: u32,
}

impl UpstreamSession {
    /// Open a new upstream session against the parsed URL.
    ///
    /// V2.1 supports plaintext + no-auth only. URLs with
    /// `username:password@` userinfo OR `tls=true`/`ssl=true` query
    /// flags fail fast with `UpstreamError::Handshake` so the
    /// operator gets a clear signal to either re-configure the
    /// upstream as `--noauth` or wait for the V2.2 SCRAM follow-up.
    pub async fn connect(
        url: &ParsedUpstreamUrl,
        connect_timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        if url.require_tls {
            return Err(UpstreamError::Handshake(
                "tls=true is not supported by the V2.1 MVP — \
                 plaintext upstream only; SCRAM + TLS land in V2.2".into(),
            ));
        }
        if url.has_userinfo {
            return Err(UpstreamError::Handshake(
                "MongoDB SCRAM-SHA-256 auth is deferred to V2.2; \
                 V2.1 supports `--noauth` upstreams only — strip the \
                 user:password@ userinfo from the credential URL or \
                 configure mongod with --noauth".into(),
            ));
        }
        let started = Instant::now();
        let connect_fut = async {
            let addr = format!("{}:{}", url.host, url.port);
            let stream = TcpStream::connect(&addr).await
                .map_err(|e| UpstreamError::TcpConnect(redact_for_audit(&e.to_string())))?;
            Ok::<_, UpstreamError>(stream)
        };
        let stream = match tokio::time::timeout(connect_timeout, connect_fut).await {
            Ok(res) => res?,
            Err(_) => {
                return Err(UpstreamError::Timeout {
                    timeout_ms: connect_timeout.as_millis().min(u32::MAX as u128) as u32,
                });
            }
        };
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
        self.stream.write_all(agent_frame).await
            .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
        self.stream.flush().await.ok();
        // Read upstream's reply: 16-byte header + body.
        let mut header = [0u8; HEADER_LEN];
        self.stream.read_exact(&mut header).await
            .map_err(|e| UpstreamError::RelayFailed(format!("read upstream header: {e}")))?;
        let parsed = MsgHeader::parse(header);
        let total = parsed.message_length as usize;
        if total < HEADER_LEN || total > MAX_MESSAGE_LEN {
            return Err(UpstreamError::PayloadTooLarge {
                bytes: total,
                max:   MAX_MESSAGE_LEN,
            });
        }
        let body_len = total - HEADER_LEN;
        let mut body = vec![0u8; body_len];
        self.stream.read_exact(&mut body).await
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
            if i + 4 > body.len() { return false; }
            let section_size = i32::from_le_bytes([
                body[i], body[i + 1], body[i + 2], body[i + 3],
            ]) as usize;
            if section_size < 4 || i + section_size > body.len() { return false; }
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
                if i + 8 > body.len() { return false; }
                if is_ok {
                    let v = f64::from_le_bytes([
                        body[i], body[i + 1], body[i + 2], body[i + 3],
                        body[i + 4], body[i + 5], body[i + 6], body[i + 7],
                    ]);
                    return v == 0.0;
                }
                i += 8;
            }
            // string
            0x02 => {
                if i + 4 > body.len() { return false; }
                let strlen = i32::from_le_bytes([
                    body[i], body[i + 1], body[i + 2], body[i + 3],
                ]) as usize;
                i += 4 + strlen;
            }
            // embedded doc / array
            0x03 | 0x04 => {
                if i + 4 > body.len() { return false; }
                let inner = i32::from_le_bytes([
                    body[i], body[i + 1], body[i + 2], body[i + 3],
                ]) as usize;
                i += inner;
            }
            // binary
            0x05 => {
                if i + 4 > body.len() { return false; }
                let blen = i32::from_le_bytes([
                    body[i], body[i + 1], body[i + 2], body[i + 3],
                ]) as usize;
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
                    Some(n) => n, None => return false,
                };
                i += nul1 + 1;
                let nul2 = match body[i..].iter().position(|&b| b == 0) {
                    Some(n) => n, None => return false,
                };
                i += nul2 + 1;
            }
            // int32
            0x10 => {
                if i + 4 > body.len() { return false; }
                if is_ok {
                    let v = i32::from_le_bytes([
                        body[i], body[i + 1], body[i + 2], body[i + 3],
                    ]);
                    return v == 0;
                }
                i += 4;
            }
            // timestamp
            0x11 => i += 8,
            // int64
            0x12 => {
                if i + 8 > body.len() { return false; }
                if is_ok {
                    let v = i64::from_le_bytes([
                        body[i], body[i + 1], body[i + 2], body[i + 3],
                        body[i + 4], body[i + 5], body[i + 6], body[i + 7],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_minimal() {
        let p = ParsedUpstreamUrl::parse("mongodb://localhost:27017/test").unwrap();
        assert_eq!(p.host, "localhost");
        assert_eq!(p.port, 27017);
        assert_eq!(p.database.as_deref(), Some("test"));
        assert!(!p.has_userinfo);
        assert!(!p.require_tls);
    }

    #[test]
    fn parse_url_default_port() {
        let p = ParsedUpstreamUrl::parse("mongodb://db/").unwrap();
        assert_eq!(p.port, 27017);
    }

    #[test]
    fn parse_url_with_userinfo_marks_flag() {
        let p = ParsedUpstreamUrl::parse("mongodb://demo:hunter2@db/test").unwrap();
        assert!(p.has_userinfo);
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
        assert_eq!(UpstreamError::TcpConnect("x".into()).audit_reason(), "TcpConnectFailed");
        assert_eq!(UpstreamError::Handshake("x".into()).audit_reason(), "ProtocolHandshakeFailed");
        assert_eq!(UpstreamError::Timeout { timeout_ms: 100 }.audit_reason(), "Timeout");
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
}
