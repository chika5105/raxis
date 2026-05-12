//! Upstream MSSQL connection driver.
//!
//! Normative reference: `credential-proxy.md §14.3` (lazy connect on
//! first allowed query) and `§14.8.3` (per-proxy implementation
//! matrix for MSSQL).
//!
//! # What this module owns
//!
//! * Parsing the **credential value** as a JDBC-style URL like
//!   `mssql://sa:hunter2@host:1433/db?encrypt=false`.
//! * Opening a real `tokio::net::TcpStream` to the upstream and
//!   driving the TDS `PRELOGIN → LOGIN7 → LOGINACK + DONE`
//!   handshake on the V2.1 MVP wire (no TLS, SQL Authentication
//!   only — no SSPI/NTLM/Entra ID).
//! * Forwarding agent-issued `SQLBatch` packets to the upstream
//!   and relaying back the upstream's `TABULAR_RESULT` packets
//!   verbatim.
//! * Surfacing structured errors at every failure point so the
//!   proxy can map them to the three V2.1 audit events
//!   (`UpstreamConnected`, `UpstreamFailed`, `DatabaseQueryCompleted`).
//!
//! # Why we hand-roll the TDS upstream wire
//!
//! `tiberius` is the obvious crate, but pulling it in for V2.1 ties
//! the proxy to ~30 transitive deps (including `async-native-tls`,
//! `tokio-util`, `pretty-hex`) and a vendored implementation of
//! the GSS-API negotiation surface for Windows Auth that we'd
//! never use. The V2.1 MVP needs only:
//!
//!   * PRELOGIN with `ENCRYPTION = NOT_SUP` — refuses TLS upstream.
//!   * LOGIN7 with SQL Authentication (cleartext password
//!     pseudo-encrypted with the nibble-swap + XOR(0xA5) trick
//!     defined in `[MS-TDS] 2.2.6.4`).
//!   * Single-packet `SQLBatch` request relay.
//!   * Single-packet `TABULAR_RESULT` response relay (we read
//!     packets until we see `status & EOM`, just as the upstream
//!     does for us).
//!
//! That's ~250 lines of straightforward byte plumbing. Windows Auth
//! / Kerberos / Entra ID / `Encrypt=true` are deferred to V3.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{BufMut, BytesMut};
use raxis_credentials::{
    CredentialBackend, CredentialError, CredentialName, ConsumerIdentity,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::OwnedConsumer;
use crate::wire::{HEADER_LEN, MAX_PACKET_LEN, PacketHeader, frame_packet, pkt, status};

/// Default upstream connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Maximum bytes the proxy will buffer per upstream response. We
/// cap at 16 MiB — well above any realistic single-batch result
/// for the V2.1 MVP, and well under the protocol's MAX_PACKET_LEN.
const MAX_RELAY_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Upstream-connect / forward errors classified into the
/// `CredentialProxyUpstreamFailed::reason` discriminants from
/// `credential-proxy.md §14.5.3`.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The credential bytes could not be parsed as a JDBC-style URL.
    #[error("invalid upstream URL: {0}")]
    InvalidUrl(String),

    /// Credential resolution through the backend failed.
    #[error("credential resolution failed: {0}")]
    CredentialResolution(String),

    /// DNS lookup or TCP connect to the upstream failed.
    #[error("tcp connect failed: {0}")]
    TcpConnect(String),

    /// Protocol-level handshake failure (PRELOGIN refused, LOGIN7
    /// shape error, unsupported auth scheme).
    #[error("mssql protocol handshake failed: {0}")]
    Handshake(String),

    /// Upstream rejected the credential at the LOGIN7 step.
    #[error("upstream auth rejected: {0}")]
    AuthRejected(String),

    /// Upstream took longer than the connect timeout.
    #[error("upstream connect timed out after {timeout_ms}ms")]
    Timeout {
        /// Timeout in milliseconds.
        timeout_ms: u32,
    },

    /// Upstream response payload exceeded `MAX_RELAY_BYTES`.
    #[error("upstream response payload too large: {bytes} > {max} bytes")]
    PayloadTooLarge {
        /// Bytes the upstream announced.
        bytes: usize,
        /// Bytes the proxy is willing to buffer.
        max: usize,
    },

    /// Mid-relay I/O error.
    #[error("upstream relay failed: {0}")]
    RelayFailed(String),
}

impl UpstreamError {
    /// Map this error to the audit-envelope `reason` enum string.
    pub fn audit_reason(&self) -> &'static str {
        match self {
            Self::InvalidUrl(_) => "ProtocolHandshakeFailed",
            Self::CredentialResolution(_) => "AuthRejected",
            Self::TcpConnect(_) => "TcpConnectFailed",
            Self::Handshake(_) => "ProtocolHandshakeFailed",
            Self::AuthRejected(_) => "AuthRejected",
            Self::Timeout { .. } => "Timeout",
            Self::PayloadTooLarge { .. } => "ProtocolHandshakeFailed",
            Self::RelayFailed(_) => "ProtocolHandshakeFailed",
        }
    }

    /// Map this error to the redacted detail string.
    pub fn audit_detail(&self) -> String {
        redact_for_audit(&self.to_string())
    }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Strip credential-leak substrings from an upstream-error message
/// before it reaches the audit envelope. Single-pass; mirrors the
/// implementation in the postgres / mysql / mongodb proxies.
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
                && bytes[i] != b'&' && bytes[i] != b' '
                && bytes[i] != b'"' && bytes[i] != b'\''
                && bytes[i] != b'\n'
            {
                i += 1;
            }
            continue;
        }
        if i + 3 <= bytes.len() && &bytes[i..i + 3] == b"://" {
            let mut auth_end = i + 3;
            while auth_end < bytes.len()
                && bytes[auth_end] != b'/' && bytes[auth_end] != b'?'
                && bytes[auth_end] != b' ' && bytes[auth_end] != b'\n'
                && bytes[auth_end] != b'"' && bytes[auth_end] != b'\''
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

/// Parsed view of a JDBC-style MSSQL credential URL.
#[derive(Debug, Clone)]
pub struct ParsedUpstreamUrl {
    /// Hostname from the credential URL.
    pub host: String,
    /// Port from the credential URL after default-port substitution
    /// (1433).
    pub port: u16,
    /// SQL Authentication username.
    pub user: String,
    /// SQL Authentication password.
    password: String,
    /// Optional default database from the URL path.
    pub database: Option<String>,
    /// True if `?encrypt=true` (or `?encrypt=strict`) was in the URL.
    /// V2.1 MVP fails fast in `connect()` if this is set.
    pub require_tls: bool,
}

impl ParsedUpstreamUrl {
    /// Parse a JDBC-style URL out of a resolved credential value.
    ///
    /// Accepted schemes: `mssql://`, `sqlserver://`, `tds://`. The
    /// proxy treats them identically.
    pub fn parse(raw_url: &str) -> Result<Self, UpstreamError> {
        let raw = raw_url.trim();
        let after_scheme = if let Some(rest) = raw.strip_prefix("mssql://") {
            rest
        } else if let Some(rest) = raw.strip_prefix("sqlserver://") {
            rest
        } else if let Some(rest) = raw.strip_prefix("tds://") {
            rest
        } else {
            return Err(UpstreamError::InvalidUrl(
                "scheme must be `mssql://`, `sqlserver://`, or `tds://`".into(),
            ));
        };
        let (userinfo, host_and_rest) = match after_scheme.find('@') {
            Some(at) => (&after_scheme[..at], &after_scheme[at + 1..]),
            None => ("", after_scheme),
        };
        let (user, password) = match userinfo.find(':') {
            Some(colon) => (
                percent_decode(&userinfo[..colon]),
                percent_decode(&userinfo[colon + 1..]),
            ),
            None if userinfo.is_empty() => (String::new(), String::new()),
            None => (percent_decode(userinfo), String::new()),
        };
        let host_end = host_and_rest
            .find(|c: char| c == '/' || c == '?')
            .unwrap_or(host_and_rest.len());
        let authority = &host_and_rest[..host_end];
        let (host, port) = match authority.rfind(':') {
            Some(colon) => {
                let h = &authority[..colon];
                let p = authority[colon + 1..].parse::<u16>().map_err(|_| {
                    UpstreamError::InvalidUrl("port is not a valid u16".into())
                })?;
                (h.to_owned(), p)
            }
            None => (authority.to_owned(), 1433u16),
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
            .map(percent_decode);
        let qlower = query_part.to_lowercase();
        let require_tls = qlower.contains("encrypt=true")
            || qlower.contains("encrypt=strict")
            || qlower.contains("encrypt=mandatory");
        Ok(Self {
            host,
            port,
            user,
            password,
            database,
            require_tls,
        })
    }

    /// Borrow the password bytes — caller MUST NOT log or surface
    /// these. Used only during the LOGIN7 build step.
    pub fn password_bytes(&self) -> &[u8] {
        self.password.as_bytes()
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((hi << 4 | lo) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Resolve the credential bytes through the backend and parse them
/// as a JDBC-style URL.
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

/// Outcome of a forwarded `SQLBatch` round trip.
#[derive(Debug)]
pub struct ForwardOutcome {
    /// The raw upstream `TABULAR_RESULT` packet bytes (one or more
    /// concatenated TDS packets — last has `status & EOM` set). The
    /// proxy writes these to the agent verbatim.
    pub frames: Vec<u8>,
    /// Wall-clock duration of the upstream round trip in ms.
    pub duration_ms: u32,
    /// Total payload bytes the proxy will write to the agent.
    pub bytes_returned: u64,
    /// True if the upstream's response stream contained an `ERROR`
    /// token (0xAA) — surfaced via `DatabaseQueryCompleted.upstream_error`.
    pub upstream_error: bool,
}

/// One live upstream session.
pub struct UpstreamSession {
    stream:          TcpStream,
    /// Hostname the audit envelope reports.
    pub host:        String,
    /// Port the audit envelope reports.
    pub port:        u16,
    /// True if the URL requested TLS (V2.1 fails fast in this case).
    pub tls:         bool,
    /// Wall-clock for the connect step.
    pub handshake_ms: u32,
}

impl UpstreamSession {
    /// Open a new upstream session against the parsed URL.
    ///
    /// V2.1 supports plaintext + SQL Authentication only.
    /// `?encrypt=true` and Windows / Entra ID auth schemes return
    /// `UpstreamError::Handshake` so the operator gets a clear
    /// signal to either re-configure the upstream or wait for V3.
    pub async fn connect(
        url: &ParsedUpstreamUrl,
        connect_timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        if url.require_tls {
            return Err(UpstreamError::Handshake(
                "?encrypt=true is not supported by the V2.1 MVP — \
                 plaintext TDS only; TLS upstream lands in V3".into(),
            ));
        }
        if url.user.is_empty() {
            return Err(UpstreamError::Handshake(
                "MSSQL upstream URL must carry SQL Authentication \
                 username (Windows Auth + Entra ID are V3 work)".into(),
            ));
        }
        let started = Instant::now();
        let connect_fut = async {
            let addr = format!("{}:{}", url.host, url.port);
            let mut stream = TcpStream::connect(&addr).await
                .map_err(|e| UpstreamError::TcpConnect(redact_for_audit(&e.to_string())))?;
            // Drive PRELOGIN.
            stream.write_all(&frame_packet(pkt::PRELOGIN, &build_prelogin_request_body())).await
                .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
            stream.flush().await.ok();
            let (header, body) = read_one_packet(&mut stream).await
                .map_err(|e| UpstreamError::Handshake(format!("read PRELOGIN response: {e}")))?;
            if header.packet_type != pkt::TABULAR_RESULT {
                return Err(UpstreamError::Handshake(format!(
                    "expected TABULAR_RESULT after PRELOGIN, got 0x{:02x}",
                    header.packet_type,
                )));
            }
            // Inspect the ENCRYPTION option from the upstream's
            // PRELOGIN response. We require ENC_NOT_SUP (0x02) or
            // ENC_OFF (0x00) — anything else means the upstream
            // wants TLS, which we do not speak in V2.1.
            match parse_prelogin_encryption(&body) {
                Some(0x00) | Some(0x02) => {}
                Some(other) => {
                    return Err(UpstreamError::Handshake(format!(
                        "upstream demanded ENCRYPTION=0x{other:02x}; V2.1 only \
                         supports plaintext (ENCRYPTION=0x00 or 0x02)"
                    )));
                }
                None => {
                    return Err(UpstreamError::Handshake(
                        "PRELOGIN response missing ENCRYPTION option".into(),
                    ));
                }
            }
            // Drive LOGIN7.
            let login = build_login7(
                &url.user,
                url.password_bytes(),
                url.database.as_deref(),
            );
            stream.write_all(&frame_packet(pkt::LOGIN7, &login)).await
                .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
            stream.flush().await.ok();
            // Read TABULAR_RESULT (LOGINACK + DONE on success, or
            // ERROR + DONE on failure).
            let frames = read_until_eom(&mut stream).await
                .map_err(|e| UpstreamError::Handshake(format!("read LOGIN7 response: {e}")))?;
            classify_login_response(&frames)?;
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
            tls:  url.require_tls,
            handshake_ms,
        })
    }

    /// Forward an `SQLBatch` packet (header + body, single packet)
    /// to the upstream and read the upstream's `TABULAR_RESULT`
    /// stream until EOM.
    ///
    /// The agent's body is **rewritten** before forwarding so that
    /// the upstream sees a TDS 7.4-compliant `ALL_HEADERS` preamble
    /// followed by the SQL text in UTF-16 LE. This is necessary
    /// because:
    ///
    /// * The proxy advertises TDS 7.4 in its LOGIN7 (see
    ///   `build_login7`), so the upstream parses every SQLBatch
    ///   packet body using the TDS 7.4 rules — which require a
    ///   well-formed `ALL_HEADERS` containing at least the
    ///   `MARS Transaction Descriptor` header (`HeaderType = 0x0002`).
    /// * Many simple agent clients (the live-e2e harness, hand-rolled
    ///   benchmarks, older drivers) emit a degenerate
    ///   `ALL_HEADERS` of `TotalLength = 4` (i.e. a 0-byte header
    ///   list). SQL Server 2022 rejects these with the "TDS protocol
    ///   stream is incorrect. The multiple active result sets (MARS)
    ///   TDS header is missing" `ERROR` token (number `4002`).
    /// * The agent's `ALL_HEADERS` cannot meaningfully cross the
    ///   proxy boundary anyway: any transaction descriptor the agent
    ///   chose refers to its OWN proxy-side connection state, not
    ///   the proxy's upstream-side connection state. The proxy is
    ///   the authoritative source for the upstream-side transaction
    ///   descriptor (always `0` until the proxy implements transaction
    ///   handling for V3).
    ///
    /// Pinned against MS SQL Server 2022 reproducer; older 2017/2019
    /// servers happen to tolerate the malformed `ALL_HEADERS`.
    pub async fn forward_sql_batch(
        &mut self,
        agent_packet: &[u8],
    ) -> Result<ForwardOutcome, UpstreamError> {
        let started = Instant::now();
        let rewritten = rewrite_sql_batch_for_upstream(agent_packet)?;
        self.stream.write_all(&rewritten).await
            .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
        self.stream.flush().await.ok();
        let frames = read_until_eom(&mut self.stream).await
            .map_err(|e| UpstreamError::RelayFailed(format!("read SQLBatch response: {e}")))?;
        let bytes_returned = frames.len() as u64;
        let upstream_error = scan_for_error_token(&frames);
        let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        Ok(ForwardOutcome {
            frames,
            duration_ms,
            bytes_returned,
            upstream_error,
        })
    }
}

/// Rewrite the agent's SQLBatch packet so the body carries a fresh
/// TDS 7.4-compliant `ALL_HEADERS` preamble followed by the
/// SQL text in UTF-16 LE.
///
/// `agent_packet` is the full TDS packet the agent sent (8-byte
/// header + body).  We parse out the SQL text, drop the agent's
/// `ALL_HEADERS` entirely, then re-frame:
///
/// ```text
///   8-byte TDS header (type=SQLBatch, status=EOM, packet_id=1,
///                      length set after assembly)
///   ALL_HEADERS:
///     u32 LE TotalLength = 22
///     u32 LE HeaderLength = 18
///     u16 LE HeaderType = 0x0002 (Transaction Descriptor)
///     u64 LE TransactionDescriptor = 0
///     u32 LE OutstandingRequestCount = 1
///   UTF-16 LE SQL text bytes
/// ```
///
/// Returns the wire bytes ready to write to the upstream.
fn rewrite_sql_batch_for_upstream(agent_packet: &[u8])
    -> Result<Vec<u8>, UpstreamError>
{
    use crate::wire::{HEADER_LEN as TDS_HEADER, PacketHeader, status, pkt};
    if agent_packet.len() < TDS_HEADER {
        return Err(UpstreamError::RelayFailed(
            "agent SQLBatch packet shorter than TDS header".into(),
        ));
    }
    let mut hb = [0u8; 8];
    hb.copy_from_slice(&agent_packet[..TDS_HEADER]);
    let h = PacketHeader::parse(hb);
    if h.packet_type != pkt::SQL_BATCH {
        return Err(UpstreamError::RelayFailed(format!(
            "expected SQLBatch (0x{:02x}) header from agent, got 0x{:02x}",
            pkt::SQL_BATCH, h.packet_type,
        )));
    }
    let body = &agent_packet[TDS_HEADER..];
    let sql_text_bytes = extract_sql_text_bytes(body);
    // Build the rewritten body. ALL_HEADERS preamble must include a
    // Transaction Descriptor header for TDS 7.4 — see
    // `[MS-TDS] 2.2.5.3.1 ALL_HEADERS` and 2.2.5.3.2
    // `Transaction Descriptor`.
    const ALL_HEADERS_LEN: u32 = 4 + 4 + 2 + 8 + 4;     // 22
    const TXN_DESC_HEADER_LEN: u32 = ALL_HEADERS_LEN - 4; // 18
    const TXN_DESC_HEADER_TYPE: u16 = 0x0002;
    let mut new_body = Vec::with_capacity(
        ALL_HEADERS_LEN as usize + sql_text_bytes.len(),
    );
    new_body.extend_from_slice(&ALL_HEADERS_LEN.to_le_bytes());
    new_body.extend_from_slice(&TXN_DESC_HEADER_LEN.to_le_bytes());
    new_body.extend_from_slice(&TXN_DESC_HEADER_TYPE.to_le_bytes());
    new_body.extend_from_slice(&0u64.to_le_bytes());     // descriptor
    new_body.extend_from_slice(&1u32.to_le_bytes());     // outstanding-req
    new_body.extend_from_slice(sql_text_bytes);
    // Re-frame the packet with the new body.  Total length must
    // include the 8-byte header.
    let total = TDS_HEADER + new_body.len();
    if total > u16::MAX as usize {
        // SQLBatch body too large to fit in a single TDS packet
        // (TDS supports multi-packet messages but the agent did not
        // send one and the proxy does not chunk in V2.1).
        return Err(UpstreamError::RelayFailed(format!(
            "rewritten SQLBatch packet length {total} exceeds u16::MAX",
        )));
    }
    let header = PacketHeader {
        packet_type: pkt::SQL_BATCH,
        status:      h.status | status::EOM,
        length:      total as u16,
        spid:        0,
        packet_id:   1,
        window:      0,
    };
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(&new_body);
    Ok(out)
}

/// Extract the SQL text bytes (UTF-16 LE, raw) from a SQLBatch body
/// — i.e. strip whatever `ALL_HEADERS` the agent prepended (or did
/// not). Mirrors the parsing rule in `wire::decode_sql_batch_body`
/// but returns the bytes rather than the decoded string so we can
/// pass them through to the upstream without re-encoding.
fn extract_sql_text_bytes(body: &[u8]) -> &[u8] {
    if body.len() < 4 {
        return body;
    }
    let total_headers =
        u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    // Defensive: a real client always emits `total_headers >= 4`,
    // but the proxy is lenient about both extremes:
    //
    // * `total_headers > body.len()` — agent omitted ALL_HEADERS
    //   entirely (TDS 7.0/7.1 shape). Treat the whole body as SQL.
    // * `total_headers <= 3` — malformed; pretend ALL_HEADERS is
    //   absent.
    if total_headers <= 3 || total_headers > body.len() {
        body
    } else {
        &body[total_headers..]
    }
}

/// Read TDS packets from `stream` until one is seen with the EOM
/// status bit set, concatenating their full bytes (header included)
/// into a single buffer so the proxy can write them to the agent
/// verbatim.
async fn read_until_eom(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4096);
    loop {
        let (header, body) = read_one_packet(stream).await?;
        if out.len() + body.len() + HEADER_LEN > MAX_RELAY_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "upstream tabular-result stream exceeded MAX_RELAY_BYTES",
            ));
        }
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&body);
        if header.status & status::EOM != 0 {
            break;
        }
    }
    Ok(out)
}

/// Read exactly one TDS packet (header + body).
async fn read_one_packet(stream: &mut TcpStream) -> std::io::Result<(PacketHeader, Vec<u8>)> {
    let mut header_bytes = [0u8; HEADER_LEN];
    stream.read_exact(&mut header_bytes).await?;
    let h = PacketHeader::parse(header_bytes);
    let total = h.length as usize;
    if total < HEADER_LEN || total > MAX_PACKET_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("TDS packet length {total} out of range"),
        ));
    }
    let body_len = total - HEADER_LEN;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    Ok((h, body))
}

/// Classify a TABULAR_RESULT frame stream (header bytes included)
/// into success / auth-rejected.
fn classify_login_response(frames: &[u8]) -> Result<(), UpstreamError> {
    if frames.is_empty() {
        return Err(UpstreamError::Handshake(
            "empty LOGIN7 response".into(),
        ));
    }
    // Walk packets; for each, scan body for ERROR / LOGINACK tokens.
    let mut i = 0;
    let mut saw_loginack = false;
    while i + HEADER_LEN <= frames.len() {
        let h = PacketHeader::parse([
            frames[i], frames[i+1], frames[i+2], frames[i+3],
            frames[i+4], frames[i+5], frames[i+6], frames[i+7],
        ]);
        let body_start = i + HEADER_LEN;
        let body_end = i + h.length as usize;
        if body_end > frames.len() { break; }
        let body = &frames[body_start..body_end];
        if let Some((number, message)) = scan_first_error_token(body) {
            return Err(UpstreamError::AuthRejected(format!(
                "TDS ERROR {number}: {}",
                redact_for_audit(&message),
            )));
        }
        if body.iter().any(|&b| b == 0xAD) {
            saw_loginack = true;
        }
        i = body_end;
        if h.status & status::EOM != 0 { break; }
    }
    if saw_loginack {
        Ok(())
    } else {
        Err(UpstreamError::Handshake(
            "LOGIN7 response missing both LOGINACK and ERROR tokens".into(),
        ))
    }
}

/// Scan a TABULAR_RESULT frame stream for any `ERROR` token (0xAA).
fn scan_for_error_token(frames: &[u8]) -> bool {
    let mut i = 0;
    while i + HEADER_LEN <= frames.len() {
        let h = PacketHeader::parse([
            frames[i], frames[i+1], frames[i+2], frames[i+3],
            frames[i+4], frames[i+5], frames[i+6], frames[i+7],
        ]);
        let body_start = i + HEADER_LEN;
        let body_end = i + h.length as usize;
        if body_end > frames.len() { break; }
        let body = &frames[body_start..body_end];
        if scan_first_error_token(body).is_some() {
            return true;
        }
        i = body_end;
    }
    false
}

/// Look for the first `ERROR` token (0xAA) in a TABULAR_RESULT body
/// and return its `(number, message)` pair. The token shape is per
/// `wire.rs::build_error_done_body`. Returns `None` if the body
/// has no ERROR token.
///
/// We don't fully parse every preceding token; we scan for the
/// 0xAA byte AT a plausible token boundary. The V2.1 MVP is willing
/// to accept the rare false positive where 0xAA happens to occur
/// inside another token's body — at worst we surface a less-clean
/// audit message; we never gain or skip an actual ERROR.
fn scan_first_error_token(body: &[u8]) -> Option<(i32, String)> {
    let mut i = 0;
    while i + 1 < body.len() {
        if body[i] == 0xAA && i + 3 < body.len() {
            // Tentative match: header 0xAA + u16 LE inner-len.
            let inner_len = u16::from_le_bytes([body[i + 1], body[i + 2]]) as usize;
            if i + 3 + inner_len <= body.len() && inner_len >= 4 + 1 + 1 + 2 {
                let token_body = &body[i + 3..i + 3 + inner_len];
                let number = i32::from_le_bytes([
                    token_body[0], token_body[1], token_body[2], token_body[3],
                ]);
                // Skip state(1) + class(1).
                let mut j = 4 + 1 + 1;
                if j + 2 > token_body.len() { return None; }
                let msg_chars = u16::from_le_bytes([token_body[j], token_body[j + 1]]) as usize;
                j += 2;
                let msg_byte_len = msg_chars * 2;
                if j + msg_byte_len > token_body.len() { return None; }
                let units: Vec<u16> = token_body[j..j + msg_byte_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let message = String::from_utf16(&units).unwrap_or_default();
                return Some((number, message));
            }
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// PRELOGIN request body
// ---------------------------------------------------------------------------

/// Build the PRELOGIN request body the proxy sends to the upstream.
/// Layout matches `wire::build_prelogin_response_body` but advertises
/// our client identity (VERSION=15.0) and `ENCRYPTION = NOT_SUP`.
fn build_prelogin_request_body() -> Vec<u8> {
    let mut body = BytesMut::with_capacity(18);
    // VERSION option header.
    body.put_u8(0x00);
    body.put_u16(11);
    body.put_u16(6);
    // ENCRYPTION option header.
    body.put_u8(0x01);
    body.put_u16(17);
    body.put_u16(1);
    // Terminator.
    body.put_u8(0xff);
    // VERSION data: 15.0.4153.1.
    body.put_u8(15);
    body.put_u8(0);
    body.put_u16_le(4153);
    body.put_u16_le(1);
    // ENCRYPTION data: 0x02 = ENCRYPT_NOT_SUP.
    body.put_u8(0x02);
    body.to_vec()
}

/// Parse the ENCRYPTION option byte out of an upstream PRELOGIN
/// response body. Returns `Some(byte)` or `None` if the response
/// shape doesn't include the ENCRYPTION option.
fn parse_prelogin_encryption(body: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i < body.len() && body[i] != 0xff {
        if i + 5 > body.len() { return None; }
        let opt_type = body[i];
        let offset = u16::from_be_bytes([body[i + 1], body[i + 2]]) as usize;
        let length = u16::from_be_bytes([body[i + 3], body[i + 4]]) as usize;
        if opt_type == 0x01 {
            // ENCRYPTION
            if offset >= body.len() || offset + length > body.len() || length == 0 {
                return None;
            }
            return Some(body[offset]);
        }
        i += 5;
    }
    None
}

// ---------------------------------------------------------------------------
// LOGIN7 builder
// ---------------------------------------------------------------------------

/// Build a LOGIN7 packet body for SQL Authentication.
///
/// Reference: `[MS-TDS] 2.2.6.4`. We advertise TDS 7.4 (the version
/// SQL Server 2014 and later speak). The packet shape is:
///
///   * Fixed 36-byte header with packet length, TDS version, etc.
///   * 12 OffsetLength tuples pointing into the variable-length
///     section.
///   * Variable-length data carrying client name, username,
///     password (XOR-and-nibble-swapped), app name, server name,
///     unused interface lib name, language, database name, client
///     ID (6 bytes), SSPI data (we send empty), AttachDBFile path,
///     ChangePassword (we send empty), SSPI long.
fn build_login7(user: &str, password: &[u8], database: Option<&str>) -> Vec<u8> {
    // UTF-16 LE encoded variable-length fields.
    let client_name = utf16_le("raxis-mssql-proxy");
    let user_utf16  = utf16_le(user);
    let pw_obf      = obfuscate_password(password);
    let app_name    = utf16_le("raxis-proxy-v2");
    let server_name = utf16_le("");
    let unused      = utf16_le("");
    let lib_name    = utf16_le("raxis-tds");
    let language    = utf16_le("");
    let db_name     = utf16_le(database.unwrap_or(""));
    let attach_file = utf16_le("");
    let change_pw   = utf16_le("");

    // Per `[MS-TDS] 2.2.6.4`, LOGIN7 has:
    //   * 36-byte fixed header (Length .. ClientLCID).
    //   * 9 OffsetLength tuples for: HostName, UserName, Password,
    //     AppName, ServerName, Unused/Extension, CltIntName,
    //     Language, Database (4 bytes each, 36 bytes total).
    //   * 6-byte ClientID (inline, no tuple — typically the MAC
    //     address; we use the process ID padded out).
    //   * 3 OffsetLength tuples for: SSPI, AttachDBFile,
    //     ChangePassword (12 bytes total).
    //   * 4-byte cbSSPILong (32-bit length when SSPI > 64 KiB; we
    //     never use SSPI so this is 0).
    //
    // Fixed + tuples + ClientID + cbSSPILong = 36 + 36 + 6 + 12 + 4 = 94.

    const FIXED_LEN: usize = 36 + 36 + 6 + 12 + 4;
    let var_offset = FIXED_LEN;
    let mut variable: Vec<u8> = Vec::new();

    let push = |buf: &mut Vec<u8>, var: &[u8]| -> (u16, u16) {
        let off = var_offset + buf.len();
        let chars = var.len() / 2;
        buf.extend_from_slice(var);
        (off as u16, chars as u16)
    };
    let t_host  = push(&mut variable, &client_name);
    let t_user  = push(&mut variable, &user_utf16);
    // Password's "char count" tuple counts UTF-16 code units, not
    // bytes (the obf has 2 bytes per code unit, so chars = bytes/2,
    // which is what `push()` already returns).
    let t_pwd   = push(&mut variable, &pw_obf);
    let t_app   = push(&mut variable, &app_name);
    let t_srv   = push(&mut variable, &server_name);
    let t_unused = push(&mut variable, &unused);
    let t_lib   = push(&mut variable, &lib_name);
    let t_lang  = push(&mut variable, &language);
    let t_db    = push(&mut variable, &db_name);
    let t_sspi  = push(&mut variable, &[][..]);
    let t_attach = push(&mut variable, &attach_file);
    let t_chgpw = push(&mut variable, &change_pw);
    let tuples = [
        t_host, t_user, t_pwd, t_app, t_srv, t_unused,
        t_lib, t_lang, t_db,
    ];
    let tail_tuples = [t_sspi, t_attach, t_chgpw];

    let total_len = FIXED_LEN + variable.len();
    let mut out = Vec::with_capacity(total_len);
    // Fixed section (36 bytes):
    //   length:u32 LE = total_len
    //   tds_version:u32 LE = 0x74000004 (TDS 7.4)
    //   packet_size:u32 LE
    //   client_pid:u32 LE
    //   conn_id:u32 LE
    //   option_flags1:u8
    //   option_flags2:u8
    //   type_flags:u8
    //   option_flags3:u8
    //   client_time_zone:i32 LE
    //   client_lcid:u32 LE
    out.extend_from_slice(&(total_len as u32).to_le_bytes());
    out.extend_from_slice(&0x74_00_00_04u32.to_le_bytes()); // TDS 7.4
    out.extend_from_slice(&4096u32.to_le_bytes());          // PacketSize
    out.extend_from_slice(&0u32.to_le_bytes());             // ClientProgVer
    out.extend_from_slice(&(std::process::id() as u32).to_le_bytes()); // ClientPID
    out.extend_from_slice(&0u32.to_le_bytes());             // ConnectionID
    out.push(0x00); // option_flags1
    out.push(0x03); // option_flags2: ODBC=1, USER_SQL_AUTH (high bits 0)
    out.push(0x00); // type_flags
    out.push(0x00); // option_flags3
    out.extend_from_slice(&0i32.to_le_bytes()); // ClientTimZone
    out.extend_from_slice(&0u32.to_le_bytes()); // ClientLCID
    // 9 OffsetLength tuples (HostName .. Database).
    for (off, len) in &tuples {
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
    }
    // ClientID: 6 bytes inline. Use the process id padded to 6.
    let pid = std::process::id();
    out.extend_from_slice(&pid.to_le_bytes());
    out.extend_from_slice(&[0u8; 2]);
    // 3 trailing OffsetLength tuples (SSPI / AttachDBFile /
    // ChangePassword).
    for (off, len) in &tail_tuples {
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
    }
    // cbSSPILong (32-bit length for SSPI when its 16-bit field
    // would overflow). We never use SSPI.
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&variable);
    debug_assert_eq!(out.len(), total_len);
    out
}

/// Encode a string as UTF-16 LE bytes (2 bytes per code unit, no BOM).
fn utf16_le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// `[MS-TDS] 2.2.6.4`: passwords in LOGIN7 are nibble-swapped and
/// XORed with 0xA5 — not real encryption, but this is what the
/// protocol requires.
fn obfuscate_password(password: &[u8]) -> Vec<u8> {
    let utf16 = String::from_utf8_lossy(password);
    let units: Vec<u16> = utf16.encode_utf16().collect();
    let mut out = Vec::with_capacity(units.len() * 2);
    for u in units {
        let lo = (u & 0x00ff) as u8;
        let hi = ((u & 0xff00) >> 8) as u8;
        let lo_swap = ((lo & 0x0f) << 4) | ((lo & 0xf0) >> 4);
        let hi_swap = ((hi & 0x0f) << 4) | ((hi & 0xf0) >> 4);
        out.push(lo_swap ^ 0xA5);
        out.push(hi_swap ^ 0xA5);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_full() {
        let p = ParsedUpstreamUrl::parse("mssql://sa:hunter2@db:1433/master").unwrap();
        assert_eq!(p.host, "db");
        assert_eq!(p.port, 1433);
        assert_eq!(p.user, "sa");
        assert_eq!(p.password_bytes(), b"hunter2");
        assert_eq!(p.database.as_deref(), Some("master"));
        assert!(!p.require_tls);
    }

    #[test]
    fn parse_url_default_port() {
        let p = ParsedUpstreamUrl::parse("mssql://sa:hunter2@db/master").unwrap();
        assert_eq!(p.port, 1433);
    }

    #[test]
    fn parse_url_sqlserver_alias() {
        let p = ParsedUpstreamUrl::parse("sqlserver://sa:hunter2@db/test").unwrap();
        assert_eq!(p.host, "db");
        assert_eq!(p.user, "sa");
    }

    #[test]
    fn parse_url_encrypt_true_marks_tls() {
        let p = ParsedUpstreamUrl::parse(
            "mssql://sa:hunter2@db/test?encrypt=true",
        ).unwrap();
        assert!(p.require_tls);
    }

    #[test]
    fn parse_url_rejects_bad_scheme() {
        let err = ParsedUpstreamUrl::parse("postgresql://x").unwrap_err();
        match err {
            UpstreamError::InvalidUrl(_) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn parse_url_rejects_empty_host() {
        let err = ParsedUpstreamUrl::parse("mssql://sa:hunter2@:1433/db").unwrap_err();
        match err {
            UpstreamError::InvalidUrl(_) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn parse_url_percent_decodes_password() {
        let p = ParsedUpstreamUrl::parse("mssql://sa:hunter%402@db/test").unwrap();
        assert_eq!(p.password_bytes(), b"hunter@2");
    }

    #[test]
    fn redact_password_query_param() {
        let s = "url=mssql://h?password=hunter2&user=foo";
        let red = redact_for_audit(s);
        assert!(red.contains("password=[REDACTED]"));
        assert!(!red.contains("hunter2"));
    }

    #[test]
    fn redact_password_in_userinfo() {
        let s = "auth failed for mssql://sa:hunter2@db/foo";
        let red = redact_for_audit(s);
        assert!(red.contains("[REDACTED]"));
        assert!(!red.contains("hunter2"));
    }

    #[test]
    fn audit_reason_mapping() {
        assert_eq!(
            UpstreamError::TcpConnect("x".into()).audit_reason(),
            "TcpConnectFailed",
        );
        assert_eq!(
            UpstreamError::AuthRejected("x".into()).audit_reason(),
            "AuthRejected",
        );
        assert_eq!(
            UpstreamError::Handshake("x".into()).audit_reason(),
            "ProtocolHandshakeFailed",
        );
        assert_eq!(
            UpstreamError::Timeout { timeout_ms: 1 }.audit_reason(),
            "Timeout",
        );
    }

    #[test]
    fn obfuscate_password_round_trip() {
        // "abc" → SQL Server's documented obfuscation: each char's
        // UTF-16 LE bytes get nibble-swapped and XORed with 0xA5.
        // 'a' = 0x0061 → lo=0x61, hi=0x00.
        //   lo nibble-swap = 0x16, ^0xA5 = 0xB3.
        //   hi nibble-swap = 0x00, ^0xA5 = 0xA5.
        let obf = obfuscate_password(b"abc");
        assert_eq!(obf.len(), 6);
        assert_eq!(obf[0], 0xB3);
        assert_eq!(obf[1], 0xA5);
    }

    #[test]
    fn build_login7_carries_username_in_utf16() {
        let pkt = build_login7("sa", b"hunter2", Some("master"));
        // Find the LE-encoded "sa" in the packet (0x73 0x00 0x61 0x00).
        let needle = [b's', 0, b'a', 0];
        assert!(pkt.windows(needle.len()).any(|w| w == needle));
        let needle_db = [b'm', 0, b'a', 0, b's', 0, b't', 0, b'e', 0, b'r', 0];
        assert!(pkt.windows(needle_db.len()).any(|w| w == needle_db));
    }

    #[test]
    fn parse_prelogin_encryption_finds_byte() {
        let body = build_prelogin_request_body();
        // Our own request body has ENC=0x02 at offset 17.
        assert_eq!(parse_prelogin_encryption(&body), Some(0x02));
    }

    #[test]
    fn scan_first_error_token_recovers_message() {
        let body = crate::wire::build_error_done_body(-9, "denied");
        let (n, m) = scan_first_error_token(&body).expect("ERROR token");
        assert_eq!(n, -9);
        assert_eq!(m, "denied");
    }

    /// V2.1 regression pin: every SQLBatch the proxy forwards to the
    /// upstream MUST begin with a TDS 7.4-compliant `ALL_HEADERS`
    /// preamble (`TotalLength = 22`, one Transaction Descriptor
    /// header with `HeaderType = 0x0002`).
    ///
    /// The agent in the live-e2e harness sends `TotalLength = 4` (no
    /// inner headers); SQL Server 2022 rejects this with the
    /// "MARS TDS header is missing" `ERROR` token. The proxy must
    /// rewrite ALL_HEADERS unconditionally before forwarding.
    #[test]
    fn rewrite_sql_batch_injects_transaction_descriptor_header() {
        use crate::wire::{frame_packet, pkt};
        // Agent body: TotalLength = 4 (degenerate ALL_HEADERS),
        // followed by "SELECT 1" UTF-16 LE.
        let mut agent_body = Vec::new();
        agent_body.extend_from_slice(&4u32.to_le_bytes());
        for u in "SELECT 1".encode_utf16() {
            agent_body.extend_from_slice(&u.to_le_bytes());
        }
        let agent_pkt = frame_packet(pkt::SQL_BATCH, &agent_body);
        let rewritten = rewrite_sql_batch_for_upstream(&agent_pkt).unwrap();
        // Rewritten body starts at offset 8 (TDS header). Must have
        // TotalLength = 22.
        let rewritten_body = &rewritten[8..];
        let total = u32::from_le_bytes([
            rewritten_body[0], rewritten_body[1],
            rewritten_body[2], rewritten_body[3],
        ]);
        assert_eq!(total, 22, "ALL_HEADERS TotalLength must be 22");
        // HeaderLength = 18.
        let hlen = u32::from_le_bytes([
            rewritten_body[4], rewritten_body[5],
            rewritten_body[6], rewritten_body[7],
        ]);
        assert_eq!(hlen, 18, "Transaction Descriptor HeaderLength must be 18");
        // HeaderType = 0x0002 (Transaction Descriptor).
        let htype = u16::from_le_bytes([rewritten_body[8], rewritten_body[9]]);
        assert_eq!(htype, 0x0002, "HeaderType must be 0x0002");
        // TransactionDescriptor bytes 10..18 are zero.
        assert_eq!(&rewritten_body[10..18], &[0u8; 8]);
        // OutstandingRequestCount bytes 18..22 = 1.
        let ors = u32::from_le_bytes([
            rewritten_body[18], rewritten_body[19],
            rewritten_body[20], rewritten_body[21],
        ]);
        assert_eq!(ors, 1, "OutstandingRequestCount must be 1");
        // SQL text "SELECT 1" UTF-16 LE follows the ALL_HEADERS.
        let sql_bytes = &rewritten_body[22..];
        let units: Vec<u16> = sql_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16(&units).unwrap();
        assert_eq!(s, "SELECT 1");
    }

    /// Defensive: an agent that omits ALL_HEADERS entirely (TDS
    /// 7.0/7.1 shape, body is just the UTF-16 SQL text) must still
    /// be rewritten to the proper TDS 7.4 form, with the entire
    /// agent body treated as SQL text.
    #[test]
    fn rewrite_sql_batch_when_agent_omits_all_headers() {
        use crate::wire::{frame_packet, pkt};
        let mut agent_body = Vec::new();
        for u in "SELECT 2".encode_utf16() {
            agent_body.extend_from_slice(&u.to_le_bytes());
        }
        let agent_pkt = frame_packet(pkt::SQL_BATCH, &agent_body);
        let rewritten = rewrite_sql_batch_for_upstream(&agent_pkt).unwrap();
        let body = &rewritten[8..];
        // Slice out the SQL bytes.
        let sql_bytes = &body[22..];
        let units: Vec<u16> = sql_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        // Note: the first 16-bit word from the agent's body becomes
        // the synthetic TotalLength when we treat the body as
        // ALL_HEADERS-prefixed in `extract_sql_text_bytes`. We
        // explicitly designed the helper to fall through to "treat
        // whole body as SQL" when `total_headers > body.len()` AND
        // when `total_headers <= 3`.  For "SELECT 2" UTF-16, the
        // first 4 bytes are `53 00 45 00` = 0x00450053 = 4521987,
        // which is > body.len(), so the fallback fires correctly.
        assert_eq!(String::from_utf16(&units).unwrap(), "SELECT 2");
    }

    /// A malformed packet (shorter than the TDS header) must be
    /// rejected with `RelayFailed`; the proxy must not panic.
    #[test]
    fn rewrite_sql_batch_rejects_truncated_packet() {
        let truncated = vec![0x01u8, 0x01, 0x00];
        let res = rewrite_sql_batch_for_upstream(&truncated);
        match res {
            Err(UpstreamError::RelayFailed(msg)) => {
                assert!(msg.contains("shorter than TDS header"),
                    "unexpected error message: {msg}");
            }
            other => panic!("expected RelayFailed, got {other:?}"),
        }
    }

    /// A packet whose header type is NOT SQLBatch must be rejected.
    /// This protects against `forward_sql_batch` being mis-called
    /// with a LOGIN7 / PRELOGIN packet, which would silently corrupt
    /// the upstream session.
    #[test]
    fn rewrite_sql_batch_rejects_non_sqlbatch_header() {
        use crate::wire::{frame_packet, pkt};
        let pkt = frame_packet(pkt::PRELOGIN, &[0u8; 4]);
        let res = rewrite_sql_batch_for_upstream(&pkt);
        match res {
            Err(UpstreamError::RelayFailed(msg)) => {
                assert!(msg.contains("expected SQLBatch"),
                    "unexpected error message: {msg}");
            }
            other => panic!("expected RelayFailed, got {other:?}"),
        }
    }
}
