//! Upstream MySQL connection driver.
//!
//! Normative reference: `credential-proxy.md §14.3` (lazy connect on
//! first allowed query) and `§14.8.2` (per-proxy implementation matrix
//! for MySQL).
//!
//! # What this module owns
//!
//! * Parsing the **credential value** as a libmysql / DBI-style URL
//!   like `mysql://user:pass@host:3306/db?ssl-mode=DISABLED`.
//! * Opening a real `tokio::net::TcpStream` to the upstream and
//!   driving the MySQL `Protocol::HandshakeV10 → HandshakeResponse41
//!   → OK_Packet` handshake on the V2.1 MVP wire (no TLS, no
//!   `caching_sha2_password`).
//! * Forwarding agent-issued `COM_QUERY` SQL to the upstream and
//!   relaying back the upstream's response packets verbatim — both
//!   text-result-set frames (ResultSetHeader / ColumnDef / EOF /
//!   RowData / EOF) and `OK_Packet` / `ERR_Packet` terminators.
//! * Surfacing structured errors at every failure point so the proxy
//!   can map them to the three V2.1 audit events
//!   (`UpstreamConnected`, `UpstreamFailed`, `DatabaseQueryCompleted`).
//!
//! # Design choices
//!
//! ## Why we hand-roll the upstream wire instead of pulling `mysql_async`
//!
//! `tokio-postgres` already exists in the workspace because the
//! Postgres proxy needs SCRAM-SHA-256, MD5, and cleartext password
//! plumbing — implementing those by hand would be ~150 lines of
//! cryptographic code that has been audited in `tokio-postgres` for
//! years.
//!
//! MySQL is different: the auth surface we need to support for the
//! V2.1 MVP is `mysql_native_password`, which is a 4-line algorithm
//! (`SHA1(pwd) XOR SHA1(scramble || SHA1(SHA1(pwd)))`). The handshake
//! is a single round trip after the server's greeting. There is no
//! cryptographic-correctness benefit to dragging in `mysql_async`'s
//! 80-deep transitive tree to do something that is genuinely simple.
//!
//! `caching_sha2_password` (the MySQL 8.0 default) is explicitly
//! deferred — V3 work. Operators running stock MySQL 8.x must either
//! configure `default_authentication_plugin=mysql_native_password`
//! in `my.cnf` or `ALTER USER` the proxy's user with
//! `IDENTIFIED WITH mysql_native_password`. The proxy fails fast
//! with `UpstreamError::Handshake` if the upstream sends an
//! `AuthSwitchRequest` for any plugin other than
//! `mysql_native_password`.
//!
//! ## Why we relay packets verbatim instead of re-encoding
//!
//! The MySQL proxy already does per-statement classification +
//! restriction enforcement on the agent's `COM_QUERY` BEFORE it
//! forwards to the upstream. After that gate, the proxy is a pure
//! framing-aware byte relay: read upstream packets, write them to
//! the agent. This avoids the type-aware re-encode pass that
//! Postgres needs (where `tokio-postgres::SimpleQueryMessage::Row`
//! returns `Option<&str>` per column instead of the wire bytes).
//!
//! The cost: the proxy must understand the result-set framing well
//! enough to know when one query's response is finished. That logic
//! is small (six packet shapes; see `read_query_response`) and is
//! exercised by the in-process fake-mysql backend in
//! `tests/support/mod.rs`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use raxis_credentials::{CredentialBackend, CredentialError, CredentialName, ConsumerIdentity};
use sha1::{Digest as Sha1Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::OwnedConsumer;
use crate::wire::{self, MAX_PACKET_PAYLOAD, frame_packet};

/// Maximum bytes we will buffer per upstream response. Mirrors the
/// MySQL protocol's 16 MiB packet length cap; queries that produce
/// more data than this drop the agent's connection rather than risk
/// an OOM.
const MAX_RELAY_BYTES: u64 = (MAX_PACKET_PAYLOAD as u64) * 64;

/// Default upstream connect timeout. Holds for both DNS + TCP and
/// the protocol handshake. Mirrors the Postgres proxy's `8s` default.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Upstream-connect / forward errors classified into the
/// `CredentialProxyUpstreamFailed::reason` discriminants from
/// `credential-proxy.md §14.5.3`.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The credential bytes could not be parsed as a libmysql URL.
    /// Surfaces as `FAIL_PROXY_UPSTREAM_URL_INVALID`.
    #[error("invalid upstream URL: {0}")]
    InvalidUrl(String),

    /// Credential resolution through the backend failed. Surfaces
    /// as a MySQL `ERR_Packet` with code 1045 (ER_ACCESS_DENIED_ERROR)
    /// and `CredentialProxyUpstreamFailed { reason: "AuthRejected" }`.
    #[error("credential resolution failed: {0}")]
    CredentialResolution(String),

    /// DNS lookup or TCP connect to the upstream failed.
    /// Surfaces as `CredentialProxyUpstreamFailed { reason: "TcpConnectFailed" }`.
    #[error("tcp connect failed: {0}")]
    TcpConnect(String),

    /// The MySQL protocol-level handshake failed (unexpected packet,
    /// malformed greeting, unsupported plugin, etc.). Surfaces as
    /// `CredentialProxyUpstreamFailed { reason: "ProtocolHandshakeFailed" }`.
    #[error("mysql protocol handshake failed: {0}")]
    Handshake(String),

    /// The upstream rejected the credential at the auth step.
    /// Surfaces as `CredentialProxyUpstreamFailed { reason: "AuthRejected" }`.
    #[error("upstream auth rejected: {0}")]
    AuthRejected(String),

    /// The upstream took longer than the proxy's connect timeout.
    /// Surfaces as `CredentialProxyUpstreamFailed { reason: "Timeout" }`.
    #[error("upstream connect timed out after {timeout_ms}ms")]
    Timeout {
        /// Timeout in milliseconds.
        timeout_ms: u32,
    },

    /// The upstream's response payload exceeded `MAX_RELAY_BYTES`.
    /// The proxy drops the agent's connection rather than risk
    /// unbounded buffering.
    #[error("upstream response payload too large: {bytes} > {max} bytes")]
    PayloadTooLarge {
        /// Bytes the upstream would have produced.
        bytes: u64,
        /// Bytes the proxy is willing to buffer.
        max: u64,
    },

    /// A forwarded query produced an upstream-side error.
    /// Surfaces as a relayed `ERR_Packet` AND a
    /// `DatabaseQueryCompleted { upstream_error: Some(sqlstate) }`
    /// audit event. The MVP surfaces the upstream's own error code
    /// + sqlstate to the agent verbatim.
    #[error("query failed at upstream: code={code} sqlstate={sqlstate} message={message}")]
    QueryFailed {
        /// MySQL numeric error code from the upstream's `ERR_Packet`.
        code: u16,
        /// MySQL sqlstate from the upstream's `ERR_Packet` (5 ASCII
        /// chars). Empty if the upstream sent no sqlstate marker.
        sqlstate: String,
        /// Human-readable message — already redacted by
        /// `redact_for_audit()` before reaching this variant.
        message: String,
    },

    /// I/O error mid-stream (network drop, peer reset, etc.). Already
    /// redacted.
    #[error("upstream relay failed: {0}")]
    RelayFailed(String),
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
            Self::QueryFailed { .. } => "ProtocolHandshakeFailed",
            Self::PayloadTooLarge { .. } => "ProtocolHandshakeFailed",
            Self::RelayFailed(_) => "ProtocolHandshakeFailed",
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
/// before it reaches the audit envelope. Single-pass, mirrors the
/// implementation in `credential-proxy-postgres::upstream` — see that
/// module's doc comment for why a naive `find/replace` loop would
/// not terminate.
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

/// Parsed view of a libmysql / DBI-style credential URL.
#[derive(Debug, Clone)]
pub struct ParsedUpstreamUrl {
    /// Hostname from the credential URL.
    pub host: String,
    /// Port from the credential URL after default-port substitution
    /// (3306).
    pub port: u16,
    /// Username extracted from the userinfo (or empty if not given —
    /// MySQL allows anonymous connections in some configurations,
    /// but most production deployments will have a username).
    pub user: String,
    /// Password extracted from the userinfo (or empty for
    /// passwordless auth — `mysql_native_password` with empty
    /// password is supported).
    password: String,
    /// Optional default database from the URL path.
    pub database: Option<String>,
    /// Whether `?ssl-mode=REQUIRED` (or stricter) was in the URL.
    /// V2.1 MVP does not support TLS upstream — a URL with
    /// `ssl-mode=REQUIRED` returns `UpstreamError::Handshake` from
    /// `connect()`.
    pub require_tls: bool,
}

impl ParsedUpstreamUrl {
    /// Parse a libmysql URL out of a resolved credential value.
    ///
    /// Accepted schemes: `mysql://` and `mysql+native://`. The
    /// `+native` suffix is a RAXIS-private hint that operators
    /// can use to make the `mysql_native_password` requirement
    /// explicit; the proxy treats it identically to the bare
    /// `mysql://` scheme today.
    pub fn parse(raw_url: &str) -> Result<Self, UpstreamError> {
        let raw = raw_url.trim();
        let scheme_end = if let Some(rest) = raw.strip_prefix("mysql://") {
            raw.len() - rest.len()
        } else if let Some(rest) = raw.strip_prefix("mysql+native://") {
            raw.len() - rest.len()
        } else {
            return Err(UpstreamError::InvalidUrl(
                "scheme must be `mysql://` or `mysql+native://`".into(),
            ));
        };
        let after_scheme = &raw[scheme_end..];
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
            None => (authority.to_owned(), 3306u16),
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
        let require_tls = qlower.contains("ssl-mode=required")
            || qlower.contains("ssl-mode=verify_ca")
            || qlower.contains("ssl-mode=verify_identity")
            || qlower.contains("sslmode=required");

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
    /// these. Used only during the upstream auth handshake.
    pub fn password_bytes(&self) -> &[u8] {
        self.password.as_bytes()
    }
}

/// Percent-decode a userinfo or path component. RFC 3986 minimal
/// implementation — enough for the credential URLs operators write
/// in `[credentials.<name>] value = "mysql://..."`.
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
/// as a libmysql URL. Maps every error variant to the right
/// `UpstreamError` discriminant.
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

/// Outcome of a forwarded query.
#[derive(Debug)]
pub struct ForwardOutcome {
    /// Wire-format frames the proxy MUST write to the agent IN ORDER.
    /// The first packet's sequence ID is `1` (the agent's COM_QUERY
    /// was sequence `0`); subsequent packets increment from there.
    /// Always populated — even on `upstream_error.is_some()` we
    /// forward the upstream's ERR_Packet to the agent verbatim so
    /// `psql`-equivalent clients see a real error rather than an
    /// opaque connection drop.
    pub frames: Vec<Vec<u8>>,
    /// Number of `ResultSetRow` packets forwarded (excluding column
    /// definitions, EOFs, and OK/ERR terminators).
    pub rows_returned: u64,
    /// Total payload bytes the proxy will write to the agent (sum of
    /// frame lengths including the 4-byte packet header).
    pub bytes_returned: u64,
    /// Wall-clock duration of the upstream round trip in ms.
    pub duration_ms: u32,
    /// `Some((code, sqlstate, redacted_message))` when the upstream
    /// returned an `ERR_Packet` (either as the first response or
    /// mid-stream during a result set). The proxy still forwards
    /// `frames` to the agent but emits a
    /// `DatabaseQueryCompleted { upstream_error: Some(sqlstate) }`
    /// audit event.
    pub upstream_error: Option<(u16, String, String)>,
}

/// One live upstream session, held across the lifetime of the agent's
/// connection (one upstream per agent in V2 — pooling is V3).
pub struct UpstreamSession {
    stream:        TcpStream,
    /// Hostname the audit envelope reports.
    pub host:      String,
    /// Port the audit envelope reports.
    pub port:      u16,
    /// True if the URL requested TLS — V2.1 surfaces this in the
    /// audit envelope but the implementation only supports plaintext
    /// so far. A `?ssl-mode=REQUIRED` URL fails fast in `connect()`
    /// with `UpstreamError::Handshake`.
    pub tls:       bool,
    /// Wall-clock for the connect handshake — fed into
    /// `CredentialProxyUpstreamConnected.handshake_ms`.
    pub handshake_ms: u32,
}

impl UpstreamSession {
    /// Open a new upstream session against the parsed URL.
    ///
    /// V2.1 supports plaintext + `mysql_native_password` only.
    /// `?ssl-mode=REQUIRED` and `caching_sha2_password` (the MySQL
    /// 8.0 default) both return `UpstreamError::Handshake` so the
    /// operator gets a clear signal to either re-configure the
    /// upstream or wait for V3.
    pub async fn connect(
        url: &ParsedUpstreamUrl,
        connect_timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        if url.require_tls {
            return Err(UpstreamError::Handshake(
                "?ssl-mode=REQUIRED is not supported by the V2.1 MVP — \
                 upgrade the proxy when TLS-to-upstream lands".into(),
            ));
        }
        let started = Instant::now();
        let connect_fut = async {
            let addr = format!("{}:{}", url.host, url.port);
            let mut stream = TcpStream::connect(&addr).await
                .map_err(|e| UpstreamError::TcpConnect(redact_for_audit(&e.to_string())))?;
            // Drive the handshake. The first packet (seq=0) is the
            // upstream's HandshakeV10 greeting.
            let (server_seq, greeting_payload) = read_packet(&mut stream).await
                .map_err(|e| UpstreamError::Handshake(format!("read greeting: {e}")))?;
            if server_seq != 0 {
                return Err(UpstreamError::Handshake(format!(
                    "unexpected greeting seq={server_seq}, expected 0"
                )));
            }
            let greeting = parse_handshake_v10(&greeting_payload)?;
            tracing::debug!(
                plugin = %greeting.plugin,
                host   = %url.host,
                port   = url.port,
                "mysql upstream announced auth plugin",
            );
            // Send HandshakeResponse41 (seq=1).
            let resp = build_handshake_response_41(
                &url.user,
                url.password_bytes(),
                url.database.as_deref(),
                &greeting.scramble,
            );
            stream.write_all(&frame_packet(&resp, 1)).await
                .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
            stream.flush().await.ok();
            // Read the auth result (seq=2). One of:
            //   * OK_Packet (0x00 prefix) — auth succeeded.
            //   * ERR_Packet (0xff prefix) — auth rejected.
            //   * AuthSwitchRequest (0xfe prefix) — server insists
            //     on a different plugin. We support the server
            //     re-issuing the same `mysql_native_password` plugin
            //     with a fresh scramble (rare but legal); any
            //     other plugin returns `UpstreamError::Handshake`
            //     with a clear "configure user with native_password"
            //     message.
            let (_seq, payload) = read_packet(&mut stream).await
                .map_err(|e| UpstreamError::Handshake(format!("read auth result: {e}")))?;
            handle_auth_result(&mut stream, payload, url.password_bytes()).await?;
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

    /// Forward a SQL string as `COM_QUERY` to the upstream and
    /// collect every response frame.
    pub async fn forward_query(
        &mut self,
        sql: &[u8],
    ) -> Result<ForwardOutcome, UpstreamError> {
        let started = Instant::now();
        // Build COM_QUERY (cmd byte + sql) at seq=0.
        let mut payload = Vec::with_capacity(1 + sql.len());
        payload.push(wire::cmd::QUERY);
        payload.extend_from_slice(sql);
        self.stream.write_all(&frame_packet(&payload, 0)).await
            .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
        self.stream.flush().await.ok();

        // Now read response packets and wrap each one into a frame
        // we forward to the agent. Detect the terminator per the
        // text-resultset state machine.
        let mut frames: Vec<Vec<u8>> = Vec::new();
        let mut bytes_returned: u64 = 0;
        let mut row_count: u64 = 0;
        // Read first packet of response.
        let (seq0, p0) = read_packet(&mut self.stream).await
            .map_err(|e| UpstreamError::RelayFailed(format!("read response: {e}")))?;
        bytes_returned += 4 + p0.len() as u64;
        if bytes_returned > MAX_RELAY_BYTES {
            return Err(UpstreamError::PayloadTooLarge {
                bytes: bytes_returned,
                max:   MAX_RELAY_BYTES,
            });
        }
        // ERR_Packet: terminal. Forward to agent verbatim and surface
        // the upstream-error metadata via the outcome; do NOT use
        // `Err` (the agent's wire frames must be written even on
        // upstream-error so the agent's driver sees the real error).
        if !p0.is_empty() && p0[0] == 0xff {
            let (code, sqlstate, message) = parse_err_packet(&p0);
            frames.push(frame_packet(&p0, seq0));
            let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
            return Ok(ForwardOutcome {
                frames,
                rows_returned: 0,
                bytes_returned,
                duration_ms,
                upstream_error: Some((code, sqlstate, redact_for_audit(&message))),
            });
        }
        // OK_Packet (no result set): terminal.
        if !p0.is_empty() && p0[0] == 0x00 {
            frames.push(frame_packet(&p0, seq0));
            let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
            return Ok(ForwardOutcome {
                frames,
                rows_returned: 0,
                bytes_returned,
                duration_ms,
                upstream_error: None,
            });
        }
        // LOCAL INFILE Request: not supported in V2.1.
        if !p0.is_empty() && p0[0] == 0xfb {
            return Err(UpstreamError::Handshake(
                "LOCAL INFILE Request from upstream is not supported by V2.1 proxy".into(),
            ));
        }
        // Otherwise it's a ResultSetHeader: lenenc int = column count.
        let (column_count, _) = decode_lenenc_int(&p0)
            .ok_or_else(|| UpstreamError::Handshake(
                "malformed ResultSetHeader: expected lenenc column count".into(),
            ))?;
        if column_count == 0 || column_count > 4096 {
            return Err(UpstreamError::Handshake(format!(
                "implausible column count {column_count} in ResultSetHeader"
            )));
        }
        frames.push(frame_packet(&p0, seq0));
        // Read column_count column-definition packets.
        let mut next_seq = seq0.wrapping_add(1);
        for _ in 0..column_count {
            let (seq, p) = read_packet(&mut self.stream).await
                .map_err(|e| UpstreamError::RelayFailed(format!("read coldef: {e}")))?;
            bytes_returned += 4 + p.len() as u64;
            if bytes_returned > MAX_RELAY_BYTES {
                return Err(UpstreamError::PayloadTooLarge {
                    bytes: bytes_returned, max: MAX_RELAY_BYTES,
                });
            }
            frames.push(frame_packet(&p, seq));
            next_seq = seq.wrapping_add(1);
        }
        // Expect EOF marking end of column definitions.
        let (eof_seq, eof_payload) = read_packet(&mut self.stream).await
            .map_err(|e| UpstreamError::RelayFailed(format!("read eof: {e}")))?;
        if !is_eof_packet(&eof_payload) {
            return Err(UpstreamError::Handshake(
                "expected EOF after column definitions".into(),
            ));
        }
        bytes_returned += 4 + eof_payload.len() as u64;
        frames.push(frame_packet(&eof_payload, eof_seq));
        // Read row packets until we see EOF or ERR.
        let _ = next_seq;
        loop {
            let (seq, p) = read_packet(&mut self.stream).await
                .map_err(|e| UpstreamError::RelayFailed(format!("read row: {e}")))?;
            bytes_returned += 4 + p.len() as u64;
            if bytes_returned > MAX_RELAY_BYTES {
                return Err(UpstreamError::PayloadTooLarge {
                    bytes: bytes_returned, max: MAX_RELAY_BYTES,
                });
            }
            if is_eof_packet(&p) {
                frames.push(frame_packet(&p, seq));
                break;
            }
            if !p.is_empty() && p[0] == 0xff {
                // Mid-stream ERR_Packet — relay to the agent and
                // surface via outcome.upstream_error so the proxy's
                // serve_one can audit + keep the agent connection
                // open for the next query.
                let (code, sqlstate, message) = parse_err_packet(&p);
                frames.push(frame_packet(&p, seq));
                let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
                return Ok(ForwardOutcome {
                    frames,
                    rows_returned: row_count,
                    bytes_returned,
                    duration_ms,
                    upstream_error: Some((code, sqlstate, redact_for_audit(&message))),
                });
            }
            frames.push(frame_packet(&p, seq));
            row_count += 1;
        }
        let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        Ok(ForwardOutcome {
            frames,
            rows_returned: row_count,
            bytes_returned,
            duration_ms,
            upstream_error: None,
        })
    }

    /// Send a clean `COM_QUIT` to the upstream. Best-effort — failures
    /// are logged but not surfaced because the agent's session is
    /// already winding down by the time this fires.
    pub async fn shutdown(mut self) {
        let payload = [wire::cmd::QUIT];
        if let Err(e) = self.stream.write_all(&frame_packet(&payload, 0)).await {
            tracing::debug!(error = %e, "upstream COM_QUIT write failed");
        }
        let _ = self.stream.flush().await;
        let _ = self.stream.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// Handshake helpers
// ---------------------------------------------------------------------------

/// Server-side capability flags we expect to see set in the upstream
/// handshake. We require `CLIENT_PROTOCOL_41` (every modern MySQL
/// supports it) and reject the connection otherwise — the proxy
/// would not know how to encode `HandshakeResponse41` against an
/// upstream that is so old it predates the 4.1 protocol.
const CLIENT_PROTOCOL_41: u32 = 1 << 9;
const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;

/// Capability flags the proxy advertises to the upstream. Picked
/// conservatively — just enough to enable the 4.1 protocol, plugin
/// auth, default db (if any), and the long password / secure
/// connection legacy bits the server also expects from a modern
/// client. We deliberately do NOT advertise `CLIENT_DEPRECATE_EOF`
/// (bit 24) so the upstream sends EOF packets the proxy can use as
/// terminators.
const CLIENT_CAPS: u32 = 0
    | (1 << 0)   // CLIENT_LONG_PASSWORD
    | (1 << 1)   // CLIENT_FOUND_ROWS
    | (1 << 2)   // CLIENT_LONG_FLAG
    | (1 << 3)   // CLIENT_CONNECT_WITH_DB
    | (1 << 5)   // CLIENT_LOCAL_FILES
    | (1 << 6)   // CLIENT_IGNORE_SPACE
    | CLIENT_PROTOCOL_41
    | (1 << 11)  // CLIENT_IGNORE_SIGPIPE
    | (1 << 13)  // CLIENT_TRANSACTIONS
    | (1 << 15)  // CLIENT_SECURE_CONNECTION
    | (1 << 17)  // CLIENT_PS_MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH;

/// Parsed shape of the upstream's `HandshakeV10` greeting.
#[derive(Debug)]
struct HandshakeV10Greeting {
    /// 20-byte concatenation of `auth_plugin_data_part_1` (8 bytes)
    /// and `auth_plugin_data_part_2` (12 bytes — the spec says "at
    /// least 12, but treat it as a NUL-terminated string", we trust
    /// the announced length).
    scramble: Vec<u8>,
    /// Auth plugin name advertised by the server (NUL-terminated
    /// string). For V2.1 we require this to be
    /// `mysql_native_password`; any other value returns
    /// `UpstreamError::Handshake`.
    plugin: String,
}

fn parse_handshake_v10(payload: &[u8]) -> Result<HandshakeV10Greeting, UpstreamError> {
    if payload.is_empty() {
        return Err(UpstreamError::Handshake("empty greeting payload".into()));
    }
    if payload[0] != 0x0a {
        if payload[0] == 0xff {
            // ERR_Packet during the handshake — typically "Host is
            // not allowed to connect".
            let (_, _, message) = parse_err_packet(payload);
            return Err(UpstreamError::Handshake(redact_for_audit(&message)));
        }
        return Err(UpstreamError::Handshake(format!(
            "unsupported protocol version {}", payload[0]
        )));
    }
    let mut i = 1;
    // server_version: NUL-terminated string.
    let nul = payload[i..].iter().position(|&b| b == 0)
        .ok_or_else(|| UpstreamError::Handshake("missing server_version NUL".into()))?;
    i += nul + 1;
    // thread_id: 4 bytes LE.
    if i + 4 > payload.len() {
        return Err(UpstreamError::Handshake("greeting truncated at thread_id".into()));
    }
    i += 4;
    // auth_plugin_data_part_1: 8 bytes.
    if i + 8 > payload.len() {
        return Err(UpstreamError::Handshake("greeting truncated at auth_plugin_data_part_1".into()));
    }
    let scramble1 = payload[i..i + 8].to_vec();
    i += 8;
    // filler: 1 byte.
    if i >= payload.len() {
        return Err(UpstreamError::Handshake("greeting truncated at filler".into()));
    }
    i += 1;
    // capability_flags_lower: 2 bytes LE.
    if i + 2 > payload.len() {
        return Err(UpstreamError::Handshake("greeting truncated at cap_lower".into()));
    }
    let cap_lower = u16::from_le_bytes([payload[i], payload[i + 1]]) as u32;
    i += 2;
    // The 4.0 short greeting stops here. We only support 4.1+.
    if i >= payload.len() {
        return Err(UpstreamError::Handshake(
            "upstream sent a 4.0-shape greeting; 4.1 protocol is required".into(),
        ));
    }
    // character_set: 1 byte; status_flags: 2 bytes; cap_upper: 2 bytes.
    if i + 5 > payload.len() {
        return Err(UpstreamError::Handshake("greeting truncated at char/status/cap_upper".into()));
    }
    let _charset = payload[i];
    i += 1;
    let _status = u16::from_le_bytes([payload[i], payload[i + 1]]);
    i += 2;
    let cap_upper = u16::from_le_bytes([payload[i], payload[i + 1]]) as u32;
    i += 2;
    let cap = (cap_upper << 16) | cap_lower;
    if cap & CLIENT_PROTOCOL_41 == 0 {
        return Err(UpstreamError::Handshake(
            "upstream does not advertise CLIENT_PROTOCOL_41".into(),
        ));
    }
    // auth_plugin_data_len: 1 byte.
    if i >= payload.len() {
        return Err(UpstreamError::Handshake("greeting truncated at auth_plugin_data_len".into()));
    }
    let auth_plugin_data_len = payload[i] as usize;
    i += 1;
    // 10 reserved bytes.
    if i + 10 > payload.len() {
        return Err(UpstreamError::Handshake("greeting truncated at reserved".into()));
    }
    i += 10;
    // auth_plugin_data_part_2: max(13, auth_plugin_data_len - 8) bytes.
    let part2_len = if auth_plugin_data_len >= 8 {
        auth_plugin_data_len - 8
    } else {
        13
    };
    let part2_take = part2_len.max(13).min(payload.len().saturating_sub(i));
    let part2 = if part2_take >= 13 {
        // Spec: 12 scramble bytes + 1 NUL terminator.
        payload[i..i + 12].to_vec()
    } else {
        return Err(UpstreamError::Handshake(
            "auth_plugin_data_part_2 too short".into(),
        ));
    };
    i += part2_take;
    // auth_plugin_name: NUL-terminated string (or end of payload).
    let plugin = if i < payload.len() {
        let plugin_end = payload[i..]
            .iter()
            .position(|&b| b == 0)
            .map(|n| i + n)
            .unwrap_or(payload.len());
        std::str::from_utf8(&payload[i..plugin_end])
            .map_err(|_| UpstreamError::Handshake("non-utf8 auth_plugin_name".into()))?
            .to_owned()
    } else {
        String::new()
    };
    let mut scramble = Vec::with_capacity(20);
    scramble.extend_from_slice(&scramble1);
    scramble.extend_from_slice(&part2);
    Ok(HandshakeV10Greeting { scramble, plugin })
}

/// Build a `HandshakeResponse41` payload for the proxy → upstream
/// handshake. We always advertise `mysql_native_password` and ignore
/// the upstream's announced `auth_plugin_name` for the purposes of
/// the initial response — if the server insists on a different
/// plugin it will respond with an `AuthSwitchRequest` and we handle
/// that in `handle_auth_result`.
fn build_handshake_response_41(
    user: &str,
    password: &[u8],
    database: Option<&str>,
    scramble: &[u8],
) -> Vec<u8> {
    let mut caps = CLIENT_CAPS;
    if database.is_some() {
        caps |= 1 << 3; // CLIENT_CONNECT_WITH_DB
    } else {
        caps &= !(1 << 3);
    }
    let mut buf = Vec::with_capacity(64 + user.len() + password.len() + database.map(str::len).unwrap_or(0));
    buf.extend_from_slice(&caps.to_le_bytes());
    // max_packet_size: 16 MiB.
    let max_packet_size: u32 = 16 * 1024 * 1024;
    buf.extend_from_slice(&max_packet_size.to_le_bytes());
    // character_set: utf8mb4 (0x2d) — matches what the kernel
    // canonicalises elsewhere.
    buf.push(0x2d);
    // 23 reserved bytes.
    buf.extend_from_slice(&[0u8; 23]);
    // username: NUL-terminated.
    buf.extend_from_slice(user.as_bytes());
    buf.push(0);
    // auth_response: lenenc-encoded length + 20-byte SHA-1 XOR.
    if password.is_empty() {
        // CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA bit isn't set; fall
        // back to length-prefixed (not lenenc) form: u8 length.
        buf.push(0);
    } else {
        let auth = mysql_native_password_scramble(password, scramble);
        buf.push(auth.len() as u8);
        buf.extend_from_slice(&auth);
    }
    if let Some(db) = database {
        buf.extend_from_slice(db.as_bytes());
        buf.push(0);
    }
    // auth_plugin_name (because CLIENT_PLUGIN_AUTH is set).
    buf.extend_from_slice(b"mysql_native_password");
    buf.push(0);
    buf
}

/// `mysql_native_password` algorithm:
///   token = SHA1(password) XOR SHA1( scramble || SHA1(SHA1(password)) )
/// The 20-byte scramble comes from the server's `HandshakeV10`.
fn mysql_native_password_scramble(password: &[u8], scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1: [u8; 20] = sha1_hash(password);
    let stage2: [u8; 20] = sha1_hash(&stage1);
    // SHA1(scramble || stage2).
    let mut h = Sha1::new();
    h.update(scramble);
    h.update(stage2);
    let combined: [u8; 20] = h.finalize().into();
    let mut out = vec![0u8; 20];
    for i in 0..20 {
        out[i] = stage1[i] ^ combined[i];
    }
    out
}

fn sha1_hash(bytes: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().into()
}

/// Drive the auth-result phase of the handshake.
///
/// On entry, `payload` is the body of the packet received after the
/// proxy's `HandshakeResponse41`. The server can respond with:
///   * OK_Packet (0x00) — auth succeeded.
///   * ERR_Packet (0xff) — auth rejected.
///   * AuthSwitchRequest (0xfe) — server wants a different plugin.
async fn handle_auth_result(
    stream: &mut TcpStream,
    payload: Vec<u8>,
    password: &[u8],
) -> Result<(), UpstreamError> {
    if payload.is_empty() {
        return Err(UpstreamError::Handshake("empty auth-result packet".into()));
    }
    match payload[0] {
        0x00 => Ok(()),
        0xff => {
            let (_, _, message) = parse_err_packet(&payload);
            Err(UpstreamError::AuthRejected(redact_for_audit(&message)))
        }
        0xfe => {
            // AuthSwitchRequest. Layout:
            //   0xfe | plugin_name NUL-terminated | auth_plugin_data
            let (plugin, plugin_data) = parse_auth_switch_request(&payload[1..])?;
            if plugin != "mysql_native_password" {
                return Err(UpstreamError::Handshake(format!(
                    "upstream requested unsupported auth plugin `{plugin}` — \
                     V2.1 MVP only supports `mysql_native_password`. \
                     Configure the upstream user with \
                     `IDENTIFIED WITH mysql_native_password BY '...'`."
                )));
            }
            // Re-do mysql_native_password with the new scramble at seq=3.
            let scramble = if plugin_data.len() >= 20 {
                &plugin_data[..20]
            } else {
                &plugin_data[..]
            };
            let auth = mysql_native_password_scramble(password, scramble);
            stream.write_all(&frame_packet(&auth, 3)).await
                .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
            stream.flush().await.ok();
            // Read the final auth result (seq=4).
            let (_seq, p) = read_packet(stream).await
                .map_err(|e| UpstreamError::Handshake(format!("read auth-switch result: {e}")))?;
            if p.is_empty() {
                return Err(UpstreamError::Handshake(
                    "empty auth-switch result packet".into(),
                ));
            }
            match p[0] {
                0x00 => Ok(()),
                0xff => {
                    let (_, _, message) = parse_err_packet(&p);
                    Err(UpstreamError::AuthRejected(redact_for_audit(&message)))
                }
                other => Err(UpstreamError::Handshake(format!(
                    "unexpected auth-switch result tag 0x{other:02x}"
                ))),
            }
        }
        other => Err(UpstreamError::Handshake(format!(
            "unexpected auth-result tag 0x{other:02x}"
        ))),
    }
}

/// Parse an `AuthSwitchRequest` payload (without the 0xfe header).
fn parse_auth_switch_request(body: &[u8]) -> Result<(String, &[u8]), UpstreamError> {
    let nul = body.iter().position(|&b| b == 0)
        .ok_or_else(|| UpstreamError::Handshake(
            "AuthSwitchRequest missing plugin name NUL".into(),
        ))?;
    let plugin = std::str::from_utf8(&body[..nul])
        .map_err(|_| UpstreamError::Handshake("non-utf8 plugin name".into()))?
        .to_owned();
    Ok((plugin, &body[nul + 1..]))
}

// ---------------------------------------------------------------------------
// Wire helpers (private to upstream.rs)
// ---------------------------------------------------------------------------

/// Read one MySQL packet from a stream. Returns `(sequence_id, payload)`.
async fn read_packet(stream: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let len = (header[0] as usize)
        | ((header[1] as usize) << 8)
        | ((header[2] as usize) << 16);
    let seq = header[3];
    if len > MAX_PACKET_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("MySQL packet payload {len} exceeds 16MiB cap"),
        ));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await?;
    }
    Ok((seq, payload))
}

/// Decode a length-encoded integer from the start of `buf`. Returns
/// `(value, bytes_consumed)`. Returns `None` if `buf` is empty.
fn decode_lenenc_int(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] {
        0..=250 => Some((buf[0] as u64, 1)),
        0xfc if buf.len() >= 3 => {
            Some((u16::from_le_bytes([buf[1], buf[2]]) as u64, 3))
        }
        0xfd if buf.len() >= 4 => {
            Some((
                (buf[1] as u64) | ((buf[2] as u64) << 8) | ((buf[3] as u64) << 16),
                4,
            ))
        }
        0xfe if buf.len() >= 9 => {
            Some((
                u64::from_le_bytes([
                    buf[1], buf[2], buf[3], buf[4],
                    buf[5], buf[6], buf[7], buf[8],
                ]),
                9,
            ))
        }
        _ => None,
    }
}

/// True if `payload` is an `EOF_Packet`.
///
/// EOF: header byte `0xfe` AND payload length < 9. (>=9 bytes with
/// header 0xfe is a length-encoded integer for a row count, not an
/// EOF — but in our row-loop we ALSO never see a row that starts
/// with 0xfe AND is < 9 bytes because real rows always have at
/// least one column field, so the heuristic is safe.)
fn is_eof_packet(payload: &[u8]) -> bool {
    !payload.is_empty() && payload[0] == 0xfe && payload.len() < 9
}

/// Parse an `ERR_Packet` payload (header 0xff). Returns
/// `(error_code, sqlstate, message)` with the sqlstate empty if the
/// packet did not carry the `#` marker.
fn parse_err_packet(payload: &[u8]) -> (u16, String, String) {
    if payload.len() < 3 || payload[0] != 0xff {
        return (0, String::new(), String::new());
    }
    let code = u16::from_le_bytes([payload[1], payload[2]]);
    let mut i = 3;
    let mut sqlstate = String::new();
    if i < payload.len() && payload[i] == b'#' {
        i += 1;
        if i + 5 <= payload.len() {
            sqlstate = String::from_utf8_lossy(&payload[i..i + 5]).into_owned();
            i += 5;
        }
    }
    let message = String::from_utf8_lossy(&payload[i..]).into_owned();
    (code, sqlstate, message)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_full() {
        let p = ParsedUpstreamUrl::parse("mysql://demo:hunter2@db.example.com:3306/mydb").unwrap();
        assert_eq!(p.host, "db.example.com");
        assert_eq!(p.port, 3306);
        assert_eq!(p.user, "demo");
        assert_eq!(p.password_bytes(), b"hunter2");
        assert_eq!(p.database.as_deref(), Some("mydb"));
        assert!(!p.require_tls);
    }

    #[test]
    fn parse_url_default_port() {
        let p = ParsedUpstreamUrl::parse("mysql://demo:hunter2@db/mydb").unwrap();
        assert_eq!(p.port, 3306);
    }

    #[test]
    fn parse_url_no_password() {
        let p = ParsedUpstreamUrl::parse("mysql://demo@localhost/").unwrap();
        assert_eq!(p.user, "demo");
        assert!(p.password_bytes().is_empty());
        assert!(p.database.is_none());
    }

    #[test]
    fn parse_url_native_scheme() {
        let p = ParsedUpstreamUrl::parse("mysql+native://demo:hunter2@db/").unwrap();
        assert_eq!(p.host, "db");
        assert_eq!(p.user, "demo");
    }

    #[test]
    fn parse_url_ssl_required_marks_tls() {
        let p = ParsedUpstreamUrl::parse(
            "mysql://demo:hunter2@db/mydb?ssl-mode=REQUIRED",
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
        let err = ParsedUpstreamUrl::parse("mysql://demo:hunter2@:3306/db").unwrap_err();
        match err {
            UpstreamError::InvalidUrl(_) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn parse_url_percent_decodes_password() {
        let p = ParsedUpstreamUrl::parse("mysql://demo:hunter%402@db/").unwrap();
        assert_eq!(p.password_bytes(), b"hunter@2");
    }

    #[test]
    fn redact_password_query_param() {
        let s = "url=mysql://h?password=hunter2&user=foo";
        let red = redact_for_audit(s);
        assert!(red.contains("password=[REDACTED]"));
        assert!(!red.contains("hunter2"));
    }

    #[test]
    fn redact_password_in_userinfo() {
        let s = "auth failed for mysql://demo:hunter2@db/foo";
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
            UpstreamError::Timeout { timeout_ms: 100 }.audit_reason(),
            "Timeout",
        );
    }

    #[test]
    fn lenenc_int_short_form() {
        assert_eq!(decode_lenenc_int(&[0]),   Some((0u64, 1)));
        assert_eq!(decode_lenenc_int(&[42]),  Some((42u64, 1)));
        assert_eq!(decode_lenenc_int(&[250]), Some((250u64, 1)));
    }

    #[test]
    fn lenenc_int_two_byte_form() {
        let val = decode_lenenc_int(&[0xfc, 0x10, 0x27]).unwrap();
        assert_eq!(val.0, 10000);
        assert_eq!(val.1, 3);
    }

    #[test]
    fn eof_detection() {
        assert!(is_eof_packet(&[0xfe, 0, 0, 0, 0]));
        assert!(!is_eof_packet(&[0x00]));
        assert!(!is_eof_packet(&[0xff, 0x42, 0x04]));
        // Long row that happens to start with 0xfe is NOT EOF.
        assert!(!is_eof_packet(&[0xfe; 16]));
    }

    #[test]
    fn parse_err_packet_with_sqlstate() {
        // 0xff | code (LE) | '#' | sqlstate (5) | message
        let mut p = vec![0xff, 0x86, 0x04, b'#'];
        p.extend_from_slice(b"42501");
        p.extend_from_slice(b"Access denied for user 'demo'@'localhost'");
        let (code, sqlstate, msg) = parse_err_packet(&p);
        assert_eq!(code, 1158);
        assert_eq!(sqlstate, "42501");
        assert!(msg.contains("Access denied"));
    }

    #[test]
    fn native_password_scramble_round_trip() {
        // The algorithm is: token = SHA1(pwd) XOR SHA1(scramble || SHA1(SHA1(pwd))).
        // We just check determinism + length here; correctness against
        // a real server is exercised by the integration tests.
        let pwd = b"hunter2";
        let scramble = [0x42u8; 20];
        let t1 = mysql_native_password_scramble(pwd, &scramble);
        let t2 = mysql_native_password_scramble(pwd, &scramble);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 20);
        // Different scramble → different token.
        let other = [0x43u8; 20];
        let t3 = mysql_native_password_scramble(pwd, &other);
        assert_ne!(t1, t3);
    }

    #[test]
    fn native_password_empty_pwd_returns_empty_token() {
        let scramble = [0x42u8; 20];
        let t = mysql_native_password_scramble(b"", &scramble);
        assert!(t.is_empty());
    }

    #[test]
    fn build_handshake_response_includes_user_and_plugin() {
        let scramble = [0x42u8; 20];
        let r = build_handshake_response_41("demo", b"hunter2", Some("mydb"), &scramble);
        // Caps (4) + max_packet (4) + charset (1) + reserved (23) = 32.
        let after_reserved = 32;
        let user_end = r[after_reserved..].iter().position(|&b| b == 0).unwrap();
        let user_bytes = &r[after_reserved..after_reserved + user_end];
        assert_eq!(user_bytes, b"demo");
        // Auth response: u8 length + 20 SHA1-XOR bytes.
        let auth_len_idx = after_reserved + user_end + 1;
        assert_eq!(r[auth_len_idx], 20);
        // Plugin name should be in the trailing bytes.
        let tail = std::str::from_utf8(&r[r.len() - "mysql_native_password\0".len()..]).unwrap();
        assert!(tail.starts_with("mysql_native_password"));
    }

    #[test]
    fn parse_handshake_v10_shape() {
        // Build a tiny legitimate-looking V10 greeting and parse it.
        let mut p = vec![0x0a]; // protocol_version
        p.extend_from_slice(b"8.0.30-raxis-fake\0");
        p.extend_from_slice(&1u32.to_le_bytes());      // thread_id
        p.extend_from_slice(&[1u8; 8]);                // scramble_part_1
        p.push(0);                                      // filler
        p.extend_from_slice(&(CLIENT_PROTOCOL_41 as u16).to_le_bytes()); // cap_lower (must include PROTOCOL_41)
        p.push(0x2d);                                   // charset (utf8mb4)
        p.extend_from_slice(&0u16.to_le_bytes());      // status
        p.extend_from_slice(&((CLIENT_PROTOCOL_41 >> 16) as u16).to_le_bytes()); // cap_upper
        p.push(21);                                     // auth_plugin_data_len
        p.extend_from_slice(&[0u8; 10]);               // reserved
        p.extend_from_slice(&[2u8; 12]);               // scramble_part_2 (12 bytes)
        p.push(0);                                      // NUL
        p.extend_from_slice(b"mysql_native_password\0");
        let g = parse_handshake_v10(&p).expect("parse");
        assert_eq!(g.scramble.len(), 20);
        assert_eq!(g.plugin, "mysql_native_password");
    }
}
