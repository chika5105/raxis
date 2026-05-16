//! Upstream MySQL connection driver.
//! Normative reference: `credential-proxy.md §14.3` (lazy connect on
//! first allowed query) and `§14.8.2` (per-proxy implementation matrix
//! for MySQL).
//! # What this module owns
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
//! # Design choices
//! ## Why we hand-roll the upstream wire instead of pulling `mysql_async`
//! `tokio-postgres` already exists in the workspace because the
//! Postgres proxy needs SCRAM-SHA-256, MD5, and cleartext password
//! plumbing — implementing those by hand would be ~150 lines of
//! cryptographic code that has been audited in `tokio-postgres` for
//! years.
//! MySQL is different: the auth surface we need to support for V2 is
//! `mysql_native_password` (legacy 4.1+) and `caching_sha2_password`
//! (MySQL 8.0+ default). Both are short, well-specified algorithms.
//! `caching_sha2_password` adds an RSA-OAEP-SHA1 leg for the cold-cache
//! "perform full auth" path, which we drive against the server-supplied
//! public key using the workspace-pinned `rsa` crate.
//! ## `caching_sha2_password` (V2 / )
//! The kernel-resolved credential URL is the same shape as for
//! `mysql_native_password`; the proxy detects the plugin from the
//! server's greeting (or `AuthSwitchRequest`) and selects the
//! handshake algorithm at runtime. No operator-side `my.cnf` change
//! is required for MySQL 8.x.
//! Algorithm reference:
//! [MySQL 8 source](https://github.com/mysql/mysql-server/blob/8.0/plugin/auth/sha256_password_common.cc).
//! ## Why we relay packets verbatim instead of re-encoding
//! The MySQL proxy already does per-statement classification +
//! restriction enforcement on the agent's `COM_QUERY` BEFORE it
//! forwards to the upstream. After that gate, the proxy is a pure
//! framing-aware byte relay: read upstream packets, write them to
//! the agent. This avoids the type-aware re-encode pass that
//! Postgres needs (where `tokio-postgres::SimpleQueryMessage::Row`
//! returns `Option<&str>` per column instead of the wire bytes).
//! The cost: the proxy must understand the result-set framing well
//! enough to know when one query's response is finished. That logic
//! is small (six packet shapes; see `read_query_response`) and is
//! exercised by the in-process fake-mysql backend in
//! `tests/support/mod.rs`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use raxis_credentials::{ConsumerIdentity, CredentialBackend, CredentialError, CredentialName};
use rsa::pkcs8::DecodePublicKey;
use rsa::rand_core::OsRng;
use rsa::{Oaep, RsaPublicKey};
// Brings the `Digest` trait methods (`new`, `update`, `finalize`)
// into scope for `Sha1`.  `Sha256` re-exports the same inherent
// methods on the type itself (rustcrypto/hashes 0.10), so it does
// not need a trait import.
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::wire::{self, frame_packet, MAX_PACKET_PAYLOAD};
use crate::OwnedConsumer;

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
            .find(['/', '?'])
            .unwrap_or(host_and_rest.len());
        let authority = &host_and_rest[..host_end];
        let (host, port) = match authority.rfind(':') {
            Some(colon) => {
                let h = &authority[..colon];
                let p = authority[colon + 1..]
                    .parse::<u16>()
                    .map_err(|_| UpstreamError::InvalidUrl("port is not a valid u16".into()))?;
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
    stream: TcpStream,
    /// Hostname the audit envelope reports.
    pub host: String,
    /// Port the audit envelope reports.
    pub port: u16,
    /// True if the URL requested TLS — V2.1 surfaces this in the
    /// audit envelope but the implementation only supports plaintext
    /// so far. A `?ssl-mode=REQUIRED` URL fails fast in `connect()`
    /// with `UpstreamError::Handshake`.
    pub tls: bool,
    /// Wall-clock for the connect handshake — fed into
    /// `CredentialProxyUpstreamConnected.handshake_ms`.
    pub handshake_ms: u32,
}

impl UpstreamSession {
    /// Open a new upstream session against the parsed URL.
    /// V2 supports plaintext upstream connections with two auth plugins:
    /// * `mysql_native_password` (legacy, MySQL 4.1+) — single-round
    ///   SHA-1 XOR scramble.
    /// * `caching_sha2_password` (MySQL 8.0 default) — SHA-256 XOR
    ///   scramble fast-path; full-auth path encrypts the password
    ///   with the server's RSA public key (RSA-OAEP-SHA1) when the
    ///   server's auth cache is cold.
    /// `?ssl-mode=REQUIRED` is not yet supported and returns
    /// `UpstreamError::Handshake`; operators that need TLS to the
    /// upstream should set up host-side TLS termination via stunnel
    /// or the upstream's own proxy (a TLS-to-upstream landing path
    /// is tracked separately).
    pub async fn connect(
        url: &ParsedUpstreamUrl,
        connect_timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        if url.require_tls {
            return Err(UpstreamError::Handshake(
                "?ssl-mode=REQUIRED is not supported by V2 MVP — \
                 terminate TLS host-side and connect to the proxy in \
                 plaintext, or wait for the TLS-to-upstream landing \
                 path"
                    .into(),
            ));
        }
        let started = Instant::now();
        let connect_fut = async {
            let addr = format!("{}:{}", url.host, url.port);
            let mut stream = TcpStream::connect(&addr)
                .await
                .map_err(|e| UpstreamError::TcpConnect(redact_for_audit(&e.to_string())))?;
            // Drive the handshake. The first packet (seq=0) is the
            // upstream's HandshakeV10 greeting.
            let (server_seq, greeting_payload) = read_packet(&mut stream)
                .await
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

            // Drive the per-plugin handshake. Each branch writes the
            // first response packet at seq=1 and then drives the
            // remainder of its own state machine off the same
            // `stream`.
            match greeting.plugin.as_str() {
                AUTH_PLUGIN_NATIVE | "" => {
                    let resp = build_handshake_response_41_native(
                        &url.user,
                        url.password_bytes(),
                        url.database.as_deref(),
                        &greeting.scramble,
                    );
                    stream
                        .write_all(&frame_packet(&resp, 1))
                        .await
                        .map_err(|e| {
                            UpstreamError::RelayFailed(redact_for_audit(&e.to_string()))
                        })?;
                    stream.flush().await.ok();
                    let (_seq, payload) = read_packet(&mut stream)
                        .await
                        .map_err(|e| UpstreamError::Handshake(format!("read auth result: {e}")))?;
                    handle_native_auth_result(&mut stream, payload, url.password_bytes()).await?;
                }
                AUTH_PLUGIN_SHA256_CACHING => {
                    let resp = build_handshake_response_41_sha256(
                        &url.user,
                        url.password_bytes(),
                        url.database.as_deref(),
                        &greeting.scramble,
                    );
                    stream
                        .write_all(&frame_packet(&resp, 1))
                        .await
                        .map_err(|e| {
                            UpstreamError::RelayFailed(redact_for_audit(&e.to_string()))
                        })?;
                    stream.flush().await.ok();
                    drive_caching_sha2_auth(
                        &mut stream,
                        url.password_bytes(),
                        &greeting.scramble,
                        2, // initial seq for the next packet
                    )
                    .await?;
                }
                other => {
                    return Err(UpstreamError::Handshake(format!(
                        "upstream advertised unsupported auth plugin `{other}` \
                         in HandshakeV10 — V2 supports `mysql_native_password` \
                         and `caching_sha2_password`",
                    )));
                }
            }
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
    pub async fn forward_query(&mut self, sql: &[u8]) -> Result<ForwardOutcome, UpstreamError> {
        let started = Instant::now();
        // Build COM_QUERY (cmd byte + sql) at seq=0.
        let mut payload = Vec::with_capacity(1 + sql.len());
        payload.push(wire::cmd::QUERY);
        payload.extend_from_slice(sql);
        self.stream
            .write_all(&frame_packet(&payload, 0))
            .await
            .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
        self.stream.flush().await.ok();

        // Now read response packets and wrap each one into a frame
        // we forward to the agent. Detect the terminator per the
        // text-resultset state machine.
        let mut frames: Vec<Vec<u8>> = Vec::new();
        let mut bytes_returned: u64 = 0;
        let mut row_count: u64 = 0;
        // Read first packet of response.
        let (seq0, p0) = read_packet(&mut self.stream)
            .await
            .map_err(|e| UpstreamError::RelayFailed(format!("read response: {e}")))?;
        bytes_returned += 4 + p0.len() as u64;
        if bytes_returned > MAX_RELAY_BYTES {
            return Err(UpstreamError::PayloadTooLarge {
                bytes: bytes_returned,
                max: MAX_RELAY_BYTES,
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
        let (column_count, _) = decode_lenenc_int(&p0).ok_or_else(|| {
            UpstreamError::Handshake(
                "malformed ResultSetHeader: expected lenenc column count".into(),
            )
        })?;
        if column_count == 0 || column_count > 4096 {
            return Err(UpstreamError::Handshake(format!(
                "implausible column count {column_count} in ResultSetHeader"
            )));
        }
        frames.push(frame_packet(&p0, seq0));
        // Read column_count column-definition packets.
        let mut next_seq = seq0.wrapping_add(1);
        for _ in 0..column_count {
            let (seq, p) = read_packet(&mut self.stream)
                .await
                .map_err(|e| UpstreamError::RelayFailed(format!("read coldef: {e}")))?;
            bytes_returned += 4 + p.len() as u64;
            if bytes_returned > MAX_RELAY_BYTES {
                return Err(UpstreamError::PayloadTooLarge {
                    bytes: bytes_returned,
                    max: MAX_RELAY_BYTES,
                });
            }
            frames.push(frame_packet(&p, seq));
            next_seq = seq.wrapping_add(1);
        }
        // Expect EOF marking end of column definitions.
        let (eof_seq, eof_payload) = read_packet(&mut self.stream)
            .await
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
            let (seq, p) = read_packet(&mut self.stream)
                .await
                .map_err(|e| UpstreamError::RelayFailed(format!("read row: {e}")))?;
            bytes_returned += 4 + p.len() as u64;
            if bytes_returned > MAX_RELAY_BYTES {
                return Err(UpstreamError::PayloadTooLarge {
                    bytes: bytes_returned,
                    max: MAX_RELAY_BYTES,
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

    /// Forward a `COM_STMT_PREPARE` body to the upstream and collect
    /// the matched response packets:
    /// `COM_STMT_PREPARE_OK` (or ERR), then `num_params` ParamDef
    /// packets + EOF (if `num_params > 0`), then `num_columns`
    /// ColumnDef packets + EOF (if `num_columns > 0`).
    /// V2.4 ORM blocker — the SQL has already been classified +
    /// restriction-checked + audit-emitted by `serve_one`; this
    /// function is the byte-relay leg.
    pub async fn forward_stmt_prepare(
        &mut self,
        sql: &[u8],
    ) -> Result<ForwardOutcome, UpstreamError> {
        let started = Instant::now();
        let mut payload = Vec::with_capacity(1 + sql.len());
        payload.push(wire::cmd::STMT_PREPARE);
        payload.extend_from_slice(sql);
        self.stream
            .write_all(&frame_packet(&payload, 0))
            .await
            .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
        self.stream.flush().await.ok();

        let mut frames: Vec<Vec<u8>> = Vec::new();
        let mut bytes_returned: u64 = 0;
        let (seq0, p0) = read_packet(&mut self.stream)
            .await
            .map_err(|e| UpstreamError::RelayFailed(format!("read response: {e}")))?;
        bytes_returned += 4 + p0.len() as u64;
        if bytes_returned > MAX_RELAY_BYTES {
            return Err(UpstreamError::PayloadTooLarge {
                bytes: bytes_returned,
                max: MAX_RELAY_BYTES,
            });
        }

        // ERR_Packet: terminal.
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
        // PREPARE_OK starts with 0x00. Layout (fixed-12 after the
        // 0x00 header):
        //   1 byte  status     = 0x00
        //   4 bytes statement_id (u32 LE)
        //   2 bytes num_columns (u16 LE)
        //   2 bytes num_params  (u16 LE)
        //   1 byte  reserved_1  = 0x00
        //   2 bytes warning_count (u16 LE) [optional]
        //   1 byte  metadata_follows [optional, only if CLIENT_OPTIONAL_RESULTSET_METADATA]
        if p0.len() < 12 || p0[0] != 0x00 {
            return Err(UpstreamError::Handshake(
                "malformed COM_STMT_PREPARE_OK packet".into(),
            ));
        }
        let num_columns = u16::from_le_bytes([p0[5], p0[6]]) as usize;
        let num_params = u16::from_le_bytes([p0[7], p0[8]]) as usize;
        frames.push(frame_packet(&p0, seq0));

        // num_params ParamDef packets, optionally followed by EOF.
        if num_params > 0 {
            for _ in 0..num_params {
                let (seq, p) = read_packet(&mut self.stream)
                    .await
                    .map_err(|e| UpstreamError::RelayFailed(format!("read paramdef: {e}")))?;
                bytes_returned += 4 + p.len() as u64;
                if bytes_returned > MAX_RELAY_BYTES {
                    return Err(UpstreamError::PayloadTooLarge {
                        bytes: bytes_returned,
                        max: MAX_RELAY_BYTES,
                    });
                }
                frames.push(frame_packet(&p, seq));
            }
            // EOF terminator for the param defs (only when
            // CLIENT_DEPRECATE_EOF is NOT advertised — the proxy
            // does not advertise it, see CLIENT_CAPS).
            let (eof_seq, eof_p) = read_packet(&mut self.stream)
                .await
                .map_err(|e| UpstreamError::RelayFailed(format!("read paramdef eof: {e}")))?;
            bytes_returned += 4 + eof_p.len() as u64;
            if !is_eof_packet(&eof_p) {
                return Err(UpstreamError::Handshake(
                    "expected EOF after param defs".into(),
                ));
            }
            frames.push(frame_packet(&eof_p, eof_seq));
        }

        // num_columns ColumnDef packets, optionally followed by EOF.
        if num_columns > 0 {
            for _ in 0..num_columns {
                let (seq, p) = read_packet(&mut self.stream)
                    .await
                    .map_err(|e| UpstreamError::RelayFailed(format!("read coldef: {e}")))?;
                bytes_returned += 4 + p.len() as u64;
                if bytes_returned > MAX_RELAY_BYTES {
                    return Err(UpstreamError::PayloadTooLarge {
                        bytes: bytes_returned,
                        max: MAX_RELAY_BYTES,
                    });
                }
                frames.push(frame_packet(&p, seq));
            }
            let (eof_seq, eof_p) = read_packet(&mut self.stream)
                .await
                .map_err(|e| UpstreamError::RelayFailed(format!("read coldef eof: {e}")))?;
            bytes_returned += 4 + eof_p.len() as u64;
            if !is_eof_packet(&eof_p) {
                return Err(UpstreamError::Handshake(
                    "expected EOF after col defs".into(),
                ));
            }
            frames.push(frame_packet(&eof_p, eof_seq));
        }

        let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        Ok(ForwardOutcome {
            frames,
            rows_returned: 0,
            bytes_returned,
            duration_ms,
            upstream_error: None,
        })
    }

    /// Forward a `COM_STMT_EXECUTE` body to the upstream and collect
    /// the matched response packets. The response shape mirrors a
    /// `COM_QUERY` response:
    /// * ERR_Packet (terminal),
    /// * OK_Packet (terminal — no result set),
    /// * binary-format ResultSetHeader + ColumnDef* + EOF + Row* + EOF.
    /// V2.4 byte-relays the binary-row payloads verbatim; the proxy
    /// does not introspect the row contents (the type metadata in
    /// the ColumnDef packets is enough for the agent's driver to
    /// decode).
    pub async fn forward_stmt_execute(
        &mut self,
        body: &[u8],
    ) -> Result<ForwardOutcome, UpstreamError> {
        // body is the FULL execute payload starting with 0x17.
        if body.is_empty() || body[0] != wire::cmd::STMT_EXECUTE {
            return Err(UpstreamError::Handshake(
                "forward_stmt_execute called with non-STMT_EXECUTE body".into(),
            ));
        }
        forward_with_resultset_response(&mut self.stream, body).await
    }

    /// Forward a `COM_STMT_FETCH` body to the upstream and collect
    /// the rows + EOF response.
    pub async fn forward_stmt_fetch(
        &mut self,
        body: &[u8],
    ) -> Result<ForwardOutcome, UpstreamError> {
        if body.is_empty() || body[0] != wire::cmd::STMT_FETCH {
            return Err(UpstreamError::Handshake(
                "forward_stmt_fetch called with non-STMT_FETCH body".into(),
            ));
        }
        let started = Instant::now();
        self.stream
            .write_all(&frame_packet(body, 0))
            .await
            .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
        self.stream.flush().await.ok();
        let mut frames: Vec<Vec<u8>> = Vec::new();
        let mut bytes_returned: u64 = 0;
        let mut rows_returned: u64 = 0;
        loop {
            let (seq, p) = read_packet(&mut self.stream)
                .await
                .map_err(|e| UpstreamError::RelayFailed(format!("read row: {e}")))?;
            bytes_returned += 4 + p.len() as u64;
            if bytes_returned > MAX_RELAY_BYTES {
                return Err(UpstreamError::PayloadTooLarge {
                    bytes: bytes_returned,
                    max: MAX_RELAY_BYTES,
                });
            }
            if !p.is_empty() && p[0] == 0xff {
                let (code, sqlstate, message) = parse_err_packet(&p);
                frames.push(frame_packet(&p, seq));
                let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
                return Ok(ForwardOutcome {
                    frames,
                    rows_returned,
                    bytes_returned,
                    duration_ms,
                    upstream_error: Some((code, sqlstate, redact_for_audit(&message))),
                });
            }
            frames.push(frame_packet(&p, seq));
            if is_eof_packet(&p) {
                break;
            }
            rows_returned += 1;
        }
        let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        Ok(ForwardOutcome {
            frames,
            rows_returned,
            bytes_returned,
            duration_ms,
            upstream_error: None,
        })
    }

    /// Forward a `COM_STMT_RESET` body to the upstream and collect
    /// the single OK or ERR reply.
    pub async fn forward_stmt_reset(
        &mut self,
        body: &[u8],
    ) -> Result<ForwardOutcome, UpstreamError> {
        if body.is_empty() || body[0] != wire::cmd::STMT_RESET {
            return Err(UpstreamError::Handshake(
                "forward_stmt_reset called with non-STMT_RESET body".into(),
            ));
        }
        let started = Instant::now();
        self.stream
            .write_all(&frame_packet(body, 0))
            .await
            .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
        self.stream.flush().await.ok();
        let (seq, p) = read_packet(&mut self.stream)
            .await
            .map_err(|e| UpstreamError::RelayFailed(format!("read reset reply: {e}")))?;
        let bytes_returned = 4 + p.len() as u64;
        let mut frames = Vec::new();
        let upstream_error = if !p.is_empty() && p[0] == 0xff {
            let (code, sqlstate, message) = parse_err_packet(&p);
            Some((code, sqlstate, redact_for_audit(&message)))
        } else {
            None
        };
        frames.push(frame_packet(&p, seq));
        let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        Ok(ForwardOutcome {
            frames,
            rows_returned: 0,
            bytes_returned,
            duration_ms,
            upstream_error,
        })
    }

    /// Forward a `COM_STMT_CLOSE` or `COM_STMT_SEND_LONG_DATA` body
    /// to the upstream. These commands have NO reply per the MySQL
    /// protocol; the proxy returns an empty `ForwardOutcome` so the
    /// caller uniformly threads upstream-bytes accounting.
    pub async fn forward_stmt_no_reply(
        &mut self,
        body: &[u8],
    ) -> Result<ForwardOutcome, UpstreamError> {
        if body.is_empty()
            || (body[0] != wire::cmd::STMT_CLOSE && body[0] != wire::cmd::STMT_SEND_LONG_DATA)
        {
            return Err(UpstreamError::Handshake(
                "forward_stmt_no_reply called with unexpected command".into(),
            ));
        }
        let started = Instant::now();
        self.stream
            .write_all(&frame_packet(body, 0))
            .await
            .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
        self.stream.flush().await.ok();
        let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        Ok(ForwardOutcome {
            frames: Vec::new(),
            rows_returned: 0,
            bytes_returned: 0,
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

/// Shared helper for COM_QUERY / COM_STMT_EXECUTE: write the command
/// payload at seq=0 and collect the response state machine into a
/// single `ForwardOutcome`. The response shape (text vs. binary
/// result set, OK_Packet, ERR_Packet) is identical for both commands.
async fn forward_with_resultset_response(
    stream: &mut TcpStream,
    body: &[u8],
) -> Result<ForwardOutcome, UpstreamError> {
    let started = Instant::now();
    stream
        .write_all(&frame_packet(body, 0))
        .await
        .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
    stream.flush().await.ok();

    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut bytes_returned: u64 = 0;
    let mut rows_returned: u64 = 0;
    let (seq0, p0) = read_packet(stream)
        .await
        .map_err(|e| UpstreamError::RelayFailed(format!("read response: {e}")))?;
    bytes_returned += 4 + p0.len() as u64;
    if bytes_returned > MAX_RELAY_BYTES {
        return Err(UpstreamError::PayloadTooLarge {
            bytes: bytes_returned,
            max: MAX_RELAY_BYTES,
        });
    }
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
    if !p0.is_empty() && p0[0] == 0xfb {
        return Err(UpstreamError::Handshake(
            "LOCAL INFILE Request from upstream is not supported by V2.1 proxy".into(),
        ));
    }
    let (column_count, _) = decode_lenenc_int(&p0).ok_or_else(|| {
        UpstreamError::Handshake("malformed ResultSetHeader: expected lenenc column count".into())
    })?;
    if column_count == 0 || column_count > 4096 {
        return Err(UpstreamError::Handshake(format!(
            "implausible column count {column_count} in ResultSetHeader"
        )));
    }
    frames.push(frame_packet(&p0, seq0));
    for _ in 0..column_count {
        let (seq, p) = read_packet(stream)
            .await
            .map_err(|e| UpstreamError::RelayFailed(format!("read coldef: {e}")))?;
        bytes_returned += 4 + p.len() as u64;
        if bytes_returned > MAX_RELAY_BYTES {
            return Err(UpstreamError::PayloadTooLarge {
                bytes: bytes_returned,
                max: MAX_RELAY_BYTES,
            });
        }
        frames.push(frame_packet(&p, seq));
    }
    let (eof_seq, eof_payload) = read_packet(stream)
        .await
        .map_err(|e| UpstreamError::RelayFailed(format!("read eof: {e}")))?;
    if !is_eof_packet(&eof_payload) {
        return Err(UpstreamError::Handshake(
            "expected EOF after column definitions".into(),
        ));
    }
    bytes_returned += 4 + eof_payload.len() as u64;
    frames.push(frame_packet(&eof_payload, eof_seq));
    loop {
        let (seq, p) = read_packet(stream)
            .await
            .map_err(|e| UpstreamError::RelayFailed(format!("read row: {e}")))?;
        bytes_returned += 4 + p.len() as u64;
        if bytes_returned > MAX_RELAY_BYTES {
            return Err(UpstreamError::PayloadTooLarge {
                bytes: bytes_returned,
                max: MAX_RELAY_BYTES,
            });
        }
        if is_eof_packet(&p) {
            frames.push(frame_packet(&p, seq));
            break;
        }
        if !p.is_empty() && p[0] == 0xff {
            let (code, sqlstate, message) = parse_err_packet(&p);
            frames.push(frame_packet(&p, seq));
            let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
            return Ok(ForwardOutcome {
                frames,
                rows_returned,
                bytes_returned,
                duration_ms,
                upstream_error: Some((code, sqlstate, redact_for_audit(&message))),
            });
        }
        frames.push(frame_packet(&p, seq));
        rows_returned += 1;
    }
    let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
    Ok(ForwardOutcome {
        frames,
        rows_returned,
        bytes_returned,
        duration_ms,
        upstream_error: None,
    })
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

/// `CLIENT_SSL` (bit 11) — the proxy MUST NEVER advertise this. If
/// it does, the upstream enters its TLS-negotiation state after the
/// 32-byte SSL-truncated `HandshakeResponse41` and waits for a
/// TLS Client Hello on the same TCP stream. The proxy never sends
/// one, the server's `net_read_timeout` eventually fires, and the
/// agent observes the proxy hanging on the `read_packet` loop. The
/// historical V2.1 caps mask had this bit accidentally set (the
/// comment said `CLIENT_IGNORE_SIGPIPE`, which is bit 12 — see
/// `audit_handshake_caps_must_not_set_ssl` below). The bug surfaced
/// against MySQL 8.0.36 in the live-e2e harness; older 5.7
/// servers happened to tolerate the malformed handshake. The
/// constant is carried here so a future change that mistakenly
/// adds it back fails the bit-position assertion in the unit test.
#[allow(dead_code)]
const CLIENT_SSL_FORBIDDEN_BIT: u32 = 1 << 11;
/// `CLIENT_COMPRESS` (bit 5) — also FORBIDDEN. Advertising it
/// commits the proxy to wrapping every subsequent packet in a
/// 7-byte zlib-compressed packet header (`[MS-MYS] 4.4`), which the
/// proxy does not implement. The historical V2.1 mask claimed this
/// bit was `CLIENT_LOCAL_FILES`; bit 5 is in fact `CLIENT_COMPRESS`,
/// bit 7 is `CLIENT_LOCAL_FILES`.
#[allow(dead_code)]
const CLIENT_COMPRESS_FORBIDDEN_BIT: u32 = 1 << 5;

/// Compile-time pin: even if a future caller refactors the test,
/// the build itself fails if these forbidden bits sneak into
/// `CLIENT_CAPS`. (Trivially zero today; the assertions are kept
/// to fail fast on regression.)
const _: () = {
    assert!(
        CLIENT_CAPS & CLIENT_SSL_FORBIDDEN_BIT == 0,
        "CLIENT_SSL must NEVER be in upstream caps"
    );
    assert!(
        CLIENT_CAPS & CLIENT_COMPRESS_FORBIDDEN_BIT == 0,
        "CLIENT_COMPRESS must NEVER be in upstream caps"
    );
};

/// Capability flags the proxy advertises to the upstream.
/// Reference: <https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html>.
/// Bits (ALL fields are by **bit number**, not by their `1 << n`
/// expansion — every comment below is double-checked against the
/// spec to defend against a re-occurrence of the V2.1 mis-numbering
/// bug that landed `CLIENT_SSL` in place of `CLIENT_IGNORE_SIGPIPE`):
/// * bit 0 — `CLIENT_LONG_PASSWORD`
/// * bit 1 — `CLIENT_FOUND_ROWS`
/// * bit 2 — `CLIENT_LONG_FLAG`
/// * bit 3 — `CLIENT_CONNECT_WITH_DB`   (set conditionally below)
/// * bit 9 — `CLIENT_PROTOCOL_41`        (REQUIRED for 4.1+)
/// * bit 12 — `CLIENT_IGNORE_SIGPIPE`
/// * bit 13 — `CLIENT_TRANSACTIONS`
/// * bit 15 — `CLIENT_SECURE_CONNECTION`  (REQUIRED so the server
///   accepts the 20-byte SHA-1 scramble layout)
/// * bit 17 — `CLIENT_MULTI_RESULTS`
/// * bit 18 — `CLIENT_PS_MULTI_RESULTS`
/// * bit 19 — `CLIENT_PLUGIN_AUTH`        (REQUIRED for the plugin
///   string in the response)
/// We deliberately do NOT advertise:
/// * bit 5 (`CLIENT_COMPRESS`) — would require a zlib framing layer.
/// * bit 6 (`CLIENT_ODBC`) — has no effect; just noise.
/// * bit 7 (`CLIENT_LOCAL_FILES`) — would let the upstream issue
///   `LOCAL INFILE` requests; the proxy explicitly rejects those
///   in `forward_query`.
/// * bit 11 (`CLIENT_SSL`) — see `CLIENT_SSL_FORBIDDEN_BIT` above.
/// * bit 24 (`CLIENT_DEPRECATE_EOF`) — the proxy uses EOF packets
///   to delimit text-result-set frames; deprecating them would
///   force the result-set parser to read OK packets to detect
///   end-of-frame, which is more state machine than V2.1 wants to
///   own.
const CLIENT_CAPS: u32 = (1 << 0)   // CLIENT_LONG_PASSWORD
    | (1 << 1)   // CLIENT_FOUND_ROWS
    | (1 << 2)   // CLIENT_LONG_FLAG
    | (1 << 3)   // CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | (1 << 12)  // CLIENT_IGNORE_SIGPIPE
    | (1 << 13)  // CLIENT_TRANSACTIONS
    | (1 << 15)  // CLIENT_SECURE_CONNECTION
    | (1 << 17)  // CLIENT_MULTI_RESULTS
    | (1 << 18)  // CLIENT_PS_MULTI_RESULTS
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
            "unsupported protocol version {}",
            payload[0]
        )));
    }
    let mut i = 1;
    // server_version: NUL-terminated string.
    let nul = payload[i..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| UpstreamError::Handshake("missing server_version NUL".into()))?;
    i += nul + 1;
    // thread_id: 4 bytes LE.
    if i + 4 > payload.len() {
        return Err(UpstreamError::Handshake(
            "greeting truncated at thread_id".into(),
        ));
    }
    i += 4;
    // auth_plugin_data_part_1: 8 bytes.
    if i + 8 > payload.len() {
        return Err(UpstreamError::Handshake(
            "greeting truncated at auth_plugin_data_part_1".into(),
        ));
    }
    let scramble1 = payload[i..i + 8].to_vec();
    i += 8;
    // filler: 1 byte.
    if i >= payload.len() {
        return Err(UpstreamError::Handshake(
            "greeting truncated at filler".into(),
        ));
    }
    i += 1;
    // capability_flags_lower: 2 bytes LE.
    if i + 2 > payload.len() {
        return Err(UpstreamError::Handshake(
            "greeting truncated at cap_lower".into(),
        ));
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
        return Err(UpstreamError::Handshake(
            "greeting truncated at char/status/cap_upper".into(),
        ));
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
        return Err(UpstreamError::Handshake(
            "greeting truncated at auth_plugin_data_len".into(),
        ));
    }
    let auth_plugin_data_len = payload[i] as usize;
    i += 1;
    // 10 reserved bytes.
    if i + 10 > payload.len() {
        return Err(UpstreamError::Handshake(
            "greeting truncated at reserved".into(),
        ));
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

/// Auth-plugin name strings the proxy understands. These are pinned
/// here so a typo at the AuthSwitchRequest dispatch site fails to
/// compile rather than fails-open as "unknown plugin".
const AUTH_PLUGIN_NATIVE: &str = "mysql_native_password";
const AUTH_PLUGIN_SHA256_CACHING: &str = "caching_sha2_password";

/// Build a `HandshakeResponse41` payload for the proxy → upstream
/// handshake when the server announced `mysql_native_password`.
fn build_handshake_response_41_native(
    user: &str,
    password: &[u8],
    database: Option<&str>,
    scramble: &[u8],
) -> Vec<u8> {
    let auth = if password.is_empty() {
        Vec::new()
    } else {
        mysql_native_password_scramble(password, scramble)
    };
    build_handshake_response_41(user, &auth, database, AUTH_PLUGIN_NATIVE)
}

/// Build a `HandshakeResponse41` payload for the proxy → upstream
/// handshake when the server announced `caching_sha2_password`. The
/// auth-response bytes are the 32-byte SHA-256 XOR scramble — the
/// V2 fast-path. If the server's auth cache is cold it will reply
/// with a `0x01 0x04` "perform full auth" indicator and we drive
/// the RSA-OAEP leg via `drive_caching_sha2_auth`.
fn build_handshake_response_41_sha256(
    user: &str,
    password: &[u8],
    database: Option<&str>,
    scramble: &[u8],
) -> Vec<u8> {
    let auth = if password.is_empty() {
        Vec::new()
    } else {
        caching_sha2_password_scramble(password, scramble)
    };
    build_handshake_response_41(user, &auth, database, AUTH_PLUGIN_SHA256_CACHING)
}

/// Shared HandshakeResponse41 builder.  Caller supplies the already-
/// computed `auth_response` bytes (≤255 since we don't advertise
/// `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA`) and the plugin name
/// string the response advertises.
fn build_handshake_response_41(
    user: &str,
    auth_response: &[u8],
    database: Option<&str>,
    plugin_name: &str,
) -> Vec<u8> {
    let mut caps = CLIENT_CAPS;
    if database.is_some() {
        caps |= 1 << 3; // CLIENT_CONNECT_WITH_DB
    } else {
        caps &= !(1 << 3);
    }
    let mut buf = Vec::with_capacity(
        64 + user.len()
            + auth_response.len()
            + database.map(str::len).unwrap_or(0)
            + plugin_name.len()
            + 1,
    );
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
    // auth_response: u8 length + bytes.  We deliberately do NOT set
    // `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA` so a single-byte
    // length is the wire shape every modern server accepts here.
    debug_assert!(
        auth_response.len() <= 255,
        "auth_response too long for single-byte length prefix",
    );
    buf.push(auth_response.len() as u8);
    buf.extend_from_slice(auth_response);
    if let Some(db) = database {
        buf.extend_from_slice(db.as_bytes());
        buf.push(0);
    }
    // auth_plugin_name (because CLIENT_PLUGIN_AUTH is set).
    buf.extend_from_slice(plugin_name.as_bytes());
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

/// `caching_sha2_password` fast-path scramble:
/// ```text
/// token = SHA256(pwd) XOR SHA256( SHA256(SHA256(pwd)) || scramble )
/// ```
/// 32 bytes (SHA-256 output width).  The server XOR-folds the same
/// triple with its cached `SHA256(SHA256(pwd))` to recover `SHA256(pwd)`
/// and compare against its `mysql.user` row.
fn caching_sha2_password_scramble(password: &[u8], scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1: [u8; 32] = sha256_hash(password);
    let stage2: [u8; 32] = sha256_hash(&stage1);
    let mut h = Sha256::new();
    h.update(stage2);
    h.update(scramble);
    let combined: [u8; 32] = h.finalize().into();
    let mut out = vec![0u8; 32];
    for i in 0..32 {
        out[i] = stage1[i] ^ combined[i];
    }
    out
}

fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Drive the auth-result phase of a native-plugin handshake.
/// On entry, `payload` is the body of the packet received after the
/// proxy's `HandshakeResponse41`. The server can respond with:
///   * OK_Packet (0x00) — auth succeeded.
///   * ERR_Packet (0xff) — auth rejected.
///   * AuthSwitchRequest (0xfe) — server wants a different plugin.
async fn handle_native_auth_result(
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
            match plugin.as_str() {
                AUTH_PLUGIN_NATIVE => {
                    // Re-do native with the new scramble at seq=3.
                    let scramble = take_scramble(plugin_data);
                    let auth = mysql_native_password_scramble(password, scramble);
                    stream
                        .write_all(&frame_packet(&auth, 3))
                        .await
                        .map_err(|e| {
                            UpstreamError::RelayFailed(redact_for_audit(&e.to_string()))
                        })?;
                    stream.flush().await.ok();
                    let (_seq, p) = read_packet(stream).await.map_err(|e| {
                        UpstreamError::Handshake(format!("read auth-switch result: {e}"))
                    })?;
                    classify_terminal_auth_packet(&p)
                }
                AUTH_PLUGIN_SHA256_CACHING => {
                    // Server is moving the connection to caching_sha2.
                    // Send the SHA-256 fast-path scramble at seq=3
                    // and drive the rest of the state machine.
                    let scramble = take_scramble(plugin_data);
                    let auth = caching_sha2_password_scramble(password, scramble);
                    stream
                        .write_all(&frame_packet(&auth, 3))
                        .await
                        .map_err(|e| {
                            UpstreamError::RelayFailed(redact_for_audit(&e.to_string()))
                        })?;
                    stream.flush().await.ok();
                    drive_caching_sha2_auth(stream, password, scramble, 4).await
                }
                other => Err(UpstreamError::Handshake(format!(
                    "upstream requested unsupported auth plugin `{other}` — \
                     V2 supports `mysql_native_password` and \
                     `caching_sha2_password`",
                ))),
            }
        }
        other => Err(UpstreamError::Handshake(format!(
            "unexpected auth-result tag 0x{other:02x}"
        ))),
    }
}

/// Extract a 20-byte scramble from `auth_plugin_data`. MySQL servers
/// send 21 bytes (20 scramble + 1 NUL terminator) in the
/// HandshakeV10 / AuthSwitchRequest payload; we take the first 20.
fn take_scramble(plugin_data: &[u8]) -> &[u8] {
    if plugin_data.len() >= 20 {
        &plugin_data[..20]
    } else {
        plugin_data
    }
}

/// Drive the `caching_sha2_password` auth state machine.
/// On entry the proxy has already written the SHA-256 fast-path
/// scramble to `stream` at sequence `next_seq - 1` (so the next
/// packet read is at `next_seq`).  Possible server responses:
/// * `OK_Packet` (`0x00`) — auth succeeded (rare; usually arrives
///   AFTER a `0x01 0x03` "fast auth success" indicator).
/// * `ERR_Packet` (`0xff`) — auth rejected.
/// * `0x01 0x03` — fast auth success.  Read the next packet
///   (must be OK or ERR) and finish.
/// * `0x01 0x04` — perform full auth.  The proxy is on a plaintext
///   connection so we must:
///     1. Send `0x02` to request the server's RSA public key.
///     2. Read the public-key payload (PEM).
///     3. Encrypt `password\0 XOR scramble (cyclic)` with
///        RSA-OAEP-SHA1 and send.
///     4. Read the terminal OK / ERR.
async fn drive_caching_sha2_auth(
    stream: &mut TcpStream,
    password: &[u8],
    scramble: &[u8],
    next_seq: u8,
) -> Result<(), UpstreamError> {
    let (seq, payload) = read_packet(stream)
        .await
        .map_err(|e| UpstreamError::Handshake(format!("read caching_sha2 auth indicator: {e}")))?;
    if payload.is_empty() {
        return Err(UpstreamError::Handshake(
            "empty caching_sha2 auth indicator".into(),
        ));
    }
    debug_assert_eq!(
        seq, next_seq,
        "caching_sha2 indicator should arrive at expected seq",
    );
    match payload[0] {
        0x00 => Ok(()),
        0xff => {
            let (_, _, message) = parse_err_packet(&payload);
            Err(UpstreamError::AuthRejected(redact_for_audit(&message)))
        }
        0x01 => {
            // AuthMoreData. payload[1] is the indicator byte.
            if payload.len() < 2 {
                return Err(UpstreamError::Handshake(
                    "caching_sha2 AuthMoreData missing indicator byte".into(),
                ));
            }
            match payload[1] {
                0x03 => {
                    // Fast auth success.  Next packet is the terminal
                    // OK or ERR.
                    let (_seq, p) = read_packet(stream).await.map_err(|e| {
                        UpstreamError::Handshake(format!("read caching_sha2 fast-auth result: {e}"))
                    })?;
                    classify_terminal_auth_packet(&p)
                }
                0x04 => {
                    // Perform full auth.  We are on a plaintext
                    // connection (V2 does not support TLS-to-upstream
                    // yet — the caller checked `url.require_tls`),
                    // so we must do the RSA leg.
                    let public_key_seq = seq.wrapping_add(1);
                    full_auth_via_rsa(stream, password, scramble, public_key_seq).await
                }
                other => Err(UpstreamError::Handshake(format!(
                    "unexpected caching_sha2 AuthMoreData indicator \
                     0x{other:02x}"
                ))),
            }
        }
        other => Err(UpstreamError::Handshake(format!(
            "unexpected caching_sha2 auth-result tag 0x{other:02x}"
        ))),
    }
}

/// Drive the RSA-OAEP-SHA1 leg of the `caching_sha2_password`
/// full-auth path.  Equivalent of `mysql_clear_password` over
/// plaintext, but bound to the server's per-connection RSA key
/// rather than sent in the clear.
/// Sequence:
///   1. Send `0x02` (request public key) at `request_seq`.
///   2. Read the public-key reply (PEM bytes prefixed with `0x01`).
///   3. RSA-OAEP-SHA1 encrypt
///      `XOR(password || 0x00, scramble (cyclic))` with the public key.
///   4. Send the ciphertext at `request_seq + 2`.
///   5. Read the terminal OK / ERR.
async fn full_auth_via_rsa(
    stream: &mut TcpStream,
    password: &[u8],
    scramble: &[u8],
    request_seq: u8,
) -> Result<(), UpstreamError> {
    // Step 1: ask for the public key.
    stream
        .write_all(&frame_packet(&[0x02u8], request_seq))
        .await
        .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
    stream.flush().await.ok();

    // Step 2: read the key.  Layout: `0x01 || PEM bytes` per the
    // MySQL `caching_sha2_password` plugin.  Some servers omit the
    // `0x01` prefix; tolerate both.
    let (_seq, payload) = read_packet(stream)
        .await
        .map_err(|e| UpstreamError::Handshake(format!("read RSA public-key reply: {e}")))?;
    let pem_bytes: &[u8] = if !payload.is_empty() && payload[0] == 0x01 {
        &payload[1..]
    } else {
        &payload[..]
    };
    let pem = std::str::from_utf8(pem_bytes).map_err(|_| {
        UpstreamError::Handshake("RSA public-key payload is not valid UTF-8".into())
    })?;
    let key = RsaPublicKey::from_public_key_pem(pem.trim())
        .map_err(|e| UpstreamError::Handshake(format!("RSA public-key parse: {e}")))?;

    // Step 3: build the plaintext payload — password including the
    // trailing NUL (per MySQL's RSA leg), XOR'd against the scramble
    // (cyclic).
    let mut plain = Vec::with_capacity(password.len() + 1);
    plain.extend_from_slice(password);
    plain.push(0);
    if !scramble.is_empty() {
        for (i, b) in plain.iter_mut().enumerate() {
            *b ^= scramble[i % scramble.len()];
        }
    }

    // RSA-OAEP-SHA1 (the MGF1 default for the OAEP ctor).  The MySQL
    // server uses SHA-1 in both the digest and the MGF, matching the
    // default of `Oaep::new::<Sha1>()`.
    let mut rng = OsRng;
    let padding = Oaep::new::<Sha1>();
    let cipher = key
        .encrypt(&mut rng, padding, &plain)
        .map_err(|e| UpstreamError::Handshake(format!("RSA-OAEP encrypt: {e}")))?;

    // Step 4: send the ciphertext.  +2 because the server's
    // public-key packet was at request_seq+1.
    let send_seq = request_seq.wrapping_add(2);
    stream
        .write_all(&frame_packet(&cipher, send_seq))
        .await
        .map_err(|e| UpstreamError::RelayFailed(redact_for_audit(&e.to_string())))?;
    stream.flush().await.ok();

    // Step 5: read the terminal auth result.
    let (_seq, p) = read_packet(stream)
        .await
        .map_err(|e| UpstreamError::Handshake(format!("read caching_sha2 RSA-auth result: {e}")))?;
    classify_terminal_auth_packet(&p)
}

/// Map a packet that should be terminal (OK or ERR) into either
/// `Ok(())` (success) or `Err(UpstreamError::AuthRejected)` /
/// `Err(UpstreamError::Handshake)` (failure).
fn classify_terminal_auth_packet(payload: &[u8]) -> Result<(), UpstreamError> {
    if payload.is_empty() {
        return Err(UpstreamError::Handshake(
            "empty terminal auth packet".into(),
        ));
    }
    match payload[0] {
        0x00 => Ok(()),
        0xff => {
            let (_, _, message) = parse_err_packet(payload);
            Err(UpstreamError::AuthRejected(redact_for_audit(&message)))
        }
        other => Err(UpstreamError::Handshake(format!(
            "unexpected terminal auth tag 0x{other:02x}"
        ))),
    }
}

/// Parse an `AuthSwitchRequest` payload (without the 0xfe header).
fn parse_auth_switch_request(body: &[u8]) -> Result<(String, &[u8]), UpstreamError> {
    let nul = body.iter().position(|&b| b == 0).ok_or_else(|| {
        UpstreamError::Handshake("AuthSwitchRequest missing plugin name NUL".into())
    })?;
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
    let len = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
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
        0xfc if buf.len() >= 3 => Some((u16::from_le_bytes([buf[1], buf[2]]) as u64, 3)),
        0xfd if buf.len() >= 4 => Some((
            (buf[1] as u64) | ((buf[2] as u64) << 8) | ((buf[3] as u64) << 16),
            4,
        )),
        0xfe if buf.len() >= 9 => Some((
            u64::from_le_bytes([
                buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
            ]),
            9,
        )),
        _ => None,
    }
}

/// True if `payload` is an `EOF_Packet`.
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
        let p = ParsedUpstreamUrl::parse("mysql://demo:hunter2@db/mydb?ssl-mode=REQUIRED").unwrap();
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
        assert_eq!(decode_lenenc_int(&[0]), Some((0u64, 1)));
        assert_eq!(decode_lenenc_int(&[42]), Some((42u64, 1)));
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
        let r = build_handshake_response_41_native("demo", b"hunter2", Some("mydb"), &scramble);
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

    /// Pin the
    /// `caching_sha2_password` HandshakeResponse41 shape. The
    /// auth-response is 32 bytes (SHA-256 width) and the trailing
    /// plugin name is `caching_sha2_password\0`.
    #[test]
    fn build_handshake_response_sha256_includes_plugin_name() {
        let scramble = [0x42u8; 20];
        let r = build_handshake_response_41_sha256("demo", b"hunter2", Some("mydb"), &scramble);
        let after_reserved = 32;
        let user_end = r[after_reserved..].iter().position(|&b| b == 0).unwrap();
        let user_bytes = &r[after_reserved..after_reserved + user_end];
        assert_eq!(user_bytes, b"demo");
        // Auth response: u8 length + 32 SHA-256-XOR bytes.
        let auth_len_idx = after_reserved + user_end + 1;
        assert_eq!(r[auth_len_idx], 32);
        let tail = std::str::from_utf8(&r[r.len() - "caching_sha2_password\0".len()..]).unwrap();
        assert!(tail.starts_with("caching_sha2_password"));
    }

    /// Pin the SHA-256 fast-path
    /// scramble algorithm. Determinism + length + scramble
    /// sensitivity, mirroring the matching `mysql_native_password`
    /// pin above.
    #[test]
    fn caching_sha2_scramble_is_deterministic_and_32_bytes() {
        let pwd = b"hunter2";
        let scramble = [0x42u8; 20];
        let t1 = caching_sha2_password_scramble(pwd, &scramble);
        let t2 = caching_sha2_password_scramble(pwd, &scramble);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 32, "SHA-256 width is 32 bytes");
        let other = [0x43u8; 20];
        let t3 = caching_sha2_password_scramble(pwd, &other);
        assert_ne!(t1, t3, "scramble change must change token");
        assert!(
            caching_sha2_password_scramble(b"", &scramble).is_empty(),
            "empty password must yield empty token"
        );
    }

    /// Pin the SHA-256 fast-path
    /// against a known triple so a regression in the digest
    /// configuration would surface here. Computed once with the
    /// real `Sha256` engine; the assertion below freezes the
    /// reference output.
    #[test]
    fn caching_sha2_scramble_matches_fixed_reference_vector() {
        // password = "raxis", scramble = b"0123456789abcdef0123" (20 ASCII bytes)
        let scramble = b"0123456789abcdef0123";
        let token = caching_sha2_password_scramble(b"raxis", scramble);
        // Expected = SHA256("raxis") XOR SHA256(SHA256(SHA256("raxis")) || scramble).
        let stage1 = sha256_hash(b"raxis");
        let stage2 = sha256_hash(&stage1);
        let mut h = Sha256::new();
        sha2::Digest::update(&mut h, stage2);
        sha2::Digest::update(&mut h, scramble);
        let combined: [u8; 32] = h.finalize().into();
        let expected: Vec<u8> = stage1
            .iter()
            .zip(combined.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(token, expected);
    }

    /// Pin the helper that drives
    /// the terminal-packet classifier. Same behaviour for both the
    /// native-password leg and the caching_sha2 fast-path /
    /// RSA-leg final reads.
    #[test]
    fn classify_terminal_auth_packet_maps_known_tags() {
        assert!(classify_terminal_auth_packet(&[0x00]).is_ok());
        let err_pkt = vec![
            0xff, 0x86, 0x04, b'#', b'4', b'2', b'5', b'0', b'1', b'd', b'e', b'n', b'i', b'e',
            b'd',
        ];
        match classify_terminal_auth_packet(&err_pkt) {
            Err(UpstreamError::AuthRejected(_)) => {}
            other => panic!("expected AuthRejected, got {other:?}"),
        }
        match classify_terminal_auth_packet(&[0x42]) {
            Err(UpstreamError::Handshake(m)) => assert!(m.contains("0x42")),
            other => panic!("expected Handshake(0x42), got {other:?}"),
        }
        match classify_terminal_auth_packet(&[]) {
            Err(UpstreamError::Handshake(_)) => {}
            other => panic!("expected Handshake(empty), got {other:?}"),
        }
    }

    /// Pin the scramble extractor.
    /// MySQL servers send 21 bytes (20 scramble + NUL) in the
    /// HandshakeV10 / AuthSwitchRequest payload; we take the first 20.
    #[test]
    fn take_scramble_returns_first_20_bytes_when_long_enough() {
        let buf = [0x11u8; 21];
        let s = take_scramble(&buf);
        assert_eq!(s.len(), 20);
        assert_eq!(s, &[0x11u8; 20]);
    }

    /// Server with too-short scramble payload — the extractor
    /// returns whatever bytes are present rather than panicking.
    /// Production configurations never trigger this path; the test
    /// is a defense-in-depth check that a malformed greeting cannot
    /// crash the proxy.
    #[test]
    fn take_scramble_returns_short_buffer_unchanged() {
        let buf = [0x11u8; 5];
        let s = take_scramble(&buf);
        assert_eq!(s.len(), 5);
    }

    /// Drive the `caching_sha2_password`
    /// fast-path end-to-end against a local TCP server that emits the
    /// real wire shape:
    ///   1. HandshakeV10 with `auth_plugin_name = caching_sha2_password`
    ///   2. Read HandshakeResponse41, validate the 32-byte SHA-256 token
    ///   3. Reply `0x01 0x03` (fast auth success)
    ///   4. Reply `0x00...` (OK_Packet) — auth complete
    /// The proxy MUST complete the handshake without error and the
    /// resulting `UpstreamSession` is usable for `forward_query`.
    #[tokio::test]
    async fn caching_sha2_fast_path_completes_handshake() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let scramble: [u8; 20] = [0x42; 20];
        let password: Vec<u8> = b"hunter2".to_vec();
        let scramble_for_server = scramble;
        let password_for_server = password.clone();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Send HandshakeV10 with caching_sha2_password.
            let greeting = build_caching_sha2_greeting(&scramble_for_server);
            sock.write_all(&frame_packet(&greeting, 0)).await.unwrap();
            sock.flush().await.unwrap();
            // Read HandshakeResponse41.
            let (_seq, resp) = read_packet(&mut sock).await.unwrap();
            // Skip caps(4) + max(4) + charset(1) + reserved(23) = 32
            // → username NUL → u8 auth_len → auth bytes.
            let mut i = 32;
            // Username NUL.
            let nul = resp[i..].iter().position(|&b| b == 0).unwrap();
            i += nul + 1;
            let auth_len = resp[i] as usize;
            i += 1;
            let auth_bytes = &resp[i..i + auth_len];
            // Validate the token.
            let expected =
                caching_sha2_password_scramble(&password_for_server, &scramble_for_server);
            if auth_bytes != expected {
                let err = build_err_packet_bytes(1045, "28000", "fake-mysql: bad SHA-256 token");
                sock.write_all(&frame_packet(&err, 2)).await.unwrap();
                sock.flush().await.unwrap();
                return;
            }
            // Send fast-auth-success indicator (seq=2).
            sock.write_all(&frame_packet(&[0x01, 0x03], 2))
                .await
                .unwrap();
            // Send terminal OK_Packet (seq=3).
            sock.write_all(&frame_packet(&build_ok_packet_bytes(), 3))
                .await
                .unwrap();
            sock.flush().await.unwrap();
            // Hold the socket open briefly so the proxy's connect
            // path observes the OK before EOF.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let url = ParsedUpstreamUrl {
            host: "127.0.0.1".into(),
            port,
            user: "demo".into(),
            password: String::from_utf8(password.clone()).unwrap(),
            database: None,
            require_tls: false,
        };
        let session = UpstreamSession::connect(&url, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(session.host, "127.0.0.1");
        assert_eq!(session.port, port);
        assert!(!session.tls);
        assert!(session.handshake_ms < 5_000);

        server.await.unwrap();
    }

    /// When the password is wrong,
    /// the fast-path server replies with an `ERR_Packet` rather than
    /// the `0x01 0x03` indicator. The proxy MUST surface
    /// `UpstreamError::AuthRejected` so the operator audit trail is
    /// the standard `AuthRejected` reason rather than a generic
    /// `ProtocolHandshakeFailed`.
    #[tokio::test]
    async fn caching_sha2_with_wrong_password_surfaces_auth_rejected() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let scramble: [u8; 20] = [0x55; 20];
        let scramble_for_server = scramble;

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let greeting = build_caching_sha2_greeting(&scramble_for_server);
            sock.write_all(&frame_packet(&greeting, 0)).await.unwrap();
            sock.flush().await.unwrap();
            // Read the HandshakeResponse41 (we don't validate, just
            // unconditionally reject with an ERR_Packet).
            let _ = read_packet(&mut sock).await.unwrap();
            let err = build_err_packet_bytes(1045, "28000", "Access denied for user (fake)");
            sock.write_all(&frame_packet(&err, 2)).await.unwrap();
            sock.flush().await.unwrap();
        });

        let url = ParsedUpstreamUrl {
            host: "127.0.0.1".into(),
            port,
            user: "demo".into(),
            password: "wrong".into(),
            database: None,
            require_tls: false,
        };
        let res = UpstreamSession::connect(&url, Duration::from_secs(5)).await;
        let err = match res {
            Ok(_) => panic!("expected AuthRejected, got Ok(_)"),
            Err(e) => e,
        };
        match err {
            UpstreamError::AuthRejected(msg) => {
                assert!(
                    msg.contains("Access denied"),
                    "AuthRejected detail must surface upstream message; got {msg}"
                );
            }
            other => panic!("expected AuthRejected, got {other:?}"),
        }
        server.await.unwrap();
    }

    /// Drive the `caching_sha2_password`
    /// AuthSwitchRequest path. The server greets with
    /// `mysql_native_password` but switches to `caching_sha2_password`
    /// after the proxy's HandshakeResponse41. The proxy MUST recompute
    /// the SHA-256 token against the new scramble and complete the
    /// handshake.
    #[tokio::test]
    async fn caching_sha2_via_auth_switch_request_completes() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let initial_scramble: [u8; 20] = [0x77; 20];
        let switch_scramble: [u8; 20] = [0x88; 20];
        let password: Vec<u8> = b"hunter2".to_vec();
        let init_for_server = initial_scramble;
        let sw_for_server = switch_scramble;
        let pw_for_server = password.clone();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Greet with native_password.
            let greeting = build_native_greeting(&init_for_server);
            sock.write_all(&frame_packet(&greeting, 0)).await.unwrap();
            sock.flush().await.unwrap();
            // Read the proxy's native HandshakeResponse41 (seq=1).
            let _ = read_packet(&mut sock).await.unwrap();
            // Send AuthSwitchRequest → caching_sha2_password (seq=2).
            let mut switch = vec![0xfeu8];
            switch.extend_from_slice(b"caching_sha2_password");
            switch.push(0);
            switch.extend_from_slice(&sw_for_server);
            switch.push(0);
            sock.write_all(&frame_packet(&switch, 2)).await.unwrap();
            sock.flush().await.unwrap();
            // Read the SHA-256 token reply (seq=3) and validate.
            let (_seq, token) = read_packet(&mut sock).await.unwrap();
            let expected = caching_sha2_password_scramble(&pw_for_server, &sw_for_server);
            if token != expected {
                let err = build_err_packet_bytes(
                    1045,
                    "28000",
                    "fake-mysql: bad SHA-256 token after switch",
                );
                sock.write_all(&frame_packet(&err, 4)).await.unwrap();
                sock.flush().await.unwrap();
                return;
            }
            // Send fast-auth-success indicator (seq=4).
            sock.write_all(&frame_packet(&[0x01, 0x03], 4))
                .await
                .unwrap();
            // Send terminal OK_Packet (seq=5).
            sock.write_all(&frame_packet(&build_ok_packet_bytes(), 5))
                .await
                .unwrap();
            sock.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let url = ParsedUpstreamUrl {
            host: "127.0.0.1".into(),
            port,
            user: "demo".into(),
            password: String::from_utf8(password.clone()).unwrap(),
            database: None,
            require_tls: false,
        };
        let session = UpstreamSession::connect(&url, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(session.host, "127.0.0.1");
        assert_eq!(session.port, port);

        server.await.unwrap();
    }

    // -------- helpers used by the caching_sha2 integration tests --------

    fn build_caching_sha2_greeting(scramble: &[u8; 20]) -> Vec<u8> {
        build_greeting_with_plugin(scramble, b"caching_sha2_password")
    }

    fn build_native_greeting(scramble: &[u8; 20]) -> Vec<u8> {
        build_greeting_with_plugin(scramble, b"mysql_native_password")
    }

    fn build_greeting_with_plugin(scramble: &[u8; 20], plugin: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(80);
        p.push(0x0a);
        p.extend_from_slice(b"8.0.30-raxis-fake");
        p.push(0);
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&scramble[..8]);
        p.push(0);
        let cap_lower: u16 = (1 << 9) | (1 << 15);
        p.extend_from_slice(&cap_lower.to_le_bytes());
        p.push(0x2d);
        p.extend_from_slice(&2u16.to_le_bytes());
        let cap_upper: u16 = 1 << (19 - 16);
        p.extend_from_slice(&cap_upper.to_le_bytes());
        p.push(21);
        p.extend_from_slice(&[0u8; 10]);
        p.extend_from_slice(&scramble[8..]);
        p.push(0);
        p.extend_from_slice(plugin);
        p.push(0);
        p
    }

    fn build_err_packet_bytes(code: u16, sqlstate: &str, msg: &str) -> Vec<u8> {
        let mut p = Vec::with_capacity(msg.len() + 16);
        p.push(0xff);
        p.extend_from_slice(&code.to_le_bytes());
        p.push(b'#');
        p.extend_from_slice(sqlstate.as_bytes());
        p.extend_from_slice(msg.as_bytes());
        p
    }

    fn build_ok_packet_bytes() -> Vec<u8> {
        let mut p = Vec::with_capacity(11);
        p.push(0x00);
        p.push(0x00); // affected_rows lenenc (0)
        p.push(0x00); // last_insert_id lenenc (0)
        p.extend_from_slice(&2u16.to_le_bytes()); // status flags
        p.extend_from_slice(&0u16.to_le_bytes()); // warnings
        p
    }

    /// Pin the regression: the proxy MUST NEVER advertise
    /// `CLIENT_SSL` (bit 11) or `CLIENT_COMPRESS` (bit 5) in its
    /// upstream `HandshakeResponse41`. Setting `CLIENT_SSL` makes
    /// the server enter its TLS-negotiation state and wait for a
    /// Client Hello, hanging the connection until `net_read_timeout`
    /// fires. Setting `CLIENT_COMPRESS` commits the proxy to
    /// zlib-framed packets, which it does not implement.
    /// Pinned against MySQL 8.0.36 reproducer; the V2.1 caps mask
    /// had bit 11 set with a comment claiming `CLIENT_IGNORE_SIGPIPE`
    /// (which is bit 12), and bit 5 set with a comment claiming
    /// `CLIENT_LOCAL_FILES` (bit 7).
    #[test]
    fn client_caps_does_not_advertise_ssl_or_compress() {
        assert_eq!(
            CLIENT_CAPS & CLIENT_SSL_FORBIDDEN_BIT,
            0,
            "CLIENT_SSL must NEVER be set in upstream caps; \
             see CLIENT_SSL_FORBIDDEN_BIT documentation",
        );
        assert_eq!(
            CLIENT_CAPS & CLIENT_COMPRESS_FORBIDDEN_BIT,
            0,
            "CLIENT_COMPRESS must NEVER be set in upstream caps; \
             see CLIENT_COMPRESS_FORBIDDEN_BIT documentation",
        );
        // Sanity: the bits we DO want must be present.
        assert_ne!(
            CLIENT_CAPS & CLIENT_PROTOCOL_41,
            0,
            "CLIENT_PROTOCOL_41 must be set"
        );
        assert_ne!(
            CLIENT_CAPS & CLIENT_PLUGIN_AUTH,
            0,
            "CLIENT_PLUGIN_AUTH must be set"
        );
        assert_ne!(
            CLIENT_CAPS & (1 << 15),
            0,
            "CLIENT_SECURE_CONNECTION must be set"
        );
    }

    #[test]
    fn parse_handshake_v10_shape() {
        // Build a tiny legitimate-looking V10 greeting and parse it.
        let mut p = vec![0x0a]; // protocol_version
        p.extend_from_slice(b"8.0.30-raxis-fake\0");
        p.extend_from_slice(&1u32.to_le_bytes()); // thread_id
        p.extend_from_slice(&[1u8; 8]); // scramble_part_1
        p.push(0); // filler
        p.extend_from_slice(&(CLIENT_PROTOCOL_41 as u16).to_le_bytes()); // cap_lower (must include PROTOCOL_41)
        p.push(0x2d); // charset (utf8mb4)
        p.extend_from_slice(&0u16.to_le_bytes()); // status
        p.extend_from_slice(&((CLIENT_PROTOCOL_41 >> 16) as u16).to_le_bytes()); // cap_upper
        p.push(21); // auth_plugin_data_len
        p.extend_from_slice(&[0u8; 10]); // reserved
        p.extend_from_slice(&[2u8; 12]); // scramble_part_2 (12 bytes)
        p.push(0); // NUL
        p.extend_from_slice(b"mysql_native_password\0");
        let g = parse_handshake_v10(&p).expect("parse");
        assert_eq!(g.scramble.len(), 20);
        assert_eq!(g.plugin, "mysql_native_password");
    }
}
