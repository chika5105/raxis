//! Upstream Postgres connection driver.
//!
//! Normative reference: `credential-proxy.md §14.3` (lazy connect on
//! first allowed query) and `§14.8.1` (per-proxy implementation matrix
//! for Postgres).
//!
//! # What this module owns
//!
//! * Parsing the **credential value** (resolved through
//!   `Arc<dyn CredentialBackend>`) as a libpq URL like
//!   `postgresql://user:pass@host:5432/db?sslmode=require`.
//! * Opening a real `tokio::net::TcpStream` to the upstream and
//!   driving the Postgres backend handshake to a usable session, via
//!   the `tokio-postgres` driver (which handles SCRAM-SHA-256, MD5,
//!   and cleartext password auth — see the rationale in
//!   `credential-proxy.md §14.8.1`).
//! * Forwarding agent-issued simple-query SQL to the upstream and
//!   re-encoding the result-set rows into Postgres wire frames the
//!   agent's libpq driver can consume verbatim.
//! * Surfacing structured errors at every failure point so the proxy
//!   can map them to the three V2.1 audit events (`UpstreamConnected`,
//!   `UpstreamFailed`, `DatabaseQueryCompleted`).
//!
//! # Design choices
//!
//! ## Why use `tokio-postgres` for upstream auth instead of hand-rolling the wire
//!
//! Postgres supports four authentication methods that the proxy may
//! encounter against a real upstream:
//!
//!   * AuthenticationCleartextPassword (rare, requires TLS in
//!     production deployments)
//!   * AuthenticationMD5Password (legacy default in Postgres ≤ 13)
//!   * AuthenticationSASL with SCRAM-SHA-256 (default in Postgres ≥ 14)
//!   * Trust auth (no credential exchange)
//!
//! Implementing SCRAM-SHA-256 from scratch is ~150 lines of HMAC /
//! PBKDF2 code that has been written, audited, and shipped in
//! `tokio-postgres` for years. Reusing it removes the largest single
//! source of cryptographic-correctness risk from this module.
//!
//! ## Why we re-encode rows instead of byte-tunneling
//!
//! `serve_one()` already does per-statement classification +
//! restriction enforcement, so the proxy is **not** a transparent
//! byte tunnel — it's an interpreting layer. Going through
//! `tokio-postgres::simple_query_raw` lets us:
//!
//!   * Apply restrictions to each statement in a multi-statement
//!     `Q` message (Postgres allows `Q` to carry semicolon-separated
//!     statements; a transparent tunnel would forward them all
//!     atomically).
//!   * Capture structured row counts for `DatabaseQueryCompleted`.
//!   * Surface upstream errors as `Some(sqlstate)` rather than
//!     opaque byte sequences.
//!
//! The cost is one re-encode pass per row. For the agent's use
//! case (interactive AI iteration, not OLTP at line-rate), this is
//! acceptable; pooling + true relay is V3 work.

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use raxis_credentials::{ConsumerIdentity, CredentialBackend, CredentialError, CredentialName};

use crate::wire::{command_complete, data_row, row_description, FieldDescriptor};
use crate::OwnedConsumer;

/// Maximum size of an upstream payload the proxy will buffer in
/// memory while re-encoding for the agent. Mirrors the `i32` length
/// header bound that Postgres itself enforces on each frame.
const MAX_REENCODE_PAYLOAD_BYTES: usize = 1_000_000;

/// Upstream-connect / forward errors classified into the three
/// `CredentialProxyUpstreamFailed::reason` discriminants from
/// `credential-proxy.md §14.5.3`.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The credential bytes could not be parsed as a libpq URL.
    /// Surfaces as `FAIL_PROXY_UPSTREAM_URL_INVALID`.
    #[error("invalid upstream URL: {0}")]
    InvalidUrl(String),

    /// Credential resolution through the backend failed.
    /// Surfaces as a Postgres `ErrorResponse` to the agent and
    /// `CredentialProxyUpstreamFailed { reason: "AuthRejected" }`.
    #[error("credential resolution failed: {0}")]
    CredentialResolution(String),

    /// DNS lookup or TCP connect to the upstream failed.
    /// Surfaces as `CredentialProxyUpstreamFailed { reason: "TcpConnectFailed" }`.
    #[error("tcp connect failed: {0}")]
    TcpConnect(String),

    /// The Postgres protocol-level handshake failed (auth rejected,
    /// version mismatch, malformed greeting). Surfaces as
    /// `CredentialProxyUpstreamFailed { reason: "ProtocolHandshakeFailed" }`.
    #[error("postgres protocol handshake failed: {0}")]
    Handshake(String),

    /// The upstream rejected the credential at the auth step.
    /// Surfaces as `CredentialProxyUpstreamFailed { reason: "AuthRejected" }`.
    #[error("upstream auth rejected: {0}")]
    AuthRejected(String),

    /// The upstream took longer than the proxy's connect timeout
    /// to respond. Surfaces as
    /// `CredentialProxyUpstreamFailed { reason: "Timeout" }`.
    #[error("upstream connect timed out after {timeout_ms}ms")]
    Timeout {
        /// Timeout in milliseconds.
        timeout_ms: u32,
    },

    /// The proxy reached upstream but a forwarded query produced an
    /// upstream-side error. Carries the upstream's sqlstate.
    /// Surfaces as a Postgres `ErrorResponse` to the agent and
    /// `DatabaseQueryCompleted { upstream_error: Some(sqlstate) }`.
    #[error("query failed at upstream: sqlstate={sqlstate} message={message}")]
    QueryFailed {
        /// Postgres sqlstate from the upstream's `ErrorResponse`.
        sqlstate: String,
        /// Human-readable message — already redacted by
        /// `redact_for_audit()` before reaching this variant.
        message: String,
    },

    /// The upstream's response payload exceeded
    /// `MAX_REENCODE_PAYLOAD_BYTES`. The proxy dropped the agent's
    /// connection rather than risk an OOM.
    #[error("upstream response payload too large: {bytes} > {max} bytes")]
    PayloadTooLarge {
        /// Bytes the upstream would have produced.
        bytes: usize,
        /// Bytes the proxy is willing to buffer.
        max: usize,
    },

    /// Catch-all for tokio-postgres errors that don't map to one of
    /// the discriminants above (network mid-stream drops, panics in
    /// the connection task, etc.). Already redacted.
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
            // Mid-session query failures are NOT upstream-connect
            // failures — they fire `DatabaseQueryCompleted` with
            // a non-null upstream_error, not `UpstreamFailed`. The
            // discriminant is still included so the catch-all path
            // emits a sensible string.
            Self::QueryFailed { .. } => "ProtocolHandshakeFailed",
            Self::PayloadTooLarge { .. } => "ProtocolHandshakeFailed",
            Self::RelayFailed(_) => "ProtocolHandshakeFailed",
        }
    }

    /// Map this error to the redacted detail string the audit
    /// envelope carries. The `Display` impl already redacts via
    /// the `tokio-postgres` driver (which never logs credential
    /// bytes), but we double-check by stripping any `password=` /
    /// `:secret@` / `?password=` substrings just in case.
    pub fn audit_detail(&self) -> String {
        redact_for_audit(&self.to_string())
    }
}

/// Strip credential-leak substrings from an upstream-error message
/// before it reaches the audit envelope. Belt-and-braces protection:
/// the upstream `tokio-postgres::Error::Display` impl never includes
/// the password bytes, but a future driver upgrade or a peer-supplied
/// error string COULD, so this helper enforces the redaction
/// regardless.
///
/// The function is single-pass: it walks the string once, copying
/// bytes verbatim except where a `password=…` (case-insensitive) or
/// `://user[:pass]@` substring is found. Single-pass is essential —
/// a naive while-loop "find then replace" would advance the cursor
/// past the replacement (which itself starts with `password=`) and
/// loop forever.
pub fn redact_for_audit(msg: &str) -> String {
    let bytes = msg.as_bytes();
    let lower: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut out = String::with_capacity(msg.len());
    let mut i = 0usize;
    while i < bytes.len() {
        // Pattern 1: `password=` query param (case-insensitive).
        if i + b"password=".len() <= bytes.len()
            && &lower[i..i + b"password=".len()] == b"password="
        {
            out.push_str("password=[REDACTED]");
            i += b"password=".len();
            // Skip until the next delimiter.
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
        // Pattern 2: libpq URL form `://user:pass@...`.
        // We recognise this as `://`, scan for the next `@`, and
        // if there's a `:` between the `://` and the `@`, redact
        // everything from the `:` to the `@`.
        if i + 3 <= bytes.len() && &bytes[i..i + 3] == b"://" {
            // Find the end of the authority (next `/` or `?` or
            // whitespace or end-of-string).
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
            // Look for `@` in the authority.
            if let Some(at_offset) = bytes[i + 3..auth_end].iter().position(|b| *b == b'@') {
                let at = i + 3 + at_offset;
                // Look for `:` in the userinfo (between `://` and `@`).
                if let Some(colon_offset) = bytes[i + 3..at].iter().position(|b| *b == b':') {
                    let colon = i + 3 + colon_offset;
                    // Emit `://<user>:[REDACTED]`.
                    out.push_str("://");
                    out.push_str(std::str::from_utf8(&bytes[i + 3..colon]).unwrap_or(""));
                    out.push_str(":[REDACTED]");
                    // Continue copying from `@`.
                    i = at;
                    continue;
                }
            }
        }
        // Default: copy one byte. We use a char-aware advance to
        // keep multi-byte UTF-8 boundaries intact.
        let ch_len = utf8_char_len(bytes[i]);
        let end = (i + ch_len).min(bytes.len());
        out.push_str(std::str::from_utf8(&bytes[i..end]).unwrap_or("?"));
        i = end;
    }
    out
}

/// Returns the byte length of the UTF-8 character starting at the
/// given lead byte. Defaults to 1 on malformed input so the caller
/// makes forward progress (the message is already a redaction-only
/// surface, so a malformed UTF-8 byte is fine to skip).
fn utf8_char_len(lead: u8) -> usize {
    // ASCII (`< 0x80`) and stray continuation bytes
    // (`0x80..=0xbf`) collapse to a 1-byte advance — the latter
    // shouldn't appear at a lead position in valid UTF-8 but we
    // treat them defensively so the redactor still makes forward
    // progress.
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

/// Parsed view of a libpq credential URL. Held by the proxy across
/// the agent's connection lifetime so the lazy upstream connect on
/// first allowed query can pick up the parsed handle without
/// re-parsing on every query.
#[derive(Debug, Clone)]
pub struct ParsedUpstreamUrl {
    /// Hostname from the credential URL — used as-is in the
    /// `CredentialProxyUpstreamConnected.upstream_host` audit field.
    pub host: String,
    /// Port from the credential URL after default-port substitution
    /// (5432).
    pub port: u16,
    /// Whether `?sslmode=require` (or stricter) was in the URL.
    pub require_tls: bool,
    /// Original URL bytes — passed to `tokio_postgres::Config` for
    /// auth handling. Treated as a secret outside this module.
    raw: String,
}

impl ParsedUpstreamUrl {
    /// Parse a libpq URL out of a resolved credential value.
    pub fn parse(raw_url: &str) -> Result<Self, UpstreamError> {
        let raw = raw_url.trim().to_owned();
        if !raw.starts_with("postgresql://") && !raw.starts_with("postgres://") {
            return Err(UpstreamError::InvalidUrl(
                "scheme must be `postgresql://` or `postgres://`".into(),
            ));
        }
        let scheme_end = raw.find("://").unwrap() + 3;
        // Strip `user[:pass]@` if present.
        let after_creds = match raw[scheme_end..].find('@') {
            Some(at) => &raw[scheme_end + at + 1..],
            None => &raw[scheme_end..],
        };
        // Split on the first `/` or `?`.
        let host_end = after_creds
            .find(['/', '?'])
            .unwrap_or(after_creds.len());
        let authority = &after_creds[..host_end];
        let (host, port) = match authority.rfind(':') {
            Some(colon) => {
                let h = &authority[..colon];
                let p = authority[colon + 1..]
                    .parse::<u16>()
                    .map_err(|_| UpstreamError::InvalidUrl("port is not a valid u16".into()))?;
                (h.to_owned(), p)
            }
            None => (authority.to_owned(), 5432u16),
        };
        if host.is_empty() {
            return Err(UpstreamError::InvalidUrl("hostname is empty".into()));
        }
        // Detect ?sslmode=require / verify-ca / verify-full.
        let require_tls = raw[scheme_end + host_end..]
            .to_lowercase()
            .contains("sslmode=require")
            || raw[scheme_end + host_end..]
                .to_lowercase()
                .contains("sslmode=verify-ca")
            || raw[scheme_end + host_end..]
                .to_lowercase()
                .contains("sslmode=verify-full");
        Ok(Self {
            host,
            port,
            require_tls,
            raw,
        })
    }

    /// The libpq URL bytes — passed to `tokio_postgres::Config`.
    /// MUST NOT be logged or surfaced to the agent.
    pub fn raw(&self) -> &str {
        &self.raw
    }
}

/// Resolve the credential bytes through the backend and parse them
/// as a libpq URL. Maps every error variant to the right
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
    // The credential bytes leave the `CredentialValue` zeroize
    // boundary here only as long as the URL is being parsed — the
    // owned `String` we surface keeps the host:port + raw URL needed
    // to re-establish upstream connections, but the password
    // substring is never logged because (a) `Display` for
    // `tokio_postgres::Error` already redacts and (b)
    // `redact_for_audit()` is the only path through which the URL
    // bytes reach an audit envelope.
    value.with_bytes(|bytes| {
        std::str::from_utf8(bytes)
            .map_err(|_| UpstreamError::InvalidUrl("credential value is not UTF-8".into()))
            .and_then(ParsedUpstreamUrl::parse)
    })
}

/// Outcome of a forwarded simple query.
#[derive(Debug)]
pub struct ForwardOutcome {
    /// Wire-format frames the proxy MUST write to the agent IN ORDER.
    /// Includes RowDescription (if any rows), DataRow per row, and
    /// CommandComplete. The caller appends ReadyForQuery itself.
    pub frames: Vec<Vec<u8>>,
    /// Number of rows returned (for write statements without a
    /// result set this is `0` and `frames` is just CommandComplete).
    pub rows_returned: u64,
    /// Number of payload bytes the proxy will write to the agent
    /// (sum of `frames` lengths).
    pub bytes_returned: u64,
    /// Wall-clock duration of the upstream round trip in ms.
    pub duration_ms: u32,
}

/// One live upstream session, held across the lifetime of the
/// agent's connection (one upstream per agent in V2 — pooling is V3).
pub struct UpstreamSession {
    client: tokio_postgres::Client,
    /// Hostname the audit envelope reports.
    pub host: String,
    /// Port the audit envelope reports.
    pub port: u16,
    /// True if the URL requested TLS — V2.1 surfaces this in the
    /// audit envelope but the implementation only supports
    /// `NoTls` for the MVP. A `?sslmode=require` URL fails fast in
    /// `connect()` with `UpstreamError::Handshake`.
    pub tls: bool,
    /// Wall-clock for the connect handshake — fed into
    /// `CredentialProxyUpstreamConnected.handshake_ms`.
    pub handshake_ms: u32,
}

impl UpstreamSession {
    /// Open a new upstream session against the parsed URL.
    ///
    /// V2.1 supports plaintext only; `?sslmode=require` returns
    /// `UpstreamError::Handshake` so the operator gets a clear
    /// signal to upgrade the proxy crate when TLS-to-upstream
    /// support lands. Cloud-managed Postgres (Aurora, Neon,
    /// Azure Database for PostgreSQL) all require TLS, so the
    /// MVP path covers self-hosted Postgres and developer
    /// docker-compose fixtures only.
    pub async fn connect(
        url: &ParsedUpstreamUrl,
        connect_timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        if url.require_tls {
            return Err(UpstreamError::Handshake(
                "?sslmode=require is not supported by the V2.1 MVP — \
                 upgrade the proxy when TLS-to-upstream lands"
                    .into(),
            ));
        }
        let started = Instant::now();
        let connect_fut = async {
            let cfg: tokio_postgres::Config =
                url.raw().parse().map_err(|e: tokio_postgres::Error| {
                    UpstreamError::InvalidUrl(redact_for_audit(&e.to_string()))
                })?;
            let (client, conn) = cfg
                .connect(tokio_postgres::NoTls)
                .await
                .map_err(|e| classify_connect_error(&e))?;
            // Drive the connection in the background. If the
            // background task panics or errors, future client
            // calls return mid-stream errors which we map to
            // `UpstreamError::RelayFailed`.
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    tracing::warn!(error = %e, "upstream postgres connection task ended");
                }
            });
            Ok::<_, UpstreamError>(client)
        };
        let client = match tokio::time::timeout(connect_timeout, connect_fut).await {
            Ok(res) => res?,
            Err(_) => {
                return Err(UpstreamError::Timeout {
                    timeout_ms: connect_timeout.as_millis().min(u32::MAX as u128) as u32,
                });
            }
        };
        let handshake_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        Ok(Self {
            client,
            host: url.host.clone(),
            port: url.port,
            tls: url.require_tls,
            handshake_ms,
        })
    }

    /// Forward a simple-query SQL string to the upstream, collecting
    /// the result-set frames in agent-wire format.
    pub async fn forward_simple_query(
        &mut self,
        sql: &str,
    ) -> Result<ForwardOutcome, UpstreamError> {
        let started = Instant::now();
        let stream = self
            .client
            .simple_query_raw(sql)
            .await
            .map_err(|e| classify_query_error(&e))?;
        // `SimpleQueryStream` contains a `PhantomPinned`, so it must
        // be pinned (we keep it on the stack via `tokio::pin!`).
        tokio::pin!(stream);
        let mut frames: Vec<Vec<u8>> = Vec::new();
        let mut row_count: u64 = 0;
        let mut bytes_returned: u64 = 0;
        let mut last_columns: Option<Vec<String>> = None;
        while let Some(item) = stream.next().await {
            let item = item.map_err(|e| classify_query_error(&e))?;
            match item {
                tokio_postgres::SimpleQueryMessage::RowDescription(cols) => {
                    let names: Vec<String> = cols.iter().map(|c| c.name().to_owned()).collect();
                    let descs: Vec<FieldDescriptor> = names
                        .iter()
                        .map(|n| FieldDescriptor::text(n.as_str()))
                        .collect();
                    last_columns = Some(names);
                    let frame = row_description(&descs);
                    bytes_returned += frame.len() as u64;
                    if bytes_returned as usize > MAX_REENCODE_PAYLOAD_BYTES {
                        return Err(UpstreamError::PayloadTooLarge {
                            bytes: bytes_returned as usize,
                            max: MAX_REENCODE_PAYLOAD_BYTES,
                        });
                    }
                    frames.push(frame);
                }
                tokio_postgres::SimpleQueryMessage::Row(row) => {
                    let names = last_columns.as_ref().ok_or_else(|| {
                        UpstreamError::Handshake(
                            "upstream returned Row before RowDescription".into(),
                        )
                    })?;
                    let values: Vec<Option<&[u8]>> = (0..names.len())
                        .map(|i| row.get(i).map(|s| s.as_bytes()))
                        .collect();
                    let frame = data_row(&values);
                    bytes_returned += frame.len() as u64;
                    if bytes_returned as usize > MAX_REENCODE_PAYLOAD_BYTES {
                        return Err(UpstreamError::PayloadTooLarge {
                            bytes: bytes_returned as usize,
                            max: MAX_REENCODE_PAYLOAD_BYTES,
                        });
                    }
                    frames.push(frame);
                    row_count += 1;
                }
                tokio_postgres::SimpleQueryMessage::CommandComplete(n) => {
                    // The libpq-style command tag for SELECT is
                    // `SELECT <n>`; for INSERT it's `INSERT 0 <n>`;
                    // tokio-postgres collapses the whole thing to
                    // a row count. The proxy has the SQL text, so
                    // it can synthesize the right tag prefix.
                    let tag = derive_command_tag(sql, n);
                    let frame = command_complete(&tag);
                    bytes_returned += frame.len() as u64;
                    frames.push(frame);
                    last_columns = None;
                }
                // tokio-postgres adds non-exhaustive variants
                // (`#[non_exhaustive]`); ignore unknowns rather
                // than fail.
                _ => {}
            }
        }
        let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        Ok(ForwardOutcome {
            frames,
            rows_returned: row_count,
            bytes_returned,
            duration_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// Extended Query Protocol — V2.4
// ---------------------------------------------------------------------------

/// Metadata returned by the upstream when the proxy `prepare()`s a
/// statement. The proxy uses this to synthesize
/// `ParameterDescription` (from `param_oids`) and `RowDescription`
/// (from `columns`) responses to a `Describe` frontend message.
#[derive(Debug, Clone)]
pub struct UpstreamPreparedMeta {
    /// Server-resolved parameter type OIDs. Length ≥ the number of
    /// `$N` placeholders the proxy parsed; positions are 1:1 with
    /// `$1`, `$2`, etc.
    pub param_oids: Vec<i32>,
    /// Result-set column descriptors in declaration order. Empty
    /// for write statements that produce no rows (DML/DDL).
    pub columns: Vec<crate::wire::FieldDescriptor>,
}

impl UpstreamSession {
    /// `PREPARE`-leg of the extended-query path. The proxy hands the
    /// SQL to the upstream so we get authoritative parameter and
    /// column metadata back; we use that to fulfil the agent's
    /// `Describe('S' | 'P')` requests with the right OIDs and column
    /// list.
    ///
    /// The upstream prepare itself is restriction-free (the SQL has
    /// already been classified + restriction-checked at the agent's
    /// `Parse` step). Failures map to the same audit reasons as
    /// query forwards via `classify_query_error`.
    pub async fn prepare_statement(
        &mut self,
        sql: &str,
    ) -> Result<UpstreamPreparedMeta, UpstreamError> {
        use crate::wire::FieldDescriptor;
        let stmt = self
            .client
            .prepare(sql)
            .await
            .map_err(|e| classify_query_error(&e))?;
        let param_oids: Vec<i32> = stmt.params().iter().map(|t| t.oid() as i32).collect();
        let columns: Vec<FieldDescriptor> = stmt
            .columns()
            .iter()
            .map(|c| FieldDescriptor {
                name: c.name().to_owned(),
                table_oid: c.table_oid().unwrap_or(0) as i32,
                attribute_num: c.column_id().unwrap_or(0),
                type_oid: c.type_().oid() as i32,
                type_size: -1,
                type_modifier: -1,
                format_code: 0,
            })
            .collect();
        Ok(UpstreamPreparedMeta {
            param_oids,
            columns,
        })
    }
}

/// Map a `tokio_postgres::Error` from `connect()` to one of the
/// `UpstreamError` discriminants the proxy reports in audit.
fn classify_connect_error(e: &tokio_postgres::Error) -> UpstreamError {
    let msg = redact_for_audit(&e.to_string());
    let lower = msg.to_lowercase();
    if lower.contains("password authentication failed")
        || lower.contains("authentication failed")
        || lower.contains("no password supplied")
    {
        UpstreamError::AuthRejected(msg)
    } else if lower.contains("connection refused")
        || lower.contains("could not connect")
        || lower.contains("network is unreachable")
        || lower.contains("no route to host")
        || lower.contains("name resolution")
        || lower.contains("name or service not known")
    {
        UpstreamError::TcpConnect(msg)
    } else {
        UpstreamError::Handshake(msg)
    }
}

/// Map a `tokio_postgres::Error` from a forwarded query to one of the
/// `UpstreamError` discriminants the proxy reports in audit. Unlike
/// connect errors, query errors carry a sqlstate that the proxy
/// surfaces verbatim back to the agent in an `ErrorResponse`.
fn classify_query_error(e: &tokio_postgres::Error) -> UpstreamError {
    let msg = redact_for_audit(&e.to_string());
    let sqlstate = e
        .as_db_error()
        .map(|d| d.code().code().to_owned())
        .unwrap_or_else(|| "XX000".to_owned());
    UpstreamError::QueryFailed {
        sqlstate,
        message: msg,
    }
}

/// Synthesize the libpq-style command-complete tag from the SQL the
/// agent ran and the row count tokio-postgres reported. The proxy
/// always re-frames the result, so we have to mint these tags
/// ourselves (libpq's `psql -c "SELECT ..."` keys on the prefix to
/// pretty-print "(N rows)").
fn derive_command_tag(sql: &str, row_count: u64) -> String {
    let trimmed = sql.trim_start();
    let verb_end = trimmed
        .find(|c: char| c.is_whitespace() || c == ';')
        .unwrap_or(trimmed.len());
    let verb = trimmed[..verb_end].to_uppercase();
    match verb.as_str() {
        "INSERT" => format!("INSERT 0 {row_count}"),
        "UPDATE" | "DELETE" | "MOVE" | "FETCH" | "COPY" => format!("{verb} {row_count}"),
        "SELECT" => format!("SELECT {row_count}"),
        _ => verb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_minimal() {
        let p = ParsedUpstreamUrl::parse("postgresql://u:p@db.example.com:5432/mydb").unwrap();
        assert_eq!(p.host, "db.example.com");
        assert_eq!(p.port, 5432);
        assert!(!p.require_tls);
    }

    #[test]
    fn parse_url_default_port() {
        let p = ParsedUpstreamUrl::parse("postgresql://u:p@db/mydb").unwrap();
        assert_eq!(p.host, "db");
        assert_eq!(p.port, 5432);
    }

    #[test]
    fn parse_url_no_creds() {
        let p = ParsedUpstreamUrl::parse("postgres://localhost:6543").unwrap();
        assert_eq!(p.host, "localhost");
        assert_eq!(p.port, 6543);
    }

    #[test]
    fn parse_url_sslmode_require_marks_tls() {
        let p = ParsedUpstreamUrl::parse("postgresql://u:p@db.example.com/mydb?sslmode=require")
            .unwrap();
        assert!(p.require_tls);
    }

    #[test]
    fn parse_url_rejects_other_scheme() {
        let err = ParsedUpstreamUrl::parse("https://db.example.com").unwrap_err();
        match err {
            UpstreamError::InvalidUrl(_) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn parse_url_rejects_empty_host() {
        let err = ParsedUpstreamUrl::parse("postgresql://u:p@:5432/db").unwrap_err();
        match err {
            UpstreamError::InvalidUrl(_) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn parse_url_rejects_bad_port() {
        let err = ParsedUpstreamUrl::parse("postgresql://u:p@db:abc/mydb").unwrap_err();
        match err {
            UpstreamError::InvalidUrl(_) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn redact_password_query_param() {
        let s = "url=postgres://h?password=hunter2&user=foo";
        let red = redact_for_audit(s);
        assert!(red.contains("password=[REDACTED]"), "got: {red}");
        assert!(!red.contains("hunter2"), "got: {red}");
    }

    #[test]
    fn redact_password_in_userinfo() {
        let s = "auth failed for postgres://demo:hunter2@db/foo";
        let red = redact_for_audit(s);
        assert!(red.contains("[REDACTED]"), "got: {red}");
        assert!(!red.contains("hunter2"), "got: {red}");
    }

    #[test]
    fn audit_reason_mapping() {
        assert_eq!(
            UpstreamError::TcpConnect("x".into()).audit_reason(),
            "TcpConnectFailed"
        );
        assert_eq!(
            UpstreamError::AuthRejected("x".into()).audit_reason(),
            "AuthRejected"
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
    fn derive_command_tag_select() {
        assert_eq!(derive_command_tag("SELECT 1", 1), "SELECT 1");
        assert_eq!(derive_command_tag("  select * from t", 7), "SELECT 7");
    }

    #[test]
    fn derive_command_tag_insert_has_zero_oid() {
        assert_eq!(
            derive_command_tag("INSERT INTO t VALUES (1)", 1),
            "INSERT 0 1"
        );
    }

    #[test]
    fn derive_command_tag_update() {
        assert_eq!(derive_command_tag("UPDATE t SET x=1", 5), "UPDATE 5");
    }
}
