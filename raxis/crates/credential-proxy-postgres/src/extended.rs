//! Extended Query Protocol — frontend message handling (V2.4).
//!
//! Reference: `credential-proxy.md §14.4` (extended-query semantics)
//! and the PostgreSQL Frontend/Backend Protocol §"Extended Query".
//!
//! # Strategy
//!
//! The proxy converts the extended-query pipeline (`Parse` → `Bind`
//! → `Describe`? → `Execute` → `Sync`) into a single substituted
//! simple-query forwarded through the existing
//! [`UpstreamSession::forward_simple_query`] path. Why simple-query
//! substitution rather than a pass-through `query_raw` over
//! `tokio_postgres::Statement`?
//!
//!   * **Restriction & audit parity.** Every other allowed code path
//!     in this proxy goes through `forward_simple_query`. Reusing it
//!     keeps the per-statement audit trail (SHA-256, classification,
//!     `DatabaseQueryCompleted` envelope) byte-identical between the
//!     simple and extended paths.
//!   * **No type-OID coverage cliff.** The set of OIDs `tokio-postgres`
//!     `ToSql` natively understands is narrower than the set the
//!     proxy needs to support for ORM compatibility. By substituting
//!     parameter values into the SQL as Postgres-text literals (plus
//!     a small per-OID binary-decoder table), the proxy delegates
//!     ALL type interpretation to the upstream parser — exactly
//!     where it already happens for the simple-query path.
//!   * **Forward-compatible.** When V3 lands binary-result-format
//!     support, the substitution path stays as the V2.4 ORM
//!     compatibility lever; binary results layer on top via a
//!     parallel `query_raw` shim without replacing this module.
//!
//! Per-connection state lives in [`ExtendedState`], threaded through
//! `serve_one` for the lifetime of one accepted client connection.

use std::collections::HashMap;

use crate::upstream::{UpstreamError, UpstreamPreparedMeta};
use crate::wire::{BindMessage, BindValue, FieldDescriptor};

// ---------------------------------------------------------------------------
// Per-connection extended-query state
// ---------------------------------------------------------------------------

/// One prepared statement the proxy is tracking on this connection.
#[derive(Debug, Clone)]
pub struct ParsedStatement {
    /// SQL with `$N` placeholders, exactly as the agent sent it.
    pub sql: String,
    /// Parameter type OIDs the AGENT supplied via Parse. May be empty
    /// or contain `0` (= "let upstream infer").
    pub agent_param_oids: Vec<i32>,
    /// Cached upstream metadata after a successful `prepare(sql)`
    /// call. Populated lazily on the first Describe / Execute. `None`
    /// until first use; once populated the proxy reuses it for every
    /// subsequent Bind/Describe/Execute against this statement.
    pub upstream_meta: Option<UpstreamPreparedMeta>,
}

/// One bound portal — a prepared statement plus a concrete value
/// vector ready for `Execute`.
#[derive(Debug, Clone)]
pub struct BoundPortal {
    /// Source statement name (looked up in `prepared`).
    pub statement_name: String,
    /// Bind frame (verbatim) — kept around so the proxy can re-decode
    /// each parameter's bytes against the upstream's resolved OID
    /// list (which we may not have known when Bind arrived).
    pub bind: BindMessage,
}

/// Per-connection extended-query book-keeping.
#[derive(Debug, Default)]
pub struct ExtendedState {
    /// Statements by name (empty string = unnamed/anonymous).
    pub prepared: HashMap<String, ParsedStatement>,
    /// Portals by name (empty string = unnamed).
    pub portals: HashMap<String, BoundPortal>,
}

impl ExtendedState {
    /// Reset everything (used on session-level errors). The kernel
    /// does not currently call this — Postgres clients are expected
    /// to issue `Sync` to reset transaction state, and the proxy
    /// preserves the statement/portal cache across `Sync`s as the
    /// spec requires.
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.prepared.clear();
        self.portals.clear();
    }
}

// ---------------------------------------------------------------------------
// Parameter substitution into a simple-query SQL string
// ---------------------------------------------------------------------------

/// Errors surfaced when the proxy cannot substitute a Bind value
/// into the prepared SQL. Each variant maps to a stable
/// `(sqlstate, message)` pair the proxy returns as `ErrorResponse`.
#[derive(Debug, Clone)]
pub enum SubstitutionError {
    /// The SQL referenced `$N` for an N greater than the number of
    /// supplied parameters.
    PlaceholderOutOfRange {
        /// The 1-indexed placeholder position the SQL referenced.
        placeholder: u32,
        /// Number of values actually supplied in the Bind.
        supplied: u32,
    },
    /// A binary-format parameter's OID is not in the V2 supported set.
    /// The operator should reconfigure their driver to use text
    /// format until V3 widens the type table.
    UnsupportedBinaryOid {
        /// 1-indexed position of the offending parameter.
        position: u32,
        /// Postgres type OID the proxy did not recognise.
        oid: i32,
    },
    /// The parameter bytes did not satisfy the OID's expected layout
    /// (e.g. an int4 that is not exactly 4 bytes long).
    MalformedBinaryValue {
        /// 1-indexed position of the offending parameter.
        position: u32,
        /// Postgres type OID the proxy attempted to decode.
        oid: i32,
        /// Static description of what was wrong.
        reason: &'static str,
    },
    /// The parameter bytes are not valid UTF-8 in text format.
    /// Postgres text format is documented as ASCII / client-encoding,
    /// but the proxy's UTF-8 boundary keeps the audit chain byte-safe.
    NonUtf8TextValue {
        /// 1-indexed position of the offending parameter.
        position: u32,
    },
}

impl SubstitutionError {
    /// Map to a `(sqlstate, message)` tuple suitable for an
    /// `ErrorResponse` reply. The wire codes follow Postgres's
    /// SQLSTATE conventions:
    ///
    /// * `42P02` — undefined parameter
    /// * `0A000` — feature not supported
    /// * `22P03` — invalid binary representation
    /// * `22021` — character not in repertoire
    pub fn to_wire(&self) -> (&'static str, String) {
        match self {
            SubstitutionError::PlaceholderOutOfRange { placeholder, supplied } => (
                "42P02",
                format!(
                    "RAXIS proxy: bind references $${} but only {} parameters were supplied",
                    placeholder, supplied
                ),
            ),
            SubstitutionError::UnsupportedBinaryOid { position, oid } => (
                "0A000",
                format!(
                    "RAXIS proxy: binary-format parameter at position {} has unsupported OID {} \
                     (FAIL_PROXY_EXT_QUERY_BINARY_PARAM_UNSUPPORTED). Configure the client driver to \
                     use text-format parameters or wait for V3 binary-OID coverage.",
                    position, oid
                ),
            ),
            SubstitutionError::MalformedBinaryValue { position, oid, reason } => (
                "22P03",
                format!(
                    "RAXIS proxy: malformed binary parameter at position {} for OID {}: {}",
                    position, oid, reason
                ),
            ),
            SubstitutionError::NonUtf8TextValue { position } => (
                "22021",
                format!(
                    "RAXIS proxy: text-format parameter at position {} is not valid UTF-8",
                    position
                ),
            ),
        }
    }
}

/// Substitute the Bind frame's parameter values into the prepared
/// SQL, producing a simple-query string ready for forwarding.
///
/// `param_oids` is the upstream-resolved parameter type list (from
/// `prepare(sql)`); the proxy uses it to decode binary-format values.
/// When `param_oids` is shorter than the number of bound values
/// (e.g. upstream prepare failed and the agent supplied OIDs in the
/// Parse), the proxy falls back to the agent-supplied OIDs.
///
/// The substituted form uses dollar-quoted string literals
/// (`$raxis$...$raxis$`) for non-numeric / non-NULL values so no
/// internal escaping is required regardless of `standard_conforming_strings`.
pub fn substitute(
    sql: &str,
    bind: &BindMessage,
    param_oids: &[i32],
) -> Result<String, SubstitutionError> {
    // Pre-decode each parameter into its substituted text form once
    // (the SQL may reference $N multiple times).
    let mut decoded: Vec<DecodedParam> = Vec::with_capacity(bind.values.len());
    for (i, v) in bind.values.iter().enumerate() {
        let oid = param_oids.get(i).copied().unwrap_or(0);
        let format = bind.format_for_value(i);
        decoded.push(decode_value(i + 1, oid, format, v)?);
    }
    rewrite_placeholders(sql, &decoded)
}

/// One pre-decoded parameter ready for splice.
#[derive(Debug, Clone)]
enum DecodedParam {
    /// SQL `NULL` — emitted verbatim (no quoting).
    Null,
    /// Numeric or otherwise unquoted literal (e.g. `42`, `1.5e10`,
    /// `'\xdeadbeef'::bytea`).
    Raw(String),
    /// A text-shaped value to be wrapped in dollar quotes.
    Text(String),
}

fn decode_value(
    position: usize,
    oid: i32,
    format: i16,
    v: &BindValue,
) -> Result<DecodedParam, SubstitutionError> {
    let pos = position as u32;
    let bytes = match v {
        BindValue::Null => return Ok(DecodedParam::Null),
        BindValue::Bytes(b) => b.as_slice(),
    };
    if format == 0 {
        // Text format: bytes are already a Postgres text literal.
        let s = std::str::from_utf8(bytes)
            .map_err(|_| SubstitutionError::NonUtf8TextValue { position: pos })?;
        return Ok(text_decoded_with_cast(oid, s));
    }
    if format != 1 {
        return Err(SubstitutionError::UnsupportedBinaryOid { position: pos, oid });
    }
    decode_binary(pos, oid, bytes)
}

/// For a known set of OIDs, attach a type cast (`::int4`) so the
/// upstream parser interprets the substituted literal correctly even
/// when the surrounding SQL is type-ambiguous (e.g. `SELECT $1`).
/// Outside the canonical set the proxy emits a bare dollar-quoted
/// string and lets the upstream's implicit coercion sort it out.
fn text_decoded_with_cast(oid: i32, s: &str) -> DecodedParam {
    use oids::*;
    match oid {
        BOOL => match s.trim() {
            "t" | "T" | "true" | "TRUE" | "1" | "yes" | "YES" => DecodedParam::Raw("TRUE".into()),
            "f" | "F" | "false" | "FALSE" | "0" | "no" | "NO" => DecodedParam::Raw("FALSE".into()),
            other => DecodedParam::Raw(format!("{}::bool", dollar_quote(other))),
        },
        INT2 | INT4 | INT8 | OID | XID | OID_REGCLASS | OID_REGPROC => {
            // Numeric literal — emit as cast to be explicit when the
            // surrounding SQL is `SELECT $1`.
            let cast = match oid {
                INT2 => "::int2",
                INT4 => "::int4",
                INT8 => "::int8",
                OID => "::oid",
                _ => "",
            };
            DecodedParam::Raw(format!("{}{}", dollar_quote(s), cast))
        }
        FLOAT4 => DecodedParam::Raw(format!("{}::float4", dollar_quote(s))),
        FLOAT8 => DecodedParam::Raw(format!("{}::float8", dollar_quote(s))),
        NUMERIC => DecodedParam::Raw(format!("{}::numeric", dollar_quote(s))),
        UUID => DecodedParam::Raw(format!("{}::uuid", dollar_quote(s))),
        DATE => DecodedParam::Raw(format!("{}::date", dollar_quote(s))),
        TIME => DecodedParam::Raw(format!("{}::time", dollar_quote(s))),
        TIMETZ => DecodedParam::Raw(format!("{}::timetz", dollar_quote(s))),
        TIMESTAMP => DecodedParam::Raw(format!("{}::timestamp", dollar_quote(s))),
        TIMESTAMPTZ => DecodedParam::Raw(format!("{}::timestamptz", dollar_quote(s))),
        JSON => DecodedParam::Raw(format!("{}::json", dollar_quote(s))),
        JSONB => DecodedParam::Raw(format!("{}::jsonb", dollar_quote(s))),
        BYTEA => DecodedParam::Raw(format!("{}::bytea", dollar_quote(s))),
        _ => DecodedParam::Text(s.to_owned()),
    }
}

fn decode_binary(position: u32, oid: i32, bytes: &[u8]) -> Result<DecodedParam, SubstitutionError> {
    use oids::*;
    match oid {
        BOOL => {
            if bytes.len() != 1 {
                return Err(SubstitutionError::MalformedBinaryValue {
                    position,
                    oid,
                    reason: "bool must be 1 byte",
                });
            }
            Ok(DecodedParam::Raw(if bytes[0] != 0 {
                "TRUE".into()
            } else {
                "FALSE".into()
            }))
        }
        INT2 => {
            if bytes.len() != 2 {
                return Err(SubstitutionError::MalformedBinaryValue {
                    position,
                    oid,
                    reason: "int2 must be 2 bytes",
                });
            }
            let v = i16::from_be_bytes([bytes[0], bytes[1]]);
            Ok(DecodedParam::Raw(format!("{v}::int2")))
        }
        INT4 | OID | XID => {
            if bytes.len() != 4 {
                return Err(SubstitutionError::MalformedBinaryValue {
                    position,
                    oid,
                    reason: "int4 must be 4 bytes",
                });
            }
            let v = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let cast = match oid {
                INT4 => "::int4",
                OID => "::oid",
                XID => "::xid",
                _ => "",
            };
            Ok(DecodedParam::Raw(format!("{v}{cast}")))
        }
        INT8 => {
            if bytes.len() != 8 {
                return Err(SubstitutionError::MalformedBinaryValue {
                    position,
                    oid,
                    reason: "int8 must be 8 bytes",
                });
            }
            let mut a = [0u8; 8];
            a.copy_from_slice(bytes);
            let v = i64::from_be_bytes(a);
            Ok(DecodedParam::Raw(format!("{v}::int8")))
        }
        FLOAT4 => {
            if bytes.len() != 4 {
                return Err(SubstitutionError::MalformedBinaryValue {
                    position,
                    oid,
                    reason: "float4 must be 4 bytes",
                });
            }
            let v = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Ok(DecodedParam::Raw(format!("'{v}'::float4")))
        }
        FLOAT8 => {
            if bytes.len() != 8 {
                return Err(SubstitutionError::MalformedBinaryValue {
                    position,
                    oid,
                    reason: "float8 must be 8 bytes",
                });
            }
            let mut a = [0u8; 8];
            a.copy_from_slice(bytes);
            let v = f64::from_be_bytes(a);
            Ok(DecodedParam::Raw(format!("'{v}'::float8")))
        }
        TEXT | VARCHAR | BPCHAR | NAME | UNKNOWN_TEXT => {
            // Text-shaped types use UTF-8-ish bytes in BOTH text and
            // binary modes (binary representation IS the UTF-8 bytes,
            // no length prefix). We treat them as opaque strings.
            let s = std::str::from_utf8(bytes)
                .map_err(|_| SubstitutionError::NonUtf8TextValue { position })?;
            Ok(DecodedParam::Text(s.to_owned()))
        }
        BYTEA => {
            // Binary `bytea` is just the raw bytes; render as the
            // canonical hex form.
            Ok(DecodedParam::Raw(format!(
                "'\\x{}'::bytea",
                hex_lower(bytes)
            )))
        }
        UUID => {
            if bytes.len() != 16 {
                return Err(SubstitutionError::MalformedBinaryValue {
                    position,
                    oid,
                    reason: "uuid must be 16 bytes",
                });
            }
            // Format as 8-4-4-4-12 hex.
            let h = hex_lower(bytes);
            let formatted = format!(
                "{}-{}-{}-{}-{}",
                &h[0..8],
                &h[8..12],
                &h[12..16],
                &h[16..20],
                &h[20..32],
            );
            Ok(DecodedParam::Raw(format!("'{formatted}'::uuid")))
        }
        JSON | JSONB => {
            // jsonb binary has a 1-byte version prefix (`\x01`); v1
            // is the only version Postgres ever emitted. Strip it
            // for jsonb; json is already plain text.
            let payload = if oid == JSONB && !bytes.is_empty() && bytes[0] == 1 {
                &bytes[1..]
            } else {
                bytes
            };
            let s = std::str::from_utf8(payload)
                .map_err(|_| SubstitutionError::NonUtf8TextValue { position })?;
            let cast = if oid == JSON { "::json" } else { "::jsonb" };
            Ok(DecodedParam::Raw(format!("{}{}", dollar_quote(s), cast)))
        }
        _ => Err(SubstitutionError::UnsupportedBinaryOid { position, oid }),
    }
}

fn rewrite_placeholders(sql: &str, decoded: &[DecodedParam]) -> Result<String, SubstitutionError> {
    let mut out = String::with_capacity(sql.len() + 32);
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // Skip over single-quoted strings, dollar-quoted strings,
        // double-quoted identifiers, and `--` / `/* */` comments so
        // a literal `$1` inside them is left untouched.
        if c == b'\'' {
            let end = scan_single_quoted(bytes, i);
            out.push_str(&sql[i..end]);
            i = end;
            continue;
        }
        if c == b'"' {
            let end = scan_double_quoted(bytes, i);
            out.push_str(&sql[i..end]);
            i = end;
            continue;
        }
        if c == b'-' && bytes.get(i + 1) == Some(&b'-') {
            let end = scan_line_comment(bytes, i);
            out.push_str(&sql[i..end]);
            i = end;
            continue;
        }
        if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let end = scan_block_comment(bytes, i);
            out.push_str(&sql[i..end]);
            i = end;
            continue;
        }
        if c == b'$' {
            // Could be either `$tag$...$tag$` (dollar-quoted string)
            // or `$N` (placeholder).
            if let Some((tag_len, body_end)) = scan_dollar_quote(bytes, i) {
                let end = body_end + tag_len;
                out.push_str(&sql[i..end]);
                i = end;
                continue;
            }
            // Try to parse a positional placeholder: `$` followed
            // by one or more ASCII digits.
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 {
                let n_str = &sql[i + 1..j];
                let n: u32 =
                    n_str
                        .parse()
                        .map_err(|_| SubstitutionError::PlaceholderOutOfRange {
                            placeholder: 0,
                            supplied: decoded.len() as u32,
                        })?;
                if n == 0 || (n as usize) > decoded.len() {
                    return Err(SubstitutionError::PlaceholderOutOfRange {
                        placeholder: n,
                        supplied: decoded.len() as u32,
                    });
                }
                match &decoded[(n - 1) as usize] {
                    DecodedParam::Null => out.push_str("NULL"),
                    DecodedParam::Raw(s) => out.push_str(s),
                    DecodedParam::Text(s) => out.push_str(&dollar_quote(s)),
                }
                i = j;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    Ok(out)
}

fn scan_single_quoted(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            // `''` is an embedded quote.
            if bytes.get(i + 1) == Some(&b'\'') {
                i += 2;
                continue;
            }
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

fn scan_double_quoted(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if bytes.get(i + 1) == Some(&b'"') {
                i += 2;
                continue;
            }
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

fn scan_line_comment(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 2;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

fn scan_block_comment(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 2;
    while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            return i + 2;
        }
        i += 1;
    }
    bytes.len()
}

/// Detect `$tag$...$tag$` at `start`; returns `(tag_len, body_end)`
/// where the close-tag begins at `body_end`. `tag` may be empty
/// (`$$...$$`).
fn scan_dollar_quote(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    if bytes[start] != b'$' {
        return None;
    }
    // Tag is `[A-Za-z_][A-Za-z0-9_]*` between two `$`.
    let mut j = start + 1;
    if j < bytes.len() && (bytes[j].is_ascii_alphabetic() || bytes[j] == b'_') {
        j += 1;
        while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
            j += 1;
        }
    }
    if j >= bytes.len() || bytes[j] != b'$' {
        // `$$...$$` (empty tag) is the only valid alternative.
        if j == start + 1 && bytes.get(start + 1) == Some(&b'$') {
            // Body starts at start+2; close tag is `$$`.
            let body_start = start + 2;
            let mut k = body_start;
            while k + 1 < bytes.len() {
                if bytes[k] == b'$' && bytes[k + 1] == b'$' {
                    return Some((2, k));
                }
                k += 1;
            }
            return None;
        }
        return None;
    }
    let tag_end = j; // points at the closing `$` of the open tag
    let tag_len = tag_end - start + 1; // includes both `$`
    let close_tag = &bytes[start..tag_end + 1];
    let body_start = tag_end + 1;
    let mut k = body_start;
    while k + close_tag.len() <= bytes.len() {
        if bytes[k] == b'$' && &bytes[k..k + close_tag.len()] == close_tag {
            return Some((tag_len, k));
        }
        k += 1;
    }
    None
}

/// Pick a dollar-quote tag that does not collide with the value's
/// bytes. The vast majority of values have no `$` sequences and use
/// the bare tag; the worst case is bounded by O(value-length).
fn dollar_quote(s: &str) -> String {
    let mut tag: String = "raxis".to_owned();
    while s.contains(&format!("${tag}$")) {
        tag.push('q');
    }
    format!("${tag}${s}${tag}$")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Canonical Postgres type OIDs used by the substitution layer. The
/// upstream is the source of truth — these mirror the values from
/// `tokio_postgres::types::Type::*`.
mod oids {
    pub const BOOL: i32 = 16;
    pub const BYTEA: i32 = 17;
    pub const NAME: i32 = 19;
    pub const INT8: i32 = 20;
    pub const INT2: i32 = 21;
    pub const INT4: i32 = 23;
    pub const TEXT: i32 = 25;
    pub const OID: i32 = 26;
    pub const XID: i32 = 28;
    pub const FLOAT4: i32 = 700;
    pub const FLOAT8: i32 = 701;
    pub const UNKNOWN_TEXT: i32 = 705;
    pub const BPCHAR: i32 = 1042;
    pub const VARCHAR: i32 = 1043;
    pub const DATE: i32 = 1082;
    pub const TIME: i32 = 1083;
    pub const TIMESTAMP: i32 = 1114;
    pub const TIMESTAMPTZ: i32 = 1184;
    pub const TIMETZ: i32 = 1266;
    pub const NUMERIC: i32 = 1700;
    pub const UUID: i32 = 2950;
    pub const JSON: i32 = 114;
    pub const JSONB: i32 = 3802;
    pub const OID_REGCLASS: i32 = 2205;
    pub const OID_REGPROC: i32 = 24;
}

/// Convenience: build a `RowDescription` frame from the upstream's
/// resolved column metadata. Used to satisfy the agent's `Describe`
/// frontend message.
pub fn row_description_for(meta: &UpstreamPreparedMeta) -> Option<Vec<u8>> {
    if meta.columns.is_empty() {
        None
    } else {
        Some(crate::wire::row_description(&meta.columns))
    }
}

/// Convert an `UpstreamError` arising from a `prepare()` call into a
/// Postgres-flavoured `(sqlstate, message)` pair the proxy returns to
/// the agent. Matches the discriminants `forward_simple_query` uses
/// so the error surface stays uniform across simple and extended
/// query paths.
pub fn prepare_error_to_wire(e: &UpstreamError) -> (String, String) {
    match e {
        UpstreamError::QueryFailed { sqlstate, message } => (sqlstate.clone(), message.clone()),
        UpstreamError::InvalidUrl(_) => (
            "08000".into(),
            "RAXIS proxy: upstream URL invalid (FAIL_PROXY_UPSTREAM_URL_INVALID)".into(),
        ),
        UpstreamError::AuthRejected(_) => (
            "28P01".into(),
            "RAXIS proxy: upstream authentication rejected (FAIL_PROXY_UPSTREAM_AUTH_REJECTED)"
                .into(),
        ),
        UpstreamError::TcpConnect(_) | UpstreamError::Timeout { .. } => (
            "08006".into(),
            "RAXIS proxy: upstream unreachable (FAIL_PROXY_UPSTREAM_UNREACHABLE)".into(),
        ),
        _ => (
            "XX000".into(),
            "RAXIS proxy: upstream prepare failed".into(),
        ),
    }
}

/// Compose a `FieldDescriptor` list into a small sanity check for
/// equality assertions in tests.
#[allow(dead_code)]
pub fn columns_signature(cols: &[FieldDescriptor]) -> Vec<(String, i32)> {
    cols.iter().map(|c| (c.name.clone(), c.type_oid)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{BindMessage, BindValue};

    fn bind(values: Vec<BindValue>, fmts: Vec<i16>) -> BindMessage {
        BindMessage {
            portal_name: String::new(),
            statement_name: String::new(),
            param_format_codes: fmts,
            values,
            result_format_codes: Vec::new(),
        }
    }

    #[test]
    fn substitute_text_int_param() {
        let b = bind(vec![BindValue::Bytes(b"42".to_vec())], vec![]);
        let out = substitute("SELECT $1", &b, &[oids::INT4]).unwrap();
        assert!(out.contains("42"), "got {out}");
    }

    #[test]
    fn substitute_null_inlines_keyword() {
        let b = bind(vec![BindValue::Null], vec![]);
        let out = substitute("SELECT $1", &b, &[oids::INT4]).unwrap();
        assert_eq!(out, "SELECT NULL");
    }

    #[test]
    fn substitute_text_string_uses_dollar_quote() {
        let b = bind(vec![BindValue::Bytes(b"hello world".to_vec())], vec![]);
        let out = substitute("SELECT $1", &b, &[oids::TEXT]).unwrap();
        assert!(out.contains("$raxis$hello world$raxis$"), "got {out}");
    }

    #[test]
    fn substitute_text_string_with_single_quotes_does_not_break() {
        let b = bind(vec![BindValue::Bytes(b"O'Brien".to_vec())], vec![]);
        let out = substitute("SELECT $1", &b, &[oids::TEXT]).unwrap();
        assert!(out.contains("$raxis$O'Brien$raxis$"), "got {out}");
    }

    #[test]
    fn substitute_text_string_with_collision_picks_alternate_tag() {
        // Value contains `$raxis$` so the substitutor must pick a
        // different tag.
        let v = b"abc $raxis$ xyz".to_vec();
        let b = bind(vec![BindValue::Bytes(v)], vec![]);
        let out = substitute("SELECT $1", &b, &[oids::TEXT]).unwrap();
        assert!(out.contains("$raxisq$"), "got {out}");
    }

    #[test]
    fn substitute_binary_int4_decodes_be() {
        let bytes = 12345i32.to_be_bytes().to_vec();
        let b = bind(vec![BindValue::Bytes(bytes)], vec![1]);
        let out = substitute("SELECT $1", &b, &[oids::INT4]).unwrap();
        assert!(out.contains("12345"), "got {out}");
    }

    #[test]
    fn substitute_binary_unsupported_oid_errors() {
        let b = bind(vec![BindValue::Bytes(vec![0xff])], vec![1]);
        let err = substitute("SELECT $1", &b, &[9999]).unwrap_err();
        match err {
            SubstitutionError::UnsupportedBinaryOid { position, oid } => {
                assert_eq!(position, 1);
                assert_eq!(oid, 9999);
            }
            other => panic!("expected UnsupportedBinaryOid, got {other:?}"),
        }
    }

    #[test]
    fn substitute_placeholder_out_of_range() {
        let b = bind(vec![BindValue::Bytes(b"x".to_vec())], vec![]);
        let err = substitute("SELECT $2", &b, &[oids::TEXT]).unwrap_err();
        match err {
            SubstitutionError::PlaceholderOutOfRange {
                placeholder,
                supplied,
            } => {
                assert_eq!(placeholder, 2);
                assert_eq!(supplied, 1);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn substitute_skips_placeholder_inside_string_literal() {
        // `$1` inside a single-quoted string must NOT be replaced.
        let b = bind(vec![BindValue::Bytes(b"X".to_vec())], vec![]);
        let out = substitute("SELECT 'has $1 inside', $1", &b, &[oids::TEXT]).unwrap();
        assert!(out.contains("'has $1 inside'"));
        assert!(out.contains("$raxis$X$raxis$"));
    }

    #[test]
    fn substitute_skips_placeholder_inside_dollar_quote() {
        let b = bind(vec![BindValue::Bytes(b"X".to_vec())], vec![]);
        let out = substitute("SELECT $tag$has $1 inside$tag$, $1", &b, &[oids::TEXT]).unwrap();
        assert!(out.contains("$tag$has $1 inside$tag$"));
        assert!(out.contains("$raxis$X$raxis$"));
    }

    #[test]
    fn substitute_skips_placeholder_inside_line_comment() {
        let b = bind(vec![BindValue::Bytes(b"X".to_vec())], vec![]);
        let out = substitute("SELECT 1 -- ignore $1\nSELECT $1", &b, &[oids::TEXT]).unwrap();
        assert!(out.contains("-- ignore $1"));
        assert!(out.contains("$raxis$X$raxis$"));
    }

    #[test]
    fn substitute_three_params_in_order() {
        let b = bind(
            vec![
                BindValue::Bytes(b"1".to_vec()),
                BindValue::Bytes(b"2".to_vec()),
                BindValue::Bytes(b"3".to_vec()),
            ],
            vec![],
        );
        let out = substitute(
            "SELECT $1, $2, $3, $1",
            &b,
            &[oids::INT4, oids::INT4, oids::INT4],
        )
        .unwrap();
        // Three references to "1", one to "2", one to "3".
        assert_eq!(out.matches('1').count(), 2);
        assert_eq!(out.matches('2').count(), 1);
        assert_eq!(out.matches('3').count(), 1);
    }

    #[test]
    fn substitute_uuid_binary_decode() {
        // 16 bytes -> 8-4-4-4-12 hex form.
        let bytes: Vec<u8> = (0u8..16).collect();
        let b = bind(vec![BindValue::Bytes(bytes)], vec![1]);
        let out = substitute("SELECT $1", &b, &[oids::UUID]).unwrap();
        assert!(
            out.contains("'00010203-0405-0607-0809-0a0b0c0d0e0f'::uuid"),
            "got {out}"
        );
    }

    #[test]
    fn substitute_bool_text() {
        let b = bind(vec![BindValue::Bytes(b"t".to_vec())], vec![]);
        let out = substitute("SELECT $1", &b, &[oids::BOOL]).unwrap();
        assert!(out.contains("TRUE"), "got {out}");
    }

    #[test]
    fn substitute_bool_binary() {
        let b = bind(vec![BindValue::Bytes(vec![1])], vec![1]);
        let out = substitute("SELECT $1", &b, &[oids::BOOL]).unwrap();
        assert!(out.contains("TRUE"), "got {out}");
        let b2 = bind(vec![BindValue::Bytes(vec![0])], vec![1]);
        let out2 = substitute("SELECT $1", &b2, &[oids::BOOL]).unwrap();
        assert!(out2.contains("FALSE"), "got {out2}");
    }

    #[test]
    fn substitute_int8_binary() {
        let bytes = 9_999_999_999i64.to_be_bytes().to_vec();
        let b = bind(vec![BindValue::Bytes(bytes)], vec![1]);
        let out = substitute("SELECT $1", &b, &[oids::INT8]).unwrap();
        assert!(out.contains("9999999999"), "got {out}");
    }

    #[test]
    fn substitute_bytea_binary() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let b = bind(vec![BindValue::Bytes(bytes)], vec![1]);
        let out = substitute("SELECT $1", &b, &[oids::BYTEA]).unwrap();
        assert!(out.contains("'\\xdeadbeef'::bytea"), "got {out}");
    }

    #[test]
    fn substitute_jsonb_binary_strips_version_byte() {
        let mut v = Vec::new();
        v.push(1u8); // version
        v.extend_from_slice(b"{\"a\":1}");
        let b = bind(vec![BindValue::Bytes(v)], vec![1]);
        let out = substitute("SELECT $1", &b, &[oids::JSONB]).unwrap();
        assert!(out.contains("$raxis${\"a\":1}$raxis$::jsonb"), "got {out}");
    }
}
