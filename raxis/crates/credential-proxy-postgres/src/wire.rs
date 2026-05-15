//! Postgres wire-protocol message helpers.
//!
//! Reference: PostgreSQL Frontend/Backend Protocol §"Message Formats".
//! <https://www.postgresql.org/docs/16/protocol-message-formats.html>
//!
//! All message bodies are big-endian. Message framing is:
//!   * Backend / Frontend (post-startup): `<u8 tag><i32 length><body>`
//!     where `length` covers the int32 itself (so body length =
//!     length - 4).
//!   * Startup / SSL / Cancel (no tag): `<i32 length><body>`.

use std::io;

use bytes::{BufMut, BytesMut};
use tokio::io::AsyncReadExt;

/// Result of the very first read from a freshly-accepted connection.
#[derive(Debug)]
pub enum StartupKind {
    /// Plain `StartupMessage` with parameters (we don't parse them
    /// in the MVP; we accept the connection regardless).
    Startup(Vec<u8>),
    /// Client requested SSL (8 bytes, code `80877103`).
    SslRequest,
    /// Client requested cancel (16 bytes, code `80877102`).
    CancelRequest,
}

/// Read the first message of a Postgres protocol session.
pub async fn read_startup<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<StartupKind> {
    let len = r.read_i32().await?;
    if !(8..=1_000_000).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("startup length out of range: {len}"),
        ));
    }
    let mut buf = vec![0u8; (len as usize) - 4];
    r.read_exact(&mut buf).await?;
    if buf.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup too short",
        ));
    }
    let code = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    match code {
        80877103 => Ok(StartupKind::SslRequest),
        80877102 => Ok(StartupKind::CancelRequest),
        // Protocol version 3.0 = 196608.
        196608 => Ok(StartupKind::Startup(buf)),
        // Newer 3.x protocols are still acceptable for the MVP.
        v if (v >> 16) == 3 => Ok(StartupKind::Startup(buf)),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported startup code {other}"),
        )),
    }
}

/// Read the body of a tagged frontend message (length-prefixed).
pub async fn read_message_body<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = r.read_i32().await?;
    if !(4..=10_000_000).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frontend message length out of range: {len}"),
        ));
    }
    let mut body = vec![0u8; (len as usize) - 4];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Parse a `Query` message body — a single C-string SQL.
pub fn parse_query_message(body: &[u8]) -> Result<String, &'static str> {
    let nul = body
        .iter()
        .position(|&b| b == 0)
        .ok_or("missing NUL terminator")?;
    let s = std::str::from_utf8(&body[..nul]).map_err(|_| "non-UTF-8 SQL")?;
    Ok(s.to_owned())
}

// ---------------------------------------------------------------------------
// Backend message constructors (responses written by the proxy).
// ---------------------------------------------------------------------------

fn put_tagged<F: FnOnce(&mut BytesMut)>(tag: u8, write_body: F) -> Vec<u8> {
    let mut body = BytesMut::with_capacity(64);
    write_body(&mut body);
    let len = (body.len() as i32) + 4;
    let mut out = Vec::with_capacity(1 + 4 + body.len());
    out.push(tag);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// `'R'` AuthenticationOk (i32 0).
pub fn authentication_ok() -> Vec<u8> {
    put_tagged(b'R', |b| b.put_i32(0))
}

/// `'S'` ParameterStatus (key, value as C strings).
pub fn parameter_status(key: &str, value: &str) -> Vec<u8> {
    put_tagged(b'S', |b| {
        b.put_slice(key.as_bytes());
        b.put_u8(0);
        b.put_slice(value.as_bytes());
        b.put_u8(0);
    })
}

/// `'K'` BackendKeyData (process_id, secret_key).
pub fn backend_key_data(process_id: i32, secret_key: i32) -> Vec<u8> {
    put_tagged(b'K', |b| {
        b.put_i32(process_id);
        b.put_i32(secret_key);
    })
}

/// `'Z'` ReadyForQuery (status byte: `'I'` idle, `'T'` in tx, `'E'` failed tx).
pub fn ready_for_query(status: u8) -> Vec<u8> {
    put_tagged(b'Z', |b| b.put_u8(status))
}

/// `'C'` CommandComplete (tag string).
pub fn command_complete(tag: &str) -> Vec<u8> {
    put_tagged(b'C', |b| {
        b.put_slice(tag.as_bytes());
        b.put_u8(0);
    })
}

/// `'E'` ErrorResponse with severity, sqlstate, message.
pub fn error_response(severity: &[u8], sqlstate: &[u8], message: &str) -> Vec<u8> {
    put_tagged(b'E', |b| {
        b.put_u8(b'S');
        b.put_slice(severity);
        b.put_u8(0);
        b.put_u8(b'V');
        b.put_slice(severity);
        b.put_u8(0);
        b.put_u8(b'C');
        b.put_slice(sqlstate);
        b.put_u8(0);
        b.put_u8(b'M');
        b.put_slice(message.as_bytes());
        b.put_u8(0);
        b.put_u8(0);
    })
}

/// Single column descriptor for a `'T'` `RowDescription` frame.
///
/// The proxy minted these from the upstream's column metadata when
/// re-encoding a forwarded result-set into Postgres wire format. Every
/// row that follows must agree on the field count and ordering; the
/// upstream Postgres driver enforces that for us, so the proxy only
/// has to copy the `name` field and use safe defaults for the rest.
#[derive(Debug, Clone)]
pub struct FieldDescriptor {
    /// Column name as the upstream returned it (UTF-8). The proxy
    /// truncates names longer than 255 bytes since libpq's wire
    /// format implicitly assumes short identifiers.
    pub name: String,
    /// OID of the source table the column came from, or 0 if the
    /// upstream did not surface one (e.g. `SELECT 1`).
    pub table_oid: i32,
    /// Attribute number within the source table (1-indexed), or 0.
    pub attribute_num: i16,
    /// Column type OID — `25` (`text`) is a safe default when the
    /// proxy has no better information; the agent's libpq will
    /// surface every value as a `text`.
    pub type_oid: i32,
    /// Column type size in bytes (`-1` = variable-length).
    pub type_size: i16,
    /// Type modifier (`-1` if absent).
    pub type_modifier: i32,
    /// Format code: `0` = text, `1` = binary. The proxy emits
    /// `text` because tokio-postgres's `simple_query_raw` API
    /// returns text-encoded values.
    pub format_code: i16,
}

impl FieldDescriptor {
    /// Construct a `text`-format column descriptor with the given
    /// name. Used by the proxy's upstream re-encoder when the
    /// upstream metadata doesn't carry a richer type OID.
    pub fn text(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            table_oid: 0,
            attribute_num: 0,
            type_oid: 25, // text
            type_size: -1,
            type_modifier: -1,
            format_code: 0, // text
        }
    }
}

/// `'T'` RowDescription frame.
///
/// Body layout (per Postgres protocol):
///
/// * `i16` field count
/// * for each field:
///   * C-string column name
///   * `i32` table OID
///   * `i16` attribute number
///   * `i32` data type OID
///   * `i16` data type size
///   * `i32` type modifier
///   * `i16` format code (0 = text, 1 = binary)
pub fn row_description(fields: &[FieldDescriptor]) -> Vec<u8> {
    put_tagged(b'T', |b| {
        b.put_i16(fields.len() as i16);
        for f in fields {
            // Truncate names defensively — the wire field is
            // implicitly bounded by `i16::MAX` total bytes per
            // RowDescription, which 255 keeps comfortably under.
            let name_bytes = f.name.as_bytes();
            let name = if name_bytes.len() > 255 {
                &name_bytes[..255]
            } else {
                name_bytes
            };
            b.put_slice(name);
            b.put_u8(0);
            b.put_i32(f.table_oid);
            b.put_i16(f.attribute_num);
            b.put_i32(f.type_oid);
            b.put_i16(f.type_size);
            b.put_i32(f.type_modifier);
            b.put_i16(f.format_code);
        }
    })
}

/// `'D'` DataRow frame.
///
/// Each value is `Some(bytes)` for the column's text-format payload
/// or `None` for SQL `NULL` (encoded as length `-1` in Postgres wire).
pub fn data_row(values: &[Option<&[u8]>]) -> Vec<u8> {
    put_tagged(b'D', |b| {
        b.put_i16(values.len() as i16);
        for v in values {
            match v {
                Some(bytes) => {
                    b.put_i32(bytes.len() as i32);
                    b.put_slice(bytes);
                }
                None => {
                    b.put_i32(-1);
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Extended Query Protocol (V2.4)
// ---------------------------------------------------------------------------
//
// Reference: PostgreSQL Frontend/Backend Protocol §"Extended Query".
// <https://www.postgresql.org/docs/16/protocol-flow.html#PROTOCOL-FLOW-EXT-QUERY>
//
// Frontend tags handled here:
//
// | Tag | Name      | Body shape                                                                  |
// |-----|-----------|-----------------------------------------------------------------------------|
// | 'P' | Parse     | <name C-str><sql C-str><i16 param_count>(<i32 oid>)*                        |
// | 'B' | Bind      | <portal C-str><stmt C-str><i16 fmt_count>(<i16>)*<i16 val_count>            |
// |     |           |   (<i32 len><bytes>|<-1>)*<i16 res_fmt_count>(<i16>)*                       |
// | 'D' | Describe  | <kind u8 'S'|'P'><name C-str>                                               |
// | 'E' | Execute   | <portal C-str><i32 max_rows>                                                |
// | 'S' | Sync      | (empty)                                                                     |
// | 'C' | Close     | <kind u8 'S'|'P'><name C-str>                                               |
// | 'H' | Flush     | (empty)                                                                     |
//
// Backend builders:
//
// | Tag | Name                | Body shape                                          |
// |-----|---------------------|-----------------------------------------------------|
// | '1' | ParseComplete       | (empty)                                             |
// | '2' | BindComplete        | (empty)                                             |
// | '3' | CloseComplete       | (empty)                                             |
// | 't' | ParameterDescription| <i16 count>(<i32 oid>)*                             |
// | 'n' | NoData              | (empty)                                             |
// | 's' | PortalSuspended     | (empty)                                             |
//
// The frontend tag 'S' Sync collides with the post-startup tag 'S'
// — context (post-startup vs. pre-startup) tells the proxy which
// applies; the proxy is post-startup at the point the dispatcher
// sees them.

/// One parameter type OID block from a `Parse` frontend message.
pub const PG_OID_UNSPECIFIED: i32 = 0;

/// Parsed `'P'` Parse message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMessage {
    /// Prepared-statement name (empty = unnamed/anonymous statement).
    pub statement_name: String,
    /// SQL text with `$N` parameter placeholders.
    pub sql: String,
    /// Parameter type OIDs declared by the client. May be empty,
    /// shorter than the number of `$N` placeholders, or contain
    /// `0` (unspecified) entries — the proxy treats any of these as
    /// "let upstream infer".
    pub param_oids: Vec<i32>,
}

/// Parse a `'P'` Parse message body.
pub fn parse_parse_message(body: &[u8]) -> Result<ParseMessage, &'static str> {
    let (name, rest) = read_cstr(body)?;
    let (sql, rest) = read_cstr(rest)?;
    let (count, mut rest) = read_i16(rest)?;
    if count < 0 {
        return Err("negative param count");
    }
    let mut oids = Vec::with_capacity(count as usize);
    for _ in 0..count as usize {
        let (oid, r) = read_i32(rest)?;
        oids.push(oid);
        rest = r;
    }
    Ok(ParseMessage {
        statement_name: name.to_owned(),
        sql: sql.to_owned(),
        param_oids: oids,
    })
}

/// One parameter value in a `Bind` body. The proxy preserves the raw
/// bytes plus their format code so it can decode according to the
/// resolved column type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindValue {
    /// SQL `NULL` (length-prefix `-1` in the wire body).
    Null,
    /// Non-null value bytes (verbatim from the wire).
    Bytes(Vec<u8>),
}

/// Parsed `'B'` Bind message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMessage {
    /// Portal name (empty = unnamed).
    pub portal_name: String,
    /// Source prepared-statement name.
    pub statement_name: String,
    /// Parameter format codes. Length is either 0 (all values are
    /// text), 1 (all values share the single code), or equal to
    /// `values.len()` (per-value codes). 0 = text, 1 = binary.
    pub param_format_codes: Vec<i16>,
    /// One entry per parameter (positions are 1-indexed → `$1`, etc).
    pub values: Vec<BindValue>,
    /// Result-column format codes. Same shape rules as
    /// `param_format_codes`. The V2 proxy always emits text result
    /// rows regardless of this field's contents — operators get
    /// interoperable wire shape; binary-format results are V3.
    pub result_format_codes: Vec<i16>,
}

impl BindMessage {
    /// Resolve the per-value format code for the `i`-th parameter.
    /// Mirrors the Postgres wire rule: 0 codes = text; 1 code =
    /// applies to every value; N codes = per-value override.
    pub fn format_for_value(&self, i: usize) -> i16 {
        match self.param_format_codes.len() {
            0 => 0,
            1 => self.param_format_codes[0],
            _ => *self.param_format_codes.get(i).unwrap_or(&0),
        }
    }
}

/// Parse a `'B'` Bind message body.
pub fn parse_bind_message(body: &[u8]) -> Result<BindMessage, &'static str> {
    let (portal, rest) = read_cstr(body)?;
    let (stmt, rest) = read_cstr(rest)?;
    let (fmt_count, mut rest) = read_i16(rest)?;
    if fmt_count < 0 {
        return Err("negative format count");
    }
    let mut formats = Vec::with_capacity(fmt_count as usize);
    for _ in 0..fmt_count as usize {
        let (code, r) = read_i16(rest)?;
        formats.push(code);
        rest = r;
    }
    let (val_count, mut rest) = read_i16(rest)?;
    if val_count < 0 {
        return Err("negative value count");
    }
    let mut values = Vec::with_capacity(val_count as usize);
    for _ in 0..val_count as usize {
        let (len, r) = read_i32(rest)?;
        rest = r;
        if len == -1 {
            values.push(BindValue::Null);
        } else if len < 0 {
            return Err("invalid value length");
        } else {
            let n = len as usize;
            if rest.len() < n {
                return Err("truncated bind value");
            }
            values.push(BindValue::Bytes(rest[..n].to_vec()));
            rest = &rest[n..];
        }
    }
    let (rfmt_count, mut rest) = read_i16(rest)?;
    if rfmt_count < 0 {
        return Err("negative result format count");
    }
    let mut rfmts = Vec::with_capacity(rfmt_count as usize);
    for _ in 0..rfmt_count as usize {
        let (code, r) = read_i16(rest)?;
        rfmts.push(code);
        rest = r;
    }
    let _ = rest; // trailing bytes are tolerated (some clients pad).
    Ok(BindMessage {
        portal_name: portal.to_owned(),
        statement_name: stmt.to_owned(),
        param_format_codes: formats,
        values,
        result_format_codes: rfmts,
    })
}

/// Parsed `'D'` Describe message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescribeMessage {
    /// `'S'` for prepared-statement, `'P'` for portal.
    pub kind: u8,
    /// Name of the statement or portal.
    pub name: String,
}

/// Parse a `'D'` Describe message body.
pub fn parse_describe_message(body: &[u8]) -> Result<DescribeMessage, &'static str> {
    if body.is_empty() {
        return Err("empty describe body");
    }
    let kind = body[0];
    if kind != b'S' && kind != b'P' {
        return Err("invalid describe kind (must be 'S' or 'P')");
    }
    let (name, _) = read_cstr(&body[1..])?;
    Ok(DescribeMessage {
        kind,
        name: name.to_owned(),
    })
}

/// Parsed `'E'` Execute message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteMessage {
    /// Source portal name.
    pub portal_name: String,
    /// Maximum rows to return (`0` = unlimited).
    pub max_rows: i32,
}

/// Parse a `'E'` Execute message body.
pub fn parse_execute_message(body: &[u8]) -> Result<ExecuteMessage, &'static str> {
    let (portal, rest) = read_cstr(body)?;
    let (max, _) = read_i32(rest)?;
    Ok(ExecuteMessage {
        portal_name: portal.to_owned(),
        max_rows: max,
    })
}

/// Parsed `'C'` Close message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseMessage {
    /// `'S'` (close prepared statement) or `'P'` (close portal).
    pub kind: u8,
    /// Name of the statement or portal to close.
    pub name: String,
}

/// Parse a `'C'` Close message body.
pub fn parse_close_message(body: &[u8]) -> Result<CloseMessage, &'static str> {
    if body.is_empty() {
        return Err("empty close body");
    }
    let kind = body[0];
    if kind != b'S' && kind != b'P' {
        return Err("invalid close kind (must be 'S' or 'P')");
    }
    let (name, _) = read_cstr(&body[1..])?;
    Ok(CloseMessage {
        kind,
        name: name.to_owned(),
    })
}

/// `'1'` ParseComplete (empty body).
pub fn parse_complete() -> Vec<u8> {
    put_tagged(b'1', |_| {})
}

/// `'2'` BindComplete (empty body).
pub fn bind_complete() -> Vec<u8> {
    put_tagged(b'2', |_| {})
}

/// `'3'` CloseComplete (empty body).
pub fn close_complete() -> Vec<u8> {
    put_tagged(b'3', |_| {})
}

/// `'n'` NoData (empty body) — sent in response to `Describe`
/// against a statement that returns no rows (DML or DDL).
pub fn no_data() -> Vec<u8> {
    put_tagged(b'n', |_| {})
}

/// `'s'` PortalSuspended (empty body) — sent when an `Execute` with
/// `max_rows > 0` returned that many rows and the cursor is still
/// open. V2 always returns the full result set, so this is provided
/// for completeness but currently unused by the proxy.
pub fn portal_suspended() -> Vec<u8> {
    put_tagged(b's', |_| {})
}

/// `'t'` ParameterDescription (one i16 count + one i32 oid per param).
pub fn parameter_description(oids: &[i32]) -> Vec<u8> {
    put_tagged(b't', |b| {
        b.put_i16(oids.len() as i16);
        for &oid in oids {
            b.put_i32(oid);
        }
    })
}

// ---------------------------------------------------------------------------
// Body-parsing helpers (private)
// ---------------------------------------------------------------------------

fn read_cstr(buf: &[u8]) -> Result<(&str, &[u8]), &'static str> {
    let nul = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or("missing NUL terminator")?;
    let s = std::str::from_utf8(&buf[..nul]).map_err(|_| "non-UTF-8 string")?;
    Ok((s, &buf[nul + 1..]))
}

fn read_i16(buf: &[u8]) -> Result<(i16, &[u8]), &'static str> {
    if buf.len() < 2 {
        return Err("short i16");
    }
    Ok((i16::from_be_bytes([buf[0], buf[1]]), &buf[2..]))
}

fn read_i32(buf: &[u8]) -> Result<(i32, &[u8]), &'static str> {
    if buf.len() < 4 {
        return Err("short i32");
    }
    Ok((
        i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        &buf[4..],
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query_extracts_sql() {
        let mut body = Vec::new();
        body.extend_from_slice(b"SELECT 1");
        body.push(0);
        let sql = parse_query_message(&body).unwrap();
        assert_eq!(sql, "SELECT 1");
    }

    #[test]
    fn parse_query_rejects_missing_nul() {
        let body = b"SELECT 1".to_vec();
        let err = parse_query_message(&body).unwrap_err();
        assert!(err.contains("NUL"));
    }

    #[test]
    fn auth_ok_round_trip() {
        let bytes = authentication_ok();
        assert_eq!(bytes[0], b'R');
        let len = i32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        assert_eq!(len, 8);
        assert_eq!(&bytes[5..], &0i32.to_be_bytes());
    }

    #[test]
    fn parameter_status_layout() {
        let bytes = parameter_status("client_encoding", "UTF8");
        assert_eq!(bytes[0], b'S');
        // Body = "client_encoding\0UTF8\0"
        let body = &bytes[5..];
        let mid = body.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&body[..mid], b"client_encoding");
        assert_eq!(&body[mid + 1..body.len() - 1], b"UTF8");
        assert_eq!(*body.last().unwrap(), 0);
    }

    #[test]
    fn ready_for_query_status_byte() {
        let bytes = ready_for_query(b'I');
        assert_eq!(bytes[0], b'Z');
        assert_eq!(*bytes.last().unwrap(), b'I');
    }

    #[test]
    fn error_response_contains_message() {
        let bytes = error_response(b"ERROR", b"42501", "blocked");
        assert_eq!(bytes[0], b'E');
        let body = std::str::from_utf8(&bytes[5..]).unwrap();
        assert!(body.contains("blocked"), "body = {body:?}");
    }

    #[test]
    fn row_description_layout_two_fields() {
        let fields = [FieldDescriptor::text("id"), FieldDescriptor::text("name")];
        let bytes = row_description(&fields);
        assert_eq!(bytes[0], b'T');
        let len = i32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        assert_eq!(len as usize, bytes.len() - 1);
        let body = &bytes[5..];
        let count = i16::from_be_bytes([body[0], body[1]]);
        assert_eq!(count, 2);
        // Field 1: name = "id\0" then 18 bytes of metadata.
        let name1_end = 2 + body[2..].iter().position(|&b| b == 0).unwrap();
        assert_eq!(&body[2..name1_end], b"id");
        // Skip the metadata block (4+2+4+2+4+2 = 18 bytes), then "name\0".
        let after_meta1 = name1_end + 1 + 18;
        let name2_end = after_meta1 + body[after_meta1..].iter().position(|&b| b == 0).unwrap();
        assert_eq!(&body[after_meta1..name2_end], b"name");
    }

    // ---------------------------------------------------------------------
    // Extended Query Protocol — round-trip tests
    // ---------------------------------------------------------------------

    fn build_parse_body(name: &str, sql: &str, oids: &[i32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(sql.as_bytes());
        body.push(0);
        body.extend_from_slice(&(oids.len() as i16).to_be_bytes());
        for &oid in oids {
            body.extend_from_slice(&oid.to_be_bytes());
        }
        body
    }

    #[test]
    fn parse_message_with_three_oids_round_trips() {
        let body = build_parse_body("stmt1", "SELECT $1, $2, $3", &[23, 25, 16]);
        let m = parse_parse_message(&body).unwrap();
        assert_eq!(m.statement_name, "stmt1");
        assert_eq!(m.sql, "SELECT $1, $2, $3");
        assert_eq!(m.param_oids, vec![23, 25, 16]);
    }

    #[test]
    fn parse_message_anonymous_no_oids() {
        let body = build_parse_body("", "SELECT 1", &[]);
        let m = parse_parse_message(&body).unwrap();
        assert!(m.statement_name.is_empty());
        assert_eq!(m.sql, "SELECT 1");
        assert!(m.param_oids.is_empty());
    }

    fn build_bind_body(
        portal: &str,
        stmt: &str,
        param_fmts: &[i16],
        values: &[Option<&[u8]>],
        result_fmts: &[i16],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(portal.as_bytes());
        body.push(0);
        body.extend_from_slice(stmt.as_bytes());
        body.push(0);
        body.extend_from_slice(&(param_fmts.len() as i16).to_be_bytes());
        for &c in param_fmts {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.extend_from_slice(&(values.len() as i16).to_be_bytes());
        for v in values {
            match v {
                Some(bytes) => {
                    body.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                    body.extend_from_slice(bytes);
                }
                None => {
                    body.extend_from_slice(&(-1i32).to_be_bytes());
                }
            }
        }
        body.extend_from_slice(&(result_fmts.len() as i16).to_be_bytes());
        for &c in result_fmts {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body
    }

    #[test]
    fn bind_message_text_params_round_trips() {
        let body = build_bind_body(
            "portal_a",
            "stmt1",
            &[],
            &[Some(b"42"), None, Some(b"hello")],
            &[],
        );
        let m = parse_bind_message(&body).unwrap();
        assert_eq!(m.portal_name, "portal_a");
        assert_eq!(m.statement_name, "stmt1");
        assert!(m.param_format_codes.is_empty());
        assert_eq!(m.values.len(), 3);
        assert_eq!(m.values[0], BindValue::Bytes(b"42".to_vec()));
        assert_eq!(m.values[1], BindValue::Null);
        assert_eq!(m.values[2], BindValue::Bytes(b"hello".to_vec()));
        assert_eq!(m.format_for_value(0), 0);
        assert_eq!(m.format_for_value(2), 0);
    }

    #[test]
    fn bind_message_per_value_format_codes() {
        let body = build_bind_body(
            "",
            "stmt2",
            &[1, 0, 1],
            &[
                Some(&[0u8, 0, 0, 42]),
                Some(b"text"),
                Some(&[0u8, 0, 0, 0, 0, 0, 0, 1]),
            ],
            &[0],
        );
        let m = parse_bind_message(&body).unwrap();
        assert_eq!(m.format_for_value(0), 1);
        assert_eq!(m.format_for_value(1), 0);
        assert_eq!(m.format_for_value(2), 1);
        assert_eq!(m.result_format_codes, vec![0]);
    }

    #[test]
    fn describe_message_kinds() {
        let mut body = Vec::new();
        body.push(b'S');
        body.extend_from_slice(b"stmt_x");
        body.push(0);
        let m = parse_describe_message(&body).unwrap();
        assert_eq!(m.kind, b'S');
        assert_eq!(m.name, "stmt_x");

        let mut body2 = Vec::new();
        body2.push(b'P');
        body2.extend_from_slice(b"portal_y");
        body2.push(0);
        let m2 = parse_describe_message(&body2).unwrap();
        assert_eq!(m2.kind, b'P');
        assert_eq!(m2.name, "portal_y");

        let bad = vec![b'X', 0];
        assert!(parse_describe_message(&bad).is_err());
    }

    #[test]
    fn execute_message_max_rows() {
        let mut body = Vec::new();
        body.extend_from_slice(b"port");
        body.push(0);
        body.extend_from_slice(&100i32.to_be_bytes());
        let m = parse_execute_message(&body).unwrap();
        assert_eq!(m.portal_name, "port");
        assert_eq!(m.max_rows, 100);
    }

    #[test]
    fn close_message_kinds_and_name() {
        let mut body = Vec::new();
        body.push(b'P');
        body.extend_from_slice(b"to_close");
        body.push(0);
        let m = parse_close_message(&body).unwrap();
        assert_eq!(m.kind, b'P');
        assert_eq!(m.name, "to_close");
    }

    #[test]
    fn parse_complete_is_empty_tagged_one() {
        let bytes = parse_complete();
        assert_eq!(bytes, vec![b'1', 0, 0, 0, 4]);
    }

    #[test]
    fn bind_complete_is_empty_tagged_two() {
        assert_eq!(bind_complete(), vec![b'2', 0, 0, 0, 4]);
    }

    #[test]
    fn close_complete_is_empty_tagged_three() {
        assert_eq!(close_complete(), vec![b'3', 0, 0, 0, 4]);
    }

    #[test]
    fn no_data_is_empty_tagged_n() {
        assert_eq!(no_data(), vec![b'n', 0, 0, 0, 4]);
    }

    #[test]
    fn portal_suspended_is_empty_tagged_lower_s() {
        assert_eq!(portal_suspended(), vec![b's', 0, 0, 0, 4]);
    }

    #[test]
    fn parameter_description_layout() {
        let bytes = parameter_description(&[23, 25, 16]);
        assert_eq!(bytes[0], b't');
        let body = &bytes[5..];
        assert_eq!(i16::from_be_bytes([body[0], body[1]]), 3);
        assert_eq!(i32::from_be_bytes([body[2], body[3], body[4], body[5]]), 23);
        assert_eq!(i32::from_be_bytes([body[6], body[7], body[8], body[9]]), 25);
        assert_eq!(
            i32::from_be_bytes([body[10], body[11], body[12], body[13]]),
            16
        );
    }

    #[test]
    fn data_row_with_null_and_text_values() {
        let v_a: &[u8] = b"hello";
        let bytes = data_row(&[Some(v_a), None, Some(b"")]);
        assert_eq!(bytes[0], b'D');
        let body = &bytes[5..];
        let count = i16::from_be_bytes([body[0], body[1]]);
        assert_eq!(count, 3);
        // First value: i32 length 5, then bytes.
        assert_eq!(i32::from_be_bytes([body[2], body[3], body[4], body[5]]), 5);
        assert_eq!(&body[6..11], b"hello");
        // Second value: i32 length -1 (NULL).
        assert_eq!(
            i32::from_be_bytes([body[11], body[12], body[13], body[14]]),
            -1
        );
        // Third value: i32 length 0, no bytes.
        assert_eq!(
            i32::from_be_bytes([body[15], body[16], body[17], body[18]]),
            0
        );
        assert_eq!(body.len(), 19);
    }
}
