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
pub async fn read_startup<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<StartupKind> {
    let len = r.read_i32().await?;
    if len < 8 || len > 1_000_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("startup length out of range: {len}"),
        ));
    }
    let mut buf = vec![0u8; (len as usize) - 4];
    r.read_exact(&mut buf).await?;
    if buf.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "startup too short"));
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
pub async fn read_message_body<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<Vec<u8>> {
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
    let nul = body.iter().position(|&b| b == 0).ok_or("missing NUL terminator")?;
    let s   = std::str::from_utf8(&body[..nul]).map_err(|_| "non-UTF-8 SQL")?;
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
            name:          name.into(),
            table_oid:     0,
            attribute_num: 0,
            type_oid:      25, // text
            type_size:     -1,
            type_modifier: -1,
            format_code:   0,  // text
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
            let name = if name_bytes.len() > 255 { &name_bytes[..255] } else { name_bytes };
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
        let err  = parse_query_message(&body).unwrap_err();
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
        let fields = [
            FieldDescriptor::text("id"),
            FieldDescriptor::text("name"),
        ];
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
        assert_eq!(i32::from_be_bytes([body[11], body[12], body[13], body[14]]), -1);
        // Third value: i32 length 0, no bytes.
        assert_eq!(i32::from_be_bytes([body[15], body[16], body[17], body[18]]), 0);
        assert_eq!(body.len(), 19);
    }
}
