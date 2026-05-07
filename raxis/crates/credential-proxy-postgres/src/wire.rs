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
}
