//! Fake-MSSQL backend for the proxy's real-upstream integration
//! tests.
//!
//! What this implements:
//!
//!   * PRELOGIN ingestion with VERSION/ENCRYPTION option parsing.
//!     The fixture replies with `ENCRYPTION = NOT_SUP` (0x02).
//!   * LOGIN7 ingestion. The fixture pulls the username out of the
//!     LOGIN7 tuples; if a known expected password is set on the
//!     fixture, the obfuscated password bytes are recovered and
//!     compared against the known plaintext.
//!   * SQLBatch ingestion. A test-supplied callback maps the SQL
//!     to either an OK reply (DONE token) or an ERROR + DONE_ERROR.
//!   * Single-packet messages only (matches the V2 proxy's wire
//!     constraint).
//!
//! Out of scope:
//!
//!   * RPC requests, multi-packet messages, COLMETADATA + ROW
//!     tokens (V3 work).

#![allow(dead_code)]

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Test-supplied response for one SQLBatch.
#[derive(Clone, Debug)]
pub enum FakeResponse {
    /// `DONE` token (no rows; success).
    Ok,
    /// `ERROR` token followed by `DONE_ERROR`.
    Err {
        /// Error number (e.g. `8120` for "Column not in GROUP BY").
        number: i32,
        /// Human-readable message.
        message: String,
    },
}

/// Fake backend handle.
pub struct FakeBackend {
    addr: std::net::SocketAddr,
}

impl FakeBackend {
    /// Bind a fake-mssql listener. The `responses` callback maps a
    /// (decoded UTF-8) SQL string to a [`FakeResponse`].
    pub async fn start(
        responses: Arc<dyn Fn(&str) -> FakeResponse + Send + Sync>,
    ) -> std::io::Result<Self> {
        Self::start_with_password(responses, None).await
    }

    /// Bind a fake-mssql listener that validates the LOGIN7
    /// username + obfuscated password against expected values.
    pub async fn start_with_password(
        responses: Arc<dyn Fn(&str) -> FakeResponse + Send + Sync>,
        expected: Option<(String, Vec<u8>)>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let r = Arc::clone(&responses);
                let e = expected.clone();
                tokio::spawn(async move {
                    let _ = serve_one(stream, r, e).await;
                });
            }
        });
        Ok(Self { addr })
    }

    /// The address the listener is bound to.
    pub fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }
}

const PRELOGIN: u8 = 0x12;
const LOGIN7: u8 = 0x10;
const SQL_BATCH: u8 = 0x01;
const TABULAR_RESULT: u8 = 0x04;
const STATUS_EOM: u8 = 0x01;

const TOKEN_LOGINACK: u8 = 0xAD;
const TOKEN_ERROR: u8 = 0xAA;
const TOKEN_DONE: u8 = 0xFD;

async fn serve_one(
    mut s: TcpStream,
    responses: Arc<dyn Fn(&str) -> FakeResponse + Send + Sync>,
    expected: Option<(String, Vec<u8>)>,
) -> std::io::Result<()> {
    // PRELOGIN.
    let (kind, _) = read_packet(&mut s).await?;
    if kind != PRELOGIN {
        return Ok(());
    }
    s.write_all(&frame_packet(
        TABULAR_RESULT,
        &build_prelogin_response_body(),
    ))
    .await?;
    s.flush().await?;
    // LOGIN7.
    let (kind, body) = read_packet(&mut s).await?;
    if kind != LOGIN7 {
        return Ok(());
    }
    let auth_ok = match expected.as_ref() {
        None => true,
        Some((expected_user, expected_password)) => {
            let parsed = parse_login7(&body);
            parsed.user == *expected_user
                && deobfuscate_password(&parsed.password) == *expected_password
        }
    };
    if !auth_ok {
        s.write_all(&frame_packet(
            TABULAR_RESULT,
            &build_error_done_body(18456, "Login failed for user"),
        ))
        .await?;
        s.flush().await?;
        return Ok(());
    }
    s.write_all(&frame_packet(TABULAR_RESULT, &build_loginack_done_body()))
        .await?;
    s.flush().await?;
    // Command loop.
    loop {
        let (kind, body) = match read_packet(&mut s).await {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        if kind != SQL_BATCH {
            return Ok(());
        }
        let sql = decode_sql_batch_body(&body).unwrap_or_default();
        let resp = responses(&sql);
        let body = match resp {
            FakeResponse::Ok => build_done_token(0x0000, 0x0000, 0),
            FakeResponse::Err { number, message } => build_error_done_body(number, &message),
        };
        s.write_all(&frame_packet(TABULAR_RESULT, &body)).await?;
        s.flush().await?;
    }
}

async fn read_packet(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 8];
    s.read_exact(&mut hdr).await?;
    let kind = hdr[0];
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if len < 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "short TDS header",
        ));
    }
    let body_len = len - 8;
    let mut body = vec![0u8; body_len];
    s.read_exact(&mut body).await?;
    Ok((kind, body))
}

fn frame_packet(kind: u8, body: &[u8]) -> Vec<u8> {
    let total = 8 + body.len();
    let mut out = Vec::with_capacity(total);
    out.push(kind);
    out.push(STATUS_EOM);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // spid
    out.push(1); // packet id
    out.push(0); // window
    out.extend_from_slice(body);
    out
}

fn build_prelogin_response_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(18);
    body.push(0x00); // VERSION header
    body.extend_from_slice(&11u16.to_be_bytes());
    body.extend_from_slice(&6u16.to_be_bytes());
    body.push(0x01); // ENCRYPTION header
    body.extend_from_slice(&17u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(0xff); // terminator
    body.extend_from_slice(&[15, 0]); // version major/minor
    body.extend_from_slice(&4153u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.push(0x02); // ENCRYPTION = NOT_SUP
    body
}

fn build_loginack_done_body() -> Vec<u8> {
    let mut body = Vec::new();
    let progname: Vec<u8> = "fake-mssql"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let inner_len = 1 + 4 + 1 + progname.len() + 4;
    body.push(TOKEN_LOGINACK);
    body.extend_from_slice(&(inner_len as u16).to_le_bytes());
    body.push(0x01);
    body.extend_from_slice(&0x73000004u32.to_be_bytes());
    body.push(("fake-mssql".len()) as u8);
    body.extend_from_slice(&progname);
    body.extend_from_slice(&[15, 0, 0, 0]);
    body.extend_from_slice(&build_done_token(0x0000, 0x0000, 0));
    body
}

fn build_done_token(status: u16, cur_cmd: u16, row_count: u64) -> Vec<u8> {
    let mut t = Vec::with_capacity(13);
    t.push(TOKEN_DONE);
    t.extend_from_slice(&status.to_le_bytes());
    t.extend_from_slice(&cur_cmd.to_le_bytes());
    t.extend_from_slice(&row_count.to_le_bytes());
    t
}

fn build_error_done_body(number: i32, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    let msg_utf16: Vec<u16> = message.encode_utf16().collect();
    let msg_bytes: Vec<u8> = msg_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let server: Vec<u16> = "fake-mssql".encode_utf16().collect();
    let server_bytes: Vec<u8> = server.iter().flat_map(|c| c.to_le_bytes()).collect();
    let inner_len = 4 + 1 + 1 + 2 + msg_bytes.len() + 1 + server_bytes.len() + 1 + 4;
    body.push(TOKEN_ERROR);
    body.extend_from_slice(&(inner_len as u16).to_le_bytes());
    body.extend_from_slice(&number.to_le_bytes());
    body.push(1);
    body.push(14);
    body.extend_from_slice(&(msg_utf16.len() as u16).to_le_bytes());
    body.extend_from_slice(&msg_bytes);
    body.push(server.len() as u8);
    body.extend_from_slice(&server_bytes);
    body.push(0);
    body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&build_done_token(0x0002, 0x0000, 0));
    body
}

fn decode_sql_batch_body(body: &[u8]) -> Option<String> {
    if body.len() < 4 {
        return None;
    }
    let total_headers = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if total_headers > body.len() {
        return decode_utf16_le(body);
    }
    decode_utf16_le(&body[total_headers..])
}

fn decode_utf16_le(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

#[derive(Default, Debug)]
struct ParsedLogin7 {
    user: String,
    password: Vec<u8>,
}

fn parse_login7(body: &[u8]) -> ParsedLogin7 {
    if body.len() < 36 + 36 + 6 + 12 + 4 {
        return ParsedLogin7::default();
    }
    // Skip 36-byte fixed section.
    let i = 36;
    // 9 OffsetLength tuples.
    let read_off = |idx: usize| -> Option<(usize, usize)> {
        let base = i + idx * 4;
        if base + 4 > body.len() {
            return None;
        }
        let off = u16::from_le_bytes([body[base], body[base + 1]]) as usize;
        let chars = u16::from_le_bytes([body[base + 2], body[base + 3]]) as usize;
        Some((off, chars))
    };
    let user_tuple = read_off(1).unwrap_or((0, 0));
    let pwd_tuple = read_off(2).unwrap_or((0, 0));
    let user_bytes = if user_tuple.1 > 0 {
        let start = user_tuple.0;
        let end = start + user_tuple.1 * 2;
        if end > body.len() {
            return ParsedLogin7::default();
        }
        body[start..end].to_vec()
    } else {
        Vec::new()
    };
    let user = decode_utf16_le(&user_bytes).unwrap_or_default();
    let password = if pwd_tuple.1 > 0 {
        let start = pwd_tuple.0;
        let end = start + pwd_tuple.1 * 2;
        if end > body.len() {
            return ParsedLogin7::default();
        }
        body[start..end].to_vec()
    } else {
        Vec::new()
    };
    ParsedLogin7 { user, password }
}

/// Reverse of the proxy's password obfuscation: each byte is XORed
/// with 0xA5 then nibble-swapped, producing a UTF-16 LE encoded
/// plaintext password.
fn deobfuscate_password(obf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(obf.len());
    for &b in obf {
        let unxor = b ^ 0xA5;
        let unswap = ((unxor & 0x0f) << 4) | ((unxor & 0xf0) >> 4);
        out.push(unswap);
    }
    // Convert UTF-16 LE → UTF-8 → bytes.
    let units: Vec<u16> = out
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).unwrap_or_default().into_bytes()
}
