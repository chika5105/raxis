//! Fake-MySQL backend for the proxy's real-upstream integration
//! tests.
//!
//! What this implements (just enough for the proxy's
//! `upstream::UpstreamSession::connect()` + `forward_query()` to
//! work end-to-end):
//!
//!   * `Protocol::HandshakeV10` greeting with a 20-byte scramble
//!     and `auth_plugin_name = "mysql_native_password"`.
//!   * `HandshakeResponse41` ingestion. The username, scramble
//!     response, and database name are recorded for the test to
//!     inspect; the password is *not* validated unless the test
//!     opts in by setting the `expected_password` field — when
//!     set, the backend recomputes the SHA-1 XOR token and either
//!     replies with `OK_Packet` or `ERR_Packet` accordingly.
//!   * `COM_QUERY` ingestion. A test-supplied callback maps the SQL
//!     to either:
//!       * `FakeResponse::Rows { columns, rows, command_tag }` — a
//!         text-resultset response.
//!       * `FakeResponse::Ok { affected_rows }` — a write
//!         statement's `OK_Packet` reply.
//!       * `FakeResponse::Err { code, sqlstate, message }` — an
//!         `ERR_Packet` reply.
//!   * `COM_QUIT`, `COM_PING`, `COM_RESET_CONNECTION` short-replies.
//!
//! Out of scope (the proxy never sends these to the upstream):
//!
//!   * Prepared statements (`COM_STMT_PREPARE`/`EXECUTE`).
//!   * `caching_sha2_password`, `sha256_password`, or other
//!     non-`mysql_native_password` auth plugins.
//!   * SSL preface.
//!   * `LOCAL INFILE`.

#![allow(dead_code)]

use std::sync::Arc;

use sha1::{Digest as Sha1Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Programmable response for a single SQL string.
#[derive(Clone, Debug)]
pub enum FakeResponse {
    /// Text-resultset reply.
    Rows {
        /// Column names in arrival order. Each column is
        /// announced as a `MYSQL_TYPE_VAR_STRING` (0xfd) text
        /// column with default decoration.
        columns: Vec<String>,
        /// Rows, each as a vector of `Option<Vec<u8>>` (None →
        /// SQL NULL, encoded on the wire as a single `0xfb` byte).
        rows: Vec<Vec<Option<Vec<u8>>>>,
    },
    /// `OK_Packet` reply (write statements without a result set).
    Ok {
        /// Number of affected rows (used for the OK packet's
        /// affected_rows lenenc field).
        affected_rows: u64,
    },
    /// `ERR_Packet` reply.
    Err {
        /// MySQL numeric error code.
        code: u16,
        /// 5-char sqlstate.
        sqlstate: String,
        /// Human-readable message.
        message: String,
    },
}

/// Fake backend handle.
pub struct FakeBackend {
    addr: std::net::SocketAddr,
}

impl FakeBackend {
    /// Bind a fake-mysql listener on a random localhost port. The
    /// `responses` callback maps a SQL string to a [`FakeResponse`]
    /// (`None` returns `OK_Packet { affected_rows = 0 }`).
    pub async fn start(
        responses: Arc<dyn Fn(&str) -> Option<FakeResponse> + Send + Sync>,
    ) -> std::io::Result<Self> {
        Self::start_with_password(responses, None).await
    }

    /// Bind a fake-mysql listener that validates the
    /// `mysql_native_password` token against a known expected
    /// password. Used to assert the proxy actually computes the
    /// SHA-1 XOR scramble correctly against a real challenge.
    pub async fn start_with_password(
        responses: Arc<dyn Fn(&str) -> Option<FakeResponse> + Send + Sync>,
        expected_password: Option<Vec<u8>>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let r = Arc::clone(&responses);
                        let pw = expected_password.clone();
                        tokio::spawn(async move {
                            let _ = serve_one(stream, r, pw).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { addr })
    }

    /// The address the listener is bound to.
    pub fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }
}

async fn serve_one(
    mut s: TcpStream,
    responses: Arc<dyn Fn(&str) -> Option<FakeResponse> + Send + Sync>,
    expected_password: Option<Vec<u8>>,
) -> std::io::Result<()> {
    // Send HandshakeV10 greeting (seq=0).
    let scramble = derive_scramble();
    let greeting = build_handshake_v10(&scramble);
    s.write_all(&frame_packet(&greeting, 0)).await?;
    s.flush().await?;

    // Read HandshakeResponse41 (seq=1).
    let (_seq, payload) = read_packet(&mut s).await?;
    let resp = parse_handshake_response_41(&payload);

    // Validate auth response if a password was supplied.
    let auth_ok = match &expected_password {
        None => true,
        Some(pw) => {
            let expected_token = mysql_native_password_token(pw, &scramble);
            resp.auth_response == expected_token
        }
    };
    if !auth_ok {
        let err = build_err_packet(1045, "28000", "Access denied for user (fake-mysql)");
        s.write_all(&frame_packet(&err, 2)).await?;
        s.flush().await?;
        return Ok(());
    }

    // OK_Packet (seq=2).
    s.write_all(&frame_packet(&build_ok_packet(0), 2)).await?;
    s.flush().await?;

    // Command loop.
    loop {
        let (_seq, p) = match read_packet(&mut s).await {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        if p.is_empty() {
            return Ok(());
        }
        match p[0] {
            // COM_QUIT.
            0x01 => return Ok(()),
            // COM_PING.
            0x0e => {
                s.write_all(&frame_packet(&build_ok_packet(0), 1)).await?;
                s.flush().await?;
            }
            // COM_QUERY.
            0x03 => {
                let sql = std::str::from_utf8(&p[1..]).unwrap_or("").to_owned();
                let resp = responses(&sql).unwrap_or(FakeResponse::Ok { affected_rows: 0 });
                write_response(&mut s, resp).await?;
            }
            // COM_RESET_CONNECTION.
            0x1f => {
                s.write_all(&frame_packet(&build_ok_packet(0), 1)).await?;
                s.flush().await?;
            }
            other => {
                // Unsupported.
                let err = build_err_packet(
                    1235,
                    "0A000",
                    &format!("fake-mysql: unsupported command 0x{other:02x}"),
                );
                s.write_all(&frame_packet(&err, 1)).await?;
                s.flush().await?;
            }
        }
    }
}

async fn write_response(s: &mut TcpStream, resp: FakeResponse) -> std::io::Result<()> {
    match resp {
        FakeResponse::Ok { affected_rows } => {
            s.write_all(&frame_packet(&build_ok_packet(affected_rows), 1))
                .await?;
        }
        FakeResponse::Err {
            code,
            sqlstate,
            message,
        } => {
            s.write_all(&frame_packet(
                &build_err_packet(code, &sqlstate, &message),
                1,
            ))
            .await?;
        }
        FakeResponse::Rows { columns, rows } => {
            // ResultSetHeader: lenenc int = column count.
            let mut hdr = Vec::with_capacity(8);
            put_lenenc_int(&mut hdr, columns.len() as u64);
            s.write_all(&frame_packet(&hdr, 1)).await?;
            // Column definitions, each as its own packet.
            let mut seq: u8 = 2;
            for col in &columns {
                let cd = build_column_def(col);
                s.write_all(&frame_packet(&cd, seq)).await?;
                seq = seq.wrapping_add(1);
            }
            // EOF after column definitions.
            s.write_all(&frame_packet(&build_eof_packet(), seq)).await?;
            seq = seq.wrapping_add(1);
            // Row packets.
            for row in &rows {
                let body = build_text_row(row);
                s.write_all(&frame_packet(&body, seq)).await?;
                seq = seq.wrapping_add(1);
            }
            // EOF terminator.
            s.write_all(&frame_packet(&build_eof_packet(), seq)).await?;
        }
    }
    s.flush().await
}

// ----- Wire helpers (vendored copies so we don't depend on the
// proxy crate's internal `wire::` module from a test fixture). -----

fn frame_packet(payload: &[u8], seq: u8) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(4 + len);
    out.push((len & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push(((len >> 16) & 0xff) as u8);
    out.push(seq);
    out.extend_from_slice(payload);
    out
}

async fn read_packet(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    let len = (hdr[0] as usize) | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    let seq = hdr[3];
    let mut payload = vec![0u8; len];
    if len > 0 {
        s.read_exact(&mut payload).await?;
    }
    Ok((seq, payload))
}

fn put_lenenc_int(buf: &mut Vec<u8>, val: u64) {
    if val < 251 {
        buf.push(val as u8);
    } else if val < (1 << 16) {
        buf.push(0xfc);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val < (1 << 24) {
        buf.push(0xfd);
        buf.push((val & 0xff) as u8);
        buf.push(((val >> 8) & 0xff) as u8);
        buf.push(((val >> 16) & 0xff) as u8);
    } else {
        buf.push(0xfe);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

fn put_lenenc_string(buf: &mut Vec<u8>, s: &[u8]) {
    put_lenenc_int(buf, s.len() as u64);
    buf.extend_from_slice(s);
}

fn build_handshake_v10(scramble: &[u8; 20]) -> Vec<u8> {
    let mut p = Vec::with_capacity(80);
    p.push(0x0a); // protocol_version
    p.extend_from_slice(b"8.0.30-raxis-fake");
    p.push(0); // NUL terminator
    p.extend_from_slice(&1u32.to_le_bytes()); // thread_id
    p.extend_from_slice(&scramble[..8]); // scramble part 1
    p.push(0); // filler
               // Capabilities (lower 16): PROTOCOL_41 + SECURE_CONNECTION + PLUGIN_AUTH.
    let cap_lower: u16 = (1 << 9) | (1 << 15) | 0;
    p.extend_from_slice(&cap_lower.to_le_bytes());
    p.push(0x2d); // charset utf8mb4
    p.extend_from_slice(&2u16.to_le_bytes()); // status flags (autocommit)
    let cap_upper: u16 = (1 << (19 - 16)) | 0; // PLUGIN_AUTH (bit 19)
    p.extend_from_slice(&cap_upper.to_le_bytes());
    p.push(21); // auth_plugin_data_len
    p.extend_from_slice(&[0u8; 10]); // reserved
    p.extend_from_slice(&scramble[8..]); // scramble part 2 (12 bytes)
    p.push(0); // NUL filler
    p.extend_from_slice(b"mysql_native_password");
    p.push(0); // NUL terminator
    p
}

fn build_ok_packet(affected_rows: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(11);
    p.push(0x00); // OK header
    put_lenenc_int(&mut p, affected_rows);
    put_lenenc_int(&mut p, 0); // last_insert_id
    p.extend_from_slice(&2u16.to_le_bytes()); // status flags (autocommit)
    p.extend_from_slice(&0u16.to_le_bytes()); // warnings
    p
}

fn build_eof_packet() -> Vec<u8> {
    let mut p = Vec::with_capacity(5);
    p.push(0xfe);
    p.extend_from_slice(&0u16.to_le_bytes()); // warnings
    p.extend_from_slice(&2u16.to_le_bytes()); // status flags
    p
}

fn build_err_packet(code: u16, sqlstate: &str, message: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(message.len() + 16);
    p.push(0xff);
    p.extend_from_slice(&code.to_le_bytes());
    p.push(b'#');
    let ss = if sqlstate.len() == 5 {
        sqlstate.as_bytes()
    } else {
        b"HY000"
    };
    p.extend_from_slice(ss);
    p.extend_from_slice(message.as_bytes());
    p
}

fn build_column_def(name: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(64 + name.len());
    put_lenenc_string(&mut p, b"def"); // catalog
    put_lenenc_string(&mut p, b""); // schema
    put_lenenc_string(&mut p, b""); // table
    put_lenenc_string(&mut p, b""); // org_table
    put_lenenc_string(&mut p, name.as_bytes()); // name
    put_lenenc_string(&mut p, name.as_bytes()); // org_name
    p.push(0x0c); // length of fixed-length fields
    p.extend_from_slice(&0x21u16.to_le_bytes()); // collation utf8_general_ci
    p.extend_from_slice(&255u32.to_le_bytes()); // column length
    p.push(0xfd); // MYSQL_TYPE_VAR_STRING
    p.extend_from_slice(&0u16.to_le_bytes()); // flags
    p.push(0); // decimals
    p.extend_from_slice(&0u16.to_le_bytes()); // filler
    p
}

fn build_text_row(values: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut p = Vec::with_capacity(
        values
            .iter()
            .map(|v| v.as_ref().map(|b| b.len()).unwrap_or(1))
            .sum::<usize>()
            + 16,
    );
    for v in values {
        match v {
            Some(bytes) => put_lenenc_string(&mut p, bytes),
            None => p.push(0xfb), // SQL NULL marker
        }
    }
    p
}

#[derive(Debug, Clone, Default)]
struct ParsedHandshakeResponse {
    user: String,
    auth_response: Vec<u8>,
    database: Option<String>,
    plugin: Option<String>,
}

fn parse_handshake_response_41(p: &[u8]) -> ParsedHandshakeResponse {
    if p.len() < 32 {
        return ParsedHandshakeResponse::default();
    }
    // Skip caps (4) + max_packet_size (4) + charset (1) + reserved (23).
    let mut i = 32;
    // Username (NUL-terminated).
    let nul = match p[i..].iter().position(|&b| b == 0) {
        Some(n) => n,
        None => return ParsedHandshakeResponse::default(),
    };
    let user = String::from_utf8_lossy(&p[i..i + nul]).into_owned();
    i += nul + 1;
    // Auth response: u8 length + that many bytes (we don't enable
    // CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA in the proxy's caps).
    if i >= p.len() {
        return ParsedHandshakeResponse {
            user,
            ..Default::default()
        };
    }
    let auth_len = p[i] as usize;
    i += 1;
    if i + auth_len > p.len() {
        return ParsedHandshakeResponse {
            user,
            ..Default::default()
        };
    }
    let auth_response = p[i..i + auth_len].to_vec();
    i += auth_len;
    // Optional database (CLIENT_CONNECT_WITH_DB).
    let mut database = None;
    if i < p.len() {
        if let Some(nul2) = p[i..].iter().position(|&b| b == 0) {
            if nul2 > 0 {
                database = Some(String::from_utf8_lossy(&p[i..i + nul2]).into_owned());
            }
            i += nul2 + 1;
        }
    }
    // Optional plugin name (CLIENT_PLUGIN_AUTH).
    let mut plugin = None;
    if i < p.len() {
        if let Some(nul3) = p[i..].iter().position(|&b| b == 0) {
            plugin = Some(String::from_utf8_lossy(&p[i..i + nul3]).into_owned());
        }
    }
    ParsedHandshakeResponse {
        user,
        auth_response,
        database,
        plugin,
    }
}

fn mysql_native_password_token(password: &[u8], scramble: &[u8; 20]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1: [u8; 20] = {
        let mut h = Sha1::new();
        h.update(password);
        h.finalize().into()
    };
    let stage2: [u8; 20] = {
        let mut h = Sha1::new();
        h.update(stage1);
        h.finalize().into()
    };
    let combined: [u8; 20] = {
        let mut h = Sha1::new();
        h.update(scramble);
        h.update(stage2);
        h.finalize().into()
    };
    let mut out = vec![0u8; 20];
    for i in 0..20 {
        out[i] = stage1[i] ^ combined[i];
    }
    out
}

fn derive_scramble() -> [u8; 20] {
    // Deterministic per-process scramble for test stability. A real
    // server would mint random bytes per connection; we use a
    // counter + pid so concurrent fake-mysql connections see
    // distinct scrambles (the proxy validates only that the
    // server's scramble + agent's password yield a token the
    // upstream accepts).
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut h = Sha1::new();
    h.update(b"raxis-fake-mysql-scramble");
    h.update(n.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    let d: [u8; 20] = h.finalize().into();
    d
}
