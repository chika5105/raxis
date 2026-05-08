//! Fake-Postgres backend that lets the unit-style integration tests
//! exercise the proxy's real-upstream-forwarding path without a
//! docker fixture.
//!
//! What this implements (just enough for `tokio-postgres`'s
//! `Config::connect(NoTls)` and `simple_query_raw` to work):
//!
//!   * StartupMessage read; AuthenticationOk in response.
//!   * Three ParameterStatus rows (`server_version`,
//!     `client_encoding`, `DateStyle`).
//!   * BackendKeyData (zeros).
//!   * ReadyForQuery (idle).
//!   * One simple-query response cycle per `Q` message, driven by
//!     a callback that lets each test inject the rows it wants
//!     returned. After the response, the backend goes back to
//!     ReadyForQuery and waits for the next `Q` or `X`.
//!   * Terminate (`X`) closes the connection cleanly.
//!
//! Out of scope (the proxy refuses extended-query messages with
//! a `0A000` ErrorResponse, so the backend never has to handle
//! them):
//!
//!   * Parse / Bind / Execute / Describe / Sync.
//!   * SCRAM / MD5 / cleartext password (we always answer
//!     AuthenticationOk regardless of the StartupMessage's
//!     `user` parameter).
//!   * SSL preface.
//!   * Cancel-request preface.

use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A row returned by the fake backend in response to a `Q` message.
#[derive(Clone)]
pub struct FakeRow {
    /// Each column's text-format payload, or `None` for SQL `NULL`.
    pub values: Vec<Option<Vec<u8>>>,
}

/// Programmable response for a single SQL string.
#[derive(Clone)]
pub struct FakeResponse {
    /// Column names (text format only).
    pub columns: Vec<String>,
    /// Rows in arrival order.
    pub rows:    Vec<FakeRow>,
    /// Command-complete tag the backend should emit (e.g. `"SELECT 3"`).
    pub command_tag: String,
}

impl FakeResponse {
    /// Empty result-set + a synthetic SELECT command tag.
    pub fn empty() -> Self {
        Self {
            columns:     vec!["dummy".into()],
            rows:        vec![],
            command_tag: "SELECT 0".into(),
        }
    }
}

/// Fake backend handle. Use [`FakeBackend::start`] to bind, then
/// query [`FakeBackend::addr`] for the listen address.
pub struct FakeBackend {
    addr:    std::net::SocketAddr,
}

impl FakeBackend {
    /// Bind a fake-pg listener on a random localhost port. The
    /// `responses` callback maps a SQL string to a [`FakeResponse`]
    /// (`None` returns "command complete: 0" with no row description,
    /// the safe default for write statements).
    pub async fn start(
        responses: Arc<dyn Fn(&str) -> Option<FakeResponse> + Send + Sync>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let r = Arc::clone(&responses);
                        tokio::spawn(async move {
                            let _ = serve_one(stream, r).await;
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
) -> std::io::Result<()> {
    // ----- StartupMessage -----
    let len = s.read_i32().await?;
    if !(8..=1_000_000).contains(&len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "startup len out of range",
        ));
    }
    let mut body = vec![0u8; (len as usize) - 4];
    s.read_exact(&mut body).await?;
    let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if code == 80877103 {
        // SSLRequest — answer 'N'.
        s.write_all(b"N").await?;
        // Then read the actual StartupMessage.
        let len = s.read_i32().await?;
        let mut body = vec![0u8; (len as usize) - 4];
        s.read_exact(&mut body).await?;
        let code2 = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        if (code2 >> 16) != 3 {
            return Ok(());
        }
    } else if (code >> 16) != 3 {
        return Ok(());
    }

    // ----- Handshake response -----
    s.write_all(&authentication_ok()).await?;
    s.write_all(&parameter_status("server_version", "14.0 (raxis-fake)")).await?;
    s.write_all(&parameter_status("client_encoding", "UTF8")).await?;
    s.write_all(&parameter_status("DateStyle", "ISO, MDY")).await?;
    s.write_all(&parameter_status("integer_datetimes", "on")).await?;
    s.write_all(&parameter_status("standard_conforming_strings", "on")).await?;
    s.write_all(&parameter_status("TimeZone", "UTC")).await?;
    s.write_all(&backend_key_data(0, 0)).await?;
    s.write_all(&ready_for_query(b'I')).await?;

    // ----- Query loop -----
    loop {
        let mut tag = [0u8; 1];
        let n = s.read(&mut tag).await?;
        if n == 0 { return Ok(()); }
        match tag[0] {
            b'Q' => {
                let len = s.read_i32().await?;
                let mut body = vec![0u8; (len as usize) - 4];
                s.read_exact(&mut body).await?;
                let nul = body.iter().position(|&b| b == 0)
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no nul"))?;
                let sql = std::str::from_utf8(&body[..nul])
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-utf8"))?
                    .to_owned();
                let resp = responses(&sql).unwrap_or_else(|| {
                    FakeResponse {
                        columns:     vec![],
                        rows:        vec![],
                        command_tag: "DO".into(),
                    }
                });
                if !resp.columns.is_empty() {
                    s.write_all(&row_description_text(&resp.columns)).await?;
                    for row in &resp.rows {
                        let refs: Vec<Option<&[u8]>> = row
                            .values
                            .iter()
                            .map(|v| v.as_deref())
                            .collect();
                        s.write_all(&data_row(&refs)).await?;
                    }
                }
                s.write_all(&command_complete(&resp.command_tag)).await?;
                s.write_all(&ready_for_query(b'I')).await?;
            }
            b'X' => return Ok(()),
            _ => {
                // Unknown frontend message — read its body and reset.
                let len = s.read_i32().await?;
                if len > 4 {
                    let mut body = vec![0u8; (len as usize) - 4];
                    s.read_exact(&mut body).await?;
                }
                s.write_all(&error_response_simple(b"0A000", "fake-pg: unsupported message")).await?;
                s.write_all(&ready_for_query(b'I')).await?;
            }
        }
    }
}

// ----- Tiny copy of the wire helpers (kept here so this support
// module doesn't depend on the proxy's internal `wire::` exports;
// the test can swap helpers freely without leaking internals). -----

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

fn authentication_ok() -> Vec<u8> {
    put_tagged(b'R', |b| b.put_i32(0))
}

fn parameter_status(key: &str, value: &str) -> Vec<u8> {
    put_tagged(b'S', |b| {
        b.put_slice(key.as_bytes());
        b.put_u8(0);
        b.put_slice(value.as_bytes());
        b.put_u8(0);
    })
}

fn backend_key_data(pid: i32, key: i32) -> Vec<u8> {
    put_tagged(b'K', |b| {
        b.put_i32(pid);
        b.put_i32(key);
    })
}

fn ready_for_query(status: u8) -> Vec<u8> {
    put_tagged(b'Z', |b| b.put_u8(status))
}

fn command_complete(tag: &str) -> Vec<u8> {
    put_tagged(b'C', |b| {
        b.put_slice(tag.as_bytes());
        b.put_u8(0);
    })
}

fn row_description_text(columns: &[String]) -> Vec<u8> {
    put_tagged(b'T', |b| {
        b.put_i16(columns.len() as i16);
        for col in columns {
            b.put_slice(col.as_bytes());
            b.put_u8(0);
            b.put_i32(0);   // table OID
            b.put_i16(0);   // attr num
            b.put_i32(25);  // text OID
            b.put_i16(-1);  // type size
            b.put_i32(-1);  // type modifier
            b.put_i16(0);   // text format
        }
    })
}

fn data_row(values: &[Option<&[u8]>]) -> Vec<u8> {
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

fn error_response_simple(sqlstate: &[u8], message: &str) -> Vec<u8> {
    put_tagged(b'E', |b| {
        b.put_u8(b'S');
        b.put_slice(b"ERROR");
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
