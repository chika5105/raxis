//! Fake-MongoDB backend for the proxy's real-upstream integration
//! tests.
//!
//! What this implements (just enough for the proxy's
//! `upstream::UpstreamSession::connect()` + `forward_op_msg()` to
//! work end-to-end):
//!
//!   * `OP_MSG` framing (op_code 2013).
//!   * Test-supplied callback maps each `(command_name)` to a
//!     [`FakeResponse`] which becomes the kind-0 BSON section of
//!     the upstream's reply.
//!   * Connection is pure no-auth — the proxy V2.1 MVP rejects URLs
//!     with `user:pass@` userinfo before even calling
//!     [`super::UpstreamSession::connect`], so this fixture deliberately
//!     does not implement SCRAM. (V2.2 follow-up will swap this for
//!     a SCRAM-SHA-256-aware fixture once the proxy gains SCRAM
//!     support.)
//!
//! Out of scope:
//!
//!   * Cursor batching / `getMore` (the V2.1 MVP relays single
//!     OP_MSG round trips; cursors land in a follow-up).
//!   * `OP_QUERY` (legacy wire — Mongo dropped it in 5.0+).
//!   * Compressed `OP_COMPRESSED` envelopes.

#![allow(dead_code)]

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Programmable response for a single command name.
#[derive(Clone, Debug)]
pub enum FakeResponse {
    /// Generic `{ ok: 1.0, payload }` reply doc. The fixture builds
    /// the BSON itself using a minimal builder.
    Ok {
        /// Key/value pairs to add to the reply doc beyond `ok: 1.0`.
        extras: Vec<(String, FakeBsonValue)>,
    },
    /// `{ ok: 0.0, code, codeName, errmsg }` shape.
    Err {
        /// MongoDB numeric error code.
        code: i32,
        /// Mongo error name (e.g. `"Unauthorized"`, `"InternalError"`).
        code_name: String,
        /// Human-readable message.
        errmsg: String,
    },
}

#[derive(Clone, Debug)]
pub enum FakeBsonValue {
    Int32(i32),
    Int64(i64),
    Double(f64),
    Bool(bool),
    String(String),
}

/// Fake backend handle.
pub struct FakeBackend {
    addr: std::net::SocketAddr,
}

impl FakeBackend {
    /// Bind a fake-mongo listener on a random localhost port.
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
    loop {
        let mut header = [0u8; 16];
        if s.read_exact(&mut header).await.is_err() {
            return Ok(());
        }
        let total = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let request_id = i32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let op_code = i32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        if total < 16 || total > 64 * 1024 * 1024 {
            return Ok(());
        }
        let body_len = total - 16;
        let mut body = vec![0u8; body_len];
        s.read_exact(&mut body).await?;
        if op_code != 2013 {
            return Ok(());
        }
        // Find first kind-0 section's BSON doc and pull out the
        // first field (= command name).
        let cmd = first_command_name(&body).unwrap_or_default();
        let resp = responses(&cmd).unwrap_or(FakeResponse::Ok { extras: vec![] });
        let reply_doc = build_reply_doc(&cmd, &resp);
        let reply_msg = build_op_msg_reply(request_id.wrapping_add(0x4000_0000), request_id, &reply_doc);
        s.write_all(&reply_msg).await?;
        s.flush().await?;
    }
}

fn first_command_name(body: &[u8]) -> Option<String> {
    if body.len() < 4 {
        return None;
    }
    let mut i = 4;
    while i < body.len() {
        let kind = body[i];
        i += 1;
        if kind == 0 {
            return first_bson_field_name(&body[i..]);
        } else if kind == 1 {
            if i + 4 > body.len() {
                return None;
            }
            let section_size = i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]) as usize;
            if section_size < 4 || i + section_size > body.len() {
                return None;
            }
            i += section_size;
        } else {
            return None;
        }
    }
    None
}

fn first_bson_field_name(doc: &[u8]) -> Option<String> {
    if doc.len() < 5 {
        return None;
    }
    let total = i32::from_le_bytes([doc[0], doc[1], doc[2], doc[3]]) as usize;
    if total < 5 || total > doc.len() {
        return None;
    }
    let body = &doc[4..total];
    if body.is_empty() || body[0] == 0 {
        return None;
    }
    let after_type = &body[1..];
    let nul = after_type.iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&after_type[..nul]).into_owned())
}

fn build_reply_doc(_cmd: &str, resp: &FakeResponse) -> Vec<u8> {
    match resp {
        FakeResponse::Ok { extras } => {
            let mut b = BsonBuilder::new();
            b = b.double("ok", 1.0);
            for (k, v) in extras {
                b = match v {
                    FakeBsonValue::Int32(n) => b.int32(k, *n),
                    FakeBsonValue::Int64(n) => b.int64(k, *n),
                    FakeBsonValue::Double(n) => b.double(k, *n),
                    FakeBsonValue::Bool(n) => b.bool_(k, *n),
                    FakeBsonValue::String(s) => b.string(k, s),
                };
            }
            b.finish()
        }
        FakeResponse::Err { code, code_name, errmsg } => {
            BsonBuilder::new()
                .double("ok", 0.0)
                .int32("code", *code)
                .string("codeName", code_name)
                .string("errmsg", errmsg)
                .finish()
        }
    }
}

fn build_op_msg_reply(request_id: i32, response_to: i32, bson_doc: &[u8]) -> Vec<u8> {
    let body_len = 4 + 1 + bson_doc.len();
    let total = 16 + body_len;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as i32).to_le_bytes());
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&response_to.to_le_bytes());
    out.extend_from_slice(&2013i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flag_bits
    out.push(0); // section kind 0
    out.extend_from_slice(bson_doc);
    out
}

#[derive(Default)]
struct BsonBuilder {
    body: Vec<u8>,
}

impl BsonBuilder {
    fn new() -> Self { Self::default() }
    fn int32(mut self, key: &str, val: i32) -> Self {
        self.body.push(0x10);
        self.body.extend_from_slice(key.as_bytes());
        self.body.push(0);
        self.body.extend_from_slice(&val.to_le_bytes());
        self
    }
    fn int64(mut self, key: &str, val: i64) -> Self {
        self.body.push(0x12);
        self.body.extend_from_slice(key.as_bytes());
        self.body.push(0);
        self.body.extend_from_slice(&val.to_le_bytes());
        self
    }
    fn double(mut self, key: &str, val: f64) -> Self {
        self.body.push(0x01);
        self.body.extend_from_slice(key.as_bytes());
        self.body.push(0);
        self.body.extend_from_slice(&val.to_le_bytes());
        self
    }
    fn bool_(mut self, key: &str, val: bool) -> Self {
        self.body.push(0x08);
        self.body.extend_from_slice(key.as_bytes());
        self.body.push(0);
        self.body.push(if val { 1 } else { 0 });
        self
    }
    fn string(mut self, key: &str, val: &str) -> Self {
        self.body.push(0x02);
        self.body.extend_from_slice(key.as_bytes());
        self.body.push(0);
        self.body.extend_from_slice(&((val.len() + 1) as i32).to_le_bytes());
        self.body.extend_from_slice(val.as_bytes());
        self.body.push(0);
        self
    }
    fn finish(self) -> Vec<u8> {
        let total = 4 + self.body.len() + 1;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(total as i32).to_le_bytes());
        out.extend_from_slice(&self.body);
        out.push(0);
        out
    }
}
