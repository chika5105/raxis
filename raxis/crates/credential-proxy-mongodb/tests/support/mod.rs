//! Fake-MongoDB backend(s) for the proxy's real-upstream
//! integration tests.
//!
//! Two fixtures live here:
//!
//! * [`FakeBackend`] — pure no-auth listener. The agent's first
//!   OP_MSG goes straight into the response callback. Used by the
//!   no-userinfo URL paths (`mongodb://host:port/db`).
//! * [`FakeScramBackend`] — listens for the proxy's SCRAM-SHA-256
//!   `saslStart` / `saslContinue` exchange first, validates the
//!   client proof against a known username + password, then hands
//!   subsequent OP_MSG frames to the response callback. Used by
//!   the V2 §2.2 SCRAM tests.
//!
//! Out of scope:
//!
//!   * Cursor batching / `getMore` (the relay path forwards single
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

/// Boxed `(command_name) -> Option<FakeResponse>` callback shared
/// between the listener task and the per-connection handlers.
/// Aliased to keep the struct/function signatures readable
/// (`clippy::type_complexity`).
pub type ResponderFn = Arc<dyn Fn(&str) -> Option<FakeResponse> + Send + Sync>;

/// Fake backend handle.
pub struct FakeBackend {
    addr: std::net::SocketAddr,
}

impl FakeBackend {
    /// Bind a fake-mongo listener on a random localhost port.
    pub async fn start(responses: ResponderFn) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let r = Arc::clone(&responses);
                tokio::spawn(async move {
                    let _ = serve_one(stream, r).await;
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

async fn serve_one(mut s: TcpStream, responses: ResponderFn) -> std::io::Result<()> {
    loop {
        let mut header = [0u8; 16];
        if s.read_exact(&mut header).await.is_err() {
            return Ok(());
        }
        let total = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let request_id = i32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let op_code = i32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        if !(16..=64 * 1024 * 1024).contains(&total) {
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
        let reply_msg =
            build_op_msg_reply(request_id.wrapping_add(0x4000_0000), request_id, &reply_doc);
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
            let section_size =
                i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]) as usize;
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
        FakeResponse::Err {
            code,
            code_name,
            errmsg,
        } => BsonBuilder::new()
            .double("ok", 0.0)
            .int32("code", *code)
            .string("codeName", code_name)
            .string("errmsg", errmsg)
            .finish(),
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
    fn new() -> Self {
        Self::default()
    }
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
        self.body
            .extend_from_slice(&((val.len() + 1) as i32).to_le_bytes());
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

    fn binary(mut self, key: &str, bytes: &[u8]) -> Self {
        self.body.push(0x05);
        self.body.extend_from_slice(key.as_bytes());
        self.body.push(0);
        self.body
            .extend_from_slice(&(bytes.len() as i32).to_le_bytes());
        self.body.push(0); // subtype 0
        self.body.extend_from_slice(bytes);
        self
    }
}

// ---------------------------------------------------------------------------
// FakeScramBackend — SCRAM-SHA-256-aware fake mongod for the V2 §2.2
// integration tests.
// ---------------------------------------------------------------------------

/// SCRAM-SHA-256-aware fake mongod. Validates the proxy's
/// saslStart / saslContinue conversation against a known username +
/// password, then dispatches subsequent OP_MSG frames through the
/// response callback (same callback shape as [`FakeBackend`]).
pub struct FakeScramBackend {
    addr: std::net::SocketAddr,
}

impl FakeScramBackend {
    /// Bind a SCRAM-aware fake-mongo listener on a random localhost
    /// port. `username` / `password` define the credential the
    /// fixture will validate the proxy's SCRAM proof against.
    pub async fn start(
        username: String,
        password: Vec<u8>,
        responses: ResponderFn,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let r = Arc::clone(&responses);
                let user = username.clone();
                let pw = password.clone();
                tokio::spawn(async move {
                    let _ = serve_scram(stream, user, pw, r).await;
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

async fn serve_scram(
    mut s: TcpStream,
    username: String,
    password: Vec<u8>,
    responses: ResponderFn,
) -> std::io::Result<()> {
    use base64::Engine as _;
    // ---- saslStart ----
    let frame = read_op_msg_frame(&mut s).await?;
    let payload = extract_bin_payload(&frame).expect("saslStart payload");
    let cf = std::str::from_utf8(&payload).unwrap();
    assert!(
        cf.starts_with("n,,n="),
        "expected SCRAM client first message, got {cf:?}"
    );
    let bare = &cf[3..];
    let user_attr = bare.split(',').next().unwrap();
    let user = user_attr.trim_start_matches("n=");
    if user != username {
        write_sasl_reply(
            &mut s,
            false,
            1,
            b"e=unknown-user",
            true,
            Some("UserNotFound"),
        )
        .await?;
        return Ok(());
    }
    let cnonce = bare.split(',').nth(1).unwrap().trim_start_matches("r=");
    let salt = b"raxis-scram-test-salt-32B-pad000";
    let iter: u32 = 4096;
    let snonce = "SERVERNONCE-XYZ";
    let combined = format!("{cnonce}{snonce}");
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
    let server_first = format!("r={combined},s={salt_b64},i={iter}");
    write_sasl_reply(&mut s, true, 1, server_first.as_bytes(), false, None).await?;

    // ---- saslContinue (proxy's client-final-message) ----
    let frame = read_op_msg_frame(&mut s).await?;
    let payload = extract_bin_payload(&frame).expect("saslContinue payload");
    let cf2 = std::str::from_utf8(&payload).unwrap();
    let mut got_combined = "";
    let mut proof_b64 = "";
    for attr in cf2.split(',') {
        if let Some(v) = attr.strip_prefix("r=") {
            got_combined = v;
        }
        if let Some(v) = attr.strip_prefix("p=") {
            proof_b64 = v;
        }
    }
    assert_eq!(got_combined, combined);

    // Server-side SCRAM crypto.
    let salted = test_pbkdf2_hmac_sha256(&password, salt, iter);
    let client_key = test_hmac_sha256(&salted, b"Client Key");
    let stored_key = test_sha256(&client_key);
    let server_key = test_hmac_sha256(&salted, b"Server Key");
    let cf_bare = format!("n={user},r={cnonce}");
    let cl_final_bare = format!("c=biws,r={combined}");
    let auth_msg = format!("{cf_bare},{server_first},{cl_final_bare}");
    let cli_sig = test_hmac_sha256(&stored_key, auth_msg.as_bytes());
    let mut expected_proof = client_key;
    for (a, b) in expected_proof.iter_mut().zip(cli_sig.iter()) {
        *a ^= *b;
    }
    let got_proof = base64::engine::general_purpose::STANDARD
        .decode(proof_b64)
        .unwrap();
    let proof_matches = got_proof == expected_proof;

    if !proof_matches {
        write_sasl_reply(
            &mut s,
            false,
            1,
            b"e=invalid-proof",
            true,
            Some("AuthenticationFailed"),
        )
        .await?;
        return Ok(());
    }
    let server_sig = test_hmac_sha256(&server_key, auth_msg.as_bytes());
    let v = base64::engine::general_purpose::STANDARD.encode(server_sig);
    let server_final = format!("v={v}");
    write_sasl_reply(&mut s, true, 1, server_final.as_bytes(), true, None).await?;

    // ---- Post-auth: dispatch subsequent OP_MSG frames through the
    // response callback (same shape as FakeBackend).
    loop {
        let mut header = [0u8; 16];
        if s.read_exact(&mut header).await.is_err() {
            return Ok(());
        }
        let total = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let request_id = i32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let op_code = i32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        if !(16..=64 * 1024 * 1024).contains(&total) || op_code != 2013 {
            return Ok(());
        }
        let body_len = total - 16;
        let mut body = vec![0u8; body_len];
        s.read_exact(&mut body).await?;
        let cmd = first_command_name(&body).unwrap_or_default();
        let resp = responses(&cmd).unwrap_or(FakeResponse::Ok { extras: vec![] });
        let reply_doc = build_reply_doc(&cmd, &resp);
        let reply_msg =
            build_op_msg_reply(request_id.wrapping_add(0x4000_0000), request_id, &reply_doc);
        s.write_all(&reply_msg).await?;
        s.flush().await?;
    }
}

async fn read_op_msg_frame(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 16];
    s.read_exact(&mut header).await?;
    let total = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let body_len = total - 16;
    let mut body = vec![0u8; body_len];
    s.read_exact(&mut body).await?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn extract_bin_payload(frame: &[u8]) -> Option<Vec<u8>> {
    let body = &frame[16..];
    let kind = *body.get(4)?;
    if kind != 0 {
        return None;
    }
    let doc = body.get(5..)?;
    let total =
        i32::from_le_bytes([*doc.first()?, *doc.get(1)?, *doc.get(2)?, *doc.get(3)?]) as usize;
    let inner = &doc[4..total - 1];
    let mut i = 0;
    while i < inner.len() {
        let t = inner[i];
        i += 1;
        if t == 0 {
            break;
        }
        let nul = inner[i..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&inner[i..i + nul]).ok()?;
        i += nul + 1;
        if t == 0x05 && name == "payload" {
            let blen =
                i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]]) as usize;
            return Some(inner[i + 5..i + 5 + blen].to_vec());
        }
        let skip = match t {
            0x01 | 0x09 | 0x11 | 0x12 => 8,
            0x02 => {
                let l = i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]])
                    as usize;
                4 + l
            }
            0x03 | 0x04 => {
                i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]]) as usize
            }
            0x05 => {
                let l = i32::from_le_bytes([inner[i], inner[i + 1], inner[i + 2], inner[i + 3]])
                    as usize;
                4 + 1 + l
            }
            0x07 => 12,
            0x08 => 1,
            0x10 => 4,
            _ => return None,
        };
        i += skip;
    }
    None
}

async fn write_sasl_reply(
    s: &mut TcpStream,
    ok: bool,
    conv_id: i32,
    payload: &[u8],
    done: bool,
    errmsg: Option<&str>,
) -> std::io::Result<()> {
    let mut b = BsonBuilder::new()
        .double("ok", if ok { 1.0 } else { 0.0 })
        .int32("conversationId", conv_id)
        .binary("payload", payload)
        .bool_("done", done);
    if let Some(m) = errmsg {
        b = b.string("errmsg", m).int32("code", 18);
    }
    let doc = b.finish();
    let body_len = 4 + 1 + doc.len();
    let total = 16 + body_len;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as i32).to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&2013i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.push(0);
    out.extend_from_slice(&doc);
    s.write_all(&out).await?;
    s.flush().await
}

fn test_pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, rounds, &mut out);
    out
}

fn test_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn test_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}
