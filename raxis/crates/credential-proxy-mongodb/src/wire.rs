//! MongoDB wire-protocol primitives.
//!
//! Reference: <https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/>
//! and the `OP_MSG` documentation under
//! <https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#op-msg>.
//!
//! Every MongoDB message starts with a 16-byte header:
//!
//! ```text
//!   int32  message_length    // total length including this header
//!   int32  request_id
//!   int32  response_to       // request_id of the request being replied to
//!   int32  op_code           // 2013 = OP_MSG (modern), 1 = OP_REPLY (legacy)
//! ```
//!
//! For `OP_MSG` (op_code 2013), the body is:
//!
//! ```text
//!   uint32 flag_bits
//!   sections... where each section is { kind:u8, ... }
//! ```
//!
//! Section kind 0 ("Body") is followed by exactly one BSON document
//! — that's the command. Section kind 1 ("Document Sequence")
//! carries arrays of BSON docs and is used for batched
//! `insert` / `update` / `delete` payloads.
//!
//! V2 MVP only needs to:
//!
//!   * Read the 16-byte header off the wire and bound the message
//!     length.
//!   * Read the body bytes and locate the kind-0 section's BSON
//!     doc.
//!   * Pull the **first BSON field name** out of that doc — that's
//!     the command name (e.g. `"find"`, `"insert"`, `"hello"`).
//!     The shipped helper (`first_command_name`) is still consumed
//!     by `lib.rs` as a fallback for the
//!     `CommandTarget::Ambiguous` audit envelope; the V2 walker in
//!     `restriction::walk_command` does the deeper parsing for
//!     `allowed_collections` / `forbidden_collections` /
//!     `max_documents` per `specs/v2/proxy-table-allowlists.md §6`.
//!
//! BSON document layout
//! ====================
//!
//! ```text
//!   int32 total_length      // including this length and trailing 0x00
//!   element*
//!   0x00                    // end-of-document
//! ```
//!
//! Element layout:
//!
//! ```text
//!   uint8 type_byte
//!   cstring name            // NUL-terminated key
//!   value                   // type-dependent
//! ```
//!
//! This module decodes the bare minimum needed for framing — header,
//! message-length bound, and `first_command_name`. The deeper BSON
//! walker that resolves collection names, `$db`, and pipeline
//! references lives in `restriction::walk_command` per
//! `specs/v2/proxy-table-allowlists.md §6`.

use bytes::{BufMut, BytesMut};

/// Hard cap on inbound message length. Real Mongo enforces a
/// 48 MiB cap (`maxMessageSizeBytes`). We refuse anything above
/// 64 MiB to bound buffering and stop a malicious agent from
/// allocating gigabytes by lying about the length field.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024 * 1024;

/// Header byte length.
pub const HEADER_LEN: usize = 16;

/// `OP_MSG` op code (modern wire).
pub const OP_MSG: i32 = 2013;

/// `OP_QUERY` op code (legacy wire, op code 2004).
///
/// Modern drivers (pymongo 4.x, the official Java driver, Node, Go,
/// Rust) negotiate down to `OP_MSG` after the first reply, but the
/// **initial handshake** — `{ ismaster: 1, helloOk: true, ... }`
/// targeting collection `admin.$cmd` — is still sent as `OP_QUERY`
/// against the legacy collection contract per the
/// `Server Discovery and Monitoring` driver spec (the legacy
/// pre-`hello` handshake form is the universal lowest common
/// denominator before the server's `maxWireVersion` is known).
/// The proxy MUST answer with an `OP_REPLY` (op code 1) carrying
/// the synthesised hello document; without it pymongo's SDAM monitor
/// reports `ServerSelectionTimeoutError: connection closed`. See
/// the iter33 root-cause note inline in `serve_one` and the
/// `op_query_initial_handshake_replied_with_op_reply` regression
/// test.
pub const OP_QUERY: i32 = 2004;

/// `OP_REPLY` op code (legacy wire, op code 1). Reply form to
/// `OP_QUERY`; required by the initial handshake even though the
/// V2 proxy never speaks `OP_REPLY` for any later command (those
/// all flow through `OP_MSG`).
pub const OP_REPLY: i32 = 1;

/// Parsed message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsgHeader {
    /// Total message length, including the header (so body length
    /// is `message_length - 16`).
    pub message_length: i32,
    /// Sender-chosen request ID.
    pub request_id: i32,
    /// `request_id` of the request being replied to (0 on requests).
    pub response_to: i32,
    /// Op code (2013 = `OP_MSG`).
    pub op_code: i32,
}

impl MsgHeader {
    /// Decode 16 header bytes off the wire.
    pub fn parse(buf: [u8; 16]) -> Self {
        Self {
            message_length: i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            request_id: i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            response_to: i32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            op_code: i32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        }
    }

    /// Encode this header into 16 wire bytes.
    pub fn encode(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&self.message_length.to_le_bytes());
        out[4..8].copy_from_slice(&self.request_id.to_le_bytes());
        out[8..12].copy_from_slice(&self.response_to.to_le_bytes());
        out[12..].copy_from_slice(&self.op_code.to_le_bytes());
        out
    }
}

/// Extract the first BSON field name from an `OP_MSG` body. Returns
/// `None` when the body is malformed or has no kind-0 section.
///
/// The body layout is `flag_bits:u32` followed by sections. We walk
/// to the first kind-0 section, parse its BSON header, and read
/// the first element's name.
pub fn first_command_name(body: &[u8]) -> Option<String> {
    if body.len() < 4 {
        return None;
    }
    let mut i = 4; // skip flag_bits
    while i < body.len() {
        let kind = body[i];
        i += 1;
        if kind == 0 {
            // Body section: BSON doc starts at i.
            return first_bson_field_name(&body[i..]);
        } else if kind == 1 {
            // Document sequence: int32 size + cstring identifier +
            // BSON docs. Skip whole section.
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
            // Unknown section kind; bail.
            return None;
        }
    }
    None
}

/// Pull the name of the first element out of a BSON document.
///
/// Layout: `[i32 total_length] [element]* [0x00]`. We skip the
/// 4-byte length, read the type byte, then scan to the first NUL
/// to terminate the field name. Returns `None` on a malformed doc
/// or the (rare) case where the doc is empty.
pub fn first_bson_field_name(doc: &[u8]) -> Option<String> {
    if doc.len() < 5 {
        return None;
    }
    let total = i32::from_le_bytes([doc[0], doc[1], doc[2], doc[3]]) as usize;
    if total < 5 || total > doc.len() {
        return None;
    }
    let body = &doc[4..total];
    if body.is_empty() || body[0] == 0x00 {
        return None;
    }
    // Skip type byte.
    let after_type = &body[1..];
    let nul = after_type.iter().position(|&b| b == 0)?;
    let name_bytes = &after_type[..nul];
    Some(String::from_utf8_lossy(name_bytes).into_owned())
}

/// Decode an `OP_QUERY` body and pull out:
///
///   * The fully-qualified collection name (e.g. `"admin.$cmd"`).
///   * The first BSON field name from the query document, which —
///     by the legacy command-on-collection-`$cmd` contract — is the
///     name of the command (e.g. `"ismaster"` / `"isMaster"` /
///     `"hello"`).
///
/// Returns `None` on a malformed frame.
///
/// `OP_QUERY` body layout
/// (`https://www.mongodb.com/docs/manual/legacy-opcodes/#op_query`):
///
/// ```text
///   int32  flags
///   cstring fullCollectionName     // e.g. "admin.$cmd"
///   int32  numberToSkip
///   int32  numberToReturn
///   document query
///   [document returnFieldsSelector] // optional, ignored
/// ```
pub fn parse_op_query_command(body: &[u8]) -> Option<(String, String)> {
    if body.len() < 4 + 1 + 4 + 4 + 5 {
        return None;
    }
    let mut i = 4; // skip flags
                   // fullCollectionName cstring.
    let nul = body[i..].iter().position(|&b| b == 0)?;
    let coll = String::from_utf8_lossy(&body[i..i + nul]).into_owned();
    i += nul + 1;
    // numberToSkip + numberToReturn.
    if i + 8 > body.len() {
        return None;
    }
    i += 8;
    // Query BSON doc starts at i.
    let cmd = first_bson_field_name(&body[i..])?;
    Some((coll, cmd))
}

/// Build an `OP_REPLY` frame (`op_code 1`) carrying a single
/// BSON document. Required by the legacy initial-handshake
/// contract (see [`OP_QUERY`]).
///
/// `OP_REPLY` body layout
/// (`https://www.mongodb.com/docs/manual/legacy-opcodes/#op_reply`):
///
/// ```text
///   int32   responseFlags          // 8 = AwaitCapable
///   int64   cursorID               // 0 for a one-shot command reply
///   int32   startingFrom           // 0
///   int32   numberReturned         // 1 for the single hello doc
///   document* documents
/// ```
pub fn build_op_reply(request_id: i32, response_to: i32, bson_doc: &[u8]) -> Vec<u8> {
    let body_len = 4 /* responseFlags */
                 + 8 /* cursorID */
                 + 4 /* startingFrom */
                 + 4 /* numberReturned */
                 + bson_doc.len();
    let total = HEADER_LEN + body_len;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(
        &MsgHeader {
            message_length: total as i32,
            request_id,
            response_to,
            op_code: OP_REPLY,
        }
        .encode(),
    );
    // responseFlags = 8 (AwaitCapable). Pymongo accepts 0 as well;
    // the canonical mongod sets `AwaitCapable` for legacy `find` /
    // `getMore` cursor compatibility. For a hello reply either is
    // fine.
    out.extend_from_slice(&8i32.to_le_bytes());
    out.extend_from_slice(&0i64.to_le_bytes()); // cursorID = 0 (no cursor)
    out.extend_from_slice(&0i32.to_le_bytes()); // startingFrom = 0
    out.extend_from_slice(&1i32.to_le_bytes()); // numberReturned = 1
    out.extend_from_slice(bson_doc);
    out
}

/// Build an `OP_MSG` reply with a single kind-0 body section
/// carrying `bson_doc` as its body.
pub fn build_op_msg_reply(request_id: i32, response_to: i32, bson_doc: &[u8]) -> Vec<u8> {
    let body_len = 4 /* flag_bits */ + 1 /* kind */ + bson_doc.len();
    let total = HEADER_LEN + body_len;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(
        &MsgHeader {
            message_length: total as i32,
            request_id,
            response_to,
            op_code: OP_MSG,
        }
        .encode(),
    );
    out.extend_from_slice(&0u32.to_le_bytes()); // flag_bits = 0
    out.push(0); // section kind 0
    out.extend_from_slice(bson_doc);
    out
}

// ---------------------------------------------------------------------------
// BSON encoding helpers — exactly the types the V2 replies need.
// ---------------------------------------------------------------------------

const BSON_DOUBLE: u8 = 0x01;
const BSON_STRING: u8 = 0x02;
const BSON_DOC: u8 = 0x03;
const BSON_ARRAY: u8 = 0x04;
const BSON_BIN: u8 = 0x05;
const BSON_BOOL: u8 = 0x08;
const BSON_INT32: u8 = 0x10;
const BSON_INT64: u8 = 0x12;

/// In-progress BSON document builder.
#[derive(Debug, Default)]
pub struct BsonBuilder {
    body: BytesMut,
}

impl BsonBuilder {
    /// Empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// `{ key: value(f64) }`.
    pub fn double(mut self, key: &str, val: f64) -> Self {
        self.body.put_u8(BSON_DOUBLE);
        self.body.put_slice(key.as_bytes());
        self.body.put_u8(0);
        self.body.put_f64_le(val);
        self
    }

    /// `{ key: value(i32) }`.
    pub fn int32(mut self, key: &str, val: i32) -> Self {
        self.body.put_u8(BSON_INT32);
        self.body.put_slice(key.as_bytes());
        self.body.put_u8(0);
        self.body.put_i32_le(val);
        self
    }

    /// `{ key: value(i64) }`.
    pub fn int64(mut self, key: &str, val: i64) -> Self {
        self.body.put_u8(BSON_INT64);
        self.body.put_slice(key.as_bytes());
        self.body.put_u8(0);
        self.body.put_i64_le(val);
        self
    }

    /// `{ key: value(bool) }`.
    pub fn bool(mut self, key: &str, val: bool) -> Self {
        self.body.put_u8(BSON_BOOL);
        self.body.put_slice(key.as_bytes());
        self.body.put_u8(0);
        self.body.put_u8(if val { 1 } else { 0 });
        self
    }

    /// `{ key: value(string) }`.
    pub fn string(mut self, key: &str, val: &str) -> Self {
        self.body.put_u8(BSON_STRING);
        self.body.put_slice(key.as_bytes());
        self.body.put_u8(0);
        // BSON UTF-8 string: int32 length-including-terminator + bytes + 0x00
        self.body.put_i32_le((val.len() + 1) as i32);
        self.body.put_slice(val.as_bytes());
        self.body.put_u8(0);
        self
    }

    /// `{ key: <inner doc> }`.
    pub fn document(mut self, key: &str, inner: Vec<u8>) -> Self {
        self.body.put_u8(BSON_DOC);
        self.body.put_slice(key.as_bytes());
        self.body.put_u8(0);
        self.body.put_slice(&inner);
        self
    }

    /// `{ key: <array doc> }` — encoded as BSON array (type
    /// `0x04`). Caller is responsible for using numeric keys
    /// `"0"`, `"1"`, … inside `inner` per the BSON array
    /// convention.
    pub fn array(mut self, key: &str, inner: Vec<u8>) -> Self {
        self.body.put_u8(BSON_ARRAY);
        self.body.put_slice(key.as_bytes());
        self.body.put_u8(0);
        self.body.put_slice(&inner);
        self
    }

    /// `{ key: BinData(0, bytes) }` — generic binary subtype 0.
    /// Used by the SCRAM-SHA-256 upstream auth path to wrap the
    /// SASL `payload` field per the MongoDB driver spec.
    pub fn binary(mut self, key: &str, bytes: &[u8]) -> Self {
        self.body.put_u8(BSON_BIN);
        self.body.put_slice(key.as_bytes());
        self.body.put_u8(0);
        // BSON binary value: int32 length, u8 subtype, bytes...
        self.body.put_i32_le(bytes.len() as i32);
        self.body.put_u8(0); // subtype 0 = generic binary
        self.body.put_slice(bytes);
        self
    }

    /// Finalise and return the encoded BSON document.
    pub fn finish(self) -> Vec<u8> {
        let inner = self.body.freeze();
        let total = 4 + inner.len() + 1;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(total as i32).to_le_bytes());
        out.extend_from_slice(&inner);
        out.push(0x00);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let h = MsgHeader {
            message_length: 256,
            request_id: 7,
            response_to: 3,
            op_code: OP_MSG,
        };
        let bytes = h.encode();
        let back = MsgHeader::parse(bytes);
        assert_eq!(h, back);
    }

    #[test]
    fn first_bson_field_name_finds_command() {
        // BSON: { hello: 1.0 }
        // Total = 4 + 1 + len("hello") + 1 + 8 + 1 = 4 + 1 + 5 + 1 + 8 + 1 = 20.
        let mut doc = Vec::new();
        doc.extend_from_slice(&20i32.to_le_bytes());
        doc.push(0x01); // double
        doc.extend_from_slice(b"hello");
        doc.push(0);
        doc.extend_from_slice(&1.0f64.to_le_bytes());
        doc.push(0); // doc terminator
        assert_eq!(first_bson_field_name(&doc).as_deref(), Some("hello"));
    }

    #[test]
    fn first_command_name_walks_op_msg_body() {
        // { find: 1 }
        let bson_doc = BsonBuilder::new().int32("find", 1).finish();
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // flag_bits
        body.push(0); // kind = body
        body.extend_from_slice(&bson_doc);
        assert_eq!(first_command_name(&body).as_deref(), Some("find"));
    }

    /// Regression test for live-e2e iter33.
    ///
    /// Pymongo 4.x (and several other modern drivers) negotiate
    /// down to `OP_MSG` only **after** the initial handshake.
    /// The initial handshake itself is sent as legacy `OP_QUERY`
    /// targeting collection `admin.$cmd` with the query document
    /// `{ ismaster: 1, helloOk: true, ... }`. The parser must
    /// recover the collection name AND the first command-doc
    /// field name from such a frame so the proxy can respond
    /// with a synthesised hello via `OP_REPLY`.
    #[test]
    fn parse_op_query_pulls_collection_and_first_command_field() {
        // Construct the OP_QUERY body pymongo would send.
        let mut body = Vec::new();
        body.extend_from_slice(&0i32.to_le_bytes()); // flags = 0
        body.extend_from_slice(b"admin.$cmd\0");
        body.extend_from_slice(&0i32.to_le_bytes()); // skip = 0
        body.extend_from_slice(&(-1i32).to_le_bytes()); // return = -1
                                                        // Query doc: { ismaster: 1, helloOk: true }
        let q = BsonBuilder::new()
            .int32("ismaster", 1)
            .bool("helloOk", true)
            .finish();
        body.extend_from_slice(&q);

        let (coll, cmd) = parse_op_query_command(&body).expect("parse");
        assert_eq!(coll, "admin.$cmd");
        assert_eq!(cmd, "ismaster");
    }

    /// Regression test for live-e2e iter33: `build_op_reply` MUST
    /// stamp `op_code = 1` (`OP_REPLY`) and `numberReturned = 1`
    /// so pymongo's SDAM monitor recognises the frame as a
    /// command reply rather than tearing the socket down.
    #[test]
    fn build_op_reply_stamps_op_code_1_and_one_returned() {
        let q = BsonBuilder::new().double("ok", 1.0).finish();
        let frame = build_op_reply(1234, 42, &q);
        // Header op_code at bytes 12..16.
        let op = i32::from_le_bytes([frame[12], frame[13], frame[14], frame[15]]);
        assert_eq!(op, OP_REPLY);
        // numberReturned at body offset 4+8+4 = 16 → frame
        // offset 16 + 16 = 32.
        let n = i32::from_le_bytes([
            frame[16 + 16],
            frame[16 + 17],
            frame[16 + 18],
            frame[16 + 19],
        ]);
        assert_eq!(n, 1);
    }

    #[test]
    fn bson_builder_emits_minimal_ok_doc() {
        let doc = BsonBuilder::new().double("ok", 1.0).finish();
        // Length-prefixed: total = 4 + 1 + 2 + 1 + 8 + 1 = 17
        assert_eq!(i32::from_le_bytes([doc[0], doc[1], doc[2], doc[3]]), 17);
        assert_eq!(doc[4], 0x01); // double
        assert_eq!(&doc[5..7], b"ok");
        assert_eq!(doc[7], 0);
        let val = f64::from_le_bytes([
            doc[8], doc[9], doc[10], doc[11], doc[12], doc[13], doc[14], doc[15],
        ]);
        assert_eq!(val, 1.0);
        assert_eq!(doc[16], 0); // terminator
    }
}
