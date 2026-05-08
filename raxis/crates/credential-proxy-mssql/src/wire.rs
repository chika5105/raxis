//! MSSQL TDS (Tabular Data Stream) wire-protocol primitives.
//!
//! Reference: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/>.
//!
//! Every TDS message starts with an 8-byte header:
//!
//! ```text
//!   uint8  type           // 0x01 SQLBatch, 0x10 LOGIN7, 0x12 PRELOGIN, 0x04 Tabular Result
//!   uint8  status         // bit 0x01 = end of message; bit 0x02 = ignore
//!   uint16 length_be      // total packet length INCLUDING header (BIG-ENDIAN)
//!   uint16 spid_be        // server process ID, 0 from client
//!   uint8  packet_id      // increments per packet within a message
//!   uint8  window         // reserved, must be 0
//! ```
//!
//! The body layout depends on `type`. V2 MVP only needs:
//!
//!   * PRELOGIN (0x12) inbound — drain.
//!     PRELOGIN (0x12) outbound — synthesise.
//!   * LOGIN7   (0x10) inbound — drain.
//!   * Tabular Result (0x04) outbound — synthesise LOGINACK + DONE.
//!   * SQLBatch (0x01) inbound — extract the UTF-16 LE SQL text.
//!     Tabular Result outbound — synthesise DONE for OK or ERROR
//!     + DONE for blocked.
//!
//! Tabular Result tokens used:
//!
//!   * 0xAD LOGINACK
//!   * 0xAA ERROR
//!   * 0xFD DONE
//!   * 0xE3 ENVCHANGE (database / packet size — V2 omits these)

use bytes::{BufMut, BytesMut};

/// TDS packet types (the first byte of the header).
pub mod pkt {
    /// SQLBatch — client → server SQL text.
    pub const SQL_BATCH:      u8 = 0x01;
    /// Pre-TDS7-Login (PRELOGIN) — version + encryption negotiation.
    pub const PRELOGIN:       u8 = 0x12;
    /// LOGIN7 — client → server credentials.
    pub const LOGIN7:         u8 = 0x10;
    /// Tabular Result — server → client.
    pub const TABULAR_RESULT: u8 = 0x04;
}

/// Status flag bits.
pub mod status {
    /// "End of message" — the last packet of a multi-packet message
    /// must set this.
    pub const EOM: u8 = 0x01;
}

/// 8-byte packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// Packet type byte.
    pub packet_type: u8,
    /// Status flags.
    pub status:      u8,
    /// Total packet length INCLUDING header (big-endian on the wire).
    pub length:      u16,
    /// Server process ID (clients send 0).
    pub spid:        u16,
    /// Sequential packet ID within a message.
    pub packet_id:   u8,
    /// Reserved, must be 0.
    pub window:      u8,
}

impl PacketHeader {
    /// Decode 8 header bytes off the wire.
    pub fn parse(buf: [u8; 8]) -> Self {
        Self {
            packet_type: buf[0],
            status:      buf[1],
            length:      u16::from_be_bytes([buf[2], buf[3]]),
            spid:        u16::from_be_bytes([buf[4], buf[5]]),
            packet_id:   buf[6],
            window:      buf[7],
        }
    }

    /// Encode this header to 8 wire bytes.
    pub fn encode(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0]     = self.packet_type;
        out[1]     = self.status;
        out[2..4]  .copy_from_slice(&self.length.to_be_bytes());
        out[4..6]  .copy_from_slice(&self.spid  .to_be_bytes());
        out[6]     = self.packet_id;
        out[7]     = self.window;
        out
    }
}

/// Minimum length in bytes a TDS packet can be (just the header).
pub const HEADER_LEN: usize = 8;

/// Hard cap on inbound packet length. Real TDS allows up to 32 MiB
/// in the negotiated `PacketSize` envchange, but we never advertise
/// > 4 KiB and refuse inbound > 64 MiB regardless to bound buffering.
pub const MAX_PACKET_LEN: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// PRELOGIN response
// ---------------------------------------------------------------------------

/// Build a minimal PRELOGIN response body. Carries only the
/// VERSION + ENCRYPTION(=2 "not supported") + terminator options.
/// Encryption "not supported" means clients fall back to plaintext
/// TDS — exactly what the V2 proxy speaks (the kernel terminates
/// TLS at the VM boundary, not at the proxy).
pub fn build_prelogin_response_body() -> Vec<u8> {
    // Two options + terminator. Each option header is 5 bytes
    // (type:u8, offset:u16 BE, length:u16 BE). Terminator is 0xff.
    //
    // Layout:
    //   type=VERSION(0x00) offset=<calc> length=6
    //   type=ENCRYPTION(0x01) offset=<calc> length=1
    //   terminator=0xff
    //   <data>
    //
    // Header section is 5+5+1 = 11 bytes; data is 6+1 = 7 bytes.
    // VERSION offset = 11; ENCRYPTION offset = 17.
    let mut body = BytesMut::with_capacity(18);
    // VERSION option header.
    body.put_u8(0x00);
    body.put_u16(11);
    body.put_u16(6);
    // ENCRYPTION option header.
    body.put_u8(0x01);
    body.put_u16(17);
    body.put_u16(1);
    // Terminator.
    body.put_u8(0xff);
    // VERSION data: major.minor.build = 15.0.4153.1 (SQL Server 2019).
    body.put_u8(15);
    body.put_u8(0);
    body.put_u16_le(4153);
    body.put_u16_le(1);
    // ENCRYPTION data: 2 = not supported.
    body.put_u8(2);
    body.to_vec()
}

// ---------------------------------------------------------------------------
// LOGINACK / DONE / ERROR tokens — Tabular Result body
// ---------------------------------------------------------------------------

const TOKEN_LOGINACK: u8 = 0xAD;
const TOKEN_ERROR:    u8 = 0xAA;
const TOKEN_DONE:     u8 = 0xFD;

/// Build a LOGINACK + DONE body — the response to LOGIN7.
pub fn build_loginack_done_body(server_version: &str) -> Vec<u8> {
    let mut body = BytesMut::with_capacity(64);

    // LOGINACK token:
    //   token_type:  0xAD
    //   length:      u16 LE   (length of the rest of the token)
    //   interface:   u8       (0x01 = TSQL)
    //   tds_version: u32 BE   (0x73000004 = TDS 7.3)
    //   progname_len:u8
    //   progname:    UTF-16 LE
    //   ver_major:   u8
    //   ver_minor:   u8
    //   ver_build_hi:u8
    //   ver_build_lo:u8
    let progname: Vec<u16> = server_version.encode_utf16().collect();
    let progname_bytes: Vec<u8> = progname
        .iter()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let token_inner_len = 1 /* interface */ + 4 /* tds_version */
        + 1 /* progname_len */ + progname_bytes.len() + 4 /* version */;

    body.put_u8(TOKEN_LOGINACK);
    body.put_u16_le(token_inner_len as u16);
    body.put_u8(0x01);                    // interface = TSQL
    body.put_u32(0x73000004);             // TDS 7.3 (BE per spec)
    body.put_u8(progname.len() as u8);
    body.put_slice(&progname_bytes);
    body.put_u8(15); body.put_u8(0); body.put_u8(0); body.put_u8(0); // version

    body.put_slice(&build_done_token(0x0000, 0x0000, 0));
    body.to_vec()
}

/// `DONE` token — terminates a tabular result stream.
pub fn build_done_token(status: u16, cur_cmd: u16, row_count: u64) -> Vec<u8> {
    let mut t = BytesMut::with_capacity(13);
    t.put_u8(TOKEN_DONE);
    t.put_u16_le(status);
    t.put_u16_le(cur_cmd);
    t.put_u64_le(row_count);
    t.to_vec()
}

/// `ERROR` token followed by a `DONE_ERROR` DONE.
pub fn build_error_done_body(error_number: i32, message: &str) -> Vec<u8> {
    let mut body = BytesMut::with_capacity(message.len() + 32);

    // ERROR token:
    //   token_type:  0xAA
    //   length:      u16 LE
    //   number:      i32 LE
    //   state:       u8
    //   class:       u8     (severity)
    //   msg_len:     u16 LE   (in characters)
    //   msg:         UTF-16 LE
    //   server_len:  u8
    //   server:      UTF-16 LE
    //   proc_len:    u8
    //   proc:        UTF-16 LE
    //   line:        i32 LE
    let msg_utf16: Vec<u16> = message.encode_utf16().collect();
    let msg_bytes: Vec<u8>  = msg_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let server: Vec<u16>    = "raxis-mssql-proxy".encode_utf16().collect();
    let server_bytes: Vec<u8> = server.iter().flat_map(|c| c.to_le_bytes()).collect();
    let inner_len = 4 + 1 + 1 + 2 + msg_bytes.len() + 1 + server_bytes.len() + 1 + 0 + 4;

    body.put_u8(TOKEN_ERROR);
    body.put_u16_le(inner_len as u16);
    body.put_i32_le(error_number);
    body.put_u8(1);  // state
    body.put_u8(14); // class (14 = security)
    body.put_u16_le(msg_utf16.len() as u16);
    body.put_slice(&msg_bytes);
    body.put_u8(server.len() as u8);
    body.put_slice(&server_bytes);
    body.put_u8(0);  // proc_len = 0
    body.put_i32_le(0);

    // DONE_ERROR: status bit 0x0002 = error
    body.put_slice(&build_done_token(0x0002, 0x0000, 0));
    body.to_vec()
}

/// Wrap a body in a TDS packet header (single-packet message, EOM
/// flag set, packet_id 1).
pub fn frame_packet(packet_type: u8, body: &[u8]) -> Vec<u8> {
    let total = HEADER_LEN + body.len();
    let header = PacketHeader {
        packet_type,
        status:    status::EOM,
        length:    total as u16,
        spid:      0,
        packet_id: 1,
        window:    0,
    };
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(body);
    out
}

/// Decode the SQLBatch body — the body is a 22-byte ALL_HEADERS
/// preamble (which we skip; V2 doesn't honour transaction
/// descriptors) followed by UTF-16 LE SQL text.
pub fn decode_sql_batch_body(body: &[u8]) -> Option<String> {
    // SQLBatch body begins with ALL_HEADERS:
    //   total_length:u32 LE = full length of headers including itself
    //   followed by `total_length - 4` bytes of headers.
    if body.len() < 4 { return None; }
    let total_headers = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if total_headers > body.len() {
        // Some clients omit ALL_HEADERS entirely on TDS 7.0/7.1; in
        // that case the bytes we read are already SQL text.
        return decode_utf16_le(body);
    }
    decode_utf16_le(&body[total_headers..])
}

fn decode_utf16_le(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 { return None; }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let h = PacketHeader {
            packet_type: pkt::SQL_BATCH,
            status:      status::EOM,
            length:      256,
            spid:        7,
            packet_id:   1,
            window:      0,
        };
        let b = h.encode();
        assert_eq!(PacketHeader::parse(b), h);
    }

    #[test]
    fn prelogin_response_has_two_option_headers_and_terminator() {
        let body = build_prelogin_response_body();
        assert_eq!(body[0],  0x00); // VERSION
        assert_eq!(body[5],  0x01); // ENCRYPTION
        assert_eq!(body[10], 0xff); // terminator
        assert_eq!(body.len(), 18);
    }

    #[test]
    fn loginack_body_carries_correct_token_byte() {
        let b = build_loginack_done_body("raxis-tds-v2");
        assert_eq!(b[0], TOKEN_LOGINACK);
    }

    #[test]
    fn error_done_body_carries_error_token_byte() {
        let b = build_error_done_body(-1, "denied");
        assert_eq!(b[0], TOKEN_ERROR);
    }

    #[test]
    fn frame_packet_sets_eom_flag() {
        let body = build_done_token(0, 0, 0);
        let pkt  = frame_packet(pkt::TABULAR_RESULT, &body);
        let h = PacketHeader::parse([
            pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5], pkt[6], pkt[7],
        ]);
        assert_eq!(h.status & status::EOM, status::EOM);
        assert_eq!(h.length as usize, pkt.len());
    }

    #[test]
    fn sql_batch_body_with_all_headers_decodes_utf16_sql() {
        // ALL_HEADERS: total = 4 (just the length).
        let mut body = Vec::new();
        body.extend_from_slice(&4u32.to_le_bytes());
        let sql = "SELECT 1";
        let utf16: Vec<u8> = sql.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        body.extend_from_slice(&utf16);
        assert_eq!(decode_sql_batch_body(&body).as_deref(), Some("SELECT 1"));
    }
}
