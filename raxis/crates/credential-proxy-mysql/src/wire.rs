//! MySQL wire-protocol primitives the proxy uses.
//!
//! Reference: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html>
//! and <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html>.
//!
//! Every MySQL packet is `<length:3 LE><sequence_id:1>` followed by
//! `length` bytes of payload. Sequence IDs reset to 0 at the start
//! of every command (`COM_*`) and increment per packet within the
//! same command. The proxy only needs to:
//!
//!   * Send a synthetic `Protocol::HandshakeV10` greeting (seq=0).
//!   * Read the client's `HandshakeResponse41` (seq=1) — payload
//!     contents are discarded; the kernel-resolved credential is
//!     what would have been used to authenticate upstream in V3.
//!   * Send an `OK_Packet` (seq=2) to signal authentication
//!     success.
//!   * Loop reading `COM_QUERY` / `COM_QUIT` / `COM_PING` packets
//!     and reply with the corresponding synthetic response.
//!
//! All multi-byte integers are little-endian.

use bytes::{BufMut, BytesMut};

/// Maximum payload length a single packet can carry. Larger
/// payloads must be split across multiple packets — V2 MVP rejects
/// any inbound packet that announces a length above this with an
/// `ERR_Packet`.
pub const MAX_PACKET_PAYLOAD: usize = 16 * 1024 * 1024 - 1;

/// MySQL command bytes (first byte of a `COM_*` packet payload).
pub mod cmd {
    /// Client signals end of session and closes the connection.
    pub const QUIT:    u8 = 0x01;
    /// Run a textual SQL statement (`COM_QUERY`).
    pub const QUERY:   u8 = 0x03;
    /// Liveness check (`COM_PING`).
    pub const PING:    u8 = 0x0e;
    /// Reset the session connection state without re-handshaking
    /// (`COM_RESET_CONNECTION`).
    pub const RESET:   u8 = 0x1f;
    /// Prepare a SQL statement (`COM_STMT_PREPARE`). Payload is
    /// `0x16 + sql_bytes`.
    pub const STMT_PREPARE: u8 = 0x16;
    /// Execute a previously-prepared statement (`COM_STMT_EXECUTE`).
    /// Payload is `0x17 + stmt_id (4 LE) + flags (1) + iter (4 LE) +
    /// null_bitmap + new_params_flag (1) + (types + values)`.
    pub const STMT_EXECUTE: u8 = 0x17;
    /// Send a long parameter value chunk (`COM_STMT_SEND_LONG_DATA`).
    /// Payload is `0x18 + stmt_id (4 LE) + param_id (2 LE) + data`.
    /// No reply expected.
    pub const STMT_SEND_LONG_DATA: u8 = 0x18;
    /// Close a prepared statement (`COM_STMT_CLOSE`). Payload is
    /// `0x19 + stmt_id (4 LE)`. No reply expected.
    pub const STMT_CLOSE: u8 = 0x19;
    /// Reset accumulated `SEND_LONG_DATA` chunks for a stmt
    /// (`COM_STMT_RESET`). Payload is `0x1a + stmt_id (4 LE)`.
    /// Reply is OK_Packet or ERR_Packet.
    pub const STMT_RESET: u8 = 0x1a;
    /// Fetch additional rows from a cursor (`COM_STMT_FETCH`).
    /// Payload is `0x1c + stmt_id (4 LE) + nrows (4 LE)`. Reply is
    /// rows + EOF (or ERR).
    pub const STMT_FETCH: u8 = 0x1c;
}

/// Capability flags the proxy advertises in the `HandshakeV10`
/// greeting it sends to the AGENT.
///
/// Reference: <https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html>.
///
/// Pinned bit positions (every comment is double-checked against
/// the spec — the V2.1 mask had bit 5/6/11 mis-numbered as
/// `LOCAL_FILES`/`IGNORE_SPACE`/`IGNORE_SIGPIPE`, which are bits
/// 7/8/12; bit 11 is `CLIENT_SSL` and bit 5 is `CLIENT_COMPRESS`):
///
/// * bit 0  — `CLIENT_LONG_PASSWORD`
/// * bit 1  — `CLIENT_FOUND_ROWS`
/// * bit 2  — `CLIENT_LONG_FLAG`
/// * bit 3  — `CLIENT_CONNECT_WITH_DB`
/// * bit 9  — `CLIENT_PROTOCOL_41` (REQUIRED)
/// * bit 12 — `CLIENT_IGNORE_SIGPIPE`
/// * bit 13 — `CLIENT_TRANSACTIONS`
/// * bit 15 — `CLIENT_SECURE_CONNECTION` (REQUIRED so client
///            sends the 20-byte SHA-1 scramble layout)
/// * bit 17 — `CLIENT_MULTI_RESULTS`
/// * bit 18 — `CLIENT_PS_MULTI_RESULTS`
/// * bit 19 — `CLIENT_PLUGIN_AUTH` (REQUIRED for the plugin name
///            field in the response)
///
/// We deliberately do NOT advertise:
///
/// * bit 5  (`CLIENT_COMPRESS`) — would tell the agent to zlib-frame
///   every subsequent packet; the proxy does not understand zlib
///   framing.
/// * bit 11 (`CLIENT_SSL`) — would tell the agent to negotiate TLS
///   over the same TCP stream; the proxy is plaintext-only.
///
/// Mirrors `upstream::CLIENT_CAPS`. See the upstream comment for
/// the full V2.1 regression history.
pub const CAPABILITIES: u32 = 0
    | (1 <<  0)  // CLIENT_LONG_PASSWORD
    | (1 <<  1)  // CLIENT_FOUND_ROWS
    | (1 <<  2)  // CLIENT_LONG_FLAG
    | (1 <<  3)  // CLIENT_CONNECT_WITH_DB
    | (1 <<  9)  // CLIENT_PROTOCOL_41
    | (1 << 12)  // CLIENT_IGNORE_SIGPIPE
    | (1 << 13)  // CLIENT_TRANSACTIONS
    | (1 << 15)  // CLIENT_SECURE_CONNECTION
    | (1 << 17)  // CLIENT_MULTI_RESULTS
    | (1 << 18)  // CLIENT_PS_MULTI_RESULTS
    | (1 << 19); // CLIENT_PLUGIN_AUTH

/// Server status flags returned by `OK_Packet`.
pub const STATUS_AUTOCOMMIT: u16 = 0x0002;

/// Construct a `HandshakeV10` greeting payload with the given
/// `auth_plugin_data` (20 random bytes the client uses for the
/// scramble). The sequence ID is the caller's responsibility.
pub fn build_handshake_v10(
    server_version: &str,
    thread_id:      u32,
    auth_plugin_data: &[u8; 20],
) -> Vec<u8> {
    let mut p = BytesMut::with_capacity(128);
    p.put_u8(0x0a); // protocol_version
    p.put_slice(server_version.as_bytes());
    p.put_u8(0); // NUL terminator

    p.put_u32_le(thread_id);
    p.put_slice(&auth_plugin_data[..8]);
    p.put_u8(0); // filler

    let cap_lower = (CAPABILITIES & 0xFFFF) as u16;
    p.put_u16_le(cap_lower);

    p.put_u8(0x21); // character_set: utf8mb4 / utf8_general_ci approx
    p.put_u16_le(STATUS_AUTOCOMMIT);

    let cap_upper = ((CAPABILITIES >> 16) & 0xFFFF) as u16;
    p.put_u16_le(cap_upper);

    // auth_plugin_data_len: 20 bytes total (8 already written + 12 remaining + 1 NUL filler).
    p.put_u8(21);

    p.put_slice(&[0u8; 10]); // reserved

    p.put_slice(&auth_plugin_data[8..]); // 12 bytes
    p.put_u8(0); // NUL terminator for the second part (per spec)

    p.put_slice(b"mysql_native_password");
    p.put_u8(0); // NUL terminator
    p.to_vec()
}

/// Construct an `OK_Packet` payload. Caller picks the sequence ID.
/// We always advertise zero affected rows / zero last-insert-id so
/// the client's driver state machine (mysql-rs, mysql2, etc.) sees
/// a "successful no-op" reply, which is exactly what the V2
/// handshake-tier MVP synthesises.
pub fn build_ok_packet() -> Vec<u8> {
    let mut p = BytesMut::with_capacity(11);
    p.put_u8(0x00); // header: OK
    put_lenenc_int(&mut p, 0); // affected_rows
    put_lenenc_int(&mut p, 0); // last_insert_id
    p.put_u16_le(STATUS_AUTOCOMMIT);
    p.put_u16_le(0); // warnings
    p.to_vec()
}

/// Construct an `EOF_Packet` payload (legacy — needed so old
/// clients see a result-set terminator after the synthesised empty
/// row stream).
pub fn build_eof_packet() -> Vec<u8> {
    let mut p = BytesMut::with_capacity(5);
    p.put_u8(0xfe);
    p.put_u16_le(0); // warnings
    p.put_u16_le(STATUS_AUTOCOMMIT);
    p.to_vec()
}

/// Construct an `ERR_Packet` payload. `error_code` is the MySQL
/// numeric code (e.g. 1142 for `ER_TABLEACCESS_DENIED_ERROR`,
/// which we use for restriction denials so the client sees an
/// authoritative-looking SQL access error rather than a
/// generic 1064 syntax error).
pub fn build_err_packet(error_code: u16, sqlstate: &str, message: &str) -> Vec<u8> {
    let mut p = BytesMut::with_capacity(message.len() + 16);
    p.put_u8(0xff);
    p.put_u16_le(error_code);
    p.put_u8(b'#');
    let sqlstate_bytes = sqlstate.as_bytes();
    if sqlstate_bytes.len() == 5 {
        p.put_slice(sqlstate_bytes);
    } else {
        p.put_slice(b"42501");
    }
    p.put_slice(message.as_bytes());
    p.to_vec()
}

/// Length-encoded integer encoder (per
/// <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_dt_integers.html>).
fn put_lenenc_int(buf: &mut BytesMut, val: u64) {
    if val < 251 {
        buf.put_u8(val as u8);
    } else if val < (1 << 16) {
        buf.put_u8(0xfc);
        buf.put_u16_le(val as u16);
    } else if val < (1 << 24) {
        buf.put_u8(0xfd);
        buf.put_u8((val & 0xFF) as u8);
        buf.put_u8(((val >> 8) & 0xFF) as u8);
        buf.put_u8(((val >> 16) & 0xFF) as u8);
    } else {
        buf.put_u8(0xfe);
        buf.put_u64_le(val);
    }
}

/// Wrap a payload in a MySQL packet header (`<len:3 LE><seq:1>`)
/// and return the wire bytes. Caller is responsible for tracking
/// the sequence ID across packets.
pub fn frame_packet(payload: &[u8], seq: u8) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(4 + len);
    out.push((len & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(seq);
    out.extend_from_slice(payload);
    out
}

/// Parsed packet header (`<len:3 LE><seq:1>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// Length of the packet's payload in bytes.
    pub payload_len: usize,
    /// MySQL sequence ID (resets to 0 at the start of every command).
    pub sequence_id: u8,
}

impl PacketHeader {
    /// Decode a 4-byte header off the wire.
    pub fn parse(buf: [u8; 4]) -> Self {
        let len = (buf[0] as usize)
            | ((buf[1] as usize) << 8)
            | ((buf[2] as usize) << 16);
        Self { payload_len: len, sequence_id: buf[3] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the wire-side companion to `upstream.rs::client_caps_does_not_advertise_ssl_or_compress`
    /// — the proxy's `HandshakeV10` greeting MUST NOT advertise
    /// `CLIENT_SSL` (bit 11) or `CLIENT_COMPRESS` (bit 5) to the
    /// agent. Doing so would commit the proxy to negotiating TLS or
    /// zlib framing it does not implement.
    #[test]
    fn capabilities_does_not_advertise_ssl_or_compress() {
        assert_eq!(
            CAPABILITIES & (1 << 11), 0,
            "CLIENT_SSL must NEVER be set in greeting caps",
        );
        assert_eq!(
            CAPABILITIES & (1 << 5), 0,
            "CLIENT_COMPRESS must NEVER be set in greeting caps",
        );
    }

    #[test]
    fn handshake_v10_advertises_protocol_41_and_secure_connection() {
        let scramble = [0x42u8; 20];
        let p = build_handshake_v10("8.0.30-raxis", 1, &scramble);
        // protocol_version
        assert_eq!(p[0], 0x0a);
        // server_version NUL-terminated
        let nul = p.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&p[1..nul], b"8.0.30-raxis");
        // Capabilities split lower/upper — reconstruct the u32 we
        // sent and assert the protocol-41 / secure-connection bits.
        let after_filler = nul + 1 + 4 + 8 + 1; // +server_ver_NUL +thread_id +scramble_lo +filler
        let cap_lower = u16::from_le_bytes([p[after_filler], p[after_filler + 1]]);
        let after_cap_lower = after_filler + 2;
        let _charset = p[after_cap_lower];
        let after_status = after_cap_lower + 1 + 2;
        let cap_upper = u16::from_le_bytes([p[after_status], p[after_status + 1]]);
        let cap = ((cap_upper as u32) << 16) | (cap_lower as u32);
        assert!(cap & (1 <<  9) != 0, "CLIENT_PROTOCOL_41 must be set");
        assert!(cap & (1 << 15) != 0, "CLIENT_SECURE_CONNECTION must be set");
        assert!(cap & (1 << 19) != 0, "CLIENT_PLUGIN_AUTH must be set");
    }

    #[test]
    fn ok_packet_advertises_autocommit() {
        let p = build_ok_packet();
        assert_eq!(p[0], 0x00);
        // Skip header (1) + lenenc affected_rows (1) + lenenc last_insert_id (1).
        let status_lo = p[3];
        let status_hi = p[4];
        let status = u16::from_le_bytes([status_lo, status_hi]);
        assert_eq!(status, STATUS_AUTOCOMMIT);
    }

    #[test]
    fn err_packet_carries_sqlstate_marker_and_code() {
        let p = build_err_packet(1142, "42501", "command denied");
        assert_eq!(p[0], 0xff);
        let code = u16::from_le_bytes([p[1], p[2]]);
        assert_eq!(code, 1142);
        assert_eq!(p[3], b'#');
        assert_eq!(&p[4..9], b"42501");
        assert_eq!(&p[9..], b"command denied");
    }

    #[test]
    fn frame_packet_round_trips_header() {
        let payload = b"Hello";
        let wire = frame_packet(payload, 7);
        let header = PacketHeader::parse([wire[0], wire[1], wire[2], wire[3]]);
        assert_eq!(header.payload_len, 5);
        assert_eq!(header.sequence_id, 7);
        assert_eq!(&wire[4..], payload);
    }
}
