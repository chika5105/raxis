// raxis-ipc — IPC framing and top-level message dispatch for RAXIS.
//
// Normative reference: specs/v1/peripherals.md §3 opening normative note.
//
// Wire format (normative, byte-exact):
//   Every message on every UDS socket is a length-prefixed bincode frame:
//     [u32 LE body_byte_count] [body_byte_count bytes of bincode]
//
//   Codec: bincode = "=2.0.1" with bincode::config::standard()
//     - variable-length integer encoding (LEB128/varint)
//     - little-endian byte order
//     - no struct/field name metadata (positional encoding)
//   Entry points: bincode::serde::encode_to_vec / decode_from_slice
//
// This crate provides:
//   - `frame` module: async read/write helpers for the 4-byte + body framing
//   - `message` module: the top-level IpcMessage enum covering all three sockets
//   - `auth` module: lightweight auth validation types shared by all sockets
//
// Crate rules (philosophy.md §1.5):
//   - No SQLite, no file I/O beyond the UDS send/recv, no key material.
//   - Depends on raxis-types for all domain types.

pub mod auth;
pub mod frame;
pub mod json_frame;
pub mod message;

pub use frame::{read_frame, write_frame, FrameError};
pub use json_frame::{
    read_json_frame, read_json_frame_async, read_json_frame_raw, write_json_frame,
    write_json_frame_async, JsonFrameError,
};
pub use message::{GatewayMessage, IpcMessage};
