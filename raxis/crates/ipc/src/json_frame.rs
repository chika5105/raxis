// raxis-ipc::json_frame — Length-prefixed JSON framing for the operator socket.
//
// Normative reference: specs/v1/peripherals.md §3 "Operator socket".
//
// Why a separate module from `frame`:
//   - `frame` is async (Tokio) + bincode. The planner socket uses it.
//   - The operator socket uses **JSON** (human-debuggable; the CLI inspects raw
//     frames during ceremonies) and the CLI runs synchronously on `std::io`,
//     not Tokio. We don't want to drag Tokio into the CLI binary just for
//     framing.
//
// Wire format — IDENTICAL to `frame`:
//
//     [u32 LE body_byte_count] [body_byte_count bytes of UTF-8 JSON]
//
// Both byte order and max body size match `frame::MAX_FRAME_BODY_BYTES` so
// that an operator can pipe an operator frame into the planner-frame parser
// for diagnostic purposes (and vice versa). The codec differs (JSON vs
// bincode) but the framing layer is the same.
//
// Failure model: every read/write returns `JsonFrameError` so callers can
// distinguish I/O errors, oversized announces, EOF-between-frames, and
// JSON parse failures.

use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::frame::MAX_FRAME_BODY_BYTES;

// ---------------------------------------------------------------------------
// JsonFrameError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum JsonFrameError {
    #[error("I/O error reading/writing frame: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame body of {0} bytes exceeds maximum {MAX_FRAME_BODY_BYTES}")]
    TooLarge(u32),

    #[error("JSON encode error: {0}")]
    Encode(serde_json::Error),

    #[error("JSON decode error: {0}")]
    Decode(serde_json::Error),

    #[error("connection closed cleanly (EOF on length prefix)")]
    Eof,
}

// ---------------------------------------------------------------------------
// write_json_frame<T>
// ---------------------------------------------------------------------------

/// Serialise `msg` as JSON, write a 4-byte LE length prefix followed by the
/// JSON body. Flushes the writer.
///
/// The writer is `&mut W: Write`, so this works for `std::os::unix::net::UnixStream`,
/// `&mut Vec<u8>`, files, and any other blocking `Write` implementor.
pub fn write_json_frame<W, T>(writer: &mut W, msg: &T) -> Result<(), JsonFrameError>
where
    W: Write,
    T: Serialize,
{
    let body = serde_json::to_vec(msg).map_err(JsonFrameError::Encode)?;

    let body_len = body.len();
    if body_len > MAX_FRAME_BODY_BYTES as usize {
        return Err(JsonFrameError::TooLarge(body_len as u32));
    }
    let body_len = body_len as u32;

    writer.write_all(&body_len.to_le_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// read_json_frame<T>
// ---------------------------------------------------------------------------

/// Read a 4-byte LE length prefix from `reader`, then read that many bytes
/// and deserialise them as JSON into `T`.
///
/// Returns `JsonFrameError::Eof` on a clean EOF while reading the length
/// prefix (peer closed cleanly between messages). Mid-frame EOF surfaces as
/// `JsonFrameError::Io(UnexpectedEof)`.
pub fn read_json_frame<R, T>(reader: &mut R) -> Result<T, JsonFrameError>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(JsonFrameError::Eof);
        }
        Err(e) => return Err(JsonFrameError::Io(e)),
    }

    let body_len = u32::from_le_bytes(len_buf);
    if body_len > MAX_FRAME_BODY_BYTES {
        return Err(JsonFrameError::TooLarge(body_len));
    }

    let mut body = vec![0u8; body_len as usize];
    reader.read_exact(&mut body)?;

    serde_json::from_slice(&body).map_err(JsonFrameError::Decode)
}

/// As `read_json_frame`, but returns the raw UTF-8 string body without
/// JSON parsing. Useful for callers that want to inspect or re-route the
/// body, or that parse with a different deserialiser (`serde_json::Value`).
pub fn read_json_frame_raw<R>(reader: &mut R) -> Result<String, JsonFrameError>
where
    R: Read,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(JsonFrameError::Eof);
        }
        Err(e) => return Err(JsonFrameError::Io(e)),
    }

    let body_len = u32::from_le_bytes(len_buf);
    if body_len > MAX_FRAME_BODY_BYTES {
        return Err(JsonFrameError::TooLarge(body_len));
    }

    let mut body = vec![0u8; body_len as usize];
    reader.read_exact(&mut body)?;

    String::from_utf8(body).map_err(|e| {
        JsonFrameError::Decode(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("non-UTF-8 frame body: {e}"),
        )))
    })
}

// ---------------------------------------------------------------------------
// Async (tokio) variants
//
// The kernel's operator socket runs inside the Tokio runtime; the CLI runs
// synchronously on `std::io`. Both sides MUST use the same wire format —
// these `_async` helpers exist solely to bridge the runtime difference. The
// sync and async pairs are byte-for-byte equivalent; the codec, byte order,
// and `MAX_FRAME_BODY_BYTES` cap are shared.
// ---------------------------------------------------------------------------

/// Async equivalent of [`write_json_frame`].
pub async fn write_json_frame_async<W, T>(writer: &mut W, msg: &T) -> Result<(), JsonFrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg).map_err(JsonFrameError::Encode)?;

    let body_len = body.len();
    if body_len > MAX_FRAME_BODY_BYTES as usize {
        return Err(JsonFrameError::TooLarge(body_len as u32));
    }
    let body_len = body_len as u32;

    writer.write_all(&body_len.to_le_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

/// Async equivalent of [`read_json_frame`].
pub async fn read_json_frame_async<R, T>(reader: &mut R) -> Result<T, JsonFrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(JsonFrameError::Eof);
        }
        Err(e) => return Err(JsonFrameError::Io(e)),
    }

    let body_len = u32::from_le_bytes(len_buf);
    if body_len > MAX_FRAME_BODY_BYTES {
        return Err(JsonFrameError::TooLarge(body_len));
    }

    let mut body = vec![0u8; body_len as usize];
    reader.read_exact(&mut body).await?;

    serde_json::from_slice(&body).map_err(JsonFrameError::Decode)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Ping {
        id: u64,
        payload: String,
    }

    /// Round-trip a typed message through the JSON frame codec.
    #[test]
    fn round_trip_single_frame() {
        let msg = Ping {
            id: 7,
            payload: "hello".to_owned(),
        };

        let mut buf = Vec::new();
        write_json_frame(&mut buf, &msg).unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let got: Ping = read_json_frame(&mut cursor).unwrap();
        assert_eq!(msg, got);
    }

    /// Multiple frames in a single buffer all round-trip in order.
    #[test]
    fn round_trip_multiple_frames() {
        let msgs: Vec<Ping> = (0..3)
            .map(|i| Ping {
                id: i,
                payload: format!("m-{i}"),
            })
            .collect();

        let mut buf = Vec::new();
        for m in &msgs {
            write_json_frame(&mut buf, m).unwrap();
        }

        let mut cursor = std::io::Cursor::new(buf);
        for m in &msgs {
            let got: Ping = read_json_frame(&mut cursor).unwrap();
            assert_eq!(m, &got);
        }

        // Next read must surface as Eof, not Io(UnexpectedEof) — the cursor is
        // exactly at the end after the last frame.
        let result: Result<Ping, _> = read_json_frame(&mut cursor);
        assert!(matches!(result, Err(JsonFrameError::Eof)));
    }

    /// Length prefix announcing more than MAX_FRAME_BODY_BYTES is rejected
    /// without allocating the buffer. Regression guard against the
    /// `vec![0u8; len]` line in earlier drafts (which would OOM on a bogus
    /// length from a malicious peer).
    #[test]
    fn rejects_oversized_announce() {
        let fake_len: u32 = MAX_FRAME_BODY_BYTES + 1;
        let buf = fake_len.to_le_bytes().to_vec();

        let mut cursor = std::io::Cursor::new(buf);
        let result: Result<Ping, _> = read_json_frame(&mut cursor);
        match result {
            Err(JsonFrameError::TooLarge(n)) => assert_eq!(n, MAX_FRAME_BODY_BYTES + 1),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// Wire format pin: little-endian byte order on the length prefix.
    /// This is the regression guard for the v1 review's "CLI-kernel
    /// endianness mismatch" finding (PR-2). If anyone ever re-introduces a
    /// big-endian variant on either side, this test stays green on the
    /// canonical helper but the corresponding side will fail at runtime.
    #[test]
    fn length_prefix_is_little_endian() {
        let msg = Ping {
            id: 1,
            payload: "x".to_owned(),
        };
        let mut buf = Vec::new();
        write_json_frame(&mut buf, &msg).unwrap();

        // First 4 bytes ARE the LE-encoded body length. JSON of {id:1,payload:"x"}
        // is `{"id":1,"payload":"x"}` = 22 bytes, so the prefix must be
        // exactly [22, 0, 0, 0].
        let body_str = serde_json::to_string(&msg).unwrap();
        let body_len = body_str.len() as u32;
        let expected_prefix = body_len.to_le_bytes();
        assert_eq!(
            &buf[..4],
            &expected_prefix,
            "first 4 bytes must equal LE-encoded body length"
        );
    }

    /// `read_json_frame_raw` returns the body verbatim without parsing.
    /// Useful for the operator handshake where the CLI parses with
    /// `serde_json::Value`.
    #[test]
    fn read_raw_returns_unparsed_body() {
        let msg = Ping {
            id: 99,
            payload: "raw".to_owned(),
        };
        let mut buf = Vec::new();
        write_json_frame(&mut buf, &msg).unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let body = read_json_frame_raw(&mut cursor).unwrap();
        assert!(body.contains("\"id\":99"));
        assert!(body.contains("\"raw\""));
    }

    /// Cross-runtime byte equivalence: a frame written with the sync helper
    /// must decode through the async helper, byte-for-byte. This is the
    /// regression guard for PR-2 — the kernel's operator socket runs on the
    /// async helper, the CLI runs on the sync helper, and they MUST agree.
    #[tokio::test]
    async fn sync_writer_and_async_reader_agree() {
        let msg = Ping {
            id: 0xDEADBEEF,
            payload: "sync→async".to_owned(),
        };

        let mut buf = Vec::new();
        write_json_frame(&mut buf, &msg).unwrap();

        let mut reader = std::io::Cursor::new(buf);
        let got: Ping = read_json_frame_async(&mut reader).await.unwrap();
        assert_eq!(msg, got);
    }

    /// And the reverse direction.
    #[tokio::test]
    async fn async_writer_and_sync_reader_agree() {
        let msg = Ping {
            id: 0xCAFEBABE,
            payload: "async→sync".to_owned(),
        };

        let mut buf: Vec<u8> = Vec::new();
        write_json_frame_async(&mut buf, &msg).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let got: Ping = read_json_frame(&mut cursor).unwrap();
        assert_eq!(msg, got);
    }
}
