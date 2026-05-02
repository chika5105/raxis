// raxis-ipc::frame — async read/write for the 4-byte LE length-prefix framing.
//
// Normative reference: specs/v1/peripherals.md §3 opening normative note.
//
// Frame format:
//   [4 bytes: u32 little-endian body length] [N bytes: bincode-encoded body]
//   The 4-byte prefix encodes N (body byte count); it is NOT included in N.
//
// Codec: bincode::config::standard() — varint integers, LE byte order,
//   no field names. Implementations MUST NOT use config::legacy().
//
// Maximum frame body size: 64 MiB (64 * 1024 * 1024 bytes). Any frame
// announcing a body larger than this is rejected with FrameError::TooLarge.
// The 16 MiB gateway response limit is enforced separately in the gateway
// handler; the frame layer allows up to 64 MiB to leave headroom for future
// message types while still bounding memory allocation on malformed input.

use bincode::config::standard;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum allowed body byte count. Frames announcing more are rejected.
pub const MAX_FRAME_BODY_BYTES: u32 = 64 * 1024 * 1024; // 64 MiB

// ---------------------------------------------------------------------------
// FrameError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error reading/writing frame: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame body of {0} bytes exceeds maximum {MAX_FRAME_BODY_BYTES}")]
    TooLarge(u32),

    #[error("bincode encode error: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("bincode decode error: {0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("connection closed cleanly (EOF on length prefix)")]
    Eof,
}

// ---------------------------------------------------------------------------
// write_frame<T>
//
// Serialises `msg` with bincode::config::standard(), prepends the 4-byte LE
// body length, and writes both to `writer`. Flushes after writing.
// ---------------------------------------------------------------------------

/// Encode `msg` to bincode and write it as a length-prefixed frame.
///
/// # Wire layout
/// ```text
/// ┌──────────────────────────────┬──────────────────────┐
/// │  body_len: u32 little-endian │  body: [u8; body_len]│
/// └──────────────────────────────┴──────────────────────┘
/// ```
pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    // Encode the message body first so we know the length.
    let body = bincode::serde::encode_to_vec(msg, standard())?;

    let body_len = body.len() as u32;
    if body_len > MAX_FRAME_BODY_BYTES {
        return Err(FrameError::TooLarge(body_len));
    }

    // Write 4-byte LE length prefix then body in one vectored write sequence.
    writer.write_all(&body_len.to_le_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// read_frame<T>
//
// Reads a 4-byte LE length prefix, allocates a buffer of that many bytes,
// fills it, then decodes the bincode payload into T.
// ---------------------------------------------------------------------------

/// Read a length-prefixed frame from `reader` and decode it as `T`.
///
/// Returns `FrameError::Eof` on a clean EOF while reading the length prefix
/// (i.e. the remote peer closed the connection between messages). Any other
/// EOF mid-frame is an `io::Error` (UnexpectedEof).
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    // Read 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            // Clean EOF between frames — peer closed the connection.
            return Err(FrameError::Eof);
        }
        Err(e) => return Err(FrameError::Io(e)),
    }

    let body_len = u32::from_le_bytes(len_buf);
    if body_len > MAX_FRAME_BODY_BYTES {
        return Err(FrameError::TooLarge(body_len));
    }

    // Read body.
    let mut body = vec![0u8; body_len as usize];
    reader.read_exact(&mut body).await?;

    // Decode.
    let (msg, _consumed) = bincode::serde::decode_from_slice(&body, standard())?;
    Ok(msg)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tokio::io::duplex;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Ping {
        id: u64,
        payload: String,
    }

    #[tokio::test]
    async fn round_trip_single_frame() {
        let msg = Ping {
            id: 42,
            payload: "hello raxis".to_owned(),
        };

        let (mut client, mut server) = duplex(4096);

        write_frame(&mut client, &msg).await.unwrap();
        let received: Ping = read_frame(&mut server).await.unwrap();

        assert_eq!(msg, received);
    }

    #[tokio::test]
    async fn round_trip_multiple_frames() {
        let msgs: Vec<Ping> = (0..5)
            .map(|i| Ping {
                id: i,
                payload: format!("msg-{}", i),
            })
            .collect();

        let (mut client, mut server) = duplex(65536);

        for m in &msgs {
            write_frame(&mut client, m).await.unwrap();
        }
        drop(client); // signal EOF after all frames written

        for expected in &msgs {
            let got: Ping = read_frame(&mut server).await.unwrap();
            assert_eq!(expected, &got);
        }

        // Next read should return Eof cleanly.
        let result: Result<Ping, _> = read_frame(&mut server).await;
        assert!(matches!(result, Err(FrameError::Eof)));
    }

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let (mut client, mut server) = duplex(16);

        // Manually write a frame claiming MAX+1 bytes.
        let fake_len: u32 = MAX_FRAME_BODY_BYTES + 1;
        client.write_all(&fake_len.to_le_bytes()).await.unwrap();

        let result: Result<Ping, _> = read_frame(&mut server).await;
        assert!(matches!(result, Err(FrameError::TooLarge(_))));
    }
}
