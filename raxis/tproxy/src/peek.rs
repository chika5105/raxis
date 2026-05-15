//! `peek` — read agent-side bytes until either a TLS ClientHello
//! is fully buffered (HTTPS — port 443) or an HTTP/1.1 request
//! preamble is complete (HTTP — port 80). Returns the buffered
//! bytes alongside the parser verdict so the byte-shuttle that
//! runs after admission can replay them upstream verbatim.
//!
//! The peek is **deliberately bounded**: 16 KiB cap on the buffer
//! before we fail the connection with `BufferOverflow`. A
//! TLS ClientHello above 16 KiB is exotic enough to be hostile;
//! an HTTP/1.1 preamble above 16 KiB is a malformed request.

use raxis_tproxy_protocol::{
    extract_host_header_from_http_request_line_block, extract_sni_from_client_hello,
    HostParseError, SniParseError,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Cap on the bytes peeked before we give up.
pub const PEEK_CAP_BYTES: usize = 16 * 1024;

/// Outcome of [`peek_https_client_hello_or_http_request`].
#[derive(Debug)]
pub struct PeekedFlow {
    /// Bytes already drained from the agent socket. The shuttle
    /// MUST replay these bytes to the upstream BEFORE pumping
    /// further reads from the agent (otherwise the upstream
    /// receives a truncated TLS ClientHello / HTTP request).
    pub buffered: Vec<u8>,
    /// Hostname extracted from the buffer. `None` if the peek
    /// found a well-formed flow but no SNI (rare for HTTPS) or
    /// no `Host:` header (an HTTP/1.0 client without one — the
    /// kernel will deny on `host_or_sni = None`).
    pub host_or_sni: Option<String>,
    /// What the parser thinks this is.
    pub kind: PeekKind,
}

/// What the peek found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeekKind {
    /// TLS ClientHello successfully parsed.
    TlsClientHello,
    /// HTTP/1.1 (or 1.0) request preamble successfully parsed.
    Http,
}

/// Errors from the peek loop.
#[derive(Debug, Error)]
pub enum PeekError {
    /// I/O failure on the agent-side socket — typically a peer
    /// reset before the parser had enough bytes.
    #[error("transport i/o: {0}")]
    Io(#[from] std::io::Error),
    /// Buffered more than [`PEEK_CAP_BYTES`] without finding a
    /// parseable flow start.
    #[error("peek buffer cap of {cap} bytes exceeded")]
    BufferOverflow {
        /// The cap that was exceeded.
        cap: usize,
    },
    /// The peek read an EOF before any parser admitted the bytes.
    /// Typical case: the agent closed the connection early.
    #[error("agent socket closed before flow was identifiable")]
    UnexpectedEof,
    /// The bytes are neither a parseable TLS ClientHello nor a
    /// parseable HTTP/1.1 request preamble.
    #[error("flow is neither TLS ClientHello nor HTTP/1.1 request")]
    UnknownFlow {
        /// The TLS parser's verdict (if any).
        sni: Option<SniParseError>,
        /// The HTTP parser's verdict (if any).
        http: Option<HostParseError>,
    },
}

/// Read from the agent socket until we either:
/// * have buffered a complete TLS ClientHello (record-len bytes
///   plus the 5-byte record header), OR
/// * have read past `\r\n\r\n` indicating the end of an HTTP/1.1
///   request preamble.
///
/// Used for both port 443 (HTTPS) and port 80 (HTTP) — we let the
/// content discriminate. The first byte of a TLS handshake record
/// is `0x16`, which is not a valid HTTP method's first byte
/// (every HTTP method byte is in the ASCII alphabetic range).
/// This makes the discrimination unambiguous: if `buffered[0] ==
/// 0x16`, we're looking at TLS; otherwise we treat it as HTTP.
pub async fn peek_https_client_hello_or_http_request<R>(
    mut reader: R,
) -> Result<PeekedFlow, PeekError>
where
    R: AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];

    loop {
        if buf.len() >= PEEK_CAP_BYTES {
            return Err(PeekError::BufferOverflow {
                cap: PEEK_CAP_BYTES,
            });
        }
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            if buf.is_empty() {
                return Err(PeekError::UnexpectedEof);
            }
            // Re-attempt parses with whatever we have; if both
            // fail we surface UnknownFlow so the caller can deny.
            return finalise_or_unknown(buf);
        }
        buf.extend_from_slice(&chunk[..n]);

        if !buf.is_empty() && buf[0] == 0x16 {
            // TLS path — we need 5 + record_len bytes before the
            // SNI parser can run cleanly.
            if buf.len() >= 5 {
                let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                let need = 5 + record_len;
                if buf.len() >= need {
                    match extract_sni_from_client_hello(&buf[..need]) {
                        Ok(sni) => {
                            return Ok(PeekedFlow {
                                buffered: buf,
                                host_or_sni: sni,
                                kind: PeekKind::TlsClientHello,
                            });
                        }
                        Err(e) => {
                            return Err(PeekError::UnknownFlow {
                                sni: Some(e),
                                http: None,
                            });
                        }
                    }
                }
            }
            continue;
        }

        // HTTP path — wait for `\r\n\r\n`.
        if windows_has_crlf_crlf(&buf) {
            match extract_host_header_from_http_request_line_block(&buf) {
                Ok(host) => {
                    return Ok(PeekedFlow {
                        buffered: buf,
                        host_or_sni: Some(host),
                        kind: PeekKind::Http,
                    });
                }
                Err(e) => {
                    return Err(PeekError::UnknownFlow {
                        sni: None,
                        http: Some(e),
                    });
                }
            }
        }
    }
}

fn windows_has_crlf_crlf(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n")
}

fn finalise_or_unknown(buf: Vec<u8>) -> Result<PeekedFlow, PeekError> {
    // Try TLS first if the leading byte hints at it.
    if !buf.is_empty() && buf[0] == 0x16 && buf.len() >= 5 {
        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() >= 5 + record_len {
            if let Ok(sni) = extract_sni_from_client_hello(&buf[..5 + record_len]) {
                return Ok(PeekedFlow {
                    buffered: buf,
                    host_or_sni: sni,
                    kind: PeekKind::TlsClientHello,
                });
            }
        }
    }
    // Then HTTP.
    if windows_has_crlf_crlf(&buf) {
        if let Ok(host) = extract_host_header_from_http_request_line_block(&buf) {
            return Ok(PeekedFlow {
                buffered: buf,
                host_or_sni: Some(host),
                kind: PeekKind::Http,
            });
        }
    }
    Err(PeekError::UnknownFlow {
        sni: None,
        http: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn peek_extracts_host_from_http_request() {
        let (kernel, mut client) = tokio::io::duplex(8192);
        let send =
            b"GET /healthz HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: x\r\n\r\n".to_vec();
        client.write_all(&send).await.unwrap();
        client.shutdown().await.unwrap();
        let flow = peek_https_client_hello_or_http_request(kernel)
            .await
            .unwrap();
        assert_eq!(flow.kind, PeekKind::Http);
        assert_eq!(flow.host_or_sni.as_deref(), Some("api.example.com"));
        assert_eq!(flow.buffered, send);
    }

    /// Build a minimal TLS 1.2 ClientHello carrying SNI for `host`.
    fn build_client_hello(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let server_name_entry_len = 1 + 2 + host_bytes.len();
        let server_name_list_len = server_name_entry_len;
        let server_name_ext_body_len = 2 + server_name_list_len;
        let server_name_ext_total = 4 + server_name_ext_body_len;
        let extensions_len = server_name_ext_total;
        let body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
        let record_len = 4 + body_len;

        let mut buf = Vec::new();
        buf.push(0x16);
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&(record_len as u16).to_be_bytes());
        buf.push(0x01);
        let body_len_u24 = body_len as u32;
        buf.push(((body_len_u24 >> 16) & 0xFF) as u8);
        buf.push(((body_len_u24 >> 8) & 0xFF) as u8);
        buf.push((body_len_u24 & 0xFF) as u8);
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0);
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        buf.extend_from_slice(&[0x01, 0x00]);
        buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&(server_name_ext_body_len as u16).to_be_bytes());
        buf.extend_from_slice(&(server_name_list_len as u16).to_be_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(host_bytes);
        buf
    }

    #[tokio::test]
    async fn peek_extracts_sni_from_real_tls_client_hello_bytes() {
        let (kernel, mut client) = tokio::io::duplex(8192);
        let hello = build_client_hello("api.anthropic.com");
        client.write_all(&hello).await.unwrap();
        client.shutdown().await.unwrap();
        let flow = peek_https_client_hello_or_http_request(kernel)
            .await
            .unwrap();
        assert_eq!(flow.kind, PeekKind::TlsClientHello);
        assert_eq!(flow.host_or_sni.as_deref(), Some("api.anthropic.com"));
        assert_eq!(flow.buffered, hello);
    }

    #[tokio::test]
    async fn peek_returns_unknown_flow_on_neither_tls_nor_http() {
        let (kernel, mut client) = tokio::io::duplex(64);
        client
            .write_all(b"random gibberish without crlf")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let err = peek_https_client_hello_or_http_request(kernel)
            .await
            .unwrap_err();
        assert!(matches!(err, PeekError::UnknownFlow { .. }));
    }

    #[tokio::test]
    async fn peek_returns_unexpected_eof_on_immediate_close() {
        let (kernel, client) = tokio::io::duplex(64);
        drop(client);
        let err = peek_https_client_hello_or_http_request(kernel)
            .await
            .unwrap_err();
        assert!(matches!(err, PeekError::UnexpectedEof));
    }
}
