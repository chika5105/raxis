//! `raxis-tproxy-protocol` — wire-protocol crate for the V2 Tier 1
//! transparent egress proxy.
//!
//! Normative reference: `specs/v2/vm-network-isolation.md §3`.
//!
//! # What ships here
//!
//! Three things, kept in one tiny crate so the in-VM
//! `raxis-tproxy` binary, the kernel-side admission service, and
//! the integration tests that exercise both can share a single
//! source of truth:
//!
//! 1. The bincode-encoded admission request/response sent over
//!    vsock between the VM and the kernel
//!    ([`ProxyAdmissionRequest`] / [`ProxyAdmissionResponse`]).
//!
//! 2. A pure-bytes parser for the TLS ClientHello SNI extension
//!    ([`extract_sni_from_client_hello`]). The Tier 1 proxy reads
//!    the SNI from the client's TLS handshake before forwarding
//!    bytes upstream, so the kernel can enforce by hostname
//!    without terminating TLS (see §3.3 of the spec).
//!
//! 3. A pure-bytes parser for the HTTP/1.1 `Host` header
//!    ([`extract_host_header_from_http_request_line_block`]) used
//!    on port 80 — TLS-free traffic where the host is in the
//!    request preamble.
//!
//! The crate has no `tokio`, no `mio`, no FD types — concrete
//! socket I/O lives in `raxis-tproxy` (the VM-side binary) and in
//! the kernel-side handler crate. This split keeps the protocol
//! testable in microseconds with no async runtime spin-up.
//!
//! # Wire encoding
//!
//! All vsock messages are length-prefixed bincode 2 values. The
//! prefix is a 4-byte big-endian unsigned length, followed by
//! exactly that many bincode bytes. The 16 MiB cap matches the
//! kernel/gateway IPC discipline elsewhere in the workspace —
//! every other vsock framing in RAXIS uses the same shape so
//! there is one mental model.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum size of a single bincode-framed admission message.
/// Mirrors the cap on the gateway IPC framing — large enough for
/// any realistic admission payload, small enough to bound a
/// malicious peer's read buffer. 16 MiB.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Admission protocol
// ---------------------------------------------------------------------------

/// Layer-7 protocol guess that the in-VM proxy hands to the kernel
/// for admission. The kernel uses this to discriminate between
/// HTTPS / HTTP / raw TCP egress when applying the egress
/// allowlist; see `vm-network-isolation.md §3.2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionProtocol {
    /// HTTPS / TLS — the proxy parsed an SNI from the client's
    /// ClientHello before any bytes were forwarded upstream.
    Https,
    /// Plain HTTP — the proxy read the `Host` header from the
    /// preamble. Method and path are in the request line; the
    /// proxy hands ONLY the host to the kernel because Tier 1
    /// enforcement is by hostname only (TLS-encrypted Tier 2
    /// requests use the credential proxy, not this path).
    Http,
    /// Raw TCP, target is one of the database / service ports
    /// covered by the iptables rules in `§3.1` (5432, 3306, 1433,
    /// 27017, 6379). Used to detect bypass attempts where the
    /// agent tries to reach a real database host directly instead
    /// of the credential proxy on `127.0.0.1`.
    Tcp,
}

impl AdmissionProtocol {
    /// Stable short string used in `TransparentProxyAdmitted`
    /// / `TransparentProxyDenied` audit payloads. Pinned by tests
    /// so the wire shape downstream forensic tools depend on
    /// cannot drift silently.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http  => "http",
            Self::Tcp   => "tcp",
        }
    }
}

/// One admission request, sent by `raxis-tproxy` to the kernel
/// over the per-VM vsock control channel after iptables redirected
/// the agent's outbound TCP connection. The kernel replies with
/// exactly one [`ProxyAdmissionResponse`] before any bytes are
/// shuttled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAdmissionRequest {
    /// Monotonically increasing per-connection counter — used by
    /// the kernel to correlate the admission decision with the
    /// audit event and (eventually) the per-connection byte
    /// counters. Starts at 1 on each fresh `raxis-tproxy` boot
    /// and rolls over at u64::MAX (the rollover is a non-issue
    /// in practice — at 1 connection/μs that's 580k years).
    pub connection_id: u64,

    /// Original destination as observed by the proxy via
    /// `SO_ORIGINAL_DST` (after iptables REDIRECT). On HTTPS this
    /// is the address the agent actually dialed; on HTTP it
    /// agrees with `host_or_sni` modulo case.
    pub original_dst_ip:   String,
    /// Original destination port (e.g. 443 for HTTPS, 80 for
    /// HTTP, 5432 for Postgres bypass detection).
    pub original_dst_port: u16,

    /// Hostname extracted from the client traffic before any
    /// bytes left the VM. For HTTPS this is the SNI from the TLS
    /// ClientHello; for HTTP it is the `Host` header value with
    /// the port stripped; for raw TCP this is `None` (no
    /// hostname is observable, so the kernel decides on
    /// `(original_dst_ip, original_dst_port)` alone).
    pub host_or_sni: Option<String>,

    /// Layer-7 protocol guess (see [`AdmissionProtocol`]).
    pub protocol: AdmissionProtocol,
}

/// The kernel's verdict for one admission request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyAdmissionResponse {
    /// The connection is admitted. The kernel will hand the
    /// proxy a transparent byte-tunnel to the real upstream
    /// (the byte-shuttling itself happens after this admission
    /// frame; this protocol only carries the verdict).
    Admit {
        /// Echo of the request's `connection_id` so the proxy
        /// can match the response to the request even if it is
        /// pipelining multiple admissions.
        connection_id: u64,
    },
    /// The connection is denied. The proxy MUST close the
    /// agent-side socket with `RST` (Linux: shutdown both
    /// halves and drop) so the agent's library returns
    /// `ECONNREFUSED` rather than hanging.
    Deny {
        /// Echo of the request's `connection_id`.
        connection_id: u64,
        /// Stable short reason string the kernel logs and the
        /// proxy includes in its denial trace. Pinned set:
        /// `"host_not_in_allowlist"`,
        /// `"proxy_target_bypass"`,
        /// `"protocol_not_permitted"`,
        /// `"port_not_redirected"`,
        /// `"unknown"`. Other backends (custom enforcement)
        /// MAY emit any string here, but the operator CLI's
        /// `raxis egress denied` view groups by these names.
        reason: DenyReason,
    },
}

/// Stable reasons a `ProxyAdmissionResponse::Deny` may carry.
/// Modeled as an enum (rather than a free-form string) so the
/// kernel's `TransparentProxyDenied` audit payload can pin a
/// finite, exhaustively-matchable taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The host (or `(ip, port)` pair for raw TCP) is not in
    /// the policy's `egress_hosts` AND/OR the active task's
    /// `allowed_egress`.
    HostNotInAllowlist,
    /// The host matches a credential-proxy `real_target` —
    /// `vm-network-isolation.md §5` proxy-bypass detection.
    /// Triggers a `SecurityViolationDetected` event in the
    /// kernel's audit chain (separate from `TransparentProxyDenied`).
    ProxyTargetBypass,
    /// The protocol guess is not one of HTTPS / HTTP / known
    /// TCP database ports. Defence-in-depth — the iptables
    /// redirect rules SHOULD prevent these from reaching
    /// `raxis-tproxy` at all, but if one does we drop it with
    /// this reason.
    ProtocolNotPermitted,
    /// The port observed via `SO_ORIGINAL_DST` is not one of
    /// the iptables-redirected set. This typically indicates
    /// a kernel-side iptables-rule misconfiguration.
    PortNotRedirected,
    /// Catch-all for any reason the kernel is not yet able to
    /// classify (forward-compat reservation).
    Unknown,
}

impl DenyReason {
    /// Stable short string for audit payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HostNotInAllowlist  => "host_not_in_allowlist",
            Self::ProxyTargetBypass   => "proxy_target_bypass",
            Self::ProtocolNotPermitted => "protocol_not_permitted",
            Self::PortNotRedirected   => "port_not_redirected",
            Self::Unknown             => "unknown",
        }
    }
}

/// Errors from encoding / decoding admission frames.
#[derive(Debug, Error)]
pub enum FrameError {
    /// The frame's length prefix exceeded `MAX_FRAME_BYTES`.
    #[error("frame too large: {len} bytes (max {max})")]
    TooLarge {
        /// Reported length from the frame's prefix.
        len: u64,
        /// Cap from `MAX_FRAME_BYTES`.
        max: usize,
    },
    /// `bincode` rejected the body — typically a corrupted vsock
    /// frame or a forward-incompat protocol change.
    #[error("bincode decode failed: {0}")]
    Decode(String),
    /// `bincode` rejected the encode — should never happen for
    /// the types in this crate; surfaced anyway for completeness.
    #[error("bincode encode failed: {0}")]
    Encode(String),
}

/// Encode one admission request as length-prefixed bincode.
pub fn encode_request(req: &ProxyAdmissionRequest) -> Result<Vec<u8>, FrameError> {
    encode_frame(req)
}

/// Encode one admission response as length-prefixed bincode.
pub fn encode_response(resp: &ProxyAdmissionResponse) -> Result<Vec<u8>, FrameError> {
    encode_frame(resp)
}

/// Decode one admission request from a length-prefixed bincode
/// buffer. Returns the request plus the number of bytes consumed.
pub fn decode_request(bytes: &[u8]) -> Result<(ProxyAdmissionRequest, usize), FrameError> {
    decode_frame(bytes)
}

/// Decode one admission response from a length-prefixed bincode
/// buffer. Returns the response plus the number of bytes
/// consumed.
pub fn decode_response(bytes: &[u8]) -> Result<(ProxyAdmissionResponse, usize), FrameError> {
    decode_frame(bytes)
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let body = bincode::serde::encode_to_vec(value, bincode::config::standard())
        .map_err(|e| FrameError::Encode(e.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { len: body.len() as u64, max: MAX_FRAME_BYTES });
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_frame<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<(T, usize), FrameError> {
    if bytes.len() < 4 {
        return Err(FrameError::Decode("frame shorter than 4-byte length prefix".into()));
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { len: len as u64, max: MAX_FRAME_BYTES });
    }
    if bytes.len() < 4 + len {
        return Err(FrameError::Decode(format!(
            "frame body truncated: have {} bytes, want {}",
            bytes.len() - 4,
            len,
        )));
    }
    let (value, consumed) = bincode::serde::decode_from_slice::<T, _>(
        &bytes[4..4 + len],
        bincode::config::standard(),
    )
    .map_err(|e| FrameError::Decode(e.to_string()))?;
    if consumed != len {
        return Err(FrameError::Decode(format!(
            "bincode consumed {consumed} of {len} body bytes",
        )));
    }
    Ok((value, 4 + len))
}

// ---------------------------------------------------------------------------
// SNI extraction
// ---------------------------------------------------------------------------

/// Extract the SNI hostname from a TLS ClientHello byte buffer.
/// Returns `Ok(Some(host))` when the ClientHello carries an SNI
/// extension with at least one entry whose `name_type` is 0
/// (`host_name`), `Ok(None)` when the handshake is well-formed
/// but the client did not negotiate SNI, and `Err` when the
/// bytes are not a parseable TLS handshake record.
///
/// This parser is **deliberately conservative** — it covers
/// exactly the shapes a typical agent toolchain (rustls,
/// OpenSSL, BoringSSL, Go crypto/tls, Python ssl, Node) emits.
/// Anything weirder than a textbook TLS 1.2 / 1.3 ClientHello
/// returns `Err(SniParseError::Malformed)` and the proxy denies
/// the connection. False denial of an exotic client is the
/// correct failure mode here — the operator can either widen
/// the parser or declare the endpoint as a credential proxy.
pub fn extract_sni_from_client_hello(buf: &[u8]) -> Result<Option<String>, SniParseError> {
    let mut cur = TlsCursor::new(buf);

    // ── Outer TLS record header (5 bytes) ──
    let content_type = cur.u8()?;
    if content_type != 0x16 {
        // 0x16 = handshake
        return Err(SniParseError::Malformed("not a handshake record"));
    }
    let _legacy_record_version = cur.u16()?;
    let record_length = cur.u16()? as usize;
    if cur.remaining() < record_length {
        return Err(SniParseError::Malformed("record body truncated"));
    }
    let record_end = cur.cursor + record_length;

    // ── Handshake header (4 bytes: type + 3-byte length) ──
    let handshake_type = cur.u8()?;
    if handshake_type != 0x01 {
        // 0x01 = ClientHello
        return Err(SniParseError::Malformed("handshake is not a ClientHello"));
    }
    let _handshake_length = cur.u24()?;

    // ── ClientHello body ──
    //   client_version (2)         legacy in TLS 1.3
    //   random (32)
    //   session_id (variable, u8 length)
    //   cipher_suites (variable, u16 length, multiples of 2)
    //   compression_methods (variable, u8 length)
    //   extensions (variable, u16 length)
    let _client_version = cur.u16()?;
    cur.skip(32)?;
    let session_id_len = cur.u8()? as usize;
    cur.skip(session_id_len)?;
    let cipher_suites_len = cur.u16()? as usize;
    cur.skip(cipher_suites_len)?;
    let compression_methods_len = cur.u8()? as usize;
    cur.skip(compression_methods_len)?;

    // Some pre-TLS 1.0 ClientHellos omit the extensions block
    // entirely. If we ran out of body bytes here, the client
    // simply did not negotiate SNI.
    if cur.cursor >= record_end {
        return Ok(None);
    }
    let extensions_len = cur.u16()? as usize;
    if cur.remaining() < extensions_len {
        return Err(SniParseError::Malformed("extensions truncated"));
    }
    let extensions_end = cur.cursor + extensions_len;

    while cur.cursor + 4 <= extensions_end {
        let ext_type = cur.u16()?;
        let ext_len = cur.u16()? as usize;
        if cur.cursor + ext_len > extensions_end {
            return Err(SniParseError::Malformed("extension body truncated"));
        }
        if ext_type == 0x0000 {
            // server_name extension. Body shape:
            //   server_name_list_len (u16)
            //   one or more ServerName entries:
            //       name_type (u8) — 0 = host_name
            //       name_length (u16)
            //       name (UTF-8 bytes)
            let body_start = cur.cursor;
            let _list_len = cur.u16()? as usize;
            // Some TLS stacks emit a single ServerName with
            // name_type=0 only. We loop defensively: read entries
            // until we hit the body's end OR find a host_name.
            while cur.cursor < body_start + ext_len {
                let name_type = cur.u8()?;
                let name_length = cur.u16()? as usize;
                if cur.cursor + name_length > body_start + ext_len {
                    return Err(SniParseError::Malformed("ServerName name truncated"));
                }
                if name_type == 0x00 {
                    let name_bytes = &buf[cur.cursor..cur.cursor + name_length];
                    let name = std::str::from_utf8(name_bytes)
                        .map_err(|_| SniParseError::Malformed("SNI not valid UTF-8"))?;
                    return Ok(Some(name.to_owned()));
                }
                cur.skip(name_length)?;
            }
            // server_name extension present but no host_name entry.
            return Ok(None);
        }
        cur.skip(ext_len)?;
    }
    Ok(None)
}

/// Failure modes from the SNI parser.
#[derive(Debug, Error)]
pub enum SniParseError {
    /// The buffer is not a parseable TLS ClientHello. The
    /// included `&'static str` distinguishes the cases for
    /// debugging without bloating allocations on the hot path.
    #[error("malformed TLS ClientHello: {0}")]
    Malformed(&'static str),
}

// ---------------------------------------------------------------------------
// HTTP Host header extraction
// ---------------------------------------------------------------------------

/// Extract the value of the `Host:` header from an HTTP/1.1
/// request preamble. The buffer MUST contain the full header
/// block terminated by `\r\n\r\n` (the proxy reads up to that
/// before forwarding); a truncated buffer returns `Err`.
///
/// Returns the bare host (port stripped). Header name match is
/// case-insensitive; whitespace around the value is trimmed.
pub fn extract_host_header_from_http_request_line_block(
    buf: &[u8],
) -> Result<String, HostParseError> {
    // Locate the end of the header block.
    let mut header_end: Option<usize> = None;
    for window_start in 0..buf.len() {
        if buf[window_start..].starts_with(b"\r\n\r\n") {
            header_end = Some(window_start);
            break;
        }
    }
    let header_end = header_end.ok_or(HostParseError::Truncated)?;
    let s = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| HostParseError::NotUtf8)?;
    for line in s.split("\r\n").skip(1) {
        // skip(1) drops the request-line ("GET / HTTP/1.1").
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                let v = value.trim();
                let host = v.split(':').next().unwrap_or("").trim();
                if host.is_empty() {
                    return Err(HostParseError::Empty);
                }
                return Ok(host.to_ascii_lowercase());
            }
        }
    }
    Err(HostParseError::Missing)
}

/// Failure modes from the `Host:` header parser.
#[derive(Debug, Error)]
pub enum HostParseError {
    /// The supplied buffer did not contain a `\r\n\r\n` end-of-
    /// header marker — the request preamble is incomplete.
    #[error("HTTP header block is incomplete (no CRLF CRLF sentinel)")]
    Truncated,
    /// The header block is not valid UTF-8.
    #[error("HTTP header block is not valid UTF-8")]
    NotUtf8,
    /// The block is well-formed but contains no `Host:` header.
    /// HTTP/1.1 mandates one — the proxy treats this as a
    /// protocol violation and denies.
    #[error("HTTP request has no Host header")]
    Missing,
    /// `Host:` is present but its value (after port-strip and
    /// whitespace-trim) is empty.
    #[error("HTTP Host header value is empty")]
    Empty,
}

// ---------------------------------------------------------------------------
// Tiny cursor helper for the TLS parser
// ---------------------------------------------------------------------------

struct TlsCursor<'a> {
    buf: &'a [u8],
    cursor: usize,
}

impl<'a> TlsCursor<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, cursor: 0 } }
    fn remaining(&self) -> usize { self.buf.len() - self.cursor }

    fn u8(&mut self) -> Result<u8, SniParseError> {
        if self.cursor + 1 > self.buf.len() {
            return Err(SniParseError::Malformed("u8 read past EOF"));
        }
        let v = self.buf[self.cursor];
        self.cursor += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16, SniParseError> {
        if self.cursor + 2 > self.buf.len() {
            return Err(SniParseError::Malformed("u16 read past EOF"));
        }
        let v = u16::from_be_bytes([self.buf[self.cursor], self.buf[self.cursor + 1]]);
        self.cursor += 2;
        Ok(v)
    }

    fn u24(&mut self) -> Result<u32, SniParseError> {
        if self.cursor + 3 > self.buf.len() {
            return Err(SniParseError::Malformed("u24 read past EOF"));
        }
        let v = (self.buf[self.cursor] as u32) << 16
            | (self.buf[self.cursor + 1] as u32) << 8
            | (self.buf[self.cursor + 2] as u32);
        self.cursor += 3;
        Ok(v)
    }

    fn skip(&mut self, n: usize) -> Result<(), SniParseError> {
        if self.cursor + n > self.buf.len() {
            return Err(SniParseError::Malformed("skip past EOF"));
        }
        self.cursor += n;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_protocol_strings_pinned() {
        assert_eq!(AdmissionProtocol::Https.as_str(), "https");
        assert_eq!(AdmissionProtocol::Http.as_str(), "http");
        assert_eq!(AdmissionProtocol::Tcp.as_str(), "tcp");
    }

    #[test]
    fn deny_reason_strings_pinned() {
        assert_eq!(DenyReason::HostNotInAllowlist.as_str(), "host_not_in_allowlist");
        assert_eq!(DenyReason::ProxyTargetBypass.as_str(), "proxy_target_bypass");
        assert_eq!(DenyReason::ProtocolNotPermitted.as_str(), "protocol_not_permitted");
        assert_eq!(DenyReason::PortNotRedirected.as_str(), "port_not_redirected");
        assert_eq!(DenyReason::Unknown.as_str(), "unknown");
    }

    #[test]
    fn admission_request_round_trips_through_frame_encode_and_decode() {
        let req = ProxyAdmissionRequest {
            connection_id: 42,
            original_dst_ip: "10.0.0.7".to_owned(),
            original_dst_port: 443,
            host_or_sni: Some("api.anthropic.com".to_owned()),
            protocol: AdmissionProtocol::Https,
        };
        let bytes = encode_request(&req).unwrap();
        let (decoded, consumed) = decode_request(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.connection_id, req.connection_id);
        assert_eq!(decoded.original_dst_ip, req.original_dst_ip);
        assert_eq!(decoded.original_dst_port, req.original_dst_port);
        assert_eq!(decoded.host_or_sni, req.host_or_sni);
        assert_eq!(decoded.protocol, req.protocol);
    }

    #[test]
    fn admission_response_round_trips_admit_and_deny() {
        for resp in [
            ProxyAdmissionResponse::Admit { connection_id: 1 },
            ProxyAdmissionResponse::Deny {
                connection_id: 2,
                reason: DenyReason::HostNotInAllowlist,
            },
            ProxyAdmissionResponse::Deny {
                connection_id: 3,
                reason: DenyReason::ProxyTargetBypass,
            },
        ] {
            let bytes = encode_response(&resp).unwrap();
            let (decoded, consumed) = decode_response(&bytes).unwrap();
            assert_eq!(consumed, bytes.len());
            match (&resp, &decoded) {
                (
                    ProxyAdmissionResponse::Admit { connection_id: a },
                    ProxyAdmissionResponse::Admit { connection_id: b },
                ) => assert_eq!(a, b),
                (
                    ProxyAdmissionResponse::Deny { connection_id: a, reason: ra },
                    ProxyAdmissionResponse::Deny { connection_id: b, reason: rb },
                ) => {
                    assert_eq!(a, b);
                    assert_eq!(ra, rb);
                }
                _ => panic!("round-trip discriminant changed"),
            }
        }
    }

    #[test]
    fn frame_decoder_rejects_a_too_short_buffer() {
        assert!(matches!(
            decode_request::<>(&[0u8, 0u8]),
            Err(FrameError::Decode(_))
        ));
    }

    #[test]
    fn frame_decoder_rejects_a_truncated_body() {
        let mut bytes = vec![0u8, 0u8, 0u8, 100u8];
        bytes.extend_from_slice(&[0u8; 5]);
        assert!(matches!(
            decode_request::<>(&bytes),
            Err(FrameError::Decode(_))
        ));
    }

    // ── Host header parser ──────────────────────────────────────────────────

    #[test]
    fn extract_host_header_basic_get() {
        let req = b"GET / HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: x\r\n\r\n";
        let host = extract_host_header_from_http_request_line_block(req).unwrap();
        assert_eq!(host, "api.example.com");
    }

    #[test]
    fn extract_host_header_strips_port() {
        let req = b"GET / HTTP/1.1\r\nHost: registry.example.com:8080\r\n\r\n";
        let host = extract_host_header_from_http_request_line_block(req).unwrap();
        assert_eq!(host, "registry.example.com");
    }

    #[test]
    fn extract_host_header_lowercases_value() {
        let req = b"GET / HTTP/1.1\r\nhost: API.Example.COM\r\n\r\n";
        let host = extract_host_header_from_http_request_line_block(req).unwrap();
        assert_eq!(host, "api.example.com");
    }

    #[test]
    fn extract_host_header_returns_truncated_when_no_crlf_crlf() {
        let req = b"GET / HTTP/1.1\r\nHost: x.example.com\r\n";
        assert!(matches!(
            extract_host_header_from_http_request_line_block(req),
            Err(HostParseError::Truncated)
        ));
    }

    #[test]
    fn extract_host_header_returns_missing_when_absent() {
        let req = b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n";
        assert!(matches!(
            extract_host_header_from_http_request_line_block(req),
            Err(HostParseError::Missing)
        ));
    }

    #[test]
    fn extract_host_header_returns_empty_when_value_blank() {
        let req = b"GET / HTTP/1.1\r\nHost:   \r\n\r\n";
        assert!(matches!(
            extract_host_header_from_http_request_line_block(req),
            Err(HostParseError::Empty)
        ));
    }

    // ── SNI parser ───────────────────────────────────────────────────────────

    /// Build a minimal TLS 1.2 ClientHello carrying one SNI
    /// extension of the supplied hostname. Pinned by RFC 5246 +
    /// RFC 6066 byte layouts; used only by tests.
    fn build_client_hello_with_sni(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let server_name_entry_len = 1 + 2 + host_bytes.len();
        let server_name_list_len = server_name_entry_len;
        let server_name_ext_body_len = 2 + server_name_list_len;
        let server_name_ext_total = 4 + server_name_ext_body_len;
        let extensions_len = server_name_ext_total;
        let body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
        let record_len = 4 + body_len;

        let mut buf = Vec::new();
        // record
        buf.push(0x16);
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&(record_len as u16).to_be_bytes());
        // handshake header
        buf.push(0x01);
        let body_len_u24 = body_len as u32;
        buf.push(((body_len_u24 >> 16) & 0xFF) as u8);
        buf.push(((body_len_u24 >> 8) & 0xFF) as u8);
        buf.push((body_len_u24 & 0xFF) as u8);
        // client_version
        buf.extend_from_slice(&[0x03, 0x03]);
        // random (32 zero bytes — fine for a parser test)
        buf.extend_from_slice(&[0u8; 32]);
        // session_id (empty)
        buf.push(0);
        // cipher_suites: TLS_AES_128_GCM_SHA256 only
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // compression_methods: null
        buf.extend_from_slice(&[0x01, 0x00]);
        // extensions
        buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        // server_name extension: type 0x0000, len ext_body_len
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&(server_name_ext_body_len as u16).to_be_bytes());
        // body
        buf.extend_from_slice(&(server_name_list_len as u16).to_be_bytes());
        buf.push(0x00); // host_name type
        buf.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(host_bytes);
        buf
    }

    #[test]
    fn extract_sni_from_minimal_tls_client_hello() {
        let hello = build_client_hello_with_sni("api.example.com");
        let sni = extract_sni_from_client_hello(&hello).unwrap();
        assert_eq!(sni.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn extract_sni_returns_none_when_no_extensions_block() {
        // Build a hand-crafted ClientHello with extensions_len=0
        let mut buf = Vec::new();
        buf.push(0x16);
        buf.extend_from_slice(&[0x03, 0x03]);
        let body_len: u16 = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2;
        let record_len: u16 = 4 + body_len;
        buf.extend_from_slice(&record_len.to_be_bytes());
        buf.push(0x01);
        buf.push(0); buf.push(0); buf.push(body_len as u8);
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0);
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        buf.extend_from_slice(&[0x01, 0x00]);
        buf.extend_from_slice(&[0x00, 0x00]);
        let sni = extract_sni_from_client_hello(&buf).unwrap();
        assert_eq!(sni, None);
    }

    #[test]
    fn extract_sni_rejects_a_non_handshake_record() {
        let bytes = vec![0x17, 0x03, 0x03, 0x00, 0x00];
        assert!(matches!(
            extract_sni_from_client_hello(&bytes),
            Err(SniParseError::Malformed(_)),
        ));
    }

    #[test]
    fn extract_sni_rejects_a_handshake_that_is_not_client_hello() {
        let mut bytes = vec![0x16, 0x03, 0x03, 0x00, 0x10];
        bytes.push(0x02); // ServerHello, not ClientHello
        bytes.extend_from_slice(&[0u8; 11]);
        assert!(matches!(
            extract_sni_from_client_hello(&bytes),
            Err(SniParseError::Malformed(_)),
        ));
    }
}
