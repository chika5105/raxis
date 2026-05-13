//! Path A3 universal-airgap admission flow.
//!
//! Normative reference: `specs/v2/airgap-architecture.md §3` + §4.
//!
//! # Flow
//!
//! The legacy `KernelChannel::Tcp` path uses `raxis-tproxy-protocol`
//! bincode framing over a TCP loopback (host-side dev only). A3
//! talks to the kernel over per-session AF_VSOCK using the
//! kernel-wide [`raxis_ipc::IpcMessage`] envelope:
//!
//! 1. **Open admission vsock.** `tokio_vsock::VsockStream::connect`
//!    to `(VMADDR_CID_HOST, admission_port)`.
//! 2. **Send `IpcMessage::TproxyAdmissionRequest`.** Length-prefixed
//!    bincode via `raxis_ipc::write_frame`.
//! 3. **Read `IpcMessage::KernelTproxyAdmissionResponse`** via
//!    `raxis_ipc::read_frame`. Any other variant on this channel is
//!    a protocol-violation; the connection is closed and the agent
//!    socket is reset with `TCP RST`.
//! 4. **On Admit** — open a SECOND vsock to
//!    `(VMADDR_CID_HOST, tunnel_port)`. Write the 48-byte handshake
//!    frame (`16-byte tunnel_id || 32-byte tunnel_token`). The
//!    kernel-side tunnel listener consumes the handshake from its
//!    `TunnelRegistry`, opens the upstream TCP, and from that point
//!    the agent ↔ kernel-tunnel pair runs through
//!    [`crate::shuttle::shuttle_with_prelude`] like the legacy path.
//! 5. **On Deny** — shutdown the agent socket. The agent's library
//!    surfaces `ECONNREFUSED` exactly like the legacy chokepoint.
//!
//! # Wire shape of the handshake frame
//!
//! Fixed 48 bytes, no length prefix (the tunnel port speaks a
//! framed handshake then raw bytes, NOT bincode-framed messages):
//!
//! ```text
//! ┌──────────────────────────────┬───────────────────────────────┐
//! │ tunnel_id   : [u8; 16]       │ tunnel_token : [u8; 32]       │
//! └──────────────────────────────┴───────────────────────────────┘
//! ```
//!
//! The kernel-side tunnel listener reads exactly 48 bytes before
//! deciding whether to proceed — a short handshake closes the
//! connection.

#![allow(unsafe_code)]

use std::io;
use std::net::{IpAddr, SocketAddr};

use raxis_ipc::{read_frame, write_frame, FrameError, IpcMessage};
use raxis_types::{
    DnsQueryType, DnsResolveRequest, DnsResolveResponse, TproxyAdmissionRequest,
    TproxyAdmissionResponse, TproxyProtocol,
};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

/// Length of the kernel-tunnel handshake frame in bytes
/// (`16 + 32 = 48`). Pinned constant so a test failure makes
/// drift impossible.
pub const TUNNEL_HANDSHAKE_LEN: usize = 16 + 32;

/// Build the fixed-shape handshake frame the guest writes as the
/// first 48 bytes of the kernel-tunnel vsock connection.
///
/// The frame layout is documented in the module-level docs.
#[must_use]
pub fn encode_tunnel_handshake(tunnel_id: Uuid, tunnel_token: &[u8; 32]) -> [u8; TUNNEL_HANDSHAKE_LEN] {
    let mut buf = [0u8; TUNNEL_HANDSHAKE_LEN];
    buf[..16].copy_from_slice(tunnel_id.as_bytes());
    buf[16..].copy_from_slice(tunnel_token);
    buf
}

/// Decode the 48-byte handshake frame (kernel-side use).
/// Returns `None` if the buffer is the wrong length.
#[must_use]
pub fn decode_tunnel_handshake(buf: &[u8]) -> Option<(Uuid, [u8; 32])> {
    if buf.len() != TUNNEL_HANDSHAKE_LEN {
        return None;
    }
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&buf[..16]);
    let mut token = [0u8; 32];
    token.copy_from_slice(&buf[16..]);
    Some((Uuid::from_bytes(id_bytes), token))
}

/// Errors surfaced by the A3 admission round-trip.
#[derive(Debug, Error)]
pub enum A3AdmissionError {
    /// Underlying transport (vsock or loopback duplex stream)
    /// failed — connection refused, reset, etc.
    #[error("transport i/o: {0}")]
    Io(#[from] io::Error),

    /// Bincode framing layer surfaced an error.
    #[error("ipc framing: {0}")]
    Frame(#[from] FrameError),

    /// Kernel returned an `IpcMessage` variant other than
    /// `KernelTproxyAdmissionResponse` on the admission channel.
    /// Protocol violation — the kernel is buggy or compromised;
    /// fail closed and shut the agent socket.
    #[error("protocol violation: unexpected response variant `{0}` on admission channel")]
    UnexpectedResponse(&'static str),

    /// Kernel returned a response whose `request_id` does not
    /// match the request we sent. Replay / mis-multiplexing.
    #[error("response request_id mismatch (sent={sent}, got={got})")]
    RequestIdMismatch {
        /// The `request_id` the guest minted for the request.
        sent: Uuid,
        /// The `request_id` the kernel echoed back.
        got:  Uuid,
    },
}

/// Ask the kernel for an admission verdict on one outbound TCP
/// flow. Returns the wire response unchanged so the caller can
/// branch on Admit / Deny.
///
/// The transport is any `AsyncRead + AsyncWrite + Unpin` so this
/// function is testable over a `tokio::io::duplex()` pair without
/// a real vsock device — the same code runs verbatim over the
/// `tokio_vsock::VsockStream` in production.
pub async fn ask_admission<S>(
    stream:        &mut S,
    session_token: &str,
    sni:           Option<String>,
    host_header:   Option<String>,
    destination:   SocketAddr,
    protocol:      TproxyProtocol,
) -> Result<TproxyAdmissionResponse, A3AdmissionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request_id = Uuid::new_v4();
    let req = TproxyAdmissionRequest {
        request_id,
        session_token: session_token.to_owned(),
        sni,
        host_header,
        destination,
        protocol,
    };
    let envelope = IpcMessage::TproxyAdmissionRequest(req);
    write_frame(stream, &envelope).await?;

    let response_envelope: IpcMessage = read_frame(stream).await?;
    let response = match response_envelope {
        IpcMessage::KernelTproxyAdmissionResponse(r) => r,
        other => {
            return Err(A3AdmissionError::UnexpectedResponse(
                ipc_message_variant_name(&other),
            ))
        }
    };

    let response_id = match &response {
        TproxyAdmissionResponse::Admit { request_id, .. } => *request_id,
        TproxyAdmissionResponse::Deny  { request_id, .. } => *request_id,
    };
    if response_id != request_id {
        return Err(A3AdmissionError::RequestIdMismatch {
            sent: request_id,
            got:  response_id,
        });
    }
    Ok(response)
}

/// Same as [`ask_admission`] but for the DNS-over-vsock channel.
///
/// Returns a populated `DnsResolveResponse` for every input
/// (empty `addresses` ⇒ NXDOMAIN-equivalent).
pub async fn ask_dns_resolve<S>(
    stream:        &mut S,
    session_token: &str,
    hostname:      &str,
    query_type:    DnsQueryType,
) -> Result<DnsResolveResponse, A3AdmissionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request_id = Uuid::new_v4();
    let req = DnsResolveRequest {
        request_id,
        session_token: session_token.to_owned(),
        hostname: hostname.to_owned(),
        query_type,
    };
    write_frame(stream, &IpcMessage::DnsResolveRequest(req)).await?;

    let envelope: IpcMessage = read_frame(stream).await?;
    let response = match envelope {
        IpcMessage::KernelDnsResolveResponse(r) => r,
        other => {
            return Err(A3AdmissionError::UnexpectedResponse(
                ipc_message_variant_name(&other),
            ))
        }
    };
    if response.request_id != request_id {
        return Err(A3AdmissionError::RequestIdMismatch {
            sent: request_id,
            got:  response.request_id,
        });
    }
    Ok(response)
}

/// Helper — extracts the destination as an `IpAddr` from a
/// resolved hostname. Used by the kernel-tunnel handshake path.
#[must_use]
pub fn ip_from_socket_addr(addr: SocketAddr) -> IpAddr {
    addr.ip()
}

/// Close the agent-side TCP socket with a TCP RST so the
/// application's libc surfaces `ECONNREFUSED`. Used on Deny and
/// on every protocol-violation path.
pub async fn deny_agent<S>(agent: &mut S) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    agent.shutdown().await
}

fn ipc_message_variant_name(msg: &IpcMessage) -> &'static str {
    match msg {
        IpcMessage::IntentRequest(_)              => "IntentRequest",
        IpcMessage::EscalationRequest(_)          => "EscalationRequest",
        IpcMessage::PlannerFetchRequest(_)        => "PlannerFetchRequest",
        IpcMessage::KernelIntentResponse(_)       => "KernelIntentResponse",
        IpcMessage::KernelEscalationResponse(_)   => "KernelEscalationResponse",
        IpcMessage::KernelPlannerFetchResponse(_) => "KernelPlannerFetchResponse",
        IpcMessage::WitnessSubmission(_)          => "WitnessSubmission",
        IpcMessage::WitnessAck { .. }             => "WitnessAck",
        IpcMessage::OperatorRequest(_)            => "OperatorRequest",
        IpcMessage::OperatorResponse(_)           => "OperatorResponse",
        IpcMessage::TproxyAdmissionRequest(_)         => "TproxyAdmissionRequest",
        IpcMessage::KernelTproxyAdmissionResponse(_)  => "KernelTproxyAdmissionResponse",
        IpcMessage::DnsResolveRequest(_)              => "DnsResolveRequest",
        IpcMessage::KernelDnsResolveResponse(_)       => "KernelDnsResolveResponse",
    }
}

// ---------------------------------------------------------------------------
// Tests — pure-async round-trip + handshake wire-shape pins.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn handshake_round_trip_preserves_bytes() {
        let id    = Uuid::new_v4();
        let token = [0x5Au8; 32];
        let encoded = encode_tunnel_handshake(id, &token);
        let (got_id, got_token) =
            decode_tunnel_handshake(&encoded).expect("decode succeeds");
        assert_eq!(got_id, id);
        assert_eq!(got_token, token);
    }

    #[test]
    fn handshake_decode_rejects_short_buffers() {
        assert!(decode_tunnel_handshake(&[]).is_none());
        assert!(decode_tunnel_handshake(&[0u8; 47]).is_none());
        assert!(decode_tunnel_handshake(&[0u8; 49]).is_none());
    }

    #[test]
    fn handshake_constant_is_48_bytes() {
        // Wire-shape pin — drift breaks every existing audit dashboard
        // that pivots on tunnel_id.
        assert_eq!(TUNNEL_HANDSHAKE_LEN, 48);
    }

    #[tokio::test]
    async fn ask_admission_round_trip_admit() {
        // Pair of in-memory streams simulates the vsock channel.
        let (mut guest_side, mut kernel_side) = duplex(8192);

        // Kernel-side task: consume the request, reply Admit.
        let kernel_task = tokio::spawn(async move {
            let envelope: IpcMessage = read_frame(&mut kernel_side).await.expect("read");
            let req = match envelope {
                IpcMessage::TproxyAdmissionRequest(r) => r,
                _ => panic!("expected admission request"),
            };
            let resp = TproxyAdmissionResponse::Admit {
                request_id:   req.request_id,
                tunnel_id:    Uuid::nil(),
                tunnel_token: [0x11u8; 32],
            };
            write_frame(&mut kernel_side, &IpcMessage::KernelTproxyAdmissionResponse(resp))
                .await
                .expect("write");
        });

        let resp = ask_admission(
            &mut guest_side,
            "session-token",
            Some("api.example.com".to_owned()),
            None,
            "1.2.3.4:443".parse().unwrap(),
            TproxyProtocol::Tls,
        )
        .await
        .expect("admission round-trip");

        match resp {
            TproxyAdmissionResponse::Admit { tunnel_token, .. } => {
                assert_eq!(tunnel_token, [0x11u8; 32]);
            }
            TproxyAdmissionResponse::Deny { .. } => panic!("expected admit"),
        }
        kernel_task.await.expect("kernel task join");
    }

    #[tokio::test]
    async fn ask_admission_round_trip_deny() {
        let (mut guest_side, mut kernel_side) = duplex(8192);
        let kernel_task = tokio::spawn(async move {
            let envelope: IpcMessage = read_frame(&mut kernel_side).await.expect("read");
            let req = match envelope {
                IpcMessage::TproxyAdmissionRequest(r) => r,
                _ => panic!("expected admission request"),
            };
            let resp = TproxyAdmissionResponse::Deny {
                request_id: req.request_id,
                reason:     "host_not_in_allowlist".to_owned(),
                hint:       Some("add to policy".to_owned()),
            };
            write_frame(&mut kernel_side, &IpcMessage::KernelTproxyAdmissionResponse(resp))
                .await
                .expect("write");
        });

        let resp = ask_admission(
            &mut guest_side,
            "session-token",
            None,
            Some("evil.example.com".to_owned()),
            "1.2.3.4:80".parse().unwrap(),
            TproxyProtocol::Http,
        )
        .await
        .expect("admission round-trip");
        match resp {
            TproxyAdmissionResponse::Deny { reason, .. } => {
                assert_eq!(reason, "host_not_in_allowlist");
            }
            TproxyAdmissionResponse::Admit { .. } => panic!("expected deny"),
        }
        kernel_task.await.expect("kernel task join");
    }

    #[tokio::test]
    async fn ask_admission_rejects_unexpected_variant() {
        let (mut guest_side, mut kernel_side) = duplex(8192);
        let kernel_task = tokio::spawn(async move {
            // Drain the request, then send a totally wrong variant.
            let _: IpcMessage = read_frame(&mut kernel_side).await.expect("read");
            let bogus = IpcMessage::WitnessAck {
                verifier_run_id: Uuid::nil(),
                accepted:        true,
                reason:          None,
            };
            write_frame(&mut kernel_side, &bogus).await.expect("write");
        });

        let result = ask_admission(
            &mut guest_side,
            "session-token",
            Some("api.example.com".to_owned()),
            None,
            "1.2.3.4:443".parse().unwrap(),
            TproxyProtocol::Tls,
        )
        .await;
        match result {
            Err(A3AdmissionError::UnexpectedResponse("WitnessAck")) => {}
            other => panic!("expected UnexpectedResponse(WitnessAck), got {other:?}"),
        }
        kernel_task.await.expect("kernel task join");
    }

    #[tokio::test]
    async fn ask_admission_detects_request_id_mismatch() {
        let (mut guest_side, mut kernel_side) = duplex(8192);
        let kernel_task = tokio::spawn(async move {
            let _: IpcMessage = read_frame(&mut kernel_side).await.expect("read");
            // Kernel sends a response with a fresh (mismatched) request_id.
            let resp = TproxyAdmissionResponse::Admit {
                request_id:   Uuid::new_v4(),
                tunnel_id:    Uuid::nil(),
                tunnel_token: [0u8; 32],
            };
            write_frame(&mut kernel_side, &IpcMessage::KernelTproxyAdmissionResponse(resp))
                .await
                .expect("write");
        });
        let result = ask_admission(
            &mut guest_side,
            "session-token",
            Some("api.example.com".to_owned()),
            None,
            "1.2.3.4:443".parse().unwrap(),
            TproxyProtocol::Tls,
        )
        .await;
        match result {
            Err(A3AdmissionError::RequestIdMismatch { .. }) => {}
            other => panic!("expected RequestIdMismatch, got {other:?}"),
        }
        kernel_task.await.expect("kernel task join");
    }

    #[tokio::test]
    async fn ask_dns_resolve_round_trip() {
        use std::net::Ipv4Addr;
        let (mut guest_side, mut kernel_side) = duplex(8192);
        let kernel_task = tokio::spawn(async move {
            let envelope: IpcMessage = read_frame(&mut kernel_side).await.expect("read");
            let req = match envelope {
                IpcMessage::DnsResolveRequest(r) => r,
                _ => panic!("expected dns request"),
            };
            let resp = DnsResolveResponse {
                request_id: req.request_id,
                addresses: vec![Ipv4Addr::new(1, 2, 3, 4).into()],
                ttl_secs: 60,
            };
            write_frame(&mut kernel_side, &IpcMessage::KernelDnsResolveResponse(resp))
                .await
                .expect("write");
        });
        let resp = ask_dns_resolve(
            &mut guest_side,
            "session-token",
            "api.example.com",
            DnsQueryType::A,
        )
        .await
        .expect("dns round-trip");
        assert_eq!(resp.addresses.len(), 1);
        assert_eq!(resp.ttl_secs, 60);
        kernel_task.await.expect("kernel task join");
    }
}
