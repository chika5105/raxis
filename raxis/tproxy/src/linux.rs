//! Linux-only glue for `raxis-tproxy` (Path A3 / Mediated egress only).
//!
//! Provides:
//!   * [`accept_loop_a3`] — bind TCP :3129, accept, read
//!     `SO_ORIGINAL_DST`, peek the flow, ask the kernel via
//!     AF_VSOCK for an admission verdict, and either tunnel the
//!     bytes through a kernel-opened upstream (`Admit`) or RST
//!     the agent socket (`Deny`).
//!   * [`bind_default_listener`] — bind the canonical V2 tproxy
//!     port (`3129`) for `iptables -j REDIRECT` to target.
//!
//! The legacy `KernelChannel::Tcp` dev-fallback (in-guest direct
//! upstream `connect()`) was removed when `EgressTier::Tier1Tproxy`
//! was deleted — the guest VM has no NIC under Mediated egress, so
//! a TCP `connect()` from inside the VM has no route. The kernel —
//! not the guest — opens the upstream TCP; the guest just shuttles
//! bytes between the agent socket and the kernel-tunnel vsock
//! stream.
//!
//! The wire-protocol code is in `raxis-tproxy-protocol` (SNI / Host
//! parser helpers used by [`crate::peek`]) and `raxis-types`
//! (`TproxyAdmissionRequest` / `TproxyAdmissionResponse` carried
//! over `IpcMessage` for A3). This module is just orchestration
//! over the TCP listener and the kernel transport.

#![allow(unsafe_code)]

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;

use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Errors surfaced by the accept loop.
#[derive(Debug, Error)]
pub enum AcceptLoopError {
    /// Fatal I/O failure on the listener — the loop returns and
    /// the supervising init-script restarts the binary.
    #[error("listener i/o: {0}")]
    Io(#[from] io::Error),
}

/// Bind the V2 default tproxy port (`3129`) for `iptables -j REDIRECT`.
pub async fn bind_default_listener() -> io::Result<TcpListener> {
    let bind_addr: SocketAddr = "0.0.0.0:3129".parse().expect("static parse");
    TcpListener::bind(bind_addr).await
}

// ---------------------------------------------------------------------------
// Path A3 accept loop — vsock admission + vsock tunnel.
//
// Normative reference: `specs/v2/airgap-architecture.md §3`.
//
// Architectural shape:
//   * Two vsock connections per accepted agent flow (admission +
//     byte tunnel) — the only production code path.
//   * Wire shape is `IpcMessage` (length-prefixed bincode) for the
//     admission round-trip, fixed 48-byte handshake then raw bytes
//     for the tunnel.
//   * The kernel — not the guest — opens the upstream TCP; the
//     guest just shuttles bytes between the agent socket and the
//     kernel-tunnel vsock stream.
// ---------------------------------------------------------------------------

/// Accept loop for the A3 universal-airgap path. Binds 0.0.0.0:3129
/// for `iptables -j REDIRECT`, then routes each accepted flow
/// through the A3 admission protocol over vsock.
///
/// The `session_token` comes from the spawned-guest environment
/// (`RAXIS_SESSION_TOKEN`); the kernel stamps it at session-spawn
/// time and the in-VM init script forwards it to the tproxy
/// process. Without a token A3 cannot authenticate to the kernel
/// and the loop refuses to start.
pub async fn accept_loop_a3(
    listener:       TcpListener,
    host_cid:       u32,
    admission_port: u32,
    tunnel_port:    u32,
    session_token:  String,
) -> Result<(), AcceptLoopError> {
    eprintln!(
        "raxis-tproxy(A3): listening 0.0.0.0:3129; kernel admission \
         vsock=cid:{host_cid}/port:{admission_port}, tunnel \
         vsock=cid:{host_cid}/port:{tunnel_port}",
    );
    loop {
        let (agent, _peer) = listener.accept().await?;
        let token  = session_token.clone();
        tokio::spawn(async move {
            let _ = handle_one_a3_connection(
                agent,
                host_cid,
                admission_port,
                tunnel_port,
                token,
            )
            .await;
        });
    }
}

/// Errors raised by [`handle_one_a3_connection`]. Surfaced for
/// the operator-stderr log line; the loop itself converts them
/// to a TCP RST on the agent side per the A3 spec.
#[derive(Debug, Error)]
pub enum A3ConnectionError {
    /// Transport-level failure (vsock dial / agent socket I/O /
    /// `SO_ORIGINAL_DST`).
    #[error("transport: {0}")]
    Io(#[from] io::Error),

    /// Admission-level protocol failure (frame error, kernel
    /// returned the wrong variant, request_id mismatch).
    #[error("admission protocol: {0}")]
    Admission(#[from] crate::a3::A3AdmissionError),

    /// Kernel returned an explicit Deny — the agent socket is
    /// already shut by the time this is returned.
    #[error("kernel denied admission: {reason}")]
    Denied {
        /// Stable short reason string from
        /// [`raxis_types::TproxyAdmissionResponse::Deny`].
        reason: String,
    },
}

#[cfg(target_os = "linux")]
async fn handle_one_a3_connection(
    mut agent:      TcpStream,
    host_cid:       u32,
    admission_port: u32,
    tunnel_port:    u32,
    session_token:  String,
) -> Result<(), A3ConnectionError> {
    use raxis_types::TproxyProtocol;
    use tokio_vsock::{VsockAddr, VsockStream};

    let original_dst = original_dst_v4(&agent)?;
    let peeked = match crate::peek::peek_https_client_hello_or_http_request(&mut agent).await {
        Ok(p) => p,
        Err(_) => {
            let _ = agent.shutdown().await;
            return Ok(());
        }
    };
    let protocol = match peeked.kind {
        crate::peek::PeekKind::TlsClientHello => TproxyProtocol::Tls,
        crate::peek::PeekKind::Http           => TproxyProtocol::Http,
    };
    let (sni, host_header) = match protocol {
        TproxyProtocol::Tls  => (peeked.host_or_sni.clone(), None),
        TproxyProtocol::Http => (None, peeked.host_or_sni.clone()),
        TproxyProtocol::Tcp  => (None, None),
    };

    // Open the admission vsock channel.
    let mut admission_vsock =
        VsockStream::connect(VsockAddr::new(host_cid, admission_port)).await?;
    let response = crate::a3::ask_admission(
        &mut admission_vsock,
        &session_token,
        sni,
        host_header,
        original_dst,
        protocol,
    )
    .await?;
    // Once the response is in hand we don't need the admission
    // vsock any longer; drop it so the kernel-side handler can
    // recycle the connection slot.
    drop(admission_vsock);

    let (tunnel_id, tunnel_token) = match response {
        raxis_types::TproxyAdmissionResponse::Admit {
            tunnel_id,
            tunnel_token,
            ..
        } => (tunnel_id, tunnel_token),
        raxis_types::TproxyAdmissionResponse::Deny { reason, .. } => {
            let _ = agent.shutdown().await;
            return Err(A3ConnectionError::Denied { reason });
        }
    };

    // Open the byte-tunnel vsock, send the handshake, splice.
    let mut tunnel = VsockStream::connect(VsockAddr::new(host_cid, tunnel_port)).await?;
    let handshake = crate::a3::encode_tunnel_handshake(tunnel_id, &tunnel_token);
    tunnel.write_all(&handshake).await?;
    // Replay the peeked prelude bytes into the kernel-side tunnel
    // so the upstream sees the original TLS ClientHello / HTTP
    // request preamble unchanged.
    if !peeked.buffered.is_empty() {
        tunnel.write_all(&peeked.buffered).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut agent, &mut tunnel).await;
    Ok(())
}

// On non-Linux we never actually run accept_loop_a3 (the tproxy
// binary aborts at the `main()` cfg guard), but we provide a stub
// so the `pub async fn` signature compiles cross-platform for the
// library docs build.
#[cfg(not(target_os = "linux"))]
async fn handle_one_a3_connection(
    _agent:          TcpStream,
    _host_cid:       u32,
    _admission_port: u32,
    _tunnel_port:    u32,
    _session_token:  String,
) -> Result<(), A3ConnectionError> {
    Err(A3ConnectionError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "Path A3 admission loop is Linux-only (uses AF_VSOCK + SO_ORIGINAL_DST)",
    )))
}

// ---------------------------------------------------------------------------
// SO_ORIGINAL_DST — Linux-specific
// ---------------------------------------------------------------------------

fn original_dst_v4(stream: &TcpStream) -> io::Result<SocketAddr> {
    use nix::sys::socket::sockopt::OriginalDst;
    use nix::sys::socket::getsockopt;
    let raw_fd = stream.as_raw_fd();
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw_fd) };
    let dst = getsockopt(&fd, OriginalDst).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("getsockopt SO_ORIGINAL_DST: {e}"))
    })?;
    let port = u16::from_be(dst.sin_port);
    let ip_bytes = u32::from_be(dst.sin_addr.s_addr).to_be_bytes();
    let ip = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}
