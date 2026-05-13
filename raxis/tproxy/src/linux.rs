//! Linux-only glue for `raxis-tproxy`.
//!
//! Provides:
//!   * [`accept_loop`] — bind TCP :3129, accept, read
//!     `SO_ORIGINAL_DST`, peek the flow, ask the kernel via vsock
//!     for an admission verdict, and either tunnel or RST.
//!
//! Not yet implemented (V2 GA target):
//!   * Real vsock client — currently a TCP fallback for development
//!     bring-up (`KernelChannel::Tcp`). The wire shape is the same
//!     bincode-framed protocol; only the transport differs.
//!
//! The wire-protocol code is in `raxis-tproxy-protocol`. The
//! decision-making code is in `raxis-egress-admission`. This
//! module is just orchestration over a TCP listener and the
//! kernel transport.

#![allow(unsafe_code)]

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use raxis_tproxy_protocol::{
    decode_response, encode_request, AdmissionProtocol, ProxyAdmissionRequest,
    ProxyAdmissionResponse,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::peek::{peek_https_client_hello_or_http_request, PeekKind};
use crate::shuttle::shuttle_with_prelude;

/// Errors surfaced by the accept loop.
#[derive(Debug, Error)]
pub enum AcceptLoopError {
    /// Fatal I/O failure on the listener — the loop returns and
    /// the supervising init-script restarts the binary.
    #[error("listener i/o: {0}")]
    Io(#[from] io::Error),
}

/// Per-connection counter — each accepted TCP stream gets a
/// monotonically increasing `connection_id`.
fn next_connection_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Pluggable transport for the kernel admission channel. In
/// production this is `KernelChannel::Vsock` (AF_VSOCK
/// CID/port-pair) — see
/// `specs/v2/airgap-architecture.md §3`; during dev bring-up and
/// integration tests it's `KernelChannel::Tcp` so the same
/// protocol code runs over loopback.
#[derive(Debug, Clone)]
pub enum KernelChannel {
    /// Connect to the kernel via a TCP socket — for development
    /// bring-up on hosts without an `AF_VSOCK` device. Speaks the
    /// legacy `raxis-tproxy-protocol` bincode framing.
    Tcp(SocketAddr),
    /// Path A3 production transport — `AF_VSOCK` to
    /// `(VMADDR_CID_HOST, admission_port)` for admission, plus
    /// `tunnel_port` for the post-admit byte tunnel. Speaks the
    /// kernel-wide `IpcMessage` envelope (length-prefixed bincode)
    /// — see [`crate::a3`]. The dual-port shape (admission +
    /// tunnel) keeps the byte path framed-free so
    /// `tokio::io::copy_bidirectional` can splice the agent socket
    /// to the kernel-side upstream TCP without an extra parser.
    Vsock {
        /// CID of the kernel-side listener. Always
        /// `VMADDR_CID_HOST` (2) in the production substrate; the
        /// field is exposed so unit tests on host machines can
        /// point the listener at a different CID.
        host_cid:       u32,
        /// Port the kernel binds for `IpcMessage`-framed
        /// admission requests.
        admission_port: u32,
        /// Port the kernel binds for the byte-tunnel handshake +
        /// raw shuttle stream.
        tunnel_port:    u32,
    },
}

impl KernelChannel {
    async fn open(&self) -> io::Result<TcpStream> {
        match self {
            KernelChannel::Tcp(addr) => TcpStream::connect(addr).await,
            // The Vsock arm of the legacy `open` path is
            // intentionally unreachable: the A3 admission flow
            // runs through `accept_loop_a3` (see below), which
            // opens vsock streams directly via `tokio_vsock`. The
            // legacy `handle_one_connection` is TCP-only.
            KernelChannel::Vsock { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "KernelChannel::Vsock must be driven via `accept_loop_a3`, not the legacy TCP path",
            )),
        }
    }
}

/// One inbound connection — peek, admit, shuttle.
async fn handle_one_connection(
    mut agent: TcpStream,
    kernel:    KernelChannel,
) -> Result<(), AcceptLoopError> {
    let cid = next_connection_id();

    // Read SO_ORIGINAL_DST.
    let original_dst = original_dst_v4(&agent)?;
    let original_dst_ip = match original_dst {
        SocketAddr::V4(v4) => v4.ip().to_string(),
        SocketAddr::V6(v6) => v6.ip().to_string(),
    };
    let original_dst_port = original_dst.port();

    // Peek the flow.
    let peeked = match peek_https_client_hello_or_http_request(&mut agent).await {
        Ok(p) => p,
        Err(_) => {
            let _ = agent.shutdown().await;
            return Ok(());
        }
    };

    let protocol = match peeked.kind {
        PeekKind::TlsClientHello => AdmissionProtocol::Https,
        PeekKind::Http           => AdmissionProtocol::Http,
    };
    let req = ProxyAdmissionRequest {
        connection_id: cid,
        original_dst_ip: original_dst_ip.clone(),
        original_dst_port,
        host_or_sni: peeked.host_or_sni.clone(),
        protocol,
    };

    // Ask the kernel.
    let mut kernel_stream = kernel.open().await?;
    let req_bytes = encode_request(&req)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    kernel_stream.write_all(&req_bytes).await?;

    let mut len_buf = [0u8; 4];
    kernel_stream.read_exact(&mut len_buf).await?;
    let body_len = u32::from_be_bytes(len_buf) as usize;
    if body_len > raxis_tproxy_protocol::MAX_FRAME_BYTES {
        return Err(AcceptLoopError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel admission frame too large",
        )));
    }
    let mut body = vec![0u8; body_len];
    kernel_stream.read_exact(&mut body).await?;
    let mut full = Vec::with_capacity(4 + body_len);
    full.extend_from_slice(&len_buf);
    full.extend_from_slice(&body);
    let (resp, _consumed) = decode_response(&full)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    match resp {
        ProxyAdmissionResponse::Admit { .. } => {
            // Open the upstream TCP. (V2 GA: the kernel returns a
            // tunnel handle — for dev bring-up we open the
            // upstream from inside the VM.) The kernel's audit
            // event already records the admission; we don't need
            // to re-ask. Real V2 will close the loopback
            // `kernel_stream` here and accept the kernel-side
            // tunnel FD over an SCM_RIGHTS / VSOCK_TRANSFER
            // channel.
            let upstream_addr = SocketAddr::new(IpAddr::V4(original_dst_ip.parse().unwrap_or("0.0.0.0".parse().unwrap())), original_dst_port);
            match TcpStream::connect(upstream_addr).await {
                Ok(upstream) => {
                    let _ = shuttle_with_prelude(&mut agent, upstream, &peeked.buffered).await;
                }
                Err(_) => {
                    let _ = agent.shutdown().await;
                }
            }
        }
        ProxyAdmissionResponse::Deny { .. } => {
            let _ = agent.shutdown().await;
        }
    }
    Ok(())
}

/// Accept connections on `listener`, dispatch each to
/// `handle_one_connection`. Runs forever; intended to be the
/// last step of `main()`.
pub async fn accept_loop(
    listener: TcpListener,
    kernel:   KernelChannel,
) -> Result<(), AcceptLoopError> {
    loop {
        let (agent, _peer) = listener.accept().await?;
        let kernel_clone = kernel.clone();
        tokio::spawn(async move {
            let _ = handle_one_connection(agent, kernel_clone).await;
        });
    }
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
// Architectural differences vs `accept_loop` above:
//   * Two vsock connections per accepted agent flow (admission +
//     byte tunnel) instead of one mixed loopback-TCP connection.
//   * Wire shape is `IpcMessage` (length-prefixed bincode) for the
//     admission round-trip, fixed 48-byte handshake then raw bytes
//     for the tunnel.
//   * The kernel — not the guest — opens the upstream TCP; the
//     guest just shuttles bytes between the agent socket and the
//     kernel-tunnel vsock stream.
// ---------------------------------------------------------------------------

/// Accept loop for the A3 universal-airgap path. Same listener
/// shape as [`accept_loop`] but routes each accepted flow through
/// the A3 admission protocol over vsock.
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
