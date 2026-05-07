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
/// CID/port-pair); during dev bring-up and integration tests
/// it's `KernelChannel::Tcp` so the same protocol code runs over
/// loopback.
#[derive(Debug, Clone)]
pub enum KernelChannel {
    /// Connect to the kernel via a TCP socket — for development
    /// bring-up on hosts without an `AF_VSOCK` device.
    Tcp(SocketAddr),
}

impl KernelChannel {
    async fn open(&self) -> io::Result<TcpStream> {
        match self {
            KernelChannel::Tcp(addr) => TcpStream::connect(addr).await,
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
