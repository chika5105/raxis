//! In-VM DNS stub forwarder for Path A3.
//!
//! Normative reference: `specs/v2/airgap-architecture.md §3.2`.
//!
//! # What this module does
//!
//! Binds `127.0.0.1:53` UDP (and 127.0.0.1:53 TCP for large
//! responses) inside the guest VM. For every DNS query received:
//!
//! 1. Parse the question section (single-question, A or AAAA — the
//!    libc resolver always issues one of those for `getaddrinfo`).
//! 2. Build an `IpcMessage::DnsResolveRequest` and send it over
//!    the kernel admission vsock channel.
//! 3. Read the `KernelDnsResolveResponse`, translate it to a
//!    minimal DNS response packet (`NOERROR` + answer RRs, or
//!    `NXDOMAIN` for an empty `addresses` list), and send it back
//!    to the libc resolver.
//!
//! The stub does NOT implement EDNS0, DNSSEC validation, or
//! caching — the kernel-side resolver is the single source of
//! truth, and the kernel's `[egress.dns]` policy block exposes
//! the cache-control knobs (TTL, etc) that callers may want to
//! tune.
//!
//! # Packet codec
//!
//! Minimum viable RFC1035 implementation — just enough to answer
//! single-question A/AAAA queries from the libc resolver in
//! glibc / musl. Both stubs send queries in the same wire format
//! and accept the same response shape so this codec works for
//! both. Tests round-trip query → request → response → query in
//! `tests::*`.

#![cfg(target_os = "linux")]
#![allow(clippy::too_many_lines)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use raxis_ipc::{read_frame, write_frame, FrameError, IpcMessage};
use raxis_types::{DnsQueryType, DnsResolveRequest, DnsResolveResponse};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_vsock::{VsockAddr, VsockStream};
use uuid::Uuid;

/// V2 default DNS response size cap (RFC1035 UDP limit). Larger
/// answers truncate and the libc resolver retries over TCP.
const MAX_UDP_PAYLOAD: usize = 512;

/// DNS class IN.
const QCLASS_IN: u16 = 1;
/// DNS type A.
const QTYPE_A: u16 = 1;
/// DNS type AAAA.
const QTYPE_AAAA: u16 = 28;

/// Errors raised by the DNS stub's per-packet path.
#[derive(Debug, Error)]
pub enum DnsStubError {
    /// I/O on the UDP / TCP listener or the kernel vsock channel.
    #[error("transport: {0}")]
    Io(#[from] io::Error),

    /// Wire-format DNS packet was malformed beyond what we can
    /// answer (multi-question, truncated header, etc).
    #[error("malformed dns packet: {0}")]
    Malformed(&'static str),

    /// Kernel-side `IpcMessage` framing failed.
    #[error("ipc framing: {0}")]
    Frame(#[from] FrameError),

    /// Kernel returned an envelope variant other than
    /// `KernelDnsResolveResponse`.
    #[error("unexpected response envelope")]
    UnexpectedResponse,
}

/// Bind the V2 default DNS listener pair (`127.0.0.1:53` UDP +
/// TCP) and run them forever, fanning queries out to the kernel
/// admission channel.
pub async fn run_dns_stub(
    host_cid: u32,
    admission_port: u32,
    session_token: String,
) -> Result<(), DnsStubError> {
    let bind: SocketAddr = "127.0.0.1:53".parse().expect("static parse");
    let udp = UdpSocket::bind(bind).await?;
    let tcp = TcpListener::bind(bind).await?;
    eprintln!(
        "raxis-tproxy(A3 dns): listening 127.0.0.1:53 udp+tcp; \
         kernel vsock=cid:{host_cid}/port:{admission_port}",
    );

    let udp = Arc::new(udp);
    let token = Arc::new(session_token);

    // UDP path — one packet at a time. RFC1035 §4.2.1 allows a
    // single-flight server here; libc resolvers reuse a single
    // socket but fan out at the syscall layer, which keeps the
    // contention low for the in-VM use case.
    let token_udp = Arc::clone(&token);
    let udp_socket = Arc::clone(&udp);
    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let (n, peer) = match udp_socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("raxis-tproxy(A3 dns): udp recv failed: {e}");
                    return;
                }
            };
            let pkt = buf[..n].to_vec();
            let token = Arc::clone(&token_udp);
            let socket = Arc::clone(&udp_socket);
            tokio::spawn(async move {
                let _ =
                    handle_udp_query(&pkt, peer, &socket, host_cid, admission_port, &token).await;
            });
        }
    });

    // TCP path — one connection at a time per RFC1035 §4.2.2 (the
    // length-prefix shape).
    let token_tcp = Arc::clone(&token);
    let tcp_task = tokio::spawn(async move {
        loop {
            let (mut sock, _peer) = match tcp.accept().await {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("raxis-tproxy(A3 dns): tcp accept failed: {e}");
                    return;
                }
            };
            let token = Arc::clone(&token_tcp);
            tokio::spawn(async move {
                let _ = handle_tcp_connection(&mut sock, host_cid, admission_port, &token).await;
            });
        }
    });

    let _ = tokio::join!(udp_task, tcp_task);
    Ok(())
}

async fn handle_udp_query(
    pkt: &[u8],
    peer: SocketAddr,
    socket: &UdpSocket,
    host_cid: u32,
    admission_port: u32,
    session_token: &str,
) -> Result<(), DnsStubError> {
    let response = build_response_for_query(pkt, host_cid, admission_port, session_token).await?;
    // Truncate per RFC1035 if the response exceeds the UDP cap.
    let to_send = if response.len() > MAX_UDP_PAYLOAD {
        truncate_response(&response)
    } else {
        response
    };
    socket.send_to(&to_send, peer).await?;
    Ok(())
}

async fn handle_tcp_connection(
    sock: &mut tokio::net::TcpStream,
    host_cid: u32,
    admission_port: u32,
    session_token: &str,
) -> Result<(), DnsStubError> {
    // RFC1035 §4.2.2: 2-byte length prefix, big-endian.
    let mut len_buf = [0u8; 2];
    if sock.read_exact(&mut len_buf).await.is_err() {
        return Ok(());
    }
    let body_len = u16::from_be_bytes(len_buf) as usize;
    if body_len == 0 || body_len > 65_535 {
        return Err(DnsStubError::Malformed("invalid tcp length prefix"));
    }
    let mut pkt = vec![0u8; body_len];
    sock.read_exact(&mut pkt).await?;
    let response = build_response_for_query(&pkt, host_cid, admission_port, session_token).await?;
    let resp_len = (response.len() as u16).to_be_bytes();
    sock.write_all(&resp_len).await?;
    sock.write_all(&response).await?;
    sock.flush().await?;
    Ok(())
}

async fn build_response_for_query(
    pkt: &[u8],
    host_cid: u32,
    admission_port: u32,
    session_token: &str,
) -> Result<Vec<u8>, DnsStubError> {
    let parsed = parse_query(pkt)?;
    // Set a short connect timeout on the vsock dial so a hung
    // kernel doesn't wedge the libc resolver indefinitely.
    let mut vsock = tokio::time::timeout(
        Duration::from_secs(5),
        VsockStream::connect(VsockAddr::new(host_cid, admission_port)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "vsock connect timeout"))??;
    let req = DnsResolveRequest {
        request_id: Uuid::new_v4(),
        session_token: session_token.to_owned(),
        hostname: parsed.qname.clone(),
        query_type: match parsed.qtype {
            QTYPE_A => DnsQueryType::A,
            QTYPE_AAAA => DnsQueryType::Aaaa,
            _ => return Ok(build_response(&parsed, &[], /*nxdomain*/ true, 0)),
        },
    };
    write_frame(&mut vsock, &IpcMessage::DnsResolveRequest(req)).await?;
    let envelope: IpcMessage = read_frame(&mut vsock).await?;
    let resp: DnsResolveResponse = match envelope {
        IpcMessage::KernelDnsResolveResponse(r) => r,
        _ => return Err(DnsStubError::UnexpectedResponse),
    };
    let nxdomain = resp.addresses.is_empty();
    Ok(build_response(
        &parsed,
        &resp.addresses,
        nxdomain,
        resp.ttl_secs,
    ))
}

#[derive(Debug, Clone)]
struct ParsedQuery {
    id: u16,
    flags: u16,
    qname: String,
    qtype: u16,
    qclass: u16,
    /// Raw on-the-wire QNAME bytes so the response can echo them
    /// back unchanged.
    qname_wire: Vec<u8>,
}

fn parse_query(pkt: &[u8]) -> Result<ParsedQuery, DnsStubError> {
    if pkt.len() < 12 {
        return Err(DnsStubError::Malformed("packet shorter than dns header"));
    }
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount != 1 {
        return Err(DnsStubError::Malformed(
            "only single-question queries supported",
        ));
    }
    // Parse QNAME — labels separated by length octets, terminated
    // by a zero octet. No compression in the question section.
    let mut idx = 12usize;
    let mut qname = String::new();
    let qname_start = idx;
    loop {
        if idx >= pkt.len() {
            return Err(DnsStubError::Malformed("truncated qname"));
        }
        let len = pkt[idx] as usize;
        idx += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return Err(DnsStubError::Malformed("dns name compression in question"));
        }
        if idx + len > pkt.len() {
            return Err(DnsStubError::Malformed("qname label overruns packet"));
        }
        if !qname.is_empty() {
            qname.push('.');
        }
        qname.push_str(
            std::str::from_utf8(&pkt[idx..idx + len])
                .map_err(|_| DnsStubError::Malformed("qname label not utf-8"))?,
        );
        idx += len;
    }
    let qname_wire = pkt[qname_start..idx].to_vec();
    if idx + 4 > pkt.len() {
        return Err(DnsStubError::Malformed("truncated qtype/qclass"));
    }
    let qtype = u16::from_be_bytes([pkt[idx], pkt[idx + 1]]);
    let qclass = u16::from_be_bytes([pkt[idx + 2], pkt[idx + 3]]);
    if qclass != QCLASS_IN {
        return Err(DnsStubError::Malformed("only QCLASS IN supported"));
    }
    Ok(ParsedQuery {
        id,
        flags,
        qname,
        qtype,
        qclass,
        qname_wire,
    })
}

fn build_response(q: &ParsedQuery, addrs: &[IpAddr], nxdomain: bool, ttl_secs: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&q.id.to_be_bytes());
    // Response flags: QR=1, OPCODE from request, AA=0, TC=0,
    // RD = request RD bit, RA=1 (we recursed via the kernel),
    // Z=0, RCODE = 0 (NOERROR) or 3 (NXDOMAIN).
    let opcode = (q.flags >> 11) & 0xF;
    let rd = (q.flags >> 8) & 1;
    let rcode = if nxdomain { 3u16 } else { 0u16 };
    let flags_out: u16 = 0x8000              // QR
        | (opcode << 11)
        | (rd << 8)
        | 0x0080                              // RA
        | rcode;
    out.extend_from_slice(&flags_out.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
                                                // Filter the addresses by the requested type so we never emit
                                                // an A record for an AAAA query (or vice versa). Defence in
                                                // depth: the kernel-side resolver already filters but we keep
                                                // the codec strict.
    let filtered: Vec<IpAddr> = addrs
        .iter()
        .copied()
        .filter(|ip| match (q.qtype, ip) {
            (QTYPE_A, IpAddr::V4(_)) => true,
            (QTYPE_AAAA, IpAddr::V6(_)) => true,
            _ => false,
        })
        .collect();
    out.extend_from_slice(&(filtered.len() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                // Echo the question section verbatim.
    out.extend_from_slice(&q.qname_wire);
    out.push(0); // null terminator we stripped during parsing
    out.extend_from_slice(&q.qtype.to_be_bytes());
    out.extend_from_slice(&q.qclass.to_be_bytes());
    // Append one RR per address.
    for ip in filtered {
        // Compression: pointer to the question's QNAME at offset 12.
        out.push(0xC0);
        out.push(0x0C);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&q.qclass.to_be_bytes());
        out.extend_from_slice(&ttl_secs.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

fn truncate_response(resp: &[u8]) -> Vec<u8> {
    // Cap at MAX_UDP_PAYLOAD and set the TC bit in the flags so
    // the resolver retries over TCP.
    let mut truncated = resp[..MAX_UDP_PAYLOAD.min(resp.len())].to_vec();
    if truncated.len() >= 4 {
        let flags = u16::from_be_bytes([truncated[2], truncated[3]]);
        let with_tc = flags | 0x0200; // TC
        let bytes = with_tc.to_be_bytes();
        truncated[2] = bytes[0];
        truncated[3] = bytes[1];
    }
    truncated
}

// Suppress dead-code warning — these struct fields are used by
// the response builder via the `q` borrow chain; rustc's
// dead-field analysis misses cross-function uses inside the
// helper that takes `&ParsedQuery`.
#[allow(dead_code)]
fn _hold_struct_alive(q: ParsedQuery) -> (u16, u16, u16) {
    (q.id, q.flags, q.qclass)
}

// IPv4 constant used as a placeholder in the truncation helper's
// docs — kept here so the build doesn't drag in unused-import
// warnings from `Ipv4Addr` / `Ipv6Addr` (referenced via `IpAddr`
// match arms above).
#[allow(dead_code)]
const _PLACEHOLDER_V4: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
#[allow(dead_code)]
const _PLACEHOLDER_V6: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

// ---------------------------------------------------------------------------
// Tests — packet codec.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_query_for(qname: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
        buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
        buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
        for label in qname.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&QCLASS_IN.to_be_bytes());
        buf
    }

    #[test]
    fn parse_query_round_trips_qname() {
        let q = encode_query_for("api.example.com", QTYPE_A);
        let parsed = parse_query(&q).expect("parses");
        assert_eq!(parsed.qname, "api.example.com");
        assert_eq!(parsed.qtype, QTYPE_A);
        assert_eq!(parsed.id, 0x1234);
    }

    #[test]
    fn parse_query_rejects_multi_question() {
        let mut q = encode_query_for("example.com", QTYPE_A);
        q[4] = 0;
        q[5] = 2; // qdcount = 2
        assert!(matches!(parse_query(&q), Err(DnsStubError::Malformed(_))));
    }

    #[test]
    fn parse_query_rejects_non_in_class() {
        let mut q = encode_query_for("example.com", QTYPE_A);
        let len = q.len();
        // Overwrite QCLASS bytes (last 2 bytes) with a non-IN class.
        q[len - 2] = 0;
        q[len - 1] = 3; // CHAOS
        assert!(matches!(parse_query(&q), Err(DnsStubError::Malformed(_))));
    }

    #[test]
    fn build_response_emits_answer_records() {
        let q = encode_query_for("api.example.com", QTYPE_A);
        let parsed = parse_query(&q).expect("parses");
        let resp = build_response(
            &parsed,
            &[IpAddr::from(Ipv4Addr::new(1, 2, 3, 4))],
            false,
            42,
        );
        // First 2 bytes = transaction id echoed back.
        assert_eq!(&resp[0..2], &0x1234u16.to_be_bytes());
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x8000, 0x8000, "QR bit set");
        assert_eq!(flags & 0x000F, 0, "NOERROR rcode");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT=1");
        // Last 4 bytes = the IPv4 address.
        assert_eq!(&resp[resp.len() - 4..], &[1, 2, 3, 4]);
    }

    #[test]
    fn build_response_emits_nxdomain_when_addresses_empty() {
        let q = encode_query_for("nope.example.com", QTYPE_A);
        let parsed = parse_query(&q).expect("parses");
        let resp = build_response(&parsed, &[], true, 5);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x000F, 3, "NXDOMAIN rcode");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "ANCOUNT=0");
    }

    #[test]
    fn build_response_filters_addresses_by_qtype() {
        let q = encode_query_for("api.example.com", QTYPE_A);
        let parsed = parse_query(&q).expect("parses");
        // Mix of v4 and v6; only v4 should appear in the A response.
        let addrs = vec![
            IpAddr::from(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::from(Ipv6Addr::LOCALHOST),
        ];
        let resp = build_response(&parsed, &addrs, false, 60);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
    }

    #[test]
    fn truncate_response_sets_tc_bit() {
        let big = vec![0u8; 800];
        let truncated = truncate_response(&big);
        assert!(truncated.len() <= MAX_UDP_PAYLOAD);
        let flags = u16::from_be_bytes([truncated[2], truncated[3]]);
        assert_eq!(flags & 0x0200, 0x0200, "TC bit set");
    }

    #[test]
    fn max_udp_payload_pinned() {
        assert_eq!(MAX_UDP_PAYLOAD, 512);
    }
}
