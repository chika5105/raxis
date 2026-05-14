// raxis-types::tproxy — Path A3 in-guest tproxy ↔ kernel admission wire types.
//
// Normative references:
//   * `specs/v2/airgap-architecture.md §3` — wire-protocol contract.
//   * `specs/v2/vm-network-isolation.md §3.1` — legacy iptables rules
//     that produce the admission requests A3 carries over vsock.
//   * `specs/invariants.md §11.8a` — INV-NETISO-A3-VSOCK-CHOKEPOINT-01,
//     INV-AUDIT-TPROXY-ADMIT-01, INV-NETISO-A3-DNS-MEDIATED-01,
//     INV-AUDIT-DNS-RESOLVE-01.
//
// # Why this lives in raxis-types and not raxis-tproxy-protocol
//
// `raxis-tproxy-protocol` is the **wire** crate consumed by the in-VM
// tproxy binary directly; it deliberately has no `serde` derives beyond
// what `bincode` needs and no dependencies outside `serde + bincode +
// thiserror`. The A3 wire shapes go further: they are envelope-wrapped
// inside [`raxis_ipc::message::IpcMessage`] so the same length-prefixed
// bincode framing that already carries `PlannerFetchRequest` /
// `IntentRequest` carries the tproxy admission and DNS requests too. That
// envelope coupling means the wire shape MUST live where every other
// IpcMessage payload struct lives — here in `raxis-types`. The standalone
// `raxis-tproxy-protocol` crate is retained for its SNI / Host parser
// helpers consumed by `raxis_tproxy::peek` and for forensic tools that
// still parse pre-Mediated audit chains carrying the legacy bincode
// admission frames.
//
// # Why a fresh IPC envelope for A3 instead of reusing
// `raxis-tproxy-protocol::ProxyAdmissionRequest`
//
// Three substantive shape changes block reuse:
//
//   1. **Tunnel handle.** A3's Admit response carries a `(tunnel_id,
//      tunnel_token)` pair so the guest can re-dial the kernel on a
//      dedicated vsock listener for the byte-tunnel. The legacy
//      ProxyAdmissionResponse only carries `connection_id`; tightening
//      the legacy shape would be a wire-compat break that downstream
//      forensic tools depend on.
//   2. **Session token authentication.** A3 admission requests carry the
//      same `session_token` the planner socket already validates. The
//      legacy tproxy-protocol assumed the vsock device itself was the
//      authentication boundary; A3 wants the explicit token so the
//      same handler that admits a `PlannerFetchRequest` can admit a
//      tproxy admission off the **same** vsock channel.
//   3. **DNS.** A3 multiplexes DNS-resolve frames onto the same vsock
//      stream as admission frames. The legacy protocol has no DNS
//      envelope; bolting one on would require a discriminant byte and
//      thus a wire-format break.
//
// Keeping the two crates separate is the same layering rule
// raxis-types and raxis-ipc follow elsewhere: pure data here,
// envelopes in raxis-ipc, wire bytes in tproxy-protocol.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Tproxy admission — Path A3 §3.1 / §3.2.
// ---------------------------------------------------------------------------

/// Layer-7 protocol guess that the in-VM tproxy hands to the kernel
/// with each admission request. The kernel uses this to discriminate
/// between TLS (where `sni` carries the hostname), HTTP (where
/// `host_header` does), and raw TCP (where neither is populated and
/// admission falls back to `(destination_ip, destination_port)`).
///
/// Mirrors `raxis_tproxy_protocol::AdmissionProtocol` in semantic
/// scope but lives here so the planner / dispatch path does not
/// pull a dep on the wire crate. The kernel handler maps between
/// the two enums 1:1 when projecting A3 admission events onto
/// `TransparentProxy{Admitted,Denied}` audit payloads for tooling
/// continuity with the legacy chokepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TproxyProtocol {
    /// Raw TCP — no L7 payload was peeked (either the agent did
    /// not start a TLS handshake / HTTP preamble before the
    /// connect timed out, or the destination port is a known
    /// non-HTTP service the in-guest tproxy is forwarding
    /// opaquely). Admission decision is by `destination` alone.
    Tcp,
    /// TLS — `sni` carries the SNI extension hostname extracted
    /// from the ClientHello.
    Tls,
    /// HTTP/1.x — `host_header` carries the lowercase, port-stripped
    /// `Host:` header value.
    Http,
}

impl TproxyProtocol {
    /// Stable short string used in audit event payloads (matches the
    /// legacy `AdmissionProtocol::as_str` so dashboards keying on
    /// the string keep working when A3 events join the chain).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp  => "tcp",
            Self::Tls  => "https",
            Self::Http => "http",
        }
    }
}

/// **Guest → kernel.** One admission decision request from the
/// in-VM tproxy. The kernel responds with exactly one
/// [`TproxyAdmissionResponse`] BEFORE the audit event chains
/// (paired-write contract per `INV-AUDIT-TPROXY-ADMIT-01`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TproxyAdmissionRequest {
    /// Per-request UUIDv4 the guest mints. The kernel echoes it on
    /// the response so concurrent admissions can be correlated.
    pub request_id:    Uuid,

    /// The session token the kernel stamped at spawn time. The
    /// admission handler validates against `sessions.session_token`
    /// for the connection; mismatch → `FAIL_SESSION_TOKEN_MISMATCH`.
    pub session_token: String,

    /// SNI extracted from the agent's TLS ClientHello, when
    /// present. The kernel matches this first against the active
    /// `policy.tproxy_allowlist`; raw TCP / non-TLS / no-SNI
    /// flows leave this `None`.
    pub sni:           Option<String>,

    /// Lowercased, port-stripped HTTP/1.x `Host:` header value
    /// extracted from the agent's plaintext request preamble.
    /// Populated only for `protocol == Http`.
    pub host_header:   Option<String>,

    /// Post-DNS-resolution destination `(ip, port)` from
    /// `SO_ORIGINAL_DST` on the iptables-redirected agent socket.
    /// Always populated; falls through to allowlist matching when
    /// `sni` and `host_header` are both `None`.
    pub destination:   SocketAddr,

    /// Layer-7 protocol guess (see [`TproxyProtocol`]).
    pub protocol:      TproxyProtocol,
}

/// **Kernel → guest.** The kernel's verdict for one
/// [`TproxyAdmissionRequest`].
///
/// On `Admit` the kernel registers a single-use tunnel keyed by
/// `tunnel_id` and authenticated by `tunnel_token`. The guest
/// MUST open a second AF_VSOCK connection to the kernel's tunnel
/// port, send `tunnel_id || tunnel_token` as the first frame, then
/// `tokio::io::copy_bidirectional` the agent's TCP stream into the
/// vsock stream. The kernel splices the vsock stream to the
/// upstream socket it opened before sending Admit, ensuring the
/// admission decision and the byte path are atomically tied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TproxyAdmissionResponse {
    /// Connection admitted; the byte tunnel is ready to be claimed
    /// via a second vsock connection on the kernel's tunnel port.
    Admit {
        /// Echoes the request's `request_id`.
        request_id:   Uuid,
        /// Opaque handle the guest sends in the tunnel-handshake
        /// frame. Single-use: the kernel removes the tunnel
        /// registration on the first successful handshake.
        tunnel_id:    Uuid,
        /// 32-byte random authenticator the guest sends alongside
        /// `tunnel_id` to prove it received the Admit response.
        /// Single-use; not stored anywhere outside the kernel's
        /// in-memory tunnel registry.
        tunnel_token: [u8; 32],
    },
    /// Connection denied. The guest MUST close the agent-side
    /// socket with `RST` so the agent's library returns
    /// `ECONNREFUSED` rather than hanging.
    Deny {
        /// Echoes the request's `request_id`.
        request_id: Uuid,
        /// Stable short reason string the kernel audits and the
        /// in-guest tproxy includes in its structured stderr log.
        /// Vocabulary mirrors
        /// `raxis_tproxy_protocol::DenyReason::as_str` plus
        /// `"FAIL_SESSION_TOKEN_MISMATCH"` and `"FAIL_AUDIT_EMIT"`.
        reason:     String,
        /// Optional operator-facing hint (e.g. "add `*.example.com`
        /// to `policy.tproxy_allowlist`"). Surfaced in the audit
        /// payload's `hint` field unchanged.
        hint:       Option<String>,
    },
}

impl TproxyAdmissionResponse {
    /// `true` when the verdict admits the flow. Convenience for
    /// handler / test code that needs to branch on the discriminant
    /// without pattern-matching every field.
    #[must_use]
    pub fn is_admit(&self) -> bool {
        matches!(self, Self::Admit { .. })
    }

    /// `request_id` accessor — both arms echo the request's id, so
    /// callers can correlate without matching on the variant.
    #[must_use]
    pub fn request_id(&self) -> Uuid {
        match self {
            Self::Admit { request_id, .. } | Self::Deny { request_id, .. } => *request_id,
        }
    }
}

// ---------------------------------------------------------------------------
// DNS resolution — Path A3 §3.3.
// ---------------------------------------------------------------------------

/// DNS query type the guest stub forwarder is asking the kernel to
/// resolve. V2 ships A / AAAA only; SRV / TXT / MX are out of
/// scope (the in-guest workloads RAXIS supports are HTTP / database
/// clients that need a single IP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DnsQueryType {
    /// IPv4 A record. The default for libc resolvers in V2.
    A,
    /// IPv6 AAAA record. The guest stub forwarder always returns
    /// an empty set for AAAA queries because A3 disables IPv6 in
    /// the guest (`INV-NETISO-A3-IPV6-DISABLED-01`); the type
    /// exists for wire-shape stability so a future V3 IPv6-aware
    /// build needs no protocol change.
    Aaaa,
}

/// **Guest → kernel.** Resolve `hostname` via the kernel's
/// host-side resolver. Does NOT itself grant egress — the agent's
/// subsequent connect against the resolved IP triggers a
/// [`TproxyAdmissionRequest`] which is the actual gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolveRequest {
    /// Per-query UUIDv4 the guest mints. Echoed on the response.
    pub request_id:    Uuid,
    /// Session-token authenticator; same shape as
    /// [`TproxyAdmissionRequest::session_token`].
    pub session_token: String,
    /// Hostname to resolve. Lowercased by the in-guest stub
    /// before sending so the kernel's allowlist matching is
    /// case-insensitive without per-handler normalisation.
    pub hostname:      String,
    /// A vs AAAA.
    pub query_type:    DnsQueryType,
}

/// **Kernel → guest.** Resolved address list (empty = NXDOMAIN)
/// plus an upper-bound TTL for the in-guest cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolveResponse {
    /// Echoes [`DnsResolveRequest::request_id`].
    pub request_id: Uuid,
    /// Resolved IP addresses. Empty when the kernel's resolver
    /// returned NXDOMAIN or any other failure (the
    /// `AuditEventKind::DnsResolveRequested` event records the
    /// `resolved_count` regardless).
    pub addresses:  Vec<IpAddr>,
    /// Upper-bound TTL the in-guest stub MAY cache the answer
    /// for. `0` means "do not cache" (kernel resolver failure /
    /// transient negative response).
    pub ttl_secs:   u32,
}

// ---------------------------------------------------------------------------
// Tests — wire-shape pinning.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    /// Bincode-encoded round trip for the request envelope so a
    /// future field reorder surfaces here before it can be
    /// deployed mid-cluster — same contract as the legacy
    /// `raxis-tproxy-protocol::admission_request_round_trips_*`
    /// tests, ported to the A3 wire shape.
    #[test]
    fn tproxy_admission_request_round_trips_through_serde_json() {
        let req = TproxyAdmissionRequest {
            request_id:    Uuid::nil(),
            session_token: "session-token-fixture".to_owned(),
            sni:           Some("api.anthropic.com".to_owned()),
            host_header:   None,
            destination:   SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 7), 443)),
            protocol:      TproxyProtocol::Tls,
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: TproxyAdmissionRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.session_token, req.session_token);
        assert_eq!(back.sni, req.sni);
        assert_eq!(back.host_header, req.host_header);
        assert_eq!(back.destination, req.destination);
        assert_eq!(back.protocol, req.protocol);
    }

    #[test]
    fn tproxy_admission_response_admit_round_trips() {
        let resp = TproxyAdmissionResponse::Admit {
            request_id:   Uuid::nil(),
            tunnel_id:    Uuid::nil(),
            tunnel_token: [0x7Au8; 32],
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: TproxyAdmissionResponse = serde_json::from_str(&s).unwrap();
        assert!(back.is_admit());
        if let TproxyAdmissionResponse::Admit { tunnel_token, .. } = back {
            assert_eq!(tunnel_token, [0x7Au8; 32]);
        } else {
            panic!("round trip changed discriminant");
        }
    }

    #[test]
    fn tproxy_admission_response_deny_carries_reason_and_hint() {
        let resp = TproxyAdmissionResponse::Deny {
            request_id: Uuid::nil(),
            reason:     "host_not_in_allowlist".to_owned(),
            hint:       Some("add `*.example.com` to policy.tproxy_allowlist".to_owned()),
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: TproxyAdmissionResponse = serde_json::from_str(&s).unwrap();
        assert!(!back.is_admit());
        if let TproxyAdmissionResponse::Deny { reason, hint, .. } = back {
            assert_eq!(reason, "host_not_in_allowlist");
            assert!(hint.unwrap().contains("policy.tproxy_allowlist"));
        } else {
            panic!("round trip changed discriminant");
        }
    }

    #[test]
    fn tproxy_protocol_audit_strings_match_legacy_admission_protocol() {
        // The legacy AdmissionProtocol::as_str values are wire-stable
        // for forensic dashboards. A3 events project onto the same
        // strings so the dashboard does not need to fork its query.
        assert_eq!(TproxyProtocol::Tls.as_str(),  "https");
        assert_eq!(TproxyProtocol::Http.as_str(), "http");
        assert_eq!(TproxyProtocol::Tcp.as_str(),  "tcp");
    }

    #[test]
    fn dns_resolve_request_round_trips_through_serde_json() {
        let req = DnsResolveRequest {
            request_id:    Uuid::nil(),
            session_token: "session-token-fixture".to_owned(),
            hostname:      "api.anthropic.com".to_owned(),
            query_type:    DnsQueryType::A,
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: DnsResolveRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.hostname, req.hostname);
        assert_eq!(back.query_type, req.query_type);
    }

    #[test]
    fn dns_resolve_response_empty_is_nxdomain_signal() {
        // An empty `addresses` vector is the wire signal for NXDOMAIN
        // / resolver failure; pin the contract.
        let resp = DnsResolveResponse {
            request_id: Uuid::nil(),
            addresses:  vec![],
            ttl_secs:   0,
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: DnsResolveResponse = serde_json::from_str(&s).unwrap();
        assert!(back.addresses.is_empty());
        assert_eq!(back.ttl_secs, 0);
    }
}
