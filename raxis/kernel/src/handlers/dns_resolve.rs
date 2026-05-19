//! `handlers::dns_resolve` — Path A3 DNS resolution chokepoint.
//!
//! Normative references:
//!   * `specs/v2/airgap-architecture.md §3.2` — DNS wire protocol.
//!   * `specs/invariants.md` — `INV-NETISO-A3-DNS-MEDIATED-01`,
//!     `INV-AUDIT-DNS-RESOLVE-01`.
//!
//! # Lifecycle
//!
//! Called once per `IpcMessage::DnsResolveRequest` frame the in-guest
//! DNS stub forwarder sends over the per-session vsock channel:
//!
//! 1. **Authenticate.** Validate `session_token` against the active
//!    sessions table; mismatch → empty response with a
//!    `DnsResolveRequested` audit row tagged `session_id=""`.
//! 2. **Resolve.** Hand the hostname to `tokio::net::lookup_host` and
//!    filter the resulting `SocketAddr`s by query type (A → IPv4,
//!    AAAA → IPv6). The kernel binds to the host's resolver, never
//!    leaks the host's `/etc/hosts` shape directly — only the IPs
//!    that come out of the standard library's resolver flow back.
//! 3. **Audit.** Emit `DnsResolveRequested { resolved_count, ttl_secs }`
//!    BEFORE the response. Single-class event (DNS itself does not
//!    grant egress — the subsequent tproxy admission does), so this
//!    is observability-only, not a paired-write.
//!
//! # TTL semantics
//!
//! V2 ships a hard-coded 60-second TTL because
//! `tokio::net::lookup_host` doesn't expose record-level TTLs from the
//! OS resolver. Operators tuning DNS caching get the same handle the
//! `[egress.dns]` policy block exposes for the gateway side once that
//! lands; until then 60s is the V2 default mirroring the gateway
//! cache TTL in `specs/v2/v2-deep-spec.md §egress`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use raxis_audit_tools::AuditEventKind;
use raxis_types::{DnsQueryType, DnsResolveRequest, DnsResolveResponse};

use crate::ipc::context::HandlerContext;

/// V2 default cache TTL the kernel tells the guest stub to honour
/// for resolver successes. Mirrors the gateway-side egress cache
/// default; future-proofed by `[egress.dns] ttl_secs` policy field
/// once that wires through.
const DNS_DEFAULT_TTL_SECS: u32 = 60;

/// TTL hint for resolver failures / NXDOMAIN. Short so a
/// transient resolver flap doesn't cache the guest into permanent
/// failure for a real upstream.
const DNS_NEGATIVE_TTL_SECS: u32 = 5;
/// Bound the host resolver call. DNS is on the guest's critical path
/// for almost every raw tool process, so a wedged host resolver must
/// degrade to a short-lived negative answer rather than parking the
/// per-session vsock handler indefinitely.
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolver-side maximum hostname length (matches the DNS wire
/// limit of 255 octets). The guest stub MUST already enforce this
/// — we defence-in-depth here so a malformed
/// `IpcMessage::DnsResolveRequest` doesn't reach `lookup_host`.
const MAX_HOSTNAME_LEN: usize = 255;

/// Handle one DNS resolution request.
///
/// Returns `DnsResolveResponse` for every input. Empty `addresses`
/// vector means "no addresses of the requested family"; the guest
/// stub translates that to a DNS `NOERROR`/NODATA response so an
/// empty AAAA arm does not poison an otherwise valid IPv4 lookup.
pub async fn handle(req: DnsResolveRequest, ctx: &Arc<HandlerContext>) -> DnsResolveResponse {
    // ── Step 1: defence-in-depth hostname validation ──────────────
    if req.hostname.is_empty() || req.hostname.len() > MAX_HOSTNAME_LEN {
        return audit_and_return(ctx, "", &req, Vec::new(), DNS_NEGATIVE_TTL_SECS);
    }

    // ── Step 2: resolve session token ─────────────────────────────
    let session_id = match resolve_session_id(&req.session_token, ctx).await {
        Some(s) => s,
        None => {
            return audit_and_return(ctx, "", &req, Vec::new(), DNS_NEGATIVE_TTL_SECS);
        }
    };

    // ── Step 3: resolve via host stdlib resolver ──────────────────
    //
    // `tokio::net::lookup_host` returns SocketAddrs, so we attach a
    // dummy `:0` port. The resolver returns both A and AAAA records
    // by default; we filter by the requested query type so the guest
    // can implement separate `getaddrinfo` calls for IPv4 / IPv6
    // (the in-guest stub mirrors the standard `nss_dns` behaviour).
    let probe = format!("{}:0", req.hostname);
    let addrs: Vec<IpAddr> =
        match tokio::time::timeout(DNS_LOOKUP_TIMEOUT, tokio::net::lookup_host(probe)).await {
            Ok(Ok(iter)) => iter
                .map(|sa| sa.ip())
                .filter(|ip| query_type_matches(req.query_type, ip))
                .collect(),
            Ok(Err(_)) | Err(_) => Vec::new(),
        };

    // ── Step 4: paired audit BEFORE response (single-class) ───────
    let ttl = if addrs.is_empty() {
        DNS_NEGATIVE_TTL_SECS
    } else {
        DNS_DEFAULT_TTL_SECS
    };
    audit_and_return(ctx, &session_id, &req, addrs, ttl)
}

fn audit_and_return(
    ctx: &Arc<HandlerContext>,
    session_id: &str,
    req: &DnsResolveRequest,
    addresses: Vec<IpAddr>,
    ttl_secs: u32,
) -> DnsResolveResponse {
    let kind = AuditEventKind::DnsResolveRequested {
        session_id: session_id.to_owned(),
        hostname: req.hostname.clone(),
        query_type: match req.query_type {
            DnsQueryType::A => "A".to_owned(),
            DnsQueryType::Aaaa => "AAAA".to_owned(),
        },
        resolved_count: addresses.len() as u32,
        ttl_secs,
    };
    let session_anchor = if session_id.is_empty() {
        None
    } else {
        Some(session_id)
    };
    if let Err(e) = ctx.audit.emit(kind, session_anchor, None, None) {
        // INV-AUDIT-DNS-RESOLVE-01 — emission failure is observable
        // via the operator-facing stderr; we still return the
        // resolved addresses (DNS is observability-only, not a
        // paired-write gate — fail-open here would leak only an
        // audit gap, not a policy decision).
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"DnsResolveRequested\",\
             \"audit_emit_failed\":\"{e}\",\"session_id\":\"{session_id}\"}}"
        );
    }
    DnsResolveResponse {
        request_id: req.request_id,
        addresses,
        ttl_secs,
    }
}

fn query_type_matches(q: DnsQueryType, ip: &IpAddr) -> bool {
    matches!(
        (q, ip),
        (DnsQueryType::A, IpAddr::V4(_)) | (DnsQueryType::Aaaa, IpAddr::V6(_))
    )
}

async fn resolve_session_id(token: &str, ctx: &Arc<HandlerContext>) -> Option<String> {
    let store = Arc::clone(&ctx.store);
    let tok = token.to_owned();
    tokio::task::spawn_blocking(move || {
        crate::authority::session::get_active_session_by_token(&tok, &store)
            .ok()
            .map(|row| row.session_id)
    })
    .await
    .ok()
    .flatten()
}

// ---------------------------------------------------------------------------
// Tests — filtering + wire shape.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn query_type_filter_admits_only_matching_family() {
        let v4: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let v6: IpAddr = Ipv6Addr::LOCALHOST.into();
        assert!(query_type_matches(DnsQueryType::A, &v4));
        assert!(!query_type_matches(DnsQueryType::A, &v6));
        assert!(query_type_matches(DnsQueryType::Aaaa, &v6));
        assert!(!query_type_matches(DnsQueryType::Aaaa, &v4));
    }

    #[test]
    fn default_and_negative_ttls_pinned() {
        // Negative-cache TTL needs to be small enough not to wedge
        // the guest behind a transient resolver flap.
        assert_eq!(DNS_DEFAULT_TTL_SECS, 60);
        assert_eq!(DNS_NEGATIVE_TTL_SECS, 5);
        assert_eq!(DNS_LOOKUP_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn max_hostname_len_matches_rfc1035() {
        // DNS wire format limits hostnames to 255 octets total.
        assert_eq!(MAX_HOSTNAME_LEN, 255);
    }
}
