//! `handlers::tproxy_admit` — Path A3 universal-airgap egress admission.
//!
//! Normative references:
//!   * `specs/v2/airgap-architecture.md §3.1` — wire protocol.
//!   * `specs/invariants.md` — `INV-NETISO-A3-VSOCK-CHOKEPOINT-01`,
//!     `INV-AUDIT-TPROXY-ADMIT-01`.
//!   * `specs/v2/vm-network-isolation.md §3` — legacy Tier-1 admission
//!     contract (this handler is the A3 generalisation that routes the
//!     same admission decision over vsock with paired auditing instead
//!     of a NAT tap with no enforcement).
//!
//! # Lifecycle
//!
//! One `handle()` call per `IpcMessage::TproxyAdmissionRequest` frame
//! the in-guest `raxis-tproxy` sends over the per-session vsock
//! admission channel. The handler:
//!
//! 1. **Authenticates.** Validates `session_token` against the active
//!    sessions table; mismatch → Deny `FAIL_SESSION_TOKEN_MISMATCH`.
//! 2. **Matches policy.** Looks the
//!    `(sni, host_header, destination)` tuple up against the policy
//!    bundle's effective egress allowlist. Operator-declared
//!    `[egress] domains` + `[egress] patterns` + the implicit-provider
//!    grants are all unioned by `PolicyBundle::effective_*` so the A3
//!    admission decision matches the legacy Tier-1 path's decision
//!    byte-for-byte on the host-matching dimension.
//! 3. **Audits BEFORE responding** (paired-write contract per
//!    `INV-AUDIT-TPROXY-ADMIT-01`). Audit emission failure causes the
//!    handler to return Deny with `reason = "FAIL_AUDIT_EMIT"` so the
//!    guest cannot observe an unobserved admission decision.
//! 4. **On Admit, registers a tunnel.** Mints a fresh `(tunnel_id,
//!    tunnel_token)` pair and inserts it into the per-kernel
//!    [`TunnelRegistry`]. The guest's subsequent dial to the kernel
//!    tunnel listener consumes the entry; the listener pairs the
//!    inbound vsock stream with the upstream TCP it opens, and runs
//!    `tokio::io::copy_bidirectional` between them. The tunnel byte
//!    path itself does NOT live in this handler — only the
//!    admission-and-register decision does.
//!
//! # Why this handler is feature-gated
//!
//! `runtime-airgap-a3` is the kernel-side compile-time switch. Without
//! it the module is compiled out entirely so the default-off build is
//! bit-identical to the V2 baseline. Production opt-in is **double**:
//! the feature MUST be compiled in AND the kernel process MUST be
//! launched with `RAXIS_AIRGAP_A3=1`. See
//! `session_spawn_orchestrator::airgap_a3_active` for the runtime
//! gate.

#![cfg(feature = "runtime-airgap-a3")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use raxis_audit_tools::AuditEventKind;
use raxis_types::{TproxyAdmissionRequest, TproxyAdmissionResponse, TproxyProtocol};
use uuid::Uuid;

use crate::authority::session::get_session_by_token;
use crate::ipc::context::HandlerContext;

// ---------------------------------------------------------------------------
// Stable wire-error vocabulary
// ---------------------------------------------------------------------------

/// Short reason strings carried in `TproxyAdmissionResponse::Deny.reason`.
///
/// Mirrors `raxis_tproxy_protocol::DenyReason::as_str` so an audit
/// reader pivoting on the legacy `TransparentProxyDenied.reason`
/// taxonomy keeps working when A3 events join the chain. Adds two
/// kernel-only failure codes that have no legacy analogue:
/// `FAIL_SESSION_TOKEN_MISMATCH` (the legacy chokepoint trusted the
/// vsock device as the auth boundary; A3 carries an explicit token)
/// and `FAIL_AUDIT_EMIT` (paired-write contract failure).
mod reasons {
    pub const HOST_NOT_IN_ALLOWLIST:    &str = "host_not_in_allowlist";
    pub const PROTOCOL_NOT_PERMITTED:   &str = "protocol_not_permitted";
    pub const SESSION_TOKEN_MISMATCH:   &str = "FAIL_SESSION_TOKEN_MISMATCH";
    pub const AUDIT_EMIT_FAILED:        &str = "FAIL_AUDIT_EMIT";
}

// ---------------------------------------------------------------------------
// TunnelRegistry — single-use tunnel handles minted by the admission
// handler and consumed by the tunnel listener.
// ---------------------------------------------------------------------------

/// One registered byte-tunnel handle. Lives in the
/// [`TunnelRegistry`] from the moment the admission handler mints
/// it (just before sending the Admit response) until the guest's
/// subsequent vsock dial on the kernel's tunnel port presents the
/// matching `(tunnel_id, tunnel_token)` pair. Single-use: the
/// tunnel listener removes the entry before opening the upstream
/// socket so a leaked token cannot be replayed.
///
/// **Why `tunnel_token` is 32 bytes.** Cryptographic-strength
/// (256 bits of entropy) — a guess against the registry by a
/// compromised peer guest would need on the order of `2^128`
/// attempts on average, which is well outside any realistic
/// attack budget. The token is minted from
/// `getrandom::getrandom` via `Uuid::new_v4` for the tunnel id
/// (already a UUIDv4) plus a separate 32-byte read for the token.
#[derive(Clone, Debug)]
pub struct RegisteredTunnel {
    /// Destination the kernel committed to opening on the guest's
    /// behalf. The tunnel listener uses this directly — the guest
    /// does NOT get to specify a destination on the tunnel
    /// connection itself.
    pub destination:  SocketAddr,
    /// Single-use token the guest sends in the tunnel-handshake
    /// frame to authenticate against this entry.
    pub tunnel_token: [u8; 32],
    /// Session whose admission produced this tunnel. Recorded so
    /// the tunnel listener can audit the byte-tunnel open against
    /// the same session id the admission was tied to.
    pub session_id:   String,
    /// Hostname / SNI the admission decision matched on, for
    /// audit-correlation purposes only — the tunnel listener does
    /// not re-validate hostname here (the admission already did).
    pub host_or_sni:  Option<String>,
}

/// In-memory single-use tunnel registry. Construct once at kernel
/// boot (one per kernel process), share via `Arc<TunnelRegistry>`
/// to the admission handler and the tunnel listener.
#[derive(Default, Debug)]
pub struct TunnelRegistry {
    by_id: Mutex<HashMap<Uuid, RegisteredTunnel>>,
}

impl TunnelRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_id: Mutex::new(HashMap::new()),
        }
    }

    /// Mint and register one tunnel handle. Returns the
    /// `(tunnel_id, tunnel_token)` pair the admission handler
    /// includes in its Admit response.
    pub fn register(&self, tunnel: RegisteredTunnel) -> (Uuid, [u8; 32]) {
        let tunnel_id = Uuid::new_v4();
        let token = tunnel.tunnel_token;
        self.by_id.lock().insert(tunnel_id, tunnel);
        (tunnel_id, token)
    }

    /// Consume one tunnel handle. The tunnel listener calls this
    /// after reading the handshake frame; returns the registered
    /// destination + session id (or `None` if the handle is
    /// unknown, mismatched, or already consumed). Single-use:
    /// the entry is removed on first match regardless of token
    /// outcome, so a malformed handshake cannot keep the entry
    /// alive for a retry.
    pub fn consume(&self, tunnel_id: Uuid, token: &[u8; 32]) -> Option<RegisteredTunnel> {
        let mut by_id = self.by_id.lock();
        let entry = by_id.remove(&tunnel_id)?;
        if &entry.tunnel_token == token {
            Some(entry)
        } else {
            None
        }
    }

    /// Number of currently-registered tunnels. Test / metrics
    /// helper only.
    pub fn len(&self) -> usize {
        self.by_id.lock().len()
    }

    /// `true` when no tunnels are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Admission handler
// ---------------------------------------------------------------------------

/// Top-level dispatch entry point. Mirrors the
/// [`handlers::planner_fetch::handle`] shape: returns a
/// [`TproxyAdmissionResponse`] for every input (no panics, no
/// early-returns into the dispatch loop) and emits exactly one
/// paired audit event before the response.
///
/// # Test seam
///
/// The `registry` parameter is the per-kernel
/// [`TunnelRegistry`] (shared between the admission handler and
/// the tunnel listener). Tests construct a fresh registry +
/// `HandlerContext` and call `handle` directly to assert wire
/// shapes / audit emissions.
pub async fn handle(
    req: TproxyAdmissionRequest,
    ctx: &Arc<HandlerContext>,
    registry: &Arc<TunnelRegistry>,
) -> TproxyAdmissionResponse {
    let request_id = req.request_id;
    let _started   = Instant::now();

    // ── Step 1: resolve session token → SessionRow ────────────────
    let session = match resolve_session(&req.session_token, ctx).await {
        Some(row) => row,
        None => {
            // No session ⇒ no session_id to anchor the audit row to.
            // We still emit a Denied event with an empty session_id
            // so a forensic reader sees the rejection on the chain
            // (the wire shape requires `session_id: String`, so we
            // pass "" as the canonical "unknown" marker — same
            // convention `handlers::planner_fetch` uses for the
            // mismatch path).
            emit_denied_audit(
                ctx,
                "",
                &req,
                reasons::SESSION_TOKEN_MISMATCH,
            );
            return deny(request_id, reasons::SESSION_TOKEN_MISMATCH, None);
        }
    };

    // ── Step 2: policy lookup ─────────────────────────────────────
    //
    // Match `(sni, host_header)` against the active policy
    // bundle's effective egress allowlist. Falls through to
    // `(destination_ip, port)` raw-TCP matching only when both
    // SNI and Host header are absent. The effective allowlist
    // union (operator-declared + implicit-provider grants) is
    // already computed by `PolicyBundle::effective_egress_*`,
    // matching the legacy Tier-1 chokepoint's decision boundary.
    let host_for_match = req
        .sni
        .as_deref()
        .or(req.host_header.as_deref());

    let allowed = match (req.protocol, host_for_match) {
        // Raw TCP with no observable hostname: admission falls
        // through to IP+port — V2 ships A3 IP-allowlist support
        // disabled, so raw TCP without SNI/Host is denied by
        // default. Operators who want raw-TCP egress declare a
        // credential proxy instead (Tier 2).
        (TproxyProtocol::Tcp, None) => false,
        // Known protocols with a hostname: hostname allowlist match.
        (_, Some(host)) => {
            let policy = ctx.policy.load();
            let domains  = policy.effective_egress_domains();
            let patterns = policy.effective_egress_patterns();
            host_allowed_against_lists(host, &domains, &patterns)
        }
        // TLS / HTTP without a hostname is a protocol violation —
        // the in-guest tproxy is supposed to peek the SNI or Host
        // header before sending the admission request. Deny.
        (_, None) => false,
    };

    if !allowed {
        // Audit BEFORE response. INV-AUDIT-TPROXY-ADMIT-01.
        let audit_ok = emit_denied_audit(
            ctx,
            &session.session_id,
            &req,
            reasons::HOST_NOT_IN_ALLOWLIST,
        );
        if !audit_ok {
            return deny(request_id, reasons::AUDIT_EMIT_FAILED, None);
        }
        return deny(
            request_id,
            reasons::HOST_NOT_IN_ALLOWLIST,
            Some(hint_for_denied_host(host_for_match)),
        );
    }

    // ── Step 3: mint + register a tunnel handle ───────────────────
    let mut tunnel_token = [0u8; 32];
    if let Err(e) = getrandom::getrandom(&mut tunnel_token) {
        // getrandom failing is essentially unreachable in
        // production (every supported host kernel has a working
        // RNG by the time the kernel starts admitting traffic),
        // but the wire-level contract demands a fail-closed Deny
        // rather than a panic. The audit chain captures the
        // failure under the protocol-not-permitted bucket since
        // there is no more specific code; the operator log line
        // surfaces the underlying error.
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"tproxy_admit_rng_failed\",\
             \"session_id\":\"{}\",\"error\":\"{e}\"}}",
            session.session_id,
        );
        let _ = emit_denied_audit(
            ctx,
            &session.session_id,
            &req,
            reasons::PROTOCOL_NOT_PERMITTED,
        );
        return deny(request_id, reasons::PROTOCOL_NOT_PERMITTED, None);
    }

    let (tunnel_id, _token_echo) = registry.register(RegisteredTunnel {
        destination:  req.destination,
        tunnel_token,
        session_id:   session.session_id.clone(),
        host_or_sni:  host_for_match.map(str::to_owned),
    });

    // ── Step 4: paired audit BEFORE response ──────────────────────
    let audit_ok = emit_granted_audit(
        ctx,
        &session.session_id,
        &req,
        host_for_match,
        tunnel_id,
    );
    if !audit_ok {
        // Audit emission failed — fail closed: remove the tunnel
        // we just registered (so the guest cannot consume it on a
        // subsequent dial) and respond Deny.
        let _ = registry.consume(tunnel_id, &tunnel_token);
        return deny(request_id, reasons::AUDIT_EMIT_FAILED, None);
    }

    TproxyAdmissionResponse::Admit {
        request_id,
        tunnel_id,
        tunnel_token,
    }
}

/// Construct a Deny response with the standard wire-shape.
fn deny(request_id: Uuid, reason: &str, hint: Option<String>) -> TproxyAdmissionResponse {
    TproxyAdmissionResponse::Deny {
        request_id,
        reason: reason.to_owned(),
        hint,
    }
}

/// Project the request → `TransparentProxyDenied`-shaped payload
/// and emit. Returns `true` on success so the caller can
/// fail-closed on audit emission failure per
/// `INV-AUDIT-TPROXY-ADMIT-01`.
fn emit_denied_audit(
    ctx:        &Arc<HandlerContext>,
    session_id: &str,
    req:        &TproxyAdmissionRequest,
    reason:     &str,
) -> bool {
    let kind = AuditEventKind::TproxyAdmissionDenied {
        session_id:        session_id.to_owned(),
        host_or_sni:       host_or_sni_for_audit(req),
        original_dst_ip:   req.destination.ip().to_string(),
        original_dst_port: req.destination.port(),
        protocol:          req.protocol.as_str().to_owned(),
        reason:            reason.to_owned(),
    };
    let session_anchor = if session_id.is_empty() {
        None
    } else {
        Some(session_id)
    };
    match ctx.audit.emit(kind, session_anchor, None, None) {
        Ok(_) => true,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"TproxyAdmissionDenied\",\
                 \"audit_emit_failed\":\"{e}\",\"session_id\":\"{session_id}\"}}"
            );
            false
        }
    }
}

/// Project the request → `TproxyAdmissionGranted` payload and
/// emit. Tunnel id is included so a forensic reader can correlate
/// the admission decision with the upstream-socket open audit
/// event the tunnel listener emits later.
fn emit_granted_audit(
    ctx:           &Arc<HandlerContext>,
    session_id:    &str,
    req:           &TproxyAdmissionRequest,
    host_for_match: Option<&str>,
    tunnel_id:     Uuid,
) -> bool {
    let kind = AuditEventKind::TproxyAdmissionGranted {
        session_id:        session_id.to_owned(),
        host_or_sni:       host_for_match.map(str::to_owned),
        original_dst_ip:   req.destination.ip().to_string(),
        original_dst_port: req.destination.port(),
        protocol:          req.protocol.as_str().to_owned(),
        tunnel_id:         tunnel_id.to_string(),
    };
    match ctx.audit.emit(kind, Some(session_id), None, None) {
        Ok(_) => true,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"TproxyAdmissionGranted\",\
                 \"audit_emit_failed\":\"{e}\",\"session_id\":\"{session_id}\"}}"
            );
            false
        }
    }
}

/// Pick the best hostname value for the audit payload:
/// SNI > Host header > none. Mirrors the legacy
/// `TransparentProxyAdmitted.host_or_sni` derivation so the audit
/// chain has a single field semantic across both chokepoints.
fn host_or_sni_for_audit(req: &TproxyAdmissionRequest) -> Option<String> {
    req.sni.clone().or_else(|| req.host_header.clone())
}

/// Hostname allowlist match using the same suffix / prefix /
/// exact rules `raxis-egress-admission::EgressAllowlist::host_is_allowed`
/// applies. Hardcoded here (rather than depending on that crate)
/// to keep the A3 handler crate-graph minimal — the rules are six
/// lines of code and the test pin in this module's tests covers
/// the same cases.
fn host_allowed_against_lists(host: &str, exact: &[String], patterns: &[String]) -> bool {
    let host_l = host.to_ascii_lowercase();
    if exact.iter().any(|h| h.eq_ignore_ascii_case(&host_l)) {
        return true;
    }
    patterns.iter().any(|p| glob_match(p, &host_l))
}

/// Single-`*` glob matcher — must produce identical verdicts to
/// `raxis-egress-admission`'s `glob_match` so the legacy and A3
/// chokepoints never disagree on a host. Tests pin parity.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return value == suffix || value.ends_with(&format!(".{suffix}"));
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return value == prefix || value.starts_with(&format!("{prefix}."));
    }
    pattern == value
}

/// Operator-facing hint for the Deny response. Surfaces in the
/// guest-side tproxy's structured stderr log to help operators
/// figure out what to add to the allowlist without reading the
/// kernel audit chain.
fn hint_for_denied_host(host: Option<&str>) -> String {
    match host {
        Some(h) if !h.is_empty() => format!(
            "add `{h}` (or a matching `*.<suffix>` pattern) to \
             policy `[egress] domains` / `[egress] patterns`",
        ),
        _ => "raw TCP without SNI or Host header is denied; declare \
              a credential proxy for the upstream"
            .to_owned(),
    }
}

async fn resolve_session(
    token: &str,
    ctx:   &Arc<HandlerContext>,
) -> Option<crate::authority::session::SessionRow> {
    let store = Arc::clone(&ctx.store);
    let token_owned = token.to_owned();
    tokio::task::spawn_blocking(move || get_session_by_token(&token_owned, &store).ok())
        .await
        .ok()
        .flatten()
}

// ---------------------------------------------------------------------------
// Tests — wire shapes + tunnel registry semantics.
// Kernel-side end-to-end tests live in `kernel/tests/airgap_a3_*.rs`
// and exercise the full handler against a populated store + audit sink.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_pinned_to_wire_strings() {
        // Audit dashboards / forensic tools key on these strings.
        // A typo'd reason silently misroutes alerts; pin them.
        assert_eq!(reasons::HOST_NOT_IN_ALLOWLIST,  "host_not_in_allowlist");
        assert_eq!(reasons::PROTOCOL_NOT_PERMITTED, "protocol_not_permitted");
        assert_eq!(reasons::SESSION_TOKEN_MISMATCH, "FAIL_SESSION_TOKEN_MISMATCH");
        assert_eq!(reasons::AUDIT_EMIT_FAILED,      "FAIL_AUDIT_EMIT");
    }

    #[test]
    fn host_match_exact_case_insensitive() {
        let exact = vec!["api.anthropic.com".to_owned()];
        let patterns: Vec<String> = vec![];
        assert!(host_allowed_against_lists("api.anthropic.com", &exact, &patterns));
        assert!(host_allowed_against_lists("API.ANTHROPIC.com", &exact, &patterns));
        assert!(!host_allowed_against_lists("evil.example.com", &exact, &patterns));
    }

    #[test]
    fn host_match_suffix_pattern() {
        let exact: Vec<String> = vec![];
        let patterns = vec!["*.anthropic.com".to_owned()];
        assert!(host_allowed_against_lists("api.anthropic.com", &exact, &patterns));
        assert!(host_allowed_against_lists("staging.api.anthropic.com", &exact, &patterns));
        assert!(host_allowed_against_lists("anthropic.com", &exact, &patterns));
        assert!(!host_allowed_against_lists("anthropic-evil.com", &exact, &patterns));
    }

    #[test]
    fn host_match_prefix_pattern() {
        let exact: Vec<String> = vec![];
        let patterns = vec!["registry.*".to_owned()];
        assert!(host_allowed_against_lists("registry.npmjs.org", &exact, &patterns));
        assert!(host_allowed_against_lists("registry", &exact, &patterns));
        assert!(!host_allowed_against_lists("evil-registry.com", &exact, &patterns));
    }

    #[test]
    fn host_match_wildcard_admits_all() {
        let exact: Vec<String> = vec![];
        let patterns = vec!["*".to_owned()];
        assert!(host_allowed_against_lists("anything.example.com", &exact, &patterns));
        assert!(host_allowed_against_lists("evil.example", &exact, &patterns));
    }

    #[test]
    fn tunnel_registry_register_then_consume_round_trip() {
        let reg = TunnelRegistry::new();
        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let tunnel = RegisteredTunnel {
            destination:  dst,
            tunnel_token: [0x7Au8; 32],
            session_id:   "sess".to_owned(),
            host_or_sni:  Some("api.example.com".to_owned()),
        };
        let (id, token) = reg.register(tunnel);
        assert_eq!(reg.len(), 1);
        let consumed = reg.consume(id, &token).expect("token matches");
        assert_eq!(consumed.destination, dst);
        assert_eq!(consumed.session_id, "sess");
        assert!(reg.is_empty(), "single-use: entry removed on consume");
    }

    #[test]
    fn tunnel_registry_consume_with_wrong_token_returns_none() {
        let reg = TunnelRegistry::new();
        let (id, _token) = reg.register(RegisteredTunnel {
            destination:  "1.2.3.4:443".parse().unwrap(),
            tunnel_token: [0xAAu8; 32],
            session_id:   "sess".to_owned(),
            host_or_sni:  None,
        });
        // Single-use: an attacker presenting the wrong token still
        // removes the entry (so the legitimate guest can't dial in
        // either — INV-AUDIT-TPROXY-ADMIT-01 fail-closed bias).
        let mismatch = reg.consume(id, &[0xFFu8; 32]);
        assert!(mismatch.is_none());
        assert!(reg.is_empty());
        // A second attempt with the real token also gets None.
        let after = reg.consume(id, &[0xAAu8; 32]);
        assert!(after.is_none());
    }

    #[test]
    fn tunnel_registry_consume_unknown_id_returns_none() {
        let reg = TunnelRegistry::new();
        let unknown = reg.consume(Uuid::new_v4(), &[0u8; 32]);
        assert!(unknown.is_none());
    }

    #[test]
    fn host_or_sni_for_audit_prefers_sni_over_host_header() {
        let req = TproxyAdmissionRequest {
            request_id:    Uuid::nil(),
            session_token: "tok".to_owned(),
            sni:           Some("sni.example.com".to_owned()),
            host_header:   Some("host.example.com".to_owned()),
            destination:   "1.2.3.4:443".parse().unwrap(),
            protocol:      TproxyProtocol::Tls,
        };
        assert_eq!(host_or_sni_for_audit(&req).as_deref(), Some("sni.example.com"));
    }

    #[test]
    fn host_or_sni_for_audit_falls_back_to_host_header() {
        let req = TproxyAdmissionRequest {
            request_id:    Uuid::nil(),
            session_token: "tok".to_owned(),
            sni:           None,
            host_header:   Some("host.example.com".to_owned()),
            destination:   "1.2.3.4:80".parse().unwrap(),
            protocol:      TproxyProtocol::Http,
        };
        assert_eq!(host_or_sni_for_audit(&req).as_deref(), Some("host.example.com"));
    }

    #[test]
    fn host_or_sni_for_audit_is_none_when_neither_present() {
        let req = TproxyAdmissionRequest {
            request_id:    Uuid::nil(),
            session_token: "tok".to_owned(),
            sni:           None,
            host_header:   None,
            destination:   "1.2.3.4:443".parse().unwrap(),
            protocol:      TproxyProtocol::Tcp,
        };
        assert!(host_or_sni_for_audit(&req).is_none());
    }
}
