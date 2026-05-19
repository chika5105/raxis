//! `raxis-egress-admission` — kernel-side admission service for the
//! V2 Tier 1 transparent egress proxy (`raxis-tproxy`).
//!
//! Normative reference: `specs/v2/vm-network-isolation.md §3-§5`.
//!
//! # What ships here
//!
//! Three pieces, kept in one tiny crate so the kernel can wire all
//! three at boot:
//!
//! 1. [`AdmissionDecision`] / [`AdmissionVerdict`] — the kernel's
//!    pure decision function over a [`ProxyAdmissionRequest`] and a
//!    snapshot of the policy's allowlist (plus, eventually, the
//!    active task's per-task `allowed_egress` list).
//!
//! 2. [`PolicyAdmissionService`] — a concrete `AdmissionService`
//!    impl that pulls the allowlist from a `PolicyView`-shaped
//!    snapshot. The kernel constructs one per session at VM boot,
//!    handing in the `Arc<ArcSwap<PolicyBundle>>` and the
//!    per-session task allowlist.
//!
//! 3. [`run_admission_loop`] — drives the bincode-framed request
//!    /response protocol over an arbitrary `tokio::io::AsyncRead +
//!    AsyncWrite` duplex. The same code drives a vsock channel in
//!    production and a loopback Unix or TCP socket in integration
//!    tests, so the loop logic itself is exercised against real
//!    bytes without needing a VM.
//!
//! Audit emission is performed by the loop AFTER the verdict is
//! sent back to the proxy — same audit-after-state-mutation order
//! used by the kernel's IPC handlers (`kernel-store.md §2.5.2`).

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod stall_tracker;

pub use stall_tracker::{
    Clock, EgressStallTracker, StallEmission, StallSignal, SystemClock, DEFAULT_THRESHOLD,
    DEFAULT_WINDOW,
};

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use raxis_audit_tools::{AuditEventKind, AuditSink, AuditWriterError};
use raxis_observability::{redact, MetricName, ObservabilityHub};
use raxis_tproxy_protocol::{
    decode_request, encode_response, AdmissionProtocol, DenyReason, FrameError,
    ProxyAdmissionRequest, ProxyAdmissionResponse,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// iter61 — `INV-OBSERVABILITY-DATAPLANE-LATENCY-06` per-verdict histogram.
// ---------------------------------------------------------------------------
//
// Closed lexicon mirrored from
// `kernel/src/observability.rs::GATEWAY_STAGES`. The admission
// loop only ever emits the `tproxy_admit` stage; the other three
// (`dns`, `tls`, `first_byte`) live behind the gateway-subprocess
// wire boundary and ship in a follow-up commit.
const GATEWAY_STAGE_TPROXY_ADMIT: &str = "tproxy_admit";
const TPROXY_ADMIT_OUTCOME_OK: &str = "ok";
const TPROXY_ADMIT_OUTCOME_DENIED: &str = "denied";
/// Deny verdicts have no upstream provider — the proxy admit
/// decision is the final stop on the path. We tag them with a
/// canonical `tproxy` provider so the dashboard pivots stay
/// total against the closed lexicon.
const TPROXY_PROVIDER_LABEL: &str = "tproxy";

/// Process-global `ObservabilityHub` handle the admission loop's
/// per-verdict timer consults. Mirrors `raxis-ipc::frame` and
/// `raxis-worktree-provision` — set once at kernel boot via
/// [`set_global_observability_hub`], unset by default so kernel-
/// less CLI tools, planner-side fixtures, and the standalone
/// admission round-trip integration tests pay zero per-verdict
/// overhead.
static OBSERVABILITY_HUB: OnceLock<Arc<ObservabilityHub>> = OnceLock::new();

/// Wire the process-global observability hub the admission loop
/// emits `raxis.gateway.stage.duration` samples to. Idempotent —
/// a second call is a no-op (`OnceLock::set` returns `Err`,
/// which we discard so re-entrant test boots don't panic).
pub fn set_global_observability_hub(hub: Arc<ObservabilityHub>) {
    let _ = OBSERVABILITY_HUB.set(hub);
}

/// Emit one `raxis.gateway.stage.duration` histogram observation
/// tagged `stage="tproxy_admit"` + the per-verdict outcome (`ok`
/// for Admit, `denied` for Deny). Hub-disabled fast path early-
/// returns on the `OnceLock::get()` arm — zero per-verdict
/// overhead.
fn record_tproxy_admit_stage(outcome: &str, duration_ms: i64) {
    let Some(hub) = OBSERVABILITY_HUB.get() else {
        return;
    };
    if !hub.enabled() {
        return;
    }
    let labels = redact::attrs([
        ("provider", TPROXY_PROVIDER_LABEL),
        ("stage", GATEWAY_STAGE_TPROXY_ADMIT),
        ("outcome", outcome),
    ]);
    hub.record_histogram(
        MetricName::GatewayStageDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// One admission verdict + the bookkeeping the kernel needs to
/// emit the matching audit event. Returned by
/// [`AdmissionService::admit`] and consumed by [`run_admission_loop`].
#[derive(Debug, Clone)]
pub struct AdmissionDecision {
    /// Echo of the request's `connection_id`.
    pub connection_id: u64,
    /// Admit or Deny verdict. Deny carries the structured reason
    /// the proxy will surface as `ECONNREFUSED` to the agent and
    /// the kernel will record in the audit chain.
    pub verdict: AdmissionVerdict,
}

/// Either Admit or Deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionVerdict {
    /// Agent's outbound connection is admitted.
    Admit,
    /// Agent's outbound connection is denied.
    Deny(DenyReason),
}

impl AdmissionDecision {
    /// Translate the decision into the wire-protocol response.
    pub fn to_response(&self) -> ProxyAdmissionResponse {
        match &self.verdict {
            AdmissionVerdict::Admit => ProxyAdmissionResponse::Admit {
                connection_id: self.connection_id,
            },
            AdmissionVerdict::Deny(reason) => ProxyAdmissionResponse::Deny {
                connection_id: self.connection_id,
                reason: *reason,
            },
        }
    }

    /// Convenience: was this an admit verdict?
    pub fn is_admit(&self) -> bool {
        matches!(self.verdict, AdmissionVerdict::Admit)
    }
}

// ---------------------------------------------------------------------------
// AdmissionService trait
// ---------------------------------------------------------------------------

/// Pluggable seam: the kernel's per-session decision policy. Tests
/// implement a deterministic `Vec<AdmissionDecision>` queue;
/// production wires [`PolicyAdmissionService`] over the active
/// `PolicyBundle`.
///
/// The trait is sync because admission is CPU-only — no I/O, no
/// store calls. The decision function consults already-loaded
/// in-memory state.
pub trait AdmissionService: Send + Sync + 'static {
    /// Decide on one admission request. The supplied
    /// `session_id` is the per-VM session that originated the
    /// request — used in the resulting audit event.
    fn admit(&self, session_id: &str, request: &ProxyAdmissionRequest) -> AdmissionDecision;
}

// ---------------------------------------------------------------------------
// Allowlist matching
// ---------------------------------------------------------------------------

/// Snapshot of the egress allowlist the admission service consults.
/// Built from `policy.toml [egress]` + the active task's
/// `[[tasks.allowed_egress]]` (when V2's per-task list is wired
/// through; for now the kernel passes the global allowlist only).
#[derive(Debug, Clone, Default)]
pub struct EgressAllowlist {
    /// Exact-match host names. Hostname comparison is case-
    /// insensitive at match time (we lower-case the SNI before
    /// matching).
    pub exact_hosts: Vec<String>,
    /// Glob patterns from `[egress] patterns`. Currently we
    /// support `*` (anything), `*.example.com` (suffix), and
    /// `example.*` (prefix) — same shapes the gateway's
    /// `policy_view::glob_match` accepts.
    pub patterns: Vec<String>,
    /// Hostnames + ports that match a credential-proxy
    /// `real_target` and MUST be denied with `proxy_target_bypass`.
    /// Empty until the credential-proxy plumbing lands; safe
    /// default — admission then falls through to the regular
    /// allowlist check.
    pub credential_proxy_real_targets: HashSet<(String, u16)>,
}

impl EgressAllowlist {
    /// Returns true iff the host is in the exact-match list OR
    /// matches one of the glob patterns. Case-insensitive.
    pub fn host_is_allowed(&self, host: &str) -> bool {
        let host_l = host.to_ascii_lowercase();
        if self
            .exact_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&host_l))
        {
            return true;
        }
        self.patterns.iter().any(|p| glob_match(p, &host_l))
    }

    /// Returns true iff the host+port matches a credential-proxy
    /// real target — used to detect bypass attempts.
    pub fn is_credential_proxy_real_target(&self, host: &str, port: u16) -> bool {
        let host_l = host.to_ascii_lowercase();
        self.credential_proxy_real_targets
            .iter()
            .any(|(h, p)| *p == port && h.eq_ignore_ascii_case(&host_l))
    }
}

/// Single-`*` glob matcher. Mirrors the gateway's
/// `policy_view::glob_match` so V2's two-tier egress (Tier 1 here,
/// Tier 2 in the gateway) uses identical match semantics.
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

// ---------------------------------------------------------------------------
// PolicyAdmissionService — production impl
// ---------------------------------------------------------------------------

/// Production [`AdmissionService`] backed by an
/// [`EgressAllowlist`]. Constructed at session boot with the
/// allowlist snapshot the kernel has already validated.
pub struct PolicyAdmissionService {
    allowlist: EgressAllowlist,
    /// Whitelisted ports (the iptables rules redirect 80, 443,
    /// 5432, 3306, 1433, 27017, 6379). Anything outside this
    /// set produces `port_not_redirected` — defence in depth
    /// against a misconfigured iptables ruleset.
    redirected_ports: HashSet<u16>,
}

impl PolicyAdmissionService {
    /// Build a service with the allowlist from the active policy
    /// (combined with the task entry). The redirected-port set
    /// defaults to the canonical V2 list from
    /// `vm-network-isolation.md §3.1` and can be overridden via
    /// [`Self::with_redirected_ports`] for tests.
    pub fn new(allowlist: EgressAllowlist) -> Self {
        Self {
            allowlist,
            redirected_ports: default_redirected_ports(),
        }
    }

    /// Override the iptables-redirected port set. Tests use this
    /// when exercising negative paths against an exotic port.
    pub fn with_redirected_ports(mut self, ports: HashSet<u16>) -> Self {
        self.redirected_ports = ports;
        self
    }
}

fn default_redirected_ports() -> HashSet<u16> {
    [80, 443, 5432, 3306, 1433, 27017, 6379]
        .into_iter()
        .collect()
}

impl AdmissionService for PolicyAdmissionService {
    fn admit(&self, _session_id: &str, request: &ProxyAdmissionRequest) -> AdmissionDecision {
        // Defence-in-depth: drop traffic on ports we wouldn't
        // expect to be iptables-redirected.
        if !self.redirected_ports.contains(&request.original_dst_port) {
            return AdmissionDecision {
                connection_id: request.connection_id,
                verdict: AdmissionVerdict::Deny(DenyReason::PortNotRedirected),
            };
        }

        // Database-bypass detection — `vm-network-isolation.md §5`.
        // Match BEFORE the allowlist so a host that would
        // otherwise be allowed at the SNI layer cannot reach
        // a real database hostname directly.
        let host_for_check = request
            .host_or_sni
            .as_deref()
            .unwrap_or(&request.original_dst_ip);
        if self
            .allowlist
            .is_credential_proxy_real_target(host_for_check, request.original_dst_port)
        {
            return AdmissionDecision {
                connection_id: request.connection_id,
                verdict: AdmissionVerdict::Deny(DenyReason::ProxyTargetBypass),
            };
        }

        // Raw TCP without any host_or_sni cannot be admitted by
        // hostname — defence in depth: deny.
        let host_match = match (&request.protocol, &request.host_or_sni) {
            (AdmissionProtocol::Tcp, None) => false,
            (_, Some(host)) => self.allowlist.host_is_allowed(host),
            (_, None) => false,
        };

        if host_match {
            AdmissionDecision {
                connection_id: request.connection_id,
                verdict: AdmissionVerdict::Admit,
            }
        } else {
            AdmissionDecision {
                connection_id: request.connection_id,
                verdict: AdmissionVerdict::Deny(DenyReason::HostNotInAllowlist),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Admission loop (drives the wire protocol over any AsyncRead+AsyncWrite)
// ---------------------------------------------------------------------------

/// Errors from `run_admission_loop`.
#[derive(Debug, Error)]
pub enum LoopError {
    /// Underlying transport read or write returned an `io::Error`.
    #[error("transport i/o: {0}")]
    Io(#[from] std::io::Error),
    /// Bincode framing error — malformed request or oversize.
    #[error("framing: {0}")]
    Frame(#[from] FrameError),
    /// Audit emission failed — the kernel treats this as fatal
    /// per `R-7`. Surfaced here so the supervising session
    /// teardown can react (e.g. tear the VM down).
    #[error("audit emission: {0}")]
    Audit(#[from] AuditWriterError),
}

/// Drive one admission session. The loop reads
/// `ProxyAdmissionRequest`s from `reader`, hands each to the
/// `AdmissionService`, writes the matching
/// `ProxyAdmissionResponse` back through `writer`, and emits one
/// `TransparentProxyAdmitted` / `TransparentProxyDenied` audit
/// event per decision.
///
/// Returns when the reader returns EOF or any frame fails to
/// decode. The kernel's session-teardown path is responsible for
/// closing the underlying transport — this function does not.
///
/// Tier-1 backwards-compat shim — equivalent to
/// [`run_admission_loop_with_stall_tracker`] with `stall_tracker
/// = None`. Existing callers keep their signature; new callers
/// (the kernel admission supervisor) use the
/// `_with_stall_tracker` variant to opt into V2
/// `SessionEgressStallDetected` emission.
pub async fn run_admission_loop<R, W, S>(
    reader: R,
    writer: W,
    service: Arc<S>,
    audit: Arc<dyn AuditSink>,
    session_id: String,
) -> Result<(), LoopError>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
    S: AdmissionService + ?Sized,
{
    run_admission_loop_with_stall_tracker(reader, writer, service, audit, session_id, None).await
}

/// V2 reviewer-egress-defaults-decision.md §7 — admission loop
/// extended with optional `EgressStallTracker` integration. When
/// `stall_tracker` is `Some`, every `Deny` verdict is also fed
/// through the tracker; if the bucket trips the configured
/// threshold inside the configured window, the loop emits ONE
/// extra `SessionEgressStallDetected` audit event tagged
/// `source = "tproxy"`. Stall emit failures are logged but do
/// not unwind the admission decision (the decision was already
/// sent to the agent and the underlying `TransparentProxyDenied`
/// is the authoritative record).
pub async fn run_admission_loop_with_stall_tracker<R, W, S>(
    reader: R,
    writer: W,
    service: Arc<S>,
    audit: Arc<dyn AuditSink>,
    session_id: String,
    stall_tracker: Option<Arc<EgressStallTracker>>,
) -> Result<(), LoopError>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
    S: AdmissionService + ?Sized,
{
    run_admission_loop_with_context(
        reader,
        writer,
        service,
        audit,
        session_id,
        None,
        stall_tracker,
    )
    .await
}

/// V3 context-aware admission loop. This is the production entry
/// point used by the session-spawn service so low-level transparent
/// proxy admission and stall events retain the owning initiative in
/// the top-level audit envelope. The older helpers intentionally
/// delegate with `initiative_id = None` for standalone tests and
/// non-kernel consumers that only know the session id.
pub async fn run_admission_loop_with_context<R, W, S>(
    mut reader: R,
    mut writer: W,
    service: Arc<S>,
    audit: Arc<dyn AuditSink>,
    session_id: String,
    initiative_id: Option<String>,
    stall_tracker: Option<Arc<EgressStallTracker>>,
) -> Result<(), LoopError>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
    S: AdmissionService + ?Sized,
{
    loop {
        // Read 4-byte big-endian length prefix.
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(LoopError::Io(e)),
        }
        let body_len = u32::from_be_bytes(len_buf) as usize;
        if body_len > raxis_tproxy_protocol::MAX_FRAME_BYTES {
            return Err(LoopError::Frame(FrameError::TooLarge {
                len: body_len as u64,
                max: raxis_tproxy_protocol::MAX_FRAME_BYTES,
            }));
        }
        let mut body = vec![0u8; body_len];
        reader.read_exact(&mut body).await?;
        // Re-prepend the length prefix so we can use the
        // shared `decode_request` (which expects a full frame).
        let mut full = Vec::with_capacity(4 + body_len);
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&body);
        let (req, _consumed) = decode_request(&full)?;

        // INV-OBSERVABILITY-DATAPLANE-LATENCY-06 — time the
        // policy-aware admission decision. `service.admit` is
        // pure CPU (no I/O), so the histogram sample is the
        // wall-clock cost of the allowlist + redirected-port
        // + credential-proxy-bypass match cascade. The hub-
        // disabled fast path inside `record_tproxy_admit_stage`
        // collapses this to a single `OnceLock::get` on the
        // CLI / unit-test path.
        let admit_started = Instant::now();
        let decision = service.admit(&session_id, &req);
        let admit_outcome = match &decision.verdict {
            AdmissionVerdict::Admit => TPROXY_ADMIT_OUTCOME_OK,
            AdmissionVerdict::Deny(_) => TPROXY_ADMIT_OUTCOME_DENIED,
        };
        record_tproxy_admit_stage(
            admit_outcome,
            admit_started.elapsed().as_millis().min(i64::MAX as u128) as i64,
        );

        let response_bytes = encode_response(&decision.to_response())?;
        writer.write_all(&response_bytes).await?;
        writer.flush().await?;

        let audit_kind = match &decision.verdict {
            AdmissionVerdict::Admit => AuditEventKind::TransparentProxyAdmitted {
                session_id: session_id.clone(),
                host_or_sni: req.host_or_sni.clone(),
                original_dst_ip: req.original_dst_ip.clone(),
                original_dst_port: req.original_dst_port,
                protocol: req.protocol.as_str().to_owned(),
            },
            AdmissionVerdict::Deny(reason) => AuditEventKind::TransparentProxyDenied {
                session_id: session_id.clone(),
                host_or_sni: req.host_or_sni.clone(),
                original_dst_ip: req.original_dst_ip.clone(),
                original_dst_port: req.original_dst_port,
                protocol: req.protocol.as_str().to_owned(),
                reason: reason.as_str().to_owned(),
            },
        };
        audit.emit(
            audit_kind,
            Some(&session_id),
            None,
            initiative_id.as_deref(),
        )?;

        // V2 reviewer-egress-defaults-decision.md §7 — feed the
        // denial through the stall tracker, if one is wired.
        // Failure to emit the stall event is logged but DOES NOT
        // unwind the admission decision (the
        // `TransparentProxyDenied` above is the authoritative
        // record; the stall event is a supplemental
        // observability signal).
        if let (Some(tracker), AdmissionVerdict::Deny(reason)) = (&stall_tracker, &decision.verdict)
        {
            if let StallSignal::Detected(emit) = tracker.record_denial(
                &session_id,
                req.host_or_sni.as_deref(),
                req.original_dst_port,
                reason.as_str(),
            ) {
                if let Err(e) = audit.emit(
                    AuditEventKind::SessionEgressStallDetected {
                        session_id: emit.session_id,
                        host_or_sni: emit.host_or_sni,
                        original_dst_port: emit.original_dst_port,
                        reason: emit.reason,
                        block_count_in_window: emit.block_count_in_window,
                        window_seconds: emit.window_seconds,
                        source: "tproxy".to_owned(),
                    },
                    Some(&session_id),
                    None,
                    initiative_id.as_deref(),
                ) {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"SessionEgressStallDetected\",\
                         \"audit_emit_failed\":\"{e}\",\"session_id\":\"{}\"}}",
                        session_id,
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn req(host: Option<&str>, port: u16, proto: AdmissionProtocol) -> ProxyAdmissionRequest {
        ProxyAdmissionRequest {
            connection_id: 1,
            original_dst_ip: "10.0.0.1".to_owned(),
            original_dst_port: port,
            host_or_sni: host.map(str::to_owned),
            protocol: proto,
        }
    }

    #[test]
    fn allowlist_exact_match_admits() {
        let svc = PolicyAdmissionService::new(EgressAllowlist {
            exact_hosts: vec!["api.anthropic.com".into()],
            ..Default::default()
        });
        let d = svc.admit(
            "sess-1",
            &req(Some("api.anthropic.com"), 443, AdmissionProtocol::Https),
        );
        assert!(d.is_admit());
    }

    #[test]
    fn allowlist_pattern_match_admits() {
        let svc = PolicyAdmissionService::new(EgressAllowlist {
            patterns: vec!["*.anthropic.com".into()],
            ..Default::default()
        });
        let d = svc.admit(
            "sess-1",
            &req(Some("api.anthropic.com"), 443, AdmissionProtocol::Https),
        );
        assert!(d.is_admit());
    }

    #[test]
    fn no_match_denies_with_host_not_in_allowlist() {
        let svc = PolicyAdmissionService::new(EgressAllowlist::default());
        let d = svc.admit(
            "sess-1",
            &req(Some("evil.example.com"), 443, AdmissionProtocol::Https),
        );
        assert!(!d.is_admit());
        match &d.verdict {
            AdmissionVerdict::Deny(r) => assert_eq!(*r, DenyReason::HostNotInAllowlist),
            _ => panic!(),
        }
    }

    #[test]
    fn raw_tcp_without_sni_denies_even_when_ip_matches_a_pattern() {
        // SNI is None on raw TCP — we cannot bind a hostname so
        // we conservatively deny. The agent must use a credential
        // proxy for outbound TCP that needs auth (the credential
        // proxy lives at 127.0.0.1, which is loopback-allowed and
        // never reaches admission).
        let svc = PolicyAdmissionService::new(EgressAllowlist {
            patterns: vec!["*".into()],
            ..Default::default()
        });
        let d = svc.admit("sess-1", &req(None, 5432, AdmissionProtocol::Tcp));
        assert!(matches!(
            d.verdict,
            AdmissionVerdict::Deny(DenyReason::HostNotInAllowlist),
        ));
    }

    #[test]
    fn unredirected_port_denies_with_port_not_redirected() {
        // Port 999 is not in the iptables-redirect list.
        let svc = PolicyAdmissionService::new(EgressAllowlist {
            exact_hosts: vec!["api.example.com".into()],
            ..Default::default()
        });
        let d = svc.admit(
            "sess-1",
            &req(Some("api.example.com"), 999, AdmissionProtocol::Tcp),
        );
        assert!(matches!(
            d.verdict,
            AdmissionVerdict::Deny(DenyReason::PortNotRedirected),
        ));
    }

    #[test]
    fn credential_proxy_real_target_match_denies_with_proxy_target_bypass() {
        let svc = PolicyAdmissionService::new(EgressAllowlist {
            exact_hosts: vec!["postgres-staging.example.com".into()],
            credential_proxy_real_targets: [("postgres-staging.example.com".into(), 5432)]
                .into_iter()
                .collect(),
            ..Default::default()
        });
        let d = svc.admit(
            "sess-1",
            &req(
                Some("postgres-staging.example.com"),
                5432,
                AdmissionProtocol::Tcp,
            ),
        );
        assert!(matches!(
            d.verdict,
            AdmissionVerdict::Deny(DenyReason::ProxyTargetBypass),
        ));
    }

    #[test]
    fn allowlist_match_is_case_insensitive_on_the_sni() {
        let svc = PolicyAdmissionService::new(EgressAllowlist {
            exact_hosts: vec!["API.Example.Com".into()],
            ..Default::default()
        });
        let d = svc.admit(
            "sess-1",
            &req(Some("api.example.com"), 443, AdmissionProtocol::Https),
        );
        assert!(d.is_admit());
    }

    // ---------------------------------------------------------------------
    // iter61 — `INV-OBSERVABILITY-DATAPLANE-LATENCY-06` witnesses.
    // ---------------------------------------------------------------------
    //
    // The admission loop's per-verdict timer emits one
    // `raxis.gateway.stage.duration` histogram observation per
    // `service.admit()` call (closed-lexicon labels:
    // `stage="tproxy_admit"`, `outcome ∈ {ok, denied}`). The
    // module-global `OBSERVABILITY_HUB` is `OnceLock`-backed and
    // cannot be reset mid-process; one combined witness exercises
    // the disabled-path → happy-path → deny-path arms in order
    // under a process-local serial guard, mirroring the same
    // pattern used by `raxis-ipc::frame` and
    // `raxis-worktree-provision`.

    use raxis_observability::{
        exporter::InMemoryExporter, AttrValue, DataPoint, HubConfig, MetricName,
        ObservabilityExporter, ObservabilityHub,
    };
    use raxis_test_support::FakeAuditSink;
    use raxis_tproxy_protocol::encode_request;
    use std::sync::Mutex;
    use tokio::io::duplex;

    fn obs_serial_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        match LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    fn tproxy_admit_counts(exp: &InMemoryExporter) -> std::collections::BTreeMap<String, u64> {
        let mut out: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
        for m in exp.metrics() {
            if m.name != MetricName::GatewayStageDuration {
                continue;
            }
            let stage_is_tproxy_admit = matches!(
                m.labels.get("stage"),
                Some(AttrValue::Str(s)) if s == GATEWAY_STAGE_TPROXY_ADMIT,
            );
            if !stage_is_tproxy_admit {
                continue;
            }
            let outcome = match m.labels.get("outcome") {
                Some(AttrValue::Str(s)) => s.clone(),
                _ => String::new(),
            };
            let count = match m.datapoint {
                DataPoint::Histo { count, .. } => count,
                _ => continue,
            };
            *out.entry(outcome).or_insert(0) += count;
        }
        out
    }

    /// Drive one `ProxyAdmissionRequest` through `run_admission_loop`
    /// end-to-end (encode → write into a duplex → loop reads →
    /// decision → response written → audit emit) using a
    /// deterministic allowlist. Closes the client write half so
    /// the loop returns `Ok(())` on the next read EOF rather than
    /// blocking.
    async fn drive_loop_with_one_request(
        svc: Arc<PolicyAdmissionService>,
        req: ProxyAdmissionRequest,
    ) -> Arc<FakeAuditSink> {
        use tokio::io::AsyncWriteExt;
        let (mut client_w, server_r) = duplex(64 * 1024);
        let (server_w, mut client_r) = duplex(64 * 1024);
        let request_bytes = encode_request(&req).unwrap();
        client_w.write_all(&request_bytes).await.unwrap();
        drop(client_w);

        let audit: Arc<FakeAuditSink> = Arc::new(FakeAuditSink::new());
        let audit_dyn: Arc<dyn AuditSink> = audit.clone();
        let drain = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut sink = Vec::new();
            let _ = client_r.read_to_end(&mut sink).await;
        });
        run_admission_loop(server_r, server_w, svc, audit_dyn, "sess-obs".to_owned())
            .await
            .unwrap();
        drain.await.ok();
        audit
    }

    /// Combined disabled-path / admit-path / deny-path witness.
    /// The serial guard MutexGuard is held across awaits — see
    /// the matching note on `raxis-ipc::frame::frame_stage_…`
    /// for the same single-runtime-no-deadlock argument.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn admission_loop_tproxy_admit_histograms_cover_admit_and_deny_and_disabled() {
        let _g = obs_serial_guard();

        // ── Witness #1 — hub-disabled fast path. The
        //    `OBSERVABILITY_HUB` global is empty before any test
        //    in this binary touches `set_global_observability_hub`.
        //    Drive one admit through the loop with the global
        //    unset and confirm no panic + the global remains
        //    unset.
        if OBSERVABILITY_HUB.get().is_none() {
            let svc = Arc::new(PolicyAdmissionService::new(EgressAllowlist {
                exact_hosts: vec!["api.anthropic.com".into()],
                ..Default::default()
            }));
            let audit = drive_loop_with_one_request(
                svc,
                ProxyAdmissionRequest {
                    connection_id: 0,
                    original_dst_ip: "10.0.0.10".to_owned(),
                    original_dst_port: 443,
                    host_or_sni: Some("api.anthropic.com".to_owned()),
                    protocol: AdmissionProtocol::Https,
                },
            )
            .await;
            // Functional behaviour unchanged: the audit sink
            // still receives one `TransparentProxyAdmitted` event.
            assert_eq!(audit.events().len(), 1);
            assert!(
                OBSERVABILITY_HUB.get().is_none(),
                "the global hub must remain unset after a hub-disabled round-trip",
            );
        }

        // ── Witness #2 — wire the hub and exercise the admit
        //    + deny verdicts. Every `service.admit()` call
        //    must emit one `GatewayStageDuration` sample under
        //    `stage="tproxy_admit"`.
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled: true,
            sample_rate: 1.0,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            Arc::clone(&exp) as Arc<dyn ObservabilityExporter>,
        ));
        set_global_observability_hub(Arc::clone(&hub));

        // Admit path: SNI in allowlist, redirected port.
        let svc_admit = Arc::new(PolicyAdmissionService::new(EgressAllowlist {
            exact_hosts: vec!["api.anthropic.com".into()],
            ..Default::default()
        }));
        let admit_audit = drive_loop_with_one_request(
            svc_admit,
            ProxyAdmissionRequest {
                connection_id: 1,
                original_dst_ip: "10.0.0.1".to_owned(),
                original_dst_port: 443,
                host_or_sni: Some("api.anthropic.com".to_owned()),
                protocol: AdmissionProtocol::Https,
            },
        )
        .await;
        assert_eq!(admit_audit.events().len(), 1);

        // Deny path: SNI not in allowlist.
        let svc_deny = Arc::new(PolicyAdmissionService::new(EgressAllowlist::default()));
        let deny_audit = drive_loop_with_one_request(
            svc_deny,
            ProxyAdmissionRequest {
                connection_id: 2,
                original_dst_ip: "10.0.0.2".to_owned(),
                original_dst_port: 443,
                host_or_sni: Some("evil.example.com".to_owned()),
                protocol: AdmissionProtocol::Https,
            },
        )
        .await;
        assert_eq!(deny_audit.events().len(), 1);

        hub.flush();
        let counts = tproxy_admit_counts(&exp);
        assert!(
            counts.get(TPROXY_ADMIT_OUTCOME_OK).copied().unwrap_or(0) >= 1,
            "expected ≥1 tproxy_admit ok sample; got {counts:?}",
        );
        assert!(
            counts
                .get(TPROXY_ADMIT_OUTCOME_DENIED)
                .copied()
                .unwrap_or(0)
                >= 1,
            "expected ≥1 tproxy_admit denied sample; got {counts:?}",
        );
    }
}
