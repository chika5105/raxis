//! In-VM TCP→VSOCK loopback forwarder.
//!
//! Normative reference: `specs/v2/credential-proxy.md` (the new
//! INV-CRED-PROXY-VM-REACHABILITY-01 plumbing) and
//! `specs/v2/vm-network-isolation.md §3` (Tier 1 / Tier 2 split).
//!
//! # Why this exists
//!
//! `credential-proxy-manager::SessionProxyHandles::loopback_env`
//! stamps URLs of the form `postgresql://raxis@127.0.0.1:54xxx/…`
//! into the executor's environment. Those proxies bind on the
//! **host's** loopback. The AVF guest has its own NAT loopback
//! with nothing listening, so a stock `libpq` / `pymongo` /
//! `redis-py` client inside the VM dialing `127.0.0.1:54xxx`
//! gets `ECONNREFUSED`.
//!
//! This forwarder sits inside the VM and bridges that gap **without
//! widening any isolation boundary**:
//!
//!   * It binds `127.0.0.1:<guest_loopback_port>` for every entry
//!     in [`raxis_vsock_loopback::LoopbackPlan`] (read from the
//!     env var [`raxis_vsock_loopback::ENV_VAR_LOOPBACK_PLAN`]).
//!   * On each accept it dials AF_VSOCK to
//!     `(VMADDR_CID_HOST, <vsock_port>)`. The host side of that
//!     CID/port pair is bound by `crates/isolation-apple-vz` as a
//!     [`VZVirtioSocketListener`], which in turn re-emits to host
//!     `127.0.0.1:<host_proxy_port>` — i.e. the credential proxy.
//!   * It splices bytes bidirectionally between the agent's TCP
//!     stream and the vsock stream until either side closes.
//!
//! The forwarder is **transport-agnostic**: it never inspects
//! payload bytes. The credential proxy on the host side is the
//! only component that ever sees plaintext credentials. From the
//! VM's perspective, `127.0.0.1:54xxx` resolves transparently
//! exactly as it would on a non-virtualised host. Stock executor
//! scripts therefore need zero changes.
//!
//! # Why each `vsock_port` is per-VM-isolated
//!
//! AVF allocates one virtio-vsock device per guest. Two VMs on the
//! same host with the same `vsock_port` are not addressable from
//! each other — vsock CIDs are per-VM and the host listener is
//! bound on a `VZVirtioSocketListener` attached to *one* specific
//! VM configuration. So the natural per-VM isolation of vsock
//! gives us session-scoped fan-out for free.
//!
//! # Lifetime
//!
//! [`spawn_forwarder`] returns after binding all guest TCP
//! listeners (so a binding error is reported synchronously to the
//! caller), and spawns one tokio task per listener that runs for
//! the lifetime of the process. The supervising init script
//! restarts the binary if any listener task panics.

use std::io;

#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddrV4};

#[cfg(target_os = "linux")]
use raxis_vsock_loopback::LoopbackEntry;
use raxis_vsock_loopback::{LoopbackPlan, ENV_VAR_LOOPBACK_PLAN};
use thiserror::Error;
#[cfg(target_os = "linux")]
use tokio::net::TcpListener;

/// Errors surfaced by [`spawn_forwarder`] during startup. Per-
/// connection errors are logged to stderr and dropped — they do
/// not propagate up to `main()` because a single bad client
/// MUST NOT take down the entire forwarder.
#[derive(Debug, Error)]
pub enum LoopbackForwarderError {
    /// The `RAXIS_VSOCK_LOOPBACK_PLAN` env var was set but failed
    /// to decode. The kernel substrate is responsible for never
    /// stamping a malformed plan, so this is a hard fail.
    #[error("decode loopback plan: {0}")]
    Decode(#[from] raxis_vsock_loopback::PlanParseError),

    /// `bind(127.0.0.1:<guest_port>)` failed for the named entry.
    /// The most common cause is another in-VM process already
    /// holding the port; the kernel substrate picks the
    /// `guest_loopback_port` to match the host-side proxy, so a
    /// collision implies a misconfiguration.
    #[error("bind 127.0.0.1:{guest_loopback_port}: {source}")]
    Bind {
        /// The guest loopback port that failed to bind.
        guest_loopback_port: u16,
        /// Underlying I/O error from `tokio::net::TcpListener::bind`.
        #[source]
        source: io::Error,
    },
}

/// Read the loopback plan from the process environment, returning
/// `Ok(None)` when the env var is absent (i.e. the kernel
/// substrate did not request any forwarding for this VM — for
/// example, a session that needs no credential proxies).
pub fn loopback_plan_from_env() -> Result<Option<LoopbackPlan>, raxis_vsock_loopback::PlanParseError>
{
    match std::env::var(ENV_VAR_LOOPBACK_PLAN) {
        Ok(s) => {
            let plan = LoopbackPlan::from_env_string(&s)?;
            if plan.is_empty() {
                Ok(None)
            } else {
                Ok(Some(plan))
            }
        }
        Err(_) => Ok(None),
    }
}

/// Bind every guest-loopback TCP listener described by `plan` and
/// spawn a forward task per listener. Returns once all binds have
/// succeeded; the spawned tasks then run until the process exits.
///
/// The forward direction is:
///
/// ```text
/// agent (in VM) ──TCP──> 127.0.0.1:guest_loopback_port
///                         │
///                         │  (this forwarder)
///                         ▼
///                    AF_VSOCK to (VMADDR_CID_HOST, vsock_port)
///                         │
///                         ▼
///                    host VZVirtioSocketListener
///                         │
///                         ▼
///                    127.0.0.1:host_proxy_port  (credential proxy)
/// ```
///
/// The kernel-side substrate (in `crates/isolation-apple-vz`) is
/// responsible for the host half; this function is the guest half.
#[cfg(target_os = "linux")]
pub async fn spawn_forwarder(plan: &LoopbackPlan) -> Result<(), LoopbackForwarderError> {
    eprintln!(
        "raxis-tproxy: vsock-loopback forwarder activating for {} entrie(s)",
        plan.len()
    );

    // Bind first, then spawn — so any bind failure surfaces as the
    // process's overall startup error rather than a silent
    // drop-on-the-floor.
    let mut bindings: Vec<(LoopbackEntry, TcpListener)> = Vec::with_capacity(plan.len());
    for entry in plan.iter() {
        let bind_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, entry.guest_loopback_port);
        let listener =
            TcpListener::bind(bind_addr)
                .await
                .map_err(|e| LoopbackForwarderError::Bind {
                    guest_loopback_port: entry.guest_loopback_port,
                    source: e,
                })?;
        eprintln!(
            "raxis-tproxy: bound 127.0.0.1:{} -> vsock(host_cid, {})",
            entry.guest_loopback_port, entry.vsock_port
        );
        bindings.push((*entry, listener));
    }

    for (entry, listener) in bindings {
        tokio::spawn(async move {
            run_forwarder_loop(entry, listener).await;
        });
    }

    Ok(())
}

/// Non-Linux stub for type-checking. The forwarder is Linux-only at
/// runtime because AF_VSOCK is a Linux concept; on macOS the
/// production binary is never executed (the in-VM target triple is
/// `*-unknown-linux-musl`), but `cargo check` on a developer's
/// laptop must still succeed.
#[cfg(not(target_os = "linux"))]
pub async fn spawn_forwarder(_plan: &LoopbackPlan) -> Result<(), LoopbackForwarderError> {
    Err(LoopbackForwarderError::Bind {
        guest_loopback_port: 0,
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "raxis-tproxy vsock-loopback forwarder is Linux-only at runtime",
        ),
    })
}

#[cfg(target_os = "linux")]
async fn run_forwarder_loop(entry: LoopbackEntry, listener: TcpListener) {
    loop {
        let (agent, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // Listener-fatal — back off briefly and try again.
                // We MUST NOT exit the loop because a single
                // transient `EMFILE` on the in-VM kernel would
                // leave the executor permanently unable to reach
                // the credential proxy.
                eprintln!(
                    "raxis-tproxy: listener accept failed on 127.0.0.1:{} (will retry): {e}",
                    entry.guest_loopback_port,
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = peer; // peer is always 127.0.0.1:* — nothing useful
        tokio::spawn(async move {
            if let Err(e) = forward_one(entry, agent).await {
                eprintln!(
                    "raxis-tproxy: forward 127.0.0.1:{} -> vsock({}): {e}",
                    entry.guest_loopback_port, entry.vsock_port,
                );
            }
        });
    }
}

#[cfg(target_os = "linux")]
async fn forward_one(entry: LoopbackEntry, mut agent: tokio::net::TcpStream) -> io::Result<()> {
    use tokio_vsock::{VsockAddr, VsockStream, VMADDR_CID_HOST};

    let mut upstream = VsockStream::connect(VsockAddr::new(VMADDR_CID_HOST, entry.vsock_port))
        .await
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "vsock connect (host_cid={VMADDR_CID_HOST}, port={}): {e}",
                    entry.vsock_port
                ),
            )
        })?;

    // Splice bidirectionally; ignore the byte counts. Per-direction
    // shutdown is handled by `copy_bidirectional` via the
    // underlying `AsyncWrite::shutdown`.
    let _ = tokio::io::copy_bidirectional(&mut agent, &mut upstream).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `loopback_plan_from_env` is a thin shim over
    /// [`LoopbackPlan::from_env_string`]; the round-trip
    /// guarantees of the wire format are exhaustively tested in
    /// the `raxis-vsock-loopback` crate itself. Here we cover the
    /// shim-specific contract: env-absence and env-empty both
    /// yield `Ok(None)` so the in-guest forwarder treats them as
    /// equivalent. Direct `from_env_string` is exercised rather
    /// than mutating the process env (which is `unsafe` and
    /// racy across test threads).
    #[test]
    fn empty_string_decodes_to_empty_plan() {
        let got = LoopbackPlan::from_env_string("").expect("decode");
        assert!(got.is_empty());
    }

    /// A populated env-string round-trips through the plan parser
    /// in declaration order, with the entries surfaced via the
    /// public `iter()` accessor used by [`spawn_forwarder`].
    #[test]
    fn populated_env_string_yields_plan_in_order() {
        let plan = LoopbackPlan::from_env_string("10001:5432,10002:27017").expect("decode");
        assert_eq!(plan.len(), 2);
        let mut it = plan.iter();
        let first = it.next().expect("first entry");
        assert_eq!(first.vsock_port, 10001);
        assert_eq!(first.guest_loopback_port, 5432);
        let second = it.next().expect("second entry");
        assert_eq!(second.vsock_port, 10002);
        assert_eq!(second.guest_loopback_port, 27017);
        assert!(it.next().is_none());
    }
}
