//! `raxis-vsock-loopback` — substrate-level VM↔host loopback bridge
//! wire format.
//!
//! Normative reference: `raxis/specs/v2/credential-proxy.md §13`
//! ("VM↔host loopback plumbing"), `raxis/specs/invariants.md
//! INV-CRED-PROXY-VM-REACHABILITY-01`.
//!
//! # Why this crate exists
//!
//! Credential proxies bind on **host** `127.0.0.1:<port>` so the
//! credential material that the proxy holds never crosses the VM
//! boundary (INV-SECRET-02, INV-VM-CAP-04). The in-VM agent
//! toolchain (libpq / pymongo / redis-py / kubectl / aws-sdk) is
//! configured by env-stamped URLs of the form
//! `postgresql://raxis@127.0.0.1:<port>/`,
//! `http://127.0.0.1:<port>`, etc. Inside an isolation VM (Apple-VZ
//! today; Firecracker tomorrow) the literal `127.0.0.1` resolves to
//! the **guest's** loopback interface — there is no listener on
//! that side, the host-bound listener is unreachable.
//!
//! The substrate fix is a per-session **vsock-loopback fan-out**:
//!
//! 1. The kernel keeps binding credential proxies on host
//!    `127.0.0.1:<host_loopback_port>` exactly as before.
//! 2. The kernel allocates a **vsock port** per proxy (one per
//!    `(session, credential)` pair) and registers a substrate-side
//!    vsock listener that, on accept, opens a host-local TCP
//!    connection to `127.0.0.1:<host_loopback_port>` and shuttles
//!    bytes bidirectionally.
//! 3. The in-VM **forwarder** (a tokio task inside the existing
//!    `raxis-tproxy` binary) reads this crate's
//!    [`LoopbackPlan`] from `RAXIS_VSOCK_LOOPBACK_PLAN`, binds
//!    `127.0.0.1:<guest_loopback_port>` for every entry, and on
//!    accept opens an AF_VSOCK connection to
//!    `(VMADDR_CID_HOST=2, vsock_port)` and shuttles bytes to the
//!    host accepter.
//! 4. The kernel stamps the credential-proxy env URLs to point at
//!    `127.0.0.1:<guest_loopback_port>` so the agent's toolchain
//!    sees a stock loopback URL — no awareness of the in-VM
//!    forwarder, no awareness of the vsock plumbing.
//!
//! ## Per-VM isolation argument
//!
//! Each isolation VM has its own `VZVirtioSocketDevice`
//! (Apple-VZ) / `vhost-vsock` instance (Firecracker). The
//! substrate registers the `VZVirtioSocketListener` on **that
//! VM's device**, not on a shared host CID. So vsock port `N`
//! on VM-A's device is a different listener from vsock port `N`
//! on VM-B's device — the substrate's per-VM device boundary is
//! the per-session isolation boundary. Cross-session access is
//! structurally impossible: an executor in VM-B that dials
//! `(VMADDR_CID_HOST, N)` reaches VM-B's listener (which
//! forwards to VM-B's host loopback proxies), never VM-A's.
//!
//! This composes cleanly with `INV-VM-NETWORK-*`: the in-guest
//! tproxy iptables rules already ACCEPT traffic to `lo`, so the
//! agent's TCP connect to `127.0.0.1:<guest_loopback_port>` is
//! not redirected through the egress-admission machinery — it
//! reaches the in-VM forwarder directly. The forwarder's
//! AF_VSOCK egress is an in-VM kernel-managed channel, never
//! observed by the iptables OUTPUT chain.
//!
//! ## What this crate does NOT do
//!
//! * It does **not** open AF_VSOCK sockets. The Linux AF_VSOCK
//!   half lives in `raxis-tproxy::vsock_loopback`; the macOS
//!   `VZVirtioSocketListener` half lives in
//!   `raxis-isolation-apple-vz::vsock_loopback_bridge`.
//! * It does **not** allocate ports. Both the vsock port and the
//!   host loopback port are chosen by the kernel-side composer
//!   (`raxis-session-spawn`) before the plan is stamped.
//! * It does **not** know which proxy is at which port. The plan
//!   is opaque from this crate's perspective; the kernel's
//!   audit chain is what associates `(credential_name, vsock_port,
//!   host_loopback_port)` triples with the human-readable proxy
//!   identity.
//!
//! # Wire shape
//!
//! `RAXIS_VSOCK_LOOPBACK_PLAN` value =
//! `<vsock_port>:<guest_loopback_port>,<vsock_port>:<guest_loopback_port>,…`
//! — comma-separated `vsock_port:guest_loopback_port` pairs. Empty
//! string is a valid plan with zero entries (no credential proxies
//! declared for this session). The encoding is deliberately
//! whitespace-free, ASCII-only, and round-trips byte-for-byte
//! through the AVF substrate's base64 envelope (no quoting
//! concerns).
//!
//! Each `vsock_port` is the AF_VSOCK port number the host
//! substrate registered the listener on; each
//! `guest_loopback_port` is the TCP port number the in-guest
//! forwarder MUST bind on `127.0.0.1`. The two are deliberately
//! decoupled (the host port number space is independent of the
//! guest's loopback port allocation) so a future host-side change
//! that needs to reuse a vsock port for multiplexing does not
//! force a guest-loopback port change.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::result_large_err)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Env var the kernel-side composer stamps and the in-guest
/// forwarder reads. Pinned at the wire-format level so renaming
/// it requires a coordinated host + guest deployment.
pub const ENV_VAR_LOOPBACK_PLAN: &str = "RAXIS_VSOCK_LOOPBACK_PLAN";

/// One forwarding entry: a vsock port on the host substrate
/// listener, paired with the TCP port the in-guest forwarder
/// MUST bind on `127.0.0.1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LoopbackEntry {
    /// AF_VSOCK port the host substrate listens on. The in-guest
    /// forwarder dials `(VMADDR_CID_HOST, vsock_port)` for any
    /// connection accepted on `guest_loopback_port`.
    pub vsock_port:           u32,
    /// TCP port the in-guest forwarder binds on `127.0.0.1`.
    /// The agent's env-stamped URL points at this port; the
    /// forwarder's `127.0.0.1:<guest_loopback_port>` listener is
    /// what the agent's libpq / pymongo / redis-py client
    /// actually connects to.
    pub guest_loopback_port:  u16,
}

/// Per-session forwarding plan. Carries every
/// `(vsock_port, guest_loopback_port)` pair the in-guest
/// forwarder needs to wire up at startup.
///
/// Determinism: entries are stored in declaration order. The
/// encoder preserves the order; the decoder accepts any order
/// and does NOT reorder. A duplicate-port (vsock or guest) is
/// rejected at decode time (see [`PlanParseError::DuplicateVsockPort`]
/// / [`PlanParseError::DuplicateGuestPort`]) — duplicates would
/// either silently shadow a forwarder or bind the same TCP port
/// twice, both of which are correctness violations the kernel
/// must surface fail-closed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopbackPlan {
    /// Forwarding entries. May be empty (a session that declared
    /// zero credentials — the env var is still stamped so the
    /// in-guest forwarder reads "no work to do" rather than
    /// guessing from the var's absence vs presence).
    pub entries: Vec<LoopbackEntry>,
}

impl LoopbackPlan {
    /// Empty plan — convenience constructor used by tests and by
    /// the kernel callsite when a session declares no credentials.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Number of forwarding entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the plan has zero entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate the entries in declaration order. Provided as a
    /// stable accessor so callers do not need to depend on the
    /// public `entries` field's container type.
    pub fn iter(&self) -> std::slice::Iter<'_, LoopbackEntry> {
        self.entries.iter()
    }

    /// Encode the plan as the comma-separated wire shape this
    /// crate's docs describe. Empty plan ⇒ empty string.
    pub fn to_env_string(&self) -> String {
        let mut out = String::with_capacity(self.entries.len() * 12);
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&entry.vsock_port.to_string());
            out.push(':');
            out.push_str(&entry.guest_loopback_port.to_string());
        }
        out
    }

    /// Decode a plan from the wire shape. Empty / whitespace-only
    /// input is a valid empty plan — the in-guest forwarder
    /// treats `RAXIS_VSOCK_LOOPBACK_PLAN=""` and a missing env var
    /// as equivalent ("no forwarders to wire").
    pub fn from_env_string(s: &str) -> Result<Self, PlanParseError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(Self::new());
        }
        let mut entries = Vec::new();
        let mut seen_vsock = std::collections::BTreeSet::new();
        let mut seen_guest = std::collections::BTreeSet::new();
        for raw in trimmed.split(',') {
            let token = raw.trim();
            if token.is_empty() {
                return Err(PlanParseError::EmptyEntry);
            }
            let (vsock_str, guest_str) = token
                .split_once(':')
                .ok_or_else(|| PlanParseError::Malformed {
                    token: token.to_owned(),
                })?;
            let vsock_port: u32 = vsock_str.parse().map_err(|_| {
                PlanParseError::Malformed { token: token.to_owned() }
            })?;
            let guest_port: u16 = guest_str.parse().map_err(|_| {
                PlanParseError::Malformed { token: token.to_owned() }
            })?;
            if vsock_port == 0 {
                return Err(PlanParseError::ZeroPort {
                    token: token.to_owned(),
                });
            }
            if guest_port == 0 {
                return Err(PlanParseError::ZeroPort {
                    token: token.to_owned(),
                });
            }
            if !seen_vsock.insert(vsock_port) {
                return Err(PlanParseError::DuplicateVsockPort {
                    vsock_port,
                });
            }
            if !seen_guest.insert(guest_port) {
                return Err(PlanParseError::DuplicateGuestPort {
                    guest_loopback_port: guest_port,
                });
            }
            entries.push(LoopbackEntry {
                vsock_port,
                guest_loopback_port: guest_port,
            });
        }
        Ok(Self { entries })
    }
}

/// Wire-format parse failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanParseError {
    /// One of the comma-separated tokens was empty (e.g.
    /// `"5432:5432,,3306:3306"`). Trailing commas are also
    /// rejected — the wire format does not allow empty tuples.
    #[error("empty entry between commas")]
    EmptyEntry,

    /// A token did not parse as `<vsock_port>:<guest_loopback_port>`.
    /// The token's raw form is included so an operator triaging the
    /// boot env knows exactly which tuple was rejected.
    #[error("malformed entry {token:?} (expected `<vsock_port>:<guest_loopback_port>`)")]
    Malformed {
        /// The raw token from the env var.
        token: String,
    },

    /// One of the ports was zero. AF_VSOCK port 0 has special
    /// "any-port" semantics, and TCP port 0 means "ephemeral";
    /// neither is meaningful for an explicit forwarding plan, so
    /// both are rejected fail-closed.
    #[error("zero port in entry {token:?} (vsock 0 is reserved; tcp 0 is ephemeral)")]
    ZeroPort {
        /// The raw token from the env var.
        token: String,
    },

    /// The same vsock port appeared more than once. The host
    /// substrate would have to register two listeners on the
    /// same vsock port — only the second would survive and the
    /// first credential proxy would be unreachable.
    #[error("duplicate vsock port {vsock_port} in plan")]
    DuplicateVsockPort {
        /// The colliding vsock port.
        vsock_port: u32,
    },

    /// The same guest loopback port appeared more than once.
    /// The in-guest forwarder would attempt two `bind(2)` calls
    /// on the same `127.0.0.1:port` and the second would fail
    /// with EADDRINUSE — half the credential proxies would be
    /// unreachable for the lifetime of the session.
    #[error("duplicate guest loopback port {guest_loopback_port} in plan")]
    DuplicateGuestPort {
        /// The colliding guest loopback port.
        guest_loopback_port: u16,
    },
}

// ---------------------------------------------------------------------------
// Tests — pure-data, run on every platform.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_plan_round_trips_through_env_string() {
        let plan = LoopbackPlan::new();
        assert_eq!(plan.to_env_string(), "");
        let recovered = LoopbackPlan::from_env_string("").unwrap();
        assert_eq!(recovered, plan);
        let recovered_ws = LoopbackPlan::from_env_string("   ").unwrap();
        assert_eq!(recovered_ws, plan);
    }

    #[test]
    fn single_entry_plan_encodes_to_canonical_token() {
        let plan = LoopbackPlan {
            entries: vec![LoopbackEntry {
                vsock_port:          5432,
                guest_loopback_port: 5432,
            }],
        };
        assert_eq!(plan.to_env_string(), "5432:5432");
        let recovered = LoopbackPlan::from_env_string("5432:5432").unwrap();
        assert_eq!(recovered, plan);
    }

    #[test]
    fn multi_entry_plan_round_trips_with_declaration_order_preserved() {
        let plan = LoopbackPlan {
            entries: vec![
                LoopbackEntry {
                    vsock_port:          54101,
                    guest_loopback_port: 54101,
                },
                LoopbackEntry {
                    vsock_port:          54102,
                    guest_loopback_port: 54102,
                },
                LoopbackEntry {
                    vsock_port:          8001,
                    guest_loopback_port: 9001,
                },
            ],
        };
        let encoded = plan.to_env_string();
        assert_eq!(encoded, "54101:54101,54102:54102,8001:9001");
        let recovered = LoopbackPlan::from_env_string(&encoded).unwrap();
        assert_eq!(recovered, plan);
    }

    #[test]
    fn decoder_rejects_empty_token_between_commas() {
        let err = LoopbackPlan::from_env_string("5432:5432,,3306:3306").unwrap_err();
        assert_eq!(err, PlanParseError::EmptyEntry);
    }

    #[test]
    fn decoder_rejects_trailing_comma() {
        let err = LoopbackPlan::from_env_string("5432:5432,").unwrap_err();
        assert_eq!(err, PlanParseError::EmptyEntry);
    }

    #[test]
    fn decoder_rejects_token_without_colon() {
        let err = LoopbackPlan::from_env_string("5432").unwrap_err();
        assert_eq!(
            err,
            PlanParseError::Malformed { token: "5432".into() },
        );
    }

    #[test]
    fn decoder_rejects_non_numeric_ports() {
        let err = LoopbackPlan::from_env_string("abc:5432").unwrap_err();
        assert!(matches!(err, PlanParseError::Malformed { .. }));
    }

    #[test]
    fn decoder_rejects_vsock_port_overflow_into_negative_or_huge() {
        // 5_000_000_000 doesn't fit in u32 — reject as malformed.
        let err = LoopbackPlan::from_env_string("5000000000:1234").unwrap_err();
        assert!(matches!(err, PlanParseError::Malformed { .. }));
    }

    #[test]
    fn decoder_rejects_zero_vsock_port() {
        let err = LoopbackPlan::from_env_string("0:5432").unwrap_err();
        assert_eq!(
            err,
            PlanParseError::ZeroPort { token: "0:5432".into() },
        );
    }

    #[test]
    fn decoder_rejects_zero_guest_port() {
        let err = LoopbackPlan::from_env_string("5432:0").unwrap_err();
        assert_eq!(
            err,
            PlanParseError::ZeroPort { token: "5432:0".into() },
        );
    }

    #[test]
    fn decoder_rejects_duplicate_vsock_port() {
        let err = LoopbackPlan::from_env_string("5432:5432,5432:5433").unwrap_err();
        assert_eq!(
            err,
            PlanParseError::DuplicateVsockPort { vsock_port: 5432 },
        );
    }

    #[test]
    fn decoder_rejects_duplicate_guest_port() {
        let err = LoopbackPlan::from_env_string("5432:5432,5433:5432").unwrap_err();
        assert_eq!(
            err,
            PlanParseError::DuplicateGuestPort {
                guest_loopback_port: 5432,
            },
        );
    }

    #[test]
    fn decoder_accepts_decoupled_vsock_and_guest_ports() {
        let plan = LoopbackPlan::from_env_string("8001:9001").unwrap();
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].vsock_port, 8001);
        assert_eq!(plan.entries[0].guest_loopback_port, 9001);
    }

    #[test]
    fn round_trip_through_serde_json_pins_field_names() {
        let plan = LoopbackPlan {
            entries: vec![LoopbackEntry {
                vsock_port:          54321,
                guest_loopback_port: 54321,
            }],
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("\"vsock_port\":54321"));
        assert!(json.contains("\"guest_loopback_port\":54321"));
        let decoded: LoopbackPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, plan);
    }

    #[test]
    fn entry_count_helpers_are_consistent() {
        let mut plan = LoopbackPlan::new();
        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
        plan.entries.push(LoopbackEntry {
            vsock_port:          1234,
            guest_loopback_port: 5678,
        });
        assert!(!plan.is_empty());
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn env_var_name_is_stable() {
        // The forwarder reads this exact name; renaming it requires
        // a coordinated host + guest update. Pinning the value
        // shifts the cost of a wire-protocol change to a test
        // failure rather than a silent runtime divergence.
        assert_eq!(ENV_VAR_LOOPBACK_PLAN, "RAXIS_VSOCK_LOOPBACK_PLAN");
    }
}
