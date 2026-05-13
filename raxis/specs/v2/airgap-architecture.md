# RAXIS V2 — Path A3 Universal Airgap Architecture

> **Status:** V2 Specified (opt-in via `RAXIS_AIRGAP_A3=1` env var +
> `runtime-airgap-a3` Cargo feature). Default-off path is bit-identical
> to the legacy `Tier1Tproxy` virtio-net-with-NAT model documented in
> `vm-network-isolation.md`.
>
> **Role in the V2 unified egress story.** This spec is the canonical
> home for the *universal* airgap model: every role's VM
> (Orchestrator, Executor, Reviewer) ships with **no** virtio-net
> device. The kernel is the sole arbiter of every byte that leaves
> the guest — HTTP, raw TCP, DNS, credential-proxy loopback — and it
> arbitrates over vsock, not over a NAT tap.
>
> **Cross-references.**
> - `vm-network-isolation.md` — Tier-1 admission contract. Path A3
>   keeps the admission contract (SNI / Host header allowlist) but
>   moves the transport from virtio-net + iptables-redirect-to-kernel
>   to AF_VSOCK + kernel-side tunnel.
> - `credential-proxy.md §12a` — vsock-loopback bridge for
>   credential-proxy URLs. Path A3 reuses the same per-VM vsock
>   device for its admission channel, its byte-tunnel channel, and
>   its DNS-over-vsock channel; the credential-proxy bridge is the
>   architectural precedent.
> - `extensibility-traits.md §3` — `EgressTier::Mediated` is the A3
>   variant that produces **no** `AvfNetworkDevice` and omits
>   Firecracker's `network-interfaces` field.
> - `kernel-mediated-egress.md` — deprecated; the A3 model
>   *generalises* kernel-mediated egress from "HTTP only" to "every
>   byte the guest sends outbound".
> - `INV-NETISO-A3-*` family in `invariants.md §6` — universal
>   no-NIC, vsock chokepoint, DNS mediation, IPv6 disabled, paired
>   audit for admission and DNS.

## 1. Why A3 exists — the gap A1/A2 leave open

The V2 baseline has the **Reviewer** at `EgressTier::None` (no NIC)
and the **Executor / Orchestrator** at `EgressTier::Tier1Tproxy`
(virtio-net + NAT + an in-guest `raxis-tproxy` binary that *should*
redirect outbound TCP to itself and *should* enforce an allowlist
before opening upstream sockets). In practice the V2 GA shipment is
asymmetric:

1. The canonical Executor rootfs does **not** ship the
   `raxis-tproxy` binary at `/usr/local/bin/raxis-tproxy`. It links
   the credential-proxy vsock-loopback forwarder as a library and
   relies on the lack of in-VM enforcement plus the **gateway**
   URL allowlist as the only line of defence.
2. The Executor VM's iptables REDIRECT chain is never installed at
   PID 1 boot — the `vm-network-isolation.md §3.1` rules are
   normative but not wired into `crates/planner-core::guest_init`.
3. The kernel-side admission accept loop only handles the
   *dev-fallback* TCP transport from `raxis-tproxy`'s
   `KernelChannel::Tcp` variant. A real `KernelChannel::Vsock`
   variant is unimplemented.

The combined effect: an Executor that runs a `bash`-invoked
`curl https://evil.example` reaches **the NAT** directly because the
in-guest iptables chain is empty and the tproxy binary is absent.
The gateway allowlist catches LLM provider calls (which go through
the kernel-mediated `PlannerFetchRequest` path) but does not catch
raw TCP from agent-spawned tools.

Path A3 closes this gap by **eliminating the virtio-net device
entirely** from every role's VM. The agent's TCP socket has nowhere
to go *except* into the in-guest tproxy listener, and the in-guest
tproxy MUST route every byte through the kernel's vsock admission
channel.

## 2. The unified A3 model end-to-end

```
┌────────────────────────────────────────────────────────────────┐
│ Guest VM (no virtio-net)                                       │
│                                                                │
│   bash, agent code, custom tool                                │
│         │                                                      │
│         ▼ TCP connect "evil.example:443"                       │
│   ┌────────────────┐                                           │
│   │ iptables nat   │  REDIRECT --to-port 3129                  │
│   └────────┬───────┘  REDIRECT UDP/53 → 127.0.0.1:53           │
│            ▼                                                   │
│   ┌────────────────┐  ┌────────────────┐                       │
│   │ raxis-tproxy   │  │ raxis-tproxy   │                       │
│   │  (TCP redir)   │  │  (DNS stub :53)│                       │
│   └────────┬───────┘  └────────┬───────┘                       │
│            │ ① peek SNI         │ ① DNS query                  │
│            │ ② admission req    │ ② resolve req                │
│            ▼                    ▼                              │
│   ┌──────────────────────────────────────┐                     │
│   │  AF_VSOCK to (VMADDR_CID_HOST, port) │                     │
│   └──────────────────────────────────────┘                     │
└────────────┼─────────────────────────────────────┼─────────────┘
             │                                     │
┌────────────▼─────────────────────────────────────▼─────────────┐
│ Kernel (host)                                                  │
│                                                                │
│   ┌─────────────────────────┐  ┌──────────────────────────┐    │
│   │ handlers::tproxy_admit  │  │ handlers::dns_resolve    │    │
│   │  • validate session     │  │  • validate session      │    │
│   │  • match SNI/Host vs    │  │  • host-side resolver    │    │
│   │    tproxy_allowlist     │  │  • emit DnsResolveReq.   │    │
│   │  • emit Granted/Denied  │  │    (low-sev) BEFORE resp │    │
│   │    BEFORE response      │  └──────────────────────────┘    │
│   └──────────┬──────────────┘                                  │
│              │ ③ on Admit: open upstream TCP                   │
│              │ ④ register tunnel (tunnel_id, tunnel_token)     │
│              ▼                                                 │
│   ┌──────────────────────────┐                                 │
│   │  kernel tunnel listener  │  guest re-dials with token →    │
│   │  • verifies tunnel_token │  bidirectional copy_bidirectional│
│   └──────────┬───────────────┘                                 │
│              ▼                                                 │
│         host TCP socket → upstream                             │
└────────────────────────────────────────────────────────────────┘
```

The kernel sees every flow. Every flow is audited (admission
granted/denied is paired-write; DNS is low-severity single-class).
The agent has no path around any of this because **there is no NIC
in the VM**.

## 3. Wire protocols

Three IPC envelopes live on the kernel's `tproxy_vsock_port` (per
session, per VM). All three use the same length-prefixed bincode
framing as the planner socket (`peripherals.md §3`).

### 3.1 `IpcMessage::TproxyAdmissionRequest` (guest → kernel)

```rust
pub struct TproxyAdmissionRequest {
    pub request_id:    Uuid,
    pub session_token: String,
    pub sni:           Option<String>,
    pub host_header:   Option<String>,
    pub destination:   SocketAddr,      // post-DNS resolved
    pub protocol:      TproxyProtocol,  // Tcp | Tls | Http
}
```

Kernel matches `sni.or(host_header)` against the session's
`policy.tproxy_allowlist`. The destination IP+port is recorded
for forensics. The protocol guess is used to pick which audit
field carries the hostname (SNI vs Host header). The kernel emits
`TproxyAdmissionGranted` (paired) on Admit and
`TproxyAdmissionDenied` (paired) on Deny, in both cases BEFORE
returning the response (audit-after-decision contract).

### 3.2 `IpcMessage::KernelTproxyAdmissionResponse` (kernel → guest)

```rust
pub enum TproxyAdmissionResponse {
    Admit { tunnel_id: Uuid, tunnel_token: [u8; 32] },
    Deny  { reason: String, hint: Option<String> },
}
```

On Admit the guest opens a **second** vsock connection to
`(VMADDR_CID_HOST, kernel_tunnel_port)`, sends
`tunnel_id || tunnel_token` as the first frame, then byte-copies
between the agent's TCP socket and the vsock stream. The kernel
verifies the token matches the registered tunnel, pairs the vsock
stream with the upstream TCP it opened, and `copy_bidirectional`s
the two streams.

`tunnel_token` is 32 random bytes minted per admission. It is
single-use: the kernel removes the tunnel registration on first
successful handshake, so a leaked token cannot be replayed.

### 3.3 `IpcMessage::DnsResolveRequest` (guest → kernel)

```rust
pub struct DnsResolveRequest {
    pub request_id:    Uuid,
    pub session_token: String,
    pub hostname:      String,
    pub query_type:    DnsQueryType,  // A | AAAA
}

pub struct DnsResolveResponse {
    pub addresses: Vec<IpAddr>,   // empty = NXDOMAIN
    pub ttl_secs:  u32,
}
```

The kernel resolves via the host's standard resolver
(`tokio::net::lookup_host` is sufficient for V2). DNS resolution
itself does NOT grant egress — the subsequent
`TproxyAdmissionRequest` against the resolved address is the gate.
The kernel emits `DnsResolveRequested { hostname, resolved_count,
ttl_secs }` as a single-class low-severity audit event so an
operator can trace which hostnames a session is asking about
even when admission later denies them.

## 4. In-guest enforcement (`crates/planner-core::guest_init`)

When `RAXIS_AIRGAP_A3=1` is set in the guest env (the kernel stamps
this iff the build was compiled with the `runtime-airgap-a3`
feature AND the operator opted in via the same env var at kernel
boot), PID 1 installs:

```
# Redirect all outbound TCP (except loopback) to raxis-tproxy
iptables -t nat -A OUTPUT -p tcp ! -d 127.0.0.1/32 -j REDIRECT --to-port 3129

# Redirect outbound UDP DNS to the in-guest stub
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 53

# Disable IPv6 — kernel admission is IPv4-only in V2; IPv6 would be a covert channel
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/lo/disable_ipv6

# Point libc resolver at the in-guest DNS stub
echo "nameserver 127.0.0.1" > /etc/resolv.conf
```

The credential-proxy loopback ports stay on `127.0.0.1` and so
are NOT redirected (the `! -d 127.0.0.1/32` exception). The
credential proxies bind on `127.0.0.1:<guest_loopback_port>` which
the existing `raxis-tproxy::loopback_forwarder` already splices
to host loopback via vsock.

## 5. Substrate config — no NIC, ever

`EgressTier::Mediated` is the A3 substitute for `Tier1Tproxy`. It
produces:

- `crates/isolation-apple-vz`: `network = None`, no
  `AvfNetworkDevice` at all.
- `crates/isolation-firecracker`: no `network-interfaces` PUT,
  guest kernel boots without `eth0`.

`EgressTier::Tier1Tproxy` is marked `#[deprecated]` but retained
so the default-off path is bit-identical to the legacy build.

## 6. Feature gating

Two layers, both required for A3 to activate:

1. **Cargo feature** `runtime-airgap-a3` on the `raxis-kernel`
   crate. When the feature is OFF the kernel compiles the A3
   handlers / vsock listeners out entirely (they are
   `#[cfg(feature = "runtime-airgap-a3")]`).
2. **Env var** `RAXIS_AIRGAP_A3=1` on the kernel process. When
   the env var is unset the kernel selects `EgressTier::Tier1Tproxy`
   for executor / orchestrator and DOES NOT install the A3
   listeners even when the feature is compiled in.

The witness tests (`kernel/tests/airgap_a3_*.rs`) gate themselves
on the feature; the live-e2e default-off path
(`kernel/tests/extended_e2e_realistic_scenario.rs`) does NOT set
`RAXIS_AIRGAP_A3` and is therefore exercised by the legacy path.

## 7. Operator workflow

See `guides/operator/21-airgap-a3-egress-allowlist.md` for the
end-to-end recipe (authoring `[[tproxy_allowlist]]`, opt-in
flow, common destinations for cargo / npm / pip / git, and the
`live-e2e/docker-compose.airgap-a3.yml` test harness).

## 8. Invariants (canonical home)

This file is the canonical home for:

- `INV-NETISO-A3-UNIVERSAL-NO-NIC-01` — when
  `RAXIS_AIRGAP_A3=1`, no role-image's VM gets a virtio-net
  device.
- `INV-NETISO-A3-VSOCK-CHOKEPOINT-01` — under A3, the kernel's
  tproxy admission gate is the SOLE arbiter of guest egress.
- `INV-NETISO-A3-DNS-MEDIATED-01` — under A3, DNS queries flow
  through the kernel; guest cannot reach external DNS servers.
- `INV-NETISO-A3-IPV6-DISABLED-01` — under A3, IPv6 is disabled
  at PID 1.
- `INV-AUDIT-TPROXY-ADMIT-01` — every `TproxyAdmissionRequest`
  emits a paired audit event (granted or denied) BEFORE the
  response is sent.
- `INV-AUDIT-DNS-RESOLVE-01` — every DNS resolution emits an
  audit event (low-severity, single-class).

Each invariant has a witness test in `kernel/tests/airgap_a3_*.rs`.
