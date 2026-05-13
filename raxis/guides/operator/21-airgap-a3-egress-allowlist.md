# Enable the Path A3 universal-airgap egress chokepoint

> **Audience.** Operators who want to take the kernel from the V2
> baseline (executor VM has a virtio-net device + NAT egress) to
> the Path A3 universal-airgap posture (no virtio-net for any
> role; every outbound flow is admitted by the kernel over
> AF_VSOCK). Recipe-level detail; the normative contract lives in
> `specs/v2/airgap-architecture.md` and the
> `INV-NETISO-A3-*` / `INV-AUDIT-TPROXY-ADMIT-01` /
> `INV-AUDIT-DNS-RESOLVE-01` invariants.

## Before you start

You will need:

  1. **A kernel binary built with the `runtime-airgap-a3` cargo
     feature.** Without it, `RAXIS_AIRGAP_A3=1` is silently
     ignored — the gate is double-checked (feature flag AND env
     var) so an operator cannot accidentally engage A3 against a
     kernel that does not ship the handler code.

     Build it with:

     ```
     cargo build --release -p raxis-kernel --features runtime-airgap-a3
     ```

     If you already ship a release kernel, ask whoever bakes
     the operator-facing distribution to enable
     `runtime-airgap-a3` on the next cut.

  2. **An executor rootfs that ships `iptables`.** The canonical
     `images/executor-starter/Containerfile` shipped with this
     branch already installs `iptables` + `iproute2`. If you use a
     custom executor image, audit the rootfs for the `iptables-nft`
     binary; A3 falls back to plain `iptables` if `iptables-nft` is
     absent, but at least one of them MUST be on `$PATH` inside
     the guest.

  3. **A `policy.toml` whose `[egress] domains` / `[egress]
     patterns` cover the upstream hosts the executor's task will
     reach.** Path A3 is fail-closed: a host that is not in the
     effective allowlist (operator-declared + the implicit
     provider grants the policy bundle materialises from
     `[[providers]]`) gets a `TproxyAdmissionDenied` event and an
     `ECONNREFUSED`-shaped failure on the agent side. The
     legacy Tier-1 path applies the same allowlist; A3 makes it
     load-bearing.

## Step 1 — Audit your effective allowlist

Run `raxis policy show effective-egress` (V2.6+) or grep the
audit chain for `DefaultProviderEgressApplied` events emitted at
the last `policy_epoch_history` advance. For a typical workload
that talks to one LLM provider and the package registries the
agent fetches dependencies from, you usually want:

```
[egress]
domains = [
  # LLM upstream (or accept the implicit-provider grant from
  # [[providers]] and leave this empty).
  "api.anthropic.com",
  # Package managers
  "registry.npmjs.org",
  "pypi.org",
  "files.pythonhosted.org",
  "crates.io",
  "static.crates.io",
  "index.crates.io",
  # GitHub git clones over HTTPS
  "github.com",
  "codeload.github.com",
]
patterns = [
  # AWS-hosted CDNs the package managers redirect to (npm and
  # pypi both fan out to *.cloudfront.net for tarball downloads).
  "*.cloudfront.net",
  # GitHub release-asset CDNs.
  "objects.githubusercontent.com",
]
```

Pay attention to the **post-redirect** target host. If `pip
install` hits `pypi.org` first and then redirects to
`*.pythonhosted.org`, BOTH need to be allowlisted; the in-guest
tproxy re-issues admission for every new flow even within a
single `pip install` invocation.

## Step 2 — Engage the gate

Set the runtime env var on the kernel process:

```
RAXIS_AIRGAP_A3=1 raxis kernel run \
    --data-dir /var/lib/raxis \
    --policy /etc/raxis/policy.toml
```

The kernel logs a single `airgap-a3-active=true` line at boot
when it has accepted the gate (feature compiled in AND env var
recognised). Absence of that line means A3 is OFF; check both
the cargo feature and the env-var spelling.

From this point on, every Executor VM the kernel spawns boots
under `EgressTier::Mediated`:

  * **No virtio-net** in the AVF / Firecracker config
    (`INV-NETISO-A3-UNIVERSAL-NO-NIC-01`).
  * **`/etc/resolv.conf` points at `127.0.0.1`** inside the guest
    (`INV-NETISO-A3-DNS-MEDIATED-01`).
  * **IPv6 is hard-disabled** (`INV-NETISO-A3-IPV6-DISABLED-01`).
  * **All outbound TCP is REDIRECTed** to the in-guest tproxy on
    `127.0.0.1:3129`, which talks to the kernel's admission
    listener over AF_VSOCK
    (`INV-NETISO-A3-VSOCK-CHOKEPOINT-01`).
  * **Every admission decision is audited** before the response
    is sent to the guest
    (`INV-AUDIT-TPROXY-ADMIT-01`).
  * **Every DNS resolution is audited**
    (`INV-AUDIT-DNS-RESOLVE-01`).

## Step 3 — Verify the chokepoint is doing its job

Run a session whose plan exercises egress (`pip install`, `npm
install`, a `curl` to a known-bad host). The audit chain should
contain matching `TproxyAdmissionGranted` / `TproxyAdmissionDenied`
events with the `host_or_sni`, `original_dst_ip`,
`original_dst_port`, and stable `reason` taxonomy. A known-bad
host (e.g. `evil.example.com`) MUST surface as
`TproxyAdmissionDenied{reason="host_not_in_allowlist"}`; the
agent's libc will see `ECONNREFUSED` and the tool will fail with
a structured error.

If you see a `TproxyAdmissionGranted` for a host that should be
denied, fix the policy IMMEDIATELY:

  * Remove the host from `[egress] domains` if it was added by
    mistake.
  * Tighten an overly permissive `*` pattern to a narrower glob.
  * Re-issue the policy via the operator-cert sign path; the
    kernel's hot-reload picks up the new bundle without a
    restart.

## Step 4 — Operating the gate

  * **Disabling.** Unset `RAXIS_AIRGAP_A3` on the kernel
    process. New sessions will boot through the legacy
    Tier1Tproxy path again; existing sessions retain whatever
    posture they spawned under.
  * **Allowlist edits.** Standard policy update flow. The
    in-guest tproxy reads the kernel's response per-admission;
    there is no in-guest cache to invalidate.
  * **DNS troubleshooting.** Set
    `RAXIS_AIRGAP_A3_HOST_CID` / `_ADMISSION_PORT` only if your
    substrate exposes a non-default CID; the defaults match
    `VMADDR_CID_HOST`, kernel admission port `5380`, kernel
    tunnel port `5381`.

## Failure modes

  * **`iptables` missing from the rootfs.** The PID-1 setup logs
    `iptables_install_failed` and the in-guest tproxy is
    unreachable. Effect: every outbound flow fails with
    ENETUNREACH on the agent side (no NIC). The kernel
    admission gate stays correct; the operator sees a hard
    fail, not a bypass.
  * **Custom executor image without `iptables`.** Same as above,
    plus you should add the package to your image build.
  * **Substrate that pre-mounts `/proc` without IPv6 sysfs
    nodes.** The IPv6 disable step skips silently
    (`ipv6_sysfs_unavailable`); already safe because no NIC.
  * **`RAXIS_AIRGAP_A3=1` set on a kernel built without the
    cargo feature.** Gate is OFF (double-check passes); kernel
    logs `airgap-a3-active=false` so the operator can spot the
    misconfiguration before a session spawns.

## Why this exists

The V2 baseline executor VM had a virtio-net device + NAT NIC
but never shipped the in-guest `iptables` REDIRECT rules that
the Tier-1 tproxy needed to be load-bearing. That meant the
admission chokepoint existed in code but not in practice: an
agent that bypassed the tproxy by dialling its destination
directly would reach the upstream unsupervised. Path A3 closes
that gap by removing the NIC entirely and routing every flow
through a chokepoint the kernel controls. See
`specs/v2/airgap-architecture.md` for the full architectural
rationale.
