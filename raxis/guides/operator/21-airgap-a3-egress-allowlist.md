# Path A3 universal-airgap egress allowlist (default, only path)

> **Audience.** Operators authoring the `[egress] domains` /
> `[egress] patterns` allowlist that Path A3 enforces on the
> kernel side. Path A3 is **the only egress path** shipped in V2
> after the Tier1Tproxy deletion (TODO
> `tier1-deletion-fold-into-cleanup-sweep`) — there is no opt-in
> toggle, no cargo feature, and no env-var gate. Recipe-level
> detail; the normative contract lives in
> `specs/v2/airgap-architecture.md` and the `INV-NETISO-A3-*` /
> `INV-AUDIT-TPROXY-ADMIT-01` / `INV-AUDIT-DNS-RESOLVE-01`
> invariants.

## Before you start

You will need:

  1. **A current kernel binary.** No cargo feature gating — the
     A3 admission listener (`handlers::tproxy_admit`), the DNS
     resolver (`handlers::dns_resolve`), and the per-session
     vsock admission / tunnel listeners are compiled in
     unconditionally. The previous `runtime-airgap-a3` cargo
     feature was removed alongside the Tier1Tproxy variant; a
     plain release build is all you need:

     ```bash
     cargo build --release -p raxis-kernel
     ```

  2. **An executor rootfs that ships `nft`.** The canonical
     `images/executor-starter/Containerfile` shipped with this
     branch already installs `nftables` + `iproute2`. If you use a
     custom executor image, audit the rootfs for the `nft` binary.
     A3 installs the chokepoint with native nftables so the userspace
     tool and the validated guest-kernel ABI stay aligned.

  3. **A `policy.toml` whose `[egress] domains` / `[egress]
     patterns` cover the upstream hosts the executor's task will
     reach.** Path A3 is fail-closed: a host that is not in the
     effective allowlist (operator-declared + the implicit
     provider grants the policy bundle materialises from
     `[[providers]]`) gets a `TproxyAdmissionDenied` event and an
     `ECONNREFUSED`-shaped failure on the agent side.

## Step 1 — Audit your effective allowlist

Run `raxis policy show effective-egress` (V2.6+) or grep the
audit chain for `DefaultProviderEgressApplied` events emitted at
the last `policy_epoch_history` advance. For a typical workload
that talks to one LLM provider and the package registries the
agent fetches dependencies from, you usually want:

```toml
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

## Step 2 — Run the kernel

No special env vars are required. Boot the kernel as usual:

```bash
raxis kernel run \
    --data-dir /var/lib/raxis \
    --policy /etc/raxis/policy.toml
```

Every Executor VM the kernel spawns boots under
`EgressTier::Mediated` unconditionally:

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
  * Re-issue the policy through `raxis policy sign` and
    `raxis epoch advance --policy <path> --sig <sig>`.

## Step 4 — Operating the gate

  * **Disabling Mediated is not supported in V2.** Mediated is
    the only non-`None` egress tier after the Tier1Tproxy
    deletion; there is no "back to NAT" toggle. If a session must
    boot without egress at all, give it `EgressTier::None`
    (Reviewer / Orchestrator default).
  * **Allowlist edits.** Standard policy update flow. The
    in-guest tproxy reads the kernel's response per-admission;
    there is no in-guest cache to invalidate.
  * **Per-port discovery overrides.** Set
    `RAXIS_AIRGAP_A3_HOST_CID` / `_ADMISSION_PORT` only if your
    substrate exposes a non-default CID; the defaults match
    `VMADDR_CID_HOST`, kernel admission port `5380`, kernel
    tunnel port `5381`. (These per-port env vars survived the
    Tier1Tproxy deletion — only the `RAXIS_AIRGAP_A3=1` ACTIVE
    toggle was removed.)

## Failure modes

  * **`nft` missing from the rootfs.** The PID-1 setup logs
    `nftables_install_failed` and the in-guest tproxy is
    unreachable. Effect: every outbound flow fails with
    ENETUNREACH on the agent side (no NIC). The kernel
    admission gate stays correct; the operator sees a hard
    fail, not a bypass.
  * **Custom executor image without `nft`.** Same as above,
    plus you should add the package to your image build.
  * **Substrate that pre-mounts `/proc` without IPv6 sysfs
    nodes.** The IPv6 disable step skips silently
    (`ipv6_sysfs_unavailable`); already safe because no NIC.

## Why this exists

The pre-deletion V2 baseline executor VM had a virtio-net device
+ NAT NIC but never shipped the in-guest `iptables` REDIRECT
rules that the Tier-1 tproxy needed to be load-bearing. That
meant the admission chokepoint existed in code but not in
practice: an agent that bypassed the tproxy by dialling its
destination directly would reach the upstream unsupervised. Path
A3 closed that gap by removing the NIC entirely and routing every
flow through a chokepoint the kernel controls. The Tier1Tproxy
deletion finished the job by making A3 the only egress path —
operators no longer have to opt in. See
`specs/v2/airgap-architecture.md` for the full architectural
rationale.
