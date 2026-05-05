# RAXIS V2 — System Requirements

> **Status:** V2 Specified
> **Audience:** Operators evaluating, installing, or deploying RAXIS V2 on a host.
> **Cross-references:**
> - `specs/v2/host-capacity.md` — runtime resource caps; this spec specifies the host's prerequisite capabilities for those caps to be enforceable
> - `specs/v2/kernel-lifecycle.md` — daemon mode prerequisites (systemd / launchd availability)
> - `specs/v2/v2-deep-spec.md §raxis-gateway` — provider API egress prerequisites
> - `specs/v2/credential-proxy.md` — `INV-VM-CAP-04`; constrains VM-side credential exposure but does not change host requirements
> - `specs/v2/integration-merge.md` — git binary / `gix` requirements

---

## 1. Overview

RAXIS V2 is a single-host control plane consisting of `raxis-kernel` (the trusted authority), `raxis-gateway` workers (provider proxies), `raxis-egress` (web egress proxy), and zero-or-more agent microVMs (each running `raxis-planner` plus `raxis-tproxy`). All components run on one physical or virtual host. There are no cluster, multi-host, or distributed-state requirements in V2.

### 1.1 Quick reference matrix

| Concern | Requirement | Notes |
|---|---|---|
| **Operating system** | Linux 5.10+ OR macOS 13.0+ | Windows not supported |
| **CPU architecture** | `x86_64` or `aarch64` | Both Linux and macOS supported on both archs |
| **Hypervisor** | Linux: KVM (`/dev/kvm`)<br>macOS: Apple Virtualization.framework | Hard requirement; the kernel will not start without |
| **Minimum memory** | 4 GB | Single small initiative; smallest viable deployment |
| **Recommended memory** | 32–128 GB | Scales with `max_aggregate_vm_memory_mb`; see §3.3 |
| **Minimum disk** | 50 GB at `disk_root` | Audit log + state.db + at least one worktree |
| **Recommended disk** | 200 GB to 4 TB | Scales with audit retention; see §4.3 |
| **File descriptors** | `ulimit -n` ≥ 4096 | Enforced at startup per `host-capacity.md §12` |
| **Filesystem at `disk_root`** | POSIX-compatible with atomic rename and `fsync` | ext4, XFS, APFS all supported |
| **Outbound network** | HTTPS to configured LLM provider APIs | Plus operator-allowlisted egress per `policy.toml` |
| **Inbound network** | None | The kernel listens only on local UDS sockets |
| **Daemon mode** | systemd (Linux) or launchd (macOS) | Required only if using `--daemon`; foreground mode has no supervisor requirement |
| **External tooling** | `git` ≥ 2.30, SQLite ≥ 3.35 | `gix` for native operations; `git` shells out for fallback |

### 1.2 Validation: `raxis doctor`

Operators can validate their host with a single command before running anything else:

```bash
$ raxis doctor
```

`raxis doctor` (§11) checks every requirement in this document and reports pass/fail per check. Operators evaluating a new host should run it first; operators deploying to production should run it as part of their installation playbook.

---

## 2. Operating System Support

### 2.1 Linux

**Supported distributions:** any with kernel 5.10 or later. Tested matrix includes:

| Distribution | Minimum version | Notes |
|---|---|---|
| Ubuntu | 22.04 LTS | systemd + journald; recommended for new deployments |
| Debian | 12 (Bookworm) | systemd + journald |
| Fedora | 38+ | systemd + journald |
| Rocky / RHEL / CentOS Stream | 9+ | systemd + journald |
| Arch Linux | rolling | systemd + journald |
| Alpine Linux | 3.18+ | OpenRC default; daemon mode requires systemd or operator-provided init script |
| NixOS | 23.11+ | systemd + journald via nixpkgs |

**Required kernel features:**

- KVM (`CONFIG_KVM=y` or `CONFIG_KVM=m` and module loaded)
- VirtIO drivers (`CONFIG_VIRTIO_NET`, `CONFIG_VIRTIO_BLK`, `CONFIG_VIRTIO_FS`)
- VSOCK (`CONFIG_VSOCKETS`, `CONFIG_VHOST_VSOCK`)
- cgroups v2 (`CONFIG_CGROUPS=y` and unified hierarchy mounted at `/sys/fs/cgroup`)

**Recommended kernel features:**

- `CONFIG_USER_NS=y` (user namespaces; useful for additional isolation hardening)
- `CONFIG_SECCOMP=y` (the kernel applies seccomp filters to gateway workers)
- XFS with `prjquota` enabled, OR ZFS, for hard per-worktree disk quotas (per `host-capacity.md §6.1`); without these, soft enforcement applies

### 2.2 macOS

**Supported versions:** macOS 13.0 (Ventura) or later. Tested on macOS 13, 14, 15.

| macOS version | Status | Notes |
|---|---|---|
| 13.0 (Ventura) | ✓ Supported | Minimum; VirtioFS and VSOCK both available |
| 14.0 (Sonoma) | ✓ Recommended | Improved Virtualization.framework error reporting |
| 15.0 (Sequoia) | ✓ Recommended | |
| 12.x (Monterey) and earlier | ✗ Not supported | VirtioFS not available; required for `/workspace` and `/raxis` mounts |

**Required macOS features:**

- Apple Virtualization.framework (built-in since macOS 11.0; usable for our purposes since 13.0)
- launchd (built-in)
- Code signing: RAXIS binaries must be signed (Gatekeeper requirement); pre-built distributions are signed by the RAXIS team's developer ID. Operators building from source on their own machine can sign locally with `codesign --sign -`.

**macOS-specific limitations:**

- Hard filesystem quotas are not natively supported on APFS; soft enforcement only.
- File descriptor limits on macOS default to 256 per process; `raxis kernel start` automatically calls `setrlimit(RLIMIT_NOFILE, 65536)` on startup, but launchd plists also need `SoftResourceLimits.NumberOfFiles = 65536` (already in the generated plist per `kernel-lifecycle.md §5`).

### 2.3 Windows: not supported

Windows is not supported in V2 for the kernel or microVM hosting. The kernel's hypervisor abstraction targets KVM and Apple Virtualization.framework; supporting Hyper-V would require a third hypervisor backend with its own VirtioFS, VSOCK, and credential-proxy semantics. This is V3+ scope at earliest, contingent on customer demand.

The `raxis` CLI binary may be built for and run on Windows for the purpose of submitting intents to a remote Linux- or macOS-hosted kernel via SSH-tunneled UDS. This is operator-DIY in V2 and not first-class supported.

### 2.4 Unsupported configurations explicitly documented

The following are known to NOT work:

- **WSL1** (Windows Subsystem for Linux v1): does not provide a real Linux kernel; KVM not available.
- **WSL2:** technically a real Linux kernel, but nested virtualization (KVM-on-Hyper-V) is unreliable; not recommended.
- **Docker containers (kernel-inside-container):** the kernel needs `/dev/kvm` access, privileged mode, and host PID namespace participation, which defeats container isolation. The `raxis-archiver` and `raxis-gateway` worker processes can run in containers (V3+); the kernel cannot.
- **Nested KVM:** running RAXIS inside a KVM guest that itself runs KVM (e.g., on a cloud VM whose host enables nested virt). Works in principle but is unreliable on most cloud providers; performance is significantly degraded. Use bare-metal cloud instances (AWS metal, GCP sole-tenant nodes) for production.
- **Apple Silicon Linux distributions** (Asahi Linux, etc.): KVM availability is partial and varies by hardware; not in the V2 tested matrix.

---

## 3. Hardware Requirements

### 3.1 CPU architecture

V2 supports `x86_64` and `aarch64`. Specific feature requirements:

**`x86_64`:**

- Hardware virtualization: VT-x (Intel) or AMD-V (AMD), enabled in BIOS/UEFI
- AES-NI (for fast cryptographic operations in the kernel)
- POPCNT, SSE4.2 (Rust standard library expects these on x86_64)

**`aarch64`:**

- ARMv8-A or later
- Virtualization extensions (EL2, GIC v3): standard on Apple Silicon, Cavium, Ampere; check vendor docs for embedded/older parts
- AES extensions (FEAT_AES)

The kernel checks for hardware virtualization at startup (`/dev/kvm` access on Linux; Virtualization.framework availability on macOS) and refuses to start if absent.

### 3.2 CPU core requirements

| Deployment size | Recommended cores | Reasoning |
|---|---|---|
| Minimum | 2 | 1 for kernel; 1 for one small VM. Adequate only for evaluation. |
| Single developer | 4–8 | Kernel + 2-4 concurrent agents + OS overhead |
| Small team (5–10 operators) | 16 | Default `max_concurrent_vms = 16`; one core per VM is comfortable |
| Production (50+ operators) | 32–64 | Higher VM concurrency; larger admission queue; more headroom for SQLite WAL checkpointing |

The kernel itself is single-threaded for its main intent dispatch loop (per the existing `kernel-core.md`); additional cores benefit microVMs (each pinned to its own vCPU) and parallel SQLite reads.

### 3.3 Memory requirements

Memory budget breaks into three categories:

```
Total host memory >= max_aggregate_vm_memory_mb        // VM workload (per host-capacity.md §5)
                  + kernel_reserved_memory_mb           // kernel + SQLite + audit buffers (default 1 GB)
                  + os_and_system_overhead              // OS, system services, monitoring, etc.
```

`os_and_system_overhead` should be at least 2 GB on Linux, 4 GB on macOS (macOS's working-set is heavier).

| Deployment size | RAM | `max_aggregate_vm_memory_mb` (recommended) |
|---|---|---|
| Minimum | 4 GB | 1024 (one 1-GB VM at a time) |
| Single developer | 16 GB | 12288 (12 GB; e.g., 6 × 2-GB VMs) |
| Small team | 64 GB | 49152 (48 GB; e.g., 16 × 3-GB VMs or 8 × 6-GB VMs) |
| Production | 128–256 GB | 98304–229376 (96 GB to 224 GB) |

The kernel's `host-capacity.md §15.4` invariant ensures it never overcommits — sizing is deterministic from the cap configured in `policy.toml`. Overcommit (relying on host swap or OOM-killer) is explicitly disallowed.

### 3.4 Disk requirements

See §4 for filesystem feature requirements; here we cover capacity.

| Deployment size | Disk at `disk_root` | Audit retention horizon (V2; V3 archiving extends this) |
|---|---|---|
| Minimum | 50 GB | ~30 days at light load |
| Single developer | 200 GB | ~6 months |
| Small team | 500 GB to 1 TB | ~1 year |
| Production | 1–4 TB OR V3 archiving | 1–7+ years |

The audit log is the dominant long-term grower. Without V3 archive lifecycle, audit segments accumulate forever (capped only by `min_free_disk_mb` halt per `host-capacity.md §7`). V2 GA deployments planning to keep more than ~1 year of audit data should plan for V3 upgrade and archive provisioning during that horizon.

Other disk consumers:

| Subsystem | Typical size | Notes |
|---|---|---|
| `state.db` (SQLite) | 100 MB to 5 GB | Grows with `pending_pushes`, indexed views, escalations |
| `master_repos/` | 10 MB to 5 GB per initiative | Soft cap: `master_repo_quota_mb` (default 8 GB) per `host-capacity.md §6.2` |
| `worktrees/` | up to 2 GB per active session | Hard cap: `worktree_quota_mb` (default 2 GB) per `host-capacity.md §6.1` |
| `bundles/` | small (KBs to MBs); ephemeral | Per-initiative bundle staging |
| `artifacts/` (immutable artifact store) | 1 to 100 GB | Operator-bound via `artifact_store_quota_gb` (default 100 GB) |

Storage performance: SSD strongly recommended (NVMe preferred). Spinning disks work for very small deployments but SQLite WAL checkpointing performance degrades substantially.

### 3.5 Network bandwidth

Outbound bandwidth requirements scale with provider API call volume:

- A single Anthropic Claude Opus call with 10K input tokens, 4K output tokens consumes ~50 KB request / ~20 KB streamed response, completing in 3–10 seconds (model-dependent).
- A loaded Orchestrator session may run 10–100 such calls per minute.
- 16 concurrent VMs at peak load can produce 100+ Mbps of provider API traffic.

Recommended:

- 100 Mbps minimum (sufficient for small developer setup)
- 1 Gbps for small team deployments
- 10 Gbps for production with many concurrent agents and active V3 archive uploads

Latency: sub-100ms RTT to the chosen provider's nearest endpoint significantly improves agent-loop wall-clock time.

---

## 4. Filesystem Requirements

### 4.1 POSIX semantics

The `disk_root` filesystem (default `/var/lib/raxis`) MUST support:

- **Atomic rename within filesystem.** Used pervasively for crash-safe writes per `integration-merge.md §11`, `audit-retention.md §4.3` (V3), and many other transactional patterns.
- **`fsync(2)` durability.** The kernel calls `fsync` before signaling completion of any persistent state change.
- **`O_DIRECT` is NOT required** but is harmless if the filesystem supports it.
- **POSIX file locks** (`fcntl(F_SETLK)`): used as a secondary mechanism alongside SQLite's write lock per `kernel-lifecycle.md §8`.
- **Hard links and symlinks** in the audit and worktrees directories.

All major Linux filesystems (ext4, XFS, Btrfs, ZFS) and macOS APFS satisfy these. Network filesystems (NFS, SMB, FUSE) are NOT supported as `disk_root` — atomic-rename and fsync semantics are unreliable across all of them.

### 4.2 Filesystem feature recommendations

| Feature | Effect on RAXIS | Filesystems that have it |
|---|---|---|
| `prjquota` (project quotas) | Hard worktree disk quotas per `host-capacity.md §6.1`; without, soft enforcement only | XFS (with `prjquota` mount option), ZFS (datasets) |
| Snapshot support | Operator backup workflows much simpler | Btrfs, ZFS, APFS, XFS (with stratis) |
| Native compression | Reduces audit log storage | Btrfs (zstd), ZFS (zstd/lz4), APFS (lzfse) |
| Encryption-at-rest | Recommended for any sensitive deployment | LUKS (under any FS), ZFS native, APFS encrypted volumes, FileVault (macOS) |

**Encryption note:** RAXIS does not encrypt its on-disk state itself. Operators handling sensitive data SHOULD enable filesystem-level encryption (LUKS / APFS encrypted / ZFS native). The kernel's `disk_root` should never be on an unencrypted volume in production deployments handling regulated data.

### 4.3 Path layout

The kernel uses these paths (all under `disk_root`):

```
/var/lib/raxis/                           # disk_root
├── state.db                               # SQLite kernel state
├── state.db-wal
├── state.db-shm
├── audit/                                 # append-only audit log segments
│   ├── 0001.log
│   └── ...
├── artifacts/                             # immutable artifact store (policies, plans, keys)
│   ├── policies/<sha>/
│   ├── plans/<sha>/
│   └── keys/<fingerprint>/
├── master_repos/                          # bare git repos, one per initiative
│   └── <initiative_uuid>/
├── worktrees/                             # per-session worktrees (mounted into VMs)
│   └── <session_uuid>/
├── bundles/                               # ephemeral inter-agent git bundles
│   └── <initiative_uuid>/
└── tmp/                                   # scratch space (cleaned at startup)
```

Per `host-capacity.md §6.3`, sizes per subsystem are independently capped. Operators may mount `audit/` on a separate filesystem from the rest of `disk_root` if they want stricter isolation between audit storage and operational state; the audit-reserve mechanism (per `host-capacity.md §7.5`) operates on whichever filesystem `audit/` lives on.

---

## 5. Hypervisor Requirements

### 5.1 Linux: KVM

**Hard requirements:**

- `/dev/kvm` exists.
- The user running `raxis-kernel` has read/write access to `/dev/kvm`. Typically achieved by adding the user to the `kvm` group:
  ```bash
  sudo usermod -a -G kvm $USER
  # log out and back in for the group change to take effect
  ```
  For system mode (per `kernel-lifecycle.md §9.2`), the dedicated `raxis` user must also be in `kvm` group.
- CPU virtualization extensions enabled in firmware (VT-x or AMD-V on x86_64; EL2 on aarch64).

**Verification:**

```bash
$ ls -l /dev/kvm
crw-rw---- 1 root kvm 10, 232 May  4 09:00 /dev/kvm

$ groups
alice ... kvm

$ kvm-ok                               # ubuntu/debian: virt-host validation
INFO: /dev/kvm exists
KVM acceleration can be used
```

`raxis doctor` (§11) checks all of these.

### 5.2 macOS: Apple Virtualization.framework

**Hard requirements:**

- macOS 13.0+ (per §2.2).
- Code-signing entitlement `com.apple.security.virtualization` on the kernel binary. Pre-built distributions ship with this entitlement; from-source builds need to be re-signed with it (the build process handles this when run on macOS).
- The kernel binary must NOT be quarantined (Gatekeeper). Pre-built binaries downloaded via the standard installer are de-quarantined automatically.

**Verification:**

```bash
$ codesign -d --entitlements - /usr/local/bin/raxis-kernel
... <key>com.apple.security.virtualization</key><true/> ...

$ xattr /usr/local/bin/raxis-kernel
# (no output = not quarantined; expected)
```

### 5.3 Why no third hypervisor (Hyper-V, Xen, etc.)

The hypervisor abstraction in V2 is opinionated: KVM for Linux, Virtualization.framework for macOS. Each is the platform-native choice with the strongest VirtioFS and VSOCK support and the simplest credential-proxy integration (per `credential-proxy.md`).

Adding a third hypervisor (Hyper-V for Windows, Xen for some embedded Linux distros, or a userspace alternative like QEMU-without-KVM) would require:

- A third backend in the kernel's hypervisor module
- A third path through the VirtioFS/VSOCK protocol implementation
- A third validation matrix for credential proxy semantics
- A third tested distribution channel

Customer demand for any of these has not materialized; if it does, V3+ will revisit.

---

## 6. Network Requirements

### 6.1 Outbound

The kernel itself makes outbound connections only for `git push` to operator-configured master repositories (per `INV-CRED-KERNEL-01` from the V2 design discussion). Other components have their own outbound needs:

| Component | Outbound to | Port | Notes |
|---|---|---|---|
| `raxis-kernel` | `git push` destinations | 22 (SSH), 443 (HTTPS) | Configured in `policy.toml` master-repo bindings |
| `raxis-gateway` workers | LLM provider APIs | 443 | Provider list in `policy.toml [[providers.credentials]]` |
| `raxis-egress` | URLs in `[plan] allowed_egress` | typically 443 | Per-plan operator authorization |
| `raxis-archiver` (V3) | Archive backend (S3, Azure, etc.) | 443 | Operator-configured |

**Provider API endpoints** (default):

| Provider | Endpoint | Port |
|---|---|---|
| Anthropic | `api.anthropic.com` | 443 |
| OpenAI | `api.openai.com` | 443 |
| (future providers) | per `policy.toml [[providers.credentials]]` | 443 |

Operators must allowlist these endpoints in any host-side firewall (egress rules). The kernel does NOT bypass operator-side firewall configuration; if a configured provider endpoint is unreachable, every inference attempt to that provider fails with `Unavailable` per `provider-failure-handling.md §5.1`.

### 6.2 Inbound

The kernel listens ONLY on local Unix domain sockets:

| Socket | Default path | Purpose |
|---|---|---|
| Operator IPC | `/var/run/raxis/operator.sock` | CLI submits intents (`raxis approve-plan`, etc.) |
| Gateway worker pool | `/var/run/raxis/gateway-workers/{0..N-1}.sock` | Kernel ↔ gateway worker IPC |
| Archiver (V3) | `/var/run/raxis/archiver.sock` | Kernel ↔ archiver IPC |

There are NO listening TCP ports. Operators wanting to submit intents from a remote machine must use SSH tunneling to forward the local UDS to a remote socket; this is documented as an advanced workflow but is not first-class supported in V2.

### 6.3 DNS

DNS resolution is required for outbound provider API calls. The kernel uses the standard libc resolver (`getaddrinfo`); no custom DNS configuration is required. Operators may configure their host's DNS (`/etc/resolv.conf` or platform equivalent) to point at internal DNS servers if they have egress filtering policies that require it.

### 6.4 TLS root certificates

The kernel and gateway workers use the platform's TLS root certificate store:

- Linux: `/etc/ssl/certs/ca-certificates.crt` (or distribution-specific equivalent)
- macOS: System Keychain trust roots

If operators run with custom CA certificates (e.g., for internal proxies that re-sign TLS), the standard platform mechanism for installing them works (e.g., `update-ca-certificates` on Debian; Keychain Access on macOS). RAXIS does not maintain its own root certificate bundle.

---

## 7. User Accounts and Privileges

### 7.1 User mode (per `kernel-lifecycle.md §9.1`)

The kernel runs as the operator's existing user account. No special user creation is needed beyond:

- Add the user to the `kvm` group (Linux) for `/dev/kvm` access
- Ensure the user can write to `RAXIS_HOME` (default `~/.local/share/raxis` on Linux, `~/Library/Application Support/raxis` on macOS)

### 7.2 System mode (per `kernel-lifecycle.md §9.2`)

System mode requires:

- A dedicated `raxis` system user (Linux) or `_raxis` (macOS convention), created at install time by `sudo raxis kernel install --system`
- The dedicated user must also be in `kvm` group on Linux
- A `raxis` group with members granted operator IPC access via group ownership of `/var/run/raxis/operator.sock`
- `sudo` available for install, uninstall, start, and stop operations

### 7.3 Privilege bounds during runtime

Once installed, the kernel does NOT require elevated privileges to run. Specifically:

- The kernel does not need root or `CAP_SYS_ADMIN` once `/dev/kvm` access is granted
- No `setuid` binaries are involved
- The kernel does not write outside `disk_root`, `/var/run/raxis/`, and `/var/log/raxis/` (system mode)

This means: an exploited kernel cannot directly write `/etc/passwd`, modify `/proc/sys`, or perform other root-only operations. The blast radius of a kernel-level compromise is bounded by the `raxis` user's filesystem and group permissions.

---

## 8. External Dependencies

### 8.1 Required at runtime

| Dependency | Minimum version | Purpose | Source |
|---|---|---|---|
| `git` | 2.30 | Fallback for complex git operations not yet supported by `gix` | OS package manager |
| SQLite | 3.35 (for `RETURNING` clause) | Kernel state store | Linked statically into the kernel binary; no external dependency |
| OpenSSL or rustls | rustls bundled | TLS for outbound HTTPS | Bundled with the binary |

The kernel binary is statically-linked for SQLite, rustls, and most other dependencies — distribution is a single binary with minimal runtime dependencies. The only runtime executables RAXIS shells out to:

- `git` (for the small set of git operations not yet in `gix`)
- The hypervisor binary (Linux: bundled Firecracker; macOS: Apple Virtualization.framework via Swift bridge)

### 8.2 Required for daemon mode (per `kernel-lifecycle.md`)

| Dependency | Required for | Notes |
|---|---|---|
| systemd | Linux user/system daemon mode | Standard on every modern Linux distribution |
| `loginctl` | Linux user daemon mode | Bundled with systemd |
| launchd | macOS user/system daemon mode | Built into macOS |

### 8.3 Required for V3 (audit retention; out of V2 scope)

| Dependency | Required for | Notes |
|---|---|---|
| Archive backend SDK | V3 archiver sidecar | Operator-chosen; the reference archiver supports S3, Azure, local mirror |
| External anchor service (optional) | V3 witness publication | Sigstore Rekor (default), CT log, custom HTTP |

### 8.4 Recommended for operations

| Dependency | Why recommended | Notes |
|---|---|---|
| A monitoring agent (Prometheus node-exporter, Datadog agent, etc.) | Host capacity visibility | RAXIS exposes metrics via `raxis kernel status` and audit events; agent integration is operator-DIY in V2 |
| Log shipper (vector, fluentd, etc.) | Centralized operational logs | journald or `kernel.{out,err}` files are the source |
| Backup tool (restic, borg, snapshots) | Disaster recovery for `disk_root` | Audit log + state.db + master_repos are the critical state |

---

## 9. Building from Source

For operators wanting to build RAXIS from source rather than use pre-built binaries:

### 9.1 Build toolchain

| Component | Minimum version | Notes |
|---|---|---|
| Rust toolchain | 1.78 | Pin via `rust-toolchain.toml` in the repo |
| `cargo` | bundled with Rust | |
| `git` | 2.30 | For fetching dependencies |
| `pkg-config` | any | For native library discovery |
| C/C++ compiler | gcc 9+ or clang 12+ | For building bundled SQLite, etc. |
| `make` | any POSIX-compatible | |

### 9.2 Platform-specific build dependencies

**Linux:**

- `libssl-dev` or `libssl3` development headers (alternative: build with `--features rustls-only` to avoid OpenSSL)
- Linux kernel headers matching the running kernel (`linux-headers-$(uname -r)`)
- For Firecracker integration: the bundled Firecracker source tree builds as part of the kernel build

**macOS:**

- Xcode Command Line Tools (`xcode-select --install`)
- Swift toolchain (bundled with Xcode CLI Tools)
- macOS SDK matching deployment target (13.0)

### 9.3 Build invocation

```bash
$ git clone https://github.com/raxis-ai/raxis
$ cd raxis
$ cargo build --release
$ sudo ./target/release/raxis kernel install --system  # production install
```

The build process is documented in detail in `docs/building.md` (separate from this requirements document).

---

## 10. Recommended Deployment Topologies

### 10.1 Single-host single-user (developer workstation)

```
[ Operator's laptop or workstation ]
  ├── raxis-kernel (--daemon, user mode)
  ├── raxis-gateway (worker pool, default 4 workers)
  ├── raxis-egress
  └── microVMs (up to max_concurrent_vms)
```

User-mode install via `raxis kernel start --daemon`. State lives under `~/.local/share/raxis/`. Operator submits intents via local UDS.

Suitable for: developer evaluation, personal-use AI agent workflows, single-tenant CI runners.

### 10.2 Single-host multi-user (small team server)

```
[ Dedicated Linux server ]
  ├── raxis-kernel (--daemon --system, runs as 'raxis' user)
  ├── raxis-gateway (worker pool)
  ├── raxis-egress
  └── microVMs (up to max_concurrent_vms)

[ Operator workstations ]
  └── raxis CLI → SSH-tunneled UDS → kernel
```

System-mode install via `sudo raxis kernel install --system`. Operators are members of the `raxis` group; they SSH to the server and submit intents via the operator UDS, OR they tunnel the UDS over SSH and run the CLI locally.

Suitable for: small teams (5–25 operators) sharing a dedicated AI agent control plane.

### 10.3 Single-host air-gapped

```
[ Air-gapped server, no internet egress ]
  ├── raxis-kernel
  ├── raxis-gateway → on-prem LLM endpoint (e.g., self-hosted vLLM, Llama.cpp server)
  ├── raxis-egress (allowlist limited to internal endpoints)
  └── microVMs
```

For environments where outbound internet is forbidden. Operator must run an internal LLM serving infrastructure and configure provider endpoints in `policy.toml` to point at internal URLs. Air-gapped deployments cannot use Sigstore Rekor for V3 witness anchoring; they would use an internal anchor service or local-only witnesses.

Suitable for: defense, classified research, regulated medical, air-gapped financial infrastructure.

### 10.4 Multi-host: NOT supported in V2

V2 is single-host. There is no protocol for multiple kernel instances to share state, coordinate sessions, or load-balance intents. Operators with workloads exceeding a single host's capacity should:

- Scale the host vertically (more CPU, more RAM, more disk)
- Run separate independent RAXIS instances on separate hosts (each with its own `policy.toml` and audit log)

True multi-host distribution is out of scope for V2 and not currently planned for V3.

---

## 11. The `raxis doctor` Preflight Check

`raxis doctor` is the canonical command for validating that a host meets RAXIS V2's requirements. It runs every check in this document and reports pass/fail per check.

### 11.1 Invocation

```bash
$ raxis doctor                              # interactive output
$ raxis doctor --json                       # structured JSON for tooling
$ raxis doctor --strict                     # exit 1 on warnings as well as failures
$ raxis doctor --check network              # just one category: network
$ raxis doctor --check filesystem,memory    # specific categories
```

Categories:
- `os` — OS version, kernel features, distribution
- `cpu` — architecture, virtualization extensions
- `memory` — total RAM and recommendations
- `disk` — `disk_root` capacity, free space, filesystem type and features
- `hypervisor` — `/dev/kvm` access, Virtualization.framework availability
- `filesystem` — POSIX features, atomic rename, fsync, quota support
- `network` — outbound connectivity to configured providers (only if `policy.toml` exists)
- `daemon` — systemd or launchd availability, lingering state (Linux user mode)
- `dependencies` — `git`, SQLite version, TLS roots
- `permissions` — `/dev/kvm` access, group memberships, sudo for `--system` operations

### 11.2 Sample output

```
$ raxis doctor
RAXIS preflight check (raxis 2.0.0)
====================================

Operating System
  ✓ Linux 6.5.0-21-generic (supported: 5.10+)
  ✓ Ubuntu 22.04 LTS (supported)
  ✓ x86_64 architecture
  ✓ systemd 252 (daemon mode supported)

CPU
  ✓ 16 cores available (recommended for production: 16+)
  ✓ VT-x virtualization extensions enabled
  ✓ AES-NI supported

Memory
  ✓ 64 GB total RAM
  ⓘ Recommended max_aggregate_vm_memory_mb: 49152 (48 GB)
  ⓘ Reserve 1 GB for kernel + ~2 GB for OS overhead

Hypervisor
  ✓ /dev/kvm exists
  ✓ User 'alice' has /dev/kvm access (member of 'kvm' group)
  ✓ KVM module loaded
  ✓ Nested virtualization NOT detected (good — bare metal)

Filesystem
  ✓ /var/lib/raxis exists (will be created if needed)
  ✓ Filesystem type: ext4
  ✓ Atomic rename: yes
  ✓ fsync durability: yes
  ⚠ Project quotas (prjquota): not enabled
    Consequence: worktree disk quotas use SOFT enforcement only (per host-capacity.md §6.1)
    Mitigation: re-mount /var/lib/raxis with prjquota OR accept soft-only enforcement
  ✓ Free space: 89 GB at /var/lib/raxis (recommended: 200+ GB for production)

Network
  ✓ Outbound HTTPS to api.anthropic.com (port 443) succeeded
  ✓ Outbound HTTPS to api.openai.com (port 443) succeeded
  ✓ DNS resolution working
  ✓ TLS root certificates: /etc/ssl/certs/ca-certificates.crt (442 roots)

File descriptors
  ✓ ulimit -n: 65536 (required: 4096+)

External dependencies
  ✓ git 2.42.0 at /usr/bin/git
  ✓ SQLite 3.42.0 (linked statically; required: 3.35+)

Daemon mode (per kernel-lifecycle.md)
  ✓ systemd available; user services supported
  ⓘ Lingering not yet enabled (will be enabled at first --daemon install)

Result: 1 WARNING, 0 FAILURES
RAXIS will run on this host. Address the warning above for production hardening.

For production deployments, also review:
  - specs/v2/host-capacity.md §3 to tune capacity caps for your hardware
  - specs/v2/kernel-lifecycle.md §11.2 for production install workflow
  - specs/v2/policy-plan-authority.md for policy structure
```

A failure (e.g., no `/dev/kvm`) produces:

```
✗ /dev/kvm does not exist
  RAXIS requires KVM hardware virtualization on Linux.
  Mitigations:
    - On bare metal: enable VT-x or AMD-V in your firmware (BIOS/UEFI) settings
    - On a cloud VM: use an instance type that supports nested virtualization
      (AWS metal instances, GCP sole-tenant nodes); most managed VMs do NOT
    - On WSL2: not supported per system-requirements.md §2.4
  See: specs/v2/system-requirements.md §5.1

Result: 1 WARNING, 1 FAILURE
RAXIS cannot run on this host. Resolve the failure above.
```

### 11.3 Integration with kernel startup

`raxis kernel start` automatically runs the subset of `raxis doctor` checks that block startup (the failure cases). If any fail, the kernel refuses to start and prints the same actionable mitigations. Operators can run the full `raxis doctor` separately for the warnings (which don't block startup but indicate suboptimal configuration).

### 11.4 JSON output for tooling

```bash
$ raxis doctor --json | jq '.checks[] | select(.status == "warning")'
{
  "category": "filesystem",
  "name": "project_quotas",
  "status": "warning",
  "message": "Project quotas (prjquota) not enabled",
  "consequence": "Soft enforcement only for worktree quotas",
  "mitigation": "Re-mount /var/lib/raxis with prjquota option",
  "spec_reference": "specs/v2/host-capacity.md#61-per-worktree-quota"
}
```

CI pipelines and infrastructure-as-code tools can parse JSON output to gate deployments on preflight success.

---

## 12. Known Incompatibilities and Limitations

### 12.1 OS / platform

- **Windows hosting:** not supported (per §2.3). The CLI may run on Windows for remote intent submission via SSH tunnel; this is operator-DIY.
- **WSL1, WSL2:** not supported (per §2.4); KVM availability is unreliable.
- **Docker container hosting the kernel:** not supported (per §2.4); container isolation is incompatible with hypervisor access requirements.
- **Nested KVM on cloud VMs:** technically works on some providers; performance is significantly degraded. Use bare-metal cloud instances for production.

### 12.2 Filesystem

- **Network filesystems (NFS, SMB, FUSE) as `disk_root`:** not supported (per §4.1); atomic-rename and fsync semantics unreliable.
- **APFS hard quotas:** not natively supported; soft enforcement only on macOS.
- **Filesystems without project quotas:** soft enforcement only for worktree caps; hard caps require XFS prjquota or ZFS datasets.

### 12.3 Hardware

- **CPUs without hardware virtualization:** RAXIS cannot run; `/dev/kvm` will be missing on Linux, Virtualization.framework will refuse to start VMs on macOS.
- **Apple Silicon Linux distributions** (Asahi Linux): not in tested matrix; KVM support varies by hardware revision.
- **Older ARM64 (pre-ARMv8):** not supported; missing virtualization extensions and AES instructions.

### 12.4 Network

- **Unreliable provider connectivity:** intermittent network failures cascade into provider circuit breaker trips per `provider-failure-handling.md §6`. Operators with marginal connectivity should consider longer `total_retry_budget_ms` or alternate provider fallbacks via aliases.
- **Proxy that re-signs TLS without proper CA install:** outbound HTTPS will fail certificate verification. Install the proxy's root CA into the platform trust store (per §6.4).

### 12.5 Multi-tenancy

- **Multi-host state sharing:** not supported in V2 (per §10.4).
- **Multi-instance per host with shared state:** not supported (per `kernel-lifecycle.md §10` Alt I); each instance needs its own `RAXIS_HOME`.
- **Per-tenant resource isolation:** V2 enforces per-initiative VM caps and per-operator queue limits, but does not provide hard tenant isolation (one greedy initiative can degrade the host for everyone within capacity bounds). True multi-tenancy with cgroup-based per-tenant resource isolation is V3+ territory.

### 12.6 Audit data

- **Unbounded audit log growth (V2):** without V3 archiver, audit segments accumulate forever; `min_free_disk_mb` halts admission when disk fills. Operators planning multi-month deployments should provision disk for audit accumulation OR plan V3 upgrade for archiving.
- **GDPR right-to-erasure (V2):** not supported. V2 audit logs cannot be selectively redacted. V3 adds chain-truncation per `audit-retention.md §9`.

### 12.7 Distribution

- **Pre-built binary signing:** binaries are signed with the RAXIS team's developer ID for macOS and GPG-signed for Linux distributions. Operators with strict supply-chain policies should verify signatures before installation.
- **From-source builds on macOS:** require Xcode Command Line Tools and ad-hoc code signing for the Virtualization.framework entitlement. Documented in `docs/building.md`.

---

## 13. Document Maintenance

This document is the canonical source for "what does RAXIS need to run." When other V2 specs introduce new requirements (e.g., a future V2.x spec requires a specific filesystem feature), they MUST also update the relevant section here. Specifically:

- New external runtime dependencies → §8
- New OS feature requirements → §2 or §5
- New disk or memory minimums → §3
- New network egress requirements → §6
- New `raxis doctor` checks → §11.1 and §11.2

V3 will produce its own `specs/v3/system-requirements.md` extending this one with V3-specific additions (archiver sidecar, optional external anchor backends, etc.).
