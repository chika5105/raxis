# RAXIS V2 — System Requirements

> **Status:** V2 baseline plus implemented V3 operational addenda
> **Audience:** Operators evaluating, installing, or deploying RAXIS V2 on a host.
> **Cross-references:**
> - `specs/v2/host-capacity.md` — runtime resource caps; this spec specifies the host's prerequisite capabilities for those caps to be enforceable
> - `specs/v2/kernel-lifecycle.md` — daemon mode prerequisites (systemd / launchd availability)
> - `specs/v2/v2-deep-spec.md §raxis-gateway` — provider API egress prerequisites
> - `specs/v2/credential-proxy.md` — `INV-VM-CAP-04`; constrains VM-side credential exposure but does not change host requirements
> - `specs/v2/integration-merge.md` — git binary / `gix` requirements
> - `specs/v2/planner-harness.md` — VM guest kernel ≥ 5.14 + cgroup v2 controllers (`INV-PLANNER-HARNESS-03`); kernel-bundled `raxis-reviewer-core` image (`INV-PLANNER-HARNESS-02`); kernel-bundled `raxis-orchestrator-core` image (`INV-PLANNER-HARNESS-05`); opt-in kernel-bundled `raxis-executor-starter` image (§10.6) consumed by [`operator-ergonomics.md`](operator-ergonomics.md) defaulting
> - `specs/v2/extensibility-traits.md §3` — `IsolationBackend` trait; this spec's §5 (Hypervisor) describes the V2-shipped impls (`FirecrackerIsolation`, `AppleVirtualizationIsolation`, `NamespaceIsolation` fallback). Future impls (Intel TDX/AMD SEV-SNP enclaves) plug in here without changing the rest of this requirements catalog. The §11 `raxis doctor` check matrix gains an explicit `[CHECK] isolation.tier` per the trait's conformance contract.

---

## 1. Overview

RAXIS V2 is a single-host control plane consisting of `raxis-kernel` (the trusted authority), `raxis-gateway` workers (provider proxies), `raxis-egress` (web egress proxy), and zero-or-more agent microVMs (each running `raxis-planner` plus `raxis-tproxy`). All components run on one physical or virtual host. There are no cluster, multi-host, or distributed-state requirements in V2.

This requirements document also calls out implemented V3 surfaces that
affect installation or operations today: dashboard capture, worktree
snapshots, prompt caching, canonical-image trust anchors, the
OpenTelemetry pusher, and the local Prometheus/Grafana stack. Deferred
V3 specs remain labeled as deferred where they appear.

### 1.1 Quick reference matrix

| Concern | Requirement | Notes |
|---|---|---|
| **Host operating system** | Linux 5.10+ OR macOS 13.0+ | Windows not supported |
| **VM guest OS kernel** | Linux **5.14+** for any operator-published planner image (Executor only in V2) | Required for atomic `cgroup.kill` per `INV-PLANNER-HARNESS-03`; `raxis doctor` validates published images. The kernel-bundled `raxis-reviewer-core` (`INV-PLANNER-HARNESS-02`) and `raxis-orchestrator-core` (`INV-PLANNER-HARNESS-05`) both ship with a RAXIS-pinned 5.14+ kernel by construction. See §2.5. |
| **VM guest kernel features** | cgroup v2 mounted; `cpu`, `memory`, `pids` controllers in `cgroup.subtree_control` | Required for in-VM process containment / CPU priority per [`planner-harness.md §10.1`](planner-harness.md) |
| **CPU architecture** | `x86_64` or `aarch64` | Both Linux and macOS supported on both archs |
| **Hypervisor** | Linux: KVM (`/dev/kvm`)<br>macOS: Apple Virtualization.framework | Hard requirement; the kernel will not start without |
| **Minimum memory** | 4 GB | Single small initiative; smallest viable deployment |
| **Recommended memory** | 32–128 GB | Scales with `max_aggregate_vm_memory_mb`; see §3.3 |
| **Minimum disk** | 50 GB at `disk_root` | Audit log + state.db + at least one worktree |
| **Recommended disk** | 200 GB to 4 TB | Scales with audit retention; see §4.3 |
| **File descriptors** | `ulimit -n` ≥ 4096 | Enforced at startup per [`host-capacity.md §12`](host-capacity.md) |
| **Filesystem at `disk_root`** | POSIX-compatible with atomic rename and `fsync` | ext4, XFS, APFS all supported |
| **Outbound network** | HTTPS to configured LLM provider APIs | Plus operator-allowlisted egress per `policy.toml` |
| **Inbound network** | None | The kernel listens only on local UDS sockets |
| **Daemon mode** | systemd (Linux) or launchd (macOS) | Required only if using `--daemon`; foreground mode has no supervisor requirement |
| **External tooling** | `git` ≥ 2.30, SQLite ≥ 3.35 | `gix` for native operations; `git` shells out for fallback |
| **Source build tooling** | Current stable Rust, Cargo, C toolchain, `make`, `pkg-config` | The repo does not currently pin a local `rust-toolchain.toml`; CI/release should pin externally if exact compiler reproducibility is required. See §9. |
| **Guest image bake tooling** | Docker, Podman, or Buildah for rootfs-producing image roles | `cargo xtask images bake` auto-detects the builder; binary-only roles do not need a container builder. |
| **Dashboard frontend build** | Node.js 20+ and npm | Required only for `dashboard-fe/`; not needed for kernel-only builds. |
| **Observability dev stack** | Docker Compose | Required for `cargo xtask observability up` and the live-e2e/perf Prometheus + Grafana stack. |
| **Bundled with kernel release** | `raxis-reviewer-core-<kernel_version>.img`, `raxis-orchestrator-core-<kernel_version>.img`, and (opt-in) `raxis-executor-starter-<kernel_version>.img`, all at `$RAXIS_INSTALL_DIR/images/` | Kernel-built canonical Reviewer image (`INV-PLANNER-HARNESS-02`) and canonical Orchestrator image (`INV-PLANNER-HARNESS-05`); both digests hardcoded in the kernel binary; neither operator-customizable. The Executor starter image is opt-in ([`planner-harness.md §10.6`](planner-harness.md)): used only when `policy.toml [default_executor_image]` selects it; its digest is published in release notes and pinned in policy via `[[vm_images]] oci_digest`. See §8.1, §11. |

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

**Required host-kernel features:**

- KVM (`CONFIG_KVM=y` or `CONFIG_KVM=m` and module loaded)
- VSOCK (`CONFIG_VSOCKETS`, `CONFIG_VHOST_VSOCK`)
- cgroups v2 (`CONFIG_CGROUPS=y` and unified hierarchy mounted at `/sys/fs/cgroup`)

**Recommended kernel features:**

- `CONFIG_USER_NS=y` (user namespaces; useful for additional isolation hardening)
- `CONFIG_SECCOMP=y` (the kernel applies seccomp filters to gateway workers)
- XFS with `prjquota` enabled, OR ZFS, for hard per-worktree disk quotas (per [`host-capacity.md §6.1`](host-capacity.md)); without these, soft enforcement applies

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
- File descriptor limits on macOS can default to 256 per process in
  interactive or GUI-launched contexts. The kernel intentionally fails
  closed when the inherited soft `RLIMIT_NOFILE` is below
  `[host_capacity] required_min_fd_limit` (default 4096). Source-tree
  runs must raise the limit in the launching shell (for example
  `ulimit -n 8192` before `cargo test`); launchd plists must set
  `SoftResourceLimits.NumberOfFiles = 65536` (already in the generated
  plist per [`kernel-lifecycle.md §5`](kernel-lifecycle.md)).

### 2.3 Windows: not supported

Windows is not supported in V2 for the kernel or microVM hosting. The kernel's hypervisor abstraction targets KVM and Apple Virtualization.framework; supporting Hyper-V would require a third hypervisor backend with its own VirtioFS, VSOCK, and credential-proxy semantics. This is V3+ scope at earliest, contingent on customer demand.

The `raxis` CLI binary may be built for and run on Windows for the purpose of submitting intents to a remote Linux- or macOS-hosted kernel via SSH-tunneled UDS. This is operator-DIY in V2 and not first-class supported.

### 2.5 VM guest kernel requirements

The host kernel runs the kernel daemon and the hypervisor; the **VM guest kernel** runs inside each microVM and hosts the `raxis-planner` process. Host and VM kernel requirements are independent:

| Concern | Host kernel | VM guest kernel |
|---|---|---|
| Minimum version | Linux 5.10+ (per §2.1) | **Linux 5.14+** (per [`planner-harness.md §10.2`](planner-harness.md)) |
| Required features | KVM, VSOCK, cgroups v2 (host-side) | cgroup v2 mounted in-VM; `cpu`, `memory`, `pids` controllers in `cgroup.subtree_control`; virtio-blk and ext4 for Firecracker workspace images; VirtioFS for Apple-VZ mounts |
| Source of the kernel | Operator's distribution (Ubuntu, Debian, etc.) | Bundled with the OCI image used to boot the VM |

**Why 5.14+ for the VM guest kernel.** The harness's process-containment substrate (`INV-PLANNER-HARNESS-03`) requires `cgroup.kill` (Linux 5.14, August 2021) for atomic, race-free process-tree teardown. Earlier kernels could only iterate `cgroup.procs` and `kill(pid, SIGKILL)` in a loop, which races against new forks; that fallback was rejected during V2 design ([`planner-harness.md §10.2`](planner-harness.md)). 5.14+ is mandatory; the kernel refuses to activate planner sessions whose VM image ships an older kernel.

**Per-role enforcement:**

- **Executor images** are operator-published per `INV-VM-CAP-03`. Operators are responsible for shipping a kernel ≥ 5.14 and a properly-configured cgroup v2 hierarchy. `raxis doctor` (§11) inspects every operator-published image at first-use and reports failures before the image is allowed to boot.
- **The Reviewer image** is the kernel-bundled `raxis-reviewer-core` (per `INV-PLANNER-HARNESS-02`). Its kernel version is fixed at RAXIS release time, always ≥ 5.14, and not operator-tunable. Operators have no Reviewer-image responsibilities.
- **The Orchestrator image** is the kernel-bundled `raxis-orchestrator-core` (per `INV-PLANNER-HARNESS-05`). Its kernel version is fixed at RAXIS release time, always ≥ 5.14, and not operator-tunable. Operators have no Orchestrator-image responsibilities — and no Orchestrator declarations in `plan.toml` either, per `INV-PLANNER-HARNESS-06`.

**Compatibility notes for operator-published images:**

- Stable distribution kernels meeting 5.14+ as of 2024: Ubuntu 22.04+ (kernel 5.15+), Debian 12+ (kernel 6.1+), RHEL 9+ (kernel 5.14+), Alpine 3.18+, Fedora 36+, Amazon Linux 2023, Rocky/AlmaLinux 9+.
- Distributions with kernels older than 5.14 (e.g., Ubuntu 20.04 with default 5.4 kernel, Debian 11 with 5.10) may still be used as the **userspace base** for an operator-published image, but the VM image must be assembled with a 5.14+ kernel (e.g., bootc / mkosi / distroless approach where the kernel is selected independently of the userspace).
- Verifier-process images (per [`verifier-processes.md`](verifier-processes.md)) inherit the same 5.14+ requirement; their cgroup substrate is used for verifier-internal process management and timeout enforcement.

### 2.6 Unsupported configurations explicitly documented

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

```text
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

The kernel's [`host-capacity.md §15.4`](host-capacity.md) invariant ensures it never overcommits — sizing is deterministic from the cap configured in `policy.toml`. Overcommit (relying on host swap or OOM-killer) is explicitly disallowed.

### 3.4 Disk requirements

See §4 for filesystem feature requirements; here we cover capacity.

| Deployment size | Disk at `disk_root` | Audit retention horizon (V2; V3 archiving extends this) |
|---|---|---|
| Minimum | 50 GB | ~30 days at light load |
| Single developer | 200 GB | ~6 months |
| Small team | 500 GB to 1 TB | ~1 year |
| Production | 1–4 TB OR V3 archiving | 1–7+ years |

The audit log is the dominant long-term grower. Without V3 archive lifecycle, audit segments accumulate forever (capped only by `min_free_disk_mb` halt per [`host-capacity.md §7`](host-capacity.md)). V2 GA deployments planning to keep more than ~1 year of audit data should plan for V3 upgrade and archive provisioning during that horizon.

Other disk consumers:

| Subsystem | Typical size | Notes |
|---|---|---|
| `state.db` (SQLite) | 100 MB to 5 GB | Grows with `pending_pushes`, indexed views, escalations |
| `repositories/` | 10 MB to 5 GB per adopted repository | RAXIS managed repository mirrors; exact Git roots adopted with `raxis repo adopt` and refreshed/published with `raxis repo {status,fetch,sync,publish}`. Soft cap: `managed_repo_quota_mb` (default 8 GB) per [`host-capacity.md §6.2`](host-capacity.md). |
| `worktrees/` | up to 2 GB per active session | Hard cap: `worktree_quota_mb` (default 2 GB) per [`host-capacity.md §6.1`](host-capacity.md) |
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

- **Atomic rename within filesystem.** Used pervasively for crash-safe writes per [`integration-merge.md §11`](integration-merge.md), `audit-retention.md §4.3` (V3), and many other transactional patterns.
- **`fsync(2)` durability.** The kernel calls `fsync` before signaling completion of any persistent state change.
- **`O_DIRECT` is NOT required** but is harmless if the filesystem supports it.
- **POSIX file locks** (`fcntl(F_SETLK)`): used as a secondary mechanism alongside SQLite's write lock per [`kernel-lifecycle.md §8`](kernel-lifecycle.md).
- **Hard links and symlinks** in the audit and worktrees directories.

All major Linux filesystems (ext4, XFS, Btrfs, ZFS) and macOS APFS satisfy these. Network filesystems (NFS, SMB, FUSE) are NOT supported as `disk_root` — atomic-rename and fsync semantics are unreliable across all of them.

### 4.2 Filesystem feature recommendations

| Feature | Effect on RAXIS | Filesystems that have it |
|---|---|---|
| `prjquota` (project quotas) | Hard worktree disk quotas per [`host-capacity.md §6.1`](host-capacity.md); without, soft enforcement only | XFS (with `prjquota` mount option), ZFS (datasets) |
| Snapshot support | Operator backup workflows much simpler | Btrfs, ZFS, APFS, XFS (with stratis) |
| Native compression | Reduces audit log storage | Btrfs (zstd), ZFS (zstd/lz4), APFS (lzfse) |
| Encryption-at-rest | Recommended for any sensitive deployment | LUKS (under any FS), ZFS native, APFS encrypted volumes, FileVault (macOS) |

**Encryption note:** RAXIS does not encrypt its on-disk state itself. Operators handling sensitive data SHOULD enable filesystem-level encryption (LUKS / APFS encrypted / ZFS native). The kernel's `disk_root` should never be on an unencrypted volume in production deployments handling regulated data.

### 4.3 Path layout

The kernel uses these paths (all under `disk_root`):

```text
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
├── repositories/                        # adopted managed repository mirrors
│   └── <repo_id>/
├── worktrees/                             # per-session worktrees (mounted into VMs)
│   └── <session_uuid>/
├── bundles/                               # ephemeral inter-agent git bundles
│   └── <initiative_uuid>/
└── tmp/                                   # scratch space (cleaned at startup)
```

Per [`host-capacity.md §6.3`](host-capacity.md), sizes per subsystem are independently capped. Operators may mount `audit/` on a separate filesystem from the rest of `disk_root` if they want stricter isolation between audit storage and operational state; the audit-reserve mechanism (per [`host-capacity.md §7.5`](host-capacity.md)) operates on whichever filesystem `audit/` lives on.

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
  For system mode (per [`kernel-lifecycle.md §9.2`](kernel-lifecycle.md)), the dedicated `raxis` user must also be in `kvm` group.
- CPU virtualization extensions enabled in firmware (VT-x or AMD-V on x86_64; EL2 on aarch64).
- Firecracker on PATH.
- `e2fsprogs` on PATH: `mkfs.ext4` for staging workspace images, and `debugfs` + `e2fsck` for read/write workspace copy-back.

**Verification:**

```bash
$ ls -l /dev/kvm
crw-rw---- 1 root kvm 10, 232 May  4 09:00 /dev/kvm

$ groups
alice ... kvm

$ kvm-ok                               # ubuntu/debian: virt-host validation
INFO: /dev/kvm exists
KVM acceleration can be used

$ command -v firecracker mkfs.ext4 debugfs e2fsck
/usr/bin/firecracker
/usr/sbin/mkfs.ext4
/usr/sbin/debugfs
/usr/sbin/e2fsck
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

The hypervisor abstraction in V2 is opinionated: KVM for Linux, Virtualization.framework for macOS. Each is the platform-native choice with the smallest practical device surface, VSOCK support, and the simplest credential-proxy integration (per [`credential-proxy.md`](credential-proxy.md)); workspace delivery is substrate-specific (Firecracker virtio-blk images, Apple-VZ VirtioFS).

Adding a third hypervisor (Hyper-V for Windows, Xen for some embedded Linux distros, or a userspace alternative like QEMU-without-KVM) would require:

- A third backend in the kernel's hypervisor module
- A third path through the workspace/VSOCK protocol implementation
- A third validation matrix for credential proxy semantics
- A third tested distribution channel

Customer demand for any of these has not materialized; if it does, V3+ will revisit.

---

## 6. Network Requirements

### 6.1 Outbound

The kernel itself makes outbound connections only for `git push` to operator-configured main repositories (per `INV-CRED-KERNEL-01` from the V2 design discussion). Other components have their own outbound needs:

| Component | Outbound to | Port | Notes |
|---|---|---|---|
| `raxis-kernel` | `git push` destinations | 22 (SSH), 443 (HTTPS) | Configured in `policy.toml` main-repo bindings |
| `raxis-gateway` workers | LLM provider APIs | 443 | Provider list in `policy.toml [[providers.credentials]]` |
| `raxis-egress` | URLs in `[plan] allowed_egress` | typically 443 | Per-plan operator authorization |
| `raxis-archiver` (V3) | Archive backend (S3, Azure, etc.) | 443 | Operator-configured |

**Provider API endpoints** (default):

| Provider | Endpoint | Port |
|---|---|---|
| Anthropic | `api.anthropic.com` | 443 |
| OpenAI | `api.openai.com` | 443 |
| (future providers) | per `policy.toml [[providers.credentials]]` | 443 |

Operators must allowlist these endpoints in any host-side firewall (egress rules). The kernel does NOT bypass operator-side firewall configuration; if a configured provider endpoint is unreachable, every inference attempt to that provider fails with `Unavailable` per [`provider-failure-handling.md §5.1`](provider-failure-handling.md).

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

### 7.1 User mode (per [`kernel-lifecycle.md §9.1`](kernel-lifecycle.md))

The kernel runs as the operator's existing user account. No special user creation is needed beyond:

- Add the user to the `kvm` group (Linux) for `/dev/kvm` access
- Ensure the user can write to `RAXIS_HOME` (default `~/.local/share/raxis` on Linux, `~/Library/Application Support/raxis` on macOS)

### 7.2 System mode (per [`kernel-lifecycle.md §9.2`](kernel-lifecycle.md))

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
| `raxis-reviewer-core-<kernel_version>.img` | Matches kernel release | Canonical Reviewer VM image (per `INV-PLANNER-HARNESS-02`); booted unconditionally for Reviewer-role tasks. Operators do NOT customize this image; the kernel verifies its on-disk SHA-256 against a compiled-in expected digest at every Reviewer activation. | Bundled with the kernel release at `$RAXIS_INSTALL_DIR/images/`; never pulled from a registry. |
| `raxis-orchestrator-core-<kernel_version>.img` | Matches kernel release | Canonical Orchestrator VM image (per `INV-PLANNER-HARNESS-05`); booted unconditionally for the auto-created Orchestrator session of every initiative. Operators do NOT customize this image; the kernel verifies its on-disk SHA-256 against a compiled-in expected digest at every Orchestrator activation. | Bundled with the kernel release at `$RAXIS_INSTALL_DIR/images/`; never pulled from a registry. |
| `raxis-executor-starter-<kernel_version>.img` | Matches kernel release | **Strongly recommended; not strictly required.** Canonical Executor starter image (per [`planner-harness.md §10.6`](planner-harness.md)); used as the operator-ergonomics defaulting target when the deployment's `policy.toml [default_executor_image] alias` points at it (per [`operator-ergonomics.md §3`](operator-ergonomics.md) D1, §18.1). Unlike the Reviewer and Orchestrator canonical images this one is **opt-in**: deployments whose plans always pin an explicit `vm_image` can omit this file with no functional impact. | Bundled with the kernel release at `$RAXIS_INSTALL_DIR/images/`; never pulled from a registry. |
| `raxis-verifier-symbol-index-<kernel_version>.img` | Matches kernel release | **Kernel-canonical verifier image (per `INV-VERIFIER-12`).** Booted unconditionally for symbol-index verifier activations when `policy.toml [prepare] auto_inject_symbol_index = true` (default) and the plan's tasks touch source files. The kernel verifies its on-disk SHA-256 against a compiled-in expected digest at every symbol-index verifier spawn (`FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH` on mismatch). Operators do NOT customize this image. The alias `"raxis-verifier-symbol-index"` is reserved at policy load (`FAIL_POLICY_RESERVED_VM_IMAGE_NAME` on collision). | Bundled with the kernel release at `$RAXIS_INSTALL_DIR/images/`; never pulled from a registry. |
| `raxis-verifier-rust-starter-<kernel_version>.img` | Matches kernel release | **Strongly recommended; not strictly required.** Tiered language starter (per [`verifier-processes.md §14.5`](verifier-processes.md)); ships with `rustc`, `cargo`, and `cargo-nextest` for the common case of `cargo test` / `cargo clippy` verifiers. Auto-selected by `setup wizard` when the operator declares Rust as a target language. **Not** kernel-canonical: the kernel does NOT verify a compiled-in digest at runtime; supply-chain integrity rests on the operator's signed `[[vm_images]] oci_digest`. The alias `"raxis-verifier-rust-starter"` is the conventional reference but operators can override `policy.toml [default_verifier_images].rust` to point at a custom image. | Bundled with the kernel release at `$RAXIS_INSTALL_DIR/images/`; never pulled from a registry. |
| `raxis-verifier-node-starter-<kernel_version>.img` | Matches kernel release | **Strongly recommended; not strictly required.** Tiered language starter for Node.js workloads (`node`, `npm`, `pnpm`); auto-selected by `setup wizard` when Node is a declared target language. Trust model and override mechanism mirror the Rust starter row above. | Bundled with the kernel release at `$RAXIS_INSTALL_DIR/images/`; never pulled from a registry. |
| `raxis-verifier-python-starter-<kernel_version>.img` | Matches kernel release | **Strongly recommended; not strictly required.** Tiered language starter for Python workloads (`python3`, `uv`, `pytest`); auto-selected by `setup wizard` when Python is a declared target language. Trust model and override mechanism mirror the Rust starter row above. | Bundled with the kernel release at `$RAXIS_INSTALL_DIR/images/`; never pulled from a registry. |
| `raxis-verifier-go-starter-<kernel_version>.img` | Matches kernel release | **Strongly recommended; not strictly required.** Tiered language starter for Go workloads (`go`, `golangci-lint`); auto-selected by `setup wizard` when Go is a declared target language. Trust model and override mechanism mirror the Rust starter row above. | Bundled with the kernel release at `$RAXIS_INSTALL_DIR/images/`; never pulled from a registry. |

The kernel binary is statically-linked for SQLite, rustls, and most other dependencies — distribution is a single binary with minimal runtime dependencies. The only runtime executables RAXIS shells out to:

- `git` (for the small set of git operations not yet in `gix`)
- The hypervisor binary (Linux: bundled Firecracker; macOS: Apple Virtualization.framework via Swift bridge)

**Canonical Reviewer image distribution.** The `raxis-reviewer-core` image is shipped as a single OCI image bundle at `$RAXIS_INSTALL_DIR/images/raxis-reviewer-core-<kernel_version>.img` (typical paths: `/usr/local/lib/raxis/images/` for system-mode installs, `~/.local/share/raxis/images/` for user-mode installs). The kernel binary contains a compiled-in SHA-256 of the image bytes; at every Reviewer-task activation the kernel re-computes the on-disk digest and refuses to boot the VM with `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` on any mismatch. Air-gapped installs work without modification — the image is a local file, not a registry artifact. See [`planner-harness.md §4.5`](planner-harness.md) and `§10.4` for the full content specification.

**Canonical Orchestrator image distribution.** Distributed in parallel with the Reviewer image at `$RAXIS_INSTALL_DIR/images/raxis-orchestrator-core-<kernel_version>.img`. The kernel binary contains a compiled-in SHA-256 of the image bytes (`EXPECTED_ORCHESTRATOR_IMAGE_DIGEST`) and a compiled-in NNSP (`ORCHESTRATOR_NNSP_BYTES`) version-locked with the image. At every Orchestrator-session activation (one per initiative), the kernel re-computes the on-disk digest and refuses to boot the VM with `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` on any mismatch. The Orchestrator image is materially larger than the Reviewer image (~50 MiB vs ~15 MiB) because it includes `bash`, `git`, `ripgrep`, and POSIX coreutils for the semantic merge conflict resolution workflow specified in [`kernel-mechanics-prompt.md §3.2 [KERNEL: CONFLICT RESOLUTION PROTOCOL]`](kernel-mechanics-prompt.md). See [`planner-harness.md §4.7`](planner-harness.md) and `§10.5` for the full content specification.

**Canonical Executor starter image distribution.** Distributed alongside the Reviewer and Orchestrator images at `$RAXIS_INSTALL_DIR/images/raxis-executor-starter-<kernel_version>.img`. **The starter image is opt-in**: nothing in the kernel's runtime depends on its presence; it is consumed only by `raxis-cli plan prepare` ([`operator-ergonomics.md §5`](operator-ergonomics.md)) when the deployment's `policy.toml` declares `[default_executor_image] alias = "raxis-executor-starter"`. The image's SHA-256 digest is published in the RAXIS release notes; the policy bundle that selects this image MUST declare a `[[vm_images]]` entry with `oci_digest = "sha256:..."` matching the release-notes digest, and the kernel verifies the digest at every Executor session activation that uses this image (per the existing `vm_images.oci_digest` enforcement; no new invariant is required). The starter image is materially larger than the Reviewer and Orchestrator images (~2 GiB compressed) because it carries general-purpose dev tooling for four mainstream language ecosystems (Node, Python, Rust, Go), the build toolchain, common Unix tooling, and `git`/`gh`. Deployments with strict size constraints or strict supply-chain requirements typically omit the starter image and have all operators pin their own custom Executor images. See [`planner-harness.md §10.6`](planner-harness.md) for the full content specification.

**Canonical Verifier symbol-index image distribution.** Distributed alongside the other canonical images at `$RAXIS_INSTALL_DIR/images/raxis-verifier-symbol-index-<kernel_version>.img`. **The symbol-index image is kernel-canonical** per `INV-VERIFIER-12` — the kernel binary contains a compiled-in SHA-256 (`EXPECTED_SYMBOL_INDEX_VERIFIER_IMAGE_DIGEST`) and refuses to spawn the verifier VM with `FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH` on any mismatch. The image is intentionally minimal (~12 MiB compressed) — Alpine Linux base, `raxis-verifier` PID-1 binary, `ctags` (universal-ctags), and a small wrapper script that walks the workspace, invokes `ctags`, and emits a normalized JSON symbol index to `/raxis/symbol_index.json`. The image's command line is fixed; operators have no per-plan customization surface for it (matching the Reviewer/Orchestrator pattern). The image alias `"raxis-verifier-symbol-index"` is reserved at policy load — any `[[vm_images]]` entry attempting to use the alias is rejected with `FAIL_POLICY_RESERVED_VM_IMAGE_NAME` per [`verifier-processes.md §14.3`](verifier-processes.md). Air-gapped installs work without modification — the image is a local file. See [`verifier-processes.md §14`](verifier-processes.md) for the full content specification and reserved-alias semantics.

**Tiered language starter verifier image distribution.** Four optional images are bundled at `$RAXIS_INSTALL_DIR/images/raxis-verifier-{rust,node,python,go}-starter-<kernel_version>.img`. **These images are bundled but NOT kernel-canonical** — distinct from the symbol-index image and from the Reviewer/Orchestrator images, the kernel does not embed a compiled-in digest for them and does not enforce a runtime digest check beyond the standard `[[vm_images]] oci_digest` mechanism. The trust boundary is: **operator-published-target-equivalent** — the operator signs `policy.toml`, the policy declares `[[vm_images]]` entries with `oci_digest` matching the release-notes digest, and the kernel enforces the per-plan `oci_digest` at every verifier spawn (existing mechanism; no new code path). This intentional asymmetry reflects the design choice that language-stack tooling is operator-mutable (an operator may want a Rust starter with `cargo-tarpaulin` baked in, or a Python starter pinned to 3.12) while the symbol-index image is structural to the Pure-Static Reviewer's correctness and must be a kernel-bound contract. The `setup wizard` ([`operator-ergonomics.md §16.3`](operator-ergonomics.md) phase 6) auto-populates `[default_verifier_images].<lang>` entries based on the operator's declared target languages and writes the corresponding `[[vm_images]] oci_digest` entries for each starter the operator chose to enable. Operators with strict size constraints or non-mainstream language targets can omit any subset of these starter files. See [`verifier-processes.md §14.5`](verifier-processes.md) for the full content specification and [`operator-ergonomics.md §16.3`](operator-ergonomics.md) for the wizard flow.

### 8.2 Required for daemon mode (per [`kernel-lifecycle.md`](kernel-lifecycle.md))

| Dependency | Required for | Notes |
|---|---|---|
| systemd | Linux user/system daemon mode | Standard on every modern Linux distribution |
| `loginctl` | Linux user daemon mode | Bundled with systemd |
| launchd | macOS user/system daemon mode | Built into macOS |

### 8.3 Implemented V3 operational dependencies

| Dependency | Required for | Notes |
|---|---|---|
| `raxis-otel-pusher` | OpenTelemetry export | Separate host process; reads `<data_dir>/observability/{spans,metrics}` and pushes OTLP over HTTP/protobuf. |
| OTLP collector endpoint | Production telemetry export | Required only when `[observability].enabled = true` and a pusher endpoint is configured. |
| Docker Compose | Local observability stack | Used by `cargo xtask observability up` and live-e2e/perf compose files to run OTel Collector, Prometheus, and Grafana. |
| Node.js 20+ and npm | Dashboard frontend build | Required for `dashboard-fe/`; backend/dashboard-kernel crates are normal Cargo workspace members. |
| Archive backend SDK | Deferred V3 audit-retention archiver | Operator-chosen; not required for the implemented OTel/dashboard capture surfaces. |
| External anchor service (optional) | Deferred V3 witness publication | Sigstore Rekor, CT log, or custom HTTP; not required for the current kernel. |

### 8.4 Recommended for operations

| Dependency | Why recommended | Notes |
|---|---|---|
| A monitoring agent (Prometheus node-exporter, Datadog agent, etc.) | Host capacity visibility | RAXIS emits authority-side metrics/traces through the implemented observability ring and `raxis-otel-pusher`; host-level CPU/disk/network metrics still come from the operator's normal monitoring stack. |
| Log shipper (vector, fluentd, etc.) | Centralized operational logs | journald or `kernel.{out,err}` files are the source |
| Backup tool (restic, borg, snapshots) | Disaster recovery for `disk_root` | Audit log + state.db + adopted `repositories/` mirrors are the critical state |

---

## 9. Building from Source

For operators wanting to build RAXIS from source rather than use pre-built binaries:

### 9.1 Build toolchain

| Component | Minimum version | Notes |
|---|---|---|
| Rust toolchain | Current stable | Workspace edition is Rust 2021. The repo does not currently carry a `rust-toolchain.toml`; release/CI automation should pin one externally when exact compiler reproducibility is required. |
| `cargo` | Bundled with Rust | Use `--locked` for operator/release builds so `Cargo.lock` is honored. |
| `git` | 2.30 | For fetching dependencies |
| `pkg-config` | any | For native library discovery |
| C/C++ compiler | gcc 9+ or clang 12+ | For crates with native build steps, bundled SQLite, and platform glue. |
| `make` | any POSIX-compatible | |
| OpenSSL 3 CLI | 3.x | Required for operator Ed25519 key generation; Rust HTTPS uses rustls. |
| Docker, Podman, or Buildah | Current stable | Required for guest-image bake roles that assemble a rootfs. |
| Node.js + npm | Node 20+ | Required only for `dashboard-fe/`. |
| Docker Compose | Current v2 plugin or compatible binary | Required only for local observability/live-e2e/perf service stacks. |

### 9.2 Platform-specific build dependencies

**Linux:**

- Linux kernel headers matching the running kernel (`linux-headers-$(uname -r)`)
- KVM/vsock/cgroup prerequisites from `cargo xtask linux-prereqs`
- `firecracker(1)` on `$PATH` before the first kernel boot on Linux
- `e2fsprogs` (`mkfs.ext4`, `debugfs`, `e2fsck`) on `$PATH` for the
  Firecracker workspace block-image transport

**macOS:**

- Xcode Command Line Tools (`xcode-select --install`)
- macOS SDK matching deployment target (13.0)
- Homebrew `openssl@3` for Ed25519 operator keys
- `codesign` for ad-hoc signing the AVF-enabled `raxis-kernel`

### 9.3 Build invocation

The canonical development/e2e setup path is the one-shot wrapper:

```bash
git clone https://github.com/chika5105/raxis
cd raxis/raxis

export RAXIS_INSTALL_DIR="$HOME/.raxis-install"
cargo xtask source-setup \
  --install-dir "$RAXIS_INSTALL_DIR" \
  --kernel-from-file /path/to/vmlinux \
  --kernel-config /path/to/vmlinux.config
```

Pinned prebuilt guest kernels use the URL/SHA variant:

```bash
cargo xtask source-setup \
  --install-dir "$RAXIS_INSTALL_DIR" \
  --kernel-url https://example.com/vmlinux-aarch64 \
  --kernel-sha256 <64-hex-digest> \
  --kernel-config /path/to/vmlinux.config
```

`source-setup` runs host prerequisites, release host tools, dashboard
frontend build, guest image bake, the trust-anchored `raxis-kernel`
rebuild, trust-anchor verification, and macOS codesign. It emits a
JSON plan and a `source_setup_step_begin` line before each phase. A
first clean machine should expect roughly: 2-20 min for host prereqs,
3-15 min for host tools, 1-6 min for the dashboard, 1-10 min when
staging a pinned prebuilt guest kernel, 10-45 min for a `--no-cache`
guest image bake, 2-10 min for the final kernel rebuild, and under
1 min for verify/codesign.

The guest-kernel and trust-anchor details are part of the contract:
`vmlinux` is staged at `$RAXIS_INSTALL_DIR/kernel/vmlinux`, its
validated config is staged at `$RAXIS_INSTALL_DIR/kernel/vmlinux.config`,
the config must satisfy
`images/kernel/raxis-guest-a3-netfilter.config`, and the host
`raxis-kernel` must embed the same public image-signing key used by the
baked manifests.

Manual equivalent:

```bash
git clone https://github.com/chika5105/raxis
cd raxis/raxis

# Verify host prerequisites.
cargo xtask dev-prereqs --install       # macOS
cargo xtask linux-prereqs               # Linux

# Build the Rust workspace using the checked-in lockfile.
cargo build --workspace --locked

# Build the host binaries operators normally run.
cargo build --release --locked \
  -p raxis-cli \
  -p raxis-kernel \
  -p raxis-gateway \
  -p raxis-otel-pusher \
  -p raxis-supervisor

# Build the dashboard frontend when serving the dashboard UI.
cd dashboard-fe
npm ci
npm run build
```

Canonical guest images and the kernel trust anchor are a separate
build step because the `raxis-kernel` binary embeds the image
manifest-signing public key:

```bash
cd /path/to/raxis/raxis
export RAXIS_INSTALL_DIR="$HOME/.raxis-install"
cargo xtask images bake \
  --kernel-from-file /path/to/vmlinux \
  --kernel-config /path/to/vmlinux.config

RAXIS_KERNEL_SIGNING_KEY_HEX="$(cat .git/info/raxis-signing-key/pk.hex)" \
  cargo build --release --locked -p raxis-kernel

cargo xtask images verify-trust-anchor --kernel target/release/raxis-kernel
cargo xtask dev-codesign --profile release     # macOS only; no-op on Linux
```

The short operator runbook is
[`guides/SETUP.md`](../../guides/SETUP.md); the prerequisite-focused
version is
[`guides/getting-started/01-prereqs.md`](../../guides/getting-started/01-prereqs.md).

---

## 10. Recommended Deployment Topologies

### 10.1 Single-host single-user (developer workstation)

```text
[ Operator's laptop or workstation ]
  ├── raxis-kernel (--daemon, user mode)
  ├── raxis-gateway (worker pool, default 4 workers)
  ├── raxis-egress
  └── microVMs (up to max_concurrent_vms)
```

User-mode install via `raxis kernel start --daemon`. State lives under `~/.local/share/raxis/`. Operator submits intents via local UDS.

Suitable for: developer evaluation, personal-use AI agent workflows, single-tenant CI runners.

### 10.2 Single-host multi-user (small team server)

```text
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

```text
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
- `vm-images` — for every operator-published VM image referenced by an installed `policy.toml` (Executor and verifier images only in V2 — Reviewer and Orchestrator are kernel-canonical): VM guest kernel ≥ 5.14, cgroup v2 mounted, required cgroup controllers (`cpu`, `memory`, `pids`) in `cgroup.subtree_control`, `raxis-planner` binary present (for planner roles)
- `canonical-images` — kernel-bundled canonical images at `$RAXIS_INSTALL_DIR/images/`:
  - `raxis-reviewer-core-<kernel_version>.img` (per `INV-PLANNER-HARNESS-02`): presence, SHA-256 digest matches kernel-binary's compiled-in `EXPECTED_REVIEWER_IMAGE_DIGEST`, content sanity (`raxis-planner` and `ripgrep` present; `/bin/sh`, `/bin/bash`, language compilers and runtimes, `git`, network utilities, editors all absent per [`planner-harness.md §10.4`](planner-harness.md))
  - `raxis-orchestrator-core-<kernel_version>.img` (per `INV-PLANNER-HARNESS-05`): presence, SHA-256 digest matches kernel-binary's compiled-in `EXPECTED_ORCHESTRATOR_IMAGE_DIGEST`, content sanity (`raxis-planner`, `bash`, `git`, `ripgrep`, and POSIX coreutils present; `python3`, `node`, `rustc`, `gcc`, package managers, `curl`, `wget`, editors, LSPs all absent per [`planner-harness.md §10.5`](planner-harness.md))
  - `raxis-executor-starter-<kernel_version>.img` (per [`planner-harness.md §10.6`](planner-harness.md); opt-in): presence (skipped if absent and the loaded `policy.toml` does NOT declare `[default_executor_image]` referencing this alias), SHA-256 digest matches the digest published in the RAXIS release notes (which is also the digest the policy's `[[vm_images]]` entry pins), content sanity (`raxis-planner`, `bash`, `node`/`npm`, `python3`/`pip`, `cargo`/`rustc`, `go`, `git`/`gh`, `rg`/`fd`/`jq`, build toolchain present per [`planner-harness.md §10.6`](planner-harness.md)); a digest mismatch with no in-flight initiative using the image is a non-fatal `WARN_DEFAULT_EXECUTOR_IMAGE_DIGEST_DRIFT`; a digest mismatch when an active initiative was activated under the now-mismatched image is `FAIL_DEFAULT_EXECUTOR_IMAGE_DIGEST_MISMATCH`
  - `raxis-verifier-symbol-index-<kernel_version>.img` (per `INV-VERIFIER-12`; structural): presence — required when `policy.toml [prepare] auto_inject_symbol_index = true` (default) AND the policy bundle declares any plan that produces source-touching tasks; otherwise downgraded to a non-fatal `WARN_SYMBOL_INDEX_IMAGE_MISSING_AUTO_INJECT_DISABLED`. SHA-256 digest matches kernel-binary's compiled-in `EXPECTED_SYMBOL_INDEX_VERIFIER_IMAGE_DIGEST`. Content sanity (`raxis-planner` PID 1 present, `ctags` present and resolves to `universal-ctags`, no shells beyond `/bin/sh` for `command` execution, no network utilities, no language compilers per [`verifier-processes.md §14`](verifier-processes.md)). A digest mismatch is `FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH` and halts further symbol-index verifier spawns until `raxis doctor canonical-images` succeeds again.
  - `raxis-verifier-{rust,node,python,go}-starter-<kernel_version>.img` (per [`verifier-processes.md §14.5`](verifier-processes.md); opt-in tiered language starters): presence (skipped if absent and the loaded `policy.toml [default_verifier_images]` does NOT reference the alias; skipped if `[default_verifier_images].<lang>` references a different alias), SHA-256 digest matches the digest published in the RAXIS release notes (which is also the digest pinned by the policy's `[[vm_images]] oci_digest` entry), content sanity per [`verifier-processes.md §14.5`](verifier-processes.md) (Rust starter: `rustc`, `cargo`, `cargo-nextest` present; Node starter: `node`, `npm`, `pnpm` present; Python starter: `python3`, `uv`, `pytest` present; Go starter: `go`, `golangci-lint` present). A digest mismatch with no in-flight verifier using the image is a non-fatal `WARN_DEFAULT_VERIFIER_IMAGE_DIGEST_DRIFT { language }`; a digest mismatch when an active verifier session was activated under the now-mismatched image is `FAIL_DEFAULT_VERIFIER_IMAGE_DIGEST_MISMATCH { language }`. Tiered starters are NOT subject to the `FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH` kernel-embedded-digest check (that check is symbol-index-only per `INV-VERIFIER-12`).

### 11.2 Sample output

```bash
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

VM images (per planner-harness.md §10 — Executor and verifier images only;
            Reviewer and Orchestrator are kernel-canonical, see below)
  ✓ raxis/rust-node:1.87-20 (Executor): kernel 6.1.0, cgroup v2, cpu+memory+pids in subtree_control, raxis-planner present
  ✓ raxis/parsers:1 (verifier): kernel 6.1.0, cgroup v2, cpu+memory+pids in subtree_control

Canonical images (kernel-bundled; not operator-customizable)

  Reviewer image (per planner-harness.md §4.5 / INV-PLANNER-HARNESS-02)
    ✓ raxis-reviewer-core-2.0.0.img present at /usr/local/lib/raxis/images/
    ✓ SHA-256 digest matches kernel's compiled-in EXPECTED_REVIEWER_IMAGE_DIGEST
    ✓ Content sanity: raxis-planner present (PID 1)
    ✓ Content sanity: ripgrep present
    ✓ Content sanity: NO shells (/bin/sh, /bin/bash, busybox)
    ✓ Content sanity: NO language toolchains (rustc, cargo, node, python, go, …)
    ✓ Content sanity: NO git binary
    ✓ Content sanity: NO network utilities (curl, wget, ssh)
    ✓ Content sanity: NO editors

  Orchestrator image (per planner-harness.md §4.7 / INV-PLANNER-HARNESS-05)
    ✓ raxis-orchestrator-core-2.0.0.img present at /usr/local/lib/raxis/images/
    ✓ SHA-256 digest matches kernel's compiled-in EXPECTED_ORCHESTRATOR_IMAGE_DIGEST
    ✓ Content sanity: raxis-planner present (PID 1)
    ✓ Content sanity: bash 5.1.4 present (foreground-only harness build)
    ✓ Content sanity: git 2.39.2 present
    ✓ Content sanity: ripgrep present
    ✓ Content sanity: POSIX coreutils present (cat, head, tail, diff, patch, sed, awk, grep, …)
    ✓ Content sanity: NO language toolchains (python3, node, rustc, gcc, …)
    ✓ Content sanity: NO package managers (npm, cargo, pip, gem)
    ✓ Content sanity: NO network utilities (curl, wget, ssh)
    ✓ Content sanity: NO editors (vi, nano, emacs)
    ✓ Content sanity: NO LSPs

  Executor starter image (per planner-harness.md §10.6 — opt-in, used by `plan prepare` defaulting)
    ✓ raxis-executor-starter-2.0.0.img present at /usr/local/lib/raxis/images/
    ✓ SHA-256 digest matches release-notes digest AND policy [[vm_images]] oci_digest pin
    ✓ Content sanity: raxis-planner present (PID 1)
    ✓ Content sanity: bash 5.1.4 present (full Executor harness build)
    ✓ Content sanity: node 20.11.1, npm 10.2.4 present
    ✓ Content sanity: python 3.11.7, pip 23.3.2 present
    ✓ Content sanity: rustc 1.76.0, cargo 1.76.0 present
    ✓ Content sanity: go 1.22.0 present
    ✓ Content sanity: git 2.43.0, gh 2.42.1 present
    ✓ Content sanity: rg 14.1.0, fd 9.0.0, jq 1.7.1 present
    ✓ Content sanity: build toolchain present (make, gcc, g++, clang, ld, ar)
    ⓘ Selected as default by current policy.toml [default_executor_image] alias = "raxis-executor-starter"

  Symbol-index verifier image (per verifier-processes.md §14 / INV-VERIFIER-12)
    ✓ raxis-verifier-symbol-index-2.0.0.img present at /usr/local/lib/raxis/images/
    ✓ SHA-256 digest matches kernel's compiled-in EXPECTED_SYMBOL_INDEX_VERIFIER_IMAGE_DIGEST
    ✓ Content sanity: raxis-verifier present (PID 1; statically linked)
    ✓ Content sanity: ctags present, resolves to 'Universal Ctags 6.0.0(p6.0.0-0-g7eed99af)'
    ✓ Content sanity: /bin/sh present (minimal posix; for `command` execution)
    ✓ Content sanity: NO additional shells (/bin/bash absent)
    ✓ Content sanity: NO language toolchains (rustc, cargo, node, python, go, …)
    ✓ Content sanity: NO network utilities (curl, wget, ssh)
    ⓘ Image alias 'raxis-verifier-symbol-index' is RESERVED — operator [[vm_images]] aliases must not collide
    ⓘ Auto-injection enabled by current policy.toml [prepare] auto_inject_symbol_index = true

  Tiered language starter verifier images (per verifier-processes.md §14.5 — opt-in)
    Rust starter (referenced by current policy [default_verifier_images].rust)
      ✓ raxis-verifier-rust-starter-2.0.0.img present at /usr/local/lib/raxis/images/
      ✓ SHA-256 digest matches release-notes digest AND policy [[vm_images]] oci_digest pin
      ✓ Content sanity: raxis-verifier present (PID 1)
      ✓ Content sanity: rustc 1.78.0, cargo 1.78.0, cargo-nextest 0.9.70 present
    Node starter (referenced by current policy [default_verifier_images].node)
      ✓ raxis-verifier-node-starter-2.0.0.img present at /usr/local/lib/raxis/images/
      ✓ SHA-256 digest matches release-notes digest AND policy [[vm_images]] oci_digest pin
      ✓ Content sanity: node 20.11.1, npm 10.2.4, pnpm 8.15.4 present
    Python starter (NOT referenced by current policy; image absent — OK)
      ⓘ raxis-verifier-python-starter-2.0.0.img absent at /usr/local/lib/raxis/images/
      ⓘ Skipped: policy [default_verifier_images].python is not set; install if Python becomes a target
    Go starter (NOT referenced by current policy; image absent — OK)
      ⓘ raxis-verifier-go-starter-2.0.0.img absent at /usr/local/lib/raxis/images/
      ⓘ Skipped: policy [default_verifier_images].go is not set; install if Go becomes a target

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

```yaml
✗ /dev/kvm does not exist
  RAXIS requires KVM hardware virtualization on Linux.
  Mitigations:
    - On bare metal: enable VT-x or AMD-V in your firmware (BIOS/UEFI) settings
    - On a cloud VM: use an instance type that supports nested virtualization
      (AWS metal instances, GCP sole-tenant nodes); most managed VMs do NOT
    - On WSL2: not supported per system-requirements.md §2.6
  See: specs/v2/system-requirements.md §5.1

Result: 1 WARNING, 1 FAILURE
RAXIS cannot run on this host. Resolve the failure above.
```

Other planner-harness-specific failures and their actionable forms:

```yaml
✗ raxis/legacy-rust:1 (Executor) ships Linux kernel 5.10.0 (required: 5.14+)
  This image cannot host a planner VM because INV-PLANNER-HARNESS-03 (cgroup.kill
  for atomic process-tree teardown) requires Linux 5.14+. Plans referencing this
  image will be rejected at approve_plan with FAIL_VM_GUEST_KERNEL_TOO_OLD.
  Mitigations:
    - Rebuild the image with a kernel ≥ 5.14 (e.g., from Ubuntu 22.04+ base, or
      bootc / mkosi with an explicit recent kernel selection)
    - Switch to a stable base image known to ship 5.14+ (Ubuntu 22.04, Debian 12,
      RHEL 9, Fedora 36+, Alpine 3.18+)
  See: specs/v2/system-requirements.md §2.5; planner-harness.md §10.2
```

```yaml
✗ raxis-reviewer-core-2.0.0.img digest mismatch
  Expected: sha256:e3b0c44298fc1c149afbf4c8996fb924...
  Observed: sha256:c057a3e7ea75c2aef3c1cd95fa1aac84...
  This indicates either (a) the kernel binary and the canonical Reviewer image
  bundle are from different RAXIS releases, (b) the on-disk image has been
  modified after install, or (c) the install was incomplete. Reviewer-role
  tasks will be blocked until this is resolved (FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH
  at every Reviewer activation; SecurityViolationDetected audit emitted).
  Mitigations:
    - Reinstall RAXIS from a verified source matching the running kernel version
    - Verify the published release SHA-256 of raxis-reviewer-core-<version>.img
      matches what is on disk
    - Do NOT attempt to "fix" by replacing the image with a custom build —
      operator-built Reviewer images are explicitly prohibited per
      INV-PLANNER-HARNESS-02
  See: specs/v2/planner-harness.md §4.5
```

```yaml
✗ raxis-reviewer-core-2.0.0.img content sanity: /bin/sh present
  The canonical Reviewer image MUST NOT contain any shell (per INV-PLANNER-HARNESS-01,
  three-layer image enforcement). Presence indicates either (a) the on-disk image
  has been tampered with, or (b) the kernel and image bundle are mismatched
  versions and the kernel's expected digest happens to match a different (broken)
  image. The kernel will refuse to boot Reviewer VMs from this image.
  Mitigations:
    - Reinstall RAXIS from a verified source
    - Verify the digest matches the published release manifest
  See: specs/v2/planner-harness.md §4.5, §10.4
```

```yaml
✗ raxis-orchestrator-core-2.0.0.img digest mismatch
  Expected: sha256:7c1b3e2f8a4d9c6e1b7a5f3d8c2e9a4b...
  Observed: sha256:9d4a7c2e8f1b3d5a6c8e2f4b9d7a1c5e...
  This indicates either (a) the kernel binary and the canonical Orchestrator image
  bundle are from different RAXIS releases, (b) the on-disk image has been
  modified after install, or (c) the install was incomplete. Initiative admission
  will be blocked until this is resolved (FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH
  at every Orchestrator activation; SecurityViolationDetected audit emitted).
  Mitigations:
    - Reinstall RAXIS from a verified source matching the running kernel version
    - Verify the published release SHA-256 of raxis-orchestrator-core-<version>.img
      matches what is on disk
    - Do NOT attempt to "fix" by replacing the image with a custom build —
      operator-built Orchestrator images are explicitly prohibited per
      INV-PLANNER-HARNESS-05
  See: specs/v2/planner-harness.md §4.7
```

```yaml
✗ raxis-orchestrator-core-2.0.0.img content sanity: /usr/bin/python3 present
  The canonical Orchestrator image MUST NOT contain language runtimes (per
  planner-harness.md §10.5). Presence indicates either (a) the on-disk image has
  been tampered with, or (b) the kernel and image bundle are mismatched versions.
  The kernel will refuse to boot Orchestrator VMs from this image, blocking all
  initiative admission.
  Mitigations:
    - Reinstall RAXIS from a verified source
    - Verify the digest matches the published release manifest
  See: specs/v2/planner-harness.md §4.7, §10.5
```

```yaml
✗ raxis-verifier-symbol-index-2.0.0.img digest mismatch
  Expected: sha256:4e8b1c7d3f9a2c5e8b1d4f7a9c2e5b8d...
  Observed: sha256:1a2c5e8b9d4f7a2c1e5b8d3f4a9c1e2b...
  This indicates either (a) the kernel binary and the canonical symbol-index
  verifier image bundle are from different RAXIS releases, (b) the on-disk image
  has been tampered with, or (c) the install was incomplete. Symbol-index verifier
  spawns will be blocked until this is resolved (FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH
  at every symbol-index verifier activation; SecurityViolationDetected audit
  emitted; further verifier spawns of this image are halted until digest matches).
  Knock-on effect: WARN_REVIEWER_MISSING_SYMBOL_INDEX will fire on every Reviewer
  activation that depended on the auto-injected symbol-index verifier output, since
  the verifier never produces /raxis/symbol_index.json.
  Mitigations:
    - Reinstall RAXIS from a verified source matching the running kernel version
    - Verify the published release SHA-256 of raxis-verifier-symbol-index-<version>.img
      matches what is on disk
    - Do NOT attempt to replace with a custom build — the symbol-index image is
      kernel-canonical per INV-VERIFIER-12; operator-built variants are prohibited
    - Workaround during recovery: set policy.toml [prepare] auto_inject_symbol_index = false
      (Reviewer continues to function; the WARN_REVIEWER_MISSING_SYMBOL_INDEX
      warning becomes the operator's signal to install a custom symbol_index
      verifier per planner-harness.md §4.1 if symbol-index data is required)
  See: specs/v2/verifier-processes.md §14
```

```yaml
✗ raxis-verifier-rust-starter-2.0.0.img digest mismatch (during in-flight verifier session)
  Expected (per policy [[vm_images]] oci_digest): sha256:8d3a5c7e1b9f2d4a6c8e1b3d5f7a9c2e...
  Observed (on disk): sha256:2a4c6e8b1d3f5a7c9e1b2d4f6a8c1e3b...
  An active verifier-VM session was spawned from this image at a moment when the
  on-disk image matched the policy-pinned digest, but the on-disk image has since
  changed. New verifier spawns will be rejected with FAIL_DEFAULT_VERIFIER_IMAGE_DIGEST_MISMATCH;
  the in-flight session is allowed to complete (its image bytes were already loaded).
  The image is OPERATOR-managed (not kernel-canonical per verifier-processes.md §14.5);
  the trust boundary is the operator-signed [[vm_images]] oci_digest.
  Mitigations:
    - Restore the image to the policy-pinned digest (re-extract from the release archive
      or re-pull the operator's published image)
    - OR: rotate the policy to pin the new digest (requires operator signature)
  See: specs/v2/verifier-processes.md §14.5
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
- **WSL1, WSL2:** not supported (per §2.6); KVM availability is unreliable.
- **Docker container hosting the kernel:** not supported (per §2.6); container isolation is incompatible with hypervisor access requirements.
- **Nested KVM on cloud VMs:** technically works on some providers; performance is significantly degraded. Use bare-metal cloud instances for production.

### 12.2 Filesystem

- **Network filesystems (NFS, SMB, FUSE) as `disk_root`:** not supported (per §4.1); atomic-rename and fsync semantics unreliable.
- **APFS hard quotas:** not natively supported; soft enforcement only on macOS.
- **Filesystems without project quotas:** soft enforcement only for worktree caps; hard caps require XFS prjquota or ZFS datasets.

### 12.3 Hardware

- **CPUs without hardware virtualization:** RAXIS cannot run; `/dev/kvm` will be missing on Linux, Virtualization.framework will refuse to start VMs on macOS.
- **Apple Silicon Linux distributions** (Asahi Linux): not in tested matrix; KVM support varies by hardware revision.
- **Older ARM64 (pre-ARMv8):** not supported; missing virtualization extensions and AES instructions.

### 12.3.1 VM image

- **Operator-published planner / verifier images with VM guest kernel < 5.14:** rejected at `approve_plan` with `FAIL_VM_GUEST_KERNEL_TOO_OLD` (per `INV-PLANNER-HARNESS-03`). Resolution: rebuild the image with a kernel ≥ 5.14, or switch base.
- **Operator attempts to publish a custom Reviewer image:** any `vm_image` field on a Reviewer-role task in `plan.toml` is rejected at `approve_plan` with `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` (per `INV-PLANNER-HARNESS-02`). Operators do not (and cannot) ship Reviewer images; the kernel-bundled `raxis-reviewer-core` is the only Reviewer image.
- **Tampered or version-mismatched canonical Reviewer image on disk:** `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` at every Reviewer activation; `SecurityViolationDetected { kind: "ReviewerImageDigestMismatch" }` audit emitted. Resolution: reinstall from a verified source.
- **Operator attempts to declare an Orchestrator profile or task:** rejected at `approve_plan` with `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED` or `FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED` (per `INV-PLANNER-HARNESS-06`). Operators do not declare Orchestrator profiles or tasks in V2; the kernel auto-creates the Orchestrator session per initiative.
- **Operator attempts to publish a custom Orchestrator image:** any `[[vm_images]]` entry in `policy.toml` whose `role_restriction` includes `"Orchestrator"` is rejected at policy load with `FAIL_POLICY_INVALID_ROLE_RESTRICTION` / `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED` (per `INV-PLANNER-HARNESS-05`). The kernel-bundled `raxis-orchestrator-core` is the only Orchestrator image.
- **Tampered or version-mismatched canonical Orchestrator image on disk:** `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` at every Orchestrator activation; `SecurityViolationDetected { kind: "OrchestratorImageDigestMismatch" }` audit emitted. Resolution: reinstall from a verified source.
- **Operator attempts to publish a `[[vm_images]]` entry with alias `"raxis-verifier-symbol-index"`:** rejected at policy load with `FAIL_POLICY_RESERVED_VM_IMAGE_NAME` (per `INV-VERIFIER-12`). The alias is reserved to disambiguate against the kernel-canonical symbol-index verifier image; operators wanting custom symbol-extraction tooling pick a different alias and set `policy.toml [prepare] auto_inject_symbol_index = false`.
- **Tampered or version-mismatched canonical symbol-index verifier image on disk:** `FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH` at every symbol-index verifier activation; `SecurityViolationDetected { kind: "SymbolIndexVerifierImageDigestMismatch" }` audit emitted; further symbol-index verifier spawns are halted until `raxis doctor canonical-images` succeeds. Reviewer activations that depended on the auto-injected symbol-index witness will see `WARN_REVIEWER_MISSING_SYMBOL_INDEX`. Resolution: reinstall from a verified source matching the kernel version, OR set `policy.toml [prepare] auto_inject_symbol_index = false` to disable auto-injection during recovery.
- **Tampered or version-mismatched tiered language starter image on disk** (Rust / Node / Python / Go starters per [`verifier-processes.md §14.5`](verifier-processes.md)): the trust boundary is the operator-signed `[[vm_images]] oci_digest`, NOT a kernel-embedded digest. A digest mismatch produces `WARN_DEFAULT_VERIFIER_IMAGE_DIGEST_DRIFT { language }` (no in-flight session) or `FAIL_DEFAULT_VERIFIER_IMAGE_DIGEST_MISMATCH { language }` (in-flight session was activated under the now-mismatched image). Resolution: restore the image to the policy-pinned digest, OR rotate the policy to pin the new digest (requires operator signature).
- **Operator-published image without cgroup v2 mounted or required controllers (`cpu`, `memory`, `pids`) in `subtree_control`:** rejected by `raxis doctor` and at first activation. Resolution: rebuild the image with the cgroup v2 substrate per [`planner-harness.md §10.1`](planner-harness.md).

### 12.4 Network

- **Unreliable provider connectivity:** intermittent network failures cascade into provider circuit breaker trips per [`provider-failure-handling.md §6`](provider-failure-handling.md). Operators with marginal connectivity should consider longer `total_retry_budget_ms` or alternate provider fallbacks via aliases.
- **Proxy that re-signs TLS without proper CA install:** outbound HTTPS will fail certificate verification. Install the proxy's root CA into the platform trust store (per §6.4).

### 12.5 Multi-tenancy

- **Multi-host state sharing:** not supported in V2 (per §10.4).
- **Multi-instance per host with shared state:** not supported (per [`kernel-lifecycle.md §10`](kernel-lifecycle.md) Alt I); each instance needs its own `RAXIS_HOME`.
- **Per-tenant resource isolation:** V2 enforces per-initiative VM caps and per-operator queue limits, but does not provide hard tenant isolation (one greedy initiative can degrade the host for everyone within capacity bounds). True multi-tenancy with cgroup-based per-tenant resource isolation is V3+ territory.

### 12.6 Audit data

- **Unbounded audit log growth (V2):** without V3 archiver, audit segments accumulate forever; `min_free_disk_mb` halts admission when disk fills. Operators planning multi-month deployments should provision disk for audit accumulation OR plan V3 upgrade for archiving.
- **GDPR right-to-erasure (V2):** not supported. V2 audit logs cannot be selectively redacted. V3 adds chain-truncation per `audit-retention.md §9`.

### 12.7 Distribution

- **Pre-built binary signing:** binaries are signed with the RAXIS team's developer ID for macOS and GPG-signed for Linux distributions. Operators with strict supply-chain policies should verify signatures before installation.
- **From-source builds on macOS:** require Xcode Command Line Tools and ad-hoc code signing for the Virtualization.framework entitlement. The maintained source-build path is in §9 and [`guides/SETUP.md`](../../guides/SETUP.md).

---

## 13. Document Maintenance

This document is the canonical source for "what does RAXIS need to run." When other V2 specs introduce new requirements (e.g., a future V2.x spec requires a specific filesystem feature), they MUST also update the relevant section here. Specifically:

- New external runtime dependencies → §8
- New OS feature requirements (host or VM-guest) → §2 (host §2.1–§2.2, VM-guest §2.5)
- New disk or memory minimums → §3
- New network egress requirements → §6
- New `raxis doctor` checks → §11.1 and §11.2
- New per-image conformance requirements → §2.5 + §11.1 `vm-images` / `canonical-images` categories

V3 will produce its own `specs/v3/system-requirements.md` extending this one with V3-specific additions (archiver sidecar, optional external anchor backends, etc.).
