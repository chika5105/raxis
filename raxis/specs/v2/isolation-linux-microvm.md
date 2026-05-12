# RAXIS V2 — Linux microVM Isolation Backend

> **Status:** V2 Specified.
> **Audience:** Implementers wiring `raxis-isolation-firecracker` against a Linux + KVM host; reviewers verifying that the Linux substrate enforces the same `R-1` invariants as the macOS Apple-VZ substrate; operators provisioning a Linux deploy box.
> **Cross-references:**
> - [`extensibility-traits.md §3`](extensibility-traits.md) — `IsolationBackend` trait surface this substrate implements.
> - [`extensibility-traits.md §3.5`](extensibility-traits.md) — Reference impl table; this is the `FirecrackerIsolation` row.
> - [`system-requirements.md §2.1, §5.1`](system-requirements.md) — host kernel + KVM admission rules this substrate inherits.
> - [`vm-network-isolation.md`](vm-network-isolation.md) — Tier-1 `raxis-tproxy` contract every isolation backend MUST satisfy.
> - [`isolation-platform-parity.md`](isolation-platform-parity.md) — feature parity matrix between Apple-VZ and Firecracker.
> - `crates/raxis-isolation/` — trait crate.
> - `crates/raxis-isolation-firecracker/` — concrete substrate (this spec's normative implementation).
> - `crates/raxis-isolation-apple-vz/` — sibling macOS substrate (this spec's parity reference).
> - `kernel/src/isolation_select.rs` — host-OS selector that picks Firecracker on Linux.

---

## §1 Why a Dedicated Linux microVM Backend

The reference RAXIS deployment runs the planner inside a hardware-virtualised microVM (`paradigm.md §3 R-1`). On macOS hosts the substrate is `raxis-isolation-apple-vz` (Virtualization.framework). On Linux hosts the substrate is `raxis-isolation-firecracker` (this spec). Three considerations forced a dedicated Linux backend rather than re-using a portable VMM:

1. **Boot latency budget.** The kernel spawns one VM per session and re-spawns on every continuation; the per-spawn cost is on the operator's hot path (operator types `raxis approve`, the orchestrator session must be ready in the same blink as a process exec). A Linux microVM with a stripped-down kernel + initramfs, KVM, and no QEMU device tree boots in single-digit-to-low-double-digit milliseconds. A general-purpose VMM (qemu-system-x86_64) is 10–50× slower from `vm.start()` to "guest agent reachable".
2. **R-1 conformance bar.** `paradigm.md §3 R-1` requires "at least equivalent to a hardware-virtualized microVM, hardware enclave, or formally verified microkernel partition." Linux namespaces + seccomp do not satisfy R-1 (kernel-shared address space). The substrate therefore MUST drive a real microVM via KVM.
3. **Cross-platform parity with Apple-VZ.** The kernel's planner-spawn / vsock-handshake / artifact-mount path is identical across hosts; the only thing that changes is which substrate is plugged into `Arc<dyn Backend>`. A Linux backend whose contract diverges from AVF would force `kernel/src/handlers/intent.rs` to fork its admission logic per-host, which is a security smell.

---

## §2 VMM Choice — Firecracker

Three candidates were evaluated for the Linux KVM seat. The substrate ships **Firecracker**.

### §2.1 Decision matrix

| Candidate              | Cold-boot | Rust   | Vsock     | VirtioFS         | API model           | Attack surface    | Verdict |
|------------------------|-----------|--------|-----------|------------------|---------------------|-------------------|---------|
| **Firecracker**        | ~125 ms reference; ~30–80 ms achievable with stripped kernel | ✅ pure-Rust, rust-vmm based | ✅ vhost-vsock UDS multiplexer | ❌ not in upstream — operator-supplied virtiofsd is required for `/workspace` / `/raxis` mounts (workaround: drive table + vsock-mediated artifact RPC, current V2 strategy) | REST over UDS, supervised child process | minimal device set; ~50 KLOC of Rust; production-hardened by AWS Lambda / Fargate | **selected** |
| Cloud Hypervisor       | ~150–250 ms | ✅ pure-Rust | ✅ vhost-vsock | ✅ virtiofs in tree | REST + library; can be linked as a crate | larger device set (full virtio-pci enumeration); ~200 KLOC | considered for V3 once virtiofs becomes the staging path; rejected for V2 because the larger device tree extends boot by ~50 ms even after trimming and the substrate gains nothing the workspace-RPC path doesn't already provide |
| qemu `-M microvm`      | ~250–500 ms | ❌ C | ✅ vhost-vsock | ✅ virtiofsd | argv + QMP socket | full QEMU codebase (~1.5 MLOC); CVE-trail | rejected — wrong end of every axis we care about |

### §2.2 Why Firecracker for V2

* **Pure-Rust, rust-vmm provenance.** The substrate links nothing C-side (Firecracker runs as a separate child process exec'd from the kernel; the substrate's REST client is a 200-line hand-rolled HTTP/1.1 over UDS, see `crates/raxis-isolation-firecracker/src/api.rs`). Defence-in-depth: a Firecracker exploit is contained to the per-session child, not the kernel binary.
* **Smallest hardware-virtualised attack surface.** Firecracker exposes virtio-blk, virtio-net (tap-only), virtio-vsock, and a serial console — and that's it. No PCI enumeration, no USB, no graphics, no audio, no power management. Every device that doesn't exist is a zero-day that can't fire.
* **Vsock matches the Apple-VZ contract byte-for-byte.** AVF exposes the planner's vsock channel via `VZVirtioSocketDevice`; Firecracker exposes it via the `/vsock` REST endpoint backed by a host-side UDS multiplexer (`CONNECT <port>\n` ⇒ `OK <peer_port>\n` handshake). Both substrates surface a host-side raw byte stream the kernel reads/writes length-prefixed bincode `IpcMessage` frames over (see `peripherals.md §3` framing). The kernel's planner-IPC code path is single-target across substrates.
* **Snapshot/resume is the future-roadmap optimisation.** Firecracker's snapshot-and-restore primitive boots a memory image in <10 ms. V2 does not yet ship snapshots (we re-boot from kernel + initramfs every session); V3 will add a per-role snapshot, gated by a deterministic `(kernel_sha, initramfs_sha, role)` cache key. The substrate code path is already structured to slot this in (the `SpawnArgs` envelope in `crates/raxis-isolation-firecracker/src/vmm.rs` accepts `extra_args` for `--restore-from-snapshot`).

### §2.3 Versions and pins

* **Firecracker binary:** ≥ `v1.6.0` (the rust-vmm vsock multiplexer wire format settled in 1.6). The `BACKEND_ID` constant (`crates/raxis-isolation-firecracker/src/lib.rs`) reports `"firecracker-1.x"` so audit consumers can filter without coupling to a point release.
* **Reference kernel:** Firecracker publishes a known-good vmlinux at `https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/<arch>/vmlinux-<kver>.bin`. RAXIS pins **5.10.225** for `x86_64` and `aarch64` as the floor (matches `system-requirements.md §1.1` "VM guest kernel ≥ 5.10"); the kernel-bundled canonical-image pipeline ships its own RAXIS-built vmlinux (5.14+) so operators on those images get the higher floor without re-staging.
* **vhost-vsock kernel module:** `vhost_vsock` MUST be loaded (the substrate refuses to spawn otherwise). Modern distros load it on demand; air-gapped / minimal kernels need an explicit `modprobe vhost_vsock` in the boot path.

---

## §3 Boot Path and Latency Budget

### §3.1 Phase breakdown

The substrate's `Backend::spawn` is the kernel's hot path. Wall-clock from `vm.start()` to "guest agent reachable on vsock" is budgeted as:

| Phase                                            | Target (ms) | Floor (ms) | Owner                                          |
|--------------------------------------------------|-------------|------------|------------------------------------------------|
| `firecracker --api-sock <path>` exec + UDS bind  | 5           | 1          | OS (`fork`/`exec`); host filesystem            |
| `wait_for_api_sock` (poll loop, 5 ms tick)       | 5           | 0          | substrate (`vmm.rs::wait_for_api_sock`)        |
| `PUT /machine-config` + `/boot-source` + `/drives/rootfs` + `/vsock` (4 round-trips on UDS) | 4    | 1     | substrate (`api.rs::request`)                  |
| `PUT /actions {InstanceStart}` returns           | 1           | 0          | Firecracker                                    |
| KVM `KVM_RUN` first vCPU enter; kernel decompress + handover to PID 1 | 30 | 15  | guest kernel (`quiet loglevel=0`)             |
| PID 1 `/init` exec; mount sysfs/proc; bring up vsock loopback | 10  | 4         | initramfs                                      |
| Planner agent connects vsock CID 3 → guest port 1024 | 5      | 1          | guest agent                                    |
| Substrate `HostVsockChannel::connect` handshake (CONNECT/OK) | 2 | 1     | substrate (`vsock.rs::connect`)                |
| **Total**                                        | **~62**     | **~23**    |                                                |

The substrate reports `CapabilityKind::BootLatencyMs = 50` (median observed on a Ryzen 7950X / 5.15 host with the kernel pins above). The capability is a microbenchmark median, not a hard guarantee — a noisy host (NUMA migrations, swap pressure) can push the tail past 100 ms. The kernel does not gate session admission on this number; it surfaces it through `raxis doctor` so operators can spot regressions.

### §3.2 Kernel cmdline (fast-boot recipe)

The substrate stamps the following cmdline by default (see `crates/raxis-isolation-firecracker/src/lib.rs::drive_boot`):

```
console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nokbd \
  quiet loglevel=0 tsc=reliable clocksource=tsc 8250.nr_uarts=0 \
  random.trust_cpu=on
```

For initramfs boots (`ImageKind::RootfsInitramfsCpio`) the substrate appends `rdinit=/init`; for EROFS rootfs boots (`ImageKind::RootfsErofs`) it appends `root=/dev/vda ro`.

Each token earns its place:

| Token                          | Why it's there                                                                                          |
|--------------------------------|---------------------------------------------------------------------------------------------------------|
| `console=ttyS0`                | Send guest printk/serial to Firecracker's serial device; the host pipes it to the per-session `console.log` for post-mortem debugging. |
| `reboot=k`                     | Use `keyboard reboot` (KVM trap) on `reboot()` — fastest exit path, no ACPI tree.                      |
| `panic=1`                      | One-second panic-to-reboot; the VMM observes the reboot as a clean exit so the audit chain records `GracefulExit { code }` not `BackendError`. |
| `pci=off`                      | Skip PCI enumeration entirely. Firecracker exposes no PCI devices; the bus-walk is pure overhead.       |
| `i8042.noaux` / `i8042.nokbd`  | Skip i8042 (PS/2) probe — Firecracker has neither port and the probe blocks for ~30 ms on fail.         |
| `quiet`                        | Suppress kernel boot banner; saves ~3–5 ms of serial-port writes.                                       |
| `loglevel=0`                   | Suppress every printk that isn't an emergency. Saves another ~5 ms of console traffic at boot.          |
| `tsc=reliable`                 | Trust the TSC as a stable clocksource without the calibration sweep.                                    |
| `clocksource=tsc`              | Pin clocksource at `tsc` directly so the kernel doesn't probe HPET/PIT.                                |
| `8250.nr_uarts=0`              | Tell the 8250 driver there are no extra UARTs — skips a slow probe loop. (`console=ttyS0` keeps the one we do have.) |
| `random.trust_cpu=on`          | Seed the kernel RNG from `RDRAND` instead of waiting for entropy. Safe on KVM where the host has its own entropy and the guest's "secrets" are session-scoped tokens the kernel mints. |
| `rdinit=/init` (initramfs only) | Make the cpio-archived `/init` PID 1 regardless of `CONFIG_DEFAULT_INIT`.                              |
| `root=/dev/vda ro` (EROFS only) | Mount the virtio-blk rootfs read-only.                                                                 |

Operator-supplied `VmSpec.boot_args` REPLACE (do not append to) the substrate defaults — same shape as Apple-VZ. The `session_spawn_orchestrator` stamps an empty `boot_args` for canonical roles so the substrate owns the cmdline.

### §3.3 Initramfs trim

The canonical Reviewer / Orchestrator / Executor-starter rootfs initramfs (built by `crates/raxis-image-builder` and `crates/raxis-initramfs-builder`) ships exactly:

* `/init` — the planner agent binary, statically linked against musl. No dynamic loader; no `ld.so` resolution.
* `/dev`, `/proc`, `/sys` — empty mount points, populated by `/init`.
* `/raxis` — empty mount point; the workspace artifact is staged via vsock-mediated RPC (V2) or virtiofs (V3+).
* `/etc/{passwd,group,resolv.conf}` — three-line files, pinned for libstd's `gethostname` / `getuid` paths.

Total uncompressed size: ~6 MB (planner agent binary dominates). Gzip-compressed cpio: ~2.2 MB. The kernel's lazy-page-fault paging means only the pages PID 1 actually touches before connecting vsock are decompressed — ~1.5 MB worth.

---

## §4 Vsock Contract (Identical to Apple-VZ)

### §4.1 Wire shape

* Host CID is fixed at `2` (KVM convention; Firecracker pins it).
* Guest CID is assigned per session; the kernel's session-spawn orchestrator picks from a free pool. CIDs `3`–`max` are valid per VM; the substrate reports the assigned CID via `Session::session_identity() -> SessionTransportId::Vsock { cid }`.
* The planner agent inside the guest binds a vsock listener on **port 1024** (`crates/raxis-isolation-firecracker/src/lib.rs::DEFAULT_PLANNER_PORT`). Apple-VZ uses the same port — this is the "single port, multi substrate" guarantee the kernel relies on.
* The host dials in via Firecracker's UDS multiplexer: `connect()` to `<runtime_dir>/<session_uuid>.vsock`, send `CONNECT 1024\n`, expect `OK <peer_port>\n`, then the stream carries length-prefixed bincode `IpcMessage` frames in both directions (`crates/raxis-isolation-firecracker/src/vsock.rs::HostVsockChannel`).

### §4.2 Frame shape

Length-prefix is a 4-byte big-endian `u32`. Maximum frame size is 16 MiB (`MAX_FRAME_BYTES`); the substrate refuses larger frames before touching the wire so a buggy guest cannot host-OOM. The kernel parses `IpcMessage` per `peripherals.md §3`; the substrate is byte-conduit-only and never inspects the payload.

### §4.3 Idle / closed semantics

* `Session::recv_intent()` blocks until the next frame arrives; returns `IsolationError::PeerClosed` when the guest exits cleanly.
* `Session::push()` returns `IsolationError::PeerClosed` when the guest dropped the connection mid-write.
* `Session::terminate()` closes the host side of the channel first (so any in-flight guest write fails fast), then kills the Firecracker child via `SIGKILL`, then removes the per-session UDS files. Idempotent.

---

## §5 Networking (Tier-1 tproxy, V2)

The substrate plumbs the `EgressTier::Tier1Tproxy` variant by adding a `PUT /network-interfaces/eth0` REST call to the boot sequence with `host_dev_name = "raxis-tap"`. The kernel-side egress wiring (per `vm-network-isolation.md §3`) is responsible for:

1. Creating the host tap device + nftables redirect into `raxis-tproxy` BEFORE calling `Backend::spawn`.
2. Tearing down the tap device + nftables ruleset on `Session` drop.

The substrate does NOT own network plumbing — it only forwards the operator-declared egress tier to Firecracker. A future `EgressTier::Tier2CredProxy` would extend the boot sequence with a per-credential socket-pair, gated by `credential-proxy.md`.

`EgressTier::None` (Reviewer images, `INV-NETISO-01`) is the no-op default — Firecracker boots without a virtio-net device at all, so the guest can't attempt egress.

---

## §6 Security Posture

The substrate inherits `paradigm.md §3 R-1` and adds the following Linux-specific hardenings:

| Hardening                                                      | Mechanism                                                                                  | Status (V2)        |
|----------------------------------------------------------------|--------------------------------------------------------------------------------------------|--------------------|
| `/dev/kvm` opened RW; no qemu/userspace fallback               | `crates/raxis-isolation-firecracker/src/lib.rs::probe_host` rejects spawn without `/dev/kvm` | ✅ implemented      |
| Firecracker child runs as the kernel's effective UID/GID       | No `setuid` / `setgid` in the child path; the `kvm` group membership is the operator's job | ✅ implemented      |
| `Session::Drop` reaps the Firecracker child + removes UDS      | `vmm.rs::Drop` calls `terminate()` which kills + waits + unlinks                          | ✅ implemented      |
| 16 MiB host-OOM cap on vsock frames                            | `vsock.rs::MAX_FRAME_BYTES`                                                                | ✅ implemented      |
| `prctl(PR_SET_NO_NEW_PRIVS)` on the Firecracker child           | TODO — `Command` argv extension                                                           | follow-up          |
| Drop ambient caps (`CAP_DROP=ALL except CAP_NET_ADMIN`)        | TODO — `Command` argv extension via `setcap`-on-binary or setuid wrapper                  | follow-up          |
| Seccomp filter on the Firecracker child                        | Firecracker ships its own seccomp profile (`--seccomp-level 2`); the substrate enables it via `extra_args` when the operator opts in. | partial — operator-opt-in |
| cgroups v2 quota (CPU + memory + pids)                         | Kernel-side; the substrate honours `VmSpec.cgroup_quota` by writing the controller files BEFORE `InstanceStart`. | follow-up: enforcement is on the kernel-runtime side, not the substrate |
| KVM-only; no fallback to user-mode emulation                   | `probe_host` returns `KvmUnavailable` ⇒ kernel admission helper refuses unless `--unsafe-fallback-isolation` is set | ✅ implemented      |

The "follow-up" rows are tracked in `isolation-platform-parity.md` as gaps to close in V2.5 / V3. None of them weaken `R-1`; the microVM seam is the load-bearing isolation, the additional hardenings are defence-in-depth.

---

## §7 Teardown Contract

`Session::shutdown(grace)` is the graceful path:

1. Send Firecracker `PUT /actions {SendCtrlAltDel}` (best-effort; if the child already exited the call fails and the wait loop below picks up the exit status).
2. Close the vsock channel.
3. `try_wait()` the child with a 20 ms tick until `grace` elapses.
4. On grace expiry, `kill()` (SIGKILL) and `wait()`; report `ExitStatus::SignalKilled { signum: 9 }`.
5. Unlink the API socket and vsock UDS files.

`Session::terminate()` is the security-kill path: same as shutdown but skips Ctrl-Alt-Del entirely and uses `grace = 0`. Idempotent. `Drop` calls `terminate` so a forgetful caller can't leak a child.

---

## §8 Mapping to the IsolationBackend Trait

| Trait method (`crates/raxis-isolation/src/lib.rs`)              | Substrate impl (`crates/raxis-isolation-firecracker/src/lib.rs`)                              |
|------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| `Backend::spawn(image, mounts, spec) -> Box<dyn Session>`        | `FirecrackerBackend::spawn` — probe host, mint UDS paths, call `boot_and_open_session`         |
| `Backend::verify_isolation_guarantee() -> IsolationLevel`        | Returns `R1Conformant` iff `/dev/kvm` is RW-openable; else `FallbackOnly`                      |
| `Backend::capability(BootLatencyMs)`                             | `Int(50)` (median; see §3.1 budget)                                                            |
| `Backend::capability(KvmAvailable)`                              | Re-runs `probe_host` (cheap fs check)                                                          |
| `Backend::capability(MaxConcurrentVms)`                          | `Int(256)` — bounded by KVM's per-host vCPU FD ceiling, not Firecracker                        |
| `Backend::capability(AttestationSupported)`                      | `Bool(false)` — Firecracker has no remote-attestation primitive (TDX/SEV-SNP are V3+)          |
| `Backend::capability(MemoryEncryption)`                          | `Bool(false)` — same reason                                                                    |
| `Backend::backend_id() -> &'static str`                          | `"firecracker-1.x"`                                                                            |
| `Session::push(&PushFrame)`                                      | `HostVsockChannel::send_frame` (4-byte BE length prefix + payload)                             |
| `Session::recv_intent() -> IntentFrame`                          | `HostVsockChannel::recv_frame`                                                                 |
| `Session::terminate()`                                           | Close channel, kill child, unlink UDS. Idempotent.                                             |
| `Session::shutdown(grace) -> ExitStatus`                         | Send Ctrl-Alt-Del, poll `try_wait`, escalate to SIGKILL on timeout                             |
| `Session::session_identity() -> SessionTransportId`              | `Vsock { cid: <assigned> }` — same shape as AVF                                                |
| `Session::take_kernel_ipc_fd() -> Option<RawFd>`                 | (V2) `None` — kernel uses the synchronous `push`/`recv_intent` path; V3 will surrender the underlying `UnixStream` fd for the kernel's async dispatch loop, mirroring AVF's `surface_kernel_ipc_fd` seam |

The kernel's `kernel/src/isolation_select.rs::build_platform_backend` instantiates `FirecrackerBackend::new(runtime_dir)` on `cfg(target_os = "linux")` and `AppleVzBackend::new(runtime_dir)` on `cfg(target_os = "macos")`. No other code in the kernel branches on host OS for substrate selection.

---

## §9 Build / Stage Pipeline

The substrate consumes two artefacts at spawn time:

1. **Kernel binary** — staged at `<install_dir>/kernel/vmlinux` by `cargo xtask images dev-kernel` (existing). Operators in the demo flow run `cargo xtask images dev-kernel --url <fc-reference-kernel-url> --sha256 <hex>`; air-gapped operators run `cargo xtask images dev-kernel --from-file vmlinux.bin`.
2. **Rootfs image** — staged by `cargo xtask images build-all` (existing). Produces a signed `cpio.gz` initramfs per role (Reviewer, Orchestrator, Executor-starter), packaged with a sibling `*.manifest.toml` that the kernel verifies against its compile-time trust anchor.

**New for V2** (this spec): `cargo xtask linux-microvm bundle` — a one-shot orchestrator that runs `dev-kernel` (from a known-good Firecracker reference URL pin) followed by `build-all` for every role, producing a complete demo-ready bundle under `<install_dir>/`. See `xtask/src/linux_microvm.rs`.

**New for V2** (this spec): `cargo xtask linux-prereqs` — host preflight that probes:

* `/dev/kvm` exists and is RW-openable by the calling user
* `vhost_vsock` module loaded (parses `/proc/modules`)
* Calling user is in the `kvm` group (parses `/proc/self/status` and `/etc/group`)
* Host kernel version ≥ 5.10 (parses `/proc/sys/kernel/osrelease`)
* `firecracker` binary on PATH (best-effort `which` shellout)

The same checks are mirrored into `raxis doctor host` (Worker A's surface) once Worker A's branch lands; the `xtask` entry point is the operator's pre-doctor probe.

---

## §10 What V2 does NOT yet ship (deferred)

| Gap                                                     | What would close it                                                                            | Target |
|---------------------------------------------------------|------------------------------------------------------------------------------------------------|--------|
| Snapshot / resume (sub-10ms boot)                       | Persist `/var/raxis/snapshots/<role>.snap` after first boot of each role; substrate `--restore-from-snapshot` arg | V3 |
| VirtioFS for `/workspace` and `/raxis` (instead of vsock-RPC artifact staging) | Wire upstream `virtiofsd` as a sidecar; add `PUT /shared-directory/<id>` to the boot REST sequence | V3 |
| `prctl(PR_SET_NO_NEW_PRIVS)` on Firecracker child       | Extend `vmm.rs::SpawnArgs` with a syscall-prefork hook                                          | V2.5 |
| Cap-drop on the Firecracker child                       | Same hook; `prctl(PR_CAPBSET_DROP, ...)` + `setresuid` to a non-privileged user                 | V2.5 |
| Operator-mandatory seccomp                              | Default `extra_args = ["--seccomp-level", "2"]` instead of operator-opt-in                      | V2.5 |
| Snapshot integrity hash chain                           | Sign `(role, kernel_sha, initramfs_sha, snapshot_sha)` with the kernel signing key; verify before `restore-from-snapshot` | V3 |
| Remote attestation (TDX / SEV-SNP)                      | New `IsolationLevel::R1ConformantStrong` substrate; out of scope for Firecracker               | V3+ |

None of these are blocking for V2 GA on Linux. The substrate as shipped enforces every R-* invariant and matches the macOS Apple-VZ contract on every observable surface.

---

## §11 Summary

The Linux microVM substrate is `raxis-isolation-firecracker`. It boots a Firecracker microVM per session, drives the boot REST sequence over a per-session UDS, dials a vsock channel on guest port 1024 for the planner-IPC frame stream, and tears down on `Drop`. Boot-to-agent-reachable is budgeted at ~50 ms (median), ~100 ms (worst-case healthy host). The contract is byte-identical to Apple-VZ from the kernel's perspective; the only host-aware code lives in `kernel/src/isolation_select.rs`.
