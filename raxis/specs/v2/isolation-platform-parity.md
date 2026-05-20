# RAXIS V2 — Cross-Platform Isolation Parity Matrix

> **Status:** V2 Specified.
> **Audience:** Reviewers verifying the macOS Apple-VZ and Linux Firecracker substrates implement the `IsolationBackend` trait identically from the kernel's perspective; operators choosing a host OS for a deployment; implementers planning V2.5 / V3 follow-ups.
> **Cross-references:**
> - [`isolation-linux-microvm.md`](isolation-linux-microvm.md) — Linux Firecracker substrate spec.
> - [`extensibility-traits.md §3`](extensibility-traits.md) — `IsolationBackend` trait surface both substrates implement.
> - [`vm-network-isolation.md`](vm-network-isolation.md) — historical Tier-1 networking contract (now superseded by Path A3; see [`airgap-architecture.md`](airgap-architecture.md)).
> - [`airgap-architecture.md`](airgap-architecture.md) — Path A3 universal-airgap egress (the only non-`None` tier shipped in V2).
> - [`system-requirements.md §1.1, §2`](system-requirements.md) — host requirements.
> - `crates/raxis-isolation-apple-vz/src/lib.rs` — macOS substrate impl.
> - `crates/raxis-isolation-firecracker/src/lib.rs` — Linux substrate impl.
> - `kernel/src/isolation_select.rs` — host-OS selector.

---

## §1 What "parity" means here

The two substrates do NOT share an inch of code below the trait surface. They share a *contract*: every method the kernel calls on `Arc<dyn Backend>` MUST behave identically as observed from the kernel's POV — same return types, same error variants, same lifecycle, same byte-on-the-wire shape across vsock, same teardown semantics. A reviewer reading `kernel/src/handlers/intent.rs` should not be able to tell which substrate is plugged in by inspecting any frame the kernel sends or receives.

This matrix tracks every observable that a reviewer might think to compare. Rows marked **✅ parity** behave identically. Rows marked **⚠️ partial** have a documented divergence with no `R-*` invariant impact (typically a per-OS hardening seam or a deferred follow-up). Rows marked **❌ gap** flag a divergence that needs closing before V2 GA on the affected platform — **none currently exist for V2**.

---

## §2 Trait surface (`raxis-isolation::Backend` + `Session`)

| Method                                           | macOS Apple-VZ                                                  | Linux Firecracker                                              | Status |
|--------------------------------------------------|-----------------------------------------------------------------|----------------------------------------------------------------|--------|
| `Backend::spawn(image, mounts, spec)`            | `AppleVzBackend::spawn` → `runtime::boot_vm`                    | `FirecrackerBackend::spawn` → `boot_and_open_session`          | ✅ parity |
| `Backend::verify_isolation_guarantee()`          | Returns `R1Conformant` on macOS 13+, else `FallbackOnly`        | Returns `R1Conformant` iff `/dev/kvm` RW-openable, else `FallbackOnly` | ✅ parity |
| `Backend::backend_id()`                          | `"apple-vz-1.x"`                                                | `"firecracker-1.x"`                                            | ✅ parity (string differs by design — both are stable per-substrate identifiers) |
| `Backend::capability(BootLatencyMs)`             | `Int(200)` median                                               | `Int(50)` median (post-fast-boot tune; [`isolation-linux-microvm.md §3.1`](isolation-linux-microvm.md)) | ✅ parity (both are hints surfaced through `raxis doctor`; kernel does NOT gate admission) |
| `Backend::capability(MaxConcurrentVms)`          | `Int(64)`                                                       | `Int(256)`                                                     | ✅ parity (substrate-honest; KVM has more headroom than AVF) |
| `Backend::capability(AttestationSupported)`      | `Bool(false)`                                                   | `Bool(false)`                                                  | ✅ parity |
| `Backend::capability(MemoryEncryption)`          | `Bool(false)`                                                   | `Bool(false)`                                                  | ✅ parity (TDX/SEV-SNP substrate is V3+) |
| `Session::push(&PushFrame)`                      | `VsockChannel::send_frame` (4-byte BE length + payload, 16 MiB cap) | `HostVsockChannel::send_frame` (same)                         | ✅ parity (byte-identical wire) |
| `Session::recv_intent()`                         | `VsockChannel::recv_frame` blocks until next frame              | `HostVsockChannel::recv_frame` (same)                          | ✅ parity |
| `Session::terminate()`                           | Close channel; `vm.stop()`; `Drop` reaps                        | Close channel; SIGKILL Firecracker child; unlink UDS           | ✅ parity (per-OS mechanism, identical observable: idempotent teardown) |
| `Session::shutdown(grace) -> ExitStatus`         | `vm.requestStop()`; poll vm state with 20 ms tick; SIGKILL on grace expiry | `SendCtrlAltDel`; poll `try_wait` with 20 ms tick; SIGKILL on grace expiry | ✅ parity (graceful → forced; both report `ExitStatus::SignalKilled { signum: 9 }` on timeout) |
| `Session::session_identity()`                    | `SessionTransportId::Vsock { cid }`                             | `SessionTransportId::Vsock { cid }` (Firecracker-assigned)     | ✅ parity (both substrates surface the canonical `Vsock { cid }` shape) |
| `Session::take_kernel_ipc_fd()`                  | `Some(<surfaced fd>)` when `surface_kernel_ipc_fd` was opted-in | `Some(<UnixStream::into_raw_fd>)` after the Firecracker UDS-vsock `CONNECT 1024` handshake succeeds | ✅ parity (both substrates surrender the live planner IPC stream to `session-spawn`) |
| `Backend::capability(KvmAvailable)`              | n/a (always returns `Bool(false)` on macOS)                     | Re-runs `probe_host`; `Bool(true)` iff `/dev/kvm` RW-openable | ✅ parity (per-OS-meaningful capability; kernel ignores on the wrong OS) |
| `Backend::capability(VirtualizationFrameworkAvailable)` | Re-runs the AVF gate; `Bool(true)` on macOS 13+         | n/a (always `Bool(false)` on Linux)                            | ✅ parity (mirror of the previous row) |

---

## §3 Boot path

| Phase                                            | macOS Apple-VZ                                                  | Linux Firecracker                                              | Notes |
|--------------------------------------------------|-----------------------------------------------------------------|----------------------------------------------------------------|-------|
| VM monitor lifecycle                             | In-process via Virtualization.framework Objective-C bridge       | Subprocess (`firecracker --api-sock <path>`); REST over UDS   | Per-OS (mandatory); the kernel sees identical typed errors via `IsolationError` |
| Kernel cmdline                                   | `console=hvc0 loglevel=8 ignore_loglevel reboot=k panic=10` (verbose for diagnostics; Apple's PL011 is async-flushed) | `console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nokbd quiet loglevel=0 tsc=reliable clocksource=tsc 8250.nr_uarts=0 random.trust_cpu=on` (fast-boot recipe) | ⚠️ partial — divergence is intentional per-VMM tuning, not a contract gap. The substrate owns the cmdline; operator-supplied `boot_args` REPLACE on both substrates. |
| Initramfs vs EROFS rootfs                        | Both supported; `ImageKind::RootfsInitramfsCpio` → `vz_initial_ram_disk_url`; `RootfsErofs` → `vz_block_device_initialization` | Both supported; initramfs → `BootSource.initrd_path`; EROFS → `PUT /drives/rootfs` | ✅ parity |
| Workspace mount path                             | VirtioFS via `VZVirtioFileSystemDeviceConfiguration`            | Fail-closed for non-empty `WorkspaceMount` until Linux workspace delivery is implemented (`virtiofsd` sidecar or a typed block/artifact transport) | ❌ gap — normal planner sessions require `/workspace`; Firecracker must not be advertised as live-e2e-ready until this closes |
| Network device                                   | No `VZ*NetworkDevice*` attachment for any tier (`EgressTier::None` and `EgressTier::Mediated` both produce a NIC-less VM) | No `PUT /network-interfaces` call for any tier (both `None` and `Mediated` omit it) | ✅ parity (Path A3 — [`airgap-architecture.md`](airgap-architecture.md) — is the only egress path; the legacy `Tier1Tproxy` virtio-net + NAT codepath was deleted alongside the variant) |
| Vsock contract                                   | Host CID 2; per-session guest CID; planner port 1024            | Host CID 2; per-session guest CID (Firecracker-assigned); planner port 1024 | ✅ parity |
| Host-side vsock channel                          | `VZVirtioSocketDevice` connect; raw bytes; bounded retry until guest planner binds | UDS multiplexer + `CONNECT 1024\n`/`OK <peer_port>\n` handshake; raw bytes; bounded retry until guest planner binds | ✅ parity (handshake invisible to the kernel; both surface a `dyn Read + Write`; both tolerate the normal post-boot listener-bind race) |
| Frame envelope                                   | 4-byte BE length + payload, 16 MiB cap (`MAX_FRAME_BYTES`)       | 4-byte BE length + payload, 16 MiB cap (`MAX_FRAME_BYTES`)     | ✅ parity (byte-identical) |
| Boot grace deadline                              | 10 s (`DEFAULT_BOOT_GRACE`)                                     | 500 ms (`DEFAULT_BOOT_GRACE`)                                  | ⚠️ partial — divergence reflects per-VMM startup distribution (AVF cold path includes Objective-C bridge init); both surface `IsolationError::SpawnFailed` on grace expiry, semantically identical |
| Console log capture                              | `vz_serial_port_attachment` → per-session `console.log`         | `VmSpec.guest_console_log` → Firecracker stdout/stderr → per-session `console.log` | ✅ parity (both refuse silent console discard and create the parent path before boot) |

---

## §4 Security posture

| Hardening                                                      | macOS Apple-VZ                                                  | Linux Firecracker                                              | Status |
|----------------------------------------------------------------|-----------------------------------------------------------------|----------------------------------------------------------------|--------|
| R-1 hardware-virtualised isolation                             | AVF (Apple Silicon Hypervisor.framework underneath)              | KVM (`/dev/kvm`)                                                | ✅ parity (both deliver R-1) |
| No fallback to user-mode emulation                             | AVF unavailable ⇒ substrate refuses spawn (kernel admission helper rejects unless `--unsafe-fallback-isolation`) | `/dev/kvm` unopenable ⇒ same | ✅ parity |
| 16 MiB host-OOM cap on vsock frames                            | `vsock.rs::MAX_FRAME_BYTES`                                     | `vsock.rs::MAX_FRAME_BYTES`                                    | ✅ parity |
| Per-session console log                                        | `<runtime_dir>/<session_uuid>.console.log`                      | `<runtime_dir>/<session_uuid>.console.log`                     | ✅ parity |
| `Session::Drop` reaps the VM                                   | `vm.stop()` then `vz_stop_callback`                             | SIGKILL the Firecracker child + unlink UDS                     | ✅ parity (idempotent on both) |
| `prctl(PR_SET_NO_NEW_PRIVS)` on the VMM child                   | n/a (in-process; the kernel binary's own posture applies)        | TODO V2.5 — extend `vmm.rs::SpawnArgs` with a `Command` argv hook | ⚠️ partial — non-blocking; doesn't weaken `R-1` |
| Drop ambient caps on the VMM child                              | n/a (in-process)                                                | TODO V2.5 — `prctl(PR_CAPBSET_DROP, ...)` + `setresuid` to non-privileged user | ⚠️ partial — non-blocking |
| Seccomp filter on the VMM                                       | macOS sandbox profile applied by launchd; not configurable from the substrate | Operator-opt-in via `extra_args = ["--seccomp-level", "2"]`; default-on slated for V2.5 | ⚠️ partial — both leave the door open to operator-defined hardening |
| cgroups-v2 quota (CPU + memory + pids)                          | `VZVirtualMachineConfiguration.{cpu,memory}` directly bound; no per-process cgroup     | Honoured via `VmSpec.cgroup_quota` writes BEFORE `InstanceStart` (kernel runtime side; substrate forwards) | ✅ parity (different mechanism, identical contract) |
| Memory encryption (SEV-SNP / TDX)                               | Apple's hypervisor handles guest-physical-addressing transparently; no SEV equivalent | Not yet (Firecracker doesn't expose SEV)                        | ⚠️ partial — V3+ for both; `Backend::capability(MemoryEncryption)` already returns `false` so the kernel doesn't claim it |
| Remote attestation                                              | n/a (DeviceCheck / App Attest is a different layer)              | Not yet (TDX/SEV-SNP substrate is V3+)                          | ⚠️ partial — V3+ for both; `Backend::capability(AttestationSupported)` already returns `false` |

---

## §5 Networking (Path A3 universal-airgap contract)

After the Tier1Tproxy deletion every supported egress tier
produces a NIC-less VM. The kernel arbitrates outbound TCP and
DNS over AF_VSOCK rather than over a virtio-net device — see
[`airgap-architecture.md`](airgap-architecture.md) for the wire protocol. The substrate's
job is to honour `EgressTier::Mediated` by emitting *no* network
device, and to honour `EgressTier::None` the same way.

| EgressTier              | macOS Apple-VZ                                                  | Linux Firecracker                                              | Status |
|-------------------------|-----------------------------------------------------------------|----------------------------------------------------------------|--------|
| `EgressTier::None`      | No `VZ*NetworkDevice*` attachment — VM has no virtio-net at all | No `PUT /network-interfaces/...` — VM has no virtio-net        | ✅ parity |
| `EgressTier::Mediated`  | No `VZ*NetworkDevice*` attachment — VM has no virtio-net; egress flows over the per-session vsock device set up by the substrate's IPC channel | No `PUT /network-interfaces/...` — VM has no virtio-net; egress flows over the per-session vsock device set up by the substrate's IPC channel | ✅ parity (both substrates structurally enforce the no-NIC invariant) |
| `EgressTier::Tier2CredProxy` | Not yet wired (V2.5 — extends the boot device list with a per-credential socketpair) | Not yet wired (V2.5 — same)                                    | ⚠️ partial — both substrates share the gap; no per-OS divergence |

The kernel-side admission gate (`handlers::tproxy_admit`,
`handlers::dns_resolve`, per-session vsock tunnel listener) is
OS-aware but lives in `kernel/src/` — the substrate never touches
it. The previous host-side tap / nftables / pf egress wiring
referenced by old revisions of this matrix was removed alongside
the `Tier1Tproxy` variant.

---

## §6 Build / stage pipeline

| Concern                                          | macOS                                                            | Linux                                                          | Status |
|--------------------------------------------------|------------------------------------------------------------------|----------------------------------------------------------------|--------|
| Guest-kernel binary staging                      | `cargo xtask images dev-kernel --from-file <PATH>` or `--url + --sha256` | Same command (`xtask/src/dev_kernel.rs` is OS-agnostic)        | ✅ parity |
| Initramfs build                                  | `cargo xtask images bake` (single end-to-end driver)             | Same command                                                    | ✅ parity |
| One-shot bundle                                  | `cargo xtask images bake` runs the full pipeline per role; AVF demo recipe in `demo-e2e-sample/AVF_DEMO.md` | `cargo xtask linux-microvm bundle`                              | ⚠️ partial — Linux-only convenience wrapper invokes the bake's stage + pack steps; macOS operators get the same outputs from `cargo xtask images bake`. No `R-*` impact. |
| Host preflight                                   | `cargo xtask dev-prereqs` — brew + rustup + linker pin | `cargo xtask linux-prereqs` — KVM, vhost_vsock, kvm group, kernel ≥ 5.10, cgroup v2, firecracker(1) | ✅ parity (per-OS surface; both emit the same `Outcome::{Ok,Warn,Fail}` shape) |
| Doctor wiring                                    | `raxis doctor host` includes `host.cgroup_v2` and `host.disk_free_mb`; AVF/KVM probe deferred to V3 | Same; `linux-prereqs` is wired into `raxis doctor host` | ⚠️ partial — wiring is a one-line `r.checks.extend(linux_prereqs::probe_linux_prereqs().checks)` in `cli/src/commands/doctor.rs::collect_host`; module signatures are aligned |

---

## §7 Selector wiring

`kernel/src/isolation_select.rs::build_platform_backend` is the single point where the host OS is mapped to a substrate. Both arms hand back `Box<dyn Backend>`:

```rust
#[cfg(target_os = "linux")]
{ Box::new(FirecrackerBackend::new(runtime_dir)) }

#[cfg(target_os = "macos")]
{ Box::new(AppleVzBackend::new(runtime_dir)) }
```

Every other code path in the kernel touches the trait, never a concrete substrate. A reviewer changing `intent.rs` cannot regress one substrate without regressing the other (the trait would no longer compile). This is the contract we lean on; the parity matrix is the human-readable sanity check.

The selector also runs `admit_backend` (also in `isolation_select.rs`) which calls `verify_isolation_guarantee()` and rejects `FallbackOnly` unless the operator explicitly opted in — the per-OS substrate decides what "fallback" means (`AVF unavailable` on macOS; `KVM unopenable` on Linux).

---

## §8 What V2 ships, what V2.5 closes, what V3+ adds

### §8.1 V2 (this matrix's scope)

* Both substrates implement the trait surface.
* All `R-*` invariants preserved on both substrates.
* All ✅-parity rows above are testable against the trait conformance fixture in `crates/raxis-isolation/tests/`.
* Firecracker is not production-ready for normal planner sessions until the `/workspace` delivery gap closes. The substrate now fails closed when a non-empty `WorkspaceMount` reaches it, so Linux operators see a deterministic admission error instead of a guest that boots and later fails in the tools layer.

### §8.2 V2.5 (next minor)

| Gap                                                     | Closing path                                                     | Substrate(s) affected     |
|---------------------------------------------------------|------------------------------------------------------------------|---------------------------|
| `prctl(PR_SET_NO_NEW_PRIVS)` on Firecracker child       | `vmm.rs::SpawnArgs` — `Command` argv prefix `setpriv --no-new-privs --reuid <uid> --regid <gid> --` | Linux only (no-op on macOS) |
| Cap-drop on Firecracker child                           | Same hook + `--clear-groups` / `--securebits noroot,no_setuid_fixup` | Linux only |
| Operator-mandatory seccomp on Firecracker               | Default `extra_args = ["--seccomp-level", "2"]` instead of opt-in | Linux only |
| `EgressTier::Tier2CredProxy` wiring                     | New device row in both substrate boot sequences; per-credential socketpair | Both |
| Wire `linux_prereqs::probe_linux_prereqs()` into `raxis doctor host` | One `r.checks.extend(...)` line; both surfaces already emit `Check`/`Outcome`/`Report` | CLI side, no substrate change |

### §8.3 V3+ (deferred)

| Feature                                                  | Notes                                                            |
|----------------------------------------------------------|------------------------------------------------------------------|
| Snapshot/resume (sub-10 ms cold-boot)                    | Firecracker has the primitive; AVF has `VZVirtualMachine.canPause`. Both substrate roadmaps converge on a `(role, kernel_sha, initramfs_sha) → snapshot.bin` cache. |
| Workspace delivery for `/workspace` and `/raxis` on Linux | Prefer a `virtiofsd` sidecar if the selected Firecracker build exposes the needed device/API; otherwise attach a kernel-owned writable block/artifact transport and copy changes back through the admission path. |
| Memory-encrypted substrate (TDX / SEV-SNP)               | New `IsolationLevel::R1ConformantStrong`; requires either a third substrate crate (`raxis-isolation-tdx`) or a Firecracker fork once Firecracker upstreams TDX. |
| Remote attestation                                       | TDX quote / SEV-SNP attestation report surfaced through `Backend::capability(AttestationReport) -> Bytes`. |

The Linux workspace-delivery row is blocking for Firecracker-backed V2
planner sessions. Until it closes, macOS AVF is the production microVM
path for workspace-backed live e2e runs.

---

## §9 How to read this matrix as a reviewer

1. Grep for ❌ — each row is a real release blocker for the affected substrate. Firecracker's current `/workspace` gap is intentional fail-closed debt, not a hidden runtime surprise.
2. Grep for ⚠️ — these are the documented divergences. Each one MUST come with either (a) a per-OS rationale that doesn't touch `R-*`, or (b) a closing-path entry in §8.
3. Read every ✅ row and ask "would the kernel notice if I swapped the substrate?". The answer should be no for every row (modulo the per-OS capability hints that the kernel explicitly ignores per the `BootLatencyMs` / `MaxConcurrentVms` / `KvmAvailable` semantics).
4. Compare against `crates/raxis-isolation/tests/` — every ✅ row should have a corresponding conformance test the kernel runs against `Arc<dyn Backend>` once the substrate is plugged in.

If a future contributor adds a method to `IsolationBackend` or a new device to either substrate, this matrix gains a row. The matrix is the single source of truth for substrate parity; the trait crate's conformance kit is the executable enforcement.
