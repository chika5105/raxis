//! Pure-data typed translator from [`raxis_isolation::VmSpec`] into the
//! AVF configuration objects we hand to `VZVirtualMachineConfiguration`.
//!
//! Why this exists as a separate, platform-agnostic module:
//!
//! * AVF's Objective-C bridge is macOS-only. Building configs on
//!   non-macOS hosts (the parent kernel doing dry-run validation, a
//!   Linux CI runner verifying the substrate compiles cleanly) needs
//!   to work without linking `Virtualization.framework`.
//! * The translator's logic — refusing inline-bytes images, choosing
//!   serial console flags, deriving the planner port — is testable
//!   without any Objective-C runtime calls.
//! * The `runtime` module on macOS consumes `AvfConfig` to build the
//!   AVF objects; the same `AvfConfig` shape is what the integration
//!   tests assert on.

use std::path::PathBuf;

use raxis_isolation::{
    EgressTier, ImageBody, ImageKind, MountMode, VerifiedImage, VmSpec, WorkspaceMount,
};

/// Errors the translator can surface.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// `VerifiedImage::body` was inline bytes; AVF requires an
    /// mmap-able file (Linux kernel image).
    #[error("inline-bytes images are not supported by AVF; the image resolver must materialise to a Path")]
    InlineBytesUnsupported,

    /// `VerifiedImage::kind` was not a Linux rootfs; AVF substrate
    /// boots Linux guests via `VZLinuxBootLoader`.
    #[error("image kind {kind:?} is not bootable as a Linux guest by this substrate")]
    UnsupportedImageKind {
        /// The unsupported kind.
        kind: ImageKind,
    },

    /// Some mount specified an empty `guest_path`. AVF's VirtioFS
    /// requires a non-empty mount-tag string (the guest mounts via
    /// `mount -t virtiofs <tag> /mountpoint`).
    #[error("workspace mount has empty guest_path (host_path={host_path:?})")]
    EmptyMountTag {
        /// The mount whose `guest_path` was empty.
        host_path: PathBuf,
    },

    /// `VmSpec::vcpu_count` was zero. AVF requires at least 1 vCPU.
    #[error("vcpu_count must be >= 1")]
    ZeroVcpus,

    /// `VmSpec::mem_mib` was below AVF's documented 64 MiB floor.
    #[error("mem_mib={requested} below AVF floor of {floor} MiB")]
    MemoryBelowFloor {
        /// What the spec asked for.
        requested: u32,
        /// AVF's documented minimum.
        floor: u32,
    },

    /// `VmSpec::linux_kernel_path` was empty. AVF's `VZLinuxBootLoader`
    /// requires a host path to the Linux kernel binary; the
    /// SubprocessIsolation-style empty-path sentinel is not legal
    /// for this substrate.
    #[error(
        "VmSpec.linux_kernel_path is empty; the kernel image resolver \
         must populate it before reaching this substrate (see \
         `kernel/src/canonical_images_preflight::linux_kernel_path`)"
    )]
    KernelPathMissing,

    /// One of the `entrypoint_argv` tokens contained whitespace.
    /// Linux's cmdline tokeniser splits on whitespace and does not
    /// honour POSIX shell quoting, so a whitespace-bearing token
    /// would silently fragment into multiple init argv entries —
    /// which would deliver an unintended argv to the planner. The
    /// substrate fails closed and instructs the caller to route the
    /// value through env (`spec.env`) instead, which goes via the
    /// `raxis.envb64=` cmdline channel that survives whitespace
    /// intact.
    #[error(
        "entrypoint_argv contains a whitespace-bearing token {arg:?}; \
         AVF cmdline tokeniser cannot pass it intact — route the \
         value through VmSpec.env instead"
    )]
    EntrypointArgvWhitespace {
        /// The offending argv token.
        arg: String,
    },
}

/// AVF's documented minimum memory size for a Linux guest. Below this
/// the framework refuses to start the VM.
pub const AVF_MIN_MEMORY_MIB: u32 = 64;

/// AF_VSOCK port the substrate pins for the kernel ↔ planner control
/// channel. Mirrored into the guest as
/// `RAXIS_KERNEL_VSOCK_LISTEN_PORT` so
/// `KernelTransportConfig::from_env_fn` resolves the planner into
/// `VsockListen { port = AVF_PLANNER_PORT }`. Pinned by
/// `extensibility-traits.md §3.4` (planner-port wire constant).
pub const AVF_PLANNER_PORT: u32 = 1024;

// ---------------------------------------------------------------------------
// Translated typed shapes
// ---------------------------------------------------------------------------

/// Linux boot loader configuration for AVF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfLinuxBootLoader {
    /// Host path of the Linux kernel image.
    pub kernel_url: PathBuf,
    /// Optional initrd path.
    pub initrd_url: Option<PathBuf>,
    /// Kernel command-line. RAXIS pins
    /// `console=hvc0 reboot=k panic=1` by default; operator can
    /// override via `VmSpec::boot_args`.
    pub command_line: String,
}

/// Translated rootfs / data drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfBlockDevice {
    /// Stable identifier. AVF doesn't natively use this but we record
    /// it so audit + diagnostic logs can correlate the device.
    pub drive_id: String,
    /// Host path of the disk image.
    pub host_path: PathBuf,
    /// Read-only flag.
    pub read_only: bool,
}

/// Translated VirtioFS share. AVF maps this to
/// `VZVirtioFileSystemDeviceConfiguration` + `VZSingleDirectoryShare`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfVirtioFsShare {
    /// VirtioFS mount tag — the guest mounts this via
    /// `mount -t virtiofs <tag> <guest_path>`.
    pub tag: String,
    /// Host directory shared with the guest.
    pub host_path: PathBuf,
    /// Read-only flag.
    pub read_only: bool,
    /// Mount path the guest is expected to use; recorded for audit
    /// and diagnostics.
    pub guest_path: String,
}

// `AvfNetworkDevice` and `AvfNetworkMode` were removed in the
// Tier1Tproxy deletion sweep. Under the surviving `EgressTier`
// variants (`None`, `Mediated`, `Tier2CredProxy`) no virtio-net
// device is attached by the AVF substrate, so the translated
// `AvfConfig.network` field is now permanently `None`. The
// `VZNATNetworkDeviceAttachment` cargo feature on
// `objc2-virtualization` was dropped at the same time — keeping
// the linker surface tight to the devices the substrate actually
// instantiates.

/// Translated VSock configuration.
///
/// AVF's `VZVirtioSocketDevice` exposes a host file descriptor for
/// each accepted guest connection. This struct carries the contract
/// the host reuses when establishing connections; the actual FD
/// management lives in `runtime::AvfRuntime` (macOS-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfVsock {
    /// Guest CID used by the planner inside the VM.
    pub guest_cid: u32,
    /// Planner port the host connects to inside the guest.
    pub planner_port: u32,
}

/// Result of translating a `VmSpec` for AVF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfConfig {
    /// vCPU count (validated >= 1).
    pub vcpu_count: u32,
    /// Memory size in MiB (validated >= `AVF_MIN_MEMORY_MIB`).
    pub mem_mib: u32,
    /// Linux boot loader.
    pub boot_loader: AvfLinuxBootLoader,
    /// Block devices (rootfs + optional data drives).
    pub block_devices: Vec<AvfBlockDevice>,
    /// VirtioFS shares.
    pub fs_shares: Vec<AvfVirtioFsShare>,
    /// VSock configuration.
    pub vsock: AvfVsock,
    /// Optional host file path for guest serial console capture.
    /// When `Some`, the runtime attaches a
    /// `VZVirtioConsoleDeviceSerialPortConfiguration` whose
    /// `fileHandleForWriting` opens the path `O_WRONLY | O_CREAT |
    /// O_APPEND` (mode 0600). Forwarded verbatim from
    /// [`raxis_isolation::VmSpec::guest_console_log`].
    pub console_log: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Translate a `VerifiedImage` + `WorkspaceMount`s + `VmSpec` into an
/// [`AvfConfig`].
///
/// Pure function — no I/O, no Objective-C calls, no platform gating.
/// Any failure is a typed [`ConfigError`].
pub fn translate(
    image: &VerifiedImage,
    mounts: &[WorkspaceMount],
    spec: &VmSpec,
) -> Result<AvfConfig, ConfigError> {
    // ---- 1. Resource envelope sanity ------------------------------------
    if spec.vcpu_count == 0 {
        return Err(ConfigError::ZeroVcpus);
    }
    if spec.mem_mib < AVF_MIN_MEMORY_MIB {
        return Err(ConfigError::MemoryBelowFloor {
            requested: spec.mem_mib,
            floor: AVF_MIN_MEMORY_MIB,
        });
    }

    // ---- 2. Boot loader -------------------------------------------------
    //
    // The boot loader needs the host path of the Linux kernel binary
    // (a `vmlinux` / `Image` blob). That path lives on `VmSpec`,
    // populated by `kernel/src/canonical_images_preflight::linux_kernel_path`
    // — NOT on `VerifiedImage`, which carries the per-role rootfs
    // payload. The two artefacts have separate lifecycles (the kernel
    // binary is a host-wide install, the rootfs is per-role and per-
    // session) and are signed under separate keys; folding them into
    // one structure was the placeholder shape this substrate carried
    // before V2 GA.
    if spec.linux_kernel_path.as_os_str().is_empty() {
        return Err(ConfigError::KernelPathMissing);
    }
    let kernel_url = spec.linux_kernel_path.clone();

    // The rootfs image body — handed to the boot loader as initrd
    // for `RootfsInitramfsCpio`, attached as a virtio-blk drive for
    // `RootfsErofs`. Inline-bytes is unsupported on either path
    // because AVF requires an mmap-able file.
    let rootfs_path = match &image.body {
        ImageBody::Path(p) => p.clone(),
        ImageBody::Bytes(_) => return Err(ConfigError::InlineBytesUnsupported),
    };
    if !image.kind.is_linux_rootfs() {
        return Err(ConfigError::UnsupportedImageKind { kind: image.kind });
    }
    // Base kernel cmdline. `hvc0` is the canonical Virtio console
    // for Linux guests under AVF; we pair it with `earlycon` so the
    // kernel's earliest printk lines (before virtio is enumerated)
    // also reach the host-side console log instead of disappearing
    // into the void. `reboot=k panic=10` gives any panic backtrace
    // ten seconds to flush to the virtio-console FIFO before AVF
    // resets the VM (we used to use `panic=1` but a one-second
    // delay is faster than the printk buffer can drain in some
    // cases, leaving the host with a zero-byte log and no idea
    // why init died). `loglevel=8 ignore_loglevel` raises printk
    // verbosity unconditionally so kernel-side mount / module
    // failures show up in the forensic trail. For initramfs boots
    // we pin `rdinit=/init` so the kernel honours our
    // cpio-archived /init regardless of `CONFIG_DEFAULT_INIT`;
    // EROFS boots get the virtio-blk root pin instead.
    // Operator-supplied [`VmSpec::boot_args`] **replace** these
    // defaults wholesale — the kernel session-spawn path stamps
    // an empty `boot_args` for the canonical roles and the
    // substrate owns the cmdline shape.
    // Note on `earlycon`: AVF does NOT expose a PL011 / 16550-compatible
    // UART, so the canonical `earlycon=pl011,…` recipe from the QEMU
    // ARM virt machine does not apply. The kernel's printk before
    // virtio-console is enumerated is therefore lost; that's an
    // accepted limitation of the AVF substrate. Once `hvc0` is up
    // (after `virtio_pci` enumerates devices) all printk lands in
    // the host-side console log.
    // **Quiet-boot opt-in.** When the host process exports
    // `RAXIS_AVF_QUIET_BOOT=1`, swap the verbose `loglevel=8
    // ignore_loglevel` pair for `quiet loglevel=0`. The Linux
    // kernel emits ~hundreds of printk lines before virtio-console
    // is enumerated; each line is a synchronous write to the host-
    // side hvc0 sink, so muting them shaves ~50–100 ms off the
    // observable boot path on the AVF substrate. Default is
    // **OFF** — operators keeping the verbose default get the
    // same forensic kernel log they had before this knob existed,
    // and any spawn that needs to debug a boot regression can
    // simply unset the env var. We deliberately read the env at
    // translate time rather than plumbing a typed
    // `VmSpec::quiet_boot` field so the operator can flip the
    // behaviour without restamping plans or VM specs that are
    // already in flight (the env var is observed once per spawn,
    // before the VZ configuration is materialised).
    let quiet_boot = std::env::var("RAXIS_AVF_QUIET_BOOT")
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let base_cmdline = if quiet_boot {
        "console=hvc0 quiet loglevel=0 reboot=k panic=10"
    } else {
        "console=hvc0 loglevel=8 ignore_loglevel reboot=k panic=10"
    };
    let mut cmdline = if spec.boot_args.is_empty() {
        match image.kind {
            ImageKind::RootfsInitramfsCpio => format!("{base_cmdline} rdinit=/init"),
            _ => format!("{base_cmdline} root=/dev/vda ro"),
        }
    } else {
        spec.boot_args.join(" ")
    };

    // Fold `VmSpec.env` into the cmdline so the in-guest /init can
    // recover the kernel-stamped session token, planner task prompt,
    // KSB snapshot, etc. without needing a side channel.
    //
    // We compose the payload from three sources, in precedence
    // order (low → high), so that an explicit operator override on
    // `spec.env` always wins over the substrate-side defaults:
    //
    //   1. **Substrate-default keys** the AVF guest needs in order
    //      to talk to the kernel:
    //
    //      * `RAXIS_SESSION_TOKEN`            — mirrored from
    //        `spec.session_token`. SubprocessIsolation auto-injects
    //        this via `Command::env` (see
    //        `test-support/subprocess_isolation.rs`); AVF must
    //        mirror the contract since there is no `Command::env`
    //        analogue at this surface.
    //      * `RAXIS_KERNEL_VSOCK_LISTEN_PORT` — pinned to the AVF
    //        planner port (`1024`, matching `AvfVsock::planner_port`)
    //        so `KernelTransportConfig::from_env_fn` resolves the
    //        guest into vsock-listen mode.
    //
    //   2. **Per-spawn `spec.env`** — what the kernel session-spawn
    //      path stamped (planner task prompt, KSB snapshot,
    //      credential-proxy loopback URLs, …).
    //
    // **Why cmdline (not virtio-fs side car).** The AVF substrate
    // already provides virtio-fs for workspace mounts, but a
    // dedicated env-propagation share would require another
    // host-tmpdir lifecycle the substrate has to clean up at
    // session teardown — and would force the guest /init to mount
    // the share before parsing env, which means the planner binary
    // (the only thing in the rootfs) would need a `mount` syscall
    // before its tokio runtime spins up. Cmdline keeps the
    // contract single-channel and inert.
    //
    // **Wire shape.** `raxis.envb64=<base64>` where the base64
    // payload decodes to `KEY1=VAL1\nKEY2=VAL2\n…`. Newline
    // separation matches the System V `env(1)` shape and lets
    // values legally carry `=` (the parser only splits on the
    // *first* `=` per line). Base64 is the only encoding that
    // survives Linux's cmdline tokeniser intact for arbitrary
    // bytes including embedded spaces, quotes, and shell
    // metacharacters.
    //
    // **Cmdline length budget.** Linux on aarch64/virt accepts up
    // to 2048 bytes by default (CONFIG_CMDLINE_LENGTH). Base64
    // overhead is 4/3 + delimiter, so the env payload limit is
    // ~1.5 KiB pre-encoding. The kernel-stamped envelope today
    // is well below 1 KiB (session token, task prompt summary,
    // KSB ≤ 4 KiB which we DON'T pass via cmdline — see KSB env
    // var note in `planner-harness.md §14.5`). If a future role
    // exceeds the budget the substrate will refuse the spawn at
    // `validateWithError:` time with a verbatim AVF error.
    {
        use base64::Engine as _;
        let mut effective: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        // (1) substrate-default keys.
        effective.insert(
            "RAXIS_SESSION_TOKEN".to_owned(),
            spec.session_token.0.clone(),
        );
        effective.insert(
            "RAXIS_KERNEL_VSOCK_LISTEN_PORT".to_owned(),
            AVF_PLANNER_PORT.to_string(),
        );
        // (2) per-spawn `spec.env` — overrides defaults.
        //
        // We **strip** `RAXIS_KERNEL_PLANNER_SOCKET` here even when
        // the kernel session-spawn path stamped it. Rationale:
        //
        //   * `KernelTransportConfig::from_env_fn` checks
        //     `RAXIS_KERNEL_PLANNER_SOCKET` BEFORE
        //     `RAXIS_KERNEL_VSOCK_LISTEN_PORT`. If the UDS env var
        //     leaks into the AVF guest, the planner picks UDS mode,
        //     calls `UnixStream::connect` on a host-only path that
        //     does not exist inside the guest filesystem, and fails
        //     with `ENOENT` — surfacing as a vsock CONNECT timeout
        //     on the host side because the planner never bound its
        //     vsock listener.
        //
        //   * The kernel stamps the UDS env unconditionally because
        //     it does not know the substrate at env-build time
        //     (substrate selection is below the kernel-side bridge).
        //     Stripping here is the substrate's responsibility — the
        //     contract is "AVF is the source of truth for which
        //     transport to expose to the guest".
        //
        //   * `RAXIS_KERNEL_VSOCK_CID` / `RAXIS_KERNEL_VSOCK_PORT`
        //     (dial-out vsock variant used by Firecracker) is also
        //     stripped for the same reason — the AVF substrate is
        //     a vsock-listen substrate, not a vsock-dial substrate.
        const STRIPPED: &[&str] = &[
            "RAXIS_KERNEL_PLANNER_SOCKET",
            "RAXIS_KERNEL_VSOCK_CID",
            "RAXIS_KERNEL_VSOCK_PORT",
        ];
        for (k, v) in &spec.env {
            if k.is_empty() {
                continue;
            }
            if STRIPPED.iter().any(|s| *s == k.as_str()) {
                continue;
            }
            effective.insert(k.clone(), v.clone());
        }

        // (3) substrate-injected RAXIS_VIRTIOFS_MOUNTS — the
        // canonical wire shape the in-guest /init parses via
        // `raxis-planner-core::guest_init::parse_virtiofs_mounts`.
        // Composed from `mounts` (the same list we just turned into
        // `AvfVirtioFsShare`s above), so the host AVF descriptor and
        // the guest mount(2) syscall observe the same triple
        // (tag, guest_path, mode).
        //
        // Format: comma-separated `<tag>:<guest_path>:<rw|ro>`.
        // Tag derivation MUST match the
        // `let tag = mount.guest_path.trim_start_matches('/').replace('/', "_")`
        // recipe used in the `AvfVirtioFsShare` translation block
        // below — otherwise the guest's `mount(2)` would refer to
        // a tag the AVF substrate never advertised.
        let valid_mounts: Vec<&WorkspaceMount> =
            mounts.iter().filter(|m| !m.guest_path.is_empty()).collect();
        if !valid_mounts.is_empty() {
            let mut mounts_env = String::new();
            for (i, mount) in valid_mounts.iter().enumerate() {
                if i > 0 {
                    mounts_env.push(',');
                }
                let tag = mount.guest_path.trim_start_matches('/').replace('/', "_");
                mounts_env.push_str(&tag);
                mounts_env.push(':');
                mounts_env.push_str(&mount.guest_path);
                mounts_env.push(':');
                let read_only = matches!(mount.mode, MountMode::ReadOnly);
                mounts_env.push_str(if read_only { "ro" } else { "rw" });
            }
            // The substrate-injected key always wins over a
            // potential operator override on `spec.env` — the
            // operator never has authority to lie to the guest about
            // which shares the substrate actually wired up.
            effective.insert("RAXIS_VIRTIOFS_MOUNTS".to_owned(), mounts_env);
        }

        let mut payload = String::new();
        for (k, v) in &effective {
            payload.push_str(k);
            payload.push('=');
            payload.push_str(v);
            payload.push('\n');
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        cmdline.push_str(" raxis.envb64=");
        cmdline.push_str(&b64);
    }

    // ---- 2.5. Init args (`spec.entrypoint_argv[1..]`) ------------------
    //
    // Linux's `parse_args()` collects unrecognised cmdline tokens into
    // `argv_init[]` (bare tokens) and `envp_init[]` (KEY=VAL tokens),
    // which are then passed to `kernel_execve(init, argv_init,
    // envp_init)`. By appending `-- <argv tail>` after the kernel
    // params we reach the planner binary with `argv = [/init, …]` —
    // the same shape `SubprocessIsolation` produces via
    // `Command::args(&spec.entrypoint_argv)`.
    //
    // We strip `entrypoint_argv[0]` because under initramfs the
    // kernel set argv[0] from `rdinit=` (the in-guest path), not
    // from the host-side path the kernel-side spawn helper recorded.
    // The dropped element is informational only — it is the planner's
    // host-side install path which is meaningless inside the guest.
    //
    // **Quoting.** Linux's cmdline tokeniser splits on whitespace and
    // does not honour POSIX shell quoting. Tokens with spaces would
    // be split into separate argv entries. The orchestrator /
    // executor / reviewer flags (`--initiative-id <UUID>`,
    // `--task-id <UUID>`) only carry hex+`-` characters and are safe;
    // a future role that needs whitespace-bearing args MUST go via
    // env (the `raxis.envb64=` channel above) rather than argv.
    if spec.entrypoint_argv.len() > 1 {
        cmdline.push_str(" --");
        for arg in spec.entrypoint_argv.iter().skip(1) {
            if arg.is_empty() {
                continue;
            }
            // Reject tokens that would break the cmdline tokeniser.
            // Caller bug — better to fail closed than to silently
            // mutate the planner argv.
            if arg.chars().any(|c| c.is_whitespace()) {
                return Err(ConfigError::EntrypointArgvWhitespace { arg: arg.clone() });
            }
            cmdline.push(' ');
            cmdline.push_str(arg);
        }
    }
    let initrd_url = match image.kind {
        ImageKind::RootfsInitramfsCpio => Some(rootfs_path.clone()),
        _ => None,
    };
    let boot_loader = AvfLinuxBootLoader {
        kernel_url,
        initrd_url,
        command_line: cmdline,
    };

    // ---- 3. Block devices ----------------------------------------------
    //
    // For `RootfsErofs` we attach the rootfs as a single read-only
    // virtio-blk drive (the guest kernel mounts it at `/dev/vda`).
    // For `RootfsInitramfsCpio` the rootfs lives in the boot loader's
    // initrd channel, so no block device is required at all — the
    // guest's root filesystem is the unpacked cpio in tmpfs.
    let block_devices = match image.kind {
        ImageKind::RootfsInitramfsCpio => Vec::new(),
        _ => vec![AvfBlockDevice {
            drive_id: "rootfs".to_owned(),
            host_path: rootfs_path,
            read_only: true,
        }],
    };

    // ---- 4. VirtioFS shares --------------------------------------------
    let mut fs_shares = Vec::with_capacity(mounts.len());
    for mount in mounts {
        if mount.guest_path.is_empty() {
            return Err(ConfigError::EmptyMountTag {
                host_path: mount.host_path.clone(),
            });
        }
        // The mount tag is the guest path with the leading slash
        // stripped — AVF disallows `/` in tags. `/workspace` ⇒
        // `workspace`, `/raxis` ⇒ `raxis`. This matches the
        // `mount -t virtiofs <tag> <path>` convention the canonical
        // Reviewer / Orchestrator images expect.
        let tag = mount.guest_path.trim_start_matches('/').replace('/', "_");
        fs_shares.push(AvfVirtioFsShare {
            tag,
            host_path: mount.host_path.clone(),
            read_only: matches!(mount.mode, MountMode::ReadOnly),
            guest_path: mount.guest_path.clone(),
        });
    }

    // ---- 5. Network ----------------------------------------------------
    //
    // After the Tier1Tproxy deletion, no surviving `EgressTier`
    // attaches a virtio-net device under the AVF substrate. The
    // translate step accepts each variant for exhaustiveness and
    // emits no network device:
    //
    // * `EgressTier::None` — Reviewer / Orchestrator (no NIC,
    //   `INV-NETISO-01`).
    // * `EgressTier::Mediated` — Path A3 universal-airgap, the
    //   canonical Executor egress (no NIC,
    //   `INV-NETISO-A3-UNIVERSAL-NO-NIC-01`; all egress flows over
    //   the per-VM vsock device to the kernel admission handler).
    // * `EgressTier::Tier2CredProxy` — V3+ placeholder; the kernel
    //   rejects this tier upstream, but the substrate honours
    //   fail-closed: no network.
    match spec.egress_tier {
        EgressTier::None | EgressTier::Mediated | EgressTier::Tier2CredProxy => {}
    }

    // ---- 6. VSock ------------------------------------------------------
    // We default to CID 3 (per Firecracker convention) and planner
    // port 1024 (per `extensibility-traits.md §3.4`) so the kernel can
    // dispatch the same `KernelPush` byte stream against both
    // substrates without per-platform knobs.
    let vsock = AvfVsock {
        guest_cid: spec.vsock_cid.unwrap_or(3),
        planner_port: AVF_PLANNER_PORT,
    };

    Ok(AvfConfig {
        vcpu_count: spec.vcpu_count,
        mem_mib: spec.mem_mib,
        boot_loader,
        block_devices,
        fs_shares,
        vsock,
        console_log: spec.guest_console_log.clone(),
    })
}

// ---------------------------------------------------------------------------
// Tests — pure-data; run on every platform.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_isolation::{
        ContentHash, EgressTier, ImageBody, ImageKind, ImageSignature, MountMode, SessionToken,
        VerifiedImage, VmSpec, WorkspaceMount,
    };

    fn fixture_image() -> VerifiedImage {
        // After the V2 substrate fix, `body` carries the per-role
        // ROOTFS path (EROFS .img or initramfs cpio.gz). The kernel
        // binary path lives on `VmSpec.linux_kernel_path`.
        VerifiedImage {
            kind: ImageKind::RootfsErofs,
            body: ImageBody::Path(PathBuf::from("/var/raxis/test/rootfs.img")),
            signature: ImageSignature(vec![0u8; 64]),
            image_id: "raxis-test-avf-1".to_owned(),
        }
    }

    fn fixture_spec() -> VmSpec {
        VmSpec {
            vcpu_count: 1,
            mem_mib: 128,
            egress_tier: EgressTier::None,
            cgroup_quota: None,
            boot_args: Vec::new(),
            entrypoint_argv: Vec::new(),
            session_token: SessionToken("avf-test-token".to_owned()),
            vsock_cid: Some(7),
            virtio_fs_mounts: Vec::new(),
            linux_kernel_path: PathBuf::from("/var/raxis/test/vmlinux.bin"),
            env: Default::default(),
            guest_console_log: None,
        }
    }

    fn fixture_mount(guest: &str, mode: MountMode) -> WorkspaceMount {
        WorkspaceMount {
            host_path: PathBuf::from(format!("/tmp/raxis-{}", guest.trim_start_matches('/'))),
            guest_path: guest.to_owned(),
            mode,
            content_hash: Some(ContentHash([0u8; 32])),
        }
    }

    // ---- happy path ----------------------------------------------------

    // ---- INV-NETISO-A3-UNIVERSAL-NO-NIC-01 witness --------------------
    //
    // After the Tier1Tproxy deletion the "no NIC for any egress tier"
    // contract is **structural**: `AvfConfig` carries no network field
    // and `translate()` has no code path that constructs one. The
    // legacy parametric witnesses (one per `EgressTier` variant) have
    // been collapsed into the smoke test below — a single call to
    // `translate()` per surviving variant confirms the function
    // accepts the tier without surfacing a `ConfigError` and the
    // structural absence of `AvfConfig.network` is enforced by the
    // compiler.

    #[test]
    fn translate_accepts_every_egress_tier_without_attaching_a_nic() {
        for tier in [
            EgressTier::None,
            EgressTier::Mediated,
            EgressTier::Tier2CredProxy,
        ] {
            let mut spec = fixture_spec();
            spec.egress_tier = tier;
            translate(&fixture_image(), &[], &spec)
                .unwrap_or_else(|e| panic!("translate must succeed for {tier:?}: {e:?}"));
        }
    }

    // -------------------------------------------------------------------

    #[test]
    fn translate_produces_canonical_default_shape() {
        let cfg = translate(&fixture_image(), &[], &fixture_spec()).unwrap();
        assert_eq!(cfg.vcpu_count, 1);
        assert_eq!(cfg.mem_mib, 128);
        // Kernel binary now comes from `VmSpec.linux_kernel_path`.
        assert_eq!(
            cfg.boot_loader.kernel_url,
            PathBuf::from("/var/raxis/test/vmlinux.bin")
        );
        // EROFS rootfs adds `root=/dev/vda ro` so the guest kernel
        // mounts the virtio-blk drive as `/`. Substrate-default env
        // keys (`RAXIS_SESSION_TOKEN`, `RAXIS_KERNEL_VSOCK_LISTEN_PORT`)
        // are folded into a `raxis.envb64=…` cmdline token even when
        // `spec.env` is empty — see
        // `translate_always_appends_substrate_default_env_keys`.
        assert!(
            cfg.boot_loader.command_line.starts_with(
                "console=hvc0 loglevel=8 ignore_loglevel reboot=k panic=10 \
                 root=/dev/vda ro raxis.envb64=",
            ),
            "unexpected cmdline shape: {:?}",
            cfg.boot_loader.command_line,
        );
        // Default fixture is `RootfsErofs` ⇒ one block device.
        assert_eq!(cfg.block_devices.len(), 1);
        assert_eq!(cfg.block_devices[0].drive_id, "rootfs");
        assert!(cfg.block_devices[0].read_only);
        // Image body now is the rootfs path, not the kernel binary.
        assert_eq!(
            cfg.block_devices[0].host_path,
            PathBuf::from("/var/raxis/test/rootfs.img"),
        );
        // Initrd channel empty for the EROFS path.
        assert!(cfg.boot_loader.initrd_url.is_none());
        assert!(cfg.fs_shares.is_empty());
        assert_eq!(cfg.vsock.guest_cid, 7);
        assert_eq!(cfg.vsock.planner_port, AVF_PLANNER_PORT);
    }

    #[test]
    fn translate_initramfs_kind_routes_to_initrd_url_and_drops_block_device() {
        let mut img = fixture_image();
        img.kind = ImageKind::RootfsInitramfsCpio;
        let cfg = translate(&img, &[], &fixture_spec()).unwrap();
        assert_eq!(
            cfg.boot_loader.initrd_url,
            Some(PathBuf::from("/var/raxis/test/rootfs.img")),
        );
        assert!(
            cfg.block_devices.is_empty(),
            "initramfs boots use the kernel's initrd channel, not virtio-blk",
        );
        assert!(
            cfg.boot_loader.command_line.starts_with(
                "console=hvc0 loglevel=8 ignore_loglevel reboot=k panic=10 \
                 rdinit=/init raxis.envb64=",
            ),
            "unexpected initramfs cmdline shape: {:?}",
            cfg.boot_loader.command_line,
        );
    }

    #[test]
    fn translate_rejects_empty_kernel_path() {
        let mut spec = fixture_spec();
        spec.linux_kernel_path = PathBuf::new();
        let err = translate(&fixture_image(), &[], &spec).unwrap_err();
        assert_eq!(err, ConfigError::KernelPathMissing);
    }

    #[test]
    fn translate_uses_default_cid_when_spec_does_not_set_one() {
        let mut spec = fixture_spec();
        spec.vsock_cid = None;
        let cfg = translate(&fixture_image(), &[], &spec).unwrap();
        assert_eq!(cfg.vsock.guest_cid, 3);
    }

    #[test]
    fn translate_overrides_cmdline_when_boot_args_provided() {
        let mut spec = fixture_spec();
        spec.boot_args = vec!["quiet".to_owned(), "loglevel=3".to_owned()];
        let cfg = translate(&fixture_image(), &[], &spec).unwrap();
        // Operator boot args replace the substrate's defaults but
        // the substrate-default env keys are still appended after.
        assert!(
            cfg.boot_loader
                .command_line
                .starts_with("quiet loglevel=3 raxis.envb64="),
            "operator boot args must lead the cmdline; got {:?}",
            cfg.boot_loader.command_line,
        );
    }

    /// Pin the env → cmdline envelope: every entry in `spec.env`
    /// MUST round-trip through `raxis.envb64=` as a base64-encoded
    /// `KEY=VAL\n…` payload. Decoder lives in
    /// `planner-orchestrator` `parse_envb64_cmdline`.
    #[test]
    fn translate_appends_envb64_token_when_spec_env_is_populated() {
        use base64::Engine as _;

        let mut spec = fixture_spec();
        spec.env
            .insert("RAXIS_SESSION_TOKEN".to_owned(), "tok-123".to_owned());
        spec.env.insert(
            "RAXIS_KERNEL_VSOCK_LISTEN_PORT".to_owned(),
            "1024".to_owned(),
        );
        // Value with whitespace + `=` MUST survive the round-trip.
        spec.env.insert(
            "RAXIS_PLANNER_TASK_PROMPT".to_owned(),
            "do thing X = Y, please".to_owned(),
        );

        let cfg = translate(&fixture_image(), &[], &spec).unwrap();
        let line = &cfg.boot_loader.command_line;

        // Default base prefix preserved.
        assert!(
            line.starts_with(
                "console=hvc0 loglevel=8 ignore_loglevel reboot=k panic=10 \
                 root=/dev/vda ro",
            ),
            "base cmdline must precede the envb64 token; got {line:?}",
        );

        // Locate and decode the token.
        let token = line
            .split_whitespace()
            .find(|tok| tok.starts_with("raxis.envb64="))
            .expect("envb64 token must be present");
        let b64 = token.strip_prefix("raxis.envb64=").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .expect("envb64 must decode as standard base64");
        let payload = std::str::from_utf8(&decoded).expect("payload must be utf-8");
        assert!(payload.contains("RAXIS_SESSION_TOKEN=tok-123\n"));
        assert!(payload.contains("RAXIS_KERNEL_VSOCK_LISTEN_PORT=1024\n"));
        assert!(payload.contains("RAXIS_PLANNER_TASK_PROMPT=do thing X = Y, please\n"));
    }

    /// Substrate-default env keys (`RAXIS_SESSION_TOKEN`,
    /// `RAXIS_KERNEL_VSOCK_LISTEN_PORT`) MUST always be folded into
    /// the cmdline, even when `spec.env` is empty — they are the
    /// AVF substrate's contract with the in-guest planner. The
    /// session token is mirrored verbatim from
    /// `VmSpec.session_token` (mirroring `SubprocessIsolation`'s
    /// `Command::env`-injection behaviour), and the listen port is
    /// the AVF-pinned `AVF_PLANNER_PORT`.
    #[test]
    fn translate_always_appends_substrate_default_env_keys() {
        use base64::Engine as _;

        // `fixture_spec()` returns an empty `spec.env`. Translation
        // MUST still produce a `raxis.envb64=` token containing the
        // two substrate-default keys.
        let cfg = translate(&fixture_image(), &[], &fixture_spec()).unwrap();
        let token = cfg
            .boot_loader
            .command_line
            .split_whitespace()
            .find(|tok| tok.starts_with("raxis.envb64="))
            .expect("substrate must always stamp the envb64 token");
        let b64 = token.strip_prefix("raxis.envb64=").unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .expect("envb64 must decode as standard base64");
        let payload = std::str::from_utf8(&bytes).unwrap();
        assert!(
            payload.contains("RAXIS_SESSION_TOKEN=avf-test-token\n"),
            "session token must be propagated; got payload {payload:?}",
        );
        assert!(
            payload.contains(&format!(
                "RAXIS_KERNEL_VSOCK_LISTEN_PORT={AVF_PLANNER_PORT}\n",
            )),
            "vsock listen port must be propagated; got payload {payload:?}",
        );
    }

    /// Per-spawn `spec.env` overrides the substrate-default keys.
    /// This is the operator-escape-hatch contract — a deployment
    /// may pin a different planner port (e.g. to multiplex two
    /// guests on the same CID range) by setting it explicitly in
    /// `spec.env`. The substrate must NOT overwrite the operator's
    /// value with its default.
    #[test]
    fn translate_lets_spec_env_override_substrate_defaults() {
        use base64::Engine as _;

        let mut spec = fixture_spec();
        spec.env.insert(
            "RAXIS_SESSION_TOKEN".to_owned(),
            "operator-supplied-token".to_owned(),
        );
        spec.env.insert(
            "RAXIS_KERNEL_VSOCK_LISTEN_PORT".to_owned(),
            "9999".to_owned(),
        );
        let cfg = translate(&fixture_image(), &[], &spec).unwrap();
        let token = cfg
            .boot_loader
            .command_line
            .split_whitespace()
            .find(|tok| tok.starts_with("raxis.envb64="))
            .unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(token.strip_prefix("raxis.envb64=").unwrap().as_bytes())
            .unwrap();
        let payload = std::str::from_utf8(&bytes).unwrap();
        assert!(
            payload.contains("RAXIS_SESSION_TOKEN=operator-supplied-token\n"),
            "spec.env override must win for session token; got {payload:?}",
        );
        assert!(
            payload.contains("RAXIS_KERNEL_VSOCK_LISTEN_PORT=9999\n"),
            "spec.env override must win for vsock port; got {payload:?}",
        );
        // The substrate default for the listen port MUST NOT also be
        // present — uniqueness in the BTreeMap means the override
        // shadows it cleanly.
        assert!(
            !payload.contains(&format!(
                "RAXIS_KERNEL_VSOCK_LISTEN_PORT={AVF_PLANNER_PORT}\n",
            )),
            "substrate default must not coexist with operator override; got {payload:?}",
        );
    }

    /// `RAXIS_KERNEL_PLANNER_SOCKET` and `RAXIS_KERNEL_VSOCK_*`
    /// (dial-out flavour) MUST NOT be propagated into the guest
    /// envelope. The kernel-side session-spawn path stamps them
    /// because it is substrate-agnostic; the AVF substrate is the
    /// authority on which transport the planner sees, and AVF
    /// guests must use the listen-vsock path keyed off the
    /// substrate-default `RAXIS_KERNEL_VSOCK_LISTEN_PORT`. If the
    /// UDS path leaks, the planner's
    /// `KernelTransportConfig::from_env_fn` selects UDS first and
    /// fails with `ENOENT` inside the guest, surfacing as a vsock
    /// CONNECT timeout on the host because the planner never
    /// binds its listener.
    #[test]
    fn translate_strips_uds_and_dial_vsock_env_keys() {
        use base64::Engine as _;

        let mut spec = fixture_spec();
        spec.env.insert(
            "RAXIS_KERNEL_PLANNER_SOCKET".to_owned(),
            "/var/lib/raxis/data/planners/abc.sock".to_owned(),
        );
        spec.env
            .insert("RAXIS_KERNEL_VSOCK_CID".to_owned(), "2".to_owned());
        spec.env
            .insert("RAXIS_KERNEL_VSOCK_PORT".to_owned(), "1234".to_owned());
        spec.env.insert(
            "RAXIS_PLANNER_TASK_PROMPT".to_owned(),
            "ship the demo".to_owned(),
        );

        let cfg = translate(&fixture_image(), &[], &spec).unwrap();
        let token = cfg
            .boot_loader
            .command_line
            .split_whitespace()
            .find(|tok| tok.starts_with("raxis.envb64="))
            .expect("substrate must always stamp the envb64 token");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(token.strip_prefix("raxis.envb64=").unwrap().as_bytes())
            .unwrap();
        let payload = std::str::from_utf8(&bytes).unwrap();

        assert!(
            !payload.contains("RAXIS_KERNEL_PLANNER_SOCKET="),
            "AVF substrate must strip the host UDS path; got {payload:?}",
        );
        assert!(
            !payload.contains("RAXIS_KERNEL_VSOCK_CID="),
            "AVF substrate must strip dial-out vsock CID; got {payload:?}",
        );
        assert!(
            !payload.contains("RAXIS_KERNEL_VSOCK_PORT="),
            "AVF substrate must strip dial-out vsock PORT; got {payload:?}",
        );
        assert!(
            payload.contains("RAXIS_PLANNER_TASK_PROMPT=ship the demo\n"),
            "non-stripped operator env must round-trip; got {payload:?}",
        );
        assert!(
            payload.contains(&format!(
                "RAXIS_KERNEL_VSOCK_LISTEN_PORT={AVF_PLANNER_PORT}\n",
            )),
            "substrate-default listen port must remain after the strip; got {payload:?}",
        );
    }

    // ---- VirtioFS share translation -----------------------------------

    #[test]
    fn translate_strips_leading_slash_from_mount_tag() {
        let mounts = vec![fixture_mount("/workspace", MountMode::ReadOnly)];
        let cfg = translate(&fixture_image(), &mounts, &fixture_spec()).unwrap();
        assert_eq!(cfg.fs_shares.len(), 1);
        assert_eq!(cfg.fs_shares[0].tag, "workspace");
        assert_eq!(cfg.fs_shares[0].guest_path, "/workspace");
        assert!(cfg.fs_shares[0].read_only);
    }

    #[test]
    fn translate_replaces_inner_slashes_with_underscores() {
        let mounts = vec![fixture_mount("/raxis/bundles", MountMode::ReadWrite)];
        let cfg = translate(&fixture_image(), &mounts, &fixture_spec()).unwrap();
        assert_eq!(cfg.fs_shares[0].tag, "raxis_bundles");
        assert!(!cfg.fs_shares[0].read_only);
    }

    #[test]
    fn translate_rejects_empty_guest_path() {
        let mounts = vec![fixture_mount("", MountMode::ReadOnly)];
        let err = translate(&fixture_image(), &mounts, &fixture_spec()).unwrap_err();
        assert_eq!(
            err,
            ConfigError::EmptyMountTag {
                host_path: PathBuf::from("/tmp/raxis-")
            }
        );
    }

    // ---- Network -------------------------------------------------------
    //
    // After the Tier1Tproxy deletion, the AVF substrate provisions
    // no virtio-net device for any surviving `EgressTier`. The
    // structural absence of `AvfConfig.network` enforces this at
    // compile time; the parametric tier-by-tier witnesses that this
    // section previously held collapsed into
    // `translate_accepts_every_egress_tier_without_attaching_a_nic`
    // above.

    // ---- Resource envelope guards --------------------------------------

    #[test]
    fn translate_rejects_zero_vcpus() {
        let mut spec = fixture_spec();
        spec.vcpu_count = 0;
        let err = translate(&fixture_image(), &[], &spec).unwrap_err();
        assert_eq!(err, ConfigError::ZeroVcpus);
    }

    #[test]
    fn translate_rejects_memory_below_avf_floor() {
        let mut spec = fixture_spec();
        spec.mem_mib = AVF_MIN_MEMORY_MIB - 1;
        let err = translate(&fixture_image(), &[], &spec).unwrap_err();
        assert_eq!(
            err,
            ConfigError::MemoryBelowFloor {
                requested: AVF_MIN_MEMORY_MIB - 1,
                floor: AVF_MIN_MEMORY_MIB,
            }
        );
    }

    // ---- Image guards --------------------------------------------------

    #[test]
    fn translate_rejects_inline_bytes_image() {
        let img = VerifiedImage {
            kind: ImageKind::RootfsErofs,
            body: ImageBody::Bytes(vec![0u8; 4]),
            signature: ImageSignature(vec![0u8; 64]),
            image_id: "inline".to_owned(),
        };
        let err = translate(&img, &[], &fixture_spec()).unwrap_err();
        assert_eq!(err, ConfigError::InlineBytesUnsupported);
    }

    #[test]
    fn translate_rejects_non_linux_image_kinds() {
        let img = VerifiedImage {
            kind: ImageKind::WasmModule,
            body: ImageBody::Path(PathBuf::from("/tmp/wasm")),
            signature: ImageSignature(vec![0u8; 64]),
            image_id: "wasm".to_owned(),
        };
        let err = translate(&img, &[], &fixture_spec()).unwrap_err();
        assert_eq!(
            err,
            ConfigError::UnsupportedImageKind {
                kind: ImageKind::WasmModule,
            }
        );

        let img2 = VerifiedImage {
            kind: ImageKind::EnclaveSigStruct,
            body: ImageBody::Path(PathBuf::from("/tmp/sgx")),
            signature: ImageSignature(vec![0u8; 64]),
            image_id: "sgx".to_owned(),
        };
        let err2 = translate(&img2, &[], &fixture_spec()).unwrap_err();
        assert_eq!(
            err2,
            ConfigError::UnsupportedImageKind {
                kind: ImageKind::EnclaveSigStruct,
            }
        );
    }
}
