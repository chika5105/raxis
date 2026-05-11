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
        floor:     u32,
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
}

/// AVF's documented minimum memory size for a Linux guest. Below this
/// the framework refuses to start the VM.
pub const AVF_MIN_MEMORY_MIB: u32 = 64;

// ---------------------------------------------------------------------------
// Translated typed shapes
// ---------------------------------------------------------------------------

/// Linux boot loader configuration for AVF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfLinuxBootLoader {
    /// Host path of the Linux kernel image.
    pub kernel_url:    PathBuf,
    /// Optional initrd path.
    pub initrd_url:    Option<PathBuf>,
    /// Kernel command-line. RAXIS pins
    /// `console=hvc0 reboot=k panic=1` by default; operator can
    /// override via `VmSpec::boot_args`.
    pub command_line:  String,
}

/// Translated rootfs / data drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfBlockDevice {
    /// Stable identifier. AVF doesn't natively use this but we record
    /// it so audit + diagnostic logs can correlate the device.
    pub drive_id:    String,
    /// Host path of the disk image.
    pub host_path:   PathBuf,
    /// Read-only flag.
    pub read_only:   bool,
}

/// Translated VirtioFS share. AVF maps this to
/// `VZVirtioFileSystemDeviceConfiguration` + `VZSingleDirectoryShare`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfVirtioFsShare {
    /// VirtioFS mount tag — the guest mounts this via
    /// `mount -t virtiofs <tag> <guest_path>`.
    pub tag:         String,
    /// Host directory shared with the guest.
    pub host_path:   PathBuf,
    /// Read-only flag.
    pub read_only:   bool,
    /// Mount path the guest is expected to use; recorded for audit
    /// and diagnostics.
    pub guest_path:  String,
}

/// Translated network device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfNetworkDevice {
    /// We use NAT mode for `Tier1Tproxy`. The kernel layers tproxy
    /// rules on top of the host's NAT bridge.
    pub mode:        AvfNetworkMode,
}

/// Network attachment mode. V2 ships only NAT for `Tier1Tproxy`;
/// `None` returns no network device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvfNetworkMode {
    /// `VZNATNetworkDeviceAttachment` — NAT-via-host bridging.
    Nat,
}

/// Translated VSock configuration.
///
/// AVF's `VZVirtioSocketDevice` exposes a host file descriptor for
/// each accepted guest connection. This struct carries the contract
/// the host reuses when establishing connections; the actual FD
/// management lives in `runtime::AvfRuntime` (macOS-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfVsock {
    /// Guest CID used by the planner inside the VM.
    pub guest_cid:    u32,
    /// Planner port the host connects to inside the guest.
    pub planner_port: u32,
}

/// Result of translating a `VmSpec` for AVF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfConfig {
    /// vCPU count (validated >= 1).
    pub vcpu_count:    u32,
    /// Memory size in MiB (validated >= `AVF_MIN_MEMORY_MIB`).
    pub mem_mib:       u32,
    /// Linux boot loader.
    pub boot_loader:   AvfLinuxBootLoader,
    /// Block devices (rootfs + optional data drives).
    pub block_devices: Vec<AvfBlockDevice>,
    /// VirtioFS shares.
    pub fs_shares:     Vec<AvfVirtioFsShare>,
    /// Optional network device.
    pub network:       Option<AvfNetworkDevice>,
    /// VSock configuration.
    pub vsock:         AvfVsock,
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
    image:    &VerifiedImage,
    mounts:   &[WorkspaceMount],
    spec:     &VmSpec,
) -> Result<AvfConfig, ConfigError> {
    // ---- 1. Resource envelope sanity ------------------------------------
    if spec.vcpu_count == 0 {
        return Err(ConfigError::ZeroVcpus);
    }
    if spec.mem_mib < AVF_MIN_MEMORY_MIB {
        return Err(ConfigError::MemoryBelowFloor {
            requested: spec.mem_mib,
            floor:     AVF_MIN_MEMORY_MIB,
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
    let cmdline = if spec.boot_args.is_empty() {
        // AVF's Linux boot loader uses a Virtio console; `hvc0` is
        // the canonical first hypervisor console. `reboot=k`
        // ensures a guest panic surfaces as a clean exit. For
        // initramfs boots we additionally pin `rdinit=/init` so the
        // guest kernel honours the cpio-archived /init regardless
        // of the kernel's CONFIG_DEFAULT_INIT default.
        match image.kind {
            ImageKind::RootfsInitramfsCpio =>
                "console=hvc0 reboot=k panic=1 rdinit=/init".to_owned(),
            _ =>
                "console=hvc0 reboot=k panic=1 root=/dev/vda ro".to_owned(),
        }
    } else {
        spec.boot_args.join(" ")
    };
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
            drive_id:  "rootfs".to_owned(),
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
        let tag = mount
            .guest_path
            .trim_start_matches('/')
            .replace('/', "_");
        fs_shares.push(AvfVirtioFsShare {
            tag,
            host_path:  mount.host_path.clone(),
            read_only:  matches!(mount.mode, MountMode::ReadOnly),
            guest_path: mount.guest_path.clone(),
        });
    }

    // ---- 5. Network ----------------------------------------------------
    let network = match spec.egress_tier {
        EgressTier::None => None,
        EgressTier::Tier1Tproxy => Some(AvfNetworkDevice {
            mode: AvfNetworkMode::Nat,
        }),
        EgressTier::Tier2CredProxy => {
            // V3+ placeholder per `extensibility-traits.md §3.4` — V2
            // never reaches here (kernel rejects the tier upstream),
            // but the substrate honours fail-closed: no network.
            None
        }
    };

    // ---- 6. VSock ------------------------------------------------------
    // We default to CID 3 (per Firecracker convention) and planner
    // port 1024 (per `extensibility-traits.md §3.4`) so the kernel can
    // dispatch the same `KernelPush` byte stream against both
    // substrates without per-platform knobs.
    let vsock = AvfVsock {
        guest_cid:    spec.vsock_cid.unwrap_or(3),
        planner_port: 1024,
    };

    Ok(AvfConfig {
        vcpu_count: spec.vcpu_count,
        mem_mib:    spec.mem_mib,
        boot_loader,
        block_devices,
        fs_shares,
        network,
        vsock,
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
            kind:      ImageKind::RootfsErofs,
            body:      ImageBody::Path(PathBuf::from("/var/raxis/test/rootfs.img")),
            signature: ImageSignature(vec![0u8; 64]),
            image_id:  "raxis-test-avf-1".to_owned(),
        }
    }

    fn fixture_spec() -> VmSpec {
        VmSpec {
            vcpu_count:        1,
            mem_mib:           128,
            egress_tier:       EgressTier::None,
            cgroup_quota:     None,
            boot_args:         Vec::new(),
            entrypoint_argv:   Vec::new(),
            session_token:     SessionToken("avf-test-token".to_owned()),
            vsock_cid:         Some(7),
            virtio_fs_mounts:  Vec::new(),
            linux_kernel_path: PathBuf::from("/var/raxis/test/vmlinux.bin"),
            env:               Default::default(),
        }
    }

    fn fixture_mount(guest: &str, mode: MountMode) -> WorkspaceMount {
        WorkspaceMount {
            host_path:    PathBuf::from(format!("/tmp/raxis-{}", guest.trim_start_matches('/'))),
            guest_path:   guest.to_owned(),
            mode,
            content_hash: Some(ContentHash([0u8; 32])),
        }
    }

    // ---- happy path ----------------------------------------------------

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
        // mounts the virtio-blk drive as `/`. Initramfs boots
        // (`RootfsInitramfsCpio`) instead get `rdinit=/init` —
        // covered by `translate_initramfs_kind_routes_to_initrd_url`.
        assert_eq!(
            cfg.boot_loader.command_line,
            "console=hvc0 reboot=k panic=1 root=/dev/vda ro"
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
        assert!(cfg.network.is_none());
        assert_eq!(cfg.vsock.guest_cid, 7);
        assert_eq!(cfg.vsock.planner_port, 1024);
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
        assert_eq!(
            cfg.boot_loader.command_line,
            "console=hvc0 reboot=k panic=1 rdinit=/init",
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
        assert_eq!(cfg.boot_loader.command_line, "quiet loglevel=3");
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

    #[test]
    fn translate_omits_network_when_egress_tier_is_none() {
        let cfg = translate(&fixture_image(), &[], &fixture_spec()).unwrap();
        assert!(cfg.network.is_none());
    }

    #[test]
    fn translate_attaches_nat_device_for_tier1_tproxy() {
        let mut spec = fixture_spec();
        spec.egress_tier = EgressTier::Tier1Tproxy;
        let cfg = translate(&fixture_image(), &[], &spec).unwrap();
        assert_eq!(cfg.network, Some(AvfNetworkDevice { mode: AvfNetworkMode::Nat }));
    }

    #[test]
    fn translate_skips_network_for_tier2_cred_proxy_until_v3() {
        let mut spec = fixture_spec();
        spec.egress_tier = EgressTier::Tier2CredProxy;
        let cfg = translate(&fixture_image(), &[], &spec).unwrap();
        // Tier-2 ships in V3; the substrate fails closed (no
        // network) until then.
        assert!(cfg.network.is_none());
    }

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
                floor:     AVF_MIN_MEMORY_MIB,
            }
        );
    }

    // ---- Image guards --------------------------------------------------

    #[test]
    fn translate_rejects_inline_bytes_image() {
        let img = VerifiedImage {
            kind:      ImageKind::RootfsErofs,
            body:      ImageBody::Bytes(vec![0u8; 4]),
            signature: ImageSignature(vec![0u8; 64]),
            image_id:  "inline".to_owned(),
        };
        let err = translate(&img, &[], &fixture_spec()).unwrap_err();
        assert_eq!(err, ConfigError::InlineBytesUnsupported);
    }

    #[test]
    fn translate_rejects_non_linux_image_kinds() {
        let img = VerifiedImage {
            kind:      ImageKind::WasmModule,
            body:      ImageBody::Path(PathBuf::from("/tmp/wasm")),
            signature: ImageSignature(vec![0u8; 64]),
            image_id:  "wasm".to_owned(),
        };
        let err = translate(&img, &[], &fixture_spec()).unwrap_err();
        assert_eq!(
            err,
            ConfigError::UnsupportedImageKind {
                kind: ImageKind::WasmModule,
            }
        );

        let img2 = VerifiedImage {
            kind:      ImageKind::EnclaveSigStruct,
            body:      ImageBody::Path(PathBuf::from("/tmp/sgx")),
            signature: ImageSignature(vec![0u8; 64]),
            image_id:  "sgx".to_owned(),
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
