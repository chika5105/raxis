//! Integration tests for the AVF substrate against the real
//! `Virtualization.framework` binding layer. No mocks.
//!
//! These tests build [`raxis_isolation_apple_vz::config::AvfConfig`]s
//! from real fixtures (a tempdir-backed VirtioFS host directory, a
//! truncated raw disk image satisfying the 512-byte multiple
//! invariant, a placeholder kernel image), then drive
//! [`raxis_isolation_apple_vz::runtime::AvfRuntime`] through the
//! same `start → connect_vsock → stop` lifecycle the kernel uses
//! at spawn time.
//!
//! On macOS hosts AVF will accept the device wiring and return a
//! typed error from one of:
//!   * `validateWithError:` (the kernel image is not a real Linux
//!     binary)
//!   * `startWithCompletionHandler:` (validation passed but boot
//!     fails reading the kernel)
//!   * `connectToPort:` (VM never reached running, fail fast on
//!     missing socket device)
//!
//! The tests assert the failure surfaces as a typed
//! [`raxis_isolation_apple_vz::runtime::RuntimeError`] — never as a
//! panic, never as the V2 stub sentinel. That is the correctness
//! signal: the device-array setters compiled, ran against AVF's
//! Objective-C bridge, and the substrate fails closed exactly where
//! the spec invariants R-6 (fail-closed default) require.
//!
//! On non-macOS hosts every method returns
//! [`raxis_isolation_apple_vz::runtime::RuntimeError::Unsupported`]
//! per the substrate's cross-platform stub.

use std::path::{Path, PathBuf};
use std::time::Duration;

use raxis_isolation::{
    ContentHash, EgressTier, ImageBody, ImageKind, ImageSignature, MountMode, SessionToken,
    VerifiedImage, VmSpec, WorkspaceMount,
};
use raxis_isolation_apple_vz::config::translate;
use raxis_isolation_apple_vz::runtime::{AvfRuntime, RuntimeError};

/// Materialise a 1 KiB truncated raw disk image at `path`. AVF's
/// `VZDiskImageStorageDeviceAttachment` requires the size to be a
/// multiple of 512.
fn make_raw_disk(path: &Path) {
    let f = std::fs::File::create(path).unwrap();
    f.set_len(1024).unwrap();
}

/// Materialise a placeholder kernel image. Real AVF will refuse to
/// boot from this; that's the point — we want to exercise the
/// validation path against real bytes on disk.
fn make_kernel_placeholder(path: &Path) {
    std::fs::write(path, vec![0u8; 4096]).unwrap();
}

/// Build a `VerifiedImage` whose `body` carries the per-role rootfs
/// path. After the V2 substrate split, `body` is the rootfs (EROFS
/// or initramfs cpio.gz) and the kernel binary lives separately on
/// `VmSpec.linux_kernel_path`.
fn fixture_image_at(rootfs_path: PathBuf) -> VerifiedImage {
    VerifiedImage {
        kind: ImageKind::RootfsErofs,
        body: ImageBody::Path(rootfs_path),
        signature: ImageSignature(vec![0u8; 64]),
        image_id: "avf-integ-1".to_owned(),
    }
}

/// Build a `VmSpec` whose `linux_kernel_path` points at a tempdir-
/// backed placeholder kernel binary. AVF will refuse to boot from
/// the placeholder bytes (that's the test's intent — exercise the
/// typed `RuntimeError::InvalidConfig` / `StartFailed` paths
/// against real `Virtualization.framework` validation), but
/// `config::translate` MUST accept the spec so the runtime layer
/// is reached at all.
///
/// The `linux_kernel_path` is supplied by the caller because the
/// substrate validates the path is non-empty BEFORE handing the
/// config to AVF — passing `PathBuf::new()` here would short-
/// circuit the test before any AVF API gets called.
fn fixture_spec(token: &str, egress: EgressTier, linux_kernel_path: PathBuf) -> VmSpec {
    VmSpec {
        vcpu_count: 1,
        mem_mib: 128,
        egress_tier: egress,
        cgroup_quota: None,
        boot_args: Vec::new(),
        entrypoint_argv: Vec::new(),
        session_token: SessionToken(token.to_owned()),
        vsock_cid: Some(11),
        virtio_fs_mounts: Vec::new(),
        linux_kernel_path,
        env: Default::default(),
        guest_console_log: None,
    }
}

fn fixture_mount(host_dir: PathBuf, guest_path: &str, mode: MountMode) -> WorkspaceMount {
    WorkspaceMount {
        host_path: host_dir,
        guest_path: guest_path.to_owned(),
        mode,
        content_hash: Some(ContentHash([0u8; 32])),
    }
}

/// Drive a substrate through `new → start → connect_vsock → stop`
/// with all four device classes wired (storage, virtiofs, network,
/// vsock). Asserts the failure surfaces as a typed
/// `RuntimeError`, never a panic.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "AVF substrate runs only on macOS hosts"
)]
fn avf_runtime_drives_full_device_array_lifecycle_against_real_avf() {
    let tmp = tempfile::tempdir().unwrap();

    // Placeholder kernel binary — `linux_kernel_path` on the spec.
    // AVF will reject the boot because the bytes are not a real
    // Linux kernel; that's the integration assertion (we exercise
    // AVF's `validateWithError:` / `startWithCompletionHandler:`
    // path against real bytes).
    let kernel_path = tmp.path().join("vmlinux.bin");
    make_kernel_placeholder(&kernel_path);

    // Placeholder rootfs disk — `VerifiedImage.body`. AVF requires
    // the file size to be a multiple of 512; `make_raw_disk`
    // truncates to 1 KiB which satisfies that.
    let rootfs_path = tmp.path().join("rootfs.img");
    make_raw_disk(&rootfs_path);

    let host_share_dir = tmp.path().join("workspace");
    std::fs::create_dir_all(&host_share_dir).unwrap();

    let image = fixture_image_at(rootfs_path);
    let mounts = vec![
        fixture_mount(host_share_dir.clone(), "/workspace", MountMode::ReadWrite),
        fixture_mount(host_share_dir, "/raxis", MountMode::ReadOnly),
    ];
    // Executor egress is `EgressTier::Mediated` post-Tier1Tproxy
    // deletion — the substrate emits no virtio-net device for any
    // surviving tier, so this test covers the canonical Mediated
    // Executor boot path on the real AVF integration surface.
    let spec = fixture_spec("avf-integ-token", EgressTier::Mediated, kernel_path);

    let cfg = translate(&image, &mounts, &spec).expect("translate succeeds for real fixture");

    // Sanity: translator wired the device shapes the substrate
    // actually instantiates (rootfs + virtiofs + vsock). There is
    // no virtio-net field to assert on after the Tier1Tproxy
    // deletion — the absence is structural.
    assert_eq!(cfg.block_devices.len(), 1, "rootfs drive present");
    assert_eq!(cfg.fs_shares.len(), 2, "two virtiofs shares");

    #[allow(unused_mut)]
    let mut runtime = AvfRuntime::new(cfg);

    match runtime.start(Duration::from_secs(2)) {
        Ok(()) => panic!("AVF should not boot a placeholder kernel image"),
        Err(RuntimeError::Unsupported) => panic!("test gated behind cfg(macos)"),
        Err(RuntimeError::InvalidConfig(reason)) => {
            // Accepted: AVF rejected the configuration (missing
            // entitlement, bad disk format, kernel not bootable).
            assert!(
                !reason.is_empty(),
                "InvalidConfig must carry a non-empty reason from AVF",
            );
        }
        Err(RuntimeError::StartFailed(reason)) => {
            // Accepted: validation passed, boot failed. The reason
            // string is from AVF's completion handler.
            assert!(
                !reason.is_empty(),
                "StartFailed must carry a non-empty reason from AVF",
            );
        }
        Err(RuntimeError::StartTimeout(_)) => {
            // Accepted: AVF took longer than the test grace.
        }
        Err(other) => panic!("unexpected AVF start outcome: {other:?}"),
    }

    // `stop` must not panic regardless of whether `start` reached
    // an alive VM; this exercises the Drop / teardown path against
    // real AVF objects.
    let exit = runtime.stop(Duration::from_millis(500));
    assert!(
        exit.is_ok(),
        "stop must complete without runtime error: {exit:?}",
    );
}

/// VSock connect against an unstarted runtime fails fast with a
/// typed reason — no panic, no fake fd.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "AVF substrate runs only on macOS hosts"
)]
fn avf_runtime_connect_vsock_without_started_vm_returns_typed_error() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel_path = tmp.path().join("vmlinux.bin");
    make_kernel_placeholder(&kernel_path);
    let rootfs_path = tmp.path().join("rootfs.img");
    make_raw_disk(&rootfs_path);

    let cfg = translate(
        &fixture_image_at(rootfs_path),
        &[],
        &fixture_spec("vsock-pre-start", EgressTier::None, kernel_path),
    )
    .unwrap();
    #[allow(unused_mut)]
    let mut runtime = AvfRuntime::new(cfg);
    match runtime.connect_vsock(1024) {
        Err(RuntimeError::VsockConnect { port, reason }) => {
            assert_eq!(port, 1024);
            assert!(reason.contains("VM not started"));
        }
        other => panic!("expected typed VsockConnect, got {other:?}"),
    }
}

/// After the Tier1Tproxy deletion the AVF substrate provisions no
/// virtio-net device for any surviving `EgressTier` variant. This
/// integration-level test confirms `translate` accepts each
/// variant and the resulting `AvfRuntime` constructs successfully
/// — the structural absence of an `AvfConfig.network` field
/// enforces the no-NIC contract at compile time, so the previous
/// parametric assertions over the field collapsed away. See
/// `INV-NETISO-A3-UNIVERSAL-NO-NIC-01`.
#[test]
fn avf_runtime_translation_round_trips_for_every_egress_tier() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel_path = tmp.path().join("vmlinux.bin");
    make_kernel_placeholder(&kernel_path);
    let rootfs_path = tmp.path().join("rootfs.img");
    make_raw_disk(&rootfs_path);

    for (label, tier) in [
        ("net-none", EgressTier::None),
        ("net-mediated", EgressTier::Mediated),
    ] {
        let cfg = translate(
            &fixture_image_at(rootfs_path.clone()),
            &[],
            &fixture_spec(label, tier, kernel_path.clone()),
        )
        .unwrap_or_else(|e| panic!("translate must succeed for {tier:?}: {e:?}"));
        // Sanity: rootfs + vsock plumbing is present even with
        // no virtio-net device.
        assert_eq!(cfg.block_devices.len(), 1);
        let _runtime = AvfRuntime::new(cfg);
    }
}
