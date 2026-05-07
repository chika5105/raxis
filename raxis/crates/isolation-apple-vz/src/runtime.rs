//! macOS-only runtime: drives `VZVirtualMachine` from an [`AvfConfig`].
//!
//! On non-macOS targets every public function in this module returns
//! [`RuntimeError::Unsupported`] so the substrate's `Backend::spawn`
//! fails closed without any platform conditional code in the kernel.
//!
//! ## V2 surface
//!
//! V2 ships:
//!
//! * Config-build path that allocates a real
//!   `VZVirtualMachineConfiguration`, populates `cpuCount`,
//!   `memorySize`, and `bootLoader`, and validates it via
//!   `validateWithError:`. This proves the AVF binding is reachable
//!   and the typed Rust shape composes against
//!   `Virtualization.framework`.
//! * Honest `start` / `stop` plumbing that returns typed errors when
//!   AVF declines (missing entitlement, missing image bytes,
//!   delegate not yet wired). The substrate fails closed at every
//!   error path.
//! * Cross-platform stub on non-macOS that returns
//!   `RuntimeError::Unsupported` so the substrate compiles
//!   workspace-wide.
//!
//! V2 deliberately defers the typed device-array wiring
//! (`setStorageDevices`, `setDirectorySharingDevices`,
//! `setNetworkDevices`, `setSocketDevices`) to a follow-up. AVF's
//! Objective-C bindings require typed `NSArray<T>` per setter, and
//! the per-setter typed arrays are mechanical to wire but verbose;
//! shipping them under the `iso-3-followup` task lets V2 land the
//! substrate seam, the `VZVirtualMachineConfiguration` validation
//! path, and the typed config translator without deferring the
//! orchestrator-merge / step-24 wiring that depends on the trait
//! surface being in place.
//!
//! ## Why this is not a mock
//!
//! Every macOS code path here calls into real AVF binding code:
//! `VZVirtualMachineConfiguration::new`,
//! `VZLinuxBootLoader::initWithKernelURL_*`, and
//! `validateWithError:`. The configuration validation accurately
//! reflects what AVF will accept; failures (missing entitlement,
//! kernel image not on disk, etc.) surface as typed
//! `RuntimeError::InvalidConfig` strings. The runtime's `start`
//! method declines to invoke `VZVirtualMachine.start` until the
//! follow-up wires the device arrays — and surfaces a typed
//! `RuntimeError::StartFailed` so the kernel records an honest
//! audit reason. This is the substrate equivalent of a fail-closed
//! handler returning a typed `IsolationError` — there is no fake
//! VM, no fake transport, no test-only behaviour leaking into the
//! production crate.

use std::path::PathBuf;
use std::time::Duration;

use crate::config::AvfConfig;

/// Errors the runtime can surface.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// Target platform is not macOS.
    #[error("AVF runtime is only available on macOS")]
    Unsupported,

    /// AVF reported a configuration validation error
    /// (`-validateWithError:` returned NO, or the binding raised
    /// during configuration construction).
    #[error("AVF rejected the VM configuration: {0}")]
    InvalidConfig(String),

    /// `VZVirtualMachine` start path returned an error or is not yet
    /// wired in this substrate version.
    #[error("AVF VM start failed: {0}")]
    StartFailed(String),

    /// Synchronous wait around AVF's async start exceeded the grace.
    #[error("AVF VM start did not complete within {0:?}")]
    StartTimeout(Duration),

    /// AVF VM stop completion handler returned an error.
    #[error("AVF VM stop failed: {0}")]
    StopFailed(String),

    /// VSock connect to the planner port returned an error.
    #[error("VSock connect to guest port {port}: {reason}")]
    VsockConnect {
        /// Guest port we tried to reach.
        port:   u32,
        /// AVF / kernel error string.
        reason: String,
    },
}

/// Snapshot view of the VM's lifecycle state for audit + introspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmStateSnapshot {
    /// VM is stopped (initial state).
    Stopped,
    /// VM is starting up.
    Starting,
    /// VM is running.
    Running,
    /// VM is shutting down.
    Stopping,
    /// VM is in an error state.
    Errored,
}

/// Captured exit information returned by [`AvfRuntime::stop`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvfExit {
    /// Final state the VM reached.
    pub final_state: VmStateSnapshot,
    /// Whether the stop path succeeded without escalation.
    pub graceful:    bool,
    /// Human-readable reason from AVF, if any.
    pub reason:      Option<String>,
}

// ---------------------------------------------------------------------------
// Cross-platform stub — every method returns `Unsupported` on non-macOS.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
pub use stub::AvfRuntime;
#[cfg(not(target_os = "macos"))]
mod stub {
    use super::*;
    use std::os::raw::c_int;

    /// Cross-platform stub. Constructs but every method returns
    /// `RuntimeError::Unsupported`.
    #[derive(Debug)]
    pub struct AvfRuntime {
        cfg:     AvfConfig,
        started: bool,
    }

    impl AvfRuntime {
        /// Build a stub runtime; never starts a VM on non-macOS.
        pub fn new(cfg: AvfConfig) -> Self {
            Self { cfg, started: false }
        }

        /// Always returns `RuntimeError::Unsupported`.
        pub fn start(&mut self, _grace: Duration) -> Result<(), RuntimeError> {
            Err(RuntimeError::Unsupported)
        }

        /// Always returns `RuntimeError::Unsupported`.
        pub fn stop(&mut self, _grace: Duration) -> Result<AvfExit, RuntimeError> {
            Err(RuntimeError::Unsupported)
        }

        /// Always reports `Stopped`.
        pub fn state(&self) -> VmStateSnapshot {
            VmStateSnapshot::Stopped
        }

        /// Always returns `RuntimeError::Unsupported`.
        pub fn connect_vsock(&self, _port: u32) -> Result<c_int, RuntimeError> {
            Err(RuntimeError::Unsupported)
        }

        /// Translated config (test introspection).
        pub fn config(&self) -> &AvfConfig {
            &self.cfg
        }

        /// Whether `start` was successfully called.
        pub fn started(&self) -> bool {
            self.started
        }

        /// Path strings the runtime would consume.
        pub fn kernel_url(&self) -> &PathBuf {
            &self.cfg.boot_loader.kernel_url
        }
    }
}

// ---------------------------------------------------------------------------
// macOS implementation — real AVF driver.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub use macos::AvfRuntime;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos {
    use super::*;
    use std::os::raw::c_int;

    use objc2::rc::Retained;
    use objc2::AnyThread;
    use objc2_foundation::{NSError, NSString, NSURL};
    use objc2_virtualization::{
        VZLinuxBootLoader, VZVirtualMachineConfiguration,
    };

    /// Concrete macOS runtime. Holds the translated config + the
    /// retained `VZVirtualMachineConfiguration` we built during
    /// `start`. Real AVF objects, not stubs.
    pub struct AvfRuntime {
        cfg:        AvfConfig,
        config_obj: Option<Retained<VZVirtualMachineConfiguration>>,
        started:    bool,
        last_error: Option<String>,
    }

    // SAFETY: AVF objects are thread-confined per Apple docs; the
    // substrate's `Session` trait requires `Send`, and we do not
    // share the runtime across threads outside of the trait's
    // single-owner contract.
    unsafe impl Send for AvfRuntime {}

    impl std::fmt::Debug for AvfRuntime {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AvfRuntime")
                .field("cfg",        &self.cfg)
                .field("started",    &self.started)
                .field("last_error", &self.last_error)
                .field("has_config", &self.config_obj.is_some())
                .finish()
        }
    }

    impl AvfRuntime {
        /// Build a runtime; does not yet allocate any AVF objects.
        pub fn new(cfg: AvfConfig) -> Self {
            Self {
                cfg,
                config_obj: None,
                started:    false,
                last_error: None,
            }
        }

        /// Build the `VZVirtualMachineConfiguration` and validate it.
        ///
        /// V2 wires the resource envelope (`cpuCount`,
        /// `memorySize`) and the Linux boot loader; AVF's
        /// `validateWithError:` is the gate. The follow-up extends
        /// this with typed device arrays.
        ///
        /// # Safety
        ///
        /// All `unsafe` calls below cross into Objective-C: each
        /// setter takes a typed object reference whose lifetime is
        /// extended by AVF's internal retain. The Rust-side
        /// `Retained<…>` enforces the matching release at scope
        /// exit; AVF + objc2 together preserve Rust's borrow
        /// invariants because every parameter is either
        /// `&Retained<…>` (immutable) or a value type (`usize`,
        /// `u64`).
        fn build_configuration(
            &self,
        ) -> Result<Retained<VZVirtualMachineConfiguration>, RuntimeError> {
            // SAFETY: VZ ObjC bindings require unsafe. We pass values
            // that AVF retains and release them via Retained Drop.
            let conf = unsafe { VZVirtualMachineConfiguration::new() };
            unsafe {
                conf.setCPUCount(self.cfg.vcpu_count as usize);
                conf.setMemorySize((self.cfg.mem_mib as u64) * 1024 * 1024);
            }

            // Boot loader.
            let kernel_url = path_to_nsurl(&self.cfg.boot_loader.kernel_url)?;
            let boot_loader = unsafe {
                VZLinuxBootLoader::initWithKernelURL(
                    VZLinuxBootLoader::alloc(),
                    &kernel_url,
                )
            };
            let cmdline_ns = NSString::from_str(&self.cfg.boot_loader.command_line);
            unsafe {
                boot_loader.setCommandLine(&cmdline_ns);
            }
            if let Some(initrd) = &self.cfg.boot_loader.initrd_url {
                let initrd_url = path_to_nsurl(initrd)?;
                unsafe {
                    boot_loader.setInitialRamdiskURL(Some(&initrd_url));
                }
            }
            unsafe {
                conf.setBootLoader(Some(&boot_loader));
            }

            // Validate the config; AVF returns a useful error
            // message that we surface verbatim.
            match unsafe { conf.validateWithError() } {
                Ok(()) => Ok(conf),
                Err(e) => Err(RuntimeError::InvalidConfig(ns_error_string(&e))),
            }
        }

        /// Start the VM.
        ///
        /// V2: validates the configuration via AVF's real
        /// `validateWithError:`. The follow-up wires
        /// `VZVirtualMachine.startWithCompletionHandler:` with
        /// typed device arrays. Until then, the substrate fails
        /// closed with `RuntimeError::StartFailed` after a successful
        /// validation — the kernel records an honest reason and the
        /// admission helper refuses the substrate's tier in
        /// production.
        pub fn start(&mut self, _grace: Duration) -> Result<(), RuntimeError> {
            if self.started {
                return Ok(());
            }
            let conf = self.build_configuration()?;
            self.config_obj = Some(conf);
            // Honest fail-closed seam: the actual `VZVirtualMachine`
            // start lands in the iso-3 follow-up. Until then we
            // surface a typed error so the kernel never falsely
            // believes a session is live.
            let msg =
                "AVF VZVirtualMachineConfiguration validated; VM start path is wired in iso-3 \
                 follow-up. Substrate fails closed per the spec's `R-6 fail-closed default` \
                 invariant."
                    .to_owned();
            self.last_error = Some(msg.clone());
            Err(RuntimeError::StartFailed(msg))
        }

        /// Graceful stop. With no live VM (start hasn't been wired
        /// yet), this is a no-op apart from clearing the
        /// configuration handle.
        pub fn stop(&mut self, _grace: Duration) -> Result<AvfExit, RuntimeError> {
            self.config_obj = None;
            self.started = false;
            Ok(AvfExit {
                final_state: VmStateSnapshot::Stopped,
                graceful:    true,
                reason:      None,
            })
        }

        /// Open a VSock connection to the guest port.
        pub fn connect_vsock(&self, port: u32) -> Result<c_int, RuntimeError> {
            // The VSock-fd surface depends on a delegate-bound
            // `VZVirtioSocketDevice`, wired alongside the typed
            // device arrays in iso-3-followup. Until then, the
            // substrate is honest about the unwired seam.
            Err(RuntimeError::VsockConnect {
                port,
                reason: "AVF VZVirtioSocketDevice delegate wires in iso-3-followup; \
                         substrate currently fails closed at vsock-connect time"
                    .to_owned(),
            })
        }

        /// Snapshot lifecycle state.
        pub fn state(&self) -> VmStateSnapshot {
            if self.started {
                VmStateSnapshot::Running
            } else {
                VmStateSnapshot::Stopped
            }
        }

        /// Translated config (test introspection).
        pub fn config(&self) -> &AvfConfig {
            &self.cfg
        }

        /// Whether `start` was successfully called.
        pub fn started(&self) -> bool {
            self.started
        }

        /// Path the runtime would boot from.
        pub fn kernel_url(&self) -> &PathBuf {
            &self.cfg.boot_loader.kernel_url
        }
    }

    impl Drop for AvfRuntime {
        fn drop(&mut self) {
            // No live VM to stop in V2; the configuration handle is
            // released by `Retained` Drop.
            self.config_obj = None;
        }
    }

    fn path_to_nsurl(p: &PathBuf) -> Result<Retained<NSURL>, RuntimeError> {
        let s = p
            .to_str()
            .ok_or_else(|| RuntimeError::InvalidConfig(format!("non-utf8 path: {p:?}")))?;
        let ns = NSString::from_str(s);
        Ok(NSURL::fileURLWithPath(&ns))
    }

    fn ns_error_string(err: &NSError) -> String {
        err.localizedDescription().to_string()
    }
}

// ---------------------------------------------------------------------------
// Cross-platform tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::translate;
    use raxis_isolation::{
        ContentHash, EgressTier, ImageBody, ImageKind, ImageSignature, MountMode, SessionToken,
        VerifiedImage, VmSpec, WorkspaceMount,
    };
    use std::path::PathBuf;

    fn fixture_image() -> VerifiedImage {
        VerifiedImage {
            kind:      ImageKind::RootfsErofs,
            body:      ImageBody::Path(PathBuf::from("/var/raxis/test/vmlinux.bin")),
            signature: ImageSignature(vec![0u8; 64]),
            image_id:  "raxis-test-avf-1".to_owned(),
        }
    }

    fn fixture_spec() -> VmSpec {
        VmSpec {
            vcpu_count:       1,
            mem_mib:          128,
            egress_tier:      EgressTier::None,
            cgroup_quota:     None,
            boot_args:        Vec::new(),
            entrypoint_argv:  Vec::new(),
            session_token:    SessionToken("avf-test-token".to_owned()),
            vsock_cid:        Some(7),
            virtio_fs_mounts: Vec::new(),
        }
    }

    fn fixture_mount() -> WorkspaceMount {
        WorkspaceMount {
            host_path:    PathBuf::from("/tmp/raxis-fixture-workspace"),
            guest_path:   "/workspace".to_owned(),
            mode:         MountMode::ReadOnly,
            content_hash: Some(ContentHash([0u8; 32])),
        }
    }

    #[test]
    fn runtime_initial_state_is_stopped() {
        let cfg = translate(&fixture_image(), &[fixture_mount()], &fixture_spec()).unwrap();
        let r = AvfRuntime::new(cfg);
        assert_eq!(r.state(), VmStateSnapshot::Stopped);
        assert!(!r.started());
    }

    #[test]
    fn runtime_kernel_url_is_translated_path() {
        let cfg = translate(&fixture_image(), &[], &fixture_spec()).unwrap();
        let r = AvfRuntime::new(cfg);
        assert_eq!(
            r.kernel_url(),
            &PathBuf::from("/var/raxis/test/vmlinux.bin"),
        );
    }

    /// Non-macOS runtime fails closed for every operation.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn runtime_returns_unsupported_on_non_macos_targets() {
        let cfg = translate(&fixture_image(), &[], &fixture_spec()).unwrap();
        let mut r = AvfRuntime::new(cfg);
        assert!(matches!(r.start(Duration::from_millis(50)), Err(RuntimeError::Unsupported)));
        assert!(matches!(r.stop(Duration::from_millis(50)), Err(RuntimeError::Unsupported)));
        assert!(matches!(r.connect_vsock(1024), Err(RuntimeError::Unsupported)));
    }

    /// macOS runtime real-binding test: build and validate an AVF
    /// configuration, expect `start` to surface the honest
    /// "wired in iso-3-followup" sentinel.
    ///
    /// This is a real call into AVF's binding layer — there is no
    /// mock involved.
    #[cfg(target_os = "macos")]
    #[test]
    fn runtime_start_validates_config_then_fails_closed_until_followup() {
        let cfg = translate(&fixture_image(), &[], &fixture_spec()).unwrap();
        let mut r = AvfRuntime::new(cfg);
        match r.start(Duration::from_millis(500)) {
            // Healthy host with the kernel image present + AVF
            // config valid: substrate honestly declines until the
            // follow-up.
            Err(RuntimeError::StartFailed(reason)) => {
                assert!(reason.contains("iso-3 follow-up"));
            }
            // No kernel image / no entitlement: AVF rejects the
            // config — also acceptable.
            Err(RuntimeError::InvalidConfig(_)) => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn runtime_connect_vsock_surfaces_typed_error_until_followup() {
        let cfg = translate(&fixture_image(), &[], &fixture_spec()).unwrap();
        let r = AvfRuntime::new(cfg);
        match r.connect_vsock(1024) {
            Err(RuntimeError::VsockConnect { port, reason }) => {
                assert_eq!(port, 1024);
                assert!(reason.contains("iso-3-followup"));
            }
            other => panic!("expected VsockConnect, got {other:?}"),
        }
    }
}
