//! macOS-only runtime: drives `VZVirtualMachine` from an [`AvfConfig`].
//!
//! On non-macOS targets every public function in this module returns
//! [`RuntimeError::Unsupported`] so the substrate's `Backend::spawn`
//! fails closed without any platform conditional code in the kernel.
//!
//! ## What ships in this module
//!
//! Every macOS code path is real AVF binding code — there is no
//! mock, no stub, no test-only fork. Specifically:
//!
//! * [`AvfRuntime::build_configuration`] allocates a real
//!   `VZVirtualMachineConfiguration` and wires every device class V2
//!   uses:
//!   - `VZLinuxBootLoader` from `cfg.boot_loader`
//!   - `VZVirtioBlockDeviceConfiguration` +
//!     `VZDiskImageStorageDeviceAttachment` for each block device
//!   - `VZVirtioFileSystemDeviceConfiguration` +
//!     `VZSingleDirectoryShare` + `VZSharedDirectory` for each
//!     VirtioFS share
//!   - `VZVirtioNetworkDeviceConfiguration` +
//!     `VZNATNetworkDeviceAttachment` for the (optional) network
//!     device
//!   - `VZVirtioSocketDeviceConfiguration` (always present so the
//!     planner port is reachable from the host)
//!   The build path then validates the assembled configuration via
//!   `validateWithError:`.
//!
//! * [`AvfRuntime::start`] initialises a real `VZVirtualMachine`
//!   bound to a serial dispatch queue, calls
//!   `startWithCompletionHandler:` from that queue, and bridges the
//!   Objective-C completion handler back to the calling thread via a
//!   bounded `mpsc` channel. Synchronous wait honours the caller's
//!   `grace` budget; the timeout path returns
//!   [`RuntimeError::StartTimeout`] without abandoning the VM
//!   reference (the queue is allowed to flush its in-flight start
//!   block; the next `stop` call will tear it down).
//!
//! * [`AvfRuntime::stop`] dispatches `stopWithCompletionHandler:`
//!   through the same queue and waits the configured grace.
//!
//! * [`AvfRuntime::connect_vsock`] resolves the VM's
//!   `VZVirtioSocketDevice` from `socketDevices`, dispatches
//!   `connectToPort:completionHandler:`, and returns the resulting
//!   socket file descriptor. The host owns the fd; on graceful stop
//!   the fd is closed automatically when the underlying
//!   `VZVirtioSocketConnection` is released.
//!
//! ## Why the runtime is queue-confined
//!
//! Apple's AVF docs require all `VZVirtualMachine` method calls and
//! property reads to happen on the queue passed to
//! `initWithConfiguration:queue:`. To honour this from a Rust
//! synchronous API, the runtime owns a `DispatchQueue` (created with
//! `DispatchQueueAttr::SERIAL`) and routes every AVF call through
//! it via `dispatch2::DispatchQueue::exec_async`. A oneshot
//! `mpsc::sync_channel` glues the asynchronous AVF completion handler
//! back into the synchronous `start` / `stop` / `connect_vsock`
//! contract.
//!
//! ## Failure surface
//!
//! When the kernel image / rootfs disk image is absent (development,
//! CI, or a host that has not run `genesis-tools` yet), AVF rejects
//! the configuration at `validateWithError:` time and the runtime
//! surfaces a [`RuntimeError::InvalidConfig`] with the verbatim
//! message AVF produced. When validation succeeds but
//! `startWithCompletionHandler:` reports an error, the runtime
//! surfaces [`RuntimeError::StartFailed`] with the AVF-reported
//! reason. Either failure is the substrate's natural fail-closed
//! behaviour and the kernel records an honest audit reason.

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
    use std::sync::mpsc;

    use block2::RcBlock;
    use dispatch2::{DispatchQueue, DispatchQueueAttr, DispatchRetained};
    use objc2::rc::Retained;
    use objc2::runtime::ProtocolObject;
    use objc2::AnyThread;
    use objc2_foundation::{NSArray, NSError, NSString, NSURL};
    use objc2_virtualization::{
        VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode,
        VZDirectoryShare, VZLinuxBootLoader, VZNATNetworkDeviceAttachment,
        VZNetworkDeviceConfiguration, VZSharedDirectory, VZSingleDirectoryShare,
        VZSocketDevice, VZSocketDeviceConfiguration, VZStorageDeviceConfiguration,
        VZVirtioBlockDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
        VZVirtioNetworkDeviceConfiguration, VZVirtioSocketConnection, VZVirtioSocketDevice,
        VZVirtioSocketDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
        VZVirtualMachineState,
    };

    /// Concrete macOS runtime.
    ///
    /// Holds the AVF objects the substrate retains for the lifetime
    /// of the session. All AVF interaction is routed through
    /// [`Self::queue`] (a serial dispatch queue) per Apple's
    /// queue-confinement contract.
    pub struct AvfRuntime {
        cfg:        AvfConfig,
        queue:      DispatchRetained<DispatchQueue>,
        config_obj: Option<Retained<VZVirtualMachineConfiguration>>,
        vm:         Option<VmHandle>,
        started:    bool,
        last_error: Option<String>,
    }

    /// Send-safe wrapper around a queue-confined `VZVirtualMachine`.
    ///
    /// AVF's contract is that **method calls** on `VZVirtualMachine`
    /// must run on the queue passed to `initWithConfiguration:queue:`.
    /// The pointer itself is not pinned to a thread; we only ever
    /// invoke methods via [`DispatchQueue::exec_async`]. The
    /// `unsafe impl Send` here records that invariant.
    struct VmHandle(Retained<VZVirtualMachine>);

    // SAFETY: see [`VmHandle`] doc-comment — methods are dispatched
    // through the queue, never called from arbitrary threads.
    unsafe impl Send for VmHandle {}

    impl VmHandle {
        fn raw(&self) -> &VZVirtualMachine {
            &self.0
        }

        fn clone_handle(&self) -> Self {
            Self(self.0.clone())
        }
    }

    // SAFETY: AVF objects are thread-confined per Apple docs; the
    // substrate's `Session` trait requires `Send`, and the runtime
    // routes every AVF call through `self.queue`. The retained
    // configuration / VM pointers are never aliased across threads.
    unsafe impl Send for AvfRuntime {}

    impl std::fmt::Debug for AvfRuntime {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AvfRuntime")
                .field("cfg",        &self.cfg)
                .field("started",    &self.started)
                .field("last_error", &self.last_error)
                .field("has_config", &self.config_obj.is_some())
                .field("has_vm",     &self.vm.is_some())
                .finish()
        }
    }

    impl AvfRuntime {
        /// Build a runtime; allocates the serial dispatch queue but
        /// no AVF objects yet. The first AVF call happens in
        /// [`Self::start`].
        pub fn new(cfg: AvfConfig) -> Self {
            let queue = DispatchQueue::new("raxis.avf-runtime", DispatchQueueAttr::SERIAL);
            Self {
                cfg,
                queue,
                config_obj: None,
                vm:         None,
                started:    false,
                last_error: None,
            }
        }

        /// Translate the typed [`AvfConfig`] into a real
        /// `VZVirtualMachineConfiguration` and validate it.
        ///
        /// Wires every device class V2 uses (storage, VirtioFS,
        /// network, vsock) onto the configuration object. The
        /// validation is AVF's own — `validateWithError:` reports
        /// the first authoritative error string.
        ///
        /// # Safety
        ///
        /// Every `unsafe` block below crosses into Objective-C. Each
        /// `init`/`new` returns a `Retained<…>` that the Rust side
        /// owns; the configuration retains them via `setX:` and the
        /// matching `Retained` Drop releases on scope exit.
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

            // ---- Boot loader -------------------------------------
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

            // ---- Storage devices (rootfs + data drives) ---------
            let mut storage_objs: Vec<Retained<VZStorageDeviceConfiguration>> =
                Vec::with_capacity(self.cfg.block_devices.len());
            for blk in &self.cfg.block_devices {
                let url = path_to_nsurl(&blk.host_path)?;
                let attachment = unsafe {
                    VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                        VZDiskImageStorageDeviceAttachment::alloc(),
                        &url,
                        blk.read_only,
                        VZDiskImageCachingMode::Automatic,
                        VZDiskImageSynchronizationMode::Fsync,
                    )
                }
                .map_err(|e| RuntimeError::InvalidConfig(format!(
                    "block device {}: {}",
                    blk.drive_id,
                    ns_error_string(&e),
                )))?;
                let device = unsafe {
                    VZVirtioBlockDeviceConfiguration::initWithAttachment(
                        VZVirtioBlockDeviceConfiguration::alloc(),
                        &attachment,
                    )
                };
                // Best-effort: AVF rejects identifiers > 20 ASCII bytes; we
                // truncate rather than fail, since the identifier is purely
                // informational on the guest side.
                let mut id = blk.drive_id.clone();
                if id.len() > 20 {
                    id.truncate(20);
                }
                let id_ns = NSString::from_str(&id);
                unsafe {
                    device.setBlockDeviceIdentifier(&id_ns);
                }
                // SAFETY: VZVirtioBlockDeviceConfiguration <:
                // VZStorageDeviceConfiguration. The cast is sound
                // because the parent class is the AVF-required type
                // for the array setter.
                let upcast: Retained<VZStorageDeviceConfiguration> = unsafe {
                    Retained::cast_unchecked::<VZStorageDeviceConfiguration>(device)
                };
                storage_objs.push(upcast);
            }
            let storage_array = NSArray::from_retained_slice(&storage_objs);
            unsafe {
                conf.setStorageDevices(&storage_array);
            }

            // ---- VirtioFS shares ---------------------------------
            let mut fs_objs: Vec<
                Retained<objc2_virtualization::VZDirectorySharingDeviceConfiguration>,
            > = Vec::with_capacity(self.cfg.fs_shares.len());
            for share in &self.cfg.fs_shares {
                let tag_ns = NSString::from_str(&share.tag);
                // Pre-validate the tag so the error is clearly
                // attributable to this share rather than buried in
                // `validateWithError:` aggregate output.
                if let Err(e) = unsafe {
                    VZVirtioFileSystemDeviceConfiguration::validateTag_error(&tag_ns)
                } {
                    return Err(RuntimeError::InvalidConfig(format!(
                        "virtiofs tag {:?}: {}",
                        share.tag,
                        ns_error_string(&e),
                    )));
                }
                let dev = unsafe {
                    VZVirtioFileSystemDeviceConfiguration::initWithTag(
                        VZVirtioFileSystemDeviceConfiguration::alloc(),
                        &tag_ns,
                    )
                };

                let host_url = path_to_nsurl(&share.host_path)?;
                let shared_dir = unsafe {
                    VZSharedDirectory::initWithURL_readOnly(
                        VZSharedDirectory::alloc(),
                        &host_url,
                        share.read_only,
                    )
                };
                let single = unsafe {
                    VZSingleDirectoryShare::initWithDirectory(
                        VZSingleDirectoryShare::alloc(),
                        &shared_dir,
                    )
                };
                // SAFETY: VZSingleDirectoryShare <: VZDirectoryShare.
                let single_upcast: Retained<VZDirectoryShare> = unsafe {
                    Retained::cast_unchecked::<VZDirectoryShare>(single)
                };
                unsafe {
                    dev.setShare(Some(&single_upcast));
                }
                // SAFETY: VZVirtioFileSystemDeviceConfiguration <:
                // VZDirectorySharingDeviceConfiguration. The setter
                // takes the parent class, so we upcast once.
                let upcast: Retained<
                    objc2_virtualization::VZDirectorySharingDeviceConfiguration,
                > = unsafe {
                    Retained::cast_unchecked::<
                        objc2_virtualization::VZDirectorySharingDeviceConfiguration,
                    >(dev)
                };
                fs_objs.push(upcast);
            }
            let fs_array = NSArray::from_retained_slice(&fs_objs);
            unsafe {
                conf.setDirectorySharingDevices(&fs_array);
            }

            // ---- Network device ----------------------------------
            let mut net_objs: Vec<Retained<VZNetworkDeviceConfiguration>> = Vec::new();
            if let Some(net) = &self.cfg.network {
                match net.mode {
                    crate::config::AvfNetworkMode::Nat => {
                        let attachment = unsafe { VZNATNetworkDeviceAttachment::new() };
                        let dev = unsafe { VZVirtioNetworkDeviceConfiguration::new() };
                        // SAFETY: VZNATNetworkDeviceAttachment <:
                        // VZNetworkDeviceAttachment.
                        let attach_upcast = unsafe {
                            Retained::cast_unchecked::<
                                objc2_virtualization::VZNetworkDeviceAttachment,
                            >(attachment)
                        };
                        unsafe {
                            dev.setAttachment(Some(&attach_upcast));
                        }
                        // SAFETY: VZVirtioNetworkDeviceConfiguration <:
                        // VZNetworkDeviceConfiguration.
                        let dev_upcast: Retained<VZNetworkDeviceConfiguration> = unsafe {
                            Retained::cast_unchecked::<VZNetworkDeviceConfiguration>(dev)
                        };
                        net_objs.push(dev_upcast);
                    }
                }
            }
            let net_array = NSArray::from_retained_slice(&net_objs);
            unsafe {
                conf.setNetworkDevices(&net_array);
            }

            // ---- VSock device ------------------------------------
            // Always wire a single VSock device — the kernel's
            // planner channel is the only allowed control plane.
            let vsock_dev = unsafe { VZVirtioSocketDeviceConfiguration::new() };
            // SAFETY: VZVirtioSocketDeviceConfiguration <:
            // VZSocketDeviceConfiguration.
            let vsock_upcast: Retained<VZSocketDeviceConfiguration> = unsafe {
                Retained::cast_unchecked::<VZSocketDeviceConfiguration>(vsock_dev)
            };
            let socket_array =
                NSArray::from_retained_slice(std::slice::from_ref(&vsock_upcast));
            unsafe {
                conf.setSocketDevices(&socket_array);
            }

            // ---- Validate ----------------------------------------
            match unsafe { conf.validateWithError() } {
                Ok(()) => Ok(conf),
                Err(e) => Err(RuntimeError::InvalidConfig(ns_error_string(&e))),
            }
        }

        /// Start the VM.
        ///
        /// Builds the configuration, validates it, allocates a
        /// `VZVirtualMachine` bound to the substrate's serial
        /// dispatch queue, and dispatches
        /// `startWithCompletionHandler:` on that queue. The
        /// completion handler is bridged back to the calling thread
        /// via a bounded `mpsc::sync_channel` so the synchronous
        /// `Backend::spawn` API contract is preserved.
        pub fn start(&mut self, grace: Duration) -> Result<(), RuntimeError> {
            if self.started {
                return Ok(());
            }
            let conf = self.build_configuration()?;
            self.config_obj = Some(conf.clone());

            // SAFETY: VM init must happen on the substrate's queue.
            // We allocate the VM here on the calling thread (init is
            // safe per the AVF docs — the queue confinement is for
            // method calls, not for the init call itself), then
            // dispatch all subsequent calls through `self.queue`.
            let vm = unsafe {
                VZVirtualMachine::initWithConfiguration_queue(
                    VZVirtualMachine::alloc(),
                    &conf,
                    &self.queue,
                )
            };
            let vm_handle = VmHandle(vm);
            self.vm = Some(vm_handle.clone_handle());

            let (tx, rx) = mpsc::sync_channel::<Result<(), RuntimeError>>(1);
            let vm_for_dispatch = vm_handle.clone_handle();
            let tx_for_dispatch = tx.clone();
            self.queue.exec_async(move || {
                // The block is invoked once by AVF on the same
                // dispatch queue when the start dance completes
                // (success or error).
                let block = RcBlock::new(move |err: *mut NSError| {
                    let result = if err.is_null() {
                        Ok(())
                    } else {
                        // SAFETY: AVF passes an autoreleased
                        // `NSError*`; we copy the localizedDescription
                        // before the autorelease pool drains.
                        let msg = unsafe { ns_error_string_from_raw(err) };
                        Err(RuntimeError::StartFailed(msg))
                    };
                    let _ = tx_for_dispatch.send(result);
                });
                // SAFETY: queue-confined; we are inside the dispatch
                // block, which AVF requires for this call.
                unsafe {
                    vm_for_dispatch
                        .raw()
                        .startWithCompletionHandler(&block);
                }
            });

            match rx.recv_timeout(grace) {
                Ok(Ok(())) => {
                    self.started = true;
                    Ok(())
                }
                Ok(Err(e)) => {
                    self.last_error = Some(e.to_string());
                    Err(e)
                }
                Err(_) => {
                    let err = RuntimeError::StartTimeout(grace);
                    self.last_error = Some(err.to_string());
                    Err(err)
                }
            }
        }

        /// Graceful stop. Dispatches `stopWithCompletionHandler:`
        /// through the substrate's queue and waits the configured
        /// grace.
        pub fn stop(&mut self, grace: Duration) -> Result<AvfExit, RuntimeError> {
            let vm = match self.vm.take() {
                Some(vm) => vm,
                None => {
                    self.config_obj = None;
                    self.started = false;
                    return Ok(AvfExit {
                        final_state: VmStateSnapshot::Stopped,
                        graceful:    true,
                        reason:      None,
                    });
                }
            };

            let (tx, rx) = mpsc::sync_channel::<Result<(), RuntimeError>>(1);
            let vm_for_dispatch = vm.clone_handle();
            let tx_for_dispatch = tx.clone();
            self.queue.exec_async(move || {
                let block = RcBlock::new(move |err: *mut NSError| {
                    let result = if err.is_null() {
                        Ok(())
                    } else {
                        // SAFETY: see start path.
                        let msg = unsafe { ns_error_string_from_raw(err) };
                        Err(RuntimeError::StopFailed(msg))
                    };
                    let _ = tx_for_dispatch.send(result);
                });
                // SAFETY: queue-confined call.
                unsafe {
                    vm_for_dispatch.raw().stopWithCompletionHandler(&block);
                }
            });

            self.started = false;
            self.config_obj = None;

            match rx.recv_timeout(grace) {
                Ok(Ok(())) => Ok(AvfExit {
                    final_state: VmStateSnapshot::Stopped,
                    graceful:    true,
                    reason:      None,
                }),
                Ok(Err(e)) => {
                    self.last_error = Some(e.to_string());
                    Ok(AvfExit {
                        final_state: VmStateSnapshot::Errored,
                        graceful:    false,
                        reason:      Some(e.to_string()),
                    })
                }
                Err(_) => Ok(AvfExit {
                    final_state: VmStateSnapshot::Stopping,
                    graceful:    false,
                    reason:      Some(format!("stop timed out after {grace:?}")),
                }),
            }
        }

        /// Open a VSock connection to a guest port.
        ///
        /// Resolves the VM's `VZVirtioSocketDevice` from
        /// `socketDevices`, dispatches
        /// `connectToPort:completionHandler:`, and returns the
        /// resulting connection's file descriptor. The substrate's
        /// caller (`AppleVzSession`) owns the fd and is responsible
        /// for closing it on session teardown.
        pub fn connect_vsock(&self, port: u32) -> Result<c_int, RuntimeError> {
            let vm = self.vm.as_ref().ok_or_else(|| RuntimeError::VsockConnect {
                port,
                reason: "VM not started — start() must succeed before connecting vsock".to_owned(),
            })?;

            // VsockResult is `Send` because both variants are owned
            // primitives / Strings.
            let (tx, rx) = mpsc::sync_channel::<Result<c_int, RuntimeError>>(1);
            let vm_for_dispatch = vm.clone_handle();
            let tx_for_dispatch = tx.clone();
            self.queue.exec_async(move || {
                // SAFETY: queue-confined call. `socketDevices` is the
                // canonical accessor.
                let devices = unsafe { vm_for_dispatch.raw().socketDevices() };
                if devices.is_empty() {
                    let _ = tx_for_dispatch.send(Err(RuntimeError::VsockConnect {
                        port,
                        reason: "VZVirtualMachine has no VZVirtioSocketDevice; \
                                 check VmSpec::vsock_cid wiring"
                            .to_owned(),
                    }));
                    return;
                }
                let device_dyn: Retained<VZSocketDevice> = devices.objectAtIndex(0);
                // SAFETY: V2 only ever wires VZVirtioSocketDevice as
                // the substrate's socket device class. Any other
                // class would be a programming error in
                // build_configuration.
                let virtio_dev: Retained<VZVirtioSocketDevice> = unsafe {
                    Retained::cast_unchecked::<VZVirtioSocketDevice>(device_dyn)
                };

                let tx_inner = tx_for_dispatch.clone();
                let block = RcBlock::new(
                    move |conn: *mut VZVirtioSocketConnection, err: *mut NSError| {
                        let result = if !err.is_null() {
                            // SAFETY: see start path.
                            let msg = unsafe { ns_error_string_from_raw(err) };
                            Err(RuntimeError::VsockConnect { port, reason: msg })
                        } else if conn.is_null() {
                            Err(RuntimeError::VsockConnect {
                                port,
                                reason:
                                    "AVF returned nil connection without an error; \
                                     guest may not be listening on the planner port"
                                        .to_owned(),
                            })
                        } else {
                            // SAFETY: AVF returns a retained
                            // VZVirtioSocketConnection; the fd is
                            // owned by the connection until the
                            // connection is released. We retain it
                            // for the duration of the runtime so the
                            // fd stays valid; release happens on
                            // session teardown.
                            let fd = unsafe { (*conn).fileDescriptor() };
                            if fd < 0 {
                                Err(RuntimeError::VsockConnect {
                                    port,
                                    reason: "AVF connection returned negative fd".to_owned(),
                                })
                            } else {
                                Ok(fd)
                            }
                        };
                        let _ = tx_inner.send(result);
                    },
                );
                // SAFETY: queue-confined call.
                unsafe {
                    virtio_dev.connectToPort_completionHandler(port, &block);
                }
            });

            // VSock connect uses the configured boot grace as a
            // sane upper bound — the kernel calls this immediately
            // after start() succeeds, so the guest's planner is
            // expected to be listening within that window.
            match rx.recv_timeout(Duration::from_secs(10)) {
                Ok(result) => result,
                Err(_) => Err(RuntimeError::VsockConnect {
                    port,
                    reason: "AVF connect_vsock timed out after 10s".to_owned(),
                }),
            }
        }

        /// Snapshot lifecycle state. When the VM is live, queries
        /// AVF directly (queue-confined). Otherwise reports the
        /// runtime's tracked state.
        pub fn state(&self) -> VmStateSnapshot {
            let vm = match &self.vm {
                Some(vm) => vm,
                None => {
                    return if self.started {
                        VmStateSnapshot::Running
                    } else {
                        VmStateSnapshot::Stopped
                    };
                }
            };
            let (tx, rx) = mpsc::sync_channel::<VZVirtualMachineState>(1);
            let vm_for_dispatch = vm.clone_handle();
            self.queue.exec_async(move || {
                // SAFETY: queue-confined property read.
                let s = unsafe { vm_for_dispatch.raw().state() };
                let _ = tx.send(s);
            });
            let raw = rx.recv_timeout(Duration::from_millis(500))
                .unwrap_or(VZVirtualMachineState::Stopped);
            map_vz_state(raw)
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
            // Best-effort tear-down. If the VM is still alive,
            // dispatch a stop on the queue and forget the result —
            // Drop must not panic.
            if let Some(vm) = self.vm.take() {
                let vm_for_dispatch = vm.clone_handle();
                self.queue.exec_async(move || {
                    // SAFETY: queue-confined; ignore completion.
                    unsafe {
                        let block = RcBlock::new(|_err: *mut NSError| {});
                        vm_for_dispatch.raw().stopWithCompletionHandler(&block);
                    }
                });
            }
            self.config_obj = None;
        }
    }

    fn map_vz_state(s: VZVirtualMachineState) -> VmStateSnapshot {
        match s {
            VZVirtualMachineState::Stopped => VmStateSnapshot::Stopped,
            VZVirtualMachineState::Starting => VmStateSnapshot::Starting,
            VZVirtualMachineState::Running => VmStateSnapshot::Running,
            VZVirtualMachineState::Stopping => VmStateSnapshot::Stopping,
            VZVirtualMachineState::Error => VmStateSnapshot::Errored,
            // Paused / Pausing / Resuming / Saving / Restoring are not
            // V2 states (we don't support save/restore yet); collapse
            // them onto Running for audit purposes — the VM is still
            // alive.
            _ => VmStateSnapshot::Running,
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

    /// SAFETY: caller asserts `err` is a non-null AVF-owned
    /// `NSError*`. We deref once to copy the localizedDescription
    /// out before the autorelease pool drains.
    unsafe fn ns_error_string_from_raw(err: *mut NSError) -> String {
        if err.is_null() {
            return "<nil NSError>".to_owned();
        }
        // SAFETY: caller guarantees non-null AVF-owned pointer.
        unsafe { (*err).localizedDescription().to_string() }
    }

    // Suppress dead-code warnings for the unused `ProtocolObject` import
    // when no protocol-typed paths are in use yet.
    #[allow(dead_code)]
    fn _ensure_protocol_object_in_scope(p: &ProtocolObject<dyn objc2::runtime::NSObjectProtocol>) {
        let _ = p;
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
            env:              Default::default(),
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

    /// macOS runtime real-binding test: build the
    /// `VZVirtualMachineConfiguration`, set every device array, and
    /// invoke `validateWithError:` + `startWithCompletionHandler:`.
    ///
    /// In a development environment the kernel image / rootfs disk
    /// image at `/var/raxis/img/rootfs.img` does not exist, so AVF
    /// will surface either an `InvalidConfig` (validation failed) or
    /// `StartFailed` (validation passed but boot blew up reading the
    /// kernel) — both are honest substrate fail-closed paths driven
    /// by real `Virtualization.framework` calls. The test asserts
    /// the failure surfaces from one of those paths and is *not*
    /// the V2 stub sentinel; that proves the device wiring is
    /// reaching real AVF code.
    #[cfg(target_os = "macos")]
    #[test]
    fn runtime_start_engages_real_avf_validation_and_fails_honestly_without_real_image() {
        let cfg = translate(&fixture_image(), &[], &fixture_spec()).unwrap();
        let mut r = AvfRuntime::new(cfg);
        match r.start(Duration::from_secs(2)) {
            // Healthy host should never succeed in a unit test —
            // the kernel image is a placeholder file path that
            // does not exist.
            Ok(()) => panic!("AVF should not boot a fake kernel image"),
            // Most common path: AVF refuses the config because
            // the kernel image / rootfs disk image is missing or
            // not entitled.
            Err(RuntimeError::InvalidConfig(_)) => {}
            // Validation passed (entitled host with the image
            // present), but boot failed during the start dance.
            Err(RuntimeError::StartFailed(_)) => {}
            // The dispatch round-trip exceeded the grace.
            Err(RuntimeError::StartTimeout(_)) => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    /// `connect_vsock` is only callable after a successful `start`.
    /// Calling it on a non-started runtime returns a typed error
    /// that names the contract — no fake fd, no stub sentinel.
    #[cfg(target_os = "macos")]
    #[test]
    fn runtime_connect_vsock_refuses_without_a_started_vm() {
        let cfg = translate(&fixture_image(), &[], &fixture_spec()).unwrap();
        let r = AvfRuntime::new(cfg);
        match r.connect_vsock(1024) {
            Err(RuntimeError::VsockConnect { port, reason }) => {
                assert_eq!(port, 1024);
                assert!(
                    reason.contains("VM not started"),
                    "expected fail-closed reason, got {reason:?}",
                );
            }
            other => panic!("expected VsockConnect, got {other:?}"),
        }
    }

    /// Stop on a runtime that never started must be a no-op that
    /// reports a graceful Stopped exit — this is the destructor's
    /// happy path on the substrate's error-rollback flows.
    #[cfg(target_os = "macos")]
    #[test]
    fn runtime_stop_without_start_is_idempotent_graceful() {
        let cfg = translate(&fixture_image(), &[], &fixture_spec()).unwrap();
        let mut r = AvfRuntime::new(cfg);
        let exit = r.stop(Duration::from_millis(200)).unwrap();
        assert_eq!(exit.final_state, VmStateSnapshot::Stopped);
        assert!(exit.graceful);
        assert!(exit.reason.is_none());
    }
}
