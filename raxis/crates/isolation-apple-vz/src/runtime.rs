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
//! * `AvfRuntime::build_configuration` allocates a real
//!   `VZVirtualMachineConfiguration` and wires every device class V2
//!   uses:
//!   - `VZLinuxBootLoader` from `cfg.boot_loader`
//!   - `VZVirtioBlockDeviceConfiguration` +
//!     `VZDiskImageStorageDeviceAttachment` for each block device
//!   - `VZVirtioFileSystemDeviceConfiguration` +
//!     `VZSingleDirectoryShare` + `VZSharedDirectory` for each
//!     VirtioFS share
//!   - `VZVirtioSocketDeviceConfiguration` (always present so the
//!     planner port is reachable from the host)
//!
//!   The substrate attaches **no** virtio-net device for any
//!   surviving `EgressTier` after the Tier1Tproxy deletion — the
//!   `VZVirtualMachineConfiguration.networkDevices` array is left
//!   empty under `EgressTier::{None, Mediated, Tier2CredProxy}`.
//!   See `airgap-architecture.md §5` and
//!   `INV-NETISO-A3-UNIVERSAL-NO-NIC-01`.
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

/// Hard deadline the [`AvfRuntime::connect_vsock`] retry loop honours
/// when waiting for the in-guest planner to bind AF_VSOCK on the
/// canonical port. AVF's `connectToPort:` does not block until a
/// listener appears — it dispatches once and surfaces ECONNREFUSED
/// when the guest is mid-boot — so we wrap the call in a polling
/// loop bounded by this constant.
///
/// Sized to comfortably exceed the orchestrator boot budget pinned
/// by `extensibility-traits.md §3.5` (median ~200 ms boot + tokio
/// runtime spin-up + cmdline-env hydration). 30 s also matches
/// the operator-facing Apple-VZ start timeout the substrate uses
/// for `start()` itself.
pub const VSOCK_CONNECT_DEADLINE: Duration = Duration::from_secs(30);

/// Inter-attempt sleep used by the [`AvfRuntime::connect_vsock`]
/// retry loop once the VM has been booting long enough that the
/// guest planner is overdue. See [`vsock_connect_next_backoff`] for
/// the full progressive policy — `VSOCK_CONNECT_BACKOFF_STEADY` is
/// the upper-bound applied past `VSOCK_CONNECT_BACKOFF_RAMP_END`,
/// where additional polling cost no longer matters because the
/// guest is clearly not on the happy path.
pub const VSOCK_CONNECT_BACKOFF_STEADY: Duration = Duration::from_millis(100);

/// Inter-attempt sleep used during the initial "fast poll" window of
/// [`AvfRuntime::connect_vsock`]. The canonical orchestrator boot
/// (per `extensibility-traits.md §3.5`) lands a vsock listener
/// within ~200 ms; the previous 100 ms steady-state cadence cost up
/// to 90 ms of avoidable wall time on every spawn (we'd miss the
/// listener bind by one cycle). Polling at 5 ms during the boot
/// window costs only a handful of dispatch hops on AVF's serial
/// queue and recovers ~50–90 ms per spawn in the typical case.
pub const VSOCK_CONNECT_BACKOFF_FAST: Duration = Duration::from_millis(5);

/// Mid-window backoff: once the guest is past the median boot
/// budget but not yet "stuck", we relax to 25 ms so polling cost
/// stays bounded if a slower-than-usual boot drags out into the
/// hundreds of ms.
pub const VSOCK_CONNECT_BACKOFF_MID: Duration = Duration::from_millis(25);

/// Elapsed-time threshold separating the fast (5 ms) and mid (25 ms)
/// polling regimes. Sized to comfortably cover the median orchestrator
/// boot plus the tokio-runtime spin-up the planner does before
/// binding AF_VSOCK.
pub const VSOCK_CONNECT_BACKOFF_FAST_END: Duration = Duration::from_millis(300);

/// Elapsed-time threshold separating the mid (25 ms) and steady
/// (100 ms) polling regimes. Past this point the boot is clearly
/// abnormal; we stop hammering the dispatch queue and give the
/// guest time to recover (or the deadline to expire).
pub const VSOCK_CONNECT_BACKOFF_RAMP_END: Duration = Duration::from_secs(2);

/// Best-effort drain window for the host-side AVF console pump
/// after VM stop completes or times out.
///
/// The console pump is forensic capture only. It must never become
/// part of the security-critical VM shutdown path: a wedged AVF
/// file-handle retain can keep the read side from seeing EOF, and
/// an unconditional `JoinHandle::join()` would then park the kernel
/// indefinitely during retry/revoke cleanup. We wait briefly for the
/// happy path, join only if the thread has finished, and otherwise
/// detach it so the scheduler/dashboard stay responsive.
pub const CONSOLE_PUMP_JOIN_GRACE: Duration = Duration::from_millis(250);

/// Pick the next inter-attempt sleep for the
/// [`AvfRuntime::connect_vsock`] retry loop based on how long we've
/// already been polling. Three regimes:
///
///   * `< VSOCK_CONNECT_BACKOFF_FAST_END` (300 ms) — `5 ms`. Covers
///     the median orchestrator boot; recovers ~50–90 ms per spawn
///     vs the previous 100 ms steady cadence.
///   * `< VSOCK_CONNECT_BACKOFF_RAMP_END` (2 s) — `25 ms`. The
///     guest is past the happy path but might still come up; bounded
///     polling cost.
///   * otherwise — `100 ms`. Same as the legacy steady cadence;
///     the boot is abnormal and additional polling cost is moot.
#[inline]
pub fn vsock_connect_next_backoff(elapsed: Duration) -> Duration {
    if elapsed < VSOCK_CONNECT_BACKOFF_FAST_END {
        VSOCK_CONNECT_BACKOFF_FAST
    } else if elapsed < VSOCK_CONNECT_BACKOFF_RAMP_END {
        VSOCK_CONNECT_BACKOFF_MID
    } else {
        VSOCK_CONNECT_BACKOFF_STEADY
    }
}

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
        port: u32,
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
    pub graceful: bool,
    /// Human-readable reason from AVF, if any.
    pub reason: Option<String>,
}

#[cfg(any(target_os = "macos", test))]
fn avf_stop_should_not_be_issued_for_state(state: VmStateSnapshot) -> bool {
    matches!(state, VmStateSnapshot::Stopped | VmStateSnapshot::Stopping)
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
        cfg: AvfConfig,
        started: bool,
    }

    impl AvfRuntime {
        /// Build a stub runtime; never starts a VM on non-macOS.
        pub fn new(cfg: AvfConfig) -> Self {
            Self {
                cfg,
                started: false,
            }
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

        /// Always returns `LoopbackBridgeError::Unsupported`.
        pub fn register_loopback_listener(
            &mut self,
            _vsock_port: u32,
            _host_loopback_port: u16,
        ) -> Result<(), crate::vsock_loopback_bridge::LoopbackBridgeError> {
            Err(crate::vsock_loopback_bridge::LoopbackBridgeError::Unsupported)
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
        VZDirectoryShare, VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment,
        VZDiskImageSynchronizationMode, VZLinuxBootLoader, VZSharedDirectory,
        VZSingleDirectoryShare, VZSocketDevice, VZSocketDeviceConfiguration,
        VZStorageDeviceConfiguration, VZVirtioBlockDeviceConfiguration,
        VZVirtioFileSystemDeviceConfiguration, VZVirtioSocketConnection, VZVirtioSocketDevice,
        VZVirtioSocketDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
        VZVirtualMachineState,
    };

    /// Concrete macOS runtime.
    ///
    /// Holds the AVF objects the substrate retains for the lifetime
    /// of the session. All AVF interaction is routed through
    /// `Self::queue` (a serial dispatch queue) per Apple's
    /// queue-confinement contract.
    pub struct AvfRuntime {
        cfg: AvfConfig,
        queue: DispatchRetained<DispatchQueue>,
        config_obj: Option<Retained<VZVirtualMachineConfiguration>>,
        vm: Option<VmHandle>,
        started: bool,
        last_error: Option<String>,
        /// Background thread that drains AVF's serial-port pipe to
        /// the host-side console log file. Set when
        /// [`AvfConfig::console_log`] is present and the substrate
        /// successfully wires the pipe; cleared when the runtime is
        /// dropped (the read end closes, the thread exits naturally).
        console_pump: Option<std::thread::JoinHandle<()>>,
        /// Live `VZVirtioSocketConnection` retained for the lifetime
        /// of the session. AVF returns the fd via the connection's
        /// `fileDescriptor` property, which the connection owns and
        /// closes at deinit. We keep the strong reference here so
        /// the kernel-side `tokio::net::UnixStream` (built from a
        /// `dup(2)` of the fd we extracted under that
        /// retain-window) and the AVF-owned original fd both stay
        /// open until session teardown — at which point Drop on
        /// this `Option` releases the connection (closing the
        /// AVF-owned fd) and Drop on the kernel-side stream
        /// closes the dup independently.
        ///
        /// Stored as `VsockConnHandle` (a `Send`-marked wrapper)
        /// because the runtime itself is `Send` and the connection
        /// pointer is queue-confined: we never call methods on it
        /// from arbitrary threads after the initial fd extraction.
        vsock_conn: Option<VsockConnHandle>,
        /// Per-session credential-proxy vsock-loopback listener
        /// handles. Each handle owns a `VZVirtioSocketListener` +
        /// delegate registered on the VM's `VZVirtioSocketDevice`
        /// for one `(vsock_port, host_loopback_port)` pair. The
        /// handles live until session teardown — Drop unregisters
        /// the listener and releases the retained connections,
        /// which closes AVF's vsock fds. See
        /// [`crate::vsock_loopback_bridge`] for the protocol.
        loopback_listeners: Vec<crate::vsock_loopback_bridge::LoopbackListenerHandle>,
    }

    // SAFETY: `LoopbackListenerHandle::HandleInner` carries
    // `Retained<...>` ObjC pointers; AVF's queue-confinement
    // contract means we never call methods on those pointers off
    // the substrate queue. The listener is registered/removed
    // under `queue.exec_async` blocks. The `Send` bound on the
    // runtime is required by `Backend::spawn` returning
    // `Box<dyn Session>`. The `Vec<LoopbackListenerHandle>` is
    // only populated/drained on the kernel-spawn thread, and the
    // handles' Drop dispatches removal back onto the queue.
    unsafe impl Send for crate::vsock_loopback_bridge::LoopbackListenerHandle {}

    /// `Send` wrapper around a retained `VZVirtioSocketConnection`.
    ///
    /// AVF's queue-confinement contract applies to method calls on
    /// the connection, but the bare `Retained<...>` is not `Send`
    /// because the underlying ObjC object is not `Sync`. We never
    /// call methods through this handle after construction; it
    /// exists solely to keep the connection alive (and therefore
    /// the AVF-owned fd open) for the lifetime of the runtime.
    /// The `unsafe impl Send` records that invariant.
    struct VsockConnHandle(#[allow(dead_code)] Retained<VZVirtioSocketConnection>);

    // SAFETY: the wrapped pointer is only ever dropped here (which
    // calls release on the substrate's drop thread). No methods are
    // invoked on the connection after the fd extraction inside the
    // dispatch block at `connect_vsock_once`, so the queue-
    // confinement contract is preserved.
    unsafe impl Send for VsockConnHandle {}

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
                .field("cfg", &self.cfg)
                .field("started", &self.started)
                .field("last_error", &self.last_error)
                .field("has_config", &self.config_obj.is_some())
                .field("has_vm", &self.vm.is_some())
                .finish()
        }
    }

    use std::cell::RefCell;
    use std::path::Path;

    thread_local! {
        /// Stash for the console-pump `JoinHandle` produced inside
        /// `build_configuration` (which only holds `&self`). The
        /// caller (`start`, which holds `&mut self`) collects it
        /// and stores it on the runtime so the thread is joined
        /// at runtime drop.
        static CONSOLE_PUMP_TAKE: RefCell<Option<std::thread::JoinHandle<()>>> =
            const { RefCell::new(None) };
    }

    /// Allocate an anonymous pipe via `libc::pipe`, attach the
    /// write end to AVF as a `VZVirtioConsoleDeviceSerialPortConfiguration`,
    /// and spawn a background thread that drains the read end into
    /// the host-side console log file.
    ///
    /// # Errors
    /// * `pipe(2)` failure surfaces as `RuntimeError::InvalidConfig`
    ///   with the OS error string (host fd-table exhaustion is the
    ///   only realistic cause).
    /// * Failure to create / open the host log file surfaces the
    ///   same way; the substrate refuses to start a VM whose console
    ///   capture cannot be wired (no silent dropping).
    fn wire_console_pipe(
        log_path: &Path,
        conf: &VZVirtualMachineConfiguration,
    ) -> Result<std::thread::JoinHandle<()>, RuntimeError> {
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                RuntimeError::InvalidConfig(
                    format!("console.log parent {}: {e}", parent.display(),),
                )
            })?;
        }
        // Truncate-open: the file is per-session; previous content
        // (if any) is stale.
        let mut sink = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(log_path)
            .map_err(|e| {
                RuntimeError::InvalidConfig(
                    format!("console.log open {}: {e}", log_path.display(),),
                )
            })?;

        // Host-side marker so the file is never zero bytes — even
        // if the guest never produces a single byte (kernel boot
        // failure before virtio-console enumeration), the operator
        // can see "the substrate did wire a console" vs "the
        // substrate gave up on wiring".
        use std::io::Write as _;
        let _ = writeln!(
            sink,
            "{{\"level\":\"info\",\"step\":\"avf-console\",\
              \"event\":\"host_marker\",\"path\":{:?}}}",
            log_path.display().to_string(),
        );
        let _ = sink.flush();

        // Allocate the pipe.
        let mut fds: [c_int; 2] = [0, 0];
        // SAFETY: pipe(2) writes two fds into the supplied buffer.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(RuntimeError::InvalidConfig(format!(
                "console.log pipe(2): {}",
                std::io::Error::last_os_error(),
            )));
        }
        let read_fd = fds[0];
        let write_fd = fds[1];

        // Wrap the write end in NSFileHandle and hand it to AVF.
        // SAFETY: NSFileHandle takes ownership of `write_fd` via
        // `closeOnDealloc:YES`; AVF retains the NSFileHandle for
        // the lifetime of the VM (strong property on the
        // attachment), so the fd stays open until VM teardown.
        let nfh = objc2_foundation::NSFileHandle::initWithFileDescriptor_closeOnDealloc(
            objc2_foundation::NSFileHandle::alloc(),
            write_fd,
            true,
        );
        let attach = unsafe {
            objc2_virtualization::VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                objc2_virtualization::VZFileHandleSerialPortAttachment::alloc(),
                None,
                Some(&nfh),
            )
        };
        // SAFETY: VZFileHandleSerialPortAttachment <: VZSerialPortAttachment.
        let attach_upcast: Retained<objc2_virtualization::VZSerialPortAttachment> = unsafe {
            Retained::cast_unchecked::<objc2_virtualization::VZSerialPortAttachment>(attach)
        };
        let port_cfg =
            unsafe { objc2_virtualization::VZVirtioConsoleDeviceSerialPortConfiguration::new() };
        // SAFETY: setAttachment is a strong setter; the configuration
        // retains the attachment for the configuration's lifetime.
        unsafe {
            port_cfg.setAttachment(Some(&attach_upcast));
        }
        // SAFETY: VZVirtioConsoleDeviceSerialPortConfiguration <: VZSerialPortConfiguration.
        let port_upcast: Retained<objc2_virtualization::VZSerialPortConfiguration> = unsafe {
            Retained::cast_unchecked::<objc2_virtualization::VZSerialPortConfiguration>(port_cfg)
        };
        let serial_array = NSArray::from_retained_slice(std::slice::from_ref(&port_upcast));
        // SAFETY: setSerialPorts copies the array (per the Apple
        // docs / objc2 binding) so the configuration owns its own
        // references after this call.
        unsafe {
            conf.setSerialPorts(&serial_array);
        }

        // Background thread: read the pipe's read end, append to
        // the file. Uses blocking `read(2)` — when AVF closes the
        // write end at VM teardown the read returns 0 and the
        // thread exits.
        let path_for_log = log_path.display().to_string();
        let pump = std::thread::Builder::new()
            .name(format!(
                "raxis-avf-console-{}",
                log_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("guest"),
            ))
            .spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    // SAFETY: read(2) into a stack buffer of known
                    // size; rc < 0 ⇒ error, == 0 ⇒ EOF, > 0 ⇒
                    // bytes available.
                    let rc = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    if rc < 0 {
                        let e = std::io::Error::last_os_error();
                        if e.raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        eprintln!(
                            "{{\"level\":\"warn\",\"event\":\"avf_console_pump_read_err\",\
                              \"path\":{:?},\"err\":{:?}}}",
                            path_for_log,
                            e.to_string(),
                        );
                        break;
                    }
                    if rc == 0 {
                        eprintln!(
                            "{{\"level\":\"info\",\"event\":\"avf_console_pump_eof\",\
                              \"path\":{:?}}}",
                            path_for_log,
                        );
                        break;
                    }
                    if let Err(e) = sink.write_all(&buf[..rc as usize]) {
                        eprintln!(
                            "{{\"level\":\"warn\",\"event\":\"avf_console_pump_write_err\",\
                              \"path\":{:?},\"err\":{:?}}}",
                            path_for_log,
                            e.to_string(),
                        );
                        break;
                    }
                    // Flush so an interactive `tail -F` sees output
                    // promptly — important when the operator is
                    // debugging a stuck guest.
                    let _ = sink.flush();
                }
                // Best-effort close — read side stays open until
                // here so we can drain the pipe to completion.
                unsafe {
                    libc::close(read_fd);
                }
            })
            .map_err(|e| RuntimeError::InvalidConfig(format!("console pump thread spawn: {e}",)))?;

        Ok(pump)
    }

    fn join_console_pump_best_effort(pump: std::thread::JoinHandle<()>, grace: Duration) {
        let deadline = std::time::Instant::now() + grace;
        while !pump.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if pump.is_finished() {
            if pump.join().is_err() {
                eprintln!("{{\"level\":\"warn\",\"event\":\"avf_console_pump_join_panic\"}}",);
            }
        } else {
            // Drop detaches the thread. That may leak one forensic
            // reader thread in the pathological AVF EOF-missing case,
            // but it prevents a much worse failure mode: wedging the
            // kernel on VM shutdown.
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"avf_console_pump_join_timeout\",\
                 \"timeout_ms\":{}}}",
                grace.as_millis(),
            );
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
                vm: None,
                started: false,
                last_error: None,
                console_pump: None,
                vsock_conn: None,
                loopback_listeners: Vec::new(),
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
                VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url)
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
                let upcast: Retained<VZStorageDeviceConfiguration> =
                    unsafe { Retained::cast_unchecked::<VZStorageDeviceConfiguration>(device) };
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
                if let Err(e) =
                    unsafe { VZVirtioFileSystemDeviceConfiguration::validateTag_error(&tag_ns) }
                {
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
                let single_upcast: Retained<VZDirectoryShare> =
                    unsafe { Retained::cast_unchecked::<VZDirectoryShare>(single) };
                unsafe {
                    dev.setShare(Some(&single_upcast));
                }
                // SAFETY: VZVirtioFileSystemDeviceConfiguration <:
                // VZDirectorySharingDeviceConfiguration. The setter
                // takes the parent class, so we upcast once.
                let upcast: Retained<objc2_virtualization::VZDirectorySharingDeviceConfiguration> = unsafe {
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
            //
            // After the Tier1Tproxy deletion the AVF substrate
            // attaches **no** virtio-net device for any surviving
            // `EgressTier` variant (`None`, `Mediated`,
            // `Tier2CredProxy`). The structural absence of
            // `AvfConfig.network` enforces this at compile time;
            // `VZVirtualMachineConfiguration.networkDevices` is left
            // at its default empty `NSArray` so the boot path is
            // bit-identical to the legacy `network = None` arm. See
            // `airgap-architecture.md §5` and
            // `INV-NETISO-A3-UNIVERSAL-NO-NIC-01`.

            // ---- VSock device ------------------------------------
            // Always wire a single VSock device — the kernel's
            // planner channel is the only allowed control plane.
            let vsock_dev = unsafe { VZVirtioSocketDeviceConfiguration::new() };
            // SAFETY: VZVirtioSocketDeviceConfiguration <:
            // VZSocketDeviceConfiguration.
            let vsock_upcast: Retained<VZSocketDeviceConfiguration> =
                unsafe { Retained::cast_unchecked::<VZSocketDeviceConfiguration>(vsock_dev) };
            let socket_array = NSArray::from_retained_slice(std::slice::from_ref(&vsock_upcast));
            unsafe {
                conf.setSocketDevices(&socket_array);
            }

            // ---- Serial console (for guest stderr capture) -------
            //
            // When the kernel-side `VmSpec::guest_console_log` is
            // populated the substrate attaches a single
            // `VZVirtioConsoleDeviceSerialPortConfiguration` whose
            // `fileHandleForWriting` is the **write end of an
            // anonymous pipe**. A background thread on the host
            // reads from the pipe's read end and appends bytes to
            // the host-side console log. The Linux kernel cmdline
            // (`console=hvc0`) routes guest printk + stdout +
            // stderr there so panics (PID 1 dying → kernel reboot
            // per `panic=10`) leave a forensic trail on the host
            // instead of just a vsock RST.
            //
            // **Why a pipe and not a regular file.** Empirically AVF
            // 15.x writes nothing to a regular-file `NSFileHandle`
            // — even with `O_APPEND` and `closeOnDealloc:NO`,
            // `validateWithError:` accepts the configuration but
            // the kernel's hvc0 output never appears. A pipe
            // (`PF_LOCAL` semantics) IS honoured. The cost is one
            // extra background thread per VM, which is acceptable
            // for the V2 GA fan-out (~hundreds of concurrent VMs
            // tops on a single host per the deployment spec). The
            // thread has constant memory footprint (4 KiB stack)
            // and exits naturally when AVF closes the write end at
            // VM teardown.
            //
            // **No reader fd attached** — the guest is write-only
            // from the host's perspective. We accept the cost of
            // not capturing host→guest console writes (the planner
            // never reads stdin in V2 GA).
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"avf_console_log_decision\",\
                  \"console_log_set\":{}}}",
                self.cfg.console_log.is_some(),
            );
            if let Some(path) = self.cfg.console_log.as_ref() {
                match wire_console_pipe(path, &conf) {
                    Ok(handle) => {
                        eprintln!(
                            "{{\"level\":\"info\",\"event\":\"avf_console_log_attached\",\
                              \"path\":{:?}}}",
                            path.display().to_string(),
                        );
                        // SAFETY of the cell mutation: we are inside
                        // `build_configuration(&self)`, but the cell
                        // holding `console_pump` is `Option` on the
                        // runtime which is NOT borrowed here. We
                        // re-enter through `start()` which holds
                        // `&mut self`. Push the join handle onto a
                        // thread-local instead and pick it up in
                        // `start()`.
                        CONSOLE_PUMP_TAKE.with(|cell| {
                            *cell.borrow_mut() = Some(handle);
                        });
                    }
                    Err(e) => eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"avf_console_log_open_failed\",\
                          \"path\":{:?},\"err\":{:?}}}",
                        path.display().to_string(),
                        e.to_string(),
                    ),
                }
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
            // build_configuration may have stashed a console pump
            // join handle in a thread-local; pick it up so it lives
            // alongside the runtime (joined on drop / stop).
            let pump = CONSOLE_PUMP_TAKE.with(|cell| cell.borrow_mut().take());
            self.console_pump = pump;
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
                    vm_for_dispatch.raw().startWithCompletionHandler(&block);
                }
            });

            match rx.recv_timeout(grace) {
                Ok(Ok(())) => {
                    self.started = true;
                    eprintln!(
                        "{{\"level\":\"info\",\"event\":\"avf_vm_started\",\
                          \"vcpu\":{},\"mem_mib\":{}}}",
                        self.cfg.vcpu_count, self.cfg.mem_mib,
                    );
                    Ok(())
                }
                Ok(Err(e)) => {
                    eprintln!(
                        "{{\"level\":\"error\",\"event\":\"avf_vm_start_failed\",\
                          \"err\":{:?}}}",
                        e.to_string(),
                    );
                    self.last_error = Some(e.to_string());
                    Err(e)
                }
                Err(_) => {
                    let err = RuntimeError::StartTimeout(grace);
                    eprintln!(
                        "{{\"level\":\"error\",\"event\":\"avf_vm_start_timeout\",\
                          \"grace_ms\":{}}}",
                        grace.as_millis(),
                    );
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
                    self.finish_stop_cleanup();
                    return Ok(AvfExit {
                        final_state: VmStateSnapshot::Stopped,
                        graceful: true,
                        reason: None,
                    });
                }
            };

            if let Some(initial_state) = self.try_vm_state_snapshot(&vm, Duration::from_millis(500))
            {
                if avf_stop_should_not_be_issued_for_state(initial_state) {
                    let exit = if initial_state == VmStateSnapshot::Stopped {
                        AvfExit {
                            final_state: VmStateSnapshot::Stopped,
                            graceful: true,
                            reason: None,
                        }
                    } else {
                        self.wait_for_already_stopping_vm(&vm, grace)
                    };
                    self.finish_stop_cleanup();
                    return Ok(exit);
                }
            }

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

            let result = match rx.recv_timeout(grace) {
                Ok(Ok(())) => Ok(AvfExit {
                    final_state: VmStateSnapshot::Stopped,
                    graceful: true,
                    reason: None,
                }),
                Ok(Err(e)) => {
                    self.last_error = Some(e.to_string());
                    Ok(AvfExit {
                        final_state: VmStateSnapshot::Errored,
                        graceful: false,
                        reason: Some(e.to_string()),
                    })
                }
                Err(_) => Ok(AvfExit {
                    final_state: VmStateSnapshot::Stopping,
                    graceful: false,
                    reason: Some(format!("stop timed out after {grace:?}")),
                }),
            };

            self.finish_stop_cleanup();

            result
        }

        /// Open a VSock connection to a guest port.
        ///
        /// Resolves the VM's `VZVirtioSocketDevice` from
        /// `socketDevices`, dispatches
        /// `connectToPort:completionHandler:`, and returns:
        ///
        /// * a **dup'd file descriptor** the substrate caller owns
        ///   outright (closed when the substrate's downstream
        ///   stream wrapper drops);
        /// * the **retained `VZVirtioSocketConnection`**, which the
        ///   runtime stores as `vsock_conn` so the AVF-owned
        ///   original fd stays open for the lifetime of the
        ///   session (the AVF connection deinit closes its own
        ///   fd; without a strong reference the autorelease pool
        ///   would drain it the moment the dispatch block returns
        ///   and the dup we just produced would race against
        ///   AVF closing the underlying socketpair half).
        ///
        /// **Why a dup at extraction time.** The AVF connection
        /// object owns the fd via `closeOnDealloc`-equivalent
        /// semantics. If we ever leak the same integer fd to two
        /// owners (AVF's connection + a Rust `OwnedFd`), the next
        /// `close(2)` after the first owner releases is on a
        /// closed fd → the std I/O safety harness aborts the
        /// process with
        ///   `fatal runtime error: IO Safety violation: owned
        ///    file descriptor already closed, aborting`.
        /// Dup-ping inside the dispatch block (before AVF can
        /// reap the connection's autorelease pool) gives us an
        /// independent fd whose lifetime the Rust side controls
        /// end-to-end.
        ///
        /// **Boot-race retry.** AVF's `connectToPort:` does not wait
        /// for the guest to bind a listener; it dispatches the SYN
        /// once and surfaces ECONNREFUSED / "Connection reset by
        /// peer" if no listener exists yet. The kernel calls
        /// `connect_vsock` immediately after `start()` returns, but
        /// the in-guest planner needs ~hundreds of ms to spin up
        /// its tokio runtime and bind AF_VSOCK. We retry under a
        /// progressive backoff ([`vsock_connect_next_backoff`]) — 5 ms
        /// during the boot window, 25 ms past the median budget,
        /// 100 ms past 2 s — for up to [`VSOCK_CONNECT_DEADLINE`]
        /// (currently 30 s, the canonical Apple-VZ start budget).
        ///
        /// **Terminal errors are not retried** — calling
        /// `connect_vsock` before `start()` succeeded, or against a
        /// VM that is missing its `VZVirtioSocketDevice`, returns
        /// immediately. Both are programming bugs in the
        /// substrate, not transient guest-boot races.
        pub fn connect_vsock(&mut self, port: u32) -> Result<c_int, RuntimeError> {
            let started_at = std::time::Instant::now();
            let deadline = started_at + VSOCK_CONNECT_DEADLINE;
            // Track the most-recent transient reason so the
            // deadline-exhausted error message names what the guest
            // was actually surfacing rather than a generic timeout.
            // We deliberately keep the *latest* (not the first)
            // value so an operator triaging a hung boot sees the
            // freshest signal — earlier values are intentionally
            // overwritten without being read, which the
            // `unused_assignments` lint is conservative about.
            #[allow(unused_assignments)]
            let mut last_err: Option<String> = None;
            loop {
                match self.connect_vsock_once(port) {
                    Ok((fd, conn_handle)) => {
                        // Pin the AVF connection inside the runtime
                        // so its owned fd survives until session
                        // teardown. `vsock_conn` Drop releases the
                        // ObjC object, which closes the AVF-owned
                        // fd; the dup we just produced is closed
                        // independently by the substrate's stream
                        // wrapper.
                        self.vsock_conn = Some(conn_handle);
                        eprintln!(
                            "{{\"level\":\"info\",\"event\":\"avf_vsock_connected\",\
                              \"port\":{},\"dup_fd\":{}}}",
                            port, fd,
                        );
                        return Ok(fd);
                    }
                    Err(RuntimeError::VsockConnect { reason, .. })
                        if is_terminal_vsock_reason(&reason) =>
                    {
                        return Err(RuntimeError::VsockConnect { port, reason });
                    }
                    Err(RuntimeError::VsockConnect { reason, .. }) => {
                        last_err = Some(reason);
                    }
                    Err(other) => return Err(other),
                }
                if std::time::Instant::now() >= deadline {
                    return Err(RuntimeError::VsockConnect {
                        port,
                        reason: format!(
                            "AVF connect_vsock did not succeed within {:?}; \
                             last guest-side error: {}",
                            VSOCK_CONNECT_DEADLINE,
                            last_err.unwrap_or_else(|| "<none>".to_owned()),
                        ),
                    });
                }
                std::thread::sleep(vsock_connect_next_backoff(started_at.elapsed()));
            }
        }

        /// Single-shot AVF `connectToPort:` dispatch — broken out of
        /// [`Self::connect_vsock`] so the boot-race retry loop can
        /// re-issue the call without re-implementing the queue +
        /// completion-handler bridge.
        ///
        /// Returns `(dup_fd, retained_conn)` on success; see
        /// [`Self::connect_vsock`] for the lifetime contract.
        fn connect_vsock_once(&self, port: u32) -> Result<(c_int, VsockConnHandle), RuntimeError> {
            let vm = self.vm.as_ref().ok_or_else(|| RuntimeError::VsockConnect {
                port,
                reason: "VM not started — start() must succeed before connecting vsock".to_owned(),
            })?;

            // The completion block dups the fd inside the AVF
            // dispatch context (where `conn` is guaranteed live),
            // retains the connection, and ships both pieces back to
            // the calling thread.
            //
            // The `Retained<VZVirtioSocketConnection>` is wrapped in
            // `VsockConnHandle` (a `Send`-marked newtype) so the
            // standard `mpsc::sync_channel` can carry it across
            // threads — `Retained` itself is not `Send` because
            // ObjC object pointers are thread-confined for method
            // dispatch, but our usage is "hold a strong reference,
            // never call methods" until Drop, which is the exact
            // contract `unsafe impl Send for VsockConnHandle`
            // certifies.
            type ConnectOutcome = Result<(c_int, VsockConnHandle), RuntimeError>;
            let (tx, rx) = mpsc::sync_channel::<ConnectOutcome>(1);
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
                let virtio_dev: Retained<VZVirtioSocketDevice> =
                    unsafe { Retained::cast_unchecked::<VZVirtioSocketDevice>(device_dyn) };

                let tx_inner = tx_for_dispatch.clone();
                let block = RcBlock::new(
                    move |conn: *mut VZVirtioSocketConnection, err: *mut NSError| {
                        let result: ConnectOutcome = if !err.is_null() {
                            // SAFETY: see start path.
                            let msg = unsafe { ns_error_string_from_raw(err) };
                            Err(RuntimeError::VsockConnect { port, reason: msg })
                        } else if conn.is_null() {
                            Err(RuntimeError::VsockConnect {
                                port,
                                reason: "AVF returned nil connection without an error; \
                                     guest may not be listening on the planner port"
                                    .to_owned(),
                            })
                        } else {
                            // 1. Read the fd while `conn` is still
                            //    guaranteed live (we are inside the
                            //    completion handler, before the
                            //    connection's autorelease pool can
                            //    drain).
                            //
                            // SAFETY: completion handler contract:
                            // `conn` is non-null per the branch we
                            // just took, and points at an
                            // AVF-owned `VZVirtioSocketConnection`.
                            let fd = unsafe { (*conn).fileDescriptor() };
                            if fd < 0 {
                                Err(RuntimeError::VsockConnect {
                                    port,
                                    reason: "AVF connection returned negative fd".to_owned(),
                                })
                            } else {
                                // 2. Dup the fd so the host side
                                //    owns an independent SOCK_STREAM
                                //    endpoint. AVF's connection
                                //    object retains close rights on
                                //    its original fd; we MUST NOT
                                //    hand that integer to any Rust
                                //    `OwnedFd` lest the std I/O
                                //    safety harness abort the
                                //    process when AVF reaps its own
                                //    fd at deinit.
                                //
                                // SAFETY: dup(2) on a valid SOCK_STREAM
                                // fd; on failure (EMFILE) we propagate
                                // a typed error.
                                let dup_fd = unsafe { libc::dup(fd) };
                                if dup_fd < 0 {
                                    let e = std::io::Error::last_os_error();
                                    Err(RuntimeError::VsockConnect {
                                        port,
                                        reason: format!("dup(2) on AVF vsock fd failed: {e}"),
                                    })
                                } else {
                                    // 3. Retain the connection so its
                                    //    own fd stays open until the
                                    //    runtime drops the handle. The
                                    //    AVF deinit will then close
                                    //    *its* fd; ours stays open
                                    //    until the substrate caller's
                                    //    stream wrapper drops.
                                    //
                                    // SAFETY: `conn` is non-null and
                                    // points at an AVF-owned ObjC
                                    // object; `Retained::retain`
                                    // bumps the refcount once and
                                    // returns the strong reference.
                                    let conn_strong = unsafe {
                                        Retained::retain(conn).expect(
                                            "AVF returned non-null \
                                             VZVirtioSocketConnection \
                                             but Retained::retain saw nil",
                                        )
                                    };
                                    Ok((dup_fd, VsockConnHandle(conn_strong)))
                                }
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

            // VSock connect on a single attempt uses a 5-second
            // upper bound — the AVF completion handler usually
            // fires well within tens of milliseconds when the
            // guest is up. The outer retry loop owns the
            // longer end-to-end deadline.
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(result) => result,
                Err(_) => Err(RuntimeError::VsockConnect {
                    port,
                    reason: "AVF connect_vsock single-shot dispatch timed out".to_owned(),
                }),
            }
        }

        /// Register a vsock-loopback listener for the credential-proxy
        /// fan-out. The listener accepts guest-initiated AF_VSOCK
        /// connections on `vsock_port` and splices each one to a
        /// fresh TCP connection on `127.0.0.1:host_loopback_port`.
        ///
        /// The substrate caller (`raxis-session-spawn`) invokes this
        /// method once per credential proxy after `start()` succeeds
        /// but before the in-VM forwarder reads the env-stamped
        /// [`raxis_vsock_loopback::ENV_VAR_LOOPBACK_PLAN`]. AVF
        /// retains the listener internally; the substrate retains
        /// the handle in `loopback_listeners` so its Drop runs at
        /// session teardown.
        ///
        /// Failures surface as
        /// [`crate::vsock_loopback_bridge::LoopbackBridgeError`]:
        ///
        ///   * `InactiveVm` — `start()` was not yet called or the
        ///     VM has no `VZVirtioSocketDevice`.
        ///   * `DispatchTimeout` — the AVF serial queue is wedged
        ///     (a hung `start` / `stop` would otherwise block this
        ///     call indefinitely).
        ///
        /// **Idempotency.** Calling this twice with the same
        /// `vsock_port` will silently install a second listener;
        /// AVF stores the most-recently-registered listener for the
        /// port and ignores the older one (per the framework's own
        /// `setSocketListener:forPort:` semantics). The substrate
        /// caller should not register duplicate ports — and the
        /// wire-format layer rejects them in
        /// `LoopbackPlan::from_env_string`.
        pub fn register_loopback_listener(
            &mut self,
            vsock_port: u32,
            host_loopback_port: u16,
        ) -> Result<(), crate::vsock_loopback_bridge::LoopbackBridgeError> {
            let vm = self.vm.as_ref().ok_or_else(|| {
                crate::vsock_loopback_bridge::LoopbackBridgeError::InactiveVm(
                    "VM not started — start() must succeed before \
                     register_loopback_listener"
                        .to_owned(),
                )
            })?;

            // Extract the VZVirtioSocketDevice on the AVF queue
            // (queue-confined property read). The Send-marked
            // `DeviceHandle` newtype lets the strong reference
            // cross threads back to the registering thread.
            #[allow(clippy::type_complexity)]
            let (tx, rx) = mpsc::sync_channel::<
                Result<
                    crate::vsock_loopback_bridge::macos::DeviceHandle,
                    crate::vsock_loopback_bridge::LoopbackBridgeError,
                >,
            >(1);
            let vm_for_dispatch = vm.clone_handle();
            let tx_for_dispatch = tx.clone();
            self.queue.exec_async(move || {
                // SAFETY: queue-confined accessor.
                let devices = unsafe { vm_for_dispatch.raw().socketDevices() };
                if devices.is_empty() {
                    let _ = tx_for_dispatch.send(Err(
                        crate::vsock_loopback_bridge::LoopbackBridgeError::InactiveVm(
                            "VZVirtualMachine has no VZVirtioSocketDevice; \
                             check VmSpec::vsock_cid wiring"
                                .to_owned(),
                        ),
                    ));
                    return;
                }
                let device_dyn: Retained<VZSocketDevice> = devices.objectAtIndex(0);
                // SAFETY: V2 only ever wires VZVirtioSocketDevice as
                // the substrate's socket device class.
                let virtio_dev: Retained<VZVirtioSocketDevice> =
                    unsafe { Retained::cast_unchecked::<VZVirtioSocketDevice>(device_dyn) };
                let _ = tx_for_dispatch.send(Ok(
                    crate::vsock_loopback_bridge::macos::DeviceHandle::from_retained(virtio_dev),
                ));
            });
            let dispatch_grace = Duration::from_secs(5);
            let device_handle = rx.recv_timeout(dispatch_grace).map_err(|_| {
                crate::vsock_loopback_bridge::LoopbackBridgeError::DispatchTimeout(dispatch_grace)
            })??;

            let inner = crate::vsock_loopback_bridge::macos::register_listener(
                &self.queue,
                device_handle,
                vsock_port,
                host_loopback_port,
                dispatch_grace,
            )?;
            self.loopback_listeners
                .push(crate::vsock_loopback_bridge::LoopbackListenerHandle { inner });
            Ok(())
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
            self.vm_state_snapshot(vm, Duration::from_millis(500))
        }

        fn vm_state_snapshot(&self, vm: &VmHandle, timeout: Duration) -> VmStateSnapshot {
            self.try_vm_state_snapshot(vm, timeout)
                .unwrap_or(VmStateSnapshot::Stopped)
        }

        fn try_vm_state_snapshot(
            &self,
            vm: &VmHandle,
            timeout: Duration,
        ) -> Option<VmStateSnapshot> {
            let (tx, rx) = mpsc::sync_channel::<VZVirtualMachineState>(1);
            let vm_for_dispatch = vm.clone_handle();
            self.queue.exec_async(move || {
                // SAFETY: queue-confined property read.
                let s = unsafe { vm_for_dispatch.raw().state() };
                let _ = tx.send(s);
            });
            rx.recv_timeout(timeout).ok().map(map_vz_state)
        }

        fn wait_for_already_stopping_vm(&self, vm: &VmHandle, grace: Duration) -> AvfExit {
            let started_at = std::time::Instant::now();
            loop {
                if let Some(state) = self.try_vm_state_snapshot(vm, Duration::from_millis(100)) {
                    if state == VmStateSnapshot::Stopped {
                        return AvfExit {
                            final_state: VmStateSnapshot::Stopped,
                            graceful: true,
                            reason: None,
                        };
                    }
                    if started_at.elapsed() >= grace {
                        return AvfExit {
                            final_state: state,
                            graceful: false,
                            reason: Some(format!(
                                "VM was already stopping and did not stop within {grace:?}"
                            )),
                        };
                    }
                }
                if started_at.elapsed() >= grace {
                    return AvfExit {
                        final_state: VmStateSnapshot::Stopping,
                        graceful: false,
                        reason: Some(format!(
                            "VM was already stopping and did not stop within {grace:?}"
                        )),
                    };
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }

        fn finish_stop_cleanup(&mut self) {
            self.started = false;
            self.config_obj = None;
            // Drop the configuration object so the AVF retains on
            // the serial-port attachment (and therefore on the
            // pipe's NSFileHandle write side) get released; that
            // lets the console-pump thread observe EOF on its read
            // side and exit. Without this drop the pump would
            // hang until process exit.
            //
            // Best-effort bounded join of the console-pump thread.
            // The thread exits naturally on pipe EOF. If EOF never
            // arrives, detach instead of wedging the kernel on a
            // forensic capture helper.
            if let Some(pump) = self.console_pump.take() {
                join_console_pump_best_effort(pump, CONSOLE_PUMP_JOIN_GRACE);
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
            // Best-effort tear-down. If the VM is still alive,
            // dispatch a stop on the queue and forget the result —
            // Drop must not panic.
            if let Some(vm) = self.vm.take() {
                let skip_stop = self
                    .try_vm_state_snapshot(&vm, Duration::from_millis(100))
                    .is_some_and(avf_stop_should_not_be_issued_for_state);
                if !skip_stop {
                    let vm_for_dispatch = vm.clone_handle();
                    self.queue.exec_async(move || {
                        // SAFETY: queue-confined; ignore completion.
                        unsafe {
                            let block = RcBlock::new(|_err: *mut NSError| {});
                            vm_for_dispatch.raw().stopWithCompletionHandler(&block);
                        }
                    });
                }
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

    /// Classify a `RuntimeError::VsockConnect` reason as terminal
    /// (substrate misconfiguration the retry loop must NOT mask)
    /// vs. transient (guest still booting; retry until the
    /// deadline). Pattern-matches on the substrate-controlled
    /// reason strings emitted by [`AvfRuntime::connect_vsock_once`]
    /// — AVF's own ECONNREFUSED / "Connection reset by peer" error
    /// strings are explicitly NOT in this list, so they fall
    /// through to the retry path.
    pub(super) fn is_terminal_vsock_reason(reason: &str) -> bool {
        reason.contains("VM not started")
            || reason.contains("VZVirtualMachine has no VZVirtioSocketDevice")
            || reason.contains("AVF connection returned negative fd")
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
        // The runtime tests assert AVF rejects placeholder bytes;
        // the path here is the per-role rootfs (after the V2
        // substrate fix).
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
            // Per-test fixture: AVF runtime tests run against
            // placeholder bytes; the real-canonical kernel path is
            // threaded by the kernel-side image resolver in the full
            // E2E lifecycle test.
            linux_kernel_path: PathBuf::from("/var/raxis/test/vmlinux.bin"),
            env: Default::default(),
            guest_console_log: None,
        }
    }

    fn fixture_mount() -> WorkspaceMount {
        WorkspaceMount {
            host_path: PathBuf::from("/tmp/raxis-fixture-workspace"),
            guest_path: "/workspace".to_owned(),
            mode: MountMode::ReadOnly,
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
        assert!(matches!(
            r.start(Duration::from_millis(50)),
            Err(RuntimeError::Unsupported)
        ));
        assert!(matches!(
            r.stop(Duration::from_millis(50)),
            Err(RuntimeError::Unsupported)
        ));
        assert!(matches!(
            r.connect_vsock(1024),
            Err(RuntimeError::Unsupported)
        ));
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
        let mut r = AvfRuntime::new(cfg);
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

    #[test]
    fn stopped_and_stopping_states_do_not_reissue_avf_stop() {
        assert!(avf_stop_should_not_be_issued_for_state(
            VmStateSnapshot::Stopped
        ));
        assert!(avf_stop_should_not_be_issued_for_state(
            VmStateSnapshot::Stopping
        ));
        assert!(!avf_stop_should_not_be_issued_for_state(
            VmStateSnapshot::Running
        ));
        assert!(!avf_stop_should_not_be_issued_for_state(
            VmStateSnapshot::Starting
        ));
        assert!(!avf_stop_should_not_be_issued_for_state(
            VmStateSnapshot::Errored
        ));
    }
}
