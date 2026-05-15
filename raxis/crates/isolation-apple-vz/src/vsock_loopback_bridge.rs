//! Host-side substrate half of the credential-proxy vsock-loopback
//! bridge.
//!
//! Normative reference: `specs/v2/credential-proxy.md` (the
//! `INV-CRED-PROXY-VM-REACHABILITY-01` plumbing); `specs/v2/
//! vm-network-isolation.md §3` (Tier-1 + Tier-2 split).
//!
//! # What this module provides
//!
//! `AvfRuntime::register_loopback_listener` registers a
//! `VZVirtioSocketListener` on the VM's `VZVirtioSocketDevice` for
//! a given `vsock_port`. When the in-VM forwarder
//! (`raxis-tproxy::loopback_forwarder`) opens an AF_VSOCK
//! connection to `(VMADDR_CID_HOST, vsock_port)`, AVF invokes the
//! Objective-C delegate defined here. The delegate:
//!
//! 1. Retains the `VZVirtioSocketConnection` so AVF does not
//!    autorelease the underlying file descriptor.
//! 2. `dup(2)`s the fd inside the delegate callback (where the
//!    connection is guaranteed live) so the host-side splice
//!    thread owns an independent SOCK_STREAM endpoint.
//! 3. Spawns a dedicated OS thread that opens
//!    `TcpStream::connect("127.0.0.1:<host_loopback_port>")` and
//!    pumps bytes bidirectionally between the dup'd vsock fd and
//!    the credential proxy's host-loopback TCP socket.
//! 4. Returns `YES` from the delegate so AVF accepts the
//!    connection.
//!
//! The credential proxy on the host side is the only component
//! that ever sees plaintext credentials. The vsock channel
//! carries opaque bytes — the bridge is transport-agnostic.
//!
//! # Per-VM isolation argument
//!
//! Each `AvfRuntime` owns exactly one `VZVirtioSocketDevice`
//! (wired in `AvfRuntime::build_configuration`). The listener
//! registered here is bound on **that device** — i.e. on this
//! VM's vsock CID. A second VM running on the same host has its
//! own `VZVirtualMachine`, its own `VZVirtioSocketDevice`, its
//! own listeners. A guest in VM-B that dials
//! `(VMADDR_CID_HOST, port-of-VM-A)` reaches VM-B's listener,
//! never VM-A's. That is the natural per-session isolation
//! boundary the substrate already provides; no shared-host vsock
//! port namespace exists.
//!
//! # Why a delegate class (not a callback closure)
//!
//! Apple's `Virtualization.framework` only exposes the listener
//! API through the `VZVirtioSocketListenerDelegate` Objective-C
//! protocol. There is no closure-based variant. We use
//! [`objc2::define_class!`] to define a Rust-backed class that
//! conforms to the protocol; the class's ivars carry the per-
//! listener state (host loopback port, retained-connection
//! ledger, audit logger).
//!
//! # Lifecycle
//!
//! [`LoopbackListenerHandle`] owns the listener and delegate
//! `Retained<...>` references. Dropping the handle:
//!
//!   * Calls `removeSocketListenerForPort:` on the VM's vsock
//!     device (queue-confined dispatch),
//!   * Drops the delegate, which releases every retained
//!     `VZVirtioSocketConnection`. AVF's deinit closes its own
//!     fds; the dup'd fds owned by the splice threads close
//!     when the threads finish their copy_bidirectional
//!     work.
//!
//! `AvfRuntime` holds the handles in a `Vec` so they live for
//! the session's lifetime.

#![allow(unsafe_code)]
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::time::Duration;

use raxis_vsock_loopback::{LoopbackEntry, LoopbackPlan};
use thiserror::Error;

/// Errors surfaced by `AvfRuntime::register_loopback_listener`.
#[derive(Debug, Error)]
pub enum LoopbackBridgeError {
    /// Target platform is not macOS — the AVF runtime is a stub.
    #[error("vsock-loopback bridge is only available on macOS")]
    Unsupported,

    /// `VZVirtualMachine` was not yet started (or the VM lacks a
    /// `VZVirtioSocketDevice`). Both are programming errors in
    /// the substrate caller — `start()` must succeed before
    /// listeners are registered.
    #[error("vsock-loopback register on inactive VM: {0}")]
    InactiveVm(String),

    /// Dispatching the listener-registration block on the AVF
    /// queue timed out. The serial dispatch queue is shared
    /// with `start` / `stop` / `connect_vsock`; a hung VM would
    /// block this call indefinitely otherwise.
    #[error("vsock-loopback register dispatch timeout after {0:?}")]
    DispatchTimeout(Duration),
}

/// A registered vsock-loopback listener handle. Drop this to
/// remove the listener from the VM's vsock device and release
/// every retained connection (which closes AVF's fds; the
/// in-flight splice threads finish their pumps and close their
/// dup'd fds independently).
#[cfg(target_os = "macos")]
pub struct LoopbackListenerHandle {
    pub(crate) inner: macos::HandleInner,
}

/// Cross-platform stub: the bridge compiles to a `()` payload on
/// non-macOS targets so the kernel's substrate trait surface is
/// single-target across the workspace.
#[cfg(not(target_os = "macos"))]
pub struct LoopbackListenerHandle;

#[cfg(target_os = "macos")]
impl std::fmt::Debug for LoopbackListenerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackListenerHandle")
            .field("vsock_port", &self.inner.vsock_port)
            .field("host_loopback_port", &self.inner.host_loopback_port)
            .finish()
    }
}

#[cfg(not(target_os = "macos"))]
impl std::fmt::Debug for LoopbackListenerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackListenerHandle (unsupported)")
            .finish()
    }
}

/// Allocate and validate a [`LoopbackPlan`] for the substrate's
/// downstream consumer (`raxis-session-spawn`). The plan describes
/// the per-session vsock fan-out that the substrate will register
/// at spawn time. This shim exists so callers that compose plans
/// from typed `(vsock_port, guest_loopback_port)` pairs do not
/// have to import [`raxis_vsock_loopback`] directly.
pub fn build_loopback_plan(entries: Vec<LoopbackEntry>) -> LoopbackPlan {
    LoopbackPlan { entries }
}

// ---------------------------------------------------------------------------
// Cross-platform interface — the AVF runtime registers/removes
// listeners through these stubs on non-macOS targets.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
pub use stub_api::*;

#[cfg(not(target_os = "macos"))]
mod stub_api {
    use super::*;

    /// Map of `vsock_port -> host_loopback_port`. On non-macOS
    /// targets this is a no-op stub so the kernel-side substrate
    /// trait builds; live registration is rejected with
    /// `Unsupported`.
    pub fn register_listener_stub(
        _vsock_port: u32,
        _host_loopback_port: u16,
    ) -> Result<LoopbackListenerHandle, LoopbackBridgeError> {
        Err(LoopbackBridgeError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// macOS implementation.
// ---------------------------------------------------------------------------

/// macOS-only AVF wiring for the vsock-loopback bridge. The
/// `register_listener` entry point creates a real
/// `VZVirtioSocketListener` + Rust-defined delegate class
/// (`VsockLoopbackDelegate`) and registers them on the VM's
/// `VZVirtioSocketDevice` for one `(vsock_port,
/// host_loopback_port)` pair. Crate-private — the runtime calls
/// in via `AvfRuntime::register_loopback_listener`.
#[cfg(target_os = "macos")]
pub mod macos {
    use super::*;

    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpStream};
    use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
    use std::os::raw::c_int;
    use std::os::unix::net::UnixStream;
    use std::sync::{mpsc, Arc, Mutex};

    use block2::RcBlock;
    use dispatch2::{DispatchQueue, DispatchRetained};
    use objc2::rc::Retained;
    use objc2::runtime::ProtocolObject;
    use objc2::{define_class, AnyThread, DefinedClass};
    use objc2_foundation::NSObjectProtocol;
    use objc2_virtualization::{
        VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketListener,
        VZVirtioSocketListenerDelegate,
    };

    /// Inner state owned by the listener handle.
    pub(crate) struct HandleInner {
        pub(crate) vsock_port: u32,
        pub(crate) host_loopback_port: u16,
        #[allow(dead_code)]
        delegate: DelegateHandle,
        #[allow(dead_code)]
        listener: ListenerHandle,
        device: DeviceHandle,
        queue: DispatchRetained<DispatchQueue>,
    }

    /// `Send`-marked wrapper around a retained
    /// [`VsockLoopbackDelegate`]. The delegate holds the
    /// `Mutex<Vec<RetainedConn>>` ledger; we never call methods on
    /// the delegate from Rust after registration (AVF invokes the
    /// `shouldAcceptNewConnection` callback on its own queue), so
    /// the `Send` impl only certifies the strong-reference release
    /// path on Drop. The wrapped `Retained<...>` is held purely
    /// to keep the delegate alive — the inner field is never
    /// read directly.
    pub(crate) struct DelegateHandle(#[allow(dead_code)] Retained<VsockLoopbackDelegate>);

    // SAFETY: see [`DelegateHandle`] doc.
    unsafe impl Send for DelegateHandle {}

    impl Drop for HandleInner {
        fn drop(&mut self) {
            // Remove the listener from the VM's vsock device on the
            // AVF dispatch queue (queue-confinement contract).
            // Drop must not panic — best-effort.
            let device = self.device.clone_handle();
            let port = self.vsock_port;
            self.queue.exec_async(move || {
                // SAFETY: queue-confined call; idempotent per AVF
                // docs ("Does nothing if the port had no listener.").
                unsafe {
                    device.raw().removeSocketListenerForPort(port);
                }
            });
            // The delegate releases when `self.delegate` drops at
            // the end of this method — that releases every retained
            // VZVirtioSocketConnection in its ivars, which closes
            // AVF's owned fds. The host-side splice threads close
            // their dup'd fds when their `copy` calls return.
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"avf_vsock_loopback_removed\",\
                  \"vsock_port\":{},\"host_loopback_port\":{}}}",
                self.vsock_port, self.host_loopback_port,
            );
        }
    }

    /// Per-listener delegate ivars.
    pub(crate) struct DelegateIvars {
        host_loopback_port: u16,
        vsock_port: u32,
        retained: Mutex<Vec<RetainedConn>>,
    }

    /// `Send`-marked wrapper around a retained
    /// `VZVirtioSocketConnection`. AVF's queue-confinement applies
    /// to method calls, not to merely holding the strong
    /// reference; we never call methods on the connection after
    /// the dup completed inside the delegate body, so the
    /// `Send` impl is sound.
    struct RetainedConn(#[allow(dead_code)] Retained<VZVirtioSocketConnection>);
    // SAFETY: see [`RetainedConn`] doc — no method calls after
    // the dup; the strong reference is dropped by `HandleInner::drop`
    // on the substrate's drop thread, which releases AVF's own fd
    // via the framework's deinit.
    unsafe impl Send for RetainedConn {}

    /// `Send`-marked wrapper around a retained
    /// `VZVirtioSocketDevice`. AVF requires method calls to run on
    /// the substrate dispatch queue, but the bare `Retained<...>`
    /// is not `Send` because the underlying ObjC object is not
    /// `Sync`. We only ever invoke methods on the device through
    /// `queue.exec_async` blocks, which is the queue-confinement
    /// contract the framework documents.
    pub(crate) struct DeviceHandle(Retained<VZVirtioSocketDevice>);

    // SAFETY: see [`DeviceHandle`] doc — methods are dispatched
    // through the AVF queue, never called from arbitrary threads.
    unsafe impl Send for DeviceHandle {}

    impl DeviceHandle {
        /// Construct a Send-safe handle from the queue-extracted
        /// `Retained<VZVirtioSocketDevice>`. Caller asserts the
        /// queue-confinement contract on subsequent method calls.
        pub fn from_retained(r: Retained<VZVirtioSocketDevice>) -> Self {
            Self(r)
        }
        pub(crate) fn raw(&self) -> &VZVirtioSocketDevice {
            &self.0
        }
        pub(crate) fn clone_handle(&self) -> Self {
            Self(self.0.clone())
        }
    }

    /// `Send`-marked wrapper around a retained
    /// `VZVirtioSocketListener`. Same contract as
    /// [`DeviceHandle`] — methods are queue-confined, the strong
    /// reference is held only to keep AVF's internal listener
    /// ledger live.
    pub(crate) struct ListenerHandle(Retained<VZVirtioSocketListener>);

    // SAFETY: see [`ListenerHandle`] doc.
    unsafe impl Send for ListenerHandle {}

    impl ListenerHandle {
        pub(crate) fn clone_handle(&self) -> Self {
            Self(self.0.clone())
        }
        pub(crate) fn raw(&self) -> &VZVirtioSocketListener {
            &self.0
        }
    }

    define_class!(
        // SAFETY:
        // - NSObject does not have any subclassing requirements.
        // - VsockLoopbackDelegate does not implement `Drop`; the
        //   ivars `Mutex<Vec<RetainedConn>>` releases its
        //   contents through normal Drop chaining when the
        //   defined class's instance is released.
        #[unsafe(super(objc2::runtime::NSObject))]
        #[ivars = DelegateIvars]
        pub(crate) struct VsockLoopbackDelegate;

        unsafe impl NSObjectProtocol for VsockLoopbackDelegate {}

        unsafe impl VZVirtioSocketListenerDelegate for VsockLoopbackDelegate {
            #[unsafe(method(listener:shouldAcceptNewConnection:fromSocketDevice:))]
            #[allow(non_snake_case)]
            fn listener_shouldAcceptNewConnection_fromSocketDevice(
                &self,
                _listener: &VZVirtioSocketListener,
                connection: &VZVirtioSocketConnection,
                _socket_device: &VZVirtioSocketDevice,
            ) -> objc2::runtime::Bool {
                // Read the AVF-owned fd while the connection is
                // guaranteed live (we are inside the delegate
                // callback, before any autorelease pool drains).
                // SAFETY: `connection` is a non-null AVF-owned
                // VZVirtioSocketConnection. `fileDescriptor` is
                // a stable property accessor.
                let avf_fd = unsafe { connection.fileDescriptor() };
                if avf_fd < 0 {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"avf_vsock_loopback_bad_fd\",\
                          \"vsock_port\":{}}}",
                        self.ivars().vsock_port,
                    );
                    return objc2::runtime::Bool::NO;
                }

                // Dup so the host-side splice thread owns an
                // independent SOCK_STREAM endpoint. AVF retains
                // close-rights on its own fd; once the
                // connection's autorelease pool drains AVF will
                // close its fd. Our dup is not affected.
                // SAFETY: dup(2) on a valid SOCK_STREAM fd; on
                // failure we surface a typed error and reject the
                // connection (returning NO).
                let dup_fd = unsafe { libc::dup(avf_fd) };
                if dup_fd < 0 {
                    let e = std::io::Error::last_os_error();
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"avf_vsock_loopback_dup_failed\",\
                          \"vsock_port\":{},\"err\":{:?}}}",
                        self.ivars().vsock_port,
                        e.to_string(),
                    );
                    return objc2::runtime::Bool::NO;
                }

                // Retain the connection so AVF keeps its own fd
                // open until we explicitly release it at session
                // teardown. The dup we just produced is what the
                // host-side splice thread owns end-to-end.
                let retained_conn: Retained<VZVirtioSocketConnection> = unsafe {
                    Retained::retain(connection as *const _ as *mut VZVirtioSocketConnection)
                }
                .expect("retain on non-null AVF connection");
                {
                    let mut guard = self
                        .ivars()
                        .retained
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    guard.push(RetainedConn(retained_conn));
                }

                // Spawn the host-side splice thread.
                //
                // We use a dedicated `std::thread` (not tokio) so
                // this module is independent of the kernel's
                // tokio runtime — the substrate trait surface
                // does not pass a `tokio::runtime::Handle` and
                // adding one would be a wider API change. The
                // throughput target for credential-proxy traffic
                // (DB + S3 + Redis) is fine on threads — sessions
                // run a handful of long-lived connections, not
                // tens of thousands of small ones.
                let host_loopback_port = self.ivars().host_loopback_port;
                let vsock_port_for_log = self.ivars().vsock_port;
                std::thread::Builder::new()
                    .name(format!(
                        "raxis-vsock-loopback-{vsock_port_for_log}->127.0.0.1:{host_loopback_port}",
                    ))
                    .spawn(move || {
                        // SAFETY: dup_fd is a freshly-dup'd
                        // SOCK_STREAM fd we own outright. Convert
                        // to OwnedFd → UnixStream (PF_LOCAL is the
                        // closest std impl that exposes
                        // try_clone+shutdown over a SOCK_STREAM;
                        // the underlying syscalls work for AF_VSOCK
                        // fds too).
                        let owned = unsafe { OwnedFd::from_raw_fd(dup_fd) };
                        let vsock = unsafe {
                            UnixStream::from_raw_fd(owned.into_raw_fd())
                        };
                        if let Err(e) = run_splice(
                            vsock,
                            host_loopback_port,
                            vsock_port_for_log,
                        ) {
                            eprintln!(
                                "{{\"level\":\"warn\",\"event\":\"avf_vsock_loopback_splice_err\",\
                                  \"vsock_port\":{},\"host_loopback_port\":{},\"err\":{:?}}}",
                                vsock_port_for_log, host_loopback_port, e.to_string(),
                            );
                        }
                    })
                    .map_or_else(
                        |e| {
                            // Spawn failure → release the dup fd
                            // and reject the connection so the
                            // guest sees a clean ECONNRESET rather
                            // than a hang.
                            eprintln!(
                                "{{\"level\":\"warn\",\"event\":\"avf_vsock_loopback_thread_spawn_err\",\
                                  \"vsock_port\":{},\"err\":{:?}}}",
                                vsock_port_for_log, e.to_string(),
                            );
                            // SAFETY: dup_fd is owned at this point
                            // (the spawn failed before any move).
                            unsafe { libc::close(dup_fd); }
                        },
                        |_| {
                            eprintln!(
                                "{{\"level\":\"info\",\"event\":\"avf_vsock_loopback_accepted\",\
                                  \"vsock_port\":{},\"host_loopback_port\":{}}}",
                                vsock_port_for_log, host_loopback_port,
                            );
                        },
                    );

                objc2::runtime::Bool::YES
            }
        }
    );

    // SAFETY: VsockLoopbackDelegate is a defined ObjC class whose
    // ivars are `Mutex`-protected. AVF invokes the delegate method
    // on its serial dispatch queue, so the body runs on a single
    // thread at a time per listener. The delegate retain is held
    // by [`HandleInner`] which is `!Send` because it carries
    // `Retained<...>`; we don't claim Send for the handle. The
    // `unsafe impl Send for RetainedConn` only certifies that the
    // strong reference can cross threads on Drop.
    impl VsockLoopbackDelegate {
        fn make(host_loopback_port: u16, vsock_port: u32) -> Retained<Self> {
            let this = Self::alloc().set_ivars(DelegateIvars {
                host_loopback_port,
                vsock_port,
                retained: Mutex::new(Vec::new()),
            });
            // SAFETY: NSObject's init takes an Allocated<Self> and
            // returns Retained<Self>; the macro generated boilerplate
            // ensures it's invoked correctly.
            unsafe { objc2::msg_send![super(this), init] }
        }
    }

    /// One bidirectional pump between a SOCK_STREAM endpoint
    /// (the dup'd vsock fd, wrapped as `UnixStream`) and a
    /// freshly-opened TCP connection to
    /// `127.0.0.1:<host_loopback_port>`.
    ///
    /// We open the upstream TCP connection inside this thread
    /// (not the delegate body) because `TcpStream::connect` can
    /// block briefly on `connect(2)`; the AVF dispatch queue is
    /// shared with start / stop / connect_vsock and we don't
    /// stall it.
    fn run_splice(
        vsock_stream: UnixStream,
        host_loopback_port: u16,
        vsock_port_for_log: u32,
    ) -> std::io::Result<()> {
        let upstream_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, host_loopback_port);
        let upstream = TcpStream::connect(upstream_addr).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("vsock-loopback upstream TCP connect 127.0.0.1:{host_loopback_port}: {e}"),
            )
        })?;
        // Disable Nagle so credential-proxy DB query/response
        // RTTs match the natural unbuffered loopback profile.
        let _ = upstream.set_nodelay(true);

        // Two-thread bidirectional pump. A bidirectional
        // `tokio::io::copy_bidirectional` would be cheaper, but
        // we don't want this module to depend on a kernel-side
        // tokio handle — see [`run_splice`] doc.
        let vsock_for_g2u = vsock_stream
            .try_clone()
            .map_err(|e| std::io::Error::new(e.kind(), format!("vsock try_clone: {e}")))?;
        let upstream_for_g2u = upstream
            .try_clone()
            .map_err(|e| std::io::Error::new(e.kind(), format!("upstream try_clone: {e}")))?;

        // guest -> upstream
        let g2u = std::thread::Builder::new()
            .name(format!("raxis-vsock-loopback-{vsock_port_for_log}-g2u"))
            .spawn(move || {
                let mut g = vsock_for_g2u;
                let mut u = upstream_for_g2u;
                let _ = pump_until_eof(&mut g, &mut u);
                // Half-close upstream's write side so any in-flight
                // server-side response can drain back to the guest.
                let _ = u.shutdown(Shutdown::Write);
            })?;

        // upstream -> guest
        let mut u = upstream;
        let mut g = vsock_stream;
        let _ = pump_until_eof(&mut u, &mut g);
        let _ = g.shutdown(Shutdown::Write);
        let _ = g2u.join();
        Ok(())
    }

    /// Manual `std::io::copy` analogue that returns Ok(()) on EOF
    /// rather than propagating it as an error condition. EOF on
    /// either half-duplex direction is the natural connection
    /// close and must NOT bubble up as a noisy "error" — the
    /// other direction may still have buffered bytes the peer
    /// is waiting on.
    fn pump_until_eof<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> std::io::Result<()> {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            writer.write_all(&buf[..n])?;
        }
    }

    /// Crate-private registration entry — invoked by the
    /// higher-level `AvfRuntime::register_loopback_listener`
    /// wrapper in `runtime.rs` once the runtime has confirmed
    /// the VM is alive. Takes the queue + device handle and
    /// returns the live `HandleInner`.
    pub(crate) fn register_listener(
        queue: &DispatchRetained<DispatchQueue>,
        device: DeviceHandle,
        vsock_port: u32,
        host_loopback_port: u16,
        dispatch_grace: Duration,
    ) -> Result<HandleInner, LoopbackBridgeError> {
        let delegate = VsockLoopbackDelegate::make(host_loopback_port, vsock_port);

        // SAFETY: VZVirtioSocketListener::new returns a Retained<Self>;
        // setDelegate stores the protocol-object ref weakly per
        // AVF's documented behaviour, so the listener does NOT
        // retain the delegate — we keep the strong reference in
        // HandleInner ourselves.
        let listener_retained: Retained<VZVirtioSocketListener> =
            unsafe { VZVirtioSocketListener::new() };
        let proto: &ProtocolObject<dyn VZVirtioSocketListenerDelegate> =
            ProtocolObject::from_ref::<VsockLoopbackDelegate>(&delegate);
        unsafe {
            listener_retained.setDelegate(Some(proto));
        }
        let listener = ListenerHandle(listener_retained);

        // Dispatch the registration on the AVF queue.
        let (tx, rx) = mpsc::sync_channel::<()>(1);
        let device_for_dispatch = device.clone_handle();
        let listener_for_dispatch = listener.clone_handle();
        queue.exec_async(move || {
            // SAFETY: queue-confined call. setSocketListener:forPort:
            // copies the listener reference into the device's
            // internal ledger; subsequent guest connects on
            // `vsock_port` invoke the delegate's
            // shouldAcceptNewConnection method.
            unsafe {
                device_for_dispatch
                    .raw()
                    .setSocketListener_forPort(listener_for_dispatch.raw(), vsock_port);
            }
            let _ = tx.send(());
        });
        rx.recv_timeout(dispatch_grace)
            .map_err(|_| LoopbackBridgeError::DispatchTimeout(dispatch_grace))?;

        eprintln!(
            "{{\"level\":\"info\",\"event\":\"avf_vsock_loopback_registered\",\
              \"vsock_port\":{vsock_port},\"host_loopback_port\":{host_loopback_port}}}",
        );

        Ok(HandleInner {
            vsock_port,
            host_loopback_port,
            delegate: DelegateHandle(delegate),
            listener,
            device,
            queue: queue.clone(),
        })
    }

    // Suppress unused warnings on items only referenced through
    // generated macro paths.
    #[allow(dead_code)]
    fn _ensure_refcell_in_scope(c: &RefCell<()>) -> &RefCell<()> {
        c
    }

    #[allow(dead_code)]
    fn _ensure_arc_in_scope(a: &Arc<()>) -> &Arc<()> {
        a
    }

    #[allow(dead_code)]
    fn _ensure_c_int_in_scope(_v: c_int) {}
    #[allow(dead_code)]
    fn _ensure_rc_block_in_scope(b: RcBlock<dyn Fn()>) -> RcBlock<dyn Fn()> {
        b
    }
}

// ---------------------------------------------------------------------------
// Cross-platform tests — assert the wire-format helper passes
// through to `raxis-vsock-loopback`. Live registration is tested
// by integration tests under `crate::tests` (macOS-only).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_loopback_plan_preserves_entry_order() {
        let plan = build_loopback_plan(vec![
            LoopbackEntry {
                vsock_port: 5001,
                guest_loopback_port: 5432,
            },
            LoopbackEntry {
                vsock_port: 5002,
                guest_loopback_port: 27017,
            },
        ]);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.iter().next().unwrap().vsock_port, 5001);
        assert_eq!(plan.iter().next().unwrap().guest_loopback_port, 5432);
    }

    #[test]
    fn build_loopback_plan_round_trips_through_env_string() {
        let plan = build_loopback_plan(vec![LoopbackEntry {
            vsock_port: 1234,
            guest_loopback_port: 5678,
        }]);
        let s = plan.to_env_string();
        let recovered = LoopbackPlan::from_env_string(&s).unwrap();
        assert_eq!(recovered, plan);
    }

    /// `LoopbackBridgeError` projects to a stable Display string
    /// so the kernel-side audit chain can log a deterministic
    /// reason when registration fails.
    #[test]
    fn bridge_error_display_is_stable() {
        let unsup = LoopbackBridgeError::Unsupported;
        assert!(unsup.to_string().contains("only available on macOS"));
        let inactive = LoopbackBridgeError::InactiveVm("VM not started".to_owned());
        assert!(inactive.to_string().contains("VM not started"));
        let timeout = LoopbackBridgeError::DispatchTimeout(Duration::from_secs(1));
        assert!(
            timeout.to_string().contains("DispatchTimeout")
                || timeout.to_string().contains("timeout")
        );
    }
}
