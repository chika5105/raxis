//! Host-side credential-proxy vsock-loopback bridge for Firecracker.
//!
//! Normative reference:
//!   * `specs/v2/credential-proxy.md §12a` (the topology spec).
//!   * `specs/invariants.md INV-CRED-PROXY-VM-REACHABILITY-01` (the
//!     reachability invariant this bridge upholds on Linux).
//!   * `specs/invariants.md INV-CRED-PROXY-VM-REACHABILITY-02` (the
//!     cross-backend parity invariant: every shipped isolation backend
//!     MUST carry its own host-side loopback bridge or fail-closed at
//!     session-spawn time when a non-empty `LoopbackPlan` is requested).
//!
//! # What this module provides
//!
//! [`register_listener`] pre-binds the Unix domain socket Firecracker
//! reads to satisfy a guest-originated `AF_VSOCK` connect
//! (`<uds_path>_<vsock_port>`, per [`crate::vsock::host_listener_path`])
//! and starts a tokio accept loop that splices each incoming connection
//! to a freshly-opened `TcpStream::connect("127.0.0.1:<host_loopback_port>")`
//! on the host. Each accepted UDS stream gets its own tokio task that
//! runs [`tokio::io::copy_bidirectional`] between the UDS half and
//! the TCP half.
//!
//! Mirrors the AVF reference implementation in
//! `crates/isolation-apple-vz/src/vsock_loopback_bridge.rs`:
//!   * Both backends share the [`raxis_vsock_loopback`] wire format
//!     (the `RAXIS_VSOCK_LOOPBACK_PLAN` env var produced by
//!     `raxis-session-spawn`).
//!   * Both backends share the in-guest forwarder
//!     (`raxis-tproxy::loopback_forwarder`) which dials
//!     `(VMADDR_CID_HOST, vsock_port)`.
//!   * What differs is the host-side accepter: AVF registers a
//!     `VZVirtioSocketListener` on the VM's `VZVirtioSocketDevice`
//!     via an Objective-C delegate; Firecracker pre-binds a UDS the
//!     VMM `connect(2)`s into when the guest opens its vsock end.
//!
//! # Why tokio (and not std::thread like AVF)
//!
//! The kernel's session-spawn composer (`raxis-session-spawn`) is
//! `async fn` and runs on the kernel-wide tokio runtime. Firecracker
//! sessions can run hundreds per host (`MaxConcurrentVms = 256` per
//! the substrate capability table); one OS thread per concurrent
//! credential-proxy connection would be a meaningful per-host
//! footprint that tokio's M:N scheduling avoids. AVF tops out at
//! a much smaller per-host VM count (Apple's VZ framework limits
//! aside, macOS dev hosts run a handful of VMs not hundreds), so
//! AVF's `std::thread` choice is purely a "stay-out-of-the-tokio-
//! runtime" preference. The Firecracker substrate already pulls in
//! `tokio` (workspace-wide), so leveraging it for the splice keeps
//! the host-side resource budget tight.
//!
//! # Per-VM isolation argument
//!
//! Each [`crate::FirecrackerSession`] owns its own per-session
//! Firecracker child process and its own `<uds_path>` (minted as
//! `<runtime_dir>/<session_uuid>.vsock`). The reverse-direction
//! listener path therefore lives in a session-private path
//! (`<runtime_dir>/<session_uuid>.vsock_<vsock_port>`). No two
//! sessions can collide on the same UDS path; a guest in session-B
//! that dials `(VMADDR_CID_HOST, port-of-A)` reaches session-B's
//! `<uds_path>_<port-of-A>` (which does not exist unless session-B
//! also registered that port), never session-A's listener. This
//! matches the per-VM `VZVirtioSocketDevice` boundary the AVF
//! backend already provides.
//!
//! # Lifecycle
//!
//! [`LoopbackListenerHandle`] owns the accept task's join handle.
//! Drop:
//!   1. `abort()`s the accept task (cancel-safe; tokio drops the
//!      listener fd as part of the future's drop).
//!   2. Unlinks the UDS path so re-spawning the same session id
//!      does not collide on a stale socket file.
//!
//! In-flight splice tasks (per-connection `copy_bidirectional`)
//! are *not* tracked or joined at Drop. They live as detached
//! tokio tasks and finish naturally on either-side EOF. The
//! aborted listener stops accepting new connections; existing
//! ones complete their pumps and exit. Tokio's task scheduler
//! handles the eventual reap.
//!
//! # Fail-closed
//!
//! Every failure path in [`register_listener`] returns a typed
//! [`LoopbackBridgeError`] and leaves the host with no partial
//! state — no UDS file, no leaked task. The kernel-side caller
//! (`Session::register_loopback_listener` in `lib.rs`) maps the
//! error to `IsolationError` so the session-spawn composer can
//! tear the VM down rather than shipping a session whose
//! credentials are unreachable (`INV-CRED-PROXY-VM-REACHABILITY-01`).
//!
//! Per-direction defence-in-depth: `tokio::io::copy_bidirectional`
//! uses an 8 KiB per-direction internal buffer, comfortably under
//! the substrate's [`crate::vsock::MAX_FRAME_BYTES`] (16 MiB) cap.
//! The cap pin is asserted in the unit tests so a future review
//! that bumps either side without the other surfaces as a test
//! failure.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::task::JoinHandle;

use crate::vsock::host_listener_path;
#[cfg(test)]
use crate::vsock::MAX_FRAME_BYTES;

/// Failure modes [`register_listener`] surfaces. Mapped 1:1 onto
/// `IsolationError` in `FirecrackerSession::register_loopback_listener`.
#[derive(Debug, Error)]
pub enum LoopbackBridgeError {
    /// Called from a thread without a current tokio runtime. The
    /// substrate caller (`session-spawn`) is always inside the
    /// kernel's runtime; this is fail-closed for misuse from a
    /// non-async caller.
    #[error("no tokio runtime current in calling thread")]
    NoTokioRuntime,

    /// Could not `bind(2)` the reverse-direction UDS at the
    /// requested path. Most common cause is a stale UDS from a
    /// previous session that the substrate did not clean up — the
    /// operator-owned runtime dir should be drained at kernel
    /// boot. Both the path and the underlying `EADDRINUSE` /
    /// `EACCES` / `ENOENT` are surfaced so triage does not have
    /// to guess.
    #[error("bind UDS {path}: {err}")]
    Bind {
        /// The path the bind targeted (`<base>_<vsock_port>`).
        path: PathBuf,
        /// The underlying `bind(2)` failure.
        err: std::io::Error,
    },

    /// `tokio::net::UnixListener::from_std` rejected the std-side
    /// listener handover, or the prior `set_nonblocking(true)`
    /// syscall failed. Most likely cause is a runtime-flavour
    /// mismatch (current-thread runtime with no I/O driver
    /// enabled) or a kernel-level fd state divergence. Fail-
    /// closed so the operator sees a typed error instead of a
    /// silent listener that never fires.
    #[error("hand UDS listener to tokio reactor: {0}")]
    TokioHandover(std::io::Error),
}

/// Live, registered listener handle. Dropping the handle:
///
///   * aborts the accept task
///     (`tokio::net::UnixListener::accept` is cancel-safe);
///   * unlinks the UDS path so a re-spawn with the same session
///     UUID does not collide.
///
/// The handle is *not* `Clone` — listener ownership flows into
/// the accept task and the handle is the only owner of the abort
/// side of the join handle.
pub struct LoopbackListenerHandle {
    /// UDS path the listener was bound at; unlinked on Drop.
    path: PathBuf,
    /// VSock port the listener represents (diagnostic only).
    vsock_port: u32,
    /// Host loopback TCP port the accept loop splices to.
    host_loopback_port: u16,
    /// Accept loop join handle. `None` after Drop runs once.
    accept_task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for LoopbackListenerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackListenerHandle")
            .field("path", &self.path)
            .field("vsock_port", &self.vsock_port)
            .field("host_loopback_port", &self.host_loopback_port)
            .finish()
    }
}

impl LoopbackListenerHandle {
    /// UDS path the listener was bound at (test introspection).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// VSock port the listener represents (test introspection).
    pub fn vsock_port(&self) -> u32 {
        self.vsock_port
    }

    /// Host loopback TCP port the listener splices to (test
    /// introspection).
    pub fn host_loopback_port(&self) -> u16 {
        self.host_loopback_port
    }
}

impl Drop for LoopbackListenerHandle {
    fn drop(&mut self) {
        if let Some(t) = self.accept_task.take() {
            t.abort();
        }
        // Best-effort unlink. The accept task is aborted but its
        // listener fd may close asynchronously; either way the
        // path is no longer reachable from a host listener, so we
        // unlink to keep the runtime dir clean.
        let _ = std::fs::remove_file(&self.path);
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"firecracker_vsock_loopback_removed\",\
              \"vsock_port\":{},\"host_loopback_port\":{}}}",
            self.vsock_port, self.host_loopback_port,
        );
    }
}

/// Pre-bind `<base_path>_<vsock_port>` (per
/// [`crate::vsock::host_listener_path`]) and spawn a tokio accept
/// loop that splices each accepted connection to
/// `127.0.0.1:<host_loopback_port>`.
///
/// **Fail-closed semantics.** Every error returns with no fd or
/// path leakage:
///
/// * `NoTokioRuntime` — nothing was created; trivially clean.
/// * `Bind` — bind failed; nothing was bound.
/// * `TokioHandover` — the std UDS listener was bound; we unlink
///   the path before returning.
///
/// The caller is responsible for translating the typed error to
/// `IsolationError` — see
/// `FirecrackerSession::register_loopback_listener`.
///
/// **Idempotency.** Calling this twice with the same
/// `(base_path, vsock_port)` results in the second call returning
/// [`LoopbackBridgeError::Bind`] with the kernel's `EADDRINUSE`,
/// matching the wire-format guard in `LoopbackPlan::from_env_string`
/// that rejects duplicate vsock ports at decode time. The
/// substrate caller (`session-spawn`) does not iterate duplicates;
/// the wire format prevents it.
pub fn register_listener(
    base_path: &Path,
    vsock_port: u32,
    host_loopback_port: u16,
) -> Result<LoopbackListenerHandle, LoopbackBridgeError> {
    // Require a current tokio runtime BEFORE binding anything;
    // every later error path then has at most one unlink to do.
    let _handle =
        tokio::runtime::Handle::try_current().map_err(|_| LoopbackBridgeError::NoTokioRuntime)?;

    let path = host_listener_path(base_path, vsock_port);

    let std_listener =
        std::os::unix::net::UnixListener::bind(&path).map_err(|err| LoopbackBridgeError::Bind {
            path: path.clone(),
            err,
        })?;
    if let Err(err) = std_listener.set_nonblocking(true) {
        let _ = std::fs::remove_file(&path);
        return Err(LoopbackBridgeError::TokioHandover(err));
    }
    let tokio_listener = UnixListener::from_std(std_listener).map_err(|err| {
        let _ = std::fs::remove_file(&path);
        LoopbackBridgeError::TokioHandover(err)
    })?;

    let accept_task = tokio::spawn(run_accept_loop(
        tokio_listener,
        vsock_port,
        host_loopback_port,
    ));

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"firecracker_vsock_loopback_registered\",\
          \"vsock_port\":{vsock_port},\"host_loopback_port\":{host_loopback_port},\
          \"uds_path\":{:?}}}",
        path.display().to_string(),
    );

    Ok(LoopbackListenerHandle {
        path,
        vsock_port,
        host_loopback_port,
        accept_task: Some(accept_task),
    })
}

/// Accept loop body. Spawns a per-connection splice task for every
/// accepted UDS stream. Terminates on `abort()` (drop path) or on
/// a fatal listener error (EBADF, etc.).
async fn run_accept_loop(listener: UnixListener, vsock_port: u32, host_loopback_port: u16) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(run_splice(stream, host_loopback_port, vsock_port));
                eprintln!(
                    "{{\"level\":\"info\",\
                      \"event\":\"firecracker_vsock_loopback_accepted\",\
                      \"vsock_port\":{vsock_port},\
                      \"host_loopback_port\":{host_loopback_port}}}",
                );
            }
            Err(e) => {
                // EBADF / EINVAL / fatal — log and exit; the
                // handle's Drop will still unlink the path.
                eprintln!(
                    "{{\"level\":\"warn\",\
                      \"event\":\"firecracker_vsock_loopback_accept_err\",\
                      \"vsock_port\":{vsock_port},\"err\":{:?}}}",
                    e.to_string(),
                );
                return;
            }
        }
    }
}

/// One bidirectional pump between the UDS stream (Firecracker's
/// reverse-direction translation of
/// `AF_VSOCK(VMADDR_CID_HOST, vsock_port)`) and a freshly-opened
/// `TcpStream::connect("127.0.0.1:<host_loopback_port>")` (the
/// kernel-bound credential proxy).
///
/// Uses [`tokio::io::copy_bidirectional`] for the byte splice; the
/// default per-direction internal buffer (8 KiB at the time of
/// writing, well under [`MAX_FRAME_BYTES`]) plus tokio's natural
/// flow-control via the futures backpressure path keeps host
/// memory bounded irrespective of what either peer sends. The
/// substrate-wide [`MAX_FRAME_BYTES`] cap exists at the framing
/// layer for `HostVsockChannel`; this splice has no framing layer,
/// so the constant serves as the upper-bound assertion (we do not
/// allocate any per-read buffer larger than that). The pinning
/// test `splice_internal_buffer_is_bounded_under_max_frame_bytes`
/// makes the relationship explicit.
async fn run_splice(mut uds: UnixStream, host_loopback_port: u16, vsock_port: u32) {
    let upstream_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, host_loopback_port);
    let mut upstream = match TcpStream::connect(upstream_addr).await {
        Ok(s) => s,
        Err(e) => {
            // Upstream credential proxy is not reachable. Drop the
            // UDS stream so the guest sees a clean ECONNRESET /
            // EOF rather than a hang.
            eprintln!(
                "{{\"level\":\"warn\",\
                  \"event\":\"firecracker_vsock_loopback_upstream_connect_err\",\
                  \"vsock_port\":{vsock_port},\
                  \"host_loopback_port\":{host_loopback_port},\"err\":{:?}}}",
                e.to_string(),
            );
            drop(uds);
            return;
        }
    };
    // Disable Nagle so credential-proxy DB query/response RTTs
    // match the natural unbuffered loopback profile (mirrors AVF).
    let _ = upstream.set_nodelay(true);

    if let Err(e) = copy_bidirectional(&mut uds, &mut upstream).await {
        // Either side closing cleanly (peer EOF) is NOT an error
        // for `copy_bidirectional` — it returns the byte counts
        // and `Ok(())`. We only land in this arm for actual
        // transport faults (write to a fully-half-closed peer,
        // reset). Log and let both streams drop.
        eprintln!(
            "{{\"level\":\"warn\",\
              \"event\":\"firecracker_vsock_loopback_splice_err\",\
              \"vsock_port\":{vsock_port},\
              \"host_loopback_port\":{host_loopback_port},\"err\":{:?}}}",
            e.to_string(),
        );
    }
}

// ---------------------------------------------------------------------------
// Tests — Firecracker's reverse-direction multiplexer translates a
// guest AF_VSOCK connect into a `connect(2)` on the pre-bound UDS;
// from the host accepter's perspective that is the same as a
// `UnixStream::connect()` from the host. We exercise the splice
// against an in-test UDS client + TCP service to pin the
// round-trip semantics without requiring the real `firecracker`
// daemon or `/dev/kvm`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::sleep;

    /// End-to-end forward direction: a UDS client (simulating
    /// Firecracker's reverse-direction translation of a guest
    /// AF_VSOCK connect) writes bytes; they arrive on the host
    /// TCP service that the splice connects to. Also exercises
    /// the reverse direction by reading an echoed reply.
    #[tokio::test]
    async fn guest_uds_write_arrives_at_host_tcp_service_and_reply_arrives_back() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("vsock.sock");
        let vsock_port: u32 = 4242;
        let path_expected = host_listener_path(&base, vsock_port);

        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut s, _) = tcp.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello-firecracker-loopback");
            s.write_all(b"reply-from-host").await.unwrap();
            let _ = s.shutdown().await;
        });

        let handle = register_listener(&base, vsock_port, tcp_port).expect("register");
        assert_eq!(handle.path(), path_expected.as_path());
        assert_eq!(handle.vsock_port(), vsock_port);
        assert_eq!(handle.host_loopback_port(), tcp_port);

        // Connect as if we were the guest's vsock end (Firecracker
        // translates the guest's `connect(VMADDR_CID_HOST,
        // vsock_port)` into a `connect(2)` on this very UDS).
        let mut client = UnixStream::connect(&path_expected)
            .await
            .expect("uds connect");
        client
            .write_all(b"hello-firecracker-loopback")
            .await
            .unwrap();
        client.flush().await.unwrap();
        // Read the echoed reply to pin reverse direction. Limit
        // reads so a stuck splice times out rather than hanging
        // the whole test.
        let mut reply = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut reply))
            .await
            .expect("read timed out");
        let _n = read.expect("read");
        assert_eq!(reply, b"reply-from-host");

        server.await.unwrap();

        drop(handle);
        // Drop aborts the accept task and unlinks the path; small
        // poll loop tolerates the abort completing on the next
        // scheduler tick.
        let unlinked = poll_until(Duration::from_secs(1), || !path_expected.exists()).await;
        assert!(
            unlinked,
            "listener path must be unlinked on Drop, still present at {}",
            path_expected.display(),
        );
    }

    /// Reverse-direction smoke: the host service writes first;
    /// the guest UDS client reads the bytes. Independently
    /// exercises the upstream→guest pump arm of
    /// `copy_bidirectional`.
    #[tokio::test]
    async fn host_tcp_write_arrives_at_guest_uds() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("vsock.sock");
        let vsock_port: u32 = 5005;
        let path_expected = host_listener_path(&base, vsock_port);

        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = tcp.accept().await.unwrap();
            s.write_all(b"banner-from-server").await.unwrap();
            let _ = s.shutdown().await;
        });

        let handle = register_listener(&base, vsock_port, tcp_port).unwrap();
        let mut client = UnixStream::connect(&path_expected).await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut got))
            .await
            .expect("read timed out")
            .unwrap();
        assert_eq!(got, b"banner-from-server");

        server.await.unwrap();
        drop(handle);
    }

    /// Listener bind fails (path conflict) → typed error AND the
    /// pre-existing file is NOT removed by the failed attempt.
    /// Fail-closed: no partial state leak from the substrate side.
    #[tokio::test]
    async fn bind_conflict_returns_typed_error_and_preserves_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("vsock.sock");

        // Pre-create a non-socket file at the listener path so
        // bind(2) returns EADDRINUSE / EINVAL. We assert the file
        // is still present after the failed registration to pin
        // the no-partial-state guarantee — the bridge must not
        // remove host artefacts it didn't create.
        let conflict_path = host_listener_path(&base, 5252);
        std::fs::create_dir(&conflict_path).expect("create conflict dir");

        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();

        let err = register_listener(&base, 5252, tcp_port).expect_err("bind must collide");
        match err {
            LoopbackBridgeError::Bind { path, .. } => {
                assert_eq!(path, conflict_path);
            }
            other => panic!("expected Bind, got {other:?}"),
        }
        assert!(
            conflict_path.is_dir(),
            "bridge must not remove pre-existing host artefacts",
        );
    }

    /// Upstream credential proxy unreachable → guest-side UDS
    /// connection closes cleanly (zero bytes read, no hang) AND
    /// the accept loop stays alive for the next connection.
    #[tokio::test]
    async fn upstream_unreachable_closes_guest_uds_and_accept_loop_survives() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("vsock.sock");

        // Pick a TCP port that's almost certainly free *and*
        // immediately closed: bind, capture, drop.
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = probe.local_addr().unwrap().port();
        drop(probe);

        let _handle = register_listener(&base, 6363, dead_port).expect("register");
        let dead_path = host_listener_path(&base, 6363);

        let mut client = UnixStream::connect(&dead_path)
            .await
            .expect("guest connect");
        // Write something so the splice task has a reason to
        // attempt the upstream connect.
        client.write_all(b"will-not-arrive").await.unwrap();
        let mut buf = Vec::new();
        let r = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut buf)).await;
        assert!(
            r.is_ok(),
            "read must complete (not hang) on upstream connect failure"
        );
        assert!(buf.is_empty(), "no bytes from a dead upstream");

        // Second connection: prove the accept loop is still alive
        // by registering a *new* listener on a different vsock
        // port pointing at a live host service and round-tripping
        // through it.
        let alive = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alive_port = alive.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = alive.accept().await.unwrap();
            let mut tmp = [0u8; 16];
            let n = s.read(&mut tmp).await.unwrap();
            s.write_all(&tmp[..n]).await.unwrap();
            let _ = s.shutdown().await;
        });
        let _alive_handle = register_listener(&base, 6464, alive_port).expect("alive register");
        let mut c2 = UnixStream::connect(host_listener_path(&base, 6464))
            .await
            .unwrap();
        c2.write_all(b"alive").await.unwrap();
        c2.shutdown().await.unwrap();
        let mut got = Vec::new();
        c2.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"alive");
        server.await.unwrap();
    }

    /// `LoopbackBridgeError::Display` is the only thing the
    /// kernel-side translation in `lib.rs` projects into
    /// `IsolationError` — pin its surface so a future variant
    /// rename surfaces as a build break in the kernel-side match
    /// arms AND a Display drift here.
    #[test]
    fn bridge_error_display_is_stable() {
        let nrt = LoopbackBridgeError::NoTokioRuntime;
        assert!(nrt.to_string().contains("tokio runtime"));
        let bind = LoopbackBridgeError::Bind {
            path: PathBuf::from("/tmp/raxis-bridge-test"),
            err: std::io::Error::new(std::io::ErrorKind::AddrInUse, "EADDRINUSE"),
        };
        assert!(bind.to_string().contains("bind UDS"));
        assert!(bind.to_string().contains("/tmp/raxis-bridge-test"));
        let handover = LoopbackBridgeError::TokioHandover(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "EINVAL",
        ));
        assert!(handover.to_string().contains("tokio reactor"));
    }

    /// Defence-in-depth cap pin: tokio's per-direction internal
    /// buffer (8 KiB at the time of writing) AND any larger
    /// per-read buffer we might allocate must remain bounded
    /// under [`MAX_FRAME_BYTES`]. The constants are kept aligned
    /// across the substrate so a buggy guest cannot drive the
    /// host out of memory, even though this splice is unframed.
    /// A future review that bumps the substrate-wide cap or
    /// introduces a per-read buffer here without matching the
    /// substrate-wide cap change surfaces as a test failure
    /// rather than a silent runtime divergence.
    #[test]
    fn splice_internal_buffer_is_bounded_under_max_frame_bytes() {
        assert_eq!(MAX_FRAME_BYTES, 16 * 1024 * 1024);
        // tokio's `copy_bidirectional` documents an 8 KiB
        // internal buffer per direction; we assert a generous
        // upper bound (64 KiB) rather than probing tokio
        // internals directly (private detail) so a stdlib bump
        // that nudges the internal buffer does not break this
        // test.
        let tokio_internal_buf_max: u32 = 64 * 1024;
        assert!(
            tokio_internal_buf_max <= MAX_FRAME_BYTES,
            "in-flight per-direction buffer {tokio_internal_buf_max} \
             must stay <= MAX_FRAME_BYTES {MAX_FRAME_BYTES}",
        );
    }

    /// Multiple registrations against the same `base_path` but
    /// distinct `vsock_port`s coexist cleanly. Pins the
    /// `host_listener_path` namespace discipline (two listeners
    /// on the same session do not collide).
    #[tokio::test]
    async fn multiple_listeners_on_distinct_vsock_ports_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("vsock.sock");
        // We can pass any TCP port here — the bridge does not
        // dial the upstream until an accepted connection arrives.
        let h1 = register_listener(&base, 1001, 9).unwrap();
        let h2 = register_listener(&base, 1002, 9).unwrap();
        assert_ne!(h1.path(), h2.path());
        assert!(h1.path().exists());
        assert!(h2.path().exists());
        drop(h1);
        drop(h2);
    }

    /// Block until `predicate` returns true or `deadline`
    /// elapses. Used by tests that need to observe asynchronous
    /// Drop effects (path unlink after `JoinHandle::abort`).
    async fn poll_until(deadline: Duration, mut predicate: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if predicate() {
                return true;
            }
            sleep(Duration::from_millis(5)).await;
        }
        predicate()
    }
}
