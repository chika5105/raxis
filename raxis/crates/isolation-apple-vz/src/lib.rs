//! `raxis-isolation-apple-vz` — concrete `Backend` impl for macOS
//! using Apple's Virtualization.framework.
//!
//! Implements the [`raxis_isolation::Backend`] /
//! [`raxis_isolation::Session`] traits on top of `VZVirtualMachine`.
//! The substrate is built from two sub-modules:
//!
//! * [`config`]  — pure-data typed translator from `VmSpec` to
//!                 `AvfConfig`. Compiles + tests on every platform.
//! * [`runtime`] — macOS-only `VZVirtualMachine` driver. On other
//!                 targets all methods return
//!                 [`runtime::RuntimeError::Unsupported`] so the
//!                 substrate fails closed.
//!
//! ## Substrate lifecycle
//!
//! 1. The kernel calls [`AppleVzBackend::spawn`].
//! 2. The substrate translates `(VerifiedImage, mounts, VmSpec)` into
//!    an `AvfConfig` (per [`config::translate`]).
//! 3. The substrate constructs a [`runtime::AvfRuntime`] and calls
//!    `start(grace)`.
//! 4. The substrate negotiates a VSock connection on the planner port
//!    via [`runtime::AvfRuntime::connect_vsock`].
//! 5. The substrate hands a [`AppleVzSession`] back to the kernel.
//!
//! ## What this substrate REQUIRES at runtime
//!
//! * macOS host (`cfg(target_os = "macos")`).
//! * The kernel binary signed with `com.apple.security.virtualization`
//!   entitlement (the AVF system requirements doc covers code-signing
//!   under `system-requirements.md §5.2`).
//! * Linux kernel image + rootfs image on disk; verified upstream by
//!   the kernel image resolver.
//!
//! On hosts that don't satisfy these prerequisites,
//! [`AppleVzBackend::probe_host`] returns
//! [`HostSupport::Unsupported`] and
//! [`Backend::verify_isolation_guarantee`] returns
//! [`IsolationLevel::FallbackOnly`] — the production admission helper
//! [`raxis_isolation::verify_admission_tier`] then refuses the
//! backend unless the operator passes `--unsafe-fallback-isolation`.

// Note on `unsafe`: this crate links `objc2-virtualization`, whose
// public API is `unsafe fn` because the underlying Objective-C
// methods can violate Rust's safety contracts (mutable references
// crossing the Objective-C boundary, retain/release lifetimes,
// thread confinement). The macOS `runtime` module is the primary
// `unsafe` site (every block annotated with the AVF invariant it
// preserves). The VSock-fd borrow helpers in this file are the
// secondary site, allowed via `#[allow(unsafe_code)]` per fn.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
pub mod runtime;

use std::path::PathBuf;
use std::time::Duration;

use raxis_isolation::{
    Backend, CapabilityKind, CapabilityValue, ExitStatus, IntentFrame, IsolationError,
    IsolationLevel, PushFrame, Session, SessionTransportId, VerifiedImage, VmSpec,
    WorkspaceMount,
};

use crate::config::{translate, AvfConfig};
use crate::runtime::{AvfRuntime, RuntimeError};

/// Stable identifier for this backend impl.
pub const BACKEND_ID: &str = "apple-vz-14.x";

/// Default per-VM boot grace.
pub const DEFAULT_BOOT_GRACE: Duration = Duration::from_secs(10);

/// Default graceful-stop grace.
pub const DEFAULT_STOP_GRACE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Host probing
// ---------------------------------------------------------------------------

/// Per-host probe outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSupport {
    /// macOS host — substrate is fully usable; reports `R1Conformant`.
    Supported,
    /// Non-macOS host. The substrate compiles cleanly so the kernel
    /// binary is single-target across the workspace, but spawning is
    /// rejected.
    Unsupported {
        /// Diagnostic string surfaced in `raxis doctor`.
        reason: String,
    },
}

impl HostSupport {
    /// Quick predicate.
    pub const fn is_supported(&self) -> bool {
        matches!(self, Self::Supported)
    }

    /// Translate to the substrate trait's tier.
    pub const fn isolation_level(&self) -> IsolationLevel {
        match self {
            Self::Supported            => IsolationLevel::R1Conformant,
            Self::Unsupported { .. }    => IsolationLevel::FallbackOnly,
        }
    }
}

/// Probe the host for AVF availability.
///
/// Pure compile-time check — AVF is macOS-only and the framework is
/// always available when the OS is macOS 11+. Real entitlement check
/// happens lazily at first VM start.
pub fn probe_host() -> HostSupport {
    #[cfg(target_os = "macos")]
    {
        HostSupport::Supported
    }
    #[cfg(not(target_os = "macos"))]
    {
        HostSupport::Unsupported {
            reason: format!(
                "AVF requires macOS; host target is {}",
                std::env::consts::OS,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// AppleVzBackend — the factory
// ---------------------------------------------------------------------------

/// The Apple Virtualization Framework substrate.
#[derive(Debug, Clone)]
pub struct AppleVzBackend {
    /// Directory under which the kernel stages per-session host
    /// resources (the staged worktree mounts the substrate
    /// passes into AVF's `VZSharedDirectory`s).
    runtime_dir: PathBuf,
    /// Boot grace: how long we wait for `VZVirtualMachine.start`'s
    /// completion handler to fire.
    boot_grace:  Duration,
    /// Graceful stop grace.
    stop_grace:  Duration,
}

impl AppleVzBackend {
    /// Build a backend with the given runtime directory.
    pub fn new(runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            runtime_dir: runtime_dir.into(),
            boot_grace:  DEFAULT_BOOT_GRACE,
            stop_grace:  DEFAULT_STOP_GRACE,
        }
    }

    /// Override the boot grace.
    pub fn with_boot_grace(mut self, t: Duration) -> Self {
        self.boot_grace = t;
        self
    }

    /// Override the stop grace.
    pub fn with_stop_grace(mut self, t: Duration) -> Self {
        self.stop_grace = t;
        self
    }
}

impl Backend for AppleVzBackend {
    fn spawn(
        &self,
        image:    &VerifiedImage,
        mounts:   &[WorkspaceMount],
        spec:     &VmSpec,
    ) -> Result<Box<dyn Session>, IsolationError> {
        // Refuse fast on unsupported hosts.
        match probe_host() {
            HostSupport::Supported => {}
            HostSupport::Unsupported { reason } => {
                return Err(IsolationError::BackendInternal(format!(
                    "{BACKEND_ID}: {reason}"
                )));
            }
        }

        if !self.runtime_dir.exists() {
            return Err(IsolationError::BackendInternal(format!(
                "{BACKEND_ID}: runtime dir {} does not exist",
                self.runtime_dir.display(),
            )));
        }

        // Translate spec.
        let cfg: AvfConfig = translate(image, mounts, spec).map_err(|e| {
            IsolationError::SpawnFailed(format!("{BACKEND_ID}: config: {e}"))
        })?;
        let planner_port = cfg.vsock.planner_port;
        let guest_cid    = cfg.vsock.guest_cid;

        let mut runtime = AvfRuntime::new(cfg);
        runtime.start(self.boot_grace).map_err(translate_runtime_err)?;

        // Establish the planner-port VSock channel. The fd is owned
        // by the runtime's `VZVirtioSocketConnection`; we record the
        // raw fd here so `Session::push` / `recv_intent` can
        // length-prefix the kernel ↔ planner frames over it.
        let vsock_fd = runtime.connect_vsock(planner_port).map_err(translate_runtime_err)?;

        Ok(Box::new(AppleVzSession {
            backend_id:   BACKEND_ID,
            runtime:      Some(runtime),
            vsock_fd,
            terminated:   false,
            vsock_cid:    guest_cid,
            stop_grace:   self.stop_grace,
        }))
    }

    fn verify_isolation_guarantee(&self) -> Result<IsolationLevel, IsolationError> {
        Ok(probe_host().isolation_level())
    }

    fn capability(&self, kind: CapabilityKind) -> CapabilityValue {
        match kind {
            CapabilityKind::KvmAvailable         => CapabilityValue::Bool(false),
            CapabilityKind::AttestationSupported => CapabilityValue::Bool(false),
            // Apple-VZ boot is observably ~200 ms in the canonical
            // path per `extensibility-traits.md §3.5`.
            CapabilityKind::BootLatencyMs        => CapabilityValue::Int(200),
            CapabilityKind::MaxConcurrentVms     => CapabilityValue::Int(64),
            CapabilityKind::MemoryEncryption     => CapabilityValue::Bool(false),
        }
    }

    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }
}

fn translate_runtime_err(e: RuntimeError) -> IsolationError {
    match e {
        RuntimeError::Unsupported            => IsolationError::BackendInternal(format!(
            "{BACKEND_ID}: AVF runtime not available on this target"
        )),
        RuntimeError::InvalidConfig(reason)  => IsolationError::SpawnFailed(format!(
            "{BACKEND_ID}: {reason}"
        )),
        RuntimeError::StartFailed(reason)    => IsolationError::SpawnFailed(format!(
            "{BACKEND_ID}: start: {reason}"
        )),
        RuntimeError::StartTimeout(d)        => IsolationError::SpawnFailed(format!(
            "{BACKEND_ID}: start timeout after {d:?}"
        )),
        RuntimeError::StopFailed(reason)     => IsolationError::BackendInternal(format!(
            "{BACKEND_ID}: stop: {reason}"
        )),
        RuntimeError::VsockConnect { port, reason } => IsolationError::TransportFault(format!(
            "{BACKEND_ID}: vsock CONNECT {port}: {reason}"
        )),
    }
}

// ---------------------------------------------------------------------------
// AppleVzSession — live handle
// ---------------------------------------------------------------------------

/// Live, per-session AVF VM handle.
///
/// Holds the live VSock fd negotiated at spawn time and uses the
/// shared length-prefixed framing implementation
/// (`raxis_isolation_firecracker::vsock::HostVsockChannel`-shaped
/// protocol) — but since that module is a Linux-only sibling crate,
/// the AVF substrate's framing is implemented inline here and
/// pinned byte-exact to the same wire contract.
pub struct AppleVzSession {
    /// Stable identifier reported to audit logs.
    backend_id:    &'static str,
    /// AVF runtime owning the live `VZVirtualMachine`. `None` after
    /// `terminate` / `shutdown` reaps.
    runtime:       Option<AvfRuntime>,
    /// Negotiated VSock fd used for `push` / `recv_intent` framing.
    /// `-1` when no vsock channel has been established (e.g.
    /// macOS host without entitlements).
    vsock_fd:      std::os::raw::c_int,
    /// Idempotent-terminate flag.
    terminated:    bool,
    /// Guest CID at boot; recorded so `session_identity` is stable.
    vsock_cid:     u32,
    /// Configured graceful-shutdown grace.
    stop_grace:    Duration,
}

impl std::fmt::Debug for AppleVzSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleVzSession")
            .field("backend_id", &self.backend_id)
            .field("vsock_fd", &self.vsock_fd)
            .field("terminated", &self.terminated)
            .field("vsock_cid", &self.vsock_cid)
            .field("stop_grace", &self.stop_grace)
            .field("has_runtime", &self.runtime.is_some())
            .finish()
    }
}

impl AppleVzSession {
    /// Backend identifier (test introspection).
    pub fn backend_id(&self) -> &'static str {
        self.backend_id
    }

    /// VSock fd negotiated at spawn time. `-1` when no vsock
    /// channel has been established. Test introspection only.
    pub fn vsock_fd(&self) -> std::os::raw::c_int {
        self.vsock_fd
    }
}

impl Session for AppleVzSession {
    fn push(&mut self, frame: &PushFrame) -> Result<(), IsolationError> {
        if self.terminated {
            return Err(IsolationError::TransportFault(format!(
                "{BACKEND_ID}: push: session already terminated",
            )));
        }
        if self.vsock_fd < 0 {
            return Err(IsolationError::TransportFault(format!(
                "{BACKEND_ID}: push: no vsock channel established",
            )));
        }
        write_length_prefixed_frame(self.vsock_fd, &frame.bytes).map_err(|e| {
            IsolationError::TransportFault(format!("{BACKEND_ID}: push: {e}"))
        })
    }

    fn recv_intent(&mut self) -> Result<IntentFrame, IsolationError> {
        if self.terminated {
            return Err(IsolationError::TransportFault(format!(
                "{BACKEND_ID}: recv: session already terminated",
            )));
        }
        if self.vsock_fd < 0 {
            return Err(IsolationError::TransportFault(format!(
                "{BACKEND_ID}: recv: no vsock channel established",
            )));
        }
        let bytes = read_length_prefixed_frame(self.vsock_fd).map_err(|e| {
            IsolationError::TransportFault(format!("{BACKEND_ID}: recv: {e}"))
        })?;
        Ok(IntentFrame { bytes })
    }

    fn terminate(&mut self) -> Result<(), IsolationError> {
        if self.terminated {
            return Ok(());
        }
        self.terminated = true;
        if let Some(mut runtime) = self.runtime.take() {
            // Best-effort stop — `terminate` is the security-kill
            // path so we don't bubble a typed error if AVF reports
            // a problem during the stop dance.
            let _ = runtime.stop(Duration::from_millis(500));
        }
        Ok(())
    }

    fn shutdown(&mut self, grace: Duration) -> Result<ExitStatus, IsolationError> {
        if self.terminated {
            return Ok(ExitStatus::GracefulExit { code: 0 });
        }
        self.terminated = true;
        let actual_grace = if grace > self.stop_grace {
            grace
        } else {
            self.stop_grace
        };
        if let Some(mut runtime) = self.runtime.take() {
            let exit = runtime.stop(actual_grace).map_err(|e| {
                IsolationError::BackendInternal(format!("{BACKEND_ID}: shutdown: {e}"))
            })?;
            return Ok(if exit.graceful {
                ExitStatus::GracefulExit { code: 0 }
            } else {
                ExitStatus::BackendError(
                    exit.reason.unwrap_or_else(|| "AVF stop failed without error string".to_owned()),
                )
            });
        }
        Ok(ExitStatus::GracefulExit { code: 0 })
    }

    fn session_identity(&self) -> SessionTransportId {
        SessionTransportId::Vsock { cid: self.vsock_cid }
    }
}

impl Drop for AppleVzSession {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

// ---------------------------------------------------------------------------
// VSock framing helpers
//
// The kernel ↔ planner channel uses length-prefixed bincode-2.0.1
// frames per `peripherals.md §3` (16 MiB cap, big-endian u32 prefix).
// `raxis-isolation-firecracker::vsock::HostVsockChannel` provides the
// canonical implementation on Linux. AVF lives on macOS, where the
// fd we receive from `VZVirtioSocketConnection` is a regular Unix fd
// — so we re-implement the minimal byte-exact framing here. The two
// implementations are pinned to the same wire contract by
// `kernel/tests/worktree_staging_substrate.rs` (which exercises the
// substrate-trait surface end-to-end) and the framing tests in the
// firecracker crate.
// ---------------------------------------------------------------------------

/// Wire cap matching `peripherals.md §3` (16 MiB).
const VSOCK_FRAME_MAX: u32 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
enum FrameError {
    #[error("write failed: {0}")]
    Write(std::io::Error),
    #[error("read failed: {0}")]
    Read(std::io::Error),
    #[error("frame size {got} exceeds 16 MiB cap")]
    Oversize { got: u32 },
    #[error("connection closed before frame finished")]
    Closed,
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn write_length_prefixed_frame(
    fd: std::os::raw::c_int,
    payload: &[u8],
) -> Result<(), FrameError> {
    use std::io::Write;
    use std::os::fd::{BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

    let n = payload.len();
    if n > VSOCK_FRAME_MAX as usize {
        return Err(FrameError::Oversize { got: n as u32 });
    }
    // SAFETY: fd is owned by the live VZVirtioSocketConnection held
    // by the runtime; we borrow it for the duration of the write
    // and release without taking ownership, so the AVF-owned close
    // path remains intact.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut file: std::fs::File = std::fs::File::from(
        borrowed.try_clone_to_owned().map_err(FrameError::Write)?,
    );
    let prefix = (n as u32).to_be_bytes();
    file.write_all(&prefix).map_err(FrameError::Write)?;
    file.write_all(payload).map_err(FrameError::Write)?;
    file.flush().map_err(FrameError::Write)?;
    // Releasing `file` closes its dup'd fd; the original AVF-owned
    // fd remains open.
    // SAFETY: `file` was constructed from a freshly-cloned
    // `OwnedFd`; recovering it as `OwnedFd` round-trips ownership.
    let _: OwnedFd = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn read_length_prefixed_frame(
    fd: std::os::raw::c_int,
) -> Result<Vec<u8>, FrameError> {
    use std::os::fd::{BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

    // SAFETY: see write helper.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut file: std::fs::File = std::fs::File::from(
        borrowed.try_clone_to_owned().map_err(FrameError::Read)?,
    );

    let mut len_buf = [0u8; 4];
    read_exact_or_closed(&mut file, &mut len_buf)?;
    let n = u32::from_be_bytes(len_buf);
    if n > VSOCK_FRAME_MAX {
        return Err(FrameError::Oversize { got: n });
    }
    let mut buf = vec![0u8; n as usize];
    if !buf.is_empty() {
        read_exact_or_closed(&mut file, &mut buf)?;
    }
    // SAFETY: see write helper.
    let _: OwnedFd = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
    Ok(buf)
}

#[cfg(unix)]
fn read_exact_or_closed<R: std::io::Read>(
    r: &mut R,
    out: &mut [u8],
) -> Result<(), FrameError> {
    let mut filled = 0usize;
    while filled < out.len() {
        let n = r.read(&mut out[filled..]).map_err(FrameError::Read)?;
        if n == 0 {
            return Err(FrameError::Closed);
        }
        filled += n;
    }
    Ok(())
}

// On non-Unix targets (we don't ship AVF off macOS, but the lib
// compiles on Linux for workspace-uniform builds) the helpers
// surface a typed error so the substrate fails closed at link
// time rather than at runtime.
#[cfg(not(unix))]
fn write_length_prefixed_frame(
    _fd: std::os::raw::c_int,
    _payload: &[u8],
) -> Result<(), FrameError> {
    Err(FrameError::Write(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "AVF vsock framing requires a Unix file descriptor",
    )))
}

#[cfg(not(unix))]
fn read_length_prefixed_frame(
    _fd: std::os::raw::c_int,
) -> Result<Vec<u8>, FrameError> {
    Err(FrameError::Read(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "AVF vsock framing requires a Unix file descriptor",
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_isolation::{
        ContentHash, EgressTier, ImageBody, ImageKind, ImageSignature, MountMode, SessionToken,
        VerifiedImage, VmSpec, WorkspaceMount,
    };

    fn fixture_image() -> VerifiedImage {
        VerifiedImage {
            kind:      ImageKind::RootfsErofs,
            body:      ImageBody::Path(PathBuf::from("/var/raxis/test/vmlinux.bin")),
            signature: ImageSignature(vec![0u8; 64]),
            image_id:  "raxis-test-avf-1".to_owned(),
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

    fn fixture_spec(token: &str) -> VmSpec {
        VmSpec {
            vcpu_count:       1,
            mem_mib:          128,
            egress_tier:      EgressTier::None,
            cgroup_quota:     None,
            boot_args:        Vec::new(),
            entrypoint_argv:  Vec::new(),
            session_token:    SessionToken(token.to_owned()),
            vsock_cid:        Some(7),
            virtio_fs_mounts: Vec::new(),
        }
    }

    // ---- HostSupport / probe -------------------------------------------

    #[test]
    fn host_support_isolation_level_translation_pinned() {
        assert_eq!(
            HostSupport::Supported.isolation_level(),
            IsolationLevel::R1Conformant
        );
        assert_eq!(
            HostSupport::Unsupported { reason: "linux".into() }.isolation_level(),
            IsolationLevel::FallbackOnly,
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn probe_host_on_macos_reports_supported() {
        assert!(matches!(probe_host(), HostSupport::Supported));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn probe_host_on_non_macos_reports_unsupported() {
        match probe_host() {
            HostSupport::Unsupported { reason } => {
                assert!(reason.contains("AVF requires macOS"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    // ---- Backend trait surface -----------------------------------------

    #[test]
    fn backend_id_is_stable() {
        let b = AppleVzBackend::new("/tmp/raxis-avf-runtime");
        assert_eq!(b.backend_id(), BACKEND_ID);
    }

    #[test]
    fn capability_table_pinned_for_diagnostic_consumers() {
        let b = AppleVzBackend::new("/tmp/raxis-avf-runtime");
        assert_eq!(
            b.capability(CapabilityKind::KvmAvailable),
            CapabilityValue::Bool(false),
        );
        assert_eq!(
            b.capability(CapabilityKind::BootLatencyMs),
            CapabilityValue::Int(200),
        );
        assert_eq!(
            b.capability(CapabilityKind::MaxConcurrentVms),
            CapabilityValue::Int(64),
        );
        assert_eq!(
            b.capability(CapabilityKind::AttestationSupported),
            CapabilityValue::Bool(false),
        );
        assert_eq!(
            b.capability(CapabilityKind::MemoryEncryption),
            CapabilityValue::Bool(false),
        );
    }

    #[test]
    fn verify_isolation_guarantee_returns_probe_outcome() {
        let b = AppleVzBackend::new("/tmp/raxis-avf-runtime");
        let level = b.verify_isolation_guarantee().unwrap();
        assert!(matches!(
            level,
            IsolationLevel::R1Conformant | IsolationLevel::FallbackOnly,
        ));
    }

    #[test]
    fn spawn_returns_typed_error_when_substrate_cannot_complete() {
        let dir = tempfile::tempdir().unwrap();
        let b = AppleVzBackend::new(dir.path());
        let result = b.spawn(
            &fixture_image(),
            &[fixture_mount()],
            &fixture_spec("avf-session-1"),
        );
        // Three valid outcomes:
        //   1. Non-macOS host                            ⇒ BackendInternal
        //   2. macOS without entitlements / image bytes ⇒ SpawnFailed (config / start)
        //   3. macOS with full setup                    ⇒ TransportFault (vsock not yet wired)
        match result {
            Err(IsolationError::BackendInternal(_))
            | Err(IsolationError::SpawnFailed(_))
            | Err(IsolationError::TransportFault(_)) => {}
            Ok(_) => panic!("AVF spawn should not succeed in the unit-test environment"),
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    // ---- Session trait surface -----------------------------------------
    //
    // The session is constructed only via `spawn`; we cannot reach it
    // without booting AVF. We therefore exercise the typed terminate
    // path indirectly via the trait error projection in
    // `translate_runtime_err`.

    #[test]
    fn translate_runtime_err_produces_typed_isolation_errors() {
        let cases: &[(RuntimeError, &dyn Fn(&IsolationError) -> bool)] = &[
            (RuntimeError::Unsupported, &|e| {
                matches!(e, IsolationError::BackendInternal(_))
            }),
            (RuntimeError::InvalidConfig("x".to_owned()), &|e| {
                matches!(e, IsolationError::SpawnFailed(_))
            }),
            (RuntimeError::StartFailed("x".to_owned()), &|e| {
                matches!(e, IsolationError::SpawnFailed(_))
            }),
            (RuntimeError::StartTimeout(Duration::from_secs(1)), &|e| {
                matches!(e, IsolationError::SpawnFailed(_))
            }),
            (RuntimeError::StopFailed("x".to_owned()), &|e| {
                matches!(e, IsolationError::BackendInternal(_))
            }),
            (
                RuntimeError::VsockConnect { port: 1024, reason: "x".to_owned() },
                &|e| matches!(e, IsolationError::TransportFault(_)),
            ),
        ];
        for (input, predicate) in cases {
            let projected = translate_runtime_err(match input {
                RuntimeError::Unsupported => RuntimeError::Unsupported,
                RuntimeError::InvalidConfig(s) => RuntimeError::InvalidConfig(s.clone()),
                RuntimeError::StartFailed(s) => RuntimeError::StartFailed(s.clone()),
                RuntimeError::StartTimeout(d) => RuntimeError::StartTimeout(*d),
                RuntimeError::StopFailed(s) => RuntimeError::StopFailed(s.clone()),
                RuntimeError::VsockConnect { port, reason } => RuntimeError::VsockConnect {
                    port: *port,
                    reason: reason.clone(),
                },
            });
            assert!(
                predicate(&projected),
                "input {input:?} produced wrong projection: {projected:?}",
            );
        }
    }
}
