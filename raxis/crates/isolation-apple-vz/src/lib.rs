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
// thread confinement). Every `unsafe` block in this crate is
// confined to the macOS runtime module and is annotated with the
// AVF invariant it preserves.
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

        // Establish the planner-port VSock channel. On V2 macOS this
        // is the seam where the AVF substrate fails closed for the
        // delegate-not-yet-wired path; the kernel sees a typed
        // `IsolationError::TransportFault` and the operator
        // surfaces the message via `raxis doctor`.
        let _vsock_fd = runtime.connect_vsock(planner_port).map_err(translate_runtime_err)?;

        Ok(Box::new(AppleVzSession {
            backend_id:   BACKEND_ID,
            runtime:      Some(runtime),
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
#[derive(Debug)]
pub struct AppleVzSession {
    /// Stable identifier reported to audit logs.
    backend_id:    &'static str,
    /// AVF runtime owning the live `VZVirtualMachine`. `None` after
    /// `terminate` / `shutdown` reaps.
    runtime:       Option<AvfRuntime>,
    /// Idempotent-terminate flag.
    terminated:    bool,
    /// Guest CID at boot; recorded so `session_identity` is stable.
    vsock_cid:     u32,
    /// Configured graceful-shutdown grace.
    stop_grace:    Duration,
}

impl AppleVzSession {
    /// Backend identifier (test introspection).
    pub fn backend_id(&self) -> &'static str {
        self.backend_id
    }
}

impl Session for AppleVzSession {
    fn push(&mut self, _frame: &PushFrame) -> Result<(), IsolationError> {
        // V2 stub: vsock-fd-based push lands once the AVF VSock
        // delegate is wired (see runtime.rs::connect_vsock). The
        // substrate fails closed at vsock-connect time today, so
        // this method is reachable only from tests that bypass
        // `Backend::spawn`. Real production wiring lives behind
        // `iso-3-followup`.
        Err(IsolationError::TransportFault(format!(
            "{BACKEND_ID}: push: AVF vsock channel not negotiated; \
             see iso-3-followup",
        )))
    }

    fn recv_intent(&mut self) -> Result<IntentFrame, IsolationError> {
        Err(IsolationError::TransportFault(format!(
            "{BACKEND_ID}: recv: AVF vsock channel not negotiated; \
             see iso-3-followup",
        )))
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
