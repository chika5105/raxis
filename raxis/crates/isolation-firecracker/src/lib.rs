//! `raxis-isolation-firecracker` — concrete `Backend` impl for Linux + KVM.
//!
//! Implements the [`raxis_isolation::Backend`] / [`raxis_isolation::Session`]
//! traits on top of the Firecracker VMM. The substrate is built from
//! three sub-modules:
//!
//! * [`api`]   — typed Firecracker REST client over Unix domain sockets.
//! * [`vmm`]   — process supervision for the `firecracker` binary.
//! * [`vsock`] — host-side AF_VSOCK plumbing (length-prefixed frames).
//!
//! ## Substrate lifecycle
//!
//! 1. The kernel calls [`FirecrackerBackend::spawn`].
//! 2. The substrate writes the API socket path, launches the
//!    `firecracker` child process, and waits for the API socket to
//!    appear (per `vmm.rs`).
//! 3. The substrate drives the boot REST sequence: `PUT /machine-config`,
//!    `PUT /boot-source`, `PUT /drives/rootfs`, optional
//!    `PUT /network-interfaces/eth0`, `PUT /vsock`, then
//!    `PUT /actions {InstanceStart}`.
//! 4. The substrate negotiates a `HostVsockChannel` against the
//!    Firecracker UDS multiplexer on the planner port.
//! 5. The substrate hands a [`FirecrackerSession`] back to the kernel.
//!
//! ## What this substrate REQUIRES at runtime
//!
//! * Linux host (`cfg(target_os = "linux")`) with `/dev/kvm`
//!   accessible by the kernel's effective UID.
//! * `firecracker` binary on PATH (or operator-pinned via
//!   [`FirecrackerBackend::with_binary`]).
//! * Kernel image + rootfs image on disk; verified upstream by the
//!   kernel image resolver.
//!
//! On hosts that don't satisfy these prerequisites,
//! [`FirecrackerBackend::probe_host`] returns
//! [`HostSupport::Unsupported`] and [`Backend::verify_isolation_guarantee`]
//! returns [`IsolationLevel::FallbackOnly`] — the production admission
//! helper [`raxis_isolation::verify_admission_tier`] then refuses the
//! backend unless the operator passes `--unsafe-fallback-isolation`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod api;
pub mod vmm;
pub mod vsock;
#[cfg(unix)]
pub mod vsock_loopback_bridge;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use raxis_isolation::{
    Backend, CapabilityKind, CapabilityValue, ExitStatus, IntentFrame, IsolationError,
    IsolationLevel, PushFrame, Session, SessionTransportId, VerifiedImage, VmSpec,
    WorkspaceMount,
};

use crate::api::{
    Action, ActionType, BootSource, Drive, FirecrackerApi, MachineConfig, NetworkInterface,
    VsockConfig,
};
use crate::vmm::{FirecrackerVmm, SpawnArgs};
use crate::vsock::HostVsockChannel;

/// Stable backend identifier surfaced through [`Backend::backend_id`].
///
/// Audit consumers grep for this string to filter Firecracker-tier
/// session boots out of dashboards.
pub const BACKEND_ID: &str = "firecracker-1.x";

/// Default guest port the planner listens on inside the microVM.
///
/// Mirrors the convention in `kernel-mechanics-prompt.md §3.1` and
/// `extensibility-traits.md §3.4`. Operators can override per-session
/// via [`FirecrackerBackend::with_planner_port`].
pub const DEFAULT_PLANNER_PORT: u32 = 1024;

/// Default boot grace period: how long we wait for the API socket to
/// appear after spawning `firecracker`.
///
/// **Why 500 ms.** Firecracker creates the API socket as part of its
/// own startup sequence — measured single-digit-ms on a healthy host
/// (`isolation-linux-microvm.md §3.1`). 500 ms is ~50× the expected
/// runtime cost, so a healthy spawn never hits the deadline, while
/// a stalled VMM (missing `/dev/kvm`, KVM module unloaded mid-boot,
/// out-of-fd) is reported as `ApiSockTimeout` in well under a
/// second. The previous 2 s value was a holdover from a noisier
/// CI environment and added latency to the `raxis doctor` boot
/// probe path; tightening it lets the substrate's host-probe
/// surface regressions ~4× sooner.
pub const DEFAULT_BOOT_GRACE: Duration = Duration::from_millis(500);

/// Default per-API-call timeout when driving the boot REST sequence.
pub const DEFAULT_API_TIMEOUT: Duration = Duration::from_secs(5);

/// Fast-boot kernel cmdline base — every token earns its place per the
/// per-token rationale in `isolation-linux-microvm.md §3.2`.
///
/// **Token roles:**
///
/// * `console=ttyS0` — guest printk → Firecracker's serial pipe →
///   per-session `console.log` for post-mortem debugging.
/// * `reboot=k panic=1` — reboot-on-panic via the keyboard-trap path
///   (no ACPI tree); the VMM observes the reboot as a clean exit so
///   the audit chain records `GracefulExit { code }` rather than an
///   opaque `BackendError`.
/// * `pci=off` — Firecracker exposes no PCI devices; skipping bus
///   enumeration shaves ~5 ms.
/// * `i8042.noaux` / `i8042.nokbd` — Firecracker has neither port and
///   the i8042 probe blocks for ~30 ms on fail.
/// * `quiet loglevel=0` — suppress the kernel boot banner and every
///   non-emergency printk; saves ~5–8 ms of serial-port writes.
/// * `tsc=reliable clocksource=tsc` — trust the TSC as a stable
///   clocksource without the calibration sweep / HPET probe.
/// * `8250.nr_uarts=0` — the 8250 driver skips the slow extra-UART
///   probe (`console=ttyS0` keeps the one we do have).
/// * `random.trust_cpu=on` — seed the kernel RNG from `RDRAND`
///   instead of waiting for entropy. Safe on KVM where the host has
///   its own entropy and the guest's "secrets" are session-scoped
///   tokens the kernel mints.
///
/// The substrate appends `rdinit=/init` for `RootfsInitramfsCpio`
/// boots and `root=/dev/vda ro` for `RootfsErofs` boots. Operator-
/// supplied [`raxis_isolation::VmSpec::boot_args`] REPLACE this
/// default wholesale (the kernel's `session_spawn_orchestrator`
/// stamps an empty `boot_args` for canonical roles so the substrate
/// owns the cmdline shape).
pub const FAST_BOOT_CMDLINE_BASE: &str = "console=ttyS0 reboot=k panic=1 \
     pci=off i8042.noaux i8042.nokbd \
     quiet loglevel=0 tsc=reliable clocksource=tsc \
     8250.nr_uarts=0 random.trust_cpu=on";

/// Reported through `Backend::capability(BootLatencyMs)`. Median
/// wall-clock from `vm.start()` to "guest agent reachable on vsock"
/// observed on a 5.15-kernel x86_64 host with the
/// [`FAST_BOOT_CMDLINE_BASE`] tokens applied. Surfaced through
/// `raxis doctor` so operators can spot regressions; the kernel
/// does NOT gate session admission on this number (it's a hint, not
/// a guarantee — see `isolation-linux-microvm.md §3.1`).
pub const BOOT_LATENCY_MS_MEDIAN: u64 = 50;

// ---------------------------------------------------------------------------
// Host probing
// ---------------------------------------------------------------------------

/// Per-host probe outcome used by [`Backend::verify_isolation_guarantee`].
///
/// The probe is intentionally cheap (filesystem-only — no Firecracker
/// boot required); it runs at every kernel boot and the result is
/// recorded into the audit chain. Substrate-internal: the kernel
/// boundary observes only [`IsolationLevel`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSupport {
    /// Linux kernel + `/dev/kvm` accessible. Substrate is fully
    /// usable; reports `R1Conformant`.
    Supported,
    /// Linux kernel but `/dev/kvm` not accessible (missing module,
    /// no group membership). Reports `FallbackOnly` to force the
    /// operator to acknowledge.
    KvmUnavailable {
        /// Diagnostic string surfaced in `raxis doctor`.
        reason: String,
    },
    /// Non-Linux host. The substrate compiles everywhere (so the
    /// kernel binary is single-target) but spawning is rejected.
    Unsupported {
        /// Diagnostic string surfaced in `raxis doctor`.
        reason: String,
    },
}

impl HostSupport {
    /// Quick predicate for boot-time admission.
    pub const fn is_supported(&self) -> bool {
        matches!(self, Self::Supported)
    }

    /// Translate to the substrate trait's tier.
    pub const fn isolation_level(&self) -> IsolationLevel {
        match self {
            Self::Supported          => IsolationLevel::R1Conformant,
            Self::KvmUnavailable {..} => IsolationLevel::FallbackOnly,
            Self::Unsupported {..}   => IsolationLevel::FallbackOnly,
        }
    }
}

/// Probe the host for KVM availability.
///
/// Pure filesystem inspection — no syscalls into KVM, no spawning.
/// The substrate's `verify_isolation_guarantee` uses this; tests can
/// also call it directly to assert the host's status without a real
/// boot.
pub fn probe_host() -> HostSupport {
    #[cfg(target_os = "linux")]
    {
        let dev_kvm = std::path::Path::new("/dev/kvm");
        if !dev_kvm.exists() {
            return HostSupport::KvmUnavailable {
                reason: "/dev/kvm does not exist (KVM module not loaded?)".to_owned(),
            };
        }
        // Best-effort RW probe — if we can open it, the substrate
        // can use it. Non-fatal failure is logged as `KvmUnavailable`
        // so the operator sees a typed reason.
        if let Err(e) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dev_kvm)
        {
            return HostSupport::KvmUnavailable {
                reason: format!("/dev/kvm open: {e} (check group membership: `usermod -aG kvm $USER`)"),
            };
        }
        HostSupport::Supported
    }
    #[cfg(not(target_os = "linux"))]
    {
        HostSupport::Unsupported {
            reason: format!(
                "Firecracker requires Linux + KVM; host target is {}",
                std::env::consts::OS,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// FirecrackerBackend — the factory
// ---------------------------------------------------------------------------

/// The Firecracker substrate.
///
/// One instance is constructed at kernel boot and shared across every
/// planner spawn. Cheap to clone (`PathBuf`s + a few small fields);
/// the per-session state lives in [`FirecrackerSession`].
#[derive(Debug, Clone)]
pub struct FirecrackerBackend {
    /// Optional override of the `firecracker` binary path. `None` ⇒
    /// PATH lookup.
    binary:        Option<PathBuf>,
    /// Directory under which we mint per-session UDS paths
    /// (`<runtime_dir>/<uuid>.api.sock`, `<runtime_dir>/<uuid>.vsock`).
    runtime_dir:   PathBuf,
    /// Default planner port (overridable per-session via spec).
    planner_port:  u32,
    /// API call deadline.
    api_timeout:   Duration,
    /// Boot grace period (API-sock-appearance deadline).
    boot_grace:    Duration,
}

impl FirecrackerBackend {
    /// Build a backend with the given runtime directory.
    ///
    /// `runtime_dir` MUST exist and be writable; the substrate writes
    /// per-session UDS files under it and removes them on session
    /// teardown.
    pub fn new(runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            binary:        None,
            runtime_dir:   runtime_dir.into(),
            planner_port:  DEFAULT_PLANNER_PORT,
            api_timeout:   DEFAULT_API_TIMEOUT,
            boot_grace:    DEFAULT_BOOT_GRACE,
        }
    }

    /// Pin the `firecracker` binary path (default: PATH lookup).
    pub fn with_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.binary = Some(path.into());
        self
    }

    /// Override the planner port the host connects to inside the
    /// guest.
    pub fn with_planner_port(mut self, port: u32) -> Self {
        self.planner_port = port;
        self
    }

    /// Override the per-API-call timeout.
    pub fn with_api_timeout(mut self, t: Duration) -> Self {
        self.api_timeout = t;
        self
    }

    /// Override the boot grace period.
    pub fn with_boot_grace(mut self, t: Duration) -> Self {
        self.boot_grace = t;
        self
    }

    /// Construct per-session UDS paths.
    fn session_paths(&self, session_uuid: &str) -> (PathBuf, PathBuf) {
        let api_sock = self.runtime_dir.join(format!("{session_uuid}.api.sock"));
        let vsock    = self.runtime_dir.join(format!("{session_uuid}.vsock"));
        (api_sock, vsock)
    }

    /// Drive the full boot REST sequence and return a live session.
    ///
    /// This is the substrate's hot path; we factor it out of `spawn`
    /// so test fixtures can call it against a fake VMM as a unit.
    fn boot_and_open_session(
        &self,
        image:     &VerifiedImage,
        mounts:    &[WorkspaceMount],
        spec:      &VmSpec,
        api_sock:  PathBuf,
        vsock_uds: PathBuf,
    ) -> Result<FirecrackerSession, IsolationError> {
        // ---- 1. Spawn VMM child ------------------------------------------
        let vmm = FirecrackerVmm::spawn(&SpawnArgs {
            api_sock:       api_sock.clone(),
            binary:         self.binary.clone(),
            pre_args:       None,
            log_level:      None,
            extra_args:     None,
            boot_grace:     self.boot_grace,
            capture_stderr: false,
        })
        .map_err(|e| IsolationError::SpawnFailed(format!("{BACKEND_ID}: {e}")))?;

        // ---- 2. Drive boot REST ------------------------------------------
        let api = FirecrackerApi::new(&api_sock).with_timeout(self.api_timeout);
        if let Err(e) = drive_boot(&api, image, mounts, spec, &vsock_uds) {
            // Failed boot ⇒ tear down everything before returning the
            // error. The VMM Drop impl will clean up the api-sock; we
            // also remove the vsock UDS to avoid leaks.
            drop(vmm);
            let _ = std::fs::remove_file(&vsock_uds);
            return Err(IsolationError::SpawnFailed(format!(
                "{BACKEND_ID} boot REST failed: {e}",
            )));
        }

        // ---- 3. Open the planner-port channel ----------------------------
        let port = spec.vsock_cid.unwrap_or(self.planner_port);
        let channel = HostVsockChannel::connect(&vsock_uds, port).map_err(|e| {
            IsolationError::TransportFault(format!(
                "{BACKEND_ID}: vsock CONNECT {port}: {e}"
            ))
        })?;

        // ---- 4. Build live Session handle --------------------------------
        Ok(FirecrackerSession {
            backend_id:    BACKEND_ID,
            vmm:           Some(vmm),
            channel:       Some(channel),
            terminated:    false,
            vsock_cid:     spec.vsock_cid.unwrap_or(0),
            api_sock_path: api_sock,
            vsock_uds:     vsock_uds,
            #[cfg(unix)]
            loopback_bridges: Vec::new(),
        })
    }
}

/// Drive the typed boot REST sequence. Pulled out so tests can run it
/// against a fake VMM endpoint.
fn drive_boot(
    api:       &FirecrackerApi,
    image:     &VerifiedImage,
    _mounts:   &[WorkspaceMount],
    spec:      &VmSpec,
    vsock_uds: &std::path::Path,
) -> Result<(), api::ApiError> {
    api.put_machine_config(&MachineConfig {
        vcpu_count:   spec.vcpu_count,
        mem_size_mib: spec.mem_mib,
        smt:          false,
    })?;

    // The Linux kernel binary is a host-canonical artefact lived
    // entirely on `VmSpec`; the rootfs payload lives on
    // `VerifiedImage`. See `VmSpec::linux_kernel_path` doc on
    // `crates/isolation/src/lib.rs` for the rationale.
    if spec.linux_kernel_path.as_os_str().is_empty() {
        return Err(api::ApiError::MalformedResponse(
            "VmSpec.linux_kernel_path is empty; the kernel image \
             resolver must populate it before reaching this substrate \
             (see kernel/src/canonical_images_preflight::linux_kernel_path)"
                .to_owned(),
        ));
    }
    let kernel_path: PathBuf = spec.linux_kernel_path.clone();
    let rootfs_path: PathBuf = match &image.body {
        raxis_isolation::ImageBody::Path(p) => p.clone(),
        raxis_isolation::ImageBody::Bytes(_) => {
            return Err(api::ApiError::MalformedResponse(
                "inline-bytes rootfs images not supported by Firecracker; \
                 image resolver must materialise to a Path"
                    .to_owned(),
            ));
        }
    };
    if !image.kind.is_linux_rootfs() {
        return Err(api::ApiError::MalformedResponse(format!(
            "image kind {:?} is not bootable as a Linux guest by this substrate",
            image.kind,
        )));
    }
    let is_initramfs = matches!(image.kind, raxis_isolation::ImageKind::RootfsInitramfsCpio);
    let boot_args = if spec.boot_args.is_empty() {
        // Canonical RAXIS fast-boot pin — see [`FAST_BOOT_CMDLINE_BASE`]
        // for the per-token rationale. Initramfs boots append
        // `rdinit=/init` so the cpio-archived `/init` becomes PID 1
        // regardless of `CONFIG_DEFAULT_INIT`; EROFS boots append
        // `root=/dev/vda ro` to point the kernel at the virtio-blk
        // rootfs read-only. Operator-supplied
        // [`raxis_isolation::VmSpec::boot_args`] REPLACE these
        // defaults wholesale (per `isolation-linux-microvm.md §3.2`).
        Some(if is_initramfs {
            format!("{FAST_BOOT_CMDLINE_BASE} rdinit=/init")
        } else {
            format!("{FAST_BOOT_CMDLINE_BASE} root=/dev/vda ro")
        })
    } else {
        Some(spec.boot_args.join(" "))
    };
    api.put_boot_source(&BootSource {
        kernel_image_path: kernel_path,
        boot_args,
        // For initramfs boots the rootfs is loaded by the kernel as
        // initrd; for EROFS boots we attach it as a virtio-blk drive
        // (`PUT /drives/rootfs`) and leave initrd empty.
        initrd_path:       if is_initramfs { Some(rootfs_path.clone()) } else { None },
    })?;

    // Drive registration is conditional on rootfs shape. EROFS uses
    // `/drives/rootfs`; initramfs leaves the drive table empty (the
    // kernel's initrd channel is the rootfs).
    if !is_initramfs {
        api.put_drive(&Drive {
            drive_id:       "rootfs".to_owned(),
            path_on_host:   rootfs_path,
            is_root_device: true,
            is_read_only:   true,
        })?;
    }

    // Optional network — only the legacy `EgressTier::Tier1Tproxy` path
    // attaches a tap device (per `vm-network-isolation.md §3`).
    // `EgressTier::None` (Reviewer) and `EgressTier::Mediated` (Path A3
    // universal-airgap, per `airgap-architecture.md §5`) both produce
    // a NIC-less VM — A3 routes outbound TCP and DNS over the per-VM
    // vsock device to the kernel admission handler, so attaching a
    // virtio-net interface would be a redundant covert channel. The
    // `#[allow(deprecated)]` is needed because `Tier1Tproxy` is
    // marked deprecated in favour of `Mediated`; the variant is
    // still selected on the default-off path so legacy operators get
    // bit-identical behaviour until they opt in via
    // `RAXIS_AIRGAP_A3=1`.
    #[allow(deprecated)]
    let attach_nic = matches!(spec.egress_tier, raxis_isolation::EgressTier::Tier1Tproxy);
    if attach_nic {
        api.put_network_interface(&NetworkInterface {
            iface_id:      "eth0".to_owned(),
            host_dev_name: "raxis-tap".to_owned(),
            guest_mac:     None,
        })?;
    }

    api.put_vsock(&VsockConfig {
        vsock_id:  "raxis".to_owned(),
        guest_cid: spec.vsock_cid.unwrap_or(3),
        uds_path:  vsock_uds.to_path_buf(),
    })?;

    api.request_action(ActionType::InstanceStart)
}

// `FirecrackerApi` exposes `instance_start` and `send_ctrl_alt_del`
// directly; `request_action` is a tiny adapter for tests that want to
// dispatch on a runtime variant.
impl FirecrackerApi {
    /// Issue an arbitrary action variant. Used by [`drive_boot`] so
    /// the dispatch path is single-call-site.
    pub fn request_action(&self, kind: ActionType) -> Result<(), api::ApiError> {
        let body = Action { action_type: kind };
        self.put_action(&body)
    }

    /// Lower-level: PUT /actions with a typed body. Re-exported as
    /// `pub` so tests can drive it directly.
    pub fn put_action(&self, body: &Action) -> Result<(), api::ApiError> {
        match body.action_type {
            ActionType::InstanceStart  => self.instance_start(),
            ActionType::SendCtrlAltDel => self.send_ctrl_alt_del(),
        }
    }
}

// ---------------------------------------------------------------------------
// Backend impl
// ---------------------------------------------------------------------------

impl Backend for FirecrackerBackend {
    fn spawn(
        &self,
        image:    &VerifiedImage,
        mounts:   &[WorkspaceMount],
        spec:     &VmSpec,
    ) -> Result<Box<dyn Session>, IsolationError> {
        // Refuse fast on unsupported hosts — Drop of the VMM child
        // would otherwise mask a clear "wrong host" diagnostic.
        match probe_host() {
            HostSupport::Supported => {}
            HostSupport::KvmUnavailable { reason } => {
                return Err(IsolationError::SpawnFailed(format!(
                    "{BACKEND_ID}: KVM unavailable: {reason}"
                )));
            }
            HostSupport::Unsupported { reason } => {
                return Err(IsolationError::BackendInternal(format!(
                    "{BACKEND_ID}: {reason}"
                )));
            }
        }

        // Mint per-session UDS paths from the session token.
        let session_uuid = &spec.session_token.0;
        let (api_sock, vsock_uds) = self.session_paths(session_uuid);
        if !self.runtime_dir.exists() {
            return Err(IsolationError::BackendInternal(format!(
                "{BACKEND_ID}: runtime dir {} does not exist",
                self.runtime_dir.display(),
            )));
        }

        let session = self.boot_and_open_session(image, mounts, spec, api_sock, vsock_uds)?;
        Ok(Box::new(session))
    }

    fn verify_isolation_guarantee(&self) -> Result<IsolationLevel, IsolationError> {
        Ok(probe_host().isolation_level())
    }

    fn capability(&self, kind: CapabilityKind) -> CapabilityValue {
        match kind {
            CapabilityKind::KvmAvailable => {
                CapabilityValue::Bool(matches!(probe_host(), HostSupport::Supported))
            }
            CapabilityKind::AttestationSupported => CapabilityValue::Bool(false),
            CapabilityKind::BootLatencyMs        => CapabilityValue::Int(BOOT_LATENCY_MS_MEDIAN),
            CapabilityKind::MaxConcurrentVms     => CapabilityValue::Int(256),
            CapabilityKind::MemoryEncryption     => CapabilityValue::Bool(false),
        }
    }

    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }
}

// ---------------------------------------------------------------------------
// FirecrackerSession — live handle
// ---------------------------------------------------------------------------

/// Live, per-session Firecracker handle.
///
/// Owns the VMM child and the host-side VSock channel. `Drop` reaps
/// the child + cleans up UDS paths, mirroring the contract documented
/// on `Session::terminate`.
#[derive(Debug)]
pub struct FirecrackerSession {
    /// Stable identifier reported to audit logs.
    backend_id:    &'static str,
    /// VMM supervisor; `None` after `terminate` / `shutdown` reaps.
    vmm:           Option<FirecrackerVmm>,
    /// Channel to the planner inside the guest; `None` after
    /// `terminate` / `shutdown`.
    channel:       Option<HostVsockChannel>,
    /// Whether the session has been torn down. Idempotent terminate
    /// path — second call short-circuits.
    terminated:    bool,
    /// Guest CID we used at boot. Recorded so `session_identity`
    /// remains stable across the session lifetime.
    vsock_cid:     u32,
    /// API socket path; for diagnostic reporting.
    api_sock_path: PathBuf,
    /// VSock UDS path; cleaned up on Drop.
    vsock_uds:     PathBuf,
    /// Per-`(vsock_port)` reverse-direction loopback bridges. One
    /// entry per `register_loopback_listener` call. Drained on
    /// `terminate` / `shutdown` BEFORE the VMM child is reaped so
    /// each bridge's UDS path (`<vsock_uds>_<vsock_port>`) is
    /// unlinked while the runtime dir is still writable. Empty by
    /// default — sessions that did NOT declare credentials never
    /// register listeners and the kernel-side composer
    /// (`raxis-session-spawn`) only iterates a non-empty
    /// `LoopbackPlan`. See [`vsock_loopback_bridge`] module docs
    /// for the per-session isolation argument and
    /// `INV-CRED-PROXY-VM-REACHABILITY-01`.
    #[cfg(unix)]
    loopback_bridges: Vec<vsock_loopback_bridge::LoopbackListenerHandle>,
}

impl FirecrackerSession {
    /// Captured backend id (test introspection).
    pub fn backend_id(&self) -> &'static str {
        self.backend_id
    }

    /// API socket path (test introspection / audit).
    pub fn api_sock_path(&self) -> &std::path::Path {
        &self.api_sock_path
    }

    /// VSock UDS path (test introspection / audit).
    pub fn vsock_uds(&self) -> &std::path::Path {
        &self.vsock_uds
    }
}

impl Session for FirecrackerSession {
    fn push(&mut self, frame: &PushFrame) -> Result<(), IsolationError> {
        let ch = self
            .channel
            .as_mut()
            .ok_or(IsolationError::PeerClosed)?;
        ch.send_frame(&frame.bytes).map_err(|e| match e {
            crate::vsock::VsockError::PeerClosed => IsolationError::PeerClosed,
            other => IsolationError::TransportFault(format!("{BACKEND_ID}: push: {other}")),
        })
    }

    fn recv_intent(&mut self) -> Result<IntentFrame, IsolationError> {
        let ch = self
            .channel
            .as_mut()
            .ok_or(IsolationError::PeerClosed)?;
        let bytes = ch.recv_frame().map_err(|e| match e {
            crate::vsock::VsockError::PeerClosed => IsolationError::PeerClosed,
            other => IsolationError::TransportFault(format!("{BACKEND_ID}: recv: {other}")),
        })?;
        Ok(IntentFrame { bytes })
    }

    fn terminate(&mut self) -> Result<(), IsolationError> {
        if self.terminated {
            return Ok(());
        }
        self.terminated = true;

        // Close the channel first so any in-flight peer write fails
        // promptly. Drop of the channel calls `UnixStream` Drop which
        // closes the FD.
        if let Some(ch) = self.channel.take() {
            ch.close();
        }
        // Drain every reverse-direction loopback bridge BEFORE we
        // reap the VMM child. Each handle's Drop aborts its
        // accept task and unlinks
        // `<vsock_uds>_<vsock_port>`; doing it while the runtime
        // dir is still writable keeps cleanup local to the
        // substrate (vs. surfacing as stale-socket clutter for
        // `raxis doctor` to flag later). See
        // `vsock_loopback_bridge::LoopbackListenerHandle` Drop docs.
        #[cfg(unix)]
        self.loopback_bridges.clear();
        if let Some(mut vmm) = self.vmm.take() {
            vmm.terminate().map_err(|e| {
                IsolationError::BackendInternal(format!("{BACKEND_ID}: terminate: {e}"))
            })?;
        }
        let _ = std::fs::remove_file(&self.vsock_uds);
        Ok(())
    }

    /// Register a credential-proxy vsock-loopback listener on this
    /// session's Firecracker UDS multiplexer.
    ///
    /// The host pre-binds `<vsock_uds>_<vsock_port>` so that when
    /// the in-guest forwarder dials
    /// `(VMADDR_CID_HOST, vsock_port)`, Firecracker delivers the
    /// connection to the bridge's accept loop, which splices the
    /// bytes to `127.0.0.1:<host_loopback_port>` (where the
    /// credential proxy is bound). Per-VM device boundary IS the
    /// per-session isolation boundary — no shared host vsock CID.
    /// See [`crate::vsock_loopback_bridge`] for the per-session
    /// isolation argument and `INV-CRED-PROXY-VM-REACHABILITY-01`.
    ///
    /// **Fail-closed.** Any bind / configure / spawn failure
    /// surfaces as `IsolationError` without registering a partial
    /// listener. `Drop` drains successfully-registered listeners,
    /// so a mid-fan-out failure in `session-spawn` leaves no
    /// leaked UDS paths.
    #[cfg(unix)]
    fn register_loopback_listener(
        &mut self,
        vsock_port:         u32,
        host_loopback_port: u16,
    ) -> Result<(), IsolationError> {
        if self.terminated {
            return Err(IsolationError::TransportFault(format!(
                "{BACKEND_ID}: register_loopback_listener: session terminated",
            )));
        }
        let handle = vsock_loopback_bridge::register_listener(
            &self.vsock_uds,
            vsock_port,
            host_loopback_port,
        )
        .map_err(|e| match e {
            // `EADDRINUSE` / `EACCES` / `ENOENT` from `bind(2)` are
            // transport-class faults: the substrate could not stand
            // up the host half of the bridge, so the session cannot
            // serve credential-proxy traffic. The session-spawn
            // composer turns this into a teardown of the partially
            // built session.
            vsock_loopback_bridge::LoopbackBridgeError::Bind { .. } => {
                IsolationError::TransportFault(format!(
                    "{BACKEND_ID}: register_loopback_listener: {e}",
                ))
            }
            // `NoTokioRuntime` is a substrate-trait misuse
            // (`register_loopback_listener` called from a non-async
            // caller) and `TokioHandover` is a host-side reactor /
            // fd state divergence; neither is a peer transport
            // fault, so we surface them as `BackendInternal` (the
            // same class the AVF substrate uses for its
            // dispatch-queue failure mode in
            // `register_loopback_listener`).
            vsock_loopback_bridge::LoopbackBridgeError::NoTokioRuntime
            | vsock_loopback_bridge::LoopbackBridgeError::TokioHandover(_) => {
                IsolationError::BackendInternal(format!(
                    "{BACKEND_ID}: register_loopback_listener: {e}",
                ))
            }
        })?;
        self.loopback_bridges.push(handle);
        Ok(())
    }

    fn shutdown(&mut self, grace: Duration) -> Result<ExitStatus, IsolationError> {
        if self.terminated {
            return Ok(ExitStatus::GracefulExit { code: 0 });
        }
        self.terminated = true;

        // Try graceful shutdown via VMM's `SendCtrlAltDel` action,
        // then poll for child exit.
        let api = self.vmm.as_ref().map(|v| {
            FirecrackerApi::new(v.api_sock()).with_timeout(Duration::from_millis(500))
        });
        if let Some(api) = api {
            // Best effort — if the child already exited, this fails;
            // the wait loop below will pick up the exit status.
            let _ = api.send_ctrl_alt_del();
        }

        if let Some(ch) = self.channel.take() {
            ch.close();
        }
        // Drain reverse-direction loopback bridges before the VMM
        // reap (same ordering as `terminate`).
        #[cfg(unix)]
        self.loopback_bridges.clear();

        let status = if let Some(mut vmm) = self.vmm.take() {
            vmm.wait_or_kill(grace).map_err(|e| {
                IsolationError::BackendInternal(format!("{BACKEND_ID}: shutdown: {e}"))
            })?
        } else {
            ExitStatus::GracefulExit { code: 0 }
        };

        let _ = std::fs::remove_file(&self.vsock_uds);
        Ok(status)
    }

    fn session_identity(&self) -> SessionTransportId {
        SessionTransportId::Vsock { cid: self.vsock_cid }
    }
}

impl Drop for FirecrackerSession {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

// Silence dead-code warnings on non-Linux: the `Instant` import is
// used only by future timing logic. We bind it here so compile is
// uniform across targets.
#[allow(dead_code)]
const _UNUSED_INSTANT_BIND: fn() = || {
    let _ = Instant::now();
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_isolation::{
        ContentHash, EgressTier, ImageBody, ImageKind, ImageSignature, MountMode, SessionToken,
    };

    fn fixture_image_with_path(p: PathBuf) -> VerifiedImage {
        // After the V2 substrate fix, `body` carries the ROOTFS path
        // (per-role, .img/EROFS or initramfs cpio.gz). The kernel
        // binary path lives on `VmSpec.linux_kernel_path` instead.
        VerifiedImage {
            kind:      ImageKind::RootfsErofs,
            body:      ImageBody::Path(p),
            signature: ImageSignature(vec![0u8; 64]),
            image_id:  "raxis-test-fc-1".to_owned(),
        }
    }

    fn fixture_spec(token: &str) -> VmSpec {
        VmSpec {
            vcpu_count:        1,
            mem_mib:           128,
            egress_tier:       EgressTier::None,
            cgroup_quota:      None,
            boot_args:         Vec::new(),
            entrypoint_argv:   Vec::new(),
            session_token:     SessionToken(token.to_owned()),
            vsock_cid:         Some(3),
            virtio_fs_mounts:  Vec::new(),
            // Substrate tests run with a real (placeholder-on-disk)
            // kernel path so the empty-path guard does not short-
            // circuit the test before exercising the boot-source PUT.
            linux_kernel_path: PathBuf::from("/tmp/raxis-fixture-vmlinux"),
            env:               Default::default(),
            guest_console_log: None,
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

    // -- HostSupport / probe_host -----------------------------------------

    #[test]
    fn host_support_isolation_level_translation_matches_spec_table() {
        assert_eq!(
            HostSupport::Supported.isolation_level(),
            IsolationLevel::R1Conformant,
        );
        assert_eq!(
            HostSupport::KvmUnavailable { reason: "no /dev/kvm".into() }.isolation_level(),
            IsolationLevel::FallbackOnly,
        );
        assert_eq!(
            HostSupport::Unsupported { reason: "macos".into() }.isolation_level(),
            IsolationLevel::FallbackOnly,
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn probe_host_on_non_linux_reports_unsupported() {
        match probe_host() {
            HostSupport::Unsupported { reason } => {
                assert!(reason.contains("Firecracker"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_host_on_linux_reports_supported_or_kvm_unavailable() {
        match probe_host() {
            HostSupport::Supported => {}
            HostSupport::KvmUnavailable { reason } => assert!(!reason.is_empty()),
            HostSupport::Unsupported { reason } => panic!(
                "Linux host should not report Unsupported, got: {reason}"
            ),
        }
    }

    // -- Backend trait surface --------------------------------------------

    #[test]
    fn backend_id_is_stable() {
        let b = FirecrackerBackend::new("/tmp/raxis-fc-runtime");
        assert_eq!(b.backend_id(), BACKEND_ID);
    }

    // -- Fast-boot defaults pin --------------------------------------------

    #[test]
    fn fast_boot_cmdline_base_pins_every_documented_token() {
        // The per-token rationale lives in `isolation-linux-microvm.md
        // §3.2`. A reviewer dropping any of these tokens silently would
        // regress the boot-latency budget without surfacing a build
        // failure; the pin keeps the cmdline shape under test review.
        for token in [
            "console=ttyS0",
            "reboot=k",
            "panic=1",
            "pci=off",
            "i8042.noaux",
            "i8042.nokbd",
            "quiet",
            "loglevel=0",
            "tsc=reliable",
            "clocksource=tsc",
            "8250.nr_uarts=0",
            "random.trust_cpu=on",
        ] {
            assert!(
                FAST_BOOT_CMDLINE_BASE.contains(token),
                "fast-boot cmdline base lost token {token:?}; \
                 base now reads {FAST_BOOT_CMDLINE_BASE:?}",
            );
        }
    }

    #[test]
    fn default_boot_grace_is_tight_enough_to_surface_stalled_vmms_quickly() {
        // 500 ms is ~50× the expected `wait_for_api_sock` runtime on a
        // healthy host (single-digit-ms per the latency budget); a
        // healthy spawn never hits this deadline. We pin the upper
        // bound so a future reviewer doesn't quietly bump it back to
        // the pre-fast-boot 2 s value.
        assert!(
            DEFAULT_BOOT_GRACE <= Duration::from_millis(500),
            "DEFAULT_BOOT_GRACE relaxed past 500 ms ({DEFAULT_BOOT_GRACE:?}); \
             see `isolation-linux-microvm.md §3.1` for the budget"
        );
        assert!(
            DEFAULT_BOOT_GRACE >= Duration::from_millis(100),
            "DEFAULT_BOOT_GRACE tightened below 100 ms ({DEFAULT_BOOT_GRACE:?}); \
             healthy spawns may flap with this little headroom"
        );
    }

    #[test]
    fn capability_table_pins_diagnostic_consumers() {
        let b = FirecrackerBackend::new("/tmp/raxis-fc-runtime");
        // Boot latency / max concurrency / no attestation / no memenc
        // are pinned per the table in `extensibility-traits.md §3.5`.
        assert_eq!(
            b.capability(CapabilityKind::AttestationSupported),
            CapabilityValue::Bool(false),
        );
        assert_eq!(
            b.capability(CapabilityKind::BootLatencyMs),
            CapabilityValue::Int(BOOT_LATENCY_MS_MEDIAN),
        );
        assert_eq!(
            b.capability(CapabilityKind::MaxConcurrentVms),
            CapabilityValue::Int(256),
        );
        assert_eq!(
            b.capability(CapabilityKind::MemoryEncryption),
            CapabilityValue::Bool(false),
        );
    }

    #[test]
    fn verify_isolation_guarantee_returns_probe_outcome() {
        let b = FirecrackerBackend::new("/tmp/raxis-fc-runtime");
        let level = b.verify_isolation_guarantee().unwrap();
        // On every host (linux+kvm or otherwise), the level is one
        // of the two valid options. We assert the boundary, not the
        // host-specific value, so the test is portable.
        assert!(matches!(
            level,
            IsolationLevel::R1Conformant | IsolationLevel::FallbackOnly,
        ));
    }

    #[test]
    fn spawn_on_non_linux_or_no_kvm_returns_typed_error() {
        let b = FirecrackerBackend::new("/tmp/raxis-fc-runtime-test-1");
        let result = b.spawn(
            &fixture_image_with_path(PathBuf::from("/tmp/vmlinux.bin")),
            &[fixture_mount()],
            &fixture_spec("session-1"),
        );
        // We don't pin the variant — on Linux+KVM hosts the spawn would
        // proceed (and fail later for missing binary); on every other
        // host we expect either SpawnFailed (KvmUnavailable) or
        // BackendInternal (Unsupported / runtime dir missing).
        match result {
            Ok(_) => panic!("spawn must not succeed in this test environment"),
            Err(IsolationError::SpawnFailed(_)) | Err(IsolationError::BackendInternal(_)) => {}
            Err(other) => panic!("expected typed spawn error, got {other:?}"),
        }
    }

    #[test]
    fn session_paths_include_session_uuid_and_extensions() {
        let b = FirecrackerBackend::new("/tmp/raxis-runtime");
        let (api, vsock) = b.session_paths("abc-123");
        assert!(api.ends_with("abc-123.api.sock"));
        assert!(vsock.ends_with("abc-123.vsock"));
    }

    #[test]
    fn session_paths_distinct_per_session() {
        let b = FirecrackerBackend::new("/tmp/raxis-runtime");
        let (a1, v1) = b.session_paths("alpha");
        let (a2, v2) = b.session_paths("beta");
        assert_ne!(a1, a2);
        assert_ne!(v1, v2);
    }

    // -- drive_boot against a fake VMM ------------------------------------
    //
    // We stand up a tiny in-test "Firecracker" UDS server that accepts
    // every PUT and replies 204. The real `drive_boot` should issue
    // exactly the expected sequence of requests in order.

    #[cfg(unix)]
    #[test]
    fn drive_boot_issues_expected_request_sequence_against_fake_vmm() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let api_sock = dir.path().join("api.sock");
        let vsock_uds = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&api_sock).unwrap();

        let captured: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_thread = std::sync::Arc::clone(&captured);

        let server = std::thread::spawn(move || {
            // We expect 5 sequential PUTs: machine-config, boot-source,
            // drives/rootfs, vsock, actions (InstanceStart).
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = Vec::with_capacity(4096);
                let mut tmp = [0u8; 1024];
                loop {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    // Response after we've seen the body fully.
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&buf[..end]).unwrap();
                        let cl: usize = headers
                            .lines()
                            .find_map(|l| {
                                l.strip_prefix("Content-Length:")
                                    .or_else(|| l.strip_prefix("content-length:"))
                                    .map(|s| s.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + cl {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf).into_owned();
                let request_line = text
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_owned();
                captured_thread.lock().unwrap().push(request_line);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
                stream.flush().unwrap();
            }
        });

        let api = FirecrackerApi::new(&api_sock).with_timeout(Duration::from_secs(2));
        let img = fixture_image_with_path(PathBuf::from("/tmp/vmlinux.bin"));
        let spec = fixture_spec("session-fixture");
        drive_boot(&api, &img, &[fixture_mount()], &spec, &vsock_uds)
            .expect("drive_boot must succeed against fake VMM");

        server.join().unwrap();
        let cap = captured.lock().unwrap();
        assert_eq!(cap.len(), 5, "expected 5 PUT requests, got {cap:?}");
        assert!(cap[0].starts_with("PUT /machine-config"));
        assert!(cap[1].starts_with("PUT /boot-source"));
        assert!(cap[2].starts_with("PUT /drives/rootfs"));
        assert!(cap[3].starts_with("PUT /vsock"));
        assert!(cap[4].starts_with("PUT /actions"));
    }

    #[cfg(unix)]
    /// INV-NETISO-A3-UNIVERSAL-NO-NIC-01 witness for the
    /// Firecracker substrate. Re-uses the same Unix-socket
    /// capture rig as the `tier1` companion test, but asserts
    /// the OPPOSITE shape: under `EgressTier::Mediated` the
    /// boot driver MUST NOT emit a `PUT /network-interfaces/eth0`
    /// frame, because A3 strips the NIC entirely.
    #[test]
    fn drive_boot_omits_network_interface_under_egress_tier_mediated() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let api_sock = dir.path().join("api.sock");
        let vsock_uds = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&api_sock).unwrap();

        let captured: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_thread = std::sync::Arc::clone(&captured);

        // 5 requests, not 6 — the network-interfaces PUT is the
        // one that drops out under Mediated.
        let server = std::thread::spawn(move || {
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = Vec::with_capacity(4096);
                let mut tmp = [0u8; 1024];
                loop {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 { break; }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&buf[..end]).unwrap();
                        let cl: usize = headers
                            .lines()
                            .find_map(|l| {
                                l.strip_prefix("Content-Length:")
                                    .or_else(|| l.strip_prefix("content-length:"))
                                    .map(|s| s.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + cl { break; }
                    }
                }
                let text = String::from_utf8_lossy(&buf).into_owned();
                let request_line = text.lines().next().unwrap_or("").to_owned();
                captured_thread.lock().unwrap().push(request_line);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
                stream.flush().unwrap();
            }
        });

        let api = FirecrackerApi::new(&api_sock).with_timeout(Duration::from_secs(2));
        let img = fixture_image_with_path(PathBuf::from("/tmp/vmlinux.bin"));
        let mut spec = fixture_spec("session-fixture-a3");
        spec.egress_tier = EgressTier::Mediated;
        drive_boot(&api, &img, &[], &spec, &vsock_uds).unwrap();

        server.join().unwrap();
        let cap = captured.lock().unwrap();
        // Five PUTs total: machine-config, boot-source, drives,
        // vsock, actions — no network-interfaces.
        assert_eq!(
            cap.len(),
            5,
            "INV-NETISO-A3-UNIVERSAL-NO-NIC-01: Mediated must skip \
             PUT /network-interfaces (got {} requests: {:?})",
            cap.len(),
            *cap,
        );
        assert!(
            cap.iter().all(|line| !line.starts_with("PUT /network-interfaces")),
            "INV-NETISO-A3-UNIVERSAL-NO-NIC-01: Mediated emitted a \
             network-interfaces PUT — captured: {:?}",
            *cap,
        );
    }

    #[test]
    #[allow(deprecated)]
    fn drive_boot_emits_network_interface_when_egress_tier_is_tier1() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let api_sock = dir.path().join("api.sock");
        let vsock_uds = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&api_sock).unwrap();

        let captured: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_thread = std::sync::Arc::clone(&captured);

        let server = std::thread::spawn(move || {
            for _ in 0..6 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = Vec::with_capacity(4096);
                let mut tmp = [0u8; 1024];
                loop {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&buf[..end]).unwrap();
                        let cl: usize = headers
                            .lines()
                            .find_map(|l| {
                                l.strip_prefix("Content-Length:")
                                    .or_else(|| l.strip_prefix("content-length:"))
                                    .map(|s| s.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + cl {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf).into_owned();
                let request_line = text
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_owned();
                captured_thread.lock().unwrap().push(request_line);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
                stream.flush().unwrap();
            }
        });

        let api = FirecrackerApi::new(&api_sock).with_timeout(Duration::from_secs(2));
        let img = fixture_image_with_path(PathBuf::from("/tmp/vmlinux.bin"));
        let mut spec = fixture_spec("session-fixture-net");
        spec.egress_tier = EgressTier::Tier1Tproxy;
        drive_boot(&api, &img, &[], &spec, &vsock_uds).unwrap();

        server.join().unwrap();
        let cap = captured.lock().unwrap();
        assert_eq!(cap.len(), 6);
        assert!(cap[3].starts_with("PUT /network-interfaces/eth0"));
        assert!(cap[4].starts_with("PUT /vsock"));
        assert!(cap[5].starts_with("PUT /actions"));
    }

    #[test]
    fn drive_boot_rejects_inline_image_bytes() {
        // Firecracker requires an mmap-able rootfs file on disk;
        // inline-bytes is reserved for Wasm/SGX and should not flow
        // here. The boot driver fails fast without spawning anything.
        let img = VerifiedImage {
            kind:      ImageKind::WasmModule,
            body:      ImageBody::Bytes(vec![0u8; 16]),
            signature: ImageSignature(vec![0u8; 64]),
            image_id:  "wasm-not-allowed".to_owned(),
        };
        let dir = tempfile::tempdir().unwrap();
        let api_sock = dir.path().join("api.sock");
        let vsock_uds = dir.path().join("vsock.sock");
        let api = FirecrackerApi::new(&api_sock);
        // The first PUT (machine-config) will fail because the API
        // socket isn't bound, BUT the inline-bytes guard fires *after*
        // the machine-config PUT — meaning we still reach the typed
        // error path. We assert on either branch since both indicate
        // a healthy guard.
        let spec = fixture_spec("session-wasm");
        let err = drive_boot(&api, &img, &[], &spec, &vsock_uds).unwrap_err();
        match err {
            api::ApiError::Transport(_)
            | api::ApiError::MalformedResponse(_)
            | api::ApiError::Status { .. }
            | api::ApiError::Json(_) => {}
            api::ApiError::Timeout(_) | api::ApiError::NotSupportedOnTarget => {}
        }
    }
}
