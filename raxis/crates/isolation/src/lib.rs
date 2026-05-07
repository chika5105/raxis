//! `raxis-isolation` — V2 agent-runtime substrate trait crate.
//!
//! **Normative reference.**
//! * `specs/v2/extensibility-traits.md §3` (the canonical home for these
//!   trait definitions; this crate is the wire-side instantiation).
//! * `specs/v2/v2-deep-spec.md §Step 10` (VirtioFS staging + VSock control).
//! * `specs/v2/system-requirements.md §5` (R-1 admission tiers).
//!
//! ## Why this is a separate crate, not part of `raxis-kernel`
//!
//! The kernel binary should compile against the *trait*, not against a
//! concrete VMM. Three downstream consumers depend on this trait:
//!
//! 1. `raxis-kernel` — uses `Arc<dyn Backend>` to spawn planner sessions.
//! 2. `raxis-isolation-firecracker` (Linux) — implements `Backend`/`Session`
//!    on top of the Firecracker VMM API.
//! 3. `raxis-isolation-apple-vz` (macOS) — implements them on top of
//!    `Virtualization.framework`.
//!
//! Test fakes (a `Subprocess` substrate that drives the trait without a
//! hypervisor) live in `raxis-test-support`, never in this crate, never
//! in the kernel. The pattern mirrors `raxis-types::Clock` /
//! `raxis-test-support::FakeClock`: the production trait surface is
//! decoupled from any fake implementation.
//!
//! ## The five jobs the substrate performs
//!
//! Per `extensibility-traits.md §3.1`:
//!
//! | # | Job        | Trait method                                  |
//! |---|------------|-----------------------------------------------|
//! | 1 | Boot       | `Backend::spawn(&image, &mount, &spec)`       |
//! | 2 | Push       | `Session::push(&KernelPush)`                  |
//! | 3 | Receive    | `Session::recv_intent()`                      |
//! | 4 | Terminate  | `Session::terminate()` (security kill)        |
//! | 5 | Shutdown   | `Session::shutdown(grace)` (graceful)         |
//!
//! Anything else (capability probing, attestation reporting, isolation
//! tier metadata) is metadata exposed to the kernel for boot-time
//! admission of the backend itself, not a separate runtime job.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// VerifiedImage — what gets booted
// ---------------------------------------------------------------------------

/// The set of image families the substrate recognises.
///
/// V2 ships only `RootfsErofs` (the EROFS-formatted rootfs image used by
/// Firecracker and AVF). Other variants are placeholders for V3+ enclave /
/// confidential-VM / Wasm backends documented in
/// `extensibility-traits.md §3.5`. Kept as a single enum so the
/// `Backend::spawn` signature does not branch on backend identity in the
/// kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ImageKind {
    /// Read-only EROFS rootfs (Firecracker, AVF). The default V2 image
    /// shape for `raxis-orchestrator-core`, `raxis-reviewer-core`, and
    /// every operator-published Executor image.
    RootfsErofs,
    /// Intel SGX `SIGSTRUCT`-shaped enclave image (V3+).
    EnclaveSigStruct,
    /// `wasm32-wasi` module bytes (V3+, edge/IoT tier).
    WasmModule,
}

/// Where the verified image bytes live on the host.
///
/// Inline bytes vs. on-disk path matters because Firecracker prefers an
/// `mmap`-able file (it reads the kernel image lazily during boot)
/// while a Wasm module is small enough to ship inline. The substrate
/// implementation chooses; the kernel just hands over the
/// `VerifiedImage`.
#[derive(Debug, Clone)]
pub enum ImageBody {
    /// Image lives at this path on the host filesystem. The substrate
    /// MUST treat the file as immutable for the lifetime of the
    /// session — concurrent rewrites would break SHA verification.
    Path(PathBuf),
    /// Inline bytes (typically a small Wasm module). Owned, so the
    /// substrate controls its lifetime.
    Bytes(Vec<u8>),
}

/// Detached signature over `(kind || sha256(bytes))`.
///
/// The kernel-side image resolver verifies this *before* calling
/// `spawn`; the backend re-checks at spawn time as defence-in-depth.
/// The byte shape is the canonical Ed25519 signature (64 bytes); we
/// keep it as `Vec<u8>` here to avoid pulling `ed25519-dalek` into the
/// trait crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSignature(pub Vec<u8>);

/// An image whose signature has been verified upstream by the kernel's
/// image resolver. The `Backend::spawn` impl re-checks at spawn time.
#[derive(Debug, Clone)]
pub struct VerifiedImage {
    /// The image family (rootfs / enclave / Wasm).
    pub kind:      ImageKind,
    /// On-disk path or inline bytes.
    pub body:      ImageBody,
    /// Detached signature over `(kind || sha256(body))`.
    pub signature: ImageSignature,
    /// Stable identifier for this image (e.g. `"raxis-orchestrator-core-v2.0"`).
    /// Logged into the kernel's session-boot audit event so an external
    /// auditor can correlate the booted image with the policy bundle's
    /// allowlist.
    pub image_id:  String,
}

// ---------------------------------------------------------------------------
// WorkspaceMount — what filesystem the guest sees
// ---------------------------------------------------------------------------

/// Read-only / read-write discriminator for mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum MountMode {
    /// Reviewer worktrees, kernel-staged `/raxis/` artifact dir.
    /// Per Step 24 / Step 24b, the Reviewer's worktree mount MUST be
    /// read-only so the SHA tree the reviewer sees is byte-identical
    /// to what the Executor committed.
    ReadOnly,
    /// Orchestrator worktree (Step 24b). The Orchestrator mutates the
    /// worktree via `git fetch`/`git merge` before submitting
    /// `IntegrationMerge`.
    ReadWrite,
}

/// SHA-256 digest of the mount source's contents at spawn time.
///
/// V2 backends are not required to verify this on every guest read
/// (would defeat lazy paging), but the digest is recorded into the
/// audit event so an external auditor can reconstruct the exact bytes
/// the guest saw. Optional because not every mount has a stable
/// content hash (e.g. an empty staging directory).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentHash(pub [u8; 32]);

/// One filesystem mount the kernel wants visible inside the guest.
///
/// VirtioFS for microVMs (Firecracker / AVF), shared-page for SGX,
/// preopen-dir for Wasm, bind-mount for the test substrate. The trait
/// surface is intentionally agnostic: `Backend::spawn` translates to
/// the impl-appropriate primitive.
#[derive(Debug, Clone)]
pub struct WorkspaceMount {
    /// Host directory the kernel staged via Step 24 / Step 24b.
    pub host_path:    PathBuf,
    /// Path inside the guest filesystem (e.g. `"/workspace"`,
    /// `"/raxis"`).
    pub guest_path:   String,
    /// Read-only vs read-write.
    pub mode:         MountMode,
    /// Optional content digest at spawn time.
    pub content_hash: Option<ContentHash>,
}

// ---------------------------------------------------------------------------
// VmSpec — resource envelope + IPC parameters
// ---------------------------------------------------------------------------

/// Egress tier the kernel wants enforced on the guest's network surface.
///
/// V2 ships only `None` (Reviewer images: `INV-NETISO-01`) and
/// `Tier1Tproxy` (Executor / Orchestrator: kernel-mediated egress per
/// `kernel-mediated-egress.md`). `Tier2CredProxy` is a V3 placeholder
/// for credential-proxy-mediated provider calls per
/// `credential-proxy.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EgressTier {
    /// No network device in the guest. Reviewer image (Step 24,
    /// `INV-NETISO-01`).
    None,
    /// Tier-1 tproxy: tap device + nftables redirect to the kernel's
    /// egress proxy (`vm-network-isolation.md §3`).
    Tier1Tproxy,
    /// V3 placeholder: per-credential proxy
    /// (`credential-proxy.md`).
    Tier2CredProxy,
}

/// Optional cgroup quota. The kernel applies this when the host
/// supports cgroups v2 (Linux); macOS / non-Linux substrates ignore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupQuota {
    /// CPU bandwidth ceiling, microseconds per `cpu.cfs_period_us`.
    /// `None` ⇒ unlimited.
    pub cpu_quota_us: Option<u64>,
    /// Memory ceiling, bytes. `None` ⇒ unlimited (bounded only by
    /// `mem_mib` in the VM config).
    pub memory_max_bytes: Option<u64>,
}

/// Opaque session token minted by the kernel and injected into the
/// guest at spawn time. Every intent the guest submits is authenticated
/// by this token; rotated per session, never re-used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken(pub String);

/// Resource envelope the impl is asked to enforce.
///
/// Fields the kernel must not let a planner control (vCPUs, memory,
/// network tier) live here so they cannot be negotiated through any
/// in-guest channel. The kernel constructs `VmSpec` from policy +
/// session metadata at spawn time.
#[derive(Debug, Clone)]
pub struct VmSpec {
    /// Number of virtual CPUs to expose.
    pub vcpu_count:       u32,
    /// Guest memory ceiling, mebibytes.
    pub mem_mib:          u32,
    /// Egress tier enforced by the substrate (microVM backends wire
    /// this to a tap device + nftables; mock substrates ignore).
    pub egress_tier:      EgressTier,
    /// Optional Linux cgroup v2 quota.
    pub cgroup_quota:     Option<CgroupQuota>,
    /// Kernel boot args (microVM only). Platform substrates that don't
    /// boot a Linux kernel ignore.
    pub boot_args:        Vec<String>,
    /// Argv passed to PID 1 inside the guest.
    pub entrypoint_argv:  Vec<String>,
    /// Per-session secret used by the guest to authenticate every
    /// intent frame.
    pub session_token:    SessionToken,
    /// VSock CID assigned to this guest. `None` for non-VSock
    /// substrates (Wasm, mock).
    pub vsock_cid:        Option<u32>,
    /// Host directories to mount into the guest. Empty for backends
    /// that route filesystem access elsewhere (Wasm preopen-dirs,
    /// SGX shared pages).
    pub virtio_fs_mounts: Vec<WorkspaceMount>,

    /// Environment variables exposed to PID 1 inside the guest.
    ///
    /// **Why per-spawn (not per-backend-instance).** The kernel's
    /// `SessionSpawnService` stamps three classes of values into
    /// this map at session-spawn time:
    ///
    /// * **Credential-proxy loopback URLs** — one entry per
    ///   `[[tasks.credentials]]` block, keyed by the operator-
    ///   declared `mount_as` field. The proxy listener binds on
    ///   the host's loopback interface and the URL it emits here
    ///   is the *only* address the agent sees; the credential
    ///   bytes themselves never leave the kernel process per
    ///   `credential-proxy.md §1`.
    ///
    /// * **Egress-admission service address** — the kernel-side
    ///   admission service binds a per-session listener and writes
    ///   its `host:port` here under
    ///   `RAXIS_TPROXY_KERNEL_TCP` so the in-guest tproxy
    ///   substrate can find it. Replaced by a vsock CID at V2 GA.
    ///
    /// * **Session token** — `RAXIS_SESSION_TOKEN` mirrors the
    ///   value of `session_token` for guests that consume it via
    ///   env rather than via the framed handshake.
    ///
    /// Substrates MUST honour this map in spawn order; the
    /// reference subprocess substrate forwards the map to
    /// `Command::env`. Firecracker / Apple-VZ stamp it through
    /// the metadata service or the boot-args env block — see each
    /// concrete substrate's docs for the exact channel.
    ///
    /// Backends that have no concept of guest env (Wasm modules,
    /// pure ring buffers) MAY ignore the map; the kernel surfaces
    /// the same values through alternative channels for those
    /// backends (currently: out-of-band session metadata RPC).
    ///
    /// **`BTreeMap` rather than `HashMap`** — deterministic
    /// iteration order makes audit-log replay reproducible.
    pub env: std::collections::BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// IsolationLevel — admission tier
// ---------------------------------------------------------------------------

/// Admission tier the backend reports at boot. Used by
/// `verify_admission_tier` (and the operator-facing `raxis doctor`)
/// to reject backends below the R-1 conformance bar.
///
/// **Stable wire shape.** The PascalCase serde projection is the same
/// shape consumed by audit events and `raxis doctor` JSON output;
/// renaming a variant would break operator tooling and audit replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IsolationLevel {
    /// Strong attestable isolation (SGX / TDX / SEV-SNP +
    /// remote-attestation). May satisfy regulatory requirements
    /// stricter than R-1.
    R1ConformantStrong,
    /// Hardware-virtualised microVM (Firecracker, Apple-VZ).
    /// Satisfies R-1.
    R1Conformant,
    /// Wasm-sandboxed (WASI capability-restricted). Acceptable for
    /// low-stakes verifiers per `raxis-security-model.md §INV-WASM-01`.
    WasmSandbox,
    /// Linux namespaces + seccomp. Does NOT satisfy R-1
    /// (kernel-shared address space). Disallowed in production
    /// without `--unsafe-fallback-isolation`.
    FallbackOnly,
    /// Test substrate (subprocess-based). Knowingly violates R-1;
    /// never compiled into release. The kernel rejects this tier
    /// unless `RAXIS_TEST_HARNESS=1` is set in the spawning process
    /// environment AND `cfg(any(debug_assertions, test))` holds for
    /// the substrate crate (enforced by `raxis-test-support`'s
    /// workspace-guard test).
    TestOnly,
}

impl IsolationLevel {
    /// Whether this tier satisfies R-1 *unconditionally* (no operator
    /// flag required). Used by the boot admission helper to reject
    /// `FallbackOnly`/`TestOnly` without explicit override.
    pub const fn r1_conformant(self) -> bool {
        matches!(self, Self::R1Conformant | Self::R1ConformantStrong)
    }
}

// ---------------------------------------------------------------------------
// Capabilities — what the operator-facing `raxis doctor` reads
// ---------------------------------------------------------------------------

/// What property of the backend the kernel is probing.
///
/// Stable enum; new variants are additive (every backend must answer
/// the existing variants meaningfully or surface
/// `CapabilityValue::Str("not-applicable")`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CapabilityKind {
    /// `/dev/kvm` accessible (Linux only).
    KvmAvailable,
    /// Backend can produce a remote-attestation quote.
    AttestationSupported,
    /// Median boot latency in milliseconds (microbenchmark).
    BootLatencyMs,
    /// Hard cap on simultaneously-live sessions this backend supports.
    MaxConcurrentVms,
    /// Backend uses CPU memory encryption (SEV-SNP / TDX).
    MemoryEncryption,
}

/// Structured capability answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CapabilityValue {
    /// Boolean property (e.g. `KvmAvailable`).
    Bool(bool),
    /// Integer property (e.g. `BootLatencyMs`, `MaxConcurrentVms`).
    Int(u64),
    /// Free-form string (e.g. `"not-applicable"`, vendor name).
    Str(String),
    /// Tier-shaped property (e.g. `MemoryEncryption` reporting a
    /// specific isolation tier).
    Tier(IsolationLevel),
}

// ---------------------------------------------------------------------------
// SessionTransportId — diagnostic identity per running session
// ---------------------------------------------------------------------------

/// Stable transport-level identifier for a live session. Used in
/// kernel diagnostic logs and audit events. MUST be stable for the
/// lifetime of the session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SessionTransportId {
    /// Vsock CID assigned to the microVM (Firecracker / AVF).
    Vsock {
        /// VSock context-id.
        cid: u32,
    },
    /// SGX enclave id (V3+).
    EnclaveId([u8; 32]),
    /// Wasm instance id (V3+).
    WasmInstance(u64),
    /// Linux pid for namespace / subprocess substrates.
    Process {
        /// Linux process id.
        pid: u32,
    },
}

// ---------------------------------------------------------------------------
// ExitStatus — what the kernel records when a session ends
// ---------------------------------------------------------------------------

/// Typed exit status the substrate reports on graceful shutdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ExitStatus {
    /// Guest PID 1 returned this exit code. `0` ⇒ normal completion.
    GracefulExit {
        /// PID 1's exit code (0 == normal).
        code: i32,
    },
    /// Guest was killed by signal (SIGTERM grace expired → SIGKILL,
    /// or operator security kill).
    SignalKilled {
        /// Unix signal number (e.g. 15 = SIGTERM, 9 = SIGKILL).
        signum: i32,
    },
    /// Grace period elapsed without the guest exiting and the forced-
    /// kill path also stalled. The substrate gave up; the kernel
    /// records this as a backend-internal failure.
    Timeout,
    /// Backend-internal failure (e.g. VMM API returned an error during
    /// shutdown). The string is opaque to callers — record it in the
    /// audit event verbatim.
    BackendError(String),
}

// ---------------------------------------------------------------------------
// IsolationError — every failure path the substrate can surface
// ---------------------------------------------------------------------------

/// Errors returned by the substrate trait methods.
///
/// Variant set is closed: callers exhaustively match. Adding a new
/// variant is a wire-compat change for any downstream tooling that
/// projects these to operator-facing diagnostic codes.
#[derive(Debug, thiserror::Error)]
pub enum IsolationError {
    /// `Backend::spawn` could not boot the guest. Typical causes:
    /// VMM API failure, image signature mismatch, resource exhaustion.
    /// The string is the backend-specific reason — projected to
    /// `FAIL_VM_SPAWN_FAILED` at the kernel handler boundary.
    #[error("spawn failed: {0}")]
    SpawnFailed(String),

    /// The guest closed its end of the IPC transport without sending
    /// `Ack(SessionShutdown)`. Surfaces from `Session::recv_intent`
    /// when the guest exits unexpectedly.
    #[error("peer closed transport")]
    PeerClosed,

    /// Transport-level fault (VSock socket error, ring-buffer
    /// corruption, host-call boundary panic). The kernel terminates
    /// the session and records a SecurityViolation if the fault
    /// pattern matches a known adversarial shape.
    #[error("transport fault: {0}")]
    TransportFault(String),

    /// `VerifiedImage::signature` did not verify at spawn time.
    /// Defense-in-depth — the kernel image resolver verified upstream,
    /// but the backend re-checks. Should never fire under normal
    /// operation.
    #[error("image signature did not verify at spawn time")]
    SignatureMismatch,

    /// Resource limit hit (cgroup quota, vCPU exhaustion, file
    /// descriptor cap). String is the limit identifier.
    #[error("resource limit reached: {0}")]
    ResourceLimit(String),

    /// Backend-internal error that doesn't fit the categories above
    /// (e.g. VMM crashed, kernel module unloaded). Investigate
    /// out-of-band.
    #[error("backend internal error: {0}")]
    BackendInternal(String),
}

// ---------------------------------------------------------------------------
// Push / Receive payload types
// ---------------------------------------------------------------------------
//
// We keep these as opaque byte buffers in the trait surface so the
// trait crate can be compiled without depending on the (large) intent /
// kernel-push enum definitions in `raxis-types`. The substrate doesn't
// inspect the payload — it just frames bytes onto its native
// transport. The kernel and planner serialize / deserialize the
// `IpcMessage` enum themselves.
//
// Why opaque rather than concrete `IpcMessage`:
//   * Keeps the substrate trait crate's dep graph minimal — Firecracker
//     and AVF impls don't need to track every IPC schema bump.
//   * Allows V3+ backends (Wasm, SGX) to plug in alternate framing
//     conventions without reworking the `IpcMessage` shape.
//   * The byte-exact framing contract is owned by `raxis-ipc::framing`
//     (length-prefixed bincode); the substrate is the byte conduit.

/// Frame the substrate pushes from kernel → guest. The byte payload is
/// a length-prefixed bincode `IpcMessage` (per
/// `peripherals.md §3` framing contract). Substrate impls never parse
/// the payload — they just frame the bytes onto VSock / shared memory /
/// host-call boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushFrame {
    /// Opaque payload. The substrate writes these bytes verbatim onto
    /// its transport.
    pub bytes: Vec<u8>,
}

/// Frame the substrate receives from guest → kernel. Same opaque
/// shape as `PushFrame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentFrame {
    /// Opaque payload received from the guest.
    pub bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Backend / Session traits — the substrate seam
// ---------------------------------------------------------------------------

/// **The factory that boots an isolated execution environment.**
///
/// `R-1` requires distinct address spaces, no shared memory, and
/// authority-mediated I/O only. An impl is conformant iff
/// `verify_isolation_guarantee()` returns
/// `Ok(IsolationLevel::R1Conformant)` AND the conformance kit
/// (`extensibility-traits.md §3.9`) passes.
///
/// **Lifecycle.** The kernel calls `spawn` once per session, holds the
/// returned `Box<dyn Session>` for the lifetime of that session, and
/// drops it on session-end. `Drop` impls of every concrete `Session`
/// MUST run `terminate()` — see `Session::terminate`.
pub trait Backend: Send + Sync + 'static {
    /// Boot an isolated execution environment with the given verified
    /// image and workspace mount. Returns a live session handle.
    ///
    /// MUST NOT return until the guest is reachable on its primary
    /// IPC transport (VSock CID, ring buffer, host-call channel,
    /// pipe — whichever the impl uses).
    ///
    /// MUST refuse a spawn if the image signature does not re-verify
    /// at spawn time — defence-in-depth backstop for the kernel's
    /// upstream image resolver.
    fn spawn(
        &self,
        image:     &VerifiedImage,
        workspace: &[WorkspaceMount],
        spec:      &VmSpec,
    ) -> Result<Box<dyn Session>, IsolationError>;

    /// Verify that this backend satisfies `R-1` at the host-hardware
    /// level. Called once at kernel startup by `raxis doctor`
    /// (`system-requirements.md §11`).
    fn verify_isolation_guarantee(&self) -> Result<IsolationLevel, IsolationError>;

    /// Probe a backend property at runtime (used by `raxis doctor`).
    fn capability(&self, kind: CapabilityKind) -> CapabilityValue;

    /// Stable identifier for this backend impl. Logged into the
    /// kernel boot audit event, surfaced in `raxis doctor`. Examples:
    /// `"firecracker-1.7"`, `"apple-vz-14.5"`, `"subprocess-test"`.
    fn backend_id(&self) -> &'static str;
}

/// **A live isolated guest.**
///
/// The kernel holds exactly one of these per active session; dropping
/// the handle MUST tear down the guest.
///
/// All four state-changing methods MUST be cancel-safe: a dropped
/// future MUST NOT leave a half-written frame on the transport.
pub trait Session: Send + 'static {
    /// Send a `KernelPush`-frame to the agent.
    ///
    /// The byte payload is a length-prefixed bincode `IpcMessage`.
    /// The substrate writes it verbatim onto its native transport.
    fn push(&mut self, frame: &PushFrame) -> Result<(), IsolationError>;

    /// Block until the next intent frame arrives from the guest.
    /// Returns `Err(IsolationError::PeerClosed)` when the guest exits.
    fn recv_intent(&mut self) -> Result<IntentFrame, IsolationError>;

    /// Immediate termination (security kill). MUST NOT signal SIGTERM
    /// or wait for graceful shutdown. Used when the kernel detects an
    /// invariant violation (`R-6` fail-closed default).
    /// MUST be idempotent.
    fn terminate(&mut self) -> Result<(), IsolationError>;

    /// Graceful shutdown: signal the guest to exit, wait at most
    /// `grace`, then forcibly kill on timeout. Returns the typed
    /// `ExitStatus` the kernel records to the audit chain.
    /// MUST be idempotent.
    fn shutdown(&mut self, grace: Duration) -> Result<ExitStatus, IsolationError>;

    /// Transport-level identity of this session for diagnostic logs.
    /// MUST be stable for the lifetime of the session.
    fn session_identity(&self) -> SessionTransportId;
}

// ---------------------------------------------------------------------------
// Boot-time admission helper
// ---------------------------------------------------------------------------

/// Outcome of `verify_admission_tier`, mirroring the §3.8 main.rs
/// sketch in `extensibility-traits.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Backend's tier ≥ `R1Conformant`. Boot proceeds normally.
    Admit,
    /// Backend reports `WasmSandbox`. Boot proceeds *only* when policy
    /// has `allow_wasm_for_low_stakes_verifiers = true`. Caller
    /// responsible for surfacing the policy check.
    AdmitWasmIfPolicyAllows,
    /// Backend reports `FallbackOnly`. Boot proceeds *only* when the
    /// kernel was started with `--unsafe-fallback-isolation`. Caller
    /// responsible for surfacing the audit event
    /// (`IsolationFallbackBypass { reason, operator_id }`).
    AdmitFallbackIfFlagSet,
    /// Backend reports `TestOnly`. Production builds reject; the
    /// `RAXIS_TEST_HARNESS=1` opt-in lives in the test crate, not in
    /// the production admission path.
    Refuse(String),
}

/// Admission helper consumed by `kernel/src/main.rs`. Pure function;
/// caller composes the result with policy / CLI flags / environment
/// before completing boot.
///
/// **Why this is a free function, not a `Backend` method.** The
/// admission decision is a *deployment* concern: it depends on policy
/// and CLI flags the substrate doesn't see. Keeping it outside the
/// trait keeps each `Backend` impl free of policy / CLI knowledge,
/// and lets the kernel boot a single, audited call site for the
/// decision (`extensibility-traits.md §3.8`).
pub fn verify_admission_tier(level: IsolationLevel) -> AdmissionDecision {
    match level {
        IsolationLevel::R1Conformant | IsolationLevel::R1ConformantStrong => {
            AdmissionDecision::Admit
        }
        IsolationLevel::WasmSandbox  => AdmissionDecision::AdmitWasmIfPolicyAllows,
        IsolationLevel::FallbackOnly => AdmissionDecision::AdmitFallbackIfFlagSet,
        IsolationLevel::TestOnly => AdmissionDecision::Refuse(
            "TestOnly isolation tier is never admitted in production builds; \
             test substrates live in `raxis-test-support` and require the \
             `RAXIS_TEST_HARNESS=1` opt-in plus a debug/test build".to_owned(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests — pure data shape and admission helper coverage
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_level_r1_conformant_helper_matches_spec_table() {
        assert!(IsolationLevel::R1Conformant.r1_conformant());
        assert!(IsolationLevel::R1ConformantStrong.r1_conformant());
        assert!(!IsolationLevel::WasmSandbox.r1_conformant());
        assert!(!IsolationLevel::FallbackOnly.r1_conformant());
        assert!(!IsolationLevel::TestOnly.r1_conformant());
    }

    #[test]
    fn verify_admission_tier_admits_r1_levels_unconditionally() {
        assert_eq!(
            verify_admission_tier(IsolationLevel::R1Conformant),
            AdmissionDecision::Admit,
        );
        assert_eq!(
            verify_admission_tier(IsolationLevel::R1ConformantStrong),
            AdmissionDecision::Admit,
        );
    }

    #[test]
    fn verify_admission_tier_gates_wasm_on_policy() {
        // The helper does not consult policy itself — it just signals
        // that the caller MUST consult policy before admitting Wasm.
        assert_eq!(
            verify_admission_tier(IsolationLevel::WasmSandbox),
            AdmissionDecision::AdmitWasmIfPolicyAllows,
        );
    }

    #[test]
    fn verify_admission_tier_gates_fallback_on_cli_flag() {
        assert_eq!(
            verify_admission_tier(IsolationLevel::FallbackOnly),
            AdmissionDecision::AdmitFallbackIfFlagSet,
        );
    }

    #[test]
    fn verify_admission_tier_refuses_test_only_in_production_path() {
        // Crucially: even when the substrate self-reports `TestOnly`,
        // the production admission path REJECTS it. Test substrates
        // (which live in `raxis-test-support`) bypass this via direct
        // wiring in `#[cfg(test)]` code paths — they never go through
        // `verify_admission_tier`.
        match verify_admission_tier(IsolationLevel::TestOnly) {
            AdmissionDecision::Refuse(reason) => {
                assert!(reason.contains("TestOnly"));
                assert!(reason.contains("raxis-test-support"));
            }
            other => panic!("TestOnly must be refused, got {other:?}"),
        }
    }

    #[test]
    fn isolation_level_serde_uses_pascal_case_wire_shape() {
        // Audit-replay tooling depends on the PascalCase strings.
        // A serde-rename refactor that flips the casing silently
        // would break operator dashboards.
        assert_eq!(
            serde_json::to_string(&IsolationLevel::R1Conformant).unwrap(),
            r#""R1Conformant""#,
        );
        assert_eq!(
            serde_json::to_string(&IsolationLevel::R1ConformantStrong).unwrap(),
            r#""R1ConformantStrong""#,
        );
        let parsed: IsolationLevel =
            serde_json::from_str(r#""FallbackOnly""#).unwrap();
        assert_eq!(parsed, IsolationLevel::FallbackOnly);
    }

    #[test]
    fn capability_value_round_trips_each_variant() {
        let cases = vec![
            CapabilityValue::Bool(true),
            CapabilityValue::Int(125),
            CapabilityValue::Str("not-applicable".to_owned()),
            CapabilityValue::Tier(IsolationLevel::R1Conformant),
        ];
        for case in cases {
            let json    = serde_json::to_string(&case).unwrap();
            let parsed: CapabilityValue = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, case, "round-trip failed: {json}");
        }
    }

    #[test]
    fn session_transport_id_round_trips_each_variant() {
        let cases = vec![
            SessionTransportId::Vsock { cid: 4 },
            SessionTransportId::EnclaveId([0xAA; 32]),
            SessionTransportId::WasmInstance(42),
            SessionTransportId::Process { pid: 12345 },
        ];
        for case in cases {
            let json    = serde_json::to_string(&case).unwrap();
            let parsed: SessionTransportId = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, case);
        }
    }

    #[test]
    fn exit_status_round_trips_each_variant() {
        let cases = vec![
            ExitStatus::GracefulExit { code: 0 },
            ExitStatus::SignalKilled { signum: 9 },
            ExitStatus::Timeout,
            ExitStatus::BackendError("vmm crashed".to_owned()),
        ];
        for case in cases {
            let json    = serde_json::to_string(&case).unwrap();
            let parsed: ExitStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, case);
        }
    }
}
