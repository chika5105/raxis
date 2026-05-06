# RAXIS V2 — Extensibility Traits (Six Pluggable Boundaries)

> **Status:** V2 Specified.
> **Audience:** Implementers extending the reference implementation to a new domain (trading, healthcare, robotics) or a new deployment topology (RAXIS Cloud, enterprise on-prem, air-gapped). Reviewers verifying that no admission-pipeline logic leaks into a trait. Auditors reasoning about which decisions are paradigm-level (concrete kernel) and which are deployment-level (pluggable).
> **Cross-references:**
> - [`paradigm.md`](../paradigm.md) — twelve `R-*` invariants this surface MUST NOT weaken
> - [`invariants.md`](../invariants.md) — reference-implementation `INV-*` enforcement points
> - [`v2/credential-proxy.md`](credential-proxy.md) — canonical `CredentialBackend` consumer
> - [`v2/provider-failure-handling.md`](provider-failure-handling.md) — canonical `InferenceRouter` consumer
> - [`v2/provider-model-selection.md`](provider-model-selection.md) — `InferenceRouter` resolution rules
> - [`v2/system-requirements.md`](system-requirements.md) — `IsolationBackend` per-platform tiers
> - [`v2/vm-network-isolation.md`](vm-network-isolation.md) — `IsolationBackend` Tier-1 networking surface
> - [`v2/kernel-lifecycle.md`](kernel-lifecycle.md) — `OperatorTransport` listener lifecycle
> - [`v1/kernel-store.md`](../v1/kernel-store.md) §2.5.2 — `AuditSink` ordering invariant (already in source)

---

## §1 — Why Trait Boundaries (And Why Only Six)

The RAXIS reference implementation in this repository targets **autonomous software engineering on a single host** with a specific stack: Firecracker on Linux + Apple Virtualization on macOS, plaintext credential files under `<data_dir>/credentials/`, append-only JSONL audit segments, a Unix Domain Socket for the operator CLI, and a kernel-owned HTTPS gateway routing to public LLM providers.

Every one of those choices is correct for the reference deployment and wrong for some other deployment a future operator may need:

- A **trading firm** needs HSM-backed signing keys (no plaintext on disk), models running on local GPUs (no public-internet exfiltration of order intent), and an immutable transparency log (Sigstore/Rekor) for non-repudiation.
- A **healthcare deployment** under HIPAA needs cloud-secrets-manager integration with per-access audit trails, on-premise inference (no PHI egress), and a centralized control plane managing multiple kernel instances.
- **RAXIS Cloud** needs the operator CLI to reach the kernel over mTLS gRPC across the network, and audit events to land in an immutable cloud ledger (S3 + Athena, or a dedicated append-only store).
- An **air-gapped government** install needs every credential, every audit byte, and every inference call to stay on the host, with periodic USB-mediated audit export.

Hard-coding the reference choices into the kernel makes the kernel non-portable. Pulling every choice out into a trait makes the kernel hollow. The right answer is to identify the **smallest set of seams** along which alternative deployments diverge — and to make exactly those seams `trait` boundaries.

### §1.1 The rule that decides what gets a trait

> **A subsystem gets a `trait` boundary if and only if substituting it does NOT weaken any `R-*` paradigm invariant from `paradigm.md`.**

Equivalently: a subsystem stays concrete if and only if it **enforces** an `R-*` invariant (substituting it would let an implementation claim RAXIS conformance while violating the paradigm).

Applying this rule yields six trait boundaries and a fixed concrete kernel:

| Subsystem | Trait? | Justification |
|---|---|---|
| Domain-specific intent kinds, file shapes, merge semantics | ✅ `DomainAdapter` | Domain-agnostic per `paradigm.md §5`; SE-specific concepts (git worktrees, `IntegrationMerge`, commits) are not paradigm-level. |
| Isolation primitive (microVM / enclave / Wasm / mock) | ✅ `IsolationBackend` | `paradigm.md §3 R-1` permits "at least equivalent to a hardware-virtualized microVM, hardware enclave, or formally verified microkernel partition." |
| Credential storage (file / Vault / AWS SM / Azure KV / HSM) | ✅ `CredentialBackend` | `R-2` requires mediation, not a specific store; the gateway-only-reads property is preserved across all backends. |
| Sealed-event persistence (SQLite / PostgreSQL / S3 / Rekor) | ✅ `AuditSink` | `R-7` requires tamper-evidence verifiable with public keys; chain math stays kernel-side, persistence is a deployment choice. |
| Operator CLI transport (UDS / mTLS gRPC / HTTPS) | ✅ `OperatorTransport` | `R-9` and `R-12` require the channel to be unforgeable by intelligence and authenticated to a human principal; the wire is replaceable. |
| Inference provider routing (HTTPS / gRPC / local vLLM / TGI) | ✅ `InferenceRouter` | `R-2` mediation is satisfied by *any* router that strips planner authority over destination + meters tokens; specific providers are deployment choices. |
| Intent admission pipeline (the 13-step gate check) | ❌ Concrete | This **is** the kernel. Abstracting it would hollow out the product and make `R-3`/`R-4`/`R-5`/`R-6` unverifiable. |
| Policy parser (`policy.toml`/`plan.toml`) | ❌ Concrete | The signed-TOML schema is the RAXIS protocol; conformance test suites verify it. New domains add new fields, not new parsers. |
| Escalation FSM | ❌ Concrete | The `Pending → Approved → Consumed` transitions are paradigm-level (`R-12`). Domain-specific escalation classes are enum variants, not trait swaps. |
| Hash chain / Merkle logic | ❌ Concrete | This **is** `R-7`. The algorithm is non-negotiable. The sink is replaceable; the chain is not. |
| `KernelPush` / `IntentRequest` framing | ❌ Concrete | The wire contract binds every planner ever written. Changing it breaks all clients. |

### §1.2 What this spec ships in V2

V2 ships:

1. The **trait definitions** in their canonical Rust crates (one trait per file, co-located with the existing concrete impl where possible).
2. The **default impls** the reference implementation already uses (`FileAuditSink`, `FirecrackerBackend`, `UnixSocketTransport`, etc.), refactored to *implement* the trait instead of being free-standing types.
3. Wiring at the kernel boot site (`kernel/src/main.rs` + `bootstrap.rs`) so each subsystem is held as `Arc<dyn Trait>` — not as a concrete type — anywhere admission code reads it.
4. A **conformance test fixture** per trait that exercises the trait's contract against any alternative impl in any future workspace member.

V2 does **not** ship alternative impls (Vault, HSM, gRPC, vLLM). Those are V3+ or out-of-tree. V2 only proves the seams exist and are testable.

---

## §2 — `DomainAdapter` — Domain-Specific Authority Operations

The reference implementation targets **autonomous software engineering**: planners read code, write code, run tests, integrate changes via `IntegrationMerge`. Other domains (trading, healthcare, robotics) need different intent kinds, different commit/merge semantics, different "deliverable" notions. The intent admission pipeline, escalation FSM, and audit chain are unchanged across domains; the *operations* the planner can request are not.

### §2.1 Trait definition

**Canonical home:** `crates/raxis-domain/src/lib.rs` (NEW).

```rust
/// Pluggable seam for domain-specific authority operations.
///
/// The kernel's intent admission pipeline (the 13-step gate check) is
/// concrete and stays the same across every domain. What changes per
/// domain is *which intent kinds exist*, *what their payloads look
/// like*, and *what "completing a task" means as a side-effect* (a git
/// commit + cherry-pick for SE, an order placement for trading, a
/// motion command for robotics).
///
/// Implementations:
/// - [`SoftwareEngineeringAdapter`] (default in the reference impl) —
///   git worktrees, ephemeral clones, `IntegrationMerge` via cherry-pick.
/// - Future: `TradingAdapter`, `HealthcareAdapter`, `RoboticsAdapter`.
pub trait DomainAdapter: Send + Sync + 'static {
    /// Domain-specific intent payload types (the closed enumeration of
    /// authority operations this domain admits). The kernel deserialises
    /// these from the typed `IntentRequest` envelope; domain-agnostic
    /// fields (`session_id`, `seq`, `nonce`) stay in the envelope.
    type IntentKind: serde::Serialize + serde::de::DeserializeOwned + Send + Sync;

    /// Domain-specific terminal task artefact (the thing
    /// `CompleteTask`'s witness binds against). For SE: a `CommitSha`.
    /// For trading: an `OrderId + FillReceipt`. For robotics: a
    /// `MotionId + ExecutionTrace`.
    type TerminalArtefact: Clone + Send + Sync;

    /// Compute the deterministic touched-set of domain resources for a
    /// given intent (the equivalent of `vcs::diff(base, head)` for SE).
    /// MUST be derived from authoritative state, not from
    /// planner-supplied manifests (`R-9` / `INV-07`).
    fn touched_resources(
        &self,
        intent: &Self::IntentKind,
        ctx: &DomainContext<'_>,
    ) -> Result<TouchedResources, DomainError>;

    /// Apply a `CompleteTask` artefact onto the master domain state
    /// (e.g., merge the candidate commit into the master worktree, or
    /// place the order on the broker, or commit the motion to the
    /// motor controller). Called only after every gate has been
    /// satisfied and the kernel has admitted the merge.
    fn apply_terminal(
        &self,
        artefact: &Self::TerminalArtefact,
        ctx: &DomainContext<'_>,
    ) -> Result<DomainCommitReceipt, DomainError>;

    /// Escalation classes specific to this domain (e.g., for SE:
    /// `ProtectedPathMerge`, `ReviewLoopExceeded`; for trading:
    /// `PositionLimitExceeded`, `MarketHaltDetected`).
    fn escalation_classes(&self) -> &'static [&'static str];
}
```

### §2.2 Reference implementation: `SoftwareEngineeringAdapter`

**Home:** `crates/raxis-domain-se/src/lib.rs` (NEW; carved out of `kernel/src/handlers/intent.rs` and `kernel/src/vcs/`).

`SoftwareEngineeringAdapter::IntentKind` is the existing `raxis-types::IntentKind` (CompleteTask, IntegrationMerge, SubmitReview, EscalationRequest, InferenceRequest, EgressRequest, FetchRequest). `TerminalArtefact` is `(CommitSha, head_tree_sha256)`. `touched_resources` invokes `kernel/src/vcs::diff`. `apply_terminal` runs the existing `IntegrationMerge` cherry-pick path.

### §2.3 Files to create

- `crates/raxis-domain/Cargo.toml` (NEW; `[lib] name = "raxis-domain"`)
- `crates/raxis-domain/src/lib.rs` — trait definition, `DomainContext`, `TouchedResources`, `DomainError`, `DomainCommitReceipt`
- `crates/raxis-domain-se/Cargo.toml` (NEW; depends on `raxis-domain`, `raxis-types`, `git2`, existing `kernel/src/vcs/` extracted into a library)
- `crates/raxis-domain-se/src/lib.rs` — `SoftwareEngineeringAdapter` impl, re-export `IntentKind`
- `crates/raxis-domain-se/src/touched.rs` — `vcs::diff`-based `TouchedResources`
- `crates/raxis-domain-se/src/terminal.rs` — `IntegrationMerge` cherry-pick logic moved out of `kernel/src/handlers/`
- `crates/raxis-domain-se/tests/conformance.rs` — exercises the trait's contract using the V2 conformance fixtures (this fixture set is shared with future adapters via `crates/raxis-domain/tests/conformance_kit.rs`)

### §2.4 Files to change

- `kernel/Cargo.toml` — add `raxis-domain = { path = "../crates/raxis-domain" }` and `raxis-domain-se = { path = "../crates/raxis-domain-se" }`
- `kernel/src/main.rs` — at boot, construct `Arc<dyn DomainAdapter>` from `SoftwareEngineeringAdapter::new(...)`; thread through `HandlerContext`
- `kernel/src/handlers/intent.rs` — replace direct `vcs::diff` calls with `ctx.domain.touched_resources(...)`; replace direct `IntegrationMerge` cherry-pick with `ctx.domain.apply_terminal(...)`
- `kernel/src/handlers/mod.rs` — `HandlerContext` gains `pub domain: Arc<dyn DomainAdapter<IntentKind=raxis_types::IntentKind, TerminalArtefact=(CommitSha, String)>>`
- `crates/raxis-types/src/intent.rs` — no schema change; `IntentKind` stays the canonical SE enum but is now re-exported from `raxis-domain-se`

### §2.5 Conformance contract

A `DomainAdapter` impl is conformant iff it satisfies these properties (mechanically verifiable in `crates/raxis-domain/tests/conformance_kit.rs`):

1. `touched_resources` is **pure** for a fixed `(intent, ctx)` pair (same inputs → same outputs across calls). Tested by replaying recorded intents against the impl twice and asserting deep equality.
2. `touched_resources` is **independent of planner-supplied manifests** — any field of `IntentKind` that originates from the planner MUST NOT appear in the returned `TouchedResources`. Tested via property-based fuzzing (mutate planner fields; assert output unchanged).
3. `apply_terminal` is **idempotent** — calling it twice with the same artefact yields the same `DomainCommitReceipt` or returns `DomainError::AlreadyApplied`. Tested by invoking twice in a row.
4. `escalation_classes()` returns a stable, sorted, deduplicated list. Tested by parsing the slice and asserting the equivalent of `Vec::is_sorted_by(|a, b| Ord::cmp(a, b))`.

---
## §3 — `IsolationBackend` — How Subprocess VMs Are Spawned

The reference implementation runs every planner, verifier, and gateway subprocess inside a hardware-virtualised microVM (Firecracker on Linux, Apple Virtualization.framework on macOS). `R-1` only requires that the isolation primitive is "at least equivalent to a hardware-virtualized microVM, hardware enclave, or formally verified microkernel partition" — it does NOT mandate microVMs specifically. Future deployments may want enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves), Wasm sandboxes (for low-stakes verifiers), or even mock backends in test environments.

### §3.1 Trait definition

**Canonical home:** `crates/raxis-isolation/src/lib.rs` (NEW; consolidates the `SpawnBackend` design described in `system-requirements.md` §5 and `vm-network-isolation.md` §3 into a single trait).

```rust
/// Pluggable seam for the isolation primitive a subprocess runs inside.
///
/// `R-1 Domain Separation` requires intelligence to run in a domain
/// distinct from authority's address space, with the isolation
/// guarantee "at least equivalent to" a hardware-virtualised microVM.
/// Stronger primitives (enclaves) and weaker primitives (Wasm, mock)
/// are in scope as long as conformance verification confirms the
/// equivalence (or, for `MockIsolation`, asserts the impl is gated to
/// `#[cfg(test)]`).
///
/// Implementations:
/// - [`FirecrackerIsolation`] — Linux microVM via Firecracker VMM API.
/// - [`AppleVirtualizationIsolation`] — macOS native VM via Apple
///   Virtualization.framework.
/// - [`NamespaceIsolation`] — Linux namespaces + seccomp (V2 fallback
///   tier for hosts without KVM; documented as **weaker** than
///   `R-1`-conformant — disallowed in production).
/// - [`MockIsolation`] (`#[cfg(test)]` only) — in-process pseudo-VM
///   for kernel handler tests; never compiled into a release artefact.
pub trait IsolationBackend: Send + Sync + 'static {
    /// Spawn a new subprocess VM with the given image and resource
    /// envelope. Returns a `VmHandle` that can later be torn down.
    /// MUST NOT return until the VM has booted and is reachable on
    /// the listed VSock CIDs.
    fn spawn(
        &self,
        spec: &VmSpec,
    ) -> Result<VmHandle, IsolationError>;

    /// Connect to the kernel's VSock listener from the spawning host.
    /// The handle returned implements `AsyncRead + AsyncWrite` so
    /// `raxis-ipc::read_frame` works unchanged across primitives.
    fn connect_vsock(
        &self,
        vm: &VmHandle,
        port: u32,
    ) -> Result<Box<dyn DuplexStream>, IsolationError>;

    /// Stop the VM, optionally signalling SIGTERM with a graceful
    /// `grace_window` first; falls back to forced stop on timeout.
    /// MUST be idempotent (calling twice on the same handle is a
    /// no-op after the first success).
    fn stop(
        &self,
        vm: &VmHandle,
        grace_window: Option<Duration>,
    ) -> Result<StopReceipt, IsolationError>;

    /// Probe a backend property at runtime (used by `raxis doctor`):
    /// e.g., does the host have KVM? what's the boot-latency tier?
    fn capability(&self, kind: CapabilityKind) -> CapabilityValue;
}
```

`VmSpec` carries: `rootfs_image_id`, `kernel_image_id`, `vcpu_count`, `mem_mib`, `vsock_cid`, `virtio_fs_mounts`, `egress_tier` (`None` | `Tier1WithTproxy` | `Tier2WithCredentialProxy`), `cgroup_quota`, `boot_args`, `entrypoint_argv`. The trait MUST NOT accept any field that lets a planner control its own isolation envelope.

### §3.2 Reference implementations

- **`FirecrackerIsolation`** (`crates/raxis-isolation-firecracker/`, NEW) — talks directly to the Firecracker VMM API over its UDS; uses `KVM_RUN` ioctls; ~125ms boot, ~5MB RAM overhead. Implements `R-1` per `system-requirements.md` §5.1.
- **`AppleVirtualizationIsolation`** (`crates/raxis-isolation-apple-vz/`, NEW) — links against `Virtualization.framework` via `objc2-virtualization`; ~200ms boot, native Apple Silicon. Implements `R-1` per `system-requirements.md` §5.2.
- **`NamespaceIsolation`** (`crates/raxis-isolation-namespace/`, NEW; **non-conformant fallback**) — `unshare(2)` + `seccomp` filters + bind-mount-only filesystem. Documented as **weaker than R-1**: usable for evaluators who do not have KVM, **disallowed in production deployments** by `raxis doctor` (emits `[FAIL]` unless `--unsafe-fallback-isolation` was passed at startup, which records `IsolationFallbackBypass` to the audit chain).
- **`MockIsolation`** (test-only, in `crates/raxis-isolation/src/mock.rs`) — gated `#[cfg(test)]`; runs the subprocess as an OS thread inside the kernel address space (knowingly violates `R-1`); used by `kernel/tests/handlers/*.rs` to exercise admission logic without spawning real VMs.

### §3.3 Files to create

- `crates/raxis-isolation/Cargo.toml`
- `crates/raxis-isolation/src/lib.rs` — trait, `VmSpec`, `VmHandle`, `IsolationError`, `StopReceipt`, `CapabilityKind/Value`
- `crates/raxis-isolation/src/duplex.rs` — `trait DuplexStream: AsyncRead + AsyncWrite + Unpin + Send` (the VSock connection abstraction)
- `crates/raxis-isolation/src/mock.rs` — `MockIsolation` (cfg-test)
- `crates/raxis-isolation/tests/conformance.rs` — spawn/stop/connect parity test (any backend MUST pass)
- `crates/raxis-isolation-firecracker/Cargo.toml`
- `crates/raxis-isolation-firecracker/src/lib.rs` — VMM API wrapper, drive registration, network-namespace setup (per `vm-network-isolation.md`)
- `crates/raxis-isolation-firecracker/src/api.rs` — Firecracker UDS client
- `crates/raxis-isolation-firecracker/src/vsock.rs` — `vhost-vsock` wiring
- `crates/raxis-isolation-apple-vz/Cargo.toml`
- `crates/raxis-isolation-apple-vz/src/lib.rs` — `VZVirtualMachine` driver, `VZVirtioSocketDevice`
- `crates/raxis-isolation-apple-vz/build.rs` — links `Virtualization.framework`
- `crates/raxis-isolation-namespace/Cargo.toml`
- `crates/raxis-isolation-namespace/src/lib.rs` — `unshare`/`pivot_root`/`seccomp-bpf` fallback

### §3.4 Files to change

- `kernel/Cargo.toml` — add the isolation crate(s); guard apple-vz behind `#[cfg(target_os = "macos")]`, firecracker behind `#[cfg(target_os = "linux")]`
- `kernel/src/main.rs` — at boot, call `select_isolation_backend()` which checks `policy.toml [isolation]` + host capability and returns `Arc<dyn IsolationBackend>`
- `kernel/src/handlers/session.rs` — `Session::spawn_vm` switches from direct Firecracker calls to `ctx.isolation.spawn(&spec)`
- `kernel/src/runtime/heartbeat.rs` — collects `isolation.capability(CapabilityKind::BootLatencyMs)` for the `raxis doctor` snapshot
- `cli/src/commands/doctor.rs` — adds `[CHECK] isolation.tier` reporting per-host whether the active backend is `R-1`-conformant or fallback
- `crates/runtime/src/heartbeat.rs` — `Snapshot` struct gains `isolation_tier: IsolationTier` field

### §3.5 Conformance contract

A `IsolationBackend` is conformant iff:

1. `spawn` returns a handle whose `VmHandle::cid` is unique across all live spawns. Tested by spawning N=64 VMs concurrently and asserting CIDs form a set of size 64.
2. `stop(vm, Some(grace))` waits at most `grace` before resorting to forced kill. Tested with a guest that ignores SIGTERM.
3. `connect_vsock(vm, port)` round-trips a `bincode`-framed `IpcMessage` byte-identical to a UDS round-trip. Tested by replaying a recorded planner session over both transports and diffing.
4. `capability(KvmAvailable)` returns `false` when `/dev/kvm` is unreadable. Tested by chmod-ing the device in a sandboxed container.
5. The implementation is `Send + Sync + 'static` (compile-time check in `crates/raxis-isolation/tests/conformance.rs`).

---
## §4 — `CredentialBackend` — Where Secrets Live

The reference implementation reads operator credentials from plaintext files at `<data_dir>/credentials/<name>.env` (chmod 0600, kernel-OS-user) and provider credentials from `<data_dir>/providers/<provider>.toml` (chmod 0600, kernel-OS-user). This is correct for solo developers and small teams. It is wrong for any deployment under HIPAA, SOC 2, PCI-DSS, or finance compliance, where credentials must live in a managed secret store with per-access auditing and (often) hardware backing.

The intent admission pipeline does not care **where** a credential lives — it cares that:

1. The kernel can resolve a name to a value at the point of injection (per `credential-proxy.md` for in-VM injection, per `gateway/src/policy_view.rs` for provider keys).
2. The planner never sees the value (per `paradigm.md §5.1` two-credential-system architecture).
3. Every resolution is recorded in the audit chain.

That triplet is preserved across every conformant backend.

### §4.1 Trait definition

**Canonical home:** `crates/raxis-credentials/src/lib.rs` (NEW).

```rust
/// Pluggable seam for credential storage and resolution.
///
/// `R-2 Mediated I/O` requires intelligence to never see credential
/// material directly. This trait does not weaken that — every impl
/// returns the value into the kernel's address space, never into a
/// VM-readable surface. The credential-proxy and the gateway are the
/// only two consumers (per the two-credential-system architecture in
/// `paradigm.md §5.1`).
///
/// Implementations:
/// - [`FileCredentialBackend`] — plaintext files under `<data_dir>/`
///   (V2 default).
/// - Future: `VaultCredentialBackend` (HashiCorp Vault),
///   `AwsSecretsManagerBackend`, `AzureKeyVaultBackend`,
///   `Pkcs11HsmBackend` (hardware-backed signing without ever
///   exporting the raw key).
pub trait CredentialBackend: Send + Sync + 'static {
    /// Resolve a credential by its policy-declared name. The
    /// caller must already have authorisation to read it (the
    /// kernel's admission pipeline checked the policy declaration).
    /// MUST emit `CredentialAccessed` to the audit chain via the
    /// `AuditSink` injected at construction time.
    fn resolve(
        &self,
        name: &CredentialName,
        consumer: ConsumerIdentity<'_>,
    ) -> Result<CredentialValue, CredentialError>;

    /// Rotate a credential. Called only by `raxis credential rotate`,
    /// which itself is a privileged operator op gated by `INV-CERT-01`.
    /// File backend: writes the new value, fsyncs, atomic-renames.
    /// Vault backend: KV v2 versioned write.
    /// HSM backend: returns `CredentialError::RotationRequiresOutOfBand`.
    fn rotate(
        &self,
        name: &CredentialName,
        new: &CredentialValue,
        actor: OperatorId,
    ) -> Result<(), CredentialError>;

    /// Probe whether a credential exists without reading its value.
    /// Used by `raxis doctor` and policy-load-time validation.
    fn exists(&self, name: &CredentialName) -> bool;

    /// Lifetime hint: when does the value's lease expire? File backend
    /// returns `Forever`. Vault backend returns the lease TTL. The
    /// kernel uses this to schedule re-resolution before injection
    /// into a long-lived VM.
    fn lease(&self, name: &CredentialName) -> Lease;
}
```

`CredentialValue` is a `secrecy::Secret<Vec<u8>>` and MUST NOT implement `Debug` or `Display` outputs that include the bytes. `Drop` zeroes the buffer (`zeroize` crate).

### §4.2 Reference implementation: `FileCredentialBackend`

**Home:** `crates/raxis-credentials-file/src/lib.rs` (NEW; consolidates the existing reader logic from `gateway/src/policy_view.rs::load_credentials` and the planned reader for `credential-proxy.md`).

- `resolve` opens `<data_dir>/credentials/<name>.env` (or `providers/<name>.toml` for provider creds), validates `mode == 0600`, validates `uid == kernel_uid`, reads the body, returns `Secret<Vec<u8>>`.
- `rotate` writes `<data_dir>/credentials/<name>.env.tmp`, fsyncs, `rename`s atomically over the existing file, fsyncs the directory, audits `CredentialRotated`.
- `exists` is `Path::exists` plus mode/uid validation.
- `lease` is always `Lease::Forever` (file lifetime equals deployment lifetime).

### §4.3 Files to create

- `crates/raxis-credentials/Cargo.toml`
- `crates/raxis-credentials/src/lib.rs` — trait, `CredentialName`, `CredentialValue` (newtyped `Secret<Vec<u8>>`), `CredentialError`, `Lease`, `ConsumerIdentity`
- `crates/raxis-credentials/src/audit.rs` — wraps any inner backend with the `CredentialAccessed` audit emission so individual impls don't all repeat the audit step
- `crates/raxis-credentials/tests/conformance.rs` — `resolve`/`rotate`/`exists` parity, audit-emission verification, `Drop`-zeroes-bytes test
- `crates/raxis-credentials-file/Cargo.toml`
- `crates/raxis-credentials-file/src/lib.rs` — `FileCredentialBackend`
- `crates/raxis-credentials-file/src/path.rs` — canonical path resolver, mode/uid validators
- `crates/raxis-credentials-file/tests/integration.rs` — end-to-end: write a credential file, resolve, rotate, verify atomicity, verify audit event

### §4.4 Files to change

- `gateway/src/policy_view.rs` — replace direct `std::fs::read_to_string("<data_dir>/providers/...")` with `Arc<dyn CredentialBackend>::resolve("providers.<id>")`
- `kernel/src/handlers/session.rs` — at session boot, fetch in-VM credentials by name via `ctx.credentials.resolve(...)` (per `credential-proxy.md` §4.2)
- `kernel/src/main.rs` — boot `Arc<dyn CredentialBackend>` from `policy.toml [credential_backend]` setting; default to `FileCredentialBackend`
- `crates/policy/src/bundle.rs` — `PolicyBundle` gains `credential_backend: CredentialBackendKind` field with default `File`; future variants `Vault`, `AwsSecretsManager`, etc.
- `cli/src/commands/credential.rs` (NEW) — `raxis credential rotate <name>` and `raxis credential list` operator ops
- `cli/src/commands/doctor.rs` — `[CHECK] credentials.backend` validates the active backend reports healthy

### §4.5 Conformance contract

A `CredentialBackend` is conformant iff:

1. `resolve(name)` returns `Err(CredentialNotFound)` for any name not previously created. Tested by attempting unknown names.
2. `rotate(name, v1)` then `resolve(name)` returns `v1`. Tested via round-trip.
3. `rotate` is atomic — concurrent `resolve`s during rotation observe either the pre-state or the post-state, never a torn read. Tested with N=8 reader threads + 1 rotator.
4. Every `resolve` emits exactly one `CredentialAccessed` audit event with `{name, consumer_kind, consumer_id, success}`. Tested by intercepting the injected `Arc<dyn AuditSink>` with `FakeAuditSink`.
5. `CredentialValue` zeroes its memory on `Drop`. Tested by leaking the bytes via a `Vec<u8>` raw pointer captured before drop, observing the bytes are zeroed after the value goes out of scope (uses `zeroize::Zeroize` semantics).

---
## §5 — `AuditSink` — Where Sealed Events Land

`R-7 Cryptographic Audit Chain` says the modification of any audit event must be detectable by an independent verifier holding only the public keys of recorded signers. The chain math is invariant: every event holds `prev_sha256`, the kernel computes it from the previous event's canonical bytes, the verifier walks the chain forward.

Where the resulting bytes are **persisted** is a deployment choice. The reference implementation appends to local JSONL segments under `<data_dir>/audit/`. RAXIS Cloud will write to S3 with object-lock. Regulated finance will mirror to a Sigstore/Rekor transparency log. Air-gapped government will keep local files plus periodic USB exports. None of those changes the chain semantics — only the byte persistence.

The `AuditSink` trait already exists in `crates/audit/src/sink.rs` (today: `FileAuditSink`, `FakeAuditSink`). V2 promotes it from "internal abstraction for testability" to "first-class extensibility point" and broadens the interface so alternate sinks can be implemented.

### §5.1 Trait definition (revised)

**Canonical home:** `crates/audit/src/sink.rs` (EXISTS; broaden the contract).

```rust
/// Pluggable seam for sealed-audit-event persistence.
///
/// `R-7 Cryptographic Audit Chain` requires audit-log modifications
/// to be detectable by an independent verifier with public keys only.
/// The HASH CHAIN is computed by the kernel (`crates/audit/src/writer.rs`)
/// — it is paradigm-load-bearing and stays in concrete kernel code.
/// This trait is **only** the storage backend underneath the writer.
///
/// Implementations:
/// - [`FileAuditSink`] — JSONL segments under `<data_dir>/audit/`
///   (V2 default).
/// - [`FakeAuditSink`] — in-memory capture for tests.
/// - Future: `PostgresAuditSink`, `S3AuditSink`,
///   `RekorTransparencyLogSink`, `UsbExportingFileSink`.
pub trait AuditSink: Send + Sync + 'static {
    /// Append one already-sealed event. The sink MUST persist
    /// durably (fsync semantics or equivalent) before returning Ok.
    /// Returns the assigned `seq` and `event_id` so downstream
    /// fanouts can cross-reference.
    fn emit(
        &self,
        kind: AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<AuditEvent, AuditWriterError>;

    /// V2 ADDITION: read events in chain order for offline
    /// verification and recovery. The sink MUST return events in
    /// strict `seq` ascending order. Used by `raxis audit verify`
    /// and `raxis audit replay` (per `v3/audit-retention.md`).
    fn read_range(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<AuditEvent>, AuditWriterError>;

    /// V2 ADDITION: explicit sync barrier. Called by the kernel
    /// after every store-transaction commit to ensure the audit
    /// pointer's "this commit was durable" promise holds. File
    /// backend: fsync segment + parent dir. S3 backend: complete
    /// the multipart upload + verify ETag.
    fn sync(&self) -> Result<(), AuditWriterError>;

    /// V2 ADDITION: the highest `seq` durably persisted. Used by
    /// recovery to detect mid-emit crashes (`crates/audit/reader.rs`).
    fn highest_durable_seq(&self) -> Result<Option<u64>, AuditWriterError>;
}
```

The existing `FileAuditSink` and `FakeAuditSink` impls in `crates/audit/src/sink.rs` are extended with `read_range`, `sync`, and `highest_durable_seq`.

### §5.2 Why the chain stays kernel-side

The kernel's `AuditWriter` (`crates/audit/src/writer.rs`) computes `event.prev_sha256 = sha256(canonicalise(prev))` before calling `sink.emit(...)`. The sink only stores; it does NOT compute the hash, choose `seq`, or pick `event_id`. Substituting a sink CANNOT weaken `R-7` because the chain is verifiable on bytes the sink merely persists, not on bytes the sink generates.

This split is what lets RAXIS Cloud have an immutable cloud ledger while still satisfying `R-7`: the cloud ledger is just bytes; the bytes verify against the chain anchored in genesis.

### §5.3 Files to create

- `crates/audit/tests/conformance.rs` (NEW) — exercises any backend's `emit`/`read_range`/`sync`/`highest_durable_seq` contract; current `FileAuditSink` and `FakeAuditSink` MUST pass

### §5.4 Files to change

- `crates/audit/src/sink.rs` — extend the `AuditSink` trait with `read_range`, `sync`, `highest_durable_seq` (existing trait keeps `emit` unchanged)
- `crates/audit/src/sink.rs` — extend `FileAuditSink` with the new methods (reads back from segment files; `sync` fsyncs the segment writer; `highest_durable_seq` reads the audit pointer)
- `crates/audit/src/sink.rs` — extend `FakeAuditSink` symmetrically (returns from in-memory vec)
- `crates/audit/src/reader.rs` — `verify_chain_*` functions accept `&dyn AuditSink` instead of `&Path`, so RAXIS Cloud / Postgres backends can be verified without exporting to disk first
- `kernel/src/main.rs` — boot site reads `policy.toml [audit_sink]` and constructs the corresponding sink; default is `FileAuditSink`
- `cli/src/commands/audit.rs` — `raxis audit verify` reads via `ctx.audit_sink.read_range(...)` instead of opening `<data_dir>/audit/*.jsonl` directly
- `cli/src/commands/doctor.rs` — `[CHECK] audit.sink_health` calls `sink.sync()` and `highest_durable_seq()` and reports

Future (V3+):
- `crates/audit-postgres/` — `PostgresAuditSink` for enterprise
- `crates/audit-s3/` — `S3AuditSink` with object-lock
- `crates/audit-rekor/` — `RekorTransparencyLogSink` mirror

### §5.5 Conformance contract

An `AuditSink` is conformant iff:

1. After `emit(e1)` returns `Ok`, then `emit(e2)` returns `Ok`, `read_range(0, 2)` returns `[e1, e2]` in that exact order. Tested by round-trip with two events and asserting the sequence.
2. `sync()` is a hard barrier: any `emit` that returned `Ok` BEFORE a successful `sync()` MUST be retrievable from `read_range` after a process restart (or, in `FakeAuditSink`, after re-reading the in-memory vector). Tested by emitting → sync → killing the process → restarting → reading.
3. `highest_durable_seq()` increments monotonically across the lifetime of the deployment. Tested by emitting 100 events and asserting `highest_durable_seq() == 99` after each batch of 10.
4. The sink MUST NOT mutate event bytes — the `prev_sha256` field of event N+1 MUST hash-validate against the canonical bytes of event N as returned by `read_range`. Tested by reading back a chain and running `verify_chain_strict`.
5. `INV-STORE-02` ordering: the kernel's contract that `audit.emit(...)` is called only AFTER the matching `tx.commit()` returned `Ok` is preserved (the trait does not enforce this; the conformance kit calls out that the contract lives in the kernel review process per `kernel-store.md §2.5.2`).

---
## §6 — `OperatorTransport` — How the Operator CLI Reaches the Kernel

The reference implementation listens on a Unix Domain Socket at `<data_dir>/operator.sock` and authenticates the operator via Ed25519 challenge-response (`cli/src/conn.rs`). The CLI runs on the same host as the kernel; the UDS is `0700`-permissioned to the kernel user; the OS enforces the trust boundary.

This is correct for self-hosted deployments. It is wrong for:

- **RAXIS Cloud (managed)** — the operator's CLI runs on a laptop; the kernel runs in a managed datacenter. The transport must be mTLS-authenticated TCP/gRPC across the network.
- **Enterprise fleet** — a centralised control plane manages hundreds of kernel instances; each kernel exposes a transport reachable by the control plane (mTLS gRPC into a private subnet).
- **Air-gapped + relay** — the operator submits commands via a separate physical relay machine that bridges to the air-gapped kernel; the transport must work over an out-of-band serial or USB channel.

The challenge-response auth ceremony (`cli/src/conn.rs::handshake`) is **identical** across all four scenarios. Only the wire is different. That's exactly the shape that calls for a trait.

### §6.1 Trait definition

**Canonical home:** `crates/raxis-operator-transport/src/lib.rs` (NEW; consolidates the listener-binding logic from `kernel/src/ipc/server.rs::accept_operator_loop` and the connect-side from `cli/src/conn.rs`).

```rust
/// Pluggable seam for the operator CLI ↔ kernel wire.
///
/// `R-9 Attributable Intent` and `R-12 Out-of-Band Escalation`
/// require this channel to (a) be unforgeable by intelligence and
/// (b) authenticate to a human principal. The Ed25519
/// challenge-response handshake stays the same across every wire.
/// Only the byte transport changes.
///
/// Implementations:
/// - [`UnixSocketTransport`] — `<data_dir>/operator.sock` (V2 default).
/// - Future: `MtlsGrpcTransport`, `WebsocketOverHttpsTransport`,
///   `SerialUsbRelayTransport`.
pub trait OperatorTransport: Send + Sync + 'static {
    /// The listener type, capable of accepting connections.
    type Listener: Send + Sync;
    /// The per-operator-call connection, framed by raxis-ipc::json_frame.
    type Connection: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin;

    /// Bind the listener at startup. UDS impl: bind+chmod 0700+chown.
    /// gRPC impl: bind a TLS-terminated listener with the kernel's
    /// server cert + mandatory client-cert verification.
    /// MUST emit `OperatorTransportListening { kind, endpoint }` to
    /// the audit chain on success.
    fn bind(
        &self,
        config: &TransportConfig,
    ) -> Result<Self::Listener, TransportError>;

    /// Accept one operator connection. The handshake (Ed25519
    /// challenge-response) runs after `accept` returns and is NOT
    /// the trait's job — the kernel runs it on the returned
    /// `Connection` regardless of transport.
    async fn accept(
        &self,
        listener: &Self::Listener,
    ) -> Result<(Self::Connection, PeerMeta), TransportError>;

    /// CLI side: dial the kernel given a transport-appropriate
    /// endpoint string. UDS: a path. gRPC: a URL. The CLI then runs
    /// the same challenge-response loop on the returned conn.
    async fn dial(
        &self,
        endpoint: &str,
    ) -> Result<Self::Connection, TransportError>;
}
```

`PeerMeta` carries transport-level peer identity hints (UDS uid, mTLS subject DN, etc.). The kernel does NOT trust `PeerMeta` for authority — the Ed25519 signature is the trust root. `PeerMeta` is logged for forensics and can be used to enforce defence-in-depth (e.g., reject a connection whose UDS uid doesn't match `kernel_uid` even if the signature would pass).

### §6.2 Reference implementation: `UnixSocketTransport`

**Home:** `crates/raxis-operator-transport-unix/src/lib.rs` (NEW; carved out of `kernel/src/ipc/server.rs::accept_operator_loop` and `cli/src/conn.rs::open_operator_connection`).

`bind`: opens `<data_dir>/operator.sock`, `chmod 0700`, `chown` to kernel uid; drops the socket on graceful shutdown.

`accept`: `tokio::net::UnixListener::accept` returning `(UnixStream, PeerMeta { uid, gid, pid })`.

`dial`: `tokio::net::UnixStream::connect`.

### §6.3 Files to create

- `crates/raxis-operator-transport/Cargo.toml`
- `crates/raxis-operator-transport/src/lib.rs` — trait, `TransportConfig`, `PeerMeta`, `TransportError`
- `crates/raxis-operator-transport/src/handshake.rs` — the transport-agnostic Ed25519 challenge-response (currently duplicated in `kernel/src/ipc/operator.rs::challenge` and `cli/src/conn.rs::handshake`; consolidated here)
- `crates/raxis-operator-transport/tests/conformance.rs`
- `crates/raxis-operator-transport-unix/Cargo.toml`
- `crates/raxis-operator-transport-unix/src/lib.rs` — `UnixSocketTransport`
- `crates/raxis-operator-transport-unix/tests/integration.rs` — bind, dial, full handshake, JSON-frame round-trip

### §6.4 Files to change

- `kernel/src/ipc/server.rs` — `accept_operator_loop` becomes generic over `Arc<dyn OperatorTransport>`; replace direct `UnixListener::bind` with `transport.bind(...)`
- `kernel/src/ipc/operator.rs` — extract `challenge`/`verify_signature` into `crates/raxis-operator-transport/src/handshake.rs` and re-export
- `cli/src/conn.rs` — replace direct `UnixStream::connect` with `transport.dial(...)`; transport selected from CLI config (`--transport unix:<path>` default; future: `--transport grpc:<url>`)
- `kernel/src/main.rs` — boot site reads `policy.toml [operator_transport]` and constructs the transport; default is `UnixSocketTransport`
- `crates/policy/src/bundle.rs` — `PolicyBundle` gains `operator_transport: OperatorTransportKind` field
- `cli/src/commands/doctor.rs` — `[CHECK] transport.reachability` dials the configured transport and runs a no-op handshake

Future (V3+):
- `crates/raxis-operator-transport-grpc/` — `MtlsGrpcTransport`
- `crates/raxis-operator-transport-relay/` — `SerialUsbRelayTransport` for air-gapped relay use

### §6.5 Conformance contract

An `OperatorTransport` is conformant iff:

1. `bind` then `dial` then `accept` returns a paired `(Connection, Connection)` whose JSON-framed bytes round-trip identically. Tested by sending an `OperatorRequest::Status` and asserting the `OperatorResponse` decodes correctly.
2. `accept`'s returned `PeerMeta` is non-spoofable from the dialer side. Tested by attempting to dial with a fabricated `PeerMeta` and asserting the kernel-side observation reflects the OS truth, not the dialer's claim.
3. The transport carries the Ed25519 challenge-response **unchanged** — the same handshake bytes that worked over UDS work over the new transport. Tested via the shared `handshake` conformance kit.
4. `bind` is idempotent in the sense that re-running on a clean shutdown succeeds; on dirty shutdown (stale UDS file, lingering TLS port) the impl MUST detect and clean up OR return `TransportError::EndpointBusy`. Tested by SIGKILL → restart.
5. The transport MUST NOT introduce a path by which a planner VM can dial the operator endpoint. UDS impl is fine because the planner has no host filesystem path; gRPC impl MUST live on a network namespace the planner VM cannot reach. Tested by attempting `transport.dial(...)` from inside a `MockIsolation` VM and asserting failure.

---
## §7 — `InferenceRouter` — How LLM Inference Is Routed and Metered

The reference implementation ships a `raxis-gateway` worker pool that forwards `InferenceRequest` IPC messages over HTTPS to public LLM providers (Anthropic, OpenAI, Google Gemini), with the kernel computing token cost and consuming budget before forwarding (`provider-failure-handling.md` §4, `provider-model-selection.md` §6).

This is correct for the SE reference deployment. It is wrong for:

- **Trading** — the model must run on local GPUs (vLLM, TGI). Sending order-decision context over the public internet to OpenAI is unacceptable.
- **Healthcare under HIPAA** — the model must be on-premise. No PHI may leave the network.
- **Regulated finance with on-prem fine-tuned models** — the gateway must route to a colocated GPU cluster, not to a SaaS provider.
- **Air-gapped** — there is no public internet at all; inference must run in-cluster.

What is unchanged across these scenarios:

- The kernel computes admission cost (`crates/policy::compute_admission_cost`) and consumes budget (`kernel/src/scheduler/budget.rs::consume_budget`) **before** the request leaves the kernel.
- The planner has no provider credentials and no DNS exit (`INV-02A`, `INV-02B`).
- The audit chain records `InferenceRequested` and `InferenceCompleted` with the resolved provider, model, and observed token usage.

What changes: the bytes between the gateway worker and the actual LLM endpoint. That's the trait surface.

### §7.1 Trait definition

**Canonical home:** `crates/raxis-inference-router/src/lib.rs` (NEW; consolidates the dispatch logic from `gateway/src/dispatch.rs::handle_fetch_request` extended for inference).

```rust
/// Pluggable seam for LLM inference routing.
///
/// `R-2 Mediated I/O` requires the planner to never see provider
/// credentials, never have direct egress, and never decide which
/// model is called (per `provider-model-selection.md`). Those
/// invariants are preserved by the kernel — the router only
/// consumes a *resolved* `(provider_id, model_id)` and dispatches
/// the call. Where the dispatched call goes is the trait's job.
///
/// Implementations:
/// - [`HttpsGatewayRouter`] — kernel-spawned `raxis-gateway` worker
///   pool calling Anthropic / OpenAI / Gemini over HTTPS (V2 default).
/// - Future: `LocalVllmRouter` (on-host GPU vLLM endpoint),
///   `LocalTgiRouter` (Hugging Face TGI), `KubernetesInferenceRouter`
///   (in-cluster gRPC inference service), `MockRouter` (tests).
pub trait InferenceRouter: Send + Sync + 'static {
    /// Dispatch a resolved inference request. The kernel has already:
    ///   - admitted the request (path/budget/policy checks),
    ///   - computed `compute_admission_cost(touched_paths, kind, policy)`,
    ///   - consumed the lane budget (worst-case-reservation per
    ///     `INV-PROVIDER-05`),
    ///   - emitted `InferenceRequested` to the audit chain.
    /// On return Ok, the kernel:
    ///   - reconciles actual vs. reserved tokens,
    ///   - emits `InferenceCompleted`,
    ///   - returns the response to the planner.
    /// On return Err with a retriable kind, the kernel may retry
    /// per `provider-failure-handling.md` §3.
    async fn complete(
        &self,
        req: ResolvedInferenceRequest<'_>,
    ) -> Result<InferenceResponse, InferenceError>;

    /// Streaming variant (for long completions where the planner
    /// wants partial results). Returns a stream the kernel forwards
    /// frame-by-frame to the planner via `KernelPush` per
    /// `kernel-push-protocol.md`. Atomicity is the kernel's
    /// responsibility — the router is allowed to fail mid-stream
    /// and the kernel will resolve to a consistent outcome.
    fn complete_streaming(
        &self,
        req: ResolvedInferenceRequest<'_>,
    ) -> Result<InferenceStream, InferenceError>;

    /// Probe the configured providers for liveness. Used by
    /// `raxis doctor` and the circuit breaker
    /// (`provider-failure-handling.md` §5).
    async fn provider_health(
        &self,
        provider_id: &ProviderId,
    ) -> Result<ProviderHealth, InferenceError>;
}
```

`ResolvedInferenceRequest` carries: `provider_id`, `model_id`, `system_prompt_bytes`, `user_prompt_bytes`, `tool_manifest`, `max_tokens`, `request_id`, `session_id`. The kernel populates every field; the planner influences only the user prompt content (already sandboxed by the kernel-prepended NNSP per `kernel-mechanics-prompt.md` §3).

`InferenceResponse` carries: `provider_observed_token_in`, `provider_observed_token_out`, `model_id_actual` (provider may auto-route within a family), `response_bytes`, `provider_request_id` (for cross-referencing with provider's own logs), `wallclock_ms`.

### §7.2 Reference implementation: `HttpsGatewayRouter`

**Home:** `crates/raxis-inference-router-https/src/lib.rs` (NEW; carved out of the existing `gateway/src/dispatch.rs` and `gateway/src/backend.rs`).

- `complete`: sends `GatewayMessage::InferenceRequest { resolved_req }` over the kernel↔gateway UDS to a worker; the worker reads provider credentials from its in-process `PolicyView::providers` and POSTs to the provider; returns the response.
- `complete_streaming`: same dispatch, returns a stream the kernel multiplexes into `KernelPush::InferenceStreamFrame`.
- `provider_health`: a worker hits the provider's `GET /v1/models` (or equivalent) and returns latency + last-seen-error.

The existing `Backend` trait in `gateway/src/backend.rs` is **internal** to the gateway crate (it abstracts mock vs. real HTTP for testing the gateway in isolation). `InferenceRouter` is a different abstraction layer — it's how the kernel talks to *any* router, of which the gateway-worker-pool router is one impl.

### §7.3 Files to create

- `crates/raxis-inference-router/Cargo.toml`
- `crates/raxis-inference-router/src/lib.rs` — trait, `ResolvedInferenceRequest`, `InferenceResponse`, `InferenceStream`, `InferenceError`, `ProviderHealth`
- `crates/raxis-inference-router/tests/conformance.rs` — exercises `complete`/`complete_streaming` parity, retriability classification, mock-router test fixture
- `crates/raxis-inference-router-https/Cargo.toml`
- `crates/raxis-inference-router-https/src/lib.rs` — `HttpsGatewayRouter`
- `crates/raxis-inference-router-https/src/dispatch.rs` — wraps the existing kernel↔gateway UDS protocol; depends on `raxis-ipc`

### §7.4 Files to change

- `gateway/src/lib.rs` — exposes the `Backend` trait as **internal** (gateway-only); the `Backend` is unchanged
- `gateway/src/runtime.rs` — `run_gateway` is exposed as the in-process body that `HttpsGatewayRouter` invokes when running the kernel-spawned-gateway topology; future routers may bypass it entirely
- `kernel/src/handlers/inference.rs` (NEW) — the kernel's inference admission handler now calls `ctx.inference_router.complete(...)` after admission/budget/audit instead of speaking directly to the gateway socket
- `kernel/src/main.rs` — boot site reads `policy.toml [inference_router]` and constructs the router; default is `HttpsGatewayRouter`
- `kernel/src/scheduler/budget.rs` — `reconcile_after_completion` is unchanged but now consumes `InferenceResponse::provider_observed_token_*` from the trait return value
- `crates/policy/src/bundle.rs` — `PolicyBundle` gains `inference_router: InferenceRouterKind` (`HttpsGateway` default; `LocalVllm`, `LocalTgi`, `KubernetesService` future)
- `cli/src/commands/doctor.rs` — `[CHECK] inference.providers` calls `provider_health` on every configured `[provider_aliases]`

### §7.5 Conformance contract

An `InferenceRouter` is conformant iff:

1. `complete(req)` does NOT mutate `req.system_prompt_bytes` or `req.user_prompt_bytes` before dispatch. Tested by intercepting bytes mid-dispatch (mock router) and diffing against the input.
2. `complete` MUST NOT pass through any planner-supplied field other than what the kernel resolved into `ResolvedInferenceRequest`. Tested by submitting a planner request with extra fields and asserting they don't reach the router.
3. `complete`'s `InferenceResponse::provider_observed_token_*` MUST be the **provider-reported** token usage, not a router-side estimate. Tested by comparing the field against the provider's HTTP response body's `usage.prompt_tokens` / `usage.completion_tokens` (for OpenAI-shaped APIs).
4. `complete_streaming`'s aggregated frames MUST equal `complete`'s response when both are run with identical input. Tested by replaying a fixture and diffing.
5. `provider_health` is non-blocking with a hard timeout (default 5s). Tested with a mock that hangs forever; the call MUST return `ProviderHealth::Timeout` within the bound.
6. The router MUST NOT call out to a provider not present in `policy.toml [providers]`. Tested by submitting a request with `provider_id = "unknown"` and asserting `Err(InferenceError::ProviderNotConfigured)`.

---
## §8 — What Stays Concrete (And Why)

The five sections above name the seams. Equally important is what does NOT get a trait. The kernel's value proposition is the admission pipeline; abstracting it would hollow out the product. The list:

| Subsystem | Canonical home | Why concrete |
|---|---|---|
| Intent admission pipeline (the 13-step gate check) | `kernel/src/handlers/intent.rs` | This **is** the kernel. Every `R-3`/`R-4`/`R-5`/`R-6` enforcement happens here. Substituting it would let an impl claim RAXIS while violating those invariants. |
| Policy parser | `crates/policy/src/loader.rs`, `crates/policy/src/bundle.rs` | The signed-TOML schema is the RAXIS protocol. New domains add new fields (`[trading]`, `[healthcare]`); they do NOT swap the parser. The parser is verifiable by the conformance test suite. |
| Plan parser | `crates/policy/src/bundle.rs` (`Plan*` types) | Same reasoning. `plan.toml` is part of the RAXIS protocol. |
| Escalation FSM | `kernel/src/handlers/escalation.rs`, `crates/types/src/escalation.rs` | The `Pending → Approved → Consumed` transitions and the eight `validate_approval_token` checks are paradigm-level (`R-12`). New escalation classes are enum variants on `IntentKind::EscalationRequest::class`, NOT trait swaps. |
| Hash chain / Merkle logic | `crates/audit/src/writer.rs`, V3 `crates/audit/src/merkle.rs` | This **is** `R-7`. The verifier (`crates/audit/src/reader.rs`) and the writer have to agree on the algorithm; substituting either one breaks tamper-evidence. |
| `IntentRequest` / `KernelPush` framing | `crates/ipc/src/frame.rs`, `crates/ipc/src/message.rs` | The wire contract binds every planner ever written. Changing it breaks all clients. |
| Session token model | `kernel/src/authority/session.rs`, `crates/types/src/id.rs::SessionId` | `R-9 Attributable Intent` is enforced here. Per-session 256-bit CSPRNG token bound to a session row is paradigm-level. |
| Policy epoch advance | `kernel/src/policy_manager.rs` | `INV-POLICY-01` (Phase 1 atomicity, Phase 2 ArcSwap, Phase 3 best-effort gateway signal) is a paradigm-load-bearing transaction shape. |
| Policy → Plan → Delegation hierarchy narrowing | `kernel/src/initiatives/lifecycle.rs::approve_plan`, `kernel/src/authority/delegation.rs` | `R-4 Authority Derivation Hierarchy`. The narrowing check is an algorithmic property of the schema, not a deployment choice. |
| Worst-case-budget reservation | `kernel/src/scheduler/budget.rs` | `INV-PROVIDER-05`. The pre-reserve-then-reconcile pattern is what prevents budget bypass via "tokens-came-back-cheaper-than-expected" races. |
| The `vcs::diff`-derived touched-paths computation | `kernel/src/vcs/diff.rs` (will move to `crates/raxis-domain-se/src/touched.rs` per §2.4) | `INV-07`. Paths are derived from authoritative VCS state, not planner manifests; for non-SE domains, `DomainAdapter::touched_resources` is the analogue, also derived from authoritative state. |

The **shape** of the rule: if substituting the subsystem could let an impl satisfy the literal `R-*` invariants while not really enforcing them, the subsystem is concrete. If substituting the subsystem changes only the persistence/transport/credential-store/inference-destination — leaving the `R-*` enforcement undisturbed — it's a trait.

---

## §9 — Wiring at Boot: How the Six Traits Compose

The kernel has exactly **one** boot site that constructs every trait impl: `kernel/src/main.rs::main`. Per §1.2, V2 ships only the default impl of each trait, but the wiring is structured so future impls can plug in without touching admission code.

### §9.1 Construction order (matters)

```
1. Load policy.toml + verify operator signature (concrete)
2. Open store (kernel.db) (concrete)
3. Construct AuditSink (§5)              ← needed by every later step
4. Construct CredentialBackend (§4)      ← uses AuditSink for emit
5. Construct InferenceRouter (§7)        ← uses CredentialBackend for provider keys
6. Construct IsolationBackend (§3)       ← uses CredentialBackend for VM kernel signing
7. Construct DomainAdapter (§2)          ← uses IsolationBackend to spawn verifier VMs
8. Construct OperatorTransport (§6)      ← bound last; once accepting, kernel is "open"
9. Run intent admission loop (concrete; depends on every trait above via HandlerContext)
```

Order is load-bearing: step 5 needs step 4 to fetch provider creds; step 6 needs step 4 because Apple Virtualization wants signed kernel images; step 9's `HandlerContext` carries `Arc<dyn Trait>` references to all six.

### §9.2 `HandlerContext` shape

`kernel/src/handlers/mod.rs` defines:

```rust
pub struct HandlerContext {
    // Existing concrete fields:
    pub store: Arc<Store>,
    pub policy: Arc<ArcSwap<PolicyBundle>>,
    pub clock: Arc<dyn Clock>,
    // New / promoted trait fields (V2):
    pub audit_sink: Arc<dyn AuditSink>,
    pub credentials: Arc<dyn CredentialBackend>,
    pub inference_router: Arc<dyn InferenceRouter>,
    pub isolation: Arc<dyn IsolationBackend>,
    pub domain: Arc<dyn DomainAdapter<IntentKind = IntentKind, TerminalArtefact = (CommitSha, String)>>,
    pub operator_transport: Arc<dyn OperatorTransport>,
}
```

Every handler in `kernel/src/handlers/*.rs` reaches concrete behavior via `ctx.<trait>.*`. There is no path by which a handler instantiates a concrete impl — the rule is enforced by a `clippy::disallowed_types` lint set in `kernel/Cargo.toml`'s lint config that bans `FileAuditSink::new`, `FirecrackerIsolation::new`, etc., from being constructed in `kernel/src/handlers/`.

### §9.3 Files to change at the wiring layer

- `kernel/Cargo.toml` — add the six trait crates plus their default-impl crates as dependencies
- `kernel/src/main.rs` — replace the existing concrete construction (e.g., direct `FileAuditSink::new`, direct `UnixListener::bind`) with `select_*_from_policy(&policy)` calls per §9.1
- `kernel/src/handlers/mod.rs` — extend `HandlerContext` with the six new fields
- `kernel/src/handlers/*.rs` — replace direct concrete calls with `ctx.<trait>` calls (one PR per handler so review surface stays bounded)
- Linting: a new file `kernel/clippy.toml` declaring `disallowed-types` for direct concrete construction inside handlers
- `kernel/tests/wiring/*.rs` (NEW) — for each trait, a test that swaps in the `Mock*` / `Fake*` impl via `HandlerContext::test_with(...)` and exercises the admission pipeline

### §9.4 Test-time composability

`crates/raxis-test-support/src/lib.rs` is extended with:

```rust
pub struct TestKernelContext {
    pub store: Store,
    pub audit: Arc<FakeAuditSink>,
    pub credentials: Arc<MockCredentialBackend>,
    pub inference: Arc<MockInferenceRouter>,
    pub isolation: Arc<MockIsolation>,
    pub domain: Arc<SoftwareEngineeringAdapter>,
    pub transport: Arc<UnixSocketTransport>,
    // ...
}
```

Existing kernel tests (`kernel/tests/mock_planner_end_to_end.rs`, `kernel/tests/kernel_full_lifecycle_e2e.rs`) are migrated to this shape. The migration is mechanical — replace `let kernel = build_kernel(...);` with `let ctx = TestKernelContext::new();` and re-route handler invocations through `ctx`.

---

## §10 — V2 Migration Plan (Phased, Mergeable)

The trait extraction touches the kernel boot site and every handler. Doing it as one PR is unreviewable. The migration is structured as five phases, each independently shippable:

**Phase A — Trait crates exist.** Create `crates/raxis-domain`, `crates/raxis-isolation`, `crates/raxis-credentials`, `crates/raxis-operator-transport`, `crates/raxis-inference-router`. Each contains only the trait, error types, and conformance kit. No impls. The kernel does not depend on them yet. Mergeable in one PR per crate.

**Phase B — Default impls in their own crates.** Create `crates/raxis-domain-se`, `crates/raxis-isolation-firecracker`, `crates/raxis-isolation-apple-vz`, `crates/raxis-credentials-file`, `crates/raxis-operator-transport-unix`, `crates/raxis-inference-router-https`. Each is a thin re-export of the existing concrete logic, refactored to implement the trait. The kernel still uses the old concrete types directly. Mergeable in one PR per impl.

**Phase C — `AuditSink` already in `crates/audit/src/sink.rs` is broadened.** Add `read_range`, `sync`, `highest_durable_seq` to the existing trait; extend `FileAuditSink` and `FakeAuditSink`. The conformance test now runs against both. Single PR.

**Phase D — Kernel wires through traits.** `HandlerContext` extended; `kernel/src/main.rs` boot site updated; one handler at a time switched from concrete to `ctx.<trait>`. One PR per handler (intent, witness, escalation, session, merge, …). After this phase, the kernel only knows about traits.

**Phase E — Conformance-kit gates land in CI.** `cargo test --workspace` runs every trait's conformance kit against every default impl. Future alternative impls (Vault, gRPC, vLLM) will get the same gate for free.

After Phase E, V2 ships. V3+ adds alternative impls (`PostgresAuditSink`, `MtlsGrpcTransport`, `LocalVllmRouter`, `Pkcs11HsmBackend`) without touching the kernel.

---

## §11 — Cross-Spec Impacts

These specs are updated to reference `extensibility-traits.md` at the relevant integration points. The references are added in the same commit cycle as this spec (one commit per affected spec for reviewability):

| Spec | Trait it consumes | Reference to add |
|---|---|---|
| `v2/credential-proxy.md` | `CredentialBackend` | §1 introduction notes "the resolution backend is pluggable per `extensibility-traits.md` §4"; checklist (§10) adds an item to refactor the credential reader to take `Arc<dyn CredentialBackend>` |
| `v2/provider-failure-handling.md` | `InferenceRouter` | §1 introduction notes "the inference dispatch backend is pluggable per `extensibility-traits.md` §7"; the kernel↔gateway protocol becomes the implementation of `HttpsGatewayRouter`, not a kernel-baked concrete |
| `v2/provider-model-selection.md` | `InferenceRouter` | §6 (resolution) clarifies that resolution returns a `ResolvedInferenceRequest` consumed by an `InferenceRouter` impl |
| `v2/system-requirements.md` | `IsolationBackend` | §5 (Hypervisor) reframes Firecracker / Apple-VZ / Namespace as the V2-shipped impls of `IsolationBackend`; raxis doctor §11 adds `[CHECK] isolation.tier` referencing `extensibility-traits.md` §3.5 |
| `v2/vm-network-isolation.md` | `IsolationBackend` | §3 (boot path) clarifies the spec describes the V2 default `FirecrackerIsolation` Tier-1 networking; alternative isolation backends MUST satisfy the same Tier-1 contract per §3.5 conformance |
| `v2/kernel-lifecycle.md` | `OperatorTransport` | §3 (kernel start) and §13 implementation checklist note the operator socket bind delegates to `Arc<dyn OperatorTransport>::bind` |
| `v2/v2-deep-spec.md` | All six | "Related Specifications" appendix gains a row for `extensibility-traits.md`; Part 2 (Authorization) gains a forward-pointer to the trait map |
| `v1/kernel-store.md` | `AuditSink` | §2.5.2 footnote adds "the AuditSink trait is V2-extensibility-pluggable per `v2/extensibility-traits.md` §5; the chain math stays in the writer" |
| `paradigm.md` | All six | §6 (Mapping) gains a sentence noting the reference implementation exposes six trait boundaries; §5.1 (current reference impl) adds a one-line pointer |
| `invariants.md` | n/a | New `INV-EXT-*` (extensibility) section optional for V2; for now, the conformance kit IS the enforcement |

---

## §12 — Conformance Kit Layout

For every trait, the conformance kit is a re-runnable `cargo test`-style suite that asserts the contract regardless of the impl. Layout:

```
crates/raxis-<trait>/
  src/
    lib.rs           ← trait definition + error types
    conformance.rs   ← reusable test fixture (the "kit")
  tests/
    conformance.rs   ← runs the kit against every default impl in this crate's dev-deps
```

Any future impl in any future crate runs the same kit by depending on `raxis-<trait>` and calling, e.g.:

```rust
#[test]
fn vault_credential_backend_conforms() {
    raxis_credentials::conformance::run_kit(|| Box::new(VaultCredentialBackend::new(...)));
}
```

The kit returns a `ConformanceReport { passed: u32, failed: Vec<Failure> }`. CI gates on `report.failed.is_empty()`.

---

## §13 — Foundational Design Decisions

### §13.1 Why six, not five, and not seven

**Decision.** Exactly six traits: `DomainAdapter`, `IsolationBackend`, `CredentialBackend`, `AuditSink`, `OperatorTransport`, `InferenceRouter`.

**Considered alternative — five traits (collapse `OperatorTransport` into `IsolationBackend`).** Rejected: the operator transport's auth ceremony (Ed25519 challenge-response) is independent of the agent isolation primitive. RAXIS Cloud runs the kernel on Linux Firecracker hosts AND operates over mTLS gRPC. The two seams are orthogonal.

**Considered alternative — seven traits (split `InferenceRouter` into `Provider` and `Router`).** Rejected: provider integration (auth, retry, parsing) is internal to the router impl. Operators don't swap providers; they swap routers (the entire dispatch path). Adding a provider trait creates a configuration surface (which router uses which providers) that benefits no real deployment.

**Considered alternative — eight traits (add `PolicyParser`, `EscalationFsm`).** Rejected: those are paradigm-level (`R-3`, `R-12`). Substituting them would let an impl claim RAXIS conformance while not enforcing the paradigm.

**Scenario it prevents.** A future PR proposes adding a `BudgetCalculator` trait so different deployments can use different cost models. The §1.1 rule (does substitution weaken any `R-*`?) immediately catches that worst-case-reservation per `INV-PROVIDER-05` is paradigm-load-bearing — substituting the calculator would let a buggy impl undercount and bypass `R-5`. The PR is rejected; a configurable cost *model* (data, not code) inside the existing concrete `compute_admission_cost` is the right answer.

### §13.2 Why default impls live in separate crates

**Decision.** `crates/raxis-credentials/` holds the trait; `crates/raxis-credentials-file/` holds the V2 default; future `crates/raxis-credentials-vault/` holds the Vault impl.

**Rejected alternative** — keep the trait and default impl in the same crate (`raxis-credentials` exports both `CredentialBackend` and `FileCredentialBackend`). Rejected because: (a) the kernel would gain a transitive build dep on the file-system specifics (chmod/uid checks) even when running with a Vault backend; (b) the conformance kit for the trait should not depend on any specific impl. Separating them keeps the trait crate small (~200 lines) and the default-impl crate replaceable.

### §13.3 Why `AuditSink` extends in place rather than getting a new trait

**Decision.** The existing `AuditSink` trait in `crates/audit/src/sink.rs` is broadened (add `read_range`, `sync`, `highest_durable_seq`) rather than replaced.

**Rationale.** The trait already exists, ships, and is used throughout the kernel. Replacing it would force a lockstep migration of every `Arc<dyn AuditSink>` field. Adding methods (with default impls returning `Err(NotSupported)` initially, then upgraded to real impls in `FileAuditSink` and `FakeAuditSink`) lets the migration land incrementally.

**Rejected alternative** — introduce `AuditPersistence` as a fresh trait, deprecate the existing `AuditSink`. Rejected: doubles the API surface for no semantic gain.

### §13.4 Why `MockIsolation` knowingly violates `R-1`

**Decision.** `MockIsolation` runs the planner subprocess as an in-process OS thread, sharing the kernel address space — a literal `R-1` violation.

**Rationale.** Kernel handler tests exercise admission logic, not isolation. Forcing every handler test to spawn a real Firecracker microVM would make `cargo test` take an hour and require KVM in CI. The mock is gated `#[cfg(test)]` and never compiles into a release artefact. The `[CHECK] isolation.tier` doctor check ensures production deployments use a `R-1`-conformant impl.

**Rejected alternative** — use a no-op stub VM (real boot, no real isolation). Rejected: still slower than in-process, still needs root, still complicates CI.

### §13.5 Why the kernel boot is the single composition root

**Decision.** Every `Arc<dyn Trait>` is constructed in `kernel/src/main.rs::main`; every consumer reads from `HandlerContext`.

**Rationale.** Single composition root → single review surface. Any change to which impl is selected lands in one file. The `clippy::disallowed_types` lint that bans concrete construction in handlers prevents drift.

**Rejected alternative** — composition via dependency-injection framework (`shaku`, `inversify-style`). Rejected: another layer of magic that obscures startup ordering. Plain `Arc::new(...)` calls in `main.rs` are debuggable with stepping and visible in stack traces.

---

## §14 — Out of V2 Scope (Documented to Prevent Re-Proposal)

- **Pluggable budget calculator.** See §13.1; paradigm-load-bearing.
- **Pluggable policy schema.** Domains add fields under `[[<domain>]]` blocks; they do NOT swap the parser.
- **Pluggable wire framing.** `bincode` over length-prefixed frames is the V2 wire; alternative wires (protobuf, MessagePack) are V3+ if a real deployment needs them, and would be additive (not replace).
- **Hot-swap of trait impls at runtime.** All six traits are constructed once at boot. Switching from `FileCredentialBackend` to `VaultCredentialBackend` requires a kernel restart (with policy edit). Hot swap would require a coordinated lifecycle (drain in-flight resolutions, re-bind, etc.) that pays no operational benefit beyond "convenient demo."
- **Pluggable hash chain algorithm.** This **is** `R-7`. The verifier and writer must agree; substitution defeats tamper-evidence.
- **Multi-tenancy primitives within a single kernel.** A kernel runs for one operator (one signed policy). Multi-tenancy is "run multiple kernels on multiple data-dirs" — already supported.

---

## §15 — Document Maintenance

Changes to this spec affect every kernel boot path and every handler. Coordination required:

- Adding a new trait requires (a) demonstrating the §1.1 rule (substitution preserves all twelve `R-*` invariants), (b) writing the conformance kit, (c) adding the entry to `HandlerContext`, (d) updating the cross-spec impacts table.
- Removing or weakening a trait's contract is a breaking change for every alternative impl built against it. Coordinate with the version-bump policy in `paradigm.md §8`.
- Changing the construction order in §9.1 is allowed only if every affected later step still has its dependencies satisfied; the author MUST update the boot-site code and the §9.1 table in the same commit.

This spec is the canonical source for trait-boundary decisions in V2. When other V2 specs introduce mechanisms that consume or produce values across one of these seams (new providers, new credentials, new escalation classes carried over a transport), they MUST update either this spec's §11 cross-spec impacts table OR add the seam-relevant detail in their own checklist.
