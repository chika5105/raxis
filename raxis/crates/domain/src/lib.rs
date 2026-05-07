//! crates/raxis-domain — the `DomainAdapter` trait crate.
//!
//! Normative reference: `specs/v2/extensibility-traits.md §2`.
//!
//! The single seam between RAXIS's domain-agnostic Kernel core and the
//! implementation-specific state primitives that vary per problem
//! domain (software engineering / git, trading / FIX, healthcare /
//! FHIR, robotics / motion-plans, …). The kernel binary is compiled
//! against this trait; concrete impls live in their own crates and
//! are wired at process boot via `Arc<dyn DomainAdapter<...>>`.
//!
//! # Wiring overview
//!
//! ```text
//!   ┌────────── kernel/src/main.rs ──────────┐
//!   │ let cred_backend = build_credentials() │
//!   │ let isolation    = build_isolation()   │
//!   │ let domain: Arc<dyn DomainAdapter> =   │
//!   │     Arc::new(GitAdapter::new(...));    │
//!   │ HandlerContext::new(..., domain, ...)  │
//!   └──────────────────────────────────────────┘
//!   The kernel never imports `raxis-domain-git` directly; the
//!   concrete adapter is the single boot-time choice.
//! ```
//!
//! # Cross-references
//!
//! * `extensibility-traits.md §2.7` — conformance contract every
//!   `DomainAdapter` impl must satisfy.
//! * `extensibility-traits.md §2.8` — phased migration plan
//!   (Phase A: trait crate; Phase B: `GitAdapter` impl; Phase C+:
//!   kernel-side call-site migration).
//! * `paradigm.md §2`, `R-9`, `R-11` — paradigm-layer requirements
//!   the trait surface preserves.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CredentialProxyHandle — the per-session reader-only credential view
// the kernel hands the `commit` method.
// ---------------------------------------------------------------------------

/// Per-session, scoped read-only handle into the credential proxy.
/// Concrete impls live in the credential-proxy crate hierarchy
/// (`raxis-credentials*`). `DomainAdapter::commit` is the only
/// touchpoint that the trait exposes for credential mediation —
/// every other stage is by construction credential-free.
///
/// **Why a separate trait, not a direct re-export of
/// `CredentialBackend`.** A `CredentialBackend` is the *backend* (file,
/// Vault, AWS Secrets Manager, …); a `CredentialProxyHandle` is a
/// *per-session lease* over that backend that has already been
/// scoped, rate-limited, and audit-tagged by the kernel. The
/// distinction matters for `INV-VM-CAP-04`: an adapter that touched
/// `CredentialBackend` directly would bypass the lease's audit
/// emission. Concrete impls live in the kernel; the trait shape is
/// here so adapters can take it as a parameter without depending on
/// kernel internals.
pub trait CredentialProxyHandle: Send + Sync {
    /// Resolve a leased credential by its policy-declared name. The
    /// returned bytes are kept in `secrecy::SecretBox` storage by the
    /// kernel-side wrapper; the `Vec<u8>` returned here is a
    /// short-lived copy the adapter is responsible for zeroing once
    /// it has injected the credential into the outbound wire frame
    /// (e.g., FIX login message, HTTP `Authorization` header).
    fn resolve_leased(
        &self,
        credential_name: &str,
    ) -> Result<Vec<u8>, DomainError>;

    /// Stable short-string identifying the underlying backend
    /// implementation. Used in audit emissions and `raxis doctor`
    /// output; carries no authority.
    fn backend_kind(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Read-only context views the kernel constructs and hands to the
// adapter. Every field is borrowed from kernel-owned state; the
// adapter never holds these across an `await` boundary.
// ---------------------------------------------------------------------------

/// Per-session read-only context. Constructed by the kernel after
/// session admission has succeeded; the adapter must not re-validate
/// authority. The `parent_state_ref` is the canonical-state anchor
/// the adapter provisions from (SE: a commit SHA on the main
/// branch; trading: a portfolio snapshot id; healthcare: a FHIR
/// bundle id).
#[derive(Debug, Clone)]
pub struct SessionContext<'a> {
    /// Stable session id (UUID-shaped string). Used by the adapter to
    /// scope per-session paths under its `sessions_root`.
    pub session_id:        &'a str,
    /// The initiative the session belongs to. The adapter typically
    /// keys per-initiative shared state (e.g., main-repo worktree lock)
    /// off this id.
    pub initiative_id:     &'a str,
    /// The canonical-state reference the session provisions from.
    /// SE: the main-branch commit SHA at session-admission time. Adapters
    /// for non-VCS domains supply their domain-specific anchor.
    pub parent_state_ref:  &'a str,
    /// Policy epoch in effect when the session was admitted. Pinned
    /// for the session's lifetime so a mid-session policy advance
    /// cannot tear the adapter's view of the world (`INV-POLICY-01`).
    pub policy_epoch_id:   u64,
}

/// Per-intent read-only context for `touched_resources`. Carries the
/// session and the intent-request envelope's identifying fields so
/// the adapter can name its diagnostics back to the kernel's audit
/// chain.
#[derive(Debug, Clone)]
pub struct AdmissionContext<'a> {
    /// The session the intent was submitted under.
    pub session:           SessionContext<'a>,
    /// The kernel-allocated intent request id (sequence-scoped).
    pub intent_request_id: &'a str,
    /// Optional task id the intent attaches to. Some intent kinds
    /// (e.g., `EgressRequest`) are not bound to a task.
    pub task_id:           Option<&'a str>,
    /// The host-path of the workspace the intent applies to. The
    /// adapter computes the touched-set against this path's content.
    pub workspace_host_path: &'a std::path::Path,
}

/// Per-commit read-only context for `commit`. Carries the audit
/// emission target so the adapter can stamp its `DomainCommitReceipt`
/// into the chain, plus the snapshot's parent/origin metadata.
#[derive(Debug, Clone)]
pub struct CommitContext<'a> {
    /// The session the commit applies to.
    pub session:           SessionContext<'a>,
    /// The intent that triggered the commit (e.g., `IntegrationMerge`).
    pub intent_request_id: &'a str,
    /// Initiative-level worktree directory roots the adapter may
    /// stage from. SE: `<data_dir>/worktrees/`. Domains with no
    /// host-path discipline ignore this field.
    pub worktree_root:     &'a std::path::Path,
}

// ---------------------------------------------------------------------------
// Workspace, Snapshot, Bundle, DomainCommitReceipt, TouchedResources
// ---------------------------------------------------------------------------

/// SHA-256 content hash; opaque to callers, displayed lower-case hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    /// Lowercase hex projection; never used as a security primitive
    /// alone (always paired with the originating `Snapshot`).
    pub fn as_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            use std::fmt::Write;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }
}

/// Opaque adapter-allocated handle to a provisioned workspace.
///
/// SE adapter: wraps a host-path + a `gix::Repository`. The kernel
/// only reads `host_path` (for VirtioFS mount) and `content_hash`
/// (for crash-recovery binding); `adapter_state` is treated as
/// opaque and shipped through `transfer` / `commit` unchanged.
pub struct WorkspaceHandle {
    /// Host-side absolute path to the workspace root the agent VM
    /// mounts read-write into the guest.
    pub host_path:    PathBuf,
    /// SHA-256 of the canonical-state snapshot at provision time.
    pub content_hash: ContentHash,
    /// Adapter-private state the kernel never inspects.
    pub adapter_state: Box<dyn std::any::Any + Send + Sync>,
}

impl std::fmt::Debug for WorkspaceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceHandle")
            .field("host_path", &self.host_path)
            .field("content_hash", &self.content_hash.as_hex())
            .field("adapter_state", &"<opaque>")
            .finish()
    }
}

/// Content-addressed snapshot of the agent's proposed work.
///
/// SE adapter: `(commit_sha, head_tree_sha256)` packed into
/// `adapter_state`; `content_hash` is the head_tree_sha256.
pub struct Snapshot {
    /// Identifying hash of the snapshot bytes.
    pub content_hash:  ContentHash,
    /// Immediate parent's content hash, if any. SE: parent commit's
    /// tree hash; domains with no parent linkage leave this `None`.
    pub parent_hash:   Option<ContentHash>,
    /// Adapter-private state.
    pub adapter_state: Box<dyn std::any::Any + Send + Sync>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("content_hash", &self.content_hash.as_hex())
            .field("parent_hash", &self.parent_hash.as_ref().map(|h| h.as_hex()))
            .field("adapter_state", &"<opaque>")
            .finish()
    }
}

/// Kernel-mediated transfer artefact. The host-path is the only field
/// the kernel touches; the kernel mounts the path read-only into the
/// destination VM at the agent-runtime-canonical mount point.
///
/// SE adapter: a `git bundle` file containing the snapshot commit
/// plus its base.
#[derive(Debug)]
pub struct Bundle {
    /// Host-side absolute path to the transferable bytes.
    pub host_path:    PathBuf,
    /// SHA-256 over the bundle bytes; the kernel writes this into
    /// the audit chain for the multi-agent transfer step.
    pub content_hash: ContentHash,
    /// Bundle byte length; the kernel uses this for budget gates and
    /// for the `[plan_bundle_limits]` enforcement.
    pub byte_len:     u64,
}

/// Receipt of a successful `commit`. Every field is hashed into the
/// audit chain under the domain-specific terminal-commit event type
/// (SE: `IntegrationMergeCompleted`; trading: `OrderSubmitted`; …).
pub struct DomainCommitReceipt {
    /// Adapter-defined unique id for this receipt. SE: the main-branch
    /// commit SHA. Trading: the broker order id.
    pub receipt_id:   String,
    /// Optional external reference (e.g., upstream remote URL the
    /// SE adapter pushed to, broker venue id, FHIR resource id). May
    /// be `None` when the commit is purely host-local.
    pub external_ref: Option<String>,
    /// Wallclock at commit-time, kernel-stamped via `chrono::Utc::now()`.
    pub committed_at: chrono::DateTime<chrono::Utc>,
    /// Adapter-private state.
    pub adapter_state: Box<dyn std::any::Any + Send + Sync>,
}

impl std::fmt::Debug for DomainCommitReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainCommitReceipt")
            .field("receipt_id", &self.receipt_id)
            .field("external_ref", &self.external_ref)
            .field("committed_at", &self.committed_at)
            .field("adapter_state", &"<opaque>")
            .finish()
    }
}

/// Domain-agnostic, structurally typed touched-set the kernel feeds
/// into the path-allowlist / scope-allowlist gate
/// (`INV-TASK-PATH-01`, `R-9`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TouchedResources {
    /// One entry per touched resource, sorted ASC by `uri`.
    pub resources: Vec<TouchedResource>,
}

/// Single-resource touch record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TouchedResource {
    /// `<scheme>://<authority>/<path>` URI. SE: `path:///src/foo.rs`
    /// (empty authority, leading `/` denotes repo root). Trading:
    /// `account://acct-42/AAPL`. Healthcare:
    /// `fhir://patient-12/Observation`.
    pub uri:  String,
    /// Whether this is an addition, modification, or deletion.
    pub op:   ResourceOp,
    /// Optional bytes-affected metric for budget gates. SE: file size.
    /// Domains with no natural byte metric leave this `None`.
    pub size: Option<u64>,
}

/// Resource-touch verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ResourceOp {
    /// New resource — did not exist in the parent snapshot.
    Create,
    /// Existed in the parent; bytes / row-set / payload changed.
    Modify,
    /// Existed in the parent; removed in the snapshot.
    Delete,
}

// ---------------------------------------------------------------------------
// DomainError
// ---------------------------------------------------------------------------

/// Errors any `DomainAdapter` method may return.
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    /// The named resource was not found in the canonical state.
    #[error("domain resource not found")]
    NotFound,

    /// Idempotency short-circuit: the snapshot was already committed
    /// in a prior call. The kernel's crash-recovery path expects this
    /// variant on retry. The receipt is the original receipt; the
    /// kernel does NOT re-emit the audit event.
    #[error("snapshot already applied (commit short-circuit)")]
    AlreadyApplied {
        /// The receipt from the original successful commit.
        receipt: DomainCommitReceipt,
    },

    /// A precondition failed (e.g., the parent state has advanced
    /// past the snapshot's parent). The kernel surfaces this as
    /// `FAIL_PRECONDITION` in the planner-side error code mapping.
    #[error("domain precondition failed: {0}")]
    PreconditionFailed(String),

    /// The credential proxy denied a leased credential. The error
    /// message is operator-readable; the credential bytes never
    /// transit this variant.
    #[error("credential proxy denied: {0}")]
    CredentialProxyDenied(String),

    /// Transient infrastructure failure (network blip, ODB lock
    /// contention, broker outage). The kernel may retry.
    #[error("transient domain error: {0}")]
    Transient(String),

    /// Permanent failure (corrupted ODB, malformed snapshot).
    /// The kernel transitions the initiative to `Blocked`.
    #[error("permanent domain error: {0}")]
    Permanent(String),
}

// ---------------------------------------------------------------------------
// DomainAdapter — the trait
// ---------------------------------------------------------------------------

/// The boundary between the domain-agnostic kernel and
/// domain-specific state management. Every method is invoked *only*
/// from inside the kernel after the relevant `R-*` admission gate
/// has fired; the impl is not responsible for re-checking authority.
///
/// Concurrency: every method may be called from multiple tokio worker
/// threads in parallel. Adapters are responsible for their own
/// internal synchronisation (the SE adapter holds a per-main-repo
/// `gix::Repository` mutex during `commit`).
///
/// The trait is `async` because some adapters (Trading: FIX session;
/// Healthcare: FHIR HTTP) are inherently I/O-bound. SE-domain methods
/// that the spec describes synchronously (`gix::diff`, host-path
/// staging) are still async-shaped because the kernel runs them on
/// the tokio blocking pool.
#[async_trait]
pub trait DomainAdapter: Send + Sync + 'static {
    /// Closed enumeration of the authority operations this domain
    /// admits. SE: `IntentKind` from `raxis-types`. Trading:
    /// `ProposeOrder | CancelOrder | …`. The kernel deserialises
    /// these out of the `IntentRequest` envelope.
    type IntentKind: Serialize
        + serde::de::DeserializeOwned
        + Clone
        + Send
        + Sync
        + std::fmt::Debug;

    /// Artefact a successful terminal-task `CompleteTask`-equivalent
    /// witness binds to. SE: `(CommitSha, head_tree_sha256)`.
    /// Trading: `(OrderId, FillReceipt)`.
    type TerminalArtefact: Clone + Send + Sync + std::fmt::Debug;

    // ── §2.2.A state-lifecycle primitives ───────────────────────────

    /// Prepare the mutable state surface the agent will operate on
    /// inside its isolated VM. Called exactly once per session,
    /// after the planner VM has been spawned but before any
    /// `KernelPush` is allowed to deliver an intent.
    ///
    /// MUST be deterministic given `(session.session_id,
    /// session.parent_state_ref)`: re-invocation MUST yield
    /// byte-identical contents at the returned host-path (modulo
    /// timestamps the impl SHOULD canonicalise).
    async fn provision_workspace(
        &self,
        session: SessionContext<'_>,
    ) -> Result<WorkspaceHandle, DomainError>;

    /// Create a content-addressed snapshot of whatever the agent has
    /// produced inside its workspace. Called when the planner submits
    /// a `CompleteTask`-equivalent intent, BEFORE admission gates run
    /// (the touched-set is derived from the snapshot per `R-9`).
    ///
    /// MUST be **idempotent**: calling twice on a workspace that has
    /// not changed MUST return the same `Snapshot` (same
    /// `content_hash`).
    async fn snapshot(
        &self,
        session: SessionContext<'_>,
        workspace: &WorkspaceHandle,
    ) -> Result<Snapshot, DomainError>;

    /// Hand a snapshot from one isolated agent VM to another (the
    /// multi-agent coordination primitive of `R-11`). The kernel
    /// always mediates: the source VM cannot write directly into the
    /// destination's workspace, and the destination cannot pull
    /// directly from the source. This call materialises a
    /// transferable `Bundle` in a kernel-controlled staging directory;
    /// the kernel then mounts that directory read-only into the
    /// destination VM.
    ///
    /// MUST be idempotent on `(snapshot.content_hash, dst.session_id)`.
    async fn transfer(
        &self,
        snapshot: &Snapshot,
        src: SessionContext<'_>,
        dst: SessionContext<'_>,
    ) -> Result<Bundle, DomainError>;

    /// Commit approved work to the canonical external system of
    /// record. This is the only method that contacts the outside
    /// world; it MUST go through the credential proxy
    /// (`INV-VM-CAP-04`) when external credentials are required.
    ///
    /// MUST be idempotent on `snapshot.content_hash`: re-invocation
    /// after a successful commit MUST return
    /// `Err(DomainError::AlreadyApplied { receipt })` carrying the
    /// original receipt — the kernel relies on this for crash recovery.
    async fn commit(
        &self,
        snapshot: &Snapshot,
        cred_proxy: &dyn CredentialProxyHandle,
        ctx: CommitContext<'_>,
    ) -> Result<DomainCommitReceipt, DomainError>;

    // ── §2.2.B kernel admission-pipeline hooks ──────────────────────

    /// Compute the deterministic touched-set of domain resources the
    /// `intent` would mutate, derived only from authoritative state
    /// (the workspace + snapshot), never from planner-supplied
    /// manifests. The kernel runs this BEFORE the path-allowlist
    /// gate (`R-9`).
    async fn touched_resources(
        &self,
        intent: &Self::IntentKind,
        ctx: AdmissionContext<'_>,
    ) -> Result<TouchedResources, DomainError>;

    /// Granular admission hook #1 — is `parent_state_ref` a valid
    /// ancestor of `target_state_ref`? The kernel's IntegrationMerge
    /// gate calls this first so it can report
    /// `FailInvalidDiff` when ancestry fails.
    ///
    /// SE: `git merge-base --is-ancestor parent target`. Trading:
    /// portfolio reachability check. Healthcare: bundle-version
    /// chain check.
    async fn is_ancestor(
        &self,
        parent_state_ref: &str,
        target_state_ref: &str,
        workspace_root:   &std::path::Path,
    ) -> Result<bool, DomainError>;

    /// Granular admission hook #2 — verify there are no
    /// "implementation-domain merge events" between
    /// `parent_state_ref` and `target_state_ref`. Reported as
    /// `FailInvalidCommitTopology` when it fails.
    ///
    /// SE: `git rev-list --min-parents=2 --count parent..target`
    /// (must be 0). Trading: no foreign-order mutations between the
    /// two snapshots. Healthcare: no out-of-band patient-record
    /// edits.
    ///
    /// Domains that have no notion of "merge commits in range" return
    /// `Ok(())` unconditionally.
    async fn topology_check(
        &self,
        parent_state_ref: &str,
        target_state_ref: &str,
        workspace_root:   &std::path::Path,
    ) -> Result<(), DomainError>;

    /// Granular admission hook #3 — compute the touched-set between
    /// the two refs. Reported as `FailInvalidDiff` when it fails.
    ///
    /// MUST be deterministic and lexicographically sorted by URI.
    async fn compute_touched_paths(
        &self,
        parent_state_ref: &str,
        target_state_ref: &str,
        workspace_root:   &std::path::Path,
    ) -> Result<TouchedResources, DomainError>;

    /// Convenience method that runs the three granular hooks in
    /// sequence and collapses their per-step errors into a single
    /// `PreconditionFailed`. Default implementation delegates to
    /// `is_ancestor` → `topology_check` → `compute_touched_paths`.
    /// Adapters with cheaper combined-paths (e.g., a single SQL
    /// query that fuses the three) override this method.
    async fn verify_state_advance(
        &self,
        parent_state_ref: &str,
        target_state_ref: &str,
        workspace_root:   &std::path::Path,
    ) -> Result<TouchedResources, DomainError> {
        match self
            .is_ancestor(parent_state_ref, target_state_ref, workspace_root)
            .await?
        {
            true => {}
            false => return Err(DomainError::PreconditionFailed(format!(
                "{parent_state_ref} is not an ancestor of {target_state_ref}"
            ))),
        }
        self.topology_check(parent_state_ref, target_state_ref, workspace_root).await?;
        self.compute_touched_paths(parent_state_ref, target_state_ref, workspace_root).await
    }

    /// Stable, sorted, deduplicated list of escalation class names
    /// the kernel's escalation FSM should accept for this domain.
    /// SE: `["protected_path_merge", "review_loop_exceeded", …]`.
    fn escalation_classes(&self) -> &'static [&'static str];

    // ── §2.2.C cleanup primitives ───────────────────────────────────

    /// Called when a session ends (terminal `CompleteTask`, abandoned
    /// after agent-disagreement, or operator-killed). Releases
    /// VM-mounted resources but does NOT delete the underlying state
    /// — the audit-retention window of `agent-disagreement.md §7`
    /// may require it for forensic replay.
    async fn teardown_workspace(
        &self,
        workspace: &WorkspaceHandle,
    ) -> Result<(), DomainError>;

    /// Called when the audit retention window closes. Permanently
    /// purges the underlying state. SE: `rm -rf` the ephemeral clone.
    /// The kernel still retains the audit-chain entry; only the
    /// bulk state goes.
    async fn purge_workspace(
        &self,
        workspace: &WorkspaceHandle,
    ) -> Result<(), DomainError>;
}

// ---------------------------------------------------------------------------
// Conformance helpers (used by adapter test suites)
// ---------------------------------------------------------------------------

/// Conformance helpers any adapter test suite may import. The full
/// `run_conformance_suite::<A>(adapter)` function is intentionally not
/// in this crate (it would force every adapter to bring `tokio` and a
/// fixture-loader); each adapter ships its own conformance test that
/// asserts the spec's `§2.7` properties against its impl.
pub mod conformance {
    use super::*;

    /// Property #1 — `provision_workspace` is deterministic.
    /// Provision twice and assert byte-equal `content_hash`.
    pub fn assert_workspace_determinism(
        h1: &WorkspaceHandle,
        h2: &WorkspaceHandle,
    ) {
        assert_eq!(
            h1.content_hash, h2.content_hash,
            "DomainAdapter::provision_workspace conformance #1: \
             two provisions of the same (session_id, parent_state_ref) \
             must produce byte-identical content_hash; got {:?} vs {:?}",
            h1.content_hash.as_hex(),
            h2.content_hash.as_hex(),
        );
    }

    /// Property #2 — `snapshot` is idempotent over an unchanged
    /// workspace.
    pub fn assert_snapshot_idempotency(s1: &Snapshot, s2: &Snapshot) {
        assert_eq!(
            s1.content_hash, s2.content_hash,
            "DomainAdapter::snapshot conformance #2: two snapshots of \
             an unchanged workspace must produce byte-identical \
             content_hash; got {:?} vs {:?}",
            s1.content_hash.as_hex(),
            s2.content_hash.as_hex(),
        );
    }

    /// Property #5 — `commit` returns `AlreadyApplied` on retry.
    pub fn assert_commit_idempotency<E: std::fmt::Debug>(
        first: &DomainCommitReceipt,
        retry: &Result<DomainCommitReceipt, DomainError>,
        adapter_kind: &str,
    ) {
        match retry {
            Err(DomainError::AlreadyApplied { receipt }) => {
                assert_eq!(
                    receipt.receipt_id, first.receipt_id,
                    "{adapter_kind}: AlreadyApplied receipt must match \
                     the original receipt_id"
                );
            }
            other => panic!(
                "{adapter_kind}: DomainAdapter::commit conformance #5 \
                 violated — retry on the same snapshot must return \
                 Err(AlreadyApplied {{ receipt }}); got {:?}",
                other,
            ),
        }
        let _ = std::any::type_name::<E>();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_hex_is_lowercase_64_chars() {
        let h = ContentHash([0xab; 32]);
        let s = h.as_hex();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(s, "ab".repeat(32));
    }

    #[test]
    fn touched_resources_serializes_round_trip() {
        let t = TouchedResources {
            resources: vec![
                TouchedResource {
                    uri:  "path:///src/foo.rs".to_owned(),
                    op:   ResourceOp::Modify,
                    size: Some(1234),
                },
                TouchedResource {
                    uri:  "path:///src/bar.rs".to_owned(),
                    op:   ResourceOp::Create,
                    size: None,
                },
            ],
        };
        let s = serde_json::to_string(&t).unwrap();
        let back: TouchedResources = serde_json::from_str(&s).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn resource_op_pascal_case_serde() {
        let create = serde_json::to_string(&ResourceOp::Create).unwrap();
        assert_eq!(create, "\"Create\"");
        let modify: ResourceOp = serde_json::from_str("\"Modify\"").unwrap();
        assert_eq!(modify, ResourceOp::Modify);
    }

    #[test]
    fn domain_error_already_applied_short_circuits_via_pattern_match() {
        let receipt = DomainCommitReceipt {
            receipt_id:   "rcpt-1".to_owned(),
            external_ref: None,
            committed_at: chrono::Utc::now(),
            adapter_state: Box::new(()),
        };
        let err = DomainError::AlreadyApplied { receipt };
        match err {
            DomainError::AlreadyApplied { receipt } => {
                assert_eq!(receipt.receipt_id, "rcpt-1");
            }
            _ => panic!("expected AlreadyApplied"),
        }
    }
}

// `serde_json` is used in tests; pull it in only there so the
// production trait crate has zero JSON dep.
#[cfg(test)]
extern crate serde_json;
