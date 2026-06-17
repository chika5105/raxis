//! crates/raxis-domain — shared domain data types.
//!
//! Normative reference: `specs/v2/extensibility-traits.md §2`.
//!
//! Shared context, result, and error shapes used by the git domain
//! implementation and the kernel.
//!
//! # Cross-references
//!
//! * `paradigm.md §2`, `R-9`, `R-11` — paradigm-layer requirements
//!   these data shapes preserve.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
    pub session_id: &'a str,
    /// The initiative the session belongs to. The adapter typically
    /// keys per-initiative shared state (e.g., main-repo worktree lock)
    /// off this id.
    pub initiative_id: &'a str,
    /// The canonical-state reference the session provisions from.
    /// SE: the main-branch commit SHA at session-admission time. Adapters
    /// for non-VCS domains supply their domain-specific anchor.
    pub parent_state_ref: &'a str,
    /// Policy epoch in effect when the session was admitted. Pinned
    /// for the session's lifetime so a mid-session policy advance
    /// cannot tear the adapter's view of the world (`INV-POLICY-01`).
    pub policy_epoch_id: u64,
}

/// Per-intent read-only context for `touched_resources`. Carries the
/// session and the intent-request envelope's identifying fields so
/// the adapter can name its diagnostics back to the kernel's audit
/// chain.
#[derive(Debug, Clone)]
pub struct AdmissionContext<'a> {
    /// The session the intent was submitted under.
    pub session: SessionContext<'a>,
    /// The kernel-allocated intent request id (sequence-scoped).
    pub intent_request_id: &'a str,
    /// Optional task id the intent attaches to. Some intent kinds
    /// (e.g., `EgressRequest`) are not bound to a task.
    pub task_id: Option<&'a str>,
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
    pub session: SessionContext<'a>,
    /// The intent that triggered the commit (e.g., `IntegrationMerge`).
    pub intent_request_id: &'a str,
    /// Initiative-level worktree directory roots the adapter may
    /// stage from. SE: `<data_dir>/worktrees/`. Domains with no
    /// host-path discipline ignore this field.
    pub worktree_root: &'a std::path::Path,
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
    pub host_path: PathBuf,
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
    pub content_hash: ContentHash,
    /// Immediate parent's content hash, if any. SE: parent commit's
    /// tree hash; domains with no parent linkage leave this `None`.
    pub parent_hash: Option<ContentHash>,
    /// Adapter-private state.
    pub adapter_state: Box<dyn std::any::Any + Send + Sync>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("content_hash", &self.content_hash.as_hex())
            .field(
                "parent_hash",
                &self.parent_hash.as_ref().map(|h| h.as_hex()),
            )
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
    pub host_path: PathBuf,
    /// SHA-256 over the bundle bytes; the kernel writes this into
    /// the audit chain for the multi-agent transfer step.
    pub content_hash: ContentHash,
    /// Bundle byte length; the kernel uses this for budget gates and
    /// for the `[plan_bundle_limits]` enforcement.
    pub byte_len: u64,
}

/// Receipt of a successful `commit`. Every field is hashed into the
/// audit chain under the domain-specific terminal-commit event type
/// (SE: `IntegrationMergeCompleted`; trading: `OrderSubmitted`; …).
pub struct DomainCommitReceipt {
    /// Adapter-defined unique id for this receipt. SE: the main-branch
    /// commit SHA. Trading: the broker order id.
    pub receipt_id: String,
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
    pub uri: String,
    /// Whether this is an addition, modification, or deletion.
    pub op: ResourceOp,
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

/// Errors surfaced by domain-specific state helpers.
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
    pub fn assert_workspace_determinism(h1: &WorkspaceHandle, h2: &WorkspaceHandle) {
        assert_eq!(
            h1.content_hash,
            h2.content_hash,
            "domain provision_workspace conformance #1: \
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
            s1.content_hash,
            s2.content_hash,
            "domain snapshot conformance #2: two snapshots of \
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
                "{adapter_kind}: domain commit conformance #5 \
                 violated — retry on the same snapshot must return \
                 Err(AlreadyApplied {{ receipt }}); got {:?}",
                other,
            ),
        }
        let _ = std::any::type_name::<E>();
    }
}

// `serde_json` is used in tests; pull it in only there so the
// production trait crate has zero JSON dep.
#[cfg(test)]
extern crate serde_json;

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
        assert!(s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(s, "ab".repeat(32));
    }

    #[test]
    fn touched_resources_serializes_round_trip() {
        let t = TouchedResources {
            resources: vec![
                TouchedResource {
                    uri: "path:///src/foo.rs".to_owned(),
                    op: ResourceOp::Modify,
                    size: Some(1234),
                },
                TouchedResource {
                    uri: "path:///src/bar.rs".to_owned(),
                    op: ResourceOp::Create,
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
            receipt_id: "rcpt-1".to_owned(),
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
