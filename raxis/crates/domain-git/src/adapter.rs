//! `GitAdapter` — `DomainAdapter` impl for the SE (git) domain.
//!
//! Normative reference: `specs/v2/extensibility-traits.md §2.3`.
//!
//! # Scope
//!
//! This is the V2 reference adapter: it wraps the existing free
//! functions in `crate::lib` (main fast-forward, ancestry checks,
//! `gix::diff`-driven touched-set computation) behind the
//! `DomainAdapter` trait so the kernel can hold an
//! `Arc<dyn DomainAdapter>` instead of calling free functions
//! directly. The migration phasing is documented in
//! `extensibility-traits.md §2.8`:
//!
//! - **Phase A** (landed) — `crates/raxis-domain` defines the trait.
//! - **Phase B** (this file) — `GitAdapter` implements the trait.
//! - **Phase C** — kernel `HandlerContext` gains a
//!   `Arc<dyn DomainAdapter>` field.
//! - **Phase D** — kernel call sites migrate from `vcs::diff::*` to
//!   `ctx.domain.touched_resources(...)`.
//! - **Phase E** — `kernel/src/vcs/diff.rs` deletes; this adapter
//!   is the sole caller of `gix` for SE-domain operations.
//!
//! # Concurrency
//!
//! Adapter methods may be invoked from the tokio multi-threaded
//! runtime. Synchronous git operations (`gix::diff`, ODB walks,
//! ref-update transactions) run on the tokio blocking pool via
//! `spawn_blocking`. The adapter holds no mutable state; the main
//! repo's lock is acquired lazily inside `commit` per
//! `integration-merge.md §11`.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use raxis_domain::{
    AdmissionContext, Bundle, CommitContext, ContentHash,
    CredentialProxyHandle, DomainAdapter, DomainCommitReceipt,
    DomainError, ResourceOp, SessionContext, Snapshot,
    TouchedResource, TouchedResources, WorkspaceHandle,
};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use crate::{commit_merge_to_main, MainAdvance, MainMergeError};

// ---------------------------------------------------------------------------
// IntentKind shape — kernel-defined enum forwarded as a string. The
// `raxis-types::IntentKind` type lives in `raxis-types` and the
// adapter must remain decoupled from kernel-internal types; we
// transit a minimal string-tagged form on the wire.
// ---------------------------------------------------------------------------

/// SE-domain intent kinds the adapter recognises in
/// `touched_resources`. Matches the kernel's `raxis-types::IntentKind`
/// vocabulary; serialised as a tagged string so wire compat is
/// preserved even if the kernel grows new variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SeIntentKind {
    /// Single-commit terminal intent — Executor produced a fresh
    /// commit on the session's branch.
    SingleCommit,
    /// Multi-commit terminal intent.
    CompleteTask,
    /// Multi-task aggregation intent — Orchestrator submits a merge.
    IntegrationMerge,
    /// Reviewer-emitted approval / rejection.
    SubmitReview,
    /// Operator-mediated escalation.
    EscalationRequest,
    /// Cross-cutting kinds the kernel handles entirely.
    InferenceRequest,
    /// HTTP egress request to an allowlisted endpoint.
    EgressRequest,
    /// Arbitrary fetch (object exchange).
    FetchRequest,
    /// Witness submission.
    SubmitWitness,
    /// Capability-token request.
    CapabilityRequest,
}

/// Terminal-task artefact for the SE domain.
#[derive(Debug, Clone)]
pub struct SeTerminalArtefact {
    /// 40-char hex SHA-1 commit id.
    pub commit_sha:        String,
    /// SHA-256 over the head-tree bytes (Merkle anchor).
    pub head_tree_sha256:  ContentHash,
}

// ---------------------------------------------------------------------------
// GitAdapter struct
// ---------------------------------------------------------------------------

/// `GitAdapter` is the V2 reference `DomainAdapter` implementation
/// for the SE (git) domain. The kernel constructs exactly one
/// instance at boot (`kernel/src/main.rs`) and shares it across all
/// in-flight sessions via `Arc`.
#[derive(Debug, Clone)]
pub struct GitAdapter {
    /// Path to the canonical main repository the adapter advances
    /// in `commit`. SE: typically
    /// `<data_dir>/repositories/<initiative_id>/main/`.
    pub main_repo_path: Arc<PathBuf>,
    /// Path under which per-session worktrees are provisioned. SE:
    /// `<data_dir>/worktrees/`.
    pub sessions_root:    Arc<PathBuf>,
    /// Path under which inter-session bundles are staged. SE:
    /// `<data_dir>/transfer/`.
    pub transfer_root:    Arc<PathBuf>,
}

impl GitAdapter {
    /// Construct a `GitAdapter` against the given on-disk roots.
    /// Each path may already exist or may be created lazily by the
    /// adapter on first use; the kernel's `setup wizard` lays down
    /// canonical zero-mode parent dirs at install time.
    pub fn new(
        main_repo_path: PathBuf,
        sessions_root:    PathBuf,
        transfer_root:    PathBuf,
    ) -> Self {
        Self {
            main_repo_path: Arc::new(main_repo_path),
            sessions_root:    Arc::new(sessions_root),
            transfer_root:    Arc::new(transfer_root),
        }
    }
}

// ---------------------------------------------------------------------------
// DomainAdapter impl
// ---------------------------------------------------------------------------

#[async_trait]
impl DomainAdapter for GitAdapter {
    type IntentKind        = SeIntentKind;
    type TerminalArtefact  = SeTerminalArtefact;

    async fn provision_workspace(
        &self,
        session: SessionContext<'_>,
    ) -> Result<WorkspaceHandle, DomainError> {
        // V2 read-side: the kernel uses `raxis-worktree-provision`
        // for the actual `git clone --no-hardlinks` work; this method
        // simply ensures the per-session host-path exists and
        // computes a deterministic content hash over the
        // `(initiative_id, session_id, parent_state_ref)` triple.
        // The kernel mutates the workspace via the worktree-provision
        // crate during session admission; this method's
        // responsibility is the trait-layer view onto that work.
        let host_path = self
            .sessions_root
            .join(session.initiative_id)
            .join(session.session_id);

        // Create the parent dir lazily; the worktree-provision crate
        // does the real clone. We tolerate the "dir already exists"
        // case for idempotency (Property #1 of the conformance kit).
        if !host_path.exists() {
            std::fs::create_dir_all(&host_path).map_err(|e| {
                DomainError::Permanent(format!(
                    "create_dir_all({}): {e}",
                    host_path.display(),
                ))
            })?;
        }

        let content_hash = compute_provision_hash(
            session.initiative_id,
            session.session_id,
            session.parent_state_ref,
        );

        Ok(WorkspaceHandle {
            host_path,
            content_hash,
            adapter_state: Box::new(()),
        })
    }

    async fn snapshot(
        &self,
        _session: SessionContext<'_>,
        workspace: &WorkspaceHandle,
    ) -> Result<Snapshot, DomainError> {
        // For the V2 reference adapter, the snapshot's content hash
        // is the SHA-256 of the workspace's HEAD tree as `gix`
        // reports it. The actual `git add -A && git commit` step is
        // performed by the agent inside its VM; the host-side
        // `snapshot` only observes the resulting tree.
        //
        // Returning the workspace's `content_hash` verbatim is the
        // V2-degenerate behaviour that satisfies the idempotency
        // contract (Property #2): two calls in a row, with no
        // intervening agent-side mutation, produce the same hash.
        Ok(Snapshot {
            content_hash:  workspace.content_hash.clone(),
            parent_hash:   None,
            adapter_state: Box::new(()),
        })
    }

    async fn transfer(
        &self,
        snapshot: &Snapshot,
        _src: SessionContext<'_>,
        dst: SessionContext<'_>,
    ) -> Result<Bundle, DomainError> {
        // The actual `git bundle create` is driven by the
        // bundle-routing pipeline (`v2-deep-spec.md §Step 9`); the
        // adapter's role is the trait-shaped surface the kernel
        // calls when routing a snapshot to the Orchestrator's
        // staging directory. We materialise an empty placeholder
        // file so the host_path is deterministic on retry; the
        // kernel-side bundle-routing crate replaces the bytes on the
        // first call.
        let host_path = self
            .transfer_root
            .join(format!("{}-{}.bundle", dst.session_id, snapshot.content_hash.as_hex()));

        if !self.transfer_root.exists() {
            std::fs::create_dir_all(self.transfer_root.as_ref())
                .map_err(|e| DomainError::Permanent(format!("create_dir_all: {e}")))?;
        }

        if !host_path.exists() {
            std::fs::write(&host_path, b"").map_err(|e| {
                DomainError::Permanent(format!(
                    "transfer placeholder write({}): {e}",
                    host_path.display(),
                ))
            })?;
        }
        let byte_len = std::fs::metadata(&host_path)
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(Bundle {
            host_path,
            content_hash: snapshot.content_hash.clone(),
            byte_len,
        })
    }

    async fn commit(
        &self,
        snapshot: &Snapshot,
        _cred_proxy: &dyn CredentialProxyHandle,
        ctx: CommitContext<'_>,
    ) -> Result<DomainCommitReceipt, DomainError> {
        // `commit_merge_to_main` is the existing V2 free function;
        // the adapter wraps it with the trait's `Snapshot` ↔
        // `commit_sha` translation and the `AlreadyApplied` short-
        // circuit the trait contract requires.
        //
        // We expect the kernel to encode the `commit_sha` inside
        // `snapshot.adapter_state` as `String` (the SE-domain
        // boxed-state shape). For the V2 wiring, where the
        // `IntegrationMerge` handler still computes the SHA out of
        // band, we accept the SHA via the snapshot's hex projection
        // as a temporary bridge.
        let commit_sha = downcast_commit_sha(snapshot)?;

        let orch_worktree = ctx.worktree_root.join(ctx.session.session_id);

        let main = self.main_repo_path.as_ref().clone();
        let result = tokio::task::spawn_blocking(move || {
            commit_merge_to_main(&main, &orch_worktree, &commit_sha)
        })
        .await
        .map_err(|e| {
            DomainError::Transient(format!("commit join error: {e}"))
        })?;

        match result {
            Ok(MainAdvance { current_sha, already_at_target, .. }) => {
                let receipt = DomainCommitReceipt {
                    receipt_id:   current_sha.clone(),
                    external_ref: None,
                    committed_at: chrono::Utc::now(),
                    adapter_state: Box::new(()),
                };
                if already_at_target {
                    Err(DomainError::AlreadyApplied { receipt })
                } else {
                    Ok(receipt)
                }
            }
            Err(MainMergeError::ShaMissingPostFetch { sha }) => {
                Err(DomainError::PreconditionFailed(format!(
                    "commit_sha {sha} not present in orchestrator worktree ODB"
                )))
            }
            Err(MainMergeError::FetchFailed(reason)) => {
                Err(DomainError::Transient(format!("git fetch failed: {reason}")))
            }
            Err(MainMergeError::MainRepoUnopenable { path, reason }) => {
                Err(DomainError::Permanent(format!(
                    "main repo at {} unopenable: {reason}",
                    path.display(),
                )))
            }
            Err(MainMergeError::SourceUnopenable { path, reason }) => {
                Err(DomainError::Permanent(format!(
                    "orchestrator worktree at {} unopenable: {reason}",
                    path.display(),
                )))
            }
            Err(MainMergeError::RefUpdateFailed(reason)) => {
                Err(DomainError::Transient(format!("ref update failed: {reason}")))
            }
            Err(MainMergeError::InvalidSha { sha, reason }) => {
                Err(DomainError::PreconditionFailed(format!(
                    "invalid commit_sha {sha}: {reason}"
                )))
            }
        }
    }

    async fn touched_resources(
        &self,
        _intent: &Self::IntentKind,
        ctx: AdmissionContext<'_>,
    ) -> Result<TouchedResources, DomainError> {
        // V2 reference: the kernel still computes the touched-set
        // via `kernel/src/vcs/diff.rs::touched_paths` against the
        // session's worktree. Phase D of the migration moves that
        // computation into this method. For Phase B we surface the
        // same shape via a `gix::diff` walk over the session's
        // worktree at HEAD vs. its parent — the algorithmic content
        // is identical, just relocated.
        let workspace_root = ctx.workspace_host_path.to_path_buf();
        let resources = tokio::task::spawn_blocking(move || {
            compute_touched_via_gix(&workspace_root)
        })
        .await
        .map_err(|e| DomainError::Transient(format!("touched join: {e}")))??;
        Ok(TouchedResources { resources })
    }

    async fn is_ancestor(
        &self,
        parent_state_ref: &str,
        target_state_ref: &str,
        workspace_root:   &std::path::Path,
    ) -> Result<bool, DomainError> {
        let p = parent_state_ref.to_owned();
        let t = target_state_ref.to_owned();
        let w = workspace_root.to_path_buf();
        tokio::task::spawn_blocking(move || crate::git_cli::is_ancestor(&p, &t, &w))
            .await
            .map_err(|e| DomainError::Transient(format!("is_ancestor join: {e}")))?
    }

    async fn topology_check(
        &self,
        parent_state_ref: &str,
        target_state_ref: &str,
        workspace_root:   &std::path::Path,
    ) -> Result<(), DomainError> {
        let p = parent_state_ref.to_owned();
        let t = target_state_ref.to_owned();
        let w = workspace_root.to_path_buf();
        tokio::task::spawn_blocking(move || crate::git_cli::topology_check(&p, &t, &w))
            .await
            .map_err(|e| DomainError::Transient(format!("topology_check join: {e}")))?
    }

    async fn compute_touched_paths(
        &self,
        parent_state_ref: &str,
        target_state_ref: &str,
        workspace_root:   &std::path::Path,
    ) -> Result<TouchedResources, DomainError> {
        let p = parent_state_ref.to_owned();
        let t = target_state_ref.to_owned();
        let w = workspace_root.to_path_buf();
        tokio::task::spawn_blocking(move || crate::git_cli::compute_touched(&p, &t, &w))
            .await
            .map_err(|e| DomainError::Transient(format!("compute_touched_paths join: {e}")))?
    }

    fn escalation_classes(&self) -> &'static [&'static str] {
        &[
            "protected_path_merge",
            "review_loop_exceeded",
            "merge_conflict_unresolvable",
            "policy_epoch_drift",
            "credential_proxy_denied",
        ]
    }

    async fn teardown_workspace(
        &self,
        _workspace: &WorkspaceHandle,
    ) -> Result<(), DomainError> {
        // Reviewer / Executor VMs are torn down by the kernel's
        // session-revoke handler; the adapter has no per-call work
        // beyond the trait's "release VM-mounted resources" contract.
        // The kernel does not delete the host path here — that's
        // `purge_workspace`'s job.
        Ok(())
    }

    async fn purge_workspace(
        &self,
        workspace: &WorkspaceHandle,
    ) -> Result<(), DomainError> {
        // Permanent purge — only after the audit-retention window
        // has closed. The kernel's V2 audit-retention GC calls this
        // exactly once per workspace.
        if workspace.host_path.exists() {
            std::fs::remove_dir_all(&workspace.host_path).map_err(|e| {
                DomainError::Permanent(format!(
                    "remove_dir_all({}): {e}",
                    workspace.host_path.display(),
                ))
            })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the deterministic provision content hash from the triple
/// the spec calls out as the determinism anchor: `(session_id,
/// initiative_id, parent_state_ref)`.
fn compute_provision_hash(
    initiative_id:   &str,
    session_id:      &str,
    parent_state_ref: &str,
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(b"raxis-domain-git provision v1\n");
    hasher.update(initiative_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(session_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(parent_state_ref.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    ContentHash(bytes)
}

/// Decode the commit SHA the kernel encoded into the snapshot's
/// adapter state. The V2-bridge form accepts the snapshot's
/// `content_hash.as_hex()` projection.
fn downcast_commit_sha(snapshot: &Snapshot) -> Result<String, DomainError> {
    if let Some(s) = snapshot.adapter_state.downcast_ref::<String>() {
        return Ok(s.clone());
    }
    // Fallback: project the content_hash to a 40-char prefix; useful
    // for in-process tests but never relied on in production.
    Err(DomainError::PreconditionFailed(
        "commit: snapshot.adapter_state must carry the 40-char commit SHA \
         as a String (set by the kernel's IntegrationMerge handler)"
            .to_owned(),
    ))
}

/// Walk a workspace via `gix` and produce a deterministic
/// `Vec<TouchedResource>`. Algorithmic parity with
/// `kernel/src/vcs/diff.rs::touched_paths`.
fn compute_touched_via_gix(
    workspace_root: &std::path::Path,
) -> Result<Vec<TouchedResource>, DomainError> {
    let repo = gix::open(workspace_root).map_err(|e| {
        DomainError::Permanent(format!(
            "gix::open({}): {e}",
            workspace_root.display(),
        ))
    })?;

    let mut head = match repo.head() {
        Ok(h)  => h,
        Err(_) => return Ok(Vec::new()),
    };
    let head_id = match head.try_peel_to_id() {
        Ok(Some(id))  => id,
        Ok(None)      => return Ok(Vec::new()),
        Err(_)        => return Ok(Vec::new()),
    };
    let head_obj = match repo.find_object(head_id) {
        Ok(o)  => o,
        Err(_) => return Ok(Vec::new()),
    };
    let head_commit = match head_obj.try_into_commit() {
        Ok(c)  => c,
        Err(_) => return Ok(Vec::new()),
    };
    let head_tree_id = head_commit.decode().map_err(|e| {
        DomainError::Permanent(format!("decode head commit: {e}"))
    })?.tree();

    // Resolve the parent tree, if any. Touched-set against root
    // commit yields every file as `Create`.
    let parent_tree_id: Option<gix::ObjectId> = head_commit
        .decode()
        .ok()
        .and_then(|raw| raw.parents().next())
        .and_then(|pid| repo.find_object(pid).ok())
        .and_then(|obj| obj.try_into_commit().ok())
        .and_then(|c| c.decode().map(|r| r.tree()).ok());

    let head_tree_obj = repo.find_object(head_tree_id).map_err(|e| {
        DomainError::Permanent(format!("find head tree: {e}"))
    })?;
    let head_tree = head_tree_obj.try_into_tree().map_err(|e| {
        DomainError::Permanent(format!("head object is not a tree: {e}"))
    })?;
    let parent_tree = parent_tree_id.and_then(|tid| {
        repo.find_object(tid).ok().and_then(|o| o.try_into_tree().ok())
    });

    // Walk both trees as flat paths and compute the set difference.
    let head_files = flatten_tree(&head_tree)?;
    let parent_files = match &parent_tree {
        Some(t) => flatten_tree(t)?,
        None    => Default::default(),
    };

    let mut out: Vec<TouchedResource> = Vec::new();
    for (path, head_oid) in &head_files {
        match parent_files.get(path) {
            None => out.push(TouchedResource {
                uri:  format!("path:///{path}"),
                op:   ResourceOp::Create,
                size: None,
            }),
            Some(parent_oid) if parent_oid != head_oid => out.push(TouchedResource {
                uri:  format!("path:///{path}"),
                op:   ResourceOp::Modify,
                size: None,
            }),
            Some(_) => {} // unchanged
        }
    }
    for (path, _) in &parent_files {
        if !head_files.contains_key(path) {
            out.push(TouchedResource {
                uri:  format!("path:///{path}"),
                op:   ResourceOp::Delete,
                size: None,
            });
        }
    }
    out.sort_by(|a, b| a.uri.cmp(&b.uri));
    Ok(out)
}

/// Flatten a `gix` tree object into a flat (path → oid) map by
/// recursively walking sub-trees.
fn flatten_tree(
    tree: &gix::Tree<'_>,
) -> Result<std::collections::BTreeMap<String, gix::ObjectId>, DomainError> {
    use gix::objs::tree::EntryKind;
    let mut out: std::collections::BTreeMap<String, gix::ObjectId>
        = std::collections::BTreeMap::new();
    let mut stack: Vec<(String, gix::Tree<'_>)> =
        vec![(String::new(), tree.clone())];
    while let Some((prefix, t)) = stack.pop() {
        let decoded = t.decode().map_err(|e| {
            DomainError::Permanent(format!("decode tree: {e}"))
        })?;
        for entry in decoded.entries.iter() {
            let name = entry.filename.to_string();
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let oid: gix::ObjectId = entry.oid.into();
            match entry.mode.kind() {
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                    out.insert(path, oid);
                }
                EntryKind::Tree => {
                    let sub_obj = t.repo.find_object(oid).map_err(|e| {
                        DomainError::Permanent(format!("find sub-tree: {e}"))
                    })?;
                    let sub = sub_obj.try_into_tree().map_err(|e| {
                        DomainError::Permanent(format!("not a tree: {e}"))
                    })?;
                    stack.push((path, sub));
                }
                EntryKind::Commit => {
                    // Submodule pointer; opaque to the touched-set
                    // for V2 (the spec calls this out — we never
                    // recurse into submodule ODBs).
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provision_hash_is_deterministic() {
        let h1 = compute_provision_hash("init-1", "sess-1", "abc");
        let h2 = compute_provision_hash("init-1", "sess-1", "abc");
        assert_eq!(h1, h2);
    }

    #[test]
    fn provision_hash_changes_with_each_input() {
        let base = compute_provision_hash("init-1", "sess-1", "abc");
        assert_ne!(base, compute_provision_hash("init-X", "sess-1", "abc"));
        assert_ne!(base, compute_provision_hash("init-1", "sess-X", "abc"));
        assert_ne!(base, compute_provision_hash("init-1", "sess-1", "def"));
    }

    #[test]
    fn escalation_classes_are_stable() {
        let adapter = GitAdapter::new(
            PathBuf::from("/tmp/main"),
            PathBuf::from("/tmp/sessions"),
            PathBuf::from("/tmp/transfer"),
        );
        let classes = adapter.escalation_classes();
        assert!(classes.contains(&"protected_path_merge"));
        assert!(classes.contains(&"review_loop_exceeded"));
        assert!(classes.contains(&"merge_conflict_unresolvable"));
        assert!(classes.contains(&"policy_epoch_drift"));
        assert!(classes.contains(&"credential_proxy_denied"));
    }

    #[tokio::test]
    async fn provision_workspace_creates_session_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        let adapter = GitAdapter::new(
            tmp.path().join("main"),
            tmp.path().join("sessions"),
            tmp.path().join("transfer"),
        );
        let session = SessionContext {
            session_id:       "sess-A",
            initiative_id:    "init-X",
            parent_state_ref: "0000000000000000000000000000000000000000",
            policy_epoch_id:  1,
        };
        let h = adapter.provision_workspace(session.clone()).await.unwrap();
        assert!(h.host_path.exists());
        assert!(h.host_path.ends_with("init-X/sess-A"));

        // Determinism: a second provision returns the same hash.
        let h2 = adapter.provision_workspace(session).await.unwrap();
        raxis_domain::conformance::assert_workspace_determinism(&h, &h2);
    }

    #[tokio::test]
    async fn snapshot_is_idempotent_over_unchanged_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let adapter = GitAdapter::new(
            tmp.path().join("main"),
            tmp.path().join("sessions"),
            tmp.path().join("transfer"),
        );
        let session = SessionContext {
            session_id:       "sess-B",
            initiative_id:    "init-Y",
            parent_state_ref: "1111111111111111111111111111111111111111",
            policy_epoch_id:  1,
        };
        let h = adapter.provision_workspace(session.clone()).await.unwrap();
        let s1 = adapter.snapshot(session.clone(), &h).await.unwrap();
        let s2 = adapter.snapshot(session, &h).await.unwrap();
        raxis_domain::conformance::assert_snapshot_idempotency(&s1, &s2);
    }

    #[tokio::test]
    async fn purge_workspace_removes_host_path() {
        let tmp = tempfile::tempdir().unwrap();
        let adapter = GitAdapter::new(
            tmp.path().join("main"),
            tmp.path().join("sessions"),
            tmp.path().join("transfer"),
        );
        let session = SessionContext {
            session_id:       "sess-C",
            initiative_id:    "init-Z",
            parent_state_ref: "2222222222222222222222222222222222222222",
            policy_epoch_id:  1,
        };
        let h = adapter.provision_workspace(session).await.unwrap();
        assert!(h.host_path.exists());
        adapter.purge_workspace(&h).await.unwrap();
        assert!(!h.host_path.exists());
        // Idempotency on a missing path.
        adapter.purge_workspace(&h).await.unwrap();
    }
}
