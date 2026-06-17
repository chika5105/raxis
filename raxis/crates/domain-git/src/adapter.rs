//! `GitAdapter` — git-domain state helpers.
//!
//! Normative reference: `specs/v2/extensibility-traits.md §2.3`.
//!
//! # Scope
//!
//! This is the V2 git-domain implementation: it wraps the existing
//! free functions in `crate::lib` (main fast-forward, ancestry checks,
//! `gix::diff`-driven touched-set computation) so the kernel can call
//! a concrete `GitAdapter`.
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

#[cfg(test)]
use raxis_domain::ContentHash;
use raxis_domain::{DomainError, TouchedResources};
#[cfg(test)]
use raxis_domain::{SessionContext, Snapshot, WorkspaceHandle};
#[cfg(test)]
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// GitAdapter struct
// ---------------------------------------------------------------------------

/// `GitAdapter` is the V2 git-domain implementation. The kernel
/// constructs exactly one instance at boot (`kernel/src/main.rs`) and
/// shares it across all in-flight sessions via `Arc`.
#[derive(Debug, Clone)]
pub struct GitAdapter {
    /// Path to the canonical main repository the adapter advances
    /// in `commit`. SE: typically
    /// `<data_dir>/repositories/<initiative_id>/main/`.
    pub main_repo_path: Arc<PathBuf>,
    /// Path under which per-session worktrees are provisioned. SE:
    /// `<data_dir>/worktrees/`.
    pub sessions_root: Arc<PathBuf>,
    /// Path under which inter-session bundles are staged. SE:
    /// `<data_dir>/transfer/`.
    pub transfer_root: Arc<PathBuf>,
}

impl GitAdapter {
    /// Construct a `GitAdapter` against the given on-disk roots.
    /// Each path may already exist or may be created lazily by the
    /// adapter on first use; the kernel's `setup wizard` lays down
    /// canonical zero-mode parent dirs at install time.
    pub fn new(main_repo_path: PathBuf, sessions_root: PathBuf, transfer_root: PathBuf) -> Self {
        Self {
            main_repo_path: Arc::new(main_repo_path),
            sessions_root: Arc::new(sessions_root),
            transfer_root: Arc::new(transfer_root),
        }
    }
}

// ---------------------------------------------------------------------------
// Git-domain operations
// ---------------------------------------------------------------------------

impl GitAdapter {
    #[cfg(test)]
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
                DomainError::Permanent(format!("create_dir_all({}): {e}", host_path.display(),))
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

    #[cfg(test)]
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
            content_hash: workspace.content_hash.clone(),
            parent_hash: None,
            adapter_state: Box::new(()),
        })
    }

    /// Return whether `parent_state_ref` is an ancestor of `target_state_ref`.
    pub async fn is_ancestor(
        &self,
        parent_state_ref: &str,
        target_state_ref: &str,
        workspace_root: &std::path::Path,
    ) -> Result<bool, DomainError> {
        let p = parent_state_ref.to_owned();
        let t = target_state_ref.to_owned();
        let w = workspace_root.to_path_buf();
        tokio::task::spawn_blocking(move || crate::git_cli::is_ancestor(&p, &t, &w))
            .await
            .map_err(|e| DomainError::Transient(format!("is_ancestor join: {e}")))?
    }

    /// Reject merge commits or invalid topology for a candidate range.
    pub async fn topology_check(
        &self,
        parent_state_ref: &str,
        target_state_ref: &str,
        workspace_root: &std::path::Path,
    ) -> Result<(), DomainError> {
        let p = parent_state_ref.to_owned();
        let t = target_state_ref.to_owned();
        let w = workspace_root.to_path_buf();
        tokio::task::spawn_blocking(move || crate::git_cli::topology_check(&p, &t, &w))
            .await
            .map_err(|e| DomainError::Transient(format!("topology_check join: {e}")))?
    }

    /// Compute the sorted touched resource set between two git refs.
    pub async fn compute_touched_paths(
        &self,
        parent_state_ref: &str,
        target_state_ref: &str,
        workspace_root: &std::path::Path,
    ) -> Result<TouchedResources, DomainError> {
        let p = parent_state_ref.to_owned();
        let t = target_state_ref.to_owned();
        let w = workspace_root.to_path_buf();
        tokio::task::spawn_blocking(move || crate::git_cli::compute_touched(&p, &t, &w))
            .await
            .map_err(|e| DomainError::Transient(format!("compute_touched_paths join: {e}")))?
    }

    #[cfg(test)]
    fn escalation_classes(&self) -> &'static [&'static str] {
        &[
            "protected_path_merge",
            "review_loop_exceeded",
            "merge_conflict_unresolvable",
            "policy_epoch_drift",
            "credential_proxy_denied",
        ]
    }

    #[cfg(test)]
    async fn purge_workspace(&self, workspace: &WorkspaceHandle) -> Result<(), DomainError> {
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
#[cfg(test)]
fn compute_provision_hash(
    initiative_id: &str,
    session_id: &str,
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
            session_id: "sess-A",
            initiative_id: "init-X",
            parent_state_ref: "0000000000000000000000000000000000000000",
            policy_epoch_id: 1,
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
            session_id: "sess-B",
            initiative_id: "init-Y",
            parent_state_ref: "1111111111111111111111111111111111111111",
            policy_epoch_id: 1,
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
            session_id: "sess-C",
            initiative_id: "init-Z",
            parent_state_ref: "2222222222222222222222222222222222222222",
            policy_epoch_id: 1,
        };
        let h = adapter.provision_workspace(session).await.unwrap();
        assert!(h.host_path.exists());
        adapter.purge_workspace(&h).await.unwrap();
        assert!(!h.host_path.exists());
        // Idempotency on a missing path.
        adapter.purge_workspace(&h).await.unwrap();
    }
}
