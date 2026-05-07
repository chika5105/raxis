//! Host-side master-branch fast-forward for V2 `IntegrationMerge`
//! Phase 2.
//!
//! Normative reference:
//!
//! * `integration-merge.md §4 Check 8` (Phase 2: idempotent domain
//!   commit, dispatched by the merge handler after Phase 1's
//!   `git_apply_pending = 1` SQLite intent).
//! * `extensibility-traits.md §2.2.A DomainAdapter::commit` —
//!   `IntegrationMerge` is the SE-domain instantiation of the
//!   paradigm primitive "authorised commit of agent-produced state
//!   to canonical external state". The trait stays in the kernel
//!   binary; this crate is the V2 reference adapter for the git
//!   domain.
//! * `v2-deep-spec.md §Step 8` (Orchestrator owns
//!   `IntegrationMerge`; Kernel verifies ancestry and path
//!   containment, then fast-forwards the master branch).
//!
//! ## What this crate does
//!
//! Two operations, both deliberately simple:
//!
//! 1. [`fetch_into_master`] — copy the merge commit (and its
//!    transitive object graph) from the Orchestrator's worktree
//!    object database (the `<data_dir>/worktrees/<orch_uuid>/.git/`
//!    directory; populated by `raxis-worktree-provision`) into the
//!    master repository's object database. This is the host-side
//!    `git fetch <orchestrator_worktree> <commit_sha>` referenced
//!    in `integration-merge.md §4 Check 8 Phase 2`. Pure object
//!    copy: it does NOT update any ref.
//! 2. [`update_master_ref`] — atomically advance
//!    `refs/heads/master` to point at the requested commit SHA via
//!    `gix-ref::file::Transaction::commit`, mirroring the host-side
//!    `git update-ref refs/heads/master <commit_sha>`.
//!
//! These two calls together implement the master-advancement work
//! the spec calls "Phase 2 (idempotent domain commit)". They are
//! independently idempotent:
//!
//! * Re-running [`fetch_into_master`] after the objects were
//!   already copied is a no-op (gix's clone path skips objects
//!   already present in the destination ODB).
//! * Re-running [`update_master_ref`] when `refs/heads/master`
//!   already equals the target SHA is a no-op (the transaction's
//!   precondition matches the target value).
//!
//! Either ordering of crash-recovery (Phase 2 partially completed,
//! Phase 3 not yet started) replays cleanly.
//!
//! ## What this crate does NOT do
//!
//! * It does not perform the SQLite Phase 1 / Phase 3 transitions
//!   (`integration-merge.md §11`); those stay in the kernel's
//!   merge handler.
//! * It does not push to upstream remotes. The optional
//!   `[git_push]` upstream push (per `integration-merge.md §14`)
//!   is a separate concern that flows through the credential
//!   proxy.
//! * It does not perform ancestry checks. The kernel's
//!   `vcs::is_ancestor` already verifies that the merge commit
//!   descends from `base_sha` BEFORE Phase 2 runs (Check 3 in the
//!   admission pipeline).
//!
//! ## Failure handling
//!
//! Every public function is fail-closed: a transient I/O error
//! returns a typed `MasterMergeError` and leaves the master ODB +
//! refs untouched at any partial state the underlying gix call
//! would have produced. The kernel's recovery path
//! (`integration-merge.md §11.3`) re-invokes both calls on next
//! boot if Phase 2 was incomplete; both are safe to retry.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::{Path, PathBuf};

mod adapter;
pub use adapter::{GitAdapter, SeIntentKind, SeTerminalArtefact};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors the master-merge module can surface.
#[derive(Debug, thiserror::Error)]
pub enum MasterMergeError {
    /// The master repository at `path` cannot be opened (path
    /// missing, not a git repo, ODB corrupt).
    #[error("master repo at {path} cannot be opened: {reason}")]
    MasterRepoUnopenable {
        /// Path the kernel asked to open.
        path:   PathBuf,
        /// Underlying gix error string.
        reason: String,
    },

    /// The Orchestrator worktree at `path` cannot be opened (the
    /// kernel passed a path that does not contain a `.git/`
    /// directory `gix::open` recognises).
    #[error("orchestrator worktree at {path} cannot be opened: {reason}")]
    SourceUnopenable {
        /// Path the kernel asked to fetch from.
        path:   PathBuf,
        /// Underlying gix error string.
        reason: String,
    },

    /// `gix::clone::PrepareFetch::fetch_only` failed during the
    /// host-side fetch step. Most commonly: the file:// URL was
    /// malformed, the source ODB is corrupt, or the requested SHA
    /// is not reachable from any ref.
    #[error("gix fetch failed: {0}")]
    FetchFailed(String),

    /// The requested SHA is not present in the master ODB after
    /// fetching. Indicates either a bug in the kernel's bundle
    /// pipeline (the Orchestrator's worktree advertises a SHA the
    /// fetch did not pull) or a corrupted Orchestrator ODB.
    #[error("requested SHA {sha} not present in master ODB after fetch")]
    ShaMissingPostFetch {
        /// The SHA the Orchestrator submitted as `commit_sha`.
        sha: String,
    },

    /// The ref-update transaction failed. Common causes: a
    /// concurrent writer raced (spec §11 mandates a master-worktree
    /// lock; if the kernel forgets to take it the transaction
    /// catches the race), or the master repo's ref database is
    /// read-only.
    #[error("ref update failed: {0}")]
    RefUpdateFailed(String),

    /// The supplied SHA is not a valid 40-char hex string.
    #[error("invalid commit SHA {sha}: {reason}")]
    InvalidSha {
        /// The bad SHA.
        sha:    String,
        /// Why it failed parse.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Snapshot of where the master branch landed after a successful
/// merge. Returned by [`commit_merge_to_master`] so the caller
/// (the kernel's merge handler) can reconcile its in-memory
/// `initiatives.current_sha` against ground truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterAdvance {
    /// Where master pointed before this call (or `None` if master
    /// did not yet exist — initial-commit case).
    pub previous_sha: Option<String>,
    /// Where master points after this call. Equals the `commit_sha`
    /// argument on success, or equals `previous_sha` when the
    /// idempotency short-circuit fires.
    pub current_sha:  String,
    /// `true` iff this call was a no-op because master already
    /// pointed at the requested SHA. The kernel's audit chain
    /// emits `IntegrationMergeCompleted` once per advancement,
    /// not per call — `already_at_target = true` lets the handler
    /// suppress the audit emission on re-run.
    pub already_at_target: bool,
}

/// Apply the merge commit produced by the Orchestrator to the
/// master repository: copy objects, then advance
/// `refs/heads/master`. This is the full Phase 2 of
/// `integration-merge.md §4 Check 8`.
///
/// **Inputs.**
///
/// * `master_repo_root` — absolute path to the master repository
///   (the canonical state target for this initiative). Must be a
///   git repository the kernel has write access to.
/// * `orch_worktree_root` — absolute path to the Orchestrator's
///   per-initiative worktree (`<data_dir>/worktrees/<orch_uuid>/`,
///   provisioned by `raxis-worktree-provision::provision_orchestrator`).
/// * `commit_sha` — the merge commit SHA the Orchestrator submitted
///   in `IntegrationMerge.commit_sha`. The kernel has already
///   verified ancestry (Check 3) and path containment (Check 5)
///   against this SHA.
///
/// **Returns.** [`MasterAdvance`] capturing the previous and
/// current master SHAs. The kernel reads `current_sha` back into
/// `initiatives.current_sha` before issuing Phase 3's
/// `git_apply_pending = 0` UPDATE.
///
/// **Idempotency.** Safe to call multiple times with the same
/// `commit_sha`. Subsequent calls observe `already_at_target =
/// true` and perform no work.
pub fn commit_merge_to_master(
    master_repo_root:   &Path,
    orch_worktree_root: &Path,
    commit_sha:         &str,
) -> Result<MasterAdvance, MasterMergeError> {
    let oid = parse_oid(commit_sha)?;

    let master_repo = open_master(master_repo_root)?;

    // Capture the master tip before any work — this is the
    // `previous_sha` we'll surface in the `MasterAdvance`.
    let previous = current_master_oid(&master_repo).ok();

    // Idempotency short-circuit: master already at the target.
    if previous.as_ref().map(|p| p == &oid).unwrap_or(false) {
        return Ok(MasterAdvance {
            previous_sha:      previous.as_ref().map(|p| p.to_string()),
            current_sha:       oid.to_string(),
            already_at_target: true,
        });
    }

    // Phase 2a — fetch objects from the Orchestrator's worktree
    // ODB into the master repo. Must complete before Phase 2b.
    fetch_into_master(master_repo_root, orch_worktree_root, &oid)?;

    // Re-open after fetch so we observe the new objects via the
    // master repo's loose-/pack-store handle.
    let master_repo = open_master(master_repo_root)?;
    if master_repo.find_object(oid).is_err() {
        return Err(MasterMergeError::ShaMissingPostFetch {
            sha: oid.to_string(),
        });
    }

    // Phase 2b — atomically advance refs/heads/master to oid.
    update_master_ref(&master_repo, &oid, previous.as_ref())?;

    Ok(MasterAdvance {
        previous_sha:      previous.as_ref().map(|p| p.to_string()),
        current_sha:       oid.to_string(),
        already_at_target: false,
    })
}

/// Fetch a commit (and its transitive object graph) from the
/// Orchestrator's worktree ODB into the master ODB.
///
/// Pure object copy: it never updates a ref. After this call the
/// master ODB sees `commit_sha` as a reachable object but no
/// branch points at it.
///
/// **Why a hand-rolled traversal, not `gix::clone::PrepareFetch`:**
/// `PrepareFetch` refuses to operate against a non-empty
/// destination, so it cannot be repurposed to pour objects into an
/// existing master repository. The alternative — invoking the
/// `gix::Remote::fetch` async API against the Orchestrator's
/// worktree — pulls in a `tokio` runtime for what is logically a
/// local-only object copy and forces packfile negotiation we do
/// not need. The traversal here is the minimal correct
/// implementation: walk every object reachable from `commit_sha`
/// (commits → trees → blobs/symlinks), short-circuit at objects
/// already present in the master ODB, and write the rest via
/// `Repository::write_object`. Each write is automatically a
/// no-op if the object already exists (gix dedups by hash).
pub fn fetch_into_master(
    master_repo_root:   &Path,
    orch_worktree_root: &Path,
    commit_sha:         &gix::ObjectId,
) -> Result<(), MasterMergeError> {
    if !master_repo_root.exists() {
        return Err(MasterMergeError::MasterRepoUnopenable {
            path:   master_repo_root.to_path_buf(),
            reason: "path does not exist".to_owned(),
        });
    }
    if !orch_worktree_root.exists() {
        return Err(MasterMergeError::SourceUnopenable {
            path:   orch_worktree_root.to_path_buf(),
            reason: "path does not exist".to_owned(),
        });
    }

    let master_repo = open_master(master_repo_root)?;
    let orch_repo = gix::open(orch_worktree_root).map_err(|e| {
        MasterMergeError::SourceUnopenable {
            path:   orch_worktree_root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;

    // Short-circuit if the object is already present.
    if master_repo.find_object(*commit_sha).is_ok() {
        return Ok(());
    }

    // Verify the SHA is present in the source ODB before we walk.
    // A missing SHA in the source is a kernel-bundle-pipeline bug
    // (Step 9 wrote a SHA the Orchestrator's worktree doesn't
    // contain), and surfaces as a typed fetch failure.
    if orch_repo.find_object(*commit_sha).is_err() {
        return Err(MasterMergeError::FetchFailed(format!(
            "commit_sha {commit_sha} not found in orchestrator worktree at {}",
            orch_worktree_root.display(),
        )));
    }

    walk_and_copy(&orch_repo, &master_repo, *commit_sha)?;

    Ok(())
}

/// Walk every commit, tree, blob, and symlink reachable from
/// `start` in `src` and write each into `dst` if not already
/// present.
fn walk_and_copy(
    src:   &gix::Repository,
    dst:   &gix::Repository,
    start: gix::ObjectId,
) -> Result<(), MasterMergeError> {
    use gix::objs::tree::EntryKind;
    use std::collections::{HashSet, VecDeque};

    let mut seen:    HashSet<gix::ObjectId> = HashSet::new();
    let mut commits: VecDeque<gix::ObjectId> = VecDeque::new();
    let mut trees:   VecDeque<gix::ObjectId> = VecDeque::new();
    let mut blobs:   VecDeque<gix::ObjectId> = VecDeque::new();

    commits.push_back(start);

    while let Some(commit_oid) = commits.pop_front() {
        if !seen.insert(commit_oid) {
            continue;
        }
        if dst.find_object(commit_oid).is_ok() {
            continue;
        }
        let obj = src.find_object(commit_oid).map_err(|e| {
            MasterMergeError::FetchFailed(format!("find_object({commit_oid}): {e}"))
        })?;
        let commit = obj.try_into_commit().map_err(|e| {
            MasterMergeError::FetchFailed(format!(
                "object {commit_oid} is not a commit: {e}"
            ))
        })?;

        // Decode and queue parents + tree.
        let raw = commit.decode().map_err(|e| {
            MasterMergeError::FetchFailed(format!("decode commit {commit_oid}: {e}"))
        })?;
        let tree_oid = raw.tree();
        trees.push_back(tree_oid);
        for parent in raw.parents() {
            if !seen.contains(&parent) {
                commits.push_back(parent);
            }
        }

        // Write the commit object into dst.
        write_object_bytes(dst, commit.data.as_slice(), gix::object::Kind::Commit)?;
    }

    while let Some(tree_oid) = trees.pop_front() {
        if !seen.insert(tree_oid) {
            continue;
        }
        if dst.find_object(tree_oid).is_ok() {
            continue;
        }
        let obj = src.find_object(tree_oid).map_err(|e| {
            MasterMergeError::FetchFailed(format!("find_object({tree_oid}): {e}"))
        })?;
        let tree = obj.try_into_tree().map_err(|e| {
            MasterMergeError::FetchFailed(format!(
                "object {tree_oid} is not a tree: {e}"
            ))
        })?;
        let decoded = tree.decode().map_err(|e| {
            MasterMergeError::FetchFailed(format!("decode tree {tree_oid}: {e}"))
        })?;
        for entry in decoded.entries.iter() {
            let oid: gix::ObjectId = entry.oid.into();
            match entry.mode.kind() {
                EntryKind::Tree            => trees.push_back(oid),
                EntryKind::Blob
                | EntryKind::BlobExecutable
                | EntryKind::Link          => blobs.push_back(oid),
                EntryKind::Commit          => {
                    // Submodule pointer; we never recurse into it.
                }
            }
        }
        write_object_bytes(dst, tree.data.as_slice(), gix::object::Kind::Tree)?;
    }

    while let Some(blob_oid) = blobs.pop_front() {
        if !seen.insert(blob_oid) {
            continue;
        }
        if dst.find_object(blob_oid).is_ok() {
            continue;
        }
        let obj = src.find_object(blob_oid).map_err(|e| {
            MasterMergeError::FetchFailed(format!("find_object({blob_oid}): {e}"))
        })?;
        write_object_bytes(dst, obj.data.as_slice(), gix::object::Kind::Blob)?;
    }

    Ok(())
}

/// Write a raw object payload into `dst`'s ODB. Uses
/// `Repository::write_blob` for blobs (the most common case) to
/// minimise allocations, and the generic `write_buf` shim for
/// commits and trees. All three are dedup-by-hash.
fn write_object_bytes(
    dst:  &gix::Repository,
    body: &[u8],
    kind: gix::object::Kind,
) -> Result<(), MasterMergeError> {
    use gix::object::Kind;
    match kind {
        Kind::Blob => {
            dst.write_blob(body).map_err(|e| {
                MasterMergeError::FetchFailed(format!("write_blob: {e}"))
            })?;
        }
        _ => {
            use gix::prelude::Write as _;
            dst.objects.write_buf(kind, body).map_err(|e| {
                MasterMergeError::FetchFailed(format!("write_buf: {e}"))
            })?;
        }
    }
    Ok(())
}

/// Atomically advance `refs/heads/master` to `oid` via a
/// `gix-ref` transaction. Used by [`commit_merge_to_master`] but
/// also exposed for tests that want to drive the ref update in
/// isolation.
///
/// `expected_previous` is the value the kernel believes master
/// points at right now; if `Some`, the transaction's precondition
/// requires the on-disk ref to equal that value (so a concurrent
/// writer's update is detected and the transaction aborts). If
/// `None`, the transaction is unconstrained — master must not
/// exist yet (an initial-commit pinning).
pub fn update_master_ref(
    repo:              &gix::Repository,
    oid:               &gix::ObjectId,
    expected_previous: Option<&gix::ObjectId>,
) -> Result<(), MasterMergeError> {
    use gix::refs::transaction::{Change, LogChange, RefEdit, RefLog, PreviousValue};
    use gix::refs::{FullName, Target};

    let full_name = FullName::try_from("refs/heads/master").map_err(|e| {
        MasterMergeError::RefUpdateFailed(format!("FullName::try_from: {e}"))
    })?;

    let previous = match expected_previous {
        Some(prev) => PreviousValue::MustExistAndMatch(Target::Object(*prev)),
        None       => PreviousValue::MustNotExist,
    };

    let edit = RefEdit {
        change: Change::Update {
            log: LogChange {
                mode:           RefLog::AndReference,
                force_create_reflog: false,
                message:        "raxis: IntegrationMerge fast-forward".into(),
            },
            expected: previous,
            new:      Target::Object(*oid),
        },
        name: full_name,
        deref: false,
    };

    repo.edit_reference(edit).map_err(|e| {
        MasterMergeError::RefUpdateFailed(format!("edit_reference: {e}"))
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn open_master(path: &Path) -> Result<gix::Repository, MasterMergeError> {
    gix::open(path).map_err(|e| MasterMergeError::MasterRepoUnopenable {
        path:   path.to_path_buf(),
        reason: e.to_string(),
    })
}

fn current_master_oid(repo: &gix::Repository) -> Result<gix::ObjectId, MasterMergeError> {
    let r = repo
        .find_reference("refs/heads/master")
        .map_err(|e| MasterMergeError::RefUpdateFailed(format!("find_reference: {e}")))?;
    Ok(r.target().try_id().map(|id| id.to_owned()).ok_or_else(|| {
        MasterMergeError::RefUpdateFailed(
            "refs/heads/master is symbolic, expected direct".to_owned(),
        )
    })?)
}

fn parse_oid(sha: &str) -> Result<gix::ObjectId, MasterMergeError> {
    gix::ObjectId::from_hex(sha.as_bytes()).map_err(|e| MasterMergeError::InvalidSha {
        sha:    sha.to_owned(),
        reason: e.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Tests — exercise master-advancement against real gix repositories.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Set up two repositories: a master repo (initially containing
    /// one commit at `base_sha`) and an "orchestrator" worktree
    /// containing two commits (`base_sha` and `merge_sha`). The
    /// orchestrator worktree was cloned from the master repo, then
    /// advanced.
    fn fixture_master_and_orchestrator(
        tmp: &Path,
    ) -> Option<(PathBuf, PathBuf, String, String)> {
        if Command::new("git").arg("--version").output().is_err() {
            return None;
        }
        let master = tmp.join("master");
        std::fs::create_dir_all(&master).ok()?;
        let run = |args: &[&str], cwd: &Path| {
            let s = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_AUTHOR_NAME", "RAXIS Test")
                .env("GIT_AUTHOR_EMAIL", "test@raxis.local")
                .env("GIT_COMMITTER_NAME", "RAXIS Test")
                .env("GIT_COMMITTER_EMAIL", "test@raxis.local")
                .env("GIT_AUTHOR_DATE", "1700000000 +0000")
                .env("GIT_COMMITTER_DATE", "1700000000 +0000")
                .output()
                .expect("git invocation");
            assert!(
                s.status.success(),
                "git {args:?} failed in {}: {} / {}",
                cwd.display(),
                String::from_utf8_lossy(&s.stdout),
                String::from_utf8_lossy(&s.stderr),
            );
            s
        };
        run(&["init", "-q"], &master);
        run(&["symbolic-ref", "HEAD", "refs/heads/master"], &master);
        run(&["config", "user.name", "RAXIS Test"], &master);
        run(&["config", "user.email", "test@raxis.local"], &master);
        run(&["config", "commit.gpgsign", "false"], &master);
        std::fs::write(master.join("README.md"), "v1\n").ok()?;
        run(&["add", "README.md"], &master);
        run(&["commit", "-q", "-m", "initial"], &master);
        let base = String::from_utf8(run(&["rev-parse", "HEAD"], &master).stdout).ok()?
            .trim().to_owned();

        // Now mint an "orchestrator worktree" by cloning master
        // and advancing it by one more commit.
        let orch = tmp.join("orchestrator.work");
        run(&["clone", "-q", master.to_str()?, orch.to_str()?], tmp);
        run(&["config", "user.name", "RAXIS Test"], &orch);
        run(&["config", "user.email", "test@raxis.local"], &orch);
        run(&["config", "commit.gpgsign", "false"], &orch);
        std::fs::write(orch.join("README.md"), "v1\nv2\n").ok()?;
        run(&["add", "README.md"], &orch);
        run(&["commit", "-q", "-m", "merge: add v2"], &orch);
        let merge_sha = String::from_utf8(run(&["rev-parse", "HEAD"], &orch).stdout).ok()?
            .trim().to_owned();

        Some((master, orch, base, merge_sha))
    }

    #[test]
    fn commit_merge_to_master_fast_forwards_master_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((master, orch, base, merge)) =
            fixture_master_and_orchestrator(tmp.path())
        else {
            eprintln!("skipping: git CLI not available");
            return;
        };

        let advance = commit_merge_to_master(&master, &orch, &merge).unwrap();
        assert_eq!(advance.previous_sha.as_deref(), Some(base.as_str()));
        assert_eq!(advance.current_sha, merge);
        assert!(!advance.already_at_target);

        // master must now point at merge.
        let head = String::from_utf8(
            std::process::Command::new("git")
                .args(["rev-parse", "refs/heads/master"])
                .current_dir(&master)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        assert_eq!(head, merge,
            "master must fast-forward to the merge commit");
    }

    #[test]
    fn commit_merge_to_master_is_idempotent_on_replay() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((master, orch, base, merge)) =
            fixture_master_and_orchestrator(tmp.path())
        else {
            eprintln!("skipping: git CLI not available");
            return;
        };

        let first = commit_merge_to_master(&master, &orch, &merge).unwrap();
        assert!(!first.already_at_target);

        // Re-run — idempotency guard: returns already_at_target.
        let second = commit_merge_to_master(&master, &orch, &merge).unwrap();
        assert!(second.already_at_target,
            "second commit_merge_to_master must be a no-op when master \
             is already at the target SHA (Check 8 Phase 2 idempotency)");
        assert_eq!(second.previous_sha.as_deref(), Some(merge.as_str()));
        assert_eq!(second.current_sha, merge);
        let _ = base;
    }

    #[test]
    fn commit_merge_to_master_fails_closed_on_bogus_sha() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((master, orch, _base, _merge)) =
            fixture_master_and_orchestrator(tmp.path())
        else {
            eprintln!("skipping: git CLI not available");
            return;
        };

        let result = commit_merge_to_master(
            &master,
            &orch,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
        match result {
            Err(MasterMergeError::ShaMissingPostFetch { sha }) => {
                assert!(sha.starts_with("deadbeef"));
            }
            // PrepareFetch may surface this as a fetch error if the
            // refspec walk doesn't find the requested SHA in the
            // source repo.
            Err(MasterMergeError::FetchFailed(_)) => {}
            other => panic!("expected ShaMissingPostFetch / FetchFailed, got {other:?}"),
        }
    }

    #[test]
    fn commit_merge_to_master_rejects_unopenable_master() {
        let tmp = tempfile::tempdir().unwrap();
        let nonexistent = tmp.path().join("never-existed");
        let orch = tmp.path().join("orch");
        std::fs::create_dir_all(&orch).unwrap();
        let result = commit_merge_to_master(
            &nonexistent,
            &orch,
            "0000000000000000000000000000000000000000",
        );
        match result {
            Err(MasterMergeError::MasterRepoUnopenable { .. }) => {}
            other => panic!("expected MasterRepoUnopenable, got {other:?}"),
        }
    }

    #[test]
    fn commit_merge_to_master_copies_full_object_graph() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((master, orch, _base, _merge)) =
            fixture_master_and_orchestrator(tmp.path())
        else {
            eprintln!("skipping: git CLI not available");
            return;
        };
        let run = |args: &[&str], cwd: &Path| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_AUTHOR_NAME", "RAXIS Test")
                .env("GIT_AUTHOR_EMAIL", "test@raxis.local")
                .env("GIT_COMMITTER_NAME", "RAXIS Test")
                .env("GIT_COMMITTER_EMAIL", "test@raxis.local")
                .env("GIT_AUTHOR_DATE", "1700000000 +0000")
                .env("GIT_COMMITTER_DATE", "1700000000 +0000")
                .output().expect("git invocation")
        };

        // Add two more commits to the orchestrator worktree to
        // build a multi-step graph.
        std::fs::write(orch.join("a.txt"), "alpha\n").unwrap();
        run(&["add", "a.txt"], &orch);
        run(&["commit", "-q", "-m", "add alpha"], &orch);
        std::fs::write(orch.join("b.txt"), "beta\n").unwrap();
        run(&["add", "b.txt"], &orch);
        run(&["commit", "-q", "-m", "add beta"], &orch);
        let final_sha = String::from_utf8(run(&["rev-parse", "HEAD"], &orch).stdout)
            .unwrap().trim().to_owned();

        // Now run the master fast-forward. Every intermediate
        // commit, tree, and blob must land in master's ODB.
        let advance = commit_merge_to_master(&master, &orch, &final_sha).unwrap();
        assert_eq!(advance.current_sha, final_sha);

        // Verify the master ODB has every blob in the chain.
        let master_repo = gix::open(&master).unwrap();
        for entry in ["README.md", "a.txt", "b.txt"] {
            let body = std::fs::read(orch.join(entry)).unwrap();
            let blob_oid = gix::ObjectId::from_hex(
                String::from_utf8(
                    run(&["hash-object", "--", entry], &orch).stdout,
                )
                .unwrap()
                .trim()
                .as_bytes(),
            )
            .unwrap();
            let copied = master_repo.find_object(blob_oid).unwrap();
            assert_eq!(
                copied.data.as_slice(),
                body.as_slice(),
                "blob for {entry} did not round-trip into master ODB",
            );
        }
    }

    #[test]
    fn parse_oid_round_trips() {
        let s = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(parse_oid(s).unwrap().to_string(), s);
    }

    #[test]
    fn parse_oid_rejects_bad_hex() {
        let err = parse_oid("nothex").unwrap_err();
        match err {
            MasterMergeError::InvalidSha { sha, .. } => assert_eq!(sha, "nothex"),
            other => panic!("expected InvalidSha, got {other:?}"),
        }
    }
}
