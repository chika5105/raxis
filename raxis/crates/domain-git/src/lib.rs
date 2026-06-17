//! Host-side target-ref advancement for V2 `IntegrationMerge`
//! Phase 2.
//! Normative reference:
//! * `integration-merge.md §4 Check 8` (Phase 2: idempotent domain
//!   commit, dispatched by the merge handler after Phase 1's
//!   `git_apply_pending = 1` SQLite intent).
//! * `extensibility-traits.md §2.2.A` — `IntegrationMerge` is the
//!   SE-domain instantiation of the paradigm primitive "authorised
//!   commit of agent-produced state to canonical external state".
//! * `v2-deep-spec.md §Step 8` (Orchestrator owns
//!   `IntegrationMerge`; Kernel verifies ancestry and path
//!   containment, then advances the target ref).
//! ## What this crate does
//! Two operations, both deliberately simple:
//! 1. [`fetch_into_main`] — copy the merge commit (and its
//!    transitive object graph) from the Orchestrator's worktree
//!    object database (the `<data_dir>/worktrees/<orch_uuid>/.git/`
//!    directory; populated by `raxis-worktree-provision`) into the
//!    main repository's object database. This is the host-side
//!    `git fetch <orchestrator_worktree> <commit_sha>` referenced
//!    in `integration-merge.md §4 Check 8 Phase 2`. Pure object
//!    copy: it does NOT update any ref.
//! 2. [`update_target_ref`] — atomically advance the
//!    operator-configured target ref (default `refs/heads/main`,
//!    overridable per-initiative via `[workspace] target_ref` in
//!    plan.toml —) to point at the
//!    requested commit SHA via `gix-ref::file::Transaction::commit`,
//!    mirroring the host-side
//!    `git update-ref <target_ref> <commit_sha>`.
//!    These two calls together implement the main-advancement work
//!    the spec calls "Phase 2 (idempotent domain commit)". They are
//!    independently idempotent:
//! * Re-running [`fetch_into_main`] after the objects were
//!   already copied is a no-op (gix's clone path skips objects
//!   already present in the destination ODB).
//! * Re-running [`update_target_ref`] when the configured
//!   target ref already equals the target SHA is a no-op (the
//!   transaction's precondition matches the target value).
//!   Either ordering of crash-recovery (Phase 2 partially completed,
//!   Phase 3 not yet started) replays cleanly.
//! ## What this crate does NOT do
//! * It does not perform the SQLite Phase 1 / Phase 3 transitions
//!   (`integration-merge.md §11`); those stay in the kernel's
//!   merge handler.
//! * It does not push to upstream remotes. The optional
//!   `[git_push]` upstream push (per `integration-merge.md §14`)
//!   is a separate concern that flows through the credential
//!   proxy.
//! * It does not perform policy ancestry checks. The kernel's
//!   `vcs::is_ancestor` already verifies that the merge commit
//!   descends from the initiative `base_sha` BEFORE Phase 2 runs
//!   (Check 3 in the admission pipeline). This crate still verifies
//!   the domain-level live-tip preservation invariant immediately
//!   before the ref transaction, because concurrent initiatives can
//!   advance `target_ref` after an initiative's original `base_sha`
//!   was minted.
//! ## Failure handling
//! Every public function is retry-safe: a transient I/O error
//! returns a typed `MainMergeError`. Failures before the ref
//! transaction leave refs untouched; a failure while refreshing the
//! checked-out worktree can leave the target ref advanced but the
//! index/worktree stale. The kernel's recovery path
//! (`integration-merge.md §11.3`) re-invokes this operation on
//! next boot; the idempotency short-circuit refreshes the worktree
//! again when the ref already points at the target SHA.
//! ## Invariants
//! * **INV-MERGE-CONSISTENCY** — structurally enforced by the
//!   gix-driven object-copy + ref-update sequence: the
//!   ref-update is performed via
//!   `gix-ref::file::Transaction::commit` with the prior tip
//!   set as the precondition, so two concurrent merge attempts
//!   either both observe the same prior tip and one wins, or
//!   one observes a newer tip and aborts. There is no path that
//!   advances the target ref past an unfetched commit because
//!   `fetch_into_main` runs first and copies the full commit
//!   graph before `update_target_ref` is invoked.
//! * **INV-MERGE-PRESERVE-LIVE-TIP** — before the ref transaction,
//!   the final published commit must descend from the live
//!   `target_ref` tip. If the Orchestrator candidate was prepared
//!   against a stale initiative `base_sha`, the adapter creates a
//!   deterministic host-side merge commit that has both the live tip
//!   and the Orchestrator candidate as parents. Conflict-free
//!   concurrent initiatives therefore compose; conflicting changes
//!   fail closed without advancing the ref.
//! * **INV-MERGE-WORKTREE-CONSISTENCY** — when the target ref is
//!   the currently checked-out branch, Phase 2 refreshes the main
//!   repository's index and working tree to the accepted commit
//!   after the ref transaction. This keeps dashboard review and
//!   post-merge inspection from seeing a dirty tree full of
//!   apparent deletions after a successful advancement.
//! * **INV-MERGE-WORKTREE-RETAIN** — structurally enforced by
//!   absence: this crate exposes no worktree cleanup or
//!   removal entry point. Successful Phase 2 leaves
//!   `<data_dir>/worktrees/<orch_uuid>/` exactly where the
//!   provisioner placed it. Worktree GC is a separate, explicit
//!   sub-task (V3) and never piggybacks on merge.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::{Path, PathBuf};

mod adapter;
pub mod git_cli;
pub use adapter::GitAdapter;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors the main-merge module can surface.
#[derive(Debug, thiserror::Error)]
pub enum MainMergeError {
    /// The main repository at `path` cannot be opened (path
    /// missing, not a git repo, ODB corrupt).
    #[error("main repo at {path} cannot be opened: {reason}")]
    MainRepoUnopenable {
        /// Path the kernel asked to open.
        path: PathBuf,
        /// Underlying gix error string.
        reason: String,
    },

    /// The Orchestrator worktree at `path` cannot be opened (the
    /// kernel passed a path that does not contain a `.git/`
    /// directory `gix::open` recognises).
    #[error("orchestrator worktree at {path} cannot be opened: {reason}")]
    SourceUnopenable {
        /// Path the kernel asked to fetch from.
        path: PathBuf,
        /// Underlying gix error string.
        reason: String,
    },

    /// `gix::clone::PrepareFetch::fetch_only` failed during the
    /// host-side fetch step. Most commonly: the file:// URL was
    /// malformed, the source ODB is corrupt, or the requested SHA
    /// is not reachable from any ref.
    #[error("gix fetch failed: {0}")]
    FetchFailed(String),

    /// The requested SHA is not present in the main ODB after
    /// fetching. Indicates either a bug in the kernel's bundle
    /// pipeline (the Orchestrator's worktree advertises a SHA the
    /// fetch did not pull) or a corrupted Orchestrator ODB.
    #[error("requested SHA {sha} not present in main ODB after fetch")]
    ShaMissingPostFetch {
        /// The SHA the Orchestrator submitted as `commit_sha`.
        sha: String,
    },

    /// The ref-update transaction failed. Common causes: a
    /// concurrent writer raced (spec §11 mandates a main-worktree
    /// lock; if the kernel forgets to take it the transaction
    /// catches the race), or the main repo's ref database is
    /// read-only.
    #[error("ref update failed: {0}")]
    RefUpdateFailed(String),

    /// The target ref advanced since the Orchestrator cloned its
    /// workspace and the adapter attempted the deterministic
    /// host-side preservation merge, but git reported conflicts (or
    /// another merge-time failure) before a publishable commit could
    /// be produced. The target ref is untouched.
    #[error(
        "concurrent target merge failed for {target_ref}: candidate {candidate_sha} could not merge with live tip {previous_sha}: {reason}"
    )]
    ConcurrentMergeFailed {
        /// Ref that was about to be advanced.
        target_ref: String,
        /// Live tip of the target ref.
        previous_sha: String,
        /// Candidate SHA submitted by the Orchestrator.
        candidate_sha: String,
        /// stderr/stdout summary from git.
        reason: String,
    },

    /// The target ref advanced but refreshing the checked-out
    /// worktree/index to the new commit failed.
    #[error("worktree refresh at {path} failed: {reason}")]
    WorktreeRefreshFailed {
        /// Repository root whose working tree was being refreshed.
        path: PathBuf,
        /// Underlying git error.
        reason: String,
    },

    /// The supplied SHA is not a valid 40-char hex string.
    #[error("invalid commit SHA {sha}: {reason}")]
    InvalidSha {
        /// The bad SHA.
        sha: String,
        /// Why it failed parse.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Snapshot of where the main branch landed after a successful
/// merge. Returned by [`commit_merge_to_main`] so the caller
/// (the kernel's merge handler) can reconcile its in-memory
/// `initiatives.current_sha` against ground truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainAdvance {
    /// Where main pointed before this call (or `None` if main
    /// did not yet exist — initial-commit case).
    pub previous_sha: Option<String>,
    /// Where main points after this call. Equals the `commit_sha`
    /// argument on ordinary fast-forward success, equals a
    /// deterministic host-side merge commit when the live target ref
    /// advanced concurrently and merged cleanly, or equals
    /// `previous_sha` when the idempotency short-circuit fires.
    pub current_sha: String,
    /// `true` iff this call was a no-op because main already
    /// pointed at the requested SHA. The kernel's audit chain
    /// emits `IntegrationMergeCompleted` once per advancement,
    /// not per call — `already_at_target = true` lets the handler
    /// suppress the audit emission on re-run.
    pub already_at_target: bool,
}

/// Apply the merge commit produced by the Orchestrator to the
/// main repository: copy objects, then advance
/// the operator-configured target ref. This is the full Phase 2 of
/// `integration-merge.md §4 Check 8`.
/// **Inputs.**
/// * `main_repo_root` — absolute path to the main repository
///   (the canonical state target for this initiative). Must be a
///   git repository the kernel has write access to.
/// * `orch_worktree_root` — absolute path to the Orchestrator's
///   per-initiative worktree (`<data_dir>/worktrees/<orch_uuid>/`,
///   provisioned by `raxis-worktree-provision::provision_orchestrator`).
/// * `commit_sha` — the merge commit SHA the Orchestrator submitted
///   in `IntegrationMerge.commit_sha`. The kernel has already
///   verified ancestry (Check 3) and path containment (Check 5)
///   against this SHA.
/// * `target_ref` — the fully-qualified ref name to advance
///   (e.g., `"refs/heads/main"` or `"refs/heads/raxis/auth-refactor"`).
///   The plan-side override + policy-side default + locked flag is
///   resolved at admission time per ; this
///   function takes the resolved string verbatim.
///   **Returns.** [`MainAdvance`] capturing the previous and
///   current target-ref SHAs. The kernel reads `current_sha` back
///   into `initiatives.current_sha` before issuing Phase 3's
///   `git_apply_pending = 0` UPDATE.
///   **Idempotency.** Safe to call multiple times with the same
///   `commit_sha`. Subsequent calls observe `already_at_target =
/// true` and perform no work.
pub fn commit_merge_to_target_ref(
    main_repo_root: &Path,
    orch_worktree_root: &Path,
    commit_sha: &str,
    target_ref: &str,
) -> Result<MainAdvance, MainMergeError> {
    let oid = parse_oid(commit_sha)?;

    let main_repo = open_main(main_repo_root)?;

    // Capture the target-ref tip before any work — this is the
    // `previous_sha` we'll surface in the `MainAdvance`.
    let previous = current_ref_oid(&main_repo, target_ref).ok();

    // Idempotency short-circuit: target ref already at the SHA.
    if previous.as_ref().map(|p| p == &oid).unwrap_or(false) {
        refresh_checked_out_worktree(main_repo_root, &oid, target_ref)?;
        return Ok(MainAdvance {
            previous_sha: previous.as_ref().map(|p| p.to_string()),
            current_sha: oid.to_string(),
            already_at_target: true,
        });
    }

    // Phase 2a — fetch objects from the Orchestrator's worktree
    // ODB into the main repo. Must complete before Phase 2b.
    fetch_into_main(main_repo_root, orch_worktree_root, &oid)?;

    // Re-open after fetch so we observe the new objects via the
    // main repo's loose-/pack-store handle.
    let main_repo = open_main(main_repo_root)?;
    if main_repo.find_object(oid).is_err() {
        return Err(MainMergeError::ShaMissingPostFetch {
            sha: oid.to_string(),
        });
    }

    let final_oid = if let Some(prev) = previous.as_ref() {
        if candidate_fast_forwards_target(main_repo_root, prev, &oid)? {
            oid
        } else {
            synthesize_concurrent_target_merge(main_repo_root, prev, &oid, target_ref)?
        }
    } else {
        oid
    };

    // Phase 2b — atomically advance the target ref to the final
    // publishable commit. In the common case this is the
    // Orchestrator candidate; when another initiative advanced the
    // same target ref, this is the deterministic host-side merge
    // commit that preserves both histories.
    let main_repo = open_main(main_repo_root)?;
    update_target_ref(&main_repo, &final_oid, previous.as_ref(), target_ref)?;
    refresh_checked_out_worktree(main_repo_root, &final_oid, target_ref)?;

    Ok(MainAdvance {
        previous_sha: previous.as_ref().map(|p| p.to_string()),
        current_sha: final_oid.to_string(),
        already_at_target: false,
    })
}

/// Convenience wrapper around [`commit_merge_to_target_ref`] pinned
/// to `refs/heads/main`, the canonical fallback when the initiative
/// did not configure a per-initiative `target_ref`
/// ( policy default). The production
/// `IntegrationMerge` handler (`raxis-kernel::handlers::intent`)
/// resolves `target_ref` from the orchestrator plan-fields registry
/// and calls [`commit_merge_to_target_ref`] directly; this wrapper
/// only feeds the in-crate test helpers, which target
/// `refs/heads/main` explicitly.
pub fn commit_merge_to_main(
    main_repo_root: &Path,
    orch_worktree_root: &Path,
    commit_sha: &str,
) -> Result<MainAdvance, MainMergeError> {
    commit_merge_to_target_ref(
        main_repo_root,
        orch_worktree_root,
        commit_sha,
        "refs/heads/main",
    )
}

/// Fetch a commit (and its transitive object graph) from the
/// Orchestrator's worktree ODB into the main ODB.
/// Pure object copy: it never updates a ref. After this call the
/// main ODB sees `commit_sha` as a reachable object but no
/// branch points at it.
/// **Why a hand-rolled traversal, not `gix::clone::PrepareFetch`:**
/// `PrepareFetch` refuses to operate against a non-empty
/// destination, so it cannot be repurposed to pour objects into an
/// existing main repository. The alternative — invoking the
/// `gix::Remote::fetch` async API against the Orchestrator's
/// worktree — pulls in a `tokio` runtime for what is logically a
/// local-only object copy and forces packfile negotiation we do
/// not need. The traversal here is the minimal correct
/// implementation: walk every object reachable from `commit_sha`
/// (commits → trees → blobs/symlinks), short-circuit at objects
/// already present in the main ODB, and write the rest via
/// `Repository::write_object`. Each write is automatically a
/// no-op if the object already exists (gix dedups by hash).
pub fn fetch_into_main(
    main_repo_root: &Path,
    orch_worktree_root: &Path,
    commit_sha: &gix::ObjectId,
) -> Result<(), MainMergeError> {
    if !main_repo_root.exists() {
        return Err(MainMergeError::MainRepoUnopenable {
            path: main_repo_root.to_path_buf(),
            reason: "path does not exist".to_owned(),
        });
    }
    if !orch_worktree_root.exists() {
        return Err(MainMergeError::SourceUnopenable {
            path: orch_worktree_root.to_path_buf(),
            reason: "path does not exist".to_owned(),
        });
    }

    let main_repo = open_main(main_repo_root)?;
    let orch_repo =
        gix::open(orch_worktree_root).map_err(|e| MainMergeError::SourceUnopenable {
            path: orch_worktree_root.to_path_buf(),
            reason: e.to_string(),
        })?;

    // Short-circuit if the object is already present.
    if main_repo.find_object(*commit_sha).is_ok() {
        return Ok(());
    }

    // Verify the SHA is present in the source ODB before we walk.
    // A missing SHA in the source is a kernel-bundle-pipeline bug
    // (Step 9 wrote a SHA the Orchestrator's worktree doesn't
    // contain), and surfaces as a typed fetch failure.
    if orch_repo.find_object(*commit_sha).is_err() {
        return Err(MainMergeError::FetchFailed(format!(
            "commit_sha {commit_sha} not found in orchestrator worktree at {}",
            orch_worktree_root.display(),
        )));
    }

    walk_and_copy(&orch_repo, &main_repo, *commit_sha)?;

    Ok(())
}

/// Walk every commit, tree, blob, and symlink reachable from
/// `start` in `src` and write each into `dst` if not already
/// present.
fn walk_and_copy(
    src: &gix::Repository,
    dst: &gix::Repository,
    start: gix::ObjectId,
) -> Result<(), MainMergeError> {
    use gix::objs::tree::EntryKind;
    use std::collections::{HashSet, VecDeque};

    let mut seen: HashSet<gix::ObjectId> = HashSet::new();
    let mut commits: VecDeque<gix::ObjectId> = VecDeque::new();
    let mut trees: VecDeque<gix::ObjectId> = VecDeque::new();
    let mut blobs: VecDeque<gix::ObjectId> = VecDeque::new();

    commits.push_back(start);

    while let Some(commit_oid) = commits.pop_front() {
        if !seen.insert(commit_oid) {
            continue;
        }
        if dst.find_object(commit_oid).is_ok() {
            continue;
        }
        let obj = src
            .find_object(commit_oid)
            .map_err(|e| MainMergeError::FetchFailed(format!("find_object({commit_oid}): {e}")))?;
        let commit = obj.try_into_commit().map_err(|e| {
            MainMergeError::FetchFailed(format!("object {commit_oid} is not a commit: {e}"))
        })?;

        // Decode and queue parents + tree.
        let raw = commit
            .decode()
            .map_err(|e| MainMergeError::FetchFailed(format!("decode commit {commit_oid}: {e}")))?;
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
        let obj = src
            .find_object(tree_oid)
            .map_err(|e| MainMergeError::FetchFailed(format!("find_object({tree_oid}): {e}")))?;
        let tree = obj.try_into_tree().map_err(|e| {
            MainMergeError::FetchFailed(format!("object {tree_oid} is not a tree: {e}"))
        })?;
        let decoded = tree
            .decode()
            .map_err(|e| MainMergeError::FetchFailed(format!("decode tree {tree_oid}: {e}")))?;
        for entry in decoded.entries.iter() {
            let oid: gix::ObjectId = entry.oid.into();
            match entry.mode.kind() {
                EntryKind::Tree => trees.push_back(oid),
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                    blobs.push_back(oid)
                }
                EntryKind::Commit => {
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
        let obj = src
            .find_object(blob_oid)
            .map_err(|e| MainMergeError::FetchFailed(format!("find_object({blob_oid}): {e}")))?;
        write_object_bytes(dst, obj.data.as_slice(), gix::object::Kind::Blob)?;
    }

    Ok(())
}

/// Write a raw object payload into `dst`'s ODB. Uses
/// `Repository::write_blob` for blobs (the most common case) to
/// minimise allocations, and the generic `write_buf` shim for
/// commits and trees. All three are dedup-by-hash.
fn write_object_bytes(
    dst: &gix::Repository,
    body: &[u8],
    kind: gix::object::Kind,
) -> Result<(), MainMergeError> {
    use gix::object::Kind;
    match kind {
        Kind::Blob => {
            dst.write_blob(body)
                .map_err(|e| MainMergeError::FetchFailed(format!("write_blob: {e}")))?;
        }
        _ => {
            use gix::prelude::Write as _;
            dst.objects
                .write_buf(kind, body)
                .map_err(|e| MainMergeError::FetchFailed(format!("write_buf: {e}")))?;
        }
    }
    Ok(())
}

/// Atomically advance `target_ref` to `oid` via a `gix-ref`
/// transaction. Used by [`commit_merge_to_target_ref`] but also
/// exposed for tests that want to drive the ref update in isolation.
/// `expected_previous` is the value the kernel believes the target
/// ref points at right now; if `Some`, the transaction's precondition
/// requires the on-disk ref to equal that value (so a concurrent
/// writer's update is detected and the transaction aborts). If
/// `None`, the transaction is unconstrained — the target ref must
/// not exist yet (an initial-commit pinning).
/// `target_ref` MUST be a fully-qualified ref name (e.g.,
/// `"refs/heads/main"`, `"refs/heads/raxis/auth-refactor"`). The
/// caller resolves the per-initiative override + policy default per
/// ; this function performs no resolution.
pub fn update_target_ref(
    repo: &gix::Repository,
    oid: &gix::ObjectId,
    expected_previous: Option<&gix::ObjectId>,
    target_ref: &str,
) -> Result<(), MainMergeError> {
    use gix::bstr::ByteSlice;
    use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
    use gix::refs::{FullName, Target};

    let full_name = FullName::try_from(target_ref).map_err(|e| {
        MainMergeError::RefUpdateFailed(format!("FullName::try_from({target_ref:?}): {e}"))
    })?;

    let previous = match expected_previous {
        Some(prev) => PreviousValue::MustExistAndMatch(Target::Object(*prev)),
        None => PreviousValue::MustNotExist,
    };

    let edit = RefEdit {
        change: Change::Update {
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: "raxis: IntegrationMerge advance".into(),
            },
            expected: previous,
            new: Target::Object(*oid),
        },
        name: full_name,
        deref: false,
    };

    let committer = gix::actor::SignatureRef {
        name: b"raxis-kernel".as_bstr(),
        email: b"raxis-kernel@localhost".as_bstr(),
        time: "0 +0000",
    };

    repo.edit_references_as(std::iter::once(edit), Some(committer))
        .map_err(|e| MainMergeError::RefUpdateFailed(format!("edit_reference: {e}")))?;
    Ok(())
}

fn refresh_checked_out_worktree(
    main_repo_root: &Path,
    oid: &gix::ObjectId,
    target_ref: &str,
) -> Result<(), MainMergeError> {
    let head_ref = std::process::Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .current_dir(main_repo_root)
        .output()
        .map_err(|e| MainMergeError::WorktreeRefreshFailed {
            path: main_repo_root.to_path_buf(),
            reason: format!("git symbolic-ref spawn failed: {e}"),
        })?;
    if !head_ref.status.success() {
        return Ok(());
    }
    let checked_out_ref = String::from_utf8_lossy(&head_ref.stdout).trim().to_owned();
    if checked_out_ref != target_ref {
        return Ok(());
    }

    let oid_s = oid.to_string();
    let reset = std::process::Command::new("git")
        .args(["reset", "--hard", oid_s.as_str()])
        .current_dir(main_repo_root)
        .output()
        .map_err(|e| MainMergeError::WorktreeRefreshFailed {
            path: main_repo_root.to_path_buf(),
            reason: format!("git reset --hard spawn failed: {e}"),
        })?;
    if !reset.status.success() {
        return Err(MainMergeError::WorktreeRefreshFailed {
            path: main_repo_root.to_path_buf(),
            reason: format!(
                "git reset --hard exited {:?}: {}",
                reset.status.code(),
                String::from_utf8_lossy(&reset.stderr)
            ),
        });
    }
    Ok(())
}

fn candidate_fast_forwards_target(
    main_repo_root: &Path,
    previous: &gix::ObjectId,
    candidate: &gix::ObjectId,
) -> Result<bool, MainMergeError> {
    if previous == candidate {
        return Ok(true);
    }

    let previous_sha = previous.to_string();
    let candidate_sha = candidate.to_string();
    let status = std::process::Command::new("git")
        .args([
            "merge-base",
            "--is-ancestor",
            previous_sha.as_str(),
            candidate_sha.as_str(),
        ])
        .current_dir(main_repo_root)
        .status()
        .map_err(|e| {
            MainMergeError::RefUpdateFailed(format!("git merge-base spawn failed: {e}"))
        })?;

    if status.success() {
        return Ok(true);
    }
    if status.code() == Some(1) {
        return Ok(false);
    }

    Err(MainMergeError::RefUpdateFailed(format!(
        "git merge-base --is-ancestor exited with {status}"
    )))
}

fn synthesize_concurrent_target_merge(
    main_repo_root: &Path,
    previous: &gix::ObjectId,
    candidate: &gix::ObjectId,
    target_ref: &str,
) -> Result<gix::ObjectId, MainMergeError> {
    let previous_sha = previous.to_string();
    let candidate_sha = candidate.to_string();
    let temp_dir = unique_merge_worktree_path(main_repo_root);

    let add = std::process::Command::new("git")
        .args([
            "worktree",
            "add",
            "--detach",
            "--quiet",
            temp_dir.to_string_lossy().as_ref(),
            previous_sha.as_str(),
        ])
        .current_dir(main_repo_root)
        .output()
        .map_err(|e| MainMergeError::RefUpdateFailed(format!("git worktree add: {e}")))?;
    if !add.status.success() {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(MainMergeError::RefUpdateFailed(format!(
            "git worktree add exited {:?}: {}{}",
            add.status.code(),
            String::from_utf8_lossy(&add.stdout),
            String::from_utf8_lossy(&add.stderr)
        )));
    }

    let merge_date = commit_committer_date(main_repo_root, &candidate_sha)
        .unwrap_or_else(|| "1970-01-01T00:00:00+00:00".to_owned());
    let mut merge = std::process::Command::new("git");
    merge
        .args([
            "merge",
            "--no-ff",
            "--no-gpg-sign",
            "-m",
            "raxis: preserve concurrent target-ref advancement",
            candidate_sha.as_str(),
        ])
        .current_dir(&temp_dir)
        .env("GIT_AUTHOR_NAME", "RAXIS Kernel")
        .env("GIT_AUTHOR_EMAIL", "kernel@raxis.local")
        .env("GIT_COMMITTER_NAME", "RAXIS Kernel")
        .env("GIT_COMMITTER_EMAIL", "kernel@raxis.local")
        .env("GIT_AUTHOR_DATE", merge_date.as_str())
        .env("GIT_COMMITTER_DATE", merge_date.as_str());
    let merge = merge
        .output()
        .map_err(|e| MainMergeError::RefUpdateFailed(format!("git merge spawn failed: {e}")))?;
    if !merge.status.success() {
        // Preserve the conflicted worktree for operator recovery. Older
        // builds aborted and deleted it, leaving only stdout/stderr in the
        // audit row. For a recoverable concurrent merge failure, the exact
        // conflicted tree is the useful artifact: dashboard/CLI surfaces can
        // point the operator at it and a future conflict editor can open it.
        return Err(MainMergeError::ConcurrentMergeFailed {
            target_ref: target_ref.to_owned(),
            previous_sha,
            candidate_sha,
            reason: format!(
                "git merge exited {:?}; conflict_worktree={}: {}{}",
                merge.status.code(),
                temp_dir.display(),
                String::from_utf8_lossy(&merge.stdout),
                String::from_utf8_lossy(&merge.stderr)
            ),
        });
    }

    let rev = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&temp_dir)
        .output()
        .map_err(|e| MainMergeError::RefUpdateFailed(format!("git rev-parse spawn failed: {e}")))?;
    if !rev.status.success() {
        cleanup_merge_worktree(main_repo_root, &temp_dir);
        return Err(MainMergeError::RefUpdateFailed(format!(
            "git rev-parse HEAD exited {:?}: {}{}",
            rev.status.code(),
            String::from_utf8_lossy(&rev.stdout),
            String::from_utf8_lossy(&rev.stderr)
        )));
    }
    let merge_sha = String::from_utf8_lossy(&rev.stdout).trim().to_owned();
    cleanup_merge_worktree(main_repo_root, &temp_dir);
    parse_oid(&merge_sha)
}

fn unique_merge_worktree_path(main_repo_root: &Path) -> PathBuf {
    let parent = main_repo_root.parent().unwrap_or(main_repo_root);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    parent.join(format!(
        ".raxis-domain-git-merge-{}-{nanos}",
        std::process::id()
    ))
}

fn commit_committer_date(main_repo_root: &Path, sha: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["show", "-s", "--format=%cI", sha])
        .current_dir(main_repo_root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn cleanup_merge_worktree(main_repo_root: &Path, temp_dir: &Path) {
    let remove = std::process::Command::new("git")
        .args([
            "worktree",
            "remove",
            "--force",
            temp_dir.to_string_lossy().as_ref(),
        ])
        .current_dir(main_repo_root)
        .output();
    if let Ok(out) = remove {
        if out.status.success() {
            return;
        }
    }
    let _ = std::fs::remove_dir_all(temp_dir);
}

/// Read the current SHA `target_ref` points at in the repository
/// rooted at `main_repo_root`. Returns `Ok(None)` when the ref does
/// not exist (the repo has no tip for this ref yet — common on
/// first merge). Errors only when the repo itself cannot be opened.
/// Used by `recovery::reconcile_git_apply_pending` (Cases A vs B
/// dispatch in `integration-merge.md §11.3`): the recovery
/// procedure compares the recorded `db_sha` (from the most recent
/// `IntegrationMergeCompleted` audit event) against this value to
/// decide whether Phase 2 was missed (Case A) or only Phase 3 was
/// missed (Case B).
pub fn current_target_ref_oid(
    main_repo_root: &Path,
    target_ref: &str,
) -> Result<Option<String>, MainMergeError> {
    let repo = open_main(main_repo_root)?;
    match current_ref_oid(&repo, target_ref) {
        Ok(oid) => Ok(Some(oid.to_string())),
        Err(_) => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn open_main(path: &Path) -> Result<gix::Repository, MainMergeError> {
    gix::open(path).map_err(|e| MainMergeError::MainRepoUnopenable {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

fn current_ref_oid(
    repo: &gix::Repository,
    target_ref: &str,
) -> Result<gix::ObjectId, MainMergeError> {
    let r = repo.find_reference(target_ref).map_err(|e| {
        MainMergeError::RefUpdateFailed(format!("find_reference({target_ref:?}): {e}"))
    })?;
    r.target().try_id().map(|id| id.to_owned()).ok_or_else(|| {
        MainMergeError::RefUpdateFailed(format!("{target_ref} is symbolic, expected direct"))
    })
}

fn parse_oid(sha: &str) -> Result<gix::ObjectId, MainMergeError> {
    gix::ObjectId::from_hex(sha.as_bytes()).map_err(|e| MainMergeError::InvalidSha {
        sha: sha.to_owned(),
        reason: e.to_string(),
    })
}

// ---------------------------------------------------------------------------
// kernel push protocol (minimum-viable)
// ---------------------------------------------------------------------------

/// Format an `Option<i32>` exit code as a human-readable string.
/// `Some(128)` → `"128"`, `None` → `"<signalled>"`.
fn display_exit_code(code: Option<i32>) -> String {
    code.map(|c| c.to_string())
        .unwrap_or_else(|| "<signalled>".to_owned())
}

/// Outcome of a successful [`push_to_remote`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// The remote name pushed to (e.g. `"origin"`).
    pub remote: String,
    /// The refspec used (e.g. `"refs/heads/main:refs/heads/main"`).
    pub refspec: String,
    /// First-line summary of the push, captured from `git push`'s
    /// stderr. Useful for the audit-record `transport_id` slot.
    pub summary: String,
}

/// Errors specific to the `push_to_remote` operation.
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    /// The main repo could not be opened (path missing, not a git
    /// repo, etc.).
    #[error("push: main repo {path} unopenable: {reason}")]
    MainRepoUnopenable {
        /// Repository path the kernel asked to push from.
        path: PathBuf,
        /// Underlying error.
        reason: String,
    },
    /// `git push` exited non-zero. The stderr is captured verbatim
    /// for the audit-record `failure_reason` slot.
    #[error("push: `git push {remote} {refspec}` exited {}: {stderr}", display_exit_code(*.code))]
    PushFailed {
        /// Remote name.
        remote: String,
        /// Refspec.
        refspec: String,
        /// Exit code from `git push`.
        code: Option<i32>,
        /// Captured stderr (truncated at 4 KiB to keep audit rows
        /// bounded).
        stderr: String,
    },
    /// `git push` could not be spawned (PATH / permission issue).
    #[error("push: `git push` spawn failed: {0}")]
    SpawnFailed(String),
    /// `git push` exceeded the wall-clock deadline.
    #[error("push: deadline exceeded after {0:?}")]
    DeadlineExceeded(std::time::Duration),
}

/// Push the current `target_ref` of `main_repo_root` to a configured
/// remote, using the operator's local git credential helpers / SSH
/// config (the kernel does NOT inject credentials directly — the
/// V2 push uses whatever auth the host has wired into git, which
/// is the operator-grade outcome and matches `integration-merge.md
/// §14`'s "git push origin main" wire shape).
/// `deadline` bounds the subprocess so a hung push (network outage,
/// auth prompt) cannot wedge the kernel commit path.
/// Returns [`PushOutcome`] on push success; the caller is
/// responsible for emitting the matching `PushCompleted` audit
/// event. Any non-zero exit surfaces as
/// [`PushError::PushFailed`] and the caller emits `PushFailed`.
pub fn push_to_remote(
    main_repo_root: &Path,
    remote: &str,
    refspec: &str,
    deadline: std::time::Duration,
) -> Result<PushOutcome, PushError> {
    if !main_repo_root.exists() {
        return Err(PushError::MainRepoUnopenable {
            path: main_repo_root.to_path_buf(),
            reason: "path does not exist".to_owned(),
        });
    }
    let mut cmd = std::process::Command::new("git");
    cmd.arg("-C")
        .arg(main_repo_root)
        .arg("push")
        .arg(remote)
        .arg(refspec)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Bound the subprocess by spawning + polling. Avoids the
    // platform-specific timeout APIs `Command` doesn't ship with.
    let started = std::time::Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| PushError::SpawnFailed(e.to_string()))?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut s) = child.stdout.take() {
                    use std::io::Read;
                    let _ = s.read_to_string(&mut stdout);
                }
                if let Some(mut s) = child.stderr.take() {
                    use std::io::Read;
                    let _ = s.read_to_string(&mut stderr);
                }
                const CAP: usize = 4096;
                let stderr = if stderr.len() > CAP {
                    let mut t = stderr[..CAP].to_owned();
                    t.push_str(&format!("\n... <truncated {} bytes>", stderr.len() - CAP));
                    t
                } else {
                    stderr
                };
                if status.success() {
                    let summary = stderr.lines().next().unwrap_or(&stdout).to_owned();
                    return Ok(PushOutcome {
                        remote: remote.to_owned(),
                        refspec: refspec.to_owned(),
                        summary,
                    });
                }
                return Err(PushError::PushFailed {
                    remote: remote.to_owned(),
                    refspec: refspec.to_owned(),
                    code: status.code(),
                    stderr,
                });
            }
            Ok(None) => {
                if started.elapsed() > deadline {
                    let _ = child.kill();
                    return Err(PushError::DeadlineExceeded(deadline));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(PushError::SpawnFailed(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — exercise main-advancement against real gix repositories.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Set up two repositories: a main repo (initially containing
    /// one commit at `base_sha`) and an "orchestrator" worktree
    /// containing two commits (`base_sha` and `merge_sha`). The
    /// orchestrator worktree was cloned from the main repo, then
    /// advanced.
    fn fixture_main_and_orchestrator(tmp: &Path) -> Option<(PathBuf, PathBuf, String, String)> {
        if Command::new("git").arg("--version").output().is_err() {
            return None;
        }
        let main = tmp.join("main");
        std::fs::create_dir_all(&main).ok()?;
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
        run(&["init", "-q"], &main);
        run(&["symbolic-ref", "HEAD", "refs/heads/main"], &main);
        run(&["config", "user.name", "RAXIS Test"], &main);
        run(&["config", "user.email", "test@raxis.local"], &main);
        run(&["config", "commit.gpgsign", "false"], &main);
        std::fs::write(main.join("README.md"), "v1\n").ok()?;
        run(&["add", "README.md"], &main);
        run(&["commit", "-q", "-m", "initial"], &main);
        let base = String::from_utf8(run(&["rev-parse", "HEAD"], &main).stdout)
            .ok()?
            .trim()
            .to_owned();

        // Now mint an "orchestrator worktree" by cloning main
        // and advancing it by one more commit.
        let orch = tmp.join("orchestrator.work");
        run(&["clone", "-q", main.to_str()?, orch.to_str()?], tmp);
        run(&["config", "user.name", "RAXIS Test"], &orch);
        run(&["config", "user.email", "test@raxis.local"], &orch);
        run(&["config", "commit.gpgsign", "false"], &orch);
        std::fs::write(orch.join("README.md"), "v1\nv2\n").ok()?;
        run(&["add", "README.md"], &orch);
        run(&["commit", "-q", "-m", "merge: add v2"], &orch);
        let merge_sha = String::from_utf8(run(&["rev-parse", "HEAD"], &orch).stdout)
            .ok()?
            .trim()
            .to_owned();

        Some((main, orch, base, merge_sha))
    }

    #[test]
    fn commit_merge_to_main_fast_forwards_main_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((main, orch, base, merge)) = fixture_main_and_orchestrator(tmp.path()) else {
            eprintln!("skipping: git CLI not available");
            return;
        };

        let advance = commit_merge_to_main(&main, &orch, &merge).unwrap();
        assert_eq!(advance.previous_sha.as_deref(), Some(base.as_str()));
        assert_eq!(advance.current_sha, merge);
        assert!(!advance.already_at_target);

        // main must now point at merge.
        let head = String::from_utf8(
            std::process::Command::new("git")
                .args(["rev-parse", "refs/heads/main"])
                .current_dir(&main)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        assert_eq!(head, merge, "main must fast-forward to the merge commit");
        let readme = std::fs::read_to_string(main.join("README.md")).unwrap();
        assert_eq!(
            readme, "v1\nv2\n",
            "checked-out main worktree must reflect the fast-forwarded commit"
        );
        let status = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&main)
            .output()
            .unwrap();
        assert!(
            status.stdout.is_empty(),
            "checked-out main worktree must stay clean after fast-forward, got {}",
            String::from_utf8_lossy(&status.stdout)
        );
    }

    #[test]
    fn commit_merge_to_main_is_idempotent_on_replay() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((main, orch, base, merge)) = fixture_main_and_orchestrator(tmp.path()) else {
            eprintln!("skipping: git CLI not available");
            return;
        };

        let first = commit_merge_to_main(&main, &orch, &merge).unwrap();
        assert!(!first.already_at_target);
        std::fs::write(main.join("README.md"), "local-drift\n").unwrap();

        // Re-run — idempotency guard: returns already_at_target.
        let second = commit_merge_to_main(&main, &orch, &merge).unwrap();
        assert!(
            second.already_at_target,
            "second commit_merge_to_main must be a no-op when main \
             is already at the target SHA (Check 8 Phase 2 idempotency)"
        );
        assert_eq!(second.previous_sha.as_deref(), Some(merge.as_str()));
        assert_eq!(second.current_sha, merge);
        let readme = std::fs::read_to_string(main.join("README.md")).unwrap();
        assert_eq!(
            readme, "v1\nv2\n",
            "idempotent replay must also heal a stale checked-out worktree"
        );
        let _ = base;
    }

    #[test]
    fn commit_merge_to_main_preserves_concurrent_target_ref_advance() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((main, orch, _base, stale_merge)) = fixture_main_and_orchestrator(tmp.path())
        else {
            eprintln!("skipping: git CLI not available");
            return;
        };

        let run = |args: &[&str], cwd: &Path| {
            let s = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_AUTHOR_NAME", "RAXIS Test")
                .env("GIT_AUTHOR_EMAIL", "test@raxis.local")
                .env("GIT_COMMITTER_NAME", "RAXIS Test")
                .env("GIT_COMMITTER_EMAIL", "test@raxis.local")
                .env("GIT_AUTHOR_DATE", "1700000001 +0000")
                .env("GIT_COMMITTER_DATE", "1700000001 +0000")
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

        std::fs::write(main.join("HOTFIX.md"), "already landed\n").unwrap();
        run(&["add", "HOTFIX.md"], &main);
        run(&["commit", "-q", "-m", "main: independent hotfix"], &main);
        let live_tip = String::from_utf8(run(&["rev-parse", "HEAD"], &main).stdout)
            .unwrap()
            .trim()
            .to_owned();

        let advance = commit_merge_to_main(&main, &orch, &stale_merge).unwrap();
        assert_eq!(advance.previous_sha.as_deref(), Some(live_tip.as_str()));
        assert_ne!(
            advance.current_sha, stale_merge,
            "a stale but conflict-free candidate should publish a new \
             host-side merge commit that preserves the live target tip"
        );

        let head = String::from_utf8(run(&["rev-parse", "HEAD"], &main).stdout)
            .unwrap()
            .trim()
            .to_owned();
        assert_eq!(head, advance.current_sha, "target ref must advance");
        run(
            &[
                "merge-base",
                "--is-ancestor",
                live_tip.as_str(),
                head.as_str(),
            ],
            &main,
        );
        run(
            &[
                "merge-base",
                "--is-ancestor",
                stale_merge.as_str(),
                head.as_str(),
            ],
            &main,
        );
        let readme = std::fs::read_to_string(main.join("README.md")).unwrap();
        assert_eq!(readme, "v1\nv2\n");
        let hotfix = std::fs::read_to_string(main.join("HOTFIX.md")).unwrap();
        assert_eq!(hotfix, "already landed\n");
    }

    #[test]
    fn commit_merge_to_main_fails_closed_on_concurrent_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((main, orch, _base, stale_merge)) = fixture_main_and_orchestrator(tmp.path())
        else {
            eprintln!("skipping: git CLI not available");
            return;
        };

        let run = |args: &[&str], cwd: &Path| {
            let s = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_AUTHOR_NAME", "RAXIS Test")
                .env("GIT_AUTHOR_EMAIL", "test@raxis.local")
                .env("GIT_COMMITTER_NAME", "RAXIS Test")
                .env("GIT_COMMITTER_EMAIL", "test@raxis.local")
                .env("GIT_AUTHOR_DATE", "1700000002 +0000")
                .env("GIT_COMMITTER_DATE", "1700000002 +0000")
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

        std::fs::write(main.join("README.md"), "v1\nconflicting-main\n").unwrap();
        run(&["add", "README.md"], &main);
        run(&["commit", "-q", "-m", "main: conflicting hotfix"], &main);
        let live_tip = String::from_utf8(run(&["rev-parse", "HEAD"], &main).stdout)
            .unwrap()
            .trim()
            .to_owned();

        let result = commit_merge_to_main(&main, &orch, &stale_merge);
        match result {
            Err(MainMergeError::ConcurrentMergeFailed {
                target_ref,
                previous_sha,
                candidate_sha,
                reason,
            }) => {
                assert_eq!(target_ref, "refs/heads/main");
                assert_eq!(previous_sha, live_tip);
                assert_eq!(candidate_sha, stale_merge);
                assert!(
                    reason.contains("CONFLICT") || reason.contains("conflict"),
                    "conflict diagnostic should mention the merge conflict: {reason}"
                );
                let conflict_worktree = reason
                    .split_once("conflict_worktree=")
                    .and_then(|(_, rest)| rest.split_once(": "))
                    .map(|(path, _)| path)
                    .expect("conflict diagnostic should preserve a recovery worktree path");
                assert!(
                    Path::new(conflict_worktree).exists(),
                    "conflict recovery worktree should be preserved: {conflict_worktree}"
                );
            }
            other => panic!("expected ConcurrentMergeFailed, got {other:?}"),
        }

        let head = String::from_utf8(run(&["rev-parse", "HEAD"], &main).stdout)
            .unwrap()
            .trim()
            .to_owned();
        assert_eq!(head, live_tip, "conflicting merge must not advance main");
    }

    #[test]
    fn commit_merge_to_main_fails_closed_on_bogus_sha() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((main, orch, _base, _merge)) = fixture_main_and_orchestrator(tmp.path()) else {
            eprintln!("skipping: git CLI not available");
            return;
        };

        let result = commit_merge_to_main(&main, &orch, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        match result {
            Err(MainMergeError::ShaMissingPostFetch { sha }) => {
                assert!(sha.starts_with("deadbeef"));
            }
            // PrepareFetch may surface this as a fetch error if the
            // refspec walk doesn't find the requested SHA in the
            // source repo.
            Err(MainMergeError::FetchFailed(_)) => {}
            other => panic!("expected ShaMissingPostFetch / FetchFailed, got {other:?}"),
        }
    }

    #[test]
    fn commit_merge_to_main_rejects_unopenable_main() {
        let tmp = tempfile::tempdir().unwrap();
        let nonexistent = tmp.path().join("never-existed");
        let orch = tmp.path().join("orch");
        std::fs::create_dir_all(&orch).unwrap();
        let result = commit_merge_to_main(
            &nonexistent,
            &orch,
            "0000000000000000000000000000000000000000",
        );
        match result {
            Err(MainMergeError::MainRepoUnopenable { .. }) => {}
            other => panic!("expected MainRepoUnopenable, got {other:?}"),
        }
    }

    #[test]
    fn commit_merge_to_main_copies_full_object_graph() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((main, orch, _base, _merge)) = fixture_main_and_orchestrator(tmp.path()) else {
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
                .output()
                .expect("git invocation")
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
            .unwrap()
            .trim()
            .to_owned();

        // Now run the main fast-forward. Every intermediate
        // commit, tree, and blob must land in main's ODB.
        let advance = commit_merge_to_main(&main, &orch, &final_sha).unwrap();
        assert_eq!(advance.current_sha, final_sha);

        // Verify the main ODB has every blob in the chain.
        let main_repo = gix::open(&main).unwrap();
        for entry in ["README.md", "a.txt", "b.txt"] {
            let body = std::fs::read(orch.join(entry)).unwrap();
            let blob_oid = gix::ObjectId::from_hex(
                String::from_utf8(run(&["hash-object", "--", entry], &orch).stdout)
                    .unwrap()
                    .trim()
                    .as_bytes(),
            )
            .unwrap();
            let copied = main_repo.find_object(blob_oid).unwrap();
            assert_eq!(
                copied.data.as_slice(),
                body.as_slice(),
                "blob for {entry} did not round-trip into main ODB",
            );
        }
    }

    /// `commit_merge_to_target_ref` must advance an arbitrary
    /// fully-qualified ref (here a PR-style
    /// `refs/heads/raxis/<initiative>` branch), not only
    /// `refs/heads/main`. This is the substrate for the PR-branch
    /// workflow described in the integration spec.
    #[test]
    fn commit_merge_to_target_ref_advances_pr_style_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((main, orch, base, merge)) = fixture_main_and_orchestrator(tmp.path()) else {
            eprintln!("skipping: git CLI not available");
            return;
        };

        // Pre-create the PR branch at base so the transaction has
        // an `expected_previous = Some(base_oid)` precondition to
        // satisfy. (Production: the kernel creates the branch at
        // `initial_sha` during `approve_plan` per // step 1.)
        let create_branch = std::process::Command::new("git")
            .args(["branch", "raxis/auth-refactor", base.as_str()])
            .current_dir(&main)
            .output()
            .expect("git branch");
        assert!(
            create_branch.status.success(),
            "pre-creating PR branch failed: {}",
            String::from_utf8_lossy(&create_branch.stderr)
        );

        let target_ref = "refs/heads/raxis/auth-refactor";
        let advance = commit_merge_to_target_ref(&main, &orch, &merge, target_ref).unwrap();
        assert_eq!(advance.previous_sha.as_deref(), Some(base.as_str()));
        assert_eq!(advance.current_sha, merge);
        assert!(!advance.already_at_target);

        // The PR branch must point at the merge commit.
        let head = String::from_utf8(
            std::process::Command::new("git")
                .args(["rev-parse", target_ref])
                .current_dir(&main)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        assert_eq!(head, merge);

        // refs/heads/main MUST NOT have moved — the PR-branch flow
        // is the spec's structural separation between RAXIS-merged
        // state and the team's SDLC-approved main branch.
        let main_head = String::from_utf8(
            std::process::Command::new("git")
                .args(["rev-parse", "refs/heads/main"])
                .current_dir(&main)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        assert_eq!(
            main_head, base,
            "refs/heads/main MUST NOT advance when the resolved \
             target_ref is a non-main PR branch"
        );
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
            MainMergeError::InvalidSha { sha, .. } => assert_eq!(sha, "nothex"),
            other => panic!("expected InvalidSha, got {other:?}"),
        }
    }

    // -------------------------------------------------------------
    // push_to_remote tests
    // -------------------------------------------------------------

    /// Build a fixture where `main` is the main repo and `bare` is
    /// a freshly-init'd bare repository acting as the upstream
    /// remote. The main repo has `bare` configured as `origin`.
    fn fixture_main_with_bare_remote(tmp: &Path) -> Option<(PathBuf, PathBuf)> {
        if Command::new("git").arg("--version").output().is_err() {
            return None;
        }
        let main = tmp.join("main");
        let bare = tmp.join("upstream.git");
        std::fs::create_dir_all(&main).ok()?;
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
                "git {args:?} in {} failed: {}",
                cwd.display(),
                String::from_utf8_lossy(&s.stderr),
            );
        };
        // Bare upstream.
        run(&["init", "-q", "--bare", bare.to_str()?], tmp);
        // Main repo with one commit.
        run(&["init", "-q"], &main);
        run(&["symbolic-ref", "HEAD", "refs/heads/main"], &main);
        run(&["config", "user.name", "RAXIS Test"], &main);
        run(&["config", "user.email", "test@raxis.local"], &main);
        run(&["config", "commit.gpgsign", "false"], &main);
        std::fs::write(main.join("README.md"), "v1\n").ok()?;
        run(&["add", "README.md"], &main);
        run(&["commit", "-q", "-m", "initial"], &main);
        // Wire `origin → bare`.
        run(&["remote", "add", "origin", bare.to_str()?], &main);
        Some((main, bare))
    }

    #[test]
    fn push_to_remote_succeeds_against_local_bare() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((main, bare)) = fixture_main_with_bare_remote(tmp.path()) else {
            eprintln!("skipping: git CLI not available");
            return;
        };
        let outcome = push_to_remote(
            &main,
            "origin",
            "refs/heads/main:refs/heads/main",
            std::time::Duration::from_secs(30),
        )
        .expect("push must succeed against a fresh bare upstream");
        assert_eq!(outcome.remote, "origin");
        assert_eq!(outcome.refspec, "refs/heads/main:refs/heads/main");

        // Verify the bare repo now has the same SHA the main has.
        let main_head = String::from_utf8(
            std::process::Command::new("git")
                .args(["rev-parse", "refs/heads/main"])
                .current_dir(&main)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        let bare_head = String::from_utf8(
            std::process::Command::new("git")
                .args(["rev-parse", "refs/heads/main"])
                .current_dir(&bare)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        assert_eq!(
            main_head, bare_head,
            "bare upstream MUST now point at the main repo's HEAD"
        );
    }

    #[test]
    fn push_to_remote_returns_push_failed_for_unknown_remote() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((main, _bare)) = fixture_main_with_bare_remote(tmp.path()) else {
            eprintln!("skipping: git CLI not available");
            return;
        };
        // `nonexistent-remote` is not configured → `git push` fails.
        let err = push_to_remote(
            &main,
            "nonexistent-remote",
            "refs/heads/main:refs/heads/main",
            std::time::Duration::from_secs(15),
        )
        .unwrap_err();
        match err {
            PushError::PushFailed {
                remote,
                code,
                stderr,
                ..
            } => {
                assert_eq!(remote, "nonexistent-remote");
                assert!(
                    code.is_some(),
                    "git push to a missing remote must produce a numeric \
                     exit code, got: {code:?}"
                );
                assert!(
                    stderr.contains("nonexistent-remote")
                        || stderr.contains("does not appear to be a git repository"),
                    "stderr should mention the bad remote name; got: {stderr}",
                );
            }
            other => panic!("expected PushFailed, got {other:?}"),
        }
    }

    #[test]
    fn push_to_remote_unopenable_main_repo_surfaces_typed_error() {
        let nonexistent = Path::new("/nonexistent/raxis-push-test/main");
        let err = push_to_remote(
            nonexistent,
            "origin",
            "refs/heads/main:refs/heads/main",
            std::time::Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(matches!(err, PushError::MainRepoUnopenable { .. }));
    }
}
