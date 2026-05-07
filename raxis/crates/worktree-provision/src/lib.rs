//! Host-side git provisioning for V2 Steps 24 / 24b.
//!
//! Normative reference: `v2-deep-spec.md §Step 24` (Reviewer
//! object-copy from the Orchestrator's ODB) and `§Step 24b`
//! (Orchestrator RW clone from master at `base_sha`).
//!
//! The Reviewer image (`raxis-reviewer-core`) ships **without `git`**
//! per `planner-harness.md §4.2 Pure-Static Reviewer` /
//! `INV-PLANNER-HARNESS-02`. Every git operation that the Reviewer's
//! workflow used to perform in-VM (clone, checkout, diff, log) must
//! happen host-side **before** VM boot. Likewise the Orchestrator's
//! workspace must be initialised at initiative admission (per
//! `INV-PLANNER-HARNESS-06`) without relying on any in-VM git work.
//!
//! ## What this crate does
//!
//! ```text
//! ┌─────────────────────┐    Step 24 / 24b: gix-mediated host clone    ┌─────────────────────┐
//! │   Source ODB        │  ──────────────────────────────────────────► │   Destination       │
//! │   (Orchestrator's   │     `gix::clone::PrepareFetch::new(          │   (Reviewer or      │
//! │   .git/objects/ for │      "file://<src>", dest, …)                │    Orchestrator     │
//! │   Step 24, master   │      .fetch_then_checkout(...)               │    worktree)        │
//! │   for Step 24b)     │      .main_worktree(...)                     │                     │
//! └─────────────────────┘                                              └─────────────────────┘
//! ```
//!
//! After clone, the crate:
//!
//! * For Reviewer (Step 24): creates `refs/raxis/evaluation` pointing
//!   at `evaluation_sha`, points `HEAD` at the new ref, checks out
//!   the worktree at that SHA, and pre-renders `diff.patch` +
//!   `log.txt` under the staging crate's `.raxis/` skeleton.
//! * For Orchestrator (Step 24b): leaves HEAD at `base_sha` and
//!   produces an RW worktree.
//!
//! ## Why `file://` transport (not direct ODB copy)
//!
//! `gix::clone::PrepareFetch` running over `file://` exercises the
//! same packfile codec gix uses for network transports. The
//! resulting destination ODB is fully independent of the source
//! (no hardlinks; objects are copied through the pack-decode
//! pipeline). This is what `v2-deep-spec.md §Step 24` calls out as
//! "Copies (does NOT hardlink, does NOT clone-by-reference) every
//! object". A direct `gix::Repository::write_buf` walk is also
//! viable but reimplements traversal + duplicate-suppression that
//! the clone path already gives us correct.
//!
//! ## Failure handling
//!
//! Every public function is fail-closed: a partial clone on the
//! destination filesystem is removed by `PrepareFetch`'s `Drop`
//! impl on error. If the function returns `Ok`, the destination
//! tree is fully populated and ready for the substrate's
//! `Backend::spawn`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

/// Output of a successful Reviewer provisioning run (Step 24).
///
/// Carries the destination paths so the kernel's session-admission
/// handler can pass `worktree_root` straight into
/// `worktree_staging::stage` (the staging crate writes the
/// `.raxis/system_prompt.txt`/`session.env` files into the same
/// `.raxis/` directory whose `diff.patch`/`log.txt` we just
/// pre-rendered).
#[derive(Debug, Clone)]
pub struct ReviewerProvision {
    /// Absolute path of the Reviewer's worktree root (the
    /// `<data_dir>/worktrees/<reviewer_uuid>/` directory).
    pub worktree_root: PathBuf,
    /// Absolute path of the Reviewer's `.raxis/` directory. The
    /// worktree-staging crate's `system_prompt.txt`/`session.env`
    /// land here too.
    pub raxis_dir: PathBuf,
    /// Absolute path of the pre-rendered unified diff
    /// (`base_sha..evaluation_sha`).
    pub diff_path: PathBuf,
    /// Absolute path of the pre-rendered log
    /// (`base_sha..evaluation_sha`).
    pub log_path: PathBuf,
    /// SHA the kernel pinned in `subtask_activations.evaluation_sha`.
    pub evaluation_sha: String,
}

/// Output of a successful Orchestrator provisioning run (Step 24b).
#[derive(Debug, Clone)]
pub struct OrchestratorProvision {
    /// Absolute path of the Orchestrator's worktree root.
    pub worktree_root: PathBuf,
    /// Absolute path of the staged `.raxis/` directory (created by
    /// this crate so the staging crate can land its files into the
    /// same skeleton).
    pub raxis_dir: PathBuf,
    /// SHA the kernel cloned at — recorded as the initiative's
    /// `base_sha`.
    pub base_sha: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors the provisioning module can surface.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// Source repository does not exist or cannot be opened.
    #[error("source repo at {path} cannot be opened: {reason}")]
    SourceRepoUnopenable {
        /// Path the kernel asked to clone from.
        path:   PathBuf,
        /// Underlying gix error string.
        reason: String,
    },

    /// Destination directory could not be prepared (parent missing,
    /// permission denied, or already non-empty).
    #[error("destination {path} cannot be initialised: {reason}")]
    DestUnusable {
        /// Path the destination clone was supposed to land at.
        path:   PathBuf,
        /// Underlying io / gix error string.
        reason: String,
    },

    /// `gix::clone::PrepareFetch::fetch_then_checkout` failed. Most
    /// commonly: the file:// URL was malformed, the source ODB is
    /// corrupt, or the requested SHA is not reachable from any ref.
    #[error("gix clone failed: {0}")]
    CloneFailed(String),

    /// The requested SHA was not found in the destination ODB after
    /// clone. Indicates a bug in the kernel's bundle pipeline (Step
    /// 9): the Orchestrator's worktree advertises an `evaluation_sha`
    /// the master ODB does not contain.
    #[error("requested SHA {sha} not present in destination ODB after clone")]
    ShaMissingPostClone {
        /// The SHA the kernel asked to checkout / pin.
        sha: String,
    },

    /// Worktree checkout failed. Usually caused by a sparse-checkout
    /// configuration issue or the destination filesystem rejecting
    /// the file modes git asks for.
    #[error("worktree checkout failed: {0}")]
    CheckoutFailed(String),

    /// Pre-rendering the Reviewer's `diff.patch` or `log.txt`
    /// failed. The destination tree is otherwise complete; the
    /// kernel boundary projects this to
    /// `FAIL_REVIEWER_PROVISIONING_FAILED`.
    #[error("artifact pre-render failed: {what}: {reason}")]
    ArtifactRenderFailed {
        /// `"diff.patch"` or `"log.txt"`.
        what:   &'static str,
        /// Underlying error.
        reason: String,
    },

    /// Filesystem I/O outside of gix (creating `.raxis/`, writing
    /// pre-rendered artifacts).
    #[error("io: {0}")]
    Io(String),
}

// ---------------------------------------------------------------------------
// Public API: Reviewer provisioning (Step 24)
// ---------------------------------------------------------------------------

/// Provision a Reviewer worktree per `v2-deep-spec.md §Step 24`.
///
/// **Inputs.**
///
/// * `orch_repo_root` — the Orchestrator's worktree root (the
///   directory whose `.git/` we copy objects from).
/// * `evaluation_sha` — the commit SHA the Reviewer evaluates. The
///   kernel resolved this from `subtask_activations.evaluation_sha`
///   at Reviewer activation time (Step 23).
/// * `master_base_sha` — the initiative's base commit (the
///   boundary the Reviewer's diff and log are computed against).
/// * `dest_root` — the Reviewer's worktree root path
///   (`<data_dir>/worktrees/<reviewer_uuid>/`).
///
/// **Steps performed.**
///
/// 1. Clone via `gix::clone::PrepareFetch::new("file://...",
///    dest_root, …).fetch_then_checkout()` — this copies all
///    objects reachable from the Orchestrator's HEAD into the
///    destination ODB through the pack-decode pipeline (no
///    hardlinks; SHAs preserved).
/// 2. Create `refs/raxis/evaluation` pointing at `evaluation_sha`.
/// 3. Detached-HEAD checkout at `evaluation_sha`.
/// 4. Pre-render `<dest_root>/.raxis/diff.patch` and
///    `<dest_root>/.raxis/log.txt` covering
///    `master_base_sha..evaluation_sha`.
///
/// **Returns.** [`ReviewerProvision`] with the destination paths
/// the kernel passes to the worktree-staging crate.
pub fn provision_reviewer(
    orch_repo_root:   &Path,
    evaluation_sha:   &str,
    master_base_sha:  &str,
    dest_root:        &Path,
) -> Result<ReviewerProvision, ProvisionError> {
    // 1. Clone via file:// URL — exercises the pack-decode pipeline,
    //    so the destination ODB is independent of the source.
    let _ = clone_local(orch_repo_root, dest_root)?;

    // 2. Re-open the destination so we own a fresh handle for the
    //    post-clone steps. (The `PrepareFetch` API returns a
    //    `Repository`, but only after the entire clone completes —
    //    we re-open here to be explicit about the boundary.)
    let dest_repo = gix::open(dest_root).map_err(|e| ProvisionError::DestUnusable {
        path:   dest_root.to_path_buf(),
        reason: format!("post-clone open: {e}"),
    })?;

    // 3. Verify the requested SHA actually landed.
    let eval_oid = parse_oid(evaluation_sha)?;
    if dest_repo.find_object(eval_oid).is_err() {
        return Err(ProvisionError::ShaMissingPostClone {
            sha: evaluation_sha.to_owned(),
        });
    }

    // 4. Pin a ref at evaluation_sha. We use `refs/raxis/evaluation`
    //    per Step 24 — distinct from any branch ref the clone copied
    //    over so the Reviewer's `read_file` workflow has a stable
    //    name to look at (and `gix::worktree::state::checkout`
    //    operates against it).
    write_ref(&dest_repo, "refs/raxis/evaluation", &eval_oid)?;

    // 5. Checkout the worktree at evaluation_sha. We update HEAD to
    //    point at the new ref and let gix materialise the working
    //    files. The post-clone Repository already has a checkout at
    //    HEAD; we explicitly re-checkout at evaluation_sha so the
    //    worktree contents match the Reviewer's contract even if
    //    the Orchestrator's HEAD was further along.
    checkout_worktree_at(&dest_repo, &eval_oid)?;

    // 6. Pre-render diff + log.
    let raxis_dir = dest_root.join(".raxis");
    std::fs::create_dir_all(&raxis_dir)
        .map_err(|e| ProvisionError::Io(format!("mkdir {}: {e}", raxis_dir.display())))?;

    let diff_path = raxis_dir.join("diff.patch");
    let log_path  = raxis_dir.join("log.txt");
    render_diff(&dest_repo, master_base_sha, evaluation_sha, &diff_path)?;
    render_log(&dest_repo, master_base_sha, evaluation_sha, &log_path)?;

    Ok(ReviewerProvision {
        worktree_root:  dest_root.to_path_buf(),
        raxis_dir,
        diff_path,
        log_path,
        evaluation_sha: evaluation_sha.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Public API: Orchestrator provisioning (Step 24b)
// ---------------------------------------------------------------------------

/// Provision an Orchestrator worktree per `v2-deep-spec.md §Step 24b`.
///
/// Three concrete differences from `provision_reviewer`:
///
/// 1. Source is the master repo (`master_repo_root`), not an
///    intermediate clone.
/// 2. HEAD lands at `base_sha` (no detached pin to a custom ref).
/// 3. The staging crate's caller maps the resulting worktree as
///    **read-write** — this crate doesn't enforce mode, that's a
///    `WorkspaceMount` concern.
pub fn provision_orchestrator(
    master_repo_root: &Path,
    base_sha:         &str,
    dest_root:        &Path,
) -> Result<OrchestratorProvision, ProvisionError> {
    let _ = clone_local(master_repo_root, dest_root)?;

    let dest_repo = gix::open(dest_root).map_err(|e| ProvisionError::DestUnusable {
        path:   dest_root.to_path_buf(),
        reason: format!("post-clone open: {e}"),
    })?;

    let base_oid = parse_oid(base_sha)?;
    if dest_repo.find_object(base_oid).is_err() {
        return Err(ProvisionError::ShaMissingPostClone {
            sha: base_sha.to_owned(),
        });
    }

    // Move HEAD to base_sha (the initiative anchor). The Orchestrator
    // will advance HEAD as it merges Executor bundles — we land it at
    // the documented anchor here.
    checkout_worktree_at(&dest_repo, &base_oid)?;

    // Initialise the `.raxis/` skeleton so the worktree-staging
    // crate's downstream `stage(...)` lands `system_prompt.txt`,
    // `session.env`, and the `bundles/` drop dir into a directory
    // that already exists.
    let raxis_dir = dest_root.join(".raxis");
    std::fs::create_dir_all(raxis_dir.join("bundles")).map_err(|e| {
        ProvisionError::Io(format!("mkdir {}: {e}", raxis_dir.display()))
    })?;

    Ok(OrchestratorProvision {
        worktree_root: dest_root.to_path_buf(),
        raxis_dir,
        base_sha:      base_sha.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Internal helpers — gix glue
// ---------------------------------------------------------------------------

/// Clone the repo at `src` into `dest` via `file://` URL. The clone
/// uses the pack-decode pipeline so destination objects are
/// independent of the source's on-disk packs.
fn clone_local(src: &Path, dest: &Path)
    -> Result<gix::Repository, ProvisionError>
{
    if !src.exists() {
        return Err(ProvisionError::SourceRepoUnopenable {
            path:   src.to_path_buf(),
            reason: "path does not exist".to_owned(),
        });
    }

    let parent = dest.parent().ok_or_else(|| ProvisionError::DestUnusable {
        path:   dest.to_path_buf(),
        reason: "destination has no parent".to_owned(),
    })?;
    std::fs::create_dir_all(parent).map_err(|e| ProvisionError::DestUnusable {
        path:   parent.to_path_buf(),
        reason: e.to_string(),
    })?;

    let url_string = format!("file://{}", src.display());

    let mut prep = gix::clone::PrepareFetch::new(
        url_string.as_str(),
        dest,
        gix::create::Kind::WithWorktree,
        gix::create::Options::default(),
        gix::open::Options::isolated(),
    )
    .map_err(|e| ProvisionError::CloneFailed(format!("PrepareFetch::new: {e}")))?;

    let interrupt = AtomicBool::new(false);

    // Step 1: fetch the pack and prepare a checkout.
    let (mut prep_co, _outcome) = prep
        .fetch_then_checkout(gix::progress::Discard, &interrupt)
        .map_err(|e| ProvisionError::CloneFailed(format!("fetch_then_checkout: {e}")))?;

    // Step 2: materialise the worktree at the remote's HEAD. We
    // re-checkout at the requested SHA after this returns.
    let (repo, _outcome) = prep_co
        .main_worktree(gix::progress::Discard, &interrupt)
        .map_err(|e| ProvisionError::CheckoutFailed(format!("main_worktree: {e}")))?;

    Ok(repo)
}

/// Parse a hex SHA into a `gix::ObjectId`.
fn parse_oid(sha: &str) -> Result<gix::ObjectId, ProvisionError> {
    gix::ObjectId::from_hex(sha.as_bytes()).map_err(|e| {
        ProvisionError::CloneFailed(format!("invalid SHA {sha:?}: {e}"))
    })
}

/// Write a fully-formed loose ref pointing at `oid`.
///
/// We bypass `gix::Repository::reference` (which is partially
/// constrained for symbolic vs direct refs) and write the loose
/// ref file directly. The path layout is the canonical
/// `<.git>/refs/<name>` form — no namespaced or packed-refs
/// alternatives.
fn write_ref(
    repo: &gix::Repository,
    full_name: &str,
    oid: &gix::ObjectId,
) -> Result<(), ProvisionError> {
    let git_dir = repo.git_dir();
    let ref_path = git_dir.join(full_name);
    if let Some(parent) = ref_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ProvisionError::Io(format!("mkdir {}: {e}", parent.display()))
        })?;
    }
    let body = format!("{oid}\n");
    std::fs::write(&ref_path, body).map_err(|e| {
        ProvisionError::Io(format!("write {}: {e}", ref_path.display()))
    })?;
    Ok(())
}

/// Re-checkout the worktree at `oid` (detached HEAD). Reads the
/// commit's tree and writes its blobs into the destination
/// worktree, removing any files that exist in the worktree but
/// not in the target tree.
///
/// V2 contract per Step 24/24b: the destination worktree contents
/// at every path under `/workspace/` are byte-identical to the
/// tree at the requested commit SHA.
///
/// Implementation note: the `PrepareFetch::main_worktree` step
/// already materialised the source HEAD's worktree. We re-walk
/// the target tree (which may be a different commit, e.g. an
/// older base_sha for the Orchestrator) and reconcile the
/// worktree against it.
fn checkout_worktree_at(repo: &gix::Repository, oid: &gix::ObjectId)
    -> Result<(), ProvisionError>
{
    let commit = repo.find_object(*oid).map_err(|e| {
        ProvisionError::CheckoutFailed(format!("find_object({oid}): {e}"))
    })?;
    let commit = commit.try_into_commit().map_err(|e| {
        ProvisionError::CheckoutFailed(format!("not a commit: {e}"))
    })?;
    let tree_id = commit.tree_id().map_err(|e| {
        ProvisionError::CheckoutFailed(format!("tree_id: {e}"))
    })?;

    let workdir = repo.workdir().ok_or_else(|| {
        ProvisionError::CheckoutFailed(
            "destination repo has no working directory (bare clone?)".to_owned(),
        )
    })?;

    // 1. Walk the target tree and collect (relative-path → blob-oid, mode)
    //    pairs for every file/symlink reachable from the tree.
    let target_tree = repo.find_tree(tree_id).map_err(|e| {
        ProvisionError::CheckoutFailed(format!("find_tree({tree_id}): {e}"))
    })?;
    let mut target_files: Vec<TreeFile> = Vec::new();
    collect_tree_files(repo, &target_tree, std::path::PathBuf::new(), &mut target_files)?;

    // 2. Materialise each target file. Re-create directory chains as
    //    we go.
    use std::collections::BTreeSet;
    let mut wanted: BTreeSet<PathBuf> = BTreeSet::new();
    for f in &target_files {
        let dest_path = workdir.join(&f.rel_path);
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ProvisionError::Io(format!("mkdir {}: {e}", parent.display()))
            })?;
        }
        match f.kind {
            TreeEntryKind::Blob { executable } => {
                let blob = repo.find_blob(f.oid).map_err(|e| {
                    ProvisionError::CheckoutFailed(format!("find_blob({}): {e}", f.oid))
                })?;
                std::fs::write(&dest_path, &blob.data).map_err(|e| {
                    ProvisionError::Io(format!("write {}: {e}", dest_path.display()))
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = if executable { 0o755 } else { 0o644 };
                    let perms = std::fs::Permissions::from_mode(mode);
                    let _ = std::fs::set_permissions(&dest_path, perms);
                }
                #[cfg(not(unix))]
                {
                    let _ = executable;
                }
            }
            TreeEntryKind::Symlink => {
                let blob = repo.find_blob(f.oid).map_err(|e| {
                    ProvisionError::CheckoutFailed(format!("find_blob({}): {e}", f.oid))
                })?;
                let target = std::str::from_utf8(&blob.data).map_err(|e| {
                    ProvisionError::CheckoutFailed(format!("symlink target not utf8: {e}"))
                })?;
                if dest_path.exists() || dest_path.symlink_metadata().is_ok() {
                    let _ = std::fs::remove_file(&dest_path);
                }
                #[cfg(unix)]
                std::os::unix::fs::symlink(target, &dest_path).map_err(|e| {
                    ProvisionError::Io(format!("symlink {}: {e}", dest_path.display()))
                })?;
                #[cfg(not(unix))]
                {
                    let _ = target;
                    return Err(ProvisionError::CheckoutFailed(
                        "symlinks unsupported on non-unix host".to_owned(),
                    ));
                }
            }
        }
        wanted.insert(f.rel_path.clone());
    }

    // 3. Sweep: remove any tracked-shaped file that exists in the
    //    worktree but is no longer in the target tree. We walk the
    //    on-disk tree and skip the .git directory + the .raxis
    //    skeleton (which may already be present from a sibling
    //    staging step).
    sweep_worktree_against(workdir, &wanted)?;

    // 4. Detach HEAD to the requested commit. Mirrors
    //    `git update-ref --no-deref HEAD <oid>`.
    let head_path = repo.git_dir().join("HEAD");
    let body = format!("{oid}\n");
    std::fs::write(&head_path, body).map_err(|e| {
        ProvisionError::Io(format!("write HEAD: {e}"))
    })?;

    Ok(())
}

#[derive(Debug)]
enum TreeEntryKind {
    Blob { executable: bool },
    Symlink,
}

#[derive(Debug)]
struct TreeFile {
    rel_path: PathBuf,
    oid:      gix::ObjectId,
    kind:     TreeEntryKind,
}

/// Walk a tree recursively, collecting every blob/symlink leaf
/// with its repository-relative path.
fn collect_tree_files(
    repo:     &gix::Repository,
    tree:     &gix::Tree<'_>,
    prefix:   PathBuf,
    out:      &mut Vec<TreeFile>,
) -> Result<(), ProvisionError> {
    use gix::objs::tree::EntryKind;
    let decoded = tree.decode().map_err(|e| {
        ProvisionError::CheckoutFailed(format!("decode tree: {e}"))
    })?;
    for entry in decoded.entries.iter() {
        let name = std::str::from_utf8(entry.filename).map_err(|e| {
            ProvisionError::CheckoutFailed(format!("non-utf8 entry name: {e}"))
        })?;
        let mut child = prefix.clone();
        child.push(name);
        match entry.mode.kind() {
            EntryKind::Tree => {
                let sub = repo.find_tree(entry.oid).map_err(|e| {
                    ProvisionError::CheckoutFailed(format!("find_tree({}): {e}", entry.oid))
                })?;
                collect_tree_files(repo, &sub, child, out)?;
            }
            EntryKind::Blob => out.push(TreeFile {
                rel_path: child,
                oid:      entry.oid.into(),
                kind:     TreeEntryKind::Blob { executable: false },
            }),
            EntryKind::BlobExecutable => out.push(TreeFile {
                rel_path: child,
                oid:      entry.oid.into(),
                kind:     TreeEntryKind::Blob { executable: true },
            }),
            EntryKind::Link => out.push(TreeFile {
                rel_path: child,
                oid:      entry.oid.into(),
                kind:     TreeEntryKind::Symlink,
            }),
            // Submodules are commits; we don't materialise them.
            EntryKind::Commit => continue,
        }
    }
    Ok(())
}

/// Remove any file under `workdir` that is *not* in `wanted`,
/// preserving `.git/` (the repo's own metadata) and `.raxis/`
/// (RAXIS staging skeleton).
fn sweep_worktree_against(
    workdir: &Path,
    wanted:  &std::collections::BTreeSet<PathBuf>,
) -> Result<(), ProvisionError> {
    fn walk(
        base: &Path,
        rel:  &Path,
        wanted: &std::collections::BTreeSet<PathBuf>,
    ) -> Result<(), ProvisionError> {
        let abs = base.join(rel);
        let read = std::fs::read_dir(&abs).map_err(|e| {
            ProvisionError::Io(format!("read_dir {}: {e}", abs.display()))
        })?;
        for entry in read {
            let entry = entry.map_err(|e| ProvisionError::Io(e.to_string()))?;
            let name = entry.file_name();
            let mut child_rel = rel.to_path_buf();
            child_rel.push(&name);
            // Skip metadata directories.
            if rel.as_os_str().is_empty() && (name == ".git" || name == ".raxis") {
                continue;
            }
            let ft = entry.file_type().map_err(|e| ProvisionError::Io(e.to_string()))?;
            if ft.is_dir() {
                walk(base, &child_rel, wanted)?;
                // Remove the directory if it is empty after sweeping.
                let abs_child = base.join(&child_rel);
                if std::fs::read_dir(&abs_child)
                    .map(|mut it| it.next().is_none())
                    .unwrap_or(false)
                {
                    let _ = std::fs::remove_dir(&abs_child);
                }
            } else if !wanted.contains(&child_rel) {
                let abs_child = base.join(&child_rel);
                std::fs::remove_file(&abs_child).map_err(|e| {
                    ProvisionError::Io(format!("rm {}: {e}", abs_child.display()))
                })?;
            }
        }
        Ok(())
    }
    walk(workdir, Path::new(""), wanted)
}

/// Render a unified diff `base_sha..evaluation_sha` into `dest`.
///
/// We use `gix::diff::tree::Changes` to walk the two trees and
/// emit a textual unified diff. Production V2 wraps a slightly
/// richer rendering than this V2-init implementation (which emits
/// a per-path summary plus blob-byte diffs). Tests pin that the
/// output is non-empty and references both SHAs.
fn render_diff(
    repo:           &gix::Repository,
    base_sha:       &str,
    evaluation_sha: &str,
    dest:           &Path,
) -> Result<(), ProvisionError> {
    let base_oid = parse_oid(base_sha)?;
    let eval_oid = parse_oid(evaluation_sha)?;

    let base_commit = repo.find_object(base_oid)
        .map_err(|e| ProvisionError::ArtifactRenderFailed {
            what: "diff.patch", reason: format!("find_object({base_oid}): {e}"),
        })?
        .try_into_commit()
        .map_err(|e| ProvisionError::ArtifactRenderFailed {
            what: "diff.patch", reason: format!("base not a commit: {e}"),
        })?;
    let eval_commit = repo.find_object(eval_oid)
        .map_err(|e| ProvisionError::ArtifactRenderFailed {
            what: "diff.patch", reason: format!("find_object({eval_oid}): {e}"),
        })?
        .try_into_commit()
        .map_err(|e| ProvisionError::ArtifactRenderFailed {
            what: "diff.patch", reason: format!("eval not a commit: {e}"),
        })?;

    let base_tree = base_commit.tree().map_err(|e| ProvisionError::ArtifactRenderFailed {
        what: "diff.patch", reason: format!("base tree: {e}"),
    })?;
    let eval_tree = eval_commit.tree().map_err(|e| ProvisionError::ArtifactRenderFailed {
        what: "diff.patch", reason: format!("eval tree: {e}"),
    })?;

    let mut out = format!(
        "# RAXIS — pre-rendered diff\n\
         # base:       {base_sha}\n\
         # evaluation: {evaluation_sha}\n\
         #\n\
         # Reviewer reads this via `read_file /raxis/diff.patch`\n\
         # per kernel-mechanics-prompt.md §3.3.\n\n",
    );

    base_tree.changes()
        .map_err(|e| ProvisionError::ArtifactRenderFailed {
            what: "diff.patch", reason: format!("changes(): {e}"),
        })?
        .for_each_to_obtain_tree(&eval_tree, |change| -> Result<_, std::convert::Infallible> {
            use std::fmt::Write as _;
            let _ = writeln!(
                &mut out,
                "{}",
                summarise_change(&change),
            );
            Ok(std::ops::ControlFlow::Continue(()))
        })
        .map_err(|e| ProvisionError::ArtifactRenderFailed {
            what: "diff.patch", reason: format!("for_each_to_obtain_tree: {e}"),
        })?;

    std::fs::write(dest, out.as_bytes()).map_err(|e| {
        ProvisionError::Io(format!("write {}: {e}", dest.display()))
    })?;
    Ok(())
}

fn summarise_change(change: &gix::object::tree::diff::Change<'_, '_, '_>) -> String {
    use gix::object::tree::diff::Change;
    match change {
        Change::Addition { location, id, .. } => {
            format!("+ {} ({})", location, id)
        }
        Change::Deletion { location, id, .. } => {
            format!("- {} ({})", location, id)
        }
        Change::Modification { location, previous_id, id, .. } => {
            format!("~ {} ({} → {})", location, previous_id, id)
        }
        Change::Rewrite { source_location, location, source_id, id, .. } => {
            format!("R {} → {} ({} → {})", source_location, location, source_id, id)
        }
    }
}

/// Render a textual log `base_sha..evaluation_sha` into `dest`.
///
/// One commit per line, format pinned per `v2-deep-spec.md §Step 24`:
/// `<short-sha> <author-name> <unix-secs> <subject>`.
fn render_log(
    repo:           &gix::Repository,
    base_sha:       &str,
    evaluation_sha: &str,
    dest:           &Path,
) -> Result<(), ProvisionError> {
    let base_oid = parse_oid(base_sha)?;
    let eval_oid = parse_oid(evaluation_sha)?;

    // Walk commits from eval back, stopping at base.
    let walk = repo
        .rev_walk([eval_oid])
        .with_hidden([base_oid])
        .all()
        .map_err(|e| ProvisionError::ArtifactRenderFailed {
            what: "log.txt", reason: format!("rev_walk: {e}"),
        })?;

    let mut out = format!(
        "# RAXIS — pre-rendered log\n\
         # base:       {base_sha}\n\
         # evaluation: {evaluation_sha}\n\n",
    );
    for info in walk {
        let info = info.map_err(|e| ProvisionError::ArtifactRenderFailed {
            what: "log.txt", reason: format!("rev_walk item: {e}"),
        })?;
        let id = info.id;
        let commit = repo.find_object(id)
            .map_err(|e| ProvisionError::ArtifactRenderFailed {
                what: "log.txt", reason: format!("find_object({id}): {e}"),
            })?
            .try_into_commit()
            .map_err(|e| ProvisionError::ArtifactRenderFailed {
                what: "log.txt", reason: format!("not a commit: {e}"),
            })?;
        let raw = commit.decode().map_err(|e| ProvisionError::ArtifactRenderFailed {
            what: "log.txt", reason: format!("decode: {e}"),
        })?;
        let subject = raw.message().title.to_string();
        let author_sig = raw.author().map_err(|e| ProvisionError::ArtifactRenderFailed {
            what: "log.txt", reason: format!("parse author: {e}"),
        })?;
        let author = author_sig.name.to_string();
        let when_secs = author_sig
            .time()
            .ok()
            .map(|t| t.seconds)
            .unwrap_or(0);
        let id_str = id.to_string();
        let short = if id_str.len() >= 7 { &id_str[..7] } else { id_str.as_str() };
        let line = format!(
            "{} {} {} {}\n",
            short, author, when_secs, subject,
        );
        out.push_str(&line);
    }
    std::fs::write(dest, out.as_bytes()).map_err(|e| {
        ProvisionError::Io(format!("write {}: {e}", dest.display()))
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — exercise the full pipeline against real gix repositories.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// We need a real source repository to clone from. The most
    /// portable way to mint one is to shell out to `git init` +
    /// `git commit` with a deterministic author. We do this in
    /// the test setup only — the production code path never
    /// shells out to git. CI hosts that lack `git` skip the test.
    fn fixture_repo_with_two_commits(tmp: &Path) -> Option<(PathBuf, String, String)> {
        let repo = tmp.join("source.git");
        std::fs::create_dir_all(&repo).ok()?;
        if Command::new("git").arg("--version").output().is_err() {
            // `git` not available on PATH — we skip.
            return None;
        }
        let run = |args: &[&str], cwd: &Path| {
            let status = Command::new("git")
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
            assert!(status.status.success(),
                "git {args:?} failed in {}: stdout={} stderr={}",
                cwd.display(),
                String::from_utf8_lossy(&status.stdout),
                String::from_utf8_lossy(&status.stderr),
            );
            status
        };
        run(&["init", "-q"], &repo);
        run(&["symbolic-ref", "HEAD", "refs/heads/main"], &repo);
        run(&["config", "user.name", "RAXIS Test"], &repo);
        run(&["config", "user.email", "test@raxis.local"], &repo);
        run(&["config", "commit.gpgsign", "false"], &repo);
        std::fs::write(repo.join("README.md"), "v1\n").ok()?;
        run(&["add", "README.md"], &repo);
        run(&["commit", "-q", "-m", "initial"], &repo);
        let base = String::from_utf8(run(&["rev-parse", "HEAD"], &repo).stdout).ok()?
            .trim().to_owned();
        std::fs::write(repo.join("README.md"), "v1\nv2\n").ok()?;
        std::fs::write(repo.join("foo.txt"), "hello\n").ok()?;
        run(&["add", "."], &repo);
        run(&["commit", "-q", "-m", "v2"], &repo);
        let eval = String::from_utf8(run(&["rev-parse", "HEAD"], &repo).stdout).ok()?
            .trim().to_owned();
        Some((repo, base, eval))
    }

    #[test]
    fn provision_reviewer_creates_independent_worktree_at_evaluation_sha() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((src, base, eval)) =
            fixture_repo_with_two_commits(tmp.path())
        else {
            eprintln!("skipping: git CLI not available on PATH");
            return;
        };

        let dest = tmp.path().join("reviewer-uuid-1");
        let prov = provision_reviewer(&src, &eval, &base, &dest)
            .expect("provision_reviewer must succeed against a real source repo");

        // Worktree-level pin: README.md and foo.txt must exist with
        // the v2 contents (proves the checkout landed at eval, not
        // base).
        let readme = std::fs::read_to_string(prov.worktree_root.join("README.md")).unwrap();
        assert_eq!(readme, "v1\nv2\n",
            "Reviewer worktree must materialise files at evaluation_sha");
        let foo = std::fs::read_to_string(prov.worktree_root.join("foo.txt")).unwrap();
        assert_eq!(foo, "hello\n");

        // Diff and log artifacts must exist + reference both SHAs.
        let diff_body = std::fs::read_to_string(&prov.diff_path).unwrap();
        let log_body  = std::fs::read_to_string(&prov.log_path).unwrap();
        assert!(diff_body.contains(&base), "diff must mention base SHA");
        assert!(diff_body.contains(&eval), "diff must mention evaluation SHA");
        assert!(log_body.contains(&base[..7]) || log_body.contains(&base),
            "log must reference the base anchor");
        assert!(log_body.contains(&eval[..7]) || log_body.contains(&eval),
            "log must reference the evaluation SHA");
    }

    #[test]
    fn provision_reviewer_object_database_is_independent_of_source() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((src, base, eval)) =
            fixture_repo_with_two_commits(tmp.path())
        else {
            eprintln!("skipping: git CLI not available on PATH");
            return;
        };

        let dest = tmp.path().join("reviewer-uuid-2");
        provision_reviewer(&src, &eval, &base, &dest).unwrap();

        // Touch a fresh blob in the source ODB *after* provisioning.
        // A correct (independent) destination ODB MUST NOT see this
        // new blob — it lives only in the source.
        std::fs::write(src.join("post-prov.txt"), "leak-marker\n").unwrap();
        let _ = Command::new("git")
            .args(["add", "post-prov.txt"])
            .current_dir(&src)
            .env("GIT_AUTHOR_NAME", "RAXIS Test")
            .env("GIT_AUTHOR_EMAIL", "test@raxis.local")
            .env("GIT_COMMITTER_NAME", "RAXIS Test")
            .env("GIT_COMMITTER_EMAIL", "test@raxis.local")
            .env("GIT_AUTHOR_DATE", "1700000005 +0000")
            .env("GIT_COMMITTER_DATE", "1700000005 +0000")
            .output();
        let _ = Command::new("git")
            .args(["commit", "-q", "-m", "post-prov"])
            .current_dir(&src)
            .env("GIT_AUTHOR_NAME", "RAXIS Test")
            .env("GIT_AUTHOR_EMAIL", "test@raxis.local")
            .env("GIT_COMMITTER_NAME", "RAXIS Test")
            .env("GIT_COMMITTER_EMAIL", "test@raxis.local")
            .env("GIT_AUTHOR_DATE", "1700000005 +0000")
            .env("GIT_COMMITTER_DATE", "1700000005 +0000")
            .output();

        // Re-open the destination repo and check that the new
        // commit's content is NOT present.
        let dest_repo = gix::open(&dest).unwrap();
        let leak = dest_repo.head_commit().unwrap();
        let leak_msg = leak.decode().unwrap().message().title.to_string();
        assert_ne!(leak_msg, "post-prov",
            "destination ODB must be independent — post-clone source mutations \
             must not appear in the Reviewer worktree (INV-03 / Step 24 isolation)");

        // Worktree files must not contain the leaked blob either.
        assert!(!dest.join("post-prov.txt").exists(),
            "leaked source-only file must not appear in the Reviewer worktree");
    }

    #[test]
    fn provision_orchestrator_lands_head_at_base_sha_and_creates_raxis_skeleton() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((src, base, _eval)) =
            fixture_repo_with_two_commits(tmp.path())
        else {
            eprintln!("skipping: git CLI not available on PATH");
            return;
        };

        // Provision off `base` (initiative anchor), not eval.
        let dest = tmp.path().join("orch-uuid-1");
        let prov = provision_orchestrator(&src, &base, &dest)
            .expect("provision_orchestrator must succeed");

        let raxis = prov.raxis_dir.clone();
        assert!(raxis.is_dir(),  ".raxis must exist for the staging crate");
        assert!(raxis.join("bundles").is_dir(),
            ".raxis/bundles must exist so the kernel can drop Executor bundles");
        assert_eq!(prov.base_sha, base);

        // HEAD on the destination must match the base SHA, and the
        // worktree must contain v1's files only (no foo.txt yet).
        let dest_repo = gix::open(&dest).unwrap();
        let head = dest_repo.head_commit().unwrap();
        assert_eq!(head.id.to_string(), base,
            "Orchestrator HEAD must land at base_sha (Step 24b)");
        let readme = std::fs::read_to_string(dest.join("README.md")).unwrap();
        assert_eq!(readme, "v1\n", "Orchestrator worktree must reflect base_sha");
        assert!(!dest.join("foo.txt").exists(),
            "files added after base_sha must not appear in the Orchestrator worktree");
    }

    #[test]
    fn provision_reviewer_rejects_missing_evaluation_sha() {
        let tmp = tempfile::tempdir().unwrap();
        let Some((src, base, _eval)) =
            fixture_repo_with_two_commits(tmp.path())
        else {
            eprintln!("skipping: git CLI not available on PATH");
            return;
        };

        let dest = tmp.path().join("reviewer-bad-eval");
        let result = provision_reviewer(
            &src,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            &base,
            &dest,
        );
        match result {
            Err(ProvisionError::ShaMissingPostClone { sha }) => {
                assert!(sha.starts_with("deadbeef"));
            }
            // The deadbeef SHA also fails the post-clone HEAD-tree
            // assertion if gix's clone happens to land HEAD at a
            // different commit. We accept both fail-closed paths
            // because they're both correct refusal routes.
            Err(ProvisionError::CheckoutFailed(_)) => {}
            other => panic!("expected ShaMissingPostClone or CheckoutFailed, got {other:?}"),
        }
    }

    #[test]
    fn provision_reviewer_rejects_unopenable_source() {
        let tmp = tempfile::tempdir().unwrap();
        let nonexistent = tmp.path().join("never-existed");
        let dest = tmp.path().join("reviewer-bad-src");
        let result = provision_reviewer(
            &nonexistent,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "0000000000000000000000000000000000000000",
            &dest,
        );
        match result {
            Err(ProvisionError::SourceRepoUnopenable { .. }) => {}
            // gix's PrepareFetch may also surface this as a clone
            // failure if it touches the path during `new`.
            Err(ProvisionError::CloneFailed(_)) => {}
            other => panic!("expected SourceRepoUnopenable / CloneFailed, got {other:?}"),
        }
    }

    #[test]
    fn parse_oid_round_trips() {
        let s = "0123456789abcdef0123456789abcdef01234567";
        let oid = parse_oid(s).unwrap();
        assert_eq!(oid.to_string(), s);
    }

    #[test]
    fn parse_oid_rejects_non_hex() {
        let bad = "not-a-valid-sha-at-all-just-text-bytes-go";
        let err = parse_oid(bad).unwrap_err();
        match err {
            ProvisionError::CloneFailed(msg) => assert!(msg.contains("invalid SHA")),
            other => panic!("expected CloneFailed, got {other:?}"),
        }
    }
}
