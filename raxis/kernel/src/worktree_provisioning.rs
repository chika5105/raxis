// V2 §Step 24 / §Step 24b — kernel-side worktree provisioning seam.
//
// Composes the `raxis-worktree-provision` (host-side `gix` clone)
// and `raxis-domain-git` (host-side commit-closure copy) crates
// into the three role-specific operations the kernel's spawn /
// activation / completion handlers invoke:
//
//   * `provision_orchestrator_worktree` — admission-time clone of
//     `<data_dir>/repositories/<repository_id>` at the operator-configured
//     `target_ref`. The destination is keyed by `initiative_id`
//     (NOT session_id) so a respawned Orchestrator session
//     re-attaches to the existing worktree without re-cloning.
//
//   * `provision_executor_worktree` — activation-time clone of the
//     Orchestrator's worktree at the exact input base selected by
//     the DAG. Root executors start at the Orchestrator anchor;
//     successor executors start at their completed predecessor's
//     `evaluation_sha` so they observe the upstream bytes they are
//     supposed to consume. RW mount so the Executor can `git commit`
//     its work.
//
//   * `provision_reviewer_worktree` — activation-time clone of the
//     Orchestrator's worktree at `evaluation_sha` (the SHA the
//     predecessor Executor stamped on the task). RO mount per
//     `v2-deep-spec.md §Step 24` (the Reviewer must see exactly
//     the bytes the Executor committed).
//
//   * `copy_executor_commit_to_orchestrator_odb` — completion-time
//     pull of the Executor's terminal commit into the
//     Orchestrator's ODB so downstream Reviewers (and the
//     IntegrationMerge handler) can resolve the SHA. Wraps
//     `raxis_domain_git::fetch_into_main` whose semantics are
//     "copy commit closure from worktree A into repository B"
//     (the name is historical — it was first written for
//     orch→main).
//
// **Why a separate module instead of folding into
// `session_spawn_orchestrator.rs`.** The provisioning step has
// distinct failure modes (`ProvisionError::SourceRepoUnopenable`,
// `ShaMissingPostClone`, `CheckoutFailed`) that translate to a
// typed `PlannerErrorCode::FailWorktreeProvision`; folding
// the gix calls into the spawn path would entangle the
// substrate-failure surface with the git-failure surface and make
// the spawn-path tests harder to drive with a fake substrate.

use std::path::{Path, PathBuf};

use raxis_isolation::{ContentHash, MountMode, WorkspaceMount};
use raxis_types::CloneStrategy;
use raxis_worktree_provision::{provision_orchestrator, provision_reviewer, ProvisionError};
use raxis_worktree_staging::{GUEST_WORKSPACE_PATH, WORKTREES_DIR};

/// The sub-directory under `<data_dir>` we mint per-Orchestrator
/// worktrees into. Mirrors the pattern `worktree_root_path` uses
/// for executor / reviewer sessions, but with a `orch-<...>`
/// session-uuid namespace so an `ls worktrees/` clearly separates
/// per-initiative orchestrator anchors from per-task executor /
/// reviewer worktrees.
fn orchestrator_subdir(initiative_id: &str) -> String {
    // `initiative_id` is a v7 UUID per `raxis_types::InitiativeId`
    // — no path-traversal characters. We still prefix with
    // `orch-` so the directory is visually distinct from per-task
    // session UUIDs and so a future GC sweep can identify
    // orchestrator-anchored worktrees by a single fnmatch.
    format!("orch-{initiative_id}")
}

/// Absolute on-disk path of the per-initiative Orchestrator
/// worktree. Pure path math — does not touch the filesystem.
pub fn orchestrator_worktree_path(data_dir: &Path, initiative_id: &str) -> PathBuf {
    data_dir
        .join(WORKTREES_DIR)
        .join(orchestrator_subdir(initiative_id))
}

/// Outcome of a successful Orchestrator worktree provisioning
/// pass. Carries the three columns the kernel writes back into
/// `sessions` so subsequent activations can find the anchor
/// without re-resolving the SHA.
#[derive(Debug, Clone)]
pub struct OrchestratorAnchor {
    /// Absolute on-disk path of the Orchestrator's worktree. The
    /// kernel writes this verbatim into `sessions.worktree_root`
    /// for the Orchestrator session row, then again for each
    /// per-task session row's `worktree_root` column at
    /// activation time.
    pub worktree_root: PathBuf,
    /// SHA the Orchestrator's HEAD points at after the clone. The
    /// kernel writes this into `sessions.base_sha` and propagates
    /// it through the per-task session rows so
    /// `IntegrationMerge`'s ancestry check has a stable boundary.
    pub base_sha: String,
    /// Fully-qualified ref the operator declared in `[git]
    /// default_target_ref` (or the V2 default `refs/heads/main`).
    /// Persisted into `sessions.base_tracking_ref` so a future
    /// `git fetch` knows which branch to pull.
    pub base_tracking_ref: String,
}

/// Outcome of a successful Executor worktree provisioning pass.
#[derive(Debug, Clone)]
pub struct ExecutorWorkspace {
    /// The mount handed to the substrate.
    pub mount: WorkspaceMount,
    /// The commit the executor starts from. The kernel persists this
    /// on the session row as `base_sha`, and CompleteTask diffs are
    /// evaluated relative to it.
    pub input_base_sha: String,
}

/// Provision (or re-attach to) the per-initiative Orchestrator
/// worktree.
///
/// **Idempotent.** If `<data_dir>/worktrees/orch-<initiative_id>/`
/// already exists with a `.git/` directory, this function opens
/// it (no clone), reads `target_ref` to recover `base_sha`, and
/// returns the anchor. This is the respawn path: every
/// `respawn_orchestrator_after_terminal_completion` /
/// `respawn_orchestrator_after_*` call goes through here exactly
/// like the first-spawn approve_plan path.
///
/// **First-spawn.** When the destination directory does not
/// exist, this function:
///
///   1. Reads the operator-configured `target_ref` from
///      `<data_dir>/repositories/<repository_id>` and resolves it to a SHA.
///   2. Calls `raxis_worktree_provision::provision_orchestrator`
///      to clone `<data_dir>/repositories/<repository_id>` into the
///      destination at `base_sha`, full worktree (Sparse is
///      structurally refused per
///      `INV-PLANNER-HARNESS-06`-adjacent §Step 27 backstop).
///   3. Returns the anchor with the resolved `base_sha` and
///      operator-configured `base_tracking_ref`.
pub fn provision_orchestrator_worktree(
    data_dir: &Path,
    initiative_id: &str,
    repository_id: &str,
    target_ref: &str,
) -> Result<OrchestratorAnchor, ProvisionError> {
    if let Err(reason) = crate::managed_repositories::validate_repository_id(repository_id) {
        return Err(ProvisionError::SourceRepoUnopenable {
            path: crate::managed_repositories::managed_repository_path(data_dir, repository_id),
            reason: format!("invalid repository id {repository_id:?}: {reason}"),
        });
    }
    let main_repo = crate::managed_repositories::managed_repository_path(data_dir, repository_id);
    let dest = orchestrator_worktree_path(data_dir, initiative_id);

    // Idempotent re-attach: a respawned orchestrator points at
    // the same per-initiative worktree the previous session left
    // behind. We open the existing tree to recover the current
    // HEAD SHA — that's the value the new session row's
    // `base_sha` should carry so the §Step 24 invariant
    // ("Executors clone from the same anchor across respawns")
    // holds across orchestrator session boundaries.
    if dest.join(".git").exists() {
        let repo = gix::open(&dest).map_err(|e| ProvisionError::SourceRepoUnopenable {
            path: dest.clone(),
            reason: format!("re-attach open: {e}"),
        })?;
        // Use the current ref tip (whatever the orchestrator
        // last fetched / merged); on first-spawn this will equal
        // `target_ref`'s SHA, on respawn it will be the
        // most-recent merge commit.
        let head_id = repo
            .head_id()
            .map_err(|e| ProvisionError::SourceRepoUnopenable {
                path: dest.clone(),
                reason: format!("re-attach head: {e}"),
            })?;
        return Ok(OrchestratorAnchor {
            worktree_root: dest,
            base_sha: head_id.to_string(),
            base_tracking_ref: target_ref.to_owned(),
        });
    }

    // First-spawn: resolve the operator's `target_ref` to a SHA
    // by opening the source repo and peeling the ref. Any failure
    // here surfaces as `SourceRepoUnopenable` so the spawn handler
    // logs a structured diagnostic rather than panicking.
    let main_repo_handle =
        gix::open(&main_repo).map_err(|e| ProvisionError::SourceRepoUnopenable {
            path: main_repo.clone(),
            reason: format!("open: {e}"),
        })?;
    let mut reference = main_repo_handle
        .try_find_reference(target_ref)
        .map_err(|e| ProvisionError::SourceRepoUnopenable {
            path: main_repo.clone(),
            reason: format!("find_reference {target_ref:?}: {e}"),
        })?
        .ok_or_else(|| ProvisionError::SourceRepoUnopenable {
            path: main_repo.clone(),
            reason: format!(
                "operator-configured target_ref {target_ref:?} does not exist \
                 in {} — operator must populate the source repository before \
                 any plan is approved",
                main_repo.display(),
            ),
        })?;
    let base_sha = reference
        .peel_to_id()
        .map_err(|e| ProvisionError::SourceRepoUnopenable {
            path: main_repo.clone(),
            reason: format!("peel_to_id {target_ref:?}: {e}"),
        })?
        .to_string();

    // Defensive: fail fast if the parent `worktrees/` directory
    // can't be created so the `provision_orchestrator` clone
    // doesn't surface this as a misleading `gix::clone::Error`.
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ProvisionError::DestUnusable {
            path: parent.to_path_buf(),
            reason: e.to_string(),
        })?;
    }

    let provision = provision_orchestrator(
        &main_repo,
        &base_sha,
        &dest,
        // Per `INV-PLANNER-HARNESS-06`-adjacent §Step 27 backstop,
        // Orchestrator worktrees MUST be `Full` — the host-side
        // 3-way merge `domain_git::commit_merge_to_target_ref`
        // breaks under sparse-trimmed working trees. The crate
        // re-checks this defensively but we assert at the
        // composition seam too.
        CloneStrategy::Full,
    )?;

    Ok(OrchestratorAnchor {
        worktree_root: provision.worktree_root,
        base_sha: provision.base_sha,
        base_tracking_ref: target_ref.to_owned(),
    })
}

/// Provision the per-task Executor worktree.
///
/// Clones the Orchestrator's worktree (passed as
/// [`OrchestratorAnchor::worktree_root`]) into
/// `<data_dir>/worktrees/<session_id>/`. The clone uses the same
/// `gix::clone::PrepareFetch` pipeline `provision_orchestrator`
/// uses — packs are decoded, no hardlinks, the destination ODB is
/// fully independent.
///
/// Returns the [`WorkspaceMount`] the substrate consumes (RW
/// because the Executor `git commit`s its work) so the kernel
/// can drop it straight into `SpawnRequest::workspace_mounts`.
pub fn provision_executor_worktree(
    data_dir: &Path,
    session_id: &str,
    orch_anchor: &OrchestratorAnchor,
    input_base_sha: &str,
) -> Result<ExecutorWorkspace, ProvisionError> {
    let dest = data_dir.join(WORKTREES_DIR).join(session_id);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ProvisionError::DestUnusable {
            path: parent.to_path_buf(),
            reason: e.to_string(),
        })?;
    }

    // The Executor's worktree IS structurally an Orchestrator-
    // shaped clone (full clone, full worktree, HEAD at
    // `input_base_sha`) — the Orchestrator clones from `main`, the
    // Executor clones from the Orchestrator's worktree. So we re-use
    // `provision_orchestrator` (whose semantics are "clone source
    // at base_sha, full worktree, no sparse"). The only distinction
    // is that the source is the Orchestrator's worktree, not the
    // bare `main` repo. `gix::clone` accepts either layout.
    let provision = provision_orchestrator(
        &orch_anchor.worktree_root,
        input_base_sha,
        &dest,
        CloneStrategy::Full,
    )?;

    Ok(ExecutorWorkspace {
        input_base_sha: input_base_sha.to_owned(),
        mount: WorkspaceMount {
            host_path: provision.worktree_root,
            guest_path: GUEST_WORKSPACE_PATH.to_owned(),
            mode: MountMode::ReadWrite,
            // Content hashing the entire git working tree on every
            // spawn would dominate the spawn-path latency budget;
            // V2 leaves this `None` and the Reviewer's read-only
            // snapshot covers the byte-equivalence audit need.
            content_hash: None::<ContentHash>,
        },
    })
}

/// Provision the per-task Reviewer worktree.
///
/// Per `v2-deep-spec.md §Step 24`, the Reviewer's worktree is a
/// read-only snapshot of the Orchestrator's worktree at
/// `evaluation_sha` (the SHA the predecessor Executor stamped on
/// the task at `CompleteTask`). The clone goes through the
/// `raxis_worktree_provision::provision_reviewer` path which:
///
///   1. Clones the Orchestrator's worktree into the destination
///      via `file://` so the destination ODB is independent.
///   2. Creates `refs/raxis/evaluation` pointing at
///      `evaluation_sha`.
///   3. Detached-HEAD checkout at `evaluation_sha`.
///   4. Pre-renders `<dest>/.raxis/diff.patch` and
///      `<dest>/.raxis/log.txt` covering
///      `base_sha..evaluation_sha`.
///
/// Returns the read-only [`WorkspaceMount`].
pub fn provision_reviewer_worktree(
    data_dir: &Path,
    session_id: &str,
    orch_anchor: &OrchestratorAnchor,
    evaluation_sha: &str,
    diff_base_sha: &str,
) -> Result<WorkspaceMount, ProvisionError> {
    let dest = data_dir.join(WORKTREES_DIR).join(session_id);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ProvisionError::DestUnusable {
            path: parent.to_path_buf(),
            reason: e.to_string(),
        })?;
    }

    let provision = provision_reviewer(
        &orch_anchor.worktree_root,
        evaluation_sha,
        diff_base_sha,
        &dest,
        // Reviewer V2 baseline is `Full`; sparse is a per-task
        // policy decision that lands on the planner-side. The
        // E2E plan does not declare sparse — full clone keeps
        // the in-VM ripgrep / read_file workflow simple.
        CloneStrategy::Full,
        &[],
    )?;

    Ok(WorkspaceMount {
        host_path: provision.worktree_root,
        guest_path: GUEST_WORKSPACE_PATH.to_owned(),
        mode: MountMode::ReadOnly,
        content_hash: None::<ContentHash>,
    })
}

/// Prefix for the kernel's per-task transfer refs. After a
/// successful `copy_executor_commit_to_orchestrator_odb`, a ref
/// at `refs/heads/raxis-transfer/<task_id>` is created pointing
/// at the executor's evaluation_sha so the next Reviewer's
/// `gix::clone::PrepareFetch` walk pulls the commit closure
/// across the file:// transport.
///
/// Without a ref, `PrepareFetch` traverses only objects
/// reachable from refs in the source's *fetch refspec* (the
/// default `+refs/heads/*:refs/remotes/origin/*`), so the
/// executor's commit objects — even though loose in the source
/// ODB after `fetch_into_main` — would not land in the
/// destination ODB and the reviewer's `provision_reviewer`
/// would surface `ProvisionError::ShaMissingPostClone`.
///
/// We stamp under `refs/heads/raxis-transfer/` (not the cleaner
/// `refs/raxis/transfer/`) precisely because the default
/// refspec only pulls `refs/heads/*` — a custom-namespace ref
/// would be invisible to the clone walker. The
/// `raxis-transfer/` infix makes the kernel-managed namespace
/// recognisable in `git branch -a` output.
pub const TRANSFER_REF_PREFIX: &str = "refs/heads/raxis-transfer/";

/// Copy the closure of `commit_sha` from the Executor's worktree
/// into the Orchestrator's ODB AND publish a per-task transfer
/// ref so the next Reviewer's `gix::clone::PrepareFetch` walk
/// finds it.
///
/// Called by the kernel's `handle_complete_task` after the task
/// row has flipped to `Completed`. After this returns Ok:
///
///   * The Orchestrator's ODB at `<data_dir>/worktrees/orch-<initiative_id>/.git/`
///     contains every reachable object from `commit_sha`.
///   * `refs/heads/raxis-transfer/<task_id>` in that ODB points at
///     `commit_sha`. The next `gix::clone` from the orch
///     worktree pulls the commit + tree + blobs because the
///     ref is in the default refspec set.
///   * The IntegrationMerge handler's
///     `commit_merge_to_target_ref` resolves `commit_sha`
///     directly out of the orch ODB.
///
/// Idempotent on re-call: `fetch_into_main` short-circuits when
/// the SHA is already present, and `write_ref_force` overwrites
/// an existing ref to the same OID with no observable effect.
pub fn copy_executor_commit_to_orchestrator_odb(
    orch_worktree_root: &Path,
    exec_worktree_root: &Path,
    task_id: &str,
    commit_sha: &str,
) -> Result<(), String> {
    let oid = gix::ObjectId::from_hex(commit_sha.as_bytes())
        .map_err(|e| format!("invalid commit_sha {commit_sha:?}: {e}"))?;

    // 1. Copy the object closure. `fetch_into_main`'s param naming
    //    is historical — its body is "walk every object reachable
    //    from `commit_sha` in source, write into destination ODB".
    raxis_domain_git::fetch_into_main(orch_worktree_root, exec_worktree_root, &oid)
        .map_err(|e| format!("fetch_into_main: {e}"))?;

    // 2. Publish a transfer ref at `refs/heads/raxis-transfer/<task_id>`
    //    so the next `gix::clone::PrepareFetch` walk includes the
    //    commit. We refuse task_ids with embedded slashes /
    //    control chars defensively — the plan parser's task_id
    //    validator already enforces this, but a structurally bad
    //    id here would silently land outside the transfer
    //    namespace.
    if task_id.is_empty() || task_id.contains(['/', '\n', ' ', '\t', '\r']) {
        return Err(format!(
            "task_id {task_id:?} contains invalid characters; \
             refusing to write transfer ref",
        ));
    }
    let ref_name = format!("{TRANSFER_REF_PREFIX}{task_id}");
    let orch_repo = gix::open(orch_worktree_root)
        .map_err(|e| format!("open orch repo at {}: {e}", orch_worktree_root.display()))?;
    use gix::bstr::ByteSlice;
    use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
    let edit = RefEdit {
        change: Change::Update {
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: format!("raxis kernel transfer-ref for task {task_id} -> {commit_sha}")
                    .into(),
            },
            // Write the new OID unconditionally — the Executor may
            // have re-run and we want the latest commit to land.
            expected: PreviousValue::Any,
            new: gix::refs::Target::Object(oid),
        },
        name: ref_name
            .clone()
            .try_into()
            .map_err(|e| format!("invalid ref name {ref_name:?}: {e}"))?,
        deref: false,
    };
    let committer = gix::actor::SignatureRef {
        name: b"raxis-kernel".as_bstr(),
        email: b"raxis-kernel@localhost".as_bstr(),
        time: "0 +0000",
    };
    orch_repo
        .edit_references_as(std::iter::once(edit), Some(committer))
        .map_err(|e| format!("write transfer ref {ref_name}: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    /// Helper: run a git CLI command in `cwd`. The provisioning
    /// pipeline is gix-only at runtime, but the test fixtures
    /// need the git CLI to seed a real source repository.
    fn run_git(cwd: &Path, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap_or_else(|e| panic!("git {args:?}: {e}"));
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr),
        );
    }

    fn git_stdout(cwd: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap_or_else(|e| panic!("git {args:?}: {e}"));
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr),
        );
        String::from_utf8(out.stdout)
            .expect("git stdout utf8")
            .trim()
            .to_owned()
    }

    /// Initialise a real source repository at
    /// `<data_dir>/repositories/main` with one commit on the
    /// requested branch. Mirrors the live-e2e harness's
    /// `bootstrap_source_repository` shape.
    ///
    /// **Portability.** `git init -b <branch>` requires git ≥ 2.28
    /// (the flag was added in 2020). Some CI sandboxes / older
    /// host installs still ship git 2.23-era binaries; on those
    /// hosts `-b` errors with `unknown switch ‘b’` and the test
    /// fixture aborts before the production gix path is even
    /// reached. We use the version-agnostic two-step instead:
    /// `git init -q` (lands HEAD on whatever the host defaults to,
    /// commonly `master` on older git) followed by
    /// `git symbolic-ref HEAD refs/heads/<branch>` to retarget HEAD.
    /// This is safe pre-commit because the symbolic-ref is rewritten
    /// before any object is bound to a branch.
    fn bootstrap_source(data_dir: &Path, branch: &str) -> String {
        let main_repo = data_dir.join("repositories").join("main");
        std::fs::create_dir_all(&main_repo).expect("mkdir main repo");
        run_git(&main_repo, &["init", "-q"]);
        run_git(
            &main_repo,
            &["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")],
        );
        run_git(&main_repo, &["config", "user.email", "test@raxis.local"]);
        run_git(&main_repo, &["config", "user.name", "raxis-test"]);
        std::fs::write(main_repo.join("README.md"), b"hello\n").unwrap();
        run_git(&main_repo, &["add", "README.md"]);
        run_git(&main_repo, &["commit", "-q", "-m", "initial"]);
        git_stdout(&main_repo, &["rev-parse", "HEAD"])
    }

    #[test]
    fn provision_orchestrator_worktree_first_spawn_creates_clone() {
        // Skip the test cleanly when git CLI is unavailable
        // (sandbox without git binary). The provisioning pipeline
        // itself is gix-only so the fixture seeding is the only
        // git-CLI dependency.
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skipping: git CLI not available");
            return;
        }
        let dd = TempDir::new().unwrap();
        let head_sha = bootstrap_source(dd.path(), "main");

        let anchor = provision_orchestrator_worktree(
            dd.path(),
            "01900000-0000-7000-8000-000000000001",
            crate::managed_repositories::DEFAULT_REPOSITORY_ID,
            "refs/heads/main",
        )
        .expect("first-spawn provisioning succeeds");

        assert_eq!(anchor.base_sha, head_sha);
        assert_eq!(anchor.base_tracking_ref, "refs/heads/main");
        assert!(anchor.worktree_root.join(".git").exists());
        assert!(anchor.worktree_root.join("README.md").exists());
    }

    #[test]
    fn provision_orchestrator_worktree_is_idempotent_on_respawn() {
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skipping: git CLI not available");
            return;
        }
        let dd = TempDir::new().unwrap();
        let _ = bootstrap_source(dd.path(), "main");
        let init = "01900000-0000-7000-8000-000000000002";
        let first = provision_orchestrator_worktree(
            dd.path(),
            init,
            crate::managed_repositories::DEFAULT_REPOSITORY_ID,
            "refs/heads/main",
        )
        .expect("first-spawn ok");
        let second = provision_orchestrator_worktree(
            dd.path(),
            init,
            crate::managed_repositories::DEFAULT_REPOSITORY_ID,
            "refs/heads/main",
        )
        .expect("re-attach ok");
        assert_eq!(first.worktree_root, second.worktree_root);
        assert_eq!(first.base_sha, second.base_sha);
    }

    #[test]
    fn provision_executor_worktree_clones_from_orch_worktree() {
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skipping: git CLI not available");
            return;
        }
        let dd = TempDir::new().unwrap();
        let _ = bootstrap_source(dd.path(), "main");
        let anchor = provision_orchestrator_worktree(
            dd.path(),
            "01900000-0000-7000-8000-000000000003",
            crate::managed_repositories::DEFAULT_REPOSITORY_ID,
            "refs/heads/main",
        )
        .expect("orch ok");
        let exec_session = "01900000-0000-7000-8000-0000000000ee";
        let provisioned =
            provision_executor_worktree(dd.path(), exec_session, &anchor, &anchor.base_sha)
                .expect("executor provisioning ok");
        assert_eq!(provisioned.input_base_sha, anchor.base_sha);
        assert_eq!(provisioned.mount.guest_path, "/workspace");
        assert!(matches!(provisioned.mount.mode, MountMode::ReadWrite));
        assert!(provisioned.mount.host_path.join(".git").exists());
        assert!(provisioned.mount.host_path.join("README.md").exists());
    }

    #[test]
    fn provision_executor_worktree_can_start_from_predecessor_evaluation_sha() {
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skipping: git CLI not available");
            return;
        }
        let dd = TempDir::new().unwrap();
        let _ = bootstrap_source(dd.path(), "main");
        let anchor = provision_orchestrator_worktree(
            dd.path(),
            "01900000-0000-7000-8000-000000000004",
            crate::managed_repositories::DEFAULT_REPOSITORY_ID,
            "refs/heads/main",
        )
        .expect("orch ok");

        let pred = provision_executor_worktree(
            dd.path(),
            "01900000-0000-7000-8000-0000000000aa",
            &anchor,
            &anchor.base_sha,
        )
        .expect("predecessor provisioning ok");
        std::fs::write(
            pred.mount.host_path.join("README.md"),
            b"hello from predecessor\n",
        )
        .expect("write predecessor fixture");
        run_git(
            &pred.mount.host_path,
            &["config", "user.email", "test@raxis.local"],
        );
        run_git(
            &pred.mount.host_path,
            &["config", "user.name", "raxis-test"],
        );
        run_git(&pred.mount.host_path, &["add", "README.md"]);
        run_git(
            &pred.mount.host_path,
            &["commit", "-q", "-m", "predecessor"],
        );
        let predecessor_sha = git_stdout(&pred.mount.host_path, &["rev-parse", "HEAD"]);

        copy_executor_commit_to_orchestrator_odb(
            &anchor.worktree_root,
            &pred.mount.host_path,
            "predecessor-task",
            &predecessor_sha,
        )
        .expect("copy predecessor commit to orchestrator ODB");

        let successor = provision_executor_worktree(
            dd.path(),
            "01900000-0000-7000-8000-0000000000bb",
            &anchor,
            &predecessor_sha,
        )
        .expect("successor provisioning ok");
        assert_eq!(successor.input_base_sha, predecessor_sha);
        assert_eq!(
            git_stdout(&successor.mount.host_path, &["rev-parse", "HEAD"]),
            predecessor_sha
        );
        assert_eq!(
            std::fs::read_to_string(successor.mount.host_path.join("README.md"))
                .expect("read successor inherited file"),
            "hello from predecessor\n"
        );
    }
}
