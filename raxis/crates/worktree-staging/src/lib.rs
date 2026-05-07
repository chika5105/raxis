//! Per-session worktree staging — V2 Step 10 ("VirtioFS Staging + VSock Push").
//!
//! Normative reference: `v2-deep-spec.md §1.5 Worktree Lifecycle` and
//! `v2-deep-spec.md §Step 10`. The Kernel stages the per-session
//! worktree directory under
//! `<data_dir>/worktrees/<session_uuid>/` and writes the
//! `.raxis/` control surface that the substrate exposes to the
//! guest:
//!
//! ```text
//!   <data_dir>/worktrees/<session_uuid>/
//!     ├── .raxis/
//!     │   ├── system_prompt.txt   ← non-negotiable prompt prefix (V2 §10)
//!     │   ├── session.env         ← session token + VSock connect params
//!     │   └── bundles/            ← Executor bundle drop dir (per Reviewer §24/24b)
//!     │
//!     └── (clone destination filled by Steps 23/24/24b)
//! ```
//!
//! The clone itself (`gix clone --filter=blob:none`, sparse-checkout,
//! Reviewer object copy) lands in Step 24/24b — this crate owns
//! the *staging* side of the contract:
//!
//! 1. Mint a worktree root path under `<data_dir>/worktrees/`.
//! 2. Create the `.raxis/` skeleton (`system_prompt.txt`,
//!    `session.env`, `bundles/`).
//! 3. Build the [`raxis_isolation::WorkspaceMount`] vector that the
//!    kernel hands to `Backend::spawn` (one entry: the worktree
//!    root, mounted at `/workspace/` per V2 §1.5).
//! 4. Compute a content hash over the staged tree so the substrate
//!    can record it into the audit chain (`R-7`).
//! 5. On session teardown, remove the staged directory.
//!
//! ## Why this is its own crate
//!
//! The staging logic is pure-data: no SQLite store, no audit sink,
//! no IPC. Pulling it out of `raxis-kernel` (a binary crate) lets
//! kernel integration tests + future operator tooling consume it
//! through a small dependency without dragging in the kernel's full
//! graph.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::{Path, PathBuf};

use raxis_isolation::{ContentHash, MountMode, WorkspaceMount};
use sha2::{Digest, Sha256};

/// Directory under `<data_dir>` where per-session worktrees live.
/// Pinned per `v2-deep-spec.md §1.5`.
pub const WORKTREES_DIR: &str = "worktrees";

/// Directory inside each worktree that holds the kernel's control
/// surface (system prompt, session env, bundle drop). Pinned per
/// `v2-deep-spec.md §Step 10`.
pub const RAXIS_DIR: &str = ".raxis";

/// Filename of the non-negotiable system prompt the kernel writes
/// before VM boot. Per `extensibility-traits.md §3.4` the planner
/// reads this once at startup.
pub const SYSTEM_PROMPT_FILENAME: &str = "system_prompt.txt";

/// Filename of the session env file (token + VSock CID/port).
pub const SESSION_ENV_FILENAME: &str = "session.env";

/// Sub-directory where Executors / Reviewers drop bundles.
pub const BUNDLES_DIRNAME: &str = "bundles";

/// Guest mount path. The substrate maps the host worktree root to
/// `/workspace/` inside the guest, per V2 §1.5.
pub const GUEST_WORKSPACE_PATH: &str = "/workspace";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors the staging module can surface.
#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    /// The supplied `data_dir` does not exist or is not a directory.
    /// Bootstrap creates `<data_dir>/worktrees/` so this firing in
    /// production means an operator deleted the dir post-boot.
    #[error("data_dir invalid: {0}")]
    DataDirInvalid(String),

    /// Filesystem write failed (creating worktree root, `.raxis/`,
    /// or one of the staged files). Wraps the underlying `io::Error`
    /// reason so the kernel boundary can project to a typed audit
    /// event.
    #[error("staging filesystem write failed: {path}: {reason}")]
    StageWriteFailed {
        /// Absolute path the write targeted.
        path:   PathBuf,
        /// Underlying I/O reason.
        reason: String,
    },

    /// Tear-down (`destroy`) hit a non-recoverable error. The
    /// `worktrees/<uuid>/` directory is still present on disk and
    /// the kernel boundary should record an audit event for the
    /// orphaned tree.
    #[error("staging destroy failed: {path}: {reason}")]
    DestroyFailed {
        /// Absolute path that failed to delete.
        path:   PathBuf,
        /// Underlying I/O reason.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// Inputs the kernel hands the staging module per session.
///
/// Pure data; the staging module does no policy / store work — the
/// kernel's session-admission handler resolves the session token,
/// VSock CID, and system prompt, then calls into staging exactly
/// once.
#[derive(Debug, Clone)]
pub struct StageInputs {
    /// `<data_dir>` — `<data_dir>/worktrees/<uuid>/` is what we mint.
    pub data_dir: PathBuf,
    /// Stable per-session UUID. The kernel mints this from
    /// `Uuid::new_v4()` at session creation; staging records it on
    /// disk so a hot-restart sweep can reconcile orphaned
    /// directories.
    pub session_uuid: String,
    /// Bytes of the non-negotiable system prompt, written verbatim
    /// to `<.raxis>/system_prompt.txt`. The kernel pre-assembles
    /// this from `prompt::assembler` per `kernel-mechanics-prompt.md
    /// §3.1`.
    pub system_prompt: String,
    /// Per-session secret the planner authenticates intent frames
    /// with. Written verbatim to the `RAXIS_SESSION_TOKEN=...` line
    /// in `session.env`.
    pub session_token: String,
    /// VSock CID the substrate assigns the guest. Written to
    /// `RAXIS_VSOCK_CID=...`.
    pub vsock_cid: u32,
    /// VSock port inside the guest the planner listens on. Written
    /// to `RAXIS_VSOCK_PORT=...`.
    pub vsock_port: u32,
    /// Read-only or read-write mount mode. Reviewer worktrees are
    /// `ReadOnly` per `v2-deep-spec.md §Step 24` (`INV-NETISO-01`
    /// adjacent — Reviewer must see exactly the bytes the Executor
    /// committed).
    pub mount_mode: MountMode,
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

/// Output the staging module returns to the session-admission
/// handler. Carries the [`WorkspaceMount`] the kernel hands to
/// `Backend::spawn`, plus the staged paths so the audit emit can
/// record them.
#[derive(Debug, Clone)]
pub struct StagedWorktree {
    /// Absolute host path of the worktree root.
    pub worktree_root: PathBuf,
    /// Absolute host path of `<.raxis>/`.
    pub raxis_dir: PathBuf,
    /// Absolute host path of `<.raxis>/bundles/`.
    pub bundles_dir: PathBuf,
    /// The `WorkspaceMount` to hand to `Backend::spawn`.
    pub mount: WorkspaceMount,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Prepare a fresh per-session worktree on the host.
///
/// The function is *idempotent on the directory layer* (creating
/// `worktrees/<uuid>/.raxis/` twice is safe), but *non-idempotent on
/// the file layer* — calling `stage` twice on the same UUID with a
/// different `system_prompt` rewrites the file. Production never
/// re-stages an existing session; the rewrite path is exercised
/// only by tests.
///
/// Failure leaves the partial directory tree on disk. The session-
/// admission handler is responsible for calling [`destroy`] on the
/// returned `worktree_root` if a downstream `Backend::spawn` fails;
/// otherwise the tree is leaked. (Same contract as the V1 worktree
/// staging path — the kernel's recovery sweep cleans up on next
/// boot.)
pub fn stage(inputs: &StageInputs) -> Result<StagedWorktree, StagingError> {
    if !inputs.data_dir.is_dir() {
        return Err(StagingError::DataDirInvalid(format!(
            "{} is not a directory",
            inputs.data_dir.display(),
        )));
    }

    let worktrees_dir = inputs.data_dir.join(WORKTREES_DIR);
    let worktree_root = worktrees_dir.join(&inputs.session_uuid);
    let raxis_dir     = worktree_root.join(RAXIS_DIR);
    let bundles_dir   = raxis_dir.join(BUNDLES_DIRNAME);

    // Layout creation is mkdir-p across three nested levels.
    create_dir_all(&bundles_dir)?;

    let prompt_path = raxis_dir.join(SYSTEM_PROMPT_FILENAME);
    write_file(&prompt_path, inputs.system_prompt.as_bytes())?;

    let env_body = render_session_env(
        &inputs.session_token,
        inputs.vsock_cid,
        inputs.vsock_port,
    );
    let env_path = raxis_dir.join(SESSION_ENV_FILENAME);
    write_file(&env_path, env_body.as_bytes())?;

    // Mount root is the worktree root, not just `.raxis/` — the
    // guest needs the whole tree so it can `git checkout` and run
    // tests. The kernel populates the rest of the tree via the
    // clone strategy in Steps 23/24/24b before spawning the VM.
    let content_hash = digest_staged_files(&prompt_path, &env_path)?;
    let mount = WorkspaceMount {
        host_path:    worktree_root.clone(),
        guest_path:   GUEST_WORKSPACE_PATH.to_owned(),
        mode:         inputs.mount_mode,
        content_hash: Some(content_hash),
    };

    Ok(StagedWorktree {
        worktree_root,
        raxis_dir,
        bundles_dir,
        mount,
    })
}

/// Tear down a previously-staged worktree.
///
/// `worktree_root` MUST be the path returned by `stage`. The function
/// is idempotent: calling `destroy` twice on the same path returns
/// `Ok` on the second call (the second `remove_dir_all` is a no-op
/// because the directory is already gone).
///
/// We deliberately don't take a `&StagedWorktree` here so the call
/// site can be wired into a `Drop` / `SessionRevoked` handler that
/// only stored the worktree root path.
pub fn destroy(worktree_root: &Path) -> Result<(), StagingError> {
    if !worktree_root.exists() {
        return Ok(());
    }
    std::fs::remove_dir_all(worktree_root).map_err(|e| StagingError::DestroyFailed {
        path:   worktree_root.to_path_buf(),
        reason: e.to_string(),
    })
}

/// Compute the absolute path of the worktree root for a session
/// without staging it. Useful for hot-restart sweeps that need to
/// answer "is this UUID's tree still on disk?" without touching it.
pub fn worktree_root_path(data_dir: &Path, session_uuid: &str) -> PathBuf {
    data_dir.join(WORKTREES_DIR).join(session_uuid)
}

/// Render the `session.env` body the planner reads at boot.
///
/// Format is intentionally simple: `KEY=VALUE\n` lines with no
/// shell quoting. The planner parses with `std::env::set_var` after
/// reading the file in `extensibility-traits.md §3.4`.
///
/// This is `pub` so tests can pin the wire shape without touching
/// the filesystem.
pub fn render_session_env(token: &str, cid: u32, port: u32) -> String {
    format!(
        "RAXIS_SESSION_TOKEN={token}\n\
         RAXIS_VSOCK_CID={cid}\n\
         RAXIS_VSOCK_PORT={port}\n",
    )
}

// ---------------------------------------------------------------------------
// Helpers (private, deterministic)
// ---------------------------------------------------------------------------

fn create_dir_all(path: &Path) -> Result<(), StagingError> {
    std::fs::create_dir_all(path).map_err(|e| StagingError::StageWriteFailed {
        path:   path.to_path_buf(),
        reason: e.to_string(),
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), StagingError> {
    std::fs::write(path, bytes).map_err(|e| StagingError::StageWriteFailed {
        path:   path.to_path_buf(),
        reason: e.to_string(),
    })
}

/// SHA-256 over the staged file pair. Pinned canonical input:
/// `prompt_bytes || env_bytes`. The substrate records this into
/// the audit event so an external auditor can reconstruct the bytes
/// the guest saw.
fn digest_staged_files(prompt_path: &Path, env_path: &Path)
    -> Result<ContentHash, StagingError>
{
    let prompt = std::fs::read(prompt_path).map_err(|e| StagingError::StageWriteFailed {
        path:   prompt_path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let env = std::fs::read(env_path).map_err(|e| StagingError::StageWriteFailed {
        path:   env_path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&prompt);
    hasher.update(&env);
    let digest = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&digest);
    Ok(ContentHash(buf))
}

// ---------------------------------------------------------------------------
// Tests — pin the host-side staging contract.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_isolation::MountMode;
    use tempfile::tempdir;

    fn fixture_inputs(data_dir: PathBuf, uuid: &str) -> StageInputs {
        StageInputs {
            data_dir,
            session_uuid:  uuid.to_owned(),
            system_prompt: "You are an Executor. Follow the contract.".to_owned(),
            session_token: "tok-test-1".to_owned(),
            vsock_cid:     7,
            vsock_port:    1024,
            mount_mode:    MountMode::ReadWrite,
        }
    }

    #[test]
    fn stage_creates_full_layout_per_spec() {
        let tmp = tempdir().unwrap();
        let inputs = fixture_inputs(tmp.path().to_path_buf(), "uuid-1");
        let staged = stage(&inputs).unwrap();
        assert!(staged.worktree_root.is_dir());
        assert!(staged.raxis_dir.is_dir());
        assert!(staged.bundles_dir.is_dir());
        assert!(staged.raxis_dir.join(SYSTEM_PROMPT_FILENAME).is_file());
        assert!(staged.raxis_dir.join(SESSION_ENV_FILENAME).is_file());
    }

    #[test]
    fn stage_writes_system_prompt_verbatim() {
        let tmp = tempdir().unwrap();
        let mut inputs = fixture_inputs(tmp.path().to_path_buf(), "uuid-prompt");
        inputs.system_prompt = "Strict-mode banner\n----\nrules.".to_owned();
        let staged = stage(&inputs).unwrap();
        let body = std::fs::read_to_string(
            staged.raxis_dir.join(SYSTEM_PROMPT_FILENAME),
        )
        .unwrap();
        assert_eq!(body, "Strict-mode banner\n----\nrules.");
    }

    #[test]
    fn stage_renders_session_env_three_lines() {
        let env = render_session_env("tok-XYZ", 42, 1025);
        let lines: Vec<&str> = env.lines().collect();
        assert_eq!(lines.len(), 3, "session.env must have exactly 3 lines, got {env:?}");
        assert_eq!(lines[0], "RAXIS_SESSION_TOKEN=tok-XYZ");
        assert_eq!(lines[1], "RAXIS_VSOCK_CID=42");
        assert_eq!(lines[2], "RAXIS_VSOCK_PORT=1025");
    }

    #[test]
    fn stage_workspace_mount_targets_guest_workspace_path() {
        let tmp = tempdir().unwrap();
        let inputs = fixture_inputs(tmp.path().to_path_buf(), "uuid-mount");
        let staged = stage(&inputs).unwrap();
        assert_eq!(staged.mount.guest_path, GUEST_WORKSPACE_PATH);
        assert_eq!(staged.mount.host_path,  staged.worktree_root);
        assert_eq!(staged.mount.mode,       MountMode::ReadWrite);
        assert!(staged.mount.content_hash.is_some(),
            "Step 10 requires a content_hash so the audit chain can record \
             the exact .raxis bytes the guest saw");
    }

    #[test]
    fn stage_uses_read_only_mount_when_caller_requests() {
        let tmp = tempdir().unwrap();
        let mut inputs = fixture_inputs(tmp.path().to_path_buf(), "uuid-ro");
        inputs.mount_mode = MountMode::ReadOnly;
        let staged = stage(&inputs).unwrap();
        assert_eq!(staged.mount.mode, MountMode::ReadOnly);
    }

    #[test]
    fn stage_content_hash_is_stable_for_same_inputs() {
        let tmp = tempdir().unwrap();
        let inputs_a = fixture_inputs(tmp.path().to_path_buf(), "uuid-a");
        let staged_a = stage(&inputs_a).unwrap();

        let tmp2 = tempdir().unwrap();
        let mut inputs_b = fixture_inputs(tmp2.path().to_path_buf(), "uuid-a");
        inputs_b.session_token = inputs_a.session_token.clone();
        inputs_b.vsock_cid     = inputs_a.vsock_cid;
        inputs_b.vsock_port    = inputs_a.vsock_port;
        inputs_b.system_prompt = inputs_a.system_prompt.clone();
        let staged_b = stage(&inputs_b).unwrap();

        assert_eq!(staged_a.mount.content_hash, staged_b.mount.content_hash);
    }

    #[test]
    fn stage_content_hash_changes_when_prompt_changes() {
        let tmp = tempdir().unwrap();
        let inputs_a = fixture_inputs(tmp.path().to_path_buf(), "uuid-h1");
        let mut inputs_b = inputs_a.clone();
        inputs_b.session_uuid = "uuid-h2".to_owned();
        inputs_b.system_prompt.push_str(" — extra rule");

        let a = stage(&inputs_a).unwrap();
        let b = stage(&inputs_b).unwrap();
        assert_ne!(a.mount.content_hash, b.mount.content_hash);
    }

    #[test]
    fn stage_content_hash_changes_when_session_token_changes() {
        let tmp = tempdir().unwrap();
        let inputs_a = fixture_inputs(tmp.path().to_path_buf(), "uuid-tok-a");
        let mut inputs_b = inputs_a.clone();
        inputs_b.session_uuid  = "uuid-tok-b".to_owned();
        inputs_b.session_token = "tok-different".to_owned();

        let a = stage(&inputs_a).unwrap();
        let b = stage(&inputs_b).unwrap();
        assert_ne!(a.mount.content_hash, b.mount.content_hash,
            "different session tokens must produce different content hashes \
             so the audit chain can detect a swapped token at replay time");
    }

    #[test]
    fn stage_rejects_missing_data_dir() {
        let inputs = fixture_inputs(PathBuf::from("/no/such/dir"), "uuid-x");
        let err = stage(&inputs).unwrap_err();
        match err {
            StagingError::DataDirInvalid(msg) => assert!(msg.contains("/no/such/dir")),
            other => panic!("expected DataDirInvalid, got {other:?}"),
        }
    }

    #[test]
    fn destroy_idempotent_on_missing_path() {
        let tmp = tempdir().unwrap();
        let absent = tmp.path().join("never-staged");
        destroy(&absent).unwrap();
        destroy(&absent).unwrap();
    }

    #[test]
    fn destroy_removes_full_tree() {
        let tmp = tempdir().unwrap();
        let inputs = fixture_inputs(tmp.path().to_path_buf(), "uuid-d1");
        let staged = stage(&inputs).unwrap();
        assert!(staged.worktree_root.is_dir());
        destroy(&staged.worktree_root).unwrap();
        assert!(!staged.worktree_root.exists());
    }

    #[test]
    fn worktree_root_path_is_deterministic_for_uuid() {
        let p = worktree_root_path(Path::new("/data"), "abc-123");
        assert_eq!(p, PathBuf::from("/data/worktrees/abc-123"));
    }

    /// Step 10 invariant: the staged worktree root MUST be directly
    /// translatable into a `WorkspaceMount`. The substrate's
    /// `Backend::spawn` then maps it into the guest at `/workspace/`.
    #[test]
    fn workspace_mount_is_directly_consumable_by_substrate_trait() {
        let tmp = tempdir().unwrap();
        let inputs = fixture_inputs(tmp.path().to_path_buf(), "uuid-mount-trait");
        let staged = stage(&inputs).unwrap();
        let mount: &WorkspaceMount = &staged.mount;
        assert_eq!(mount.host_path, staged.worktree_root);
        assert_eq!(mount.guest_path, "/workspace");
        assert!(mount.content_hash.is_some());
    }
}
