// raxis-kernel::vcs::diff — Git subprocess wrappers.
//
// Normative reference: kernel-core.md §2.3 `src/vcs/diff.rs` + §2.5.8.
//
// All five functions spawn the git CLI as a subprocess. No libgit2 dependency.
// Every call uses `git -C <worktree_root>` so the repository is unambiguous.
//
// Timeout: 30s default (RAXIS_VCS_TIMEOUT_SECS env override, hard cap 120s).
// All timeouts map to VcsError::GitError with a descriptive message.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use thiserror::Error;

// ---------------------------------------------------------------------------
// CommitSha newtype — validated 40-char lowercase hex
// ---------------------------------------------------------------------------

/// A validated 40-character lowercase hex commit SHA.
/// Constructors reject anything that is not exactly 40 hex chars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSha(String);

impl CommitSha {
    /// Parse and validate a commit SHA string. Returns `Err` if not 40-char hex.
    pub fn new(s: &str) -> Result<Self, VcsError> {
        let s = s.trim();
        if s.len() != 40 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VcsError::InvalidSha(s.to_owned()));
        }
        Ok(CommitSha(s.to_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CommitSha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum VcsError {
    #[error("invalid SHA-1 (must be 40 hex chars): {0:?}")]
    InvalidSha(String),

    #[error("git subprocess failed: {message}")]
    GitError { message: String },

    #[error("git diff failed (exit {exit_code}): {stderr}")]
    DiffFailed { exit_code: i32, stderr: String },

    #[error("base SHA is not an ancestor of head SHA")]
    NotAncestor,

    #[error("head commit is a root commit (no parent)")]
    HeadIsRootCommit,

    #[error("commit SHA not found in repository: {sha}")]
    ShaNotFound { sha: String },

    #[error("merge commit found in SingleCommit range (count: {merge_count})")]
    MergeCommitInRange { merge_count: u64 },

    #[error("git subprocess timed out after {timeout_secs}s")]
    Timeout { timeout_secs: u64 },
}

// ---------------------------------------------------------------------------
// Timeout helper
// ---------------------------------------------------------------------------

fn vcs_timeout() -> Duration {
    let secs = std::env::var("RAXIS_VCS_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30)
        .min(120);
    Duration::from_secs(secs)
}

/// Run a git command, capturing stdout + stderr. Returns (stdout, stderr, exit_code).
/// Kills the process and returns VcsError::Timeout if the deadline passes.
fn run_git(
    args: &[&str],
    worktree_root: &Path,
    timeout: Duration,
) -> Result<(String, String, i32), VcsError> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(worktree_root)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| VcsError::GitError {
            message: format!("failed to spawn git: {e}"),
        })?;

    let deadline = Instant::now() + timeout;
    let timeout_secs = timeout.as_secs();

    // Poll until done or deadline.
    loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(VcsError::Timeout { timeout_secs });
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => {
                return Err(VcsError::GitError {
                    message: format!("wait error: {e}"),
                })
            }
        }
    }

    let output = child.wait_with_output().map_err(|e| VcsError::GitError {
        message: format!("wait_with_output error: {e}"),
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(-1);
    Ok((stdout, stderr, code))
}

// ---------------------------------------------------------------------------
// pub fn touched_paths
//
// Normative: kernel-core.md §2.3 — git diff <base> <head> --name-only
// (legacy form, retained for INV-07 derivation).
// ---------------------------------------------------------------------------

/// Returns all file paths touched between `base_sha` and `head_sha`.
/// Uses `--name-only` (INV-07 form). Sorted for reproducibility.
pub fn touched_paths(
    base_sha: &CommitSha,
    head_sha: &CommitSha,
    worktree_root: &Path,
) -> Result<Vec<PathBuf>, VcsError> {
    let timeout = vcs_timeout();
    let (stdout, stderr, code) = run_git(
        &["diff", base_sha.as_str(), head_sha.as_str(), "--name-only", "--no-renames"],
        worktree_root,
        timeout,
    )?;

    if code != 0 {
        return Err(VcsError::DiffFailed {
            exit_code: code,
            stderr,
        });
    }

    let mut paths: Vec<PathBuf> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect();
    paths.sort();
    Ok(paths)
}

// ---------------------------------------------------------------------------
// pub fn compute
//
// Normative: kernel-core.md §2.5.8 — canonical path scope enforcement.
// Uses --name-status --no-renames; skips deleted files (status D).
// ---------------------------------------------------------------------------

/// Canonical path diff for scope enforcement.
/// Uses `git diff <base> <head> --name-status --no-renames`.
/// Deleted files (status `D`) are excluded per §2.5.8 path scope rules.
pub fn compute(
    base_sha: &CommitSha,
    head_sha: &CommitSha,
    worktree_root: &Path,
) -> Result<Vec<PathBuf>, VcsError> {
    let timeout = vcs_timeout();
    let (stdout, stderr, code) = run_git(
        &[
            "diff",
            base_sha.as_str(),
            head_sha.as_str(),
            "--name-status",
            "--no-renames",
        ],
        worktree_root,
        timeout,
    )?;

    if code != 0 {
        return Err(VcsError::DiffFailed {
            exit_code: code,
            stderr,
        });
    }

    // Parse "STATUS<TAB>PATH" lines.
    // Status codes: A (added), M (modified), D (deleted), T (type change), U (unmerged).
    // Scope enforcement: include all non-deleted paths.
    let mut paths: Vec<PathBuf> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let mut parts = line.splitn(2, '\t');
            let status = parts.next()?.trim();
            let path = parts.next()?.trim();
            // Skip purely deleted files — they no longer exist in head.
            if status.starts_with('D') {
                None
            } else {
                Some(PathBuf::from(path))
            }
        })
        .collect();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

// ---------------------------------------------------------------------------
// pub fn is_ancestor
//
// Normative: kernel-core.md §2.3 — git merge-base --is-ancestor <base> <head>
// ---------------------------------------------------------------------------

/// Returns `true` if `base_sha` is an ancestor of `head_sha`.
/// Exit 0 → true, exit 1 → false, other → Err.
pub fn is_ancestor(
    base_sha: &CommitSha,
    head_sha: &CommitSha,
    worktree_root: &Path,
) -> Result<bool, VcsError> {
    let timeout = vcs_timeout();
    let (_, stderr, code) = run_git(
        &["merge-base", "--is-ancestor", base_sha.as_str(), head_sha.as_str()],
        worktree_root,
        timeout,
    )?;

    match code {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(VcsError::GitError {
            message: format!("merge-base --is-ancestor exited {code}: {stderr}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// pub fn rev_parse_parent
//
// Normative: kernel-core.md §2.3 — git rev-parse --verify <head>^1
// ---------------------------------------------------------------------------

/// Returns the first parent SHA of `head_sha`.
/// Maps specific failure modes to typed VcsError variants.
pub fn rev_parse_parent(
    head_sha: &CommitSha,
    worktree_root: &Path,
) -> Result<CommitSha, VcsError> {
    let timeout = vcs_timeout();
    let ref_arg = format!("{}^1", head_sha.as_str());
    let (stdout, stderr, code) = run_git(
        &["rev-parse", "--verify", &ref_arg],
        worktree_root,
        timeout,
    )?;

    if code == 0 {
        let sha = stdout.trim();
        return CommitSha::new(sha).map_err(|_| VcsError::GitError {
            message: format!("git rev-parse returned non-SHA: {sha:?}"),
        });
    }

    // Classify failure.
    let stderr_lower = stderr.to_lowercase();
    if stderr_lower.contains("unknown revision") || stderr_lower.contains("ambiguous argument") {
        return Err(VcsError::HeadIsRootCommit);
    }
    if stderr_lower.contains("needed a single revision") || stderr_lower.contains("not a valid object name") {
        return Err(VcsError::ShaNotFound {
            sha: head_sha.as_str().to_owned(),
        });
    }
    Err(VcsError::GitError {
        message: format!("rev-parse --verify {ref_arg} exited {code}: {stderr}"),
    })
}

// ---------------------------------------------------------------------------
// pub fn topology_check
//
// Normative: kernel-core.md §2.3 + §2.5.8
// git rev-list <base>..<head> --min-parents=2 --count
// ---------------------------------------------------------------------------

/// Verifies no merge commits exist in `base_sha..head_sha`.
/// Returns `Ok(())` if the range is clean; `Err(MergeCommitInRange)` otherwise.
/// Not called for IntentKind::IntegrationMerge.
pub fn topology_check(
    base_sha: &CommitSha,
    head_sha: &CommitSha,
    worktree_root: &Path,
) -> Result<(), VcsError> {
    let timeout = vcs_timeout();
    let range = format!("{}..{}", base_sha.as_str(), head_sha.as_str());
    let (stdout, stderr, code) = run_git(
        &["rev-list", &range, "--min-parents=2", "--count"],
        worktree_root,
        timeout,
    )?;

    if code != 0 {
        return Err(VcsError::GitError {
            message: format!("rev-list --count exited {code}: {stderr}"),
        });
    }

    let count: u64 = stdout.trim().parse().unwrap_or(0);
    if count > 0 {
        return Err(VcsError::MergeCommitInRange { merge_count: count });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests — no git subprocess calls; test the CommitSha validator only.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_sha_accepted() {
        let sha = CommitSha::new("a".repeat(40).as_str()).unwrap();
        assert_eq!(sha.as_str().len(), 40);
    }

    #[test]
    fn short_sha_rejected() {
        assert!(CommitSha::new("abc123").is_err());
    }

    #[test]
    fn non_hex_rejected() {
        assert!(CommitSha::new(&"z".repeat(40)).is_err());
    }

    #[test]
    fn uppercase_normalised_to_lower() {
        let sha = CommitSha::new(&"A".repeat(40)).unwrap();
        assert!(sha.as_str().chars().all(|c| c.is_lowercase() || c.is_ascii_digit()));
    }
}
