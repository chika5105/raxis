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

    /// `git diff --name-status` produced a status code we cannot interpret
    /// — `X`, `B`, an unrecognised letter, or a malformed line.
    /// Spec: kernel-store.md §2.5.8 "touched_paths construction" status table.
    #[error("invalid diff output line: {line:?}")]
    InvalidDiffOutput { line: String },

    /// `git diff` returned a `U` (unmerged) row. The intent must be rejected;
    /// the worktree contains an unresolved merge conflict.
    /// Spec: §2.5.8 "U (unmerged) → Reject intent: VcsDiffError::UnmergedPaths".
    #[error("unmerged path in diff: {path:?}")]
    UnmergedPaths { path: String },

    /// `git diff` returned an `R` (rename) row. The kernel always passes
    /// `--no-renames`; a rename row indicates a code path that omitted that
    /// flag (a kernel bug, not a user error).
    /// Spec: §2.5.8 "R (rename) → Reject intent: VcsDiffError::UnexpectedRenameRow".
    #[error("unexpected rename row in diff (--no-renames must be passed): {line:?}")]
    UnexpectedRenameRow { line: String },

    /// A path returned by `git diff` contains a `..` traversal segment, an
    /// absolute leading `/`, or another shape the spec rejects.
    /// Spec: §2.5.8 post-processing assertions.
    #[error("path traversal or absolute path detected: {path:?}")]
    PathTraversalDetected { path: String },
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
// Normative reference: kernel-store.md §2.5.8 "touched_paths construction".
//
// Spec contract (verbatim):
//   - Status codes A, M, D, T → include the single path in column 2.
//   - Status code C<score>   → include BOTH source (col 2) AND destination
//                              (col 3); conservative enforcement.
//   - Status code U          → reject (UnmergedPaths).
//   - Status code R          → reject (UnexpectedRenameRow); --no-renames was
//                              omitted, which is a kernel bug.
//   - Status code X / B / unknown → reject (InvalidDiffOutput).
//
// Post-processing (also normative):
//   - Strip leading `./` from each path.
//   - Reject any path containing a `..` component.
//   - Reject any absolute (leading `/`) path.
//   - Sort lexicographically; dedup.
// ---------------------------------------------------------------------------

/// Canonical path diff for scope enforcement.
///
/// Runs `git diff <base> <head> --name-status --no-renames`, parses every
/// row by `parse_name_status_row`, and returns the post-processed
/// lexicographically-sorted unique path list. ANY parse failure aborts the
/// entire diff with a typed error — partial path lists are never returned
/// because they would silently widen `effective_allow` checks.
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
            "-z", // NUL-terminate paths so embedded whitespace and quotes parse losslessly
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

    let raw_paths = parse_name_status_z(&stdout)?;

    // Post-process: strip `./`, reject `..` and absolute paths, sort, dedup.
    let mut paths = Vec::with_capacity(raw_paths.len());
    for raw in raw_paths {
        paths.push(post_process_path(&raw)?);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Parse `git diff --name-status --no-renames -z` output.
///
/// `-z` framing: each row is `<status>\t<path>\0` (or for copy rows
/// `C<score>\0<src>\0<dst>` per the git man page — but with `--no-renames`
/// copies are also collapsed, so we treat any `C` row as a parse error to
/// avoid relying on undocumented behaviour). NUL terminators preserve paths
/// containing `\t`, `\n`, or quotes.
fn parse_name_status_z(stdout: &str) -> Result<Vec<String>, VcsError> {
    let mut out = Vec::new();
    let mut iter = stdout.split('\0').peekable();
    while let Some(field) = iter.next() {
        if field.is_empty() {
            // Trailing NUL after the last record produces an empty trailing
            // field on most git versions. Skip cleanly.
            if iter.peek().is_none() {
                break;
            }
            continue;
        }

        // Each non-copy row is "<status>\t<path>"; for copy/rename rows
        // (which we do not expect with --no-renames) git emits
        // "<status>\0<src>\0<dst>" with the status alone in this field.
        let (status, path_in_same_field) = match field.split_once('\t') {
            Some((s, p)) => (s.to_owned(), Some(p.to_owned())),
            None => (field.to_owned(), None),
        };

        match classify_status(&status) {
            DiffStatus::SinglePath => {
                let path = path_in_same_field.ok_or_else(|| VcsError::InvalidDiffOutput {
                    line: field.to_owned(),
                })?;
                if path.is_empty() {
                    return Err(VcsError::InvalidDiffOutput { line: field.to_owned() });
                }
                out.push(path);
            }
            DiffStatus::CopyRow => {
                // C<score> rows: source in next field, destination in the one
                // after. We must include BOTH (§2.5.8 conservative rule).
                let src = iter.next().ok_or_else(|| VcsError::InvalidDiffOutput {
                    line: format!("{status} (missing source path)"),
                })?;
                let dst = iter.next().ok_or_else(|| VcsError::InvalidDiffOutput {
                    line: format!("{status} (missing destination path)"),
                })?;
                if src.is_empty() || dst.is_empty() {
                    return Err(VcsError::InvalidDiffOutput {
                        line: format!("{status} src={src:?} dst={dst:?}"),
                    });
                }
                out.push(src.to_owned());
                out.push(dst.to_owned());
            }
            DiffStatus::Unmerged => {
                let p = path_in_same_field.unwrap_or_default();
                return Err(VcsError::UnmergedPaths { path: p });
            }
            DiffStatus::Rename => {
                return Err(VcsError::UnexpectedRenameRow {
                    line: format!("{status}\t{path_in_same_field:?}"),
                });
            }
            DiffStatus::Invalid => {
                return Err(VcsError::InvalidDiffOutput {
                    line: format!("{status}\t{path_in_same_field:?}"),
                });
            }
        }
    }
    Ok(out)
}

/// Apply the post-processing rules: strip leading `./`, reject `..`
/// components, reject absolute paths.
fn post_process_path(raw: &str) -> Result<PathBuf, VcsError> {
    let trimmed = raw.strip_prefix("./").unwrap_or(raw);

    if trimmed.starts_with('/') {
        return Err(VcsError::PathTraversalDetected { path: raw.to_owned() });
    }
    // Reject `..` as a path component (not a substring — `foo..bar` is fine).
    let pb = PathBuf::from(trimmed);
    if pb.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(VcsError::PathTraversalDetected { path: raw.to_owned() });
    }
    Ok(pb)
}

/// Classification of a `--name-status` status code per §2.5.8.
#[derive(Debug, PartialEq, Eq)]
enum DiffStatus {
    /// A, M, D, T — one path in column 2.
    SinglePath,
    /// C<score> — two paths (source + destination), both included.
    CopyRow,
    /// U — unmerged file; intent must be rejected.
    Unmerged,
    /// R<score> — rename; should never appear with --no-renames.
    Rename,
    /// Anything else (X, B, malformed, unknown).
    Invalid,
}

/// Map a status code string ("A", "M100", "C75", "U", …) to its category.
fn classify_status(code: &str) -> DiffStatus {
    let first = match code.chars().next() {
        Some(c) => c,
        None => return DiffStatus::Invalid,
    };
    match first {
        'A' | 'M' | 'D' | 'T' => DiffStatus::SinglePath,
        'C' => DiffStatus::CopyRow,
        'U' => DiffStatus::Unmerged,
        'R' => DiffStatus::Rename,
        _ => DiffStatus::Invalid,
    }
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

    // Surface a parse failure as a real error — `unwrap_or(0)` would silently
    // pass a malformed git response and let merge commits sneak through. If
    // git ever returns non-numeric output (different version, broken locale,
    // etc.) we'd rather fail loudly.
    let trimmed = stdout.trim();
    let count: u64 = trimmed.parse().map_err(|e| VcsError::GitError {
        message: format!("rev-list --count returned non-numeric output {trimmed:?}: {e}"),
    })?;
    if count > 0 {
        return Err(VcsError::MergeCommitInRange { merge_count: count });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests — exercise the CommitSha validator and the diff-output parser.
//
// We do NOT spawn git here; the parser is pure and the integration tests
// for the live `git` invocation belong in `kernel/tests/vcs_integration.rs`
// (added by PR-7 follow-up if/when we want a git fixture).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── CommitSha ────────────────────────────────────────────────────────

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

    // ── classify_status ──────────────────────────────────────────────────

    #[test]
    fn classify_status_canonical_letters() {
        assert_eq!(classify_status("A"), DiffStatus::SinglePath);
        assert_eq!(classify_status("M"), DiffStatus::SinglePath);
        assert_eq!(classify_status("D"), DiffStatus::SinglePath);
        assert_eq!(classify_status("T"), DiffStatus::SinglePath);
        assert_eq!(classify_status("M100"), DiffStatus::SinglePath);
        assert_eq!(classify_status("C75"), DiffStatus::CopyRow);
        assert_eq!(classify_status("U"), DiffStatus::Unmerged);
        assert_eq!(classify_status("R90"), DiffStatus::Rename);
        assert_eq!(classify_status("X"), DiffStatus::Invalid);
        assert_eq!(classify_status("B"), DiffStatus::Invalid);
        assert_eq!(classify_status(""), DiffStatus::Invalid);
        assert_eq!(classify_status("?"), DiffStatus::Invalid);
    }

    // ── post_process_path ────────────────────────────────────────────────

    #[test]
    fn post_process_strips_leading_dot_slash() {
        let p = post_process_path("./src/foo.rs").unwrap();
        assert_eq!(p, PathBuf::from("src/foo.rs"));
    }

    #[test]
    fn post_process_keeps_normal_paths() {
        let p = post_process_path("a/b/c.txt").unwrap();
        assert_eq!(p, PathBuf::from("a/b/c.txt"));
    }

    #[test]
    fn post_process_rejects_absolute_path() {
        let err = post_process_path("/etc/passwd").unwrap_err();
        assert!(matches!(err, VcsError::PathTraversalDetected { .. }));
    }

    #[test]
    fn post_process_rejects_dotdot_component() {
        let err = post_process_path("foo/../bar").unwrap_err();
        assert!(matches!(err, VcsError::PathTraversalDetected { .. }));
    }

    #[test]
    fn post_process_allows_dotdot_substring_in_filename() {
        // A filename containing `..` as part of a name (not as a component)
        // is fine — `foo..bar` is a valid filename, not a parent reference.
        let p = post_process_path("dir/foo..bar.rs").unwrap();
        assert_eq!(p, PathBuf::from("dir/foo..bar.rs"));
    }

    // ── parse_name_status_z ──────────────────────────────────────────────

    /// Simulate `git diff --name-status -z` for the canonical happy path:
    /// added, modified, deleted, type-change. All four are included, with
    /// deletions kept (per the spec table — `D` is included for path-scope
    /// enforcement; the earlier `compute` dropped them, which was a bug).
    #[test]
    fn parse_z_canonical_single_path_rows() {
        let stdout = "A\tsrc/added.rs\0M\tsrc/modified.rs\0D\tsrc/deleted.rs\0T\tsrc/type_change.rs\0";
        let paths = parse_name_status_z(stdout).unwrap();
        assert_eq!(
            paths,
            vec![
                "src/added.rs",
                "src/modified.rs",
                "src/deleted.rs",
                "src/type_change.rs",
            ]
        );
    }

    /// `M100` (modified with similarity score 100) must classify as
    /// SinglePath — the score suffix is informational and varies by git
    /// version. Regression guard against the earlier `status.starts_with('D')`
    /// pattern that did not handle suffix-bearing codes.
    #[test]
    fn parse_z_handles_score_suffix_on_modified() {
        let stdout = "M100\tsrc/foo.rs\0";
        let paths = parse_name_status_z(stdout).unwrap();
        assert_eq!(paths, vec!["src/foo.rs"]);
    }

    /// Copy rows produce TWO entries (source AND destination), both passed
    /// through to `effective_allow`. Spec: §2.5.8 conservative rule.
    #[test]
    fn parse_z_copy_row_produces_both_paths() {
        let stdout = "C75\0src/orig.rs\0src/copy.rs\0";
        let paths = parse_name_status_z(stdout).unwrap();
        assert_eq!(paths, vec!["src/orig.rs", "src/copy.rs"]);
    }

    /// Unmerged paths are a hard reject — UnmergedPaths variant.
    #[test]
    fn parse_z_unmerged_is_rejected() {
        let stdout = "U\tsrc/conflict.rs\0";
        let err = parse_name_status_z(stdout).unwrap_err();
        match err {
            VcsError::UnmergedPaths { path } => assert_eq!(path, "src/conflict.rs"),
            other => panic!("expected UnmergedPaths, got {other:?}"),
        }
    }

    /// Rename rows must never appear because we always pass `--no-renames`;
    /// if they do it's a kernel bug. Surfaces as `UnexpectedRenameRow`.
    #[test]
    fn parse_z_rename_row_is_rejected_as_kernel_bug() {
        let stdout = "R85\tsrc/old.rs\0";
        let err = parse_name_status_z(stdout).unwrap_err();
        assert!(matches!(err, VcsError::UnexpectedRenameRow { .. }));
    }

    /// Unknown / malformed status codes (`X`, `B`, etc.) are rejected as
    /// `InvalidDiffOutput` — we never silently include or drop them.
    #[test]
    fn parse_z_unknown_status_is_invalid() {
        for bad in ["X\tfoo.rs\0", "B\tfoo.rs\0", "?\tfoo.rs\0"] {
            let err = parse_name_status_z(bad).unwrap_err();
            assert!(
                matches!(err, VcsError::InvalidDiffOutput { .. }),
                "expected InvalidDiffOutput for {bad:?}, got {err:?}"
            );
        }
    }

    /// Mixed-format output containing a path with `\t` in the body parses
    /// correctly thanks to `-z`. Names with embedded tabs are rare but legal
    /// in git; this is the regression guard.
    #[test]
    fn parse_z_tolerates_tab_in_filename() {
        // `weird\tname.rs` after the status's tab.
        let stdout = "M\tweird\tname.rs\0";
        let paths = parse_name_status_z(stdout).unwrap();
        assert_eq!(paths, vec!["weird\tname.rs"]);
    }

    /// Empty input (no diff rows) is the valid "no changes" case.
    #[test]
    fn parse_z_empty_returns_empty_vec() {
        assert!(parse_name_status_z("").unwrap().is_empty());
    }

    /// Trailing NUL after the last record — emitted by some git versions —
    /// must NOT cause a parse failure or an empty-string entry.
    #[test]
    fn parse_z_trailing_nul_is_tolerated() {
        let stdout = "M\tsrc/foo.rs\0\0";
        let paths = parse_name_status_z(stdout).unwrap();
        assert_eq!(paths, vec!["src/foo.rs"]);
    }
}
