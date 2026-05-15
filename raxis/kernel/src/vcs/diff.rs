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
        &[
            "diff",
            base_sha.as_str(),
            head_sha.as_str(),
            "--name-only",
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
/// `-z` framing (verified empirically against git 2.39+; matches the
/// `git-diff(1)` man page entry for `-z` under `--raw`/`--name-status`):
///
///   - A/M/D/T row : `<status>\0<path>\0`            — TWO fields
///   - `C<score>`    : `<status>\0<src>\0<dst>\0`      — THREE fields
///   - `R<score>`    : `<status>\0<src>\0<dst>\0`      — THREE (rejected: --no-renames)
///   - U           : `<status>\0<path>\0`            — TWO fields (rejected: unmerged)
///
/// **Important:** `-z` does NOT keep the `<status>\t<path>` shape that
/// the no-`-z` form uses. Every field — status, path, src, dst — is its
/// own NUL-separated record. An earlier version of this parser assumed
/// the `\t` separator was preserved under `-z`, which made `compute()`
/// reject every real git diff with `InvalidDiffOutput`. The integration
/// tests in `git_integration` below caught the bug.
///
/// NUL terminators preserve paths containing `\t`, `\n`, or quotes —
/// hence why `-z` is used in the first place.
fn parse_name_status_z(stdout: &str) -> Result<Vec<String>, VcsError> {
    let mut out = Vec::new();
    // `-z` always terminates fields with `\0`, including the LAST one,
    // so `split('\0')` yields a trailing empty string we must ignore.
    let mut iter = stdout.split('\0').peekable();

    while let Some(status) = iter.next() {
        if status.is_empty() {
            // Trailing empty field after the last record's terminator,
            // OR a back-to-back `\0\0` pair (which some git versions emit
            // at end-of-stream). Either way: skip until we either find a
            // non-empty status or exhaust the iterator.
            if iter.peek().is_none() {
                break;
            }
            continue;
        }

        match classify_status(status) {
            DiffStatus::SinglePath => {
                let path =
                    next_nonempty_field(&mut iter).ok_or_else(|| VcsError::InvalidDiffOutput {
                        line: format!("{status} (missing path field)"),
                    })?;
                out.push(path);
            }
            DiffStatus::CopyRow => {
                // C<score> rows: source in next field, destination in the one
                // after. We must include BOTH (§2.5.8 conservative rule).
                let src =
                    next_nonempty_field(&mut iter).ok_or_else(|| VcsError::InvalidDiffOutput {
                        line: format!("{status} (missing source path)"),
                    })?;
                let dst =
                    next_nonempty_field(&mut iter).ok_or_else(|| VcsError::InvalidDiffOutput {
                        line: format!("{status} (missing destination path)"),
                    })?;
                out.push(src);
                out.push(dst);
            }
            DiffStatus::Unmerged => {
                // The unmerged row's path field still follows on the wire
                // (per the `-z` framing); pull it so the error message is
                // useful, but do not let a missing field hide the violation.
                let path = next_nonempty_field(&mut iter).unwrap_or_default();
                return Err(VcsError::UnmergedPaths { path });
            }
            DiffStatus::Rename => {
                // Rename rows emit src + dst like copy rows. Drain both so
                // the error report can name them — easier debugging than
                // a bare "rename" message.
                let src = next_nonempty_field(&mut iter).unwrap_or_default();
                let dst = next_nonempty_field(&mut iter).unwrap_or_default();
                return Err(VcsError::UnexpectedRenameRow {
                    line: format!("{status}\t{src:?} -> {dst:?}"),
                });
            }
            DiffStatus::Invalid => {
                return Err(VcsError::InvalidDiffOutput {
                    line: status.to_owned(),
                });
            }
        }
    }
    Ok(out)
}

/// Pull the next field from the iterator, skipping over leading empty
/// fields (which can happen if the stream contains stray `\0\0`).
/// Returns `None` only if the iterator is fully exhausted.
fn next_nonempty_field<'a, I: Iterator<Item = &'a str>>(iter: &mut I) -> Option<String> {
    for f in iter {
        if !f.is_empty() {
            return Some(f.to_owned());
        }
    }
    None
}

/// Apply the post-processing rules: strip leading `./`, reject `..`
/// components, reject absolute paths.
fn post_process_path(raw: &str) -> Result<PathBuf, VcsError> {
    let trimmed = raw.strip_prefix("./").unwrap_or(raw);

    if trimmed.starts_with('/') {
        return Err(VcsError::PathTraversalDetected {
            path: raw.to_owned(),
        });
    }
    // Reject `..` as a path component (not a substring — `foo..bar` is fine).
    let pb = PathBuf::from(trimmed);
    if pb
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(VcsError::PathTraversalDetected {
            path: raw.to_owned(),
        });
    }
    Ok(pb)
}

/// Classification of a `--name-status` status code per §2.5.8.
#[derive(Debug, PartialEq, Eq)]
enum DiffStatus {
    /// A, M, D, T — one path in column 2.
    SinglePath,
    /// `C<score>` — two paths (source + destination), both included.
    CopyRow,
    /// U — unmerged file; intent must be rejected.
    Unmerged,
    /// `R<score>` — rename; should never appear with --no-renames.
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
        &[
            "merge-base",
            "--is-ancestor",
            base_sha.as_str(),
            head_sha.as_str(),
        ],
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
pub fn rev_parse_parent(head_sha: &CommitSha, worktree_root: &Path) -> Result<CommitSha, VcsError> {
    let timeout = vcs_timeout();
    let ref_arg = format!("{}^1", head_sha.as_str());
    let (stdout, stderr, code) =
        run_git(&["rev-parse", "--verify", &ref_arg], worktree_root, timeout)?;

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
    if stderr_lower.contains("needed a single revision")
        || stderr_lower.contains("not a valid object name")
    {
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
        assert!(sha
            .as_str()
            .chars()
            .all(|c| c.is_lowercase() || c.is_ascii_digit()));
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

    // ── parse_name_status_z fixtures ─────────────────────────────────────
    //
    // The byte shapes below were captured from real `git diff -z` output
    // (verified against git 2.39+ and cross-checked with the integration
    // tests in `git_integration` below). Every fixture uses the
    // `<status>\0<path>\0` framing that real git emits — NEVER the
    // `<status>\t<path>\0` shape that an earlier version of this parser
    // (and these tests!) incorrectly assumed. See the parser doc comment
    // for the full framing rules.

    /// Canonical happy path: A / M / D / T rows. Deletions are KEPT
    /// (per §2.5.8 — D is in scope for path enforcement; an earlier
    /// `compute` dropped them, which was a bug).
    #[test]
    fn parse_z_canonical_single_path_rows() {
        let stdout =
            "A\0src/added.rs\0M\0src/modified.rs\0D\0src/deleted.rs\0T\0src/type_change.rs\0";
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
        let stdout = "M100\0src/foo.rs\0";
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
        let stdout = "U\0src/conflict.rs\0";
        let err = parse_name_status_z(stdout).unwrap_err();
        match err {
            VcsError::UnmergedPaths { path } => assert_eq!(path, "src/conflict.rs"),
            other => panic!("expected UnmergedPaths, got {other:?}"),
        }
    }

    /// Rename rows must never appear because we always pass `--no-renames`;
    /// if they do it's a kernel bug. Surfaces as `UnexpectedRenameRow`.
    /// Real `-z` rename rows have THREE fields (status, src, dst).
    #[test]
    fn parse_z_rename_row_is_rejected_as_kernel_bug() {
        let stdout = "R85\0src/old.rs\0src/new.rs\0";
        let err = parse_name_status_z(stdout).unwrap_err();
        assert!(matches!(err, VcsError::UnexpectedRenameRow { .. }));
    }

    /// Unknown / malformed status codes (`X`, `B`, etc.) are rejected as
    /// `InvalidDiffOutput` — we never silently include or drop them.
    #[test]
    fn parse_z_unknown_status_is_invalid() {
        for bad in ["X\0foo.rs\0", "B\0foo.rs\0", "?\0foo.rs\0"] {
            let err = parse_name_status_z(bad).unwrap_err();
            assert!(
                matches!(err, VcsError::InvalidDiffOutput { .. }),
                "expected InvalidDiffOutput for {bad:?}, got {err:?}"
            );
        }
    }

    /// Filenames containing `\t` parse correctly — the whole point of
    /// using `-z` is that NUL is the only field separator, so embedded
    /// tabs / newlines / quotes pass through untouched.
    #[test]
    fn parse_z_tolerates_tab_in_filename() {
        let stdout = "M\0weird\tname.rs\0";
        let paths = parse_name_status_z(stdout).unwrap();
        assert_eq!(paths, vec!["weird\tname.rs"]);
    }

    /// Filenames containing `\n` (newline) — also legal in unix, also
    /// preserved by `-z`.
    #[test]
    fn parse_z_tolerates_newline_in_filename() {
        let stdout = "M\0weird\nname.rs\0";
        let paths = parse_name_status_z(stdout).unwrap();
        assert_eq!(paths, vec!["weird\nname.rs"]);
    }

    /// Empty input (no diff rows) is the valid "no changes" case.
    #[test]
    fn parse_z_empty_returns_empty_vec() {
        assert!(parse_name_status_z("").unwrap().is_empty());
    }

    /// Trailing NUL after the last record — always present, since `-z`
    /// terminates every field — must NOT cause a parse failure or
    /// produce an empty-string entry.
    #[test]
    fn parse_z_trailing_nul_is_tolerated() {
        let stdout = "M\0src/foo.rs\0";
        let paths = parse_name_status_z(stdout).unwrap();
        assert_eq!(paths, vec!["src/foo.rs"]);
    }

    /// Defensive: missing path field after a SinglePath status surfaces
    /// `InvalidDiffOutput` rather than silently dropping the row.
    #[test]
    fn parse_z_missing_path_after_status_is_invalid() {
        // "A\0" with no following field: the iterator yields ["A", ""].
        // The trailing "" is ignored as a terminator-only field, so the
        // path lookup fails.
        let stdout = "A\0";
        let err = parse_name_status_z(stdout).unwrap_err();
        assert!(
            matches!(err, VcsError::InvalidDiffOutput { .. }),
            "missing path after status MUST surface InvalidDiffOutput, got {err:?}"
        );
    }

    /// Defensive: copy row with missing destination surfaces
    /// `InvalidDiffOutput` (rather than silently producing only the src).
    #[test]
    fn parse_z_copy_row_missing_destination_is_invalid() {
        let stdout = "C75\0src/orig.rs\0";
        let err = parse_name_status_z(stdout).unwrap_err();
        assert!(
            matches!(err, VcsError::InvalidDiffOutput { .. }),
            "copy row missing destination MUST surface InvalidDiffOutput, got {err:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Integration tests — exercise every public function against a REAL git repo
// generated in a `tempfile::TempDir` and discarded on test completion.
//
// Why not in `kernel/tests/vcs_integration.rs`?
//   `raxis-kernel` is a binary crate (no `[lib]` target), so external
//   integration tests cannot import `raxis_kernel::vcs::diff`. Living in
//   `#[cfg(test)] mod ...` here gives the integration tests the same
//   `super::*` access the parser tests use, while still exercising the
//   real `git` subprocess path the parser tests deliberately skip.
//
// Skip behaviour:
//   Every test calls `skip_if_no_git()` first so hosts without `git` on
//   PATH simply log "SKIP" and pass. We never panic on a host-property
//   issue.
//
// Determinism:
//   `GitRepo` fixes `user.email`/`user.name`/`commit.gpgsign=false`/
//   `core.autocrlf=false` and pins the initial branch to `main` via
//   `symbolic-ref`. Commit timestamps still vary (git uses wall time),
//   so we never assert on SHAs themselves — only on diff output, ancestry
//   relationships, and merge-commit counts.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod git_integration {
    use super::*;
    use raxis_test_support::{git_available, GitRepo};

    /// Skip helper — every test starts with this. Returning early on a
    /// missing git binary keeps the test green on minimal CI images.
    fn skip_if_no_git() -> bool {
        if !git_available() {
            eprintln!("SKIP: git binary not available on PATH");
            return true;
        }
        false
    }

    /// Promote a `GitRepo`-returned hex string into the typed `CommitSha`.
    /// The fixture already validates 40-char lowercase hex, so this is
    /// just a wrapping convenience.
    fn sha(s: &str) -> CommitSha {
        CommitSha::new(s).expect("GitRepo handed back an invalid SHA — fixture bug")
    }

    // ── touched_paths ────────────────────────────────────────────────────

    #[test]
    fn touched_paths_returns_added_modified_and_deleted() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let base_hex = repo.commit_files(
            &[("a.txt", "1"), ("b.txt", "2"), ("doomed.txt", "3")],
            "base: a, b, doomed",
        );
        let _ = repo.delete_file_commit("doomed.txt", "delete doomed");
        let _ = repo.commit_file("a.txt", "MODIFIED", "modify a");
        let head_hex = repo.commit_file("c.txt", "C", "add c");

        let paths = touched_paths(&sha(&base_hex), &sha(&head_hex), repo.path())
            .expect("touched_paths must succeed on a valid range");

        // Sorted; includes A (c.txt), M (a.txt), D (doomed.txt). b.txt is
        // unchanged and must NOT appear.
        assert_eq!(
            paths,
            vec![
                PathBuf::from("a.txt"),
                PathBuf::from("c.txt"),
                PathBuf::from("doomed.txt"),
            ],
            "touched_paths must include A+M+D and exclude unchanged paths"
        );
    }

    #[test]
    fn touched_paths_empty_for_identical_shas() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let only = repo.commit_file("x.txt", "x", "init");
        let paths = touched_paths(&sha(&only), &sha(&only), repo.path()).unwrap();
        assert!(
            paths.is_empty(),
            "diff of a SHA against itself must be empty"
        );
    }

    #[test]
    fn touched_paths_rejects_unknown_sha() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let real = repo.commit_file("a.txt", "x", "init");
        let bogus = sha(&"f".repeat(40));
        let err = touched_paths(&sha(&real), &bogus, repo.path()).unwrap_err();
        assert!(
            matches!(err, VcsError::DiffFailed { .. }),
            "diff against unknown SHA must surface DiffFailed, got {err:?}"
        );
    }

    // ── compute (the canonical -z parser path) ────────────────────────────

    #[test]
    fn compute_returns_post_processed_sorted_unique_paths() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let base = repo.commit_files(&[("z.txt", "z"), ("dir/y.txt", "y")], "base");
        // Mix: add new file, modify existing in subdir, delete top-level.
        std::fs::write(repo.path().join("dir/y.txt"), "modified").expect("write modify");
        std::fs::create_dir_all(repo.path().join("dir/sub")).unwrap();
        std::fs::write(repo.path().join("dir/sub/new.txt"), "n").unwrap();
        let _ = repo.commit_files(
            &[("dir/y.txt", "modified"), ("dir/sub/new.txt", "n")],
            "modify y, add sub/new",
        );
        let head = repo.delete_file_commit("z.txt", "delete z");

        let paths = compute(&sha(&base), &sha(&head), repo.path()).expect("compute must succeed");

        // Sorted lexicographically, unique. dir/sub/new (A), dir/y (M),
        // z (D). Subdirectory paths must NOT have leading `./` after
        // post-processing.
        assert_eq!(
            paths,
            vec![
                PathBuf::from("dir/sub/new.txt"),
                PathBuf::from("dir/y.txt"),
                PathBuf::from("z.txt"),
            ],
        );
    }

    #[test]
    fn compute_empty_diff_returns_empty_vec() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let only = repo.commit_file("a.txt", "x", "init");
        let paths = compute(&sha(&only), &sha(&only), repo.path()).unwrap();
        assert!(paths.is_empty());
    }

    #[test]
    fn compute_includes_deletion_rows() {
        // Regression guard: an earlier `compute` implementation dropped D
        // rows entirely, which would silently widen `effective_allow`
        // checks (a deleted file outside the allowlist would not flag).
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let base = repo.commit_files(&[("keep.txt", "k"), ("gone.txt", "g")], "base");
        let head = repo.delete_file_commit("gone.txt", "delete gone");

        let paths = compute(&sha(&base), &sha(&head), repo.path()).unwrap();
        assert_eq!(
            paths,
            vec![PathBuf::from("gone.txt")],
            "D rows MUST be included — deletions are subject to path scope"
        );
    }

    // ── is_ancestor ──────────────────────────────────────────────────────

    #[test]
    fn is_ancestor_true_for_strict_ancestor() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let a = repo.commit_file("1.txt", "1", "first");
        let b = repo.commit_file("2.txt", "2", "second");
        assert!(is_ancestor(&sha(&a), &sha(&b), repo.path()).unwrap());
    }

    #[test]
    fn is_ancestor_true_for_same_commit() {
        // git treats a commit as an ancestor of itself (exit 0).
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let a = repo.commit_file("1.txt", "1", "first");
        assert!(
            is_ancestor(&sha(&a), &sha(&a), repo.path()).unwrap(),
            "a commit MUST be its own ancestor (git contract)"
        );
    }

    #[test]
    fn is_ancestor_false_for_unrelated_branch_tips() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let _ = repo.commit_file("base.txt", "0", "base");
        repo.create_branch("feature");
        let feature_tip = repo.commit_file("feat.txt", "F", "feature work");
        repo.checkout("main");
        let main_tip = repo.commit_file("main.txt", "M", "main work");

        // feature_tip is not an ancestor of main_tip (diverged).
        assert!(!is_ancestor(&sha(&feature_tip), &sha(&main_tip), repo.path()).unwrap());
        assert!(!is_ancestor(&sha(&main_tip), &sha(&feature_tip), repo.path()).unwrap());
    }

    // ── rev_parse_parent ─────────────────────────────────────────────────

    #[test]
    fn rev_parse_parent_returns_first_parent() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let parent_hex = repo.commit_file("a.txt", "1", "first");
        let child_hex = repo.commit_file("b.txt", "2", "second");
        let parent_resolved = rev_parse_parent(&sha(&child_hex), repo.path()).unwrap();
        assert_eq!(parent_resolved.as_str(), parent_hex);
    }

    #[test]
    fn rev_parse_parent_on_root_commit_returns_head_is_root_commit() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let root = repo.commit_file("a.txt", "1", "root");
        let err = rev_parse_parent(&sha(&root), repo.path()).unwrap_err();
        assert!(
            matches!(
                err,
                VcsError::HeadIsRootCommit | VcsError::ShaNotFound { .. }
            ),
            "root commit MUST surface as HeadIsRootCommit (preferred) or ShaNotFound \
             depending on git version, got {err:?}"
        );
    }

    #[test]
    fn rev_parse_parent_unknown_sha_surfaces_typed_error() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let _ = repo.commit_file("a.txt", "x", "init");
        let bogus = sha(&"e".repeat(40));
        let err = rev_parse_parent(&bogus, repo.path()).unwrap_err();
        assert!(
            matches!(
                err,
                VcsError::ShaNotFound { .. }
                    | VcsError::HeadIsRootCommit
                    | VcsError::GitError { .. }
            ),
            "unknown SHA MUST surface a typed error, got {err:?}"
        );
    }

    // ── topology_check ───────────────────────────────────────────────────

    #[test]
    fn topology_check_passes_on_linear_history() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let base = repo.commit_file("a.txt", "1", "first");
        let head = repo.commit_file("b.txt", "2", "second");
        topology_check(&sha(&base), &sha(&head), repo.path())
            .expect("linear history must pass topology_check");
    }

    #[test]
    fn topology_check_passes_on_empty_range() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let only = repo.commit_file("a.txt", "1", "init");
        topology_check(&sha(&only), &sha(&only), repo.path())
            .expect("empty range MUST pass topology_check (zero merges = clean)");
    }

    #[test]
    fn topology_check_rejects_merge_commit_in_range() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let base = repo.commit_file("base.txt", "0", "base");
        repo.create_branch("feature");
        repo.commit_file("feat.txt", "F", "on feature");
        repo.checkout("main");
        repo.commit_file("main.txt", "M", "on main");
        let merge = repo.merge_no_ff("feature", "merge feature");

        let err = topology_check(&sha(&base), &sha(&merge), repo.path()).unwrap_err();
        match err {
            VcsError::MergeCommitInRange { merge_count } => {
                assert_eq!(
                    merge_count, 1,
                    "exactly one merge commit (--no-ff) was created"
                );
            }
            other => panic!("expected MergeCommitInRange, got {other:?}"),
        }
    }

    // ── End-to-end: real diff → check_paths (path-scope smoke) ───────────
    //
    // Demonstrates the fixture's value beyond `vcs::diff` itself: any
    // path-scope test that wants real diff input rather than a synthetic
    // `Vec<PathBuf>` builds on the same `GitRepo` fixture.

    #[test]
    fn end_to_end_compute_then_check_paths_against_glob_allowlist() {
        if skip_if_no_git() {
            return;
        }
        let repo = GitRepo::init();
        let base = repo.commit_file("src/lib.rs", "fn main(){}", "init src/lib.rs");

        // Make a change strictly inside src/ — should be allowed by a
        // `src/**` allowlist.
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/util.rs"), "// util").unwrap();
        let head_in_scope =
            repo.commit_files(&[("src/util.rs", "// util")], "add src/util.rs (in scope)");

        let in_scope_paths = compute(&sha(&base), &sha(&head_in_scope), repo.path())
            .expect("compute on in-scope diff must succeed");
        assert_eq!(in_scope_paths, vec![PathBuf::from("src/util.rs")]);

        // Verify the path matches the glob pattern `src/**`. We use the
        // raw `glob` crate the same way `path_scope::AllowSet` does, so
        // this test pins the same matching semantics path-scope enforces.
        let pat = glob::Pattern::new("src/**").expect("glob compile");
        for p in &in_scope_paths {
            assert!(
                pat.matches_path(p),
                "in-scope path {p:?} MUST match the glob {pat:?}"
            );
        }

        // Now make a change OUTSIDE src/ — should NOT match the allowlist.
        std::fs::write(repo.path().join("README.md"), "outside scope").unwrap();
        let head_out_of_scope = repo.commit_files(
            &[("README.md", "outside scope")],
            "add README.md (out of scope)",
        );

        let out_of_scope_paths = compute(&sha(&base), &sha(&head_out_of_scope), repo.path())
            .expect("compute on out-of-scope diff must succeed");
        // Range covers BOTH commits (in_scope + out_of_scope), so both paths
        // appear; that's intentional — we want to assert that path-scope
        // enforcement, when fed real diff output, sees the violator.
        assert!(out_of_scope_paths.contains(&PathBuf::from("README.md")));
        let any_violation = out_of_scope_paths.iter().any(|p| !pat.matches_path(p));
        assert!(
            any_violation,
            "real-diff path-scope smoke MUST find at least one path outside `src/**`"
        );
    }
}
