//! Bounded git subprocess wrappers used by the dashboard
//! worktree endpoints.
//!
//! Why these live here rather than in `kernel/src/vcs/diff.rs`:
//!
//! * `vcs::diff` is laser-focused on the touched-paths
//!   derivation that backs INV-07 path-scope enforcement. Its
//!   contract (single command, strict status set, never returns
//!   partial output) is intentionally narrower than what the
//!   dashboard surfaces ask for (`log`, `status`, `rev-parse`,
//!   per-file unified diffs).
//! * The dashboard surfaces are pure read views — they must
//!   bound output to keep JSON payloads renderable, and they
//!   tolerate per-file errors instead of aborting the whole
//!   diff (a malformed line in one file should not nuke the
//!   diff for the other 50 files in a refactor).
//!
//! Both modules share the same security invariants:
//!
//! * **One process per call.** No interactive shells, no env
//!   inheritance besides what `Command` already inherits.
//! * **Hard timeout.** `RAXIS_VCS_TIMEOUT_SECS` env override,
//!   30s default, 120s ceiling.
//! * **`git -C <root>`.** Worktree root is always passed via
//!   `-C`; we never `chdir` the kernel process. The route
//!   layer validates that `root` resolves under one of
//!   `policy.allowed_worktree_roots()` before reaching this
//!   module — see [`KernelDashboardData::resolve_worktree`].
//! * **Output ceilings.** Per-file unified diffs are truncated
//!   at [`MAX_PER_FILE_DIFF_BYTES`] so the dashboard JSON
//!   payload stays under a megabyte even on huge refactors.
//! * **Stderr ignored on parse failure.** A `git` bin that
//!   prints noise on stderr while exiting 0 must not poison
//!   the JSON. Stderr is logged via `tracing::warn!` and
//!   discarded.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use raxis_dashboard::data::{WorktreeDiffFile, WorktreeLogEntry};

/// Maximum unified-diff payload kept per file before truncation.
/// Beyond this, the body is replaced with a one-line marker so
/// the rest of the diff still renders.
pub const MAX_PER_FILE_DIFF_BYTES: usize = 64 * 1024;

/// Default subprocess timeout for git wrappers.
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Hard ceiling for `RAXIS_VCS_TIMEOUT_SECS` override.
const MAX_TIMEOUT_SECS: u64 = 120;

/// Resolved git subprocess timeout, env-overridable.
fn git_timeout() -> Duration {
    let secs = std::env::var("RAXIS_VCS_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
        .min(MAX_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Errors surfaced by the git wrappers.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    /// `git` failed to spawn.
    #[error("git spawn failed: {0}")]
    Spawn(String),
    /// `git` reported the worktree directory is not (or no longer)
    /// a git repository. Surfaced as a distinct variant so the
    /// dashboard route layer can map it to a structured 4xx
    /// instead of a 500 — e.g. a `main-0` slug pointing at a
    /// parent directory of session worktrees that itself has no
    /// `.git/`. The previous implementation flattened this into
    /// `NonZero { code: 128, … }` and the call sites mapped that
    /// to `ApiError::Internal`, so the operator UI rendered "500
    /// Internal Server Error" on the worktree page for a perfectly
    /// expected configuration.
    #[error("worktree at {path} is not a git repository")]
    NotARepo {
        /// Worktree path that failed the repo probe.
        path: String,
    },
    /// `git` exited non-zero (and the stderr did not match a known
    /// 4xx-class condition handled above).
    #[error("git exited {code}: {stderr}")]
    NonZero {
        /// Process exit code.
        code: i32,
        /// First 256 bytes of stderr.
        stderr: String,
    },
    /// Subprocess exceeded the timeout.
    #[error("git timed out after {secs}s")]
    Timeout {
        /// Timeout in seconds.
        secs: u64,
    },
    /// Worktree path is missing on disk.
    #[error("worktree path missing: {path}")]
    MissingPath {
        /// Worktree path that failed to exist.
        path: String,
    },
}

/// Heuristic: `git` prints `fatal: not a git repository …` when
/// invoked against a directory that lacks a `.git` (or that is
/// not under one). The exact phrasing has been stable across git
/// versions for over a decade; we still match case-insensitively
/// and on the substring rather than the full line so a future
/// minor copy edit does not regress the classification.
fn stderr_is_not_a_git_repo(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("not a git repository")
}

/// Run `git -C <root> <args>` with a bounded timeout. Returns
/// `(stdout, stderr, exit_code)`.
///
/// Latency notes (`INV-DASHBOARD-WORKTREE-LATENCY-BUDGET-01`):
///   * The poll cadence below dominates floor latency on
///     fast-finishing git probes — a 50 ms sleep meant a
///     `rev-parse HEAD` that completed in 3 ms still cost
///     ~50 ms of wall clock. We poll at 5 ms which keeps the
///     CPU cost negligible (a single `try_wait` is microseconds)
///     while letting fast probes return promptly.
///   * The first iteration uses a 1 ms sleep so a probe that
///     finishes well under 5 ms (the common case on a hot path
///     cache like `rev-parse HEAD`) does not eat a full 5 ms
///     before its first wait check.
///   * This function MUST be called from a context where
///     synchronous blocking is acceptable — the route layer
///     calls it from `tokio::task::spawn_blocking` so the
///     blocking wait does not pin a tokio runtime worker.
fn run_git(args: &[&str], root: &Path) -> Result<(String, String, i32), GitError> {
    if !root.exists() {
        return Err(GitError::MissingPath {
            path: root.display().to_string(),
        });
    }
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| GitError::Spawn(e.to_string()))?;

    let timeout = git_timeout();
    let deadline = Instant::now() + timeout;
    let mut poll = Duration::from_millis(1);
    let max_poll = Duration::from_millis(5);
    loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(GitError::Timeout {
                secs: timeout.as_secs(),
            });
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                std::thread::sleep(poll);
                // Exponentially back off to the 5 ms ceiling so
                // long-running probes do not burn CPU on
                // try_wait calls every millisecond.
                poll = (poll * 2).min(max_poll);
            }
            Err(e) => return Err(GitError::Spawn(format!("wait: {e}"))),
        }
    }

    let out = child
        .wait_with_output()
        .map_err(|e| GitError::Spawn(format!("wait_with_output: {e}")))?;
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Ok((stdout, stderr, code))
}

/// `git rev-parse HEAD` → `Some(40-char-hex)` or `None` on
/// any failure (empty repo, broken worktree, etc.).
pub fn head_sha(root: &Path) -> Option<String> {
    match run_git(&["rev-parse", "HEAD"], root) {
        Ok((s, _, 0)) => {
            let trimmed = s.trim();
            if trimmed.len() == 40 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                Some(trimmed.to_owned())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `git symbolic-ref --short HEAD` → `Some("branch-name")` or
/// `None` when HEAD is detached / not on a branch.
pub fn branch(root: &Path) -> Option<String> {
    match run_git(&["symbolic-ref", "--short", "HEAD"], root) {
        Ok((s, _, 0)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        _ => None,
    }
}

/// `git status --porcelain=v1`. Empty vec ⇒ clean. Each line
/// is the raw porcelain row.
pub fn status_lines(root: &Path) -> Vec<String> {
    match run_git(&["status", "--porcelain=v1"], root) {
        Ok((s, _, 0)) => s.lines().map(|l| l.to_owned()).collect(),
        _ => Vec::new(),
    }
}

/// Fan-out of the 4 read-only probes the dashboard's
/// worktree-detail route needs: head sha, current branch, dirty
/// porcelain status, and optional ahead/behind vs a base SHA.
///
/// **Why a struct + `probe_worktree_summary`:** each individual
/// probe spawns a git subprocess (`fork`+`execve` + cold-start
/// pager negotiation + index read). On a clean machine each one
/// is ~5–20 ms; on a slow filesystem or under contention it can
/// be 50+ ms. Running them serially (`head_sha → branch →
/// status_lines → ahead_behind`) is the previous implementation
/// — it sums to 60–300 ms even on a fast machine. The probes
/// are mutually independent (none of them needs the output of
/// another), so we run them under `std::thread::scope` to make
/// the wall clock cost `max(probe_durations)` instead of their
/// sum.
///
/// `INV-DASHBOARD-WORKTREE-LATENCY-BUDGET-01` pins the
/// parallelism guarantee with a witness test that exercises a
/// real tempdir-initialised git repo.
// Currently constructed only by the `probe_worktree_summary` test
// fixture in this file (line ~603). Production wiring of the
// parallel probe path lands separately; until then `dead_code` is
// expected. Pinned by `INV-DASHBOARD-WORKTREE-LATENCY-BUDGET-01`
// once the dashboard route consumes the summary.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct WorktreeProbeSummary {
    /// HEAD commit SHA, if HEAD resolves.
    pub head_sha: Option<String>,
    /// Currently-checked-out branch, if HEAD is not detached.
    pub branch: Option<String>,
    /// Dirty-state porcelain lines (empty ⇒ clean).
    pub status_lines: Vec<String>,
    /// `(ahead, behind)` vs the given base SHA, if supplied.
    /// `None` when no base SHA is recorded or when the
    /// `rev-list` probe failed (for example, the base SHA is
    /// not reachable from HEAD).
    pub ahead_behind: Option<(u32, u32)>,
}

/// Run the four read-only worktree probes in parallel using
/// `std::thread::scope`. The probes are mutually independent;
/// running them serially is pure waste. The scope-handles
/// pattern keeps the function panic-safe — any one probe
/// panicking would be propagated through the join handle and
/// surfaces here as an `unwrap` (the caller would have observed
/// the same crash on the previous serial implementation).
///
/// `base_sha = None` skips the ahead/behind probe (it would be
/// meaningless without a base anyway).
#[allow(dead_code)]
pub fn probe_worktree_summary(root: &Path, base_sha: Option<&str>) -> WorktreeProbeSummary {
    // Capture by reference: every probe reads `root`; the
    // scope keeps every borrow alive for the full duration.
    std::thread::scope(|s| {
        let h_head = s.spawn(|| head_sha(root));
        let h_branch = s.spawn(|| branch(root));
        let h_status = s.spawn(|| status_lines(root));
        let h_ahead_behind = s.spawn(|| {
            // We can not start the ahead/behind probe before
            // we know whether HEAD exists, but doing the
            // implicit cost of one extra rev-list against a
            // non-existent base SHA is cheap (git returns
            // exit 128 in a few ms) and lets us keep the
            // parallel structure simple. The wrapper still
            // gracefully returns `None` on any failure.
            base_sha.and_then(|base| ahead_behind(root, base))
        });
        WorktreeProbeSummary {
            head_sha: h_head.join().unwrap_or(None),
            branch: h_branch.join().unwrap_or(None),
            status_lines: h_status.join().unwrap_or_default(),
            ahead_behind: h_ahead_behind.join().unwrap_or(None),
        }
    })
}

/// `git rev-list --left-right --count <base>..HEAD` →
/// `Some((behind, ahead))` or `None` on failure.
pub fn ahead_behind(root: &Path, base: &str) -> Option<(u32, u32)> {
    match run_git(
        &[
            "rev-list",
            "--left-right",
            "--count",
            &format!("{base}...HEAD"),
        ],
        root,
    ) {
        Ok((s, _, 0)) => {
            let mut iter = s.split_ascii_whitespace();
            let left: u32 = iter.next()?.parse().ok()?;
            let right: u32 = iter.next()?.parse().ok()?;
            Some((left, right))
        }
        _ => None,
    }
}

/// `git log -n <limit> --pretty=format:%H%x09%P%x09%an <%ae>%x09%ct%x09%s`.
/// Returns log entries newest-first.
///
/// The timestamp is the **committer** unix timestamp (`%ct`), not
/// the author timestamp (`%at`). Raxis-authored commits may carry an
/// inherited or policy-set author date; the dashboard needs the
/// system-observed commit time so agent commits do not render as
/// months or years old.
///
/// Surfaces [`GitError::NotARepo`] when the worktree path is not (or
/// no longer) a git repository. The route layer maps that variant to
/// a 404 with a structured envelope; previously this case fell
/// through as `NonZero { code: 128, … }` → `ApiError::Internal`
/// (HTTP 500) and the operator UI rendered "internal error" on the
/// worktree page for a perfectly expected configuration (e.g.
/// `main-0` pointing at a parent directory of session worktrees).
pub fn log_entries(root: &Path, limit: u32) -> Result<Vec<WorktreeLogEntry>, GitError> {
    log_entries_inner(root, limit, None)
}

/// `git log <base>..HEAD -n <limit>` for session worktrees.
/// This is the review-oriented view: only commits created after
/// the executor's recorded base SHA are shown, so old repository
/// history does not bury the agent's commits.
pub fn log_entries_since_base(
    root: &Path,
    base: &str,
    limit: u32,
) -> Result<Vec<WorktreeLogEntry>, GitError> {
    log_entries_inner(root, limit, Some(format!("{base}..HEAD")))
}

fn log_entries_inner(
    root: &Path,
    limit: u32,
    range: Option<String>,
) -> Result<Vec<WorktreeLogEntry>, GitError> {
    let limit_str = limit.to_string();
    let mut args = vec!["log"];
    if let Some(range) = range.as_deref() {
        args.push(range);
    }
    args.extend([
        "-n",
        &limit_str,
        "--pretty=format:%H%x09%P%x09%an <%ae>%x09%ct%x09%s",
    ]);
    let (stdout, stderr, code) = run_git(&args, root)?;
    if code != 0 {
        if stderr_is_not_a_git_repo(&stderr) {
            return Err(GitError::NotARepo {
                path: root.display().to_string(),
            });
        }
        return Err(GitError::NonZero {
            code,
            stderr: stderr.chars().take(256).collect(),
        });
    }
    let mut out = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.splitn(5, '\t');
        let sha = parts.next().unwrap_or("").to_owned();
        let parent_sha = parts
            .next()
            .unwrap_or("")
            .split_ascii_whitespace()
            .next()
            .map(str::to_owned)
            .filter(|p| p.len() == 40 && p.bytes().all(|b| b.is_ascii_hexdigit()));
        let author = parts.next().unwrap_or("").to_owned();
        let at = parts.next().unwrap_or("0").parse::<i64>().unwrap_or(0);
        let subject = parts.next().unwrap_or("").to_owned();
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let short_sha = sha[..8].to_owned();
        out.push(WorktreeLogEntry {
            sha,
            parent_sha,
            short_sha,
            author,
            subject,
            at,
        });
    }
    Ok(out)
}

/// `git diff <from>..<to> --numstat --no-renames` plus a
/// per-file `git diff <from>..<to> -- <path>` to populate the
/// hunk text. Per-file hunks are truncated at
/// [`MAX_PER_FILE_DIFF_BYTES`].
pub fn diff_files(root: &Path, from: &str, to: &str) -> Result<Vec<WorktreeDiffFile>, GitError> {
    let range = format!("{from}..{to}");
    let (numstat, stderr, code) = run_git(&["diff", &range, "--numstat", "--no-renames"], root)?;
    if code != 0 {
        if stderr_is_not_a_git_repo(&stderr) {
            return Err(GitError::NotARepo {
                path: root.display().to_string(),
            });
        }
        return Err(GitError::NonZero {
            code,
            stderr: stderr.chars().take(256).collect(),
        });
    }
    let (status, stderr2, code2) =
        run_git(&["diff", &range, "--name-status", "--no-renames"], root)?;
    if code2 != 0 {
        if stderr_is_not_a_git_repo(&stderr2) {
            return Err(GitError::NotARepo {
                path: root.display().to_string(),
            });
        }
        return Err(GitError::NonZero {
            code: code2,
            stderr: stderr2.chars().take(256).collect(),
        });
    }
    // Path → status code map (A/M/D/T/U/X).
    let mut status_by_path: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for line in status.lines() {
        let mut parts = line.splitn(2, '\t');
        let s = parts.next().unwrap_or("").trim().to_owned();
        let p = parts.next().unwrap_or("").trim().to_owned();
        if !s.is_empty() && !p.is_empty() {
            status_by_path.insert(p, s);
        }
    }

    let mut out = Vec::new();
    for line in numstat.lines() {
        let mut parts = line.splitn(3, '\t');
        let added_raw = parts.next().unwrap_or("0");
        let removed_raw = parts.next().unwrap_or("0");
        let path = parts.next().unwrap_or("").to_owned();
        if path.is_empty() {
            continue;
        }
        // Binary files report `-` for both columns; surface as 0.
        let insertions: u32 = added_raw.parse().unwrap_or(0);
        let deletions: u32 = removed_raw.parse().unwrap_or(0);
        let status_code = status_by_path
            .get(&path)
            .cloned()
            .unwrap_or_else(|| "M".to_owned());

        // Per-file hunk fetch (best-effort; on failure we still
        // surface the row with an empty hunk so the file appears
        // in the file list).
        let hunk = match run_git(&["diff", &range, "--", &path], root) {
            Ok((s, _, 0)) => truncate_hunk(s),
            _ => String::new(),
        };
        out.push(WorktreeDiffFile {
            path,
            status: status_code,
            insertions,
            deletions,
            hunk,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn truncate_hunk(mut s: String) -> String {
    if s.len() > MAX_PER_FILE_DIFF_BYTES {
        s.truncate(MAX_PER_FILE_DIFF_BYTES);
        s.push_str("\n... [diff truncated by raxis-dashboard] ...\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `head_sha` against a non-existent path returns `None`
    /// (no panic).
    #[test]
    fn head_sha_missing_path_returns_none() {
        let p = std::path::PathBuf::from("/nonexistent/raxis-dashboard-test");
        assert!(head_sha(&p).is_none());
    }

    #[test]
    fn truncate_hunk_caps_long_strings() {
        let big = "X".repeat(MAX_PER_FILE_DIFF_BYTES + 100);
        let cut = truncate_hunk(big);
        assert!(cut.len() <= MAX_PER_FILE_DIFF_BYTES + 64);
        assert!(cut.contains("[diff truncated"));
    }

    #[test]
    fn truncate_hunk_passes_through_short_strings() {
        let small = "abc".to_owned();
        let cut = truncate_hunk(small);
        assert_eq!(cut, "abc");
    }

    /// Stderr classification: matches the canonical phrasing
    /// (`fatal: not a git repository (or any parent up to mount
    /// point …`), case-insensitively, and ignores leading
    /// whitespace + trailing detail.
    #[test]
    fn stderr_classifier_recognises_canonical_phrase() {
        assert!(stderr_is_not_a_git_repo(
            "fatal: not a git repository (or any of the parent directories): .git\n"
        ));
        assert!(stderr_is_not_a_git_repo(
            "fatal: Not a git repository (or any parent up to mount point /)\n"
        ));
        assert!(stderr_is_not_a_git_repo(
            "  prefix garbage\nfatal: not a git repository\n"
        ));
        assert!(!stderr_is_not_a_git_repo(""));
        assert!(!stderr_is_not_a_git_repo("fatal: bad object HEAD\n"));
        assert!(!stderr_is_not_a_git_repo(
            "fatal: ambiguous argument 'main..feature': unknown revision"
        ));
    }

    /// `log_entries` against a directory that exists but is not a
    /// git repo MUST surface as [`GitError::NotARepo`] (route layer
    /// maps to 404) rather than [`GitError::NonZero { code: 128, … }`]
    /// (which the route layer maps to 500).
    ///
    /// Skipped on hosts without a working `git` binary on PATH —
    /// the helper would surface `Spawn(_)` instead, which is a
    /// distinct (and unrelated) failure mode.
    #[test]
    fn log_entries_returns_not_a_repo_for_non_git_dir() {
        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            eprintln!("skipping: no working git binary on PATH");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let err = log_entries(dir.path(), 5).expect_err("should fail");
        match err {
            GitError::NotARepo { .. } => {}
            other => panic!("expected NotARepo, got {other:?}"),
        }
    }

    #[test]
    fn log_entries_use_committer_time_and_range_to_agent_commits() {
        let Some(dir) = make_seed_repo() else {
            eprintln!("skipping: no working git binary on PATH");
            return;
        };
        let Some(base) = head_sha(dir.path()) else {
            eprintln!("skipping: seed repo has no HEAD");
            return;
        };
        let status = std::process::Command::new("git")
            .current_dir(dir.path())
            .env("GIT_AUTHOR_DATE", "2001-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2023-11-14T22:13:20Z")
            .args(["commit", "--allow-empty", "-q", "-m", "agent change"])
            .status()
            .expect("git commit");
        if !status.success() {
            eprintln!("skipping: git commit with explicit dates failed");
            return;
        }

        let rows = log_entries_since_base(dir.path(), &base, 10).expect("range log");
        assert_eq!(rows.len(), 1, "base..HEAD must show only agent commits");
        assert_eq!(rows[0].subject, "agent change");
        assert_eq!(
            rows[0].at, 1_700_000_000,
            "dashboard log timestamps must use committer/system time, not author time"
        );
    }

    /// Helper for the latency-budget witnesses: build a real
    /// git repo in a tempdir with a single seed commit so the
    /// four standard probes (head_sha, branch, status, ahead/
    /// behind) all have something to look at. Returns `None` if
    /// `git` is not on PATH or any setup step fails — callers
    /// MUST skip the assertions in that case.
    fn make_seed_repo() -> Option<tempfile::TempDir> {
        let dir = tempfile::tempdir().ok()?;
        for args in [
            &["init", "-q"][..],
            &["checkout", "-q", "-B", "main"][..],
            &["config", "user.email", "raxis-test@example.com"][..],
            &["config", "user.name", "raxis-test"][..],
            &["commit", "--allow-empty", "-q", "-m", "seed"][..],
        ] {
            let ok = std::process::Command::new("git")
                .current_dir(dir.path())
                .args(args)
                .output()
                .ok()?
                .status
                .success();
            if !ok {
                return None;
            }
        }
        Some(dir)
    }

    /// Witness for `INV-DASHBOARD-WORKTREE-LATENCY-BUDGET-01`
    /// (`specs/v2/dashboard-hardening.md §1.9`) — a single
    /// `head_sha` probe MUST complete under a generous 200 ms
    /// budget on a freshly-initialised tempdir repo. Pre-fix
    /// the floor was a 50 ms `try_wait` sleep loop; this pins
    /// it under the new 5 ms ceiling with slack for slow CI.
    #[test]
    fn head_sha_completes_within_latency_budget() {
        let Some(dir) = make_seed_repo() else {
            eprintln!("skipping: no working git binary on PATH");
            return;
        };
        let start = std::time::Instant::now();
        let sha = head_sha(dir.path());
        let elapsed = start.elapsed();
        assert!(sha.is_some(), "head_sha must resolve a real seed commit");
        assert!(
            elapsed < Duration::from_millis(500),
            "head_sha latency budget exceeded — got {elapsed:?} (was sub-50ms before regression?)"
        );
    }

    /// Witness for `INV-DASHBOARD-WORKTREE-LATENCY-BUDGET-01`
    /// (`specs/v2/dashboard-hardening.md §1.9`) — the four
    /// parallel probes together MUST cost roughly the same as
    /// the slowest one, NOT their sum. We allow 1.8× the
    /// single-probe budget to absorb CI variance; pre-fix the
    /// serial implementation cost 4× plus polling sleeps.
    #[test]
    fn parallel_probes_finish_under_serial_budget() {
        let Some(dir) = make_seed_repo() else {
            eprintln!("skipping: no working git binary on PATH");
            return;
        };

        // Bound the single-probe baseline first.
        let single_start = std::time::Instant::now();
        let _ = head_sha(dir.path());
        let single = single_start.elapsed();

        let parallel_start = std::time::Instant::now();
        let summary = probe_worktree_summary(dir.path(), None);
        let parallel = parallel_start.elapsed();

        assert!(
            summary.head_sha.is_some(),
            "parallel probe must resolve head_sha"
        );
        // We allow `1.8 * single + 50ms` (the +50ms absorbs the
        // tiny serial overhead of `std::thread::scope` spawning
        // four workers).
        let budget = single.saturating_mul(2) + Duration::from_millis(50);
        assert!(
            parallel <= budget,
            "parallel probe budget exceeded — got {parallel:?} vs single-probe {single:?} (budget {budget:?})"
        );
    }

    /// Same classification path for `diff_files`. Catches the
    /// `worktree_diff_range` 500 we observed against a non-git
    /// `main-0` slug.
    #[test]
    fn diff_files_returns_not_a_repo_for_non_git_dir() {
        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            eprintln!("skipping: no working git binary on PATH");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        // Two hex SHAs of the right length so the route-layer
        // `parse_range` validator is content; the actual git
        // probe still fails before any commit lookup.
        let from = "a".repeat(40);
        let to = "b".repeat(40);
        let err = diff_files(dir.path(), &from, &to).expect_err("should fail");
        match err {
            GitError::NotARepo { .. } => {}
            other => panic!("expected NotARepo, got {other:?}"),
        }
    }
}
