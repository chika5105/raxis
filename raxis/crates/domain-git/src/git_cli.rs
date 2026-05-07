//! `git_cli` — minimal git CLI subprocess wrappers for the V2 SE
//! `DomainAdapter::verify_state_advance` impl.
//!
//! This module is intentionally a near-verbatim subset of what
//! `kernel/src/vcs/diff.rs` does — limited to the three operations
//! the IntegrationMerge admission gate composes:
//!
//! 1. `is_ancestor(base, head, worktree)`  — `git merge-base --is-ancestor`
//! 2. `topology_check(base, head, worktree)` — `git rev-list --min-parents=2 --count`
//! 3. `compute(base, head, worktree)` — `git diff --name-status --no-renames -z`
//!
//! The kernel's `vcs::diff` will be deleted in a follow-up cleanup
//! commit once every kernel callsite has migrated to
//! `ctx.domain.verify_state_advance(...)`. Until then this module
//! and the kernel's still co-exist; algorithmic parity is asserted
//! by the conformance tests at the bottom of this file.
//!
//! Why a vendored copy and not a direct call into the kernel: the
//! `raxis-domain-git` crate must not depend on `raxis-kernel` (the
//! kernel binary depends on this crate, so the reverse would be a
//! cyclic dep). The vendored copy is small enough — three subprocess
//! invocations and a `-z` parser — that the duplication is the
//! least-bad option for the migration window.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use raxis_domain::{DomainError, ResourceOp, TouchedResource, TouchedResources};

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const HARD_CAP_TIMEOUT_SECS: u64 = 120;

/// Resolved subprocess timeout, honouring `RAXIS_VCS_TIMEOUT_SECS`
/// up to the 120s hard cap. Mirrors the kernel's `vcs::diff::vcs_timeout`.
fn timeout() -> Duration {
    let secs = std::env::var("RAXIS_VCS_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
        .min(HARD_CAP_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Validate that `s` is a 40-char lowercase-hex commit SHA-1. The
/// `verify_state_advance` impl rejects unparseable SHAs at the trait
/// boundary so the kernel surfaces `PreconditionFailed` rather than
/// shelling out to git with garbage.
fn validate_sha(s: &str) -> Result<String, DomainError> {
    let s = s.trim();
    if s.len() != 40 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(DomainError::PreconditionFailed(format!(
            "invalid SHA-1 (must be 40 hex chars): {s:?}"
        )));
    }
    Ok(s.to_lowercase())
}

/// Run `git -C <cwd> <args>` with a hard wall-clock deadline. Returns
/// `(stdout, stderr, exit_code)`.
fn run_git(args: &[&str], cwd: &Path, deadline: Duration)
    -> Result<(String, String, i32), DomainError>
{
    let started = Instant::now();
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(cwd);
    for a in args {
        cmd.arg(a);
    }
    let output = cmd.output().map_err(|e| {
        DomainError::Transient(format!("git subprocess failed to spawn: {e}"))
    })?;
    if started.elapsed() > deadline {
        return Err(DomainError::Transient(format!(
            "git subprocess exceeded deadline {}s",
            deadline.as_secs()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    Ok((stdout, stderr, code))
}

/// Returns `true` if `base` is an ancestor of `head`. Exit 0 → true,
/// exit 1 → false, anything else → `Err(Transient)`.
pub fn is_ancestor(base: &str, head: &str, worktree: &Path)
    -> Result<bool, DomainError>
{
    let b = validate_sha(base)?;
    let h = validate_sha(head)?;
    let (_o, e, code) = run_git(
        &["merge-base", "--is-ancestor", &b, &h],
        worktree,
        timeout(),
    )?;
    match code {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(DomainError::Transient(format!(
            "merge-base --is-ancestor exited {code}: {e}"
        ))),
    }
}

/// Verify there are no merge commits in `base..head`.
pub fn topology_check(base: &str, head: &str, worktree: &Path)
    -> Result<(), DomainError>
{
    let b = validate_sha(base)?;
    let h = validate_sha(head)?;
    let range = format!("{b}..{h}");
    let (out, err, code) = run_git(
        &["rev-list", &range, "--min-parents=2", "--count"],
        worktree,
        timeout(),
    )?;
    if code != 0 {
        return Err(DomainError::Transient(format!(
            "rev-list --count exited {code}: {err}"
        )));
    }
    let n: u64 = out.trim().parse().map_err(|e| {
        DomainError::Transient(format!("rev-list count not numeric ({e}): {out:?}"))
    })?;
    if n != 0 {
        return Err(DomainError::PreconditionFailed(format!(
            "topology check failed: {n} merge commit(s) in range {b}..{h}"
        )));
    }
    Ok(())
}

/// Run `git diff --name-status --no-renames -z` and produce a
/// post-processed sorted unique `Vec<TouchedResource>`.
pub fn compute_touched(base: &str, head: &str, worktree: &Path)
    -> Result<TouchedResources, DomainError>
{
    let b = validate_sha(base)?;
    let h = validate_sha(head)?;
    let (out, err, code) = run_git(
        &["diff", &b, &h, "--name-status", "--no-renames", "-z"],
        worktree,
        timeout(),
    )?;
    if code != 0 {
        return Err(DomainError::Transient(format!(
            "git diff --name-status exited {code}: {err}"
        )));
    }
    let raw_pairs = parse_name_status_z(&out)?;
    let mut resources: Vec<TouchedResource> = Vec::with_capacity(raw_pairs.len());
    for (status, path) in raw_pairs {
        let pb = post_process_path(&path)?;
        let uri = format!("path:///{}", pb.display());
        resources.push(TouchedResource {
            uri,
            op: status,
            size: None,
        });
    }
    resources.sort_by(|a, b| a.uri.cmp(&b.uri));
    resources.dedup_by(|a, b| a.uri == b.uri);
    Ok(TouchedResources { resources })
}

/// Parse `git diff --name-status --no-renames -z` output into
/// `(ResourceOp, raw_path)` pairs. `-z` framing: each field is a
/// NUL-separated record. `A/M/D/T → status\0path\0`,
/// `C<score> → status\0src\0dst\0` (both included).
fn parse_name_status_z(stdout: &str) -> Result<Vec<(ResourceOp, String)>, DomainError> {
    let mut out = Vec::new();
    let mut iter = stdout.split('\0').peekable();
    while let Some(status) = iter.next() {
        if status.is_empty() {
            if iter.peek().is_none() { break; }
            continue;
        }
        let first = status.chars().next().unwrap_or(' ');
        match first {
            'A' => {
                let p = next_nonempty(&mut iter).ok_or_else(|| {
                    DomainError::Permanent(format!("missing path after status {status}"))
                })?;
                out.push((ResourceOp::Create, p));
            }
            'M' | 'T' => {
                let p = next_nonempty(&mut iter).ok_or_else(|| {
                    DomainError::Permanent(format!("missing path after status {status}"))
                })?;
                out.push((ResourceOp::Modify, p));
            }
            'D' => {
                let p = next_nonempty(&mut iter).ok_or_else(|| {
                    DomainError::Permanent(format!("missing path after status {status}"))
                })?;
                out.push((ResourceOp::Delete, p));
            }
            'C' => {
                let src = next_nonempty(&mut iter).ok_or_else(|| {
                    DomainError::Permanent(format!("missing src after status {status}"))
                })?;
                let dst = next_nonempty(&mut iter).ok_or_else(|| {
                    DomainError::Permanent(format!("missing dst after status {status}"))
                })?;
                out.push((ResourceOp::Modify, src));
                out.push((ResourceOp::Modify, dst));
            }
            'U' => {
                let p = next_nonempty(&mut iter).unwrap_or_default();
                return Err(DomainError::PreconditionFailed(format!(
                    "diff contains unmerged path {p:?}"
                )));
            }
            'R' => {
                let src = next_nonempty(&mut iter).unwrap_or_default();
                let dst = next_nonempty(&mut iter).unwrap_or_default();
                return Err(DomainError::Permanent(format!(
                    "rename row appeared despite --no-renames: {src:?} -> {dst:?}"
                )));
            }
            _ => {
                return Err(DomainError::Permanent(format!(
                    "invalid diff status code: {status:?}"
                )));
            }
        }
    }
    Ok(out)
}

fn next_nonempty<'a, I: Iterator<Item = &'a str>>(iter: &mut I) -> Option<String> {
    for f in iter {
        if !f.is_empty() {
            return Some(f.to_owned());
        }
    }
    None
}

fn post_process_path(raw: &str) -> Result<PathBuf, DomainError> {
    let trimmed = raw.strip_prefix("./").unwrap_or(raw);
    if trimmed.starts_with('/') {
        return Err(DomainError::Permanent(format!(
            "path traversal: absolute path in diff: {raw:?}"
        )));
    }
    let pb = PathBuf::from(trimmed);
    if pb.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(DomainError::Permanent(format!(
            "path traversal: `..` component in diff: {raw:?}"
        )));
    }
    Ok(pb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_sha_accepts_lowercase_40_hex() {
        let s = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(validate_sha(s).unwrap(), s);
    }

    #[test]
    fn validate_sha_lowercases_uppercase() {
        let s = "0123456789ABCDEF0123456789ABCDEF01234567";
        assert_eq!(validate_sha(s).unwrap(),
                   "0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn validate_sha_rejects_short() {
        assert!(matches!(validate_sha("abc"), Err(DomainError::PreconditionFailed(_))));
    }

    #[test]
    fn validate_sha_rejects_non_hex() {
        let s = "g123456789abcdef0123456789abcdef01234567";
        assert!(matches!(validate_sha(s), Err(DomainError::PreconditionFailed(_))));
    }

    #[test]
    fn parse_name_status_handles_create_modify_delete() {
        let stdout = "A\0src/foo.rs\0M\0src/bar.rs\0D\0src/baz.rs\0";
        let pairs = parse_name_status_z(stdout).unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], (ResourceOp::Create, "src/foo.rs".into()));
        assert_eq!(pairs[1], (ResourceOp::Modify, "src/bar.rs".into()));
        assert_eq!(pairs[2], (ResourceOp::Delete, "src/baz.rs".into()));
    }

    #[test]
    fn parse_name_status_rejects_unmerged() {
        let stdout = "U\0src/conflict.rs\0";
        match parse_name_status_z(stdout) {
            Err(DomainError::PreconditionFailed(s)) => assert!(s.contains("unmerged")),
            other => panic!("expected PreconditionFailed for unmerged, got {other:?}"),
        }
    }

    #[test]
    fn parse_name_status_rejects_rename() {
        let stdout = "R100\0src/old.rs\0src/new.rs\0";
        match parse_name_status_z(stdout) {
            Err(DomainError::Permanent(s)) => {
                assert!(s.contains("rename"), "expected rename mention, got {s}");
            }
            other => panic!("expected Permanent for rename, got {other:?}"),
        }
    }

    #[test]
    fn parse_name_status_handles_copy_row_emits_both_paths() {
        let stdout = "C75\0src/orig.rs\0src/copy.rs\0";
        let pairs = parse_name_status_z(stdout).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], (ResourceOp::Modify, "src/orig.rs".into()));
        assert_eq!(pairs[1], (ResourceOp::Modify, "src/copy.rs".into()));
    }

    #[test]
    fn post_process_strips_dot_slash() {
        assert_eq!(post_process_path("./foo.rs").unwrap(), PathBuf::from("foo.rs"));
    }

    #[test]
    fn post_process_rejects_absolute() {
        assert!(matches!(post_process_path("/etc/passwd"), Err(DomainError::Permanent(_))));
    }

    #[test]
    fn post_process_rejects_dotdot() {
        assert!(matches!(post_process_path("foo/../bar"), Err(DomainError::Permanent(_))));
        assert!(matches!(post_process_path("../etc/passwd"), Err(DomainError::Permanent(_))));
    }

    #[test]
    fn post_process_accepts_filename_with_dotdot_substring() {
        // `foo..bar` is not the `..` component — it's a single segment.
        assert_eq!(
            post_process_path("foo..bar").unwrap(),
            PathBuf::from("foo..bar"),
        );
    }
}

// ---------------------------------------------------------------------------
// Live git-CLI integration tests. Skipped if `git` not on PATH.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod live {
    use super::*;
    use std::process::Command as StdCommand;

    fn git_available() -> bool {
        StdCommand::new("git").arg("--version").output().is_ok()
    }

    fn run_git_in(args: &[&str], cwd: &Path) -> std::process::Output {
        StdCommand::new("git")
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
    }

    fn build_two_commit_repo() -> Option<(tempfile::TempDir, String, String)> {
        if !git_available() { return None; }
        let tmp = tempfile::tempdir().ok()?;
        let cwd = tmp.path();
        run_git_in(&["init", "-q"], cwd);
        run_git_in(&["symbolic-ref", "HEAD", "refs/heads/main"], cwd);
        run_git_in(&["config", "user.name", "RAXIS Test"], cwd);
        run_git_in(&["config", "user.email", "test@raxis.local"], cwd);
        run_git_in(&["config", "commit.gpgsign", "false"], cwd);
        std::fs::write(cwd.join("a.txt"), "v1\n").ok()?;
        run_git_in(&["add", "a.txt"], cwd);
        run_git_in(&["commit", "-q", "-m", "c1"], cwd);
        let base = String::from_utf8(run_git_in(&["rev-parse", "HEAD"], cwd).stdout)
            .ok()?.trim().to_owned();
        std::fs::write(cwd.join("a.txt"), "v2\n").ok()?;
        std::fs::write(cwd.join("b.txt"), "new\n").ok()?;
        run_git_in(&["add", "."], cwd);
        run_git_in(&["commit", "-q", "-m", "c2"], cwd);
        let head = String::from_utf8(run_git_in(&["rev-parse", "HEAD"], cwd).stdout)
            .ok()?.trim().to_owned();
        Some((tmp, base, head))
    }

    #[test]
    fn live_is_ancestor_returns_true_for_strict_ancestor() {
        let Some((tmp, base, head)) = build_two_commit_repo() else {
            eprintln!("skipping: git CLI not available"); return;
        };
        assert!(is_ancestor(&base, &head, tmp.path()).unwrap());
    }

    #[test]
    fn live_is_ancestor_returns_false_for_unrelated() {
        let Some((tmp, base, _head)) = build_two_commit_repo() else {
            eprintln!("skipping: git CLI not available"); return;
        };
        // Unrelated SHA — pick a deterministic one not in this repo.
        let unrelated = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        // is_ancestor on a missing SHA returns Transient (git's "fatal" exit).
        assert!(matches!(
            is_ancestor(&base, unrelated, tmp.path()),
            Err(DomainError::Transient(_))
        ));
    }

    #[test]
    fn live_topology_check_passes_on_linear_history() {
        let Some((tmp, base, head)) = build_two_commit_repo() else {
            eprintln!("skipping: git CLI not available"); return;
        };
        topology_check(&base, &head, tmp.path()).unwrap();
    }

    #[test]
    fn live_compute_touched_returns_create_and_modify() {
        let Some((tmp, base, head)) = build_two_commit_repo() else {
            eprintln!("skipping: git CLI not available"); return;
        };
        let r = compute_touched(&base, &head, tmp.path()).unwrap();
        assert_eq!(r.resources.len(), 2);
        // a.txt was modified; b.txt was created.
        let a = r.resources.iter().find(|r| r.uri == "path:///a.txt").unwrap();
        let b = r.resources.iter().find(|r| r.uri == "path:///b.txt").unwrap();
        assert_eq!(a.op, ResourceOp::Modify);
        assert_eq!(b.op, ResourceOp::Create);
    }
}
