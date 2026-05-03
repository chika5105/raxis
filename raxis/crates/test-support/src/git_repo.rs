// GitRepo — TempDir-backed real-git fixture for VCS integration tests.
//
// Why this exists:
//   The kernel's `vcs::diff` module shells out to `git` (no libgit2 dep,
//   per kernel-core.md §2.3). The unit tests in `vcs/diff.rs` cover the
//   pure parser, but every assertion about how `git diff --name-status -z`
//   actually behaves on a real repository — copy rows, deletions, the
//   trailing-NUL emission, merge-commit detection, root-commit handling
//   — needs an honest-to-goodness git repo on disk. Mocking the subprocess
//   would just re-pin the same byte strings the parser tests already pin.
//
// What this fixture is NOT:
//   - Not a libgit2 wrapper. We shell out to the same `git` binary the
//     kernel uses; this is intentional so the tests catch any version-skew
//     surprise the kernel would also hit.
//   - Not a long-lived workspace. Each `GitRepo` owns a `tempfile::TempDir`;
//     when the fixture is dropped the directory is recursively removed.
//     Tests that need persistence between runs should not use this.
//   - Not a replacement for `mem_store()`. This is for VCS-shaped tests
//     only.
//
// Skip behaviour:
//   `git_available()` is exposed so integration tests can early-return
//   on hosts that don't have `git` on PATH (CI sandboxes, minimal Docker
//   images). The fixture's `init`/`commit_*` methods all spawn git; if
//   the binary is missing they panic with a clear message.

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// Returns `true` if a `git` binary is reachable on `PATH`. Integration
/// tests that depend on `GitRepo` should call this first and `return`
/// (effectively skipping themselves) on `false`, rather than panicking
/// on an environment that simply lacks git.
pub fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A real git repository inside a temporary directory.
///
/// The repo is initialised with deterministic config:
///   - `init.defaultBranch = main`           — predictable HEAD
///   - `user.email = raxis-test@example.com` — needed for commits
///   - `user.name  = raxis-test`             — needed for commits
///   - `commit.gpgsign = false`              — never tries to sign
///   - `core.autocrlf = false`               — line endings byte-stable
///
/// The underlying `TempDir` is recursively removed when `GitRepo` is
/// dropped (RAII), so test bodies don't need explicit cleanup.
pub struct GitRepo {
    /// Held to extend the temp directory's lifetime to the fixture's.
    /// Public visibility would let a test leak the dir; deliberately
    /// kept private — callers go through `path()` and the helpers.
    _tmp: TempDir,
    root: PathBuf,
}

impl GitRepo {
    /// Initialise a new empty repo in a fresh temp directory. Panics on
    /// any git failure — this is a test-only helper and a failure here
    /// means the test environment is broken.
    pub fn init() -> Self {
        let tmp = TempDir::new().expect("GitRepo: TempDir::new failed");
        let root = tmp.path().to_path_buf();

        // `git init -b <name>` was added in git 2.28 (2020). Many CI
        // hosts still ship 2.20–2.25 (Debian buster, RHEL 8 base image,
        // Ubuntu 18.04). Fall back to the symbolic-ref dance, which has
        // worked since git 1.5: `git init` → `git symbolic-ref HEAD
        // refs/heads/main`. This pins the initial branch to `main`
        // regardless of host git version or `init.defaultBranch` global.
        run_git_or_panic(&root, &["init", "-q"], "git init");
        run_git_or_panic(
            &root,
            &["symbolic-ref", "HEAD", "refs/heads/main"],
            "symbolic-ref HEAD",
        );

        // Everything below is local config (no global writes). `--local`
        // requires the repo to already exist, hence the order.
        run_git_or_panic(&root, &["config", "user.email", "raxis-test@example.com"], "config user.email");
        run_git_or_panic(&root, &["config", "user.name",  "raxis-test"],             "config user.name");
        run_git_or_panic(&root, &["config", "commit.gpgsign", "false"],              "config commit.gpgsign");
        run_git_or_panic(&root, &["config", "core.autocrlf",  "false"],              "config core.autocrlf");

        Self { _tmp: tmp, root }
    }

    /// Absolute path to the worktree root. This is what kernel VCS
    /// functions take as their `worktree_root` argument.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Write `content` to `relative_path` (creating parent dirs if
    /// needed), `git add` it, then commit with `message`. Returns the
    /// 40-char lowercase hex SHA of the new commit.
    ///
    /// `relative_path` MUST be relative — joining an absolute path
    /// would silently escape the temp dir.
    pub fn commit_file(&self, relative_path: &str, content: &str, message: &str) -> String {
        assert!(
            !Path::new(relative_path).is_absolute(),
            "GitRepo::commit_file: relative_path must be relative, got {relative_path:?}"
        );

        let abs = self.root.join(relative_path);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("GitRepo::commit_file: mkdir {parent:?}: {e}"));
        }
        std::fs::write(&abs, content)
            .unwrap_or_else(|e| panic!("GitRepo::commit_file: write {abs:?}: {e}"));

        run_git_or_panic(&self.root, &["add", "--", relative_path], "git add");
        run_git_or_panic(&self.root, &["commit", "-q", "-m", message], "git commit");
        self.head_sha()
    }

    /// Convenience: commit several files in one commit.
    /// Returns the resulting HEAD SHA.
    pub fn commit_files(&self, files: &[(&str, &str)], message: &str) -> String {
        for (path, content) in files {
            assert!(
                !Path::new(path).is_absolute(),
                "GitRepo::commit_files: path must be relative, got {path:?}"
            );
            let abs = self.root.join(path);
            if let Some(parent) = abs.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| panic!("GitRepo::commit_files: mkdir {parent:?}: {e}"));
            }
            std::fs::write(&abs, content)
                .unwrap_or_else(|e| panic!("GitRepo::commit_files: write {abs:?}: {e}"));
            run_git_or_panic(&self.root, &["add", "--", path], "git add");
        }
        run_git_or_panic(&self.root, &["commit", "-q", "-m", message], "git commit");
        self.head_sha()
    }

    /// `git rm` a tracked file and commit the deletion. Returns the
    /// resulting HEAD SHA. Used to exercise the `D` (deleted) status row.
    pub fn delete_file_commit(&self, relative_path: &str, message: &str) -> String {
        run_git_or_panic(&self.root, &["rm", "-q", "--", relative_path], "git rm");
        run_git_or_panic(&self.root, &["commit", "-q", "-m", message], "git commit");
        self.head_sha()
    }

    /// Create a new branch from current HEAD and switch to it.
    pub fn create_branch(&self, name: &str) {
        run_git_or_panic(&self.root, &["checkout", "-q", "-b", name], "git checkout -b");
    }

    /// Switch to an existing branch.
    pub fn checkout(&self, name: &str) {
        run_git_or_panic(&self.root, &["checkout", "-q", name], "git checkout");
    }

    /// Merge `branch` into current HEAD with `--no-ff` (forces a real
    /// merge commit even when fast-forward would be possible). Returns
    /// the merge commit SHA. Used to exercise `topology_check`.
    pub fn merge_no_ff(&self, branch: &str, message: &str) -> String {
        run_git_or_panic(
            &self.root,
            &["merge", "--no-ff", "-q", "-m", message, branch],
            "git merge --no-ff",
        );
        self.head_sha()
    }

    /// Return the 40-char lowercase hex SHA of the current HEAD.
    pub fn head_sha(&self) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("GitRepo::head_sha: failed to spawn git rev-parse");
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            panic!(
                "GitRepo::head_sha: git rev-parse HEAD failed (exit {:?}): {stderr}",
                out.status.code()
            );
        }
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }
}

/// Run `git -C <root> <args>` and panic with a descriptive message on
/// non-zero exit. Used internally by every `GitRepo` mutator.
fn run_git_or_panic(root: &Path, args: &[&str], label: &str) {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("GitRepo::{label}: spawn git failed: {e}"));
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        panic!(
            "GitRepo::{label}: git {args:?} exited {:?}\nstdout: {stdout}\nstderr: {stderr}",
            out.status.code()
        );
    }
}

// ---------------------------------------------------------------------------
// Tests for the fixture itself.
//
// These are the smoke checks that the fixture lays down a real repo,
// produces parseable SHAs, and cleans itself up. They guard the kernel
// integration tests below from spurious failures rooted in the fixture.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Skip helper: every test here is no-op on hosts without `git`.
    /// We deliberately do NOT panic — a missing binary is a property
    /// of the host, not a test failure.
    fn skip_if_no_git() -> bool {
        if !git_available() {
            eprintln!("SKIP: git binary not available on PATH");
            return true;
        }
        false
    }

    #[test]
    fn init_creates_a_valid_repo_with_dot_git() {
        if skip_if_no_git() { return; }
        let repo = GitRepo::init();
        assert!(repo.path().join(".git").is_dir(),
            "init must create a .git directory");
    }

    #[test]
    fn commit_file_returns_a_40_hex_sha() {
        if skip_if_no_git() { return; }
        let repo = GitRepo::init();
        let sha = repo.commit_file("hello.txt", "hi", "init");
        assert_eq!(sha.len(), 40, "SHA must be 40 hex chars, got {sha:?}");
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA must be all hex, got {sha:?}");
        assert!(sha.chars().all(|c| !c.is_ascii_uppercase()),
            "SHA must be lowercase, got {sha:?}");
    }

    #[test]
    fn two_commits_produce_distinct_shas() {
        if skip_if_no_git() { return; }
        let repo = GitRepo::init();
        let s1 = repo.commit_file("a.txt", "1", "first");
        let s2 = repo.commit_file("b.txt", "2", "second");
        assert_ne!(s1, s2, "back-to-back commits must produce distinct SHAs");
    }

    #[test]
    fn commit_files_writes_every_path() {
        if skip_if_no_git() { return; }
        let repo = GitRepo::init();
        repo.commit_files(
            &[("a.txt", "A"), ("dir/b.txt", "B"), ("dir/sub/c.txt", "C")],
            "bulk",
        );
        for p in ["a.txt", "dir/b.txt", "dir/sub/c.txt"] {
            assert!(repo.path().join(p).is_file(),
                "expected {p} to exist after commit_files");
        }
    }

    #[test]
    fn delete_file_commit_removes_path_from_worktree() {
        if skip_if_no_git() { return; }
        let repo = GitRepo::init();
        repo.commit_file("doomed.txt", "x", "add");
        repo.delete_file_commit("doomed.txt", "delete");
        assert!(!repo.path().join("doomed.txt").exists(),
            "delete_file_commit must remove the path from the worktree");
    }

    #[test]
    fn branch_and_merge_produces_a_merge_commit() {
        if skip_if_no_git() { return; }
        let repo = GitRepo::init();
        repo.commit_file("base.txt", "0", "base");
        repo.create_branch("feature");
        repo.commit_file("feat.txt", "F", "on feature");
        repo.checkout("main");
        repo.commit_file("main.txt", "M", "on main");
        let merge_sha = repo.merge_no_ff("feature", "merge feature");
        assert_eq!(merge_sha.len(), 40);

        let out = Command::new("git")
            .arg("-C").arg(repo.path())
            .args(["rev-list", "--min-parents=2", "--count", "HEAD"])
            .output()
            .unwrap();
        let count: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
        assert_eq!(count, 1, "merge_no_ff must produce exactly one merge commit reachable from HEAD");
    }

    #[test]
    fn relative_path_assertion_fires_on_absolute_input() {
        if skip_if_no_git() { return; }
        let repo = GitRepo::init();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            repo.commit_file("/etc/passwd", "x", "x");
        }));
        assert!(r.is_err(), "absolute path MUST panic — would otherwise escape TempDir");
    }

    #[test]
    fn drop_cleans_up_temp_dir() {
        if skip_if_no_git() { return; }
        let path = {
            let repo = GitRepo::init();
            repo.commit_file("a.txt", "x", "init");
            repo.path().to_path_buf()
        };
        // After drop, the temp dir must be gone.
        assert!(!path.exists(),
            "TempDir-backed GitRepo failed to clean up on drop: {path:?}");
    }

    #[test]
    fn two_independent_repos_are_isolated() {
        if skip_if_no_git() { return; }
        let r1 = GitRepo::init();
        let r2 = GitRepo::init();
        assert_ne!(r1.path(), r2.path(),
            "each GitRepo must own its own TempDir");
        let s1 = r1.commit_file("only-in-r1.txt", "1", "x");
        let s2 = r2.commit_file("only-in-r2.txt", "2", "x");
        assert_ne!(s1, s2);
        assert!( r1.path().join("only-in-r1.txt").exists());
        assert!(!r2.path().join("only-in-r1.txt").exists());
        assert!( r2.path().join("only-in-r2.txt").exists());
        assert!(!r1.path().join("only-in-r2.txt").exists());
    }
}
