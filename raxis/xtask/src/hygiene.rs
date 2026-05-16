// xtask/src/hygiene.rs — host-side worktree hygiene + disk-pressure preflight.
//
// Two operator-facing entry points are exposed via `cargo xtask`:
//
//   * `cargo xtask hygiene [--dry-run] [--max-age-days N]
//                          [--keep BRANCH ...] [--main-ref REF]`
//
//     Sweep `git worktree list` and remove every parent-side
//     worktree whose branch tip is reachable from the resolved
//     "main" ref AND whose files are not actively held open by
//     any process. The main checkout, anything passed to
//     `--keep`, and the worktree the xtask was invoked from are
//     always retained.
//
//     The merge-base reference is resolved as follows so the
//     sweep works for forks / repos with a renamed default
//     branch (`master` / `trunk` / `develop`) and not just the
//     literal `origin/main`:
//
//       1. If the operator passes `--main-ref REF`, use REF
//          verbatim (no parsing — caller owns the format, e.g.
//          `origin/develop` or `refs/remotes/origin/develop`).
//       2. Otherwise auto-detect via
//          `git symbolic-ref --short refs/remotes/origin/HEAD`
//          (returns e.g. `origin/main` / `origin/master`).
//       3. If auto-detect fails (no remote, detached, etc.),
//          fall back to the literal `origin/main`.
//
//     The chosen ref + its source is logged at sweep start as
//     `[hygiene] main_ref=<ref> (auto|--main-ref override|fallback)`
//     so the operator can audit which branch the merge-base
//     check ran against.
//
//   * `cargo xtask hygiene-check [--threshold-pct N]`
//
//     Read-only disk-pressure probe. Exits non-zero when the repo
//     volume, `/private/tmp`, or `/var/folders/*` is above the
//     threshold (default 85%). Used by the live-e2e harness as a
//     sub-second preflight so a host that is one `cargo build` away
//     from `DiskFullHaltEntered` no longer eats a 31-min mid-flight
//     `FailDiskFull` sweep.
//
// The motivation is operational: parent-side parallel agents create
// `git worktree add` checkouts for each task; each checkout carries
// a multi-GiB `cargo target/`. A single saturating run of seven
// concurrent workers filled 902 GiB and tripped the kernel's
// `DiskFullHaltEntered` safety circuit during a live-e2e iteration
// (iter 16, 1867 s, all activations rejected with `FailDiskFull`).
// Periodic `cargo xtask hygiene` sweeps prevent the recurrence —
// see `INV-HOST-HYGIENE-01` (`raxis/specs/invariants.md`).
//
// Classification logic is split into a pure `classify(...)` function
// + a small `ClassifyContext` so the unit tests can exercise the
// REMOVABLE / KEEP decision without spawning git.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context};

// ---------------------------------------------------------------------------
// Public entry points wired into `xtask::main`.
// ---------------------------------------------------------------------------

/// `cargo xtask hygiene [--dry-run] [--max-age-days N] [--keep BRANCH ...]`
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = HygieneOpts::parse(args)?;
    let summary = sweep_worktrees(&opts)?;
    eprintln!(
        "[hygiene] removed={} kept={} dry_run={} disk_free_before={} disk_free_after={}",
        summary.removed.len(),
        summary.kept.len(),
        opts.dry_run,
        human_bytes(summary.disk_free_before_bytes),
        human_bytes(summary.disk_free_after_bytes),
    );
    Ok(())
}

/// `cargo xtask hygiene-check [--threshold-pct N]`
pub fn run_check(args: &[String]) -> anyhow::Result<()> {
    let mut threshold_pct: u32 = 85;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--threshold-pct" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow!("--threshold-pct requires an integer argument"))?;
                threshold_pct = val
                    .parse()
                    .with_context(|| format!("--threshold-pct {val:?} is not an integer"))?;
                i += 2;
            }
            other => bail!(
                "unknown flag for `hygiene-check`: {other:?}\n\
                 usage: cargo xtask hygiene-check [--threshold-pct N]"
            ),
        }
    }

    let repo_root = repo_root_for_cwd()?;
    let report = disk_pressure_report(&repo_root, threshold_pct)?;
    for v in &report.volumes {
        eprintln!(
            "[hygiene-check] mount={mount} target={target} used_pct={pct} free={free}",
            mount = v.mount,
            target = v.target.display(),
            pct = v.used_pct,
            free = human_bytes(v.free_bytes),
        );
    }
    if report.over_threshold {
        bail!(
            "host disk pressure: at least one volume above {threshold_pct}% \
             — refusing to proceed (INV-HOST-HYGIENE-01). Run \
             `cargo xtask hygiene` to prune stale worktrees, then retry."
        );
    }
    eprintln!("[hygiene-check] all monitored volumes below {threshold_pct}% — clear");
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI options.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HygieneOpts {
    pub dry_run: bool,
    pub max_age_days: Option<u64>,
    pub keep_branches: HashSet<String>,
    /// Operator-supplied override for the merge-base reference.
    ///
    /// `None` means "auto-detect via
    /// `git symbolic-ref --short refs/remotes/origin/HEAD`,
    /// fall back to `origin/main` if auto-detect fails";
    /// `Some(REF)` pins the literal value passed on the CLI.
    /// See [`resolve_main_ref`] for the resolution order.
    pub main_ref: Option<String>,
}

impl HygieneOpts {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut dry_run = false;
        let mut max_age_days = None;
        let mut keep_branches: HashSet<String> = HashSet::new();
        let mut main_ref: Option<String> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--dry-run" => {
                    dry_run = true;
                    i += 1;
                }
                "--max-age-days" => {
                    let val = args
                        .get(i + 1)
                        .ok_or_else(|| anyhow!("--max-age-days requires an integer"))?;
                    max_age_days =
                        Some(val.parse().with_context(|| {
                            format!("--max-age-days {val:?} is not an integer")
                        })?);
                    i += 2;
                }
                "--keep" => {
                    let val = args
                        .get(i + 1)
                        .ok_or_else(|| anyhow!("--keep requires a branch name"))?;
                    keep_branches.insert(val.clone());
                    i += 2;
                }
                "--main-ref" => {
                    let val = args.get(i + 1).ok_or_else(|| {
                        anyhow!(
                            "--main-ref requires a git ref (e.g. \
                             origin/main, origin/develop, \
                             refs/remotes/origin/master)"
                        )
                    })?;
                    if val.is_empty() {
                        bail!("--main-ref REF must be non-empty");
                    }
                    main_ref = Some(val.clone());
                    i += 2;
                }
                other => bail!(
                    "unknown flag for `hygiene`: {other:?}\n\
                     usage: cargo xtask hygiene [--dry-run] \
                     [--max-age-days N] [--keep BRANCH ...] \
                     [--main-ref REF]"
                ),
            }
        }
        Ok(Self {
            dry_run,
            max_age_days,
            keep_branches,
            main_ref,
        })
    }
}

// ---------------------------------------------------------------------------
// Default-branch ref resolution (auto-detect + fallback).
// ---------------------------------------------------------------------------

/// Source of the resolved main-ref value, surfaced in the
/// `[hygiene] main_ref=<ref> (<source>)` log line so the
/// operator can audit which branch the merge-base check ran
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainRefSource {
    /// `--main-ref REF` was supplied by the operator.
    OperatorOverride,
    /// `git symbolic-ref --short refs/remotes/origin/HEAD`
    /// returned a usable value.
    AutoDetected,
    /// Auto-detect failed (no remote, detached, repo with no
    /// `origin/HEAD`, etc.) — fell back to the literal
    /// `origin/main`.
    Fallback,
}

impl MainRefSource {
    fn label(self) -> &'static str {
        match self {
            MainRefSource::OperatorOverride => "--main-ref override",
            MainRefSource::AutoDetected => "auto",
            MainRefSource::Fallback => "fallback",
        }
    }
}

/// Parse the raw output of `git symbolic-ref --short
/// refs/remotes/origin/HEAD` into a bare ref name. Returns
/// `None` on empty / whitespace-only output.
///
/// `--short` is supposed to strip the `refs/remotes/` prefix
/// already, but we defensively strip it again so a future git
/// version (or a caller that swaps `--short` for the long form)
/// still produces a clean `origin/<branch>` value.
pub fn parse_symbolic_ref_output(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let stripped = trimmed.strip_prefix("refs/remotes/").unwrap_or(trimmed);
    if stripped.is_empty() {
        return None;
    }
    Some(stripped.to_string())
}

/// Try to discover the host repo's default-branch ref via
/// `git symbolic-ref --short refs/remotes/origin/HEAD`.
/// Returns `None` if the call fails (no `origin/HEAD`, repo has
/// no `origin` remote, detached state, etc.) — caller is
/// expected to fall back to `origin/main`.
fn auto_detect_main_ref(repo_root: &Path) -> Option<String> {
    let raw = run_git(
        &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        repo_root,
    )
    .ok()?;
    parse_symbolic_ref_output(&raw)
}

/// Resolution order for the merge-base reference, applied in
/// `sweep_worktrees`:
///
///   1. Operator override (`--main-ref REF`) if set;
///   2. Auto-detect via `git symbolic-ref` if the repo has a
///      configured `origin/HEAD`;
///   3. Literal `origin/main` fallback.
///
/// Returns `(resolved_ref, source)` so the caller can both log
/// the chosen value AND tag its provenance.
fn resolve_main_ref(opts: &HygieneOpts, repo_root: &Path) -> (String, MainRefSource) {
    if let Some(r) = opts.main_ref.as_deref() {
        return (r.to_string(), MainRefSource::OperatorOverride);
    }
    if let Some(r) = auto_detect_main_ref(repo_root) {
        return (r, MainRefSource::AutoDetected);
    }
    ("origin/main".to_string(), MainRefSource::Fallback)
}

// ---------------------------------------------------------------------------
// Worktree enumeration + classification (pure, unit-testable).
// ---------------------------------------------------------------------------

/// One row in `git worktree list --porcelain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeEntry {
    pub path: PathBuf,
    pub head: String,
    pub branch: Option<String>,
    pub is_main: bool,
    pub is_locked: bool,
    pub is_detached: bool,
}

/// Classifier output. `Remove` means the sweep is allowed to
/// invoke `git worktree remove --force <path>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Keep(KeepReason),
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepReason {
    /// The main checkout — never touched.
    MainCheckout,
    /// Branch is on the operator's `--keep` allowlist.
    OnKeepList,
    /// The xtask itself is running from this worktree; removing it
    /// would yank the binary out from under us.
    SelfInvocation,
    /// `git worktree lock` says hands-off.
    Locked,
    /// Detached HEAD — we can't reason about merged-ness without a
    /// branch ref, so play safe.
    DetachedHead,
    /// Branch tip is NOT reachable from `origin/main` — the worker's
    /// commits have not landed yet, so its files are still load-bearing.
    BranchAhead,
    /// A live process holds files open under the worktree (lsof or
    /// ps-cwd evidence). Removing would race with the worker.
    InUse,
    /// HEAD commit is younger than the operator's `--max-age-days`
    /// floor. Useful for "only sweep worktrees that have been idle
    /// for at least a week" workflows on shared hosts.
    TooNew,
}

/// Inputs the classifier needs that are NOT purely a property of the
/// worktree row. Wrapped so unit tests can stub each predicate.
pub struct ClassifyContext<'a> {
    pub keep_branches: &'a HashSet<String>,
    /// Absolute path of the worktree the xtask itself is running
    /// from, if discoverable. The worktree containing this path is
    /// always retained.
    pub self_dir: Option<&'a Path>,
    /// `true` if the worktree's HEAD commit is reachable from
    /// `origin/main` (i.e. the branch has merged / been folded in).
    pub is_ancestor_of_main: &'a dyn Fn(&str) -> bool,
    /// `true` if any process holds files open under the worktree
    /// (lsof check OR ps-cwd check).
    pub is_in_use: &'a dyn Fn(&Path) -> bool,
    /// Operator-supplied minimum age in days. When `Some(n)`, the
    /// worktree's HEAD commit must be at least `n` days old to be
    /// REMOVABLE; otherwise the classifier returns `KeepReason::TooNew`.
    pub max_age_days: Option<u64>,
    /// Returns the head commit's age in seconds (UNIX-time-of-now
    /// minus committer-time). Only consulted when `max_age_days` is
    /// `Some`.
    pub head_age_secs: &'a dyn Fn(&str) -> Option<u64>,
}

/// Pure classifier — REMOVABLE only when every guard clears.
pub fn classify(wt: &WorktreeEntry, ctx: &ClassifyContext<'_>) -> Decision {
    if wt.is_main {
        return Decision::Keep(KeepReason::MainCheckout);
    }
    if wt.is_locked {
        return Decision::Keep(KeepReason::Locked);
    }
    if let Some(branch) = wt.branch.as_deref() {
        let stripped = branch.trim_start_matches("refs/heads/");
        if ctx.keep_branches.contains(branch) || ctx.keep_branches.contains(stripped) {
            return Decision::Keep(KeepReason::OnKeepList);
        }
    }
    if let Some(self_dir) = ctx.self_dir {
        if self_dir == wt.path || self_dir.starts_with(&wt.path) {
            return Decision::Keep(KeepReason::SelfInvocation);
        }
    }
    if wt.is_detached {
        return Decision::Keep(KeepReason::DetachedHead);
    }
    if !(ctx.is_ancestor_of_main)(&wt.head) {
        return Decision::Keep(KeepReason::BranchAhead);
    }
    if (ctx.is_in_use)(&wt.path) {
        return Decision::Keep(KeepReason::InUse);
    }
    if let Some(min_days) = ctx.max_age_days {
        if let Some(age_secs) = (ctx.head_age_secs)(&wt.head) {
            let age_days = age_secs / 86_400;
            if age_days < min_days {
                return Decision::Keep(KeepReason::TooNew);
            }
        }
    }
    Decision::Remove
}

/// Parse `git worktree list --porcelain` output into [`WorktreeEntry`]s.
/// The first non-bare row is treated as the main checkout.
pub fn parse_worktree_list(porcelain: &str) -> Vec<WorktreeEntry> {
    let mut out: Vec<WorktreeEntry> = Vec::new();
    let mut cur: Option<WorktreeEntry> = None;
    let mut first = true;
    for line in porcelain.lines() {
        if line.is_empty() {
            if let Some(mut e) = cur.take() {
                if first {
                    e.is_main = true;
                    first = false;
                }
                out.push(e);
            }
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let key = parts.next().unwrap_or("");
        let val = parts.next().unwrap_or("");
        match key {
            "worktree" => {
                cur = Some(WorktreeEntry {
                    path: PathBuf::from(val),
                    head: String::new(),
                    branch: None,
                    is_main: false,
                    is_locked: false,
                    is_detached: false,
                });
            }
            "HEAD" => {
                if let Some(c) = cur.as_mut() {
                    c.head = val.to_string();
                }
            }
            "branch" => {
                if let Some(c) = cur.as_mut() {
                    c.branch = Some(val.to_string());
                }
            }
            "detached" => {
                if let Some(c) = cur.as_mut() {
                    c.is_detached = true;
                }
            }
            "locked" => {
                if let Some(c) = cur.as_mut() {
                    c.is_locked = true;
                }
            }
            _ => {}
        }
    }
    if let Some(mut e) = cur.take() {
        if first {
            e.is_main = true;
        }
        out.push(e);
    }
    out
}

// ---------------------------------------------------------------------------
// Runtime sweep — git/process plumbing + disk accounting.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct SweepSummary {
    pub removed: Vec<PathBuf>,
    pub kept: Vec<(PathBuf, KeepReason)>,
    pub disk_free_before_bytes: u64,
    pub disk_free_after_bytes: u64,
}

fn sweep_worktrees(opts: &HygieneOpts) -> anyhow::Result<SweepSummary> {
    let repo_root = repo_root_for_cwd()?;

    let (resolved_main_ref, main_ref_source) = resolve_main_ref(opts, &repo_root);
    eprintln!(
        "[hygiene] main_ref={resolved_main_ref} ({})",
        main_ref_source.label(),
    );

    let porcelain = run_git(&["worktree", "list", "--porcelain"], &repo_root)?;
    let entries = parse_worktree_list(&porcelain);
    let self_dir = std::env::current_dir().ok();

    let disk_free_before_bytes = volume_free_bytes(&repo_root).unwrap_or(0);

    // Bind a `&str` outside the closure so the captured
    // reference lives as long as `ctx` (the closure literal
    // borrows by reference, and `&str` is `Copy`).
    let main_ref_for_closure: &str = resolved_main_ref.as_str();

    let ctx = ClassifyContext {
        keep_branches: &opts.keep_branches,
        self_dir: self_dir.as_deref(),
        is_ancestor_of_main: &|head| {
            run_git(
                &["merge-base", "--is-ancestor", head, main_ref_for_closure],
                &repo_root,
            )
            .is_ok()
        },
        is_in_use: &|p| process_holds_path(p),
        max_age_days: opts.max_age_days,
        head_age_secs: &|head| head_commit_age_secs(head, &repo_root),
    };

    let mut summary = SweepSummary {
        disk_free_before_bytes,
        ..Default::default()
    };

    for wt in &entries {
        let decision = classify(wt, &ctx);
        match decision {
            Decision::Keep(reason) => {
                eprintln!(
                    "[hygiene] KEEP path={:?} branch={:?} reason={:?}",
                    wt.path.display().to_string(),
                    wt.branch,
                    reason,
                );
                summary.kept.push((wt.path.clone(), reason));
            }
            Decision::Remove => {
                eprintln!(
                    "[hygiene] REMOVE path={:?} branch={:?} head={} dry_run={}",
                    wt.path.display().to_string(),
                    wt.branch,
                    wt.head,
                    opts.dry_run,
                );
                if !opts.dry_run {
                    if let Err(e) = remove_worktree_with_force(&wt.path, &repo_root) {
                        eprintln!(
                            "[hygiene] WARN remove failed for {}: {e:#}",
                            wt.path.display(),
                        );
                    }
                }
                summary.removed.push(wt.path.clone());
            }
        }
    }

    if !opts.dry_run {
        if let Err(e) = run_git(&["worktree", "prune", "-v"], &repo_root) {
            eprintln!("[hygiene] WARN `git worktree prune` failed: {e:#}");
        }
    }

    summary.disk_free_after_bytes = volume_free_bytes(&repo_root).unwrap_or(0);
    Ok(summary)
}

/// `git worktree remove --force <path>` then `rm -rf <path>` to
/// reclaim any orphaned files (e.g. `target/` left behind when the
/// branch was pruned but the directory survived).
fn remove_worktree_with_force(path: &Path, repo_root: &Path) -> anyhow::Result<()> {
    let _ = run_git(
        &["worktree", "remove", "--force", &path.to_string_lossy()],
        repo_root,
    );
    if path.exists() {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("rm -rf {} after `git worktree remove`", path.display()))?;
    }
    Ok(())
}

fn head_commit_age_secs(head: &str, repo_root: &Path) -> Option<u64> {
    let raw = run_git(&["log", "-1", "--format=%ct", head], repo_root).ok()?;
    let committer_ts: u64 = raw.trim().parse().ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(now.saturating_sub(committer_ts))
}

fn run_git(args: &[&str], cwd: &Path) -> anyhow::Result<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("spawning git {args:?}"))?;
    if !out.status.success() {
        bail!(
            "git {args:?} failed: status={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn repo_root_for_cwd() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir().context("std::env::current_dir")?;
    let out = run_git(&["rev-parse", "--show-toplevel"], &cwd)?;
    Ok(PathBuf::from(out.trim()))
}

/// True when ANY live process holds a resource under `path`.
///
/// We use `lsof -Fn -d cwd` rather than `ps -axwwo cwd` because the
/// macOS `ps` does NOT print other processes' CWDs to unprivileged
/// callers (it emits a blank column), which would silently flip
/// REMOVE for every active worktree. `lsof -d cwd` reads each
/// process's `proc_pidpath`-equivalent CWD directly via the kernel
/// and works for unprivileged callers on both macOS and Linux. We
/// deliberately avoid the recursive `lsof +D <path>` form because
/// it walks every file under `<path>/target/` and can take minutes
/// against a multi-GiB cargo cache; the CWD signal alone is enough
/// to detect "an in-flight worker is actively running inside this
/// worktree", which is the exact case the spec requires.
fn process_holds_path(path: &Path) -> bool {
    let path_s = match path.canonicalize() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => path.to_string_lossy().into_owned(),
    };
    let prefix = format!("{path_s}/");
    if let Ok(out) = Command::new("lsof").args(["-Fn", "-d", "cwd"]).output() {
        // `lsof` exits non-zero when it can't read every process; the
        // partial output is still useful for our scan, so don't gate
        // on `out.status.success()`.
        let body = String::from_utf8_lossy(&out.stdout);
        for line in body.lines() {
            // `-Fn` emits one record per line; CWD lines begin with `n`.
            if let Some(cwd) = line.strip_prefix('n') {
                if cwd == path_s || cwd.starts_with(&prefix) {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Disk-pressure probe (used by both `hygiene` and `hygiene-check`).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VolumeReport {
    pub target: PathBuf,
    pub mount: String,
    pub used_pct: u32,
    pub free_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct PressureReport {
    pub volumes: Vec<VolumeReport>,
    pub over_threshold: bool,
}

/// Aggregate disk-pressure probe across the repo volume,
/// `/private/tmp`, and `/var/folders/*` (AVF guest dir).
pub fn disk_pressure_report(
    repo_root: &Path,
    threshold_pct: u32,
) -> anyhow::Result<PressureReport> {
    let mut targets: Vec<PathBuf> = Vec::new();
    targets.push(repo_root.to_path_buf());
    targets.push(PathBuf::from("/private/tmp"));
    if let Ok(read_dir) = std::fs::read_dir("/var/folders") {
        for entry in read_dir.flatten() {
            let p = entry.path();
            if p.is_dir() {
                targets.push(p);
            }
        }
    }

    let mut seen_mounts: HashSet<String> = HashSet::new();
    let mut volumes: Vec<VolumeReport> = Vec::new();
    let mut over = false;
    for t in targets {
        if !t.exists() {
            continue;
        }
        let v = match probe_volume(&t) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !seen_mounts.insert(v.mount.clone()) {
            continue;
        }
        if v.used_pct >= threshold_pct {
            over = true;
        }
        volumes.push(v);
    }
    Ok(PressureReport {
        volumes,
        over_threshold: over,
    })
}

fn probe_volume(target: &Path) -> anyhow::Result<VolumeReport> {
    let out = Command::new("df")
        .args(["-Pk", &target.to_string_lossy()])
        .output()
        .with_context(|| format!("spawning df -Pk {}", target.display()))?;
    if !out.status.success() {
        bail!(
            "df -Pk {} failed: {}",
            target.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let body = String::from_utf8_lossy(&out.stdout);
    let line = body
        .lines()
        .nth(1)
        .ok_or_else(|| anyhow!("df produced no data row for {}", target.display()))?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    // POSIX `df -P` columns: Filesystem 1024-blocks Used Available Capacity Mounted-on
    if fields.len() < 6 {
        bail!("unexpected df output for {}: {line:?}", target.display());
    }
    let avail_kb: u64 = fields[3]
        .parse()
        .with_context(|| format!("parsing df Available={:?}", fields[3]))?;
    let cap_str = fields[4].trim_end_matches('%');
    let used_pct: u32 = cap_str
        .parse()
        .with_context(|| format!("parsing df Capacity={:?}", fields[4]))?;
    let mount = fields[5..].join(" ");
    Ok(VolumeReport {
        target: target.to_path_buf(),
        mount,
        used_pct,
        free_bytes: avail_kb.saturating_mul(1024),
    })
}

fn volume_free_bytes(target: &Path) -> Option<u64> {
    probe_volume(target).ok().map(|v| v.free_bytes)
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut idx = 0;
    while v >= 1024.0 && idx < UNITS.len() - 1 {
        v /= 1024.0;
        idx += 1;
    }
    format!("{v:.1}{}", UNITS[idx])
}

// ---------------------------------------------------------------------------
// Tests — classifier fixtures + porcelain parser smoke.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, branch: Option<&str>, head: &str) -> WorktreeEntry {
        WorktreeEntry {
            path: PathBuf::from(path),
            head: head.to_string(),
            branch: branch.map(|b| format!("refs/heads/{b}")),
            is_main: false,
            is_locked: false,
            is_detached: false,
        }
    }

    fn ctx_default<'a>(
        keep: &'a HashSet<String>,
        self_dir: Option<&'a Path>,
    ) -> ClassifyContext<'a> {
        ClassifyContext {
            keep_branches: keep,
            self_dir,
            is_ancestor_of_main: &|_| true,
            is_in_use: &|_| false,
            max_age_days: None,
            head_age_secs: &|_| None,
        }
    }

    #[test]
    fn parses_porcelain_output_into_entries() {
        let porcelain = "\
worktree /repo/main
HEAD aaaaaaaa
branch refs/heads/main

worktree /tmp/work-1
HEAD bbbbbbbb
branch refs/heads/worker/feature-1

worktree /tmp/work-2
HEAD cccccccc
detached
";
        let entries = parse_worktree_list(porcelain);
        assert_eq!(entries.len(), 3);
        assert!(entries[0].is_main);
        assert_eq!(entries[0].path, PathBuf::from("/repo/main"));
        assert_eq!(
            entries[1].branch.as_deref(),
            Some("refs/heads/worker/feature-1")
        );
        assert!(!entries[1].is_main);
        assert!(entries[2].is_detached);
        assert!(entries[2].branch.is_none());
    }

    #[test]
    fn main_checkout_is_always_kept() {
        let mut wt = entry("/repo", Some("main"), "aaaa");
        wt.is_main = true;
        let keep = HashSet::new();
        let ctx = ctx_default(&keep, None);
        assert_eq!(
            classify(&wt, &ctx),
            Decision::Keep(KeepReason::MainCheckout)
        );
    }

    #[test]
    fn keep_list_short_and_full_branch_name() {
        let wt_short = entry("/tmp/w1", Some("worker/keep-me"), "aa");
        let wt_full = entry("/tmp/w2", Some("worker/keep-full"), "bb");
        let mut keep = HashSet::new();
        keep.insert("worker/keep-me".to_string());
        keep.insert("refs/heads/worker/keep-full".to_string());
        let ctx = ctx_default(&keep, None);
        assert_eq!(
            classify(&wt_short, &ctx),
            Decision::Keep(KeepReason::OnKeepList)
        );
        assert_eq!(
            classify(&wt_full, &ctx),
            Decision::Keep(KeepReason::OnKeepList)
        );
    }

    #[test]
    fn self_invocation_dir_is_never_removed() {
        let wt = entry("/tmp/me", Some("worker/me"), "aa");
        let keep = HashSet::new();
        let self_dir = PathBuf::from("/tmp/me/raxis/xtask");
        let ctx = ctx_default(&keep, Some(&self_dir));
        assert_eq!(
            classify(&wt, &ctx),
            Decision::Keep(KeepReason::SelfInvocation)
        );
    }

    #[test]
    fn branch_not_yet_landed_is_kept() {
        let wt = entry("/tmp/w", Some("worker/in-flight"), "aa");
        let keep = HashSet::new();
        let ctx = ClassifyContext {
            keep_branches: &keep,
            self_dir: None,
            is_ancestor_of_main: &|_| false,
            is_in_use: &|_| false,
            max_age_days: None,
            head_age_secs: &|_| None,
        };
        assert_eq!(classify(&wt, &ctx), Decision::Keep(KeepReason::BranchAhead));
    }

    #[test]
    fn open_files_keep_the_worktree() {
        let wt = entry("/tmp/w", Some("worker/landed-busy"), "aa");
        let keep = HashSet::new();
        let ctx = ClassifyContext {
            keep_branches: &keep,
            self_dir: None,
            is_ancestor_of_main: &|_| true,
            is_in_use: &|_| true,
            max_age_days: None,
            head_age_secs: &|_| None,
        };
        assert_eq!(classify(&wt, &ctx), Decision::Keep(KeepReason::InUse));
    }

    #[test]
    fn max_age_days_floors_young_commits() {
        let wt = entry("/tmp/w", Some("worker/landed-young"), "aa");
        let keep = HashSet::new();
        let ctx = ClassifyContext {
            keep_branches: &keep,
            self_dir: None,
            is_ancestor_of_main: &|_| true,
            is_in_use: &|_| false,
            max_age_days: Some(7),
            // 2 days old — younger than the 7-day floor.
            head_age_secs: &|_| Some(2 * 86_400),
        };
        assert_eq!(classify(&wt, &ctx), Decision::Keep(KeepReason::TooNew));
    }

    #[test]
    fn max_age_days_admits_old_commits() {
        let wt = entry("/tmp/w", Some("worker/landed-old"), "aa");
        let keep = HashSet::new();
        let ctx = ClassifyContext {
            keep_branches: &keep,
            self_dir: None,
            is_ancestor_of_main: &|_| true,
            is_in_use: &|_| false,
            max_age_days: Some(7),
            head_age_secs: &|_| Some(30 * 86_400),
        };
        assert_eq!(classify(&wt, &ctx), Decision::Remove);
    }

    #[test]
    fn locked_worktree_is_kept_even_when_landed() {
        let mut wt = entry("/tmp/w", Some("worker/landed"), "aa");
        wt.is_locked = true;
        let keep = HashSet::new();
        let ctx = ctx_default(&keep, None);
        assert_eq!(classify(&wt, &ctx), Decision::Keep(KeepReason::Locked));
    }

    #[test]
    fn detached_head_is_kept() {
        let mut wt = entry("/tmp/w", None, "aa");
        wt.is_detached = true;
        let keep = HashSet::new();
        let ctx = ctx_default(&keep, None);
        assert_eq!(
            classify(&wt, &ctx),
            Decision::Keep(KeepReason::DetachedHead)
        );
    }

    #[test]
    fn landed_idle_worktree_is_removable() {
        let wt = entry("/tmp/w", Some("worker/landed-idle"), "aa");
        let keep = HashSet::new();
        let ctx = ctx_default(&keep, None);
        assert_eq!(classify(&wt, &ctx), Decision::Remove);
    }

    /// Fixture mirroring the live-host worktree list from the
    /// motivating disk-fill incident — main + six workers, with
    /// only one (the `landed-empty` row) merged AND idle.
    #[test]
    fn live_host_fixture_classifies_correctly() {
        let porcelain = "\
worktree /Users/op/raxis
HEAD 11111111
branch refs/heads/main

worktree /private/tmp/raxis-active-1
HEAD 22222222
branch refs/heads/worker/active-1

worktree /private/tmp/raxis-active-2
HEAD 33333333
branch refs/heads/worker/active-2

worktree /private/tmp/raxis-keep-explicit
HEAD 44444444
branch refs/heads/worker/keep-explicit

worktree /private/tmp/raxis-self
HEAD 55555555
branch refs/heads/worker/host-hygiene-respawn

worktree /private/tmp/raxis-landed-empty
HEAD 66666666
branch refs/heads/worker/landed-empty
";
        let entries = parse_worktree_list(porcelain);
        let mut keep = HashSet::new();
        keep.insert("worker/keep-explicit".to_string());
        let self_dir = PathBuf::from("/private/tmp/raxis-self/raxis/xtask");
        // Only the `landed-empty` row has its tip in `origin/main`.
        let landed: HashSet<&'static str> = ["66666666"].into_iter().collect();
        let ctx = ClassifyContext {
            keep_branches: &keep,
            self_dir: Some(&self_dir),
            is_ancestor_of_main: &|h| landed.contains(h),
            is_in_use: &|_| false,
            max_age_days: None,
            head_age_secs: &|_| None,
        };
        let decisions: Vec<_> = entries.iter().map(|e| classify(e, &ctx)).collect();
        assert_eq!(decisions[0], Decision::Keep(KeepReason::MainCheckout));
        assert_eq!(decisions[1], Decision::Keep(KeepReason::BranchAhead));
        assert_eq!(decisions[2], Decision::Keep(KeepReason::BranchAhead));
        assert_eq!(decisions[3], Decision::Keep(KeepReason::OnKeepList));
        assert_eq!(decisions[4], Decision::Keep(KeepReason::SelfInvocation));
        assert_eq!(decisions[5], Decision::Remove);
    }

    // -----------------------------------------------------------------
    // --main-ref REF + auto-detect coverage (INV-HOST-HYGIENE-01).
    // -----------------------------------------------------------------

    #[test]
    fn opts_default_main_ref_is_none() {
        let opts = HygieneOpts::parse(&[]).expect("parse with no args");
        assert!(
            opts.main_ref.is_none(),
            "no --main-ref means auto-detect at sweep time, not a hardcoded literal"
        );
    }

    #[test]
    fn opts_parser_accepts_main_ref_long_form() {
        let args = vec![
            "--main-ref".to_string(),
            "refs/remotes/origin/develop".to_string(),
        ];
        let opts = HygieneOpts::parse(&args).expect("parse --main-ref");
        assert_eq!(
            opts.main_ref.as_deref(),
            Some("refs/remotes/origin/develop"),
            "operator override stored verbatim — caller owns the format"
        );
    }

    #[test]
    fn opts_parser_accepts_main_ref_short_form() {
        let args = vec!["--main-ref".to_string(), "origin/master".to_string()];
        let opts = HygieneOpts::parse(&args).expect("parse --main-ref");
        assert_eq!(opts.main_ref.as_deref(), Some("origin/master"));
    }

    #[test]
    fn opts_parser_main_ref_combines_with_other_flags() {
        let args = vec![
            "--dry-run".to_string(),
            "--main-ref".to_string(),
            "origin/trunk".to_string(),
            "--keep".to_string(),
            "worker/keep-me".to_string(),
            "--max-age-days".to_string(),
            "3".to_string(),
        ];
        let opts = HygieneOpts::parse(&args).expect("parse mixed flags");
        assert!(opts.dry_run);
        assert_eq!(opts.main_ref.as_deref(), Some("origin/trunk"));
        assert_eq!(opts.max_age_days, Some(3));
        assert!(opts.keep_branches.contains("worker/keep-me"));
    }

    #[test]
    fn opts_parser_rejects_main_ref_without_value() {
        let args = vec!["--main-ref".to_string()];
        let err = HygieneOpts::parse(&args).expect_err("missing value should fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--main-ref requires"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn opts_parser_rejects_empty_main_ref() {
        let args = vec!["--main-ref".to_string(), "".to_string()];
        let err = HygieneOpts::parse(&args).expect_err("empty value should fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--main-ref REF must be non-empty"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn parse_symbolic_ref_output_short_form_main() {
        // `git symbolic-ref --short refs/remotes/origin/HEAD` typically
        // emits `origin/main\n` on a vanilla github repo.
        assert_eq!(
            parse_symbolic_ref_output("origin/main\n"),
            Some("origin/main".to_string())
        );
    }

    #[test]
    fn parse_symbolic_ref_output_short_form_master_or_develop() {
        // Forks / older repos with the previous default-branch
        // convention; what `master` looks like is exactly what
        // we need to NOT hardcode against.
        assert_eq!(
            parse_symbolic_ref_output("origin/master\n"),
            Some("origin/master".to_string())
        );
        assert_eq!(
            parse_symbolic_ref_output("origin/develop\n"),
            Some("origin/develop".to_string())
        );
        assert_eq!(
            parse_symbolic_ref_output("origin/trunk\n"),
            Some("origin/trunk".to_string())
        );
    }

    #[test]
    fn parse_symbolic_ref_output_strips_long_refs_remotes_prefix() {
        // Defensive: if a future git version (or a caller that
        // drops `--short`) emits the long form, we still
        // produce a clean `origin/<branch>` value.
        assert_eq!(
            parse_symbolic_ref_output("refs/remotes/origin/main\n"),
            Some("origin/main".to_string())
        );
        assert_eq!(
            parse_symbolic_ref_output("refs/remotes/origin/develop"),
            Some("origin/develop".to_string())
        );
    }

    #[test]
    fn parse_symbolic_ref_output_handles_trailing_whitespace() {
        assert_eq!(
            parse_symbolic_ref_output("  origin/main  \n"),
            Some("origin/main".to_string())
        );
    }

    #[test]
    fn parse_symbolic_ref_output_returns_none_for_empty_or_whitespace() {
        // Mirror the failure modes of the underlying git call:
        // detached worktree with no `origin/HEAD`, or a repo
        // that never set up a remote — both surface as empty
        // stdout. Caller falls back to the literal `origin/main`.
        assert!(parse_symbolic_ref_output("").is_none());
        assert!(parse_symbolic_ref_output("\n").is_none());
        assert!(parse_symbolic_ref_output("   \t  \n").is_none());
    }

    #[test]
    fn main_ref_source_label_is_stable() {
        // Pinned: the log line
        // `[hygiene] main_ref=<ref> (<source>)` is the only
        // operator-visible audit hook for the resolved ref.
        assert_eq!(
            MainRefSource::OperatorOverride.label(),
            "--main-ref override"
        );
        assert_eq!(MainRefSource::AutoDetected.label(), "auto");
        assert_eq!(MainRefSource::Fallback.label(), "fallback");
    }
}
