//! Shared dashboard-attach helpers for kernel integration tests.
//!
//! Two test binaries in this crate (`full_e2e_session_lifecycle` and
//! `extended_e2e_realistic_scenario`) need to:
//!
//!   1. Bind the kernel-mounted dashboard to a non-default test port
//!      so a developer's running daemon on the spec default `:9820`
//!      keeps working in parallel.
//!   2. Mint an autologin JWT against the kernel's challenge-response
//!      auth surface using the test's in-memory operator key.
//!   3. Print a copyable autologin URL to stderr so the operator (or
//!      the QA worker) can attach a browser to the live test in
//!      under a second.
//!   4. Best-effort spawn the OS-native URL opener so the dashboard
//!      pops in the operator's default browser.
//!
//! The lifecycle test originally inlined every step of this flow; the
//! realistic-scenario test was built without it, leaving the dashboard
//! mounted but with no operator-visible login path. Pulling the
//! helpers into one module lets both binaries share the *exact same*
//! mint + URL shape so the QA tour drives an identical authenticated
//! session regardless of which test happens to be in flight.
//!
//! ## Best-effort contract
//!
//! Every helper here returns gracefully on failure (`Option::None`,
//! `Result::Err(reason)`, etc.) and the caller in the test driver
//! treats a missing dashboard / failed mint as a soft skip — the
//! test must still pass on a headless CI runner without a built
//! `dashboard-fe/dist`, without `open(1)`, and (for the realistic
//! scenario) without the live-e2e gates set.
//!
//! ## Auto-build of the React bundle (`INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01` + `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-FRESH-01`)
//!
//! [`locate_dashboard_dist`] runs `npm ci` (when `node_modules/`
//! is absent) followed by `npm run build` on demand if
//! `dashboard-fe/dist/index.html` is missing OR stale relative
//! to the in-tree `dashboard-fe/src/**` + root config files.
//! Without the bundle the kernel's dashboard server returns HTTP
//! 404 for `/`, `/login`, and every SPA route — and a STALE
//! bundle silently masks new FE features (new pages, new
//! sidebar entries, new types) that have been committed but
//! never re-bundled. Both shapes degrade operator-side review
//! identically, so the harness treats them as one invariant
//! family.
//!
//! `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-FRESH-01` is the iter68
//! companion of the iter52 presence-only check: a `dist/`
//! whose mtime is older than the newest tracked source file
//! triggers an in-place `npm run build` before the harness
//! hands the path to the kernel. The freshness probe mirrors
//! `xtask/src/images.rs::check_staged_binary_freshness` —
//! single-pass mtime walk of `dashboard-fe/src/**` + a fixed
//! list of root config files, compared to `dist/index.html`
//! mtime. Operator opt-out via `RAXIS_E2E_SKIP_DASHBOARD_BUILD=1`
//! preserves the iter52 semantics (skip rebuild entirely; use
//! the on-disk dist as-is even if stale — for CI lanes that
//! pre-bake the bundle externally).
//!
//! **Hard-fail policy.** When
//! `RAXIS_E2E_SKIP_DASHBOARD_BUILD` is **unset** the harness
//! MUST produce a working bundle. Any failure in the auto-install
//! / auto-build / post-build-sanity chain panics the test with an
//! actionable remediation message rather than silently degrading
//! the dashboard to JSON-only. This is the iter52 lesson: the
//! previous behaviour swallowed `tsc: command not found` (caused
//! by a fresh worktree with no `node_modules/`), surfaced only as
//! a single `[dashboard-bundle]` warning line buried in the cargo
//! log, and left the operator-facing dashboard UI silently broken
//! for the duration of the live-e2e run. Dashboard QA workers
//! attached to such a run could not validate any V2.7 / V3
//! evidence and reported false-RED verdicts. Hard-fail forces
//! the failure to surface immediately so the operator fixes
//! `node_modules/` (or sets the explicit opt-out) before the
//! test ever submits its first plan.
//!
//! **Opt-out (CI lanes that pre-build).** Set
//! `RAXIS_E2E_SKIP_DASHBOARD_BUILD=1` to skip both the install and
//! the build. The dashboard will serve JSON API only (no UI) and
//! the harness logs the explicit opt-out. This is the path for
//! release-build CI that bakes `dashboard-fe/dist/` outside the
//! cargo-test driver.
//!
//! **Bounded waits.** `npm ci` is bounded by
//! `RAXIS_E2E_NPM_INSTALL_TIMEOUT_SECS` (default 600 s, override
//! upward for cold registry pulls). `npm run build` is bounded
//! by `RAXIS_E2E_NPM_BUILD_TIMEOUT_SECS` (default 300 s). Both
//! satisfy
//! [`INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`](../../specs/invariants.md).

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer as _, SigningKey};

/// Loopback host the kernel binds the dashboard on (the spec
/// requires loopback-only binding for the operator surface — TLS
/// for non-loopback exposure is the operator's responsibility,
/// not the test harness's).
pub const DASHBOARD_BIND_ADDRESS: &str = "127.0.0.1";

/// Test-managed dashboard port. Stays off the spec default
/// `9820` so a developer daemon listening there keeps working
/// while the test binary runs. Override via
/// `RAXIS_E2E_DASHBOARD_PORT` when `19820` is itself busy.
pub const DASHBOARD_DEFAULT_PORT: u16 = 19820;

/// Resolve the test-managed dashboard port from the environment,
/// falling back to [`DASHBOARD_DEFAULT_PORT`].
pub fn configured_dashboard_port() -> u16 {
    std::env::var("RAXIS_E2E_DASHBOARD_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DASHBOARD_DEFAULT_PORT)
}

/// Operator opt-out env var (`INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01`).
/// When set to `1`, [`locate_dashboard_dist`] skips both the
/// `npm ci` install and the `npm run build` step and returns
/// `None` (dashboard serves JSON API only). The opt-out is for
/// release-CI lanes that bake the React bundle externally.
pub const ENV_SKIP_DASHBOARD_BUILD: &str = "RAXIS_E2E_SKIP_DASHBOARD_BUILD";

/// Bounded-wait override for the `npm ci` step
/// (`INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01` /
/// `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01`). Default 600 s
/// — generous to cover a cold-registry pull on a fresh worktree.
pub const ENV_NPM_INSTALL_TIMEOUT_SECS: &str = "RAXIS_E2E_NPM_INSTALL_TIMEOUT_SECS";
const DEFAULT_NPM_INSTALL_TIMEOUT_SECS: u64 = 600;

/// Bounded-wait override for the `npm run build` step. Default
/// 300 s — generous to cover a full `tsc -b && vite build`
/// production build on a slow CI runner.
pub const ENV_NPM_BUILD_TIMEOUT_SECS: &str = "RAXIS_E2E_NPM_BUILD_TIMEOUT_SECS";
const DEFAULT_NPM_BUILD_TIMEOUT_SECS: u64 = 300;

/// The token included in every panic message produced by the
/// auto-bundle pipeline so a CI log scraper / operator can pin
/// the failure mode by substring without parsing the whole
/// remediation block.
pub const FE_BUNDLE_VIOLATION_TOKEN: &str = "INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01 VIOLATED";

/// Companion token for the iter68 freshness-rebuild path
/// (`INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-FRESH-01`). When a stale
/// `dist/` triggers an in-place rebuild and that rebuild fails,
/// the panic body carries THIS token rather than the
/// PRESENT-01 token, so an operator scanning a CI log can
/// distinguish "first-time build broke" from "staleness
/// rebuild broke" without parsing the whole remediation block.
pub const FE_BUNDLE_FRESHNESS_VIOLATION_TOKEN: &str =
    "INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-FRESH-01 VIOLATED";

/// Root-level config files whose mtimes participate in the
/// freshness probe. A change to any of these implies a stale
/// `dist/`: build-tool config, type-checker config, dep lock,
/// CSS pipeline config, or the vite entry HTML. Members that
/// do not exist on disk are skipped silently; only the
/// existing-and-newer-than-dist case votes "stale".
///
/// We deliberately do NOT include `dashboard-fe/Cargo.toml` (no
/// such file) or transitively-included npm package files
/// (`node_modules/**`) — the latter is owned by the lockfile,
/// so `package-lock.json` is sufficient as a proxy.
const DASHBOARD_FE_FRESHNESS_CONFIG_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "vite.config.ts",
    "vite.config.js",
    "tsconfig.json",
    "tsconfig.app.json",
    "tsconfig.node.json",
    "tailwind.config.js",
    "tailwind.config.ts",
    "postcss.config.js",
    "postcss.config.ts",
    "index.html",
];

/// Verdict of the dist-vs-source freshness probe. The variants
/// drive the structured `[dashboard-bundle] freshness=...`
/// stderr log line so a build-log replay always answers "did
/// the freshness gate fire on this run, and which way".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DashboardFeFreshness {
    /// No `dist/index.html` on disk; the freshness probe is a
    /// no-op (the missing-bundle path handles this).
    DistMissing,
    /// `dist/index.html` exists AND every probed source file's
    /// mtime is `<=` the dist mtime. Fast path: no rebuild.
    Fresh,
    /// `dist/index.html` exists but at least one tracked source
    /// file is newer. Carries the offending path + the two
    /// mtimes so the operator-visible log line is actionable
    /// without a second filesystem walk.
    Stale {
        dist_mtime_unix: i64,
        newest_source_path: PathBuf,
        newest_source_mtime_unix: i64,
    },
    /// The filesystem walk hit an error (permission, transient
    /// I/O). Treated as `Fresh` by [`classify_bundle_state`] so
    /// a flaky filesystem does not force needless rebuilds —
    /// the conservative arm. The variant exists so the witness
    /// suite can pin the policy.
    ProbeError { reason: String },
}

impl DashboardFeFreshness {
    /// True when the classifier MUST treat the dist as fresh
    /// (either it is, or the probe could not decide and the
    /// conservative default fires).
    pub fn is_fresh(&self) -> bool {
        matches!(
            self,
            DashboardFeFreshness::Fresh | DashboardFeFreshness::ProbeError { .. }
        )
    }
}

/// Pure-data classification of the `dashboard-fe` workspace state
/// at the moment the harness needs to mount the dashboard. Drives
/// the dispatch in [`locate_dashboard_dist`] and is exhaustively
/// witness-tested below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleState {
    /// `dashboard-fe/dist/index.html` is already on disk AND
    /// fresh relative to the in-tree source (or the operator
    /// opted out of rebuilds via `RAXIS_E2E_SKIP_DASHBOARD_BUILD=1`).
    /// Fast path: no subprocess work needed; the harness just
    /// hands the path to the kernel.
    DistAlreadyBuilt,

    /// `dist/index.html` is on disk BUT stale relative to the
    /// in-tree source — at least one tracked file under
    /// `dashboard-fe/src/**` or a root config file has an mtime
    /// later than the dist's. Run `npm run build` in place to
    /// refresh the bundle. `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-FRESH-01`.
    DistStaleNeedsRebuild,

    /// `RAXIS_E2E_SKIP_DASHBOARD_BUILD=1` is set; harness must
    /// silently return `None` (dashboard serves JSON-only). No
    /// subprocess work; this is the operator-explicit opt-out.
    OptOutByEnv,

    /// `dashboard-fe/package.json` is absent. The workspace shape
    /// is broken; nothing the harness can do. Hard-fail with a
    /// remediation message.
    HardFailMissingPackageJson,

    /// `dashboard-fe/node_modules/` is absent (or its
    /// `.bin/vite` is missing). Run `npm ci` first, then proceed
    /// to the build step.
    NeedsInstallThenBuild,

    /// `node_modules/` is populated; just need the build step.
    NeedsBuildOnly,
}

/// Pure classifier — exhaustively witnessable without spawning
/// any subprocess. The actual dispatch in
/// [`locate_dashboard_dist`] composes this with the install +
/// build subprocess steps; pinning the policy decision here
/// means the witness coverage need not depend on the host
/// having a usable `npm` binary.
///
/// Precedence (first match wins):
///   1. `dist_present && (dist_is_fresh || skip_env_set)` →
///      `DistAlreadyBuilt`. The opt-out preserves iter52
///      semantics: an operator who pre-bakes the bundle
///      externally MUST get their dist back unchanged.
///   2. `skip_env_set` (with no dist) → `OptOutByEnv`.
///   3. `!package_json_present` → `HardFailMissingPackageJson`
///      (unless `dist_present`, in which case fall back to
///      `DistAlreadyBuilt` because rebuild is impossible
///      without `package.json` — a stale bundle is strictly
///      better than no bundle).
///   4. `!node_modules_vite_present` → `NeedsInstallThenBuild`.
///   5. `dist_present` (implies !fresh, !skip) →
///      `DistStaleNeedsRebuild`.
///   6. Otherwise → `NeedsBuildOnly`.
pub fn classify_bundle_state(
    dist_index_present: bool,
    dist_is_fresh: bool,
    skip_env_set: bool,
    package_json_present: bool,
    node_modules_vite_present: bool,
) -> BundleState {
    if dist_index_present && (dist_is_fresh || skip_env_set) {
        return BundleState::DistAlreadyBuilt;
    }
    if skip_env_set {
        return BundleState::OptOutByEnv;
    }
    if !package_json_present {
        if dist_index_present {
            // Stale dist + no package.json → can't rebuild.
            // Use stale as the lesser evil (a serving SPA, even
            // if missing the newest features, beats HTTP 404).
            return BundleState::DistAlreadyBuilt;
        }
        return BundleState::HardFailMissingPackageJson;
    }
    if !node_modules_vite_present {
        return BundleState::NeedsInstallThenBuild;
    }
    if dist_index_present {
        return BundleState::DistStaleNeedsRebuild;
    }
    BundleState::NeedsBuildOnly
}

/// Convert a `std::time::SystemTime` to a Unix-epoch i64 of
/// seconds. Mirrors `xtask::images::mtime_to_unix`; we keep a
/// private copy here so the kernel test crate does not pull in
/// the xtask binary's internals.
fn system_time_to_unix_secs(mtime: std::time::SystemTime) -> i64 {
    mtime
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Walk `dashboard-fe/src/**` and the [`DASHBOARD_FE_FRESHNESS_CONFIG_FILES`]
/// fixed list, returning the newest mtime found alongside the
/// path that owns it. `None` when neither the src tree nor any
/// config file exists (a fresh-clone shape where nothing tracks
/// against the dist). Walk errors surface as
/// `Err(reason)` so the caller can route to
/// [`DashboardFeFreshness::ProbeError`].
fn newest_source_mtime_in_dashboard_fe(
    fe_root: &Path,
) -> Result<Option<(std::time::SystemTime, PathBuf)>, String> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    // Walk src/** recursively.
    let src_root = fe_root.join("src");
    if src_root.is_dir() {
        walk_dir_recursive(&src_root, &mut best)?;
    }
    // Stat each root config file individually.
    for name in DASHBOARD_FE_FRESHNESS_CONFIG_FILES {
        let p = fe_root.join(name);
        if let Ok(meta) = std::fs::metadata(&p) {
            if let Ok(m) = meta.modified() {
                match &best {
                    None => best = Some((m, p.clone())),
                    Some((cur, _)) if m > *cur => best = Some((m, p.clone())),
                    _ => {}
                }
            }
        }
    }
    Ok(best)
}

/// Recursive `src/**` walk. `node_modules` and `dist` are
/// pruned at the directory level because the walk seed is
/// `dashboard-fe/src/` (neither lives under it), but we keep
/// the name-based prune as a defence-in-depth in case the
/// caller seeds with `fe_root` directly in a future variant.
fn walk_dir_recursive(
    dir: &Path,
    best: &mut Option<(std::time::SystemTime, PathBuf)>,
) -> Result<(), String> {
    let read = std::fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in read {
        let entry = entry.map_err(|e| format!("read_dir entry under {}: {e}", dir.display()))?;
        let path = entry.path();
        // Skip hidden + node_modules + dist as a belt-and-
        // suspenders prune; the seed is normally `src/` so
        // these branches never fire.
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.') || name == "node_modules" || name == "dist" {
                continue;
            }
        }
        let ft = entry
            .file_type()
            .map_err(|e| format!("file_type {}: {e}", path.display()))?;
        if ft.is_dir() {
            walk_dir_recursive(&path, best)?;
        } else if ft.is_file() {
            let meta = entry
                .metadata()
                .map_err(|e| format!("metadata {}: {e}", path.display()))?;
            let m = meta
                .modified()
                .map_err(|e| format!("mtime {}: {e}", path.display()))?;
            match best {
                None => *best = Some((m, path)),
                Some((cur, _)) if m > *cur => *best = Some((m, path)),
                _ => {}
            }
        }
    }
    Ok(())
}

/// Probe `dashboard-fe/dist/index.html` against the in-tree
/// source for freshness. Cheap (sub-millisecond on a normal
/// dashboard-fe tree) and side-effect-free.
///
/// Conservative on probe errors: a transient filesystem error
/// returns [`DashboardFeFreshness::ProbeError`] which the
/// classifier maps back to "treat as fresh" — we do NOT force a
/// needless rebuild on a flaky permission. The operator can
/// always force a rebuild manually (delete `dist/`, set
/// `RAXIS_E2E_SKIP_DASHBOARD_BUILD=1`, etc.).
pub fn probe_dashboard_fe_freshness(fe_root: &Path) -> DashboardFeFreshness {
    let dist_index = fe_root.join("dist").join("index.html");
    let dist_mtime = match std::fs::metadata(&dist_index).and_then(|m| m.modified()) {
        Ok(m) => m,
        Err(_) => return DashboardFeFreshness::DistMissing,
    };
    match newest_source_mtime_in_dashboard_fe(fe_root) {
        Err(reason) => DashboardFeFreshness::ProbeError { reason },
        Ok(None) => DashboardFeFreshness::Fresh,
        Ok(Some((src_mtime, src_path))) => {
            if src_mtime > dist_mtime {
                DashboardFeFreshness::Stale {
                    dist_mtime_unix: system_time_to_unix_secs(dist_mtime),
                    newest_source_path: src_path,
                    newest_source_mtime_unix: system_time_to_unix_secs(src_mtime),
                }
            } else {
                DashboardFeFreshness::Fresh
            }
        }
    }
}

/// Resolve the bounded timeout for `npm ci` from the env, with
/// fallback to [`DEFAULT_NPM_INSTALL_TIMEOUT_SECS`]. A garbage
/// or non-positive value falls back to the default (does not
/// panic) so a misconfigured CI lane does not falsely fail the
/// invariant witness.
fn npm_install_timeout() -> Duration {
    Duration::from_secs(
        std::env::var(ENV_NPM_INSTALL_TIMEOUT_SECS)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_NPM_INSTALL_TIMEOUT_SECS),
    )
}

/// Resolve the bounded timeout for `npm run build` from the env.
/// Same fallback policy as [`npm_install_timeout`].
fn npm_build_timeout() -> Duration {
    Duration::from_secs(
        std::env::var(ENV_NPM_BUILD_TIMEOUT_SECS)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_NPM_BUILD_TIMEOUT_SECS),
    )
}

/// Run an `npm` subcommand under the given bounded timeout. On
/// timeout the child is SIGKILL'd (and reaped) and we return an
/// `Err(reason)` carrying the elapsed wall-clock + the timeout.
/// On non-zero exit returns `Err` with the exit code. On spawn
/// failure (e.g., `npm` not installed) returns `Err` with the
/// underlying `io::Error`.
///
/// `inherit_io = true` streams the npm output to the harness's
/// stderr so the operator sees the real `tsc: command not found`
/// `EACCES` / `network unreachable` reason; `false` swallows
/// for the witness tests that don't want stderr clutter.
fn run_npm_bounded(
    fe_root: &Path,
    args: &[&str],
    timeout: Duration,
    inherit_io: bool,
) -> Result<(), String> {
    let started = Instant::now();
    let stdout_cfg = if inherit_io {
        std::process::Stdio::inherit()
    } else {
        std::process::Stdio::null()
    };
    let stderr_cfg = if inherit_io {
        std::process::Stdio::inherit()
    } else {
        std::process::Stdio::null()
    };
    let mut child = match std::process::Command::new("npm")
        .args(args)
        .current_dir(fe_root)
        .stdout(stdout_cfg)
        .stderr(stderr_cfg)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return Err(format!(
                "spawn `npm {}` in {}: {e} (install Node + npm, then re-run, \
                 or set {}=1 to opt out)",
                args.join(" "),
                fe_root.display(),
                ENV_SKIP_DASHBOARD_BUILD,
            ));
        }
    };

    // Bounded poll on the child. `try_wait` is non-blocking; we
    // sleep a short tick between polls so we don't spin hot.
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let elapsed = started.elapsed();
                if status.success() {
                    return Ok(());
                }
                return Err(format!(
                    "`npm {}` exited with {status:?} after {:.1}s in {}",
                    args.join(" "),
                    elapsed.as_secs_f32(),
                    fe_root.display(),
                ));
            }
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "`npm {}` exceeded bounded timeout {:?} (override via \
                         {} for install or {} for build); SIGKILL'd",
                        args.join(" "),
                        timeout,
                        ENV_NPM_INSTALL_TIMEOUT_SECS,
                        ENV_NPM_BUILD_TIMEOUT_SECS,
                    ));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("`npm {}` try_wait error: {e}", args.join(" "),));
            }
        }
    }
}

/// Probe whether `node_modules/` looks healthy enough to skip
/// `npm ci`. We pin on `node_modules/.bin/vite` because that is
/// the binary `npm run build` actually invokes (after the `tsc -b`
/// step which lives at `node_modules/.bin/tsc`); a partial /
/// half-pruned `node_modules/` will fail the build with the
/// exact iter52 symptom (`tsc: command not found`).
fn node_modules_vite_present(fe_root: &Path) -> bool {
    fe_root
        .join("node_modules")
        .join(".bin")
        .join("vite")
        .is_file()
        || fe_root
            .join("node_modules")
            .join(".bin")
            .join("tsc")
            .is_file()
}

/// Absolute path to the React production bundle, installing
/// deps + building it on demand if missing.
///
/// **Invariant**:
/// `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01` (this is the
/// canonical enforcement site). When
/// [`ENV_SKIP_DASHBOARD_BUILD`] is unset, every failure in the
/// install / build / post-build chain panics the test with the
/// [`FE_BUNDLE_VIOLATION_TOKEN`] in the panic body. When the
/// env var is set the function silently returns `None`
/// (dashboard serves JSON-only) and never panics.
///
/// The kernel's `[dashboard].static_dir` field consumes the
/// returned path; without a real `dist/index.html` the dashboard
/// server returns HTTP 404 for `/`, `/login`, and every SPA
/// route. The `CARGO_MANIFEST_DIR` anchor is the `kernel/` crate
/// root, so `..` walks to `raxis/`.
pub fn locate_dashboard_dist() -> Option<PathBuf> {
    let raxis_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("kernel/ crate root has a parent (raxis/)")
        .to_path_buf();
    let fe_root = raxis_root.join("dashboard-fe");
    let dist = fe_root.join("dist");

    let dist_index = dist.join("index.html");
    let skip_env = std::env::var(ENV_SKIP_DASHBOARD_BUILD)
        .map(|v| v == "1")
        .unwrap_or(false);
    let package_json_present = fe_root.join("package.json").is_file();
    let node_modules_ok = node_modules_vite_present(&fe_root);

    let freshness = probe_dashboard_fe_freshness(&fe_root);
    log_freshness_probe(&freshness);

    let state = classify_bundle_state(
        dist_index.is_file(),
        freshness.is_fresh(),
        skip_env,
        package_json_present,
        node_modules_ok,
    );

    match state {
        BundleState::DistAlreadyBuilt => {
            // If we're using a stale dist because the operator
            // explicitly opted out, leave an audit trail so the
            // log answers "why is the UI showing old data" on
            // future inspections.
            if let DashboardFeFreshness::Stale { .. } = &freshness {
                if skip_env {
                    eprintln!(
                        "[dashboard-bundle] WARNING: dist/ is stale relative to \
                         dashboard-fe/src/** but {ENV_SKIP_DASHBOARD_BUILD}=1 — \
                         serving stale bundle as requested. Unset the env var \
                         to let the harness auto-rebuild on staleness \
                         (INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-FRESH-01)."
                    );
                } else if !package_json_present {
                    eprintln!(
                        "[dashboard-bundle] WARNING: dist/ is stale AND \
                         dashboard-fe/package.json missing — cannot rebuild. \
                         Serving stale bundle as last-resort fallback. \
                         Restore the workspace shape (see \
                         INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01)."
                    );
                }
            }
            Some(dist)
        }
        BundleState::DistStaleNeedsRebuild => {
            let (dist_unix, src_path, src_unix) = match &freshness {
                DashboardFeFreshness::Stale {
                    dist_mtime_unix,
                    newest_source_path,
                    newest_source_mtime_unix,
                } => (
                    *dist_mtime_unix,
                    newest_source_path.clone(),
                    *newest_source_mtime_unix,
                ),
                // `classify_bundle_state` only routes here when
                // `dist_is_fresh == false && skip == false &&
                // dist_present == true`, which only fires from
                // `Stale`. ProbeError + Fresh both report fresh
                // (see `is_fresh`), DistMissing implies no dist.
                other => {
                    panic!(
                        "{FE_BUNDLE_FRESHNESS_VIOLATION_TOKEN}: classifier routed to \
                         DistStaleNeedsRebuild but freshness probe returned {other:?} \
                         — classify_bundle_state and probe_dashboard_fe_freshness drifted. \
                         File a kernel-tests bug; this should not happen in production.",
                    );
                }
            };
            eprintln!(
                "[dashboard-bundle] freshness=stale: dist mtime={} src mtime={} \
                 newest_source={} → running `npm run build` in {} (bounded by \
                 {}={}s; opt out via {ENV_SKIP_DASHBOARD_BUILD}=1)",
                dist_unix,
                src_unix,
                src_path.display(),
                fe_root.display(),
                ENV_NPM_BUILD_TIMEOUT_SECS,
                npm_build_timeout().as_secs(),
            );
            let build_started = Instant::now();
            if let Err(reason) =
                run_npm_bounded(&fe_root, &["run", "build"], npm_build_timeout(), true)
            {
                panic!(
                    "{FE_BUNDLE_FRESHNESS_VIOLATION_TOKEN}: stale-dist rebuild \
                     failed in {}: {reason}. The harness detected that \
                     dashboard-fe/dist/index.html is older than {} but the \
                     in-place rebuild did not succeed. Diagnose with \
                     `cd raxis/dashboard-fe && npm run build` directly, OR \
                     set {ENV_SKIP_DASHBOARD_BUILD}=1 to explicitly opt out \
                     (the dashboard will then serve the stale bundle).",
                    fe_root.display(),
                    src_path.display(),
                );
            }
            eprintln!(
                "[dashboard-bundle] stale-dist rebuild OK in {:.1}s",
                build_started.elapsed().as_secs_f32(),
            );
            if !dist_index.is_file() {
                panic!(
                    "{FE_BUNDLE_FRESHNESS_VIOLATION_TOKEN}: post-rebuild sanity \
                     check failed in {}: {} is not a file after `npm run build` \
                     returned success on the stale-dist path. Inspect the npm \
                     output above for warnings.",
                    fe_root.display(),
                    dist_index.display(),
                );
            }
            Some(dist)
        }
        BundleState::OptOutByEnv => {
            eprintln!(
                "[dashboard-bundle] {ENV_SKIP_DASHBOARD_BUILD}=1 — skipping \
                 `npm ci` and `npm run build`. Dashboard will serve JSON \
                 API only (no UI). Per INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01, \
                 this is the explicit opt-out path."
            );
            None
        }
        BundleState::HardFailMissingPackageJson => {
            panic!(
                "{FE_BUNDLE_VIOLATION_TOKEN}: dashboard-fe/package.json missing \
                 at {}. The harness expected a `dashboard-fe/` workspace at \
                 the canonical path; without it the React bundle cannot be \
                 built. Either restore the workspace shape OR set \
                 {ENV_SKIP_DASHBOARD_BUILD}=1 to explicitly opt out (the \
                 dashboard will then serve JSON-only).",
                fe_root.display(),
            );
        }
        BundleState::NeedsInstallThenBuild => {
            eprintln!(
                "[dashboard-bundle] dashboard-fe/node_modules/.bin/vite missing — \
                 running `npm ci` in {} (bounded by {}={}s; opt out via \
                 {ENV_SKIP_DASHBOARD_BUILD}=1)",
                fe_root.display(),
                ENV_NPM_INSTALL_TIMEOUT_SECS,
                npm_install_timeout().as_secs(),
            );
            let install_started = Instant::now();
            if let Err(reason) = run_npm_bounded(&fe_root, &["ci"], npm_install_timeout(), true) {
                panic!(
                    "{FE_BUNDLE_VIOLATION_TOKEN}: `npm ci` failed in {}: \
                     {reason}. Either install a working Node + npm \
                     toolchain (see raxis/guides/getting-started/), pre-build \
                     the bundle and re-run, OR set \
                     {ENV_SKIP_DASHBOARD_BUILD}=1 to explicitly opt out (the \
                     dashboard will then serve JSON-only).",
                    fe_root.display(),
                );
            }
            eprintln!(
                "[dashboard-bundle] npm ci OK in {:.1}s",
                install_started.elapsed().as_secs_f32(),
            );
            run_build_or_panic(&fe_root, &dist, &dist_index)
        }
        BundleState::NeedsBuildOnly => run_build_or_panic(&fe_root, &dist, &dist_index),
    }
}

/// Emit a one-line structured stderr trace of the freshness
/// probe outcome. Mirrors the
/// `xtask::images::handle_staged_binary_freshness` audit shape
/// so a CI log scraper can join the two events on the same
/// time-window.
fn log_freshness_probe(freshness: &DashboardFeFreshness) {
    match freshness {
        DashboardFeFreshness::DistMissing => {
            eprintln!("[dashboard-bundle] freshness=dist_missing");
        }
        DashboardFeFreshness::Fresh => {
            eprintln!("[dashboard-bundle] freshness=fresh");
        }
        DashboardFeFreshness::Stale {
            dist_mtime_unix,
            newest_source_path,
            newest_source_mtime_unix,
        } => {
            eprintln!(
                "[dashboard-bundle] freshness=stale dist_mtime_unix={} \
                 newest_source={} newest_source_mtime_unix={}",
                dist_mtime_unix,
                newest_source_path.display(),
                newest_source_mtime_unix,
            );
        }
        DashboardFeFreshness::ProbeError { reason } => {
            eprintln!(
                "[dashboard-bundle] freshness=probe_error reason={reason:?} \
                 — treating as fresh (conservative fallback)"
            );
        }
    }
}

/// Run `npm run build` in `fe_root` and return the dist path on
/// success, panicking with the [`FE_BUNDLE_VIOLATION_TOKEN`] on
/// any failure. Factored out so the
/// [`BundleState::NeedsInstallThenBuild`] and
/// [`BundleState::NeedsBuildOnly`] arms share one panic shape.
fn run_build_or_panic(fe_root: &Path, dist: &Path, dist_index: &Path) -> Option<PathBuf> {
    eprintln!(
        "[dashboard-bundle] running `npm run build` in {} (bounded by {}={}s; \
         opt out via {ENV_SKIP_DASHBOARD_BUILD}=1)",
        fe_root.display(),
        ENV_NPM_BUILD_TIMEOUT_SECS,
        npm_build_timeout().as_secs(),
    );
    let build_started = Instant::now();
    if let Err(reason) = run_npm_bounded(fe_root, &["run", "build"], npm_build_timeout(), true) {
        panic!(
            "{FE_BUNDLE_VIOLATION_TOKEN}: `npm run build` failed in {}: \
             {reason}. Diagnose with `cd raxis/dashboard-fe && npm ci && \
             npm run build` directly, OR set \
             {ENV_SKIP_DASHBOARD_BUILD}=1 to explicitly opt out (the \
             dashboard will then serve JSON-only).",
            fe_root.display(),
        );
    }
    eprintln!(
        "[dashboard-bundle] npm run build OK in {:.1}s",
        build_started.elapsed().as_secs_f32(),
    );
    if !dist_index.is_file() {
        panic!(
            "{FE_BUNDLE_VIOLATION_TOKEN}: post-build sanity check failed in \
             {}: {} is not a file after `npm run build` returned success. \
             The build step is lying about success — inspect the npm output \
             above for warnings, OR set {ENV_SKIP_DASHBOARD_BUILD}=1 to \
             explicitly opt out (the dashboard will then serve JSON-only).",
            fe_root.display(),
            dist_index.display(),
        );
    }
    Some(dist.to_path_buf())
}

/// Result of [`mint_dashboard_jwt`]. `None` ⇒ best-effort failure
/// the caller must tolerate (browser-open is skipped). Field
/// shape mirrors the dashboard's `/api/auth/verify` JSON response
/// 1:1 so [`build_autologin_url`] can re-emit them in the URL
/// fragment the React `LoginPage::parseAutologinHash` consumes.
pub struct DashboardSession {
    pub token: String,
    pub operator_id: String,
    pub display_name: String,
    pub roles: Vec<String>,
    pub expires_at: u64,
}

/// V3 iter69 — `INV-LIVE-E2E-DASHBOARD-PORT-CLEAR-ON-BOOT-01`.
///
/// Operator opt-out env var for the [`pre_flight_clear_dashboard_port`]
/// pre-flight kill step. When set to `1`, the helper logs the
/// configured port + the PIDs that would have been killed and
/// returns without sending any signal. The default (env var
/// unset) is to actively SIGTERM + SIGKILL any process whose
/// socket is bound to the configured dashboard port BEFORE the
/// test kernel attempts to bind it.
pub const ENV_SKIP_DASHBOARD_PORT_PREFLIGHT: &str = "RAXIS_E2E_SKIP_DASHBOARD_PORT_PREFLIGHT";

/// V3 iter69 — `INV-LIVE-E2E-DASHBOARD-PORT-CLEAR-ON-BOOT-01`.
///
/// Active teardown of any process whose listening socket is on
/// the test-configured dashboard port (default `19820`). Called
/// transparently from [`mutate_dashboard_block_in_policy`] before
/// the kernel daemon spawns, so an operator who launches a
/// second live-e2e run while a previous kernel is still holding
/// the port does not silently double-bind via macOS
/// `SO_REUSEPORT` — the new kernel correctly takes ownership of
/// `127.0.0.1:<port>` and the user's autologin URL works on the
/// first try.
///
/// **Why this lives in the harness, not in `cargo test`'s
/// teardown.** A previous kernel that crashed (panic, SIGKILL,
/// `RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT=1`) leaves its dashboard
/// port live indefinitely. The next test invocation has no
/// other natural point to discover-and-kill it; rolling the
/// pre-flight into `mutate_dashboard_block_in_policy` makes
/// every dashboard-bound test crate inherit the cleanup for
/// free.
///
/// **Best-effort.** Failures (lsof missing, kill denied) are
/// logged structurally and never panic — the worst case is the
/// kernel's subsequent `bind(2)` returning `EADDRINUSE` and the
/// test surfacing the existing iter21 error message, which is
/// strictly better than the silent double-bind shape.
///
/// **Opt-out.** Set [`ENV_SKIP_DASHBOARD_PORT_PREFLIGHT`]`=1` to
/// disable the kill step (the helper still logs the configured
/// port + observed listener PIDs so a CI runner can audit the
/// pre-flight outcome without disturbing the host).
pub fn pre_flight_clear_dashboard_port(port: u16) {
    let skip = std::env::var(ENV_SKIP_DASHBOARD_PORT_PREFLIGHT)
        .map(|v| v == "1")
        .unwrap_or(false);
    let pids = listening_pids_on_port(port);
    if pids.is_empty() {
        eprintln!(
            "[dashboard-preflight] port {port} clear (no listeners) — \
             INV-LIVE-E2E-DASHBOARD-PORT-CLEAR-ON-BOOT-01",
        );
        return;
    }
    if skip {
        eprintln!(
            "[dashboard-preflight] {ENV_SKIP_DASHBOARD_PORT_PREFLIGHT}=1 — \
             skipping kill step; observed listeners on port {port}: {pids:?}. \
             The subsequent kernel bind(2) may fail with EADDRINUSE.",
        );
        return;
    }
    eprintln!(
        "[dashboard-preflight] port {port} has stale listeners {pids:?} — \
         sending SIGTERM (then SIGKILL after 1s grace) \
         per INV-LIVE-E2E-DASHBOARD-PORT-CLEAR-ON-BOOT-01",
    );
    for pid in &pids {
        send_signal_best_effort(*pid, /* sigkill */ false);
    }
    // Single short grace window for orderly shutdown — well below
    // the `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01` envelope.
    std::thread::sleep(Duration::from_secs(1));
    let still = listening_pids_on_port(port);
    if !still.is_empty() {
        eprintln!(
            "[dashboard-preflight] port {port} still held by {still:?} after \
             SIGTERM — escalating to SIGKILL",
        );
        for pid in &still {
            send_signal_best_effort(*pid, /* sigkill */ true);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let remaining = listening_pids_on_port(port);
    if remaining.is_empty() {
        eprintln!(
            "[dashboard-preflight] port {port} cleared successfully — \
             INV-LIVE-E2E-DASHBOARD-PORT-CLEAR-ON-BOOT-01 satisfied",
        );
    } else {
        eprintln!(
            "[dashboard-preflight] WARNING: port {port} STILL held by {remaining:?} \
             after SIGKILL — the kernel's subsequent bind(2) will likely fail \
             with EADDRINUSE. Manually clear the port and retry.",
        );
    }
}

/// Resolve the list of PIDs holding a listening TCP socket on
/// `127.0.0.1:<port>`. Returns an empty Vec when:
///   * `lsof(1)` is not on `PATH` (best-effort skip; the
///     caller's logs make this explicit).
///   * No listener matches.
///   * `lsof` returns non-zero but stderr is suppressed (we do
///     not pipe stderr through to avoid spurious "permission
///     denied for kernel_task" noise on macOS).
fn listening_pids_on_port(port: u16) -> Vec<u32> {
    // `lsof -nP -iTCP:<port> -sTCP:LISTEN -t` prints one PID per
    // line; `-n` and `-P` skip DNS / service-name resolution so
    // the call is fast on a saturated DNS host.
    let output = std::process::Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Send SIGTERM (or SIGKILL when `sigkill = true`) to `pid`.
/// Failures are swallowed — the caller's polling loop is the
/// source of truth for "did this work" and surfaces the
/// remediation message itself.
fn send_signal_best_effort(pid: u32, sigkill: bool) {
    let sig = if sigkill { "-KILL" } else { "-TERM" };
    let _ = std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// In-place mutation of the genesis-emitted `[dashboard]` block:
///
///   * change `bind_port    = 9820` → `bind_port    = {test_port}`
///     so the test-managed dashboard does not collide with a
///     running developer daemon on the spec default 9820.
///   * insert `static_dir   = "<dashboard-fe/dist>"` immediately
///     after the port line when the React production bundle has
///     been built — without it the kernel's dashboard server
///     serves the JSON API only (no UI), which defeats the
///     visual-debug purpose of mounting the dashboard at all.
///
/// Genesis emits the block flush-left (the `\` line continuations
/// in `genesis_tools::policy_toml::render_genesis_policy_toml`
/// strip the source-file indentation), so each key sits at
/// column 0. We preserve that shape so the rewritten file stays
/// formatted the same way the genesis emitter would have written
/// it. Failure mode: if the genesis template is ever changed and
/// the `bind_port    = 9820` literal disappears, this helper
/// panics with a clear remediation — silently failing here would
/// land the test on the spec default port and silently skip the
/// `static_dir` injection (no UI served), exactly the failure
/// mode we are trying to prevent.
///
/// **V3 iter69**: invokes [`pre_flight_clear_dashboard_port`] up
/// front so any stale listener (orphaned `raxis-kernel` from a
/// prior `RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT=1` run, leftover
/// dashboard daemon, etc.) is SIGTERM/SIGKILL'd before the test
/// kernel attempts to bind. Opt out via
/// [`ENV_SKIP_DASHBOARD_PORT_PREFLIGHT`]`=1`.
pub fn mutate_dashboard_block_in_policy(data_dir: &Path) {
    let port = configured_dashboard_port();
    mutate_dashboard_block_in_policy_on_port(data_dir, port);
}

/// Pick an currently-free loopback port for tests that may spawn
/// multiple real kernels concurrently inside the same test binary.
///
/// The listener is dropped before the kernel binds, so this is still
/// best-effort, but it avoids every harness-owned kernel racing on the
/// same fixed dashboard port. Callers that need a human-stable dashboard
/// URL should keep using [`configured_dashboard_port`].
pub fn allocate_ephemeral_dashboard_port() -> u16 {
    std::net::TcpListener::bind((DASHBOARD_BIND_ADDRESS, 0))
        .expect("bind ephemeral dashboard port")
        .local_addr()
        .expect("read ephemeral dashboard port")
        .port()
}

/// Rewrite the genesis-emitted dashboard block to use an explicit
/// loopback port. See [`mutate_dashboard_block_in_policy`] for the
/// fixed-port live-e2e variant.
pub fn mutate_dashboard_block_in_policy_on_port(data_dir: &Path, port: u16) {
    // Pre-flight: clear the dashboard port BEFORE we touch the
    // policy file so a stale listener does not silently shadow
    // the new kernel's bind on macOS SO_REUSEPORT semantics.
    pre_flight_clear_dashboard_port(port);
    let policy_path = data_dir.join("policy").join("policy.toml");
    let mut body = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", policy_path.display()));
    const NEEDLE: &str = "bind_port    = 9820\n";
    let replacement = match locate_dashboard_dist() {
        Some(dist) => {
            let mut s = String::new();
            s.push_str(&format!("bind_port    = {port}\n"));
            s.push_str("# static_dir injected by tests/common/dashboard.rs.\n");
            s.push_str(&format!(
                "static_dir   = {:?}\n",
                dist.display().to_string()
            ));
            s
        }
        None => {
            let mut s = String::new();
            s.push_str(&format!("bind_port    = {port}\n"));
            s.push_str("# NOTE: dashboard-fe/dist not found; serving JSON API only.\n");
            s
        }
    };
    if !body.contains(NEEDLE) {
        panic!(
            "mutate_dashboard_block_in_policy: cannot find {NEEDLE:?} in \
             genesis-emitted policy.toml at {}. The genesis template's \
             [dashboard] block has changed shape — re-anchor this helper \
             against the new format in \
             `genesis_tools::policy_toml::render_genesis_policy_toml`.",
            policy_path.display(),
        );
    }
    body = body.replacen(NEEDLE, &replacement, 1);
    std::fs::write(&policy_path, body)
        .unwrap_or_else(|e| panic!("rewrite {}: {e}", policy_path.display()));
}

/// Block until `127.0.0.1:<port>` accepts a TCP connection or
/// `deadline` elapses. Returns `false` on timeout. We use a raw
/// `TcpStream::connect_timeout` rather than an HTTP probe because
/// the dashboard's accept-loop binds the socket BEFORE the router
/// state is fully wired — a TCP success is the earliest signal
/// that JSON requests will not get connection-refused.
pub fn wait_for_dashboard_port(port: u16, deadline: Duration) -> bool {
    let addr = format!("{}:{}", DASHBOARD_BIND_ADDRESS, port);
    let parsed: std::net::SocketAddr = match addr.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let start = Instant::now();
    while start.elapsed() < deadline {
        if std::net::TcpStream::connect_timeout(&parsed, Duration::from_millis(250)).is_ok() {
            // Accept-loop is up; give the router state one tick to
            // finish wiring before the first POST hits.
            std::thread::sleep(Duration::from_millis(150));
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

/// Drive the kernel's challenge-response auth dance against the
/// in-test operator key and return the minted JWT envelope.
/// Returns `None` on any HTTP / JSON error so the caller can
/// log + skip the browser-open step (the test must still pass
/// without a browser).
pub fn mint_dashboard_jwt(
    signing_key: &SigningKey,
    port: u16,
    label: &'static str,
) -> Option<DashboardSession> {
    let base = format!("http://{}:{}", DASHBOARD_BIND_ADDRESS, port);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    // Step 1 — request a challenge.
    let challenge_resp = client
        .get(format!("{base}/api/auth/challenge"))
        .send()
        .ok()?;
    if !challenge_resp.status().is_success() {
        eprintln!(
            "[{label}] dashboard /api/auth/challenge: HTTP {}",
            challenge_resp.status(),
        );
        return None;
    }
    let challenge_body: serde_json::Value = challenge_resp.json().ok()?;
    let challenge_hex = challenge_body.get("challenge")?.as_str()?.to_owned();
    let challenge_bytes = hex::decode(&challenge_hex).ok()?;
    if challenge_bytes.len() != 32 {
        return None;
    }

    // Step 2 — sign with the test's operator key (the same one
    // `bootstrap_with_custom_cert` minted the operator cert
    // with, so the kernel's policy-side `operator_entry` lookup
    // succeeds inside `verify`).
    let signature = signing_key.sign(&challenge_bytes);
    let pubkey = signing_key.verifying_key().to_bytes();
    let signature_hex = hex::encode(signature.to_bytes());
    let pubkey_hex = hex::encode(pubkey);

    // ── Paste-fallback for the operator ─────────────────────────
    //
    // If the autologin redirect ever fails (stale FE bundle,
    // hash-routing quirk, browser strips fragments, …) the
    // operator can still log in by pasting the values below into
    // the dashboard's manual challenge-response form. The
    // challenge is a one-time nonce (single-use, ~5 min TTL), so
    // the signature has no value beyond this single mint attempt.
    eprintln!("[{label}] dashboard manual-fallback (paste into /login if autologin fails):");
    eprintln!("[{label}]   1. CLI command   : raxis auth sign {challenge_hex}");
    eprintln!("[{label}]   2. Signature hex : {signature_hex}");
    eprintln!("[{label}]   3. Public key hex: {pubkey_hex}");

    // Step 3 — verify.
    let verify_body = serde_json::json!({
        "challenge":  challenge_hex,
        "signature":  signature_hex,
        "public_key": pubkey_hex,
    });
    let verify_resp = client
        .post(format!("{base}/api/auth/verify"))
        .json(&verify_body)
        .send()
        .ok()?;
    if !verify_resp.status().is_success() {
        eprintln!(
            "[{label}] dashboard /api/auth/verify: HTTP {} (body: {:?})",
            verify_resp.status(),
            verify_resp.text().unwrap_or_default(),
        );
        return None;
    }
    let verify_payload: serde_json::Value = verify_resp.json().ok()?;
    Some(DashboardSession {
        token: verify_payload.get("token")?.as_str()?.to_owned(),
        operator_id: verify_payload.get("operator_id")?.as_str()?.to_owned(),
        display_name: verify_payload.get("display_name")?.as_str()?.to_owned(),
        roles: verify_payload
            .get("roles")?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        expires_at: verify_payload.get("expires_at")?.as_u64()?,
    })
}

/// Build the autologin URL the dashboard's React `LoginPage`
/// consumes via `parseAutologinHash`. Mirror the field set 1:1
/// — any drift will land the operator on the manual flow.
pub fn build_autologin_url(port: u16, session: &DashboardSession) -> String {
    fn encode(s: &str) -> String {
        // Minimal RFC-3986 percent-encoding of the few characters
        // the autologin payload may carry. We do NOT pull in
        // `urlencoding` or `percent-encoding` for one call site;
        // the values here are constrained (hex JWT segments,
        // ASCII operator names, lowercase role names) so a small
        // bespoke pass is sufficient.
        s.bytes()
            .flat_map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => vec![b],
                _ => format!("%{b:02X}").into_bytes(),
            })
            .map(|b| b as char)
            .collect()
    }
    let roles_csv = session
        .roles
        .iter()
        .map(|r| encode(r))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "http://{addr}:{port}/login#autologin=1\
         &token={token}\
         &operator_id={op}\
         &display_name={name}\
         &roles={roles}\
         &expires_at={exp}\
         &next=%2F",
        addr = DASHBOARD_BIND_ADDRESS,
        port = port,
        token = encode(&session.token),
        op = encode(&session.operator_id),
        name = encode(&session.display_name),
        roles = roles_csv,
        exp = session.expires_at,
    )
}

/// Open a URL in the best-available browser for the current
/// host. Delegates to [`super::browser::open_in_best_browser`]
/// which performs the Cursor-vs-system dispatch + per-OS
/// fallback. Returns `Ok(())` when the URL reached an opener (or
/// was explicitly suppressed via `RAXIS_E2E_BROWSER=none`), and
/// `Err(reason)` when no opener could be invoked AND the URL was
/// only printed.
///
/// Pinned as a thin wrapper instead of an inline migration so
/// every other call site that already imports
/// `dashboard::spawn_url_opener` keeps working — the new Cursor
/// integration lands transparently for them.
pub fn spawn_url_opener(url: &str) -> Result<(), String> {
    use super::browser::{open_in_best_browser, OpenOutcome};
    match open_in_best_browser(url) {
        OpenOutcome::Cursor | OpenOutcome::System { .. } | OpenOutcome::Suppressed => Ok(()),
        OpenOutcome::Printed => {
            Err("no URL opener could be invoked on this host (URL was printed)".to_owned())
        }
    }
}

/// End-to-end glue called from the test driver after the kernel
/// daemon's `RAXIS dashboard: …` log line has fired. Wires the
/// wait + mint + URL build + browser-spawn steps. ALL failures
/// are non-fatal — the test must still pass headless.
///
/// On success returns the autologin URL the caller should hand
/// to its `Tier3Reporter::set_dashboard_url(...)` so the
/// post-run artifact block surfaces the same URL the in-band
/// stderr line already printed. The label (e.g. `"e2e"`,
/// `"realism-e2e"`) controls the bracketed prefix on every
/// stderr line so an operator scanning the test log can attribute
/// each mint to its driver.
pub fn open_dashboard_with_autologin(
    signing_key: &SigningKey,
    port: u16,
    label: &'static str,
) -> Option<String> {
    if !wait_for_dashboard_port(port, Duration::from_secs(10)) {
        eprintln!(
            "[{label}] dashboard at {}:{} did not become reachable within 10s — \
             skipping autologin",
            DASHBOARD_BIND_ADDRESS, port,
        );
        return None;
    }
    let session = match mint_dashboard_jwt(signing_key, port, label) {
        Some(s) => s,
        None => {
            eprintln!(
                "[{label}] dashboard JWT mint failed; skipping browser open \
                 (kernel logs may have details)",
            );
            return None;
        }
    };
    let url = build_autologin_url(port, &session);
    eprintln!(
        "[{label}] dashboard ready: http://{}:{}/  (autologin URL printed below for manual fallback)",
        DASHBOARD_BIND_ADDRESS, port,
    );
    eprintln!("[{label}] dashboard autologin URL: {url}");
    if let Err(e) = spawn_url_opener(&url) {
        eprintln!(
            "[{label}] could not open browser ({e}); paste the URL above into a browser to autologin",
        );
    } else {
        eprintln!(
            "[{label}] dashboard opened in default browser as operator '{}' (roles={:?})",
            session.display_name, session.roles,
        );
    }
    Some(url)
}

// ---------------------------------------------------------------------------
// Witness tests for INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01` — exhaustive
    /// pure-data witness over [`classify_bundle_state`]. Pinning
    /// the policy decision here means a future maintainer cannot
    /// silently re-introduce the iter52 silent-degrade behaviour
    /// (every regression flips at least one of these arms).
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_present_01_classifier_dist_already_built_wins_when_fresh() {
        // A FRESH dist always wins over every other knob — the
        // classic iter52 contract, preserved post-iter68.
        for skip in [false, true] {
            for pkg in [false, true] {
                for nm in [false, true] {
                    assert_eq!(
                        classify_bundle_state(true, true, skip, pkg, nm),
                        BundleState::DistAlreadyBuilt,
                        "skip={skip} pkg={pkg} nm={nm}",
                    );
                }
            }
        }
    }

    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_present_01_classifier_skip_env_wins_over_failure_arms() {
        // Opt-out wins over package_json_missing /
        // node_modules_missing — the operator's "I'll handle the
        // bundle externally" wins over the workspace-shape arms.
        // (Freshness is moot when dist is absent.)
        for pkg in [false, true] {
            for nm in [false, true] {
                assert_eq!(
                    classify_bundle_state(false, false, true, pkg, nm),
                    BundleState::OptOutByEnv,
                    "pkg={pkg} nm={nm}",
                );
            }
        }
    }

    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_present_01_classifier_missing_package_json_hard_fails() {
        // No dist + no opt-out + no package.json ⇒ workspace
        // shape is broken; hard-fail.
        for nm in [false, true] {
            assert_eq!(
                classify_bundle_state(false, false, false, false, nm),
                BundleState::HardFailMissingPackageJson,
                "nm={nm}",
            );
        }
    }

    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_present_01_classifier_missing_node_modules_needs_install() {
        // No dist + no opt-out + package.json present + no
        // node_modules ⇒ run `npm ci` first then build.
        assert_eq!(
            classify_bundle_state(false, false, false, true, false),
            BundleState::NeedsInstallThenBuild,
        );
    }

    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_present_01_classifier_node_modules_present_needs_build_only(
    ) {
        // No dist + no opt-out + package.json + node_modules.bin
        // populated ⇒ skip install, just build.
        assert_eq!(
            classify_bundle_state(false, false, false, true, true),
            BundleState::NeedsBuildOnly,
        );
    }

    // ─── INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-FRESH-01 witnesses ───

    /// A stale dist + no opt-out + healthy workspace routes to
    /// `DistStaleNeedsRebuild` (the new arm). This is the
    /// canonical iter68 path: dist exists but src is newer →
    /// re-run `npm run build` in place.
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_fresh_01_stale_dist_with_healthy_workspace_rebuilds() {
        assert_eq!(
            classify_bundle_state(true, false, false, true, true),
            BundleState::DistStaleNeedsRebuild,
        );
    }

    /// A stale dist + healthy workspace BUT no node_modules → we
    /// must run `npm ci` first (NeedsInstallThenBuild covers
    /// both the "no dist" and the "stale dist after a fresh
    /// worktree" shapes).
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_fresh_01_stale_dist_no_node_modules_installs_first() {
        assert_eq!(
            classify_bundle_state(true, false, false, true, false),
            BundleState::NeedsInstallThenBuild,
        );
    }

    /// A stale dist + opt-out preserves iter52 semantics — the
    /// operator explicitly said "don't touch the bundle", so we
    /// hand it back as-is even though src is newer. Emits a
    /// WARNING log line so the staleness is visible in CI logs.
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_fresh_01_stale_dist_opt_out_preserves_stale() {
        for pkg in [false, true] {
            for nm in [false, true] {
                assert_eq!(
                    classify_bundle_state(true, false, true, pkg, nm),
                    BundleState::DistAlreadyBuilt,
                    "stale + opt-out MUST short-circuit to fast-path: pkg={pkg} nm={nm}",
                );
            }
        }
    }

    /// A stale dist + no package.json → can't rebuild. Fall
    /// back to serving the stale dist (a serving SPA, even if
    /// outdated, beats HTTP 404). This is the strict superset
    /// of the iter52 hard-fail: missing-pkg-json only hard-
    /// fails when there is no usable dist on disk either.
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_fresh_01_stale_dist_no_package_json_falls_back() {
        for nm in [false, true] {
            assert_eq!(
                classify_bundle_state(true, false, false, false, nm),
                BundleState::DistAlreadyBuilt,
                "stale + no pkg-json MUST fall back to stale dist: nm={nm}",
            );
        }
    }

    /// The freshness violation token is operator-facing and
    /// carried verbatim by panics from the stale-rebuild path.
    /// Pin the spelling so a rephrase does not silently break
    /// CI log scrapers / runbook references.
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_fresh_01_violation_token_shape() {
        assert_eq!(
            FE_BUNDLE_FRESHNESS_VIOLATION_TOKEN,
            "INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-FRESH-01 VIOLATED",
        );
    }

    /// `DashboardFeFreshness::is_fresh()` mapping into the
    /// classifier — `Fresh` and `ProbeError` both vote fresh
    /// (conservative arm); `DistMissing` and `Stale` do not.
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_fresh_01_is_fresh_mapping() {
        assert!(DashboardFeFreshness::Fresh.is_fresh());
        assert!(DashboardFeFreshness::ProbeError {
            reason: "synthetic".to_owned(),
        }
        .is_fresh());
        assert!(!DashboardFeFreshness::DistMissing.is_fresh());
        assert!(!DashboardFeFreshness::Stale {
            dist_mtime_unix: 100,
            newest_source_path: PathBuf::from("synthetic"),
            newest_source_mtime_unix: 200,
        }
        .is_fresh());
    }

    /// End-to-end freshness probe over a synthetic
    /// `dashboard-fe/` shape. Exercises all four
    /// `DashboardFeFreshness` arms against real filesystem
    /// state so a regression in either
    /// `newest_source_mtime_in_dashboard_fe` or
    /// `probe_dashboard_fe_freshness` trips here rather than
    /// silently masking a stale bundle on a live-e2e run.
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_fresh_01_probe_round_trip() {
        let tmp = tempfile::tempdir().expect("mkdtemp");
        let fe = tmp.path();

        // 1. No dist/, no src/ → DistMissing.
        assert_eq!(
            probe_dashboard_fe_freshness(fe),
            DashboardFeFreshness::DistMissing,
        );

        // 2. dist/index.html present, no src/ tracked → Fresh
        //    (nothing to invalidate it).
        std::fs::create_dir_all(fe.join("dist")).expect("mkdir dist");
        std::fs::write(fe.join("dist").join("index.html"), b"<!doctype html>")
            .expect("write index.html");
        // Backdate the dist so a subsequent src write is
        // unambiguously newer regardless of FS mtime resolution.
        let week_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(7 * 86400);
        set_mtime(&fe.join("dist").join("index.html"), week_ago);
        assert_eq!(
            probe_dashboard_fe_freshness(fe),
            DashboardFeFreshness::Fresh
        );

        // 3. Add a src/ file with mtime newer than dist → Stale.
        std::fs::create_dir_all(fe.join("src")).expect("mkdir src");
        let src_file = fe.join("src").join("App.tsx");
        std::fs::write(&src_file, b"export const App = () => null;").expect("write src/App.tsx");
        let now = std::time::SystemTime::now();
        set_mtime(&src_file, now);
        match probe_dashboard_fe_freshness(fe) {
            DashboardFeFreshness::Stale {
                newest_source_path, ..
            } => {
                assert_eq!(newest_source_path, src_file);
            }
            other => panic!("expected Stale, got {other:?}"),
        }

        // 4. Backdate the src file so dist is again newer →
        //    Fresh (the reverse-order case).
        set_mtime(&src_file, week_ago - std::time::Duration::from_secs(86400));
        assert_eq!(
            probe_dashboard_fe_freshness(fe),
            DashboardFeFreshness::Fresh
        );

        // 5. A root config file (e.g., package.json) newer than
        //    dist also votes Stale — exercising the
        //    DASHBOARD_FE_FRESHNESS_CONFIG_FILES path.
        let pkg = fe.join("package.json");
        std::fs::write(&pkg, b"{}").expect("write package.json");
        set_mtime(&pkg, now);
        match probe_dashboard_fe_freshness(fe) {
            DashboardFeFreshness::Stale {
                newest_source_path, ..
            } => {
                assert_eq!(newest_source_path, pkg);
            }
            other => panic!("expected Stale via package.json, got {other:?}"),
        }
    }

    /// Helper for the round-trip witness. We `filetime`-style
    /// mtime-set via `utimensat`-equivalent on every platform
    /// supported by `std`. Failure to set the mtime panics so a
    /// misconfigured FS that silently ignores the write does not
    /// produce false-green test runs.
    fn set_mtime(path: &Path, when: std::time::SystemTime) {
        // `std::fs::File::set_modified` is stable since 1.75.
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap_or_else(|e| panic!("open {} for mtime set: {e}", path.display()));
        f.set_modified(when)
            .unwrap_or_else(|e| panic!("set_modified {}: {e}", path.display()));
    }

    /// The opt-out env var name is part of the operator-facing
    /// surface — the [`classify_bundle_state`] decision pivots
    /// on it and the `dashboard-bundle` log lines reference it
    /// verbatim. Pin the spelling so a typo (`SKIP_DASHBOARD` vs
    /// `SKIP_BUILD` etc.) trips here rather than silently
    /// breaking the opt-out path on a release-CI lane.
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_present_01_opt_out_env_var_name_pinned() {
        assert_eq!(ENV_SKIP_DASHBOARD_BUILD, "RAXIS_E2E_SKIP_DASHBOARD_BUILD");
        assert_eq!(
            ENV_NPM_INSTALL_TIMEOUT_SECS,
            "RAXIS_E2E_NPM_INSTALL_TIMEOUT_SECS"
        );
        assert_eq!(
            ENV_NPM_BUILD_TIMEOUT_SECS,
            "RAXIS_E2E_NPM_BUILD_TIMEOUT_SECS"
        );
    }

    /// Every panic produced by the auto-bundle pipeline carries
    /// the [`FE_BUNDLE_VIOLATION_TOKEN`] verbatim so a CI log
    /// scraper can pin the failure mode without parsing the
    /// whole remediation body. Pin the token shape so a
    /// rephrase doesn't silently break the scraper.
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_present_01_violation_token_shape() {
        assert_eq!(
            FE_BUNDLE_VIOLATION_TOKEN,
            "INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01 VIOLATED",
        );
    }

    /// `npm install` / `npm run build` timeouts default to
    /// generous-but-bounded values. Pin the defaults so a
    /// regression that flipped one of them to `0` (which would
    /// disable the bound, re-introducing the
    /// `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01` violation)
    /// trips here.
    // Constant guards: enforce the generous-but-bounded
    // `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01` envelope at
    // compile time. Runtime `assert!`s on `const` values would
    // be optimised out and Clippy correctly flags them as dead.
    const _: () = {
        assert!(
            DEFAULT_NPM_INSTALL_TIMEOUT_SECS >= 60,
            "install timeout must allow a cold registry pull"
        );
        assert!(
            DEFAULT_NPM_INSTALL_TIMEOUT_SECS <= 1800,
            "install timeout must be bounded (30 min ceiling)"
        );
        assert!(
            DEFAULT_NPM_BUILD_TIMEOUT_SECS >= 30,
            "build timeout must allow a real `tsc -b && vite build`"
        );
        assert!(
            DEFAULT_NPM_BUILD_TIMEOUT_SECS <= 900,
            "build timeout must be bounded (15 min ceiling)"
        );
    };

    /// `node_modules_vite_present` returns `false` for an
    /// empty / missing tree (the iter52 root-cause shape: a
    /// fresh `git worktree add` with no `npm ci` ever run leaves
    /// `dashboard-fe/node_modules/` absent, which the previous
    /// implementation silently glossed over and tried to run
    /// `npm run build` against, getting `tsc: command not found`).
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_present_01_node_modules_probe_handles_missing_tree() {
        let tmp = tempfile::tempdir().expect("create tmpdir");
        // No node_modules/ at all.
        assert!(
            !node_modules_vite_present(tmp.path()),
            "missing node_modules/ MUST classify as absent",
        );
        // node_modules/ present but empty (.bin missing) — the
        // half-pruned shape that bites in practice.
        std::fs::create_dir_all(tmp.path().join("node_modules")).expect("mkdir node_modules");
        assert!(
            !node_modules_vite_present(tmp.path()),
            "node_modules/ without .bin/vite|.bin/tsc MUST classify as absent",
        );
        // node_modules/.bin/vite present (synthetic shape) — happy
        // path. We only stat the file so any non-empty marker works.
        std::fs::create_dir_all(tmp.path().join("node_modules").join(".bin"))
            .expect("mkdir node_modules/.bin");
        std::fs::write(
            tmp.path().join("node_modules").join(".bin").join("vite"),
            b"#!/bin/sh\nexit 0\n",
        )
        .expect("write fake vite");
        assert!(
            node_modules_vite_present(tmp.path()),
            "node_modules/.bin/vite presence MUST classify as healthy",
        );
    }

    // ── V3 iter69 — `INV-LIVE-E2E-DASHBOARD-PORT-CLEAR-ON-BOOT-01`
    //
    // Pin the opt-out env-var name + the empty-listeners
    // fast-path shape so a regression that renames the env var
    // or makes the helper hang on a free port surfaces here
    // rather than at next live-e2e bootstrap.

    #[test]
    fn inv_live_e2e_dashboard_port_clear_on_boot_01_env_var_name_pinned() {
        assert_eq!(
            ENV_SKIP_DASHBOARD_PORT_PREFLIGHT,
            "RAXIS_E2E_SKIP_DASHBOARD_PORT_PREFLIGHT",
        );
    }

    #[test]
    fn inv_live_e2e_dashboard_port_clear_on_boot_01_listening_pids_returns_empty_on_free_port() {
        // Bind a fresh ephemeral socket so we *know* the OS just
        // assigned us a free port, drop the listener, and probe.
        // The probe must return Vec::new() in <100ms.
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral test port");
        let port = listener.local_addr().expect("ephemeral local_addr").port();
        drop(listener);
        let started = Instant::now();
        let pids = listening_pids_on_port(port);
        let elapsed = started.elapsed();
        assert!(
            pids.is_empty(),
            "freshly-released ephemeral port {port} must have no listeners, got {pids:?}",
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "listening_pids_on_port must answer in <5s on a free port (got {elapsed:?})",
        );
    }

    /// Bounded-timeout helpers honour the env-var override and
    /// fall back to the default on a parse error / empty
    /// string / non-positive value (so a misconfigured CI lane
    /// does not falsely fail the invariant witness).
    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_present_01_timeout_overrides_clamp_safely() {
        // Snapshot + restore the env vars so the test is
        // hermetic against parallel runs in the same process.
        struct EnvGuard(&'static str, Option<String>);
        impl EnvGuard {
            fn set(key: &'static str, value: &str) -> Self {
                let prior = std::env::var(key).ok();
                // SAFETY: Test-only mutation guarded by Drop.
                unsafe {
                    std::env::set_var(key, value);
                }
                EnvGuard(key, prior)
            }
            fn unset(key: &'static str) -> Self {
                let prior = std::env::var(key).ok();
                // SAFETY: Test-only mutation guarded by Drop.
                unsafe {
                    std::env::remove_var(key);
                }
                EnvGuard(key, prior)
            }
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.1 {
                    // SAFETY: Test-only restore.
                    Some(v) => unsafe {
                        std::env::set_var(self.0, v);
                    },
                    None => unsafe {
                        std::env::remove_var(self.0);
                    },
                }
            }
        }

        let _g = EnvGuard::unset(ENV_NPM_INSTALL_TIMEOUT_SECS);
        assert_eq!(
            npm_install_timeout(),
            Duration::from_secs(DEFAULT_NPM_INSTALL_TIMEOUT_SECS)
        );
        let _g = EnvGuard::set(ENV_NPM_INSTALL_TIMEOUT_SECS, "1200");
        assert_eq!(npm_install_timeout(), Duration::from_secs(1200));
        let _g = EnvGuard::set(ENV_NPM_INSTALL_TIMEOUT_SECS, "0");
        assert_eq!(
            npm_install_timeout(),
            Duration::from_secs(DEFAULT_NPM_INSTALL_TIMEOUT_SECS),
            "non-positive override MUST fall back to default",
        );
        let _g = EnvGuard::set(ENV_NPM_INSTALL_TIMEOUT_SECS, "garbage");
        assert_eq!(
            npm_install_timeout(),
            Duration::from_secs(DEFAULT_NPM_INSTALL_TIMEOUT_SECS),
            "unparseable override MUST fall back to default",
        );
    }
}
