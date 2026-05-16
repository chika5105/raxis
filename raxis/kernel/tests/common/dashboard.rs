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
//! ## Auto-build of the React bundle (`INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01`)
//!
//! [`locate_dashboard_dist`] runs `npm ci` (when `node_modules/`
//! is absent) followed by `npm run build` on demand if
//! `dashboard-fe/dist/index.html` is missing. Without the bundle
//! the kernel's dashboard server returns HTTP 404 for `/`,
//! `/login`, and every SPA route — silently breaking operator-side
//! review during a live-e2e run.
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

/// Pure-data classification of the `dashboard-fe` workspace state
/// at the moment the harness needs to mount the dashboard. Drives
/// the dispatch in [`locate_dashboard_dist`] and is exhaustively
/// witness-tested below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleState {
    /// `dashboard-fe/dist/index.html` is already on disk — the
    /// fast path. No subprocess work needed; the harness just
    /// hands the path to the kernel.
    DistAlreadyBuilt,

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
pub fn classify_bundle_state(
    dist_index_present: bool,
    skip_env_set: bool,
    package_json_present: bool,
    node_modules_vite_present: bool,
) -> BundleState {
    if dist_index_present {
        return BundleState::DistAlreadyBuilt;
    }
    if skip_env_set {
        return BundleState::OptOutByEnv;
    }
    if !package_json_present {
        return BundleState::HardFailMissingPackageJson;
    }
    if !node_modules_vite_present {
        return BundleState::NeedsInstallThenBuild;
    }
    BundleState::NeedsBuildOnly
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

    let state = classify_bundle_state(
        dist_index.is_file(),
        skip_env,
        package_json_present,
        node_modules_ok,
    );

    match state {
        BundleState::DistAlreadyBuilt => Some(dist),
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
pub fn mutate_dashboard_block_in_policy(data_dir: &Path) {
    let policy_path = data_dir.join("policy").join("policy.toml");
    let mut body = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", policy_path.display()));
    const NEEDLE: &str = "bind_port    = 9820\n";
    let port = configured_dashboard_port();
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
    fn inv_live_e2e_dashboard_fe_bundle_present_01_classifier_dist_already_built_wins() {
        // Even with everything else broken, an existing dist
        // index file is always the fast path — never re-build.
        for skip in [false, true] {
            for pkg in [false, true] {
                for nm in [false, true] {
                    assert_eq!(
                        classify_bundle_state(true, skip, pkg, nm),
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
        for pkg in [false, true] {
            for nm in [false, true] {
                assert_eq!(
                    classify_bundle_state(false, true, pkg, nm),
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
                classify_bundle_state(false, false, false, nm),
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
            classify_bundle_state(false, false, true, false),
            BundleState::NeedsInstallThenBuild,
        );
    }

    #[test]
    fn inv_live_e2e_dashboard_fe_bundle_present_01_classifier_node_modules_present_needs_build_only(
    ) {
        // No dist + no opt-out + package.json + node_modules.bin
        // populated ⇒ skip install, just build.
        assert_eq!(
            classify_bundle_state(false, false, true, true),
            BundleState::NeedsBuildOnly,
        );
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
