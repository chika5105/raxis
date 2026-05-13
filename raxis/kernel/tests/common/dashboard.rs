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
//! ## Auto-build of the React bundle
//!
//! [`locate_dashboard_dist`] runs `npm run build` on demand if
//! `dashboard-fe/dist/index.html` is missing. Without the bundle
//! the kernel's dashboard server returns HTTP 404 for `/`,
//! `/login`, and every SPA route — silently breaking operator-side
//! review during a live-e2e run. CI lanes that pre-build the
//! bundle (or genuinely want JSON-only) can opt out via
//! `RAXIS_E2E_SKIP_DASHBOARD_BUILD=1`. Build failure is tolerated
//! (falls back to JSON-only) so the live-e2e fix loop can still
//! iterate on non-UI failure modes when the FE is broken.

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

/// Absolute path to the React production bundle, building it on
/// demand if missing. The kernel's `[dashboard].static_dir` field
/// consumes this; without a real `dist/index.html` the dashboard
/// server returns HTTP 404 for `/`, `/login`, and every SPA route,
/// which silently breaks operator-side review during a live-e2e
/// run (the JSON API still works, but no UI). The CARGO_MANIFEST_DIR
/// anchor is the `kernel/` crate root, so `..` walks to `raxis/`.
///
/// Auto-build policy: if `dashboard-fe/dist/index.html` is absent,
/// run `npm run build` from `dashboard-fe/`. This is opt-out via
/// `RAXIS_E2E_SKIP_DASHBOARD_BUILD=1` for CI lanes that pre-build
/// the bundle as a separate step. Build failure surfaces a clear
/// remediation message and falls back to JSON-only mode (rather
/// than panicking the entire test) so the live-e2e fix loop can
/// still iterate on non-UI failure modes when the FE is broken.
pub fn locate_dashboard_dist() -> Option<PathBuf> {
    let raxis_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent()?.to_path_buf();
    let fe_root = raxis_root.join("dashboard-fe");
    let dist = fe_root.join("dist");

    if dist.join("index.html").is_file() {
        return Some(dist);
    }

    if std::env::var("RAXIS_E2E_SKIP_DASHBOARD_BUILD")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        eprintln!(
            "[dashboard-bundle] dashboard-fe/dist not present and \
             RAXIS_E2E_SKIP_DASHBOARD_BUILD=1 — dashboard will serve \
             JSON API only (no UI)."
        );
        return None;
    }

    if !fe_root.join("package.json").is_file() {
        eprintln!(
            "[dashboard-bundle] dashboard-fe/package.json missing at {}; \
             cannot auto-build the React bundle. Dashboard will serve \
             JSON API only (no UI).",
            fe_root.display()
        );
        return None;
    }

    eprintln!(
        "[dashboard-bundle] dashboard-fe/dist/index.html missing — \
         running `npm run build` in {} (opt out via \
         RAXIS_E2E_SKIP_DASHBOARD_BUILD=1)",
        fe_root.display()
    );
    let build_started = std::time::Instant::now();
    let status = std::process::Command::new("npm")
        .arg("run")
        .arg("build")
        .current_dir(&fe_root)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();
    match status {
        Ok(s) if s.success() => {
            eprintln!(
                "[dashboard-bundle] npm run build OK in {:.1}s",
                build_started.elapsed().as_secs_f32()
            );
        }
        Ok(s) => {
            eprintln!(
                "[dashboard-bundle] npm run build exited with {s:?}; \
                 dashboard will serve JSON API only (no UI). Re-run \
                 `cd raxis/dashboard-fe && npm install && npm run build` \
                 manually to diagnose."
            );
            return None;
        }
        Err(e) => {
            eprintln!(
                "[dashboard-bundle] failed to spawn `npm run build`: \
                 {e}. Dashboard will serve JSON API only (no UI). \
                 Install Node + npm or set RAXIS_E2E_SKIP_DASHBOARD_BUILD=1 \
                 to silence this."
            );
            return None;
        }
    }

    if dist.join("index.html").is_file() {
        Some(dist)
    } else {
        eprintln!(
            "[dashboard-bundle] post-build sanity check failed: {} not \
             present after `npm run build`. Falling back to JSON-only.",
            dist.join("index.html").display()
        );
        None
    }
}

/// Result of [`mint_dashboard_jwt`]. `None` ⇒ best-effort failure
/// the caller must tolerate (browser-open is skipped). Field
/// shape mirrors the dashboard's `/api/auth/verify` JSON response
/// 1:1 so [`build_autologin_url`] can re-emit them in the URL
/// fragment the React `LoginPage::parseAutologinHash` consumes.
pub struct DashboardSession {
    pub token:        String,
    pub operator_id:  String,
    pub display_name: String,
    pub roles:        Vec<String>,
    pub expires_at:   u64,
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
            s.push_str(&format!("static_dir   = {:?}\n", dist.display().to_string()));
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
        if std::net::TcpStream::connect_timeout(
            &parsed, Duration::from_millis(250),
        ).is_ok() {
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
    if challenge_bytes.len() != 32 { return None; }

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
    eprintln!(
        "[{label}] dashboard manual-fallback (paste into /login if autologin fails):"
    );
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
        token:        verify_payload.get("token")?.as_str()?.to_owned(),
        operator_id:  verify_payload.get("operator_id")?.as_str()?.to_owned(),
        display_name: verify_payload.get("display_name")?.as_str()?.to_owned(),
        roles:        verify_payload.get("roles")?
                         .as_array()?
                         .iter()
                         .filter_map(|v| v.as_str().map(str::to_owned))
                         .collect(),
        expires_at:   verify_payload.get("expires_at")?.as_u64()?,
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
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
                | b'-' | b'_' | b'.' | b'~' => vec![b],
                _ => format!("%{b:02X}").into_bytes(),
            })
            .map(|b| b as char)
            .collect()
    }
    let roles_csv = session.roles.iter()
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
        addr  = DASHBOARD_BIND_ADDRESS,
        port  = port,
        token = encode(&session.token),
        op    = encode(&session.operator_id),
        name  = encode(&session.display_name),
        roles = roles_csv,
        exp   = session.expires_at,
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
        OpenOutcome::Printed => Err(
            "no URL opener could be invoked on this host (URL was printed)".to_owned(),
        ),
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
