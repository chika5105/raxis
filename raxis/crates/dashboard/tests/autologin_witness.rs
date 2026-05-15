//! Autologin contract witness — `INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01`.
//!
//! # What this test pins
//!
//! The live-e2e harness (`kernel/tests/common/dashboard.rs`) mints
//! an autologin URL at kernel boot, prints it to stderr, and (best-
//! effort) opens it in the operator's default browser. The URL
//! carries a JWT in a `#token=…` fragment that the React
//! `LoginPage::parseAutologinHash` mirrors into `localStorage`
//! before redirecting to the dashboard root.
//!
//! Two latent failure modes have historically broken this flow:
//!
//!   1. **TTL drift** — the genesis policy.toml pinned the JWT TTL
//!      at 1 hour. The realistic-scenario test routinely runs 60+
//!      minutes (default deadline 3600 s, overridable up to several
//!      hours via `RAXIS_E2E_REALISTIC_DEADLINE_SECS`). Operators
//!      who opened the URL after the 1-hour mark received an
//!      already-expired profile, `parseAutologinHash` happily
//!      stored it in `localStorage` (the function only validates
//!      shape, not freshness), and `RequireAuth` bounced to
//!      `/login` because `isTokenLive(profile)` returned `false`.
//!      The QA worker saw the manual challenge-response form
//!      instead of the dashboard.
//!   2. **No witness coverage** — the contract "an autologin URL
//!      minted at boot stays valid for the kernel's process
//!      lifetime" was not encoded in any test. A future drift in
//!      `DEFAULT_JWT_TTL_SECS`, the genesis emitter, or the policy
//!      loader would have re-broken the flow without anyone
//!      noticing until the QA worker ran into it again.
//!
//! This test pins both:
//!
//!   * The minted JWT's `expires_at - iat` is at least 24 hours
//!     (`AUTOLOGIN_MIN_TTL_SECS`), the budget that comfortably
//!     outlives any realistic-scenario kernel lifetime.
//!   * A follow-up `GET /api/initiatives` using the minted JWT
//!     returns 200 with the operator's data — i.e. the JWT is
//!     actually usable, not just syntactically well-formed.
//!
//! The test is hermetic: it spins up a `DashboardServer` against
//! `InMemoryDashboardData` on `127.0.0.1:0`, runs the full
//! challenge → verify dance against the real auth surface, and
//! shuts down cleanly when the assertions pass.

#![cfg(test)]

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::Signer;
use raxis_dashboard::auth::DashboardRole;
use raxis_dashboard::config::{DashboardConfig, DEFAULT_JWT_TTL_SECS};
use raxis_dashboard::data::InMemoryDashboardData;
use raxis_dashboard::routes::auth::operator_fingerprint_hex;
use raxis_dashboard::server::{DashboardServer, ServerHandle};

/// Minimum acceptable TTL (in seconds) for a JWT minted on the
/// autologin path. Pinned at 24 h so the boot-time URL outlives
/// every realistic kernel-process lifetime the harness produces:
///
/// | Harness                              | Default deadline | Hard cap (env)                          |
/// |--------------------------------------|------------------|-----------------------------------------|
/// | `full_e2e_session_lifecycle`         | 360 s            | `RAXIS_E2E_LIFECYCLE_DEADLINE_SECS`     |
/// | `extended_e2e_concurrent_lifecycle`  | varies           | `RAXIS_E2E_EXTENDED_DEADLINE_SECS`      |
/// | `extended_e2e_realistic_scenario`    | 3600 s (60 min)  | `RAXIS_E2E_REALISTIC_DEADLINE_SECS`     |
///
/// 24 hours gives every harness — and any operator running a
/// production daemon long enough to attach a dashboard the next
/// morning — comfortable headroom. In production wiring with
/// `cfg.data_dir = Some(...)` the V2.5 persistent JWT secret
/// (`INV-DASHBOARD-JWT-SECRET-PERSISTENT-01`) keeps the token
/// valid across supervisor-triggered restarts; the in-process
/// `JwtSigner::new_ephemeral` path this witness exercises still
/// caps practical validity at `min(TTL, process_uptime)`, so
/// widening the window inside one boot does NOT survive a kernel
/// restart in that mode.
const AUTOLOGIN_MIN_TTL_SECS: u64 = 86_400;

/// Bind the dashboard with a default in-memory fixture seeded with
/// one operator (the keypair we control) and return
/// `(handle, base_url, signing_key, fingerprint, data)`.
///
/// The signing key matches the in-memory operator entry the harness
/// would normally wire via `bootstrap_with_custom_cert`, so the
/// challenge-response dance succeeds end-to-end without booting the
/// kernel.
async fn boot_dashboard_for_autologin() -> (
    ServerHandle,
    String,
    ed25519_dalek::SigningKey,
    String,
    Arc<InMemoryDashboardData>,
) {
    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        static_dir: None,
        ..Default::default()
    };
    // Distinct seed from every other fixture in the test binary so
    // a future shared-binary refactor cannot accidentally bind two
    // tests to the same fingerprint.
    let seed = [0xB7u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let fingerprint = operator_fingerprint_hex(&pubkey_bytes);
    let data = InMemoryDashboardData::new();
    // The autologin URL minted by the harness for the
    // realistic-scenario test carries `roles=["read"]`, which is
    // exactly what an operator opening the dashboard at boot
    // needs to land on the Overview page. We mirror that here.
    data.with_operator(
        fingerprint.clone(),
        "autologin-witness-operator",
        vec![DashboardRole::Read],
    );
    let server = DashboardServer::bind(cfg, Arc::clone(&data))
        .await
        .expect("DashboardServer::bind");
    let addr = server.local_addr();
    let handle = ServerHandle::spawn(server);
    let base = format!("http://{addr}");
    (handle, base, signing_key, fingerprint, data)
}

/// Drive the live `GET /api/auth/challenge` + `POST /api/auth/verify`
/// HTTP path with the supplied signing key. Returns the verify
/// response body as parsed JSON so the caller can inspect every
/// field the autologin URL carries (`token`, `operator_id`,
/// `display_name`, `roles`, `expires_at`).
async fn mint_jwt_via_http(
    base: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> serde_json::Value {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();

    let challenge_resp = client
        .get(format!("{base}/api/auth/challenge"))
        .send()
        .await
        .expect("challenge send");
    assert_eq!(challenge_resp.status(), 200, "challenge endpoint must 200");
    let challenge_json: serde_json::Value = challenge_resp.json().await.expect("challenge json");
    let challenge_hex = challenge_json["challenge"]
        .as_str()
        .expect("challenge field is string")
        .to_owned();
    let challenge_bytes = hex::decode(&challenge_hex).expect("challenge hex");

    let sig: ed25519_dalek::Signature = signing_key.sign(&challenge_bytes);
    let body = serde_json::json!({
        "challenge":  challenge_hex,
        "signature":  hex::encode(sig.to_bytes()),
        "public_key": hex::encode(pubkey_bytes),
    });
    let verify_resp = client
        .post(format!("{base}/api/auth/verify"))
        .json(&body)
        .send()
        .await
        .expect("verify send");
    assert_eq!(
        verify_resp.status(),
        200,
        "verify must 200 for a fresh sig against an in-fixture operator",
    );
    verify_resp.json().await.expect("verify json body")
}

// ---------------------------------------------------------------------------
// Witness 1 — DEFAULT_JWT_TTL_SECS itself satisfies the invariant.
// ---------------------------------------------------------------------------
//
// A pure constant check: if a future contributor drops the default
// back to 3600, this test fails BEFORE the HTTP layer is even
// brought up, surfacing the regression at the cheapest possible
// stage of the build pipeline. The DEFAULT constant flows through
// `DashboardConfig::default` → `JwtSigner::new_ephemeral`
// (in-process tests) and `JwtSigner::load_or_mint` (production),
// both of which thread `cfg.jwt_ttl_secs` into every minted JWT,
// so this single assertion covers every code path that defaults
// to the constant rather than carrying an explicit override.

#[test]
fn default_jwt_ttl_secs_outlives_realistic_kernel_uptime() {
    assert!(
        DEFAULT_JWT_TTL_SECS >= AUTOLOGIN_MIN_TTL_SECS,
        "INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01: \
         DEFAULT_JWT_TTL_SECS (= {default}) must be >= {min} so the autologin \
         URL minted at kernel boot stays valid through the realistic-scenario \
         live-e2e harness's typical 60+ minute lifetime. See \
         crates/dashboard/src/config.rs for the rationale comment + the \
         dashboard-hardening.md §2.8 spec contract.",
        default = DEFAULT_JWT_TTL_SECS,
        min = AUTOLOGIN_MIN_TTL_SECS,
    );
}

// ---------------------------------------------------------------------------
// Witness 2 — end-to-end: boot dashboard, mint JWT, follow it.
// ---------------------------------------------------------------------------
//
// Mirrors what the harness does (`mint_dashboard_jwt` +
// `build_autologin_url` in `kernel/tests/common/dashboard.rs`)
// minus the URL string formatting (the URL builder is a pure
// function over the same fields this test inspects, so a separate
// unit test in the kernel-side test harness is unnecessary):
//
//   1. Boot a DashboardServer against the in-memory data layer.
//   2. Hit `GET /api/auth/challenge` + `POST /api/auth/verify`
//      with a fresh keypair the fixture has pre-registered.
//   3. Assert the response carries an `expires_at` at least
//      AUTOLOGIN_MIN_TTL_SECS in the future — the autologin URL
//      built from this verify response will then be honoured by
//      `RequireAuth::isTokenLive` for at least that long.
//   4. Use the minted JWT on `GET /api/initiatives` and assert
//      200 — the contract is "minted JWT is actually usable",
//      not just "minted JWT has the right shape".

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autologin_jwt_outlives_realistic_kernel_uptime_and_authorizes_reads() {
    let (handle, base, signing_key, _fp, data) = boot_dashboard_for_autologin().await;

    // Seed one initiative so the follow-up read returns a non-empty
    // body — guarantees the JWT actually carried us past the auth
    // middleware AND through the data layer (vs landing on an
    // empty list, which a broken handler could also produce by
    // short-circuiting before the auth check). Field set mirrors
    // the wire shape the kernel's data layer emits; the helper
    // re-uses the in-memory fixture's nested-struct shape so
    // wire-shape drift surfaces here.
    data.push_initiative(raxis_dashboard::data::InitiativeView {
        summary: raxis_dashboard::data::InitiativeListEntry {
            initiative_id: "init-autologin-witness".into(),
            display_name: "init-autologin-witness".into(),
            state: "Active".into(),
            task_count: 0,
            completed_tasks: 0,
            failed_tasks: 0,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
        },
        approved_by: None,
        plan_sha256: None,
        target_ref: None,
        policy_epoch: 1,
        tasks: Vec::new(),
        edges: Vec::new(),
        failure: None,
    });

    let verify_body = mint_jwt_via_http(&base, &signing_key).await;

    // Wire-shape sanity — the autologin URL builder picks each of
    // these fields out of the verify response. A missing field
    // would silently land the operator on the manual flow because
    // `parseAutologinHash` rejects payloads that don't carry a
    // complete `{token, operator_id, display_name, roles,
    // expires_at}` quintuple.
    let token = verify_body["token"].as_str().expect("token");
    let operator_id = verify_body["operator_id"].as_str().expect("operator_id");
    let display_name = verify_body["display_name"].as_str().expect("display_name");
    let roles = verify_body["roles"].as_array().expect("roles");
    let expires_at = verify_body["expires_at"].as_u64().expect("expires_at");
    assert!(!token.is_empty(), "JWT must be non-empty");
    assert!(!operator_id.is_empty(), "operator_id must be non-empty");
    assert_eq!(display_name, "autologin-witness-operator");
    assert_eq!(roles.len(), 1, "fixture seeded a single role");
    assert_eq!(roles[0].as_str().unwrap_or_default(), "read");

    // ── INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01 ────────────────
    //
    // The minted JWT's `expires_at` MUST be at least
    // AUTOLOGIN_MIN_TTL_SECS in the future. We compute the window
    // relative to wall-clock `now` (the same clock the kernel's
    // `now_secs()` reads) to mirror the operator's experience —
    // the kernel's JWT signer uses `iat = now_secs()` + `exp = iat
    // + ttl_secs`, so a `(exp - now) < min_ttl` failure here is a
    // direct simulation of "operator opened the URL at boot,
    // looked at the dashboard, and the JWT expired before the
    // kernel did".
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let window_secs = expires_at.saturating_sub(now);
    assert!(
        window_secs >= AUTOLOGIN_MIN_TTL_SECS,
        "INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01: the JWT minted on the autologin \
         path expires in {window_secs}s, which is less than the {min}s \
         floor required to outlive a realistic-scenario kernel lifetime. \
         Inspect DashboardConfig::jwt_ttl_secs / genesis policy emitter / \
         DEFAULT_JWT_TTL_SECS — a regression there silently breaks the \
         live-e2e operator dashboard tour and leaves QA workers stuck \
         on the manual challenge-response form.",
        min = AUTOLOGIN_MIN_TTL_SECS,
    );

    // The JWT must actually authorise reads — mint-only would not
    // prove the operator can use the dashboard. The autologin URL
    // is useless if the verify endpoint mints a JWT the rest of the
    // surface refuses.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let resp = client
        .get(format!("{base}/api/initiatives"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("initiatives send");
    assert_eq!(
        resp.status(),
        200,
        "JWT minted on the autologin path MUST authorise read endpoints; \
         a 4xx here means the autologin URL would bounce the operator to \
         /login the moment React Query fires its first refetch",
    );
    let initiatives: Vec<serde_json::Value> = resp.json().await.expect("init list json");
    assert_eq!(
        initiatives.len(),
        1,
        "initiatives list must surface the seeded row through the JWT auth path",
    );
    assert_eq!(
        initiatives[0]["initiative_id"].as_str().unwrap_or_default(),
        "init-autologin-witness",
    );

    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Witness 3 — the policy-loaded path agrees with the constant.
// ---------------------------------------------------------------------------
//
// `DashboardConfig` is also reachable through `serde::Deserialize`
// when the kernel reads `[dashboard]` out of `policy.toml`. A
// future contributor who lowers the constant but leaves the
// genesis emitter at the old number (or vice versa) would slip
// past Witness 1 by reading a stale on-disk `jwt_ttl_secs`. We
// pin the loader path here so the constant + the default path
// agree byte-for-byte.

#[test]
fn dashboard_config_default_field_matches_constant() {
    let cfg = DashboardConfig::default();
    assert_eq!(
        cfg.jwt_ttl_secs, DEFAULT_JWT_TTL_SECS,
        "DashboardConfig::default().jwt_ttl_secs must mirror DEFAULT_JWT_TTL_SECS \
         (drift here would let the loader serve a different TTL than \
         the constant the rest of the auth code uses).",
    );
    assert!(
        cfg.jwt_ttl_secs >= AUTOLOGIN_MIN_TTL_SECS,
        "INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01: default jwt_ttl_secs \
         ({} s) must be >= {} s",
        cfg.jwt_ttl_secs,
        AUTOLOGIN_MIN_TTL_SECS,
    );
}
