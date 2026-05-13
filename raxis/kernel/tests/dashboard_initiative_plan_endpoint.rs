//! Witness test for the `GET /api/initiatives/:id/plan` endpoint.
//!
//! Normative reference:
//!   * `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01` — every approved
//!     initiative MUST surface its **original submitted** `plan.toml`
//!     to read-role operators within 60 s of approval, byte-for-byte
//!     (no re-parse / re-serialize).
//!   * `dashboard-hardening.md §plan-view` — wire shape, status
//!     codes (200 / 404 / 410), and Cache-Control contract.
//!
//! What this exercises (with REAL runtime objects, no mocks):
//!   1. The full HTTP path: `KernelDashboardData → axum router →
//!      reqwest client`, reaching `data::get_initiative_plan` after
//!      the JWT challenge-response handshake.
//!   2. Both kernel-store back-ends:
//!        * V1 (`signed_plan_artifacts`)
//!        * V2.1 (`plan_bundles` + `plan_bundle_artifacts`)
//!      fall through the same `views::plan_fields::submitted_toml_for_initiative`
//!      lookup, so the wire body is byte-identical to the bytes the
//!      operator originally sealed.
//!   3. Error disambiguation:
//!        * 404 — initiative id unknown (typo / stale link).
//!        * 410 — initiative exists but its plan blob is missing
//!          (the dashboard renders "Plan archived" rather than a
//!          generic 5xx).
//!   4. The `Cache-Control` header: `private, max-age=60` for
//!      approved plans, `private, no-store` for `Draft` plans whose
//!      bytes are still volatile.
//!
//! Linked invariants:
//!   * `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`
//!   * `INV-DASHBOARD-AUTH-01` (anonymous → 401)

#![cfg(test)]

use std::sync::Arc;

use arc_swap::ArcSwap;
use ed25519_dalek::{Signer, SigningKey};
use raxis_audit_tools::genesis::write_genesis_segment;
use raxis_dashboard::config::DashboardConfig;
use raxis_policy::{OperatorEntry, PolicyBundle};
use raxis_store::Store;
use raxis_test_support::stub_cert_for_pubkey;
use raxis_types::{
    BundleArtifact, BundleNonce, BundleSha256, OperatorFingerprint, PlanBundle,
};
use rusqlite::{params, TransactionBehavior};

/// Spin up a fresh on-disk data dir with `kernel.db` migrated and
/// a genesis-ed audit chain. Returns the tempdir guard so its
/// lifetime outlives the caller's reads.
fn fresh_data_dir() -> (tempfile::TempDir, Arc<Store>) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd  = tmp.path();
    std::fs::create_dir_all(dd.join("audit")).unwrap();
    write_genesis_segment(&dd.join("audit"), &[0xC1u8; 32], &[0u8; 64], 1_700_000_000)
        .expect("write_genesis_segment");
    let store = Store::open(&dd.join("kernel.db")).expect("Store::open");
    (tmp, Arc::new(store))
}

/// Build a single-operator policy bundle whose only operator is
/// `op_pk`, with `permitted_ops` driving the dashboard role mapper.
/// The fingerprint is the SHA-256 prefix the dashboard auth layer
/// expects for JWT-issued bearer tokens.
fn policy_with_operator(op_pk: [u8; 32]) -> Arc<ArcSwap<PolicyBundle>> {
    use sha2::Digest;
    let pubkey_hex  = hex::encode(op_pk);
    let fingerprint = hex::encode(&sha2::Sha256::digest(op_pk)[..16]);
    let bundle = PolicyBundle::for_tests_with_operators(vec![OperatorEntry {
        pubkey_fingerprint: fingerprint,
        display_name:       "alice".into(),
        pubkey_hex:         pubkey_hex.clone(),
        permitted_ops:      Vec::new(),
        cert:               stub_cert_for_pubkey(pubkey_hex),
        force_misconfig_bypass: false,
    }]);
    Arc::new(ArcSwap::from_pointee(bundle))
}

/// Run the JWT challenge → sign → verify dance against `base` and
/// return the bearer token. Mirrors the helper in
/// `dashboard_kernel_data.rs` so the two suites stay in sync; we
/// duplicate it locally rather than export it because the support
/// crate is `pub(crate)`-shy and a test-only helper would creep
/// into the public surface.
async fn obtain_token(
    base:    &str,
    client:  &reqwest::Client,
    signing: &SigningKey,
    pk:      [u8; 32],
) -> String {
    use reqwest::header::CONTENT_TYPE;
    use serde_json::json;

    let chal: serde_json::Value = client
        .get(format!("{base}/api/auth/challenge"))
        .send().await.unwrap()
        .json().await.unwrap();
    let challenge_hex = chal["challenge"].as_str().unwrap().to_owned();
    let sig = signing.sign(&hex::decode(&challenge_hex).unwrap());
    let body = json!({
        "challenge":  challenge_hex,
        "signature":  hex::encode(sig.to_bytes()),
        "public_key": hex::encode(pk),
    });
    let verify: serde_json::Value = client
        .post(format!("{base}/api/auth/verify"))
        .header(CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send().await.unwrap()
        .json().await.unwrap();
    verify["token"].as_str().unwrap().to_owned()
}

/// Insert one `initiatives` row plus its `signed_plan_artifacts`
/// header so the V1 lookup path resolves to `plan_bytes`. Mirrors
/// the kernel's pre-V2 admission write set.
async fn seed_v1_initiative(
    store:               &Store,
    initiative_id:       &str,
    state:               &str,
    approved_at_unix:    Option<i64>,
    plan_bytes:          &[u8],
    signed_by_fingerprint: &str,
    stored_at_unix:      i64,
) {
    let conn = store.lock().await;
    let initiatives          = raxis_store::Table::Initiatives.as_str();
    let signed_plan_artifacts = raxis_store::Table::SignedPlanArtifacts.as_str();

    conn.execute(
        &format!(
            "INSERT INTO {initiatives} \
                 (initiative_id, state, terminal_criteria_json, \
                  plan_artifact_sha256, created_at, approved_at) \
             VALUES (?1, ?2, '{{}}', 'sha-bytes', 1700000000, ?3)"
        ),
        params![initiative_id, state, approved_at_unix],
    ).unwrap();
    conn.execute(
        &format!(
            "INSERT INTO {signed_plan_artifacts} \
                 (initiative_id, plan_bytes, plan_sig, stored_at, \
                  signed_by_fingerprint) \
             VALUES (?1, ?2, X'00', ?3, ?4)"
        ),
        params![initiative_id, plan_bytes, stored_at_unix, signed_by_fingerprint],
    ).unwrap();
}

/// Insert one `initiatives` row whose `plan_bundle_sha256` points
/// at a freshly-sealed V2.1 bundle holding the supplied plan TOML
/// at `artifact_seq=0`. Mirrors the V2 admission write set
/// described in `plan-bundle-sealing.md §8.1 step 12`.
async fn seed_v2_1_initiative(
    store:                &Store,
    initiative_id:        &str,
    approved_at_unix:     Option<i64>,
    plan_bytes:           &[u8],
    bundle_sha256:        BundleSha256,
    plan_artifact_sha256: BundleSha256,
    bundle_nonce:         BundleNonce,
    signed_by:            OperatorFingerprint,
    sealed_at_unix:       u64,
    signed_at_unix:       u64,
) {
    let bundle = PlanBundle::new_v2_1(
        sealed_at_unix,
        signed_at_unix,
        bundle_nonce,
        "witness-plan".to_owned(),
        vec![BundleArtifact {
            name:   "plan.toml".to_owned(),
            bytes:  plan_bytes.to_vec(),
            sha256: plan_artifact_sha256,
        }],
    );

    let mut conn = store.lock().await;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
    raxis_store::plan_bundles::insert_bundle(
        &tx, &bundle_sha256, b"canonical-bundle-bytes",
        &[0xCDu8; 64], &signed_by, &bundle, sealed_at_unix as i64,
    ).unwrap();
    raxis_store::plan_bundles::insert_artifacts(
        &tx, &bundle_sha256, &bundle.artifacts,
    ).unwrap();
    let initiatives = raxis_store::Table::Initiatives.as_str();
    tx.execute(
        &format!(
            "INSERT INTO {initiatives} \
                 (initiative_id, state, terminal_criteria_json, \
                  plan_artifact_sha256, created_at, approved_at, \
                  plan_bundle_sha256) \
             VALUES (?1, 'Executing', '{{}}', ?2, 1700000000, ?3, ?4)"
        ),
        params![
            initiative_id,
            hex::encode(plan_artifact_sha256.as_bytes()),
            approved_at_unix,
            bundle_sha256.as_bytes().as_slice(),
        ],
    ).unwrap();
    tx.commit().unwrap();
}

/// Insert an initiative WITHOUT any plan artifact to exercise the
/// "plan archived / purged" 410 path.
async fn seed_orphan_initiative(store: &Store, initiative_id: &str) {
    let conn = store.lock().await;
    let initiatives = raxis_store::Table::Initiatives.as_str();
    conn.execute(
        &format!(
            "INSERT INTO {initiatives} \
                 (initiative_id, state, terminal_criteria_json, \
                  plan_artifact_sha256, created_at) \
             VALUES (?1, 'Draft', '{{}}', 'sha-orphan', 1700000000)"
        ),
        params![initiative_id],
    ).unwrap();
}

// ───────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_endpoint_returns_v1_signed_bytes_byte_for_byte_with_cache_header() {
    use reqwest::header::AUTHORIZATION;

    let (tmp, store) = fresh_data_dir();

    // Sign the policy with a known operator key for the JWT
    // handshake.
    let signing = SigningKey::from_bytes(&[0x71u8; 32]);
    let pk      = signing.verifying_key().to_bytes();
    let policy  = policy_with_operator(pk);

    // Byte-precise plan body — embed bytes a re-serializer
    // would naturally re-format (trailing whitespace + comment +
    // unconventional spacing) so we can pin "byte-for-byte" in
    // the assertion below.
    let plan_bytes: &[u8] = b"# witness plan v1\n\
        [orchestrator]\n\
        model = \"opus-4\"   \n\
        \n\
        # trailing comment\n";

    seed_v1_initiative(
        &store,
        "init-v1",
        "Executing",
        Some(1_700_000_500),
        plan_bytes,
        "abcd1234abcd1234abcd1234abcd1234",
        1_700_000_400,
    ).await;

    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        ..Default::default()
    };
    let handle = raxis_dashboard_kernel::start_dashboard(
        cfg,
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
    ).await.expect("start_dashboard");

    let base   = format!("http://{}", handle.local_addr());
    let client = reqwest::Client::new();
    let token  = obtain_token(&base, &client, &signing, pk).await;

    let resp = client
        .get(format!("{base}/api/initiatives/init-v1/plan"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200, "happy path must 200");

    // Cache-Control must be the approved-plan flavour.
    let cc = resp
        .headers()
        .get("cache-control")
        .expect("cache-control header present")
        .to_str().unwrap()
        .to_owned();
    assert_eq!(cc, "private, max-age=60",
        "approved plans must carry the 60s private cache header");

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["initiative_id"], "init-v1");
    assert_eq!(body["approval_status"], "approved");
    assert_eq!(body["approved_at_unix"], 1_700_000_500);
    assert_eq!(body["submitted_at_unix"], 1_700_000_400);
    assert_eq!(body["submitted_by"], "abcd1234abcd1234abcd1234abcd1234");
    assert_eq!(
        body["submitted_toml_bytes"].as_u64().unwrap(),
        plan_bytes.len() as u64,
    );

    // Byte-for-byte fidelity is the load-bearing claim of
    // `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`. Read the
    // wire string back to bytes and compare.
    let wire_toml = body["submitted_toml"].as_str().expect("submitted_toml str");
    assert_eq!(
        wire_toml.as_bytes(),
        plan_bytes,
        "wire body MUST equal the originally-sealed plan_bytes byte-for-byte; \
         got {wire_toml:?}, expected {:?}",
        std::str::from_utf8(plan_bytes).unwrap(),
    );

    handle.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_endpoint_returns_v2_1_bundle_bytes_with_bundle_sha_metadata() {
    use reqwest::header::AUTHORIZATION;

    let (tmp, store) = fresh_data_dir();

    let signing = SigningKey::from_bytes(&[0x72u8; 32]);
    let pk      = signing.verifying_key().to_bytes();
    let policy  = policy_with_operator(pk);

    // Compute a real SHA-256 of the plan bytes so the wire
    // metadata round-trip is realistic. The bundle_sha256 is a
    // distinct synthetic value; the lookup keys off
    // `initiatives.plan_bundle_sha256` so any 32-byte blob works.
    let plan_bytes: &[u8] = b"# v2.1 witness\n[orchestrator]\nmodel = \"sonnet\"\n";
    let plan_sha = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(plan_bytes);
        BundleSha256::new(h.finalize().into())
    };
    let bundle_sha   = BundleSha256::new([0xB1u8; 32]);
    let bundle_nonce = BundleNonce::new([0x42u8; 16]);
    let signer_fp    = OperatorFingerprint::new([0x55u8; 8]);

    seed_v2_1_initiative(
        &store,
        "init-v2",
        Some(1_700_000_777),
        plan_bytes,
        bundle_sha,
        plan_sha,
        bundle_nonce,
        signer_fp,
        1_700_000_700u64, // sealed_at
        1_700_000_690u64, // signed_at (envelope)
    ).await;

    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        ..Default::default()
    };
    let handle = raxis_dashboard_kernel::start_dashboard(
        cfg,
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
    ).await.expect("start_dashboard");

    let base   = format!("http://{}", handle.local_addr());
    let client = reqwest::Client::new();
    let token  = obtain_token(&base, &client, &signing, pk).await;

    let resp = client
        .get(format!("{base}/api/initiatives/init-v2/plan"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(body["initiative_id"], "init-v2");
    assert_eq!(body["approval_status"], "approved");
    assert_eq!(body["approved_at_unix"], 1_700_000_777);
    // V2.1 surfaces the bundle hash + the operator-supplied
    // signed_at envelope timestamp (preferred over sealed_at when
    // both are present — see KernelDashboardData::get_initiative_plan).
    assert_eq!(body["bundle_sha256"], hex::encode(bundle_sha.as_bytes()));
    assert_eq!(body["plan_sha256"],   hex::encode(plan_sha.as_bytes()));
    assert_eq!(body["submitted_at_unix"], 1_700_000_690);
    assert_eq!(body["submitted_by"],      hex::encode(signer_fp.as_bytes()));

    let wire_toml = body["submitted_toml"].as_str().unwrap();
    assert_eq!(wire_toml.as_bytes(), plan_bytes,
        "V2.1 path MUST surface plan_bundle_artifacts.artifact_bytes verbatim");

    handle.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_endpoint_disambiguates_404_from_410() {
    use reqwest::header::AUTHORIZATION;

    let (tmp, store) = fresh_data_dir();

    let signing = SigningKey::from_bytes(&[0x73u8; 32]);
    let pk      = signing.verifying_key().to_bytes();
    let policy  = policy_with_operator(pk);

    seed_orphan_initiative(&store, "init-orphan").await;

    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        ..Default::default()
    };
    let handle = raxis_dashboard_kernel::start_dashboard(
        cfg,
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
    ).await.expect("start_dashboard");
    let base   = format!("http://{}", handle.local_addr());
    let client = reqwest::Client::new();
    let token  = obtain_token(&base, &client, &signing, pk).await;

    // 1) Unknown initiative → 404.
    let resp_404 = client
        .get(format!("{base}/api/initiatives/init-does-not-exist/plan"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send().await.unwrap();
    assert_eq!(resp_404.status().as_u16(), 404,
        "unknown initiative must 404, never 5xx");
    let body_404: serde_json::Value = resp_404.json().await.unwrap();
    assert_eq!(body_404["code"], "FAIL_DASHBOARD_NOT_FOUND");

    // 2) Known initiative with NO plan artifact → 410.
    let resp_410 = client
        .get(format!("{base}/api/initiatives/init-orphan/plan"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send().await.unwrap();
    assert_eq!(resp_410.status().as_u16(), 410,
        "initiative without sealed plan must 410, never 5xx");
    let body_410: serde_json::Value = resp_410.json().await.unwrap();
    assert_eq!(body_410["code"], "FAIL_DASHBOARD_GONE");

    handle.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_endpoint_emits_no_store_for_pending_drafts_and_requires_auth() {
    use reqwest::header::AUTHORIZATION;

    let (tmp, store) = fresh_data_dir();

    let signing = SigningKey::from_bytes(&[0x74u8; 32]);
    let pk      = signing.verifying_key().to_bytes();
    let policy  = policy_with_operator(pk);

    // A `Draft` initiative with a valid plan body (V1 path). Per
    // the route handler's PLAN_CACHE_CONTROL_VOLATILE branch the
    // response carries `Cache-Control: private, no-store` because
    // pre-approval the bytes are still mutable.
    let plan_bytes: &[u8] = b"[orchestrator]\nmodel = \"draft\"\n";
    seed_v1_initiative(
        &store,
        "init-draft",
        "Draft",
        None,
        plan_bytes,
        "feedfacefeedfacefeedfacefeedface",
        1_700_000_300,
    ).await;

    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        ..Default::default()
    };
    let handle = raxis_dashboard_kernel::start_dashboard(
        cfg,
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
    ).await.expect("start_dashboard");

    let base   = format!("http://{}", handle.local_addr());
    let client = reqwest::Client::new();

    // Anonymous → 401 (auth gate is shared with every other
    // initiative endpoint; verifying it here pins the contract for
    // this route specifically).
    let resp_anon = client
        .get(format!("{base}/api/initiatives/init-draft/plan"))
        .send().await.unwrap();
    assert_eq!(resp_anon.status().as_u16(), 401,
        "anonymous request must 401, not leak plan bytes");

    let token = obtain_token(&base, &client, &signing, pk).await;
    let resp = client
        .get(format!("{base}/api/initiatives/init-draft/plan"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let cc = resp.headers().get("cache-control").unwrap()
        .to_str().unwrap().to_owned();
    assert_eq!(cc, "private, no-store",
        "Draft plans must NOT be browser-cached — bytes are still volatile");

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["approval_status"], "pending");
    assert!(body["approved_at_unix"].is_null());
    let wire_toml = body["submitted_toml"].as_str().unwrap();
    assert_eq!(wire_toml.as_bytes(), plan_bytes);

    handle.shutdown().await.unwrap();
}
