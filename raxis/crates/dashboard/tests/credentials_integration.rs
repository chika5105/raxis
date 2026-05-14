//! Integration tests for the dashboard credential viewer surface.
//!
//! Exercises the full HTTP-layer contract for
//! `INV-DASHBOARD-CREDENTIAL-*`:
//!
//!   * default-MASKED listing (no plaintext on the listing wire);
//!   * admin-role gate on the reveal endpoints (read / write_policy
//!     get 403, NOT 401, NOT 200 with empty bytes);
//!   * paired audit emission BEFORE the response leaves the kernel
//!     (the in-memory fixture's `recorded_operator_audits` ledger
//!     is the witness — it's appended inside the route handler
//!     prior to `Json(reveal).into_response()`);
//!   * Anthropic-name reveals fold into
//!     `OperatorRevealedSystemCredential { severity = "critical" }`;
//!   * rate limiter on per-operator reveal floods (HTTP 429
//!     `FAIL_DASHBOARD_RATE_LIMITED`, audit emitted with
//!     `outcome = "RejectedValidation"`);
//!   * unknown initiative / credential ⇒ 404 with structured code;
//!   * 401 / 403 failure paths still emit audit (the gap-coverage
//!     spec mandates rejection rows so a forensic walk records
//!     denied-attempts).
//!
//! These tests are hermetic: `InMemoryDashboardData` +
//! `DashboardServer` bound to `127.0.0.1:0`. No kernel boot, no
//! on-disk store, no network egress.

#![cfg(test)]

use std::sync::Arc;
use std::time::Duration;

use raxis_audit_tools::AuditEventKind;
use raxis_dashboard::auth::DashboardRole;
use raxis_dashboard::config::DashboardConfig;
use raxis_dashboard::data::{
    CredentialFixture, CredentialMetadata, InMemoryDashboardData,
};
use raxis_dashboard::routes::auth::operator_fingerprint_hex;
use raxis_dashboard::server::{DashboardServer, ServerHandle};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// Spin up the dashboard with a single registered operator
/// holding the supplied roles, mint that operator a JWT, and
/// return everything the test needs to drive the HTTP surface.
async fn serve_with_role(
    role: DashboardRole,
) -> (
    ServerHandle,
    String,
    String,
    Arc<InMemoryDashboardData>,
    String, // operator fingerprint
) {
    let cfg = DashboardConfig {
        enabled:      true,
        bind_address: "127.0.0.1".into(),
        bind_port:    0,
        static_dir:   None,
        ..Default::default()
    };
    // Stable seed so the fingerprint doesn't drift across runs;
    // we vary it per-role so different roles have distinct
    // fingerprints (handy for the rate-limiter test below
    // which needs to ensure two operators don't share a bucket).
    let seed: [u8; 32] = match role {
        DashboardRole::Admin       => [0xA1; 32],
        DashboardRole::WritePolicy => [0xB2; 32],
        DashboardRole::Read        => [0xC3; 32],
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let fingerprint = operator_fingerprint_hex(&pubkey_bytes);
    let data = InMemoryDashboardData::new();
    data.with_operator(fingerprint.clone(), "cred-tester", vec![role]);
    let server = DashboardServer::bind(cfg, Arc::clone(&data))
        .await
        .expect("bind");
    let addr = server.local_addr();
    let handle = ServerHandle::spawn(server);
    let base = format!("http://{addr}");
    let token = mint_jwt(&base, &signing_key).await;
    (handle, base, token, data, fingerprint)
}

/// Drive the challenge → verify HTTP path with the given keypair
/// and return the issued JWT.
async fn mint_jwt(base: &str, signing_key: &ed25519_dalek::SigningKey) -> String {
    let client = reqwest::Client::new();
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();

    let challenge_resp = client
        .get(format!("{base}/api/auth/challenge"))
        .send()
        .await
        .expect("challenge send");
    assert_eq!(challenge_resp.status(), 200);
    let challenge_json: serde_json::Value =
        challenge_resp.json().await.expect("challenge json");
    let challenge_hex = challenge_json["challenge"]
        .as_str()
        .expect("challenge string")
        .to_owned();
    let challenge_bytes = hex::decode(&challenge_hex).expect("hex");

    use ed25519_dalek::Signer;
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
    assert_eq!(verify_resp.status(), 200);
    let verify_json: serde_json::Value = verify_resp.json().await.expect("verify json");
    verify_json["token"]
        .as_str()
        .expect("token string")
        .to_owned()
}

/// Helper: build a credential fixture with conventional defaults.
fn fixture(name: &str, plaintext: &str) -> CredentialFixture {
    CredentialFixture {
        metadata:  CredentialMetadata {
            name:                 name.to_owned(),
            proxy_type:           "postgres".into(),
            mount_as:             Some("DATABASE_URL".into()),
            format_hint:          "libpq URL".into(),
            upstream_host_port:   Some("127.0.0.1:5432".into()),
            byte_size:            plaintext.len() as u64,
            sha256_prefix:        Some("deadbeef".into()),
            loaded_from_path:     Some(format!("/tmp/{name}.env")),
            is_revealable:        true,
            reveal_required_role: "admin".into(),
        },
        plaintext: plaintext.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Listing endpoint
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_initiative_credentials_returns_metadata_only_no_plaintext_field() {
    let (handle, base, token, data, _fp) =
        serve_with_role(DashboardRole::Read).await;
    data.push_initiative_credential(
        "init-1",
        fixture("test-pg-dev", "postgres://user:hunter2@db:5432/app"),
    );

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/initiatives/init-1/credentials"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200, "read role suffices for listing");

    let body_text = res.text().await.expect("text body");
    // Defence-in-depth: the wire MUST NOT contain the
    // plaintext bytes nor any field that names the secret.
    assert!(
        !body_text.contains("hunter2"),
        "listing wire must NOT contain plaintext; body was: {body_text}",
    );
    assert!(
        !body_text.contains("\"plaintext\""),
        "listing wire must NOT carry a 'plaintext' field; body was: {body_text}",
    );
    let body: serde_json::Value = serde_json::from_str(&body_text).expect("json");
    assert_eq!(body["credentials"][0]["name"], "test-pg-dev");
    assert_eq!(body["credentials"][0]["proxy_type"], "postgres");

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_emits_operator_listed_credentials_audit_with_count() {
    let (handle, base, token, data, fp) =
        serve_with_role(DashboardRole::Read).await;
    data.push_initiative_credential("init-1", fixture("a", "x"))
        .push_initiative_credential("init-1", fixture("b", "y"));

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/initiatives/init-1/credentials"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200);

    let audits = data.recorded_operator_audits();
    let row = audits
        .iter()
        .find(|e| matches!(e, AuditEventKind::OperatorListedCredentials { .. }))
        .expect("paired audit emission");
    if let AuditEventKind::OperatorListedCredentials {
        operator_fingerprint, initiative_id, count, outcome,
    } = row
    {
        assert_eq!(*operator_fingerprint, fp);
        assert_eq!(*initiative_id, "init-1");
        assert_eq!(*count, 2, "audit row carries the surfaced row count");
        assert_eq!(outcome, "Accepted");
    } else {
        unreachable!()
    }
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_initiative_credentials_unknown_initiative_returns_404() {
    let (handle, base, token, _data, _fp) =
        serve_with_role(DashboardRole::Read).await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/initiatives/init-missing/credentials"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 404);
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["code"], "FAIL_DASHBOARD_NOT_FOUND");
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_system_credentials_rejects_read_role() {
    let (handle, base, token, data, _fp) =
        serve_with_role(DashboardRole::Read).await;
    data.push_system_credential(fixture("providers.anthropic", "sk-ant-…"));

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/system/credentials"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 403, "system listing is admin-only");

    // Even on rejection, the audit chain MUST record the
    // attempt so a forensic walker sees the denied access.
    let audits = data.recorded_operator_audits();
    let denied = audits.iter().any(|e| {
        matches!(
            e,
            AuditEventKind::OperatorListedSystemCredentials { outcome, .. }
                if outcome == "RejectedPermission"
        )
    });
    assert!(denied, "listing-denied audit row not found: {audits:?}");
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_system_credentials_admin_returns_metadata() {
    let (handle, base, token, data, _fp) =
        serve_with_role(DashboardRole::Admin).await;
    data.push_system_credential(fixture("providers.anthropic", "sk-ant-…"));

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/system/credentials"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200);
    let body_text = res.text().await.expect("text");
    assert!(!body_text.contains("sk-ant"), "no plaintext on listing");
    assert!(body_text.contains("providers.anthropic"));
    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Reveal endpoint — role gate
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reveal_initiative_credential_rejects_read_role_with_403_and_audits() {
    let (handle, base, token, data, fp) =
        serve_with_role(DashboardRole::Read).await;
    data.push_initiative_credential("init-1", fixture("test-pg-dev", "secret"));

    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "{base}/api/initiatives/init-1/credentials/test-pg-dev/reveal"
        ))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 403, "reveal is admin-only");
    let body_text = res.text().await.expect("text");
    assert!(!body_text.contains("secret"), "no plaintext on rejection");

    // The denied attempt MUST surface in the audit chain.
    let audits = data.recorded_operator_audits();
    let denied = audits.iter().any(|e| {
        matches!(
            e,
            AuditEventKind::OperatorRevealedCredential {
                operator_fingerprint, outcome, ..
            } if operator_fingerprint == &fp && outcome == "RejectedPermission"
        )
    });
    assert!(denied, "rejection audit row not found: {audits:?}");
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reveal_initiative_credential_rejects_write_policy_role_with_403() {
    let (handle, base, token, data, _fp) =
        serve_with_role(DashboardRole::WritePolicy).await;
    data.push_initiative_credential("init-1", fixture("test-pg-dev", "secret"));

    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "{base}/api/initiatives/init-1/credentials/test-pg-dev/reveal"
        ))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(
        res.status(),
        403,
        "write_policy is NOT a sufficient grant for credential reveal",
    );
    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Reveal endpoint — happy path (admin)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reveal_initiative_credential_admin_path_returns_plaintext_and_audits_first() {
    let (handle, base, token, data, fp) =
        serve_with_role(DashboardRole::Admin).await;
    data.push_initiative_credential(
        "init-1",
        fixture("test-pg-dev", "postgres://user:hunter2@db/app"),
    );

    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "{base}/api/initiatives/init-1/credentials/test-pg-dev/reveal"
        ))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["name"], "test-pg-dev");
    assert_eq!(body["plaintext"], "postgres://user:hunter2@db/app");
    assert_eq!(body["encoding"], "utf8");
    let exp = body["expires_at_unix"].as_u64().expect("expires_at_unix");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        exp > now && exp <= now + 60,
        "expires_at_unix must be in the (now, now+60] window, got {exp}",
    );

    // Audit-paired-write contract: the row exists in the
    // recorded ledger by the time the response arrives back
    // here. The handler appends BEFORE writing the response,
    // so the appearance order in `recorded_operator_audits`
    // is the kernel's post-response visibility.
    let audits = data.recorded_operator_audits();
    let success = audits.iter().any(|e| {
        matches!(
            e,
            AuditEventKind::OperatorRevealedCredential {
                operator_fingerprint, initiative_id, credential_name, outcome, ..
            } if operator_fingerprint == &fp
              && initiative_id == "init-1"
              && credential_name == "test-pg-dev"
              && outcome == "Accepted"
        )
    });
    assert!(success, "success audit row not found: {audits:?}");
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reveal_initiative_credential_unknown_name_returns_404() {
    let (handle, base, token, data, _fp) =
        serve_with_role(DashboardRole::Admin).await;
    data.push_initiative_credential("init-1", fixture("known", "x"));

    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "{base}/api/initiatives/init-1/credentials/missing/reveal"
        ))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 404);
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["code"], "FAIL_DASHBOARD_NOT_FOUND");
    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// System reveal — Anthropic Critical-severity
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reveal_system_anthropic_credential_emits_critical_severity_audit() {
    let (handle, base, token, data, fp) =
        serve_with_role(DashboardRole::Admin).await;
    data.push_system_credential(fixture("providers.anthropic", "sk-ant-test"));

    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "{base}/api/system/credentials/providers.anthropic/reveal"
        ))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200);

    // INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01: the
    // Anthropic reveal MUST carry `severity = "critical"`
    // (NOT "high"). This is the tripwire that catches a
    // future refactor that folds system + initiative reveals
    // into a single severity bucket.
    let audits = data.recorded_operator_audits();
    let critical = audits.iter().any(|e| {
        matches!(
            e,
            AuditEventKind::OperatorRevealedSystemCredential {
                operator_fingerprint, credential_name, severity, outcome, ..
            } if operator_fingerprint == &fp
              && credential_name == "providers.anthropic"
              && severity == "critical"
              && outcome == "Accepted"
        )
    });
    assert!(
        critical,
        "Anthropic reveal MUST emit severity=critical: {audits:?}",
    );
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reveal_initiative_credential_emits_high_severity_audit() {
    // Spec: system reveals are uniformly `severity = "critical"`
    // (the notification-routing layer escalates Anthropic-named
    // system reveals further to a Critical-priority inbox row);
    // per-initiative reveals are uniformly `severity = "high"`.
    // This test pins the per-initiative severity floor — a future
    // refactor that drops it to "low" or omits the field would be
    // a forensics regression.
    let (handle, base, token, data, _fp) =
        serve_with_role(DashboardRole::Admin).await;
    data.push_initiative_credential("init-1", fixture("test-pg-dev", "secret"));

    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "{base}/api/initiatives/init-1/credentials/test-pg-dev/reveal"
        ))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200);
    let audits = data.recorded_operator_audits();
    let high = audits.iter().any(|e| {
        matches!(
            e,
            AuditEventKind::OperatorRevealedCredential { severity, .. }
                if severity == "high"
        )
    });
    assert!(
        high,
        "per-initiative reveal must emit severity=high: {audits:?}",
    );
    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reveal_initiative_credential_rate_limit_kicks_in_after_threshold() {
    let (handle, base, token, data, fp) =
        serve_with_role(DashboardRole::Admin).await;
    data.with_reveal_rate_limit(3, Duration::from_secs(60));
    data.push_initiative_credential("init-1", fixture("c1", "v1"));

    let client = reqwest::Client::new();
    let url = format!("{base}/api/initiatives/init-1/credentials/c1/reveal");

    // First 3 reveals succeed.
    for i in 0..3 {
        let res = client
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .expect("send");
        assert_eq!(res.status(), 200, "reveal #{i} should succeed");
    }
    // 4th gets 429.
    let res = client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(
        res.status(),
        429,
        "4th reveal in the window must be rate-limited",
    );
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["code"], "FAIL_DASHBOARD_RATE_LIMITED");

    // The throttled attempt MUST audit too — denied attempts
    // are forensic signal, not silent drops.
    let audits = data.recorded_operator_audits();
    let throttled = audits.iter().any(|e| {
        matches!(
            e,
            AuditEventKind::OperatorRevealedCredential {
                operator_fingerprint, outcome, ..
            } if operator_fingerprint == &fp && outcome == "RejectedValidation"
        )
    });
    assert!(throttled, "rate-limit audit row not found: {audits:?}");
    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Auth gate — unauth requests get 401, never reveal bytes
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reveal_credential_without_auth_yields_401_not_500() {
    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        static_dir: None,
        ..Default::default()
    };
    let data = InMemoryDashboardData::new();
    data.push_initiative_credential("init-1", fixture("c1", "secret"));
    let server = DashboardServer::bind(cfg, Arc::clone(&data))
        .await
        .expect("bind");
    let addr = server.local_addr();
    let handle = ServerHandle::spawn(server);
    let base = format!("http://{addr}");

    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "{base}/api/initiatives/init-1/credentials/c1/reveal"
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 401);
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["code"], "FAIL_DASHBOARD_AUTH_MISSING");
    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Audit-tightening — read-only endpoints do NOT emit Operator* events
// ---------------------------------------------------------------------------

/// `worker/audit-tightening` retired the read-only
/// `OperatorViewed*` emissions because they drowned the chain
/// in dashboard pageview noise (iter48 saw 1258 / 1260 chain
/// rows be `OperatorViewed*` rows). This test pins the new
/// invariant: a `GET /api/initiatives` must succeed without
/// appending an `OperatorViewed*` row to the operator-audit
/// ledger.
///
/// See `specs/v2/dashboard-operator-action-audit-coverage.md
/// §signal-vs-noise` for the policy and
/// `specs/v2/dashboard-operator-action-audit-coverage.md §2` for
/// the updated coverage table.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(deprecated)] // pattern-matches the deprecated variants on purpose
async fn list_initiatives_does_not_emit_operator_viewed_initiative_list_audit() {
    let (handle, base, token, data, _fp) =
        serve_with_role(DashboardRole::Read).await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/initiatives"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200);
    let audits = data.recorded_operator_audits();
    let any_viewed = audits.iter().any(|e| {
        matches!(
            e,
            AuditEventKind::OperatorViewedInitiativeList { .. }
                | AuditEventKind::OperatorViewedInitiative { .. }
                | AuditEventKind::OperatorViewedInitiativeDag { .. }
                | AuditEventKind::OperatorViewedInitiativeTasks { .. }
        )
    });
    assert!(
        !any_viewed,
        "Expected no OperatorViewed* row after a read-only list \
         (signal-vs-noise tightening). Saw: {audits:?}",
    );
    handle.shutdown().await.expect("shutdown");
}
