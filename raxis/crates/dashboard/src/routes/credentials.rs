//! Credential viewer endpoints — `INV-DASHBOARD-CREDENTIAL-*`.
//!
//! Two scopes:
//!
//!   * Per-initiative: `GET /api/initiatives/:id/credentials` lists
//!     the credential metadata; `POST /api/initiatives/:id/
//!     credentials/:name/reveal` returns the plaintext bytes.
//!     Listing is `read`-role; reveal is `admin`-only.
//!   * System-wide: `GET /api/system/credentials` lists provider /
//!     gateway-bound credentials; `POST /api/system/credentials/:name/
//!     reveal` returns the plaintext. Both are `admin`-only — a
//!     `read`-role caller can't even discover the system credential
//!     names.
//!
//! Every request emits a paired `Operator*` audit event BEFORE the
//! response is returned (`INV-AUDIT-OPERATOR-ACTION-01` /
//! `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01`). Failure paths
//! audit too with the rejection class on `outcome`.
//!
//! The reveal endpoints are rate-limited via the data layer's
//! `enforce_reveal_rate_limit` (default 5 reveals per 60s per
//! operator). A 429 also audits — the dashboard cares about
//! operators that hammer the endpoint.

use axum::extract::{Path, State};
use axum::Json;
use raxis_audit_tools::AuditEventKind;

use crate::auth::DashboardRole;
use crate::data::{
    operator_outcome, CredentialListResponse, CredentialMetadata, CredentialReveal,
};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

// ---------------------------------------------------------------------------
// GET /api/initiatives/:id/credentials
// ---------------------------------------------------------------------------

/// Per-initiative credential listing.
///
/// Returns metadata only — `INV-DASHBOARD-CREDENTIAL-DEFAULT-MASKED-01`
/// pins the wire shape so a future refactor can't accidentally add a
/// `bytes` field.
pub async fn list_initiative<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(initiative_id): Path<String>,
) -> ApiResult<Json<CredentialListResponse>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read)
        && !op.has_role(DashboardRole::WritePolicy)
        && !op.has_role(DashboardRole::Admin)
    {
        emit_initiative_listed(
            &*state.data,
            &op,
            &initiative_id,
            0,
            operator_outcome::REJECTED_PERMISSION,
        );
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    let result = state.data.list_initiative_credentials(&initiative_id);
    let credentials = match result {
        Ok(c) => c,
        Err(err) => {
            emit_initiative_listed(
                &*state.data,
                &op,
                &initiative_id,
                0,
                operator_outcome::outcome_from_api_error(&err),
            );
            return Err(err);
        }
    };
    let count = credentials.len() as u32;
    state
        .data
        .emit_operator_audit(AuditEventKind::OperatorListedCredentials {
            operator_fingerprint: op.fingerprint.clone(),
            initiative_id:        initiative_id.clone(),
            count,
            outcome:              operator_outcome::ACCEPTED.into(),
        })?;
    Ok(Json(CredentialListResponse { credentials }))
}

fn emit_initiative_listed<D>(
    data: &D,
    op: &AuthorizedOperator,
    initiative_id: &str,
    count: u32,
    outcome: &'static str,
) where
    D: crate::data::DashboardData + ?Sized,
{
    let _ = data.emit_operator_audit(AuditEventKind::OperatorListedCredentials {
        operator_fingerprint: op.fingerprint.clone(),
        initiative_id:        initiative_id.to_owned(),
        count,
        outcome:              outcome.into(),
    });
}

// ---------------------------------------------------------------------------
// POST /api/initiatives/:id/credentials/:name/reveal
// ---------------------------------------------------------------------------

/// Per-initiative credential reveal.
///
/// `INV-DASHBOARD-CREDENTIAL-REVEAL-ROLE-GATED-01`: requires the
/// `admin` role; `read` / `write_policy` get 403.
/// `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01`: the
/// `OperatorRevealedCredential` event is emitted BEFORE the
/// plaintext leaves the kernel.
pub async fn reveal_initiative<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path((initiative_id, credential_name)): Path<(String, String)>,
) -> ApiResult<Json<CredentialReveal>>
where
    D: crate::data::DashboardData,
{
    // Step 1: role gate. `admin`-only — no read / write_policy
    // fallbacks. Forbidden audits before returning.
    if !op.has_role(DashboardRole::Admin) {
        emit_initiative_revealed(
            &*state.data,
            &op,
            &initiative_id,
            &credential_name,
            operator_outcome::REJECTED_PERMISSION,
        );
        return Err(ApiError::Forbidden { required: "admin".into() });
    }
    // Step 2: rate limit. Throttled callers audit at
    // `RejectedValidation`; the route returns 429. We DO NOT
    // double-emit the rate-limit error as `RejectedPermission` —
    // the operator does have the role; the kernel is just
    // refusing to service the call.
    if let Err(err) = state.data.enforce_reveal_rate_limit(&op.fingerprint) {
        emit_initiative_revealed(
            &*state.data,
            &op,
            &initiative_id,
            &credential_name,
            operator_outcome::outcome_from_api_error(&err),
        );
        return Err(err);
    }
    // Step 3: actual fetch. Wrapped in spawn_blocking because the
    // kernel impl reads from disk.
    let data = std::sync::Arc::clone(&state.data);
    let init_for_fetch = initiative_id.clone();
    let cred_for_fetch = credential_name.clone();
    let result = tokio::task::spawn_blocking(move || {
        data.reveal_initiative_credential(&init_for_fetch, &cred_for_fetch)
    })
    .await
    .map_err(|e| ApiError::Internal {
        log_only: format!("reveal_initiative_credential join error: {e}"),
    });
    let reveal = match result.and_then(|r| r) {
        Ok(r) => r,
        Err(err) => {
            emit_initiative_revealed(
                &*state.data,
                &op,
                &initiative_id,
                &credential_name,
                operator_outcome::outcome_from_api_error(&err),
            );
            return Err(err);
        }
    };
    // Step 4: audit-emission MUST happen BEFORE the response. A
    // sink failure flips the response into InternalError so the
    // operator never gets plaintext without an audit row.
    state
        .data
        .emit_operator_audit(AuditEventKind::OperatorRevealedCredential {
            operator_fingerprint: op.fingerprint.clone(),
            initiative_id:        initiative_id.clone(),
            credential_name:      credential_name.clone(),
            severity:             "high".into(),
            outcome:              operator_outcome::ACCEPTED.into(),
        })?;
    Ok(Json(reveal))
}

fn emit_initiative_revealed<D>(
    data: &D,
    op: &AuthorizedOperator,
    initiative_id: &str,
    credential_name: &str,
    outcome: &'static str,
) where
    D: crate::data::DashboardData + ?Sized,
{
    let _ = data.emit_operator_audit(AuditEventKind::OperatorRevealedCredential {
        operator_fingerprint: op.fingerprint.clone(),
        initiative_id:        initiative_id.to_owned(),
        credential_name:      credential_name.to_owned(),
        severity:             "high".into(),
        outcome:              outcome.into(),
    });
}

// ---------------------------------------------------------------------------
// GET /api/system/credentials
// ---------------------------------------------------------------------------

/// System-wide credential listing.
///
/// Admin-only — even discovering the names of provider credentials
/// requires the admin role. `read` callers cannot enumerate which
/// providers the kernel is configured against.
pub async fn list_system<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<CredentialListResponse>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Admin) {
        emit_system_listed(
            &*state.data,
            &op,
            0,
            operator_outcome::REJECTED_PERMISSION,
        );
        return Err(ApiError::Forbidden { required: "admin".into() });
    }
    let result = state.data.list_system_credentials();
    let credentials = match result {
        Ok(c) => c,
        Err(err) => {
            emit_system_listed(
                &*state.data,
                &op,
                0,
                operator_outcome::outcome_from_api_error(&err),
            );
            return Err(err);
        }
    };
    let count = credentials.len() as u32;
    state
        .data
        .emit_operator_audit(AuditEventKind::OperatorListedSystemCredentials {
            operator_fingerprint: op.fingerprint.clone(),
            count,
            outcome: operator_outcome::ACCEPTED.into(),
        })?;
    Ok(Json(CredentialListResponse { credentials }))
}

fn emit_system_listed<D>(
    data: &D,
    op: &AuthorizedOperator,
    count: u32,
    outcome: &'static str,
) where
    D: crate::data::DashboardData + ?Sized,
{
    let _ = data.emit_operator_audit(AuditEventKind::OperatorListedSystemCredentials {
        operator_fingerprint: op.fingerprint.clone(),
        count,
        outcome: outcome.into(),
    });
}

// ---------------------------------------------------------------------------
// POST /api/system/credentials/:name/reveal
// ---------------------------------------------------------------------------

/// System-wide credential reveal.
///
/// Same admin-gate + rate-limit + paired-audit contract as the
/// per-initiative reveal, BUT the audit row carries
/// `severity = "critical"` (vs `"high"` for per-initiative). This
/// pins the notification routing so a system-credential reveal
/// (Anthropic in particular) surfaces in the operator inbox at
/// Critical priority — `INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01`.
pub async fn reveal_system<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(credential_name): Path<String>,
) -> ApiResult<Json<CredentialReveal>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Admin) {
        emit_system_revealed(
            &*state.data,
            &op,
            &credential_name,
            operator_outcome::REJECTED_PERMISSION,
        );
        return Err(ApiError::Forbidden { required: "admin".into() });
    }
    if let Err(err) = state.data.enforce_reveal_rate_limit(&op.fingerprint) {
        emit_system_revealed(
            &*state.data,
            &op,
            &credential_name,
            operator_outcome::outcome_from_api_error(&err),
        );
        return Err(err);
    }
    let data = std::sync::Arc::clone(&state.data);
    let cred_for_fetch = credential_name.clone();
    let result = tokio::task::spawn_blocking(move || {
        data.reveal_system_credential(&cred_for_fetch)
    })
    .await
    .map_err(|e| ApiError::Internal {
        log_only: format!("reveal_system_credential join error: {e}"),
    });
    let reveal = match result.and_then(|r| r) {
        Ok(r) => r,
        Err(err) => {
            emit_system_revealed(
                &*state.data,
                &op,
                &credential_name,
                operator_outcome::outcome_from_api_error(&err),
            );
            return Err(err);
        }
    };
    state
        .data
        .emit_operator_audit(AuditEventKind::OperatorRevealedSystemCredential {
            operator_fingerprint: op.fingerprint.clone(),
            credential_name:      credential_name.clone(),
            severity:             "critical".into(),
            outcome:              operator_outcome::ACCEPTED.into(),
        })?;
    Ok(Json(reveal))
}

fn emit_system_revealed<D>(
    data: &D,
    op: &AuthorizedOperator,
    credential_name: &str,
    outcome: &'static str,
) where
    D: crate::data::DashboardData + ?Sized,
{
    let _ = data.emit_operator_audit(AuditEventKind::OperatorRevealedSystemCredential {
        operator_fingerprint: op.fingerprint.clone(),
        credential_name:      credential_name.to_owned(),
        severity:             "critical".into(),
        outcome:              outcome.into(),
    });
}

// Reference: silence dead-code on the metadata type if no test
// touches it inline (the JSON field is used by the FE).
#[allow(dead_code)]
fn _credential_metadata_compiles() -> CredentialMetadata {
    CredentialMetadata {
        name: String::new(),
        proxy_type: String::new(),
        mount_as: None,
        format_hint: String::new(),
        upstream_host_port: None,
        byte_size: 0,
        sha256_prefix: None,
        loaded_from_path: None,
        is_revealable: false,
        reveal_required_role: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::DashboardRole;
    use crate::data::{CredentialFixture, InMemoryDashboardData};
    use std::time::Duration;

    fn fixture(name: &str, plaintext: &str) -> CredentialFixture {
        CredentialFixture {
            metadata: CredentialMetadata {
                name: name.to_owned(),
                proxy_type: "postgres".into(),
                mount_as: Some("DATABASE_URL".into()),
                format_hint: "libpq URL".into(),
                upstream_host_port: Some("127.0.0.1:5432".into()),
                byte_size: plaintext.len() as u64,
                sha256_prefix: Some("aa".repeat(4)),
                loaded_from_path: Some(format!("/var/raxis/credentials/{name}.env")),
                is_revealable: true,
                reveal_required_role: "admin".into(),
            },
            plaintext: plaintext.to_owned(),
        }
    }

    fn admin_op() -> AuthorizedOperator {
        AuthorizedOperator {
            fingerprint: "fp-admin-1".into(),
            display_name: "alice".into(),
            roles: vec![DashboardRole::Read, DashboardRole::Admin],
            claims: crate::auth::OperatorClaims {
                fingerprint: "fp-admin-1".into(),
                display_name: "alice".into(),
                roles: vec!["read".into(), "admin".into()],
                exp: 0,
                iat: 0,
                jti: "jti-1".into(),
            },
        }
    }

    fn read_op() -> AuthorizedOperator {
        AuthorizedOperator {
            fingerprint: "fp-read-1".into(),
            display_name: "bob".into(),
            roles: vec![DashboardRole::Read],
            claims: crate::auth::OperatorClaims {
                fingerprint: "fp-read-1".into(),
                display_name: "bob".into(),
                roles: vec!["read".into()],
                exp: 0,
                iat: 0,
                jti: "jti-2".into(),
            },
        }
    }

    /// `INV-DASHBOARD-CREDENTIAL-REVEAL-ROLE-GATED-01` —
    /// `read`-role gets 403 (NOT 401) on the reveal endpoint;
    /// the failure audits with `RejectedPermission`.
    #[tokio::test]
    async fn reveal_initiative_forbidden_for_read_role_audits_rejection() {
        let d = InMemoryDashboardData::new();
        d.push_initiative_credential("init-1", fixture("test-pg-dev", "postgresql://u:p@h/db"));
        let result = reveal_initiative(
            axum::extract::State(_app_state(&d)),
            read_op(),
            axum::extract::Path(("init-1".into(), "test-pg-dev".into())),
        )
        .await;
        let err = result.expect_err("read role must be forbidden");
        match err {
            ApiError::Forbidden { required } => assert_eq!(required, "admin"),
            other => panic!("expected Forbidden, got {other:?}"),
        }
        let audits = d.recorded_operator_audits();
        // exactly one OperatorRevealedCredential audit with
        // RejectedPermission outcome — no plaintext was returned.
        assert_eq!(audits.len(), 1);
        match &audits[0] {
            AuditEventKind::OperatorRevealedCredential {
                initiative_id,
                credential_name,
                outcome,
                severity,
                ..
            } => {
                assert_eq!(initiative_id, "init-1");
                assert_eq!(credential_name, "test-pg-dev");
                assert_eq!(outcome, "RejectedPermission");
                assert_eq!(severity, "high");
            }
            other => panic!("unexpected audit kind: {other:?}"),
        }
    }

    /// `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01` — admin
    /// reveal returns plaintext AND emits exactly one
    /// `OperatorRevealedCredential` audit with `Accepted`
    /// outcome. The audit row carries the credential name + the
    /// initiative id; the plaintext is in the response, never
    /// in the audit row.
    #[tokio::test]
    async fn reveal_initiative_admin_returns_plaintext_and_audits() {
        let d = InMemoryDashboardData::new();
        d.push_initiative_credential(
            "init-1",
            fixture("test-pg-dev", "postgresql://u:p@h/db"),
        );
        let resp = reveal_initiative(
            axum::extract::State(_app_state(&d)),
            admin_op(),
            axum::extract::Path(("init-1".into(), "test-pg-dev".into())),
        )
        .await
        .expect("admin reveal succeeds");
        assert_eq!(resp.0.plaintext, "postgresql://u:p@h/db");
        assert_eq!(resp.0.encoding, "utf8");
        assert!(resp.0.expires_at_unix > 0);
        let audits = d.recorded_operator_audits();
        assert_eq!(audits.len(), 1);
        match &audits[0] {
            AuditEventKind::OperatorRevealedCredential {
                outcome,
                credential_name,
                severity,
                ..
            } => {
                assert_eq!(outcome, "Accepted");
                assert_eq!(credential_name, "test-pg-dev");
                assert_eq!(severity, "high");
            }
            other => panic!("unexpected audit kind: {other:?}"),
        }
    }

    /// 404 on unknown credential: the audit row still fires with
    /// `RejectedValidation`. No plaintext leaves the kernel.
    #[tokio::test]
    async fn reveal_initiative_unknown_credential_audits_404() {
        let d = InMemoryDashboardData::new();
        d.push_initiative_credential("init-1", fixture("test-pg-dev", "x"));
        let err = reveal_initiative(
            axum::extract::State(_app_state(&d)),
            admin_op(),
            axum::extract::Path(("init-1".into(), "missing".into())),
        )
        .await
        .expect_err("missing credential is 404");
        assert!(matches!(err, ApiError::NotFound { .. }));
        let audits = d.recorded_operator_audits();
        assert_eq!(audits.len(), 1);
        match &audits[0] {
            AuditEventKind::OperatorRevealedCredential { outcome, .. } => {
                assert_eq!(outcome, "RejectedValidation");
            }
            other => panic!("unexpected audit kind: {other:?}"),
        }
    }

    /// Rate limiter denies a 6th call within the window. Both the
    /// 6th call AND its audit row carry the throttle outcome.
    #[tokio::test]
    async fn reveal_initiative_rate_limiter_kicks_in_after_max() {
        let d = InMemoryDashboardData::new();
        d.with_reveal_rate_limit(2, Duration::from_secs(60));
        d.push_initiative_credential("init-1", fixture("test-pg-dev", "x"));
        // Two calls succeed.
        for _ in 0..2 {
            let _ok = reveal_initiative(
                axum::extract::State(_app_state(&d)),
                admin_op(),
                axum::extract::Path(("init-1".into(), "test-pg-dev".into())),
            )
            .await
            .expect("first 2 calls succeed");
        }
        // Third call is throttled.
        let err = reveal_initiative(
            axum::extract::State(_app_state(&d)),
            admin_op(),
            axum::extract::Path(("init-1".into(), "test-pg-dev".into())),
        )
        .await
        .expect_err("third call rate-limited");
        match err {
            ApiError::TooManyRequests { max, .. } => assert_eq!(max, 2),
            other => panic!("expected TooManyRequests, got {other:?}"),
        }
        let audits = d.recorded_operator_audits();
        // 2 success audits + 1 throttle audit.
        assert_eq!(audits.len(), 3);
        match &audits[2] {
            AuditEventKind::OperatorRevealedCredential { outcome, .. } => {
                assert_eq!(outcome, "RejectedValidation");
            }
            other => panic!("unexpected audit kind: {other:?}"),
        }
    }

    /// System credential reveal carries `severity = "critical"`.
    #[tokio::test]
    async fn reveal_system_admin_audits_critical() {
        let d = InMemoryDashboardData::new();
        d.push_system_credential(fixture("providers.anthropic-prod", "sk-ant-redacted"));
        let resp = reveal_system(
            axum::extract::State(_app_state(&d)),
            admin_op(),
            axum::extract::Path("providers.anthropic-prod".into()),
        )
        .await
        .expect("admin system reveal succeeds");
        assert_eq!(resp.0.plaintext, "sk-ant-redacted");
        let audits = d.recorded_operator_audits();
        assert_eq!(audits.len(), 1);
        match &audits[0] {
            AuditEventKind::OperatorRevealedSystemCredential {
                severity,
                outcome,
                credential_name,
                ..
            } => {
                assert_eq!(severity, "critical");
                assert_eq!(outcome, "Accepted");
                assert_eq!(credential_name, "providers.anthropic-prod");
            }
            other => panic!("unexpected audit kind: {other:?}"),
        }
    }

    /// `read`-role can't even list system credentials.
    #[tokio::test]
    async fn list_system_forbidden_for_read_role() {
        let d = InMemoryDashboardData::new();
        d.push_system_credential(fixture("providers.anthropic-prod", "sk"));
        let err = list_system(
            axum::extract::State(_app_state(&d)),
            read_op(),
        )
        .await
        .expect_err("read can't list system creds");
        match err {
            ApiError::Forbidden { required } => assert_eq!(required, "admin"),
            other => panic!("expected Forbidden, got {other:?}"),
        }
        let audits = d.recorded_operator_audits();
        assert_eq!(audits.len(), 1);
        match &audits[0] {
            AuditEventKind::OperatorListedSystemCredentials { outcome, .. } => {
                assert_eq!(outcome, "RejectedPermission");
            }
            other => panic!("unexpected audit kind: {other:?}"),
        }
    }

    fn _app_state(
        data: &std::sync::Arc<InMemoryDashboardData>,
    ) -> AppState<InMemoryDashboardData> {
        // Build a minimal AppState — auth state isn't exercised
        // by these tests; they bypass the extractor entirely by
        // calling the handler with a hand-rolled
        // AuthorizedOperator.
        use crate::config::DashboardConfig;
        use crate::server::{AppStateInner, ShutdownSignal};
        let cfg = DashboardConfig {
            enabled: true,
            ..Default::default()
        };
        let auth = crate::auth::build_auth_state(&cfg).expect("build auth");
        std::sync::Arc::new(AppStateInner {
            data: std::sync::Arc::clone(data),
            auth,
            config: cfg,
            shutdown: ShutdownSignal::new(),
        })
    }
}
