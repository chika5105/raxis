//! Policy view + write endpoints.
//!
//! * `GET  /api/policy`          — structured snapshot (read role).
//! * `GET  /api/policy/toml`     — raw TOML bytes (write_policy role).
//! * `PUT  /api/policy/toml`     — install a new signed policy
//!   artifact + detached signature (write_policy role).
//!
//! The PUT endpoint is the only WRITE surface in the entire
//! dashboard backend (V2 extended-gap §4.7 R-9). It mirrors the
//! CLI flow `raxis policy reload --policy <toml> --sig <sig>`: the
//! operator must supply BOTH a new TOML artifact AND a detached
//! Ed25519 signature over those exact bytes, signed by the
//! authority key. The dashboard never holds the authority private
//! key (the air-gapped operator signs offline and pastes the
//! signature into the editor).

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::auth::DashboardRole;
use crate::data::{PolicyAdvancement, PolicySnapshotView};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/policy` — structured snapshot.
///
/// Audit discipline: pure read-only browse. The
/// `OperatorViewedPolicySnapshot` emission was retired in
/// an earlier audit-noise sweep per the signal-vs-noise policy in
/// `specs/v2/dashboard-operator-action-audit-coverage.md`. The
/// state-mutating `PUT /api/policy/toml` path continues to
/// audit via `PolicyUpdatedViaDashboard`.
pub async fn snapshot<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<PolicySnapshotView>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read)
        && !op.has_role(DashboardRole::WritePolicy)
        && !op.has_role(DashboardRole::Admin)
    {
        return Err(ApiError::Forbidden {
            required: "read".into(),
        });
    }
    let view = state.data.policy_snapshot()?;
    Ok(Json(view))
}

/// `GET /api/policy/toml` — raw TOML bytes (write_policy role).
///
/// Audit discipline: pure read-only browse. The
/// `OperatorViewedPolicyToml` emission was retired in
/// an earlier audit-noise sweep per the signal-vs-noise policy in
/// `specs/v2/dashboard-operator-action-audit-coverage.md`. The
/// raw TOML view is gated to `write_policy` role so the role
/// gate (and its `OperatorAuth*` chain) remain the forensic
/// trail for "who has the keys to surface the raw allowlist".
pub async fn raw_toml<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<impl IntoResponse>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::WritePolicy) && !op.has_role(DashboardRole::Admin) {
        return Err(ApiError::Forbidden {
            required: "write_policy".into(),
        });
    }
    let body = state.data.policy_toml_bytes()?;
    Ok((
        [(header::CONTENT_TYPE, "application/toml; charset=utf-8")],
        body,
    ))
}

/// Request body for `PUT /api/policy/toml`. Both fields are
/// required; the wire shape is JSON because raw TOML+signature
/// uploads via `application/octet-stream` would require a
/// multipart parser, which the dashboard avoids on principle.
///
/// Field encoding:
///   * `toml` — the new policy.toml contents as a UTF-8 string.
///   * `signature_b64` — exactly 64 raw Ed25519 signature bytes,
///     base64-encoded (standard alphabet, with or without
///     padding). The dashboard rejects any other length.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdatePolicyRequest {
    /// New policy.toml UTF-8 source. The kernel re-hashes this
    /// to the canonical SHA-256 the audit chain records.
    pub toml: String,
    /// Base64-encoded 64-byte Ed25519 detached signature over
    /// the EXACT bytes of `toml`. Standard alphabet; padding
    /// optional.
    pub signature_b64: String,
}

/// Response body for `PUT /api/policy/toml`. Mirrors the CLI's
/// `raxis policy reload` outcome shape so frontend code can use
/// the same renderer for both surfaces.
#[derive(Debug, Clone, Serialize)]
pub struct UpdatePolicyResponse {
    /// Same fields as [`PolicyAdvancement`].
    #[serde(flatten)]
    pub advancement: PolicyAdvancement,
}

/// `PUT /api/policy/toml` — install a new signed policy artifact.
///
/// Authorization: `write_policy` role (granted to operators with
/// `RotateEpoch` in their cert's `permitted_ops`).
///
/// Errors:
///   * `400 FAIL_DASHBOARD_BAD_REQUEST` — request body malformed
///     (invalid JSON, missing field, signature not valid base64).
///   * `400 FAIL_DASHBOARD_POLICY_INVALID` — kernel validator
///     rejected the artifact (signature bad, replay, malformed
///     TOML). The validator's short message is surfaced verbatim.
///   * `403 FAIL_DASHBOARD_FORBIDDEN` — operator lacks
///     `write_policy` role.
///   * `500 FAIL_DASHBOARD_INTERNAL` — IO trouble persisting the
///     new files (the rollback path also failed). The operator
///     should re-check on-disk state before retrying.
pub async fn update_toml<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Json(body): Json<UpdatePolicyRequest>,
) -> ApiResult<Json<UpdatePolicyResponse>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::WritePolicy) && !op.has_role(DashboardRole::Admin) {
        return Err(ApiError::Forbidden {
            required: "write_policy".into(),
        });
    }
    if body.toml.trim().is_empty() {
        return Err(ApiError::BadRequest {
            detail: "field `toml` is empty".into(),
        });
    }
    let trimmed_b64 = body.signature_b64.trim();
    if trimmed_b64.is_empty() {
        return Err(ApiError::BadRequest {
            detail: "field `signature_b64` is empty".into(),
        });
    }
    // Accept both padded and unpadded base64 — the CLI emits
    // standard padded base64 (`base64::encode`) but a
    // copy/paste from a terminal that strips trailing `=`
    // shouldn't tank the request.
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed_b64.as_bytes())
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed_b64.as_bytes())
        })
        .map_err(|e| ApiError::BadRequest {
            detail: format!("signature_b64 is not valid base64: {e}"),
        })?;
    if sig_bytes.len() != 64 {
        return Err(ApiError::BadRequest {
            detail: format!(
                "signature must decode to 64 bytes (got {})",
                sig_bytes.len(),
            ),
        });
    }
    // The kernel-side impl does file IO + a synchronous SQL
    // transaction inside `advance_epoch`; bounce to
    // spawn_blocking so the tokio scheduler doesn't park its
    // runtime worker on a syscall.
    let data = std::sync::Arc::clone(&state.data);
    let fingerprint = op.fingerprint.clone();
    let toml_bytes = body.toml.into_bytes();
    let advancement = tokio::task::spawn_blocking(move || {
        data.update_policy_toml(&fingerprint, &toml_bytes, &sig_bytes)
    })
    .await
    .map_err(|e| ApiError::Internal {
        log_only: format!("update_policy_toml join error: {e}"),
    })??;
    Ok(Json(UpdatePolicyResponse { advancement }))
}
