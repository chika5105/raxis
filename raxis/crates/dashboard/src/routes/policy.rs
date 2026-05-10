//! Policy view endpoints. The `PUT /api/policy/toml` write
//! surface is implemented in P5 once the kernel-glue can wire the
//! epoch-advance path; for now we expose the read-only views.

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;

use crate::auth::DashboardRole;
use crate::data::PolicySnapshotView;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/policy` — structured snapshot.
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
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    Ok(Json(state.data.policy_snapshot()?))
}

/// `GET /api/policy/toml` — raw TOML bytes (write_policy role).
pub async fn raw_toml<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<impl IntoResponse>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::WritePolicy) && !op.has_role(DashboardRole::Admin) {
        return Err(ApiError::Forbidden { required: "write_policy".into() });
    }
    let body = state.data.policy_toml_bytes()?;
    Ok((
        [(header::CONTENT_TYPE, "application/toml; charset=utf-8")],
        body,
    ))
}
