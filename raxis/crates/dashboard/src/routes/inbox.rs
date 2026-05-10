//! `GET /api/inbox` — operator inbox.

use axum::extract::State;
use axum::Json;

use crate::auth::DashboardRole;
use crate::data::AuditEntryView;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/inbox`.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<Vec<AuditEntryView>>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read)
        && !op.has_role(DashboardRole::WritePolicy)
        && !op.has_role(DashboardRole::Admin)
    {
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    Ok(Json(state.data.list_inbox()?))
}
