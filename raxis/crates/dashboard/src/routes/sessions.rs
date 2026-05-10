//! Session endpoints: list + detail. (Stream is wired in P4.)

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::SessionView;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// Query string for `GET /api/sessions`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Page size; clamped to `[1, 200]`. Default 50.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 { 50 }

/// `GET /api/sessions`.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<SessionView>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    Ok(Json(state.data.list_sessions(q.limit.clamp(1, 200))?))
}

/// `GET /api/sessions/:id`.
pub async fn detail<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
) -> ApiResult<Json<SessionView>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    Ok(Json(state.data.get_session(&id)?))
}

fn require_read(op: &AuthorizedOperator) -> ApiResult<()> {
    if !op.has_role(DashboardRole::Read)
        && !op.has_role(DashboardRole::WritePolicy)
        && !op.has_role(DashboardRole::Admin)
    {
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    Ok(())
}
