//! Task endpoints: detail + structured outputs.
//!
//! Spec §4.3 — `GET /api/tasks/:id`, `GET /api/tasks/:id/outputs`.

use axum::extract::{Path, State};
use axum::Json;

use crate::auth::DashboardRole;
use crate::data::{StructuredOutputView, TaskView};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/tasks/:id`.
pub async fn detail<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
) -> ApiResult<Json<TaskView>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    Ok(Json(state.data.get_task(&id)?))
}

/// `GET /api/tasks/:id/outputs`.
pub async fn outputs<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<StructuredOutputView>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let task = state.data.get_task(&id)?;
    Ok(Json(task.structured_outputs))
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
