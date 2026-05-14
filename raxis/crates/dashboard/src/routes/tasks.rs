//! Task endpoints: detail + structured outputs.
//!
//! Spec §4.3 — `GET /api/tasks/:id`, `GET /api/tasks/:id/outputs`.
//!
//! Audit discipline: these handlers are read-only forensics
//! browsers. Per `specs/v2/dashboard-operator-action-audit-
//! coverage.md §signal-vs-noise`, read-only `OperatorViewed*`
//! emissions were retired in `worker/audit-tightening` because
//! they drowned out actual state-affecting events in the chain
//! (iter48 saw 1258/1260 chain rows be `OperatorViewed*`
//! dashboard pageviews). The audit chain is the system's
//! forensic ledger for state-affecting actions; dashboard
//! pageview metrics belong in observability, not the chain.

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
    let task = state.data.get_task(&id)?;
    Ok(Json(task))
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
