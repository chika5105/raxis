//! Initiative endpoints.
//!
//! Spec §4.3 — `GET /api/initiatives`,
//! `GET /api/initiatives/:id`, `GET /api/initiatives/:id/dag`,
//! `GET /api/initiatives/:id/tasks`.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::DashboardRole;
use crate::data::{DagEdge, InitiativeListEntry, InitiativeView, TaskView};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// Query string for `GET /api/initiatives`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Optional state filter (case-insensitive).
    #[serde(default)]
    pub state: Option<String>,
    /// Page size; clamped to `[1, 200]`. Default 50.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 { 50 }

/// `GET /api/initiatives`.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<InitiativeListEntry>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let limit = q.limit.clamp(1, 200);
    let out = state.data.list_initiatives(limit, q.state.as_deref())?;
    Ok(Json(out))
}

/// `GET /api/initiatives/:id`.
pub async fn detail<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
) -> ApiResult<Json<InitiativeView>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let view = state.data.get_initiative(&id)?;
    Ok(Json(view))
}

/// DAG-shaped view returned by `GET /api/initiatives/:id/dag`.
#[derive(Debug, Serialize)]
pub struct DagView {
    /// Initiative id this DAG belongs to.
    pub initiative_id: String,
    /// Nodes (one per task).
    pub nodes: Vec<DagNode>,
    /// Edges (predecessor → successor).
    pub edges: Vec<DagEdge>,
}

/// One DAG node.
#[derive(Debug, Serialize)]
pub struct DagNode {
    /// Task id.
    pub task_id: String,
    /// Task title.
    pub title: String,
    /// Task FSM state.
    pub state: String,
}

/// `GET /api/initiatives/:id/dag`.
pub async fn dag<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
) -> ApiResult<Json<DagView>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let init = state.data.get_initiative(&id)?;
    let nodes = init.tasks.iter().map(|t| DagNode {
        task_id: t.task_id.clone(),
        title: t.title.clone(),
        state: t.state.clone(),
    }).collect();
    Ok(Json(DagView {
        initiative_id: init.summary.initiative_id,
        nodes,
        edges: init.edges,
    }))
}

/// `GET /api/initiatives/:id/tasks`.
pub async fn tasks<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<TaskView>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    Ok(Json(state.data.list_tasks(&id)?))
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
