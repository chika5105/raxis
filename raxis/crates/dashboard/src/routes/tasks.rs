//! Task endpoints: detail + structured outputs.
//!
//! Spec §4.3 — `GET /api/tasks/:id`, `GET /api/tasks/:id/outputs`.
//!
//! Audit discipline: these handlers are read-only forensics
//! browsers. Per `specs/v2/dashboard-operator-action-audit-
//! coverage.md §signal-vs-noise`, read-only `OperatorViewed*`
//! emissions were retired in an earlier audit-noise sweep because
//! they drowned out actual state-affecting events in the chain
//! (iter48 saw 1258/1260 chain rows be `OperatorViewed*`
//! dashboard pageviews). The audit chain is the system's
//! forensic ledger for state-affecting actions; dashboard
//! pageview metrics belong in observability, not the chain.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::{StructuredOutputView, TaskLlmTurnView, TaskView};
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

/// Query string for `GET /api/tasks/:id/llm-turns`.
#[derive(Debug, Deserialize)]
pub struct LlmTurnsQuery {
    /// Number of recent records to return. Capped at 500 by the
    /// data-layer impl. Defaults to 50 when omitted — enough to
    /// fill a typical operator scroll without paging.
    #[serde(default = "default_llm_turns_limit")]
    pub limit: u32,
}

fn default_llm_turns_limit() -> u32 {
    50
}

/// `GET /api/tasks/:id/llm-turns?limit=N`.
///
/// Returns the last `N` raw LLM-turn records captured for this
/// task — the upstream provider's raw response envelopes
/// (status, body, latency), keyed by `task_id` so the records
/// survive VM restarts within the same task. Backed by the
/// kernel's per-task on-disk file ring (see
/// `raxis-dashboard-kernel::TaskLlmCapture`).
///
/// `INV-DASHBOARD-TASK-LLM-CAPTURE-01`.
pub async fn llm_turns<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
    Query(q): Query<LlmTurnsQuery>,
) -> ApiResult<Json<Vec<TaskLlmTurnView>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    // Touch the task to ensure it exists — the data layer
    // returns `NotFound { kind: "task" }` for a typo so the
    // operator gets a clean 404 instead of an empty body.
    let _ = state.data.get_task(&id)?;
    let records = state.data.tail_task_llm_turns(&id, q.limit)?;
    Ok(Json(records))
}

fn require_read(op: &AuthorizedOperator) -> ApiResult<()> {
    if !op.has_role(DashboardRole::Read)
        && !op.has_role(DashboardRole::WritePolicy)
        && !op.has_role(DashboardRole::Admin)
    {
        return Err(ApiError::Forbidden {
            required: "read".into(),
        });
    }
    Ok(())
}
