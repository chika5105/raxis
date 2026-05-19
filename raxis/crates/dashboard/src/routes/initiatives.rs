//! Initiative endpoints.
//!
//! Spec §4.3 — `GET /api/initiatives`,
//! `GET /api/initiatives/:id`, `GET /api/initiatives/:id/dag`,
//! `GET /api/initiatives/:id/tasks`,
//! `GET /api/initiatives/:id/plan`
//! (`INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`).
//!
//! Audit discipline: every endpoint here is a read-only
//! browser. The `OperatorViewedInitiative*` /
//! `OperatorViewedPlanToml` emissions were retired in
//! an earlier audit-noise sweep per the signal-vs-noise policy in
//! `specs/v2/dashboard-operator-action-audit-coverage.md`. The
//! audit chain is the system's forensic ledger for
//! state-affecting actions; dashboard pageview metrics live in
//! observability instead. The state-mutating policy / approval
//! flows in `routes::policy` and the credential reveal flow in
//! `routes::credentials` continue to audit unchanged.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::DashboardRole;
use crate::data::{DagEdge, InitiativeListEntry, InitiativePlanView, InitiativeView, TaskView};
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

fn default_limit() -> u32 {
    50
}

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
    /// Operator-authored `[workspace].name`.
    pub display_name: String,
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
    /// Semantic agent type (`Orchestrator`, `Executor`, `Reviewer`).
    pub agent_type: String,
    /// Task FSM state.
    pub state: String,
    /// `true` when an executor/reviewer subtask activation is live
    /// for this task. Mirrors `TaskView::is_active`: the FSM state
    /// can be `Admitted` while the task is mid-execution between
    /// VM hops, so the FE renders a Running pill / pulse whenever
    /// `is_active` is true regardless of the `state` string. See
    /// `INV-DASHBOARD-RUNNING-STATE-VISIBLE-01`.
    pub is_active: bool,
    /// Latest gate state per gate so the FE can render witness gates
    /// as first-class dashed DAG nodes. Includes both issued-but-not-
    /// answered verifier tokens (`latest_verdict = "Pending"`) and
    /// durable witness rows (`Pass` / `Fail` / `Inconclusive`).
    /// Empty when no verifier has been spawned for the task.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gate_verdict_summary: Vec<crate::data::DagGateVerdictChip>,
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
    // iter68 PR 4 — one aggregating SQL hop fetches every task's
    // latest-verdict-per-gate so the DAG renders chips inline.
    // Failure here is *not* fatal — an empty map degrades the DAG
    // to its iter-67 shape (no chips) rather than 500'ing the
    // entire DAG view. The structured-log line surfaces the gap.
    let chip_map = state.data.list_dag_gate_summaries(&id).unwrap_or_else(|e| {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"DagGateChipsDegraded\",\
             \"initiative_id\":\"{id}\",\"error\":\"{e}\"}}"
        );
        std::collections::HashMap::new()
    });
    let nodes = init
        .tasks
        .iter()
        .map(|t| DagNode {
            task_id: t.task_id.clone(),
            title: t.title.clone(),
            agent_type: t.agent_type.clone(),
            state: t.state.clone(),
            is_active: t.is_active,
            gate_verdict_summary: chip_map.get(&t.task_id).cloned().unwrap_or_default(),
        })
        .collect();
    Ok(Json(DagView {
        initiative_id: init.summary.initiative_id,
        display_name: init.summary.display_name,
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
    let rows = state.data.list_tasks(&id)?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// Plan view — `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`
// ---------------------------------------------------------------------------

/// `Cache-Control` header for the plan-view endpoint. Approved
/// plans are immutable post-approval (see kernel-store.md §plan-
/// authority + plan-bundle-sealing.md §8.2 "stored once keyed by
/// bundle_sha256"), so a 60-second private cache is safe and
/// dramatically reduces dashboard ↔ kernel round-trips when an
/// operator clicks back-and-forth between tabs. The matching FE
/// `staleTime` (also 60 s) keeps the React Query cache aligned
/// with the HTTP cache.
///
/// `private` (not `public`) ⇒ no proxy-side caching — operator
/// JWT context is per-request and operator-bound; never share
/// the response across operators.
const PLAN_CACHE_CONTROL_APPROVED: &str = "private, max-age=60";

/// Cache-Control for plans whose initiative is still in
/// `Draft` (or whose admission was rejected). The body can change
/// next request, so the FE must NOT cache it client-side.
const PLAN_CACHE_CONTROL_VOLATILE: &str = "private, no-store";

/// `GET /api/initiatives/:id/plan` — surfaces the original
/// submitted `plan.toml` byte-for-byte.
///
/// Auth: same `read` role as every other initiative endpoint. The
/// route does NOT differentiate between read / write_policy /
/// admin operators — read-role suffices.
///
/// Status code mapping:
///   * 200 — plan present (approved or pending).
///   * 404 `FAIL_DASHBOARD_NOT_FOUND` — initiative id unknown.
///   * 410 `FAIL_DASHBOARD_GONE`      — initiative exists but
///     plan archived/purged.
///   * 401/403 — auth / permission failures (shared shape with
///     every other endpoint).
///   * 500 — DB read failure or malformed-UTF-8 row (the kernel
///     pins UTF-8 at write time; a non-UTF-8 row is a real bug
///     that surfaces as a structured `FAIL_DASHBOARD_INTERNAL`).
pub async fn plan<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
) -> Result<Response, ApiError>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let view: InitiativePlanView = state.data.get_initiative_plan(&id)?;
    let cache_control = if view.approval_status == "approved" {
        PLAN_CACHE_CONTROL_APPROVED
    } else {
        PLAN_CACHE_CONTROL_VOLATILE
    };
    let json = Json(view).into_response();
    let mut response = (StatusCode::OK, json).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    Ok(response)
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
