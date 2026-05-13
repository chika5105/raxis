//! Initiative endpoints.
//!
//! Spec §4.3 — `GET /api/initiatives`,
//! `GET /api/initiatives/:id`, `GET /api/initiatives/:id/dag`,
//! `GET /api/initiatives/:id/tasks`,
//! `GET /api/initiatives/:id/plan`
//! (`INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`).

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use raxis_audit_tools::AuditEventKind;
use serde::{Deserialize, Serialize};

use crate::auth::DashboardRole;
use crate::data::{
    operator_outcome, DagEdge, InitiativeListEntry, InitiativePlanView, InitiativeView, TaskView,
};
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
    if let Err(e) = require_read(&op) {
        emit_list_audit(&*state.data, &op, 0, q.state.as_deref(), operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    let limit = q.limit.clamp(1, 200);
    let out = match state.data.list_initiatives(limit, q.state.as_deref()) {
        Ok(rows) => rows,
        Err(err) => {
            emit_list_audit(&*state.data, &op, 0, q.state.as_deref(), operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    let count = out.len() as u32;
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedInitiativeList {
        operator_fingerprint: op.fingerprint.clone(),
        count,
        state_filter: q.state.clone(),
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
    Ok(Json(out))
}

fn emit_list_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    count: u32,
    state_filter: Option<&str>,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedInitiativeList {
        operator_fingerprint: op.fingerprint.clone(),
        count,
        state_filter: state_filter.map(str::to_owned),
        outcome: outcome.into(),
    });
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
    if let Err(e) = require_read(&op) {
        emit_detail_audit(&*state.data, &op, &id, operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    let view = match state.data.get_initiative(&id) {
        Ok(v) => v,
        Err(err) => {
            emit_detail_audit(&*state.data, &op, &id, operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedInitiative {
        operator_fingerprint: op.fingerprint.clone(),
        initiative_id: id.clone(),
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
    Ok(Json(view))
}

fn emit_detail_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    initiative_id: &str,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedInitiative {
        operator_fingerprint: op.fingerprint.clone(),
        initiative_id: initiative_id.to_owned(),
        outcome: outcome.into(),
    });
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
    if let Err(e) = require_read(&op) {
        emit_dag_audit(&*state.data, &op, &id, operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    let init = match state.data.get_initiative(&id) {
        Ok(v) => v,
        Err(err) => {
            emit_dag_audit(&*state.data, &op, &id, operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    let nodes = init.tasks.iter().map(|t| DagNode {
        task_id: t.task_id.clone(),
        title: t.title.clone(),
        state: t.state.clone(),
    }).collect();
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedInitiativeDag {
        operator_fingerprint: op.fingerprint.clone(),
        initiative_id: id.clone(),
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
    Ok(Json(DagView {
        initiative_id: init.summary.initiative_id,
        nodes,
        edges: init.edges,
    }))
}

fn emit_dag_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    initiative_id: &str,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedInitiativeDag {
        operator_fingerprint: op.fingerprint.clone(),
        initiative_id: initiative_id.to_owned(),
        outcome: outcome.into(),
    });
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
    if let Err(e) = require_read(&op) {
        emit_tasks_audit(&*state.data, &op, &id, 0, operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    let rows = match state.data.list_tasks(&id) {
        Ok(r) => r,
        Err(err) => {
            emit_tasks_audit(&*state.data, &op, &id, 0, operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    let count = rows.len() as u32;
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedInitiativeTasks {
        operator_fingerprint: op.fingerprint.clone(),
        initiative_id: id.clone(),
        count,
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
    Ok(Json(rows))
}

fn emit_tasks_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    initiative_id: &str,
    count: u32,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedInitiativeTasks {
        operator_fingerprint: op.fingerprint.clone(),
        initiative_id: initiative_id.to_owned(),
        count,
        outcome: outcome.into(),
    });
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
    if let Err(e) = require_read(&op) {
        emit_plan_audit(&*state.data, &op, &id, None, operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    let view: InitiativePlanView = match state.data.get_initiative_plan(&id) {
        Ok(v) => v,
        Err(err) => {
            emit_plan_audit(&*state.data, &op, &id, None, operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    // INV-DASHBOARD-OPERATOR-ACTION-AUDIT-COVERAGE-01:
    // emit `OperatorViewedPlanToml` BEFORE returning the
    // plan bytes. The audit row carries the plan SHA-256
    // so a forensic walker can correlate the read with the
    // exact byte sequence the operator saw.
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedPlanToml {
        operator_fingerprint: op.fingerprint.clone(),
        initiative_id: id.clone(),
        plan_sha256: view.plan_sha256.clone(),
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
    let cache_control = if view.approval_status == "approved" {
        PLAN_CACHE_CONTROL_APPROVED
    } else {
        PLAN_CACHE_CONTROL_VOLATILE
    };
    let json = Json(view).into_response();
    let mut response = (StatusCode::OK, json).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        // `from_static` is infallible for an ASCII string literal.
        HeaderValue::from_static(cache_control),
    );
    Ok(response)
}

fn emit_plan_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    initiative_id: &str,
    plan_sha256: Option<&str>,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedPlanToml {
        operator_fingerprint: op.fingerprint.clone(),
        initiative_id: initiative_id.to_owned(),
        plan_sha256: plan_sha256.map(str::to_owned),
        outcome: outcome.into(),
    });
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
