//! Task endpoints: detail + structured outputs.
//!
//! Spec §4.3 — `GET /api/tasks/:id`, `GET /api/tasks/:id/outputs`.

use axum::extract::{Path, State};
use axum::Json;
use raxis_audit_tools::AuditEventKind;

use crate::auth::DashboardRole;
use crate::data::{operator_outcome, StructuredOutputView, TaskView};
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
    if let Err(e) = require_read(&op) {
        emit_detail_audit(&*state.data, &op, &id, operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    let task = match state.data.get_task(&id) {
        Ok(t) => t,
        Err(err) => {
            emit_detail_audit(&*state.data, &op, &id, operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedTask {
        operator_fingerprint: op.fingerprint.clone(),
        task_id: id.clone(),
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
    Ok(Json(task))
}

fn emit_detail_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    task_id: &str,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedTask {
        operator_fingerprint: op.fingerprint.clone(),
        task_id: task_id.to_owned(),
        outcome: outcome.into(),
    });
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
    if let Err(e) = require_read(&op) {
        emit_outputs_audit(&*state.data, &op, &id, 0, operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    let task = match state.data.get_task(&id) {
        Ok(t) => t,
        Err(err) => {
            emit_outputs_audit(&*state.data, &op, &id, 0, operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    let count = task.structured_outputs.len() as u32;
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedTaskOutputs {
        operator_fingerprint: op.fingerprint.clone(),
        task_id: id.clone(),
        count,
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
    Ok(Json(task.structured_outputs))
}

fn emit_outputs_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    task_id: &str,
    count: u32,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedTaskOutputs {
        operator_fingerprint: op.fingerprint.clone(),
        task_id: task_id.to_owned(),
        count,
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
