//! Escalation endpoints.

use axum::extract::{Path, State};
use axum::Json;
use raxis_audit_tools::AuditEventKind;

use crate::auth::DashboardRole;
use crate::data::{operator_outcome, EscalationView};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/escalations`.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<Vec<EscalationView>>>
where
    D: crate::data::DashboardData,
{
    if let Err(e) = require_read(&op) {
        emit_list_audit(&*state.data, &op, 0, operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    let rows = match state.data.list_escalations() {
        Ok(r) => r,
        Err(err) => {
            emit_list_audit(&*state.data, &op, 0, operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    let count = rows.len() as u32;
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedEscalationList {
        operator_fingerprint: op.fingerprint.clone(),
        count,
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
    Ok(Json(rows))
}

fn emit_list_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    count: u32,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedEscalationList {
        operator_fingerprint: op.fingerprint.clone(),
        count,
        outcome: outcome.into(),
    });
}

/// `GET /api/escalations/:id`.
pub async fn detail<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
) -> ApiResult<Json<EscalationView>>
where
    D: crate::data::DashboardData,
{
    if let Err(e) = require_read(&op) {
        emit_detail_audit(&*state.data, &op, &id, operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    let view = match state.data.get_escalation(&id) {
        Ok(v) => v,
        Err(err) => {
            emit_detail_audit(&*state.data, &op, &id, operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedEscalation {
        operator_fingerprint: op.fingerprint.clone(),
        escalation_id: id.clone(),
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
    Ok(Json(view))
}

fn emit_detail_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    escalation_id: &str,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedEscalation {
        operator_fingerprint: op.fingerprint.clone(),
        escalation_id: escalation_id.to_owned(),
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
