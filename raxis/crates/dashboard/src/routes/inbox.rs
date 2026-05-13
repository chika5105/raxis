//! `GET /api/inbox` — operator inbox.

use axum::extract::State;
use axum::Json;
use raxis_audit_tools::AuditEventKind;

use crate::auth::DashboardRole;
use crate::data::{operator_outcome, AuditEntryView};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/inbox`.
///
/// `INV-DASHBOARD-OPERATOR-ACTION-AUDIT-COVERAGE-01`: every
/// inbox open emits `OperatorViewedInbox`. The inbox surface
/// pulls a slice of the operator-audit chain itself, so a
/// reader walking it is a forensic event in its own right.
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
        emit_list_audit(&*state.data, &op, 0, operator_outcome::REJECTED_PERMISSION);
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    let rows = match state.data.list_inbox() {
        Ok(r) => r,
        Err(err) => {
            emit_list_audit(&*state.data, &op, 0, operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    let count = rows.len() as u32;
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedInbox {
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
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedInbox {
        operator_fingerprint: op.fingerprint.clone(),
        count,
        outcome: outcome.into(),
    });
}
