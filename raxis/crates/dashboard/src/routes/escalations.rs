//! Escalation endpoints.
//!
//! Audit discipline: pure read-only browsers. The
//! `OperatorViewedEscalationList` / `OperatorViewedEscalation`
//! emissions were retired in an earlier audit-noise sweep per the
//! signal-vs-noise policy in
//! `specs/v2/dashboard-operator-action-audit-coverage.md` —
//! dashboard pageviews are not state-affecting and belong in
//! observability metrics rather than the forensic audit chain.

use axum::extract::{Path, State};
use axum::Json;

use crate::auth::DashboardRole;
use crate::data::EscalationView;
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
    require_read(&op)?;
    let rows = state.data.list_escalations()?;
    Ok(Json(rows))
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
    require_read(&op)?;
    let view = state.data.get_escalation(&id)?;
    Ok(Json(view))
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
