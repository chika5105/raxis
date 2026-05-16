//! `GET /api/inbox` — operator inbox.
//!
//! Audit discipline: pure read-only browser. The
//! `OperatorViewedInbox` emission was retired in
//! an earlier audit-noise sweep per the signal-vs-noise policy in
//! `specs/v2/dashboard-operator-action-audit-coverage.md` —
//! the inbox is itself a projection of the audit chain, so a
//! per-open audit row drowns out the signal it surfaces.

use axum::extract::State;
use axum::Json;

use crate::auth::DashboardRole;
use crate::data::AuditEntryView;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/inbox`.
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
        return Err(ApiError::Forbidden {
            required: "read".into(),
        });
    }
    let rows = state.data.list_inbox()?;
    Ok(Json(rows))
}
