//! Audit chain endpoint with cursor-based pagination.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::AuditEntryView;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// Query string for `GET /api/audit`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Cursor — return entries strictly older than this seq.
    /// Omit on the first page; pass the previous page's last
    /// `seq` to get the next page.
    #[serde(default)]
    pub cursor: Option<u64>,
    /// Page size; clamped to `[1, 500]`. Default 100.
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Filter by initiative id.
    #[serde(default)]
    pub initiative_id: Option<String>,
}

fn default_limit() -> u32 { 100 }

/// `GET /api/audit`.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<AuditEntryView>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    Ok(Json(state.data.list_audit(
        q.cursor,
        q.limit.clamp(1, 500),
        q.initiative_id.as_deref(),
    )?))
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
