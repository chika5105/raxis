//! Global witness timeline — `GET /api/witnesses?limit=N`.
//!
//! iter68 PR 5. Powers the cross-task Witnesses page (sidebar
//! glyph `W`). Read-only browse, capped at 500 rows server-side
//! to keep the wire response bounded.
//!
//! Per `specs/v2/dashboard-operator-action-audit-coverage.md
//! §signal-vs-noise`, read-only `OperatorViewed*` emissions were
//! retired so this handler emits no audit row — pageview metrics
//! belong in observability, not the chain.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::WitnessView;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// Query parameters for `GET /api/witnesses`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Server-side capped at 500. Defaults to 100 — wide enough
    /// to fill a single-page scroll without paging.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    100
}

/// `GET /api/witnesses?limit=N`.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<WitnessView>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let limit = q.limit.min(500);
    let rows = state.data.list_recent_witnesses(limit)?;
    Ok(Json(rows))
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
