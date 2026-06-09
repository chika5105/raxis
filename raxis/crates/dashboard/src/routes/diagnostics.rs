//! Diagnostics endpoints.
//!
//! `GET /api/diagnostics` returns a read-only triage projection over
//! existing kernel facts: health, audit rows, notifications, and
//! kernel-owned log lines. The route does not mutate state and emits no
//! operator audit row; it is an operator browse surface, not an action.

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::DiagnosticsResponse;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

const DIAGNOSTICS_CACHE_CONTROL: &str = "no-store, max-age=0, must-revalidate";

/// Query parameters for `GET /api/diagnostics`.
#[derive(Debug, Deserialize)]
pub struct DiagnosticsQuery {
    /// Optional initiative id focus. Global findings may still be
    /// returned when they explain scoped failures.
    pub initiative_id: Option<String>,
    /// Maximum findings to return (default 50, max 200).
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    50
}

/// `GET /api/diagnostics`.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<DiagnosticsQuery>,
) -> ApiResult<impl IntoResponse>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read) {
        return Err(ApiError::Forbidden {
            required: "read".into(),
        });
    }
    let resp: DiagnosticsResponse = state
        .data
        .diagnostics(q.initiative_id.as_deref(), q.limit.min(200))?;
    Ok((
        [(header::CACHE_CONTROL, DIAGNOSTICS_CACHE_CONTROL)],
        Json(resp),
    ))
}
