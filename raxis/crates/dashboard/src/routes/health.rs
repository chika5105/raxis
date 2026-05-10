//! `GET /api/health` — kernel health snapshot.
//!
//! Spec §4.2 grants the `admin` role to read this endpoint
//! because the kernel-health surface contains operational
//! metadata (active session counts, doctor-style checks). All
//! other operators get a sanitized `{ status: "ok" }` shape.

use axum::extract::State;
use axum::Json;

use crate::auth::DashboardRole;
use crate::data::HealthSnapshot;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/health` — full health snapshot for `admin` operators,
/// sanitized snapshot for everyone else.
pub async fn health<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<HealthSnapshot>>
where
    D: crate::data::DashboardData,
{
    let full = state.data.health();
    if op.has_role(DashboardRole::Admin) {
        return Ok(Json(full));
    }
    if !op.has_role(DashboardRole::Read) {
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    // Sanitize for non-admins: keep the coarse status + active
    // counts, drop the per-check details.
    Ok(Json(HealthSnapshot {
        status: full.status,
        checks: vec![],
        kernel_booted_at: full.kernel_booted_at,
        policy_epoch: full.policy_epoch,
        active_initiatives: full.active_initiatives,
        active_sessions: full.active_sessions,
        pending_escalations: full.pending_escalations,
    }))
}
