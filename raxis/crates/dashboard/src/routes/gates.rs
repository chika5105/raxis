//! Per-gate stats endpoint — `GET /api/gates/stats`.
//!
//! Surfaces the per-`gate_type` rollup the dashboard's Gates
//! page renders as a minimal table + sparkline strip. Every
//! row is computed server-side from `witness_records` and the
//! `tasks.gate_fixup_attempts` column so the FE never makes a
//! policy decision about how to bucket the data.
//!
//! This is a read-only browse — no audit row is emitted (the
//! signal-vs-noise policy in
//! `specs/v2/dashboard-operator-action-audit-coverage.md`
//! retires `OperatorViewed*` for paged-list reads).
//!
//! INV-DASHBOARD-GATE-STATS-PER-GATE-ROLLUP-01 (see
//! `specs/invariants.md`): the rollup MUST be stable-ordered
//! by `gate_type` and MUST include `generated_at` so the
//! frontend can flag stale renders during a multi-tab session.

use axum::extract::State;
use axum::Json;

use crate::auth::DashboardRole;
use crate::data::GateStatsResponse;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/gates/stats` — per-gate rollup of witness outcomes
/// + cumulative fixup-loop counter. Read-role suffices; the
/// signal is operator-visible by design.
pub async fn stats<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<GateStatsResponse>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let resp = state.data.gate_stats()?;
    Ok(Json(resp))
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
