//! `GET /api/health` — kernel health snapshot.
//! `GET /api/health/subsystems` — per-subsystem health cards.
//!
//! Spec §4.2 grants the `admin` role to read `/api/health`
//! because the kernel-health surface contains operational
//! metadata (active session counts, doctor-style checks). All
//! other operators get a sanitized `{ status: "ok" }` shape.
//!
//! The subsystem-health surface gates on `read` like every
//! other privileged-read view, and emits an
//! `OperatorHealthQueried` audit event per
//! `INV-AUDIT-OPERATOR-ACTION-01`. Verdicts come from the
//! kernel's own bookkeeping — the dashboard never invents a
//! status (`INV-DASHBOARD-VALIDATE-01`).

use axum::extract::State;
use axum::Json;
use raxis_audit_tools::AuditEventKind;

use crate::auth::DashboardRole;
use crate::data::{operator_outcome, HealthSnapshot, SubsystemHealthResponse};
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

/// `GET /api/health/subsystems` — per-subsystem cards for the
/// dashboard Health tab. Honours `INV-AUDIT-OPERATOR-ACTION-01`
/// (audit emit on success and on each rejection path) and
/// `INV-DASHBOARD-VALIDATE-01` (validate auth + permission
/// before any privileged read).
pub async fn subsystems<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<SubsystemHealthResponse>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read) {
        let err = ApiError::Forbidden { required: "read".into() };
        emit_health_audit(
            &*state.data,
            &op,
            operator_outcome::outcome_from_api_error(&err),
        );
        return Err(err);
    }
    let snapshot = match state.data.subsystem_health() {
        Ok(s) => s,
        Err(err) => {
            emit_health_audit(
                &*state.data,
                &op,
                operator_outcome::outcome_from_api_error(&err),
            );
            return Err(err);
        }
    };
    state
        .data
        .emit_operator_audit(AuditEventKind::OperatorHealthQueried {
            operator_fingerprint: op.fingerprint.clone(),
            outcome:              operator_outcome::ACCEPTED.into(),
        })?;
    Ok(Json(snapshot))
}

fn emit_health_audit<D>(data: &D, op: &AuthorizedOperator, outcome: &'static str)
where
    D: crate::data::DashboardData + ?Sized,
{
    let _ = data.emit_operator_audit(AuditEventKind::OperatorHealthQueried {
        operator_fingerprint: op.fingerprint.clone(),
        outcome:              outcome.into(),
    });
}
