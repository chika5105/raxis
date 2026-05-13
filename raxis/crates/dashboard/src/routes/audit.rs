//! Audit chain endpoint with cursor-based pagination, plus the
//! chain-integrity status endpoint (`GET /api/audit/chain-status`).
//!
//! The chain-status surface — `INV-AUDIT-DASHBOARD-01` — is the
//! kernel's own integrity verdict made visible to the operator
//! through the dashboard. The dashboard MUST NOT reimplement the
//! verify; the verdict comes from the kernel's
//! `raxis_audit_tools::verify_chain_from` walker so there is
//! exactly one source of truth.

use axum::extract::{Query, State};
use axum::Json;
use raxis_audit_tools::AuditEventKind;
use serde::{Deserialize, Serialize};

use crate::auth::DashboardRole;
use crate::data::{operator_outcome, AuditEntryView, ChainStatusView};
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
///
/// `INV-DASHBOARD-OPERATOR-ACTION-AUDIT-COVERAGE-01`: paging
/// the chain itself audits via `OperatorViewedAuditChain` so a
/// forensic reviewer can reconstruct who walked which range
/// and when. The cursor + filter are recorded so the rebuilt
/// page is unambiguous.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<AuditEntryView>>>
where
    D: crate::data::DashboardData,
{
    if let Err(e) = require_read(&op) {
        emit_list_audit(&*state.data, &op, q.cursor, 0, q.initiative_id.as_deref(), operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    let rows = match state.data.list_audit(
        q.cursor,
        q.limit.clamp(1, 500),
        q.initiative_id.as_deref(),
    ) {
        Ok(r) => r,
        Err(err) => {
            emit_list_audit(&*state.data, &op, q.cursor, 0, q.initiative_id.as_deref(), operator_outcome::outcome_from_api_error(&err));
            return Err(err);
        }
    };
    let count = rows.len() as u32;
    state.data.emit_operator_audit(AuditEventKind::OperatorViewedAuditChain {
        operator_fingerprint: op.fingerprint.clone(),
        cursor_seq: q.cursor,
        count,
        initiative_id_filter: q.initiative_id.clone(),
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
    Ok(Json(rows))
}

fn emit_list_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    cursor_seq: Option<u64>,
    count: u32,
    initiative_id_filter: Option<&str>,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorViewedAuditChain {
        operator_fingerprint: op.fingerprint.clone(),
        cursor_seq,
        count,
        initiative_id_filter: initiative_id_filter.map(str::to_owned),
        outcome: outcome.into(),
    });
}

/// Query string for `GET /api/audit/chain-status`.
#[derive(Debug, Deserialize, Default)]
pub struct ChainStatusQuery {
    /// When `true`, bypass any cached verdict and re-verify the
    /// chain on this call. The data layer rate-limits the
    /// re-verify path internally (no more than once every ~30 s
    /// regardless of caller intent) so a chatty operator UI
    /// cannot pin a worker thread on chain re-walks.
    ///
    /// Defaults to `false` — `GET` calls served from the cache
    /// are safe to fire on every page mount.
    #[serde(default)]
    pub reverify: bool,
}

/// Response wrapper for `GET /api/audit/chain-status`. Wraps
/// `ChainStatusView` plus the request-side reverify flag so the
/// FE can show "this was a fresh verify" vs "cached" affordance.
#[derive(Debug, Serialize)]
pub struct ChainStatusResponse {
    /// Whether the data layer actually performed a fresh walk
    /// for this request (vs returning the cached verdict).
    pub fresh: bool,
    /// The status verdict.
    #[serde(flatten)]
    pub status: ChainStatusView,
}

/// `GET /api/audit/chain-status` — surfaces the kernel's
/// audit-chain integrity verdict to the operator UI per
/// `INV-AUDIT-DASHBOARD-01`. The verdict comes from the kernel's
/// own `verify_chain_from` walker (no FE re-implementation).
///
/// Audit discipline: implicit (cache-hit) reads are NOT audited
/// — they would flood the chain with one row per page mount.
/// The explicit `?reverify=true` path IS audited via
/// `OperatorAuditChainReverified` per `INV-AUDIT-OPERATOR-ACTION-01`,
/// since it deliberately pins a kernel worker thread on a full
/// chain walk.
pub async fn chain_status<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<ChainStatusQuery>,
) -> ApiResult<Json<ChainStatusResponse>>
where
    D: crate::data::DashboardData,
{
    if let Err(e) = require_read(&op) {
        if q.reverify {
            emit_reverify_audit(
                &*state.data,
                &op,
                "unknown",
                0,
                operator_outcome::outcome_from_api_error(&e),
            );
        }
        return Err(e);
    }
    let (fresh, status) = match state.data.audit_chain_status(q.reverify) {
        Ok(v) => v,
        Err(err) => {
            if q.reverify {
                emit_reverify_audit(
                    &*state.data,
                    &op,
                    "unknown",
                    0,
                    operator_outcome::outcome_from_api_error(&err),
                );
            }
            return Err(err);
        }
    };
    if q.reverify {
        state
            .data
            .emit_operator_audit(AuditEventKind::OperatorAuditChainReverified {
                operator_fingerprint: op.fingerprint.clone(),
                verdict:              status.status.clone(),
                last_verified_seq:    status.last_verified_seq,
                outcome:              operator_outcome::ACCEPTED.into(),
            })?;
    }
    Ok(Json(ChainStatusResponse { fresh, status }))
}

fn emit_reverify_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    verdict: &str,
    last_verified_seq: u64,
    outcome: &'static str,
) where
    D: crate::data::DashboardData + ?Sized,
{
    let _ = data.emit_operator_audit(AuditEventKind::OperatorAuditChainReverified {
        operator_fingerprint: op.fingerprint.clone(),
        verdict:              verdict.to_owned(),
        last_verified_seq,
        outcome:              outcome.into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_status_query_defaults_to_no_reverify() {
        let q: ChainStatusQuery = serde_json::from_str("{}").unwrap();
        assert!(!q.reverify);
    }

    #[test]
    fn chain_status_query_parses_reverify_true() {
        let q: ChainStatusQuery = serde_json::from_str(r#"{"reverify":true}"#).unwrap();
        assert!(q.reverify);
    }
}
