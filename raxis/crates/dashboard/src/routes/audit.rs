//! Audit chain endpoint with cursor-based pagination, plus the
//! chain-integrity status endpoint (`GET /api/audit/chain-status`)
//! and the curated recent-activity feed (`GET /api/audit/recent`).
//!
//! The chain-status surface — `INV-AUDIT-DASHBOARD-01` — is the
//! kernel's own integrity verdict made visible to the operator
//! through the dashboard. The dashboard MUST NOT reimplement the
//! verify; the verdict comes from the kernel's
//! `raxis_audit_tools::verify_chain_from` walker so there is
//! exactly one source of truth.
//!
//! Audit discipline: paging the chain is itself a read-only
//! browse, so the `OperatorViewedAuditChain` emission was retired
//! in an earlier audit-noise sweep. The chain re-verify path
//! (`?reverify=true`) was emitting `OperatorAuditChainReverified`
//! per request; the second audit-noise sweep retired that too
//! because verifying the audit chain does not mutate kernel
//! state and emitting an audit row about verifying the audit
//! chain is recursive noise. The data-layer rate-limit
//! (≤ 1 reverify per ~30 s per operator) plus the cache-hit
//! short-circuit are enough to keep the walker from being
//! abused; signal-vs-noise policy in
//! `specs/v2/dashboard-operator-action-audit-coverage.md`.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::DashboardRole;
use crate::data::{recent_activity_filter, AuditEntryView, ChainStatusView};
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

fn default_limit() -> u32 {
    100
}

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
    let rows =
        state
            .data
            .list_audit(q.cursor, q.limit.clamp(1, 500), q.initiative_id.as_deref())?;
    Ok(Json(rows))
}

/// Query string for `GET /api/audit/recent`. The recent-activity
/// feed is what the dashboard Overview surfaces in its "Recent
/// activity" widget; we curate the audit chain server-side so
/// the FE never has to make a policy decision about what to
/// hide. See `specs/v2/dashboard-operator-action-audit-coverage.md
/// §signal-vs-noise`.
#[derive(Debug, Deserialize)]
pub struct RecentQuery {
    /// Page size; clamped to `[1, 50]`. Default 10.
    #[serde(default = "default_recent_limit")]
    pub limit: u32,
}

fn default_recent_limit() -> u32 {
    10
}

/// Maximum chain rows the recent-activity handler walks before
/// giving up and returning whatever it has accumulated. The
/// curated filter rejects most rows so an honest "newest 10
/// state-affecting events" answer may need to scan back further
/// than 10 raw chain rows. Cap kept tight so an operator-side
/// cold cache never pins a kernel worker on a megabyte read.
const RECENT_ACTIVITY_SCAN_CAP: u32 = 500;

/// `GET /api/audit/recent` — curated state-affecting events.
///
/// Returns the most recent N audit rows whose `event_kind` falls
/// in the [`recent_activity_filter::IMPORTANT_EVENT_KINDS`]
/// allow-list. The handler walks back through the chain up to
/// `RECENT_ACTIVITY_SCAN_CAP` rows so an operator who triggers
/// a burst of noise (mark-all-read, credential-list polling)
/// still sees the underlying state-changing events.
///
/// Audit discipline: this is a read-only browser like
/// `/api/audit`; it does NOT emit an `OperatorViewed*` row
/// (see signal-vs-noise policy in
/// `specs/v2/dashboard-operator-action-audit-coverage.md`).
pub async fn recent<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<RecentQuery>,
) -> ApiResult<Json<Vec<AuditEntryView>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let limit = q.limit.clamp(1, 50) as usize;
    let scan = state
        .data
        .list_audit(None, RECENT_ACTIVITY_SCAN_CAP, None)?;
    let curated: Vec<AuditEntryView> = scan
        .into_iter()
        .filter(|row| recent_activity_filter::is_important(&row.event_kind))
        .take(limit)
        .collect();
    Ok(Json(curated))
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
/// Audit discipline: every branch here is a read of an existing
/// kernel verdict (cache hit) or a re-walk of the already-persisted
/// chain. Neither mutates kernel state, and the data-layer
/// rate-limit on `?reverify=true` keeps a chatty UI from pinning
/// a worker thread. No `Operator*` audit fires — emitting a row
/// about verifying the audit chain is recursive noise (signal-
/// vs-noise policy in
/// `specs/v2/dashboard-operator-action-audit-coverage.md`).
pub async fn chain_status<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<ChainStatusQuery>,
) -> ApiResult<Json<ChainStatusResponse>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let (fresh, status) = state.data.audit_chain_status(q.reverify)?;
    Ok(Json(ChainStatusResponse { fresh, status }))
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
