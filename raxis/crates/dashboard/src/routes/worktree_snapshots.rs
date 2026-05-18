//! Worktree-snapshot endpoints — iter68.
//!
//! Spec: `specs/v3/worktree-snapshots.md` §5.
//!
//! Surface:
//!
//!   * `GET /api/tasks/:task_id/worktree-snapshots`
//!     — list, newest first.
//!   * `GET /api/worktree-snapshots/:snapshot_id`
//!     — one row + its four `*_blob_sha256`s.
//!   * `GET /api/worktree-snapshots/:snapshot_id/blob/:kind`
//!     — stream a body blob, `kind ∈ {diff,log,tree,porcelain}`.
//!
//! Audit discipline: these are read-only forensics browsers.
//! Per `specs/v2/dashboard-operator-action-audit-coverage.md
//! §signal-vs-noise`, `OperatorViewed*` emissions were retired in
//! an earlier audit-noise sweep — pageview metrics live in
//! observability, not the chain.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::Response;
use axum::Json;

use crate::auth::DashboardRole;
use crate::data::{WorktreeSnapshotBlobKind, WorktreeSnapshotView};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/tasks/:task_id/worktree-snapshots`.
pub async fn list_for_task<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(task_id): Path<String>,
) -> ApiResult<Json<Vec<WorktreeSnapshotView>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    // Touch the task first so a typo surfaces as a clean 404
    // (kind = "task") instead of an empty list silently.
    let _ = state.data.get_task(&task_id)?;
    let rows = state.data.list_worktree_snapshots(&task_id)?;
    Ok(Json(rows))
}

/// `GET /api/worktree-snapshots/:snapshot_id`.
pub async fn detail<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(snapshot_id): Path<String>,
) -> ApiResult<Json<WorktreeSnapshotView>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let row = state.data.get_worktree_snapshot(&snapshot_id)?;
    Ok(Json(row))
}

/// `GET /api/worktree-snapshots/:snapshot_id/blob/:kind`.
///
/// Streams the content-addressed body blob with
/// `Content-Type: application/octet-stream` and an aggressive
/// immutable cache header — the bodies are content-addressed by
/// `sha256` so they can never change for a given snapshot_id /
/// kind pair. The browser-side timeline can therefore cache
/// liberally without staleness risk.
pub async fn blob<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path((snapshot_id, kind_str)): Path<(String, String)>,
) -> ApiResult<Response>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let kind = match kind_str.as_str() {
        "diff" => WorktreeSnapshotBlobKind::Diff,
        "log" => WorktreeSnapshotBlobKind::Log,
        "tree" => WorktreeSnapshotBlobKind::Tree,
        "porcelain" => WorktreeSnapshotBlobKind::Porcelain,
        // Unknown kind in URL — 404 (the route extractor matched
        // a literal `:kind`, the policy decision is the
        // dashboard's, and an unknown kind isn't authorisation-
        // bearing so 404 is preferable to 400).
        _ => {
            return Err(ApiError::NotFound {
                kind: "worktree_snapshot_blob_kind".into(),
            })
        }
    };
    let bytes = state.data.read_worktree_snapshot_blob(&snapshot_id, kind)?;
    // INV-WORKTREE-SNAPSHOT-CONTENT-ADDR-01: the body is
    // identified by its sha256 → `immutable` is safe.
    let resp = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(Body::from(bytes))
        .map_err(|e| ApiError::Internal {
            log_only: format!("worktree-snapshot blob response build: {e}"),
        })?;
    Ok(resp)
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
