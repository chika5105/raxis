//! Notification endpoints.
//!
//! * `GET  /api/notifications`            — list notifications.
//! * `GET  /api/notifications/unread-count` — badge count.
//! * `PATCH /api/notifications/:id/read`   — mark one as read.
//! * `POST /api/notifications/mark-all-read` — mark all as read.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::DashboardRole;
use crate::data::NotificationView;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

// ---------------------------------------------------------------------------
// GET /api/notifications
// ---------------------------------------------------------------------------

/// Query parameters for the notification list endpoint.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Max rows to return (default 50, max 200).
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// If `true`, return only unread notifications.
    #[serde(default)]
    pub unread_only: bool,
    /// Filter by initiative id.
    pub initiative_id: Option<String>,
}

fn default_limit() -> u32 {
    50
}

/// `GET /api/notifications`.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<NotificationView>>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read) {
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    let rows = state.data.list_notifications(
        q.limit.min(200),
        q.unread_only,
        q.initiative_id.as_deref(),
    )?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// GET /api/notifications/unread-count
// ---------------------------------------------------------------------------

/// Response for the unread-count endpoint.
#[derive(Debug, Serialize)]
pub struct UnreadCountResponse {
    /// Number of unread notifications.
    pub count: u64,
}

/// `GET /api/notifications/unread-count`.
pub async fn unread_count<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<UnreadCountResponse>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read) {
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    let count = state.data.notification_count_unread()?;
    Ok(Json(UnreadCountResponse { count }))
}

// ---------------------------------------------------------------------------
// PATCH /api/notifications/:id/read
// ---------------------------------------------------------------------------

/// Response for marking a notification as read.
#[derive(Debug, Serialize)]
pub struct MarkReadResponse {
    /// `true` if the notification was previously unread and is
    /// now marked as read. `false` if it was already read or
    /// does not exist.
    pub updated: bool,
}

/// `PATCH /api/notifications/:id/read`.
///
/// The kernel-side impl ([`crate::data::DashboardData::mark_notification_read`])
/// takes a blocking SQLite write lock (`tokio::sync::Mutex::blocking_lock`
/// under the hood). Calling that from inside the axum async handler would
/// panic with `Cannot block the current thread from within a runtime` and
/// surface as a connection reset (no JSON envelope) to the operator UI.
/// We bounce the trait call onto `spawn_blocking` — same pattern as
/// `routes::policy::update_toml` — so the tokio worker thread is not pinned
/// on a syscall.
pub async fn mark_read<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(notification_id): Path<String>,
) -> ApiResult<Json<MarkReadResponse>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read) {
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    let data = std::sync::Arc::clone(&state.data);
    let updated = tokio::task::spawn_blocking(move || {
        data.mark_notification_read(&notification_id)
    })
    .await
    .map_err(|e| ApiError::Internal {
        log_only: format!("mark_notification_read join error: {e}"),
    })??;
    Ok(Json(MarkReadResponse { updated }))
}

// ---------------------------------------------------------------------------
// POST /api/notifications/mark-all-read
// ---------------------------------------------------------------------------

/// Response for marking all notifications as read.
#[derive(Debug, Serialize)]
pub struct MarkAllReadResponse {
    /// Number of notifications that were marked as read.
    pub count: u64,
}

/// `POST /api/notifications/mark-all-read`.
///
/// Same `spawn_blocking` rationale as [`mark_read`] — the kernel-side
/// impl takes a blocking SQLite write lock. Without this bounce the
/// handler panics on every operator click of the "Mark all read"
/// button, surfacing as a connection-reset rather than a structured
/// JSON envelope.
pub async fn mark_all_read<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<MarkAllReadResponse>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read) {
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    let data = std::sync::Arc::clone(&state.data);
    let count = tokio::task::spawn_blocking(move || {
        data.mark_all_notifications_read()
    })
    .await
    .map_err(|e| ApiError::Internal {
        log_only: format!("mark_all_notifications_read join error: {e}"),
    })??;
    Ok(Json(MarkAllReadResponse { count }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_query_defaults_are_correct() {
        // Empty query string → default limit 50, unread_only false,
        // initiative_id None.
        let q: ListQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, 50);
        assert!(!q.unread_only);
        assert!(q.initiative_id.is_none());
    }

    #[test]
    fn list_query_parses_all_fields() {
        let q: ListQuery = serde_json::from_str(
            r#"{"limit":10,"unread_only":true,"initiative_id":"init-x"}"#,
        )
        .unwrap();
        assert_eq!(q.limit, 10);
        assert!(q.unread_only);
        assert_eq!(q.initiative_id.as_deref(), Some("init-x"));
    }

    #[test]
    fn unread_count_response_serializes() {
        let resp = UnreadCountResponse { count: 42 };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["count"], 42);
    }

    #[test]
    fn mark_read_response_serializes() {
        let resp = MarkReadResponse { updated: true };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["updated"], true);
    }

    #[test]
    fn mark_all_read_response_serializes() {
        let resp = MarkAllReadResponse { count: 5 };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["count"], 5);
    }
}
