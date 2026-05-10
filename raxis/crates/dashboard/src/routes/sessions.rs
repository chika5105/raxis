//! Session endpoints: list, detail, and SSE stream (§4.3 P4).

use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::Json;
use futures_util::stream::{self, Stream, StreamExt};
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::SessionView;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};
use crate::stream::StreamEvent;

/// Query string for `GET /api/sessions`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Page size; clamped to `[1, 200]`. Default 50.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 { 50 }

/// `GET /api/sessions`.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<SessionView>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    Ok(Json(state.data.list_sessions(q.limit.clamp(1, 200))?))
}

/// `GET /api/sessions/:id`.
pub async fn detail<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
) -> ApiResult<Json<SessionView>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    Ok(Json(state.data.get_session(&id)?))
}

/// Query string for `GET /api/sessions/:id/stream`.
#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    /// Number of replay-tail events the SSE handler emits
    /// before attaching the live subscription. Clamped to
    /// `[0, 500]`. Default 100.
    #[serde(default = "default_tail")]
    pub tail: usize,
}

fn default_tail() -> usize { 100 }

/// `GET /api/sessions/:id/stream`. Server-Sent Events stream of
/// the session's captured model output.
///
/// Wire shape: each event is `event: <kind>\ndata: <json>\n\n`.
/// Special control frames:
///   * `event: tail-complete` — the replay tail has been
///     drained; live frames begin next.
///   * `event: lagged\ndata: <count>\n\n` — slow subscriber
///     missed `count` events.
///   * `event: closed\n` — publisher dropped the broadcast
///     (session terminated). The HTTP connection closes
///     immediately after.
pub async fn stream<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
    Query(q): Query<StreamQuery>,
) -> Result<impl IntoResponse, ApiError>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let tail_n = q.tail.min(500);
    // Replay tail (file-ring snapshot) first.
    let tail = state.data.stream_tail(&id, tail_n).unwrap_or_default();
    // Subscribe (may legitimately fail with NotFound for a
    // session that never produced output — surfaced as 404 by
    // the route layer).
    let sub_result = state.data.stream_subscribe(&id);
    let sse_stream = build_sse_stream(tail, sub_result);
    Ok(Sse::new(sse_stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

/// Build the SSE stream: replay-tail frames first, then a
/// `tail-complete` marker, then live frames from the
/// subscription. Lagged frames produce a `lagged` event;
/// publisher-drop produces `closed` then completes.
fn build_sse_stream(
    tail: Vec<StreamEvent>,
    sub_result: Result<crate::stream::StreamSubscription, ApiError>,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    let tail_iter = tail.into_iter().map(|e| {
        let payload = serde_json::to_string(&e.payload).unwrap_or_else(|_| "null".into());
        Ok(Event::default()
            .event(e.kind)
            .data(payload)
            .id(e.at_ms.to_string()))
    });
    let tail_marker = stream::once(async {
        // Emit a non-empty `data` so the SSE frame fully flushes
        // to the wire (axum/hyper hold the chunk until the
        // separator pair is in the buffer; an empty data field
        // can stall behind that flush boundary on macOS).
        Ok(Event::default().event("tail-complete").data("ok"))
    });
    let live_stream: futures_util::stream::BoxStream<'static, Result<Event, Infallible>> =
        match sub_result {
            Ok(sub) => Box::pin(stream::unfold(
                (sub, false),
                |(mut sub, mut closed)| async move {
                    if closed {
                        return None;
                    }
                    match sub.recv().await {
                        Ok(Some(e)) => {
                            let payload = serde_json::to_string(&e.payload)
                                .unwrap_or_else(|_| "null".into());
                            let evt = Event::default()
                                .event(e.kind)
                                .data(payload)
                                .id(e.at_ms.to_string());
                            Some((Ok(evt), (sub, false)))
                        }
                        Ok(None) => {
                            // Publisher dropped — emit one
                            // terminal frame, then have the
                            // next iteration return None.
                            let evt = Event::default()
                                .event("closed")
                                .data("publisher-dropped");
                            closed = true;
                            Some((Ok(evt), (sub, closed)))
                        }
                        Err(n) => {
                            let evt = Event::default()
                                .event("lagged")
                                .data(n.to_string());
                            Some((Ok(evt), (sub, false)))
                        }
                    }
                },
            )),
            Err(_) => Box::pin(stream::once(async {
                Ok(Event::default().event("closed").data("no-stream-source"))
            })),
        };
    stream::iter(tail_iter).chain(tail_marker).chain(live_stream)
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
