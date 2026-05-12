//! Session endpoints: list, detail, and SSE stream (§4.3 P4).

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::Json;
use futures_util::stream::{self, Stream, StreamExt};
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::SessionView;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator, ShutdownSignal};
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
/// Wire shape: each event is `event: <kind>\ndata: <json>\n\n`
/// with `id: <at_ms>\n` so the browser's EventSource auto-
/// reconnect carries the last seen id back via the
/// `Last-Event-ID` request header.
///
/// Special control frames:
///   * `event: tail-complete` — the replay tail has been
///     drained; live frames begin next.
///   * `event: lagged\ndata: <count>\n\n` — slow subscriber
///     missed `count` events.
///   * `event: closed\n` — publisher dropped the broadcast
///     (session terminated). The HTTP connection closes
///     immediately after.
///   * `event: kernel-shutdown\n` — emitted exactly once just
///     before the kernel goes through orderly shutdown so the
///     browser's EventSource backoff does not retry against a
///     listener that is no longer there.
///
/// # Resume contract (`Last-Event-ID`)
///
/// On reconnect the browser includes the id of the last event
/// it saw via `Last-Event-ID: <at_ms>`. The handler skips every
/// replay-tail event with `at_ms <= last_id` so the operator
/// does NOT see duplicate frames after a transient network
/// blip. Live frames are not de-duplicated against the resume
/// id (the live broadcast channel only emits forward-going
/// events; a duplicate would imply the kernel re-published the
/// same captured chunk, which is a kernel bug, not a
/// subscriber concern).
///
/// The query string `?tail=N` overrides the replay-tail size
/// and is clamped to `[0, 500]`. `Last-Event-ID` is honoured
/// regardless of the tail size.
pub async fn stream<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(id): Path<String>,
    Query(q): Query<StreamQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    // Fast-path the kernel-shutdown case: a freshly-attached
    // subscriber that hits a kernel that already triggered
    // shutdown gets a single sentinel frame and a clean close
    // instead of being parked against a draining hyper.
    if state.shutdown.is_triggered() {
        let shutdown_only = stream::once(async {
            Ok::<_, Infallible>(
                Event::default()
                    .event("kernel-shutdown")
                    .data("server-shutting-down"),
            )
        });
        return Ok(Sse::new(shutdown_only)
            .keep_alive(
                axum::response::sse::KeepAlive::new()
                    .interval(std::time::Duration::from_secs(15))
                    .text("keep-alive"),
            )
            .into_response());
    }

    let tail_n = q.tail.min(500);
    let resume_id = parse_last_event_id(&headers);
    // Replay tail (file-ring snapshot) first.
    let tail_full = state.data.stream_tail(&id, tail_n).unwrap_or_default();
    let tail: Vec<StreamEvent> = match resume_id {
        Some(last) => tail_full.into_iter().filter(|e| e.at_ms > last).collect(),
        None => tail_full,
    };
    // Subscribe (may legitimately fail with NotFound for a
    // session that never produced output — surfaced as 404 by
    // the route layer).
    let sub_result = state.data.stream_subscribe(&id);
    let shutdown = Arc::clone(&state.shutdown);
    let sse_stream = build_sse_stream(tail, sub_result, shutdown);
    Ok(Sse::new(sse_stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(std::time::Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response())
}

/// Parse the SSE `Last-Event-ID` request header into a `u64`
/// (`at_ms` value). Returns `None` when the header is missing,
/// non-ASCII, or not a u64.
///
/// Standardises handling for tests + handler. The HTTP spec
/// says `Last-Event-ID` is a header; some browsers also place
/// it in a query parameter on the EventSource URL — we only
/// honour the header here because `?tail=N` is already the
/// query-side knob and we don't want two ways to express the
/// same intent.
pub(crate) fn parse_last_event_id(headers: &HeaderMap) -> Option<u64> {
    let raw = headers.get(axum::http::header::HeaderName::from_static("last-event-id"))?;
    let s = raw.to_str().ok()?;
    s.trim().parse::<u64>().ok()
}

/// Build the SSE stream: replay-tail frames first, then a
/// `tail-complete` marker, then live frames from the
/// subscription. Lagged frames produce a `lagged` event;
/// publisher-drop produces `closed` then completes; kernel
/// shutdown produces `kernel-shutdown` then completes.
fn build_sse_stream(
    tail: Vec<StreamEvent>,
    sub_result: Result<crate::stream::StreamSubscription, ApiError>,
    shutdown: Arc<ShutdownSignal>,
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
                (sub, false, shutdown),
                |(mut sub, closed, shutdown)| async move {
                    if closed {
                        return None;
                    }
                    // Race the subscriber's next event against
                    // the shutdown signal so a long-poll
                    // handler unblocks promptly when the
                    // kernel is winding down (rather than
                    // waiting for the broadcast publisher to
                    // be dropped, which can take seconds and
                    // would otherwise hang
                    // `serve_with_shutdown`).
                    tokio::select! {
                        biased;
                        _ = shutdown.notified() => {
                            let evt = Event::default()
                                .event("kernel-shutdown")
                                .data("server-shutting-down");
                            Some((Ok(evt), (sub, true, shutdown)))
                        }
                        msg = sub.recv() => match msg {
                            Ok(Some(e)) => {
                                let payload = serde_json::to_string(&e.payload)
                                    .unwrap_or_else(|_| "null".into());
                                let evt = Event::default()
                                    .event(e.kind)
                                    .data(payload)
                                    .id(e.at_ms.to_string());
                                Some((Ok(evt), (sub, false, shutdown)))
                            }
                            Ok(None) => {
                                // Publisher dropped — emit one
                                // terminal frame, then have the
                                // next iteration return None.
                                let evt = Event::default()
                                    .event("closed")
                                    .data("publisher-dropped");
                                Some((Ok(evt), (sub, true, shutdown)))
                            }
                            Err(n) => {
                                let evt = Event::default()
                                    .event("lagged")
                                    .data(n.to_string());
                                Some((Ok(evt), (sub, false, shutdown)))
                            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn parse_last_event_id_returns_none_when_missing() {
        let h = HeaderMap::new();
        assert_eq!(parse_last_event_id(&h), None);
    }

    #[test]
    fn parse_last_event_id_returns_some_for_well_formed() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::HeaderName::from_static("last-event-id"),
            HeaderValue::from_static("12345"),
        );
        assert_eq!(parse_last_event_id(&h), Some(12345));
    }

    #[test]
    fn parse_last_event_id_returns_none_for_garbage() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::HeaderName::from_static("last-event-id"),
            HeaderValue::from_static("not-a-number"),
        );
        assert_eq!(parse_last_event_id(&h), None);
    }

    #[test]
    fn parse_last_event_id_trims_whitespace() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::HeaderName::from_static("last-event-id"),
            HeaderValue::from_static("  42  "),
        );
        assert_eq!(parse_last_event_id(&h), Some(42));
    }
}
