//! Session endpoints: list, detail, and SSE stream (§4.3 P4).
//!
//! Audit discipline: the list and detail endpoints are pure
//! read-only browsers. The `OperatorViewedSessionList` /
//! `OperatorViewedSession` emissions were retired in
//! `worker/audit-tightening` per the signal-vs-noise policy in
//! `specs/v2/dashboard-operator-action-audit-coverage.md`. The
//! SSE attach (`OperatorOpenedSessionStream`) IS still audited:
//! it's a one-shot per-attach event that hands the operator a
//! long-lived window into session-private capture data, so the
//! attach moment is forensically interesting and not a periodic
//! "view" emission.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::Json;
use futures_util::stream::{self, Stream, StreamExt};
use raxis_audit_tools::AuditEventKind;
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::{operator_outcome, SessionView};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator, ShutdownSignal};
use crate::stream::StreamEvent;

/// Query string for `GET /api/sessions`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Page size; clamped to `[1, 200]`. Default 50.
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Filter by initiative id — narrows the result to sessions
    /// that any task on this initiative is linked to.
    #[serde(default)]
    pub initiative_id: Option<String>,
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
    let rows = state
        .data
        .list_sessions(q.limit.clamp(1, 200), q.initiative_id.as_deref())?;
    Ok(Json(rows))
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
    let view = state.data.get_session(&id)?;
    Ok(Json(view))
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
/// the session's captured model output AND of any kernel audit
/// event whose `session_id` matches the request path (the
/// audit→stream bridge is owned by `raxis-dashboard-kernel`'s
/// `StreamingAuditSink` decorator; see
/// `INV-DASHBOARD-STREAM-PRODUCER-01`).
///
/// Wire shape: every data frame carries the **full envelope** as
/// the SSE `data:` field —
/// `{"at_ms": <u64>, "kind": <string>, "payload": <any>}` — and
/// emits as the default `message` event so the browser's
/// `EventSource.onmessage` handler picks every frame up without
/// per-kind `addEventListener` calls. The `id:` field still
/// carries `at_ms` so the browser's auto-reconnect path round-
/// trips through `Last-Event-ID`. The wire used to set
/// `event: <kind>` and put only the payload in `data:`; that
/// silently dropped any frame whose `kind` the FE hadn't pre-
/// registered (the audit-bridge fanout would have made that
/// list unmaintainable). `INV-DASHBOARD-STREAM-ENVELOPE-01`
/// pins the new wire so future bridge producers (gateway
/// tokens, planner tool calls) don't reintroduce the per-kind
/// listener requirement.
///
/// Special control frames keep their typed `event:` names so
/// the FE can branch on protocol semantics rather than parsing
/// JSON:
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
    if let Err(e) = require_read(&op) {
        emit_stream_audit(&*state.data, &op, &id, operator_outcome::outcome_from_api_error(&e));
        return Err(e);
    }
    // Spec contract (`dashboard-hardening.md §1.6`):
    //
    // > Unknown session: `404 Not Found` JSON envelope (NOT a hung
    // > connection), even when `Last-Event-ID` is present.
    //
    // Resolve the session id against the data layer first so a
    // typo / stale URL surfaces as a structured 404 the operator
    // UI can render, rather than as a 200 SSE response that emits
    // a single `tail-complete` frame and then keeps the connection
    // open until the browser's idle timeout. The kernel-side
    // `stream_subscribe` impl lazily creates a per-session capture
    // so it never returns NotFound on its own; the explicit
    // pre-check is the only enforcement point.
    //
    // We map every non-success (including transient store-read
    // errors) directly to the corresponding ApiError so the
    // failure surface for the SSE handler matches the rest of the
    // session API surface (`/api/sessions/:id` returns 404 / 500
    // through the same path).
    if let Err(err) = state.data.get_session(&id) {
        emit_stream_audit(&*state.data, &op, &id, operator_outcome::outcome_from_api_error(&err));
        return Err(err);
    }
    // Audit the SSE attach BEFORE we hand the long-lived
    // connection to the operator. Per
    // `INV-DASHBOARD-OPERATOR-ACTION-AUDIT-COVERAGE-01` the
    // attach itself is the audited event; the keepalive frames
    // that follow are NOT audited (they would flood the chain).
    state.data.emit_operator_audit(AuditEventKind::OperatorOpenedSessionStream {
        operator_fingerprint: op.fingerprint.clone(),
        session_id: id.clone(),
        outcome: operator_outcome::ACCEPTED.into(),
    })?;
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

fn emit_stream_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    session_id: &str,
    outcome: &'static str,
) where D: crate::data::DashboardData + ?Sized {
    let _ = data.emit_operator_audit(AuditEventKind::OperatorOpenedSessionStream {
        operator_fingerprint: op.fingerprint.clone(),
        session_id: session_id.to_owned(),
        outcome: outcome.into(),
    });
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
        // `Event::default()` (no `.event(...)` call) emits a
        // default `message`-type SSE frame so EventSource's
        // `onmessage` handler picks every event up uniformly
        // (see `INV-DASHBOARD-STREAM-ENVELOPE-01`).
        let data = envelope_json(&e);
        Ok(Event::default().data(data).id(e.at_ms.to_string()))
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
                                let data = envelope_json(&e);
                                let evt = Event::default()
                                    .data(data)
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

/// Render one [`StreamEvent`] as the wire envelope the FE
/// expects on the `data:` field — `{at_ms, kind, payload}`.
/// Serialisation failures collapse to `"null"` so a single
/// malformed payload never poisons the whole stream.
fn envelope_json(e: &StreamEvent) -> String {
    serde_json::to_string(&serde_json::json!({
        "at_ms":   e.at_ms,
        "kind":    e.kind,
        "payload": e.payload,
    }))
    .unwrap_or_else(|_| "null".into())
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
