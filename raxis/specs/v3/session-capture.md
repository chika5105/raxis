# Per-session lifecycle capture

**Status.** Implemented. Spec parity with
`raxis/crates/dashboard-kernel/src/session_capture.rs`,
`raxis/kernel/src/main.rs` (observer wiring),
`raxis/crates/dashboard/src/routes/sessions.rs` (post-mortem
route), and
`raxis/dashboard-fe/src/pages/SessionDetail.tsx`
(Post-mortem tab). Pinned by
`INV-DASHBOARD-SESSION-CAPTURE-FIXED-RING-01`,
`INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`,
`INV-DASHBOARD-SESSION-CAPTURE-NAMESPACED-PER-SESSION-01`
([`raxis/specs/invariants.md §11.19`](../invariants.md)).

**Author intent.** Operators reported that "the session data
gets deleted once the session is done" — the dashboard's
existing live SSE stream is exactly that, live: once the
session terminates the stream closes and there's no
operator-facing surface that lets them reconstruct the
session's lifecycle. The audit chain holds the durable
record, but it's keyed by sequence number and intermixed
with every other session's events; reconstructing one
session's post-mortem from the chain is tedious. The
dashboard needs a per-session post-mortem surface where
records persist past Completed / Failed / Aborted for the
lifetime of a bounded on-disk ring — exactly the pattern
`TaskLlmCapture` ships for the per-task raw-LLM surface.

## Why a fresh capture surface (and not `SessionStreamCapture`)

The pre-existing
`raxis-dashboard-kernel::SessionStreamCapture` mirrors **agent
output / audit-stream events** to the dashboard, keyed by
`session_id`. The records are dense and tuned for the live
`/api/sessions/:id/stream` SSE — a captured stream is best
viewed as it happened, while it is happening.

`SessionCapture` is a parallel surface with the same key
shape (`session_id`) but a different payload (sparse
lifecycle records — FSM transitions, KSB snapshots,
audit-event mirrors) and a different lifetime contract
(persists past session termination for post-mortem). Sharing
the surface would conflate the two views and force one to
win on record shape; keeping them parallel keeps both
operator-actionable:

* `SessionStreamCapture` — "show me the bytes / tool calls
  from this session as they happened" (dense agent output,
  live-stream tuned).
* `SessionCapture`       — "show me the lifecycle / state
  transitions / audit signal from this session, including
  after it terminated" (sparse lifecycle, post-mortem tuned).

Modelled directly on `TaskLlmCapture` so contributors who know
one know the other: same fixed-size ring, same per-id keying
(`session_id` here vs `task_id` there), same `subscribe`/`tail`
API surface, same on-disk persistence so it survives kernel
restart.

## On-disk shape

```text
<data_dir>/session-capture/<session_id>.ndjson
```

One line per record, JSON-serialised `SessionCaptureRecord`:

```rust
pub struct SessionCaptureRecord {
    pub session_id: String,
    pub kind:       String,         // "fsm_transition" | "audit_event" | "ksb_snapshot" | …
    pub ts_unix:    i64,
    pub payload:    serde_json::Value,
}
```

The `kind` field is a plain string (not a Rust enum variant)
so future kinds (e.g. `"reviewer_verdict"`,
`"escalation_pending"`) land without an FE bump — unknown
kinds collapse to a generic render path on the
`<SessionPostmortemPanel>` component.

The on-disk path uses an `.ndjson` extension (NOT `.jsonl`)
so a casual `ls -la <data_dir>/` operator can tell the two
adjacent surfaces apart at a glance:

| Surface              | Extension | Subdir                    |
|----------------------|-----------|---------------------------|
| `SessionStreamCapture` | `.jsonl` | `<data_dir>/streams/`     |
| `TaskLlmCapture`       | `.jsonl` | `<data_dir>/llm-turns/`   |
| `SessionCapture`       | `.ndjson` | `<data_dir>/session-capture/` |

## Bounds

`SessionCaptureConfig` carries two ceilings (both enforced
on every append):

| Field                          | Default     | Why                                                                    |
|--------------------------------|-------------|------------------------------------------------------------------------|
| `max_bytes_per_session`        | 512 KiB     | A long-running session's transition + audit-mirror records sum to a few KB at most; 512 KiB gives ~50× headroom while keeping a hundred terminated sessions under 50 MiB. |
| `max_records_per_session`      | 2 000       | A typical session emits ~10 transitions + 20 audit mirrors. 2 000 gives ~50× headroom against pathological retry storms. |
| `broadcast_capacity`           | 64          | Same as the other capture surfaces; smooth dashboard scroll without queueing. |

Compaction triggers when EITHER ceiling would be exceeded by
the next append. The compaction rewrite keeps the most-recent
~50 % of records — operators NEVER see silently mutated
records, only an evicted tail.

## Writer wiring

The kernel main loop installs a
[`SessionLifecycleObserver`] (a `raxis_audit_tools::AuditSink`
decorator) AFTER the `StreamingAuditSink` so every audit
emission that carries a `session_id` lands in BOTH the live
SSE stream (via `SessionStreamCapture`) AND the per-session
post-mortem ring (via `SessionCapture`). The observer is
decoupled: when `SessionCapture::new` fails at boot
(read-only data dir / EROFS / ENOSPC) the observer is not
installed and the dashboard route degrades to an empty
post-mortem list.

The observer's mirror records are appended under the
`kind = "audit_event"` shape. Future PRs can add a dedicated
`SessionFsmObserver` hooking the FSM-transition emitter
(`raxis-kernel::initiatives::task_transitions`) to append
under `kind = "fsm_transition"` directly; the wire shape is
ready today.

## Reader wiring

`raxis-dashboard-kernel::KernelDashboardData` holds an
`Option<Arc<SessionCapture>>` (mirror of
`task_llm_capture`); the
`raxis_dashboard::data::DashboardData::tail_session_capture`
impl forwards to `SessionCapture::tail` and projects the
records to the wire view
`raxis_dashboard::data::SessionCaptureView`.

`GET /api/sessions/:session_id/capture?limit=N` returns the
last `N` records (capped at 500 by the data layer, defaults
to 200 by the route layer). The route does NOT pre-fetch the
session via `get_session` — a terminated session is exactly
the case where the live `get_session` may 404 but the
post-mortem is still on disk, and we MUST NOT gate the
post-mortem on the live view.

## Frontend surface

`raxis/dashboard-fe/src/pages/SessionDetail.tsx` renders the
SessionDetail page with a two-tab strip at the bottom:

* **Live stream** — the existing `<SessionStream>` SSE.
* **Post-mortem** — the new `<SessionPostmortemPanel>` polls
  `/api/sessions/:id/capture` every 5 s and renders the
  records as a timeline (timestamp + kind badge + raw JSON
  payload).

The default tab is `stream` (operators land here while the
session is running 95 % of the time). The post-mortem tab is
the one-click affordance for the post-mortem case.

## Invariants

* `INV-DASHBOARD-SESSION-CAPTURE-FIXED-RING-01` — bounded
  ring, never silently mutated. Witnesses:
  `compaction_kicks_in_when_max_bytes_exceeded`,
  `compaction_kicks_in_when_max_records_exceeded`,
  `compaction_under_write_race`.
* `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`
  — records remain queryable post-termination.
  Witnesses: `persistence_across_new_instances`,
  `tail_after_session_state_drop`,
  `lifecycle_observer_mirrors_audit_events_into_capture`,
  `session_capture_route_returns_empty_list_with_no_capture_wired`.
* `INV-DASHBOARD-SESSION-CAPTURE-NAMESPACED-PER-SESSION-01`
  — A's records never bleed into B's tail.
  Witness: `session_ids_are_isolated_per_namespace`.

All invariant text is canonical in
[`raxis/specs/invariants.md §11.19`](../invariants.md).
