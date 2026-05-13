# Dashboard backend hardening contract (V2.5)

Normative companion to `v2_extended_gaps.md §4` (operator
dashboard). This document records the guarantees the
`raxis-dashboard` HTTP backend MUST hold through the live
end-to-end run and the bounds it enforces to honour them.

The contract is split into:

1. What the backend GUARANTEES — invariants every release
   must preserve.
2. What the backend EXPLICITLY DOES NOT do — boundaries the
   kernel / policy / operator UI own.
3. The numeric bounds + their rationale (single source of
   truth so the next contributor can change them
   intentionally rather than by accident).
4. SSE reconnection contract.
5. Where the implementation lives (so the next reader can
   verify the guarantees in code).

---

## 1. Guarantees

### 1.1 No panic on untrusted input

For every wire input — Authorization header, JWT body, JSON
request body, query parameters, path segments — a malformed
value MUST surface as a typed `ApiError` that maps to a
4xx JSON envelope (`error::ApiError`), never a panic and
never a 500.

The handlers in `crates/dashboard/src/routes/` use
`AxumJson<T>` / `Query<T>` extractors, which already
return 400 on parse failure. The auth surface
(`routes::auth`) defends with explicit hex / length checks
before touching crypto. The git surface
(`routes::git::validate_name` + `validate_relative_path`)
rejects path traversal, NUL bytes, backslashes, `.git`,
absolute paths, and over-long inputs at the route layer.

### 1.2 No poisoned-Arc panic

Synchronous mutexes use `parking_lot::Mutex` (no poisoning).
Where `std::sync::Mutex` remains for trait reasons
(`tokio::sync::broadcast` / `Notify` are async-only), the
holder either does not panic while holding the lock or
recovers via `lock().map_err(|p| p.into_inner())`.

### 1.3 Bounded resources per request

| Bound                       | Value             | Code constant                                              |
|-----------------------------|-------------------|------------------------------------------------------------|
| Default JSON body limit     | 16 KiB            | `BODY_LIMIT_DEFAULT` in `crates/dashboard/src/server.rs`   |
| `auth/verify` body limit    | 4 KiB             | `BODY_LIMIT_AUTH`                                          |
| `policy/toml` body limit    | 1 MiB             | `BODY_LIMIT_POLICY`                                        |
| Per-handler wall-clock      | 30 s              | `HANDLER_TIMEOUT`                                          |
| In-flight request cap       | 256               | `MAX_INFLIGHT_REQUESTS`                                    |
| Audit-chain walk per req    | 200 000 records   | `MAX_AUDIT_WALK_RECORDS` in `crates/dashboard-kernel/src/lib.rs` |
| Tree listing entries        | 5 000             | `MAX_TREE_ENTRIES`                                          |
| Inline file size            | 2 MiB             | `MAX_FILE_INLINE_BYTES`                                     |
| Worktree path length        | 4 KiB             | `MAX_REL_PATH_LEN` in `crates/dashboard/src/routes/git.rs` |
| SSE tail replay max         | 2 000 events      | `routes::sessions::stream` / `data::stream_tail`            |
| Audit page size             | 500               | `routes::audit::list` `limit.clamp(1,500)`                 |
| Notification page size      | 200               | `routes::notifications::list` `limit.clamp(1,200)`         |

The cap above is enforced by tower-http /
tower middleware applied per-route in
`crates/dashboard/src/server.rs::build_router`.

### 1.4 Repo browsing sandbox

`/api/git/worktrees/:name/{tree,file}` honour the
`policy.allowed_worktree_roots()` containment that the
diff endpoints already enforce, plus:

* The route-layer `validate_relative_path` rejects every
  malformed path before the data layer is invoked.
* The data-layer `resolve_within_root` re-applies the
  structural checks AND inspects every joined component
  with `symlink_metadata`. A symlink anywhere on the path
  causes the request to be rejected — never followed.
* `.git` is filtered both at the route layer (any
  segment) and in the directory walk (basename = `.git`).
* The leaf must be a regular file for the file endpoint;
  pipes / sockets / character devices yield `BadRequest`.
* Inline content > `MAX_FILE_INLINE_BYTES` yields
  `BadRequest` with a "use streaming download" hint.

### 1.5 Graceful shutdown

`DashboardServer::serve_with_shutdown` drains the listener
on the supplied future and additionally fires a process-wide
`ShutdownSignal`. Long-running SSE handlers `select!` on
that signal and emit a final `event: kernel-shutdown` frame
before returning, so connected clients see a clean close
instead of an abrupt TCP RST.

The kernel main loop wraps the dashboard in a
`tokio::select!` with the signal future from
`signal::ctrl_c` so SIGINT / SIGTERM both flow through.

### 1.6 SSE keep-alive + Last-Event-ID resume

* The SSE handler emits keep-alive comments (axum's
  `KeepAlive`) so an idle session stays connected through
  intermediate proxies.
* The handler reads the `Last-Event-ID` request header on
  reconnect and skips any tail event whose `at_ms` is `≤`
  the parsed cursor, so a reconnecting client does not see
  duplicate events.
* If the session id is unknown, the handler returns 404
  (not 500), even when `Last-Event-ID` is present.

### 1.7 Stream-capture init failure does NOT take the
kernel down

`KernelDashboardData::new` and `start_dashboard` return
`Result` types that surface a streams-directory init
failure. The kernel main loop logs a structured warn line
(`dashboard_streams_init_failed`) and continues without a
dashboard rather than panicking. The other kernel surfaces
(operator UDS, audit chain, AVF spawn) are unaffected.

---

## 2. Audit surface contracts (V2.5 addendum)

### 2.1 Chain status comes from the kernel walker (`INV-AUDIT-DASHBOARD-01`)

`GET /api/audit/chain-status` surfaces the kernel's own
integrity verdict via
`raxis_audit_tools::verify_chain_from(audit_dir, 0)`. The
dashboard does NOT re-implement the walk — there is exactly
one source of truth for chain integrity, and it is the
kernel binary's own audit-tools crate.

Wire shape:

```
{
  "fresh": true | false,
  "status": "ok" | "broken" | "unknown",
  "last_verified_seq": <u64>,
  "total_records": <u64>,
  "segment_count": <u64>,
  "verified_at_ms": <u64>,
  "last_error": <string | null>
}
```

* `status = "ok"` ⇒ end-to-end walker pass.
* `status = "broken"` ⇒ first walker error; `last_error`
  carries the operator-safe short reason and
  `last_verified_seq` carries the seq the break was
  observed at.
* `status = "unknown"` ⇒ verdict has not been produced
  yet (the walker has not run since boot).

Rate limit: explicit `?reverify=true` forces a fresh walk;
otherwise the data layer honours a 30 s in-process TTL on
the verdict cache so an idle dashboard cannot pin a worker
thread on chain re-walks. The cache lives in
`KernelDashboardData::chain_status_cache`.

### 2.2 Every operator action is audited (`INV-AUDIT-OPERATOR-ACTION-01`)

Every operator-initiated dashboard handler — mutating OR
privileged-read — emits a structured `Operator*` audit
event via `DashboardData::emit_operator_audit`. The event
kinds are append-only on `raxis_audit_tools::AuditEventKind`:

| Event kind                              | Surface                                              |
|-----------------------------------------|------------------------------------------------------|
| `OperatorNotificationMarkedRead`        | `PATCH /api/notifications/:id/read`                  |
| `OperatorNotificationsMarkedAllRead`    | `POST /api/notifications/mark-all-read`              |
| `OperatorWorktreeAccessed`              | `GET /api/git/worktrees/:name{,/log,/tree}`          |
| `OperatorDiffViewed`                    | `GET /api/git/worktrees/:name/diff{,/<range>}`       |
| `OperatorFileContentFetched`            | `GET /api/git/worktrees/:name/file?path=…`           |
| `OperatorAuditChainReverified`          | `GET /api/audit/chain-status?reverify=true`          |
| `OperatorNotificationViewed`            | (reserved for per-notification GET)                  |
| `OperatorHealthQueried`                 | `GET /api/health/subsystems`                         |

Every event carries:

  * `operator_fingerprint` — JWT-derived `fp-<hex>` of the caller;
  * resource correlation fields (id, path, refs, count, …);
  * `outcome` — `Accepted` / `RejectedValidation` /
    `RejectedPermission` / `InternalError`.

Discipline (enforced by `routes::*`):

  1. Validate auth + role + schema + path safety BEFORE any
     side effect, privileged read, or audit emit on the
     success path.
  2. On the success path: audit AFTER the side effect / read,
     BEFORE returning the Json response. An audit-emit
     failure on the success path surfaces as `InternalError`
     to the operator — the invariant cannot be silently
     violated.
  3. On every failure path (permission rejection,
     validation rejection, NotFound, internal-error): audit
     with the rejection class on `outcome` and the
     resource correlation fields filled in as far as
     validation got.

Cache-hit reads on `chain-status` are NOT audited — that path
is idempotent + read-only and would otherwise flood the chain
on every page mount.

### 2.3 Validation precedes side effects (`INV-DASHBOARD-VALIDATE-01`)

Every dashboard handler:

  1. Validates `Authorization: Bearer <jwt>` via the
     `AuthorizedOperator` extractor (`server::AuthorizedOperator::from_request_parts`).
  2. Re-resolves the operator's roles via
     `data.lookup_operator_roles(&claims.fingerprint)`.
  3. Gates on the required `DashboardRole` (`Read` /
     `WritePolicy` / `Admin`).
  4. Parses the request schema via typed extractors
     (`Json<T>` / `Query<T>` / `Path<T>`) — malformed input
     surfaces as a 400 from axum's parser, never a panic.
  5. Runs surface-specific validators (`validate_name`,
     `validate_relative_path`, range parser, …).
  6. Only THEN touches the data layer.

Every failure surfaces as a structured `ApiError` JSON
envelope with a stable `code` (`FAIL_DASHBOARD_*`). The
`Internal { log_only }` variant carries the operator-facing
text to `tracing::error!` only — the wire body is a generic
`"internal error"` so the dashboard cannot become a leak
channel for kernel internals.

### 2.4 Subsystem health is kernel-derived

`GET /api/health/subsystems` enumerates the kernel-side
`SUBSYSTEM_CATALOG`:

  * `kernel_main_loop`
  * `audit_writer`
  * `credential_proxies`
  * `egress_admission`
  * `session_spawn_pool`
  * `planner_registry`
  * `observability_pusher`
  * `git_worktree_pool`
  * `dashboard_sse_pump`

For each, the data layer derives a status (`ok` /
`degraded` / `failing` / `unknown`) from a live signal —
the dashboard does NOT invent statuses. The aggregate
status returned alongside the per-card list is the
worst-case wins: `failing > degraded > unknown > ok`.

Grafana deep-links are surfaced per-card when the kernel
boot detected `RAXIS_GRAFANA_BASE_URL` in the environment
(the observability worker's `cargo xtask observability up`
block sets this). When absent, the FE hides the button —
no per-tile link is invented.

---

## 2.5. Boundaries the dashboard does NOT cross

* **Authentication only — no authorization or policy
  enforcement.** The dashboard verifies an Ed25519
  signature against the operator's pubkey, mints a
  short-lived HS256 JWT, and routes role-gated handlers
  via `AuthorizedOperator::has_role`. Policy (which
  operator may rotate which epoch, which session may
  inherit which capability) lives in the kernel; the
  dashboard never re-implements it.
* **No kernel state mutation outside `PUT /api/policy/toml`.**
  Every other endpoint is a pure read. The single write
  surface delegates to `policy_manager::advance_epoch`
  via the `PolicyAdvancer` trait — the dashboard does not
  know how to commit a new epoch on its own.
* **No certificate validation beyond JWT verify.** The
  challenge-response flow trusts the operator's pubkey
  via the `PolicyBundle::operator_entry` lookup; cert
  expiry / revocation is enforced upstream by the kernel's
  `CertEnforcer`. Adding cert-chain verification in the
  dashboard would duplicate (and inevitably drift from)
  kernel-side logic.
* **No long-running compute.** Every handler is wrapped
  in a 30 s wall-clock timeout (SSE excluded by design).
  Anything that would block for longer is the kernel's
  job; the dashboard surfaces a 504 / disconnect.
* **No silent retries on the write surface.** `PUT
  /api/policy/toml` either commits cleanly or surfaces a
  structured error; the dashboard does not re-stage the
  bytes or retry across epochs.

---

## 3. SSE reconnection contract (frontend-facing)

* Endpoint: `GET /api/sessions/:id/stream`.
* Auth: standard `Authorization: Bearer <jwt>` (the SSE
  handler reuses the JWT extractor — anonymous SSE is not
  supported).
* Tail size: query param `?tail=N`, clamped to
  `[0, 2000]`. Default 100.
* Resume: clients SHOULD send `Last-Event-ID: <ms>` on
  reconnect (the EventSource API does this automatically).
  The server uses the value to filter the tail replay so
  the first frame after reconnect is the next event after
  the cursor.
* Shutdown: when the kernel triggers shutdown, the server
  emits an `event: kernel-shutdown` frame with a
  short payload string and closes the stream. Clients
  SHOULD NOT auto-reconnect on this event — the kernel is
  going away, not the connection.
* Unknown session: `404 Not Found` JSON envelope (NOT a
  hung connection), even when `Last-Event-ID` is present.

---

## 4. Where to verify each guarantee

| Guarantee                            | File                                                                | Notes                                  |
|--------------------------------------|---------------------------------------------------------------------|----------------------------------------|
| Body limits + timeout + concurrency  | `crates/dashboard/src/server.rs::build_router`                      | Per-route layers + global limit         |
| Audit walk cap                       | `crates/dashboard-kernel/src/lib.rs::list_audit`                    | `MAX_AUDIT_WALK_RECORDS` ring buffer    |
| Repo sandbox                         | `crates/dashboard-kernel/src/lib.rs::resolve_within_root`           | Symlink + traversal containment         |
| Repo route validators                | `crates/dashboard/src/routes/git.rs`                                | `validate_name` + `validate_relative_path` |
| SSE Last-Event-ID                    | `crates/dashboard/src/routes/sessions.rs`                           | `parse_last_event_id` + tail filter     |
| SSE shutdown sentinel                | `crates/dashboard/src/server.rs::ShutdownSignal`                    | `select!` in `build_sse_stream`         |
| Graceful start-failure handling      | `crates/dashboard-kernel/src/lib.rs::start_dashboard`               | Returns `Result`; kernel main matches  |
| Smoke tests                          | `crates/dashboard/tests/hardening_smoke.rs`                         | Auth + body + path + burst             |

---

## 5. Rationale (why these bounds)

* **30 s handler timeout.** Gives the audit-chain walk
  cap headroom under cold-cache conditions while still
  expiring slow-loris clients well before the load
  balancer's 60 s default.
* **256 in-flight requests.** Roughly the per-host
  connection budget for a single operator's browser tab
  (HTTP/1.1 with default 6 connections × ~50 SSE +
  polling clients), with margin for a debugging operator
  who pops open multiple tabs.
* **200 000 audit-walk cap.** A busy multi-initiative
  day produces ~50 000 audit rows; the 4× headroom keeps
  the dashboard usable until ops rotate / archive
  segments without making the cap easy to forget about.
* **2 MiB inline file cap.** Big enough for any source
  file or JSON manifest a worktree contains, small enough
  that a misclick on a database file or compiled binary
  surfaces a structured error instead of streaming a
  multi-gig blob through the operator's browser.
* **5 000 tree entries.** Bigger than any source-tree
  directory the dashboard would render (the largest
  legitimate node_modules tops out around 2 000); the
  cap exists to defend against a worktree where
  `node_modules` accidentally grew past its usual size,
  not to limit normal browsing.

When changing any of these, please update the table in
§1.3 in the same commit so the contract stays in sync
with the code.
