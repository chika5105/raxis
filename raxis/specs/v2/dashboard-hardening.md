# Dashboard backend hardening contract (V2.5)

This document records the guarantees the `raxis-dashboard` HTTP
backend MUST hold through the live end-to-end run and the
bounds it enforces to honour them.

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

### 1.8 Health surface freshness contract (`INV-DASHBOARD-HEALTH-NO-CACHE-01` + `INV-DASHBOARD-HEALTH-REFRESH-CADENCE-01`)

The operator-facing Health page is a *freshness oracle* — its
purpose is to tell an on-call operator whether the kernel they
are looking at right now is healthy right now. Two structural
properties make that work:

1. **Backend: `Cache-Control: no-store, max-age=0,
   must-revalidate` on every health response.** Every handler
   in `crates/dashboard/src/routes/health.rs` (`/api/health`,
   `/api/health/subsystems`, `/api/health/kernel-lifecycle`)
   sets the same conservative `Cache-Control` triple via
   the `HEALTH_CACHE_CONTROL` constant. The trio defeats:
     * browser memory/disk cache (`no-store`),
     * in-flight reuse on identical concurrent requests
       (`max-age=0`),
     * proxy + service-worker revalidation drift
       (`must-revalidate`).
   The previous header-free 200 OK was eligible for browser
   heuristic caching, which made the Health page appear
   frozen even while React Query was firing its
   `refetchInterval` — the polling hit the browser cache,
   not the kernel. Pinned by
   `INV-DASHBOARD-HEALTH-NO-CACHE-01`.

   *Witness.* `crates/dashboard/tests/hardening_smoke.rs::health_routes_emit_no_store_cache_control`
   asserts every health route returns a response whose
   `Cache-Control` header carries each of the three tokens.

2. **Frontend: 5 s polling cadence with
   `refetchIntervalInBackground: true` and a visible
   freshness pill.** The `<HealthPage>` query has
   `refetchInterval: 5_000` (subsystem cards 10 s), AND
   `refetchIntervalInBackground: true` so polling continues
   when the operator backgrounds the tab (multi-monitor
   workflows are the canonical case). The page renders a
   `data-testid="health-freshness"` pill — a tiny "Updated
   Xs ago" badge with a 1 s ticker — so the operator sees
   that polling IS happening even when consecutive Healthy
   snapshots carry identical values. Pinned by
   `INV-DASHBOARD-HEALTH-REFRESH-CADENCE-01`.

   *Witness.* `dashboard-fe/src/test/health-polling.test.tsx`
   drives the page with fake timers and asserts:
     * a `health` call fires on initial mount,
     * a second `health` call fires after advancing 5.1 s,
     * a third `health` call fires after advancing another
       5.1 s, AND
     * the displayed `policy_epoch` updates from `#1` to
       `#2` across polls (rules out structural-sharing
       same-reference re-render bugs).

   The freshness pill carries
   `data-fetching="true|false"` and `data-stale="true|false"`
   so a future end-to-end probe can assert the live signal
   without parsing visible text.

### 1.9 Worktree-loading latency budget (`INV-DASHBOARD-WORKTREE-LATENCY-BUDGET-01`)

The operator-facing worktree list/detail surfaces
(`/api/git/worktrees`, `/api/git/worktrees/:name`,
`/api/git/worktrees/:name/{log,diff,tree,file}`) MUST NOT pin a
tokio runtime worker thread on synchronous git subprocess waits.
The previous implementation had three structural problems
(operators reported "latency in loading the git worktrees"):

1. **The route handlers awaited synchronous blocking calls.**
   `git rev-parse HEAD`, `symbolic-ref --short HEAD`,
   `status --porcelain=v1`, and `rev-list --left-right --count`
   are blocking `std::process::Command` wrappers; the route
   layer called them directly inside an `async fn`. Each request
   pinned a tokio worker for the full duration of the busy-wait
   loop, which under load starved every other dashboard request
   including the per-second Health-freshness poll
   (`INV-DASHBOARD-HEALTH-REFRESH-CADENCE-01`).

2. **The `run_git` wait loop polled `Child::try_wait` every
   50 ms.** Even a probe that finished in 3 ms paid a ~50 ms
   wall-clock floor per subprocess.

3. **`get_worktree` ran the four probes serially.** The probes
   are mutually independent; serial execution multiplied the
   floor latency by 4 (`4 * 50 = 200 ms` minimum on the previous
   implementation; in practice 60–300 ms on a clean machine).

The fix is three-layered:

* **Route layer:** every blocking data-layer call in
  `crates/dashboard/src/routes/git.rs` is wrapped in
  `tokio::task::spawn_blocking` so the blocking wait happens on
  a blocking worker, NOT on the async runtime.
* **Subprocess wrapper:** `run_git` in
  `crates/dashboard-kernel/src/git.rs` polls `try_wait` with an
  exponential back-off that starts at 1 ms and caps at 5 ms.
  Fast probes (the common case for `rev-parse HEAD` on a hot
  filesystem) return in a few ms; slow probes back off to a
  5 ms ceiling so the polling itself stays cheap.
* **Per-detail-probe parallelism:**
  `git::probe_worktree_summary` runs the four independent probes
  under `std::thread::scope` so wall-clock is `max(probe_durations)`
  instead of `sum(probe_durations)`. The detail handler reads
  `head_sha`, `branch`, `status_lines`, and `ahead_behind` in
  one parallel fan-out.

Pinned by `INV-DASHBOARD-WORKTREE-LATENCY-BUDGET-01`.

*Conservative target.* `/api/git/worktrees/:name` on a clean
machine should render under 250 ms p50 / 800 ms p95 on the
realistic-scenario workload. Hot-path probes against a small
seed repo measure ~5–10 ms each on macOS with an SSD; under the
fan-out the four probes complete in ~15 ms wall-clock total.

*Witnesses.*

* `crates/dashboard-kernel/src/git.rs::tests::head_sha_completes_within_latency_budget`
  — single probe completes under a 500 ms budget on a real
  tempdir-initialised repo (skipped if `git` is not on PATH).
  The budget is generous to absorb slow CI hosts but still
  pins the regression: the pre-fix implementation routinely
  exceeded 200 ms because the busy-wait floor + cold-start
  exec dominated.
* `crates/dashboard-kernel/src/git.rs::tests::parallel_probes_finish_under_serial_budget`
  — the four-probe fan-out completes inside `(2 × single-probe
  budget) + 50 ms`, NOT inside `4 × single-probe budget`. This
  pins the parallelism guarantee: a future contributor who
  accidentally rewrites the fan-out as a serial chain trips
  the assertion.

*Structural blockers not addressed here.* `git diff` per-file
hunks (`diff_files`) still spawn one subprocess per file; this
is bounded by `MAX_PER_FILE_DIFF_BYTES` but on a 200-file
refactor the wall clock can still exceed the budget. The honest
fix is a single `git diff --raw --patch --no-renames` call
parsed into per-file blocks, but that is a larger refactor with
its own correctness surface (patch-block boundary detection)
and is intentionally scoped out of the latency-budget fix.

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

```text
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

## 2.6. Audit chain ≠ notifications inbox (`INV-NOTIF-SCOPE-01`)

The audit chain and the operator-notifications inbox are two
distinct surfaces with two distinct contracts. Conflating them
is the bug `INV-NOTIF-SCOPE-01` exists to prevent.

| Surface                | Audit chain                                                    | Notifications inbox                                     |
|------------------------|----------------------------------------------------------------|---------------------------------------------------------|
| Purpose                | Forensic-grade record of EVERY operator action + system event  | Operator-attention surface — "do I need to act?"        |
| Append discipline      | Append-only, hash-chained, never filtered                      | Filtered projection — strict subset of audit events     |
| Rendered at            | `/audit` page + `raxis_audit_tools::ChainReader`               | `/notifications` page + sidebar badge count             |
| Has `read` / mark-read | NO — reading is non-mutating                                   | YES — `PATCH /api/notifications/:id/read`               |
| Operator-action events | INCLUDED (every `Operator*` kind from §2.2)                    | EXCLUDED (operators don't notify themselves)            |
| Source of truth        | `raxis-audit-tools` chain at `<data_dir>/audit/`               | `kernel.db::notifications` table + `inbox.jsonl`        |
| Wipe semantics         | Never wiped — moving a kernel forward never destroys forensics | Wipeable in dev via `cargo xtask dev-reset notifications` |

**The taxonomy lives in code, not docs.** The mapping
`AuditEventKind → Option<NotificationPriority>` is defined by
`notification_priority` in
`crates/dashboard-kernel/src/notification_filter.rs` and is
EXHAUSTIVE — adding a new `AuditEventKind` variant to
`raxis_audit_tools::event::AuditEventKind` REQUIRES extending
both the typed match and its str-keyed companion
`notification_priority_for_kind_str`, or the workspace fails to
compile (`#[deny(unreachable_patterns)]` + the type's lack of
`#[non_exhaustive]` both pin this).

**Filter sites — defence-in-depth.** Two gates drop non-notifying
events:

1. `kernel/src/notifications/sink.rs::NotifyingAuditSink::emit`
   — primary filter. Computes
   `notification_priority(&kind)` BEFORE any inbox-side I/O
   (no SQLite write, no `inbox.jsonl` append, no SSE
   fan-out). The audit-sink upstream is unaffected — the event
   is still appended to the chain.
2. `kernel/src/notifications/mod.rs::dispatch` — string-keyed
   defence-in-depth. Recomputes
   `notification_priority_for_kind_str(&event.event_kind)` and
   short-circuits if `None`. This catches any caller that
   bypasses the typed sink (e.g. test helpers wiring a raw
   audit envelope into the dispatcher).

**Categories that MUST NOT notify** (audit-only):

  * Every `Operator*` event from §2.2 (mark-read, view-diff,
    view-file, view-worktree, chain-reverify, view-health).
  * Routine lifecycle events (`SessionVmSpawned`, `SessionCreated`,
    `TaskAdmitted`, `TaskStateChanged`,
    `IntentAccepted` / `IntentRejected`,
    `CredentialProxyStarted`,
    `DefaultProviderEgressApplied`, `KernelPushEnqueued`,
    `PushAttempted`, `NotificationDelivered`, …).
  * High-volume I/O events (`DatabaseQueryExecuted`,
    `HttpProxyRequestExecuted`, `RedisCommandExecuted`,
    `MongoCommandExecuted`, `SmtpMessageRelayed`, all
    cloud-credential serve / cache events).

**Categories that DO notify** are split across four priority
buckets:

  * **Critical** — chain integrity, isolation refusal,
    breakglass, security violation, replay rejection,
    operator-cert revocation, disk-full halt, lineage /
    initiative quarantine, …
  * **High** — escalation submitted / timed out,
    `OperatorAttentionRequired`, witness rejected, verifier
    crash, gateway crash / quarantine, push failed, plan
    rejected, initiative aborted, certificate expiring soon, …
  * **Medium** — kernel started / stopped, policy advanced,
    plan approved, escalation approved / denied, witness
    accepted, integration merge completed, push completed,
    review aggregation completed, …
  * **Low** — disk healthy after full, admission deferred at
    cap, gateway respawn, git-consistency verified.

**Operational consequence.** The notification surface is a
strict subset of the audit chain — by construction, by exhaustive
match, and by the two-layer defence-in-depth filter. Operators
look at `/notifications` to know what needs them; they look at
`/audit` for the complete record (including their own actions).

**Reset path (dev-mode).** `cargo xtask dev-reset notifications`
truncates the `notifications` SQLite table and removes
`<data_dir>/notifications/inbox.jsonl`. It NEVER touches
`<data_dir>/audit/`; the command's smoke test asserts the
audit-segment file is byte-identical before/after.

## 2.7 Credentials view (`INV-DASHBOARD-CREDENTIAL-*`)

The dashboard surfaces every credential the kernel knows about
(per-initiative + system-wide) through dedicated read-only and
admin-only reveal endpoints. The contract is **default-masked
+ explicit reveal + audit-paired + auto-hide**.

### 2.7.1 Listing surfaces

  * `GET /api/initiatives/:id/credentials` — `read` role.
    Returns metadata only (name, proxy type, mount alias,
    format hint, byte size, SHA-256 prefix, on-disk path,
    `is_revealable`, `reveal_required_role`). NEVER returns
    plaintext. Wire shape pinned by
    `crates/dashboard/src/data.rs::CredentialMetadata`; no
    `plaintext` / `bytes` field.
  * `GET /api/system/credentials` — `read` role.
    Same metadata wire shape; covers
    `<data_dir>/providers/*.toml` (Anthropic, OpenAI, etc.).
    `INV-DASHBOARD-CREDENTIAL-VIEWER-LISTS-ALL-OPERATOR-VISIBLE-SECRETS-01`
    pins this contract: every credential the kernel uses —
    including the planner / reviewer LLM provider keys — MUST
    appear here for any operator with at least the `read`
    role, so the operator can audit the surface area without
    reading the disk. Plaintext is never on this wire; the
    reveal endpoint stays admin-only and emits a paired
    audit row on every attempt regardless of outcome.

Both listings audit at emission time:
`OperatorListedCredentials` and
`OperatorListedSystemCredentials`. The audit row carries the
operator fingerprint and the row count (no plaintext).

### 2.7.2 Reveal surfaces

> **TODO(authority split):** Reveal currently uses the dashboard
> `admin` role, which is derived from broad operator authority
> (`OperatorCertInstall`). Keep this fail-closed behavior for the
> present release, but introduce a narrower operator permission such
> as `CredentialReveal` or `CredentialReadSensitive` before expanding
> multi-operator deployments. Credential reveal should not permanently
> require certificate-install authority.

  * `POST /api/initiatives/:id/credentials/:name/reveal` —
    `admin` role. Returns `CredentialReveal { name, plaintext,
    encoding, byte_size, expires_at_unix, sha256_prefix }`.
    `expires_at_unix` is set to `now + 30s`.
  * `POST /api/system/credentials/:name/reveal` — `admin`
    role. Same wire shape; `expires_at_unix` is set to
    `now + 15s` (shorter window because the system creds are
    higher-impact).

Both reveal endpoints emit BEFORE returning the body — the
Anthropic-key invariant (no plaintext without an audit row)
is crash-safe only with this ordering. Per-initiative
reveals carry `severity = "high"`; system reveals carry
`severity = "critical"`.

### 2.7.3 Rate limit

The reveal endpoints are throttled to 5 reveals per operator
per 60-second sliding window (configurable via the
`reveal_rate_limit_per_window` and
`reveal_rate_limit_window_secs` fields on
`KernelDashboardData`; defaults pinned in
`raxis-dashboard-kernel`). Throttled callers receive HTTP
429 with `Retry-After-Secs`; the rejection itself audits
under `outcome = "RejectedValidation"`.

### 2.7.4 Defence-in-depth

  * `CredentialReveal` carries a manual `Debug` impl that
    REDACTS the `plaintext` field — accidental
    `tracing::error!("{reveal:?}")` does not leak.
  * The kernel-side `read_credential_bytes` helper goes
    through `FileCredentialBackend::resolve`, which in turn
    runs `validate_path_security` (chmod-0600 + uid check).
    A tampered file fails the reveal closed with
    `ApiError::Internal`; no plaintext is returned.
  * The bytes are projected onto the wire shape inside a
    `CredentialValue::with_bytes` closure, so the SecretBox-
    wrapped backend value zeros its inner copy on drop.
  * No `Display` impl on the credential structs — the only
    sanctioned exfil path is the `Serialize` derive that
    ships the bytes inside the audited reveal response.

### 2.7.5 Frontend contract

  * Each credential renders as a card with metadata + a
    `Reveal plaintext` button. The button is **always
    clickable** for authenticated operators (the role gate
    is enforced server-side); the FE labels the button with
    a tooltip naming the required role and tags it with
    `data-reveal-eligible="false"` so dense styling shows
    the role mismatch visually.
  * Admin operators see a confirmation modal naming the
    credential and the audit class before any reveal call
    fires (defence-in-depth against accidental reveals).
  * `read`-role operators bypass the modal and round-trip
    directly so the kernel emits the paired
    `OperatorRevealedCredential { outcome: "RejectedPermission" }`
    audit row before returning 403; the FE then renders
    the structured error inline. This is the
    `INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01`
    contract — silent failure (button does nothing, no UI
    feedback, no audit row) is forbidden.
  * Credentials with `is_revealable=false` do NOT round-trip
    on click — the kernel cannot satisfy them under any role
    — and instead surface a local explanation pointing at
    the on-disk path. (No 4xx that the operator has no
    way to resolve.)
  * On reveal, the plaintext is rendered in a Monaco viewer
    (read-only, monospace, copy button) inside the card.
    A countdown timer above the plaintext block shows
    seconds until auto-hide.
  * `Hide now` button gives the operator a manual early-mask
    affordance.
  * No `localStorage` / `sessionStorage` persistence —
    closing the tab discards the cached plaintext.
  * The Shell sidebar shows the **Credentials** link to every
    authenticated operator (not just admins) so the listing
    surface is reachable from the chrome — the role gate
    on reveal is the single source of truth, not the nav
    visibility.

### 2.7.6 Anthropic special handling

`INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01` — the
Anthropic key is the highest-value secret in the system. The
reveal modal carries an explicit warning naming the
credential and the audit class; the audit emission is
`severity = "critical"`; the auto-hide is 15 seconds; the
event surfaces in the operator notifications inbox at
`Critical` priority so a second operator catches it in real
time. See [`dashboard-operator-action-audit-coverage.md §6`](dashboard-operator-action-audit-coverage.md)
for the full contract.

## 2.8 Autologin URL (`INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01`)

The kernel's test harness (`kernel/tests/common/dashboard.rs`)
mints a fully-signed JWT during boot and prints a URL of the
shape

```text
http://127.0.0.1:<port>/login#autologin=1
    &token=<jwt>
    &operator_id=<fp>
    &display_name=<name>
    &roles=<r1,r2,…>
    &expires_at=<unix>
    &next=%2F
```

to stderr, then best-effort opens it in the operator's default
browser via `spawn_url_opener`. The QA worker (and any human
operator) follows the URL to attach a fresh browser to the live
test without typing a challenge-response sequence by hand.

The React `LoginPage::parseAutologinHash` consumes the URL
fragment, mirrors the values into `localStorage`
(`raxis.dashboard.token.v1` + `raxis.dashboard.profile.v1`), then
`window.location.assign("/")` does a full-page navigation so
`RequireAuth` reads the freshly-written profile on the next
mount. The fragment is never transmitted over the wire (HTTP
layer drops the part after `#` by spec) and is scrubbed by the
page-load navigation, so the JWT never lingers in browser
history.

### 2.8.1 Invariant

**`INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01`** — *An autologin
URL minted at kernel boot MUST remain valid for the kernel's
process lifetime.*

Concretely, the JWT carried in the URL fragment MUST have an
`expires_at` at least **24 hours** in the future at mint time.
Realistic-scenario live-e2e runs routinely exceed 60 minutes
(default deadline `RAXIS_E2E_REALISTIC_DEADLINE_SECS=3600`,
overridable to multi-hour values for slow-VM iterations); the
original 1-hour TTL the spec pinned regularly expired mid-run,
leaving the QA worker stuck on the manual challenge-response
form because `parseAutologinHash` happily mirrors an expired
profile into `localStorage` (it validates shape, not freshness)
and `RequireAuth` then bounces to `/login`. The 24-hour floor
keeps the boot-time URL alive through every realistic kernel-
process lifetime in production today.

The contract is bounded by the kernel's per-boot HMAC-secret
regeneration (`JwtSigner::new` mints a fresh 32-byte secret from
`OsRng` at every kernel boot and discards it on shutdown): every
JWT — autologin or otherwise — is invalidated the instant the
kernel exits, so widening the TTL inside one boot does NOT
survive a restart.

### 2.8.2 TTL placement + override

The default TTL is pinned in three places that MUST agree
byte-for-byte:

| Surface                                                  | Default | Pinned in                                                                  |
|----------------------------------------------------------|---------|----------------------------------------------------------------------------|
| `[dashboard].jwt_ttl_secs` (genesis-emitted policy.toml) | 86 400  | `crates/genesis-tools/src/policy_toml.rs::DEFAULT_DASHBOARD_JWT_TTL_SECS`   |
| `DashboardConfig::default().jwt_ttl_secs`                | 86 400  | `crates/dashboard/src/config.rs::DEFAULT_JWT_TTL_SECS`                     |
| `JwtSigner::new(ttl_secs)` clamp (production minimum)    | 60      | `crates/dashboard/src/auth.rs::JwtSigner::new` (clamps to ≥ 60 s)          |

Operators concerned about session length on exposed hosts MAY
lower the value via the `[dashboard]` block (clamped to a 60 s
floor so the dashboard does not become unusable through a
misconfiguration) and rotate the policy epoch; the witness test
(`crates/dashboard/tests/autologin_witness.rs`) pins the default
constant and the genesis-emitted artifact agree at 86 400.

### 2.8.3 URL admittance rules

The URL fragment is admitted by `parseAutologinHash` only when
ALL of the following hold:

  * `autologin=1` is present (otherwise a stray `#token=…` from
    a bookmark / share link cannot accidentally land an operator
    on a stale credential).
  * `token`, `operator_id`, `display_name`, `roles`, `expires_at`
    are ALL present. Missing any one ⇒ `null` ⇒ no
    `localStorage` write; the operator falls through to the
    manual challenge-response form. This protects against an
    upstream URL builder that drops fields (e.g. a broken
    template rebuild).
  * `roles` is a comma-separated, non-empty list. An empty role
    set would render a logged-in but un-authorised session that
    bounces from every protected route.
  * `expires_at` parses as a positive integer. We do NOT reject
    already-expired values here — the `RequireAuth` route guard
    is the single seam that judges freshness (`isTokenLive`), so
    a future TTL extension cannot accidentally double-check
    freshness in two places that disagree.
  * `next`, if present, MUST start with `/` and MUST NOT start
    with `//` (open-redirect protection). Otherwise `next`
    defaults to `/`.

### 2.8.4 Frontend redirect contract

`parseAutologinHash` returns the parsed payload, the page mirrors
it into `localStorage`, and then `window.location.assign(next)`
performs a real (non-SPA) navigation. The SPA `navigate()` path
was deliberately rejected: `RequireAuth`, the React Query auth
subscriber, and the top-level layout all snapshot `localStorage`
once at mount, so a SPA navigation keeps the same React tree
mounted and the freshly-written token is NOT picked up until the
operator manually refreshes. The full-page reload guarantees the
new tree boots from a clean React root and reads `localStorage`
on first render, which is exactly the contract the live-e2e QA
tour pins (Run 3 + Run 4 in `dashboard-fe/QA-CHECKLIST.md`).

### 2.8.5 Witness coverage

`crates/dashboard/tests/autologin_witness.rs` pins the contract
end-to-end:

  * Asserts `DEFAULT_JWT_TTL_SECS ≥ AUTOLOGIN_MIN_TTL_SECS`
    (= 86 400) at the constant level, so a regression surfaces
    before the HTTP layer is even brought up.
  * Boots an in-memory `DashboardServer`, runs the real
    `GET /api/auth/challenge` → `POST /api/auth/verify` HTTP
    path with a fresh keypair, and asserts the minted JWT's
    `expires_at - now() ≥ AUTOLOGIN_MIN_TTL_SECS`.
  * Hits `GET /api/initiatives` with the minted JWT and asserts
    `200 OK` — "mint" is necessary but not sufficient; the
    contract is "the operator can actually drive the dashboard
    for the next 24 h" (limited by kernel uptime).

`crates/genesis-tools/src/policy_toml.rs::dashboard_section_is_emitted_with_enabled_true_and_loopback_defaults`
asserts the on-disk policy.toml carries `jwt_ttl_secs = 86400`,
so the genesis emitter and the constant cannot drift.

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
| Autologin TTL invariant              | `crates/dashboard/tests/autologin_witness.rs`                       | `INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01` |

---

## 5. Failure-visibility rendering contract (`INV-DASHBOARD-FAILURE-VISIBILITY-01`)

Operator-experience contract: every failure or rejection event
surfaced by the dashboard MUST display its reason to the
operator. A bare red badge with no reason text is a contract
violation — the operator never has to grep `kernel.stderr.log`
or open devtools to figure out why something failed.

### 5.1 Failure-bearing entity surfaces

The following entity view shapes carry an optional
`failure: FailureInfo | null` field. The kernel-side projection
walks the audit chain on construction and attaches the most
recent failure event corresponding to the entity's terminal
state (V3 step — V2.5 ships the wire shape with `failure: None`
for every entity, plus the FE empty-state affordance below):

| View                            | Terminal-failure states                                                            | Source events                                                                                                          |
|---------------------------------|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `SessionView.failure`           | `Failed` / `VmFailedFinal` / `Errored`                                             | `SessionVmFailedFinal` / `SessionVmExited` / `WorktreeProvisionFailed`                                                  |
| `TaskView.failure`              | `Failed` / `Aborted` / `Cancelled` / `BlockedRecoveryPending`                      | `TaskStateChanged` (terminal) / `TaskBlockedForRecovery` / `WitnessRejected` / `ReviewerRejected`                       |
| `InitiativeView.failure`        | `Failed` / `Aborted`                                                               | `InitiativeAborted` / aggregated `TaskFailed`                                                                            |
| `SubsystemHealthCard.last_error`| `failing` / `degraded`                                                             | Most recent reporter `summary` when the reporter is unhealthy                                                            |

`TaskView` additionally carries `blocked_downstream: Vec<String>`
populated for terminal-failure tasks so the FE can render the
cascade in the DAG side panel without re-walking the graph.

### 5.2 `FailureInfo` wire shape

```rust
pub struct FailureInfo {
    pub kind: String,                       // PascalCase audit kind
    pub message: String,                    // free-form, NOT truncated
    pub fields: Vec<FailureField>,          // (label, value) rows
    pub artifacts: Vec<FailureArtifact>,    // (label, href) links
    pub event_id: Option<String>,           // audit-chain anchor
    pub seq: Option<u64>,                   // audit-chain anchor
    pub observed_at: u64,                   // unix-seconds
}
```

All optional fields use
`#[serde(default, skip_serializing_if = …)]` so additions are
append-only — pre-existing FE bundles and CLI tooling that mirror
the wire shape keep parsing the response without panicking on the
new key. `Option<FailureInfo>` is dropped entirely from the JSON
when `None`, so a healthy entity ships the same bytes it did
before V2.5.

### 5.3 Audit-event surfaces

Every failure-bearing audit event surfaced through the
Notifications / Audit / SSE wire carries its reason directly in
the payload (`reason`, `final_reason`, `block_reason`, `detail`,
`exit_code`, `failure_class`, …). The frontend extracts a
`FailureInfo`-shaped view from the payload via
`dashboard-fe/src/lib/failure-extract.ts::failureFromAuditEvent`
so the same rendering surface (`<FailureReasonPanel>` /
`<FailurePill>`) renders consistently across pages.

Failure-bearing audit kinds (cross-referenced against
`crates/audit/src/event.rs`):

  * **Lifecycle.** `SessionVmFailedFinal`, `SessionVmExited`,
    `TaskBlockedForRecovery`, `InitiativeAborted`,
    `WorktreeProvisionFailed`.
  * **Review.** `WitnessRejected`, `ReviewerRejected`,
    `ReviewerDisagreement`, `VerifierProcessFailed`.
  * **Egress / proxy.** `TransparentProxyDenied`,
    `SessionEgressDenied`, `SessionEgressStallDetected`,
    `CredentialProxyUpstreamFailed`,
    `CredentialProxyConnectionFailed`.
  * **Approval / escalation.** `EscalationDenied`,
    `OperatorApprovalDenied`.
  * **Policy.** `PolicyAdvanceRejected`, `PolicyAdvanceFailed`,
    `ReplayRejected`.
  * **Git.** `PushFailed`, `MergeFastForwardFailed`.
  * **Runtime.** `GatewayCrashed`, `GatewayQuarantined`,
    `GatewaySignalFailed`, `NotificationDeliveryFailed`.
  * **Intent.** `IntentRejected`.
  * **Operator-action rejections.** Every `Operator*` event whose
    `outcome != Accepted`.

### 5.4 Frontend rendering contract

`<FailureReasonPanel>` (full panel, used on detail pages + DAG
side panel) and `<FailurePill>` (one-line companion, used on list
rows + audit ribbons) live in
`dashboard-fe/src/components/FailureReasonPanel.tsx`. Every page
that renders a failure-bearing entity MUST compose one of these
rather than render a bespoke red badge. Specifically:

  * **List surfaces.** `<FailurePill failed reason={…}>` stacked
    beneath the `<StateBadge>` in the state column. Tooltip
    carries the full reason.
  * **Detail surfaces.** `<FailureReasonPanel reason={…}>` block
    immediately beneath the page header. Always renders on a
    terminal-failure entity, even when `reason === null` — the
    empty-state affordance (§5.5) covers the gap.
  * **DAG side panel.** `<FailureReasonPanel reason={…} collapsible>`
    inside the focused-task aside, plus a "Blocks N downstream
    tasks" tally driven by `TaskView.blocked_downstream`.
  * **Audit chain.** Failure-bearing rows ship a compact pill in
    the row header and a full panel above the JSON dump when
    expanded.
  * **Notifications.** Failure-bearing rows render a compact pill
    beneath the body line; mutation failures (Mark-read,
    Mark-all-read) render an inline `<ActionFailureBanner>` at
    the top of the page.
  * **Audit chain banner.** `Re-verify chain` failures render an
    inline `<ReverifyFailureRow>` directly beneath the banner so
    the audit-tools error message lands where the operator clicked.
  * **Health.** `failing` / `degraded` subsystem cards render
    `last_error` as a red inline-error band beneath the status
    pill.

### 5.5 Empty-reason rule

When a failure-bearing entity ships `failure: null` /
`last_error: null`, the dashboard MUST render
`"⚠ KERNEL BUG: No reason supplied — kernel bug
(INV-FAILURE-REASON-MANDATORY-01 violated)"` as a **red alert
band** (`role="alert"`, `bg-bad/10`, `border-bad/60`) — NOT
muted info chrome and NOT the status colour alone. The string
is operator-actionable: the originating kernel reporter MUST
always supply a reason (per `INV-FAILURE-REASON-MANDATORY-01`
in `specs/invariants.md`), and a missing reason is a kernel
bug to file rather than expected behaviour.

`<FailureReasonPanel>` exposes three `whenMissing` modes:

  * `missing-reason-bug` (default for Failed entities) — emit the
    kernel-bug affordance per the contract above. The DOM
    carries `data-failure-empty="missing-reason-bug"` and
    `data-invariant="INV-FAILURE-REASON-MANDATORY-01"` so E2E
    tooling and operator dashboards can deep-link straight to
    the violating entity. Once the kernel honours the invariant
    end-to-end this branch should NEVER fire in production —
    its visibility is the regression alarm.
  * `absent` — return `null`; used by parents that aren't sure
    whether the entity is failed yet.
  * `no-error-reported` — render `"No error reported"`; used on
    surfaces where a missing reason is plausibly normal (e.g.
    in-flight `Running` sessions).

#### 5.5.1 Kernel-side counterpart — `INV-FAILURE-REASON-MANDATORY-01`

The empty-reason rule is the dashboard half of a paired
invariant. The kernel half is `INV-FAILURE-REASON-MANDATORY-01`
(`specs/invariants.md`): every transition into a
terminal-failure or blocked state
(`TaskState::Failed | Aborted | BlockedRecoveryPending`,
`InitiativeState::Failed | Aborted | Blocked`,
`SessionRevoked`) MUST carry a non-empty, human-readable
reason. The kernel enforces this through:

  * The `FailureReason` newtype in `crates/types/src/error.rs`
    whose constructor rejects empty / whitespace-only input —
    making it mechanically impossible to construct a Failed
    transition without a reason.
  * `debug_assert!` gates at `transition_task_in_tx` and
    sibling FSM transition functions for defense-in-depth in
    debug / test builds.
  * Audit-emit-site `debug_assert!` for terminal-failure event
    kinds (`TaskFailedOnWorkerPrematureExit`,
    `InitiativeAborted`, `SessionRevoked`, …) so the audit
    chain never carries an empty `failure_reason` /
    `revoke_reason` field.

The dashboard's `missing-reason-bug` rendering is therefore a
**belt-and-braces visibility net** for an invariant the kernel
already enforces at the type level. If operators ever see the
red kernel-bug band in production, that is a structural
regression that bypassed both compile-time enforcement and
the runtime debug_assert — file an immediate kernel bug citing
`INV-FAILURE-REASON-MANDATORY-01` and the violating entity's
`event_id` from the audit chain.

**Clean-exit-no-terminal-intent sub-case (P2 layer).** The kernel's
Mode-B post-exit synthesis path
(`kernel/src/session_spawn_orchestrator.rs::spawn_planner_dispatcher`)
first received per-session activity-tracker breadcrumbs (the
P2 patch landed in `4f661a5`) so even a clean `Ok(_)` return
from `drive_planner_stream` carried `(last_intent_kind, seq,
outcome, ts)` into the synthesis arm. The `<FailureReasonPanel>`
now surfaces a row that lets the operator disambiguate a
runaway-loop exit (planner ran for N turns then hit
`MaxTurnsExceeded`) from a boot-failure exit (planner died
before its first model turn) at a glance, with no kernel-log
spelunking required.

#### 5.5.2 Concrete-reason mandate — `INV-FAILURE-REASON-CONCRETE-01`

`INV-FAILURE-REASON-MANDATORY-01` requires the reason be
*non-empty*; `INV-FAILURE-REASON-CONCRETE-01` adds the
*concreteness* gate: the reason MUST name the SPECIFIC cause
and (where applicable) the operator-actionable remedy.
Multi-option umbrella strings of the form
`<Cause1> / <Cause2> / <Cause3>` (the canonical
regression baseline) and opaque placeholders like
`(no reason)` / `see logs` / `unknown reason` / `unspecified
reason` / `something went wrong` are violations — see
`specs/invariants.md` for the verbatim forbidden-phrase set.

**Pre-fix dashboard symptom.** The `<FailureReasonPanel>`
rendered the umbrella verbatim — `"executor VM exited
without submitting a terminal intent (MaxTurnsExceeded /
TokensExceeded / DispatchIdle / process death). Kernel
synthesised Running → Failed …"`. The P2 kernel-side patch (`4f661a5`)
replaced this with the activity-tracker template but STILL
hedged the cause as `(likely MaxTurnsExceeded / TokensExceeded
/ DispatchIdle)` — a structurally identical multi-option
umbrella that `INV-FAILURE-REASON-CONCRETE-01` forbids. The
panel's kernel-bug empty-state fired ONLY on `null` / `""`,
so either umbrella slipped through the visibility net even
though it was operationally indistinguishable from a missing
reason.

**Post-fix steady-state (P3 layer).** The kernel's Mode-B
premature-exit synthesiser in `session_spawn_orchestrator`
is now driven by a structured `PlannerExitOutcome` enum the
planner ships over `IpcMessage::PlannerExitNotice`
immediately before EOF. The formatter produces strings like
`"executor planner reached max_turns budget (60 used / 60
limit) without submitting a terminal intent — raise
RAXIS_PLANNER_MAX_TURNS …"`. The dashboard surfaces THAT
verbatim — no special FE handling is required because the
kernel-side fix makes concreteness structural. The activity-
tracker rendering helpers (`render_clean_exit_with_activity`
/ `render_clean_exit_without_activity`) were also retemplated
to remove the `(likely MaxTurnsExceeded / TokensExceeded /
DispatchIdle)` hedge — they now NAME the missing
`PlannerExitNotice` and point at the substrate's
`SessionVmExited` audit event for forensic correlation. The
kernel-bug badge `data-failure-empty="missing-reason-bug"`
fires only on the actual `null` / `""` empty-state, NOT on
the post-fix concrete strings.

**FE follow-up: the `(no reason)` fallback.** The previous
`failure-extract.ts` mapping for `WitnessRejected` /
`ReviewerRejected` / `EscalationDenied` / `PolicyAdvanceRejected`
/ `PolicyAdvanceFailed` / `ReplayRejected` / `GatewayQuarantined`
/ `NotificationDeliveryFailed` collapsed missing payload
`reason` / `detail` to the string `"(no reason)"` — a hedge
placeholder that bypassed the panel's `(no message)` empty-state
and rendered as a non-empty-but-empty-of-information message.
Post-fix the mapping leaves `message` empty in that case so the
panel's empty-state badge fires correctly, surfacing the gap
as a kernel bug per `INV-FAILURE-REASON-MANDATORY-01`.

### 5.6 Action-failure rule

When a dashboard mutation rejects (`Approve` → `RejectedPermission`,
`Mark all read` → `InternalError`, `Re-verify chain` →
`FAIL_DASHBOARD_AUDIT_*`, …), the dashboard MUST render the
`ApiError.code` + `ApiError.detail` inline at the surface that
initiated the action. The error is dismissible (via
`mutation.reset()` / setter callback) so the operator
acknowledges it explicitly. A toast-only treatment is
non-conformant — toasts hide the reason after a few seconds and
the operator has no way to recall what the rejection text said.

### 5.7 Out of scope: host-hygiene (developer / CI concern)

Parent-side worktree disk hygiene (`INV-HOST-HYGIENE-01`) is
**deliberately not** a dashboard surface. The reference
implementation (`cargo xtask hygiene` + `cargo xtask
hygiene-check`) is a workspace-only developer tool with no
analogue in a production install (a `brew install raxis`
operator has no cargo workspace and no parent-side
aegis-worktrees to sweep), and the live-e2e harness preflight
surfaces detected pressure through a structured stderr
envelope (`OPERATOR_ATTENTION_REQUIRED HostHygieneDiskPressure
{json}`) consumed by the harness / terminal user / CI log
scraper, not by this dashboard.

The dashboard contract for `OperatorAttentionRequired`
remains unchanged: every kernel-emitted audit event in the
existing set (`DiskFull`, `FdLimitInsufficient`,
`InitiativeStarvation`, `ArchiverLagging`, …) renders through
the notifications inbox and the failure-reason panels per
§5.1–§5.6. The dashboard MUST NOT consume an
`attention_kind = "HostHygieneDiskPressure"` arm — the kernel
does not emit one (audit chain stays kernel-scoped for
runtime invariants only), and a future deployment that wants
to forward this developer-host signal somewhere structured
should pipe stderr rather than re-route through the
kernel-runtime dashboard surface.

Cross-reference: `INV-HOST-HYGIENE-01`
(`specs/invariants.md`),
`guides/operator/18-host-hygiene.md`.

## 5.8 Plan visibility — `plan-view` (`INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`)

The dashboard surfaces every initiative's **original
submitted** `plan.toml` byte-for-byte through a dedicated
endpoint so operators can review, audit, copy, and
forensically reproduce the exact bytes the planner
operator sealed at admission.

### 5.8.1 Endpoint

`GET /api/initiatives/:initiative_id/plan` — read-role JWT
required (same auth gate as `GET /api/initiatives/:id`).

**Wire shape.**

```json
{
  "initiative_id":        "init-019e228a-…",
  "plan_sha256":          "ab12…",         // hex; from initiatives.plan_artifact_sha256
  "bundle_sha256":        "cd34…",         // hex; null for V1 plans (no bundle)
  "submitted_toml":       "[orchestrator]\n…",
  "submitted_toml_bytes": 1234,            // server-computed byte length
  "submitted_at_unix":    1_700_000_690,
  "submitted_by":         "deadbeefdeadbeef", // operator fingerprint hex
  "approval_status":      "approved" | "pending" | "rejected",
  "approved_at_unix":     1_700_000_777    // null when not approved
}
```

`approval_status` is derived from the initiative FSM row:

| `initiatives.state`                                | `approved_at` | `approval_status` |
|----------------------------------------------------|---------------|-------------------|
| `Draft`                                            | any           | `pending`         |
| `Executing` / `Completed` / `Failed` / `Aborted`   | `Some(_)`     | `approved`        |
| `Executing` / `Completed` / `Failed` / `Aborted`   | `None`        | `rejected`        |

The `rejected` row is operationally rare — it only appears
when an FSM transition advanced past `Draft` without the
admission path setting `approved_at` (a kernel bug). The
dashboard surfaces it as a distinct copy so the operator
can correlate against the originating audit row.

### 5.8.2 Status code mapping

| Status | Code                          | When                                                             |
|--------|-------------------------------|------------------------------------------------------------------|
| 200    | —                             | Plan present (approved or pending).                              |
| 401    | `FAIL_DASHBOARD_UNAUTHORIZED` | Missing / invalid JWT (shared with every endpoint).              |
| 403    | `FAIL_DASHBOARD_FORBIDDEN`    | Operator lacks the `read` role.                                  |
| 404    | `FAIL_DASHBOARD_NOT_FOUND`    | Initiative id does not exist.                                    |
| 410    | `FAIL_DASHBOARD_GONE`         | Initiative exists but its plan blob was archived / purged.       |
| 500    | `FAIL_DASHBOARD_INTERNAL`     | DB read failure or non-UTF-8 plan bytes (the latter is a kernel bug — every production producer pins UTF-8 at write time). |

**404 vs 410 is load-bearing.** A 404 means "wrong link"
(operator typo / stale URL); the frontend renders
"Initiative not found" with a back-link to the list. A 410
means "plan gone" (forensic archival has run, or the
initiative pre-dates V2 storage paths and its blob was
swept); the frontend renders "Plan archived or purged"
inline with the rest of the panel still chrome-loaded so
the operator sees what the initiative was even if the
bytes are no longer accessible. Folding both into 5xx —
or both into 404 — collapses two operationally distinct
paths.

### 5.8.3 Cache-Control

| Approval status   | Header                          | Rationale                                                 |
|-------------------|---------------------------------|-----------------------------------------------------------|
| `approved`        | `Cache-Control: private, max-age=60` | Approved plans are immutable post-approval ([`plan-bundle-sealing.md §8.2`](plan-bundle-sealing.md)); 60 s of client-side caching dramatically reduces dashboard ↔ kernel round-trips when an operator clicks back-and-forth between tabs. `private` (not `public`) means no proxy-side caching — operator JWT context is per-request and operator-bound; never share the response across operators. |
| `pending` / `rejected` | `Cache-Control: private, no-store` | Draft bytes are still mutable (the operator may re-seal); caching them across refreshes leaks stale plans to the frontend. |

The frontend's `useInitiativePlan` TanStack Query hook
holds a 60-second `staleTime` so the React cache and the
HTTP cache stay aligned (a plan re-fetch never out-paces
the server-side cache).

### 5.8.4 Byte-for-byte fidelity

The kernel-data layer
(`raxis-dashboard-kernel::KernelDashboardData::get_initiative_plan`)
walks the V1 → V2.1 fallback chain through
`raxis_store::views::plan_fields::submitted_toml_for_initiative`:

1. **V1 path.** `signed_plan_artifacts.plan_bytes` keyed
   by `initiative_id`.
2. **V2.1 path.** `initiatives.plan_bundle_sha256` →
   `plan_bundle_artifacts` row whose
   `artifact_name = 'plan.toml'`.

Neither path runs the bytes through a TOML parser. The
endpoint MUST surface the literal bytes (preserved
comments, blank lines, trailing whitespace, byte-order
markers). A re-encoded view actively hides operator
intent — operators routinely embed `# why this lane`
annotations in TOML to disambiguate later operator review,
and the plan signature verifies against the literal sealed
bytes (a TOML round-trip would invalidate the signature).
The byte-for-byte requirement is the load-bearing claim of
`INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`.

### 5.8.5 Frontend contract

* **Component.** `dashboard-fe/src/components/InitiativePlanView.tsx`.
  Renders the TOML in a read-only Monaco editor with
  syntax highlighting (Monaco's `ini` mode — closest
  built-in language to TOML), theme-aware (`vs` / `vs-dark`
  follows the dashboard's light / dark-mode toggle).
* **Page integration.** Collapsible "Plan TOML" panel on
  `dashboard-fe/src/pages/InitiativeDetail.tsx`. Open /
  closed state is mirrored to the URL (`?plan=open`) so
  operators can share a deep-link to the panel. The Monaco
  editor mounts only when the panel is open (avoids
  paying the editor's startup cost on initiative pages
  where the operator does not click in).
* **Header surface.** Submission metadata: operator
  fingerprint, submitted-at (Unix → operator-local
  timestamp), approval badge with colour mapped to
  `approval_status`, plan / bundle SHA-256 chips
  (truncated, hover for full hex).
* **Actions.** "Copy" (clipboard API + transient "Copied!"
  status) and "Download" (Blob → `<initiative_id>.plan.toml`).
* **Loading.** Skeleton spinner while the React Query is
  pending (`q.isPending`).
* **Error states.** 404 ⇒ inline "Initiative not found"
  with a back-link; 410 ⇒ inline "Plan archived or purged
  (the initiative still exists; only the original sealed
  TOML has been archived)"; other errors ⇒ shared
  `<ErrorBox>` component with `code` + `detail`.
* **Scroll discipline.** `max-height: 60vh`, vertical
  scroll only — no horizontal overflow. Operator can resize
  the panel by dragging Monaco's bottom edge if their plan
  is large.
* **WCAG-AA contrast.** Monaco's `vs-dark` theme ships at
  AAA contrast for the default token colours; the panel
  chrome (header, badges, buttons) inherits the dashboard's
  shared design tokens which the dashboard's QA pass
  already checks.

### 5.8.6 Witness coverage

| Surface                                           | Test                                                                                  |
|---------------------------------------------------|---------------------------------------------------------------------------------------|
| Backend HTTP path (V1 + V2.1 + 404 + 410 + auth)  | `raxis/kernel/tests/dashboard_initiative_plan_endpoint.rs` (4 cases)                  |
| Store helper (V1 lookup + 404 fallback)           | `raxis/crates/store/src/views/plan_fields.rs::tests::submitted_toml_returns_v1_*`     |
| Dashboard data layer (in-memory fixture)          | `raxis/crates/dashboard/src/data.rs::tests::in_memory_get_initiative_plan_*`          |
| `ApiError::Gone` envelope mapping                 | `raxis/crates/dashboard/src/error.rs::tests::gone_yields_410_with_distinct_code`      |
| Frontend component (loading / loaded / 404 / 410 / copy / download) | `raxis/dashboard-fe/src/test/initiative-plan-view.test.tsx` (6 cases) |

### 5.8.7 Cross-reference with the live-e2e plan fixtures

The dashboard reads the original sealed TOML from the
kernel store (V1 or V2.1 path); the live-e2e harness
materialises `plan_primary.toml` / `plan_sibling.toml` as
repo-checked-in files. Both surfaces SHOULD agree
byte-for-byte for the most-recent green iter — if they
diverge, the kernel's admission path has been changing the
bytes between submission and seal (which would break plan
signature verification). The dashboard panel is the
operator-facing witness; the checked-in files are the
developer-facing fixture.

## 5.9 JWT-secret persistence (`INV-DASHBOARD-JWT-SECRET-PERSISTENT-01`)

Pre-V2.5 the dashboard's HS256 signing secret was minted via
`OsRng` on every kernel boot and discarded on shutdown. That
contract was operator-friendly while the only way the kernel
restarted was an operator-initiated stop+start (rare, expected
session loss). After [`self-healing-supervisor.md`](self-healing-supervisor.md) shipped, the
kernel can autonomously restart on deadlock detection, panic,
or OOM — at which point operators in the middle of reviewing
an initiative would silently lose their JWT, get bounced to
`/login`, and lose any unsaved React state (a partially-filled
escalation response, an editor cursor mid-policy, etc.) with
no signal that "this was an automatic restart, not your
fault".

V2.5 fixes this by persisting the HS256 secret to
`<data_dir>/auth/dashboard_jwt.secret` (`0600`, auth dir
`0700`). The on-disk format also persists a `secret_generation`
counter that is bound into every JWT claim's `gen` field.
Operators retain explicit "kick everyone out" control via the
`raxis dashboard rotate-jwt-secret` CLI command, which bumps
the on-disk generation and mints fresh bytes — every
pre-rotation token immediately fails verification (the `gen`
claim no longer matches the live signer).

The full design — including the file format, the boot path,
the rotation contract, and the operator UX — is normative in
`specs/v2/self-healing-supervisor.md §10`. The witness tests
live in `crates/dashboard/src/jwt_secret.rs::tests` and
`crates/dashboard/src/auth.rs::tests`. Cross-reference
`INV-SUPERVISOR-OPERATOR-CONTINUITY-01` (the operator-facing
property) and `INV-DASHBOARD-JWT-SECRET-PERSISTENT-01` (the
on-disk contract that enables it).

## 5.10 Kernel-lifecycle banner (`INV-DASHBOARD-KERNEL-LIFECYCLE-01`)

The dashboard ships a global `<KernelLifecycleBanner>` (mounted
in `Shell.tsx`) that polls `GET /api/health/kernel-lifecycle`
every 5 s and renders the supervisor's view of the kernel
process: `Healthy` (no banner), `Restarting` (amber, with
attempt N/M and reason), or `Halted` (rose, with sub-state and
operator-action hint). The banner is the operator's primary
window into supervisor activity — it is what tells them
"this is an automatic restart, not a network glitch" before
their JWT seamlessly verifies under the post-restart kernel
(per §5.9 above).

**Banner-source contract.** The verdict in the banner comes
from a single source: the supervisor's atomic sentinel file
(`<data_dir>/kernel_lifecycle_status.json`) read by
`crates/dashboard/src/routes/health.rs::read_kernel_lifecycle_response`.
The dashboard NEVER infers a lifecycle state from any other
signal (e.g. counting recent `KernelStarted` audit rows or
querying the supervisor over IPC). The handler returns a
synthetic `Healthy { fresh: true }` envelope when the sentinel
is missing or `data_dir` is unconfigured — this is the
intentional default for operators who never opted into
`RAXIS_SUPERVISOR_AUTO_RESTART=1`, so they see no supervisor
chrome on every page.

**Staleness handling.** When the sentinel's `updated_at_unix_secs`
is older than `2 × window_secs` AND its recorded supervisor PID
is no longer alive (probed via `nix::sys::signal::kill(pid, None)`
with `Errno::ESRCH` ⇒ gone), the handler returns
`Halted { sub_state: "SupervisorGone", fresh: false }` and the
banner renders the same rose treatment as a CircuitOpen halt.
This is the contract for "the supervisor process itself died
mid-supervision" — the operator should still see actionable
chrome rather than a stale Healthy badge.

**Cross-reference: orchestrator respawn-ceiling.** A separate
sweep adds an `OrchestratorRespawnCeilingExceeded` audit event
to the kernel for the *logical* respawn-loop case (kernel alive,
audit chain growing, but the orchestrator is stuck issuing
rejected RetrySubTask intents in a tight loop). When that event
lands, the supervisor sentinel will gain a new `Halted`
sub-state (`OrchestratorRespawnCeiling`) and this banner MUST
surface it under the same rose treatment so operators see both
flavours of recovery in one panel — supervisor-side process
recovery (this spec) and kernel-side logical recovery
(orchestrator respawn ceiling). The banner switch is a one-liner
in `KernelLifecycleBanner::headlineFor`; the cross-spec
coordination ticket lives in
[`self-healing-supervisor.md §10.7`](self-healing-supervisor.md).

Cross-reference: `INV-DASHBOARD-KERNEL-LIFECYCLE-01`
(`specs/invariants.md`),
`specs/v2/self-healing-supervisor.md §5.4`,
`specs/v2/self-healing-supervisor.md §10.7`,
`crates/dashboard/src/routes/health.rs`,
`dashboard-fe/src/components/KernelLifecycleBanner.tsx`.

## 5.11 Task-state rendering completeness (`INV-DASHBOARD-TASK-STATE-COMPLETENESS-01`)

The dashboard MUST render every variant of the kernel
`TaskState` FSM with a **distinct visual representation**. The
canonical 8-tuple — pinned by the `tasks.state` SQL CHECK
constraint in `kernel-store.md §2.5.1 Table 5` and by
`raxis_types::fsm::TaskState::ALL` — is:

| TaskState                | Dashboard tone | Visual hint                                |
|--------------------------|----------------|--------------------------------------------|
| `Admitted`               | `muted`        | grey badge — queued, awaiting first intent |
| `Running`                | `info`         | blue badge w/ pulse — actively executing   |
| `GatesPending`           | `warn`         | amber — paused awaiting gate verdict       |
| `Completed`              | `ok`           | emerald — terminal success                 |
| `Failed`                 | `bad`          | rose — terminal failure                    |
| `Aborted`                | `block`        | violet — operator/initiative abort         |
| `Cancelled`              | `block`        | violet — bulk-cancelled by `abort_initiative` |
| `BlockedRecoveryPending` | `warn`         | amber — kernel-crash recovery in flight    |

The exhaustiveness contract is enforced on BOTH sides:

* **FE side** (`dashboard-fe/src/lib/state-color.ts`): the
  module exports `KERNEL_TASK_STATES`, `KERNEL_INITIATIVE_STATES`,
  and `KERNEL_SESSION_STATES` as the canonical pinned tuples,
  plus a `hasExplicitStateEntry(state)` helper that returns
  `true` iff the state has a direct `MAP[state]` entry (the
  helper deliberately does NOT consult the case-normalised
  fallback path or the "unknown → muted" trap door). The
  exhaustiveness witness lives at
  `dashboard-fe/src/test/state-color.test.ts` and walks
  `KERNEL_TASK_STATES` asserting `hasExplicitStateEntry` for
  each. A companion case specifically pins
  `stateTone("Running") !== stateTone("Admitted")` so a
  tone-collision regression (the invisibility shape)
  trips at TSC time rather than during a live-e2e run.

* **Kernel side** (`crates/dashboard-kernel/src/lib.rs`): the
  test
  `inv_dashboard_task_state_completeness_projection_round_trips_every_variant`
  synthesises a `TaskRow` for every variant of
  `TaskState::ALL`, pushes it through the production
  `task_row_to_view` projection, and asserts
  `TaskView.state == TaskState::as_sql_str()` for each. The
  same test pins `TaskState::ALL.len() == 8` as a
  cross-language drift trip-wire — a new variant in the Rust
  enum MUST be matched by a new entry in `KERNEL_TASK_STATES`
  on the TS side or both witnesses fail in the same commit.

**Why the cross-language pin.** saw the IntegrationMerge
coordinator task sit in `Running` for the full lifetime of an
initiative while the operator dashboard surface only ever
displayed `Admitted` and `Completed` rows. The root cause was
two-tiered: the executor sub-task FSM transitions
`Admitted → Running → Completed` move so quickly that a 4 s
polling cadence routinely misses the `Running` window, AND the
coordinator's `task_id == initiative_id` rendering made its
long-running `Running` row invisible behind an opaque UUID
title (see §5.12 below). The completeness invariant is the
structural defence: even when a variant becomes the ONLY
visible state for a non-trivial window (the coordinator's
multi-minute merge phase), the badge MUST be visually distinct
from every other state so operators can read the current
trajectory at a glance.

Cross-reference: `INV-DASHBOARD-TASK-STATE-COMPLETENESS-01`
(`specs/invariants.md`),
`raxis_types::fsm::TaskState` (kernel-store.md §2.5.1 Table 5),
`crates/dashboard-kernel/src/lib.rs::task_row_to_view`,
`dashboard-fe/src/lib/state-color.ts::MAP`.

## 5.11.1 FSM state visibility contract (`INV-DASHBOARD-FSM-STATE-VISIBILITY-01`)

Completeness (every variant has an entry) is necessary but not
sufficient — the paper-cut was that every variant DID
have an entry, but `Admitted` and `Running` rendered with
near-identical visual weight (muted vs info tone, plus a
pulsing dot conditional on `tone === "info"`). When the
kernel stopped emitting push events for the
`Admitted → Running` edge (see
`INV-DASHBOARD-PUSH-FSM-COMPLETENESS-01` below — the kernel
fix that lands alongside this FE contract), operators reading
the dashboard saw only `Admitted` rows and concluded the
kernel had stalled. The FE contract therefore widens
"completeness" into "visibility": every state MUST be
distinguishable on a glance regardless of colour-vision
profile, monitor calibration, or push-stream connectivity.

**Visual treatment table (`state-color.ts::VISUAL`).** Every
kernel FSM variant carries a tuple
`(tone, glyph, label, description)`:

| FSM            | State                    | Tone   | Glyph | Operator-facing description                                         |
| -------------- | ------------------------ | ------ | ----- | ------------------------------------------------------------------- |
| Initiative     | `Draft`                  | muted  | `◇`   | plan not yet approved by an operator                                |
| Initiative     | `ApprovedPlan`           | warn   | `◆`   | operator approved the plan; orchestrator not yet spawned            |
| Initiative     | `Executing`              | info   | `▶`   | orchestrator is driving sub-tasks toward terminality (pulses)       |
| Initiative     | `Blocked`                | block  | `⏸`   | no admissible task; operator unblock or escalation required         |
| Initiative     | `Completed`              | ok     | `✓`   | terminal success — every required task reached Completed            |
| Initiative     | `Failed`                 | bad    | `✗`   | terminal failure — a required task or merge step failed             |
| Initiative     | `Aborted`                | block  | `⊠`   | operator-initiated stop via `abort_initiative`                      |
| Task           | `Admitted`               | muted  | `◌`   | queued; awaiting first planner intent or session spawn              |
| Task           | `Running`                | info   | `▶`   | an executor is actively processing intents on this task (pulses)    |
| Task           | `GatesPending`           | warn   | `⏳`  | paused awaiting witness records for one or more gates               |
| Task           | `Completed`              | ok     | `✓`   | terminal success                                                    |
| Task           | `Failed`                 | bad    | `✗`   | terminal failure                                                    |
| Task           | `Aborted`                | block  | `⊠`   | operator-initiated stop                                             |
| Task           | `Cancelled`              | block  | `⊘`   | kernel-initiated cancel via `abort_initiative` cascade              |
| Task           | `BlockedRecoveryPending` | warn   | `↻`   | in-flight at kernel crash; awaits operator `task resume`            |
| Session-row    | `Spawning`               | muted  | `◌`   | VM substrate is booting; planner has not connected yet              |
| Session-row    | `Running`                | info   | `▶`   | session is connected and dispatching intents (pulses)               |
| Session-row    | `Paused`                 | warn   | `⏸`   | session blocked on an outstanding kernel push (e.g. escalation)     |
| Session-row    | `Completed`              | ok     | `✓`   | session reached its planned terminal state cleanly                  |
| Session-row    | `Failed`                 | bad    | `✗`   | session crashed or surrendered with a failure reason                |
| Session-row    | `Revoked`                | block  | `⊠`   | kernel/operator revoked this session token; planner cannot resume   |
| Session-row    | `Expired`                | muted  | `…`   | passive lapse of `expires_at`; expected terminal lifecycle end      |

`<StateBadge>` and `<StatusLegend>` render the glyph alongside
the colour and label; the `description` surfaces on hover via
`title=`. The pulsing dot (the `pulse-dot` animation in
`StateBadge.tsx`) is now driven by an explicit `pulse` flag on
the visual treatment rather than by `tone === "info"`, so a
future state can opt-in (or opt-out) without colour-coupling
side-effects.

**Two-axis disambiguation (`(tone, glyph)` uniqueness within
each enum).** The witness in
`dashboard-fe/src/test/state-color.test.ts` walks every
`KERNEL_*_STATES` array and asserts the `(tone, glyph)` pair
is unique within the enum. This forecloses the
"two states share a tone AND a glyph" trap: e.g. `Aborted`
(operator stop) and `Cancelled` (kernel cascade) both land on
`block`, but `⊠` ≠ `⊘`; `GatesPending` and `BlockedRecoveryPending`
both land on `warn`, but `⏳` ≠ `↻`.

**Failure mode this rules out.** A future refactor that
collapses two tones (e.g. unifying `bad` and `block` for a
"red category") cannot silently regress the visibility
contract — the witness will trip the moment two states share
the resulting `(tone, glyph)` pair. Likewise, dropping the
glyph axis from `<StateBadge>` would trip the witness's
`stateGlyph(...)` non-empty assertions.

Cross-reference: `INV-DASHBOARD-FSM-STATE-VISIBILITY-01`
(`specs/invariants.md`),
`INV-DASHBOARD-PUSH-FSM-COMPLETENESS-01` (kernel-side
push-protocol companion),
`dashboard-fe/src/lib/state-color.ts::VISUAL`,
`dashboard-fe/src/components/StateBadge.tsx`,
`dashboard-fe/src/components/StatusLegend.tsx`.

## 5.12 IntegrationMerge visibility (`INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01`)

The synthetic IntegrationMerge coordinator-task row that
`kernel/src/initiatives/lifecycle.rs::auto_spawn_orchestrator_session_in_tx`
admits in lockstep with the Orchestrator session
([`v2-deep-spec.md §Step 11 IntegrationMerge`](v2-deep-spec.md)) has
`task_id == initiative_id` by construction so that downstream
FK consumers (`task_intent_ranges`,
`lane_budget_reservations`) can join against a real `tasks`
row. Without an explicit dashboard carve-out, that
identity-by-construction reads in the operator surface as a
duplicate row of the initiative — same UUID in the title slot
and the id chip — which hides the row's actual FSM state
behind an opaque hex string and inflates the
`task_count` / `completed_tasks` denominator without
explaining where the missing 50% went.

**Chosen surface: option (A) — first-class visible task.**
The dashboard renders the coordinator row inline with every
other task, plus a stable human title (`Integration merge`)
and a stable display id (`«integration-merge»`):

  1. **Kernel-side projection** stamps the title:
     `crates/dashboard-kernel/src/lib.rs::task_row_to_view`
     detects the `task_id == initiative_id` predicate and
     overrides `TaskView.title = "Integration merge"`. The
     constant lives at
     `crates/dashboard-kernel/src/lib.rs::INTEGRATION_MERGE_TITLE`
     and is reused by tests.
  2. **FE substitution** swaps the id chip:
     `dashboard-fe/src/lib/state-color.ts` exports
     `taskDisplayId(task_id, initiative_id)` which returns
     `«integration-merge»` for the coordinator row and the
     verbatim `task_id` otherwise. Wired into
     `InitiativeDetail.tsx`, `InitiativeDag.tsx`, and
     `TaskDetail.tsx`. Routing and copy-to-clipboard keep
     using the real `task_id` so deep-links and audit-chain
     joins remain stable.
  3. **Progress arithmetic preserved**: the coordinator row
     counts toward `task_count` AND (eventually)
     `completed_tasks`. The Overview progress widget reads
     "N done / M total = M%" without any
     denominator-exclusion bookkeeping. For an initiative with
     one declared sub-task, the widget therefore reads
     "1 done / 2 total = 50%" while the executor task is
     `Completed` and the merge phase is `Running`. When the
     merge finishes the same widget reaches `100%` without an
     option-(B) Merge-phase-pill carve-out.
  4. **State pill is the full FSM**: the coordinator's
     `Admitted → Running → Completed` trajectory renders
     through the same `StateBadge` as every other task,
     guaranteed visible-and-distinct by §5.11 above.

**Forbidden behaviour.** A future change that hides the
coordinator from the task list AND keeps counting it in the
denominator (the paper-cut), or renders it as an
opaque UUID-titled row that looks like a duplicate of the
parent initiative, is forbidden. Option (B) — "exclude from
`task_count` / `completed_tasks` and render a separate
`<MergePhasePill>` beside the progress bar" — is documented
as a future candidate but is **NOT** wired today; selecting it
requires touching every consumer of `task_count` /
`completed_tasks` in the FE plus the kernel-side projection,
and option (A) preserves the existing arithmetic for minimum
impedance. The title carve-out
+ FE display-id helper are pure render-time substitutions, so
a future migration to (B) does not need to re-litigate the
title contract.

Cross-reference:
`INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01`
(`specs/invariants.md`),
`v2/v2-deep-spec.md §IntegrationMerge / Operator surface`,
`kernel/src/initiatives/lifecycle.rs::auto_spawn_orchestrator_session_in_tx`,
`crates/dashboard-kernel/src/lib.rs::task_row_to_view`,
`dashboard-fe/src/lib/state-color.ts::taskDisplayId`.

## 5.13 Wire-time units (`INV-DASHBOARD-WIRE-UNITS-CONSISTENT-01`)

Every timestamp / duration field on the dashboard wire schema
(`crates/dashboard/src/data.rs`) MUST carry an unambiguous
unit, exposed in one of two ways:

  1. **Suffixed field name** — `_ms`, `_s`, `_us`, `_ns`, or
     the spelled-out forms `_unix_secs` / `_at_unix`. The
     suffix is the contract; no doc-comment is required when
     the suffix is present.
  2. **Doc-comment with explicit unit** — when the historical
     field name does not carry a suffix (e.g. `created_at`,
     `updated_at`, `kernel_booted_at`, `last_observed_at`,
     `at`, `signed_at`, `advanced_at`, FailureInfo
     `observed_at`), the field MUST carry a doc-comment line
     that begins `Unix-seconds` or `Unix-milliseconds`. The
     reviewer reads the comment to know which producer helper
     to call.

Both producers and consumers MUST honour the documented unit:

  * **Kernel producers** in `crates/dashboard-kernel/src/lib.rs`
    (and any other crate writing into a `data.rs` wire struct)
    pick the helper matching the field's documented unit.
    `fn unix_now_s() -> u64` is the canonical helper for
    seconds-typed fields; `fn unix_now_ms() -> u64` is the
    canonical helper for `_ms`-suffixed fields. When a single
    builder writes both unit families (the
    `subsystem_health` builder is the exemplar — it populates
    `last_observed_at` in seconds AND `generated_at_ms` in
    milliseconds in the same response struct), both locals
    MUST be in scope and the reviewer MUST be able to match
    each per-arm tuple to its destination field's unit at a
    glance.
  * **FE consumers** in `dashboard-fe/src/` read the wire
    field at the documented unit. `fmtRelative` and
    `fmtAbsolute` (`dashboard-fe/src/lib/format.ts`) both
    expect unix-seconds and document so in their function
    signatures. The only sanctioned conversion is at the
    field-name boundary, and the field name's `_ms` suffix
    must be locally visible at the conversion site (cf.
    `ChainStatusBanner.tsx` divides `s.verified_at_ms` by
    1000 before passing to `fmtAbsolute`;
    `FailureReasonPanel.tsx` multiplies a documented
    `unixSeconds` by 1000 before passing to `new Date(...)`).

**The bug class this prevents.** surfaced the failure
mode this section exists to forbid: the kernel emitted
`unix_now_ms()` (milliseconds) into
`SubsystemHealthCard.last_observed_at` — a field documented
at `data.rs:802-804` as **"Unix-seconds when the kernel last
reported on this subsystem."** The FE's `fmtRelative` correctly
read the field as seconds per the documented contract,
computed `1.78×10¹² s − 1.78×10⁹ s ≈ 1.78×10¹² seconds`, and
rendered **"in 56,347 years"** on every one of the nine
subsystem cards. The render path had no defence because both
the Rust `u64` and the JS `number` accept either magnitude
without complaint, and there was no integration test that
asserted "the Health page renders a sensible relative-time
string for a healthy subsystem". The producer was changed to
`unix_now_s()` for the seconds-typed field while
`generated_at_ms` and `verified_at_ms` (correctly
`_ms`-suffixed) stayed on `unix_now_ms()`.

**Future strengthening.** A typed wrapper pair —
`UnixSeconds(u64)` and `UnixMillis(u64)` in
`crates/dashboard/src/data.rs`, with `Serialize` /
`Deserialize` impls that round-trip the inner integer
verbatim — would make this contract compiler-checked rather
than reviewer-checked. Filed for the post-validation cleanup
sweep; not wired today because it touches every wire field
and the live operator bug only needed a one-line producer fix.

Cross-reference:
`INV-DASHBOARD-WIRE-UNITS-CONSISTENT-01`
(`specs/invariants.md`),
`crates/dashboard/src/data.rs` (wire schema with per-field
unit doc-comments),
`crates/dashboard-kernel/src/lib.rs::unix_now_s` /
`::unix_now_ms` (kernel-side helpers),
`dashboard-fe/src/lib/format.ts::fmtRelative` /
`::fmtAbsolute` (FE consumers, both seconds-typed).

## 6. Rationale (why these bounds)

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

---

## §10 — Permanent-failure escalation surface

`INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01` and
`INV-OPERATOR-APPROVE-RECOVERY-SEMANTICS-01`. This section
documents the per-cause approve semantics for the
`AuditEventKind::InitiativePermanentFailureEscalated` chain
anchor introduced in and the underlying
`LogicalDeadlock`-class escalation row.

### §10.1 — Per-cause approve matrix

The kernel-side helper
`kernel::initiative_escalation::escalate_initiative_on_permanent_failure`
inserts ONE `LogicalDeadlock` escalation row per
`(initiative_id, cause_kind, cause_seq)` triple and emits the
`InitiativePermanentFailureEscalated` chain anchor. The
operator-approve handler is the SAME for every cause (all
in-scope causes ride the existing
`approve_logical_deadlock_escalation_in_tx` path). The cause
discriminator is preserved on the chain anchor so dashboards
can render per-cause guidance without forking the approve
machinery.

| Cause kind | Recoverable via approve | Approve semantics | Re-failure semantics |
|---|---|---|---|
| `OrchestratorRespawnCeilingExceeded` | Yes | Reset NNSP counter; flip `Failed → Executing`; next decision-cycle re-spawns the orchestrator. | If respawn re-trips the ceiling, a fresh escalation lands with a NEW idempotency key (the attempt counter advanced). Operator can Deny to settle the FSM. |
| `MergeFastForwardFailed` | Yes | Flip `Failed → Executing`; orchestrator's next decision-cycle re-attempts the merge. | If FF still refused, fresh anchor lands with a different `cause_seq` (the integration ref's `target_ref` may have advanced) — operator should Deny + manually rebase. |
| `PushFailed` | Yes | Flip `Failed → Executing`; next merge attempt re-attempts the push. | If push still failing, fresh anchor lands with the new push attempt's reason text in `cause_seq`. |
| `SessionVmFailedFinal` | Yes (transient host pressure) | Flip `Failed → Executing`; next session-spawn cycle re-attempts. | If still permanent, fresh anchor with `total_attempts` advanced. |
| `PlanRejected` | **No** | Flip `Failed → Executing` is a structural no-op (the rejected plan needs to be re-submitted; approve does not re-run admission). Operator should Deny + open a fresh plan. The chain anchor's `recoverable_via_approve = false` field surfaces this in the inbox. | N/A. |
| `EscalationTimedOut` | Yes | Flip `Failed → Executing`; the original blocked work resumes. | If the underlying condition that drove the original escalation is still present, it re-trips immediately. |
| `EscalationRateLimitExceeded` | **No** | Approve is structural no-op (the storm pattern needs out-of-band investigation). Operator should Deny. | N/A. |
| `SessionEgressStallDetected` | Yes | Flip `Failed → Executing`; orchestrator's next decision-cycle re-runs the egress-blocked session. | If egress still stalled, fresh anchor with the stalled session_id in `cause_seq`. |

### §10.2 — Anti-loop guarantee

The helper's `cause_seq` always includes a per-instance
discriminator (attempt counter, reason hash, refspec, etc.)
so a re-fire after an unsuccessful approve does NOT silently
dedup against the just-approved row. The new escalation
shows up in the inbox as a fresh row with a NEW
idempotency_key; the operator sees the cycle and can choose
Deny as the semantically-correct response. This guarantees
the system can never enter the
`approve → no-op → silently stuck` failure mode pinned by
`INV-OPERATOR-APPROVE-RECOVERY-SEMANTICS-01`.

### §10.3 — Anchor-less escalation path

The helper's two-tier FK-anchor lookup (most-recently-touched
worker session → most-recent Orchestrator session for the
initiative) covers every well-formed initiative. In the
pathological case where BOTH lookups fail (no session of any
kind ever bound to the initiative — a corrupted-state
scenario), the helper emits the chain anchor with
`escalation_id = None` and writes a structured warn log
(`LogicalDeadlockEscalationSkippedNoFkAnchor`). The inbox
notification still fires (the `InitiativePermanentFailureEscalated`
event routes to Critical), so the operator is paged even
though no operator-actionable escalation row exists. The
dashboard renders this as a "chain-only; manual triage
required" badge per the `escalation_id` JSON-null signal.

### §10.4 — Deferred coverage

Not every in-scope kind is wired yet. The
following emit sites are deferred follow-ups:

* `SessionVmFailedFinal` — emit site
  (`spawn_with_transient_retry`) lacks `Arc<HandlerContext>`;
  needs caller-side wiring at every spawn entry point or a
  helper-API rework.
* `PlanRejected` — emit site (plan admission) needs
  initiative_id surfacing.
* `EscalationTimedOut` — no production emit site (defined +
  serialised in tests, but no kernel-side timeout sweep
  exists yet).
* `EscalationRateLimitExceeded` — emit site is inside the
  escalation-submit transaction without `Arc<HandlerContext>`;
  the chain anchor still fires (Critical-classified per
 Bug 4) but no per-event helper invocation lands.
* `SessionEgressStallDetected` — emit site needs
  session→initiative_id resolution.
* `InitiativeStateChanged{new_state: Failed}` (catch-all) —
  needs `from`-state classification to avoid double-firing
  on already-wired kinds.

For each deferred kind the chain-side `AuditEventKind` event
continues to fire unchanged; only the operator-actionable
escalation enrichment is missing. The
`INV-NOTIFICATION-PRIORITY-PARITY-01`-extension means the
notification dispatch gate still routes the chain event to
Critical for every kind, so the
inbox-level paging signal is preserved even on the deferred
paths.
