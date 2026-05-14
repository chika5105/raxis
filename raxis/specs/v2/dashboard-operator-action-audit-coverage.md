# Dashboard operator-action audit coverage

> **Canonical home for**
> `INV-DASHBOARD-OPERATOR-ACTION-AUDIT-COVERAGE-01`,
> `INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01`.
> Pairs with `audit-paired-writes.md` (the audit-emission contract),
> `dashboard-hardening.md` (the dashboard's TCB boundary), and
> `secrets-model.md` (the credential lifecycle).
>
> **Update log**
>
>   * 2026-05-13 (`worker/audit-tightening`) — read-only
>     `OperatorViewed*` emissions retired. The chain is the
>     system's forensic ledger of state-affecting actions; pure
>     pageviews belong in observability metrics, not the chain.
>     iter48 surfaced 1258 / 1260 chain rows being
>     `OperatorViewed*` noise, which drowned out actual signal.
>     See §signal-vs-noise below for the policy and the
>     coverage table for the per-endpoint status.

## §1 — Why this spec exists

The dashboard is the operator's TCB boundary into the kernel.
Every operator action that mutates state OR exposes operator-
private data is forensically interesting: a security review of an
incident MUST be able to reconstruct who saw what and when.
Without comprehensive audit coverage, the chain records the
agent's behaviour with high fidelity and the operator's behaviour
with massive blind spots.

`INV-AUDIT-OPERATOR-ACTION-01` (canonical home:
`dashboard-hardening.md §2.2`) pins the per-emission contract:
exactly one structured `Operator*` event per action, with
`operator_fingerprint`, resource correlation fields, and a stable
`outcome` discriminant. This spec extends that contract to the
*coverage* dimension: every endpoint that MUST emit, the variant
it emits, and the small set of explicit exclusions.

## §2 — Coverage table

The table below enumerates every dashboard HTTP endpoint, the
required audit emission, and the current status. Statuses:

  * **UPHELD** — emission was wired before this spec and remains
    in force.
  * **CLOSED** — gap-closer that this spec landed. Still in force
    unless marked **RETIRED** below.
  * **NEW** — credential-viewer family added alongside this
    spec.
  * **RETIRED** — emission was removed by
    `worker/audit-tightening` (2026-05-13). The pre-existing
    `AuditEventKind` variant is marked `#[deprecated]` so
    already-persisted chains continue to decode; new chain rows
    of these kinds are no longer written. Replacement (if any)
    is named in the row's comment.
  * **EXCLUDED** — never auditable by design.

| Action | Endpoint | Method | Audit emission | Severity | Status |
|---|---|---|---|---|---|
| Pre-auth challenge | `/api/auth/challenge` | GET | (none — pre-auth) | n/a | EXCLUDED |
| Verify challenge | `/api/auth/verify` | POST | `OperatorAuthSucceeded` / `OperatorAuthFailed` (existing auth flow) | medium | UPHELD |
| Logout | `/api/auth/logout` | POST | `OperatorAuthLogout` (existing auth flow) | low | UPHELD |
| Health snapshot | `/api/health` | GET | `OperatorHealthQueried` | none | UPHELD |
| Subsystem health | `/api/health/subsystems` | GET | `OperatorHealthQueried` | none | UPHELD |
| List initiatives | `/api/initiatives` | GET | ~~`OperatorViewedInitiativeList`~~ (none) | none | RETIRED |
| Initiative detail | `/api/initiatives/:id` | GET | ~~`OperatorViewedInitiative`~~ (none) | none | RETIRED |
| Initiative DAG | `/api/initiatives/:id/dag` | GET | ~~`OperatorViewedInitiativeDag`~~ (none) | none | RETIRED |
| Initiative tasks | `/api/initiatives/:id/tasks` | GET | ~~`OperatorViewedInitiativeTasks`~~ (none) | none | RETIRED |
| Task detail | `/api/tasks/:id` | GET | ~~`OperatorViewedTask`~~ (none) | none | RETIRED |
| Task outputs | `/api/tasks/:id/outputs` | GET | ~~`OperatorViewedTaskOutputs`~~ (none) | none | RETIRED |
| List sessions | `/api/sessions` | GET | ~~`OperatorViewedSessionList`~~ (none) | none | RETIRED |
| Session detail | `/api/sessions/:id` | GET | ~~`OperatorViewedSession`~~ (none) | none | RETIRED |
| Open session stream | `/api/sessions/:id/stream` | GET | `OperatorOpenedSessionStream` (once per attach) | none | UPHELD |
| List escalations | `/api/escalations` | GET | ~~`OperatorViewedEscalationList`~~ (none) | none | RETIRED |
| Escalation detail | `/api/escalations/:id` | GET | ~~`OperatorViewedEscalation`~~ (none) | none | RETIRED |
| Audit chain page | `/api/audit` | GET | ~~`OperatorViewedAuditChain`~~ (none) | none | RETIRED |
| Recent activity feed | `/api/audit/recent` | GET | (none — curated read) | none | EXCLUDED |
| Audit chain status (cache hit) | `/api/audit/chain-status` | GET | (none — debounced cache read) | none | EXCLUDED |
| Audit chain re-verify | `/api/audit/chain-status?reverify=true` | GET | `OperatorAuditChainReverified` | low | UPHELD |
| Operator inbox | `/api/inbox` | GET | ~~`OperatorViewedInbox`~~ (none) | none | RETIRED |
| List notifications | `/api/notifications` | GET | ~~`OperatorViewedNotifications`~~ (none) | none | RETIRED |
| Unread badge | `/api/notifications/unread-count` | GET | (none — polled badge) | n/a | EXCLUDED |
| Mark notification read | `/api/notifications/:id/read` | PATCH | `OperatorNotificationMarkedRead` | low | UPHELD |
| Mark all read | `/api/notifications/mark-all-read` | POST | `OperatorNotificationsMarkedAllRead` | low | UPHELD |
| Policy snapshot | `/api/policy` | GET | ~~`OperatorViewedPolicySnapshot`~~ (none) | none | RETIRED |
| Raw policy.toml | `/api/policy/toml` | GET | ~~`OperatorViewedPolicyToml`~~ (none — role gate suffices) | none | RETIRED |
| Update policy.toml | `/api/policy/toml` | PUT | `PolicyUpdatedViaDashboard` (existing) | high | UPHELD |
| List worktrees | `/api/git/worktrees` | GET | ~~`OperatorViewedWorktreeList`~~ (none) | none | RETIRED |
| Worktree detail | `/api/git/worktrees/:name` | GET | `OperatorWorktreeAccessed { surface = "detail" }` | low | UPHELD |
| Worktree log | `/api/git/worktrees/:name/log` | GET | `OperatorWorktreeAccessed { surface = "log" }` | low | UPHELD |
| Worktree diff (default) | `/api/git/worktrees/:name/diff` | GET | `OperatorDiffViewed` | low | UPHELD |
| Worktree diff (range) | `/api/git/worktrees/:name/diff/:range` | GET | `OperatorDiffViewed` | low | UPHELD |
| Worktree tree | `/api/git/worktrees/:name/tree` | GET | `OperatorWorktreeAccessed { surface = "tree" }` | low | UPHELD |
| Worktree file | `/api/git/worktrees/:name/file` | GET | `OperatorFileContentFetched` | low | UPHELD |
| List initiative credentials | `/api/initiatives/:id/credentials` | GET | `OperatorListedCredentials` | none | NEW |
| Reveal initiative credential | `/api/initiatives/:id/credentials/:name/reveal` | POST | `OperatorRevealedCredential` | high | NEW |
| List system credentials | `/api/system/credentials` | GET | `OperatorListedSystemCredentials` | low | NEW |
| Reveal system credential | `/api/system/credentials/:name/reveal` | POST | `OperatorRevealedSystemCredential` | critical | NEW |
| View plan TOML | `/api/initiatives/:id/plan` | GET | ~~`OperatorViewedPlanToml`~~ (none) | none | RETIRED |

**Outcome semantics on every row.** Every audit emission carries
a stable `outcome` discriminant: `Accepted` (success path),
`RejectedPermission` (auth/role gate), `RejectedValidation`
(schema, NotFound, rate-limited), or `InternalError` (uncaught
upstream failure). The handler emits exactly once per request
regardless of which branch fires.

## §3 — Severity → notification mapping

The `severity` field on each row maps to the notification routing
contract pinned by `INV-NOTIF-SCOPE-01`:

| Severity | Notification priority | Inbox? | Sidebar badge? |
|---|---|---|---|
| `none` | `None` | No | No |
| `low` | `Low` | Yes | No |
| `medium` | `Medium` | Yes | Yes |
| `high` | `High` | Yes | Yes (highlighted) |
| `critical` | `Critical` | Yes | Yes (alert banner) |

Most read-only `OperatorViewed*` events are `none` priority —
they belong in the audit chain for forensic walks, but flooding
the operator inbox with "you opened the initiative list" rows
would defeat the inbox's attention-routing purpose. The
`*Reveal*` events ARE notification-bearing because they expose
plaintext that the audit reviewer cares about catching in real
time.

## §signal-vs-noise — what the audit chain is for

> Pinned by `worker/audit-tightening` after iter48 surfaced
> 1258 / 1260 chain rows being `OperatorViewed*` pageview
> noise. This section is the policy. It is NOT an `INV-*`
> invariant — the user pushed back on lint-style invariants for
> taxonomy decisions like this. The text below is the contract
> nonetheless: future contributors adding new emit sites MUST
> reconcile their addition against this signal/noise split.

### Definition

The audit chain is the system's **forensic ledger of
state-affecting actions**. A row belongs in the chain iff a
post-incident review would want to reconstruct who did the
thing, with what arguments, against what kernel state, and
when. A row that exists only to prove an operator opened a tab
on the dashboard is not state-affecting — it is observability
telemetry — and lives elsewhere (Datadog / Prometheus / the
in-memory dashboard metrics counter, never the chain).

### Audit-worthy (KEEP)

Anything that could be subpoena'd or replayed for forensics.
Examples by category:

  * **State mutations** — `Initiative*Created`, `PlanApproved`,
    `IntentAccepted`, `TaskTransitioned`, `Session*Spawned`,
    `*Completed`, `*Failed`, `*Stopped`,
    `IntegrationMergeCompleted`, `Operator*Approved`,
    `Operator*Denied`, `OperatorRevealedCredential`,
    `OperatorRotatedDashboardJwtSecret`, ….
  * **Security events** — `SecurityViolationDetected`,
    `EgressDenied`, `TproxyAdmissionDenied`,
    `KernelDeadlockDetected`, `KernelCrashedBySignal`,
    `SupervisorRefusedRestart`, ….
  * **Lifecycle events that affect kernel state** —
    `KernelStarted` (once at boot, not per tick), `KernelStopped`,
    `KernelBootedFromSupervisorRestart`,
    `OrchestratorRespawnCeilingExceeded`,
    `ExecutorRespawnFromReviewRejection`, ….
  * **Authentication / authorization** —
    `OperatorAuthSucceeded` / `OperatorAuthFailed` (the moments
    of grant / denial), `OperatorAuthLogout`,
    `OperatorTokenRevoked`, ….
  * **Operator surfaces that touch operator-private material
    one resource at a time** — `OperatorWorktreeAccessed`,
    `OperatorDiffViewed`, `OperatorFileContentFetched`,
    `OperatorAuditChainReverified`, `OperatorHealthQueried`,
    `OperatorListedCredentials`,
    `OperatorListedSystemCredentials`,
    `OperatorOpenedSessionStream`. These touch one named
    resource per emit and a forensic walker uses them to answer
    "did operator X look at worktree Y at time T?". They are
    NOT periodic pageview emissions — they fire once per
    operator-driven action against a specific named target.

### Audit-NOISE (DROP)

Pageview / liveness telemetry that drowns out signal:

  * **Read-only views** —
    `OperatorViewedInitiativeList`,
    `OperatorViewedSessionList`,
    `OperatorViewedAuditChain`,
    `OperatorViewedEscalationList`,
    `OperatorViewedInbox`,
    `OperatorViewedNotifications`,
    `OperatorViewedPolicySnapshot`,
    `OperatorViewedPolicyToml`,
    `OperatorViewedWorktreeList`,
    `OperatorViewedTask`,
    `OperatorViewedTaskOutputs`,
    `OperatorViewedSession`,
    `OperatorViewedEscalation`,
    `OperatorViewedInitiative`,
    `OperatorViewedInitiativeDag`,
    `OperatorViewedInitiativeTasks`,
    `OperatorViewedPlanToml`,
    `OperatorViewedWorktreeLog`. The variants stay on the enum
    as `#[deprecated]` so existing chains keep deserializing;
    emit sites have been removed.
  * **Heartbeat / keep-alive events** — anything periodic that
    exists only to prove liveness. Audit `KernelStarted` once
    at boot; do NOT audit per-tick. Audit the SSE attach
    (`OperatorOpenedSessionStream`); do NOT audit the per-15s
    keepalive frames.
  * **Routine notification deliveries** — `NotificationDelivered`
    is currently borderline; the row carries the actual
    notification kind + payload, which IS forensically
    interesting (a forensic walker reconstructs which alerts
    fired). Today's contract: KEEP `NotificationDelivered`
    until a future audit pass demonstrates a noise pattern
    similar to the `OperatorViewed*` family.

### Why not an `INV-*` invariant

The user pushed back on lint-style invariants for taxonomy
decisions like this. The signal/noise split is a *policy* not
an *invariant*: it depends on what operators care about, what
forensic reviewers want to find, and what observability
infrastructure is in place around the kernel — all of which
shift over time. A `#[deprecated]` annotation on the retired
variants plus this §section is the canonical record.

### Recent-activity feed

The dashboard Overview's "Recent activity" widget surfaced the
iter48 noise. Even after retiring `OperatorViewed*`, the chain
still records per-click events that are forensically useful but
not what an operator wants to see in a 10-row "what changed?"
widget (mark-read, credential-list, health-query,
worktree-access, …). The widget therefore consumes a
**curated** endpoint `GET /api/audit/recent` whose server-side
allow-list (`raxis_dashboard::data::recent_activity_filter::IMPORTANT_EVENT_KINDS`)
admits only:

  * initiative lifecycle (admit, approve, fail, close);
  * plan + task transitions;
  * session-lifecycle terminal events (spawn, fail-final,
    revoke);
  * security events;
  * integration-merge events;
  * operator-mutating actions (plan approve / reject,
    credential reveal, policy update, dry-run admit,
    chain-reverify);
  * kernel boot / shutdown / supervisor restart.

The allow-list lives in **one** place so a reviewer can audit
the curation policy at a glance. The dashboard FE never makes
a policy decision about what to hide — the read-only TCB
projection rule from `dashboard-hardening.md` extends here. New
state-affecting variants MUST be added to
`IMPORTANT_EVENT_KINDS` if they should appear on the Overview.

## §4 — Exclusion criteria

Endpoints listed as **EXCLUDED** in §2 follow these rules:

### §4.1 Pre-auth surfaces

  * `GET /api/auth/challenge` — there is no operator identity
    yet; the challenge is what creates the JWT in the first
    place. The auth flow's own `OperatorAuthSucceeded` /
    `OperatorAuthFailed` events cover the boundary.

### §4.2 Polled badge counters

  * `GET /api/notifications/unread-count` — the dashboard sidebar
    polls this every 5 s for the unread badge. Auditing every
    poll would emit ~20k rows per operator per day; the
    audit-chain-walker performance gates would degrade and the
    forensic signal-to-noise ratio would tank. The list endpoint
    `GET /api/notifications` IS audited (lower poll cadence,
    higher per-call payload).

### §4.3 SSE keepalive frames

  * The SSE attach itself audits via `OperatorOpenedSessionStream`
    (once per attach). The per-15s keepalive bytes that follow
    the initial subscription are protocol-level liveness signals,
    not operator actions, and are NOT audited.

### §4.4 Cache-hit reads

  * `GET /api/audit/chain-status` (no `?reverify=true`) returns
    the cached integrity verdict; the `reverify` path IS audited
    via `OperatorAuditChainReverified` because it pins a kernel
    worker on a full chain walk. The cache-hit path runs in <
    1 ms per call and would generate one row per page mount.

### §4.5 Pure UI state

Theme toggle, filter URL params, sidebar collapse, column-width
preferences, etc. NEVER reach the kernel; they live in the FE
state store and are not auditable on the kernel side. Operators
who want to audit FE-side preferences should mine the browser's
own `localStorage` snapshot at incident-response time.

## §5 — Polling debounce contract

For endpoints that are polled by the FE on a fast cadence (the
sidebar refresh path), the data layer SHOULD emit one audit row
per operator per endpoint per 5-minute window — not one per call.
This is the carve-out in `INV-DASHBOARD-OPERATOR-ACTION-AUDIT-
COVERAGE-01` for "polling-style queries". The current
implementation does NOT yet debounce (every call audits); the
debounce is a follow-up commit tracked in
`raxis-roadmap.md §audit-debouncing`.

Polled endpoints in the current dashboard:
  * `GET /api/initiatives` — sidebar refresh, ~5s cadence.
  * `GET /api/sessions` — sidebar refresh, ~5s cadence.
  * `GET /api/notifications` — sidebar refresh, ~5s cadence.

The unread-count companion endpoint is excluded entirely (§4.2).

## §6 — Anthropic credential — special handling

`INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01` pins the
following invariants for any reveal of a `providers.anthropic*`
credential:

  1. **Role gate.** `admin` role REQUIRED. `read` and
     `write_policy` get HTTP 403 with audit-paired
     `RejectedPermission`.
  2. **Confirmation modal.** The FE renders an explicit warning
     naming the credential and the audit class before any
     reveal call goes out:

         > The Anthropic API key is a high-value secret.
         > Revealing will be audited as
         > OperatorRevealedSystemCredential at Critical
         > severity. Confirm only if necessary for diagnostics.

  3. **Critical severity.** The audit row carries
     `severity = "critical"` (NOT `"high"`).
  4. **15s auto-hide.** Shorter than the 30s default for
     per-initiative credentials.
  5. **Inbox notification.** Surfaces in the operator
     notifications inbox at `Critical` priority. A second
     operator sees the reveal happened even if they were not in
     front of the dashboard at the time.

### §6.1 No-leak property

The Anthropic key MUST NEVER appear in any non-admin endpoint,
log line, error envelope, or response body. The defence-in-depth
for this property comprises:

  * `CredentialReveal::Debug` REDACTS the `plaintext` field —
    accidental `tracing::error!("{reveal:?}")` does not leak.
  * The `with_bytes` closure in `read_credential_bytes` is the
    only sanctioned bytes-handling path; the SecretBox-wrapped
    `CredentialValue` zeros its inner copy on drop.
  * No `Display` impl on `CredentialMetadata` /
    `CredentialReveal` — the FE renders via `Serialize`, the
    only canonical exfil surface.

A code-search audit of `raxis/crates/dashboard*` and
`raxis/kernel/src/dashboard/` confirms zero current callers
print the struct via `Debug`, but the redaction is a low-cost
forward guarantee against future regressions.

## §7 — Witness tests

  * `crates/dashboard/src/routes/credentials.rs::tests` — six
    tests covering role gate (read forbidden, admin allowed),
    rate-limit enforcement, NotFound audit shape, and the
    Critical-severity flag on the system reveal path.
  * `crates/dashboard-kernel/src/notification_filter.rs::tests` —
    `credential_reveals_notify_with_correct_priority` pins the
    severity → priority routing for the new reveal events.
  * Existing route tests for the non-credential endpoints stay
    in scope; the gap-closer commits did not regress any.

## §8 — Cross-references

  * `INV-AUDIT-OPERATOR-ACTION-01` — the per-emission contract
    every row in §2 fans out from. Canonical home:
    `dashboard-hardening.md §2.2`.
  * `INV-NOTIF-SCOPE-01` — the audit→notification routing this
    spec's severity column maps onto.
  * `INV-DASHBOARD-CREDENTIAL-DEFAULT-MASKED-01` /
    `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01` /
    `INV-DASHBOARD-CREDENTIAL-REVEAL-ROLE-GATED-01` /
    `INV-DASHBOARD-CREDENTIAL-AUTO-HIDE-01` — the credential-
    viewer family this spec extends.
  * `audit-paired-writes.md §credential-reveal` — the audit-
    emission contract for the reveal path.
  * `secrets-model.md §dashboard-reveal` — the credential-life
    cycle model the dashboard reveal slots into.
