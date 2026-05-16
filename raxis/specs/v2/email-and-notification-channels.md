# RAXIS V2 — Email & Operator Notification Channels

> **Status:** V2 Specified
> **V2.5 forward-only consolidation:** The original draft below
> distinguishes a `WebhookChannel` (HMAC-signed HTTPS POST to an
> operator URL) from the future `Sidecar`-style integrations.  In
> V2.5 those were folded into a single `Sidecar` channel kind:
> `Webhook` ≡ "HTTP POST a JSON payload to a URL" was a strict
> subset of `Sidecar`, shipped without HMAC signing in the kernel
> path, and lacked the per-channel concurrency cap + 3-state
> circuit breaker that `Sidecar` provides.  Read
> every reference to `WebhookChannel` / "Webhook kind" / `crates/
> raxis-notification-webhook/` below as historical context for the
> `Sidecar` surface.  HMAC signing is the sidecar process's
> responsibility — kernel→sidecar trust is the loopback boundary.
>
> **Role:** Canonical home for two related but separately-bounded subsystems:
>
> 1. **`OperatorNotificationChannel`** — the kernel→operator outbound transport seam (Shell, File, Email, Sidecar today; Slack/PagerDuty/Teams via operator-run sidecar translators).  V1-draft `Webhook` was folded into `Sidecar` in V2.5 (forward-only).  The 7th extensibility trait per [`extensibility-traits.md §6A`](extensibility-traits.md). Implements forward-compat from `cli-readonly.md §5.6.6`.
> 2. **`SmtpCredentialProxy`** — agent→external SMTP relay, the 6th `proxy_type` per [`credential-proxy.md §3.6`](credential-proxy.md). Lets agents send email as part of their work without ever holding the SMTP password.
>
> The two subsystems share the SMTP transport library (`crates/raxis-smtp-client/`) but are not the same code path. Mixing them would erase the `R-9` attribution boundary (an operator-attributed channel triggerable from agent intent would let the agent forge operator-attributed email).
>
> **Cross-references:**
> - [`extensibility-traits.md §6A`](extensibility-traits.md) (NEW) — `OperatorNotificationChannel` trait registration + V2 ship list + conformance kit
> - [`extensibility-traits.md §1.1`](extensibility-traits.md) — The §1.1 rule and the seventh trait row
> - [`extensibility-traits.md §13.1`](extensibility-traits.md) — Why seven traits, not six (decision rationale)
> - [`credential-proxy.md §3.6`](credential-proxy.md) (NEW) — SMTP `proxy_type` reference
> - `cli-ceremony.md §4.1` — `raxis notify channel | route | credential` operator-write commands
> - `cli-readonly.md §5.6` — Existing `[notifications]` schema and `raxis inbox`
> - [`policy-plan-authority.md §4`](policy-plan-authority.md) — Schema for `[[notifications.credentials]]` and `[[notifications.channels.email|webhook]]`
> - [`kernel-mechanics-prompt.md §3`](kernel-mechanics-prompt.md) — Agent NNSP addition for SMTP proxy availability
> - `v1/kernel-core.md §2.3` — Escalation handler step 5 dispatch hook (already routes to `notifications::dispatch`)
> - `v1/kernel-store.md §2.5.2` — AuditSink ordering invariant (NotificationDelivered events emit post-commit)

---

## §1 — Why this spec exists

### §1.1 The two distinct goals

This spec serves two operator-visible goals:

**Goal A — Operator notification of escalations and security-relevant kernel events.**
The kernel emits audit events (`EscalationSubmitted`, `PathScopeOverrideApplied`, `KeyRevocationApplied`, …). The operator wants those routed to a destination they actually check — local shell file (`raxis inbox`), email, Slack, PagerDuty. The destination is **transport-pluggable**.

**Goal B — Agents that need to send email as part of their work.**
A code-review bot summarises findings to a human reviewer; a release-automation agent emails a build report; a CI-triage agent notifies the on-call when a pipeline fails. The agent **must not hold SMTP credentials** (`INV-VM-CAP-04`), must not be able to spoof `From:` or relay-spam, and every send must be audited.

### §1.2 Why these are separate subsystems

| Property | Goal A — Operator notification | Goal B — Agent SMTP egress |
| --- | --- | --- |
| Direction | kernel → operator | agent → upstream relay |
| Originator | Kernel (operator authority) | Agent (plan-delegated authority) |
| Trigger | Audit-event emit matching a `[[notifications.routes]]` entry | Agent SMTP socket write to `localhost:<port>` |
| Recipients | Operator-fixed (`To:` configured in policy) | Policy-allowlisted; agent picks within allowlist |
| Sender | Channel `from_address` (kernel-controlled) | Substituted by proxy from policy `from_address`; agent's `MAIL FROM` recorded but overridden |
| Body | Pre-rendered by per-event-kind formatter | Agent-controlled, hashed for audit, optionally archived |
| Trust | Operator-trusted | Agent-untrusted (every header/recipient/byte filtered) |
| Primary `R-*` | `R-7` (audit emits notification record), `R-9` (operator attribution) | `R-2` (mediated egress), `R-9` (task attribution), `INV-VM-CAP-04` |
| Existing scaffolding | `[[notifications.channels]]` v1 schema; Email/Webhook handlers deferred to v2 (`cli-readonly.md §5.6.6`) | Tier-2 credential proxy in [`credential-proxy.md §3`](credential-proxy.md) |
| Audit kind | `NotificationDelivered`, `NotificationDeliveryFailed` | `SmtpProxyConnected`, `SmtpProxyMessageSent`, `SmtpProxyMessageRejected`, `SmtpProxyRateLimited` |

**The R-9 attribution rule** drives the boundary: an operator-attributed email and an agent-attributed email are distinct kinds of message-in-the-world, and they MUST land in distinct audit records and distinct policy surfaces. Combining the trait would let an agent intent (or a buggy handler) emit a `NotificationDelivered` record with operator attribution, which would let the agent forge audit-bound operator messages. The trait surfaces are split for that reason.

### §1.3 What is shared

The two subsystems share **only** the SMTP transport library (`crates/raxis-smtp-client/`):

- TLS hardening (cipher allowlist, cert validation, SNI).
- AUTH PLAIN / LOGIN / XOAUTH2 implementations (RFC 4954).
- MIME body framing (RFC 5322).
- Error mapping (SMTP response codes → typed `SmtpError`).

That crate has no policy logic, no audit logic, no credential resolution. It is a thin async SMTP client. Both `EmailChannel` (Goal A) and `SmtpCredentialProxy` (Goal B) call into it but bring their own credential source, recipient enforcement, and audit emission.

---

## §2 — Goal A: `OperatorNotificationChannel` trait

### §2.1 The §1.1 rule revisited

[`extensibility-traits.md §1.1`](extensibility-traits.md) says: *a subsystem stays concrete if and only if it enforces an `R-*` invariant.* Applying the rule to operator-notification:

- **What enforces `R-*`?** The dispatcher's idempotency-on-`(event_seq, channel_id)`, the per-route ACL, the audit emission of `NotificationDelivered`/`NotificationDeliveryFailed`, the requirement that the dispatch never blocks the kernel commit path. All of these stay **kernel-side** in `kernel/src/notifications/dispatch.rs` and DO NOT vary by channel.
- **What varies by channel?** The wire (filesystem write vs SMTP vs HTTPS POST), the credential source (none vs SMTP password vs HMAC secret), the rate-limit class (instantaneous file write vs round-trip-to-relay).

Substituting a channel impl preserves every `R-*`: the dispatcher still emits the audit record, still respects the route, still doesn't block. Conclusion: this is a transport seam, exactly like `OperatorTransport` (in the inverse direction).

### §2.2 Trait definition

**Canonical home:** `crates/raxis-notification/src/lib.rs` (NEW).

```rust
//! crates/raxis-notification/src/lib.rs
//! Operator-attributed outbound notification transport.
//! V2 ships four impls (in separate crates per the §1.2 separation rule):
//!   - `crates/raxis-notification-shell/`       ShellChannel  (default; v1 carryover)
//!   - `crates/raxis-notification-file/`        FileChannel   (v1 carryover)
//!   - `crates/raxis-notification-email/`       EmailChannel  (NEW v2)
//!   - `crates/raxis-notification-webhook/`     WebhookChannel (NEW v2)
//! V3+ adds `SlackChannel`, `PagerDutyChannel`, `TeamsChannel`, etc.
//! without touching the kernel.

use raxis_types::{AuditEventId, AuditEventKind, EventSeq, PolicyEpoch};
use std::time::Duration;

#[async_trait::async_trait]
pub trait OperatorNotificationChannel: Send + Sync + 'static {
    /// Stable identifier matching `[[notifications.channels]].id`.
    fn id(&self) -> &str;

    /// Channel kind, used in audit records and `raxis notify channel list` output.
    fn kind(&self) -> ChannelKind;

    /// Deliver one notification.
    /// **Idempotency:** the dispatcher MAY call `deliver` more than once for
    /// the same `(payload.event_seq, channel_id)` pair after a transient
    /// failure. The impl MUST be idempotent. For `EmailChannel`, this means
    /// reusing `Message-Id: <event_seq.event_id@raxis.kernel>` so SMTP relays
    /// can dedupe.
    /// **Latency budget:** 30 s soft, 60 s hard. The dispatcher cancels the
    /// `tokio::Future` at the hard deadline and emits
    /// `NotificationDeliveryFailed { reason: Timeout }`.
    async fn deliver(
        &self,
        payload: &NotificationPayload,
    ) -> Result<DeliveryReceipt, ChannelError>;

    /// Pre-flight liveness probe.
    /// Used at boot (every channel is probed once before the kernel opens
    /// the operator transport) and on demand by `raxis notify test`. For
    /// `EmailChannel`, this is `EHLO` + STARTTLS + AUTH (without sending
    /// mail). For `WebhookChannel`, an `OPTIONS` request to the configured
    /// URL.
    /// Probe failure does NOT abort kernel boot — the channel is marked
    /// `Degraded` and a `NotificationChannelDegraded { id, reason }` audit
    /// event is emitted; routes targeting it continue to attempt delivery.
    async fn probe(&self) -> Result<ProbeOutcome, ChannelError>;

    /// Concurrency class for the dispatcher's per-channel scheduler.
    /// `Fast` channels (Shell, File) can run unbounded-parallel; the
    /// dispatcher fans out one task per event. `Slow` channels (Email,
    /// Webhook, Slack) are serialised per-channel-id with a small worker
    /// pool (default 4) so a backlog of events doesn't cause the kernel to
    /// open hundreds of SMTP connections.
    fn dispatch_class(&self) -> DispatchClass;

    /// Maximum payload size this channel can transport.
    /// `EmailChannel`: 50 KiB (RFC suggests 998-byte lines; we cap at 50 KiB
    /// summary + 250 KiB JSON attachment by default, configurable).
    /// `WebhookChannel`: 1 MiB.
    fn max_payload_bytes(&self) -> usize;
}

#[derive(Debug, Clone)]
pub struct NotificationPayload {
    /// Monotonically increasing audit-chain sequence number; unique per kernel.
    pub event_seq: EventSeq,
    /// ULID of the originating audit record.
    pub event_id: AuditEventId,
    /// Typed event kind.
    pub event_kind: AuditEventKind,
    /// Policy epoch in force when the event was emitted.
    pub policy_epoch: PolicyEpoch,
    /// Wall-clock emission time (kernel monotonic + offset).
    pub emitted_at_ms: u64,
    /// Pre-rendered single-line summary (the same string `raxis log` shows).
    pub human_summary: String,
    /// Severity hint (channel impls MAY map to per-channel priority).
    pub severity: NotificationSeverity,
    /// Full JSON of the audit event, for channels that attach structured data.
    pub structured_payload: serde_json::Value,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ChannelKind {
    Shell,
    File,
    Email,
    Webhook,
    Slack,    // V3+; reserved here so v2 schema doesn't need a migration
    PagerDuty,
    Teams,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NotificationSeverity {
    /// Operator must see this immediately. Routed to all channels regardless
    /// of route ACL (e.g., kernel boot failure detected by self-test).
    Critical,
    /// Security-relevant; route ACL applies but channels SHOULD prioritise.
    Security,
    /// Default operational visibility.
    Operational,
    /// Low-volume informational; many routes silence this.
    Info,
}

#[derive(Debug, Clone, Copy)]
pub enum DispatchClass {
    Fast,
    Slow,
}

#[derive(Debug, Clone)]
pub enum DeliveryReceipt {
    /// Successfully delivered. `transport_id` is the SMTP `Message-Id`,
    /// HTTP response body's id field, etc. — written to the audit record.
    Delivered { transport_id: String, latency_ms: u32 },
    /// Already delivered on a prior attempt (idempotency hit). Treated as
    /// success by the dispatcher; an `AlreadyDelivered` audit subevent is
    /// emitted at INFO level.
    AlreadyDelivered { original_seq: EventSeq },
    /// Channel rendered the payload but suppressed it because of a
    /// channel-specific filter (e.g., `Severity::Info` below threshold).
    Suppressed { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("upstream rejected payload: {code} {message}")]
    Rejected { code: String, message: String },

    #[error("upstream unreachable: {reason}")]
    Unreachable { reason: String },

    #[error("authentication failed: {reason}")]
    AuthFailed { reason: String },

    #[error("rate-limited; retry_after_ms={retry_after_ms:?}")]
    RateLimited { retry_after_ms: Option<u64> },

    #[error("payload size {observed_bytes} exceeds channel max {max_bytes}")]
    PayloadTooLarge { observed_bytes: usize, max_bytes: usize },

    #[error("delivery timed out after {elapsed_ms}ms")]
    Timeout { elapsed_ms: u32 },

    #[error("internal error: {0}")]
    Internal(#[source] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub reachable: bool,
    pub auth_ok: bool,
    pub round_trip_ms: u32,
    pub server_banner: Option<String>,
}
```

### §2.3 Channel-kind impls

#### §2.3.1 `ShellChannel` (refactored from v1)

**Canonical home:** `crates/raxis-notification-shell/src/lib.rs`.

Pure file-append. `target` is `<data_dir>/notifications/inbox.jsonl` by default; the operator views via `raxis inbox` (`cli-readonly.md §5.5.16`).

- `dispatch_class` = `Fast`.
- `max_payload_bytes` = `usize::MAX` (file system bounded).
- `probe()` opens the target with `O_APPEND | O_CREAT`, writes a no-op marker line, returns `Ok`.
- `deliver()` writes one JSON line per event (the v1 schema), `fsync`-best-effort.

#### §2.3.2 `FileChannel` (refactored from v1)

Identical to Shell except `target` is operator-supplied. Used for piping to journald, syslog, sidecar tailers.

#### §2.3.3 `EmailChannel` (NEW v2)

**Canonical home:** `crates/raxis-notification-email/src/lib.rs`.

Holds `Arc<dyn CredentialBackend>` (resolves the SMTP cred at deliver-time, not boot, so credential rotation works without restart). Maintains a per-channel-id keep-alive SMTP connection (re-opened on idle > 5 min or on EHLO failure) so a burst of events doesn't pay the TLS handshake cost N times.

**Render path:**

1. Build RFC 5322 headers:
   ```yaml
   From:        <channel.from_address>
   To:          <channel.to_addresses, comma-joined>
   Subject:     [RAXIS:{severity}] {event_kind}: {short_summary}
   Message-Id:  <{event_seq}.{event_id}@raxis-kernel>
   X-RAXIS-Event-Seq: {event_seq}
   X-RAXIS-Policy-Epoch: {policy_epoch}
   X-RAXIS-Severity: {severity}
   Date:        <RFC 2822 date from emitted_at_ms>
   MIME-Version: 1.0
   Content-Type: multipart/alternative; boundary="raxis-{event_id}"
   ```

2. `text/plain` part: `human_summary` plus a "Full audit event:" footer with the JSON pretty-printed. Capped at 50 KiB.

3. `application/json` attachment named `audit-{event_seq}.json` with the full `structured_payload`. Capped at 250 KiB; truncated with a clearly marked `"_truncated": true` field if it would exceed.

4. SMTP DATA: deliver to the relay configured in `[[notifications.channels.email]].smtp_relay` using the cred resolved at step 0. Authenticate per `auth_method` (`Plain`, `Login`, `Xoauth2`). STARTTLS mandatory unless `smtp_relay` ends in `:465` (implicit TLS).

5. On `250 OK`, emit `NotificationDelivered { channel_id, event_seq, transport_id: message_id_from_response, latency_ms }`. On any non-`2xx` SMTP code, emit `NotificationDeliveryFailed { channel_id, event_seq, reason: "smtp:{code} {text}" }` and return `ChannelError::Rejected`.

**Idempotency:** the relay-side dedup key is `Message-Id`. RAXIS-side, the dispatcher consults the existing `notification_dispatch` table (see §6.5) before calling `deliver`; an entry with `(event_seq, channel_id, status=Delivered)` short-circuits to `DeliveryReceipt::AlreadyDelivered`.

**Connection management:**

- One persistent connection per channel-id (`self: Arc<Mutex<Option<SmtpConnection>>>`).
- On `deliver()`, lock; if connection is None or last-used > 5 min, open a new one (EHLO + STARTTLS + AUTH).
- Send the message; release the lock.
- On error, drop the connection (next `deliver` will reopen).

**Rate-limit class:** `Slow`. The dispatcher serialises calls per channel-id with a 4-worker pool.

**`max_payload_bytes`:** 300 KiB (50 KiB summary + 250 KiB JSON).

#### §2.3.4 `WebhookChannel` (NEW v2)

**Canonical home:** `crates/raxis-notification-webhook/src/lib.rs`.

HTTPS POST with HMAC-SHA256 of `(timestamp_ms || ":" || body)` in `X-RAXIS-Signature: t={ts},v1={hex}` header. Operator-side verifier rejects requests where `|now() - ts| > 5 min`. HTTP `2xx` = delivered; `4xx` non-`429` = `Rejected` (no retry); `429` and `5xx` = retry per the dispatcher's exponential backoff.

`max_payload_bytes` = 1 MiB (HTTPS PUT can carry the full structured payload).

### §2.4 Dispatcher (kernel-side, concrete — not abstracted)

**Canonical home:** `kernel/src/notifications/dispatch.rs`.

The dispatcher is **not** a trait. It enforces the R-7 audit-emit ordering (`NotificationDelivered` post-commit per `kernel-store.md §2.5.2`), idempotency on `(event_seq, channel_id)`, per-channel concurrency caps, and graceful kernel-shutdown drain. All of those are kernel invariants and must be uniform across channel impls.

```rust
//! kernel/src/notifications/dispatch.rs

pub struct NotificationDispatcher {
    channels: HashMap<String, Arc<dyn OperatorNotificationChannel>>,
    routes: HashMap<AuditEventKind, Vec<String>>,           // event_kind -> channel ids
    default_channels: Vec<String>,
    store: Arc<Store>,                                       // for the dispatch idempotency table
    audit: Arc<dyn AuditSink>,
    policy_epoch: AtomicU32,
}

impl NotificationDispatcher {
    pub async fn dispatch(&self, payload: NotificationPayload) {
        let channel_ids = self.routes
            .get(&payload.event_kind)
            .unwrap_or(&self.default_channels);

        for channel_id in channel_ids {
            let channel = self.channels.get(channel_id).cloned();
            let payload = payload.clone();
            let store = self.store.clone();
            let audit = self.audit.clone();

            // Per dispatch_class, run on a per-channel-id worker pool or fan out unbounded.
            self.scheduler_for(channel_id).spawn(async move {
                let already = store.notifications_check_dispatched(
                    payload.event_seq, channel_id
                ).await;
                if already { return; }

                let started = Instant::now();
                let result = tokio::time::timeout(
                    Duration::from_secs(60),
                    channel.deliver(&payload),
                ).await;

                let outcome = match result {
                    Ok(Ok(receipt)) => {
                        store.notifications_record_delivered(
                            payload.event_seq, channel_id, &receipt
                        ).await;
                        AuditEventKind::NotificationDelivered { /* ... */ }
                    }
                    Ok(Err(e)) => AuditEventKind::NotificationDeliveryFailed {
                        channel_id: channel_id.clone(),
                        event_seq: payload.event_seq,
                        reason: format!("{e}"),
                    },
                    Err(_elapsed) => AuditEventKind::NotificationDeliveryFailed {
                        channel_id: channel_id.clone(),
                        event_seq: payload.event_seq,
                        reason: "timeout".into(),
                    },
                };
                audit.emit(outcome).await;
            });
        }
    }
}
```

Key properties:

- **Never blocks the kernel commit path.** `dispatch` returns immediately after spawning per-channel tasks. Handler failure cannot abort the originating SQLite transaction (per `kernel-core.md §2.3` step 5).
- **Idempotent.** The `notification_dispatch` table (see §6.5) records every `(event_seq, channel_id, status)`. A retry checks before delivering.
- **Bounded concurrency.** Slow channels share a 4-worker pool per channel-id; Fast channels run unbounded.
- **Graceful drain.** On `SIGTERM`, the kernel stops accepting new dispatches but waits up to 30 s for in-flight `Slow` deliveries. Pending events that don't drain emit `NotificationDeliveryFailed { reason: KernelShutdownDrainTimeout }`.

### §2.5 Audit events for Goal A

| Event kind | When emitted | Required fields |
| --- | --- | --- |
| `NotificationDispatched` | Per `(event_seq, channel_id)` pair the dispatcher takes responsibility for | `event_seq`, `channel_id`, `event_kind`, `policy_epoch`, `dispatched_at_ms` |
| `NotificationDelivered` | On `Ok(DeliveryReceipt::Delivered)` from a channel | `event_seq`, `channel_id`, `transport_id`, `latency_ms`, `delivered_at_ms` |
| `NotificationDeliveryFailed` | On any `Err(ChannelError)` or timeout | `event_seq`, `channel_id`, `reason` (typed string), `error_class` (`Rejected`\|`Unreachable`\|`AuthFailed`\|`RateLimited`\|`PayloadTooLarge`\|`Timeout`\|`Internal`), `failed_at_ms` |
| `NotificationChannelDegraded` | On boot probe failure | `channel_id`, `kind`, `probe_reason` |
| `NotificationTestSent` | Operator runs `raxis notify test` | `channel_id`, `actor`, `triggered_at_ms` |

These events follow the post-commit emission ordering in `kernel-store.md §2.5.2` — they are emitted **after** the parent transaction (e.g., the escalation that triggered the notification) is committed, so a delivery failure can never roll back the parent state.

---

## §3 — Goal B: SMTP credential proxy (agent egress)

This section is the canonical home for `proxy_type = "smtp"`. The structural shape mirrors [`credential-proxy.md §3.1`](credential-proxy.md) (k8s) and §4.1 (PostgreSQL TCP proxying) — re-read those for the surrounding context.

### §3.1 Threat model

The agent VM is **untrusted**. Every byte the agent writes to the SMTP socket may be hostile. The proxy's job is to:

1. **Prevent credential exfiltration.** The agent must never observe the SMTP password / OAuth2 token. The proxy authenticates upstream; the agent's SMTP session sees no AUTH offering.
2. **Prevent `From:` spoofing.** Agents can use SMTP to deliver messages that *look like* they came from the operator (or any other identity), gaining inbox-trust they don't deserve. The proxy substitutes a fixed `from_address` from policy. The agent's `MAIL FROM` is recorded in audit but discarded on the wire.
3. **Prevent open-relay abuse.** A compromised agent could weaponise the relay to send phishing or spam. `allowed_recipient_domains` and `allowed_recipient_addresses` allowlists, plus per-task and per-session rate limits, structurally bound this.
4. **Prevent plaintext-credential exposure.** STARTTLS or implicit TLS (port 465) is mandatory. If the upstream rejects STARTTLS, the proxy aborts the session and audits.
5. **Provide forensic visibility.** Every send produces a `SmtpProxyMessageSent` audit record with the recipient list, body SHA-256, message size, and (optionally) the body archived in the immutable artifact store.

### §3.2 Schema (Rust types in `crates/policy/`)

```rust
//! crates/policy/src/proxy/smtp.rs

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpProxyConfig {
    pub auth_method: SmtpAuthMethod,
    /// The `From:` address the proxy substitutes on every outbound message.
    /// Agent's `MAIL FROM` is overridden, not echoed.
    pub from_address: EmailAddress,
    /// If true, proxy MUST negotiate STARTTLS before AUTH; failure aborts.
    /// If false, `real_target` MUST end in `:465` (implicit TLS); enforced
    /// by `PolicyBundle::validate`.
    pub require_starttls: bool,
    /// Recipient domain allowlist. Non-empty (validated). Case-insensitive
    /// suffix match (`.example.com` matches `ops.example.com`).
    pub allowed_recipient_domains: Vec<DomainName>,
    /// Optional further restriction to specific addresses. If present,
    /// recipients MUST match both the domain allowlist AND this set.
    pub allowed_recipient_addresses: Option<Vec<EmailAddress>>,
    /// Maximum DATA payload size in bytes. Default 524_288 (512 KiB).
    pub max_message_bytes: u32,
    /// Maximum recipients per message. Default 5; max 50 (validated).
    pub max_recipients_per_message: u8,
    /// If true, the proxy archives the full body to the immutable artifact
    /// store (`immutable-artifact-store.md`) and emits the artifact CID in
    /// the audit record. Default false (digest-only audit).
    pub audit_message_bodies: bool,
    /// Per-session rate limit. Counts messages sent within the rolling window.
    pub rate_limit_per_session: RateLimit,
    /// Per-task rate limit (stricter; defends against a runaway single task).
    pub rate_limit_per_task: RateLimit,
}

#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpAuthMethod {
    /// AUTH PLAIN — base64-encoded username/password (RFC 4616).
    Plain,
    /// AUTH LOGIN — historical Microsoft variant; same security.
    Login,
    /// AUTH XOAUTH2 — bearer token in SASL XOAUTH2 string (Gmail, Office365).
    /// Token resolution goes through `CredentialBackend::resolve_oauth2`.
    Xoauth2,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub count: u32,
    pub window_seconds: u32,
}
```

### §3.3 `policy.toml` schema

```toml
# Goal B: agent SMTP egress
[[permitted_credentials]]
name           = "smtp-ops-relay"
environment    = "ops-notifications"
description    = "Agent-controlled SMTP relay; substitutes From, allowlists recipients"
proxy_types    = ["smtp"]
real_target    = "smtp.example.com:587"

[permitted_credentials.smtp]
auth_method                 = "plain"
from_address                = "raxis-agent@example.com"
require_starttls            = true
allowed_recipient_domains   = ["example.com", "ops.example.com"]
allowed_recipient_addresses = []                                           # optional further restriction
max_message_bytes           = 524288
max_recipients_per_message  = 5
audit_message_bodies        = false
rate_limit_per_session      = { count = 10, window_seconds = 3600 }
rate_limit_per_task         = { count = 3,  window_seconds = 600  }
```

### §3.4 `plan.toml` schema

```toml
[[tasks.credentials]]
name       = "smtp-ops-relay"
proxy_type = "smtp"
mount_as   = "SMTP_URL"            # → smtp://localhost:2525 (no auth, plain wire — STARTTLS happens proxy-to-upstream)
```

The kernel allocates a port from the credential-proxy reserved range ([`credential-proxy.md §13.3`](credential-proxy.md) — extended in §6.4 of this spec).

### §3.5 Wire flow

```text
Agent (in VM)                    SMTP proxy (kernel-side)              Real upstream relay
  -- TCP connect localhost:2525 --→
                                    (open upstream conn)
                                    -- TCP --→
                                                                        ←-- 220 smtp.example.com ESMTP
                                    -- EHLO --→
                                                                        ←-- 250-STARTTLS, AUTH PLAIN, ...
                                    -- STARTTLS --→
                                                                        ←-- 220 Ready
                                    (TLS handshake)
                                    -- EHLO --→
                                                                        ←-- 250-AUTH PLAIN, ...
                                    -- AUTH PLAIN <kernel-resolved> --→
                                                                        ←-- 235 Authenticated
  ←-- 220 RAXIS SMTP proxy --
  -- EHLO agent.local --→
  ←-- 250-PIPELINING\n250-8BITMIME\n250 SIZE 524288 --
       (no AUTH offered to agent; SIZE = max_message_bytes)
  -- MAIL FROM:<agent-anything@x> --→
       (proxy: discard agent value, substitute policy from_address upstream)
                                    -- MAIL FROM:<raxis-agent@example.com> --→
                                                                        ←-- 250 OK
  ←-- 250 OK --
  -- RCPT TO:<reviewer@example.com> --→
       (proxy: check domain "example.com" ∈ allowed_recipient_domains)
       (proxy: check addr ∈ allowed_recipient_addresses if non-empty)
       (proxy: increment recipients_in_message; refuse if > max_recipients_per_message)
                                    -- RCPT TO:<reviewer@example.com> --→
                                                                        ←-- 250 OK
  ←-- 250 OK --
  -- RCPT TO:<attacker@evil.example.org> --
       (proxy: domain "evil.example.org" ∉ allowed_recipient_domains)
       (proxy: emit SmtpProxyMessageRejected { reason: "RecipientDomainNotAllowed" })
       (proxy: do NOT forward to upstream)
  ←-- 550 5.7.1 Recipient domain not in allowlist --
  -- DATA --→
       (proxy: forward; capture bytes for SHA-256 + size enforcement)
                                    -- DATA --→
                                                                        ←-- 354 Start mail input
  ←-- 354 Start mail input --
  -- <body bytes ...>\r\n.\r\n --→
       (proxy: streams to upstream, hashes incrementally, aborts at max_message_bytes)
       (proxy: increment session/task counters, check rate limits BEFORE final response forward)
                                    -- <body> --→
                                                                        ←-- 250 OK Queued as <id>
       (proxy: emit SmtpProxyMessageSent { ... })
  ←-- 250 OK Queued as <id> --
  -- QUIT --→
                                    (proxy keeps upstream conn open for next message in session)
  ←-- 221 Bye --
```

### §3.6 SMTP-server side (proxy to agent)

**Canonical home:** `crates/raxis-cred-proxy/src/smtp/server.rs`.

Minimal SMTP server, NOT a full relay. Only commands handled:

| Command | Behaviour |
| --- | --- |
| `HELO` / `EHLO` | Respond with `RAXIS-Proxy-1.0`, advertise `PIPELINING`, `8BITMIME`, `SIZE <max_message_bytes>`. **Never advertise AUTH.** |
| `MAIL FROM:<…>` | Accept `250 OK`. Record agent-supplied value for audit; discard from the wire. |
| `RCPT TO:<…>` | Validate against allowlist; either `250 OK` (forward upstream) or `550` (reject; emit `SmtpProxyMessageRejected`). |
| `DATA` | Stream bytes to upstream, enforce size, hash for audit. Convert agent's CRLF-terminated dot-stuffed body verbatim. |
| `RSET` | Forward upstream; reset proxy state. |
| `NOOP` | `250 OK`. |
| `QUIT` | `221 Bye`. |
| `VRFY`, `EXPN`, `STARTTLS`, `AUTH` (anything else) | Reject `502 Command not implemented`. **No auth surface to the agent.** |

The agent sees a deliberately limited SMTP — exactly one verb-flow (deliver one or more messages, then quit). No relay mode, no per-recipient delivery-status notifications, no header injection capability.

### §3.7 Header sanitisation

The proxy MUST strip and rewrite the following headers in the `DATA` body before forwarding:

| Header | Action | Rationale |
| --- | --- | --- |
| `From:` | **Replace** with `<from_address>` from policy | Prevents agent from spoofing operator/other identity |
| `Sender:` | **Drop** | Companion to `From:`; same threat |
| `Return-Path:` | **Drop** (relay rewrites it anyway) | Standard practice |
| `Bcc:` | **Drop entirely**; the proxy emits one DATA per RCPT internally if Bcc was present in the SMTP envelope, but the body header MUST NOT contain Bcc | Prevents agent leaking recipient lists into bodies of public CCs |
| `Resent-From:`, `Resent-Sender:` | Drop | Same spoofing concern |
| `Received:` | Drop any agent-injected `Received:` headers; keep only those added by the proxy and upstream | Agent could inject misleading routing headers |
| `Message-Id:` | Replace with `<{task_id}.{rng}@raxis-proxy>` | Stable, attributable Message-Id |
| All other headers | Forward verbatim | `Subject`, `Date`, `MIME-Version`, `Content-Type`, `Content-Disposition`, `In-Reply-To`, `References`, `X-*`, etc. |

The header rewrite happens in a streaming parser (read until `\r\n\r\n`, parse headers, rewrite, emit, then stream the body verbatim). The parser is in `crates/raxis-smtp-client/src/header.rs` and is tested against an RFC-5322 corpus.

### §3.8 Rate limiting and burst protection

Two independent counters per credential proxy:

- **Per-task:** `rate_limit_per_task` (default 3 messages / 600 s). Defends against a single runaway task that has decided email is its solution to everything. Counter persists in `kernel/src/store/smtp_rate.rs::SmtpProxyRateTable`, keyed by `(task_id, credential_name)`.
- **Per-session:** `rate_limit_per_session` (default 10 messages / 3600 s). Defends against a hostile-but-low-and-slow session that splits its emails across many tasks. Keyed by `(session_id, credential_name)`.

Both counters use a sliding-window-with-bucket implementation (10 buckets per window for memory bound). When either is exceeded:

- Reject the in-progress `RCPT TO` (or the next `RCPT TO` if mid-message) with `421 4.7.0 Rate limit exceeded; retry after N seconds`.
- Emit `SmtpProxyRateLimited { task_id, session_id, credential_name, scope: "task" | "session", count_in_window, window_seconds, retry_after_seconds }`.
- The agent's SMTP client receives a `421` and is expected to back off (most do; misbehaving clients get the same `421` on the next attempt — the proxy never crashes-on-flood).

### §3.9 Audit events for Goal B

| Event kind | When emitted | Required fields |
| --- | --- | --- |
| `SmtpProxyConnected` | Agent opens the local SMTP socket | `task_id`, `session_id`, `credential_name`, `proxy_port`, `connected_at_ms` |
| `SmtpProxyMessageSent` | Upstream returns `2xx` to `<CRLF>.<CRLF>` end-of-DATA | `task_id`, `session_id`, `credential_name`, `from_address` (kernel-substituted), `agent_supplied_from` (recorded but overridden), `recipients` (final allowlist-passed set), `subject_sha256`, `body_sha256`, `body_size_bytes`, `body_artifact_cid` (if `audit_message_bodies = true`), `upstream_message_id`, `latency_ms` |
| `SmtpProxyMessageRejected` | Proxy refuses any phase before `250 OK` for end-of-DATA | `task_id`, `session_id`, `credential_name`, `phase` (`Connect` \| `MailFrom` \| `RcptTo` \| `Data` \| `BodyHeaderRewrite`), `reason` (typed), `agent_visible_smtp_code`, `rejected_at_ms` |
| `SmtpProxyRateLimited` | Per-task or per-session counter exceeded | per §3.8 above |
| `SmtpProxyUpstreamError` | Upstream returned an error the proxy could not satisfy | `task_id`, `credential_name`, `upstream_code`, `upstream_text`, `phase` |
| `SmtpProxyDisconnected` | Agent closes socket OR proxy times out (60 s idle) | `task_id`, `session_id`, `credential_name`, `messages_sent_this_session`, `disconnect_reason` (`AgentQuit` \| `ProxyIdleTimeout` \| `UpstreamFailure` \| `KernelShutdown`) |

### §3.10 NNSP additions (agent-facing prompt)

[`kernel-mechanics-prompt.md §3`](kernel-mechanics-prompt.md) gains an SMTP block when the task has an `[[tasks.credentials]]` entry with `proxy_type = "smtp"`:

```python
## SMTP Proxy

You have access to an SMTP relay at $SMTP_URL (e.g., smtp://localhost:2525).
You may send email as part of your task.

CONSTRAINTS:
- The From: address is fixed to <{from_address}>. Any From: header you set
  will be silently replaced.
- Recipients are restricted to: <{allowed_recipient_domains, comma-joined}>.
  RCPT TO addresses outside this allowlist are rejected with `550 5.7.1`.
- Maximum {max_message_bytes} bytes per message, {max_recipients_per_message}
  recipients per message.
- Rate limited to {rate_limit_per_task.count} messages per {rate_limit_per_task.window_seconds}s
  for this task ({rate_limit_per_session.count}/{rate_limit_per_session.window_seconds}s for the session).
- AUTH commands are rejected; you don't need credentials. The proxy
  authenticates upstream on your behalf.
- BCC headers are stripped. Use multiple RCPT TO entries instead.
- Every message you send is recorded with subject hash, body hash, and
  recipient list. The operator can audit anything you send.

USAGE PATTERN (Python):
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["To"] = "reviewer@example.com"
    msg["Subject"] = "Build report"
    msg.set_content("...")
    with smtplib.SMTP("localhost", 2525) as s:
        s.send_message(msg)
```

The proxy reads the policy at provisioning and templates the constraints into the prompt — operators can't lie to the agent about its own constraints; the prompt is generated from the same `SmtpProxyConfig` that the proxy enforces.

---

## §4 — CLI surface

### §4.1 Goal A — Operator notification CLI

These commands wrap edits to `policy.toml` and call the existing `policy sign` ceremony (`cli-ceremony.md §4.1 policy sign`). The signed policy bundle remains the source of truth — the CLI provides ergonomics, not bypass.

#### §4.1.1 Channel management

```text
# List channels (read-only; reads active PolicyBundle).
raxis notify channel list [--kind email|webhook|shell|file] [--json]

# Add an email channel. Edits policy.toml in place; prompts for confirmation
# and re-signs with the operator's key.
raxis notify channel add <channel-id> \
    --kind email \
    --to <addr>[,<addr>...] \
    --from <addr> \
    --smtp-relay smtps://smtp.example.com:587 \
    --auth-method plain|login|xoauth2 \
    --cred-ref <smtp-cred-name>

# Add a webhook channel.
raxis notify channel add <channel-id> \
    --kind webhook \
    --target https://hooks.example.com/raxis \
    --cred-ref <hmac-cred-name>

# Delete a channel. Refuses if any [[notifications.routes]] still
# references it; operator must `raxis notify route delete` first.
raxis notify channel delete <channel-id>

# Synchronous probe — same code path as boot probe.
raxis notify channel probe <channel-id>

# Send a synthetic event through the channel.
# Emits AuditEventKind::NotificationTestSent regardless of outcome.
raxis notify test --channel <channel-id> [--severity Operational|Security|Critical|Info]
```

#### §4.1.2 Route management

```bash
raxis notify route list [--event-kind <kind>] [--channel <channel-id>] [--json]

raxis notify route add \
    --event-kind EscalationSubmitted \
    --channel ops-email,audit-mirror

raxis notify route delete \
    --event-kind EscalationSubmitted \
    --channel ops-email
```

#### §4.1.3 Notification credential management

These manage the SMTP / webhook credentials the *kernel itself* uses to talk to upstream channels. Stored in `<data_dir>/credentials/<cred-ref>.notify-cred` (mode `0600`, kernel-readable only).

```text
# Add an SMTP credential. Password read from STDIN, never argv.
raxis notify credential add <cred-ref> \
    --kind smtp-plain \
    --username <user> \
    < <(stty -echo; read -s p; echo "$p")

# Or for OAuth2:
raxis notify credential add <cred-ref> \
    --kind smtp-xoauth2 \
    --username <user>@<domain> \
    --refresh-token-from-stdin

raxis notify credential list [--json]
raxis notify credential delete <cred-ref>
raxis notify credential rotate <cred-ref>           # prompts for new secret on stdin
```

**Why a separate `notify credential` namespace** (rather than reusing `raxis credential`):

| Option | Pros | Cons |
| --- | --- | --- |
| Reuse `raxis credential add` (existing) | Single namespace | Conflates "credential the kernel uses for itself" with "credential the kernel proxies for an agent". The latter is referenced from `[[permitted_credentials]]` and bound to `proxy_type`; the former is referenced from `[[notifications.channels]]` and never enters a VM. Mixing them is a category error. |
| Separate `raxis notify credential` namespace | Mirrors the trust boundary (operator-only credentials vs operator-mediated-for-agent credentials) | One more command surface |

**Decision:** separate namespace. The trust boundary is real, and surfacing it in the CLI helps operators reason about who can read each credential. The on-disk layout shares the `<data_dir>/credentials/` directory but uses distinct extensions: `<name>.cred` (agent-egress, referenced by `proxy_type`) vs `<name>.notify-cred` (kernel-channel, referenced by `cred_ref`).

### §4.2 Goal B — Agent SMTP proxy CLI

These reuse the existing `raxis credential add` flow — the credential itself looks like any other Tier-2 credential and is managed identically. The only thing that's new is the schema validator for `proxy_type = "smtp"` and the per-credential SMTP config block.

```text
# Add an SMTP credential the proxy will use to authenticate upstream.
# Password read from STDIN.
raxis credential add smtp-ops-relay --proxy-type smtp \
    --auth-method plain \
    --username service@example.com \
    --password-stdin

# After this, the operator edits [[permitted_credentials]] in policy.toml
# (or uses `raxis credential permit`) to set the [permitted_credentials.smtp]
# block with from_address, allowlists, rate limits, etc.
```

The existing `raxis credential list`, `raxis credential delete`, `raxis credential rotate` commands gain `proxy_type = "smtp"` support transparently.

---

## §5 — Wiring at boot

### §5.1 Construction order (extends [`extensibility-traits.md §9.1`](extensibility-traits.md))

The seven-trait composition order becomes:

```text
1. Load policy.toml + verify operator signature              (concrete)
2. Open store (kernel.db)                                    (concrete)
3. Construct AuditSink (§5)                                  ← needed by every later step
4. Construct CredentialBackend (§4)                          ← uses AuditSink
5. Construct InferenceRouter (§7)                            ← uses CredentialBackend
6. Construct IsolationBackend (§3) + verify_isolation_guarantee
7. Construct DomainAdapter (§2)                              ← uses IsolationBackend
8. Construct OperatorTransport (§6)                          ← bound last in the listener path
9. Construct OperatorNotificationChannel set (§6.5 NEW)      ← uses CredentialBackend + AuditSink
10. Probe every channel (best-effort; degraded ok)
11. Run intent admission loop
```

Step 9 happens AFTER `OperatorTransport::bind` (operators can connect) but BEFORE `intent admission loop` (so any escalation submitted in the first second of operation has a working dispatcher). Step 10 runs in parallel — channel probes timeout-bounded at 10 s each, results logged via `NotificationChannelDegraded` for failures.

### §5.2 `HandlerContext` extension

```rust
// kernel/src/handlers/mod.rs (extended from extensibility-traits.md §9.2)

pub struct HandlerContext {
    // existing fields …
    pub audit_sink:        Arc<dyn AuditSink>,
    pub credentials:       Arc<dyn CredentialBackend>,
    pub inference_router:  Arc<dyn InferenceRouter>,
    pub isolation:         Arc<dyn IsolationBackend>,
    pub domain:            Arc<dyn DomainAdapter<...>>,
    pub operator_transport: Arc<dyn OperatorTransport>,

    // V2 NEW (§6.5):
    pub notifications:     Arc<NotificationDispatcher>,
}
```

The dispatcher (concrete; per §2.4) wraps `Vec<Arc<dyn OperatorNotificationChannel>>`. Handlers call `ctx.notifications.dispatch(payload)` after the parent SQLite commit. They never see the trait directly.

---

## §6 — Storage additions

### §6.1 New tables

```sql
-- crates/store/src/notifications.rs

-- Per-(event_seq, channel_id) idempotency table. Survives kernel restart.
CREATE TABLE IF NOT EXISTS notification_dispatch (
    event_seq         INTEGER NOT NULL,
    channel_id        TEXT    NOT NULL,
    status            TEXT    NOT NULL CHECK (status IN ('Dispatched','Delivered','Failed','Suppressed')),
    transport_id      TEXT,                                   -- SMTP Message-Id, etc.
    failure_reason    TEXT,
    failure_class     TEXT,                                   -- ChannelError discriminant
    attempts          INTEGER NOT NULL DEFAULT 1,
    first_attempt_ms  INTEGER NOT NULL,
    last_attempt_ms   INTEGER NOT NULL,
    PRIMARY KEY (event_seq, channel_id)
) STRICT;

-- Per-session and per-task SMTP rate-limit state.
CREATE TABLE IF NOT EXISTS smtp_proxy_rate_buckets (
    bucket_key        TEXT    NOT NULL,                       -- "task:<task_id>:<cred>" or "session:<session_id>:<cred>"
    window_start_ms   INTEGER NOT NULL,
    bucket_index      INTEGER NOT NULL,                       -- 0..9 (10 buckets per window)
    count             INTEGER NOT NULL,
    PRIMARY KEY (bucket_key, window_start_ms, bucket_index)
) STRICT;

-- Channel boot-probe state. Reflects the last probe outcome; written by
-- `raxis notify channel probe` and the boot probe.
CREATE TABLE IF NOT EXISTS notification_channel_health (
    channel_id        TEXT PRIMARY KEY,
    last_probe_ms     INTEGER NOT NULL,
    reachable         INTEGER NOT NULL,
    auth_ok           INTEGER NOT NULL,
    round_trip_ms     INTEGER NOT NULL,
    server_banner     TEXT,
    last_error        TEXT
) STRICT;
```

### §6.2 GC

The periodic kernel maintenance loop (the one that does git orphan sweep + cgroup sweep) gains two new sweeps:

- `notification_dispatch`: rows with `last_attempt_ms < now() - retention_days * 86_400_000` are pruned (default 90 days). Keeps the table from growing unboundedly. Retention is configurable per `policy.toml [notifications].retention_days`.
- `smtp_proxy_rate_buckets`: rows with `window_start_ms + window_seconds*1000 < now() - 86_400_000` are pruned (older than the longest configured window + 24 h grace).

Both sweeps run inside `BEGIN IMMEDIATE` transactions so they cannot interleave with active dispatch / send.

---

## §7 — Implementation phases (mergeable PRs)

Phased to be reviewable, each independently shippable.

**Phase A — Trait crate.** Create `crates/raxis-notification/src/lib.rs` with the trait, error types, and conformance kit. Add `crates/raxis-notification-shell/` and `crates/raxis-notification-file/` as default impls re-exporting the v1 logic. The kernel does not depend on them yet. (~1 day, single PR.)

**Phase B — Dispatcher concrete.** `kernel/src/notifications/dispatch.rs`. Wires the existing v1 dispatcher behind the trait; idempotency on `notification_dispatch` table. One PR, ~400 LoC.

**Phase C — `EmailChannel`.** `crates/raxis-notification-email/src/lib.rs`, depending on `crates/raxis-smtp-client/`. Conformance kit + integration tests against a `letterbox`/`maildrop` fixture container. (~3 days.)

**Phase D — `WebhookChannel`.** `crates/raxis-notification-webhook/src/lib.rs`. (~1 day.)

**Phase E — SMTP proxy server.** `crates/raxis-cred-proxy/src/smtp/server.rs` plus header-rewrite parser in `crates/raxis-smtp-client/src/header.rs`. (~5 days; SMTP-server side is the most error-prone surface.)

**Phase F — CLI.** `cli/src/notify.rs` for Goal A; extension of `cli/src/credential.rs` for Goal B SMTP variant. (~2 days.)

**Phase G — Integration tests.** `kernel/tests/notifications_smtp_e2e.rs`, `kernel/tests/smtp_proxy_e2e.rs` against the maildrop fixture. (~2 days.)

**Phase H — Documentation rollout.** This spec; cross-references in cli-ceremony, cli-readonly, policy-plan-authority, kernel-mechanics-prompt, v2-deep-spec, kernel-lifecycle. (Concurrent with code phases.)

Total surface: ~14–17 calendar-days for the full V2 email subsystem.

---

## §8 — Files to create

| Path | Role |
| --- | --- |
| `crates/raxis-notification/src/lib.rs` | NEW — `OperatorNotificationChannel` trait, `ChannelError`, `NotificationPayload`, conformance kit |
| `crates/raxis-notification/src/conformance.rs` | NEW — generic conformance test fixture for any impl |
| `crates/raxis-notification-shell/src/lib.rs` | NEW — `ShellChannel` impl (refactored from v1) |
| `crates/raxis-notification-file/src/lib.rs` | NEW — `FileChannel` impl (refactored from v1) |
| `crates/raxis-notification-email/src/lib.rs` | NEW — `EmailChannel` impl |
| `crates/raxis-notification-webhook/src/lib.rs` | NEW — `WebhookChannel` impl |
| `crates/raxis-smtp-client/src/lib.rs` | NEW — Async SMTP client (TLS, AUTH, MAIL/RCPT/DATA, header-rewrite parser) |
| `crates/raxis-smtp-client/src/header.rs` | NEW — RFC 5322 streaming header parser/rewriter |
| `crates/raxis-smtp-client/tests/headers.rs` | NEW — RFC 5322 corpus tests |
| `crates/raxis-cred-proxy/src/smtp/server.rs` | NEW — SMTP-server side of the agent proxy |
| `crates/raxis-cred-proxy/src/smtp/policy.rs` | NEW — `SmtpProxyConfig` validation + recipient allowlist matcher |
| `crates/raxis-cred-proxy/src/smtp/rate.rs` | NEW — Sliding-window-bucket rate limiter |
| `crates/raxis-cred-proxy/tests/smtp_e2e.rs` | NEW — End-to-end agent SMTP egress tests against maildrop fixture |
| `crates/policy/src/proxy/smtp.rs` | NEW — `SmtpProxyConfig` deserialiser, validator |
| `crates/policy/src/notifications.rs` | NEW — `[[notifications.channels.email]]` + `[[notifications.channels.webhook]]` deserialisers, validator |
| `kernel/src/notifications/dispatch.rs` | NEW — concrete dispatcher (idempotency, rate-class scheduling, drain-on-shutdown) |
| `kernel/src/notifications/mod.rs` | NEW — module root, re-exports the trait |
| `kernel/src/notifications/probe.rs` | NEW — boot-time probe + `raxis notify channel probe` handler |
| `kernel/tests/notifications_smtp_e2e.rs` | NEW — E2E for `EmailChannel` |
| `kernel/tests/smtp_proxy_e2e.rs` | NEW — E2E for `SmtpCredentialProxy` |
| `cli/src/notify/mod.rs` | NEW — `raxis notify` subcommand root |
| `cli/src/notify/channel.rs` | NEW — `notify channel add|delete|list|probe|test` |
| `cli/src/notify/route.rs` | NEW — `notify route add|delete|list` |
| `cli/src/notify/credential.rs` | NEW — `notify credential add|delete|list|rotate` |

## §9 — Files to change

| Path | Change |
| --- | --- |
| `kernel/src/handlers/mod.rs` | Extend `HandlerContext` with `notifications: Arc<NotificationDispatcher>`. Replace direct calls to v1 channel handlers with `ctx.notifications.dispatch(payload)` |
| `kernel/src/handlers/intent.rs` | At each post-commit notification site (escalation, path-scope override, key-revocation, plan-load, …), build `NotificationPayload` and dispatch |
| `kernel/src/main.rs` | Phase 9 of [`extensibility-traits.md §9.1`](extensibility-traits.md) — construct channels per policy, register with dispatcher |
| `kernel/src/policy_manager.rs` | On policy reload, refresh dispatcher's channel set + routes via `dispatcher.reconcile_with_policy()` |
| `kernel/src/maintenance.rs` | Add `notification_dispatch` GC sweep + `smtp_proxy_rate_buckets` GC sweep |
| `crates/store/src/notifications.rs` | NEW (per §6.1) — table DDL, helpers `notifications_check_dispatched`, `notifications_record_delivered`, `smtp_rate_increment`, `smtp_rate_check_and_increment` |
| `crates/store/src/lib.rs` | Re-export `notifications` module; bump schema version |
| `crates/store/migrations/V<N>__notifications.sql` | NEW migration with the three tables in §6.1 |
| `crates/policy/src/loader.rs` | Parse `[[notifications.credentials]]`, `[[notifications.channels.email]]`, `[[notifications.channels.webhook]]`, `[[permitted_credentials.smtp]]`; reject invalid configs |
| `crates/policy/src/bundle.rs` | Validate STARTTLS-or-implicit-TLS, allowlist non-empty, `from_address` parseable, recipient cap ≤ 50 |
| `crates/policy/src/error.rs` | Add `FAIL_NOTIFY_CHANNEL_INVALID`, `FAIL_NOTIFY_CRED_INVALID`, `FAIL_NOTIFY_ROUTE_REFERENCES_UNKNOWN_CHANNEL`, `FAIL_SMTP_PROXY_PLAINTEXT_REJECTED`, `FAIL_SMTP_PROXY_RECIPIENT_ALLOWLIST_EMPTY`, `FAIL_SMTP_PROXY_FROM_ADDRESS_INVALID`, `FAIL_SMTP_PROXY_RATE_LIMIT_INVALID` |
| `crates/raxis-cred-proxy/src/lib.rs` | Register the `smtp` proxy_type, route to `smtp::server` |
| `crates/raxis-cred-proxy/src/types.rs` | Add `Smtp` variant to `ProxyType` enum |
| `crates/audit/src/event.rs` | Add notification + SMTP-proxy audit event variants per §2.5 and §3.9 |
| `cli/src/main.rs` | Wire `notify` subcommand |
| [`raxis/specs/v2/extensibility-traits.md`](extensibility-traits.md) | Add `OperatorNotificationChannel` as 7th trait (§6.5 NEW); update §1.2 trait count, §9 boot order, §13.1 "Why seven", §11 cross-spec impacts |
| [`raxis/specs/v2/credential-proxy.md`](credential-proxy.md) | Add §3.6 SMTP proxy_type; update §11.1 schema, §13.3 reserved-port table, §6.2 NNSP additions |
| [`raxis/specs/v2/policy-plan-authority.md`](policy-plan-authority.md) | Schema additions for `[[notifications.credentials]]`, channel email/webhook blocks, `[[permitted_credentials.smtp]]` |
| [`raxis/specs/v1/cli-ceremony.md`](../v1/cli-ceremony.md) | Add `raxis notify` channel/route/credential commands; cross-reference this spec |
| [`raxis/specs/v1/cli-readonly.md`](../v1/cli-readonly.md) | Add `raxis notify channel list`, `raxis notify route list` (read-only) |
| [`raxis/specs/v2/kernel-mechanics-prompt.md`](kernel-mechanics-prompt.md) | NNSP block for SMTP proxy availability per §3.10 |
| [`raxis/specs/v2/v2-deep-spec.md`](v2-deep-spec.md) | Register `INV-NOTIFY-01..06`, `INV-SMTP-PROXY-01..05` invariants |
| [`raxis/specs/v2/kernel-lifecycle.md`](kernel-lifecycle.md) | Boot-probe step + drain-on-shutdown semantics for notifications |
| [`raxis/specs/invariants.md`](../invariants.md) | Reference notification/SMTP invariants |

---

## §10 — Invariants

### §10.1 Goal A — `INV-NOTIFY-*`

- **`INV-NOTIFY-01` — Dispatcher never blocks the parent transaction.** A handler that emits `NotificationDispatched` does so after the originating SQLite `COMMIT`. Channel `deliver()` failure NEVER causes the parent state change to roll back. Verified by `kernel/tests/notification_isolation.rs` which runs a channel impl that always panics; the parent escalation still commits and is observable via `raxis log`.

- **`INV-NOTIFY-02` — Idempotency on `(event_seq, channel_id)`.** A retry of the same payload on the same channel returns `DeliveryReceipt::AlreadyDelivered` and does NOT re-call upstream. Verified by `crates/raxis-notification/conformance::idempotency_under_retry`.

- **`INV-NOTIFY-03` — No agent-attributable surface.** No `IntentKind` variant can cause an `OperatorNotificationChannel::deliver` call. Notification dispatch is triggered exclusively by audit-event emission, and audit events are the kernel's authority record (`R-7`). Verified by `kernel/tests/notification_no_agent_path.rs` which fuzzes intents and asserts the dispatcher counter does not increment from agent-initiated paths.

- **`INV-NOTIFY-04` — STARTTLS or implicit TLS for `EmailChannel`.** `PolicyBundle::validate` rejects an `[[notifications.channels.email]]` entry that has `require_starttls = false` and a `smtp_relay` not on a TLS port. There is no path by which kernel-side SMTP credentials cross the wire in plaintext. Verified by `crates/policy/tests/notification_email_validation.rs`.

- **`INV-NOTIFY-05` — Channel kinds are a closed enumeration.** Adding a new channel kind (e.g., V3 Slack) requires extending `ChannelKind`, the policy-loader switch, the conformance kit, and the audit event payload. Operators cannot inject ad-hoc channel kinds via policy. Verified by exhaustiveness check in `match` arms.

- **`INV-NOTIFY-06` — Retention bound.** `notification_dispatch` rows older than `retention_days` (default 90) are pruned by the periodic GC sweep. Operators retain delivery history within the operator-configured window; older history is reconstructable from the audit log (which is permanent). Verified by `kernel/tests/notification_gc.rs`.

### §10.2 Goal B — `INV-SMTP-PROXY-*`

- **`INV-SMTP-PROXY-01` — Agent never observes upstream credentials.** The proxy never advertises `AUTH` to the agent. The proxy authenticates upstream after `STARTTLS`. Verified by `crates/raxis-cred-proxy/tests/smtp_e2e::agent_sees_no_auth`.

- **`INV-SMTP-PROXY-02` — Agent's `From:` is structurally overridden.** The proxy substitutes `from_address` from policy on both the SMTP envelope (`MAIL FROM`) and the message header (`From:`). The agent's value is recorded in audit but never propagated to upstream. Verified by `crates/raxis-cred-proxy/tests/smtp_e2e::from_substitution_idempotent`.

- **`INV-SMTP-PROXY-03` — Recipient allowlist is structurally enforced.** Every `RCPT TO` is matched against `allowed_recipient_domains` (case-insensitive) and `allowed_recipient_addresses` (if present). Mismatches are rejected with `550 5.7.1` and produce `SmtpProxyMessageRejected`. Verified by `crates/raxis-cred-proxy/tests/smtp_e2e::recipient_allowlist`.

- **`INV-SMTP-PROXY-04` — Rate limits are atomic and audited.** Per-task and per-session counter checks happen inside a `BEGIN IMMEDIATE` transaction in `smtp_proxy_rate_buckets` to prevent two concurrent sends from passing the limit. Both check and increment occur in the same transaction. Verified by `crates/raxis-cred-proxy/tests/smtp_e2e::rate_limit_concurrent`.

- **`INV-SMTP-PROXY-05` — Bcc and forging-relevant headers are stripped.** The header-rewrite parser drops `Bcc:`, `Resent-From:`, `Sender:`, `Return-Path:`, agent-injected `Received:`. Verified by `crates/raxis-smtp-client/tests/headers::header_rewrite`.

---

## §11 — Conformance kit

### §11.1 `OperatorNotificationChannel` conformance fixture

`crates/raxis-notification/src/conformance.rs` provides a generic test harness:

```rust
pub fn run_conformance_kit<F>(make_channel: F) -> TestResult
where F: Fn() -> Box<dyn OperatorNotificationChannel>
{
    test_id_stable(&make_channel());
    test_kind_matches_id(&make_channel());
    test_probe_succeeds_against_fixture(&make_channel());
    test_deliver_succeeds(&make_channel());
    test_idempotency_under_retry(&make_channel());
    test_payload_too_large(&make_channel());
    test_timeout_is_returned(&make_channel());
    test_dispatch_class_matches_kind(&make_channel());
    Ok(())
}
```

Every impl ships its own `tests/conformance.rs` calling `run_conformance_kit(|| Box::new(MyChannel::for_test()))`. Future channels (Slack, PagerDuty) inherit the kit for free.

### §11.2 SMTP proxy conformance

The SMTP proxy is a concrete impl, not a trait, so its conformance is end-to-end against a maildrop fixture container. The test suite asserts the `INV-SMTP-PROXY-*` invariants above against a real SMTP wire.

---

## §12 — Comparison: alternatives considered (and rejected)

### §12.1 Goal A — alternatives

| Approach | Rejected because |
| --- | --- |
| Inline SMTP password in `policy.toml` | Operators commit secrets to git; rotation = re-sign; violates the project-wide pattern that policy holds names, never values |
| Single notification trait that handles both operator-attributed and agent-attributed messages | Erases the `R-9` attribution boundary; an agent intent could trigger an operator-attributed delivery |
| Reuse `OperatorTransport` trait for outbound notifications | Different semantics: `OperatorTransport` is request-response from operator; notification is fire-and-forget from kernel |
| Skip the trait; ship Email/Webhook as concrete kernel modules | Reasonable, but adding Slack/PagerDuty later means re-touching the kernel for every channel kind |
| Trigger notification from within the parent transaction | Violates `INV-NOTIFY-01`; a slow SMTP relay could stall an escalation commit |

### §12.2 Goal B — alternatives

| Approach | Rejected because |
| --- | --- |
| Tier-1 SNI tproxy + agent-supplied SMTP credentials | Defeats `INV-VM-CAP-04`; agent holds the password |
| HTTP API only (require Mailgun/SendGrid/SES via HTTPS) | Forces every customer onto a third-party email API; not all deployments can use one. **This option remains available**: an operator can configure `proxy_type = "http_audit_only"` ([`credential-proxy.md §3.5`](credential-proxy.md)) pointing at their email-provider's REST endpoint. This spec adds `proxy_type = "smtp"` for deployments whose only relay is plain SMTP. |
| Allow agents to set `From:` freely | Spoofing risk; agent could impersonate operator |
| No body audit | Loses forensic visibility; an exfiltrated body has no audit trail |
| Per-message AUTH instead of session-AUTH | Wasteful round-trips; modern relays support session auth and reuse |
| Allow plaintext SMTP (`require_starttls = false`) on non-TLS port | Plaintext credentials on the wire; never. The validator refuses such a config. |

---

## §13 — Document maintenance

This spec is the canonical source for both subsystems. When other V2 specs touch:

- A new audit event kind that operators want emailed → add a `[[notifications.routes]]` entry; do NOT modify the trait.
- A new channel kind (Slack, PagerDuty, Teams) → extend `ChannelKind`, add a new crate `crates/raxis-notification-<kind>/`, run the conformance kit, update §1.2 of this spec to reflect the new ship list.
- A new agent-egress protocol that's "like SMTP" (e.g., XMPP, Matrix) → add a new `proxy_type`, do NOT shoehorn into `proxy_type = "smtp"`.

When this spec changes, the cross-spec impact list (§9) is the audit trail of every co-spec to update in lockstep.
