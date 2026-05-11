# `[notifications]` — channels and event routing

> **Topic:** Policy reference | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

The notifications block tells the kernel where to deliver
operator-facing events: escalations needing approval, lineage
quarantines, plan rejections, etc. The default channel is `"shell"`
— a JSONL append at `<data-dir>/notifications/inbox.jsonl` that the
operator reads via `raxis inbox`. You can override or add channels
(file, webhook, pager) and route specific event kinds to specific
channels.

The block is **optional**; omitting it falls through to a single
implicit `"shell"` channel that catches everything.

---

## Field reference

### `[[notifications.channels]]`

Each block declares one channel.

| Field | Type | Required | Effect |
|---|---|---|---|
| `id` | `String` | yes | Stable channel identifier. Referenced from `[notifications.routes]` and `[notifications.default]`. |
| `kind` | `String` | yes | One of `"shell"` (JSONL append), `"file"` (custom path), `"webhook"` (HTTP POST), `"pager"` (PagerDuty integration). |
| Per-kind fields | various | depends | See examples below. |

### `[notifications.routes]`

A map of `event_kind → [channel_id]`. The kernel dispatches a copy
of the event to every channel in the list. An event_kind absent
from the map falls through to `[notifications.default]`.

Empty list (`[]`) is the spec's "silenced" form — the kernel
records the event in audit but does not dispatch any notification.

### `[notifications.default]`

Default channel list for event kinds without an explicit route.
When omitted: `["shell"]`.

---

## Example — production with PagerDuty + Slack

```toml
[[notifications.channels]]
id   = "shell"
kind = "shell"

[[notifications.channels]]
id        = "ops-pager"
kind      = "pager"
service_key_credential = "pagerduty-prod.toml"     # under <data-dir>/credentials/
severity  = "critical"

[[notifications.channels]]
id          = "slack-prod"
kind        = "webhook"
url         = "https://hooks.slack.com/services/T0/B0/XYZ"
auth_credential = "slack-webhook.toml"
content_type    = "application/json"

[[notifications.channels]]
id    = "audit-archive"
kind  = "file"
path  = "/var/lib/raxis/audit-mirror/notifications.jsonl"

[notifications.routes]
EscalationRaised      = ["ops-pager", "slack-prod", "shell"]
LineageQuarantined    = ["ops-pager", "shell"]
PolicyReloaded        = ["audit-archive"]
HostDiskLow           = ["ops-pager", "slack-prod"]
PlanBundleReplay      = []                           # silenced — auditable, not paging

[notifications.default]
channels = ["shell"]
```

## Example — dev sandbox

```toml
# Just shell + file:
[[notifications.channels]]
id   = "shell"
kind = "shell"

[[notifications.channels]]
id   = "tail-log"
kind = "file"
path = "/tmp/raxis-notifications.jsonl"

[notifications.routes]
EscalationRaised   = ["tail-log", "shell"]
LineageQuarantined = ["tail-log", "shell"]
```

`tail -f /tmp/raxis-notifications.jsonl` in another terminal gives
a live operator dashboard.

---

## How channel kinds work

### `shell` (the default)

Appends one JSON line to `<data-dir>/notifications/inbox.jsonl`.
Read with:

```bash
raxis inbox                              # newest first
raxis inbox --since 1h --json
raxis inbox --kind EscalationRaised
```

### `file`

Same shape as `shell` but at a custom path. Useful for piping
notifications to log aggregators (Logstash, Vector, etc.).

```toml
[[notifications.channels]]
id   = "file-channel"
kind = "file"
path = "/var/log/raxis-notifications.jsonl"
```

### `webhook`

HTTP POST per event. Fields:

| Field | Required | Effect |
|---|---|---|
| `url` | yes | Webhook URL. |
| `auth_credential` | optional | Filename under `<data-dir>/credentials/` containing `Authorization` header value. |
| `content_type` | optional, default `"application/json"` | Sent as the `Content-Type` header. |

The kernel never includes secrets in the body. Each POST is
fire-and-forget with a 5s timeout; failures are logged but not
retried.

### `pager`

PagerDuty integration. Fields:

| Field | Required | Effect |
|---|---|---|
| `service_key_credential` | yes | Filename under `<data-dir>/credentials/` containing the PagerDuty integration key. |
| `severity` | optional, default `"warning"` | Maps to PagerDuty's `severity`. |

---

## How routing works

```text
Event "EscalationRaised" emitted by kernel
    └─ Lookup [notifications.routes]["EscalationRaised"]
        ├── if present: dispatch to listed channels
        └── if absent:  dispatch to [notifications.default].channels
            └─ default falls back to ["shell"] when omitted
```

A single event fans out to multiple channels. The dispatch is
parallel; one slow webhook does not block the others.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `Validation: notifications.channels duplicate id` | Two `[[notifications.channels]]` share an `id`. |
| `Validation: route references unknown channel id` | A `[notifications.routes]` entry names a channel not declared. |
| Events show in audit but no notification fires | The route is `[]` (intentionally silenced) OR the channel kind is `webhook` and the URL is unreachable (check `raxis log --kind NotificationDispatchFailed`). |
| PagerDuty pages don't dispatch | The `service_key_credential` file is missing or wrong mode. `chmod 600 …`. |
| `inbox.jsonl` doesn't exist | The shell channel is fine — the file is created lazily on the first event. `raxis inbox` exits 2 until then. |

---

## Reference: relevant CLI + state

| Surface | Purpose |
|---|---|
| `raxis inbox [--kind K] [--since DURATION] [--limit N] [--json]` | Read the shell channel inbox. |
| `raxis log --kind NotificationDispatched` | Audit every successful dispatch. |
| `raxis log --kind NotificationDispatchFailed` | Audit failed dispatches with the underlying error. |
| `<data-dir>/notifications/inbox.jsonl` | The shell channel's append-only file. |
| `<data-dir>/credentials/<name>` | Webhook / pager credential storage; mode 0600 enforced. |

---

## Variations

- **Silence specific events.** `EventKind = []` in routes.
- **Notify-on-everything.** Make `[notifications.default]` route to
  multiple channels; every uncategorised event fans out to all.
- **Local-only.** Only declare the implicit `shell` channel; events
  pile up in `inbox.jsonl` for the operator to read at their
  convenience.
