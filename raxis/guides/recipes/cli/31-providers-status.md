# `raxis providers status` and `raxis providers reset`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

LLM provider gateway health surface. The kernel funnels every
planner LLM call through the `raxis-gateway` sidecar; `providers
status` shows per-provider liveness, recent errors, and quota.
`providers reset` clears the per-provider error counters after an
operator confirms the upstream issue is resolved.

---

## Syntax

```text
raxis providers status            [--json]
raxis providers reset <provider>  [--reason <text>]
```

---

## providers status — health snapshot

```bash
raxis providers status
# Output:
# PROVIDER       BASE_URL                            STATUS    REQ_TODAY    ERR_RATE   LAST_ERROR
# anthropic-1    https://api.anthropic.com           ok        4321         0.4%       —
# openai-1       https://api.openai.com              degraded  2100         18.3%      2026-05-10T17:02:00Z 503 service_unavailable
# self-host      http://10.0.0.5:8080                quarantined  0          —          2026-05-10T16:00:00Z circuit_open
# stub-provider  stub://internal                      ok        45           0%         —
```

Statuses:

- `ok` — last 5 minutes are healthy.
- `degraded` — error rate above
  `[gateway.circuit_breaker].degraded_threshold` (default 5%).
- `quarantined` — circuit breaker tripped (error rate above
  `[gateway.circuit_breaker].open_threshold`); the gateway refuses
  to dispatch to this provider until the operator resets.
- `unknown` — no traffic in the observation window.

`--json` form for dashboards:

```bash
raxis providers status --json | jq '.[] | select(.status != "ok")'
```

---

## providers reset — clear circuit breaker

After confirming the upstream provider is healthy again (e.g., the
provider's status page is green), `providers reset` clears the
breaker so the gateway resumes dispatching:

```bash
raxis providers reset openai-1 \
  --reason "openai status page confirmed recovered"
# Output:
# provider:    openai-1
# from_status: degraded
# to_status:   ok
# reset_at:    2026-05-10T17:30:00Z
```

The reset is recorded in audit (`ProviderCircuitReset`).

`reset` does not retry in-flight requests — only re-opens the
breaker for new traffic. Sessions blocked on planner LLM calls will
naturally retry on their next intent.

---

## Provider config recap

Providers are declared in `policy.toml` under `[[providers.entries]]`:

```toml
[[providers.entries]]
id            = "anthropic-1"
base_url      = "https://api.anthropic.com"
default_model = "claude-3-5-sonnet-20241022"
credential_id = "anthropic-key"
[providers.entries.pricing]
input_per_1k_tokens  = 0.003
output_per_1k_tokens = 0.015
```

See the [providers section recipe](../policy/10-providers-section.md)
for the full schema. The `credential_id` references a credential
registered with `raxis credential add --kind generic`.

---

## Common errors

| Symptom | Fix |
|---|---|
| `status: gateway not running` | The `raxis-gateway` sidecar is down; check its systemd unit. |
| `reset: provider not found` | Wrong id; matches the `id` in `[[providers.entries]]`. |
| `reset: provider not in degraded/quarantined` | No circuit to clear. |
| `OPERATOR_NOT_AUTHORIZED` | Cert lacks `ResetProvider` in `permitted_ops`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis credential verify <id>` | Sanity-check the credential the provider uses. |
| `raxis log --kind ProviderError` | Past provider errors. |
| `raxis policy show` | Inspect `[[providers.entries]]` config. |
| `raxis status` | Confirms gateway sidecar liveness. |

---

## Variations

- **Provider-failure runbook.** When `providers status` shows
  `degraded`, fall back to a secondary provider in the same
  `[[providers.entries]]` array; sessions auto-route to the next
  healthy provider.
- **Self-hosted endpoint.** A locally-run model behind the gateway;
  add as a `[[providers.entries]]` and treat exactly the same.
- **Periodic synthetic probe.** Cron a tiny "ping" plan that
  exercises every provider; alert on any non-ok status.
- **Zero-LLM mode.** Use `stub-provider` (no real LLM call) for
  end-to-end tests where you don't want the gateway hitting real
  providers.
