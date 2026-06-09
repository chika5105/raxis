# Add a new LLM provider

> **Topic:** Operations | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

End-to-end: register a new LLM provider with the gateway, attach
its credential, configure pricing, smoke-test, and (optionally) set
it as the default for a model family.

---

## Prerequisites

- An API key for the provider (Anthropic, OpenAI, OpenRouter,
  Bedrock, Vertex, a self-hosted endpoint, etc.).
- Operator authority for `RegisterCredential` and `SignPolicy`.
- A working `raxis-gateway` sidecar (`raxis providers status`
  returns at least one provider).

---

## Steps

### 1. Register the credential

```bash
raxis credential add \
  --id     anthropic-prod \
  --kind   generic \
  --secret /tmp/anthropic.token \
  --label  "Anthropic prod API key"
```

For provider-specific kinds (e.g., AWS Bedrock), use the matching
kind so the proxy knows the auth shape:

```bash
raxis credential add \
  --id     bedrock-prod \
  --kind   aws_iam \
  --secret /tmp/bedrock-iam.json \
  --restriction '{"allowed_actions":["bedrock:InvokeModel"]}'
```

See [`cli/20-credential-add`](../cli/20-credential-add.md).

### 2. Add the provider to policy

Pull current policy and add an entry:

```bash
raxis policy show > /tmp/policy.toml
```

Append:

```toml
[[providers.entries]]
id              = "anthropic-prod"
base_url        = "https://api.anthropic.com"
default_model   = "claude-3-5-sonnet-20241022"
credential_id   = "anthropic-prod"
priority        = 100                 # higher = preferred when multiple match a model
[providers.entries.pricing]
input_per_1k_tokens  = 0.003
output_per_1k_tokens = 0.015

[[providers.entries.allowed_models]]
model = "claude-3-5-sonnet-20241022"
[[providers.entries.allowed_models]]
model = "claude-haiku-4-5"
```

| Field | Meaning |
|---|---|
| `id` | Stable id, used in `providers status` and budget reports. |
| `base_url` | Provider's API endpoint. The gateway hits this URL. |
| `default_model` | Used when a session doesn't request a specific model. |
| `credential_id` | The `raxis credential add` id; the gateway consults the proxy for the live secret. |
| `priority` | When multiple providers serve the same model, higher wins. |
| `pricing` | USD per 1k tokens; budget accounting uses this. |
| `allowed_models` | Hard whitelist; sessions can only request models in this list. |

### 3. Re-sign and apply

```bash
raxis policy sign /tmp/policy.toml --key /tmp/op.key
raxis --operator-key /tmp/op.key epoch advance \
  --policy /tmp/policy.toml \
  --sig /tmp/policy.sig
raxis providers status | grep anthropic-prod
# Output: status ok (or unknown until first traffic).
```

### 4. Verify connectivity

```bash
raxis credential verify anthropic-prod
# Expected: liveness ok, auth_check ok.

raxis providers status
# Expected: anthropic-prod listed; status: unknown -> ok after first traffic.
```

### 5. Smoke-test with a small plan

A throwaway plan that exercises the provider:

```bash
cat > /tmp/probe-plan.toml <<'EOF'
[plan.initiative]
description = "Probe new provider"

[workspace]
name        = "probe-anthropic-prod"
lane_id     = "default"
repository  = "main"
target_ref  = "refs/heads/main"

[[tasks]]
task_name            = "probe"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = []     # @raxis-explicit no-write-acknowledged
predecessors       = []
description        = "Provider probe"
prompt             = """Print the provider id you're using and exit."""
EOF

INIT="$(raxis submit plan /tmp/probe-plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT"
# Wait...
raxis explain probe
raxis log "$INIT" --kind ProviderRequestStarted
```

You'll see a `ProviderRequestStarted` event with `provider_id:
anthropic-prod`. Confirm the request completed (`ProviderRequestCompleted`).

### 6. Make it the default for a model

If multiple providers serve `claude-3-5-sonnet-20241022`, the
kernel uses `priority` to pick. Bump the new provider's priority
above the others to make it default.

For per-role overrides, configure
`[provider_aliases_defaults.executor]`,
`[provider_aliases_defaults.reviewer]`, and
`[orchestrator] provider_alias` in policy — see
`specs/v2/provider-model-selection.md`. Per-task provider pinning
goes through profiles (not directly on `[[tasks]]`).

---

## Common errors

| Symptom | Fix |
|---|---|
| `policy sign: provider id duplicated` | Two `[[providers.entries]]` with the same id; rename one. |
| `policy sign: credential_id not found` | Credential not registered; `raxis credential add` first. |
| `providers status: degraded immediately` | Auth failing; `raxis credential verify <id>` to debug. |
| `providers status: quarantined immediately` | Repeated 5xx; check the provider's status page or your firewall. |
| Sessions still route to old provider | Lower the old provider's `priority`, or set `provider_id` per-task. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis credential add` | Register the API key. |
| `raxis credential verify <id>` | Auth + liveness. |
| `raxis providers status` | Per-provider health. |
| `raxis providers reset <id>` | Clear circuit breaker. |
| [policy/10-providers-section](../policy/10-providers-section.md) | Full schema. |

---

## Variations

- **Self-hosted model.** `base_url = "http://10.0.0.5:8080"`,
  `credential_id = ""` for an unauthenticated endpoint, or use a
  generic credential.
- **Failover pair.** Register two providers (priority 100 and 90)
  for the same model; sessions auto-route to the higher-priority
  one, fall back when degraded.
- **Per-team provider.** Different lanes get different
  `provider_id` defaults via a `[providers.lane_overrides]`
  section (when supported).
- **Cost-tier ladder.** Register `gpt-4o-mini`, `gpt-4o`, and
  `o1-preview` separately with distinct prices; plans pick based
  on cost-vs-capability needs.
