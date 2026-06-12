# `[[providers]]` — LLM provider entries

> **Topic:** Policy reference | **Time to read:** ~4 min | **Complexity:** ⭐⭐ Intermediate

`[[providers]]` declares the LLM providers model routing may use.
Each entry binds a stable `provider_id`, a provider `kind`, the
credential file backing it, and request limits. Optional
`pricing.*` fields are operator overrides for enterprise contracts
or volume discounts. Without them, RAXIS uses provider-reported
usage and labels the pricing source in the dashboard, with bundled
rates only as an estimate fallback.

---

## Field reference

Each `[[providers]]` block declares one provider.

| Field | Type | Required | Default | Effect |
|---|---|---|---|---|
| `provider_id` | `String` | yes | — | Stable provider identifier. Must be unique. |
| `kind` | `String` | yes | — | Provider family. Canonical V2 values include `Anthropic`, `OpenAI`, `Gemini`, `Bedrock`, and `http_sidecar`. |
| `credentials_file` | `String` | yes | — | Filename **relative to `<data-dir>/providers/`**. The file must exist, be `0600`, and be a TOML map of provider-specific keys (`api_key = "…"`, etc.). |
| `inference_timeout_ms` | `u32` | no | `30000` | Per-inference request deadline. |
| `data_fetch_timeout_ms` | `u32` | no | `10000` | Per-data-fetch request deadline. |
| `max_response_bytes` | `u64` | no | `16777216` | Maximum gateway response body size. |
| `pricing.input_tokens_per_dollar` | `u64` | no | runtime/provider or bundled estimate | Optional override: how many input tokens equal one dollar. |
| `pricing.output_tokens_per_dollar` | `u64` | no | runtime/provider or bundled estimate | Optional override for output tokens. |
| `pricing.cache_read_tokens_per_dollar` | `u64` | no | input override/rate fallback | Optional prompt-cache read override. |
| `pricing.cache_creation_tokens_per_dollar` | `u64` | no | input override/rate fallback | Optional prompt-cache creation override. |

`pricing.*` is optional for LLM-bearing provider entries. If you set
one override, keep it truthful: the dashboard will label costs as
operator-policy priced.

---

## Example — Anthropic

```toml
[[providers]]
provider_id           = "anthropic-prod"
kind                  = "Anthropic"
credentials_file      = "anthropic-prod.toml"
inference_timeout_ms  = 30000
data_fetch_timeout_ms = 10000
max_response_bytes    = 16777216

# Optional operator pricing override.
pricing.input_tokens_per_dollar  = 200000     # $5 per 1M tokens
pricing.output_tokens_per_dollar = 50000      # $20 per 1M tokens
```

The matching credential file:

```bash
cat > "$RAXIS_DATA_DIR/providers/anthropic-prod.toml" <<EOF
api_key = "sk-ant-REPLACE_ME"
EOF
chmod 600 "$RAXIS_DATA_DIR/providers/anthropic-prod.toml"
```

## Example — OpenAI + fallback

```toml
[[providers]]
provider_id      = "openai-primary"
kind             = "OpenAI"
credentials_file = "openai-primary.toml"

[[providers]]
provider_id      = "anthropic-fallback"
kind             = "Anthropic"
credentials_file = "anthropic-fallback.toml"
```

Plans choose provider/model order through `[model_routing]` and
plan-side provider aliases. When the primary provider/model is
unavailable, the kernel attempts the signed fallback chain and still
records which provider/model actually answered.

## Example — local Ollama (no auth)

```toml
[[providers]]
provider_id      = "local-ollama"
kind             = "http_sidecar"
credentials_file = "ollama.toml"     # contains base_url = "http://127.0.0.1:11434"
pricing.input_tokens_per_dollar  = 1000000   # effectively free
pricing.output_tokens_per_dollar = 1000000
```

Local/custom providers can omit pricing, but then RAXIS cannot know
their real contract cost. Set high `pricing.*` override values only
when you want the budget display to model "negligible cost."

---

## Step-by-step — wiring a new provider

```bash
# 1. Drop the credential file.
mkdir -p "$RAXIS_DATA_DIR/providers"
cat > "$RAXIS_DATA_DIR/providers/new-provider.toml" <<EOF
api_key = "REPLACE_ME"
EOF
chmod 600 "$RAXIS_DATA_DIR/providers/new-provider.toml"

# 2. Add [[providers]] to policy.toml.
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"

# 3. Re-sign.
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"

# 4. Restart the kernel (gateway supervisor reads providers at boot).
# Then verify:
raxis providers status
```

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `BOOT_ERR_CREDENTIAL_MODE` | The `<id>.toml` file under `providers/` is not `0600`. `chmod 600 …`. |
| Cost looks estimated | Add a `pricing.*_tokens_per_dollar` override only when you know your contract/list rates. RAXIS otherwise labels bundled fallback pricing as an estimate. |
| `Validation: provider id already declared` | Two entries share an `id`. Pick a unique one. |
| `CircuitOpen` on every request to one provider | The breaker is open after consecutive failures. Run `raxis providers reset <id>` to force-close it. |

---

## Reference: relevant CLI

| Command | Purpose |
|---|---|
| `raxis providers status [--json]` | Per (provider, model) circuit-breaker state. |
| `raxis providers reset <id> [<model>]` | Force-close the breaker. If `<model>` is omitted, resets every model under the provider. |
| `raxis credential add <name>` / `rotate` / `remove` | Manage the credential file (alternative to hand-editing `providers/<id>.toml`). |
| `raxis credential audit <name>` | Audit history of every change to a credential file. |

---

## Variations

- **Single-provider tight install.** One `[[providers]]`,
  one credential. Most demos use exactly this shape.
- **Tiered fallback.** Three providers in order — primary,
  secondary, tertiary. Configure with three `[[providers]]` entries
  and ordered role chains in `[model_routing]`.
- **Dev (no inference).** Omit `[model_routing]` and `[[providers]]`
  entirely. The kernel boots; sessions can be created; LLM-bearing
  intents fail at the gateway level. Useful for verifier-only tests.
