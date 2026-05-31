# `[[providers]]` — LLM provider entries

> **Topic:** Policy reference | **Time to read:** ~4 min | **Complexity:** ⭐⭐ Intermediate

`[[providers]]` declares the LLM providers the gateway will route
to. Each entry binds a stable `id` (referenced by plans), a `kind`
(provider family), the credential file backing it, the default
model, and the pricing block the kernel uses to convert tokens into
admission cost. The block is the gateway's authoritative
configuration; the file under `<data-dir>/providers/<id>.toml`
holds only the secret bytes.

---

## Field reference

Each `[[providers]]` block declares one provider.

| Field | Type | Required | Default | Effect |
|---|---|---|---|---|
| `provider_id` | `String` | yes | — | Stable provider identifier. Must be unique. |
| `kind` | `String` | yes | — | Provider family. Canonical V2 values: `Anthropic`, `OpenAI`, `Bedrock`, `Vertex`, `Ollama`. Unknown kinds fail policy load. |
| `credentials_file` | `String` | yes | — | Filename **relative to `<data-dir>/providers/`**. The file must exist, be `0600`, and be a TOML map of provider-specific keys (`api_key = "…"`, etc.). |
| `inference_timeout_ms` | `u32` | no | `30000` | Per-inference request deadline. |
| `data_fetch_timeout_ms` | `u32` | no | `10000` | Per-data-fetch request deadline. |
| `max_response_bytes` | `u64` | no | `16777216` | Maximum gateway response body size. |
| `pricing.input_tokens_per_dollar` | `u64` | yes | — | How many input tokens equal one dollar. Used by the budget heuristic to project token spend into admission units. |
| `pricing.output_tokens_per_dollar` | `u64` | yes | — | Same for output tokens. |
| `pricing.cache_read_tokens_per_dollar` | `u64` | no | input rate | Optional prompt-cache read rate. |
| `pricing.cache_creation_tokens_per_dollar` | `u64` | no | input rate | Optional prompt-cache creation rate. |

`pricing.*` is **mandatory** for any LLM-bearing provider entry —
`PolicyBundle::validate` rejects entries without it.

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
pricing.input_tokens_per_dollar  = 100000
pricing.output_tokens_per_dollar = 33333

[[providers]]
provider_id      = "anthropic-fallback"
kind             = "Anthropic"
credentials_file = "anthropic-fallback.toml"
pricing.input_tokens_per_dollar  = 200000
pricing.output_tokens_per_dollar = 50000
```

Plans target a provider via `[[providers]] id` in the system prompt
or via the gateway's failover policy. When the primary's circuit
breaker opens (e.g., 5xx storm), the gateway falls back to the
secondary.

## Example — local Ollama (no auth)

```toml
[[providers]]
provider_id      = "local-ollama"
kind             = "Ollama"
credentials_file = "ollama.toml"     # contains base_url = "http://127.0.0.1:11434"
pricing.input_tokens_per_dollar  = 1000000   # effectively free
pricing.output_tokens_per_dollar = 1000000
```

Even local providers need pricing values — the budget heuristic
uses them, so set them to large values to model "negligible cost".

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
| `Validation: pricing.input_tokens_per_dollar required` | Add the pricing block. Even a placeholder is better than an unset value. |
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
