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

Each `[[providers]]` (canonically `[[providers.entries]]` in the
serialised TOML) block declares one provider.

| Field | Type | Required | Default | Effect |
|---|---|---|---|---|
| `id` | `String` | yes | — | Stable provider identifier, referenced by `[[providers]] id` and by `[default_model]` lookups inside the gateway. Must be unique. |
| `kind` | `String` | yes | — | Provider family. Canonical V2 values: `Anthropic`, `OpenAI`, `Bedrock`, `Vertex`, `Ollama`. Unknown kinds fail policy load. |
| `credentials` | `String` | yes | — | Filename **relative to `<data-dir>/providers/`**. The file must exist, be `0600`, and be a TOML map of provider-specific keys (`api_key = "…"`, etc.). |
| `default_model` | `String` | yes | — | The model the gateway uses when an inference request doesn't pin one. Must be a model the provider supports; the gateway calls `provider.list_models()` at boot and rejects unrecognised defaults. |
| `pricing.input_tokens_per_dollar` | `u64` | yes | — | How many input tokens equal one dollar. Used by the budget heuristic to project token spend into admission units. |
| `pricing.output_tokens_per_dollar` | `u64` | yes | — | Same for output tokens. |
| `pricing.usage_units` | `String` | optional | "tokens" | Reserved; future support for non-token usage measurement. |
| `circuit_breaker.consecutive_failures` | `u32` | optional | 5 | After this many consecutive failed requests, the gateway opens the breaker for this (provider, model). Subsequent requests fail fast with `CircuitOpen`. |
| `circuit_breaker.cooldown_secs` | `u64` | optional | 60 | Seconds the breaker stays open before transitioning to half-open. |

`pricing.*` is **mandatory** for any LLM-bearing provider entry —
`PolicyBundle::validate` rejects entries without it.

---

## Example — Anthropic

```toml
[[providers.entries]]
id            = "anthropic-prod"
kind          = "Anthropic"
credentials   = "anthropic-prod.toml"
default_model = "claude-haiku-4-5"

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
[[providers.entries]]
id            = "openai-primary"
kind          = "OpenAI"
credentials   = "openai-primary.toml"
default_model = "gpt-4-turbo"
  pricing.input_tokens_per_dollar  = 100000
  pricing.output_tokens_per_dollar = 33333

[[providers.entries]]
id            = "anthropic-fallback"
kind          = "Anthropic"
credentials   = "anthropic-fallback.toml"
default_model = "claude-haiku-4-5"
  pricing.input_tokens_per_dollar  = 200000
  pricing.output_tokens_per_dollar = 50000
```

Plans target a provider via `[[providers]] id` in the system prompt
or via the gateway's failover policy. When the primary's circuit
breaker opens (e.g., 5xx storm), the gateway falls back to the
secondary.

## Example — local Ollama (no auth)

```toml
[[providers.entries]]
id            = "local-ollama"
kind          = "Ollama"
credentials   = "ollama.toml"     # contains base_url = "http://127.0.0.1:11434"
default_model = "llama3:70b"
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

# 2. Add [[providers.entries]] to policy.toml.
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
| `default_model not in provider.list_models()` | Typo, or the provider rotated model names. `raxis providers status` shows the live model list once the gateway boots. |
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

- **Single-provider tight install.** One `[[providers.entries]]`,
  one credential. Most demos use exactly this shape.
- **Tiered fallback.** Three providers in order — primary,
  secondary, tertiary. The gateway's circuit-breaker layout makes
  this transparent; configure with three entries and a route in
  `[gateway]`.
- **Dev (no inference).** Omit `[gateway]` and `[[providers]]`
  entirely. The kernel boots; sessions can be created; LLM-bearing
  intents fail at the gateway level. Useful for verifier-only tests.
