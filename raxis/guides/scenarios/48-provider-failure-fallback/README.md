# Scenario 48 — Provider Failure Fallback

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~12 min | **Provider:** Anthropic primary + secondary

Configure the policy with a primary Anthropic provider and a
deliberately-broken secondary (bad API key or unreachable endpoint).
Run a small initiative. The gateway tries the primary, the call
succeeds, no fallback fires — that's the negative control. Then
revoke the primary's key (or yank the file), re-run, and watch the
gateway transparently fall through to the secondary while the
audit chain records the failover.

## When to use this

- You're hardening a production install and want to validate the
  fallback chain end-to-end before relying on it.
- You're rehearsing a "provider outage" incident drill.
- You're tuning per-provider timeouts and need an observable
  failover signal.

---

## Prerequisites

- **One-time setup complete.** See
  [`../../getting-started/README.md`](../../getting-started/README.md)
  for Homebrew, or [`../../SETUP.md`](../../SETUP.md) for source
  builds.
- **Kernel running.**
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported.**
- **Two provider credential files** in `$RAXIS_DATA_DIR/providers/`,
  mode `0600`. The "primary" can be your real Anthropic key; the
  "secondary" can be the *same* key with a different `id` so the
  fallback is otherwise indistinguishable, or a second valid
  account.

---

## What this scenario demonstrates

- `[[providers.entries]]` is ordered; the gateway tries them in
  declaration order on the policy's `fallback_chain` when a call
  fails.
- The kernel emits `ProviderFailover` audit rows on every
  failover. Operators can alert on these.
- A single failing provider does **not** abort the task — the
  Executor sees the retry as a single transparent `InferenceCompleted`
  event with `provider_id` set to the secondary.
- If **all** providers in the chain fail, the kernel emits
  `InferenceFailed` and the planner sees `FAIL_LLM_UNAVAILABLE`.

---

## Files in this scenario

| File | Purpose |
|---|---|
| `policy.toml` | Two `[[providers.entries]]` blocks plus a `fallback_chain = ["anthropic-prod", "anthropic-secondary"]`. Replace the API keys with yours. |
| `credential.toml` | Two `[provider.<id>]` blocks (primary + secondary) — copy each to `$RAXIS_DATA_DIR/providers/<id>.toml` and `chmod 600`. |

(No `plan.toml` — reuse any short single-task plan, e.g. scenario
01's `plan.toml`.)

---

## Run it

```bash
# 1. Merge policy delta + re-sign.
cat ./policy.toml >> "$RAXIS_DATA_DIR/policy/policy.toml"
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig    "$RAXIS_DATA_DIR/policy/policy.sig"

# 2. Run a tiny initiative to establish the baseline.
cp /path/to/raxis/guides/scenarios/01-hello-world/plan.toml /tmp/plan-baseline.toml
INIT_BASE="$(raxis submit plan /tmp/plan-baseline.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_BASE"
# Confirm Completed.
raxis initiative show "$INIT_BASE" --with-tasks

# Expect zero ProviderFailover events.
raxis log "$INIT_BASE" --kind ProviderFailover --json | wc -l
# 0

# 3. Break the primary.
mv "$RAXIS_DATA_DIR/providers/anthropic-prod.toml" \
   "$RAXIS_DATA_DIR/providers/anthropic-prod.toml.disabled"
# (or edit the file to use an invalid bearer token; either way the
#  gateway's first call to the primary fails.)

# 4. Re-run.
INIT_FAILOVER="$(raxis submit plan /tmp/plan-baseline.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_FAILOVER"

# 5. Restore the primary (and clean up).
mv "$RAXIS_DATA_DIR/providers/anthropic-prod.toml.disabled" \
   "$RAXIS_DATA_DIR/providers/anthropic-prod.toml"
```

---

## What "success" looks like

```bash
# 1. The failover initiative completed.
raxis initiative show "$INIT_FAILOVER" --with-tasks
# greeter: Completed

# 2. At least one ProviderFailover event fired, naming both providers.
raxis log "$INIT_FAILOVER" --kind ProviderFailover --json \
  | jq '.[0] | {from: .payload.from_provider, to: .payload.to_provider, reason: .payload.reason}'
# {
#   "from": "anthropic-prod",
#   "to":   "anthropic-secondary",
#   "reason": "AuthenticationFailed" (or whatever you induced)
# }

# 3. The InferenceCompleted event names the *secondary* as the
#    serving provider.
raxis log "$INIT_FAILOVER" --kind InferenceCompleted --json \
  | jq '.[0].payload.provider_id'
# "anthropic-secondary"

# 4. Chain still verifies.
raxis verify-chain
```

If both providers fail (deliberately mis-configure both), the
expected shape is:

```bash
raxis log "$INIT_FAILOVER" --kind InferenceFailed --limit 1 --json \
  | jq '.[0].payload.attempted_providers'
# ["anthropic-prod", "anthropic-secondary"]
# Task transitions to Failed with reason FAIL_LLM_UNAVAILABLE.
```

---

## Variations

- **Tune the timeout.** Add `per_provider_timeout_ms = 5000` to the
  primary's block. Make the primary point at a host that
  silently drops connections (e.g. `127.0.0.1:9` blackhole). Watch
  the gateway fail over after 5s instead of immediately.
- **Three-deep chain.** Add a third provider. Break the first two.
  Confirm the failover reaches the third before giving up.
- **Confirm "no failback".** After the failover, do not restore the
  primary. The next initiative starts with `anthropic-prod` again
  on the first attempt (failover is per-call, not sticky); restore
  the primary to flip back.

---

## Tear-down

```bash
raxis initiative abort "$INIT_FAILOVER" 2>/dev/null || true
# Roll back the fallback config if you don't want it active:
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"   # remove [[providers.entries]] blocks
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_DATA_DIR/keys/authority_keypair.pem"
raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig    "$RAXIS_DATA_DIR/policy/policy.sig"
```

---

## Cross-references

- Recipe: [`../../recipes/policy/10-providers-section.md`](../../recipes/policy/10-providers-section.md)
  documents the providers block and fallback semantics.
- Spec: `specs/v2/extensibility-traits.md §7` (inference routing
  trait); `specs/v2/v2-deep-spec.md §provider-fallback`.
- Related scenarios:
  - [`43-policy-epoch-advance-live`](../43-policy-epoch-advance-live/)
    — the live re-signing flow used here.
  - [`44-session-revocation`](../44-session-revocation/) — a different
    "kill switch" surface that exercises a similar audit pattern.
