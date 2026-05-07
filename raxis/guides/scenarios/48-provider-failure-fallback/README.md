# Scenario 48 — Provider Failure Fallback

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~10 min | **Provider:** Anthropic + a non-existent secondary

Configure a primary Anthropic provider and a deliberately-broken
secondary. Watch the gateway retry-then-fail-over without disturbing
the kernel.

---

## Prerequisites

Same as scenario 04. Working Anthropic credentials.

---

## What this scenario demonstrates

- Provider-side `fallback_chain` configuration in policy.
- Gateway-emitted `WARN_LLM_FALLBACK` audits.

---

## Run it

```bash
# Apply policy.toml that adds a fallback chain.
raxis policy publish ./policy.toml.signed
# Then run any short scenario (e.g. scenario 04). Watch the audits.
```
