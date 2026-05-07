# Scenario 32 — Load-Test Witness

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~15 min | **Provider:** Anthropic

After the Executor builds an HTTP service, a mechanical witness uses
`hey` (or `wrk`) to put it under load and asserts a p99 ceiling.

---

## Prerequisites

Same as scenario 15. Plus `hey` on $PATH (`brew install hey` /
`go install github.com/rakyll/hey@latest`).

---

## What this scenario demonstrates

- Beyond-build mechanical witnesses: a *behavioural* check.
- Per-witness timeout via `wall_clock_seconds`.

---

## Repository setup

Same as scenario 15.

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"
```
