# Scenario 16 — Feature Flag Rollout

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

Add a feature flag (off by default), then a follow-up task flips it
to on once an Operator approves the second initiative.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- Two-phase rollout via two separate initiatives.
- Operator approval gating (the second initiative is intentionally
  separate so the operator can sit on it).

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-16"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/config" "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
echo '{"new_pricing": false}' > config/flags.json
echo "fn main() { println!(\"hi\"); }" > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
raxis plan validate ./plan-step1.toml
raxis submit plan ./plan-step1.toml --no-dry-run
INIT1="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT1"

# Later, after canary period:
raxis plan validate ./plan-step2.toml
raxis submit plan ./plan-step2.toml --no-dry-run
INIT2="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT2"
```
