# Scenario 23 — Escalation Flow

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

After the maximum revision rounds is exceeded, the kernel escalates
to the Operator for manual intervention. Demonstrates the V2
"escalation" terminal state and how to inspect it.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- The escalation terminal state when `max_revision_rounds` is hit.
- `raxis escalation list` and `raxis escalation accept` CLI flow.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-23"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
echo "fn main() { }" > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"

# Wait for escalation:
raxis escalation list --json
```
