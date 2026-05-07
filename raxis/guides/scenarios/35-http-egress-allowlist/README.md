# Scenario 35 — HTTP Egress Allowlist

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~10 min | **Provider:** Anthropic

The Executor needs to GET a JSON file from `api.github.com`. The
plan declares `allowed_egress = ["api.github.com:443"]`; everything
else is denied. Demonstrates the V2 transparent egress proxy
(raxis-tproxy + raxis-egress-admission) end-to-end.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- `allowed_egress` declarations.
- The kernel's admission service refusing `evil.example.com`.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-35"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/data"
cd "$DEMO_ROOT"

git init -q
echo "{}" > data/placeholder.json
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
```
