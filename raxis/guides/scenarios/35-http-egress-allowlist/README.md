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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/data"
cd "$RAXIS_MAIN_REPO"

git init -q
echo "{}" > data/placeholder.json
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/35-http-egress-allowlist/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```
