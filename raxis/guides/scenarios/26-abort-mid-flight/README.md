# Scenario 26 — Abort Mid-Flight

> **Complexity:** ⭐ Beginner | **Wall clock:** ~5 min | **Provider:** Anthropic

Operator aborts an initiative while it's running. Demonstrates the
clean-shutdown path: VMs torn down, witnesses cancelled, ledger
states transitioned to `Aborted`.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- `raxis initiative abort` on a running initiative.
- The audit chain (`AUDIT_INITIATIVE_ABORTED`).

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-26"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
echo "fn main() {}" > src/main.rs
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
sleep 5  # let the VM boot
raxis initiative abort "$INIT_ID"
```
