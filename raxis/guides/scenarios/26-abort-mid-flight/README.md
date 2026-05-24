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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/src"
cd "$RAXIS_MAIN_REPO"

git init -q
echo "fn main() {}" > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/26-abort-mid-flight/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
sleep 5  # let the VM boot
raxis initiative abort "$INIT_ID"
```
