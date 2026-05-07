# Scenario 22 — Reviewer Rejection Then Pass

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

A Reviewer rejects an Executor's first attempt; on the next round
the Executor incorporates feedback and the Reviewer accepts.
Demonstrates the V2 revision-cycle protocol.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- The Executor → Reviewer → Executor revise-loop.
- The kernel's enforcement of `revision_round` increments and
  Reviewer-driven rejection codes.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-22"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
echo "fn main() { println!(\"hi\"); }" > src/main.rs
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
