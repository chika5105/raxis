# Scenario 28 — cargo clippy Verifier

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

A clippy-driven mechanical witness ensures lint-cleanness. The
Executor must produce code that passes `cargo clippy -- -D warnings`.

---

## Prerequisites

Same as scenario 04. Plus `rustup component add clippy` if not
already installed.

---

## What this scenario demonstrates

- A stricter mechanical witness using `-D warnings` to fail on any
  lint.
- The kernel rejecting commits that don't satisfy.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-28"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --lib --name demo28 -q
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
