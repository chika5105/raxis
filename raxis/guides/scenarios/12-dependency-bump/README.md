# Scenario 12 — Dependency Bump

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~8 min | **Provider:** Anthropic

A bumper agent updates `Cargo.toml` and `Cargo.lock`, then a verifier
runs `cargo build` to make sure nothing broke.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- Use of `cross_cutting_artifacts = ["Cargo.lock"]`, which would
  otherwise trip the per-task allowlist.
- A mechanical witness via `[[tasks.witnesses]]`.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-12"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --lib --name demo12 -q
cargo add serde@1.0.0 -q
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
