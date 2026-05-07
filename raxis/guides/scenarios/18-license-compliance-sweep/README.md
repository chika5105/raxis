# Scenario 18 — License Compliance Sweep

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

A reviewer-style Executor walks `Cargo.toml` + `Cargo.lock` and writes
`COMPLIANCE.md` listing every license in the dep graph. Useful for
RBAC-bound legal reviews.

---

## Prerequisites

Same as scenario 04. `cargo` available.

---

## What this scenario demonstrates

- Read source-of-truth files + write a single audit doc.
- A `Mechanical` witness via `cargo metadata --format-version=1`.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-18"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --bin --name demo18 -q
cargo add serde@1 anyhow -q
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
