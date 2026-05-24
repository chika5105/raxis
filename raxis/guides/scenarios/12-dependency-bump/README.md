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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

cargo init --lib --name demo12 -q
cargo add serde@1.0.0 -q
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/12-dependency-bump/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```
