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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

cargo init --lib --name demo28 -q
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/28-cargo-clippy-verifier/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```
