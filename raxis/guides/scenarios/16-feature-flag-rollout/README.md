# Scenario 16 — Feature Flag Rollout

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

Add a feature flag (off by default), then a follow-up task flips it
to on once an Operator approves the second initiative.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- Two-phase rollout via two separate initiatives.
- Operator approval gating (the second initiative is intentionally
  separate so the operator can sit on it).

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/config" "$RAXIS_MAIN_REPO/src"
cd "$RAXIS_MAIN_REPO"

git init -q
echo '{"new_pricing": false}' > config/flags.json
echo "fn main() { println!(\"hi\"); }" > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
raxis plan validate ./plan-step1.toml
INIT1="$(raxis submit plan ./plan-step1.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT1"

# Later, after canary period:
raxis plan validate ./plan-step2.toml
INIT2="$(raxis submit plan ./plan-step2.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT2"
```
