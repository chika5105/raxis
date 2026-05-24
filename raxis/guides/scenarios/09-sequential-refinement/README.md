# Scenario 09 — Sequential Refinement

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

Three Executors in a chain, each polishing the previous one's output.
After this scenario you understand the V2 chain pattern and how
`evaluation_sha` propagates through `predecessors`.

---

## Prerequisites

Same as scenario 01.

---

## What this scenario demonstrates

- A 3-task chain: `draft → refine → polish`.
- Each successor sees the predecessor's terminal commit_sha as its
  base.
- The kernel's `path_allowlist` propagation across the chain.

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

git init -q
echo "# Demo" > README.md
mkdir -p docs && touch docs/.keep
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/09-sequential-refinement/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
raxis initiative show "$INIT_ID" --with-tasks
```

---

## What "success" looks like

`docs/spec.md` evolves across three commits, each by a different
agent.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$RAXIS_MAIN_REPO"
```

---

## Cross-references

- Pattern: [`../../patterns/single-executor-reviewer.md`](../../patterns/single-executor-reviewer.md).
