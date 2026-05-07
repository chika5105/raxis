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
export DEMO_ROOT="/tmp/raxis-scenario-09"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

git init -q
echo "# Demo" > README.md
mkdir -p docs && touch docs/.keep
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
raxis inspect-initiative "$INIT_ID" --with-tasks
```

---

## What "success" looks like

`docs/spec.md` evolves across three commits, each by a different
agent.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Pattern: [`../../patterns/single-executor-reviewer.md`](../../patterns/single-executor-reviewer.md).
