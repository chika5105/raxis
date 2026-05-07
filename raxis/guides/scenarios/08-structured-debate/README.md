# Scenario 08 — Structured Debate

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~12 min | **Provider:** Anthropic

Two designer agents argue across rounds before a single Executor
implements. After this scenario you understand the V2 multi-round
deliberation pattern and how `predecessors` chains compose.

---

## Prerequisites

Same as scenario 01.

---

## What this scenario demonstrates

- Reviewer-shaped Designer tasks that produce structured opinions
  (no code).
- A chain `proposal_a → critique_b → revised_a → final_decision` that
  emerges from `predecessors` edges.
- The kernel's even-handed handling of "Reviewer" agents that don't
  evaluate code but produce text artefacts.

See [`../../patterns/structured-debate.md`](../../patterns/structured-debate.md)
for the abstract pattern.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-08"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

git init -q && cargo init --lib --name demo08 -q
mkdir -p docs && touch docs/.keep
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan   ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"
raxis inspect-initiative "$INIT_ID" --with-tasks
```

---

## What "success" looks like

```
designer_a:    Completed
designer_b:    Completed
implementer:   Completed
```

`docs/decision.md` exists, written by `designer_b`'s second-round
artifact, and `src/lib.rs` reflects the chosen design.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Pattern: [`../../patterns/structured-debate.md`](../../patterns/structured-debate.md).
