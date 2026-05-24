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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

git init -q && cargo init --lib --name demo08 -q
mkdir -p docs && touch docs/.keep
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/08-structured-debate/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan   ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
raxis initiative show "$INIT_ID" --with-tasks
```

---

## What "success" looks like

```yaml
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
rm -rf "$RAXIS_MAIN_REPO"
```

---

## Cross-references

- Pattern: [`../../patterns/structured-debate.md`](../../patterns/structured-debate.md).
