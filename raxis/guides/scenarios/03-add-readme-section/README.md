# Scenario 03 — Add a README Section

> **Complexity:** ⭐ Beginner | **Wall clock:** ~6 min | **Provider:** Anthropic

The Executor adds a single new section to the repo's [`README.md`](README.md)
under a strict `path_allowlist`. After this scenario you understand
how V2 entry-shape rules turn `path_allowlist = ["README.md"]` into a
hard exact-match constraint and what `FAIL_PATH_POLICY_VIOLATION`
looks like when an agent tries to wander off-path.

---

## Prerequisites

Same as scenario 01 (one-time setup; kernel running; operator key
exported; Anthropic credentials present).

---

## What this scenario demonstrates

- Exact-filename `path_allowlist` (no globs, no directory expansion).
- The `INV-08` opaque-rejection contract: the kernel returns
  `FAIL_PATH_POLICY_VIOLATION` without exposing which path was wrong.
- The Orchestrator's reaction to a path-policy rejection: it nudges
  the Executor with a critique-prepended retry.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-03"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

git init -q
cat > README.md <<'EOF'
# Demo

This is the demo repository for RAXIS scenario 03.

## Existing section

This section is unchanged.
EOF
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"

cp /path/to/raxis/guides/scenarios/03-add-readme-section/plan.toml ./plan.toml
```

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan   ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"
raxis initiative show "$INIT_ID" --with-tasks
```

---

## What "success" looks like

- [`README.md`](README.md) gains a new top-level section titled "Quickstart" or
  similar.
- `git log` shows one new commit by the Executor.
- `raxis initiative show` reports `documenter: Completed`.
- The audit chain has one `IntentAccepted` and one `TaskCompleted`
  event — no path-policy rejections.

---

## Variations

- **Force a path violation.** Edit the plan to ask the Executor to
  also touch `LICENSE` (which is NOT in the allowlist). Watch the
  kernel reject the commit with `FAIL_PATH_POLICY_VIOLATION` and the
  Executor retry inside the allowlist on the next round.
- **Widen the allowlist.** Change `path_allowlist = ["README.md"]` to
  `path_allowlist = ["./"]` and ask the Executor to also create
  `CHANGELOG.md`. This time both files appear in one commit.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#path-allowlists`](../../CONCEPTS.md#path-allowlists).
- Spec: `specs/v2/policy-plan-authority.md` for the path-allowlist
  precedence rules.
