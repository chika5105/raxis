# Scenario 01 — Hello World

> **Complexity:** ⭐ Beginner | **Wall clock:** ~5 min | **Provider:** Anthropic

The smallest possible RAXIS plan that actually does work. One Executor
writes a single file (`HELLO.md`) and submits `CompleteTask`. No
Reviewer, no merge gate, no verifier — pure baseline. After this
scenario you have proven the kernel boots, signs, admits, and runs
exactly one task to completion.

---

## Prerequisites

- **One-time setup complete.** See [`../../SETUP.md`](../../SETUP.md).
- **Kernel running** (`raxis-kernel` in another terminal).
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported** in this shell.
- **Anthropic credentials** at
  `$RAXIS_DATA_DIR/providers/anthropic-prod.toml` (mode 0600).

If your install pre-dates this scenario, run the three-line "Confirming
an existing install" check at the bottom of `SETUP.md`.

---

## What this scenario demonstrates

- A minimal valid `plan.toml` (one task, no predecessors, no Reviewer).
- The full operator workflow: validate → submit → approve → inspect.
- The kernel's audit chain emitting one `IntentAccepted` and one
  `TaskCompleted` event end-to-end.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-01"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

git init -q
echo "# Demo repo for scenario 01" > README.md
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the scratch directory:

```bash
cp /path/to/raxis/guides/scenarios/01-hello-world/plan.toml "$DEMO_ROOT/plan.toml"
```

---

## Run it

```bash
# 1. Local pre-flight: catch obvious mistakes before round-trip.
raxis plan validate "$DEMO_ROOT/plan.toml"

# 2. Submit + approve.
raxis submit plan "$DEMO_ROOT/plan.toml" --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
echo "INIT_ID=$INIT_ID"
raxis plan approve "$INIT_ID"

# 3. Watch.
raxis initiative show "$INIT_ID" --with-tasks
```

The expected progression:

1. `raxis plan validate` exits 0 with a list of `[OK]` lines.
2. `raxis submit plan` returns a fresh `initiative_id` and `Status:
   Draft`.
3. `raxis plan approve` reports `tasks_admitted: 1`.
4. The Orchestrator boots, activates the `greeter` task.
5. The Executor writes `HELLO.md` and submits `CompleteTask`.
6. `raxis initiative show` eventually shows `greeter: Completed`.

---

## What "success" looks like

```bash
# Final state
raxis initiative show "$INIT_ID" --with-tasks
# greeter: Completed

# The audit chain has the lifecycle events.
raxis log "$INIT_ID" | head -20
# InitiativeCreated, PlanApproved, SessionCreated (Orchestrator),
# SessionCreated (Executor), IntentAccepted, TaskCompleted, ...

# The chain still verifies.
raxis verify-chain
```

---

## Variations

- **Add a system prompt nudge.** Edit `[[tasks]] context` to ask the
  Executor to write a haiku instead of a greeting.
- **Tighten the allowlist.** Change `path_allowlist = ["./"]` to
  `path_allowlist = ["HELLO.md"]` to demonstrate exact-filename mode.
- **Watch the audit chain live.** In a third terminal:
  `tail -f "$RAXIS_DATA_DIR/audit/segment-000.jsonl"`.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#path-allowlists`](../../CONCEPTS.md#path-allowlists),
  [`#agent-types`](../../CONCEPTS.md#agent-types).
- Pattern: this is the **degenerate case** of
  [`../../patterns/single-executor-reviewer.md`](../../patterns/single-executor-reviewer.md)
  with the Reviewer dropped.
- Spec: `specs/v1/cli-ceremony.md` for the CLI surface;
  `specs/v2/v2-deep-spec.md §Step 6` for the agent-type model.
