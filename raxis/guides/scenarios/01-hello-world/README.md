# Scenario 01 — Hello World

> **Complexity:** ⭐ Beginner | **Wall clock:** ~5 min | **Provider:** Anthropic

The smallest possible RAXIS plan that actually does work. One Executor
writes a single file (`HELLO.md`) and submits `CompleteTask`. No
Reviewer, no merge gate, no verifier — pure baseline. After this
scenario you have proven the kernel boots, signs, admits, and runs
exactly one task to completion.

---

## Prerequisites

- **One-time setup complete.** See
  [`../../getting-started/README.md`](../../getting-started/README.md)
  for Homebrew, or [`../../SETUP.md`](../../SETUP.md) for source
  builds.
- **Kernel running** (`raxis-kernel` in another terminal).
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported** in this shell.
- **Anthropic credentials** at
  `$RAXIS_DATA_DIR/providers/anthropic-prod.toml` (mode 0600).

Use [`../README.md`](../README.md) as the shared Homebrew runner for
all numbered scenarios.

---

## What this scenario demonstrates

- A minimal valid `plan.toml` (one task, no predecessors, no Reviewer).
- The full operator workflow: validate → submit → approve → inspect.
- The kernel's audit chain emitting one `IntentAccepted` and one
  `TaskCompleted` event end-to-end.

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"

rm -rf "$RAXIS_MAIN_REPO"
install -d "$(dirname "$RAXIS_MAIN_REPO")"
git init -q "$RAXIS_MAIN_REPO"
git -C "$RAXIS_MAIN_REPO" symbolic-ref HEAD refs/heads/main

printf '# Demo repo for scenario 01\n' > "$RAXIS_MAIN_REPO/README.md"
git -C "$RAXIS_MAIN_REPO" -c user.email=demo@raxis.local -c user.name=Demo add .
git -C "$RAXIS_MAIN_REPO" -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
# 1. Local pre-flight: catch obvious mistakes before round-trip.
PLAN_PATH="$PWD/plan.toml"
raxis plan validate "$PLAN_PATH"

# 2. Submit + approve.
INIT_ID="$(raxis submit plan "$PLAN_PATH" --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
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

# The result landed on the canonical repo.
git -C "$RAXIS_MAIN_REPO" show main:HELLO.md
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
# Optional: reset the canonical scenario repo.
# rm -rf "$RAXIS_MAIN_REPO"
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
