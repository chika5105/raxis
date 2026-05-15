# Scenario 02 — Single Executor + Reviewer

> **Complexity:** ⭐ Beginner | **Wall clock:** ~8 min | **Provider:** Anthropic

Add a Reviewer to scenario 01. The Executor writes a small utility,
the Reviewer evaluates it, and the kernel either fast-forwards main
or kicks the Executor back into a critique-prepended retry. After this
scenario you understand `predecessors`, the Reviewer activation gate,
and the rejection retry loop.

---

## Prerequisites

Same as scenario 01 (one-time setup; kernel running; operator key
exported; Anthropic credentials present).

---

## What this scenario demonstrates

- The Reviewer agent type and its `predecessors` activation rule.
- The kernel's `evaluation_sha` injection so the Reviewer always
  evaluates the *exact* SHA the Executor produced.
- The retry loop when a Reviewer rejects: the kernel prepends the
  critique to the Executor's next system prompt and re-boots.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-02"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

git init -q
mkdir src
cat > src/lib.rs <<'EOF'
//! A tiny utility crate. The scenario's Executor will add an `add` function.
EOF
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

```bash
cp /path/to/raxis/guides/scenarios/02-single-executor-reviewer/plan.toml "$DEMO_ROOT/plan.toml"
```

---

## Run it

```bash
raxis plan validate "$DEMO_ROOT/plan.toml"
raxis submit plan   "$DEMO_ROOT/plan.toml" --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"

raxis initiative show "$INIT_ID" --with-tasks
```

Expected progression:

1. The Executor (`adder`) boots and implements `pub fn add(a: i32, b:
   i32) -> i32` in `src/lib.rs` with a unit test.
2. After `CompleteTask` lands, the kernel boots the Reviewer
   (`reviewer`) at the Executor's `evaluation_sha`.
3. The Reviewer either approves (initiative completes; main
   advances) or rejects (Executor reboots with the critique).

---

## What "success" looks like

```yaml
greeter:    Completed
reviewer:   Completed
```

Initiative `Status: Completed`. The audit chain shows
`SubmitReview { approved: true }` followed by the
`IntegrationMergeCompleted` event.

---

## Variations

- **Force a rejection.** Edit `[[tasks.reviewer]] context` to demand
  Property-Based-Tests (which the Executor won't have written) so the
  Reviewer rejects the first attempt.
- **Increase the retry budget.** *(V2.6 — not wired today.)* The
  planned `max_review_rejections` task field is reserved but the
  kernel does not yet parse it (see `specs/v2/V2_GAPS.md` §12.13).
  The counter substrate (`subtask_activations.review_reject_count`)
  IS now bumped per terminal-rejection round; the parser + ceiling
  check in `handle_retry_sub_task` are the remaining follow-ups.
  Until then the Orchestrator harness decides when to give up.
- **Tighten the path allowlist.** Set `path_allowlist = ["src/lib.rs"]`
  to demonstrate exact-filename mode.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#agent-types`](../../CONCEPTS.md#agent-types),
  [`#dependency-rules-the-dag`](../../CONCEPTS.md#dependency-rules-the-dag).
- Pattern: [`../../patterns/single-executor-reviewer.md`](../../patterns/single-executor-reviewer.md).
- Spec: `specs/v2/agent-disagreement.md` for the rejection FSM.
