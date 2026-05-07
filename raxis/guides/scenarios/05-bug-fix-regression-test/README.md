# Scenario 05 — Two-task bug fix: regression test first, then fix

> **Complexity:** ⭐ Beginner | **Wall clock:** ~12 min | **Provider:** Anthropic

A two-task plan with a `predecessors` edge: the first Executor writes
a regression test that *currently fails*, the second Executor writes
the fix that makes it pass. After this scenario you understand how
the kernel sequences predecessor → successor and how `evaluation_sha`
and the V2 task-graph activation rules combine to enforce ordering.

---

## Prerequisites

Same as scenario 04 (cargo on $PATH).

---

## What this scenario demonstrates

- DAG topology with a `predecessors = ["..."]` edge.
- Sequenced execution: the kernel does NOT activate the fixer until
  the test-author task is `Completed`.
- A `cargo test` mechanical witness on the fixer task that gates the
  merge on green tests.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-05"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --lib --name demo05 -q
cat > src/lib.rs <<'EOF'
//! Demo with a known bug: divisor of zero panics instead of returning Err.
pub fn safe_div(a: i64, b: i64) -> Result<i64, &'static str> {
    Ok(a / b)
}
EOF
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init (with bug: panics on b=0)"

cp /path/to/raxis/guides/scenarios/05-bug-fix-regression-test/plan.toml ./plan.toml
```

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan   ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"

# Watch the DAG advance.
watch -n 2 "raxis inspect-initiative $INIT_ID --with-tasks"
```

Expected progression:

1. `regression_test` activates first.
2. Executor adds a `#[test]` that exercises `safe_div(1, 0)` and
   asserts `is_err()`. Submits CompleteTask.
3. The kernel's witness verifier runs `cargo test`; the test fails
   (the bug is still there), but the test-author task is graded on
   *the test itself being well-formed*, not on it currently passing.
   The verifier in the plan is `cargo build` — green build is
   sufficient for the test-author phase.
4. `fixer` activates. Executor changes `safe_div` to return
   `Err("division by zero")` when `b == 0`. The `cargo_test`
   verifier on `fixer` re-runs the same test and now it passes.
5. The merge advances master.

---

## What "success" looks like

```
regression_test: Completed
fixer:           Completed
```

`raxis witnesses fixer` shows the cargo-test witness with
`final_status = passed`.

---

## Variations

- **Make the test author write a green test.** Change the test to
  call `safe_div(10, 2)` instead of `safe_div(1, 0)`. The fixer task
  becomes idle work; the merge still passes.
- **Reverse the order.** Drop the `predecessors` line on `fixer` and
  watch the kernel reject at admission with a structurally invalid
  DAG.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#dependency-rules-the-dag`](../../CONCEPTS.md#dependency-rules-the-dag),
  [`#mechanical-witnesses`](../../CONCEPTS.md#mechanical-witnesses).
- Spec: `specs/v2/v2-deep-spec.md §Step 21` for the V2 sub-task DAG
  activation rules; `verifier-processes.md §4.1.1` for the per-task
  verifier path.
