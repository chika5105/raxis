# Scenario 04 — Fix a typo with a build witness

> **Complexity:** ⭐ Beginner | **Wall clock:** ~10 min | **Provider:** Anthropic

A regression-protected fix: the Executor patches a typo in a Rust
source file, and the merge gates on a green `cargo build`. After this
scenario you understand how mechanical witnesses are declared per
task, how `WitnessSubmission` flows from the verifier subprocess to
the kernel, and how a red build blocks the merge.

---

## Prerequisites

- Same as scenario 01.
- A working `cargo` on `$PATH` (the verifier subprocess uses it
  directly).

---

## What this scenario demonstrates

- Per-task `[[tasks.verifiers]]` declarations.
- Mechanical witnesses (`raxis-verifier` runs `cargo build`).
- Merge-block on `final_status != "passed"` per
  `verifier-processes.md §4.1.1`.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-04"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --lib --name demo04 -q
sed -i.bak 's/^pub fn add(left:/pub fn ad(left:/' src/lib.rs && rm src/lib.rs.bak
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init (with intentional typo)"

cp /path/to/raxis/guides/scenarios/04-fix-typo-with-witness/plan.toml ./plan.toml
```

The intentional typo (`fn ad(...)` instead of `fn add(...)`) breaks
`cargo build` against the corresponding test. The Executor's job is
to fix it.

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan   ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"

raxis inspect-initiative "$INIT_ID" --with-tasks
raxis witnesses "$(raxis inspect-initiative "$INIT_ID" --with-tasks --json | jq -r '.tasks[0].task_id')"
```

---

## What "success" looks like

- The Executor's commit fixes `fn ad` → `fn add`.
- `raxis witnesses <task_id>` shows one row with
  `result_class = Pass`, `final_status = passed`.
- `raxis verify-chain` exits 0.

---

## Variations

- **Force a red witness.** Edit the plan to ask the Executor to
  rename the function instead of fixing the typo. The verifier reports
  `failed`, the merge blocks, and the kernel emits
  `FAIL_INSUFFICIENT_WITNESS`.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#mechanical-witnesses`](../../CONCEPTS.md#mechanical-witnesses).
- Spec: `specs/v2/verifier-processes.md §4.1.1` for the per-task
  verifier path; `§9` for the verifier-VM lifecycle.
