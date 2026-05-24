# Scenario 23 — Escalation Flow

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

When the Orchestrator gives up after a Reviewer keeps rejecting,
it issues `RaiseEscalation` and the kernel records an escalation
the Operator must `approve`/`deny` from the CLI. This scenario
exercises the V2 escalation terminal state and the inspection
flow.

> **Status (V2.5).** Kernel-enforced *ceilings* on review rounds
> (the planned `max_review_rejections` / `max_revision_rounds`
> task fields) are NOT parsed today — see
> §12.13. The substrate they read against
> (`subtask_activations.review_reject_count`) is wired as of
> V2.5 (`handle_submit_review` bumps the counter on terminal
> rejection rounds), but the parser + `handle_retry_sub_task`
> ceiling check are V2.6 follow-ups. The escalation in this
> scenario is therefore driven by the **Orchestrator harness's**
> own "give up after N rounds" heuristic, not by a kernel
> ceiling.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- The escalation terminal state reached after the Orchestrator
  gives up on a stuck Executor / Reviewer pair.
- `raxis escalation list` and `raxis escalation approve` /
  `raxis escalation deny` CLI flow (the older `accept` spelling
  was renamed; see `cli/src/cmd/escalation.rs`).

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/src"
cd "$RAXIS_MAIN_REPO"

git init -q
echo "fn main() { }" > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/23-escalation-flow/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"

# Wait for escalation:
raxis escalation list --json
```
