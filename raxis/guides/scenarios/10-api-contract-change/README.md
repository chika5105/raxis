# Scenario 10 — API Contract Change

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~12 min | **Provider:** Anthropic

Backend handler + matching test + matching docs in three coordinated
tasks. After this scenario you understand how the kernel keeps three
disjoint path allowlists composable and how `cross_cutting_artifacts`
on the Orchestrator handles shared lockfiles.

---

## Prerequisites

Same as scenario 04 (cargo on $PATH).

---

## What this scenario demonstrates

- Three Executors with disjoint allowlists (`src/`, `tests/`,
  `docs/`).
- A coordinated change across all three.
- The Orchestrator's role at IntegrationMerge time.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-10"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --lib --name demo10 -q
mkdir -p tests docs
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
```

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Spec: `specs/v2/v2-deep-spec.md §Step 11` — hybrid allowlist.
